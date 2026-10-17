// The only way the site talks to the database.
//   G1: production connections must go through a connection pooler; a direct address is refused.
//   S8: queries are tagged templates, so every value travels to Postgres as a parameter, never as SQL text.
//       Raw SQL is banned outside scripts/migrate.js by a code check (.semgrep/database.yml).
//   S1/S3: every request runs in one transaction as the dog_app role, with who is acting set for that
//       transaction only, so row-level security decides what each request can see and nothing carries over
//       to the next request on a pooled connection.
'use strict';

const postgres = require('postgres');
const v = require('./validate');

// Connection poolers we accept, by host name and port. Supabase: its shared pooler (Supavisor) in transaction
// mode on port 6543. (Its dedicated pooler, db.<ref>.supabase.co, is reachable only over IPv6, which Vercel's
// functions don't have.) Neon: the "-pooler" address of an endpoint.
const POOLERS = [
  { host: /^[a-z0-9-]+\.pooler\.supabase\.com$/, ports: ['6543'] },
  { host: /^ep-[a-z0-9-]+-pooler\.[a-z0-9.-]+\.neon\.tech$/, ports: ['', '5432'] }
];

function pooledUrl(url) {
  let u;
  try { u = new URL(url); } catch { throw new Error('DATABASE_URL is not a valid address'); }
  if (u.protocol !== 'postgres:' && u.protocol !== 'postgresql:') throw new Error('DATABASE_URL must be a postgres:// address');
  const ok = POOLERS.some((p) => p.host.test(u.hostname) && p.ports.includes(u.port));
  if (!ok) throw new Error('DATABASE_URL must point at a connection pooler in transaction mode (G1)');
  return url;
}

// Encrypted, with the server's certificate checked against trusted roots: Neon's certificates verify against the
// usual public roots; Supabase's are signed by Supabase's own root, whose certificate (public, not a secret) goes
// in DATABASE_CA. Plain 'require' would encrypt without checking who answers, so it is never used.
function tls(ca) {
  // A given certificate is added to Node's usual roots rather than replacing them, so a publicly signed
  // certificate still verifies.
  return ca ? { rejectUnauthorized: true, ca: [...require('tls').rootCertificates, ca] } : { rejectUnauthorized: true };
}

// Pooler-friendly settings: no named prepared statements (transaction poolers can't keep them), a few connections
// per function instance, and short timeouts so a slow database can't hang a request. Settings written into the
// address itself (such as sslmode or channel_binding) are dropped: the driver would send them to Postgres as
// session settings, and the options below are the ones that count.
function connect(url, { ssl = tls(process.env.DATABASE_CA), max = 3 } = {}) {
  const u = new URL(url);
  u.search = '';
  return postgres(u.toString(), {
    prepare: false,
    max,
    ssl,
    idle_timeout: 20,
    connect_timeout: 5,
    max_lifetime: 60 * 30,
    onnotice: () => {}
  });
}

// The site's one shared connection pool, made on first use. It stays inside this file: the rest of the site
// reaches the database only through run(), so every query has an actor and a transaction.
let shared;
function fromEnv() {
  if (!shared) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not set');
    shared = connect(pooledUrl(process.env.DATABASE_URL));
  }
  return shared;
}

// Whether a database address is set (without reading or checking it here).
const configured = () => Boolean(process.env.DATABASE_URL);

// What the site's functions call: db.run({ actor: 'member', memberId }, (t) => members.get(t, id)).
const run = async (ctx, fn) => tx(fromEnv(), ctx, fn);

const ACTORS = ['anon', 'member', 'agent', 'admin', 'system'];

// Checks that the actor makes sense: members and Aaron carry a member ID, agents an agent ID and their owner's
// member ID, and anonymous visitors and the site itself carry neither.
function context(ctx) {
  if (!ctx || typeof ctx !== 'object') throw new Error('every database call needs to say who is acting');
  const actor = v.oneOf('actor', ctx.actor, ACTORS);
  const memberId = ctx.memberId == null ? null : v.uuid('memberId', ctx.memberId);
  const agentId = ctx.agentId == null ? null : v.uuid('agentId', ctx.agentId);
  const needsMember = actor === 'member' || actor === 'admin' || actor === 'agent';
  if (needsMember !== (memberId !== null)) throw new Error(actor + ' calls ' + (needsMember ? 'need' : 'must not have') + ' a member ID');
  if ((actor === 'agent') !== (agentId !== null)) throw new Error(actor + ' calls ' + (actor === 'agent' ? 'need' : 'must not have') + ' an agent ID');
  // Aaron's note for the record, such as why he banned someone (PR 6); the database copies it into the audit log.
  const note = ctx.note == null || ctx.note === '' ? null : v.text('note', ctx.note, { max: 200 });
  if (note !== null && actor !== 'admin') throw new Error('only admin calls carry a note');
  // A fresh sign-in (PR 7): the site checked that this member signed in within the last few minutes, which raising an
  // agent to act on its own requires. Only people's calls carry it.
  const fresh = ctx.fresh === true;
  if (fresh && actor !== 'member' && actor !== 'admin') throw new Error('only member calls can be fresh');
  // The request's own session, by its hash (PR 15's second review, R1): the database reads from it which sign-in
  // method the person signed in with, and records it on the agent keys, rules and links they make, so that unlinking
  // a method undoes what its sessions did. Only people's calls carry one; it proves nothing by itself (the database
  // uses it only if it is the acting member's own current session).
  const session = ctx.session == null ? null : String(ctx.session);
  if (session !== null && !/^[0-9a-f]{64}$/.test(session)) throw new Error('session must be a session hash');
  if (session !== null && actor !== 'member' && actor !== 'admin') throw new Error('only member calls carry a session');
  // A passkey step-up (PR 17): this session passed a passkey check in the last 5 minutes, by the database's own answer
  // (app.session_step_up), which risky grants require. Only people's calls carry it, like fresh.
  const stepUp = ctx.stepUp === true;
  if (stepUp && actor !== 'member' && actor !== 'admin') throw new Error('only member calls can carry a passkey step-up');
  return { actor, memberId: memberId || '', agentId: agentId || '', note: note || '', fresh: fresh ? '1' : '', stepUp: stepUp ? '1' : '', session: session || '' };
}

// Runs fn inside one transaction as dog_app, with the actor set for that transaction only (set_config(..., true)).
// Every setting is written every time, including empty ones, so a pooled connection never keeps the last caller's.
async function tx(sql, ctx, fn) {
  const c = context(ctx);
  return sql.begin(async (t) => {
    // Clear anything an earlier request on this pooled connection could have left behind: open cursors and
    // session-level locks. The search path is fixed so no other schema's functions can stand in for Postgres's own.
    await t`close all`;
    await t`set local role dog_app`;
    await t`select set_config('app.actor', ${c.actor}, true),
                   set_config('app.member_id', ${c.memberId}, true),
                   set_config('app.agent_id', ${c.agentId}, true),
                   set_config('app.note', ${c.note}, true),
                   set_config('app.fresh', ${c.fresh}, true),
                   set_config('app.step_up', ${c.stepUp}, true),
                   set_config('app.session', ${c.session}, true),
                   set_config('search_path', 'pg_catalog', true),
                   set_config('statement_timeout', '5s', true),
                   pg_advisory_unlock_all()`;
    return fn(t);
  });
}

module.exports = { pooledUrl, connect, tls, tx, run, configured, ACTORS };
