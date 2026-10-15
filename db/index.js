// The only way the site talks to the database.
//   G1: production connections must go through a connection pooler; a direct address is refused.
//   S8: queries are tagged templates, so every value travels to Postgres as a parameter, never as SQL text.
//       Raw SQL (sql.unsafe) is banned outside scripts/migrate.js by a code check (.semgrep/database.yml).
//   S1/S3: every request runs in one transaction as the dog_app role, with who is acting set for that
//       transaction only, so row-level security decides what each request can see and nothing carries over
//       to the next request on a pooled connection.
'use strict';

const postgres = require('postgres');
const v = require('./validate');

// Connection poolers we accept, by host name and port. Supabase: its shared pooler (Supavisor) or its dedicated
// pooler (PgBouncer), both in transaction mode on port 6543. Neon: the "-pooler" address of an endpoint.
const POOLERS = [
  { host: /^[a-z0-9-]+\.pooler\.supabase\.com$/, ports: ['6543'] },
  { host: /^db\.[a-z0-9]+\.supabase\.co$/, ports: ['6543'] },
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

// Pooler-friendly settings: no named prepared statements (transaction poolers can't keep them), a few connections
// per function instance, and short timeouts so a slow database can't hang a request.
function connect(url, { ssl = 'require', max = 3 } = {}) {
  return postgres(url, {
    prepare: false,
    max,
    ssl,
    idle_timeout: 20,
    connect_timeout: 5,
    max_lifetime: 60 * 30,
    onnotice: () => {}
  });
}

let shared;
function fromEnv() {
  if (!shared) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not set');
    shared = connect(pooledUrl(process.env.DATABASE_URL));
  }
  return shared;
}

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
  return { actor, memberId: memberId || '', agentId: agentId || '' };
}

// Runs fn inside one transaction as dog_app, with the actor set for that transaction only (set_config(..., true)).
// Every setting is written every time, including empty ones, so a pooled connection never keeps the last caller's.
async function tx(sql, ctx, fn) {
  const c = context(ctx);
  return sql.begin(async (t) => {
    await t`set local role dog_app`;
    await t`select set_config('app.actor', ${c.actor}, true),
                   set_config('app.member_id', ${c.memberId}, true),
                   set_config('app.agent_id', ${c.agentId}, true),
                   set_config('statement_timeout', '5s', true)`;
    return fn(t);
  });
}

module.exports = { pooledUrl, connect, fromEnv, tx, ACTORS };
