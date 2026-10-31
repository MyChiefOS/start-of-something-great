// G6 load test: thousands of simulated members and agents use a private copy of the site at once, while the break-in
// read checks (S2, S3: nobody sees rows that aren't theirs) run alongside and must keep passing. It builds a throwaway database on TEST_DATABASE_URL's server,
// drives the real request handlers (no network in between), and prints the timings and the result.
// Usage: TEST_DATABASE_URL=postgres://... node test/perf/load-test.js [members] [agents] [seconds] [concurrency]
// This measures the code and the database, not the network or Vercel; the production check runs on the preview copy.
// It creates and drops a database and a login role, so it refuses any server but this machine's own unless
// LOAD_TEST_ANY_HOST=1 is set (and then it requires an encrypted connection). Never point it at the preview or production.
'use strict';

// A post JEVs challenged or held for its owner (enforce mode, 028): accepted and waiting, saying so. That is the
// system working, not an error; the load run still counts every other answer.
const challenged = (r) => r.statusCode === 202 && (/"challenge":"/.test(r.body) || /our automatic checks \(JEVs\)/.test(r.body));

const { promote } = require('../helpers');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../../db');
const c = require('../../signin/crypto');
const store = require('../../db/signin');
const { migrate } = require('../../scripts/migrate');

const SERVER = process.env.TEST_DATABASE_URL;
const [MEMBERS, AGENTS, SECONDS, CONCURRENCY] = [2000, 1000, 60, 40].map((d, i) => Number(process.argv[2 + i]) || d);
const ORIGIN = 'https://dayonegreat.com';

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function request(method, url, { cookie = '', key, json, query = {} } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '198.51.100.' + (1 + Math.floor(Math.random() * 250)) };
  if (method === 'POST') headers.origin = ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url, headers, query, body: json === undefined ? undefined : JSON.stringify(json) };
}
const pct = (xs, p) => { if (!xs.length) return 0; const s = xs.slice().sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
const pick = (xs) => xs[Math.floor(Math.random() * xs.length)];

function serverHost() {
  if (!SERVER) throw new Error('set TEST_DATABASE_URL');
  const host = new URL(SERVER).hostname;
  const local = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(host);
  if (!local && process.env.LOAD_TEST_ANY_HOST !== '1') throw new Error('the load test only runs against this machine (localhost); ' + host + ' refused');
  return { local, ssl: local ? false : 'require' };
}

async function main() {
  const { local, ssl } = serverHost();
  const NAME = 'dog_load_' + crypto.randomBytes(4).toString('hex');
  const WEB = NAME + '_web';
  const PW = crypto.randomBytes(18).toString('base64url');
  const at = (d, user, pass) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = pass; } return u.toString(); };
  const server = postgres(SERVER, { max: 1, ssl, onnotice: () => {} });
  // Leftovers from an earlier run that was killed (only on this machine's own server, where nothing else lives).
  if (local) {
    for (const { datname } of await server`select datname from pg_database where datname like 'dog\\_load\\_%'`) {
      if (/^dog_load_[0-9a-f]{8}$/.test(datname)) await server.unsafe(`drop database if exists ${datname} with (force)`);
    }
    for (const { rolname } of await server`select rolname from pg_roles where rolname like 'dog\\_load\\_%'`) {
      if (/^dog_load_[0-9a-f]{8}_web$/.test(rolname)) await server.unsafe(`drop role if exists ${rolname}`);
    }
  }
  let su, web, cleaned = false;
  // Each step runs on its own, so one failing doesn't skip the rest; also run if the process is stopped.
  const cleanup = async () => {
    if (cleaned) return;
    cleaned = true;
    for (const step of [() => web && web.end({ timeout: 5 }), () => su && su.end({ timeout: 5 }),
      () => server.unsafe(`drop database if exists ${NAME} with (force)`), () => server.unsafe(`drop role if exists ${WEB}`), () => server.end({ timeout: 5 })]) {
      try { await step(); } catch (e) { console.error('cleanup: ' + e.message); }
    }
  };
  for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { cleanup().finally(() => process.exit(130)); });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(NAME), { max: 4, ssl, onnotice: () => {} });
  try {
    await migrate(su);
    await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
    web = db.connect(at(NAME, WEB, PW), local ? { ssl: false, max: 20 } : { max: 20 });
    const run = (ctx, fn) => db.tx(web, ctx, fn);
    const feed = require('../../api/feed.js');
    const agentsApi = require('../../api/agents.js');
    const CFG = { ipKey: crypto.randomBytes(32) };

    console.log('Setting up ' + MEMBERS + ' members and ' + AGENTS + ' agents…');
    const t0 = Date.now();
    const members = [];
    const make = async (i) => {
      const token = c.token(32);
      const level = i % 3 === 0 ? 2 : 1;
      const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('m' + i + NAME)], keyVersion: 1,
        level: 1, displayName: 'Member ' + i, sessionHash: c.sha256hex(token), sessionDays: 30 }));
      if (level === 2) await promote(su, out.memberId); // phase 1 (021): level 2 is JEVs's promotion
      members[i] = { id: out.memberId, level, cookie: '__Host-dog_session=' + token };
    };
    for (let i = 0; i < MEMBERS; i += 50) await Promise.all(Array.from({ length: Math.min(50, MEMBERS - i) }, (_, k) => make(i + k)));
    const owners = members.filter((m) => m.level === 2);
    const agents = [];
    for (let i = 0; i < AGENTS; i += 25) {
      await Promise.all(Array.from({ length: Math.min(25, AGENTS - i) }, async (_, k) => {
        const owner = owners[(i + k) % owners.length];
        const r = res();
        await agentsApi.handle(request('POST', '/api/agents', { cookie: owner.cookie, json: { name: 'Agent ' + (i + k) }, query: { route: '' } }), r, run, CFG);
        const a = JSON.parse(r.body);
        // Half the agents act on their own (their owner signed in just now), half draft.
        if ((i + k) % 2 === 0) {
          const rr = res();
          await agentsApi.handle(request('POST', '/api/agents/rules', { cookie: owner.cookie, json: { agent: a.agent_id, post: 'act', reply: 'draft', report: 'draft', daily_cap: 1000 }, query: { route: 'rules' } }), rr, run, CFG);
        }
        agents.push({ id: a.agent_id, key: a.key, owner, acts: (i + k) % 2 === 0 });
      }));
    }
    console.log('Set up in ' + Math.round((Date.now() - t0) / 1000) + ' s.');

    const live = [];
    const timings = {};
    const errors = {};
    const note = (op, ms, ok, detail) => {
      (timings[op] = timings[op] || []).push(ms);
      if (!ok) { errors[op] = (errors[op] || 0) + 1; if ((errors[op] || 0) <= 3) console.log('  error in ' + op + ': ' + detail); }
    };
    const ops = [
      [40, 'read the people feed', async () => { const r = res(); await feed.handle(request('GET', '/api/feed', { query: { lane: 'people' } }), r, run); return [r.statusCode === 200, r.statusCode]; }],
      [15, 'read the agents feed', async () => { const r = res(); await feed.handle(request('GET', '/api/feed', { query: { lane: 'agents' } }), r, run); return [r.statusCode === 200, r.statusCode]; }],
      [10, 'member posts', async () => {
        const m = pick(members.filter((x) => x.level === 2));
        const r = res(); await feed.handle(request('POST', '/api/feed', { cookie: m.cookie, json: { body: 'load ' + crypto.randomUUID() } }), r, run);
        if (r.statusCode === 201) live.push(JSON.parse(r.body).id);
        // In enforce mode (028) JEVs may challenge a post from a burst of new accounts: a 202 naming the challenge is
        // the system working, not an error.
        return [r.statusCode === 201 || challenged(r), r.statusCode + ' ' + r.body.slice(0, 80)];
      }],
      [15, 'agent posts or drafts', async () => {
        const a = pick(agents);
        const r = res(); await feed.handle(request('POST', '/api/feed', { key: a.key, json: { body: 'agent load ' + crypto.randomUUID() } }), r, run);
        return [r.statusCode === (a.acts ? 201 : 202) || challenged(r), r.statusCode + ' ' + r.body.slice(0, 80)];
      }],
      [6, 'owner checks the inbox and approves', async () => {
        const a = pick(agents.filter((x) => !x.acts));
        const r = res(); await agentsApi.handle(request('GET', '/api/agents/activity', { cookie: a.owner.cookie, query: { route: 'activity' } }), r, run, CFG);
        const d = JSON.parse(r.body).inbox[0];
        if (!d) return [r.statusCode === 200, r.statusCode];
        const r2 = res();
        await agentsApi.handle(request('POST', '/api/agents/approve', { cookie: a.owner.cookie, json: { draft: d.id, hash: c.sha256hex(d.body) }, query: { route: 'approve' } }), r2, run, CFG);
        // An approved draft is checked by JEVs again, and a burst of agents from one network can be held for Aaron:
        // "Approved, and held for review" (202) is the system working, as for the other steps. CI found this twice
        // (Oct 29: 1 approval in 89), which the test had counted as an error.
        const held = r2.statusCode === 202 && /held for review/.test(r2.body);
        return [[201, 409].includes(r2.statusCode) || held, r2.statusCode + ' ' + r2.body.slice(0, 80)];
      }],
      [6, 'member reports a post', async () => {
        if (!live.length) return [true, 'none yet'];
        const m = pick(members);
        const r = res(); await feed.handle(request('POST', '/api/feed', { cookie: m.cookie, json: { report: pick(live), reason: 'spam' } }), r, run);
        return [[202, 404, 409, 429].includes(r.statusCode), r.statusCode + ' ' + r.body.slice(0, 80)];
      }],
      [5, 'someone opens a profile', async () => {
        const r = res(); await feed.handle(request('GET', '/api/feed', { query: { profile: pick(members).id } }), r, run); return [r.statusCode === 200, r.statusCode];
      }],
      [3, 'someone opens a receipt', async () => {
        const r = res(); await feed.handle(request('GET', '/api/feed', { query: { lane: 'agents', limit: '1' } }), r, run);
        const p = JSON.parse(r.body).posts[0];
        if (!p) return [true, 'none yet'];
        const r2 = res(); await feed.handle(request('GET', '/api/feed', { query: { receipt: p.id } }), r2, run); return [r2.statusCode === 200, r2.statusCode];
      }]
    ];
    const total = ops.reduce((n, o) => n + o[0], 0);
    const choose = () => { let x = Math.random() * total; for (const o of ops) { x -= o[0]; if (x < 0) return o; } return ops[0]; };

    // The break-in checks keep running during the load: someone signed out and a member see nothing that isn't theirs.
    const tables = (await su`select c.relname as name from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'app' and c.relkind = 'r'`).map((r) => r.name);
    // An outsider who takes no part in the load, so everything they can see should be only their own sign-in rows.
    const otoken = c.token(32);
    const o = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('outsider' + NAME)], keyVersion: 1,
      level: 1, displayName: 'Outsider', sessionHash: c.sha256hex(otoken), sessionDays: 30 }));
    const outsider = { id: o.memberId };
    // The sub-agent limits (PR 16) are readable by anyone signed in; they are public in the migration.
    const allowed = { members: 1, identities: 1, sessions: 1, subagent_settings: 1 };
    // Rows everyone may read: JEVs's mode (shadow or enforce) is public on purpose (PR 12); its thresholds are not.
    const PUBLIC_ROWS = { jevs_settings: 1, timer_slot: 1, invariant_slot: 1 }; // timer_slot (027) and invariant_slot (032): heartbeat rows, readable by anyone
    let breakinRuns = 0;
    const violations = [];
    const stopAt = Date.now() + SECONDS * 1000;
    const breakin = (async () => {
      while (Date.now() < stopAt) {
        for (const [label, ctx] of [['anon', { actor: 'anon' }], ['member', { actor: 'member', memberId: outsider.id, session: c.sha256hex(otoken) }]]) {
          for (const t of tables) {
            try {
              const [{ n }] = await run(ctx, (x) => x.unsafe(`select count(*)::int as n from app.${t}`));
              const may = (label === 'member' ? (allowed[t] || 0) : 0) + (PUBLIC_ROWS[t] || 0);
              if (n > may) violations.push(label + ' saw ' + n + ' rows of ' + t);
            } catch (e) { if (e.code !== '42501') violations.push(label + ' ' + t + ': ' + e.message); }
          }
        }
        breakinRuns++;
      }
    })();

    console.log('Running for ' + SECONDS + ' s with ' + CONCURRENCY + ' requests at a time…');
    const workers = Array.from({ length: CONCURRENCY }, async () => {
      while (Date.now() < stopAt) {
        const [, op, fn] = choose();
        const s = process.hrtime.bigint();
        let ok, detail;
        try { [ok, detail] = await fn(); } catch (e) { ok = false; detail = e.message; }
        note(op, Number(process.hrtime.bigint() - s) / 1e6, ok, detail);
      }
    });
    await Promise.all(workers.concat([breakin]));

    const all = Object.values(timings).flat();
    console.log('\nResults (' + MEMBERS + ' members, ' + AGENTS + ' agents, ' + SECONDS + ' s, ' + CONCURRENCY + ' at a time)');
    console.log('requests: ' + all.length + ' (' + Math.round(all.length / SECONDS) + ' a second), errors: ' + Object.values(errors).reduce((a, b) => a + b, 0));
    for (const [op, xs] of Object.entries(timings)) {
      console.log('  ' + op.padEnd(38) + String(xs.length).padStart(7) + ' requests   p50 ' + pct(xs, 0.5).toFixed(0).padStart(5) + ' ms   p95 ' +
        pct(xs, 0.95).toFixed(0).padStart(5) + ' ms   p99 ' + pct(xs, 0.99).toFixed(0).padStart(5) + ' ms   errors ' + (errors[op] || 0));
    }
    console.log('break-in checks during the load: ' + breakinRuns + ' full rounds, ' + violations.length + ' violations');
    for (const v of violations.slice(0, 10)) console.log('  ' + v);
    process.exitCode = violations.length || Object.keys(errors).length ? 1 : 0;
  } finally {
    await cleanup();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
