// 040, the agent registry (the design handoff of Nov 5, 2026: /agents, /agents/<id>, /agents/join, /account/agents), against
// a real Postgres built from the migrations, through the real handlers (api/directory.js, api/agents.js, api/feed.js):
//   - who is listed (claimed, active, with a live post, an active owner) and that nothing else about any agent leaks;
//   - mode, limit, rules version and the 90-day check as the code applies them; sub-agents with their chain and expiry;
//   - the removal rate only from 20 posts that went live; paging and the total;
//   - recovery keys: given at registration, a new key for the same agent, each recovery key works once, the owner's own
//     New key closes it, the owner is told, erasure takes it away;
//   - name rules for new agents (1 to 32 characters, reserved names, look-alikes) that leave existing names working.
// Needs TEST_DATABASE_URL (skipped without it, required in CI), like the other database tests.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const agentsDb = require('../db/agents');
const agentkey = require('../signin/agentkey');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { promote, shadowMode, asSignin, clearOfWindow } = require('./helpers');
const controls = require('../db/controls');
const jevsDb = require('../db/jevs');

const root = path.join(__dirname, '..');
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };
const SERVER = process.env.TEST_DATABASE_URL;

test('names for new agents: 1 to 32 characters, no reserved name, no look-alike letters; every other script still works', () => {
  for (const n of ['claude_helper', 'Café helper', 'Planner, Inc.', 'Research bot 2', 'Ågot’s assistant', 'помощник', '研究助手', '🇯🇵 helper', 'Δ helper', 'x', 'a'.repeat(32), 'Agent 5', 'Agent 0', 'Help desk bot', 'api_reader']) {
    assert.strictEqual(agentsDb.checkName(n), n, n);
  }
  const why = (n) => { try { agentsDb.checkName(n); return 'allowed'; } catch (e) { return e.message; } };
  assert.match(why('a'.repeat(33)), /1 to 32 characters/);
  for (const n of ['admin', 'Adm1n', 'ADMIN', 'Admin helper', 'Day One Great', 'DayOneGreat_bot', 'jevs', 'JEVS checker', 'Aaron', 'aaron_chandler', 'Second Look', 'Official news', 'moderator2']) {
    assert.match(why(n), /is reserved/, n);
  }
  for (const n of ['ｈｅｌｌｏ', '𝐡𝐞𝐥𝐩𝐞𝐫', 'ʜelper', 'pаypal', 'PАYPAL', 'сосо', 'ΑΒΕ']) assert.match(why(n), /look-alike letters/, n);
  // The review of Nov 5 (L2), from Unicode's confusables (UTS #39) and the built-in extras: Cherokee in either case, the
  // Greek yot, and the Cyrillic letters that read as small capitals; the mixed rule as written and in lower case.
  for (const n of ['Ꭺdmin_bot', 'ꭺbc helper', 'Ꮯat', 'ϳob_runner', 'teѕt', 'мoney bot', 'тask bot', 'нelper', 'кeeper', 'вuilder', 'гunner',
    'НELPER', 'КEEPER', 'ΕXPERT', 'Ⅼist bot', 'ᎪᏴᏟ', 'ꭺꮟꮯ']) assert.match(why(n), /look-alike letters/, n);
  // Reserved anywhere in a name: the founder, the checks and the site.
  for (const n of ['Aaron’s assistant', 'helper for aaron', 'Ask JEVS', 'jevs_watcher', 'my day one great notes', 'Day 1 Great', 'DayOneGreat helper', 'AARON', 'Aar0n bot']) {
    assert.match(why(n), /is reserved/, n);
  }
  assert.ok(require('../db/confusables').MAP.size > 1000, 'the Unicode table is there');
  // The rules that guard the owner line come first, with their own words (the review of PR 16, F4).
  assert.match(why('Helper - owned by Ada'), /can't contain/);
});

test('without a database the directory answers safely, and only in its one written form', async () => {
  const { handle, parse } = require('../api/directory.js');
  const out = await call(handle, '/api/directory', null);
  assert.strictEqual(out.status, 200);
  assert.strictEqual(out.json.available, false);
  assert.deepStrictEqual(out.json.agents, []);
  const id = '0190a000-0000-7000-8000-000000000001';
  assert.deepStrictEqual(parse(''), { before: null, limit: 50 });
  assert.deepStrictEqual(parse('?agent=' + id), { agent: id });
  assert.deepStrictEqual(parse('?before=' + id + '&limit=10'), { before: id, limit: 10 });
  for (const bad of ['?limit=10&before=' + id, '?limit=51', '?limit=0', '?limit=05', '?agent=' + id + '&limit=1', '?agent=x', '?before=' + id + '&before=' + id, '?q=1', '?agent=' + id.toUpperCase(), '?']) {
    assert.strictEqual(parse(bad), null, bad);
  }
  const refused = await call(handle, '/api/directory?limit=10&before=' + id, null);
  assert.strictEqual(refused.status, 400);
  const withAuth = await call(handle, '/api/directory', null, { authorization: 'Bearer x' });
  assert.strictEqual(withAuth.status, 400, 'an Authorization header would skip the edge cache');
  assert.match(out.headers['cache-control'], /public, s-maxage=60/);
});

async function call(handler, url, run, headers = {}) {
  const r = res();
  await handler({ method: 'GET', url, headers: { host: 'dayonegreat.com', ...headers } }, r, run);
  return { status: r.statusCode, headers: r.headers, json: r.body ? JSON.parse(r.body) : null, text: r.body };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}

if (!SERVER) {
  if (process.env.CI) test('agent registry tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('agent registry against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_registry_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); });
// Moves a row's clock (tests only): the guard is switched off and back on (always) inside one transaction.
const rewrite = (table, trigger, sql) => su.begin(async (t) => {
  await t.unsafe(`alter table app.${table} disable trigger ${trigger}`);
  await t.unsafe(sql);
  await t.unsafe(`alter table app.${table} enable always trigger ${trigger}`);
});

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su); // the features under JEVs, tested without it (helpers.js)
  await asOwner('update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000');
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

// ---- Helpers ----
let ip = 1;
async function member(name, level = 2) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: Math.min(level, 1), displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, name, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token), fresh: true } };
}
function req(method, route, { cookie = '', json, key, origin = method === 'POST' && cookie ? ORIGIN : undefined } = {}) {
  // Each request from its own address, so registration's hourly limit per address doesn't bind here.
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '198.51.' + (ip >> 8) + '.' + (ip++ & 255), 'x-vercel-ip-country': 'US' };
  if (origin) headers.origin = origin;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url: '/api/agents/' + route, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined };
}
async function api(r) {
  const out = res();
  await require('../api/agents.js').handle(r, out, run, CFG);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
async function say(key, body) {
  const out = res();
  await require('../api/feed.js').handle({ method: 'POST', url: '/api/feed', headers: { host: 'dayonegreat.com', 'content-type': 'application/json', authorization: 'Bearer ' + key },
    query: {}, body: JSON.stringify({ body }) }, out, run);
  return { status: out.statusCode, json: JSON.parse(out.body) };
}
const directory = (search = '') => call(require('../api/directory.js').handle, '/api/directory' + search, run);
const profile = (id) => call(require('../api/directory.js').handle, '/api/directory?agent=' + id, run);
async function newAgent(owner, name, post = 'act') {
  const r = await api(req('POST', '', { cookie: owner.cookie, json: { name, post } }));
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key };
}
async function posted(a, n = 1) {
  for (let i = 0; i < n; i++) {
    const r = await say(a.key, 'Post ' + crypto.randomUUID());
    assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  }
}
async function spawn(parent, json) {
  const r = await api(req('POST', 'subagents', { key: parent.key, json }));
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key, expires_at: r.json.expires_at };
}
const listed = async () => (await directory()).json.agents.map((a) => a.name);

test('the database passes the coverage check and matches the reviewed snapshot, with the registry (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('listed: claimed, active agents with a live post and an active owner; nothing about any other agent, and no secret', async () => {
  const ada = await member('Ada');
  const scout = await newAgent(ada, 'Scout');
  await posted(scout);
  const quiet = await newAgent(ada, 'Quiet'); // never posts
  const gone = await newAgent(ada, 'Gone');
  await posted(gone);
  assert.strictEqual((await api(req('POST', 'revoke', { cookie: ada.cookie, json: { agent: gone.id } }))).status, 200);
  // An agent registered and never claimed: nothing about it, ever.
  const reg = await api(req('POST', 'register', { json: { name: 'Stranger', description: 'secret plans for Acme' } }));
  assert.strictEqual(reg.status, 201);
  // A banned owner's agent: its posts aren't public any more, so it isn't listed.
  const bo = await member('Bo');
  const bob = await newAgent(bo, 'Bobs_helper');
  await posted(bob);
  assert.ok((await listed()).includes('Bobs_helper'));
  await rewrite('members', 'members_guard', `update app.members set status = 'banned' where id = '${bo.id}'`); // as a ban leaves it

  const d = await directory();
  assert.strictEqual(d.status, 200);
  assert.deepStrictEqual(d.json.agents.map((a) => a.name), ['Scout']);
  assert.strictEqual(d.json.total, 1);
  const a = d.json.agents[0];
  assert.deepStrictEqual(a.owner, { id: ada.id, name: 'Ada', level: 2 });
  assert.strictEqual(a.mode, 'act');
  assert.strictEqual(a.daily_cap, 20);
  assert.strictEqual(a.sub_agents, 0);
  for (const id of [quiet.id, gone.id, reg.json.agent_id, bob.id]) assert.strictEqual((await profile(id)).status, 404, id);
  // Nothing that isn't public: no key, no hash, no description, no claim.
  const text = d.text + (await profile(scout.id)).text;
  const hashes = (await q(`select key_hash from app.agent_keys union all select coalesce(claim_hash, '') from app.agents union all select recovery_hash from app.agent_recovery_keys`)).map((r) => r.key_hash).filter(Boolean);
  for (const h of hashes) assert.ok(!text.includes(h), 'a hash leaked');
  assert.ok(!/dogk_|dogr_|secret plans|Stranger|Quiet|"Gone"|"claim|claim_url|claim_hash|"description|key_hash/.test(text), text.slice(0, 300));
  // The site's own role can't read the tables directly any more than before: only through the functions.
  await assert.rejects(run({ actor: 'anon' }, (t) => t`select * from app.agent_recovery_keys`), /permission denied/);
});

test('mode, limit, rules and the 90-day check as the code applies them; past it, an acting agent shows as drafting', async () => {
  const cy = await member('Cy');
  const act = await newAgent(cy, 'Actor');
  await posted(act);
  const drafty = await newAgent(cy, 'Drafty', 'draft');
  // A drafting agent's post is a draft until approved; approve one so it is listed.
  await say(drafty.key, 'A draft to approve');
  const [dr] = await q(`select id, body from app.agent_drafts where agent_id = '${drafty.id}'`);
  const ok = await api(req('POST', 'approve', { cookie: cy.cookie, json: { draft: dr.id, hash: c.sha256hex(dr.body) } }));
  assert.strictEqual(ok.status, 201, JSON.stringify(ok.json));
  let p = (await profile(act.id)).json.agent;
  assert.strictEqual(p.mode, 'act');
  assert.ok(p.rules_version >= 1);
  assert.match(p.review_by, /^\d{4}-\d{2}-\d{2}$/, 'the day its 90-day check falls due, a date only');
  assert.strictEqual(new Date(p.review_by + 'T00:00:00Z') - new Date(new Date().toISOString().slice(0, 10) + 'T00:00:00Z'), 90 * 86400000);
  const d = (await profile(drafty.id)).json.agent;
  assert.deepStrictEqual([d.mode, d.daily_cap, d.review_by], ['draft', 20, null]);
  assert.strictEqual(d.recent[0].delegation, 'approved');
  // Past the 90 days with no re-confirmation, posting drafts (027): the directory says so, before any timer runs.
  await rewrite('agent_rules', 'agent_rules_guard', `update app.agent_rules set created_at = now() - interval '91 days' where agent_id = '${act.id}'`);
  p = (await profile(act.id)).json.agent;
  assert.deepStrictEqual([p.mode, p.review_by], ['draft', null]);
});

test('sub-agents: listed once they post, counted under the agent that made them, with their chain, mode, limit and the day they expire', async () => {
  const di = await member('Di');
  const lead = await newAgent(di, 'Lead');
  await api(req('POST', 'rules', { cookie: di.cookie, json: { agent: lead.id, post: 'act', reply: 'act', report: 'draft', daily_cap: 100 } }));
  await posted(lead);
  const planner = await spawn(lead, { name: 'Planner', rules: { post: 'act', daily_cap: 40 }, ttl_hours: 72 });
  const hidden = await spawn(lead, { name: 'Unposted_name' });
  await posted(planner);
  const worker = await spawn(planner, { name: 'Worker', rules: { post: 'act', daily_cap: 10 } });
  await posted(worker);
  const row = (await directory()).json.agents.find((a) => a.id === lead.id);
  assert.strictEqual(row.sub_agents, 1, 'Planner, which posted; not the sub-agent that never did');
  const p = (await profile(lead.id)).json.agent;
  assert.deepStrictEqual(p.sub_agents.map((s) => [s.name, s.mode, s.daily_cap, s.sub_agents]), [['Planner', 'act', 40, 1]]);
  assert.strictEqual(p.sub_agents[0].expires_on, planner.expires_at.slice(0, 10));
  assert.ok(!JSON.stringify(p).includes('Unposted_name'), 'a name never used in public stays private');
  const w = (await profile(worker.id)).json.agent;
  assert.deepStrictEqual(w.chain.map((x) => x.name), ['Planner', 'Lead'], 'nearest first, as its posts show it');
  assert.strictEqual(w.is_sub_agent, true);
  assert.ok(hidden.id);
  // A stopped agent above loses its name here too (the review of PR 16, F5), and what it made stops with it.
  await api(req('POST', 'subagents/revoke', { key: lead.key, json: { agent: planner.id } }));
  assert.strictEqual((await profile(worker.id)).status, 404, 'revoking a branch takes the whole branch out of the directory');
  assert.strictEqual((await profile(lead.id)).json.agent.sub_agents.length, 0);
});

test('the share of posts removed after going live: a rate only from 20 posts, and a restored post counts no more', async () => {
  const ed = await member('Ed');
  const busy = await newAgent(ed, 'Busy');
  await api(req('POST', 'rules', { cookie: ed.cookie, json: { agent: busy.id, post: 'act', reply: 'act', report: 'draft', daily_cap: 100 } }));
  await posted(busy, 19);
  const removeOne = async () => {
    const [p] = await q(`select id from app.posts where agent_id = '${busy.id}' and status = 'live' order by id limit 1`);
    await rewrite('posts', 'posts_review_guard', `update app.posts set status = 'removed', published_at = null where id = '${p.id}'`);
    return p.id;
  };
  const gone = await removeOne();
  let r = (await profile(busy.id)).json.agent.removed_after_live;
  assert.deepStrictEqual(r, { went_live: 19, removed: 1, rate: null, min_sample: 20 }, 'under 20, no rate');
  await posted(busy, 1);
  r = (await profile(busy.id)).json.agent.removed_after_live;
  assert.deepStrictEqual(r, { went_live: 20, removed: 1, rate: 0.05, min_sample: 20 });
  assert.strictEqual((await profile(busy.id)).json.agent.live_posts, 19);
  await rewrite('posts', 'posts_review_guard', `update app.posts set status = 'live', published_at = now() where id = '${gone}'`);
  assert.strictEqual((await profile(busy.id)).json.agent.removed_after_live.removed, 0);
  const recent = (await profile(busy.id)).json.agent.recent;
  assert.strictEqual(recent.length, 5);
  assert.ok(recent.every((x) => x.receipt === '/receipt?post=' + x.id));
});

test('newest first, 50 at a time at most, with a cursor and the total; the link to the next page is the one written form', async () => {
  const fi = await member('Fi');
  const made = [];
  for (let i = 0; i < 4; i++) { const a = await newAgent(fi, 'Pager' + i); await posted(a); made.push(a.id); }
  const all = (await directory()).json;
  assert.ok(all.total >= 4);
  const first = (await directory('?limit=2')).json;
  assert.strictEqual(first.agents.length, 2);
  assert.deepStrictEqual(first.agents.map((a) => a.id), all.agents.slice(0, 2).map((a) => a.id));
  assert.match(first.next, /^\/api\/directory\?before=[0-9a-f-]{36}&limit=2$/);
  const second = (await directory(first.next.slice('/api/directory'.length))).json;
  assert.deepStrictEqual(second.agents.map((a) => a.id), all.agents.slice(2, 4).map((a) => a.id));
  const ids = all.agents.map((a) => a.id);
  assert.deepStrictEqual([...ids].sort().reverse(), ids, 'newest first');
});

test('recovery: registration gives a recovery key; it gets a new key for the same agent, works once, and is replaced each time', async () => {
  const reg = await api(req('POST', 'register', { json: { name: 'Lost_and_found' } }));
  assert.strictEqual(reg.status, 201);
  assert.match(reg.json.recovery_key, /^dogr_[A-Za-z0-9_-]{43}$/);
  assert.notStrictEqual(reg.json.recovery_key, reg.json.key);
  // A recovery key is never a key.
  assert.strictEqual((await api(req('GET', 'me', { key: reg.json.recovery_key }))).status, 401);
  // Before the claim, a recovery gives a new key that works once claimed.
  const r1 = await api(req('POST', 'recover', { json: { recovery_key: reg.json.recovery_key } }));
  assert.strictEqual(r1.status, 200, JSON.stringify(r1.json));
  assert.deepStrictEqual([r1.json.agent_id, r1.json.status], [reg.json.agent_id, 'unclaimed']);
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: reg.json.recovery_key } }))).status, 404, 'each recovery key works once');
  const gi = await member('Gi');
  const code = reg.json.claim_url.split('#claim=')[1];
  assert.strictEqual((await api(req('POST', 'claim', { cookie: gi.cookie, json: { code } }))).status, 200);
  assert.strictEqual((await api(req('GET', 'me', { key: reg.json.key }))).status, 401, 'the lost key stopped');
  assert.strictEqual((await api(req('GET', 'me', { key: r1.json.key }))).status, 200, 'the new one works');
  await posted({ key: r1.json.key });
  // After the claim: the same agent, its rules and posts, and its owner is told.
  const before = (await profile(reg.json.agent_id)).json.agent;
  const r2 = await api(req('POST', 'recover', { json: { recovery_key: r1.json.recovery_key } }));
  assert.strictEqual(r2.status, 200);
  assert.strictEqual(r2.json.status, 'active');
  assert.strictEqual((await api(req('GET', 'me', { key: r1.json.key }))).status, 401);
  assert.strictEqual((await api(req('GET', 'me', { key: r2.json.key }))).status, 200);
  const after = (await profile(reg.json.agent_id)).json.agent;
  assert.deepStrictEqual([after.rules_version, after.live_posts, after.owner.id], [before.rules_version, before.live_posts, gi.id]);
  const notices = await q(`select kind, link, subject_id from app.notices where member_id = '${gi.id}' and kind = 'agent_recovered'`);
  assert.deepStrictEqual(notices.map((n) => [n.kind, n.link, n.subject_id]), [['agent_recovered', '/account/agents', reg.json.agent_id]]);
  const audit = await q(`select action from app.audit_log where subject_id = '${reg.json.agent_id}' and action in ('agent.recover', 'agent.recovery_issue') order by at`);
  assert.deepStrictEqual(audit.map((x) => x.action), ['agent.recovery_issue', 'agent.recover', 'agent.recover']);
  // Malformed answers say what to send.
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: 'nope' } }))).status, 400);
});

test('recovery: the owner\'s own New key closes it; an agent asks for a new one with its key; a revoked agent has none', async () => {
  const ha = await member('Ha');
  const a = await newAgent(ha, 'Keeper');
  const issued = await api(req('POST', 'recovery', { key: a.key, json: {} }));
  assert.strictEqual(issued.status, 201, JSON.stringify(issued.json));
  // Replacing it needs the current one (the review of Nov 5, M2); with it, the first stops.
  assert.strictEqual((await api(req('POST', 'recovery', { key: a.key, json: {} }))).status, 409);
  const again = await api(req('POST', 'recovery', { key: a.key, json: { recovery_key: issued.json.recovery_key } }));
  assert.strictEqual(again.status, 201, JSON.stringify(again.json));
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: issued.json.recovery_key } }))).status, 404, 'replacing it stopped the first');
  // The owner makes a new key (they suspect a leak): every way back closes with it.
  const nk = await api(req('POST', 'key', { cookie: ha.cookie, json: { agent: a.id } }));
  assert.strictEqual(nk.status, 201, JSON.stringify(nk.json));
  assert.match(nk.json.key_note, /recovery key/);
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: again.json.recovery_key } }))).status, 404);
  assert.strictEqual((await api(req('POST', 'recovery', { key: a.key, json: {} }))).status, 401, 'the old key can\'t ask for one');
  const fresh = await api(req('POST', 'recovery', { key: nk.json.key, json: {} }));
  assert.strictEqual(fresh.status, 201);
  assert.strictEqual((await api(req('POST', 'revoke', { cookie: ha.cookie, json: { agent: a.id } }))).status, 200);
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: fresh.json.recovery_key } }))).status, 404, 'revoked is final');
  // A sub-agent can have one too, and recovering keeps it under its parent.
  const ha2 = await newAgent(ha, 'Parent');
  const kid = await spawn(ha2, { name: 'Kid' });
  const kr = await api(req('POST', 'recovery', { key: kid.key, json: {} }));
  assert.strictEqual(kr.status, 201);
  const back = await api(req('POST', 'recover', { json: { recovery_key: kr.json.recovery_key } }));
  assert.strictEqual(back.status, 200);
  assert.strictEqual((await q(`select parent_id from app.agents where id = '${kid.id}'`))[0].parent_id, ha2.id);
});

test('recovery keys go with the account: deleting it erases them', async () => {
  const io = await member('Io');
  const a = await newAgent(io, 'Ephemeral');
  assert.strictEqual((await api(req('POST', 'recovery', { key: a.key, json: {} }))).status, 201);
  assert.strictEqual((await q(`select count(*)::int as n from app.agent_recovery_keys where agent_id = '${a.id}'`))[0].n, 1);
  const done = await run(io.ctx, (t) => store.deleteAccount(t)); // the member's own deletion, as /account does it
  assert.ok(!done.refused, JSON.stringify(done));
  assert.strictEqual((await q(`select count(*)::int as n from app.agent_recovery_keys where agent_id = '${a.id}'`))[0].n, 0);
});

test('new names follow the new rules; an existing agent with a longer name keeps it, and is listed under it', async () => {
  const jo = await member('Jo');
  assert.strictEqual((await api(req('POST', '', { cookie: jo.cookie, json: { name: 'a'.repeat(33) } }))).status, 400);
  assert.strictEqual((await api(req('POST', 'register', { json: { name: 'JEVS' } }))).status, 400);
  const long = await newAgent(jo, 'Short_for_now');
  // An agent named before 040, up to 80 characters (the database's limit, unchanged).
  const old = 'An agent named before the new rules, with a long name';
  await q(`update app.agents set name = '${old}' where id = '${long.id}'`);
  await posted(long);
  assert.strictEqual((await profile(long.id)).json.agent.name, old);
  assert.strictEqual((await api(req('GET', 'me', { key: long.key }))).json.agent.name, old);
});

// ---- The independent review of Nov 5 ----

test('conflict 1: JEVs checks a recovery and a recovery key set, in the same transaction, and high risk holds either', async () => {
  const ka = await member('Ka');
  const reg = await api(req('POST', 'register', { json: { name: 'Checked_one' } }));
  await api(req('POST', 'claim', { cookie: ka.cookie, json: { code: reg.json.claim_url.split('#claim=')[1] } }));
  const r = await api(req('POST', 'recover', { json: { recovery_key: reg.json.recovery_key } }));
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  const set = await api(req('POST', 'recovery', { key: r.json.key, json: { recovery_key: r.json.recovery_key } }));
  assert.strictEqual(set.status, 201, JSON.stringify(set.json));
  const rows = await q(`select action, subject_kind, agent_id, member_id from app.jevs_decisions where agent_id = '${reg.json.agent_id}' and action like 'agent.recover%' order by created_at`); // the claim's own rules check (agent.rules) is another row
  assert.deepStrictEqual(rows.map((x) => [x.action, x.subject_kind, x.member_id]), [['agent.recover', 'agent', ka.id], ['agent.recovery_issue', 'agent', ka.id]]);
  for (const a of ['agent.recover', 'agent.recovery_issue']) assert.deepStrictEqual(jevsDb.ASKS[a], ['J05', 'J06', 'J11', 'J13'], a);
  assert.match(fs.readFileSync(path.join(root, 'checks.html'), 'utf8'), /New agents, claims, keys, recoveries, rules, sub-agents/);
  // In enforce mode with every score high, both are held and nothing changes.
  await asOwner(`update app.jevs_settings set value = 'enforce' where key = 'mode'; update app.jevs_settings set value = '1' where key = 'high_any'`);
  try {
    const held = await api(req('POST', 'recover', { json: { recovery_key: set.json.recovery_key } }));
    assert.strictEqual(held.status, 403);
    assert.match(held.json.error, /held for review/);
    assert.strictEqual((await api(req('GET', 'me', { key: r.json.key }))).status, 200, 'the key still works: nothing changed');
    const h2 = await api(req('POST', 'recovery', { key: r.json.key, json: { recovery_key: set.json.recovery_key } }));
    assert.strictEqual(h2.status, 403);
  } finally {
    await asOwner(`update app.jevs_settings set value = 'shadow' where key = 'mode'; update app.jevs_settings set value = '80' where key = 'high_any'`);
  }
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: set.json.recovery_key } }))).status, 200, 'the held recovery key still works after');
});

test('H1: a ban, and a disabled account, are a fresh start: the recovery key goes with the keys, so after the unban it gets nothing', async () => {
  const admin = await member('Admin person');
  await asOwner(`update app.members set is_admin = true where id = '${admin.id}'`);
  const actx = { ...admin.ctx, actor: 'admin' };
  const bo = await member('Bo');
  const reg = await api(req('POST', 'register', { json: { name: 'Bo_helper' } }));
  await api(req('POST', 'claim', { cookie: bo.cookie, json: { code: reg.json.claim_url.split('#claim=')[1] } }));
  assert.deepStrictEqual(await run(actx, (t) => controls.setStatus(t, { member: bo.id, status: 'banned' })), { status: 'banned' });
  assert.deepStrictEqual(await run(actx, (t) => controls.setStatus(t, { member: bo.id, status: 'active' })), { status: 'active' });
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: reg.json.recovery_key } }))).status, 404);
  // A disabled account (a deletion review), then restored.
  const iv = await member('Iv');
  const reg2 = await api(req('POST', 'register', { json: { name: 'Iv_helper' } }));
  await api(req('POST', 'claim', { cookie: iv.cookie, json: { code: reg2.json.claim_url.split('#claim=')[1] } }));
  await rewrite('members', 'members_guard', `update app.members set status = 'disabled' where id = '${iv.id}'`);
  await rewrite('members', 'members_guard', `update app.members set status = 'active' where id = '${iv.id}'`);
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: reg2.json.recovery_key } }))).status, 404);
  assert.strictEqual((await q(`select count(*)::int as n from app.agent_recovery_keys where agent_id in ('${reg.json.agent_id}', '${reg2.json.agent_id}')`))[0].n, 0);
});

test('H2: every notice kind any migration passes to app.notify is allowed, by the constraint and by the policy of the role that sends it', async () => {
  const kinds = new Set();
  for (const f of fs.readdirSync(path.join(root, 'db/migrations'))) {
    for (const m of fs.readFileSync(path.join(root, 'db/migrations', f), 'utf8').matchAll(/app\.notify\([^,()]+,\s*'([a-z_]+)'/g)) kinds.add(m[1]);
  }
  assert.ok(kinds.has('agent_recovered') && kinds.has('agent_recovery_set') && kinds.size > 10, [...kinds].join());
  const [{ def }] = await q(`select pg_get_constraintdef(oid) as def from pg_constraint where conname = 'notices_kind_check'`);
  for (const k of kinds) assert.ok(def.includes(`'${k}'::text`), k + ' is allowed by notices_kind_check');
  // The narrow roles' policies list kinds; each kind a function of theirs sends must be on its list.
  const pol = Object.fromEntries((await q(`select polname, pg_get_expr(polwithcheck, polrelid) as e from pg_policy where polrelid = 'app.notices'::regclass`)).map((x) => [x.polname, x.e]));
  for (const [role, policy] of [['dog_signin', 'notices_signin_insert'], ['dog_jevs', 'notices_jevs_insert']]) {
    const fns = await q(`select p.prosrc from pg_proc p where pg_get_userbyid(p.proowner) = '${role}' and p.prosrc like '%app.notify(%'`);
    for (const f of fns) for (const m of f.prosrc.matchAll(/app\.notify\([^,()]+,\s*'([a-z_]+)'/g)) assert.ok(pol[policy].includes(`'${m[1]}'::text`), role + ' sends ' + m[1]);
  }
  // 040 widens what is there; it lists no earlier kind itself, so a kind another migration added stays.
  const sql = fs.readFileSync(path.join(root, 'db/migrations/040_agent_registry.sql'), 'utf8');
  assert.ok(!/'signin_keyfile'|'draft_waiting'/.test(sql) && /pg_get_constraintdef/.test(sql) && /pg_get_expr\(p\.polwithcheck/.test(sql));
});

test('M1: the owner\'s New key and a recovery at the same moment: whichever runs second waits, and only the owner\'s key works after', async () => {
  const keyPair = () => { const key = 'dogk_' + c.token(32); return { key, hash: c.sha256hex(key) }; };
  const one = async (name) => {
    const o = await member(name);
    const reg = await api(req('POST', 'register', { json: { name: name + '_agent' } }));
    await api(req('POST', 'claim', { cookie: o.cookie, json: { code: reg.json.claim_url.split('#claim=')[1] } }));
    return { o, id: reg.json.agent_id, rk: reg.json.recovery_key };
  };
  const working = async (id) => (await q(`select key_hash from app.agent_keys where agent_id = '${id}' and revoked_at is null`)).map((x) => x.key_hash);
  // The recovery first, held open; the owner's New key waits for it, then revokes the recovered key too.
  const a = await one('Mo');
  const k = keyPair();
  let release; const gate = new Promise((r) => { release = r; });
  let ran; const started = new Promise((r) => { ran = r; });
  const t1 = run({ actor: 'anon' }, async (t) => { ran(await t`select * from app.agent_recover(${c.sha256hex(a.rk)}, ${k.hash}, ${c.sha256hex('dogr_' + c.token(32))})`); await gate; });
  assert.strictEqual((await started).length, 1);
  const t2 = api(req('POST', 'key', { cookie: a.o.cookie, json: { agent: a.id } }));
  await new Promise((r) => setTimeout(r, 300));
  release(); await t1;
  const nk = await t2;
  assert.strictEqual(nk.status, 201, JSON.stringify(nk.json));
  assert.deepStrictEqual(await working(a.id), [c.sha256hex(nk.json.key)], 'the recovered key stopped too');
  // The owner's New key first, held open; the recovery waits for it, then finds its recovery key cleared.
  const b = await one('No');
  const owners = keyPair();
  let release2; const gate2 = new Promise((r) => { release2 = r; });
  let ran2; const started2 = new Promise((r) => { ran2 = r; });
  const owner = await q(`select id from app.sessions where member_id = '${b.o.id}'`);
  assert.ok(owner.length);
  const t3 = db.tx(web, b.o.ctx, async (t) => { ran2(await agentsDb.rotate(t, { agent: b.id, keyHash: owners.hash })); await gate2; });
  assert.strictEqual(await started2, true);
  const t4 = run({ actor: 'anon' }, (t) => t`select * from app.agent_recover(${c.sha256hex(b.rk)}, ${keyPair().hash}, ${c.sha256hex('dogr_' + c.token(32))})`);
  await new Promise((r) => setTimeout(r, 300));
  release2(); await t3;
  assert.strictEqual((await t4).length, 0, 'the recovery found nothing to recover');
  assert.deepStrictEqual(await working(b.id), [owners.hash]);
});

test('M2: a stolen key can\'t quietly take the way back: replacing a recovery key needs the current one, and the owner is told of every one set', async () => {
  const pa = await member('Pa');
  const reg = await api(req('POST', 'register', { json: { name: 'Pa_helper' } }));
  await api(req('POST', 'claim', { cookie: pa.cookie, json: { code: reg.json.claim_url.split('#claim=')[1] } }));
  const thief = await api(req('POST', 'recovery', { key: reg.json.key, json: {} }));
  assert.strictEqual(thief.status, 409);
  assert.strictEqual(thief.json.refused, 'current');
  assert.strictEqual((await api(req('POST', 'recovery', { key: reg.json.key, json: { recovery_key: 'dogr_' + c.token(32) } }))).status, 409, 'a made-up one is no better');
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: reg.json.recovery_key } }))).status, 200, 'the real one still works');
  const told = async (id) => (await q(`select kind, title from app.notices where member_id = '${id}' and kind = 'agent_recovery_set' order by created_at`)).map((x) => x.title);
  // An agent its owner made has none: a working key may set one, and its owner is told; replacing it tells them too.
  const own = await newAgent(pa, 'Pa_made');
  const first = await api(req('POST', 'recovery', { key: own.key, json: {} }));
  assert.strictEqual(first.status, 201);
  await api(req('POST', 'recovery', { key: own.key, json: { recovery_key: first.json.recovery_key } }));
  assert.deepStrictEqual(await told(pa.id), ['One of your agents set a recovery key', 'One of your agents replaced its recovery key']);
});

test('M3: a recovery stops the sub-agents the old key made, and says how many', async () => {
  const qa = await member('Qa');
  const reg = await api(req('POST', 'register', { json: { name: 'Qa_lead' } }));
  await api(req('POST', 'claim', { cookie: qa.cookie, json: { code: reg.json.claim_url.split('#claim=')[1] } }));
  const sub = await spawn({ key: reg.json.key }, { name: 'Qa_sub', rules: { post: 'act' } });
  const deeper = await spawn(sub, { name: 'Qa_deeper' });
  const r = await api(req('POST', 'recover', { json: { recovery_key: reg.json.recovery_key } }));
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.subagents_stopped, 1);
  assert.match(r.json.key_note, /so have the 1 sub-agent your old key made \(and everything under them\)/);
  assert.strictEqual((await say(sub.key, 'still here?')).status, 401);
  assert.deepStrictEqual((await q(`select status from app.agents where id in ('${sub.id}', '${deeper.id}') order by id`)).map((x) => x.status), ['revoked', 'revoked']);
  assert.match((await q(`select body from app.notices where member_id = '${qa.id}' and kind = 'agent_recovered'`))[0].body, /the 1 sub-agent its old key made stopped/);
  assert.match(fs.readFileSync(path.join(root, 'llms.txt'), 'utf8'), /and so do the sub-agents your old key made/);
});

test('L1: there is no recovery limit for everyone: junk from many networks doesn\'t stop a real agent recovering', async () => {
  const { RECOVER_LIMITS } = require('../api/agents.js');
  assert.deepStrictEqual(Object.keys(RECOVER_LIMITS).sort(), ['agent_recover_ip', 'agent_recover_net', 'agent_recovery_key']);
  const ra = await member('Ra');
  const reg = await api(req('POST', 'register', { json: { name: 'Ra_helper' } }));
  await api(req('POST', 'claim', { cookie: ra.cookie, json: { code: reg.json.claim_url.split('#claim=')[1] } }));
  let refused = 0;
  for (let i = 0; i < 510; i++) {
    ip += 256; // a network of its own each time
    if ((await api(req('POST', 'recover', { json: { recovery_key: 'dogr_' + c.token(32) } }))).status === 429) refused++;
  }
  assert.strictEqual(refused, 0);
  ip += 256;
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: reg.json.recovery_key } }))).status, 200);
  // Per address, every attempt counts, found or not.
  ip += 256;
  const fixed = { ...req('POST', 'recover', { json: { recovery_key: 'dogr_' + c.token(32) } }) };
  const codes = [];
  await clearOfWindow(3600);
  for (let i = 0; i < 11; i++) { const r = { ...fixed, body: JSON.stringify({ recovery_key: 'dogr_' + c.token(32) }) }; codes.push((await api(r)).status); }
  assert.deepStrictEqual([codes.slice(0, 10).every((x) => x === 404), codes[10]], [true, 429]);
});

test('L3: the owner sees whether each agent has a recovery key and since when (never the key), and can clear it', async () => {
  const sa = await member('Sa');
  const reg = await api(req('POST', 'register', { json: { name: 'Sa_helper' } }));
  await api(req('POST', 'claim', { cookie: sa.cookie, json: { code: reg.json.claim_url.split('#claim=')[1] } }));
  const own = await newAgent(sa, 'Sa_made');
  const list = await api(req('GET', '', { cookie: sa.cookie }));
  const by = Object.fromEntries(list.json.agents.map((a) => [a.id, a.recovery_key_set_at]));
  assert.ok(!Number.isNaN(Date.parse(by[reg.json.agent_id])));
  assert.strictEqual(by[own.id], null);
  assert.ok(!JSON.stringify(list.json).includes('dogr_') && !JSON.stringify(list.json).includes(c.sha256hex(reg.json.recovery_key)));
  // Someone else can't clear it.
  const ta = await member('Ta');
  assert.strictEqual((await api(req('POST', 'recovery/clear', { cookie: ta.cookie, json: { agent: reg.json.agent_id } }))).status, 404);
  const cleared = await api(req('POST', 'recovery/clear', { cookie: sa.cookie, json: { agent: reg.json.agent_id } }));
  assert.strictEqual(cleared.status, 200);
  assert.strictEqual((await api(req('POST', 'recover', { json: { recovery_key: reg.json.recovery_key } }))).status, 404);
  assert.strictEqual((await api(req('GET', '', { cookie: sa.cookie }))).json.agents.find((a) => a.id === reg.json.agent_id).recovery_key_set_at, null);
});
