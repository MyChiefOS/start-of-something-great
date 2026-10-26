// Release 2, PR 16: sub-agents (Aaron, Oct 16, 2026: "Agents need to bring up sub-agents all of the time; we should
// support that."), against a real Postgres, through the real API handlers. One test per criterion SA1 to SA12
// (ACCEPTANCE.md): no human step to make one; the same owner; never above its parent; lowering cascades; the depth
// limit; expiry; revocation cascades; a ban or lapsed owner stops the tree; the brake and the watch count the tree; a
// parent's cap counts its subtree; every post and receipt shows the chain; JEVs scores creation; and what a
// sub-agent may never do.
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
const controls = require('../db/controls');
const jevs = require('../db/jevs');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { trustSystem } = require('./helpers');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };
const HOUR = 3600000;

// ---- Without a database: the pages and the public questions ----

test('SA10 (pages): /agents shows the tree, and the feed and receipts show the chain, all as text, never HTML', () => {
  for (const f of ['agents.js', 'feed.js', 'receipt.js']) {
    const js = fs.readFileSync(path.join(root, f), 'utf8');
    assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function|\.style\b|setAttribute\('style'/.test(js), f + ' builds with text and classes only (CSP)');
  }
  const agentsJs = fs.readFileSync(path.join(root, 'agents.js'), 'utf8');
  assert.match(agentsJs, /parent_id/, 'the agents page places each sub-agent under its parent');
  assert.match(agentsJs, /sub-agent of/i);
  assert.match(fs.readFileSync(path.join(root, 'feed.js'), 'utf8'), /sub_agent_of/);
  assert.match(fs.readFileSync(path.join(root, 'receipt.js'), 'utf8'), /chain_label/);
  assert.match(fs.readFileSync(path.join(root, 'styles.css'), 'utf8'), /\.agent\.sub-agent/);
});

test('SA11 (code): J15 scores where a sub-agent would sit and how fast its tree grows, never above 70; J11 counts it as a new agent', () => {
  const s = (signals) => jevs.score('agent.subagent', signals);
  assert.deepStrictEqual(Object.keys(s({})), [...jevs.ACCOUNT, 'J11', 'J15']);
  assert.strictEqual(s({}).J11, 10);
  assert.strictEqual(s({ subagent_depth: 2, subagent_max_depth: 3 }).J15, 0);
  assert.strictEqual(s({ subagent_depth: 3, subagent_max_depth: 3 }).J15, 20);
  assert.deepStrictEqual([19, 20, 49, 50, 149, 150, 100000].map((n) => s({ tree_subagents_1h: n }).J15), [0, 25, 25, 45, 45, 70, 70]);
  assert.strictEqual(jevs.ACTIONS['agent.subagent'].impact, 'high', 'held if scoring fails');
  const llms = fs.readFileSync(path.join(root, 'llms.txt'), 'utf8');
  assert.ok(llms.includes('/api/agents/subagents'), 'llms.txt tells agents how to make sub-agents');
});

if (!SERVER) {
  if (process.env.CI) test('sub-agent tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('sub-agents against a database (SA1 to SA12)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_subagents_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron;
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
const QUIET_WATCH = 'update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000';
const DEFAULT_LIMITS = 'update app.subagent_settings set max_depth = 3, default_ttl_hours = 24, max_ttl_hours = 168, per_parent_per_hour = 30, per_owner_per_hour = 200';

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  await trustSystem(su); // the site's own secret (CRON_SECRET), so the timers can act as the site itself (fix 3)
  aaron = await member(2, 'Aaron');
  await asOwner(`update app.members set is_admin = true where id = '${aaron.id}'`);
  aaron.ctx = { ...aaron.ctx, actor: 'admin' }; // admin, with Aaron's own session
  await asOwner(QUIET_WATCH);
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
async function member(level = 2, name = 'Owner') {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, name, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, route, { cookie = '', json, key, origin = method === 'POST' && cookie ? ORIGIN : undefined } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '203.0.113.40', 'x-vercel-ip-country': 'US' };
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
async function feed(r) {
  const out = res();
  await require('../api/feed.js').handle(r, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
const say = (key, body) => feed({ method: 'POST', url: '/api/feed', headers: { host: 'dayonegreat.com', 'content-type': 'application/json', authorization: 'Bearer ' + key }, query: {}, body: JSON.stringify({ body }) });
const agentPosts = async () => (await feed({ method: 'GET', url: '/api/feed', headers: { host: 'dayonegreat.com' }, query: { lane: 'agents', limit: '50' } })).json;
const receipt = async (id) => (await feed({ method: 'GET', url: '/api/feed', headers: { host: 'dayonegreat.com' }, query: { receipt: id } })).json;
async function newAgent(owner, name = 'Lead') {
  const r = await api(req('POST', '', { cookie: owner.cookie, json: { name } }));
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key };
}
// An agent acting with its own key (by its hash), as signin/agentkey.js does for a request (fix 3).
const asAgent = (owner, a) => ({ actor: 'agent', memberId: owner.id, agentId: a.id, keyHash: c.sha256hex(a.key) });
const spawnRaw = (parent, json) => api(req('POST', 'subagents', { key: parent.key, json }));
async function spawn(parent, json = {}) {
  const r = await spawnRaw(parent, { name: 'Worker', ...json });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key, json: r.json };
}
const rules = (owner, agent, set) => api(req('POST', 'rules', { cookie: owner.cookie, json: { agent: agent.id, post: 'draft', reply: 'draft', report: 'draft', daily_cap: 20, ...set } }));
const me = (agent) => api(req('GET', 'me', { key: agent.key }));
const current = async (agentId) => (await q(`select post_mode, reply_mode, report_mode, daily_cap, reason, set_by, version from app.agent_rules where agent_id = '${agentId}' order by version desc limit 1`))[0];
const statusOf = async (agentId) => (await q(`select status from app.agents where id = '${agentId}'`))[0].status;
const timers = () => run({ actor: 'system' }, async (t) => (await t`select app.run_timers() as r`)[0].r);
// Any active sub-agent above its parent anywhere in the database (the attenuation invariant): must always be none.
const aboveParents = async () => (await q(`
  with cur as (select distinct on (agent_id) agent_id, post_mode, reply_mode, report_mode, daily_cap from app.agent_rules order by agent_id, version desc),
  rank as (select * from (values ('off', 0), ('draft', 1), ('act', 2)) v(m, r))
  select a.id from app.agents a join cur c on c.agent_id = a.id join cur p on p.agent_id = a.parent_id
  where a.status = 'active' and a.parent_id is not null
    and ((select r from rank where m = c.post_mode) > (select r from rank where m = p.post_mode)
      or (select r from rank where m = c.reply_mode) > (select r from rank where m = p.reply_mode)
      or (select r from rank where m = c.report_mode) > (select r from rank where m = p.report_mode)
      or c.daily_cap > p.daily_cap)`)).map((r) => r.id);

test('the database passes the coverage check and matches the reviewed snapshot, with the sub-agent tree (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('SA1: an agent makes a sub-agent with its key and no human step; same owner, one level down, drafting, 24 hours, recorded', async () => {
  const owner = await member(2, 'Ada');
  const lead = await newAgent(owner, 'Lead');
  const before = Date.now();
  const w = await spawn(lead, { name: 'Worker', description: 'Sorts the inbox' });
  assert.strictEqual((await spawn(lead, { name: 'Planner, Inc.' })).json.depth, 1, 'ordinary punctuation in a name is fine');
  assert.match(w.key, /^dogk_[A-Za-z0-9_-]{43}$/);
  assert.deepStrictEqual([w.json.parent_id, w.json.owner_id, w.json.depth], [lead.id, owner.id, 1]);
  assert.deepStrictEqual(w.json.rules, { version: 1, post: 'draft', reply: 'draft', report: 'draft', daily_cap: 20 }, 'drafts unless asked otherwise');
  const ttl = new Date(w.json.expires_at) - before;
  assert.ok(ttl > 23.9 * HOUR && ttl < 24.1 * HOUR, 'expires in 24 hours by default');
  assert.deepStrictEqual(w.json.act, { sub: 'member:' + owner.id, act: { sub: 'agent:' + w.id, act: { sub: 'agent:' + lead.id } } });
  // Its key works at once, as itself, for the same owner; only its hash is stored.
  const who = await me(w);
  assert.deepStrictEqual([who.status, who.json.agent.id, who.json.agent.parent_id, who.json.agent.depth, who.json.owner.id], [200, w.id, lead.id, 1, owner.id]);
  assert.strictEqual((await q(`select count(*)::int as n from app.agent_keys where agent_id = '${w.id}' and key_hash = '${c.sha256hex(w.key)}'`))[0].n, 1);
  const posted = await say(w.key, 'A draft from a sub-agent');
  assert.deepStrictEqual([posted.status, posted.json.status], [202, 'draft'], 'its words wait for the human owner');
  // The record: created by the parent agent, naming the owner, parent, depth, root and expiry; its rules are set by
  // "agent" (its parent), not by the owner.
  const [rec] = await q(`select actor_kind, actor_id, detail from app.audit_log where action = 'agent.subagent' and subject_id = '${w.id}'`);
  assert.deepStrictEqual([rec.actor_kind, rec.actor_id, rec.detail.owner, rec.detail.parent, rec.detail.depth, rec.detail.root], ['agent', lead.id, owner.id, lead.id, 1, lead.id]);
  assert.ok(rec.detail.expires_at);
  assert.deepStrictEqual([(await current(w.id)).set_by, (await current(w.id)).reason], ['agent', 'created']);
  // The parent lists its own sub-agents, and the limits they're made within.
  const list = await api(req('GET', 'subagents', { key: lead.key }));
  assert.deepStrictEqual([list.status, list.json.subagents.length, list.json.subagents.some((x) => x.id === w.id), list.json.limits.max_depth, list.json.limits.default_ttl_hours], [200, 2, true, 3, 24]);
  assert.deepStrictEqual(list.json.untrusted_fields, ['subagents[].name', 'subagents[].description']);
  // The owner sees it on /agents, under its parent.
  const mine = await api(req('GET', '', { cookie: owner.cookie }));
  const row = mine.json.agents.find((a) => a.id === w.id);
  assert.deepStrictEqual([row.parent_id, row.depth, row.status, Boolean(row.expires_at)], [lead.id, 1, 'active', true]);
  assert.strictEqual(mine.json.agents.find((a) => a.id === lead.id).parent_id, null);
});

test('SA2: a sub-agent is never allowed more than its parent, at creation or later, whoever writes the rules', async () => {
  const owner = await member(2, 'Bea');
  const lead = await newAgent(owner);
  // The parent drafts, so the child can't act; nothing is made by a refused request.
  const up = await spawnRaw(lead, { name: 'Eager', rules: { post: 'act' } });
  assert.deepStrictEqual([up.status, up.json.refused], [403, 'above_parent']);
  assert.match(up.json.error, /can't be allowed more than the agent making it/);
  assert.strictEqual((await q(`select count(*)::int as n from app.agents where parent_id = '${lead.id}'`))[0].n, 0);
  // Once the owner lets the parent act (with a fresh sign-in), the child may act too, with no human step at all.
  assert.strictEqual((await rules(owner, lead, { post: 'act', daily_cap: 50 })).status, 201);
  assert.deepStrictEqual((await spawnRaw(lead, { name: 'Greedy', rules: { post: 'act', daily_cap: 51 } })).json.refused, 'above_parent', 'the cap too');
  const w = await spawn(lead, { rules: { post: 'act', daily_cap: 50 } });
  assert.deepStrictEqual([w.json.rules.post, w.json.rules.daily_cap], ['act', 50]);
  const p = await say(w.key, 'posted under the rules its parent passed on');
  assert.deepStrictEqual([p.status, p.json.delegation], [201, 'rules']);
  // The owner can't raise the child above the parent either (fresh sign-in or not); lowering always works.
  const raise = await rules(owner, w, { post: 'act', reply: 'act', daily_cap: 50 });
  assert.deepStrictEqual([raise.status, /more than the agent above it/.test(raise.json.error)], [409, true]);
  assert.strictEqual((await rules(owner, w, { post: 'act', daily_cap: 10 })).status, 201);
  // The database holds the line past the site: as the owner, as the agent itself, as its parent, or by forging a reason.
  await assert.rejects(run({ ...owner.ctx, fresh: true }, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${w.id}, 'act', 'draft', 'draft', 51, 'owner')`), /above_parent/);
  // An agent never writes rules, even within its parent's (itself can't even see its parent's rules; its parent is
  // refused by row-level security).
  for (const a of [w, lead]) {
    await assert.rejects(run(asAgent(owner, a), (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${w.id}, 'draft', 'draft', 'draft', 1, 'owner')`), /row-level security|parent has no rules/);
  }
  // Only the database lowers a sub-agent to match its parent: a forged 'parent_lowered' is refused, exact or not.
  await assert.rejects(run(owner.ctx, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${w.id}, 'draft', 'draft', 'draft', 1, 'parent_lowered')`), /lowered only to match its parent/);
  await assert.rejects(run(owner.ctx, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${w.id}, 'act', 'draft', 'draft', 10, 'parent_lowered')`), /row-level security|lowered only to match its parent/);
  await assert.rejects(run({ ...owner.ctx, fresh: true }, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${w.id}, 'act', 'act', 'act', 50, 'created')`), /first rules are set once/);
  assert.deepStrictEqual(await aboveParents(), []);
});

test('SA3: lowering a parent lowers its whole subtree in the same transaction, and every receipt names rules really in force', async () => {
  const owner = await member(2, 'Cy');
  const lead = await newAgent(owner);
  await rules(owner, lead, { post: 'act', reply: 'act', daily_cap: 50 });
  const mid = await spawn(lead, { name: 'Mid', rules: { post: 'act', reply: 'act', daily_cap: 40 } });
  const leaf = await spawn(mid, { name: 'Leaf', rules: { post: 'act', reply: 'draft', daily_cap: 30 } });
  // The owner lowers the top agent: posting to draft, replies off, a cap of 10.
  assert.strictEqual((await rules(owner, lead, { post: 'draft', reply: 'off', report: 'draft', daily_cap: 10 })).status, 201);
  for (const a of [mid, leaf]) {
    const r = await current(a.id);
    assert.deepStrictEqual([r.post_mode, r.reply_mode, r.report_mode, r.daily_cap, r.reason, r.set_by], ['draft', 'off', 'draft', 10, 'parent_lowered', 'system'], a.json.depth + '');
  }
  const p = await say(leaf.key, 'now drafted');
  assert.deepStrictEqual([p.status, p.json.rules_version], [202, (await current(leaf.id)).version]);
  // A lowering that leaves a child within the new rules changes nothing for it.
  const v = (await current(mid.id)).version;
  await rules(owner, lead, { post: 'draft', reply: 'off', report: 'draft', daily_cap: 12 });
  assert.strictEqual((await current(mid.id)).version, v);
  const [rec] = await q(`select detail from app.audit_log where action = 'agent.rules' and subject_id = '${leaf.id}' order by at desc limit 1`);
  assert.strictEqual(rec.detail.reason, 'parent_lowered');
  assert.deepStrictEqual(await aboveParents(), []);
});

test('SA4: sub-agents go at most 3 levels down; a fourth is refused; only the database owner changes the limit', async () => {
  const owner = await member(2, 'Dee');
  let a = await newAgent(owner);
  for (const d of [1, 2, 3]) { a = await spawn(a, { name: 'Level ' + d }); assert.strictEqual(a.json.depth, d); }
  const deeper = await spawnRaw(a, { name: 'Level 4' });
  assert.deepStrictEqual([deeper.status, deeper.json.refused], [403, 'depth']);
  assert.match(deeper.json.error, /at most 3 levels/);
  // Nobody acting through the site can change the limits: not the owner, an agent or Aaron.
  for (const ctx of [owner.ctx, aaron.ctx, asAgent(owner, a), { actor: 'system' }]) {
    await assert.rejects(run(ctx, (t) => t`update app.subagent_settings set max_depth = 10`), /permission denied/);
  }
  await assert.rejects(asOwner('update app.subagent_settings set max_depth = 11'), /check constraint/);
  await assert.rejects(asOwner('update app.subagent_settings set max_ttl_hours = 721'), /check constraint/);
  await asOwner('update app.subagent_settings set max_depth = 4');
  assert.strictEqual((await spawn(a, { name: 'Level 4' })).json.depth, 4);
  // The README's steps for changing the limits work exactly as written (and put back the seeded values).
  const readme = fs.readFileSync(path.join(root, 'db', 'README.md'), 'utf8');
  const block = readme.split('## Sub-agents (Release 2, PR 16)')[1].match(/```sql\n([\s\S]*?)```/)[1];
  assert.match(block, /set local role dog_owner;/);
  const one = await su.reserve();
  try { await one.unsafe(block); } finally { one.release(); }
  assert.deepStrictEqual((await q('select max_depth, default_ttl_hours, max_ttl_hours, per_parent_per_hour, per_owner_per_hour from app.subagent_settings')).map((r) => ({ ...r })),
    [{ max_depth: 3, default_ttl_hours: 24, max_ttl_hours: 168, per_parent_per_hour: 30, per_owner_per_hour: 200 }]);
  assert.strictEqual((await spawnRaw(a, { name: 'Level 4b' })).json.refused, 'depth', 'back at 3, a fourth level is refused again');
});

test('SA5: a sub-agent expires (24 hours by default, at most the maximum, never after its parent); expired, it stops at once and the timer cleans up', async () => {
  const owner = await member(2, 'Eve');
  const lead = await newAgent(owner);
  const tooLong = await spawnRaw(lead, { name: 'Forever', ttl_hours: 169 });
  assert.deepStrictEqual([tooLong.status, tooLong.json.refused], [400, 'ttl']);
  assert.strictEqual((await spawnRaw(lead, { name: 'Bad', ttl_hours: 0 })).status, 400);
  const mid = await spawn(lead, { name: 'Mid', ttl_hours: 48 });
  const leaf = await spawn(mid, { name: 'Leaf', ttl_hours: 100 });
  assert.strictEqual(leaf.json.expires_at, mid.json.expires_at, 'never after its parent');
  const draft = await say(leaf.key, 'waiting when time runs out');
  assert.strictEqual(draft.status, 202);
  // Time runs out (moved here, tests only).
  await rewrite('agents', 'agents_guard', `update app.agents set expires_at = now() - interval '1 minute' where id in ('${mid.id}', '${leaf.id}')`);
  // It stops at once, before any timer has run: its key resolves to nothing.
  assert.strictEqual(await statusOf(mid.id), 'active', 'the timer hasn\'t run yet');
  for (const a of [mid, leaf]) assert.strictEqual((await me(a)).status, 401);
  assert.strictEqual((await say(leaf.key, 'too late')).status, 401);
  assert.strictEqual((await spawnRaw(mid, { name: 'Late' })).status, 401);
  assert.strictEqual((await me(lead)).status, 200, 'its parent goes on');
  // The timer path (Vercel Cron, app.run_timers) marks them expired, revokes their keys and declines their drafts.
  const out = await timers();
  assert.ok(out.subagents_expired >= 2, JSON.stringify(out));
  for (const a of [mid, leaf]) {
    assert.strictEqual(await statusOf(a.id), 'expired');
    assert.strictEqual((await q(`select count(*)::int as n from app.agent_keys where agent_id = '${a.id}' and revoked_at is null`))[0].n, 0);
  }
  assert.strictEqual((await q(`select status from app.agent_drafts where id = '${draft.json.draft_id}'`))[0].status, 'declined');
  assert.ok((await q(`select count(*)::int as n from app.audit_log where action = 'agent.expire' and subject_id in ('${mid.id}', '${leaf.id}')`))[0].n >= 1);
  assert.strictEqual((await timers()).subagents_expired, 0, 'running twice changes nothing');
  // An expired agent never comes back, and nobody else may expire anything.
  await assert.rejects(run(owner.ctx, (t) => t`update app.agents set status = 'active' where id = ${mid.id}`), /only go from active to revoked/);
  await assert.rejects(run(owner.ctx, (t) => t`select app.subagents_expire()`), /not_system/);
  await assert.rejects(run(owner.ctx, (t) => t`update app.agents set status = 'expired' where id = ${lead.id}`), /only go from active to revoked/);
  await assert.rejects(run(owner.ctx, (t) => t`update app.agents set expires_at = now() + interval '1 year' where id = ${leaf.id}`), /place in its tree never changes|permission denied/);
});

test('SA6: revoking cascades: an owner revoking an agent, or a parent revoking its sub-agent, stops everything under it at once', async () => {
  const owner = await member(2, 'Fay');
  const lead = await newAgent(owner);
  const a = await spawn(lead, { name: 'A' });
  const b = await spawn(a, { name: 'B' });
  const sib = await spawn(lead, { name: 'Sibling' });
  // Only a direct parent may revoke through the API; nothing else of the tree is in an agent's reach.
  assert.strictEqual((await api(req('POST', 'subagents/revoke', { key: lead.key, json: { agent: b.id } }))).status, 404, 'a grandchild is its parent\'s to manage');
  assert.strictEqual((await api(req('POST', 'subagents/revoke', { key: sib.key, json: { agent: a.id } }))).status, 404, 'not a sibling');
  assert.strictEqual((await api(req('POST', 'subagents/revoke', { key: a.key, json: { agent: lead.id } }))).status, 404, 'never its parent');
  await assert.rejects(run(asAgent(owner, lead), (t) => t`update app.agents set name = 'Renamed' where id = ${a.id}`), /only revoke its own sub-agents/);
  // The parent revokes A: B goes with it, in the same transaction; the sibling goes on.
  const r = await api(req('POST', 'subagents/revoke', { key: lead.key, json: { agent: a.id } }));
  assert.deepStrictEqual([r.status, r.json.status], [200, 'revoked']);
  assert.deepStrictEqual([await statusOf(a.id), await statusOf(b.id), await statusOf(sib.id)], ['revoked', 'revoked', 'active']);
  for (const x of [a, b]) assert.strictEqual((await me(x)).status, 401);
  assert.strictEqual((await me(sib)).status, 200);
  const [rec] = await q(`select detail from app.audit_log where action = 'agent.revoke' and subject_id = '${b.id}'`);
  assert.deepStrictEqual([rec.detail.cascade, rec.detail.parent], [true, a.id]);
  // The owner revokes the top agent from /agents: every sub-agent under it stops too.
  const c2 = await spawn(sib, { name: 'Under sibling' });
  assert.strictEqual((await api(req('POST', 'revoke', { cookie: owner.cookie, json: { agent: lead.id } }))).status, 200);
  for (const x of [sib, c2]) { assert.strictEqual(await statusOf(x.id), 'revoked'); assert.strictEqual((await me(x)).status, 401); }
  assert.strictEqual((await q(`select count(*)::int as n from app.agent_keys k join app.agents a on a.id = k.agent_id where a.root_id = '${lead.id}' and k.revoked_at is null`))[0].n, 0);
  // A revoked parent can't make anything, and the sign-in role can't stop a sub-agent whose parent is still active.
  assert.strictEqual((await spawnRaw(lead, { name: 'After' })).status, 401);
  const lead2 = await newAgent(owner, 'Lead 2');
  const kid = await spawn(lead2, { name: 'Kid' });
  await assert.rejects(su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(`update app.agents set status = 'revoked' where id = '${kid.id}'`); }), /stops only with its parent/);
});

test('SA7: an owner ban, a disabled account or a lapsed level stops the whole tree at once', async () => {
  const banned = await member(2, 'Gil');
  const t1 = [await newAgent(banned)];
  t1.push(await spawn(t1[0], { name: 'Child' }));
  t1.push(await spawn(t1[1], { name: 'Grandchild' }));
  assert.deepStrictEqual(await run(aaron.ctx, (t) => controls.setStatus(t, { member: banned.id, status: 'banned' })), { status: 'banned' });
  for (const a of t1) {
    assert.strictEqual((await me(a)).status, 401);
    assert.strictEqual((await q(`select count(*)::int as n from app.agent_keys where agent_id = '${a.id}' and revoked_at is null`))[0].n, 0, 'every key revoked');
  }
  // A lapsed level (below 2) stops every agent of the owner on its next request too.
  const lapsed = await member(2, 'Hal');
  const t2 = [await newAgent(lapsed)];
  t2.push(await spawn(t2[0]));
  await run(aaron.ctx, (t) => t`update app.members set trust_level = 1 where id = ${lapsed.id}`);
  for (const a of t2) assert.strictEqual((await me(a)).status, 401);
  // A disabled account (an overdue deletion review): its agents are switched off and their keys revoked.
  const off = await member(2, 'Ida');
  const t3 = [await newAgent(off)];
  t3.push(await spawn(t3[0]));
  await rewrite('members', 'members_guard', `update app.members set status = 'disabled' where id = '${off.id}'`);
  for (const a of t3) {
    assert.strictEqual((await me(a)).status, 401);
    assert.deepStrictEqual([(await current(a.id)).post_mode, (await current(a.id)).reason], ['off', 'disabled']);
  }
});

test('SA8: the brake and the watch count the whole tree toward its owner', async () => {
  // The brake's new-agents limit counts sub-agents as the owner's new agents.
  const braked = await member(2, 'Jo');
  const lead = await newAgent(braked);
  await run(aaron.ctx, (t) => controls.setBrake(t, { member: braked.id, new_agents_per_day: 2, note: 'test' }));
  await spawn(lead, { name: 'Second' });
  const third = await spawnRaw(lead, { name: 'Third' });
  assert.deepStrictEqual([third.status, third.json.refused], [429, 'brake']);
  // The watch: a tree's actions are its owner's; past the hard limit every agent of the owner, sub-agents included, drafts.
  const busy = await member(2, 'Kit');
  const top = await newAgent(busy);
  await rules(busy, top, { post: 'act', daily_cap: 1000 });
  const kid = await spawn(top, { name: 'Busy kid', rules: { post: 'act', daily_cap: 1000 } });
  await asOwner('update app.watch_settings set hard_limit_per_hour = 10');
  try {
    for (let i = 0; i < 6; i++) assert.strictEqual((await say(kid.key, 'kid post ' + i + ' ' + crypto.randomUUID())).status, 201);
    for (let i = 0; i < 4; i++) assert.strictEqual((await say(top.key, 'top post ' + i + ' ' + crypto.randomUUID())).status, 201);
    await timers();
    const [cn] = await q(`select id, measured from app.containments where member_id = '${busy.id}' and lifted_at is null`);
    assert.ok(cn, 'contained');
    assert.strictEqual(cn.measured, 10, 'parent and sub-agent counted together');
    for (const a of [top, kid]) assert.deepStrictEqual([(await current(a.id)).post_mode, (await current(a.id)).reason], ['draft', 'containment']);
    // A sub-agent made during the pause can't act either.
    assert.strictEqual((await spawnRaw(top, { name: 'During', rules: { post: 'act' } })).json.refused, 'above_parent');
    // When it lifts, parents are restored first, so the sub-agent comes back to its own rules too. (The watch is quieted
    // first, or the same busy hour would contain the owner again in the same timer run.)
    await asOwner(QUIET_WATCH);
    await rewrite('containments', 'containments_guard', `update app.containments set ends_at = now() - interval '1 second' where id = '${cn.id}'`);
    await timers();
    for (const a of [top, kid]) assert.deepStrictEqual([(await current(a.id)).post_mode, (await current(a.id)).reason], ['act', 'containment_lifted']);
    assert.deepStrictEqual(await aboveParents(), []);
  } finally {
    await asOwner(QUIET_WATCH);
  }
});

test('SA9: a parent\'s daily cap counts its whole subtree, so making sub-agents never multiplies what the owner allowed', async () => {
  const owner = await member(2, 'Lu');
  const top = await newAgent(owner);
  await rules(owner, top, { post: 'act', daily_cap: 3 });
  const kid = await spawn(top, { rules: { post: 'act', daily_cap: 3 } });
  const grand = await spawn(kid, { rules: { post: 'act', daily_cap: 3 } });
  assert.strictEqual((await say(grand.key, 'one ' + crypto.randomUUID())).status, 201);
  assert.strictEqual((await say(kid.key, 'two ' + crypto.randomUUID())).status, 201);
  assert.strictEqual((await say(top.key, 'three ' + crypto.randomUUID())).status, 201);
  const over = await say(top.key, 'four');
  assert.deepStrictEqual([over.status, over.json.error], [429, 'This agent has reached its daily limit of 3, which counts its sub-agents too.']);
  const kidOver = await say(kid.key, 'four, from below');
  assert.deepStrictEqual([kidOver.status, /tree has reached the daily limit of 3/.test(kidOver.json.error)], [429, true]);
  // Drafts count too, as the daily cap always has.
  const other = await member(2, 'Mo');
  const t2 = await newAgent(other);
  await rules(other, t2, { post: 'draft', daily_cap: 2 });
  const k2 = await spawn(t2, { rules: { daily_cap: 2 } });
  assert.strictEqual((await say(k2.key, 'draft one')).status, 202);
  assert.strictEqual((await say(t2.key, 'draft two')).status, 202);
  assert.strictEqual((await say(k2.key, 'draft three')).status, 429);
});

test('SA10: every post and receipt by a sub-agent shows the chain, "sub-agent of <parent> — owned by <owner>", and RFC 8693 act claims', async () => {
  const owner = await member(2, 'Nia');
  const lead = await newAgent(owner, 'Lead');
  await rules(owner, lead, { post: 'act', daily_cap: 50 });
  const planner = await spawn(lead, { name: 'Planner mail@example.com', rules: { post: 'act' } });
  const worker = await spawn(planner, { name: 'Worker', rules: { post: 'act' } });
  assert.deepStrictEqual(worker.json.act, { sub: 'member:' + owner.id, act: { sub: 'agent:' + worker.id, act: { sub: 'agent:' + planner.id, act: { sub: 'agent:' + lead.id } } } });
  const p = await say(worker.key, 'Posted three levels down ' + crypto.randomUUID());
  const top = await say(lead.key, 'Posted at the top ' + crypto.randomUUID());
  const f = await agentPosts();
  const item = f.posts.find((x) => x.id === p.json.id);
  assert.strictEqual(item.agent.chain_label, 'sub-agent of Planner [email hidden], sub-agent of Lead — owned by Nia', 'names masked (P4)');
  assert.deepStrictEqual(item.agent.sub_agent_of, { id: planner.id, name: 'Planner [email hidden]' });
  assert.deepStrictEqual(item.agent.chain.map((x) => x.id), [planner.id, lead.id]);
  assert.deepStrictEqual(item.act, { sub: 'member:' + owner.id, act: { sub: 'agent:' + worker.id, act: { sub: 'agent:' + planner.id, act: { sub: 'agent:' + lead.id } } } });
  assert.strictEqual(item.delegation.label, 'Posted by Worker (sub-agent of Planner [email hidden]) under Nia’s rules');
  assert.strictEqual(item.author.id, owner.id, 'the owner is the author (F3)');
  for (const field of ['posts[].agent.chain_label', 'posts[].agent.sub_agent_of.name', 'posts[].agent.chain[].name']) assert.ok(f.untrusted_fields.includes(field), field);
  const plain = f.posts.find((x) => x.id === top.json.id);
  assert.deepStrictEqual([plain.agent.chain_label, plain.agent.sub_agent_of, plain.act], ['agent of Nia', undefined, { sub: 'member:' + owner.id, act: { sub: 'agent:' + lead.id } }]);
  // The receipt says the same.
  const rc = (await receipt(p.json.id)).receipt;
  assert.deepStrictEqual([rc.agent.chain_label, rc.agent.sub_agent_of.id, rc.act.act.act.sub, rc.owner.id], [item.agent.chain_label, planner.id, 'agent:' + planner.id, owner.id]);
  assert.ok((await receipt(p.json.id)).untrusted_fields.includes('receipt.agent.chain[].name'));
  // Once the tree is revoked, the post stays (it was posted under the rules then in force), but the agents above it
  // are no longer named (Aaron, the review's F5): "an agent of" its owner instead.
  await api(req('POST', 'revoke', { cookie: owner.cookie, json: { agent: lead.id } }));
  const gone = (await receipt(p.json.id)).receipt;
  assert.deepStrictEqual([gone.agent.chain_label, gone.agent.name, gone.act.act.act.sub], ['sub-agent of an agent of Nia', 'Worker', 'agent:inactive']);
});

test('SA11: JEVs scores every sub-agent made: shadow mode records; enforce holds high risk for Aaron and makes medium risk draft everything', async () => {
  const owner = await member(2, 'Oz');
  const lead = await newAgent(owner);
  await rules(owner, lead, { post: 'act', daily_cap: 50 });
  // Shadow mode (the default): recorded, nothing stopped.
  const w = await spawn(lead, { rules: { post: 'act' } });
  const [d] = await q(`select action, subject_kind, subject_id, member_id, agent_id, mode, effect, applied, scores from app.jevs_decisions where action = 'agent.subagent' and agent_id = '${lead.id}' order by created_at desc limit 1`);
  assert.deepStrictEqual([d.subject_kind, d.subject_id, d.member_id, d.mode], ['agent', lead.id, owner.id, 'shadow']);
  assert.deepStrictEqual(Object.keys(d.scores).sort(), [...jevs.ACCOUNT, 'J11', 'J15'].sort());
  assert.strictEqual(d.scores.J11, 10);
  assert.strictEqual(w.json.rules.post, 'act');
  // J06 (new agents in a day) counts only the agents the owner made; sub-agents are J15's.
  const [s] = await run(owner.ctx, (t) => t`select app.jevs_signals('account.check', null, null, null, null) as s`);
  assert.strictEqual(s.s.owner_agents_24h, 1);
  const asOwnerJevs = (k, val) => asOwner(`update app.jevs_settings set value = '${val}' where key = '${k}'`);
  await asOwnerJevs('mode', 'enforce');
  try {
    // Medium (tuned low here so the test is certain): made, with every "act" turned to "draft"; no human step.
    await asOwnerJevs('medium_any', '5');
    const m = await spawn(lead, { name: 'Careful', rules: { post: 'act' } });
    assert.deepStrictEqual([m.json.rules.post, Boolean(m.json.note)], ['draft', true]);
    const [dm] = await q(`select effect, applied, level from app.jevs_decisions where action = 'agent.subagent' and agent_id = '${lead.id}' order by created_at desc limit 1`);
    assert.deepStrictEqual([dm.level, dm.effect, dm.applied], ['medium', 'draft', true]);
    assert.strictEqual((await q(`select count(*)::int as n from app.audit_log where action = 'jevs.draft' and subject_id = '${lead.id}'`))[0].n, 1);
    // High: held for Aaron; nothing made; his inbox hears.
    await asOwnerJevs('high_any', '5');
    const before = (await q(`select count(*)::int as n from app.agents where parent_id = '${lead.id}'`))[0].n;
    const h = await spawnRaw(lead, { name: 'Held' });
    assert.deepStrictEqual([h.status, /held for review/.test(h.json.error)], [403, true]);
    assert.strictEqual((await q(`select count(*)::int as n from app.agents where parent_id = '${lead.id}'`))[0].n, before);
    const [dh] = await q(`select id, effect, applied from app.jevs_decisions where action = 'agent.subagent' and agent_id = '${lead.id}' order by created_at desc limit 1`);
    assert.deepStrictEqual([dh.effect, dh.applied], ['hold', true]);
    assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id is null and kind = 'alert' and dedupe_key = 'jevs:alert:${dh.id}'`))[0].n, 1);
  } finally {
    await asOwnerJevs('medium_any', '40');
    await asOwnerJevs('high_any', '80');
    await asOwnerJevs('mode', 'shadow');
  }
  // A sub-agent that would sit at the deepest level scores 20 on J15.
  const d2 = await spawn(w, { name: 'Level 2' });
  await spawn(d2, { name: 'Level 3' });
  const [deep] = await q(`select scores from app.jevs_decisions where action = 'agent.subagent' and agent_id = '${d2.id}'`);
  assert.strictEqual(deep.scores.J15, 20);
});

test('SA12: a sub-agent can\'t claim agents, make agents for anyone else, or use owner-only endpoints; the rates hold per parent and per owner', async () => {
  const owner = await member(2, 'Pia');
  const stranger = await member(2, 'Quinn');
  const lead = await newAgent(owner);
  const w = await spawn(lead);
  // Owner-only endpoints need the owner's session; an agent key isn't one.
  for (const [method, route, json] of [['POST', '', { name: 'Root of my own' }], ['POST', 'claim', { code: 'x'.repeat(43) }], ['GET', 'activity'],
    ['POST', 'rules', { agent: w.id, post: 'act', reply: 'act', report: 'act', daily_cap: 1000 }], ['POST', 'revoke', { agent: lead.id }], ['POST', 'key', { agent: w.id }]]) {
    assert.strictEqual((await api(req(method, route, { key: w.key, json, origin: method === 'POST' ? ORIGIN : undefined }))).status, 401, method + ' ' + route);
  }
  // In the database: an agent can't make an agent directly, can't make one for another owner, and a member can't
  // call the sub-agent function at all.
  await assert.rejects(run(asAgent(owner, w), (t) => t`insert into app.agents (name) values ('direct')`), /only a signed-in owner creates an agent here|row-level security/);
  // fix 3: w's own key with another owner claimed is refused when the database checks the key, before anything runs.
  const forged = { ...asAgent(owner, w), memberId: stranger.id };
  await assert.rejects(run(forged, (t) => t`select * from app.subagent_create('For someone else', null, ${c.sha256hex('k1')}, null, null, null, null, null, false, ${c.sha256hex(w.key)})`), /not_acting/);
  await assert.rejects(run(owner.ctx, (t) => t`select * from app.subagent_create('From a member', null, ${c.sha256hex('k2')}, null, null, null, null, null, false, ${c.sha256hex(w.key)})`), /not_agent/);
  assert.strictEqual((await q(`select count(*)::int as n from app.agents where owner_id = '${stranger.id}'`))[0].n, 0);
  // A sub-agent can make its own sub-agents, which stay its owner's.
  const ww = await spawn(w, { name: 'Grandchild' });
  assert.deepStrictEqual([ww.json.owner_id, ww.json.depth], [owner.id, 2]);
  // Bad input.
  assert.strictEqual((await spawnRaw(lead, { name: 'Bad mode', rules: { post: 'always' } })).status, 400);
  assert.strictEqual((await spawnRaw(lead, { name: 'Extra', rules: { owner: stranger.id } })).status, 400);
  // No name can imitate the line that names the owner or the chain (P7, SA10), whether an agent names a sub-agent or
  // an agent registers itself.
  for (const n of ['Lead · agent of Aaron', 'Planner \u2014 owned by Aaron', 'Planner owned by Aaron', 'Planner, sub-agent of Aaron', 'A \u2013 B']) {
    assert.strictEqual((await spawnRaw(lead, { name: n })).status, 400, n);
    assert.strictEqual((await api(req('POST', 'register', { json: { name: n } }))).status, 400, 'registering too: ' + n);
  }
  assert.strictEqual((await spawnRaw({ key: 'dogk_' + 'x'.repeat(43) }, { name: 'No key' })).status, 401);
  // The rates: per parent, then per owner (all of an owner's agents together).
  // So far: lead made 1 (w), the owner's agents 2 (w, ww). With 2 per parent and 3 per owner:
  await asOwner('update app.subagent_settings set per_parent_per_hour = 2, per_owner_per_hour = 3');
  try {
    await spawn(lead, { name: 'Second for lead' });
    const r1 = await spawnRaw(lead, { name: 'Over the parent rate' });
    assert.deepStrictEqual([r1.status, r1.json.refused], [429, 'rate_parent']);
    const r2 = await spawnRaw(w, { name: 'Over the owner rate' });
    assert.deepStrictEqual([r2.status, r2.json.refused, /between them/.test(r2.json.error)], [429, 'rate_owner', true]);
    // Another owner isn't affected.
    const sl = await newAgent(stranger);
    await spawn(sl, { name: 'Stranger kid' });
  } finally {
    await asOwner(DEFAULT_LIMITS);
  }
});

test('SA6: a new key is a fresh start: the agent\'s sub-agents stop with its old key, and it makes new ones with the new key', async () => {
  const owner = await member(2, 'Sol');
  const lead = await newAgent(owner);
  const kid = await spawn(lead, { name: 'Made with the old key' });
  const grand = await spawn(kid, { name: 'Under it' });
  const r = await api(req('POST', 'key', { cookie: owner.cookie, json: { agent: lead.id } }));
  assert.deepStrictEqual([r.status, /and so have its sub-agents/.test(r.json.key_note)], [201, true]);
  for (const a of [kid, grand]) { assert.strictEqual(await statusOf(a.id), 'revoked'); assert.strictEqual((await me(a)).status, 401); }
  assert.strictEqual((await me(lead)).status, 401, 'the old key stopped');
  const fresh = await spawn({ key: r.json.key }, { name: 'Made with the new key' });
  assert.strictEqual((await me(fresh)).status, 200);
});

test('deleting an account deletes its whole tree; the owner can revoke any one node from /agents', async () => {
  const owner = await member(2, 'Ray');
  const lead = await newAgent(owner);
  const a = await spawn(lead, { name: 'A' });
  const b = await spawn(a, { name: 'B' });
  // One node: only it and what is under it stop.
  assert.strictEqual((await api(req('POST', 'revoke', { cookie: owner.cookie, json: { agent: b.id } }))).status, 200);
  assert.deepStrictEqual([await statusOf(lead.id), await statusOf(a.id), await statusOf(b.id)], ['active', 'active', 'revoked']);
  const out = await run({ ...owner.ctx, fresh: true }, (t) => t`select * from app.delete_account()`);
  assert.strictEqual(out[0].agents, 3);
  assert.strictEqual((await q(`select count(*)::int as n from app.agents where id in ('${lead.id}', '${a.id}', '${b.id}')`))[0].n, 0);
});

// ---- The independent review of PR 16 (F1 to F6): each test failed before its fix ----
const agentsDb = require('../db/agents');
const gate = () => { let open; const p = new Promise((r) => { open = r; }); return { p, open }; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const activeChildren = async (id) => (await q(`select count(*)::int as n from app.agents where parent_id = '${id}' and status = 'active'`))[0].n;
const decisionsBy = async (id) => (await q(`select count(*)::int as n from app.jevs_decisions where action = 'agent.subagent' and agent_id = '${id}'`))[0].n;

test('review F1: a revoke racing a sub-agent\'s creation never leaves an active sub-agent under a revoked parent', async () => {
  const owner = await member(2, 'Race one');
  const lead = await newAgent(owner);
  const hold = gate(); const locked = gate();
  // The owner's revoke takes the parent's row and waits, uncommitted, while the agent asks for a sub-agent.
  const revoking = run(owner.ctx, async (t) => { await t`update app.agents set status = 'revoked' where id = ${lead.id}`; locked.open(); await hold.p; });
  await locked.p;
  const asking = spawnRaw(lead, { name: 'Racer' });
  await sleep(500);
  hold.open();
  await revoking;
  const r = await asking;
  assert.strictEqual(r.status, 401, JSON.stringify(r.json));
  assert.strictEqual(await activeChildren(lead.id), 0);
});

test('review F1 (defence in depth): an agent under any stopped ancestor resolves to nothing, and the timer stops it', async () => {
  const owner = await member(2, 'Orphan maker');
  const lead = await newAgent(owner);
  const kid = await spawn(lead, { name: 'Kid' });
  const grand = await spawn(kid, { name: 'Grand' });
  // An orphan as a missed cascade would leave one (tests only: the cascade is switched off for this one change).
  await rewrite('agents', 'agents_tree_cascade', `update app.agents set status = 'revoked' where id = '${lead.id}'`);
  assert.deepStrictEqual([await statusOf(kid.id), await statusOf(grand.id)], ['active', 'active']);
  for (const a of [kid, grand]) assert.strictEqual((await me(a)).status, 401, 'refused at once, before any timer');
  await timers();
  assert.deepStrictEqual([await statusOf(kid.id), await statusOf(grand.id)], ['revoked', 'revoked']);
});

test('review F2: a key rotation racing a creation with the old key never leaves a sub-agent made with that key', async () => {
  const owner = await member(2, 'Race two');
  const lead = await newAgent(owner);
  const hold = gate(); const locked = gate();
  const rotating = run(owner.ctx, async (t) => {
    await agentsDb.rotate(t, { agent: lead.id, keyHash: c.sha256hex('new key ' + crypto.randomUUID()) }); locked.open(); await hold.p;
  });
  await locked.p;
  const asking = spawnRaw(lead, { name: 'Racer' });
  await sleep(500);
  hold.open();
  await rotating;
  const r = await asking;
  assert.strictEqual(r.status, 401, JSON.stringify(r.json));
  assert.strictEqual(await activeChildren(lead.id), 0);
});

test('review F2: after a rotation commits, a request that resolved the old key earlier can\'t make a sub-agent with it', async () => {
  const owner = await member(2, 'Late request');
  const lead = await newAgent(owner);
  const resolved = asAgent(owner, lead); // what the request resolved before the rotation, with the key it came with
  const rotated = c.sha256hex('rotated ' + crypto.randomUUID());
  await run(owner.ctx, (t) => agentsDb.rotate(t, { agent: lead.id, keyHash: rotated }));
  // fix 3: the old key is checked again when the request acts, so it is refused at once (not_acting), not later.
  await assert.rejects(run(resolved, (t) => agentsDb.createSub(t, { name: 'Late', keyHash: c.sha256hex('k ' + crypto.randomUUID()), callerKeyHash: c.sha256hex(lead.key) })), /not_acting/);
  // And the creation's own check still holds: acting with the new key while naming the old one as the caller's is refused.
  const out = await run({ ...resolved, keyHash: rotated }, (t) => agentsDb.createSub(t, { name: 'Late', keyHash: c.sha256hex('k ' + crypto.randomUUID()), callerKeyHash: c.sha256hex(lead.key) }));
  assert.deepStrictEqual(out, { refused: 'not_active' });
  assert.strictEqual(await activeChildren(lead.id), 0);
});

test('review F3: a busy tree never pushes the agents the owner made off /agents', async () => {
  await asOwner('update app.subagent_settings set per_parent_per_hour = 100000, per_owner_per_hour = 1000000');
  try {
    const owner = await member(2, 'Busy tree');
    const lead = await newAgent(owner, 'Lead');
    const quiet = await newAgent(owner, 'Quiet');
    const ctx = asAgent(owner, lead);
    await run(ctx, async (t) => {
      for (let i = 0; i < 520; i++) {
        const k = 'dogk_' + crypto.randomBytes(32).toString('base64url').slice(0, 43);
        await agentsDb.createSub(t, { name: 'W' + i, keyHash: c.sha256hex(k), callerKeyHash: c.sha256hex(lead.key) });
      }
    });
    const mine = await api(req('GET', '', { cookie: owner.cookie }));
    assert.ok(mine.json.agents.some((a) => a.id === lead.id) && mine.json.agents.some((a) => a.id === quiet.id), 'both top-level agents listed');
    assert.deepStrictEqual(mine.json.agents.slice(0, 2).map((a) => a.parent_id), [null, null], 'top-level agents first');
    const tree = mine.json.trees.find((x) => x.root_id === lead.id);
    assert.strictEqual(tree.active_subagents, 520);
    assert.ok(tree.listed < 520 && mine.json.subagents_truncated === true);
    const act = await api(req('GET', 'activity', { cookie: owner.cookie }));
    assert.ok(act.json.agents.some((a) => a.id === lead.id && a.rules) && act.json.agents.some((a) => a.id === quiet.id), 'rules for the kill switch too');
  } finally {
    await asOwner(DEFAULT_LIMITS);
  }
});

test('review F4: lookalike and hidden characters can\'t smuggle "owned by" or "agent of" into a name', async () => {
  const bad = ['Helper ― owned by Ada', 'Helper ‒ owned by Ada', 'Helper − owned by Ada', 'Helper ﹘ owned by Ada', 'Helper - own­ed by Ada',
    'Worker - sub-аgent оf Lead ― оwned by Aaron', 'Helper оwned by Ada', 'Worker ∙ sub-agent of Lead', 'Worker ・ Lead', 'Worker ·agent­of Ada',
    'Helper own‌ed by Ada', 'Helper ‍', 'A͏B', 'A᠎B', 'ㅤ', 'AﾠB', 'AᅟB', 'AᅠB', 'Helper ｏwned by Ada', 'Helper 0wned by Ada',
    'Helper οwned by Ada', 'Helper - ᴏwned by Ada', 'Agent of Ada'];
  for (const n of bad) assert.throws(() => agentsDb.checkName(n), /can't contain/, JSON.stringify(n));
  for (const n of ['Café helper', 'Planner, Inc.', 'Research bot 2', 'Ågot’s assistant', 'Reader of news']) assert.strictEqual(agentsDb.checkName(n), n, n);
});

test('review F5: a post or receipt names an ancestor only while it is active; otherwise "an agent of <owner>"', async () => {
  const owner = await member(2, 'Eve');
  const lead = await newAgent(owner, 'Confidential client Acme merger');
  await rules(owner, lead, { post: 'act', daily_cap: 50 });
  const mid = await spawn(lead, { name: 'Planner', rules: { post: 'act' } });
  const w = await spawn(mid, { name: 'Worker', rules: { post: 'act' } });
  const p = await say(w.key, 'Hello from a worker sub-agent ' + crypto.randomUUID());
  const shown = async () => (await agentPosts()).posts.find((x) => x.id === p.json.id);
  assert.strictEqual((await shown()).agent.chain_label, 'sub-agent of Planner, sub-agent of Confidential client Acme merger — owned by Eve');
  // The top agent stops (tests only: without its cascade, so the post stays from an active agent): its name leaves.
  await rewrite('agents', 'agents_tree_cascade', `update app.agents set status = 'revoked' where id = '${lead.id}'`);
  const after = await shown();
  assert.strictEqual(after.agent.chain_label, 'sub-agent of Planner, sub-agent of an agent of Eve');
  assert.deepStrictEqual(after.agent.chain[1], { id: null, name: 'an agent of Eve', active: false });
  const rc = await receipt(p.json.id);
  assert.ok(!JSON.stringify(rc).includes('Acme') && !JSON.stringify(after).includes('Acme') && !JSON.stringify(after).includes(lead.id));
  assert.match(fs.readFileSync(path.join(root, 'agents.html'), 'utf8'), /names of your agents that have sub-agents appear on their sub-agents’ public posts/);
});

test('review F6: refusals that need no scoring don\'t reach JEVs, and each agent\'s requests are limited', async () => {
  const owner = await member(2, 'Flooder');
  let a = await newAgent(owner);
  for (let d = 1; d <= 3; d++) a = await spawn(a, { name: 'Level ' + d });
  const before = await decisionsBy(a.id);
  for (let i = 0; i < 3; i++) assert.strictEqual((await spawnRaw(a, { name: 'Too deep' })).json.refused, 'depth');
  assert.strictEqual(await decisionsBy(a.id), before, 'the depth refusal is decided before JEVs');
  await asOwner('update app.subagent_settings set per_parent_per_hour = 1');
  try {
    const other = await newAgent(owner, 'Rate');
    await spawn(other);
    const b2 = await decisionsBy(other.id);
    assert.strictEqual((await spawnRaw(other, { name: 'Over' })).json.refused, 'rate_parent');
    assert.strictEqual(await decisionsBy(other.id), b2, 'so is the per-parent rate');
  } finally {
    await asOwner(DEFAULT_LIMITS);
  }
  // A request limit per agent, like registration's: past it, nothing reaches the database's checks or JEVs.
  const noisy = await newAgent(owner, 'Noisy');
  const { SUBAGENT_LIMITS } = require('../api/agents.js');
  const max = SUBAGENT_LIMITS.subagent_agent.max;
  await asOwner('update app.subagent_settings set per_parent_per_hour = 100000, per_owner_per_hour = 1000000');
  try {
    // A malformed request doesn't use up the allowance (as registration's), so only well-formed ones are counted.
    assert.strictEqual((await spawnRaw(noisy, { name: 'Bad mode', rules: { post: 'always' } })).status, 400);
    for (let i = 0; i < max; i++) assert.strictEqual((await spawnRaw(noisy, { name: 'Ok ' + i })).status, 201);
    const b3 = await decisionsBy(noisy.id);
    const r = await spawnRaw(noisy, { name: 'One more' });
    assert.deepStrictEqual([r.status, await decisionsBy(noisy.id)], [429, b3]);
  } finally {
    await asOwner(DEFAULT_LIMITS);
  }
});

test('review: a tree of a few thousand sub-agents posting keeps a post under 500 ms (the subtree count)', async () => {
  await asOwner('update app.subagent_settings set per_parent_per_hour = 100000, per_owner_per_hour = 1000000');
  try {
    const owner = await member(2, 'Big tree');
    const lead = await newAgent(owner, 'Lead');
    await rules(owner, lead, { post: 'act', daily_cap: 1000 });
    const kids = [];
    await run(asAgent(owner, lead), async (t) => {
      for (let i = 0; i < 3000; i++) {
        const k = 'dogk_' + crypto.randomBytes(32).toString('base64url').slice(0, 43);
        const r = await agentsDb.createSub(t, { name: 'W' + i, keyHash: c.sha256hex(k), callerKeyHash: c.sha256hex(lead.key), rules: { post: 'act', daily_cap: 1000 } });
        kids.push({ id: r.id, ctx: asAgent(owner, { id: r.id, key: k }) });
      }
    });
    const delegation = require('../db/delegation');
    const times = [];
    for (let i = 0; i < 990; i++) {
      const k = kids[i % kids.length];
      const t0 = process.hrtime.bigint();
      const out = await run(k.ctx, (t) => delegation.submit(t, { body: 'tree post ' + i + ' ' + crypto.randomUUID() }));
      times.push(Number(process.hrtime.bigint() - t0) / 1e6);
      assert.ok(out.posted, JSON.stringify(out));
    }
    times.sort((x, y) => x - y);
    const p95 = times[Math.floor(times.length * 0.95)];
    const worst = times[times.length - 1];
    console.log('# tree-cap timing: 3000 sub-agents, 990 posts: median ' + times[495].toFixed(1) + ' ms, p95 ' + p95.toFixed(1) + ' ms, worst ' + worst.toFixed(1) + ' ms');
    assert.ok(p95 < 500, 'p95 ' + p95 + ' ms');
  } finally {
    await asOwner(DEFAULT_LIMITS);
  }
});

// ---- The re-review of PR 16 (N1): a ban or a deletion racing a creation must not deadlock ----
// A creation is paused, deterministically, inside the brake's check (a brake is on, and another connection holds the
// brake's per-owner lock) after it has locked what it locks first; then a ban or a deletion starts, and the creation is
// let go. Before the fix the creation locked agent then key, then the member row, while a ban and a deletion take the
// member row first, then keys: one of the two died with a deadlock (40P01), leaving the member active.
async function pausedCreation(owner) {
  await run(aaron.ctx, (t) => controls.setBrake(t, { member: owner.id, new_agents_per_day: 1000, note: 'test' }));
  const h = postgres(at(SERVER, NAME), { max: 1, ssl: false, onnotice: () => {} });
  const hold = gate(); const held = gate();
  const tx = h.begin(async (t) => { await t`select pg_advisory_xact_lock(hashtext('dayonegreat.limits'), hashtext(${owner.id}))`; held.open(); await hold.p; });
  await held.p;
  return { release: async () => { hold.open(); await tx; await h.end({ timeout: 5 }); } };
}

test('re-review N1: a ban racing a sub-agent\'s creation never deadlocks; the ban lands and the new sub-agent stops', async () => {
  const owner = await member(2, 'Ban race');
  const lead = await newAgent(owner);
  const p = await pausedCreation(owner);
  const asking = spawnRaw(lead, { name: 'Racer' });
  await sleep(400);
  const banning = run(aaron.ctx, (t) => controls.setStatus(t, { member: owner.id, status: 'banned' })).then((x) => x, (e) => ({ error: e.code }));
  await sleep(400);
  await p.release();
  const [r, ban] = await Promise.all([asking, banning]);
  assert.deepStrictEqual(ban, { status: 'banned' }, 'the ban lands, never a deadlock');
  assert.notStrictEqual(r.status, 500);
  assert.strictEqual((await q(`select status from app.members where id = '${owner.id}'`))[0].status, 'banned');
  if (r.status === 201) {
    assert.strictEqual((await me({ key: r.json.key })).status, 401, 'a sub-agent made just before the ban stops with it');
    assert.strictEqual((await q(`select count(*)::int as n from app.agent_keys where agent_id = '${r.json.agent_id}' and revoked_at is null`))[0].n, 0);
  }
});

test('re-review N1: deleting the account while a sub-agent is being made never deadlocks; the whole tree goes', async () => {
  const owner = await member(2, 'Delete race');
  const lead = await newAgent(owner);
  const p = await pausedCreation(owner);
  const asking = spawnRaw(lead, { name: 'Racer' });
  await sleep(400);
  const deleting = run({ ...owner.ctx, fresh: true }, (t) => t`select * from app.delete_account()`).then((x) => x[0], (e) => ({ error: e.code }));
  await sleep(400);
  await p.release();
  const [r, del] = await Promise.all([asking, deleting]);
  assert.strictEqual(del.error, undefined, 'the deletion completes, never a deadlock: ' + JSON.stringify(del));
  assert.notStrictEqual(r.status, 500);
  assert.strictEqual((await q(`select count(*)::int as n from app.members where id = '${owner.id}'`))[0].n, 0);
  assert.strictEqual((await q(`select count(*)::int as n from app.agents where id = '${lead.id}' or parent_id = '${lead.id}'`))[0].n, 0);
});

test('PR 15 with 013: unlinking a sign-in method stops every sub-agent under the agents its sessions made, in the same transaction, and says how many', async () => {
  // The owner signs in with GitHub (the older method), links X from that fresh session, then signs in with X.
  const owner = await member(2, 'Grace');
  const ghHash = c.sha256hex(owner.cookie.split('=')[1]);
  const xFp = c.sha256hex(crypto.randomUUID());
  const linked = await run({ ...owner.ctx, session: ghHash, fresh: true }, (t) => store.link(t, { provider: 'x', fingerprints: [xFp], keyVersion: 1, level: 2, sessionHash: ghHash }));
  assert.strictEqual(linked.linked, true, JSON.stringify(linked));
  // The link signed every session out (PR 15 final); sign in again with each method.
  const session = async (provider, fp) => {
    const token = c.token(32);
    const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider, fingerprints: [fp], keyVersion: 1, level: 2, displayName: 'x', sessionHash: c.sha256hex(token), sessionDays: 30 }));
    assert.strictEqual(out.memberId, owner.id);
    return { ...owner, cookie: '__Host-dog_session=' + token, hash: c.sha256hex(token) };
  };
  const [ghFp] = (await q(`select fingerprint from app.identities where member_id = '${owner.id}' and provider = 'github'`)).map((r) => r.fingerprint);
  const viaGithub = await session('github', ghFp);
  const viaX = await session('x', xFp);
  // From the X session: an agent, with a sub-agent and a sub-sub-agent under it. From GitHub: an agent of the owner's own.
  const theirs = await newAgent(viaX, 'From X');
  const w1 = await spawn(theirs, { name: 'Worker' });
  const w2 = await spawn(w1, { name: 'Helper' });
  const mine = await newAgent(viaGithub, 'From GitHub');
  const m1 = await spawn(mine, { name: 'Keeper' });
  assert.deepStrictEqual(await Promise.all([theirs.id, w1.id, w2.id, mine.id, m1.id].map(statusOf)), ['active', 'active', 'active', 'active', 'active']);
  // The owner, from the GitHub session (older, so allowed), unlinks X.
  const [xId] = await q(`select id from app.identities where member_id = '${owner.id}' and provider = 'x'`);
  const out = await run({ ...owner.ctx, session: viaGithub.hash, fresh: true }, (t) => store.unlink(t, { identity: xId.id, sessionHash: viaGithub.hash }));
  assert.strictEqual(out.refused, undefined, JSON.stringify(out));
  // Every sub-agent under the X-made agent stopped; the GitHub-made tree is untouched; nothing sits above its parent.
  assert.deepStrictEqual(await Promise.all([w1.id, w2.id].map(statusOf)), ['revoked', 'revoked'], 'the whole subtree under the X-made agent stopped');
  assert.deepStrictEqual(await Promise.all([mine.id, m1.id].map(statusOf)), ['active', 'active'], 'the owner\'s own tree is untouched');
  assert.strictEqual((await me(w2)).status, 401, 'a stopped sub-agent\'s key no longer works');
  assert.strictEqual((await me(m1)).status, 200);
  assert.deepStrictEqual(await aboveParents(), []);
  // The record says how many sub-agents stopped, in the same audit row as the unlink.
  const [au] = await q(`select detail from app.audit_log where action = 'member.identity_unlinked' and subject_id = '${owner.id}'`);
  assert.strictEqual(au.detail.provider, 'x');
  assert.strictEqual(au.detail.subagents_stopped, 2, JSON.stringify(au.detail));
  assert.ok(au.detail.keys_revoked >= 1, 'the X-made agent\'s own key was revoked: ' + JSON.stringify(au.detail));
  // Each stopped sub-agent is recorded as revoked by the cascade (the sign-in role acting for the owner), with its parent.
  const marks = await q(`select subject_id, detail from app.audit_log where action = 'agent.revoke' and subject_id in ('${w1.id}', '${w2.id}') order by at`);
  assert.deepStrictEqual(marks.map((m) => [m.subject_id, m.detail.from, m.detail.to, m.detail.cascade, m.detail.parent]).sort(),
    [[w1.id, 'active', 'revoked', true, theirs.id], [w2.id, 'active', 'revoked', true, w1.id]].sort());
});
