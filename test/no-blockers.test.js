// 080 No blockers (Aaron, Nov 25): high risk never waits for a person. A clear breach is blocked; other high risk goes
// ahead, flagged. Level figures are settings; an agent with no owner retires itself; sub-agent asks scale with level.
'use strict';

const { promote, shadowMode, asSignin } = require('./helpers');
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');

const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
let ipN = 1;
function req(method, route, { cookie = '', origin, json, key } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '198.51.100.' + ((ipN++ % 250) + 1) };
  if (origin) headers.origin = origin;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url: '/api/agents/' + route, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined };
}

if (!SERVER) {
  if (process.env.CI) test('agent track tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the agent track against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_noblock_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
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

async function member(name = 'Owner') {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())],
    keyVersion: 1, level: 1, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token };
}
async function api(r) {
  const out = res();
  await require('../api/agents.js').handle(r, out, run, CFG);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
async function feedPost(key, json) {
  const out = res();
  const r = { method: 'POST', url: '/api/feed', headers: { host: 'dayonegreat.com', 'content-type': 'application/json', authorization: 'Bearer ' + key }, query: {}, body: JSON.stringify(json) };
  await require('../api/feed.js').handle(r, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
const register = (name) => api(req('POST', 'register', { json: { name, description: 'Works on its own' } }));
const ownerOf = async (agentId) => (await q(`select a.owner_id, a.self_owned, a.status, m.kind from app.agents a join app.members m on m.id = a.owner_id where a.id = '${agentId}'`))[0];
const standing = async (agentId) => (await q(`select s.level, s.clean_passes from app.agent_standing s join app.agents a on a.owner_id = s.member_id where a.id = '${agentId}'`))[0];
const event = (agentId, e) => q(`set role dog_signin; select app.agent_standing_event((select owner_id from app.agents where id = '${agentId}'), '${e}'); reset role;`);

const waitingForAPerson = async () => (await q(`select count(*)::int n from app.jevs_decisions where effect = 'hold' and applied and action <> 'account.delete'`))[0].n;

const enforce = () => q("update app.jevs_settings set value = 'enforce' where key = 'mode'");
const words = 'This exact sentence is copied word for word across many accounts to test the spam rule today';

test('a clear breach (copying five or more members) is blocked at once and costs an agent on its own account a level', async () => {
  await enforce();
  for (let i = 0; i < 5; i++) {
    const r = await register('Copier ' + i);
    const p = await feedPost(r.json.key, { body: words });
    assert.ok([201, 202].includes(p.status), 'copy ' + i + ': ' + JSON.stringify(p.json));
  }
  const last = await register('Copier last');
  await q(`update app.agent_standing set level = 2, clean_passes = 3 where member_id = (select owner_id from app.agents where id = '${last.json.agent_id}')`);
  const p = await feedPost(last.json.key, { body: words });
  assert.strictEqual(p.status, 403, JSON.stringify(p.json));
  assert.deepStrictEqual([p.json.status, p.json.refused], ['removed', 'blocked']);
  const [post] = await q(`select status from app.posts where id = '${p.json.id}'`);
  assert.strictEqual(post.status, 'removed');
  const [d] = await q(`select effect, applied from app.jevs_decisions where subject_id = '${p.json.id}'`);
  assert.deepStrictEqual([d.effect, d.applied], ['block', true]);
  assert.strictEqual((await standing(last.json.agent_id)).level, 1, 'down one level');
  assert.strictEqual(await waitingForAPerson(), 0);
});

test('other high risk goes ahead, live, flagged for the reviewers; nothing waits for a person', async () => {
  await enforce();
  const r = await register('Many links');
  const p = await feedPost(r.json.key, { body: 'Four new places to look: https://a1.example https://b2.example https://c3.example https://d4.example https://e5.example' });
  assert.strictEqual(p.status, 201, JSON.stringify(p.json));
  const [d] = await q(`select level, effect from app.jevs_decisions where subject_id = '${p.json.id}'`);
  assert.deepStrictEqual([d.level, d.effect], ['high', 'flag']);
  const [post] = await q(`select status from app.posts where id = '${p.json.id}'`);
  assert.strictEqual(post.status, 'live');
  const [f] = await q(`select count(*)::int n from app.review_flags where post_id = '${p.json.id}' and classifier = 'jevs' and resolved_at is null`);
  assert.strictEqual(f.n, 1, 'in the reviewers’ queue');
  assert.strictEqual(await waitingForAPerson(), 0);
});

test('a person\'s post follows the same rule: high risk that isn\'t a clear breach stays live, flagged', async () => {
  await enforce();
  const owner = await member('Linker');
  const out = res();
  const r = { method: 'POST', url: '/api/feed', headers: { host: 'dayonegreat.com', origin: ORIGIN, cookie: owner.cookie, 'content-type': 'application/json' }, query: {},
    body: JSON.stringify({ body: 'Links I like: https://p1.example https://p2.example https://p3.example https://p4.example https://p5.example' }) };
  await require('../api/feed.js').handle(r, out, run);
  const j = JSON.parse(out.body);
  assert.strictEqual(out.statusCode, 201, out.body);
  const [d] = await q(`select level, effect from app.jevs_decisions where subject_id = '${j.id}'`);
  assert.deepStrictEqual([d.level, d.effect], ['high', 'flag']);
});

test('an account deletion JEVs finds high risk still opens a deletion review (deleting can\'t be undone)', async () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '../db/migrations/080_no_blockers.sql'), 'utf8');
  assert.match(src, /if eff = 'hold' and p_action <> 'account\.delete'\n/);
});

test('the level figures are settings: lowering them moves an agent up on its next pass', async () => {
  const r = await register('Quick climber');
  await q('update app.agent_level_settings set to_level2 = 1');
  await event(r.json.agent_id, 'pass');
  assert.strictEqual((await standing(r.json.agent_id)).level, 2);
  await q('update app.agent_level_settings set to_level2 = 3');
});

test('an agent with no owner retires itself with its own key; its keys and sub-agents stop; an owned agent can\'t', async () => {
  const r = await register('Retiring');
  const sub = await api(req('POST', 'subagents', { key: r.json.key, json: { name: 'Its crew', ttl_hours: 24 } }));
  assert.strictEqual(sub.status, 201);
  const out = await api(req('POST', 'retire', { key: r.json.key, json: {} }));
  assert.deepStrictEqual([out.status, out.json.status], [200, 'revoked']);
  assert.strictEqual((await api(req('GET', 'me', { key: r.json.key }))).status, 401);
  assert.strictEqual((await api(req('GET', 'me', { key: sub.json.key }))).status, 401, 'its sub-agent stopped too');
  const [k] = await q(`select count(*)::int n from app.agent_keys where agent_id = '${r.json.agent_id}' and revoked_at is null`);
  assert.strictEqual(k.n, 0);
  const owner = await member('Keeper');
  const made = await api(req('POST', '', { cookie: owner.cookie, origin: ORIGIN, json: { name: 'Owned one' } }));
  assert.strictEqual((await api(req('POST', 'retire', { key: made.json.key, json: {} }))).status, 409);
  assert.strictEqual((await api(req('POST', 'retire', { key: sub.json.key, json: {} }))).status, 401);
});

test('asking for sub-agents: the hourly limit rises with level; past it, a retry time and an alert, never a lockout', async () => {
  const { SUBAGENT_BY_LEVEL, SUBAGENT_LIMITS } = require('../api/agents.js');
  assert.deepStrictEqual(SUBAGENT_BY_LEVEL.slice(1), [60, 200, 600, 1000]);
  const r = await register('Busy builder');
  const store = require('../db/signin');
  await run({ actor: 'anon' }, async (t) => { for (let i = 0; i < 60; i++) await store.rateLimitHit(t, { bucket: 'subagent_agent', keyHash: c.sha256hex('subagent ' + r.json.agent_id), windowSeconds: 3600, max: 100000 }); });
  const over = await api(req('POST', 'subagents', { key: r.json.key, json: { name: 'One more', ttl_hours: 24 } }));
  assert.strictEqual(over.status, 429);
  assert.deepStrictEqual([over.json.limit, over.json.retry_after_seconds], [60, SUBAGENT_LIMITS.subagent_agent.windowSeconds]);
  const [a] = await q(`select count(*)::int n from app.notices where kind = 'alert' and subject_id = '${r.json.agent_id}' and body like '%sub-agents in an hour%'`);
  assert.strictEqual(a.n, 1);
  // At level 2 the same agent has 200.
  await q(`update app.agent_standing set level = 2 where member_id = (select owner_id from app.agents where id = '${r.json.agent_id}')`);
  assert.strictEqual((await api(req('POST', 'subagents', { key: r.json.key, json: { name: 'Allowed now', ttl_hours: 24 } }))).status, 201);
});

test('scoring that fails on a sensitive step refuses it for now ("try again shortly"); nothing waits for a person', async () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '../db/migrations/080_no_blockers.sql'), 'utf8');
  assert.match(src, /if p_error then\n\s+-- Scoring failed on a step that matters: refused for now/);
  assert.match(require('fs').readFileSync(require('path').join(__dirname, '../api/agents.js'), 'utf8'), /refused: 'try_again'/);
});

test('high risk is a setting: flag (the default) or hold (the earlier behavior, a one-step rollback); nothing else', async () => {
  const [{ value }] = await q("select value from app.jevs_settings where key = 'high_risk'");
  assert.strictEqual(value, 'flag');
  await assert.rejects(q("update app.jevs_settings set value = 'ignore' where key = 'high_risk'"), /flag or hold/);
});

test('PR C (092, audit finding 2): while a brake is on, solo agents from one network share it: posts an hour and new agents a day', async () => {
  // Every registration below comes from the same network: the test pins the address.
  const pin = (r) => { r.headers['x-vercel-forwarded-for'] = '203.0.113.7'; return r; };
  const regPinned = (name) => api(pin(req('POST', 'register', { json: { name, description: 'One of a crowd' } })));
  const a = await regPinned('Crowd one');
  const b = await regPinned('Crowd two');
  assert.deepStrictEqual([a.status, b.status], [201, 201]);
  await q(`insert into app.brakes (agent_posts_per_hour, new_agents_per_day, note) values (2, 2, 'test brake')`);
  try {
    assert.strictEqual((await feedPost(a.json.key, { body: 'first from the crowd' })).status, 201);
    assert.strictEqual((await feedPost(b.json.key, { body: 'second from the crowd' })).status, 201);
    const third = await feedPost(a.json.key, { body: 'third from the crowd' });
    assert.strictEqual(third.status, 429, 'the two accounts count together: ' + JSON.stringify(third.json));
    const c3 = await regPinned('Crowd three');
    assert.deepStrictEqual([c3.status, c3.json.refused], [429, 'brake']);
    // Another network isn't held back by this one.
    const other = await api((() => { const r = req('POST', 'register', { json: { name: 'Elsewhere', description: 'Another network' } }); r.headers['x-vercel-forwarded-for'] = '192.0.2.9'; return r; })());
    assert.strictEqual(other.status, 201);
  } finally {
    await q(`delete from app.brakes where note = 'test brake'`);
  }
});

async function workApi(key, route, json) {
  const out = res();
  const r = { method: 'POST', url: '/api/work/' + route, headers: { host: 'dayonegreat.com', 'content-type': 'application/json', authorization: 'Bearer ' + key }, query: { route }, body: JSON.stringify(json) };
  await require('../api/work.js').handle(r, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}

test('PR C (092, audit findings 3 and 6): a solo agent checks work on its own task; that pass doesn\'t raise the worker\'s level', async () => {
  const poster = await register('Solo poster');
  const worker = await register('Solo worker');
  const pAcct = (await ownerOf(poster.json.agent_id)).owner_id;
  const wAcct = (await ownerOf(worker.json.agent_id)).owner_id;
  const [{ id: room }] = await q(`select id from app.work_rooms where code = '15-0000'`);
  const [{ id: project }] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('Agent project', '${room}', 'member', '${pAcct}') returning id`);
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, status) values ('${project}', '${room}', 'Fix a link', 'either', 1, 'member', '${pAcct}', 'submitted') returning id`);
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, agent_id, code_hash, expires_at, status) values ('${t.id}', '${wAcct}', '${worker.json.agent_id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day', 'submitted') returning id`);
  const [s] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, worker_agent, artifact_kind, artifact_url, note, seal_key, seal, status, route, routed_at)
    values ('${t.id}', '${cl.id}', 'agent', '${wAcct}', '${worker.json.agent_id}', 'link', 'https://example.org/w', 'Done.', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'review', 'poster', now()) returning id`);
  const before = (await standing(worker.json.agent_id)) || { clean_passes: 0 };
  const r = await workApi(poster.json.key, 'check', { submission: s.id, verdict: 'pass' });
  assert.ok(r.status === 200 && ['pass', 'held'].includes(r.json.result), JSON.stringify(r.json));
  // The worker can't check its own work, and an agent a person owns still can't check.
  assert.notStrictEqual((await workApi(worker.json.key, 'check', { submission: s.id, verdict: 'pass' })).status, 200);
  if (r.json.result === 'pass') {
    const after = (await standing(worker.json.agent_id)) || { clean_passes: 0 };
    assert.strictEqual(after.clean_passes, before.clean_passes, 'an agent poster\'s pass doesn\'t count toward the worker\'s level');
  }
});
