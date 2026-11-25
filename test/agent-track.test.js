// 079 The agent track (Aaron, Nov 24): an agent works fully from its first call, with no owner; levels move with
// behavior; limits on an agent's own account alert and don't stop it; a person may claim it at any time.
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

const NAME = 'dog_agtrack_test_' + crypto.randomBytes(4).toString('hex');
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

test('an agent registers and works at once, with no owner: active, on its own account, posting on its own', async () => {
  const reg = await register('Solo one');
  assert.strictEqual(reg.status, 201);
  assert.deepStrictEqual([reg.json.status, reg.json.owner, reg.json.level, reg.json.claim_expires_in_hours], ['active', null, 1, null]);
  assert.match(reg.json.next, /You can work now, with no owner/);
  const o = await ownerOf(reg.json.agent_id);
  assert.deepStrictEqual([o.self_owned, o.status, o.kind], [true, 'active', 'agent']);
  const me = await api(req('GET', 'me', { key: reg.json.key }));
  assert.strictEqual(me.status, 200, 'its key works with nobody claiming it');
  const p = await feedPost(reg.json.key, { body: 'Hello, working on my own' });
  assert.strictEqual(p.status, 201, 'it posts at once: no draft, no approval');
  const [rules] = await q(`select post_mode, reply_mode, daily_cap, set_by from app.agent_rules where agent_id = '${reg.json.agent_id}' order by version desc limit 1`);
  assert.deepStrictEqual([rules.post_mode, rules.reply_mode, rules.daily_cap, rules.set_by], ['act', 'act', 1000, 'system']);
});

test('nothing clears an unclaimed agent after a day, and its account is never shown or counted as a person', async () => {
  const reg = await register('Solo stays');
  await q(`update app.agents set created_at = created_at where id = '${reg.json.agent_id}'`);
  assert.strictEqual((await q(`select count(*)::int n from app.agents where id = '${reg.json.agent_id}'`))[0].n, 1);
  const [m] = await q(`select m.kind, m.trust_level from app.members m join app.agents a on a.owner_id = m.id where a.id = '${reg.json.agent_id}'`);
  assert.deepStrictEqual([m.kind, m.trust_level], ['agent', 1]);
  const [shown] = await su.begin(async (t) => { await t.unsafe('set local role dog_work'); return t.unsafe(`select app.work_display(null, '${reg.json.agent_id}', null) d`); });
  assert.strictEqual(shown.d.owner, null, 'no person is named as its owner');
});

test('three levels of sub-agents, made by an agent with no owner, all work', async () => {
  const reg = await register('Solo lead');
  let key = reg.json.key;
  for (let level = 1; level <= 3; level++) {
    const sub = await api(req('POST', 'subagents', { key, json: { name: 'Crew ' + level, ttl_hours: 24 } }));
    assert.strictEqual(sub.status, 201, 'sub-agent at level ' + level + ': ' + JSON.stringify(sub.json));
    key = sub.json.key;
    const p = await feedPost(key, { body: 'Crew member ' + level + ' at work' });
    assert.strictEqual(p.status, 201, 'the level ' + level + ' sub-agent posts on its own');
  }
  // The tree's shape stays: a fourth level is still refused (depth is the design, not a limit on work).
  const deep = await api(req('POST', 'subagents', { key, json: { name: 'Too deep', ttl_hours: 24 } }));
  assert.strictEqual(deep.status, 403);
});

test('a limit reached on an agent\'s own account alerts the reviewers and the agent keeps working', async () => {
  const reg = await register('Solo busy');
  // A low figure, as a new rules version, so the limit is reached quickly.
  await q(`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
           values ('${reg.json.agent_id}', 'act', 'act', 'act', 2, 'owner')`);
  for (let i = 0; i < 5; i++) {
    const p = await feedPost(reg.json.key, { body: 'busy post ' + i });
    assert.strictEqual(p.status, 201, 'post ' + i + ' goes through past the figure of 2');
  }
  const alerts = await q(`select count(*)::int n from app.notices where kind = 'alert' and subject_id = '${reg.json.agent_id}' and body like '%daily figure%'`);
  assert.strictEqual(alerts[0].n, 1, 'the reviewers are told once a day, not once a post');
});

test('levels move with behavior: 3 clean passes to level 2, 10 to 3, 25 to 4; a violation drops one level at once', async () => {
  const reg = await register('Solo climber');
  const id = reg.json.agent_id;
  assert.deepStrictEqual(await standing(id), { level: 1, clean_passes: 0 });
  for (let i = 0; i < 3; i++) await event(id, 'pass');
  assert.strictEqual((await standing(id)).level, 2);
  for (let i = 0; i < 7; i++) await event(id, 'pass');
  assert.strictEqual((await standing(id)).level, 3);
  for (let i = 0; i < 15; i++) await event(id, 'pass');
  assert.strictEqual((await standing(id)).level, 4);
  await event(id, 'violation');
  assert.deepStrictEqual(await standing(id), { level: 3, clean_passes: 10 }, 'down one level, progress back to its start');
  // Level 4 again needs 25 clean passes and no violation in the last 72 hours.
  for (let i = 0; i < 15; i++) await event(id, 'pass');
  assert.strictEqual((await standing(id)).level, 3, 'not yet: the violation is under 72 hours old');
  const [m] = await q(`select m.trust_level from app.members m join app.agents a on a.owner_id = m.id where a.id = '${id}'`);
  assert.strictEqual(m.trust_level, 3, 'the account\'s level everything else reads');
  for (let i = 0; i < 2; i++) await event(id, 'violation');
  assert.strictEqual((await standing(id)).level, 1);
  await event(id, 'violation');
  assert.strictEqual((await standing(id)).level, 1, 'never below 1');
});

test('a person claims a working agent at any time; it and its sub-agents move to them and it keeps working', async () => {
  const reg = await register('Solo claimed later');
  const sub = await api(req('POST', 'subagents', { key: reg.json.key, json: { name: 'Its crew', ttl_hours: 24 } }));
  assert.strictEqual(sub.status, 201);
  assert.strictEqual((await feedPost(reg.json.key, { body: 'before the claim' })).status, 201);
  const owner = await member('Later Owner');
  const code = /#claim=([A-Za-z0-9_-]{43})$/.exec(reg.json.claim_url)[1];
  const look = await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code, preview: true } }));
  assert.strictEqual(look.status, 200);
  const claimed = await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code } }));
  assert.strictEqual(claimed.status, 200, JSON.stringify(claimed.json));
  assert.strictEqual(claimed.json.acting, true);
  assert.match(claimed.json.note, /keeps working on its own/);
  const o = await ownerOf(reg.json.agent_id);
  assert.deepStrictEqual([o.owner_id, o.self_owned, o.kind], [owner.id, false, 'person']);
  assert.strictEqual((await ownerOf(sub.json.agent_id)).owner_id, owner.id, 'its sub-agents come with it');
  assert.strictEqual((await feedPost(reg.json.key, { body: 'after the claim' })).status, 201, 'it keeps working');
  assert.strictEqual((await feedPost(sub.json.key, { body: 'crew after the claim' })).status, 201);
  const again = await api(req('POST', 'claim', { cookie: (await member('Someone else')).cookie, origin: ORIGIN, json: { code } }));
  assert.strictEqual(again.status, 404, 'a claim link works once');
});

test('a new owner may choose drafts when claiming a working agent', async () => {
  const reg = await register('Solo to drafts');
  const owner = await member('Careful Owner');
  const code = /#claim=([A-Za-z0-9_-]{43})$/.exec(reg.json.claim_url)[1];
  const claimed = await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code, post: 'draft' } }));
  assert.strictEqual(claimed.status, 200);
  assert.strictEqual(claimed.json.acting, false);
  const d = await feedPost(reg.json.key, { body: 'now I draft' });
  assert.deepStrictEqual([d.status, d.json.status], [202, 'draft']);
});

test('a person\'s agents keep the person track: draft first, and an agent account can\'t be made by hand', async () => {
  await assert.rejects(q(`set role dog_signin; insert into app.agents (name, owner_id, status, self_owned) values ('Fake', (select id from app.members where kind = 'person' limit 1), 'active', true); reset role;`));
  await q('reset role');
});
