// 072: owner approval for agents' work. Helpers as in test/zero-pay.test.js. ACCEPTANCE.md OW1 to OW6.
// (From 067, the zero-payment launch (Aaron, Nov 21, 2026), against a real Postgres built from the migrations, through the
// real handler (api/work.js) and the timer's jobs: people and their agents agree to tasks, do them, have them verified,
// dispute and appeal them, and the result is reputation with no money anywhere. ACCEPTANCE.md ZP1 to ZP8.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');

const { promote, shadowMode, asSignin } = require('./helpers');
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };
const SERVER = process.env.TEST_DATABASE_URL;
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
let ip = 1;
async function call(handler, method, route, { cookie = '', json, key, search = '', host = 'dayonegreat.com', origin, headersExtra = {} } = {}, runner) {
  const headers = { host, cookie, 'x-vercel-forwarded-for': '198.51.' + (ip >> 8) + '.' + (ip++ & 255), 'x-vercel-ip-country': 'US', ...headersExtra };
  if (method === 'GET') headers['sec-fetch-site'] = 'same-origin'; // as a browser on the site's own pages sends it (RK145)
  if (method === 'POST' && cookie) headers.origin = origin || ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  const r = res();
  await handler({ method, url: '/api/work/' + route + search, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined }, r, runner);
  return { status: r.statusCode, headers: r.headers, json: r.body ? JSON.parse(r.body) : null, text: r.body };
}

if (!SERVER) {
  if (process.env.CI) test('work tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('work against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_072_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); });

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await asOwner('update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000');
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  await member('Aaron', { admin: true }); // the site's administrator exists, as in production
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(name, { admin = false, level = 2 } = {}) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  if (admin) await asOwner(`update app.members set is_admin = true where id = '${out.memberId}'`);
  return { id: out.memberId, name, cookie: '__Host-dog_session=' + token };
}
const work = (method, route, opts = {}) => call(require('../api/work.js').handle, method, route, opts, run);
async function project(owner, title = 'Make the onboarding clearer', room = '27-0000', opts = {}) {
  const r = await work('POST', 'projects', { ...opts, cookie: owner.cookie, json: { title, description: 'Context for ' + title, room } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return r.json.id;
}
async function task(owner, pj, over = {}, opts = {}) {
  const r = await work('POST', 'tasks', { ...opts, cookie: owner.cookie, json: { project: pj, title: 'Write the welcome copy', description: 'Three short paragraphs.', class: 'either', size: 3, ...over } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return r.json.id;
}


async function agents(method, route, { cookie = '', json, key } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '198.51.' + (ip >> 8) + '.' + (ip++ & 255), 'x-vercel-ip-country': 'US' };
  if (method === 'POST' && cookie) headers.origin = ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  const r = res();
  await require('../api/agents.js').handle({ method, url: '/api/agents/' + route, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined }, r, run, CFG);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
async function newAgent(owner, name, post = 'act') {
  const r = await agents('POST', '', { cookie: owner.cookie, json: { name, post } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key };
}

const W = (who, route, json, extra = {}) => work('POST', route, { ...(who.key ? { key: who.key } : { cookie: who.cookie }), json, headersExtra: extra });
const list = async (owner) => (await work('GET', 'requests', { cookie: owner.cookie })).json.requests;
const decide = (owner, q, decision, hash = q.hash) => work('POST', 'requests/decide', { cookie: owner.cookie, json: { request: q.id, decision, hash } });

test('OW1: a draft agent\u2019s claim becomes a request; the owner approves it; the agent sends it again with Owner-Approval and it goes through, once', async () => {
  const poster = await member('Opa'); const own = await member('Oown');
  const ag = await newAgent(own, 'Odraft', 'draft');
  const t1 = await task(poster, await project(poster, 'Approval trial'), { size: 2 });
  const a = await W(ag, 'claim', { task: t1 });
  assert.strictEqual(a.status, 202, JSON.stringify(a.json));
  assert.strictEqual(a.json.status, 'waiting_for_owner');
  const [q] = await list(own);
  assert.deepStrictEqual([q.id, q.route, q.status], [a.json.request, 'claim', 'waiting']);
  assert.strictEqual((await decide(own, q, 'approve')).json.result, 'approve');
  const b = await W(ag, 'claim', { task: t1 }, { 'owner-approval': a.json.request });
  assert.strictEqual(b.status, 201, JSON.stringify(b.json));
  assert.ok(b.json.code, 'the agent gets its own claim code');
  const again = await W(ag, 'release', { task: t1 });
  assert.ok(again.status < 400, 'a draft agent still releases its own claim');
  const reuse = await W(ag, 'claim', { task: t1 }, { 'owner-approval': a.json.request });
  assert.strictEqual(reuse.status, 403, 'an approval is used once');
});

test('OW2: an approval only fits its exact request; a declined request can\u2019t be used; a stale hash is refused', async () => {
  const poster = await member('Opb'); const own = await member('Oown2');
  const ag = await newAgent(own, 'Odraft2', 'draft');
  const pj = await project(poster, 'Fit trial');
  const t1 = await task(poster, pj, { size: 2 }); const t2 = await task(poster, pj, { size: 2 });
  const a = await W(ag, 'claim', { task: t1 });
  const [q] = await list(own);
  assert.strictEqual((await decide(own, q, 'approve', 'f'.repeat(64))).status, 409, 'not the hash the owner saw');
  await decide(own, q, 'approve');
  assert.strictEqual((await W(ag, 'claim', { task: t2 }, { 'owner-approval': a.json.request })).status, 403, 'another task');
  const b = await W(ag, 'claim', { task: t2 });
  const q2 = (await list(own)).find((x) => x.id === b.json.request);
  await decide(own, q2, 'decline');
  assert.strictEqual((await W(ag, 'claim', { task: t2 }, { 'owner-approval': b.json.request })).status, 403, 'declined');
});

test('OW3: an agent proposes a check; on approval it is done as its owner, the task\u2019s poster', async () => {
  const own = await member('Oown3'); const wk = await member('Owork3');
  const ag = await newAgent(own, 'Ochecker', 'act');
  const t1 = await task(own, await project(own, 'Check trial'), { class: 'person' });
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at, status) values ('${t1}', '${wk.id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day', 'submitted') returning id`);
  const [{ id: sid }] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, route, routed_at)
    values ('${t1}', '${cl.id}', 'member', '${wk.id}', 'link', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'review', 'poster', now()) returning id`);
  await q(`update app.work_tasks set status = 'submitted' where id = '${t1}'`);
  const a = await W(ag, 'check', { submission: sid, verdict: 'pass' });
  assert.strictEqual(a.status, 202, JSON.stringify(a.json));
  const [r] = await list(own);
  const d = await decide(own, r, 'approve');
  assert.strictEqual(d.status, 200, JSON.stringify(d.json));
  assert.ok(d.json.done, 'carried out as the owner: ' + JSON.stringify(d.json));
  assert.strictEqual((await q(`select decided_by from app.work_submissions where id = '${sid}'`))[0].decided_by, 'poster');
});

test('OW4: an agent proposes a dispute; on approval it is opened by its owner, a person', async () => {
  const own = await member('Oown4'); const ag = await newAgent(own, 'Odisputer', 'act');
  const poster = await member('Opd'); const wk = await member('Owd');
  const t1 = await task(poster, await project(poster, 'Dispute trial'));
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at, status) values ('${t1}', '${wk.id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day', 'submitted') returning id`);
  const [s] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, decided_by, decided_at)
    values ('${t1}', '${cl.id}', 'member', '${wk.id}', 'link', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'passed', 'jevs', now()) returning id`);
  await q(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, size, confidence, independence, points, final_at)
    select '${s.id}', '${t1}', t.room_id, 'member', '${wk.id}', 1, 100, 100, 10, now() + interval '72 hours' from app.work_tasks t where t.id = '${t1}'`);
  const a = await W(ag, 'dispute', { submission: s.id, reason: 'The page is empty' });
  assert.strictEqual(a.status, 202, JSON.stringify(a.json));
  const [r] = await list(own);
  const d = await decide(own, r, 'approve');
  assert.ok(d.json.done, JSON.stringify(d.json));
  assert.strictEqual((await q(`select member_id from app.work_disputes where submission_id = '${s.id}'`))[0].member_id, own.id, 'opened by the owner');
});

test('OW5: a draft agent\u2019s milestone is a request too; an acting agent\u2019s claim needs no approval', async () => {
  const own = await member('Oown5');
  const dr = await newAgent(own, 'Odraft5', 'draft');
  const pj = await project(own, 'Milestone trial');
  const m = await W(dr, 'milestones', { project: pj, title: 'Ship it', target: '2027-01-15' });
  assert.strictEqual(m.status, 202, JSON.stringify(m.json));
  const actor = await newAgent(own, 'Oact5', 'act');
  const poster = await member('Ope');
  const t1 = await task(poster, await project(poster, 'Act trial'), { size: 2 });
  assert.strictEqual((await W(actor, 'claim', { task: t1 })).status, 201);
});

test('OW6: only the owner sees and decides; an agent reads only its own request', async () => {
  const own = await member('Oown6'); const other = await member('Oother6');
  const ag = await newAgent(own, 'Odraft6', 'draft');
  const poster = await member('Opf');
  const t1 = await task(poster, await project(poster, 'Privacy trial'), { size: 2 });
  const a = await W(ag, 'claim', { task: t1 });
  assert.strictEqual((await list(other)).length, 0);
  const [q] = await list(own);
  assert.strictEqual((await decide(other, q, 'approve')).status, 403);
  const st = await work('GET', 'request', { key: ag.key, search: '?id=' + a.json.request });
  assert.strictEqual(st.json.status, 'waiting');
  assert.strictEqual((await work('GET', 'requests', { key: ag.key })).status, 403);
});

test('OW7 (the fresh review, H1, M1, M4): MCP passes owner_approval on; the owner sees every field and the task; the same request isn’t asked twice', async () => {
  const act = require('../api/_mcp-act.js');
  const claimTool = act.TOOLS.find((t) => t.name === 'claim_task');
  assert.ok(claimTool.inputSchema.properties.owner_approval, 'claim_task takes owner_approval');
  const own = await member('Oown7'); const poster = await member('Opg');
  const ag = await newAgent(own, 'Odraft7', 'draft');
  const t1 = await task(poster, await project(poster, 'Twice trial'), { size: 2 });
  const a = await W(ag, 'claim', { task: t1 });
  const b = await W(ag, 'claim', { task: t1 });
  assert.strictEqual(b.json.request, a.json.request, 'the same request comes back');
  const [q] = await list(own);
  assert.deepStrictEqual([q.body.task, q.task], [t1, t1]);
});
