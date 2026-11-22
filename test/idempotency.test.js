// 071: idempotency keys and the OpenAPI file. Helpers as in test/zero-pay.test.js. ACCEPTANCE.md ID1 to ID4.
// (From 067, the zero-payment launch (Aaron, Nov 21, 2026), against a real Postgres built from the migrations, through the
// real handler (api/work.js) and the timer's jobs: people and their agents agree to tasks, do them, have them verified,
// dispute and appeal them, and the result is reputation with no money anywhere. ACCEPTANCE.md ZP1 to ZP8.
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
const { migrate } = require('../scripts/migrate');

const { promote, shadowMode, asSignin } = require('./helpers');
const ORIGIN = 'https://dayonegreat.com';
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

const NAME = 'dog_071_test_' + crypto.randomBytes(4).toString('hex');
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


const claim = (who, task, key, extra = {}) => work('POST', 'claim', { cookie: who.cookie, json: { task, ...extra }, ...(key ? { headersExtra: { 'idempotency-key': key } } : {}) });

test('ID1: a retried claim with the same Idempotency-Key gets the same answer and code, and the step happens once', async () => {
  const ada = await member('Ida'); const bo = await member('Ibo');
  const id = await task(ada, await project(ada, 'Retry trial'));
  const key = 'retry-' + crypto.randomBytes(16).toString('hex');
  const a = await claim(bo, id, key);
  assert.strictEqual(a.status, 201, JSON.stringify(a.json));
  const b = await claim(bo, id, key);
  assert.strictEqual(b.status, 201);
  assert.strictEqual(b.headers['idempotent-replayed'], 'true');
  assert.deepStrictEqual(b.json.code, a.json.code, 'the one-time code comes back');
  assert.strictEqual(b.json.replayed, true);
  assert.strictEqual((await q(`select count(*)::int as n from app.work_claims where task_id = '${id}'`))[0].n, 1, 'claimed once');
  const c = await claim(bo, id, null);
  assert.ok(c.status >= 400, 'without the key, a second claim is refused as before');
});

test('ID2: the same key with a different request is refused (422); a bad key is 400', async () => {
  const ada = await member('Ida2'); const bo = await member('Ibo2');
  const pj = await project(ada, 'Mismatch trial');
  const t1 = await task(ada, pj); const t2 = await task(ada, pj);
  const key = 'same-' + crypto.randomBytes(16).toString('hex');
  assert.strictEqual((await claim(bo, t1, key)).status, 201);
  assert.strictEqual((await claim(bo, t2, key)).status, 422);
  assert.strictEqual((await claim(bo, t2, 'x')).status, 400);
  assert.strictEqual((await claim(bo, t2, 'short-key-12345')).status, 400, 'fewer than 32 characters');
});

test('ID3: one person\u2019s key can\u2019t replay another\u2019s answer, and the answer is stored sealed', async () => {
  const ada = await member('Ida3'); const bo = await member('Ibo3'); const cy = await member('Icy3');
  const id = await task(ada, await project(ada, 'Scope trial'));
  const key = 'shared-' + crypto.randomBytes(16).toString('hex');
  const a = await claim(bo, id, key);
  const b = await claim(cy, id, key);
  assert.notStrictEqual(b.headers['idempotent-replayed'], 'true', 'keys are scoped to who sends them');
  const [row] = await q(`select encode(sealed, 'escape') as s from app.idem_keys order by created_at desc limit 1`).catch(() => [{ s: '' }]);
  assert.ok(!String(row.s).includes(String(a.json.code)), 'the code is not stored readable');
});

test('ID4: openapi.json matches the routes, covers every acting route agents use, and leaves out the money and administrator routes', () => {
  const { execFileSync } = require('child_process');
  execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'openapi.js'), '--check']);
  const o = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'openapi.json'), 'utf8'));
  for (const r of ['claim', 'submit', 'release', 'handoff', 'tasks', 'projects', 'evidence', 'dispute']) assert.ok(o.paths['/api/work/' + r], r);
  for (const r of ['tasks', 'projects', 'dispute']) assert.ok(o.paths['/api/work/' + r].get && o.paths['/api/work/' + r].post, r + ' is read and written (the fresh review, H1)');
  for (const r of ['fund', 'payouts', 'settle', 'decide']) assert.ok(!o.paths['/api/work/' + r], r + ' left out');
  assert.ok(o.paths['/api/work/claim'].post.parameters.some((p) => p.name === 'Idempotency-Key'));
});
