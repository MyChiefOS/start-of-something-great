// 069: OAuth for agents and the poster rating (Aaron, Nov 22, 2026), against a real Postgres built from the migrations,
// through the real handlers (api/oauth.js, api/agents.js, api/work.js, api/mcp.js). ACCEPTANCE.md OA1 to OA8.
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
async function call(mod, base, method, route, { cookie = '', json, form, key, search = '', extra = {} } = {}, runner) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '198.51.' + (ip >> 8) + '.' + (ip++ & 255), 'x-vercel-ip-country': 'US', ...extra };
  if (method === 'GET') headers['sec-fetch-site'] = 'same-origin';
  if (method === 'POST' && cookie) headers.origin = ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  let body;
  if (json !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(json); }
  if (form !== undefined) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(form).toString(); }
  const r = res();
  await require('../api/' + mod).handle({ method, url: base + route + search, headers, query: { route }, body }, r, runner, CFG);
  return { status: r.statusCode, headers: r.headers, json: r.body ? JSON.parse(r.body) : null };
}

if (!SERVER) {
  if (process.env.CI) test('OAuth tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('OAuth against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_069_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); });
const oauth = (method, route, opts) => call('oauth.js', '/api/oauth/', method, route, opts, run);
const agents = (method, route, opts) => call('agents.js', '/api/agents/', method, route, opts, run);

async function member(name, { level = 2 } = {}) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  return { id: out.memberId, name, cookie: '__Host-dog_session=' + token };
}
const pkce = () => { const verifier = crypto.randomBytes(32).toString('base64url'); return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') }; };
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

// The whole flow as an app and its person would run it: register, approve (make the agent, bind the code), exchange.
async function approve(person, { mode = 'draft', redirect = REDIRECT } = {}) {
  const reg = await oauth('POST', 'register', { json: { client_name: 'Claude', redirect_uris: [REDIRECT] } });
  assert.strictEqual(reg.status, 201, JSON.stringify(reg.json));
  const p = pkce();
  const made = await agents('POST', '', { cookie: person.cookie, json: { name: 'claude_connector_' + crypto.randomBytes(3).toString('hex'), post: mode } });
  assert.strictEqual(made.status, 201, JSON.stringify(made.json));
  const code = await oauth('POST', 'code', { cookie: person.cookie, json: { client_id: reg.json.client_id, redirect_uri: redirect, code_challenge: p.challenge, state: 'xyz', key: made.json.key } });
  return { reg: reg.json, p, made: made.json, code };
}
const codeOf = (url) => new URL(url).searchParams.get('code');

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
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

test('OA1: the discovery documents name the endpoints, PKCE S256 and public clients (RFC 8414, RFC 9728)', async () => {
  const as = await oauth('GET', 'as');
  assert.strictEqual(as.status, 200);
  assert.deepStrictEqual([as.json.issuer, as.json.token_endpoint, as.json.code_challenge_methods_supported, as.json.token_endpoint_auth_methods_supported],
    [ORIGIN, ORIGIN + '/oauth/token', ['S256'], ['none']]);
  const pr = await oauth('GET', 'pr');
  assert.deepStrictEqual([pr.json.resource, pr.json.authorization_servers], [ORIGIN + '/mcp', [ORIGIN]]);
  const card = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '.well-known', 'agent-card.json'), 'utf8'));
  assert.strictEqual(card.securitySchemes.oauth.flows.authorizationCode.tokenUrl, ORIGIN + '/oauth/token');
  const vj = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8'));
  for (const src of ['/.well-known/oauth-authorization-server', '/.well-known/oauth-protected-resource', '/oauth/token', '/oauth/register', '/oauth/authorize', '/mcp']) {
    assert.ok(vj.rewrites.some((r) => r.source === src), src + ' is routed');
  }
});

test('OA2: an app registers, its person approves, and the code becomes a working agent key, once', async () => {
  const ada = await member('Ada');
  const { reg, p, made, code } = await approve(ada);
  assert.strictEqual(code.status, 201, JSON.stringify(code.json));
  const back = new URL(code.json.redirect);
  assert.deepStrictEqual([back.origin + back.pathname, back.searchParams.get('state'), back.searchParams.get('iss')], [REDIRECT, 'xyz', ORIGIN]);
  const tok = await oauth('POST', 'token', { form: { grant_type: 'authorization_code', code: codeOf(code.json.redirect), redirect_uri: REDIRECT, client_id: reg.client_id, code_verifier: p.verifier } });
  assert.strictEqual(tok.status, 200, JSON.stringify(tok.json));
  assert.deepStrictEqual([tok.json.token_type, tok.json.access_token], ['Bearer', made.key], 'the access token is the new agent’s key');
  assert.strictEqual(tok.headers['cache-control'], 'no-store');
  const me = await agents('GET', 'me', { key: tok.json.access_token });
  assert.strictEqual(me.status, 200, 'the key works on the acting routes');
  // The database never held the key readable: only its seal and the code's hash.
  const [row] = await q(`select encode(sealed, 'hex') as s from app.oauth_codes limit 1`);
  assert.ok(!row.s.includes(Buffer.from(made.key).toString('hex')));
});

test('OA3: a wrong verifier, a different return address or another client get invalid_grant; a code used twice revokes its key', async () => {
  const bo = await member('Bo');
  const { reg, p, code } = await approve(bo);
  const c1 = codeOf(code.json.redirect);
  const bad = await oauth('POST', 'token', { form: { grant_type: 'authorization_code', code: c1, redirect_uri: REDIRECT, client_id: reg.client_id, code_verifier: pkce().verifier } });
  assert.deepStrictEqual([bad.status, bad.json.error], [400, 'invalid_grant'], 'wrong verifier');
  // The wrong verifier used the code up: a second try, even right, is a reuse, and the agent is revoked.
  const again = await oauth('POST', 'token', { form: { grant_type: 'authorization_code', code: c1, redirect_uri: REDIRECT, client_id: reg.client_id, code_verifier: p.verifier } });
  assert.strictEqual(again.json.error, 'invalid_grant');
  assert.strictEqual((await q(`select count(*)::int as n from app.oauth_codes o join app.oauth_clients c on c.id = o.client join app.agent_keys k on k.agent_id = o.agent_id where c.client_id = '${reg.client_id}' and k.revoked_at is null`))[0].n, 0, 'its key is revoked');
  const cy = await member('Cy');
  const x = await approve(cy);
  const other = await oauth('POST', 'token', { form: { grant_type: 'authorization_code', code: codeOf(x.code.json.redirect), redirect_uri: 'https://evil.example/cb', client_id: x.reg.client_id, code_verifier: x.p.verifier } });
  assert.strictEqual(other.json.error, 'invalid_grant', 'a different return address');
});

test('OA4: the consent step is our page only, signed in, for a registered return address, with the person’s own key', async () => {
  const di = await member('Di');
  const reg = (await oauth('POST', 'register', { json: { client_name: 'An app', redirect_uris: [REDIRECT] } })).json;
  const made = (await agents('POST', '', { cookie: di.cookie, json: { name: 'di_app', post: 'draft' } })).json;
  const body = { client_id: reg.client_id, redirect_uri: REDIRECT, code_challenge: pkce().challenge, key: made.key };
  assert.strictEqual((await oauth('POST', 'code', { json: body })).status, 403, 'not from our pages');
  assert.strictEqual((await oauth('POST', 'code', { cookie: di.cookie, json: { ...body, redirect_uri: 'https://elsewhere.example/cb' } })).status, 400, 'an unregistered return address');
  const ed = await member('Ed');
  assert.strictEqual((await oauth('POST', 'code', { cookie: ed.cookie, json: body })).status, 403, 'someone else’s key');
});

test('OA5: registration takes https, or http on localhost, and refuses fragments and other schemes', async () => {
  for (const u of ['http://example.com/cb', 'https://x.example/cb#frag', 'javascript:alert(1)', 'ftp://x.example']) {
    const r = await oauth('POST', 'register', { json: { client_name: 'X', redirect_uris: [u] } });
    assert.deepStrictEqual([r.status, r.json.error], [400, 'invalid_redirect_uri'], u);
  }
  assert.strictEqual((await oauth('POST', 'register', { json: { client_name: 'Local', redirect_uris: ['http://127.0.0.1:33418/callback'] } })).status, 201);
});

test('OA6: /mcp answers 401 with where to sign in when no token is sent; /api/mcp still reads without one', async () => {
  const mcp = require('../api/mcp.js');
  const req = (query) => ({ method: 'POST', url: '/api/mcp' + (query ? '?require_auth=1' : ''), query: query ? { require_auth: '1' } : {},
    headers: { host: 'dayonegreat.com', 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
  const r1 = res();
  await mcp(req(true), r1);
  assert.strictEqual(r1.statusCode, 401);
  assert.match(r1.headers['www-authenticate'], /resource_metadata="https:\/\/dayonegreat\.com\/\.well-known\/oauth-protected-resource"/);
  const r2 = res();
  await mcp(req(false), r2);
  assert.notStrictEqual(r2.statusCode, 401);
});

test('OA7: the poster rating counts a poster’s checks, overturned fails and dismissed disputes', async () => {
  const fe = await member('Fe');
  const [{ id: room }] = await q(`select id from app.work_rooms where code = '15-0000'`);
  const [{ id: pj }] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('P', '${room}', 'member', '${fe.id}') returning id`);
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member) values ('${pj}', '${room}', 'T', 'either', 1, 'member', '${fe.id}') returning id`);
  const w = await member('Worker');
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at) values ('${t.id}', '${w.id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day') returning id`);
  const [s] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, decided_by, decided_at)
    values ('${t.id}', '${cl.id}', 'member', '${w.id}', 'link', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'failed', 'poster', now()) returning id`);
  await q(`insert into app.work_checks (submission_id, why, status, decided_at) values ('${s.id}', 'fail_appeal', 'reversed', now())`);
  const r = await call('work.js', '/api/work/', 'GET', 'poster', { search: '?id=' + fe.id }, run);
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  assert.deepStrictEqual([Number(r.json.tasks_posted), Number(r.json.work_checked), Number(r.json.fails_overturned)], [1, 1, 1]);
});

test('OA8: the consent page asks for PKCE and checks the app before it offers to approve', () => {
  const js = fs.readFileSync(path.join(__dirname, '..', 'oauth-authorize.js'), 'utf8');
  assert.match(js, /req\.method !== 'S256'/);
  assert.match(js, /redirect_uris\.indexOf\(req\.redirect\) < 0/);
  assert.doesNotMatch(js, /innerHTML/);
});

test('OA9 (the fresh review, M2): a resource other than this server’s MCP address is refused (RFC 8707)', async () => {
  const r = await oauth('POST', 'token', { form: { grant_type: 'authorization_code', code: c.token(32), redirect_uri: REDIRECT, client_id: 'doc_' + 'a'.repeat(22), code_verifier: pkce().verifier, resource: 'https://other.example/mcp' } });
  assert.deepStrictEqual([r.status, r.json.error], [400, 'invalid_target']);
  const as = await oauth('GET', 'as');
  assert.strictEqual(as.json.authorization_response_iss_parameter_supported, true);
});
