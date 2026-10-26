// The go-live gate (launch.js): setting up the database never opens Release 2 by itself, the private preview is only
// for allow-listed people, and preview content is never served to, or cached for, someone signed out.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const launch = require('../launch');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');

const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';

// Runs fn with these environment variables set, then puts every one back exactly as it was.
async function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) { saved[k] = process.env[k]; if (vars[k] === undefined) delete process.env[k]; else process.env[k] = vars[k]; }
  try { return await fn(); } finally {
    for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  }
}

test('the stage is closed unless set to public, whatever else is written; preview now counts as closed', () => {
  assert.strictEqual(launch.stage({}), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: '' }), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'open' }), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'live' }), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: ' Preview ' }), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'preview' }), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'PUBLIC' }), 'public');
});

test('the allow-list takes account IDs and email addresses, and ignores user names and anything malformed', () => {
  const env = { LAUNCH_PREVIEW_ALLOW: 'github:12345, x:678 email:Aaron@Example.com github:aaronc x:@handle email:not-an-address bogus:1 , ,' };
  assert.deepStrictEqual([...launch.allowList(env)].sort(), ['email:aaron@example.com', 'github:12345', 'x:678']);
  // Forgiving where it's safe: a space after the colon, semicolons, and leading zeros (providers send none).
  const loose = { LAUNCH_PREVIEW_ALLOW: 'github: 7002; github:07003;x:  0009' };
  assert.deepStrictEqual([...launch.allowList(loose)].sort(), ['github:7002', 'github:7003', 'x:9']);
  assert.strictEqual(launch.allowList({}).size, 0);
});

test('mayJoin never stands in the way: preview is no longer a stage, and while closed db.configured() keeps sign-in off', () => {
  // The allow-list paths are unreachable now (R-14 removes them). Setting LAUNCH_STAGE=preview can't switch them on.
  const preview = { LAUNCH_STAGE: 'preview', LAUNCH_PREVIEW_ALLOW: 'github:12345' };
  assert.strictEqual(launch.mayJoin('github', '999', preview), true);
  assert.strictEqual(launch.mayJoin('github', '999', { LAUNCH_STAGE: 'public' }), true);
  assert.strictEqual(launch.mayJoin('github', '999', {}), true);
});

test('a database address alone never opens Release 2: db.configured() needs the gate opened too', async () => {
  const url = 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres';
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: undefined }, () => assert.strictEqual(db.configured(), false));
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: 'closed' }, () => assert.strictEqual(db.configured(), false));
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: 'nonsense' }, () => assert.strictEqual(db.configured(), false));
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: 'preview' }, () => assert.strictEqual(db.configured(), false));
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: 'public' }, () => assert.strictEqual(db.configured(), true));
  await withEnv({ DATABASE_URL: undefined, LAUNCH_STAGE: 'public' }, () => assert.strictEqual(db.configured(), false));
});

test('while closed, every Release 2 route answers as if there were no database, even with an address set', async () => {
  await withEnv({ DATABASE_URL: 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres', LAUNCH_STAGE: undefined }, async () => {
    const r = res();
    await require('../api/feed.js')(req('GET'), r);
    assert.strictEqual(r.statusCode, 200);
    assert.match(JSON.parse(r.body).opens, /isn\u2019t switched on yet/);
    const a = res();
    await require('../api/agents.js')(req('POST', { route: 'register', json: { name: 'x' } }), a);
    assert.strictEqual(a.statusCode, 503);
  });
});

test('during the preview, the MCP server shows agents no posts, without touching the database', async () => {
  const mcp = require('../api/mcp.js');
  await withEnv({ DATABASE_URL: 'postgres://u:p@nowhere.invalid:6543/postgres', LAUNCH_STAGE: 'preview' }, async () => {
    const r = res();
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_posts', arguments: {} } });
    await mcp({ method: 'POST', url: '/api/mcp', headers: { host: 'dayonegreat.com', 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body, query: {} }, r);
    assert.strictEqual(r.statusCode, 200, r.body.slice(0, 300));
    assert.match(r.body, /has not opened yet/, 'the answer says posting isn\u2019t open, rather than listing posts');
  });
});

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, { query = {}, cookie = '', origin, json, host = 'dayonegreat.com', route } = {}) {
  const headers = { host, cookie, 'x-vercel-forwarded-for': '203.0.113.31' };
  if (origin) headers.origin = origin;
  if (json !== undefined) headers['content-type'] = 'application/json';
  if (route !== undefined) query = { route };
  return { method, url: route !== undefined ? '/api/agents/' + route : '/api/feed', headers, query, body: json !== undefined ? JSON.stringify(json) : undefined };
}

if (!SERVER) {
  if (process.env.CI) test('launch-gate tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the go-live gate against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_launch_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, alice;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())],
    keyVersion: 1, level: 2, displayName: 'Alice', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  alice = { id: out.memberId, cookie: '__Host-dog_session=' + token };
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function feed(query, cookie = '') {
  const out = res();
  await require('../api/feed.js').handle(req('GET', { query, cookie }), out, run);
  return out;
}

test('LAUNCH_STAGE=preview answers exactly as closed: no Release 2 route opens, even with a database address', async () => {
  await withEnv({ DATABASE_URL: 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres', LAUNCH_STAGE: 'preview' }, async () => {
    const r = res();
    await require('../api/feed.js')(req('GET'), r);
    assert.strictEqual(r.statusCode, 200);
    assert.match(JSON.parse(r.body).opens, /isn\u2019t switched on yet/);
    assert.doesNotMatch(r.body, /private preview|November 6/);
    const a = res();
    await require('../api/agents.js')(req('POST', { route: 'register', json: { name: 'x' } }), a);
    assert.strictEqual(a.statusCode, 503);
  });
});

test('once public, the feed is open to everyone and cached at the edge again', async () => {
  await withEnv({ LAUNCH_STAGE: 'public' }, async () => {
    const out = await feed({});
    assert.strictEqual(out.statusCode, 200);
    assert.match(out.getHeader('Vercel-CDN-Cache-Control'), /s-maxage=/);
  });
});

