// The go-live gate (launch.js): setting up the database never opens Release 2 by itself, and LAUNCH_STAGE=preview
// (no longer a stage, Aaron, Oct 24: "NO preview systems") answers exactly as closed.
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

test('the repository decides the stage (launch.json), LAUNCH_STAGE can only close it, and preview counts as closed', () => {
  const open = { stage: 'public' }, shut = { stage: 'closed' };
  // The repository's stage: only an exact public opens; a missing file or anything else is closed.
  assert.strictEqual(launch.stage({}, open), 'public');
  assert.strictEqual(launch.stage({}, shut), 'closed');
  assert.strictEqual(launch.stage({}, null), 'closed', 'no file: closed');
  for (const bad of [{}, { stage: '' }, { stage: 'preview' }, { stage: 'open' }, { stage: 7 }]) assert.strictEqual(launch.stage({}, bad), 'closed', JSON.stringify(bad));
  assert.strictEqual(launch.stage({}, { stage: ' PUBLIC ' }), 'public');
  // LAUNCH_STAGE: unset, empty or public changes nothing; anything else closes, and it never opens a closed repository.
  for (const v of [undefined, '', 'public', 'PUBLIC']) assert.strictEqual(launch.stage({ LAUNCH_STAGE: v }, open), 'public', String(v));
  for (const v of ['closed', 'open', 'live', ' Preview ', 'preview']) assert.strictEqual(launch.stage({ LAUNCH_STAGE: v }, open), 'closed', v);
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'public' }, shut), 'closed', 'the Vercel setting never opens the site');
});

test('R-14: the preview paths PR #50 made unreachable are gone (no allow-list, no preview-only reading, no preview check)', () => {
  const fs = require('fs');
  const path = require('path');
  const root = path.join(__dirname, '..');
  assert.deepStrictEqual(Object.keys(launch).sort(), ['STAGES', 'envCap', 'repoStage', 'stage'], 'launch.js exports only the stage and its two parts');
  const files = ['launch.js', 'join.js', 'signin/flow.js', 'api/feed.js', 'api/agents.js', 'api/mcp.js', 'scripts/setup-production.js'];
  for (const f of files) {
    const src = fs.readFileSync(path.join(root, f), 'utf8').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
    assert.doesNotMatch(src, /LAUNCH_PREVIEW_ALLOW|allowList|mayJoin|PREVIEW_MESSAGE|stage\(\)\s*===\s*'preview'|error=preview|sent=preview|sent_preview/, f);
  }
});

test('only an exact public stage opens Release 2: a stage added later stays closed (F2)', async () => {
  const url = 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres';
  const real = launch.stage;
  try {
    launch.stage = () => 'beta';
    await withEnv({ DATABASE_URL: url }, () => assert.strictEqual(db.configured(), false));
  } finally { launch.stage = real; }
});

test('a database address alone never opens Release 2: db.configured() needs the gate opened too', async () => {
  const url = 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres';
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: undefined }, () => assert.strictEqual(db.configured(), launch.repoStage() === 'public'));
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: 'closed' }, () => assert.strictEqual(db.configured(), false));
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: 'nonsense' }, () => assert.strictEqual(db.configured(), false));
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: 'preview' }, () => assert.strictEqual(db.configured(), false));
  await withEnv({ DATABASE_URL: url, LAUNCH_STAGE: 'public' }, () => assert.strictEqual(db.configured(), true));
  await withEnv({ DATABASE_URL: undefined, LAUNCH_STAGE: 'public' }, () => assert.strictEqual(db.configured(), false));
});

test('while closed, every Release 2 route answers as if there were no database, even with an address set', async () => {
  await withEnv({ DATABASE_URL: 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres', LAUNCH_STAGE: 'closed' }, async () => {
    const r = res();
    await require('../api/feed.js')(req('GET'), r);
    assert.strictEqual(r.statusCode, 200);
    assert.match(JSON.parse(r.body).opens, /isn\u2019t switched on yet/);
    const a = res();
    await require('../api/agents.js')(req('POST', { route: 'register', json: { name: 'x' } }), a);
    assert.strictEqual(a.statusCode, 503);
  });
});

test('with LAUNCH_STAGE=preview, the MCP server shows agents no posts, without touching the database', async () => {
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
    keyVersion: 1, level: 1, displayName: 'Alice', sessionHash: c.sha256hex(token), sessionDays: 30 }));
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
    const H = { host: 'dayonegreat.com', 'x-vercel-forwarded-for': '203.0.113.31' };
    const n = res();
    await require('../api/notify.js')({ method: 'GET', url: '/api/notify/appeals', headers: H, query: { route: 'appeals' } }, n);
    assert.strictEqual(n.statusCode, 503, 'notices off');
    const cr = res();
    await require('../api/cron.js')({ method: 'GET', url: '/api/cron', headers: { ...H, authorization: 'Bearer ' + 'x'.repeat(40) }, query: {} }, cr);
    assert.strictEqual(cr.statusCode, 503, 'timers off');
  });
});

test('once public, the feed is open to everyone and cached at the edge again', async () => {
  await withEnv({ LAUNCH_STAGE: 'public' }, async () => {
    const out = await feed({});
    assert.strictEqual(out.statusCode, 200);
    assert.match(out.getHeader('Vercel-CDN-Cache-Control'), /s-maxage=/);
  });
});

