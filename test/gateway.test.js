// The JEVs gateway, slice 1 (GATEWAY.md): what runs in Supabase is exactly what this repository builds, GitHub's
// token check refuses anything our sign-in app didn't issue, and the router answers only the routes it should.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { build, OUT } = require('../scripts/build-gateway');
const { PROVIDERS } = require('../signin/providers');

const root = path.join(__dirname, '..');

test('the committed gateway bundle is exactly a fresh build of this repository', async () => {
  const fresh = await build({ write: false });
  assert.ok(fs.existsSync(OUT), 'run: node scripts/build-gateway.js');
  assert.strictEqual(fs.readFileSync(OUT, 'utf8'), fresh, 'the bundle is out of date: run node scripts/build-gateway.js and commit it');
  assert.ok(!/@simplewebauthn|@peculiar/.test(fresh), 'passkeys are not part of the gateway');
  assert.ok(fresh.length < 400000, 'the bundle stays small: ' + fresh.length + ' bytes');
});

function fakeFetch(answer) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url: String(url), init });
    return answer(String(url), init);
  };
  f.calls = calls;
  return f;
}
const reply = (status, json, headers = {}) => new Response(JSON.stringify(json), { status, headers });

test('GitHub token check: accepted only when our own sign-in app issued the token', async (t) => {
  const real = global.fetch;
  t.after(() => { global.fetch = real; });
  const gh = PROVIDERS.github;
  global.fetch = fakeFetch(() => reply(200, { id: 304218593, login: 'someone' }, { 'X-OAuth-Client-Id': 'Ov23ourapp' }));
  assert.deepStrictEqual(await gh.whoIs('gho_tokentoken', { clientId: 'Ov23ourapp' }), { accountId: '304218593', level: 1, recheckAfter: null });
  assert.match(global.fetch.calls[0].url, /^https:\/\/api\.github\.com\/user$/);
  assert.strictEqual(global.fetch.calls[0].init.headers.Authorization, 'Bearer gho_tokentoken');
  // Another app's token, a personal token (no issuing app), or an answer without the header: refused.
  for (const headers of [{ 'X-OAuth-Client-Id': 'Iv23someoneelse' }, {}]) {
    global.fetch = fakeFetch(() => reply(200, { id: 304218593 }, headers));
    assert.strictEqual(await gh.whoIs('gho_tokentoken', { clientId: 'Ov23ourapp' }), null, JSON.stringify(headers));
  }
  // GitHub refusing the token, an odd answer, or no client ID configured: refused, and nothing is fetched without one.
  global.fetch = fakeFetch(() => reply(401, { message: 'Bad credentials' }, { 'X-OAuth-Client-Id': 'Ov23ourapp' }));
  assert.strictEqual(await gh.whoIs('gho_tokentoken', { clientId: 'Ov23ourapp' }), null);
  global.fetch = fakeFetch(() => reply(200, { id: 'not a number' }, { 'X-OAuth-Client-Id': 'Ov23ourapp' }));
  assert.strictEqual(await gh.whoIs('gho_tokentoken', { clientId: 'Ov23ourapp' }), null);
  global.fetch = fakeFetch(() => reply(200, { id: 1 }, { 'X-OAuth-Client-Id': 'Ov23ourapp' }));
  for (const [tok, id] of [['gho_tokentoken', null], ['', 'Ov23ourapp'], ['x'.repeat(300), 'Ov23ourapp'], [undefined, 'Ov23ourapp']]) {
    assert.strictEqual(await gh.whoIs(tok, { clientId: id }), null);
  }
  assert.strictEqual(global.fetch.calls.length, 0);
});

test('identify still swaps, checks and revokes in one place, now with the issuing-app check too', async (t) => {
  const real = global.fetch;
  t.after(() => { global.fetch = real; });
  const gh = PROVIDERS.github;
  global.fetch = fakeFetch((url) => {
    if (url.startsWith('https://github.com/login/oauth/access_token')) return reply(200, { access_token: 'gho_fresh' });
    if (url === 'https://api.github.com/user') return reply(200, { id: 42 }, { 'X-OAuth-Client-Id': 'Ov23ourapp' });
    return reply(204, {});
  });
  const who = await gh.identify({ clientId: 'Ov23ourapp', clientSecret: 's' }, { code: 'c', verifier: 'v' });
  assert.deepStrictEqual(who, { accountId: '42', level: 1, recheckAfter: null });
  const urls = global.fetch.calls.map((c) => c.url);
  assert.deepStrictEqual(urls, ['https://github.com/login/oauth/access_token', 'https://api.github.com/user', 'https://api.github.com/applications/Ov23ourapp/token']);
  assert.strictEqual(global.fetch.calls[2].init.method, 'DELETE', 'the token is revoked afterwards');
});

test('the gateway answers only its routes: health, the feed, and its six sign-in routes', async () => {
  const { handle } = require('../gateway/handler');
  const { ROUTES } = require('../gateway/auth');
  assert.deepStrictEqual(Object.keys(ROUTES).sort(), ['GET account', 'GET me', 'POST account/name', 'POST github/complete', 'POST logout', 'POST logout-all']);
  const res = () => { const r = { statusCode: 200, headers: {}, body: '' }; r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; }; r.getHeader = (k) => r.headers[k.toLowerCase()]; r.end = (b) => { r.body = b || ''; r.headersSent = true; }; return r; };
  for (const [method, url, status] of [['GET', '/jevs-gateway/auth/github/start', 404], ['GET', '/auth/github/callback', 404], ['POST', '/auth/email/start', 404],
    ['POST', '/auth/passkey/enrol/options', 404], ['GET', '/auth/github/complete', 405], ['GET', '/functions/v1/jevs-gateway/nothing', 404], ['GET', '/', 404]]) {
    const r = res();
    await handle({ method, url, headers: { host: 'dayonegreat.com' }, query: {} }, r);
    assert.strictEqual(r.statusCode, status, method + ' ' + url);
  }
  // With no database configured (as in this test), sign-in is off, as it is on the site today.
  const r = res();
  await handle({ method: 'GET', url: '/jevs-gateway/auth/me', headers: { host: 'dayonegreat.com' }, query: {} }, r);
  assert.strictEqual(r.statusCode, 503);
});

test('the gateway pooler rule: Supabase\'s dedicated pooler only on port 6543, only a real project reference', () => {
  const db = require('../db');
  assert.ok(db.pooledUrl('postgres://dog_web:x@db.nksagchwpyljvjiwolmp.supabase.co:6543/postgres'));
  assert.throws(() => db.pooledUrl('postgres://dog_web:x@db.nksagchwpyljvjiwolmp.supabase.co:5432/postgres'), /pooler/);
});
