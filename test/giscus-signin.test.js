// Sign in with giscus (Aaron, Oct 28, 2026): the browser's own giscus sign-in, sent from /join, is turned into a
// GitHub account by giscus.app and GitHub, and that account is signed in. End to end against a real Postgres built
// from the migrations, with giscus.app and GitHub faked at the network edge. Needs TEST_DATABASE_URL.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const { make, SESSION } = require('../signin/flow');
const { PROVIDERS, GISCUS_TOKEN_URL } = require('../signin/providers');
const { migrate } = require('../scripts/migrate');
const { trustSystem, TEST_SYSTEM_SECRET } = require('./helpers');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const KEYS = [{ version: 1, key: crypto.randomBytes(32) }];

// A giscus session as giscus makes it: a 12-byte IV in hex, then base64 ciphertext.
const sessionFor = () => crypto.randomBytes(12).toString('hex') + crypto.randomBytes(48).toString('base64');

// The network edge: giscus.app turns a session into a token; GitHub says whose token it is. Every call is recorded.
const calls = [];
function fakeNetwork({ sessions = {}, tokens = {}, giscusDown = false } = {}) {
  calls.length = 0;
  global.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    const reply = (status, body) => ({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) });
    if (String(url) === GISCUS_TOKEN_URL) {
      if (giscusDown) return reply(503, { error: 'down' });
      const { session } = JSON.parse(init.body || '{}');
      return sessions[session] ? reply(200, { token: sessions[session] }) : reply(400, { error: 'Invalid state value.' });
    }
    if (String(url) === 'https://api.github.com/user') {
      const t = String((init.headers || {}).Authorization || '').replace(/^Bearer /, '');
      return tokens[t] ? reply(200, { id: tokens[t], login: 'someone' }) : reply(401, { message: 'Bad credentials' });
    }
    return reply(404, {});
  };
}

function req(method, url, { cookie = '', origin = ORIGIN, body, ip = '203.0.113.20', country } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': ip, 'sec-fetch-site': 'same-origin',
    'content-type': 'application/x-www-form-urlencoded' };
  if (origin) headers.origin = origin;
  if (country) headers['x-vercel-ip-country'] = country;
  return { method, url, headers, body: new URLSearchParams(body || {}).toString(), query: {} };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function jar() {
  const j = {};
  return {
    take(r) {
      for (const sc of [].concat(r.getHeader('Set-Cookie') || [])) {
        const pair = sc.split(';')[0];
        const name = pair.slice(0, pair.indexOf('=')), value = pair.slice(pair.indexOf('=') + 1);
        assert.ok(name.startsWith('__Host-') && /HttpOnly/.test(sc) && /Secure/.test(sc) && /SameSite=Lax/.test(sc), name);
        if (/Max-Age=0/.test(sc) || !value) delete j[name]; else j[name] = value;
      }
      return r;
    },
    header() { return Object.entries(j).map(([k, v]) => k + '=' + v).join('; '); },
    get(name) { return j[name]; }
  };
}

test('the session goes only to giscus.app and the token only to GitHub; the session\'s shape is checked first', () => {
  const p = read('signin/providers.js');
  assert.match(p, /const GISCUS_TOKEN_URL = 'https:\/\/giscus\.app\/api\/oauth\/token';/);
  assert.match(p, /const GISCUS_SESSION = \/\^\[0-9a-f\]\{24\}\[A-Za-z0-9\+\/\]\{16,1500\}=\{0,2\}\$\/;/);
  const page = read('join.js');
  assert.match(page, /localStorage\.getItem\('giscus-session'\)/, '/join reads giscus\'s own saved sign-in');
  assert.match(page, /fetch\('\/auth\/giscus', \{ method: 'POST', credentials: 'same-origin'/, 'and sends it only to our own server');
});

if (!SERVER) {
  if (process.env.CI) test('giscus sign-in tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('giscus sign-in against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
} else {
  const NAME = 'dog_giscus_test_' + crypto.randomBytes(4).toString('hex');
  const WEB = NAME + '_web';
  const PW = crypto.randomBytes(18).toString('base64url');
  const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
  let server, su, web, flow;
  const realFetch = global.fetch;

  test.before(async () => {
    server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
    await server.unsafe('create database ' + NAME);
    su = postgres(at(NAME), { max: 2, ssl: false, prepare: false, onnotice: () => {} });
    await migrate(su);
    await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
    web = db.connect(at(NAME, WEB, PW), { ssl: false, max: 3 });
    await trustSystem(su);
    const cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: crypto.randomBytes(32), fingerprintKeys: KEYS, github: null, x: null };
    flow = make({ config: cfg, run: (ctx, fn) => db.tx(web, ctx, fn), providers: PROVIDERS, sendEmail: null });
  });
  test.after(async () => {
    global.fetch = realFetch;
    for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
    if (server) {
      await server.unsafe(`drop database if exists ${NAME} with (force)`);
      await server.unsafe(`drop role if exists ${WEB}`);
      await server.end({ timeout: 5 });
    }
  });

  const signIn = async (browser, body, opts = {}) => {
    const r = res(); await flow.giscusSignIn(req('POST', '/auth/giscus', { cookie: browser.header(), body, ...opts }), r);
    browser.take(r);
    return { status: r.statusCode, ...JSON.parse(r.body) };
  };
  const me = async (browser) => { const r = res(); await flow.me(req('GET', '/auth/me', { cookie: browser.header() }), r); return JSON.parse(r.body); };
  const q = async (sql) => [...await su.unsafe(sql)];

  test('a giscus sign-in signs that GitHub account in for 30 days, as GitHub sign-in would; nothing of the token is kept', async () => {
    const s = sessionFor(), token = 'ghu_' + 'a'.repeat(36);
    fakeNetwork({ sessions: { [s]: token }, tokens: { [token]: 9001 } });
    const b = jar();
    assert.deepStrictEqual(await signIn(b, { session: s }), { status: 200, signed_in: true, go: '/feed' });
    assert.ok(b.get(SESSION));
    const who = await me(b);
    assert.strictEqual(who.signed_in, true);
    assert.deepStrictEqual(calls.map((x) => x.url), [GISCUS_TOKEN_URL, 'https://api.github.com/user'], 'one call to each, nothing else');
    assert.deepStrictEqual(JSON.parse(calls[0].init.body), { session: s }, 'giscus.app gets the session only');
    assert.strictEqual(calls[1].init.headers.Authorization, 'Bearer ' + token, 'GitHub gets the token only');
    const [row] = await q(`select i.provider, i.fingerprint = '${c.fingerprints(KEYS, 'github', '9001')[0]}' as same_fp,
      s.expires_at > now() + interval '29 days 23 hours' as thirty from app.sessions s join app.identities i on i.id = s.identity_id
      where s.member_id = '${who.member_id}'`);
    assert.deepStrictEqual(row, { provider: 'github', same_fp: true, thirty: true }, 'the same fingerprint as GitHub sign-in, so both reach one member');
    const dump = JSON.stringify(await q(`select * from app.identities`)) + JSON.stringify(await q(`select * from app.audit_log`));
    assert.ok(!dump.includes(token) && !dump.includes(s) && !dump.includes('9001') && !dump.includes('someone'), 'no token, session, ID or name stored');
    const again = jar();
    assert.strictEqual((await signIn(again, { session: s })).signed_in, true, 'the same person again: the same member');
    assert.strictEqual((await me(again)).member_id, who.member_id);
  });

  test('a made-up or wrongly shaped session signs nobody in, and a bad shape never reaches giscus', async () => {
    fakeNetwork({});
    const b = jar();
    for (const bad of ['', 'x', 'not-a-session', '0'.repeat(24) + '!!!!', 'a'.repeat(3000)]) {
      assert.deepStrictEqual(await signIn(b, { session: bad }), { status: 200, error: 'giscus' }, JSON.stringify(bad.slice(0, 20)));
    }
    assert.strictEqual(calls.length, 0, 'nothing was sent anywhere');
    assert.deepStrictEqual(await signIn(b, { session: sessionFor() }), { status: 200, error: 'giscus' }, 'giscus says it is not a session of its own');
    assert.strictEqual(b.get(SESSION), undefined);
  });

  test('if giscus.app or GitHub doesn\'t answer, nobody is signed in and the page says why; nobody already signed in is affected', async () => {
    const s = sessionFor(), token = 'ghu_' + 'b'.repeat(36);
    fakeNetwork({ sessions: { [s]: token }, tokens: { [token]: 9002 } });
    const ok = jar();
    assert.strictEqual((await signIn(ok, { session: s })).signed_in, true);
    fakeNetwork({ sessions: { [s]: token }, giscusDown: true });
    assert.deepStrictEqual(await signIn(jar(), { session: s }), { status: 200, error: 'giscus' });
    fakeNetwork({ sessions: { [s]: token }, tokens: {} });
    assert.deepStrictEqual(await signIn(jar(), { session: s }), { status: 200, error: 'giscus' }, 'GitHub refuses the token');
    assert.strictEqual((await me(ok)).signed_in, true, 'already signed in: still signed in');
  });

  test('only from our own pages: a cross-site request is refused before anything is sent', async () => {
    fakeNetwork({});
    const r = await signIn(jar(), { session: sessionFor() }, { origin: 'https://evil.example' });
    assert.strictEqual(r.status, 403);
    assert.strictEqual(calls.length, 0);
  });

  test('from a declined region: a new person is declined before anything is stored; a member confirms first, then signs in', async () => {
    const newS = sessionFor(), newT = 'ghu_' + 'c'.repeat(36), memS = sessionFor(), memT = 'ghu_' + 'd'.repeat(36);
    fakeNetwork({ sessions: { [newS]: newT, [memS]: memT }, tokens: { [newT]: 9003, [memT]: 9004 } });
    const members = async () => (await q(`select count(*)::int as n from app.members`))[0].n;
    const before = await members();
    assert.deepStrictEqual(await signIn(jar(), { session: newS }, { country: 'FR' }), { status: 200, declined: true });
    assert.deepStrictEqual(await signIn(jar(), { session: newS, confirm: '1' }, { country: 'FR' }), { status: 200, declined: true }, 'confirming changes nothing for a new person');
    assert.strictEqual(await members(), before, 'nothing stored');
    assert.strictEqual((await signIn(jar(), { session: memS })).signed_in, true, 'a member who joined from home');
    const away = jar();
    assert.deepStrictEqual(await signIn(away, { session: memS }, { country: 'DE' }), { status: 200, region: 'Germany' });
    assert.strictEqual((await signIn(away, { session: memS, confirm: '1' }, { country: 'DE' })).signed_in, true);
  });

  test('a banned member is not signed in', async () => {
    const s = sessionFor(), token = 'ghu_' + 'e'.repeat(36);
    fakeNetwork({ sessions: { [s]: token }, tokens: { [token]: 9005 } });
    const b = jar();
    const first = await signIn(b, { session: s });
    const id = (await me(b)).member_id;
    assert.strictEqual(first.signed_in, true);
    // Banning is Aaron's; here the test acts as the site itself, with its own secret (fix 3), as test/signin.test.js does.
    await su.begin(async (t) => { await t`select app.act_as('system', null, null, false, null, null, ${TEST_SYSTEM_SECRET})`; await t.unsafe(`update app.members set status = 'banned' where id = '${id}'`); });
    assert.deepStrictEqual(await signIn(jar(), { session: s }), { status: 200, error: 'unavailable' });
  });

  test('only a path on this site is followed after signing in', async () => {
    const s = sessionFor(), token = 'ghu_' + 'f'.repeat(36);
    fakeNetwork({ sessions: { [s]: token }, tokens: { [token]: 9006 } });
    assert.strictEqual((await signIn(jar(), { session: s, return_to: '/review' })).go, '/review');
    assert.strictEqual((await signIn(jar(), { session: s, return_to: 'https://evil.example/' })).go, '/');
  });
}
