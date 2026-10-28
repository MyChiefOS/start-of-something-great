// 023 (Aaron, Oct 28, 2026): signing in to the site by posting a one-time code through giscus. End to end against a
// real Postgres built from the migrations: the site's sign-in flow (signin/flow.js) makes the code, the JEVs gate's own
// code (supabase/functions/jevs/gate.mjs) claims it from a GitHub event shaped as jevs.yml builds it, and the site
// signs the browser in. Needs TEST_DATABASE_URL like test/signin.test.js.
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
const { migrate } = require('../scripts/migrate');
const { trustSystem } = require('./helpers');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
// The gate's hash key is the Vault value dog_fingerprint_key_1; the site gets the same bytes from the broker as
// FINGERPRINT_KEY_1 (route B). The same stand-in here for both.
const GATE_KEY = 'f'.repeat(40);
const SITE_KEYS = [{ version: 1, key: Buffer.from(GATE_KEY, 'utf8') }];

// ---- Fake requests, responses and a browser's cookie jar (as in test/signin.test.js) ----
function req(method, url, { cookie = '', origin = ORIGIN, body, ip = '203.0.113.9', country } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': ip, 'sec-fetch-site': 'same-origin' };
  if (origin) headers.origin = origin;
  if (country) headers['x-vercel-ip-country'] = country;
  headers['content-type'] = 'application/x-www-form-urlencoded';
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

test('the code the site shows is exactly what the gate reads; anything else in the comment is not a code', async () => {
  const J = await import('../supabase/functions/jevs/core.mjs');
  assert.strictEqual(J.signinCode('DOG-7K4M-Q2XH'), 'DOG-7K4M-Q2XH');
  assert.strictEqual(J.signinCode('  dog-7k4m-q2xh \n'), 'DOG-7K4M-Q2XH', 'case and spaces around it are forgiven');
  for (const b of ['my code: DOG-7K4M-Q2XH', 'DOG-7K4M-Q2XH thanks', 'DOG-7K4M-Q2X', 'DOG-7K0M-Q2XH', 'DOG-7K4M-Q2XHH', '']) {
    assert.strictEqual(J.signinCode(b), null, JSON.stringify(b));
  }
  const flow = read('signin/flow.js');
  assert.match(flow, /const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';/, 'no 0, O, 1 or I: 32 characters, 40 random bits in a code');
});

test('the workflow hides a sign-in code comment in either mode, replies, and a failed hide stops nothing', () => {
  const y = read('.github/workflows/jevs.yml');
  assert.match(y, /- name: Hide a sign-in code \(used or not, in either mode\)\n[\s\S]*?continue-on-error: true[\s\S]*?jq -e '\.signin != null' result\.json[\s\S]*?classifier: OUTDATED/);
  assert.match(y, /- name: Reply to \/agent commands and sign-in codes/);
});

if (!SERVER) {
  if (process.env.CI) test('code sign-in tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('code sign-in against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
} else {
  const NAME = 'dog_code_test_' + crypto.randomBytes(4).toString('hex');
  const WEB = NAME + '_web';
  const PW = crypto.randomBytes(18).toString('base64url');
  const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
  let server, su, web, G, flow, cfg;
  let n = 0;

  test.before(async () => {
    G = await import('../supabase/functions/jevs/gate.mjs');
    server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
    await server.unsafe('create database ' + NAME);
    su = postgres(at(NAME), { max: 2, ssl: false, prepare: false, onnotice: () => {} });
    await migrate(su);
    await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
    web = db.connect(at(NAME, WEB, PW), { ssl: false, max: 3 });
    await trustSystem(su);
    cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: crypto.randomBytes(32), fingerprintKeys: SITE_KEYS, github: null, x: null };
    flow = make({ config: cfg, run: (ctx, fn) => db.tx(web, ctx, fn), providers: {}, sendEmail: null });
  });
  test.after(async () => {
    for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
    if (server) {
      await server.unsafe(`drop database if exists ${NAME} with (force)`);
      await server.unsafe(`drop role if exists ${WEB}`);
      await server.end({ timeout: 5 });
    }
  });

  const start = async (browser, opts = {}) => {
    const r = res(); await flow.codeStart(req('POST', '/auth/code/start', { cookie: browser.header(), ...opts }), r);
    browser.take(r);
    return { status: r.statusCode, ...JSON.parse(r.body) };
  };
  const finish = async (browser, opts = {}) => {
    const r = res(); await flow.codeFinish(req('POST', '/auth/code/finish', { cookie: browser.header(), ...opts }), r);
    browser.take(r);
    return { status: r.statusCode, ...JSON.parse(r.body) };
  };
  // A comment posted through giscus, as jevs.yml sends it to the gate.
  const post = (id, login, body, extra = {}) => {
    n += 1;
    return G.handle(su, {
      event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1,
      post: { node_id: 'DC_code_' + n, thread_node_id: 'c' + n, body, created_at: new Date().toISOString() },
      author: { id, login, type: 'User', created_at: '2015-01-01T00:00:00Z' }, ...extra
    }, { key: GATE_KEY });
  };
  const me = async (browser) => { const r = res(); await flow.me(req('GET', '/auth/me', { cookie: browser.header() }), r); return JSON.parse(r.body); };
  // Reading and ageing rows straight in the database, as the test superuser (row-level security doesn't bind it).
  const owner = async (q) => [...await su.unsafe(q)];

  test('a person gets a code, posts it through giscus, and is signed in for 30 days; nothing names them but GitHub', async () => {
    const b = jar();
    const s = await start(b);
    assert.strictEqual(s.status, 200);
    assert.match(s.code, /^DOG-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
    assert.strictEqual(s.expires_in, 600);
    assert.deepStrictEqual(await finish(b), { status: 200, waiting: true }, 'not posted yet');
    const g = await post(8001, 'coder', s.code);
    assert.deepStrictEqual(g.signin, { claimed: true, founder: false });
    assert.match(g.reply, /This code is now claimed for `@coder`: the browser that asked for it can sign in to Day One Great as you\. If that wasn't you, sign out everywhere/);
    assert.strictEqual(g.alert, false, 'an ordinary member\'s sign-in alerts no one');
    const replay = await G.handle(su, { event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1,
      post: { node_id: 'DC_code_' + n, thread_node_id: 'c' + n, body: s.code, created_at: new Date().toISOString() },
      author: { id: 8001, login: 'coder', type: 'User', created_at: '2015-01-01T00:00:00Z' } }, { key: GATE_KEY });
    assert.deepStrictEqual(replay.signin, { claimed: true, founder: false }, 'a retried run of the same post still says claimed (the CSO\'s finding 8)');
    const f = await finish(b);
    assert.deepStrictEqual(f, { status: 200, signed_in: true, go: '/feed' });
    assert.ok(b.get(SESSION), 'a session cookie');
    const who = await me(b);
    assert.strictEqual(who.signed_in, true);
    const [row] = await owner(`select s.expires_at > now() + interval '29 days 23 hours' as thirty, i.provider, i.fingerprint = '${c.fingerprints(SITE_KEYS, 'github', '8001')[0]}' as same_fp
      from app.sessions s join app.identities i on i.id = s.identity_id where s.member_id = '${who.member_id}'`);
    assert.deepStrictEqual(row, { thirty: true, provider: 'github', same_fp: true },
      'a 30-day session, and the same fingerprint GitHub sign-in gives this account, so both ways reach one member');
    const dump = JSON.stringify(await owner(`select * from app.code_signins`));
    assert.ok(!dump.includes(s.code) && !dump.includes('8001') && !dump.includes('coder'), 'no code, ID or name is stored, only keyed hashes');
  });

  test('a code works once, only for the browser that asked for it', async () => {
    const b = jar(), thief = jar();
    const s = await start(b);
    await start(thief);
    await post(8002, 'once', s.code);
    assert.deepStrictEqual(await finish(thief), { status: 200, waiting: true }, 'another browser gets nothing from this code');
    assert.strictEqual((await finish(b)).signed_in, true);
    const again = await post(8003, 'late', s.code);
    assert.deepStrictEqual(again.signin, { claimed: false, founder: false }, 'posting a used code claims nothing');
    assert.match(again.reply, /This code didn't sign anyone in/);
    const b2 = jar();
    assert.deepStrictEqual(await finish(b2), { status: 200, expired: true }, 'a browser with no code of its own');
  });

  test('a code expires after 10 minutes, and an edited comment never claims one', async () => {
    const b = jar();
    const s = await start(b);
    await owner(`update app.code_signins set expires_at = now() - interval '1 second' where status = 'waiting'`);
    const late = await post(8004, 'slow', s.code);
    assert.deepStrictEqual(late.signin, { claimed: false, founder: false });
    assert.deepStrictEqual(await finish(b), { status: 200, expired: true });
    const b2 = jar();
    const s2 = await start(b2);
    n += 1;
    const edited = await G.handle(su, { event: 'discussion_comment', action: 'edited', mode: 'enforce', discussion: 1,
      post: { node_id: 'DC_code_e' + n, thread_node_id: 'ce' + n, body: s2.code, created_at: new Date().toISOString() },
      author: { id: 8005, login: 'editor', type: 'User', created_at: '2015-01-01T00:00:00Z' } }, { key: GATE_KEY });
    assert.strictEqual(edited.signin, undefined);
    assert.deepStrictEqual(await finish(b2), { status: 200, waiting: true });
  });

  test('the site can\'t choose who signs in: only the gate\'s role may claim a code, and sign-in takes the account from the claim', async () => {
    const b = jar();
    const s = await start(b);
    const tagHash = c.sha256hex(b.get('__Host-dog_code'));
    const codeHash = c.hmacHex(SITE_KEYS[0].key, 'signin-code:' + s.code);
    await assert.rejects(web.begin(async (t) => { await t`set local role dog_app`; await t`select app.code_claim(${codeHash}, ${'a'.repeat(64)})`; }),
      /permission denied/, 'the site\'s role can\'t claim a code for any account');
    const [args] = await owner(`select pg_get_function_identity_arguments('app.code_sign_in(text, text, text, integer, text)'::regprocedure) as a`);
    assert.doesNotMatch(args.a, /fingerprint|github|account/i, 'sign-in takes no account from the caller');
    assert.deepStrictEqual(await finish(b), { status: 200, waiting: true });
    assert.ok(tagHash.length === 64);
  });

  test('a banned account\'s post claims nothing; the founder\'s account is never banned, and its claims alert', async () => {
    const b = jar();
    const s = await start(b);
    const banned = await post(8006, 'banned-one', s.code, { bans: [8006] });
    assert.deepStrictEqual(banned.signin, { claimed: false, founder: false });
    assert.deepStrictEqual(await finish(b), { status: 200, waiting: true });
    const f = await post(304218593, 'MyChiefOS', s.code, { bans: [304218593] });
    assert.deepStrictEqual(f.signin, { claimed: true, founder: true }, 'Aaron can always sign in, whatever the ban list says');
    assert.strictEqual(f.alert, true, 'a code claimed by the founder\'s account (Aaron\'s, which Claude also posts as) alerts on the JEVs alerts issue (the CSO\'s finding 1)');
    assert.strictEqual((await finish(b)).signed_in, true);
  });

  test('only from our own pages: a cross-site start or finish is refused', async () => {
    const b = jar();
    assert.strictEqual((await start(b, { origin: 'https://evil.example' })).status, 403);
    assert.strictEqual(b.get('__Host-dog_code'), undefined);
    const s = await start(b);
    await post(8007, 'csrf', s.code);
    assert.strictEqual((await finish(b, { origin: 'https://evil.example' })).status, 403);
    assert.strictEqual((await finish(b)).signed_in, true);
  });

  test('from a declined region: the page asks where the person lives before any code is made; a new person is declined and nothing of the code is kept; a member signs in', async () => {
    const b = jar();
    assert.deepStrictEqual(await start(b, { country: 'FR' }), { status: 200, region: 'France' }, 'no code yet');
    assert.strictEqual(b.get('__Host-dog_code'), undefined);
    const s = await start(b, { country: 'FR', body: { confirm: '1' } });
    assert.match(s.code, /^DOG-/);
    await post(8008, 'newfr', s.code);
    assert.deepStrictEqual(await finish(b, { country: 'FR', body: { confirm: '1' } }), { status: 200, declined: true });
    assert.strictEqual(b.get(SESSION), undefined);
    const fp = c.fingerprints(SITE_KEYS, 'github', '8008')[0];
    const [{ k }] = await owner(`select count(*)::int as k from app.identities where fingerprint = '${fp}'`);
    assert.strictEqual(k, 0, 'no account is made');
    const [{ left }] = await owner(`select count(*)::int as left from app.code_signins where fingerprint = '${fp}'`);
    assert.strictEqual(left, 0, 'the claimed code and the fingerprint it held are deleted at once (Oct 16 rule; the CSO\'s finding 4)');
    // A member who lives elsewhere, travelling.
    const home = jar();
    const s1 = await start(home);
    await post(8009, 'traveller', s1.code);
    assert.strictEqual((await finish(home)).signed_in, true);
    const away = jar();
    assert.deepStrictEqual(await start(away, { country: 'DE' }), { status: 200, region: 'Germany' });
    const s2 = await start(away, { country: 'DE', body: { confirm: '1' } });
    await post(8009, 'traveller', s2.code);
    assert.strictEqual((await finish(away, { country: 'DE', body: { confirm: '1' } })).signed_in, true);
  });

  test('codes that expired more than an hour ago are cleared every time a code is made', async () => {
    const b = jar();
    await start(b);
    await owner(`update app.code_signins set expires_at = now() - interval '2 hours'`);
    await start(jar());
    const [{ old }] = await owner(`select count(*)::int as old from app.code_signins where expires_at < now() - interval '1 hour'`);
    assert.strictEqual(old, 0);
  });

  test('sessions last a flat 30 days (Aaron, Oct 28): no idle limit', async () => {
    assert.strictEqual(require('../signin/config').IDLE_DAYS, 30);
    assert.strictEqual(require('../signin/config').SESSION_DAYS, 30);
  });
}
