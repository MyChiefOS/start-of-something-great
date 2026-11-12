// 037 (Aaron, Nov 5, 2026): every way in needs two things, and all three end at the same check. End to end against a
// real Postgres built from the migrations, through the site's own sign-in flow (signin/flow.js) and the JEVs gate's own
// code (supabase/functions/jevs/gate.mjs), with a stand-in for the browser's key (test/helpers/browser-key.js):
//   lane 1, first time or a lost file: a code posted through giscus, then a new PIN; lane 2, a new browser: the key
//   file and the PIN; lane 3, this browser again: its key and the PIN. The browser key signs a one-time challenge made
//   for this site's address; the database checks the signature itself and the PIN; the 5th wrong PIN alerts and the
//   10th cancels that browser key (or key file); the GitHub lane always stays open.
// Needs TEST_DATABASE_URL like test/code-signin.test.js.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const session = require('../signin/session');
const { make, SESSION } = require('../signin/flow');
const { migrate } = require('../scripts/migrate');
const { trustSystem, clearOfWindow } = require('./helpers');
const BK = require('./helpers/browser-key');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const GATE_KEY = 'f'.repeat(40);
const SITE_KEYS = [{ version: 1, key: Buffer.from(GATE_KEY, 'utf8') }];
const sha = (x) => crypto.createHash('sha256').update(x).digest('hex');
const FILE_A = sha('a private file of any type'), FILE_B = sha('another private file');
const PIN = BK.PIN;

// ---- Without a database: what the browser signs, and the site's own check of it ----

test('the site and the database sign the same bytes, and the site\'s own check (Node\'s crypto) refuses any other origin, challenge or signature', () => {
  const k = BK.make();
  const ch = 'A'.repeat(43);
  assert.strictEqual(c.signinMessage(ORIGIN, ch).toString('utf8'), 'dayonegreat-signin-v1\nhttps://dayonegreat.com\n' + ch);
  assert.match(read('db/migrations/037_signin_pin.sql'), /convert_to\('dayonegreat-signin-v1' \|\| chr\(10\) \|\| p_origin \|\| chr\(10\) \|\| p_challenge, 'UTF8'\)/,
    'the database builds the same message');
  const sig = Buffer.from(BK.proof(k, ch).sig, 'base64url');
  assert.strictEqual(c.p256Verify(k.raw, c.signinMessage(ORIGIN, ch), sig), true);
  assert.strictEqual(c.p256Verify(k.raw, c.signinMessage('https://dayonegreat.co', ch), sig), false, 'a look-alike address');
  assert.strictEqual(c.p256Verify(k.raw, c.signinMessage(ORIGIN, 'B'.repeat(43)), sig), false, 'another challenge');
  assert.strictEqual(c.p256Verify(BK.make().raw, c.signinMessage(ORIGIN, ch), sig), false, 'another key');
  assert.strictEqual(c.p256Verify(k.raw, c.signinMessage(ORIGIN, ch), sig.subarray(1)), false, 'a short signature');
  assert.strictEqual(c.p256Verify(Buffer.alloc(65), c.signinMessage(ORIGIN, ch), sig), false, 'not a key');
});

test('the page makes its browser name from the same two lists the server accepts', () => {
  const js = read('pin.js');
  const list = (name) => JSON.parse(js.match(new RegExp('var ' + name + ' = (\\[\\[[^;]*?\\]\\]);'))[1].replace(/'/g, '"'));
  assert.deepStrictEqual(list('BROWSERS').map((x) => x[1]).concat('A browser'), session.BROWSER_NAMES);
  assert.deepStrictEqual(list('DEVICES').map((x) => x[1]).concat('a device'), session.DEVICE_NAMES);
  assert.ok(session.BROWSER_LABELS.has('Firefox on Linux') && session.BROWSER_LABELS.has('A browser on a device'));
  assert.ok(!session.BROWSER_LABELS.has('Firefox 131 on Linux x86_64'), 'never the full browser details');
});

test('the browser key can\'t be exported: /join/pin makes it with Web Crypto, extractable false, and keeps it in IndexedDB', () => {
  const js = read('pin.js');
  assert.match(js, /generateKey\(\{ name: 'ECDSA', namedCurve: 'P-256' \}, false, \['sign'\]\)/);
  assert.match(js, /indexedDB\.open\(/);
  assert.doesNotMatch(js, /exportKey\('(jwk|pkcs8)'/, 'only the public key is ever exported (raw)');
  assert.doesNotMatch(js, /sessionStorage\.setItem\([^)]*pin/i, 'the PIN is never kept in the browser');
  // localStorage holds one yes, "this browser keeps a sign-in key" (so /join opens /join/pin), and nothing else.
  assert.deepStrictEqual([...js.matchAll(/localStorage\.setItem\(([^)]*)\)/g)].map((m) => m[1]), ["FLAG, '1'"], 'only the flag');
  assert.match(js, /var FLAG = 'dog-signin-key';/);
});

if (!SERVER) {
  if (process.env.CI) test('PIN sign-in tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('PIN sign-in against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
} else {
  const NAME = 'dog_pin_test_' + crypto.randomBytes(4).toString('hex');
  const WEB = NAME + '_web';
  const PW = crypto.randomBytes(18).toString('base64url');
  const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
  let server, su, web, G, flow;
  let n = 0, ipN = 0;

  test.before(async () => {
    G = await import('../supabase/functions/jevs/gate.mjs');
    server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
    await server.unsafe('create database ' + NAME);
    su = postgres(at(NAME), { max: 2, ssl: false, prepare: false, onnotice: () => {} });
    await migrate(su);
    await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
    web = db.connect(at(NAME, WEB, PW), { ssl: false, max: 3 });
    await trustSystem(su);
    const cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: crypto.randomBytes(32), fingerprintKeys: SITE_KEYS, github: null, x: null };
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

  // ---- A browser: its cookies, its key, and requests as /join sends them ----
  // Each request from its own /24 (053 limits key-file tries per /24 and per /48).
  const nextIp = () => { ipN += 1; return '198.19.' + (ipN % 250) + '.' + (1 + Math.floor(ipN / 250)); };
  function req(method, url, { cookie = '', origin = ORIGIN, body, ip = nextIp(), country } = {}) {
    const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': ip, 'sec-fetch-site': 'same-origin', 'content-type': 'application/x-www-form-urlencoded' };
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
  function browser() {
    const j = {};
    return {
      key: null, keyId: null, setCookies: [],
      take(r) {
        for (const sc of [].concat(r.getHeader('Set-Cookie') || [])) {
          this.setCookies.push(sc);
          const pair = sc.split(';')[0];
          const k = pair.slice(0, pair.indexOf('=')), v = pair.slice(pair.indexOf('=') + 1);
          if (/Max-Age=0/.test(sc) || !v) delete j[k]; else j[k] = v;
        }
        return r;
      },
      header() { return Object.entries(j).map(([k, v]) => k + '=' + v).join('; '); },
      get(k) { return j[k]; }
    };
  }
  const call = async (b, handler, url, opts = {}) => {
    const r = res(); await flow[handler](req('POST', url, { cookie: b.header(), ...opts }), r); b.take(r);
    return { status: r.statusCode, ...JSON.parse(r.body) };
  };
  const challenge = async (b, opts = {}) => (await call(b, 'challenge', '/auth/challenge', opts)).challenge;
  const me = async (b) => { const r = res(); await flow.me(req('GET', '/auth/me', { cookie: b.header() }), r); return JSON.parse(r.body); };
  const owner = async (q) => [...await su.unsafe(q)];
  // 053 (Aaron, Nov 8: "Follow the STIG guidelines", V-222432): 3 failed sign-ins in 15 minutes lock the account, every
  // way in, for 15 minutes. These stand in for the 15 minutes passing.
  const passLock = (id) => su.unsafe(`update app.signin_failures set at = at - interval '16 minutes' where member_id = '${id}';
    update app.signin_locks set until = now() - interval '1 second' where member_id = '${id}'`);
  const audited = async (id, action) => (await owner(`select count(*)::int as n from app.audit_log where subject_id = '${id}' and action = '${action}'`))[0].n;
  const post = (id, login, body) => {
    n += 1;
    return G.handle(su, { event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1,
      post: { node_id: 'DC_pin_' + n, thread_node_id: 'p' + n, body, created_at: new Date().toISOString() },
      author: { id, login, type: 'User', created_at: '2015-01-01T00:00:00Z' } }, { key: GATE_KEY });
  };

  // Lane 1: a code for this username and file, posted by that GitHub account, then the new PIN and this browser's key.
  async function lane1(b, { id, login, file = FILE_A, pin = PIN, body = {} } = {}) {
    const s = await call(b, 'codeStart', '/auth/code/start', { body: { login, file } });
    assert.match(s.code, /^DOG-/);
    assert.deepStrictEqual(await call(b, 'codeFinish', '/auth/code/finish'), { status: 200, waiting: true }, 'waiting until it is posted');
    assert.strictEqual((await post(id, login, s.code)).signin.claimed, true);
    const claimed = await call(b, 'codeFinish', '/auth/code/finish');
    assert.strictEqual(claimed.claimed, true, 'claimed: the page now asks for a new PIN');
    assert.ok(claimed.expires_in > 0 && claimed.expires_in <= 600);
    const k = BK.make();
    const out = await call(b, 'codeFinish', '/auth/code/finish', { body: { ...body, pin, pub: k.pub, label: BK.LABEL, ...BK.proof(k, await challenge(b)) } });
    if (out.signed_in) { b.key = k; b.keyId = out.key_id; }
    return out;
  }
  // Lane 2: the key file and the PIN, adding a new key for this browser.
  async function lane2(b, { login, file = FILE_A, pin = PIN, origin = ORIGIN, key = BK.make() } = {}) {
    const ch = await challenge(b);
    const out = await call(b, 'keyFileSignIn', '/auth/key', { body: { login, file, pin, pub: key.pub, label: BK.LABEL, ...BK.proof(key, ch, origin) } });
    if (out.signed_in) { b.key = key; b.keyId = out.key_id; }
    return out;
  }
  // Lane 3: this browser's key and the PIN.
  async function lane3(b, { pin = PIN, origin = ORIGIN, proof } = {}) {
    const p = proof || BK.proof(b.key, await challenge(b), origin);
    return call(b, 'browserSignIn', '/auth/browser', { body: { key_id: b.keyId, pin, ...p } });
  }
  const signedOut = (b) => { for (const k of [SESSION]) b.take({ getHeader: () => [k + '=; Path=/; Max-Age=0'] }); };

  test('the database\'s own signature check agrees with Node\'s crypto on 150 random keys and messages, and refuses every changed bit and every malformed input', async () => {
    const q = (pub, msg, sig) => su`select app.p256_verify(${pub}, ${msg}, ${sig}) as v`.then((r) => r[0].v);
    for (let i = 0; i < 150; i++) {
      const k = BK.make();
      const msg = crypto.randomBytes(1 + (i % 120));
      const sig = Buffer.from(k.sign(msg), 'base64url');
      assert.strictEqual(await q(k.raw, msg, sig), true, 'valid ' + i);
      const badSig = Buffer.from(sig); badSig[i % 64] ^= 1 << (i % 8);
      assert.strictEqual(await q(k.raw, msg, badSig), false, 'a changed signature bit ' + i);
      const badMsg = Buffer.from(msg); badMsg[i % msg.length] ^= 1 << (i % 8);
      assert.strictEqual(await q(k.raw, badMsg, sig), false, 'a changed message bit ' + i);
      const badKey = Buffer.from(k.raw); badKey[1 + (i % 64)] ^= 1 << (i % 8);
      assert.strictEqual(await q(badKey, msg, sig), false, 'a changed key bit ' + i);
    }
    const k = BK.make(); const msg = Buffer.from('x'); const sig = Buffer.from(k.sign(msg), 'base64url');
    const N = Buffer.from('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 'hex');
    const zero = Buffer.alloc(32);
    for (const [why, s] of [['r = 0', Buffer.concat([zero, sig.subarray(32)])], ['s = 0', Buffer.concat([sig.subarray(0, 32), zero])],
      ['r = n', Buffer.concat([N, sig.subarray(32)])], ['s = n', Buffer.concat([sig.subarray(0, 32), N])],
      ['63 bytes', sig.subarray(1)], ['empty', Buffer.alloc(0)]]) {
      assert.strictEqual(await q(k.raw, msg, s), false, why);
    }
    // s and n - s are both valid ECDSA signatures (malleability); harmless here, since every challenge works once.
    const sN = (BigInt('0x' + N.toString('hex')) - BigInt('0x' + sig.subarray(32).toString('hex'))).toString(16).padStart(64, '0');
    assert.strictEqual(await q(k.raw, msg, Buffer.concat([sig.subarray(0, 32), Buffer.from(sN, 'hex')])), true, 'n - s: the same signature in its other form');
    const off = Buffer.from(k.raw); off[64] ^= 1;
    assert.strictEqual((await su`select app.p256_point_ok(${off}) as v`)[0].v, false, 'a point off the curve');
    assert.strictEqual((await su`select app.p256_point_ok(${Buffer.concat([Buffer.from([2]), k.raw.subarray(1, 33)])}) as v`)[0].v, false, 'a compressed key');
    assert.strictEqual((await su`select app.p256_point_ok(${Buffer.concat([Buffer.from([4]), Buffer.alloc(64)])}) as v`)[0].v, false, 'zeros');
  });

  test('lane 1, first time: the code posted through GitHub, a new PIN and this browser\'s key; signed in for 30 days with a cookie kept only as a hash; no PIN or private key is stored', async () => {
    const b = browser();
    const out = await lane1(b, { id: 9001, login: 'firsttimer' });
    assert.strictEqual(out.signed_in, true);
    assert.match(out.key_id, /^[0-9a-f-]{36}$/, 'the browser keeps the ID of its key');
    const who = await me(b);
    assert.strictEqual(who.signed_in, true);
    // The session cookie: random, __Host-, HttpOnly, Secure, 30 days; the database keeps only its SHA-256.
    const cookie = b.setCookies.find((x) => x.startsWith(SESSION + '='));
    assert.match(cookie, /^__Host-dog_session=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000$/);
    const token = b.get(SESSION);
    const [row] = await owner(`select token_hash, expires_at > now() + interval '29 days 23 hours' as thirty, expires_at < now() + interval '30 days 1 minute' as not_more
      from app.sessions where member_id = '${who.member_id}'`);
    assert.deepStrictEqual({ ...row }, { token_hash: c.sha256hex(token), thirty: true, not_more: true });
    const everything = JSON.stringify(await owner(`select * from app.sessions`));
    assert.ok(!everything.includes(token), 'the cookie itself is nowhere in the database');
    // The PIN and the key: a keyed hash with a salt, and the public key only.
    const [pin] = await owner(`select encode(salt, 'hex') as salt, encode(pin_hash, 'hex') as h from app.signin_pins where member_id = '${who.member_id}'`);
    assert.match(pin.h, /^[0-9a-f]{64}$/);
    assert.notStrictEqual(pin.h, sha(PIN), 'not a plain hash of the PIN');
    assert.notStrictEqual(pin.h, sha(pin.salt + PIN), 'not an unkeyed salted hash either');
    const dump = JSON.stringify(await owner(`select p.*, b.* from app.signin_pins p, app.browser_keys b where p.member_id = b.member_id`));
    assert.ok(!dump.includes(PIN), 'the PIN is nowhere in the database');
    const [bk] = await owner(`select encode(public_key, 'base64') as pk, label from app.browser_keys where id = '${out.key_id}'`);
    assert.strictEqual(Buffer.from(bk.pk, 'base64').toString('base64url'), b.key.pub, 'the public key, as the browser sent it');
    assert.strictEqual(bk.label, 'Firefox on Linux');
  });

  test('lane 3, this browser again: its key and the PIN, no file and no post; the next day the same', async () => {
    const b = browser();
    await lane1(b, { id: 9002, login: 'returning' });
    const id = (await me(b)).member_id;
    signedOut(b);
    assert.strictEqual((await me(b)).signed_in, false);
    const out = await lane3(b);
    assert.deepStrictEqual(out, { status: 200, signed_in: true, go: '/feed' });
    assert.strictEqual((await me(b)).member_id, id, 'the same account');
    // Another browser can't use this key's ID without the key itself, whatever PIN it knows.
    const thief = browser(); thief.keyId = b.keyId; thief.key = BK.make();
    assert.strictEqual((await lane3(thief)).retry, true, 'a signature by any other key is refused, and no PIN is tested');
    const [{ failed }] = await owner(`select failed from app.browser_keys where id = '${b.keyId}'`);
    assert.strictEqual(failed, 0, 'nothing was counted against the real browser');
  });

  test('lane 2, a new browser: the key file and the PIN, no post; the member is told "New browser added"; the file without the PIN, or the PIN without the file, signs nobody in', async () => {
    const first = browser();
    await lane1(first, { id: 9003, login: 'traveller2', file: FILE_A });
    const id = (await me(first)).member_id;
    const laptop = browser();
    const out = await lane2(laptop, { login: 'Traveller2', file: FILE_A });
    assert.strictEqual(out.signed_in, true);
    assert.strictEqual((await me(laptop)).member_id, id);
    const [note] = await owner(`select title, body, link from app.notices where member_id = '${id}' and kind = 'signin_browser'`);
    assert.deepStrictEqual({ title: note.title, link: note.link }, { title: 'New browser added', link: '/account' });
    // The laptop now signs in on its own, with lane 3.
    signedOut(laptop);
    assert.strictEqual((await lane3(laptop)).signed_in, true);
    // The file alone: refused before anything is asked of the database.
    const thief = browser();
    const k = BK.make();
    const noPin = await call(thief, 'keyFileSignIn', '/auth/key', { body: { login: 'traveller2', file: FILE_A, pub: k.pub, label: BK.LABEL, ...BK.proof(k, await challenge(thief)) } });
    assert.strictEqual(noPin.signed_in, undefined);
    assert.match(noPin.error, /PIN of six digits/);
    assert.match((await lane2(thief, { login: 'traveller2', file: FILE_A, pin: '246813' })).error, /That PIN isn’t right\. 9 tries are left before your key file is cancelled\./);
    assert.match((await lane2(thief, { login: 'traveller2', file: FILE_B })).error, /don’t match/, 'the PIN without the file');
    assert.strictEqual((await me(thief)).signed_in, false);
  });

  test('a challenge works once: replaying a used one is refused, even with its valid signature, and so is one that timed out', async () => {
    const b = browser();
    await lane1(b, { id: 9004, login: 'replayer' });
    signedOut(b);
    const proof = BK.proof(b.key, await challenge(b));
    assert.strictEqual((await lane3(b, { proof })).signed_in, true);
    signedOut(b);
    const again = await lane3(b, { proof });
    assert.strictEqual(again.signed_in, undefined, 'the same challenge and signature, sent again');
    assert.strictEqual(again.retry, true);
    // Captured on the way and sent from elsewhere: the same.
    const elsewhere = browser(); elsewhere.keyId = b.keyId;
    assert.strictEqual((await call(elsewhere, 'browserSignIn', '/auth/browser', { body: { key_id: b.keyId, pin: PIN, ...proof } })).signed_in, undefined);
    // A wrong PIN uses the challenge up too: it can't then be used with the right one.
    const p2 = BK.proof(b.key, await challenge(b));
    assert.strictEqual((await lane3(b, { proof: p2, pin: '246813' })).pin_error, true);
    assert.strictEqual((await lane3(b, { proof: p2 })).retry, true);
    // Older than 2 minutes.
    const p3 = BK.proof(b.key, await challenge(b));
    await owner(`update app.signin_challenges set expires_at = now() - interval '1 second' where used_at is null`);
    assert.strictEqual((await lane3(b, { proof: p3 })).retry, true);
    assert.strictEqual((await lane3(b)).signed_in, true, 'a fresh challenge works');
  });

  test('a challenge made for, or signed with, another site\'s address is refused, in the site and in the database itself', async () => {
    const b = browser();
    await lane1(b, { id: 9005, login: 'originer' });
    signedOut(b);
    // Signed with a look-alike's address (what a look-alike site's own page would put in): refused.
    assert.strictEqual((await lane3(b, { origin: 'https://dayonegreat.co' })).retry, true);
    // In the database alone, as if the site's own check were skipped (a site login in the wrong hands): a challenge
    // made for another address, signed with that address, is refused for this one; so is a signature with another key.
    const store = require('../db/signin');
    const anon = { actor: 'anon' };
    const other = await db.tx(web, anon, (t) => store.challengeIssue(t, 'https://dayonegreat.co'));
    const viaDb = (p, origin = ORIGIN) => db.tx(web, anon, (t) => store.browserSignIn(t, { keyId: b.keyId, displayName: 'New member',
      sessionHash: c.sha256hex(c.token(32)), sessionDays: 30, pin: PIN, challenge: p.challenge, origin, signature: Buffer.from(p.sig, 'base64url') }));
    assert.strictEqual((await viaDb(BK.proof(b.key, other, 'https://dayonegreat.co'))).status, 'bad_proof', 'a challenge for another address');
    const mine = await db.tx(web, anon, (t) => store.challengeIssue(t, ORIGIN));
    assert.strictEqual((await viaDb(BK.proof(BK.make(), mine))).status, 'bad_proof', 'the database checks the signature itself');
    const mine2 = await db.tx(web, anon, (t) => store.challengeIssue(t, ORIGIN));
    assert.strictEqual((await viaDb(BK.proof(b.key, mine2))).status, 'ok', 'the real browser\'s signature, through the same path');
    const [{ n: sessions }] = await owner(`select count(*)::int as n from app.sessions s join app.browser_keys k on k.member_id = s.member_id where k.id = '${b.keyId}'`);
    assert.ok(sessions >= 1);
  });

  test('wrong PINs in this browser: the 3rd locks the account for 15 minutes (V-222432), the 5th tells Aaron and the member, the 10th cancels this browser\'s key; after the lock GitHub signs in, and the key file adds the browser again', async () => {
    const b = browser();
    await lane1(b, { id: 9006, login: 'forgetful', file: FILE_A });
    const id = (await me(b)).member_id;
    signedOut(b);
    const keyId = b.keyId;
    // A right PIN resets the count: 3 wrong, then (after the lock) right, then 9 wrong still leaves the key.
    for (let i = 0; i < 2; i++) assert.strictEqual((await lane3(b, { pin: '246813' })).tries_left, 9 - i);
    assert.strictEqual((await lane3(b, { pin: '246813' })).refused, 'locked', 'the 3rd makes the lock, and the answer says so');
    // The 3rd failure locked the account (V-222432). While it is locked no PIN is tested or counted: the right PIN and a
    // wrong one get the same answer, so a guesser learns nothing (the review of 053, H1). Each failure, the lock and each
    // refusal are in the audit log, as failures.
    const failedNow = async () => (await owner(`select failed from app.browser_keys where id = '${keyId}'`))[0].failed;
    assert.strictEqual((await lane3(b)).refused, 'locked', 'the right PIN');
    assert.strictEqual((await lane3(b, { pin: '246813' })).refused, 'locked', 'a wrong PIN, the same answer');
    assert.strictEqual(await failedNow(), 3, 'and nothing was counted');
    assert.deepStrictEqual([await audited(id, 'signin.failed'), await audited(id, 'signin.locked'), await audited(id, 'signin.refused')], [3, 1, 2]);
    await passLock(id);
    assert.strictEqual((await lane3(b)).signed_in, true);
    signedOut(b);
    const alerts = async () => (await owner(`select title from app.notices where member_id is null and kind = 'alert' and subject_id = '${id}' and dedupe_key like 'watch:pin%' order by created_at`)).map((r) => r.title);
    const notes = async () => (await owner(`select title from app.notices where member_id = '${id}' and kind = 'signin_pin' and title <> 'Sign-in locked for 15 minutes' order by created_at`)).map((r) => r.title);
    for (let i = 1; i <= 9; i++) {
      // Every 3rd failure locks the account for 15 minutes (stood in for here); the key's own count goes on.
      if (i > 1 && (i - 1) % 3 === 0) await passLock(id);
      const r = await lane3(b, { pin: '246813' });
      if (i % 3 === 0) assert.strictEqual(r.refused, 'locked', 'try ' + i + ' makes the lock');
      else assert.strictEqual(r.tries_left, 10 - i, 'try ' + i);
      if (i === 4) assert.deepStrictEqual(await alerts(), [], 'nothing before the 5th');
      if (i === 5) {
        assert.deepStrictEqual(await alerts(), ['Wrong PINs for one account'], 'the 5th alerts Aaron');
        assert.deepStrictEqual(await notes(), ['Wrong PINs were tried'], 'and tells the member in-app');
      }
    }
    assert.strictEqual((await lane3(b, { pin: '246813' })).refused, 'locked', 'the 9th locked it again');
    await passLock(id);
    const tenth = await lane3(b, { pin: '246813' });
    assert.strictEqual(tenth.cancelled, true, 'the 10th cancels this browser\'s key');
    assert.deepStrictEqual(await alerts(), ['Wrong PINs for one account', 'A member\'s browser key was cancelled']);
    assert.deepStrictEqual(await notes(), ['Wrong PINs were tried', 'A browser of yours was cancelled']);
    assert.strictEqual((await owner(`select count(*)::int as n from app.browser_keys where id = '${keyId}'`))[0].n, 0);
    assert.strictEqual((await lane3(b)).no_key, true, 'even the right PIN no longer works with that key');
    // The key file and PIN add this browser again, and GitHub works.
    assert.strictEqual((await lane2(b, { login: 'forgetful', file: FILE_A })).signed_in, true);
    assert.strictEqual((await me(b)).member_id, id);
    const c2 = browser();
    assert.strictEqual((await lane1(c2, { id: 9006, login: 'forgetful', file: FILE_B, pin: '864209' })).signed_in, true, 'the GitHub lane');
    assert.strictEqual((await me(c2)).member_id, id, 'the same account');
  });

  test('wrong PINs with the key file: the 3rd locks the account for 15 minutes, the 5th alerts, the 10th cancels the key file; then the GitHub lane works and sets a new PIN', async () => {
    const b = browser();
    await lane1(b, { id: 9007, login: 'filepin', file: FILE_A });
    const id = (await me(b)).member_id;
    const thief = browser();
    const pinFailed = async () => (await owner(`select pin_failed from app.file_keys where member_id = '${id}'`))[0].pin_failed;
    for (let i = 1; i <= 9; i++) {
      if (i === 4) {
        // The 3rd failure locked the account, every way in (V-222432): with the right file, the right PIN and a wrong one
        // get the same answer and nothing is counted; the member's own browser is locked too (the review of 053, H1).
        assert.strictEqual((await lane2(thief, { login: 'filepin', file: FILE_A, pin: '975318' })).refused, 'locked');
        assert.strictEqual((await lane2(thief, { login: 'filepin', file: FILE_A })).refused, 'locked', 'the right PIN, the same answer');
        assert.strictEqual(await pinFailed(), 3, 'nothing counted while locked');
        assert.strictEqual((await lane3(b)).refused, 'locked', 'locked, every way in');
      }
      if (i > 1 && (i - 1) % 3 === 0) await passLock(id);
      const r = await lane2(thief, { login: 'filepin', file: FILE_A, pin: '975318' });
      if (i % 3 === 0) assert.strictEqual(r.refused, 'locked', 'try ' + i + ' makes the lock');
      else assert.strictEqual(r.tries_left, 10 - i, 'try ' + i);
    }
    await passLock(id);
    const alerts = (await owner(`select title from app.notices where member_id is null and subject_id = '${id}' and dedupe_key like 'watch:pin5:file:%'`)).map((r) => r.title);
    assert.deepStrictEqual(alerts, ['Wrong PINs for one account']);
    const tenth = await lane2(thief, { login: 'filepin', file: FILE_A, pin: '975318' });
    assert.strictEqual(tenth.start_again, true);
    assert.strictEqual((await owner(`select count(*)::int as n from app.file_keys where member_id = '${id}'`))[0].n, 0, 'the key file is cancelled');
    assert.match((await lane2(browser(), { login: 'filepin', file: FILE_A })).error, /don’t match/, 'even with the right PIN');
    assert.strictEqual((await lane3(b)).signed_in, true, 'the member\'s own browser still signs in');
    const back = browser();
    assert.strictEqual((await lane1(back, { id: 9007, login: 'filepin', file: FILE_B, pin: '520741' })).signed_in, true, 'GitHub, a new file and a new PIN');
    assert.strictEqual((await me(back)).member_id, id);
    assert.match((await owner(`select title from app.notices where member_id = '${id}' and title = 'Your PIN was changed'`))[0].title, /PIN was changed/);
    signedOut(b);
    assert.strictEqual((await lane3(b)).pin_error, true, 'the old PIN no longer works');
    assert.strictEqual((await lane3(b, { pin: '520741' })).signed_in, true, 'the new one does, in every browser');
  });

  test('a PIN anyone would try first is refused when it is set: one digit repeated, runs, short patterns', async () => {
    for (const [i, p] of ['000000', '111111', '123456', '654321', '234567', '901234', '121212', '123123', '112233', '159753'].entries()) {
      const b = browser();
      const s = await call(b, 'codeStart', '/auth/code/start', { body: { login: 'weak' + p, file: FILE_A } });
      await post(9100 + i, 'weak' + p, s.code);
      assert.strictEqual((await call(b, 'codeFinish', '/auth/code/finish')).claimed, true);
      const k = BK.make();
      const out = await call(b, 'codeFinish', '/auth/code/finish', { body: { pin: p, pub: k.pub, label: BK.LABEL, ...BK.proof(k, await challenge(b)) } });
      assert.strictEqual(out.pin_error, true, p);
      assert.match(out.error, /harder to guess/, p);
      // The code is still claimed: a better PIN finishes the sign-in.
      const k2 = BK.make();
      assert.strictEqual((await call(b, 'codeFinish', '/auth/code/finish', { body: { pin: '135792', pub: k2.pub, label: BK.LABEL, ...BK.proof(k2, await challenge(b)) } })).signed_in, true, p);
    }
    assert.deepStrictEqual((await su`select array_agg(app.pin_weak(x) order by x) as w from unnest(array['135792','864209','246813','520741']) x`)[0].w, [false, false, false, false]);
  });

  test('members from before 037 (a key file, no PIN) aren\'t locked out: either of today\'s ways sets their PIN and gives the browser its key, and from then on the file alone signs nobody in', async () => {
    // A database built to 036, a member who signed in by code (so has a key file) under 036's own functions, then 037.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-036-'));
    for (const f of fs.readdirSync(path.join(root, 'db', 'migrations'))) if (f < '037') fs.copyFileSync(path.join(root, 'db', 'migrations', f), path.join(dir, f));
    const NAME2 = NAME + '_old';
    await server.unsafe('create database ' + NAME2);
    const su2 = postgres(at(NAME2), { max: 2, ssl: false, prepare: false, onnotice: () => {} });
    const WEB2 = WEB + '_old';
    let web2;
    try {
      await migrate(su2, { dir });
      await su2.unsafe(`create role ${WEB2} login noinherit password '${PW}'; grant dog_app to ${WEB2}`);
      web2 = db.connect(at(NAME2, WEB2, PW), { ssl: false, max: 2 });
      const run = (ctx, fn) => db.tx(web2, ctx, fn);
      const cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: crypto.randomBytes(32), fingerprintKeys: SITE_KEYS, github: null, x: null };
      const f2 = make({ config: cfg, run, providers: {}, sendEmail: null });
      const loginHash = (l) => c.hmacHex(SITE_KEYS[0].key, 'signin-login:' + l.toLowerCase());
      const fileKey = (l, f) => c.hmacHex(SITE_KEYS[0].key, 'signin-file:' + l.toLowerCase() + ':' + f);
      // Two members as 036 made them: a code, claimed by the gate, signed in with 036's app.code_sign_in.
      const oldMember = async (id, login, file) => {
        const tag = c.token(32); const code = 'DOG-' + crypto.randomBytes(4).toString('hex').toUpperCase().replace(/[^A-HJ-NP-Z2-9]/g, 'A').slice(0, 4) + '-AAAA';
        await run({ actor: 'anon' }, (t) => t`select app.code_issue(${c.hmacHex(SITE_KEYS[0].key, 'signin-code:' + code)}, ${c.sha256hex(tag)}, ${loginHash(login)}, ${fileKey(login, file)})`);
        n += 1;
        await G.handle(su2, { event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1,
          post: { node_id: 'DC_old_' + n, thread_node_id: 'o' + n, body: code, created_at: new Date().toISOString() },
          author: { id, login, type: 'User', created_at: '2015-01-01T00:00:00Z' } }, { key: GATE_KEY });
        const [r] = await run({ actor: 'anon' }, (t) => t`select * from app.code_sign_in(${c.sha256hex(tag)}, 'New member', ${c.sha256hex(c.token(32))}, 30, null)`);
        assert.strictEqual(r.status, 'ok', 'signed in under 036');
        return r.member_id;
      };
      const m1 = await oldMember(9201, 'oldtimer', FILE_A);
      const m2 = await oldMember(9202, 'oldgithub', FILE_A);
      const [{ s: kept }] = await su2.unsafe(`select count(*)::int as s from app.sessions`);
      // Now 037, as the runner applies it.
      await migrate(su2);
      assert.strictEqual((await su2.unsafe(`select count(*)::int as s from app.sessions`))[0].s, kept, 'sessions already issued are untouched');
      assert.strictEqual((await su2.unsafe(`select count(*)::int as n from app.signin_pins`))[0].n, 0, 'nobody has a PIN yet');
      const call2 = async (b, handler, url, opts = {}) => {
        const r = res(); await f2[handler](req('POST', url, { cookie: b.header(), ...opts }), r); b.take(r);
        return { status: r.statusCode, ...JSON.parse(r.body) };
      };
      const ch2 = async (b) => (await call2(b, 'challenge', '/auth/challenge')).challenge;
      // Lane 2 with the key file: the PIN typed becomes their PIN.
      const b = browser(); const k = BK.make();
      // The first PIN is typed twice (the review of 037, L3): once alone is asked again, and nothing is set.
      const once = await call2(b, 'keyFileSignIn', '/auth/key', { body: { login: 'oldtimer', file: FILE_A, pin: '864209', pub: k.pub, label: BK.LABEL, ...BK.proof(k, await ch2(b)) } });
      assert.strictEqual(once.confirm_pin, true);
      assert.match(once.error, /This is your first PIN\. Type it again to set it\./);
      const k1 = BK.make();
      const typo = await call2(b, 'keyFileSignIn', '/auth/key', { body: { login: 'oldtimer', file: FILE_A, pin: '864209', pin_again: '864208', pub: k1.pub, label: BK.LABEL, ...BK.proof(k1, await ch2(b)) } });
      assert.strictEqual(typo.confirm_pin, true, 'two different PINs set nothing');
      assert.strictEqual((await su2.unsafe(`select count(*)::int as n from app.signin_pins where member_id = '${m1}'`))[0].n, 0);
      const out = await call2(b, 'keyFileSignIn', '/auth/key', { body: { login: 'oldtimer', file: FILE_A, pin: '864209', pin_again: '864209', pub: k.pub, label: BK.LABEL, ...BK.proof(k, await ch2(b)) } });
      assert.strictEqual(out.signed_in, true, 'signed in with the key file, as today, once');
      assert.strictEqual((await su2.unsafe(`select count(*)::int as n from app.signin_pins where member_id = '${m1}'`))[0].n, 1, 'and the PIN is set');
      assert.strictEqual((await su2.unsafe(`select count(*)::int as n from app.browser_keys where member_id = '${m1}'`))[0].n, 1, 'and this browser has its key');
      // From now on: the file needs that PIN.
      const thief = browser(); const k2 = BK.make();
      const stolen = await call2(thief, 'keyFileSignIn', '/auth/key', { body: { login: 'oldtimer', file: FILE_A, pin: '135792', pub: k2.pub, label: BK.LABEL, ...BK.proof(k2, await ch2(thief)) } });
      assert.strictEqual(stolen.pin_error, true, 'the file with any other PIN is refused');
      // And the database refuses the old PIN-less way for the site's login, for every member.
      await assert.rejects(run({ actor: 'anon' }, (t) => t`select * from app.file_sign_in(${loginHash('oldgithub')}, ${fileKey('oldgithub', FILE_A)}, 'x', ${c.sha256hex(c.token(32))}, 30, null)`),
        /permission denied/, 'the key file alone is no longer a way in, even from the site\'s own database login');
      await assert.rejects(run({ actor: 'anon' }, (t) => t`select * from app.code_sign_in(${'a'.repeat(64)}, 'x', ${c.sha256hex(c.token(32))}, 30, null)`), /permission denied/);
      // Lane 1 (GitHub) for the other: a new PIN and this browser's key, the same account.
      const g = browser();
      const s = await call2(g, 'codeStart', '/auth/code/start', { body: { login: 'oldgithub', file: FILE_B } });
      n += 1;
      await G.handle(su2, { event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1,
        post: { node_id: 'DC_old_' + n, thread_node_id: 'o' + n, body: s.code, created_at: new Date().toISOString() },
        author: { id: 9202, login: 'oldgithub', type: 'User', created_at: '2015-01-01T00:00:00Z' } }, { key: GATE_KEY });
      assert.strictEqual((await call2(g, 'codeFinish', '/auth/code/finish')).claimed, true);
      const k3 = BK.make();
      const o3 = await call2(g, 'codeFinish', '/auth/code/finish', { body: { pin: '246813', pub: k3.pub, label: BK.LABEL, ...BK.proof(k3, await ch2(g)) } });
      assert.strictEqual(o3.signed_in, true);
      const [{ mid }] = await su2.unsafe(`select member_id as mid from app.browser_keys where id = '${o3.key_id}'`);
      assert.strictEqual(mid, m2, 'the same account it always was');
    } finally {
      if (web2) await web2.end({ timeout: 5 });
      await su2.end({ timeout: 5 });
      await server.unsafe(`drop database if exists ${NAME2} with (force)`);
      await server.unsafe(`drop role if exists ${WEB2}`);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('the review of 037, H1: the only functions the site\'s role can run that make a session are the three ways in, and the buyer door (063)', async () => {
    // Which functions make a session: those whose body inserts into app.sessions, and every function that calls one of
    // them, found from the bodies themselves, so a function added later is covered without editing this list.
    const fns = await owner(`select p.oid::regprocedure::text as sig, p.proname as name, p.prosrc as src,
      has_function_privilege('dog_app', p.oid, 'EXECUTE') as app from pg_proc p where p.pronamespace = 'app'::regnamespace`);
    const makes = new Set(fns.filter((f) => /insert\s+into\s+app\.sessions\b/i.test(f.src)).map((f) => f.name));
    for (let grew = true; grew;) {
      grew = false;
      for (const f of fns) {
        if (makes.has(f.name)) continue;
        if ([...makes].some((m) => new RegExp('\\bapp\\.' + m + '\\s*\\(').test(f.src))) { makes.add(f.name); grew = true; }
      }
    }
    assert.ok(makes.has('sign_in_core') && makes.has('sign_in'), 'the search finds the known ones: ' + [...makes].join(', '));
    const reachable = fns.filter((f) => f.app && makes.has(f.name)).map((f) => f.name).sort();
    // 063 (Aaron, Nov 11): the buyer door's two, each checking a WebAuthn signature in the database (test/buyer-keys.test.js).
    assert.deepStrictEqual(reachable, ['browser_sign_in', 'buyer_register', 'buyer_sign_in', 'code_sign_in_pin', 'file_sign_in_pin'],
      'app.sign_in (the switched-off GitHub, X and email sign-ins), app.code_sign_in and app.file_sign_in are the sign-in role\'s only');
    // And the site's role really is refused: the review's R1, a session for a member by naming their fingerprint.
    await assert.rejects(web.begin(async (t) => { await t`set local role dog_app`;
      await t`select * from app.sign_in('github', ${[c.sha256hex('anyone')]}::text[], 1::smallint, 1::smallint, 'x', ${c.sha256hex('s')}, 30, null::timestamptz, null::uuid, null::text)`; }),
      /permission denied for function sign_in/);
    // The flow for those sign-ins, in production (no runOff), makes no session either.
    assert.match(read('signin/flow.js'), /const runOff = deps\.runOff \|\| run;/);
    assert.match(read('db/README.md'), /Switching any of them on needs the browser key and PIN step first/);
  });

  test('the review of 037, M2: the site checks lane 3\'s signature itself too, so a fault in the database\'s check alone signs nobody in', async () => {
    const b = browser();
    await lane1(b, { id: 9301, login: 'm2member' });
    signedOut(b);
    // Break the database's own check on purpose: it now accepts any signature.
    const real = (await owner(`select pg_get_functiondef('app.p256_verify(bytea, bytea, bytea)'::regprocedure) as d`))[0].d;
    await su.unsafe(`create or replace function app.p256_verify(pub bytea, msg bytea, sig bytea) returns boolean language sql immutable set search_path = pg_catalog as $$ select true $$`);
    try {
      const forged = { challenge: await challenge(b), sig: Buffer.alloc(64, 7).toString('base64url') };
      const out = await lane3(b, { proof: forged });
      assert.strictEqual(out.signed_in, undefined, 'a forged signature with the right PIN is refused by the site\'s own check');
      assert.strictEqual(out.retry, true);
      const [{ failed }] = await owner(`select failed from app.browser_keys where id = '${b.keyId}'`);
      assert.strictEqual(failed, 0, 'and no PIN was tested');
    } finally {
      await su.unsafe(real);
    }
    assert.strictEqual((await lane3(b)).signed_in, true, 'the real browser still signs in');
    assert.doesNotMatch(read('signin/flow.js'), /proofOf\(form, null\)/);
    assert.match(read('signin/flow.js'), /if \(!pub \|\| !c\.p256Verify\(/);
  });

  test('the review of 037, M3 (Aaron, Nov 5), with 053 (Nov 8, the STIG): 3 wrong key files tell the member, pause the key file for 10 minutes and lock the account for 15; a stranger can\'t cancel the key file', async () => {
    const b = browser();
    await lane1(b, { id: 9302, login: 'm3member', file: FILE_A });
    const id = (await me(b)).member_id;
    signedOut(b);
    const stranger = browser();
    const answers = [];
    for (let round = 0; round < 4; round++) {
      for (let i = 0; i < 3; i++) answers.push(await lane2(stranger, { login: 'm3member', file: sha('guess ' + round + ' ' + i) }));
      // Aaron, Nov 8 (V-222432): the account is locked, every way in, this browser too, for 15 minutes; the member and
      // Aaron are told. (Before, under "checks alert, never lock out", this browser and GitHub stayed open.)
      if (round === 0) {
        assert.strictEqual((await lane3(b)).refused, 'locked', 'this browser (lane 3) is locked too');
        assert.strictEqual((await owner(`select count(*)::int as n from app.notices where member_id = '${id}' and title = 'Sign-in locked for 15 minutes'`))[0].n, 1);
        assert.strictEqual(await audited(id, 'signin.locked'), 1);
        assert.strictEqual((await lane2(browser(), { login: 'm3member', file: FILE_A })).refused, 'locked', 'even the right file waits out the lock');
      }
      await owner(`update app.file_keys set paused_until = now() - interval '1 second' where member_id = '${id}'`);
      await passLock(id);
    }
    // Each 3rd wrong file pauses the key file; these 3 came fast, so they also locked the account, and the answer says so.
    assert.strictEqual(answers.filter((a) => a.refused === 'locked').length, 4, 'every 3rd wrong file pauses it and, this fast, locks the account');
    assert.ok(!answers.some((a) => a.start_again), 'wrong files never cancel the key file');
    assert.strictEqual((await owner(`select count(*)::int as n from app.file_keys where member_id = '${id}'`))[0].n, 1);
    const notes = await owner(`select title from app.notices where member_id = '${id}' and title = 'Key-file sign-in paused for 10 minutes'`);
    assert.ok(notes.length >= 1, 'the member is told in-app');
    assert.strictEqual((await lane2(browser(), { login: 'm3member', file: FILE_A })).signed_in, true, 'after the pause the right file works');
    const c2 = browser();
    assert.strictEqual((await lane1(c2, { id: 9302, login: 'm3member', file: FILE_A })).signed_in, true, 'and GitHub always did');
    // 053: a new code is refused while the account is locked, and that refusal is recorded too (the second review of 053, 6).
    for (let i = 0; i < 3; i++) await lane2(stranger, { login: 'm3member', file: sha('code lane ' + i) });
    assert.strictEqual((await lane1(browser(), { id: 9302, login: 'm3member', file: FILE_A })).refused, 'locked');
    assert.ok((await owner(`select count(*)::int as n from app.audit_log where subject_id = '${id}' and action = 'signin.refused' and detail->>'lane' = 'code'`))[0].n >= 1);
    await owner(`update app.file_keys set paused_until = now() - interval '1 second' where member_id = '${id}'`);
    await passLock(id);
    // 053 (V-222462): a key file for a username nobody has is recorded too, with no account to count against.
    const before = (await owner(`select count(*)::int as n from app.audit_log where action = 'signin.failed' and subject_id is null and detail->>'reason' = 'no_account'`))[0].n;
    assert.match((await lane2(browser(), { login: 'nobody-here-053', file: FILE_A })).error, /don’t match/);
    assert.strictEqual((await owner(`select count(*)::int as n from app.audit_log where action = 'signin.failed' and subject_id is null and detail->>'reason' = 'no_account'`))[0].n, before + 1);
    // Only that username is paused.
    const other = browser();
    await lane1(other, { id: 9303, login: 'm3other', file: FILE_B });
    for (let i = 0; i < 3; i++) await lane2(stranger, { login: 'm3member', file: sha('again ' + i) });
    assert.strictEqual((await lane2(browser(), { login: 'm3other', file: FILE_B })).signed_in, true, 'another member\'s account is untouched');
  });

  test('the third review of 053, M1: 3 wrong key files more than 15 minutes apart pause the key file but lock nothing, and the words say only that', async () => {
    const b = browser();
    await lane1(b, { id: 9310, login: 'slowguess', file: FILE_A });
    const id = (await me(b)).member_id;
    signedOut(b);
    const stranger = browser();
    const older = () => su.unsafe(`update app.signin_failures set at = at - interval '16 minutes' where member_id = '${id}'`);
    for (let i = 0; i < 2; i++) { await lane2(stranger, { login: 'slowguess', file: sha('slow ' + i) }); await older(); }
    const third = await lane2(stranger, { login: 'slowguess', file: sha('slow 2') });
    assert.strictEqual(third.paused, true, 'paused, not locked');
    assert.doesNotMatch(third.error, /locked/);
    assert.strictEqual((await owner(`select count(*)::int as n from app.signin_locks where member_id = '${id}'`))[0].n, 0);
    const [note] = await owner(`select body from app.notices where member_id = '${id}' and title = 'Key-file sign-in paused for 10 minutes' order by created_at desc limit 1`);
    assert.match(note.body, /still sign you in/);
    assert.doesNotMatch(note.body, /locked/);
    assert.strictEqual((await lane3(b)).signed_in, true, 'the member\'s own browser signs in');
  });

  test('the fourth review of 053, L-1: whichever wrong try makes the lock answers "locked", never "try again" or "get a new code"', async () => {
    const b = browser();
    await lane1(b, { id: 9311, login: 'mixedtries', file: FILE_A });
    const id = (await me(b)).member_id;
    signedOut(b);
    for (let i = 0; i < 2; i++) assert.ok((await lane3(b, { pin: '246813' })).tries_left > 0);
    // A wrong key file is the 3rd failure in 15 minutes: the answer is the lock, not "don't match".
    assert.strictEqual((await lane2(browser(), { login: 'mixedtries', file: sha('mixed') })).refused, 'locked');
    assert.strictEqual((await owner(`select count(*)::int as n from app.signin_locks where member_id = '${id}'`))[0].n, 1);
    await passLock(id);
    // The same with a wrong PIN as the 3rd.
    await lane2(browser(), { login: 'mixedtries', file: sha('mixed 2') });
    await lane3(b, { pin: '246813' });
    assert.strictEqual((await lane3(b, { pin: '246813' })).refused, 'locked');
  });

  test('the review of 037, L1: a sign-in the database refuses (a banned member) still uses up its challenge, so the same signed request never works again', async () => {
    const b = browser();
    await lane1(b, { id: 9304, login: 'l1member' });
    const id = (await me(b)).member_id;
    signedOut(b);
    const status = (x) => su.begin(async (t) => { await t.unsafe('alter table app.members disable trigger members_guard'); await t.unsafe(`update app.members set status = '${x}' where id = '${id}'`); await t.unsafe('alter table app.members enable trigger members_guard'); });
    await status('banned');
    try {
      const p = BK.proof(b.key, await challenge(b));
      const first = await lane3(b, { proof: p });
      assert.strictEqual(first.refused, 'banned');
      const [ch] = await owner(`select used_at is not null as used from app.signin_challenges where challenge_hash = '${sha(p.challenge)}'`);
      assert.strictEqual(ch.used, true, 'the challenge is used up although the sign-in was refused');
      await status('active');
      const again = await lane3(b, { proof: p });
      assert.strictEqual(again.retry, true, 'the same signed request, once the ban is lifted, is refused');
    } finally {
      await status('active');
    }
  });

  test('the review of 037, L2: when lane 1 sets a PIN again, the member\'s other browsers can be removed in the same step (offered, on by default)', async () => {
    const b = browser();
    await lane1(b, { id: 9305, login: 'l2member', file: FILE_A });
    const id = (await me(b)).member_id;
    const laptop = browser();
    await lane2(laptop, { login: 'l2member', file: FILE_A });
    const count = async () => (await owner(`select count(*)::int as n from app.browser_keys where member_id = '${id}'`))[0].n;
    assert.strictEqual(await count(), 2);
    // A new code: once claimed, the page learns the account has a PIN and 2 browsers, so it offers to remove them.
    const g = browser();
    const s1 = await call(g, 'codeStart', '/auth/code/start', { body: { login: 'l2member', file: FILE_B } });
    await post(9305, 'l2member', s1.code);
    const claimed = await call(g, 'codeFinish', '/auth/code/finish');
    assert.deepStrictEqual([claimed.claimed, claimed.has_pin, claimed.browsers], [true, true, 2]);
    const k = BK.make();
    const out = await call(g, 'codeFinish', '/auth/code/finish', { body: { pin: '864209', remove_others: '1', pub: k.pub, label: BK.LABEL, ...BK.proof(k, await challenge(g)) } });
    assert.strictEqual(out.signed_in, true);
    assert.strictEqual(await count(), 1, 'only the new browser is left');
    const [note] = await owner(`select body from app.notices where member_id = '${id}' and title = 'Your PIN was changed' order by created_at desc limit 1`);
    assert.match(note.body, /your other browsers \(2\) were removed/);
    signedOut(laptop);
    assert.strictEqual((await lane3(laptop, { pin: '864209' })).no_key, true, 'the old browser can\'t try the new PIN');
    // Without it, they stay.
    const g2 = browser();
    const s2 = await call(g2, 'codeStart', '/auth/code/start', { body: { login: 'l2member', file: FILE_A } });
    await post(9305, 'l2member', s2.code);
    await call(g2, 'codeFinish', '/auth/code/finish');
    const k2 = BK.make();
    assert.strictEqual((await call(g2, 'codeFinish', '/auth/code/finish', { body: { pin: '520741', pub: k2.pub, label: BK.LABEL, ...BK.proof(k2, await challenge(g2)) } })).signed_in, true);
    assert.strictEqual(await count(), 2);
    assert.match(read('join/pin.html'), /<input id="pin-remove-others" name="remove_others" type="checkbox" checked>/, 'the step offers it, on by default');
  });

  test('the site\'s role reads no PIN, key or challenge table, and can\'t make or test a PIN itself', async () => {
    for (const tbl of ['app.pin_keys', 'app.signin_pins', 'app.browser_keys', 'app.signin_challenges']) {
      await assert.rejects(web.begin(async (t) => { await t`set local role dog_app`; await t.unsafe('select * from ' + tbl); }), /permission denied/, tbl);
    }
    for (const q of [`select app.pin_digest(gen_random_uuid(), '\\x00'::bytea, '135792')`, `select app.pin_matches(gen_random_uuid(), '135792')`,
      `select app.pin_store(gen_random_uuid(), '135792')`, `select app.signin_proof('\\x00'::bytea, 'x', 'x', '\\x00'::bytea)`]) {
      await assert.rejects(web.begin(async (t) => { await t`set local role dog_app`; await t.unsafe(q); }), /permission denied/, q);
    }
  });

  test('the account page lists this browser and others with a way to remove one, the PIN and the key file; the PIN changes with the current one; sign out everywhere cancels every browser', async () => {
    const b = browser();
    await lane1(b, { id: 9008, login: 'acct', file: FILE_A });
    const laptop = browser();
    await lane2(laptop, { login: 'acct', file: FILE_A });
    const account = async (x) => { const r = res(); await flow.account(req('GET', '/auth/account', { cookie: x.header() }), r); return JSON.parse(r.body); };
    const a = await account(b);
    assert.ok(a.pin && a.pin.set_at, 'the PIN is set (never shown)');
    assert.ok(a.key_file && a.key_file.created_at, 'the key file');
    assert.deepStrictEqual(a.browsers.map((x) => x.id).sort(), [b.keyId, laptop.keyId].sort());
    assert.ok(a.browsers.every((x) => x.label === 'Firefox on Linux' && x.added && !('public_key' in x)));
    const form = async (x, handler, url, body) => { const r = res(); await flow[handler](req('POST', url, { cookie: x.header(), body }), r); x.take(r); return r.headers.location; };
    // Removing the laptop's browser from the phone: it no longer signs in, and the member is told.
    assert.strictEqual(await form(b, 'browserRemove', '/auth/account/browser/remove', { id: laptop.keyId }), '/account?saved=browser_removed#browsers');
    signedOut(laptop);
    assert.strictEqual((await lane3(laptop)).no_key, true);
    assert.strictEqual(await form(b, 'browserRemove', '/auth/account/browser/remove', { id: laptop.keyId }), '/account?error=browser#browsers', 'gone already');
    // Someone else's browser can't be removed.
    const other = browser();
    await lane1(other, { id: 9009, login: 'acct-other' });
    assert.strictEqual(await form(b, 'browserRemove', '/auth/account/browser/remove', { id: other.keyId }), '/account?error=browser#browsers');
    // Changing the PIN.
    assert.strictEqual(await form(b, 'pinChange', '/auth/account/pin', { current: PIN, next: '864209', again: '864201' }), '/account?error=pin_again#pin');
    assert.strictEqual(await form(b, 'pinChange', '/auth/account/pin', { current: PIN, next: '123456', again: '123456' }), '/account?error=pin_weak#pin');
    assert.strictEqual(await form(b, 'pinChange', '/auth/account/pin', { current: '000001', next: '864209', again: '864209' }), '/account?error=pin_wrong&left=9#pin');
    assert.strictEqual(await form(b, 'pinChange', '/auth/account/pin', { current: PIN, next: '864209', again: '864209' }), '/account?saved=pin#pin');
    signedOut(b);
    assert.strictEqual((await lane3(b, { pin: '864209' })).signed_in, true, 'the new PIN signs in');
    // 10 wrong current PINs sign that session out (the account stays open).
    let last;
    // Wrong current PINs are failed checks too: the 3rd locks the account (V-222432), and while it is locked no current
    // PIN is tested or counted; this browser stays signed in (the review of 053, H1).
    for (let i = 0; i < 3; i++) last = await form(b, 'pinChange', '/auth/account/pin', { current: '000002', next: '975318', again: '975318' });
    assert.strictEqual(last, '/account?error=pin_locked#pin', 'the 3rd makes the lock, and says so');
    assert.strictEqual(await form(b, 'pinChange', '/auth/account/pin', { current: '864209', next: '975318', again: '975318' }), '/account?error=pin_locked#pin', 'even the right PIN, while locked');
    assert.strictEqual((await me(b)).signed_in, true, 'still signed in');
    const acct = (await owner(`select member_id from app.browser_keys where id = '${b.keyId}'`))[0].member_id;
    // Past each lock (stood in for here), 10 wrong current PINs sign that session out (the account stays open).
    for (let i = 3; i < 10; i++) {
      if (i % 3 === 0) await passLock(acct);
      last = await form(b, 'pinChange', '/auth/account/pin', { current: '000002', next: '975318', again: '975318' });
    }
    assert.strictEqual(last, '/join?error=pin_signed_out');
    assert.strictEqual((await me(b)).signed_in, false);
    // The last lock was passed before the 10th, so the member signs straight back in.
    assert.strictEqual((await lane3(b, { pin: '864209' })).signed_in, true, 'and signs back in');
    // Sign out everywhere: every session, the key file and every browser key go; GitHub brings the member back.
    const out = res(); await flow.logout(req('POST', '/auth/logout-all', { cookie: b.header() }), out, true); b.take(out);
    assert.strictEqual((await owner(`select count(*)::int as n from app.browser_keys where id = '${b.keyId}'`))[0].n, 0, 'every browser key of the member is gone');
    assert.strictEqual((await lane3(b, { pin: '864209' })).no_key, true, 'this browser\'s key is cancelled too');
  });

  test('the administrator signs in by the same three ways, all checked in the database', async () => {
    const a = browser();
    await lane1(a, { id: 9010, login: 'chief2', file: FILE_A });
    const id = (await me(a)).member_id;
    await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${id}'`); });
    signedOut(a);
    assert.strictEqual((await lane3(a)).signed_in, true, 'lane 3');
    const r = res(); await flow.me(req('GET', '/auth/me', { cookie: a.header() }), r);
    const [s] = await owner(`select m.is_admin from app.sessions s join app.members m on m.id = s.member_id where s.token_hash = '${c.sha256hex(a.get(SESSION))}'`);
    assert.strictEqual(s.is_admin, true);
    assert.strictEqual((await lane2(browser(), { login: 'chief2', file: FILE_A })).signed_in, true, 'lane 2');
    await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = false where id = '${id}'`); });
  });

  test('challenges: same-site only, at most 60 per network in 10 minutes, and cleared an hour after they expire', async () => {
    const b = browser();
    assert.strictEqual((await call(b, 'challenge', '/auth/challenge', { origin: 'https://evil.example' })).status, 403);
    const ip = '192.0.2.200';
    await clearOfWindow(600);
    for (let i = 0; i < 60; i++) assert.match((await call(b, 'challenge', '/auth/challenge', { ip })).challenge, /^[A-Za-z0-9_-]{43}$/);
    assert.strictEqual((await call(b, 'challenge', '/auth/challenge', { ip })).status, 429);
    await owner(`update app.signin_challenges set expires_at = now() - interval '2 hours'`);
    await challenge(b);
    assert.strictEqual((await owner(`select count(*)::int as n from app.signin_challenges where expires_at < now() - interval '1 hour'`))[0].n, 0);
    const [row] = await owner(`select origin, expires_at <= now() + interval '2 minutes' as short from app.signin_challenges order by created_at desc limit 1`);
    assert.deepStrictEqual({ ...row }, { origin: ORIGIN, short: true });
  });
}
