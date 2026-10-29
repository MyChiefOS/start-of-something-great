// Release 2, PR 2: sign-in and trust levels (S5, S6, S12, SF4, F1, F10), end to end against a real Postgres with
// fake GitHub and X that check PKCE the way the real ones do. Needs TEST_DATABASE_URL like test/db.test.js.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const h = require('../signin/http');
const config = require('../signin/config');
const { PROVIDERS } = require('../signin/providers');
const { make, SESSION } = require('../signin/flow');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');
const { trustSystem, TEST_SYSTEM_SECRET, promote } = require('./helpers');
// Acting as an administrator straight in the database (the test superuser), with the proof the site gives (fix 3):
// app.act_as, as db/index.js calls it, with the administrator's own session. Settings set by hand now count for nothing.
const actAsAdmin = (t, ctx) => t`select app.act_as('admin', ${ctx.memberId}::uuid, null, false, ${ctx.session}, null, null)`;
// The same for the site itself (the timers), with its own secret.
const actAsSystem = (t) => t`select app.act_as('system', null, null, false, null, null, ${TEST_SYSTEM_SECRET})`;

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const key = () => crypto.randomBytes(32).toString('base64');

// ---- Fake requests and responses -------------------------------------------------------------------------------
function req(method, url, { cookie = '', origin, body, ip = '203.0.113.7', host = 'dayonegreat.com', site } = {}) {
  const headers = { host, cookie, 'x-vercel-forwarded-for': ip };
  if (origin) headers.origin = origin;
  if (site) headers['sec-fetch-site'] = site;
  if (body !== undefined) headers['content-type'] = 'application/x-www-form-urlencoded';
  return { method, url, headers, body: body === undefined ? undefined : new URLSearchParams(body).toString(), query: {} };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
// A browser's cookie jar, enough for these flows: keeps __Host- cookies and drops cleared ones.
function jar() {
  const j = {};
  return {
    take(r) {
      for (const sc of [].concat(r.getHeader('Set-Cookie') || [])) {
        const [pair, ...attrs] = sc.split(';').map((s) => s.trim());
        const [name, value] = [pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1)];
        if (/Max-Age=0/.test(sc) || !value) delete j[name]; else j[name] = value;
        assert.ok(name.startsWith('__Host-'), name + ' must be a __Host- cookie');
        for (const a of ['Path=/', 'Secure', 'HttpOnly', 'SameSite=Lax']) assert.ok(attrs.includes(a), name + ' lacks ' + a);
        assert.ok(!attrs.some((a) => /^Domain=/i.test(a)), name + ' must not set Domain');
      }
      return r;
    },
    header() { return Object.entries(j).map(([k, v]) => k + '=' + v).join('; '); },
    get(name) { return j[name]; },
    set(name, value) { j[name] = value; }
  };
}

// Fake providers: they remember the PKCE challenge for each state and refuse a code exchange whose verifier doesn't
// match it, as GitHub and X do.
function fakeProviders(accounts) {
  const challenges = new Map();
  const make1 = (name) => ({
    redirectUri: ORIGIN + '/auth/' + name + '/callback',
    authorizeUrl(cr, { state, challenge }) { challenges.set(state, challenge); return 'https://' + name + '.example/authorize?state=' + state; },
    async identify(cr, { code, verifier }) {
      const [state, account] = code.split('|');
      const want = challenges.get(state);
      challenges.delete(state);
      if (!want || crypto.createHash('sha256').update(verifier).digest('base64url') !== want) return null;
      return accounts[name + ':' + account] || null;
    }
  });
  return { github: make1('github'), x: make1('x') };
}

// ---- Tests that need no database -------------------------------------------------------------------------------

test('open redirects: only a path on this site is accepted as the place to return to', () => {
  for (const ok of ['/', '/proposals', '/research/decision-loop?x=1']) assert.strictEqual(h.returnPath(ok), ok);
  for (const bad of ['//evil.com', '/\\evil.com', 'https://evil.com', 'javascript:alert(1)', '/\t/evil.com', ' /x', '', null, '/x\n', '/' + 'a'.repeat(300), '/%0d%0aSet-Cookie:x']) {
    const out = h.returnPath(bad);
    assert.ok(out === '/' || (out === bad && !/[\r\n]/.test(decodeURIComponent(out))), JSON.stringify(bad) + ' -> ' + out);
  }
});

test('S6: rate limits use Vercel\'s own IP header, IPv6 grouped by /64, hashed with a daily key', () => {
  const k = crypto.randomBytes(32);
  const r = (ip, extra = {}) => ({ headers: { 'x-vercel-forwarded-for': ip, ...extra } });
  assert.strictEqual(h.ipRange(r('203.0.113.7')), '203.0.113.7');
  assert.strictEqual(h.ipRange(r('2001:db8:1:2:aaaa::1')), '2001:db8:1:2::/64');
  assert.strictEqual(h.ipRange(r('2001:db8:1:2:aaaa::1')), h.ipRange(r('2001:0db8:0001:0002:ffff:1:2:3')));
  assert.strictEqual(h.ipRange({ headers: { 'x-forwarded-for': '1.2.3.4' } }), 'unknown', 'a header the visitor can set is ignored');
  assert.strictEqual(h.ipRange(r('::ffff:203.0.113.7')), '203.0.113.7', 'an IPv4 address written the IPv6 way');
  assert.notStrictEqual(h.ipKey(r('203.0.113.7'), k, '2026-10-15'), h.ipKey(r('203.0.113.7'), k, '2026-10-16'), 'the key changes daily');
  assert.match(h.ipKey(r('203.0.113.7'), k), /^[0-9a-f]{64}$/);
});

test('sealed state can\'t be read or changed, and fingerprints depend on the key', () => {
  const k = c.subkey(key(), 'oauth state');
  const s = c.seal(k, { s: 'abc', e: 1 });
  assert.deepStrictEqual(c.open(k, s), { s: 'abc', e: 1 });
  const raw = Buffer.from(s, 'base64url'); raw[raw.length - 1] ^= 1;
  assert.strictEqual(c.open(k, raw.toString('base64url')), null, 'a changed cookie is refused');
  assert.strictEqual(c.open(c.subkey(key(), 'oauth state'), s), null, 'another key can\'t open it');
  // Encrypted, so the contents can't be read from it. Checked with a long value: a 3-letter one like 'abc' turns up
  // in random base64url text now and then, which made this test fail by chance.
  const secret = 'state-value-that-must-never-appear-in-the-cookie';
  const sealed = c.seal(k, { s: secret });
  assert.ok(!sealed.includes(secret) && !Buffer.from(sealed, 'base64url').includes(Buffer.from(secret)));
  assert.ok(!sealed.includes(Buffer.from(JSON.stringify({ s: secret })).toString('base64url').slice(0, 40)), 'not merely encoded');
  const k1 = { version: 1, key: crypto.randomBytes(32) }, k2 = { version: 2, key: crypto.randomBytes(32) };
  const [a, b] = c.fingerprints([k2, k1], 'github', '12345');
  assert.notStrictEqual(a, b);
  assert.notStrictEqual(c.fingerprints([k1], 'x', '12345')[0], b, 'the provider is part of the fingerprint');
  assert.ok(!a.includes('12345'));
  assert.strictEqual(config.parseKeys('1:' + Buffer.alloc(16).toString('base64')), null, 'keys shorter than 32 bytes are refused');
  assert.strictEqual(config.parseKeys('1:' + key() + ',1:' + key()), null, 'duplicate versions are refused');
  const env = { FINGERPRINT_KEY_1: key(), FINGERPRINT_KEY_2: key(), FINGERPRINT_KEY_X: key(), OTHER: 'x' };
  assert.deepStrictEqual(config.keysFromEnv(env).map((k) => k.version), [2, 1], 'one setting per key; the highest number is current');
  assert.strictEqual(config.keysFromEnv({}), null);
  assert.strictEqual(config.keysFromEnv({ FINGERPRINT_KEY_1: 'short' }), null, 'a weak key switches sign-in off');
});

test('CSRF: posts must come from our own pages', () => {
  assert.ok(h.sameSite({ headers: { origin: ORIGIN } }));
  assert.ok(h.sameSite({ headers: { origin: ORIGIN, 'sec-fetch-site': 'same-origin' } }));
  assert.ok(!h.sameSite({ headers: {} }), 'no Origin');
  assert.ok(!h.sameSite({ headers: { origin: 'https://evil.com' } }));
  assert.ok(!h.sameSite({ headers: { origin: 'https://dayonegreat.com.evil.com' } }));
  assert.ok(!h.sameSite({ headers: { origin: ORIGIN, 'sec-fetch-site': 'cross-site' } }));
  assert.ok(!h.sameSite({ headers: { origin: 'http://dayonegreat.com' } }), 'plain HTTP');
});

test('GitHub and X requests use PKCE (S256), our exact callback address per provider, and a state', () => {
  const g = new URL(PROVIDERS.github.authorizeUrl({ clientId: 'id' }, { state: 'st', challenge: 'ch' }));
  assert.strictEqual(g.origin + g.pathname, 'https://github.com/login/oauth/authorize');
  assert.strictEqual(g.searchParams.get('redirect_uri'), ORIGIN + '/auth/github/callback');
  assert.strictEqual(g.searchParams.get('code_challenge_method'), 'S256');
  assert.strictEqual(g.searchParams.get('state'), 'st');
  assert.strictEqual(g.searchParams.get('scope'), '', 'GitHub: no scopes, public identity only');
  const x = new URL(PROVIDERS.x.authorizeUrl({ clientId: 'id' }, { state: 'st', challenge: 'ch' }));
  assert.strictEqual(x.origin + x.pathname, 'https://x.com/i/oauth2/authorize');
  assert.strictEqual(x.searchParams.get('redirect_uri'), ORIGIN + '/auth/x/callback');
  assert.strictEqual(x.searchParams.get('code_challenge_method'), 'S256');
  assert.strictEqual(x.searchParams.get('scope'), 'tweet.read users.read');
});

test('the sign-in endpoint is off unless fully set up, and only answers on dayonegreat.com', async () => {
  const saved = { ...process.env };
  for (const k of Object.keys(process.env).filter((x) => /^(SESSION_SECRET|FINGERPRINT_KEY_\d+|IP_HASH_KEY|DATABASE_URL)$/.test(x))) delete process.env[k];
  try {
    delete require.cache[require.resolve('../api/auth.js')];
    const auth = require('../api/auth.js');
    const r1 = res(); await auth({ ...req('GET', '/auth/me'), query: { route: 'me' } }, r1);
    assert.strictEqual(r1.statusCode, 503);
    const r2 = res(); await auth({ ...req('GET', '/auth/nope'), query: { route: 'nope' } }, r2);
    assert.strictEqual(r2.statusCode, 404);
    const r3 = res(); await auth({ ...req('GET', '/auth/logout'), query: { route: 'logout' } }, r3);
    assert.strictEqual(r3.statusCode, 405, 'logging out is a POST, never a link');
  } finally { process.env = saved; delete require.cache[require.resolve('../api/auth.js')]; }
  assert.ok(!h.onSite({ headers: { host: 'start-of-something-great-git-x-chief-os.vercel.app' } }), 'previews are off');
  assert.ok(!h.onSite({ headers: { host: 'dayonegreat.ai' } }));
  assert.ok(h.onSite({ headers: { host: 'dayonegreat.com' } }));
});

test('the router sends each address to the right step, with the right provider and logout scope', async () => {
  const { ROUTES } = require('../api/auth.js');
  const calls = [];
  const fake = new Proxy({}, { get: (_, name) => (...args) => calls.push([name, ...args.slice(2)]) });
  for (const k of Object.keys(ROUTES)) await ROUTES[k](fake, {}, {});
  assert.deepStrictEqual(calls, [['start', 'github'], ['callback', 'github'], ['start', 'x'], ['callback', 'x'], ['emailStart'],
    ['emailContinue'], ['emailFinish'], ['logout', false], ['logout', true], ['me'], ['account'], ['rename'], ['deleteAccount'], ['unlink'], ['formToken'],
    ['regionContinue'], ['regionCancel'], ['codeStart'], ['codeFinish'], ['keyFileSignIn']]);
  assert.deepStrictEqual(Object.keys(ROUTES).filter((k) => k.startsWith('POST')),
    ['POST email/start', 'POST email/finish', 'POST logout', 'POST logout-all', 'POST account/name', 'POST account/delete', 'POST account/unlink',
      'POST region/continue', 'POST region/cancel', 'POST code/start', 'POST code/finish', 'POST key'],
    'only these change anything, and all are POSTs');
});

test('form bodies: read the same whether Vercel has already parsed them or not, and refused when too big', async () => {
  const typed = { 'content-type': 'application/x-www-form-urlencoded' };
  assert.deepStrictEqual(await h.form({ headers: typed, body: { t: 'abc' } }), { t: 'abc' });
  assert.deepStrictEqual(await h.form({ headers: typed, body: 't=abc&confirm=1' }), { t: 'abc', confirm: '1' });
  assert.deepStrictEqual(await h.form({ headers: typed, body: undefined, [Symbol.asyncIterator]: async function* () { yield Buffer.from('t=abc'); } }), { t: 'abc' });
  assert.strictEqual(await h.form({ headers: typed, body: 't=' + 'x'.repeat(3000) }), null);
  assert.strictEqual(await h.form({ headers: typed, body: { t: 'x'.repeat(3000) } }), null);
  assert.strictEqual(await h.form({ headers: { 'content-type': 'application/json' }, body: { t: 'abc' } }), null);
});

test('SF4, S5: the join page signs people in with GitHub through giscus: two fields at most, no password, no form', () => {
  const html = fs.readFileSync(path.join(root, 'join.html'), 'utf8');
  const fields = html.match(/<(input|select|textarea|form)\b[^>]*>/g) || [];
  // Phase 1 (Aaron, Oct 23): GitHub users only. Since Oct 28 sign-in asks for two things: the GitHub username and a key
  // file, which never leaves the device (SF4 allows up to 5 fields and no new password).
  assert.deepStrictEqual(fields, ['<input id="code-login" name="login" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="40">',
    '<input id="code-file" name="file" type="file">']);
  assert.ok(!/type="password"|autocomplete="(new|current)-password"/.test(html));
  assert.match(html, /<script src="https:\/\/giscus\.app\/client\.js"/);
  assert.match(html, /data-repo="MyChiefOS\/start-of-something-great"/);
  assert.ok(!/auth\/(x|email)\//.test(html), 'no X or email sign-in on the page');
  const v = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  const csp = v.headers.find((h) => h.source === '/join').headers.find((h) => h.key === 'Content-Security-Policy').value;
  assert.match(csp, /script-src 'self' https:\/\/giscus\.app;/);
  assert.match(csp, /frame-src https:\/\/giscus\.app;/);
  assert.match(csp, /form-action 'none'/);
});

// ---- End to end against a real database ------------------------------------------------------------------------

if (!SERVER) {
  if (process.env.CI) test('sign-in tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('sign-in flows (S5, S6, S12, F1, F10)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_signin_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 3 });
  await trustSystem(su); // fix 3: the site itself acts only with its own secret
  // These tests are about the levels sign-in itself verifies. JEVs's automatic level 2, which now comes at once (no
  // wait, Oct 16, 2026), would lift every clean GitHub sign-up to 2; it is tested in test/jevs.test.js, so here no
  // question can pass it.
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.jevs_settings set value = '0' where key = 'pass_max'`); });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

function setup({ keys, accounts = {}, mail = [] } = {}) {
  const cfg = {
    ready: true, sessionKey: key(), ipKey: crypto.randomBytes(32),
    fingerprintKeys: keys || [{ version: 1, key: crypto.randomBytes(32) }],
    github: { clientId: 'g', clientSecret: 's' }, x: { clientId: 'x', clientSecret: 's' }
  };
  const flow = make({ config: cfg, run: (ctx, fn) => db.tx(web, ctx, fn), providers: fakeProviders(accounts), sendEmail: async (to, link) => mail.push({ to, link }) });
  return { flow, cfg, accounts, mail };
}
// The email form's sealed time stamp (PR 12 bot check), as /auth/form hands it out, opened ageMs ago.
const stamp = (env, ageMs = 5000) => c.seal(c.subkey(env.cfg.sessionKey, 'form time'), { k: 'join', t: Date.now() - ageMs });
// An administrator for tests that act as one straight in the database: a real member with a real session.
let adminCtx;
async function admin() {
  if (!adminCtx) {
    const env = setup({ accounts: { 'github:99001': { accountId: '99001', name: 'Admin', level: 2, recheckAfter: null } } });
    const a = await oauth(env, 'github', '99001');
    adminCtx = { memberId: (await me(env, a.browser)).member_id, session: hashOf(a.browser) };
  }
  return adminCtx;
}
// Fix 3: the database checks, from that session, that the member really is an administrator. The owner makes them one
// (as the setup run does) only while fn runs, so the README's administrator steps below still start with none.
const setAdmin = (id, on) => su.begin(async (t) => { await t`set local role dog_owner`; await t`update app.members set is_admin = ${on} where id = ${id}`; });
async function withAdmin(fn) {
  const boss = await admin();
  await setAdmin(boss.memberId, true);
  try { return await fn(boss); } finally { await setAdmin(boss.memberId, false); }
}
// The full GitHub or X round trip, as a browser would do it.
async function oauth(env, provider, account, { browser = jar(), query = '', ip } = {}) {
  const r1 = browser.take(res());
  // A link starts only from our own pages (PR 15's review, F5), as the /account button does.
  await env.flow.start(req('GET', '/auth/' + provider + '/start' + query, { cookie: browser.header(), ip, site: /link=1/.test(query) ? 'same-origin' : undefined }), r1, provider);
  browser.take(r1);
  if (r1.statusCode !== 302) return { browser, r: r1 };
  const state = new URL(r1.getHeader('Location')).searchParams.get('state');
  const r2 = res();
  await env.flow.callback(req('GET', '/auth/' + provider + '/callback?code=' + encodeURIComponent(state + '|' + account) + '&state=' + state, { cookie: browser.header(), ip }), r2, provider);
  browser.take(r2);
  return { browser, r: r2, state };
}
async function me(env, browser) {
  const r = res(); await env.flow.me(req('GET', '/auth/me', { cookie: browser.header() }), r);
  return JSON.parse(r.body);
}
const q = (sql) => su.unsafe(sql);

test('F1: joining with GitHub takes one round trip and lands at level 1, back where you started', async () => {
  const env = setup({ accounts: { 'github:1001': { accountId: '1001', name: 'Grace H', level: 1, recheckAfter: null } } });
  const { browser, r } = await oauth(env, 'github', '1001', { query: '?return_to=/proposals' });
  assert.strictEqual(r.statusCode, 303);
  assert.strictEqual(r.getHeader('Location'), '/proposals');
  assert.ok(browser.get(SESSION), 'a session cookie is set');
  assert.ok(!browser.get('__Host-dog_oauth_github'), 'the state cookie is gone');
  const who = await me(env, browser);
  assert.deepStrictEqual({ ...who, member_id: undefined }, { signed_in: true, member_id: undefined, display_name: 'New member', trust_level: 1 },
    'names and usernames from GitHub are not kept (S12)');
  assert.match(who.member_id, /^[0-9a-f-]{36}$/, 'you can see your own member ID');
});

test('open redirects: a sign-in started with an outside return address comes back home', async () => {
  const env = setup({ accounts: { 'github:1002': { accountId: '1002', name: 'R', level: 1, recheckAfter: null } } });
  for (const bad of ['//evil.com/x', 'https://evil.com', '/\\evil.com']) {
    const { r } = await oauth(env, 'github', '1002', { query: '?return_to=' + encodeURIComponent(bad) });
    assert.strictEqual(r.getHeader('Location'), '/', bad);
  }
});

test('S12, S5: we keep a fingerprint and the level, never the account ID, and only a hash of the session', async () => {
  const env = setup({ accounts: { 'github:777000123': { accountId: '777000123', name: 'Kept Private', level: 1, recheckAfter: null } } });
  const { browser } = await oauth(env, 'github', '777000123');
  const dump = JSON.stringify(await q(`select * from app.identities`)) + JSON.stringify(await q(`select * from app.sessions`)) + JSON.stringify(await q(`select * from app.members`));
  assert.ok(!dump.includes('777000123'), 'the provider account ID is not stored');
  assert.ok(!dump.includes('Kept Private'), 'the provider\'s name for the person is not stored');
  assert.ok(!dump.includes(browser.get(SESSION)), 'the session token is not stored');
  assert.ok(dump.includes(c.sha256hex(browser.get(SESSION))));
  const cols = (await q(`select table_name || '.' || column_name as c from information_schema.columns where table_schema = 'app'`)).map((r) => r.c);
  for (const col of cols) assert.ok(!/(password|account_id|provider_user|email$|email_address|access_token|refresh_token|avatar|ip_address)/.test(col), col);
});

test('OAuth: a wrong, missing, swapped or expired state is refused, and so is a code exchange with the wrong verifier', async () => {
  const env = setup({ accounts: { 'github:2001': { accountId: '2001', name: 'X', level: 1, recheckAfter: null } } });
  const b = jar();
  const r1 = res(); await env.flow.start(req('GET', '/auth/github/start'), r1, 'github'); b.take(r1);
  const state = new URL(r1.getHeader('Location')).searchParams.get('state');
  const call = async (url, cookie) => { const r = res(); await env.flow.callback(req('GET', url, { cookie }), r, url.split('/')[2]); return r.getHeader('Location'); };
  assert.strictEqual(await call('/auth/github/callback?code=' + state + '|2001&state=wrong', b.header()), '/join?error=expired');
  assert.strictEqual(await call('/auth/github/callback?code=' + state + '|2001&state=' + state, ''), '/join?error=expired', 'no cookie');
  // The GitHub state cookie presented at the X callback (mix-up).
  assert.strictEqual(await call('/auth/x/callback?code=' + state + '|2001&state=' + state, b.header().replace('dog_oauth_github', 'dog_oauth_x')), '/join?error=expired');
  // Expired: a cookie sealed in the past.
  const old = c.seal(c.subkey(env.cfg.sessionKey, 'oauth state'), { p: 'github', s: state, v: 'v', r: '/', l: null, e: Date.now() - 1 });
  assert.strictEqual(await call('/auth/github/callback?code=' + state + '|2001&state=' + state, '__Host-dog_oauth_github=' + old), '/join?error=expired');
  // A cookie made with another server's key.
  const forged = c.seal(c.subkey(key(), 'oauth state'), { p: 'github', s: state, v: 'v', r: '/', l: null, e: Date.now() + 60000 });
  assert.strictEqual(await call('/auth/github/callback?code=' + state + '|2001&state=' + state, '__Host-dog_oauth_github=' + forged), '/join?error=expired');
  // Right state, wrong verifier: the provider refuses the exchange.
  const wrongV = c.seal(c.subkey(env.cfg.sessionKey, 'oauth state'), { p: 'github', s: state, v: c.token(32), r: '/', l: null, e: Date.now() + 60000 });
  assert.strictEqual(await call('/auth/github/callback?code=' + state + '|2001&state=' + state, '__Host-dog_oauth_github=' + wrongV), '/join?error=provider');
  assert.strictEqual(await call('/auth/github/callback?error=access_denied&state=' + state, b.header()), '/join?error=cancelled');
  assert.strictEqual((await q(`select count(*)::int as n from app.sessions`))[0].n >= 0, true);
});

test('signing in again finds the same member and replaces the session; an X business account starts at level 1 (021), recorded', async () => {
  const env = setup({ accounts: { 'github:3001': { accountId: '3001', name: 'Same', level: 1, recheckAfter: null },
    'x:9001': { accountId: '9001', name: 'Acme Inc', level: 2, recheckAfter: new Date(Date.now() + 30 * 86400000).toISOString() } } });
  const first = await oauth(env, 'github', '3001');
  const oldToken = first.browser.get(SESSION);
  const again = await oauth(env, 'github', '3001', { browser: first.browser });
  assert.notStrictEqual(again.browser.get(SESSION), oldToken, 'a fresh session token at every sign-in');
  const stale = jar(); stale.set(SESSION, oldToken);
  assert.deepStrictEqual(await me(env, stale), { signed_in: false }, 'the old session ended');
  const members = await q(`select count(distinct member_id)::int as n from app.identities where provider = 'github'`);
  const x = await oauth(env, 'x', '9001');
  // RK82 (021): a sign-in gives level 1 at most, whatever the site asks; level 2 is JEVs's promotion. The cap is recorded.
  assert.strictEqual((await me(env, x.browser)).trust_level, 1);
  const [row] = await q(`select level, recheck_after is not null as recheck from app.identities where provider = 'x'`);
  assert.deepStrictEqual({ ...row }, { level: 1, recheck: true });
  const [capped] = await q(`select detail from app.audit_log where action = 'signup.level_capped' order by at desc limit 1`);
  assert.deepStrictEqual(capped.detail, { provider: 'x', asked: 2, given: 1 });
  assert.ok(members[0].n >= 1);
});

test('linking: only while signed in, never by matching email, and never onto someone else\'s account', async () => {
  const env = setup({ accounts: { 'github:4001': { accountId: '4001', name: 'A', level: 1, recheckAfter: null },
    'x:4002': { accountId: '4002', name: 'A on X', level: 1, recheckAfter: null },
    'github:4003': { accountId: '4003', name: 'B', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '4001');
  const memberA = (await q(`select member_id from app.sessions where token_hash = '${c.sha256hex(a.browser.get(SESSION))}'`))[0].member_id;
  const linked = await oauth(env, 'x', '4002', { browser: a.browser, query: '?link=1' });
  assert.strictEqual(linked.r.getHeader('Location'), '/join?linked=1', 'a link signs this browser out too (PR 15 re-review, R4)');
  const [ids] = await q(`select count(*)::int as n from app.identities where member_id = '${memberA}'`);
  assert.strictEqual(ids.n, 2, 'X is now a second way into the same account');
  // B tries to link A's GitHub account to B: refused.
  const b = await oauth(env, 'github', '4003');
  const steal = await oauth(env, 'github', '4001', { browser: b.browser, query: '?link=1' });
  assert.strictEqual(steal.r.getHeader('Location'), '/account?error=taken_method', 'a failed link returns to the account page (PR 15)');
  // Linking without being signed in is refused before going to the provider.
  const anon = await oauth(env, 'x', '4002', { query: '?link=1' });
  assert.strictEqual(anon.r.getHeader('Location'), '/join?error=signin');
});

test('email links: same answer for every address, a Continue page that changes nothing, single use, 15 minutes', async () => {
  const env = setup();
  const post = async (url, body, opts = {}) => { const r = res(); const b = opts.browser || jar(); const full = url.endsWith('start') ? { ft: stamp(env), ...body } : body; await (url.endsWith('start') ? env.flow.emailStart : env.flow.emailFinish)(req('POST', url, { body: full, origin: ORIGIN, cookie: b.header(), ...opts }), r); b.take(r); return r; };
  const noOrigin = res(); await env.flow.emailStart(req('POST', '/auth/email/start', { body: { email: 'a@example.com' } }), noOrigin);
  assert.strictEqual(noOrigin.getHeader('Location'), '/join?error=expired', 'a post without our Origin is refused');
  assert.strictEqual(env.mail.length, 0);
  const asker = jar();
  const r1 = await post('/auth/email/start', { email: '  Ada@Example.com ' }, { browser: asker });
  assert.strictEqual(r1.getHeader('Location'), '/join?sent=1');
  assert.strictEqual(env.mail.length, 1);
  assert.strictEqual(env.mail[0].to, 'ada@example.com');
  const link = new URL(env.mail[0].link);
  assert.strictEqual(link.origin, ORIGIN, 'the link is built from our address, not the request\'s');
  assert.strictEqual(link.search, '', 'the token is not in the part of the address browsers send');
  const t = new URLSearchParams(link.hash.slice(1)).get('t');
  assert.match(t, /^[A-Za-z0-9_-]{43}$/);
  // Opening the link (as a mail scanner would) only shows a button; the server never sees the token.
  const page = res(); await env.flow.emailContinue(req('GET', link.pathname), page);
  assert.strictEqual(page.statusCode, 200);
  assert.match(page.body, /<form id="finish" method="post" action="\/auth\/email\/finish">/);
  assert.match(page.body, /<script src="\/signin\.js"><\/script>/);
  assert.strictEqual(page.getHeader('Referrer-Policy'), 'same-origin', 'our own form post must carry an Origin header');
  assert.strictEqual((await q(`select count(*)::int as n from app.email_tokens where used_at is not null`))[0].n, 0, 'nothing used up');
  // Opened in another browser: it asks first, and uses nothing up until the person confirms.
  const elsewhere = await post('/auth/email/finish', { t });
  assert.strictEqual(elsewhere.statusCode, 200);
  assert.match(elsewhere.body, /Was this you\?/);
  assert.match(elsewhere.body, /name="confirm" value="1"/);
  assert.strictEqual((await q(`select count(*)::int as n from app.email_tokens where used_at is not null`))[0].n, 0, 'still nothing used up');
  // A cross-site post (or one with no Origin) can't use the link, and leaves it usable.
  const forged = res(); await env.flow.emailFinish(req('POST', '/auth/email/finish', { body: { t } }), forged);
  assert.strictEqual(forged.getHeader('Location'), '/join?error=expired');
  const forged2 = res(); await env.flow.emailFinish(req('POST', '/auth/email/finish', { body: { t }, origin: 'https://evil.com' }), forged2);
  assert.strictEqual(forged2.getHeader('Location'), '/join?error=expired');
  assert.ok(!forged.getHeader('Set-Cookie') && !forged2.getHeader('Set-Cookie'));
  const done = await post('/auth/email/finish', { t }, { browser: asker });
  assert.strictEqual(done.getHeader('Location'), '/', 'in the browser that asked, it signs straight in');
  assert.strictEqual((await me(env, asker)).trust_level, 0);
  assert.ok(!asker.get('__Host-dog_email'), 'the browser marker is cleared');
  const again = await post('/auth/email/finish', { t });
  assert.strictEqual(again.getHeader('Location'), '/join?error=expired', 'single use');
  // Confirming in another browser works too, once.
  const other = jar();
  await post('/auth/email/start', { email: 'two@example.com' }, { browser: jar() });
  const t2 = new URLSearchParams(new URL(env.mail[1].link).hash.slice(1)).get('t');
  const confirmed = await post('/auth/email/finish', { t: t2, confirm: '1' }, { browser: other });
  assert.strictEqual(confirmed.getHeader('Location'), '/');
  assert.strictEqual((await me(env, other)).signed_in, true);
  // Expired after 15 minutes.
  const lateBrowser = jar();
  await post('/auth/email/start', { email: 'late@example.com' }, { browser: lateBrowser });
  await q(`update app.email_tokens set expires_at = now() - interval '1 second' where used_at is null`);
  const late = await post('/auth/email/finish', { t: new URLSearchParams(new URL(env.mail[2].link).hash.slice(1)).get('t') }, { browser: lateBrowser });
  assert.strictEqual(late.getHeader('Location'), '/join?error=expired');
  assert.ok(!JSON.stringify(await q(`select * from app.email_tokens`)).includes('example.com'), 'the address is never stored');
  const bad = await post('/auth/email/start', { email: 'not an email' });
  assert.strictEqual(bad.getHeader('Location'), '/join?error=email');
});

test('S6: too many email links or sign-in attempts are slowed down', async () => {
  const env = setup();
  const send = async (email, ip) => { const r = res(); await env.flow.emailStart(req('POST', '/auth/email/start', { body: { email, ft: stamp(env) }, origin: ORIGIN, ip }), r); return r.getHeader('Location'); };
  const out = [];
  for (let i = 0; i < 6; i++) out.push(await send('same@example.com', '198.51.100.' + (i + 1)));
  assert.deepStrictEqual(out, ['/join?sent=1', '/join?sent=1', '/join?sent=1', '/join?sent=1', '/join?sent=1', '/join?error=slow'], '5 links an hour per address');
  const byIp = [];
  for (let i = 0; i < 11; i++) byIp.push(await send('user' + i + '@example.com', '192.0.2.50'));
  assert.strictEqual(byIp.filter((x) => x === '/join?error=slow').length, 1, '10 links an hour per IP');
  let slow = 0;
  for (let i = 0; i < 31; i++) { const r = res(); await env.flow.start(req('GET', '/auth/github/start', { ip: '192.0.2.99' }), r, 'github'); if (r.getHeader('Location') === '/join?error=slow') slow++; }
  assert.strictEqual(slow, 1, '30 sign-in starts per 10 minutes per IP');
  assert.ok(!JSON.stringify(await q(`select * from app.rate_limits`)).includes('192.0.2'), 'no raw IP is stored');
});

test('F10: a banned member can\'t sign back in with the same account, and their sessions stop working', async () => {
  const env = setup({ accounts: { 'github:5001': { accountId: '5001', name: 'Banned', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '5001');
  // Banning is Aaron's (PR 6 adds the button); here the test acts as an administrator.
  await withAdmin((boss) => su.begin(async (t) => {
    await actAsAdmin(t, boss);
    await t.unsafe(`update app.members set status = 'banned' where id = (select member_id from app.sessions where token_hash = '${c.sha256hex(a.browser.get(SESSION))}')`);
  }));
  assert.deepStrictEqual(await me(env, a.browser), { signed_in: false });
  const back = await oauth(env, 'github', '5001');
  assert.strictEqual(back.r.getHeader('Location'), '/join?error=unavailable');
  assert.ok(!back.browser.get(SESSION));
});

test('sessions last a flat 30 days (Aaron, Oct 28: no 7-day idle limit), and logging out is a same-site POST', async () => {
  const env = setup({ accounts: { 'github:6001': { accountId: '6001', name: 'L', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '6001');
  const hash = c.sha256hex(a.browser.get(SESSION));
  await q(`update app.sessions set last_seen_at = now() - interval '29 days' where token_hash = '${hash}'`);
  assert.strictEqual((await me(env, a.browser)).signed_in, true, 'unused for 29 days: still signed in');
  await q(`update app.sessions set last_seen_at = now() - interval '31 days' where token_hash = '${hash}'`);
  assert.deepStrictEqual(await me(env, a.browser), { signed_in: false }, 'unused past 30 days');
  await q(`update app.sessions set last_seen_at = now(), expires_at = now() - interval '1 second' where token_hash = '${hash}'`);
  assert.deepStrictEqual(await me(env, a.browser), { signed_in: false }, 'expired');

  const b = await oauth(env, 'github', '6001');
  const other = await oauth(env, 'github', '6001'); // a second device
  const cross = res(); await env.flow.logout(req('POST', '/auth/logout-all', { cookie: b.browser.header(), origin: 'https://evil.com' }), cross, true);
  assert.strictEqual((await me(env, b.browser)).signed_in, true, 'a cross-site post logs nobody out');
  const out = res(); await env.flow.logout(req('POST', '/auth/logout-all', { cookie: other.browser.header(), origin: ORIGIN }), out, true);
  other.browser.take(out);
  assert.ok(!other.browser.get(SESSION), 'the cookie is cleared');
  assert.deepStrictEqual(await me(env, other.browser), { signed_in: false });
  assert.deepStrictEqual(await me(env, b.browser), { signed_in: false }, 'log out everywhere ended the other device too');
});

test('S12: a new fingerprint key takes over at each person\'s next sign-in', async () => {
  const k1 = { version: 1, key: crypto.randomBytes(32) }, k2 = { version: 2, key: crypto.randomBytes(32) };
  const accounts = { 'github:7001': { accountId: '7001', name: 'Rotate', level: 1, recheckAfter: null } };
  const before = await oauth(setup({ keys: [k1], accounts }), 'github', '7001');
  const memberBefore = (await me(setup({ keys: [k1], accounts }), before.browser));
  const after = await oauth(setup({ keys: [k2, k1], accounts }), 'github', '7001');
  const [row] = await q(`select key_version, fingerprint from app.identities i join app.sessions s on s.member_id = i.member_id where s.token_hash = '${c.sha256hex(after.browser.get(SESSION))}' and i.provider = 'github'`);
  assert.strictEqual(row.key_version, 2);
  assert.strictEqual(row.fingerprint, c.fingerprints([k2], 'github', '7001')[0]);
  assert.strictEqual((await q(`select count(*)::int as n from app.identities where fingerprint = '${c.fingerprints([k1], 'github', '7001')[0]}'`))[0].n, 0);
  assert.strictEqual(memberBefore.signed_in, true);
});

test('F10, S12: after a fingerprint key rotation, email members keep their account and a banned one stays out', async () => {
  const k1 = { version: 1, key: crypto.randomBytes(32) }, k2 = { version: 2, key: crypto.randomBytes(32) };
  const viaEmail = async (keys, email) => {
    const env = setup({ keys });
    const b = jar();
    const r1 = res(); await env.flow.emailStart(req('POST', '/auth/email/start', { body: { email, ft: stamp(env) }, origin: ORIGIN, cookie: b.header() }), r1); b.take(r1);
    const t = new URLSearchParams(new URL(env.mail[0].link).hash.slice(1)).get('t');
    const r2 = res(); await env.flow.emailFinish(req('POST', '/auth/email/finish', { body: { t }, origin: ORIGIN, cookie: b.header() }), r2); b.take(r2);
    return { b, env, location: r2.getHeader('Location') };
  };
  const first = await viaEmail([k1], 'keep@example.com');
  const id = (await me(first.env, first.b)).member_id;
  const later = await viaEmail([k2, k1], 'keep@example.com');
  assert.strictEqual((await me(later.env, later.b)).member_id, id, 'the same account after the rotation');
  const banned = await viaEmail([k1], 'gone@example.com');
  const bannedId = (await me(banned.env, banned.b)).member_id;
  await withAdmin((boss) => su.begin(async (t) => { await actAsAdmin(t, boss); await t.unsafe(`update app.members set status = 'banned' where id = '${bannedId}'`); }));
  const back = await viaEmail([k2, k1], 'gone@example.com');
  assert.strictEqual(back.location, '/join?error=unavailable', 'still banned after the rotation');
});

test('the sign-in function can\'t attach a method to someone else, or sign in while acting as a member', async () => {
  const env = setup({ accounts: { 'github:9101': { accountId: '9101', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9101');
  const victim = (await me(env, a.browser)).member_id;
  const call = (ctx, link) => db.tx(web, ctx, (t) => t`select * from app.sign_in('x', ${t.array([c.sha256hex('attacker' + Math.random())])}::text[], 1::smallint, 2::smallint,
    'z', ${c.sha256hex('s' + Math.random())}, 30, null, ${link}::uuid, null)`);
  await assert.rejects(call({ actor: 'anon' }, victim), /bad sign-in request/, 'someone not signed in naming a member to link to');
  const other = await oauth(setup({ accounts: { 'github:9102': { accountId: '9102', level: 1, recheckAfter: null } } }), 'github', '9102');
  const otherId = (await me(env, other.browser)).member_id;
  const asOther = { actor: 'member', memberId: otherId, session: hashOf(other.browser) }; // fix 3: really that member
  await assert.rejects(call(asOther, victim), /bad sign-in request/, 'one member linking to another');
  await assert.rejects(call(asOther, null), /bad sign-in request/, 'a plain sign-in while acting as a member');
  const [lvl] = await q(`select trust_level from app.members where id = '${victim}'`);
  assert.strictEqual(lvl.trust_level, 1, 'the victim was not raised to level 2');
});

test('a level Aaron lowers by hand survives the member\'s next sign-in, and no level is raised by hand', async () => {
  const env = setup({ accounts: { 'github:9401': { accountId: '9401', level: 1, recheckAfter: null }, 'github:9402': { accountId: '9402', level: 1, recheckAfter: null } } });
  const members = require('../db/members');
  // Fix 3: Aaron is a real administrator with his own session (an invented member ID no longer acts as anyone).
  const adminAct = (fn) => withAdmin((boss) => db.tx(web, { actor: 'admin', ...boss }, fn));
  const slow = await oauth(env, 'github', '9401');
  const slowId = (await me(env, slow.browser)).member_id;
  assert.strictEqual(await adminAct((t) => members.lowerTrustLevel(t, slowId, 0)), true);
  const again = await oauth(env, 'github', '9401');
  assert.strictEqual((await me(env, again.browser)).trust_level, 0, 'a demotion holds after signing in again');
  const trusted = await oauth(env, 'github', '9402');
  const trustedId = (await me(env, trusted.browser)).member_id;
  // Oct 16, 2026: no trust levels promoted by hand. Only a verified sign-in or JEVs raises one.
  await assert.rejects(adminAct((t) => t`update app.members set trust_level = 2 where id = ${trustedId}`), /never by hand/);
  await q(`update app.sessions set last_seen_at = now() - interval '2 hours' where member_id = '${trustedId}'`);
  assert.strictEqual((await me(env, trusted.browser)).trust_level, 1, 'still the level sign-in verified');
  await assert.rejects(db.tx(web, { actor: 'member', memberId: trustedId, session: hashOf(trusted.browser) }, (t) => t`update app.members set level_set_by_admin = 3 where id = ${trustedId}`), /permission denied/);
});

test('the README\'s administrator steps work exactly as written, and change only the one member', async () => {
  const env = setup({ accounts: { 'github:9301': { accountId: '9301', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9301');
  const id = (await me(env, a.browser)).member_id;
  const readme = fs.readFileSync(path.join(root, 'db', 'README.md'), 'utf8');
  const block = readme.slice(readme.indexOf('### Making Aaron the administrator')).match(/```sql\n([\s\S]*?)```/)[1];
  assert.match(block, /PASTE-YOUR-MEMBER-ID/);
  // Run on one connection, as the SQL editor does.
  const editor = postgres(at(SERVER, NAME), { max: 1, ssl: false, onnotice: () => {} });
  try { await editor.unsafe(block.replace('PASTE-YOUR-MEMBER-ID', id)); } finally { await editor.end({ timeout: 5 }); }
  const admins = await q(`select id from app.members where is_admin`);
  assert.deepStrictEqual(admins.map((r) => r.id), [id]);
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = false where id = '${id}'`); });
});

test('the site\'s own role can\'t read session hashes, email links or fingerprints, or make anyone an administrator', async () => {
  const env = setup({ accounts: { 'github:8001': { accountId: '8001', name: 'P', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '8001');
  const id = (await q(`select member_id from app.sessions where token_hash = '${c.sha256hex(a.browser.get(SESSION))}'`))[0].member_id;
  const asMember = (fn) => db.tx(web, { actor: 'member', memberId: id, session: hashOf(a.browser) }, fn);
  for (const attempt of [(t) => t`select token_hash from app.sessions`, (t) => t`select fingerprint from app.identities`,
    (t) => t`select * from app.email_tokens`, (t) => t`select * from app.rate_limits`, (t) => t`update app.members set is_admin = true where id = ${id}`]) {
    await assert.rejects(asMember(attempt), /permission denied/);
  }
  const mine = await asMember((t) => t`select provider, level from app.identities`);
  assert.deepStrictEqual(mine.map((r) => r.provider), ['github'], 'a member sees which methods they use, and only their own');
  await assert.rejects(q(`update app.members set is_admin = true where id = '${id}'`), /only the database owner can change administrator rights/, 'not even a superuser acting as itself');
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${id}'`); });
  assert.strictEqual((await me(env, a.browser)).signed_in, true);
  const [adm] = await q(`select is_admin from app.members where id = '${id}'`);
  assert.strictEqual(adm.is_admin, true, 'the owner can');
  const [audit] = await q(`select count(*)::int as n from app.audit_log where subject_id = '${id}' and action in ('member.joined', 'member.signed_in')`);
  assert.strictEqual(audit.n, 2, 'joining and signing in are in the audit log');
});

// ---- PR 15: linking a sign-in method can't be used to get a fresh session or lasting access ----------------------
// A stolen session cookie used to be enough to link the thief's own GitHub or X, which also handed out a brand-new
// (fresh) session: enough to let agents act, make keys and pass the fresh-delete check, and to keep signing in as the
// victim after "sign out everywhere". Now: starting a link needs a fresh session; it completes only for the same
// session; it makes no session at all and ends every other session of the member; the member is told in-app and the
// audit log records it; and a method can be unlinked (fresh session, never the last one).
const hashOf = (browser) => c.sha256hex(browser.get(SESSION));
const ago = (browser, minutes) => q(`update app.sessions set created_at = now() - interval '${minutes} minutes' where token_hash = '${hashOf(browser)}'`);
const countIds = async (id) => (await q(`select count(*)::int as n from app.identities where member_id = '${id}'`))[0].n;

test('PR 15: starting a link needs a fresh sign-in, so an older (or stolen) session cookie can\'t link another method', async () => {
  const env = setup({ accounts: { 'github:9501': { accountId: '9501', level: 1, recheckAfter: null }, 'x:9502': { accountId: '9502', level: 2, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9501');
  const id = (await me(env, a.browser)).member_id;
  await ago(a.browser, 11);
  const tried = await oauth(env, 'x', '9502', { browser: a.browser, query: '?link=1' });
  assert.strictEqual(tried.r.statusCode, 303, 'not sent to the provider');
  assert.strictEqual(tried.r.getHeader('Location'), '/account?error=fresh_method');
  assert.ok(!tried.browser.get('__Host-dog_oauth_x'), 'no sign-in state is handed out');
  assert.strictEqual(await countIds(id), 1);
  // Signed in again (fresh), the same member can link.
  const again = await oauth(env, 'github', '9501', { browser: a.browser });
  const ok = await oauth(env, 'x', '9502', { browser: again.browser, query: '?link=1' });
  assert.strictEqual(ok.r.getHeader('Location'), '/join?linked=1');
  assert.strictEqual(await countIds(id), 2);
});

test('PR 15: a link makes no new session (no freshness) and, once a method is added, ends every session of the member, the linking one too (re-review R4), with a notice and an audit row', async () => {
  const env = setup({ accounts: { 'github:9511': { accountId: '9511', level: 1, recheckAfter: null }, 'x:9512': { accountId: '9512', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9511');
  const otherDevice = await oauth(env, 'github', '9511');
  const id = (await me(env, a.browser)).member_id;
  await ago(a.browser, 9);
  const linked = await oauth(env, 'x', '9512', { browser: a.browser, query: '?link=1&return_to=/account' });
  assert.strictEqual(linked.r.getHeader('Location'), '/join?linked=1', 'sent to sign in again, with a note saying why');
  const cookies = [].concat(linked.r.getHeader('Set-Cookie') || []);
  assert.ok(cookies.some((x) => x.startsWith(SESSION + '=') && /Max-Age=0/.test(x)), 'this browser\'s session cookie is cleared');
  assert.ok(!cookies.some((x) => x.startsWith(SESSION + '=') && !/Max-Age=0/.test(x)), 'no session is made');
  assert.strictEqual((await q(`select token_hash from app.sessions where member_id = '${id}'`)).length, 0, 'every session of the member ended, this one too');
  assert.deepStrictEqual(await me(env, a.browser), { signed_in: false });
  assert.deepStrictEqual(await me(env, otherDevice.browser), { signed_in: false });
  const join = fs.readFileSync(path.join(root, 'join.js'), 'utf8');
  assert.match(join, /linked: 'Linked\. To keep your account safe, adding a sign-in method signs you out everywhere, here too\. Sign in again with any of your sign-in methods\.'/);
  // Either method signs in again.
  for (const [p, acct] of [['github', '9511'], ['x', '9512']]) assert.strictEqual((await me(env, (await oauth(env, p, acct)).browser)).member_id, id);
  const notices = await q(`select kind, title, body, link, subject_kind from app.notices where member_id = '${id}'`);
  assert.deepStrictEqual(notices.map((n) => [n.kind, n.title, n.link, n.subject_kind]), [['signin_linked', 'A new sign-in method was linked', '/account', 'identity']]);
  assert.match(notices[0].body, /^X can now sign in to your account\. To keep your account safe, every session of yours was signed out, the one that linked it too, so sign in again with whichever method you like\./);
  const [au] = await q(`select actor_kind, actor_id, detail from app.audit_log where action = 'member.identity_linked' and subject_id = '${id}'`);
  assert.deepStrictEqual([au.actor_kind, au.actor_id, au.detail], ['member', id, { provider: 'x', sessions_ended: 2 }]);
  // Verifying again a method that is already theirs adds nothing and signs nobody out.
  const b = await oauth(env, 'github', '9511');
  const again = await oauth(env, 'x', '9512', { browser: b.browser, query: '?link=1' });
  assert.strictEqual(again.r.getHeader('Location'), '/');
  assert.strictEqual((await me(env, b.browser)).signed_in, true);
});

test('PR 15: a link completes only for the session that started it, not another session of the same member', async () => {
  const env = setup({ accounts: { 'github:9521': { accountId: '9521', level: 1, recheckAfter: null }, 'x:9522': { accountId: '9522', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9521');
  const id = (await me(env, a.browser)).member_id;
  const r1 = res();
  await env.flow.start(req('GET', '/auth/x/start?link=1', { cookie: a.browser.header(), site: 'same-origin' }), r1, 'x');
  a.browser.take(r1);
  const state = new URL(r1.getHeader('Location')).searchParams.get('state');
  const second = await oauth(env, 'github', '9521');
  const mixed = jar();
  mixed.set(SESSION, second.browser.get(SESSION));
  mixed.set('__Host-dog_oauth_x', a.browser.get('__Host-dog_oauth_x'));
  const r2 = res();
  await env.flow.callback(req('GET', '/auth/x/callback?code=' + encodeURIComponent(state + '|9522') + '&state=' + state, { cookie: mixed.header() }), r2, 'x');
  assert.strictEqual(r2.getHeader('Location'), '/account?error=link', 'refused, back on the account page');
  assert.strictEqual(await countIds(id), 1);
});

test('PR 15: the database links only from the member\'s own fresh session, and sign-in itself no longer links', async () => {
  const env = setup({ accounts: { 'github:9531': { accountId: '9531', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9531');
  const id = (await me(env, a.browser)).member_id;
  const ctx = { actor: 'member', memberId: id, session: hashOf(a.browser) };
  const fp = () => c.sha256hex('linked' + Math.random());
  await assert.rejects(db.tx(web, ctx, (t) => t`select * from app.sign_in('x', ${t.array([fp()])}::text[], 1::smallint, 1::smallint,
    'z', ${c.sha256hex('s' + Math.random())}, 30, null, ${id}::uuid, null)`), /bad sign-in request/, 'sign-in never links (it would make a fresh session)');
  const link = (who, sessionHash) => db.tx(web, who, (t) => t`select * from app.identity_link('x', ${t.array([fp()])}::text[], 1::smallint, 1::smallint,
    null::timestamptz, ${sessionHash}, null)`);
  const other = await oauth(setup({ accounts: { 'github:9532': { accountId: '9532', level: 1, recheckAfter: null } } }), 'github', '9532');
  await assert.rejects(link(ctx, hashOf(other.browser)), /fresh_sign_in/, 'another member\'s session counts for nothing');
  await assert.rejects(link({ actor: 'anon' }, hashOf(a.browser)), /bad sign-in request/);
  await ago(a.browser, 11);
  await assert.rejects(link({ ...ctx, fresh: true }, hashOf(a.browser)), /fresh_sign_in/, 'the session\'s own start time decides, by the database clock');
  assert.strictEqual(await countIds(id), 1);
  await ago(a.browser, 1);
  const [out] = await link(ctx, hashOf(a.browser));
  assert.strictEqual(out.member_id, id);
  assert.strictEqual(await countIds(id), 2);
});

test('PR 15: unlinking a method needs a same-site POST and a fresh session, never removes the last one, and tells the member', async () => {
  const env = setup({ accounts: { 'github:9541': { accountId: '9541', level: 1, recheckAfter: null },
    'x:9542': { accountId: '9542', level: 2, recheckAfter: new Date(Date.now() + 30 * 86400000).toISOString() } } });
  const a = await oauth(env, 'github', '9541');
  const id = (await me(env, a.browser)).member_id;
  await promote(su, id); // level 2 is JEVs's promotion (021), not the X method
  await oauth(env, 'x', '9542', { browser: a.browser, query: '?link=1' });
  await oauth(env, 'github', '9541', { browser: a.browser }); // a link signs everyone out (R4): sign in again
  assert.strictEqual((await me(env, a.browser)).trust_level, 2);
  const otherDevice = await oauth(env, 'github', '9541');
  const page = res();
  await env.flow.account(req('GET', '/auth/account', { cookie: a.browser.header() }), page);
  const signIns = JSON.parse(page.body).sign_ins;
  assert.deepStrictEqual(signIns.map((s) => s.provider), ['github', 'x']);
  for (const s of signIns) assert.match(s.id, /^[0-9a-f-]{36}$/, 'each method has an ID to unlink it by');
  const xId = signIns.find((s) => s.provider === 'x').id;
  const unlink = async (browser, body, opts = {}) => { const r = res(); await env.flow.unlink(req('POST', '/auth/account/unlink', { cookie: browser.header(), origin: ORIGIN, body, ...opts }), r); return r.getHeader('Location'); };
  assert.strictEqual(await unlink(a.browser, { id: xId }, { origin: 'https://evil.example' }), '/account', 'a cross-site post changes nothing');
  assert.strictEqual(await unlink(jar(), { id: xId }), '/join?error=signin');
  await ago(a.browser, 11);
  assert.strictEqual(await unlink(a.browser, { id: xId }), '/account?error=fresh_method');
  await assert.rejects(db.tx(web, { actor: 'member', memberId: id, session: hashOf(a.browser), fresh: true }, (t) => t`select * from app.identity_unlink(${xId}::uuid, ${hashOf(a.browser)})`), /fresh_sign_in/);
  assert.strictEqual(await countIds(id), 2);
  await ago(a.browser, 1);
  const stranger = await oauth(setup({ accounts: { 'github:9543': { accountId: '9543', level: 1, recheckAfter: null } } }), 'github', '9543');
  assert.strictEqual(await unlink(stranger.browser, { id: xId }), '/account?error=unlink', 'nobody unlinks another member\'s method');
  assert.strictEqual(await unlink(a.browser, { id: 'not-an-id' }), '/account?error=unlink');
  assert.strictEqual(await countIds(id), 2);
  assert.strictEqual(await unlink(a.browser, { id: xId }), '/account?saved=unlinked');
  assert.strictEqual(await countIds(id), 1);
  // Since 021 no method gives level 2; this member's level 2 is JEVs's promotion, which stays.
  assert.strictEqual((await me(env, a.browser)).trust_level, 2, 'JEVs\'s level 2 isn\'t tied to a method');
  assert.deepStrictEqual(await me(env, otherDevice.browser), { signed_in: false }, 'every other session ended');
  assert.strictEqual((await me(env, a.browser)).signed_in, true, 'this one stays');
  const [n] = await q(`select title from app.notices where member_id = '${id}' and kind = 'signin_unlinked'`);
  assert.strictEqual(n.title, 'A sign-in method was removed');
  const [au] = await q(`select actor_kind, detail from app.audit_log where action = 'member.identity_unlinked' and subject_id = '${id}'`);
  assert.deepStrictEqual([au.actor_kind, au.detail], ['member', { provider: 'x', sessions_ended: 1, also_unlinked: [], keys_revoked: 0, agents_lowered: 0 }]);
  const githubId = signIns.find((s) => s.provider === 'github').id;
  assert.strictEqual(await unlink(a.browser, { id: githubId }), '/account?error=last_method');
  await assert.rejects(db.tx(web, { actor: 'member', memberId: id, session: hashOf(a.browser) }, (t) => t`select * from app.identity_unlink(${githubId}::uuid, ${hashOf(a.browser)})`), /last_method/);
  assert.strictEqual(await countIds(id), 1);
  // Unlinked, that X account is a stranger again: signing in with it makes a new account, not this one.
  const back = await oauth(env, 'x', '9542');
  assert.notStrictEqual((await me(env, back.browser)).member_id, id);
});

// ---- PR 15, after its independent review (F1, F2, F4, F5, F6) ----------------------------------------------------
const twoBrowsers = (b) => { const x = jar(); x.set(SESSION, b.get(SESSION)); return x; };

test('PR 15 review F1: seniority. A session may unlink only methods linked after the one it signed in with, so an intruder who linked their own method can\'t evict the owner, and the owner can always remove the intruder', async () => {
  const env = setup({ accounts: { 'github:9601': { accountId: '9601', level: 1, recheckAfter: null }, 'x:9602': { accountId: '9602', level: 1, recheckAfter: null },
    'x:9603': { accountId: '9603', level: 1, recheckAfter: null } } });
  const owner = await oauth(env, 'github', '9601');
  const id = (await me(env, owner.browser)).member_id;
  const shared = twoBrowsers(owner.browser); // a cookie copied within its fresh 10 minutes: owner and intruder share it
  assert.strictEqual((await oauth(env, 'x', '9602', { browser: shared, query: '?link=1' })).r.getHeader('Location'), '/join?linked=1');
  assert.deepStrictEqual(await me(env, shared), { signed_in: false }, 'the copied cookie died with the link (R4)');
  const ownerAgain = await oauth(env, 'github', '9601');
  const [row] = await q(`select i.provider from app.sessions s join app.identities i on i.id = s.identity_id where s.token_hash = '${hashOf(ownerAgain.browser)}'`);
  assert.strictEqual(row.provider, 'github', 'each session records the method it signed in with');
  const intruder = await oauth(env, 'x', '9602');
  assert.strictEqual((await me(env, intruder.browser)).member_id, id);
  const page = res();
  await env.flow.account(req('GET', '/auth/account', { cookie: intruder.browser.header() }), page);
  const ids = Object.fromEntries(JSON.parse(page.body).sign_ins.map((s) => [s.provider, s.id]));
  const unlink = async (b, identity) => { const r = res(); await env.flow.unlink(req('POST', '/auth/account/unlink', { cookie: b.header(), origin: ORIGIN, body: { id: identity } }), r); return r.getHeader('Location'); };
  assert.strictEqual(await unlink(intruder.browser, ids.github), '/account?error=senior', 'the later method can\'t remove the older one');
  assert.strictEqual(await unlink(shared, ids.github), '/join?error=signin', 'and the copied session is gone');
  await assert.rejects(db.tx(web, { actor: 'member', memberId: id, session: hashOf(intruder.browser) }, (t) => t`select * from app.identity_unlink(${ids.github}::uuid, ${hashOf(intruder.browser)})`), /not_senior/);
  assert.strictEqual(await countIds(id), 2);
  assert.strictEqual((await me(env, ownerAgain.browser)).signed_in, true, 'the intruder\'s refused attempts signed the owner out of nothing');
  // The owner, signed in with the older method, removes the intruder's: the intruder's session ends.
  const back = await oauth(env, 'github', '9601');
  assert.strictEqual(await unlink(back.browser, ids.x), '/account?saved=unlinked');
  assert.deepStrictEqual(await me(env, intruder.browser), { signed_in: false });
  assert.strictEqual(await countIds(id), 1);
  const again = await oauth(env, 'x', '9602');
  assert.notStrictEqual((await me(env, again.browser)).member_id, id, 'the intruder\'s X no longer reaches the account');
  // A session with no recorded method (made before this migration) can't unlink anything until it signs in again.
  const third = await oauth(env, 'github', '9601');
  assert.strictEqual((await oauth(env, 'x', '9603', { browser: third.browser, query: '?link=1' })).r.getHeader('Location'), '/join?linked=1');
  await oauth(env, 'github', '9601', { browser: third.browser });
  await q(`update app.sessions set identity_id = null where token_hash = '${hashOf(third.browser)}'`);
  const p2 = res();
  await env.flow.account(req('GET', '/auth/account', { cookie: third.browser.header() }), p2);
  const later = JSON.parse(p2.body).sign_ins.find((s) => s.provider === 'x');
  assert.strictEqual(await unlink(third.browser, later.id), '/account?error=senior');
  assert.strictEqual(await countIds(id), 2);
});

test('PR 15 review F2: the member lock comes before the session check, so a link can\'t complete from a session another link just ended', async () => {
  const env = setup({ accounts: { 'github:9611': { accountId: '9611', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9611');
  const b = await oauth(env, 'github', '9611');
  const id = (await me(env, a.browser)).member_id;
  const ctx = { actor: 'member', memberId: id, session: hashOf(a.browser) };
  const fp = () => c.sha256hex('race' + Math.random());
  const call = (t, h) => t`select * from app.identity_link('x', ${t.array([fp()])}::text[], 1::smallint, 1::smallint, null::timestamptz, ${h}, null)`;
  let release;
  const gate = new Promise((r) => { release = r; });
  const t1 = db.tx(web, ctx, async (t) => { const r = await call(t, hashOf(a.browser)); await gate; return r; });
  await new Promise((r) => setTimeout(r, 300));
  const t2 = db.tx(web, ctx, (t) => call(t, hashOf(b.browser)));
  await new Promise((r) => setTimeout(r, 300));
  release();
  const [r1, r2] = await Promise.allSettled([t1, t2]);
  assert.strictEqual(r1.status, 'fulfilled');
  assert.strictEqual(r2.status, 'rejected');
  assert.match(r2.reason.message, /fresh_sign_in/, 'the second link finds its session gone');
  assert.strictEqual(await countIds(id), 2);
  assert.strictEqual((await q(`select token_hash from app.sessions where member_id = '${id}'`)).length, 0, 'the first link ended every session, its own too (R4)');
});

test('PR 15 review F4: two members linking the same method at the same moment: the second is refused as taken, not an error', async () => {
  const env = setup({ accounts: { 'github:9621': { accountId: '9621', level: 1, recheckAfter: null }, 'github:9622': { accountId: '9622', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9621');
  const b = await oauth(env, 'github', '9622');
  const ida = (await me(env, a.browser)).member_id;
  const idb = (await me(env, b.browser)).member_id;
  const same = c.sha256hex('same-x-' + Math.random());
  const args = (br) => ({ provider: 'x', fingerprints: [same], keyVersion: 1, level: 1, sessionHash: hashOf(br) });
  let release;
  const gate = new Promise((r) => { release = r; });
  const t1 = db.tx(web, { actor: 'member', memberId: ida, session: hashOf(a.browser) }, async (t) => { const r = await store.link(t, args(a.browser)); await gate; return r; });
  await new Promise((r) => setTimeout(r, 300));
  const t2 = db.tx(web, { actor: 'member', memberId: idb, session: hashOf(b.browser) }, (t) => store.link(t, args(b.browser)));
  await new Promise((r) => setTimeout(r, 300));
  release();
  const [r1, r2] = await Promise.allSettled([t1, t2]);
  assert.strictEqual(r1.status, 'fulfilled');
  assert.strictEqual(r2.status, 'fulfilled', r2.reason && r2.reason.message);
  assert.deepStrictEqual(r2.value, { refused: 'taken' });
});

test('PR 15 review F5: a link starts only from our own pages (Sec-Fetch-Site same-origin, and a same-origin Origin or Referer where sent)', async () => {
  const env = setup({ accounts: { 'github:9631': { accountId: '9631', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9631');
  const start = async (headers) => { const r = res(); const rq = req('GET', '/auth/x/start?link=1', { cookie: a.browser.header() }); Object.assign(rq.headers, headers); await env.flow.start(rq, r, 'x'); return r; };
  for (const h of [{}, { 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': 'same-site' }, { 'sec-fetch-site': 'none' },
    { 'sec-fetch-site': 'same-origin', origin: 'https://evil.example' }, { 'sec-fetch-site': 'same-origin', referer: 'https://evil.example/x' },
    { 'sec-fetch-site': 'same-origin', referer: 'https://dayonegreat.com.evil.example/account' }]) {
    const r = await start(h);
    assert.strictEqual(r.getHeader('Location'), '/account?error=link', JSON.stringify(h));
    assert.ok(![].concat(r.getHeader('Set-Cookie') || []).some((x) => x.startsWith('__Host-dog_oauth_')), 'no sign-in state: ' + JSON.stringify(h));
  }
  const ok = await start({ 'sec-fetch-site': 'same-origin', referer: ORIGIN + '/account' });
  assert.strictEqual(ok.statusCode, 302);
  // A plain sign-in (no link) is unchanged: it may start from anywhere, such as a bookmark.
  const plain = res();
  await env.flow.start(req('GET', '/auth/github/start'), plain, 'github');
  assert.strictEqual(plain.statusCode, 302);
});

test('PR 15 review F6: a traveller\'s sealed confirmation works once; a replayed copy signs nobody in', async () => {
  const env = setup({ accounts: { 'github:9641': { accountId: '9641', level: 1, recheckAfter: null } } });
  await oauth(env, 'github', '9641');
  const fr = (r) => { r.headers['x-vercel-ip-country'] = 'FR'; return r; };
  const b = jar();
  const r1 = res();
  await env.flow.start(fr(req('GET', '/auth/github/start', { cookie: b.header() })), r1, 'github'); b.take(r1);
  const state = new URL(r1.getHeader('Location')).searchParams.get('state');
  const r2 = res();
  await env.flow.callback(fr(req('GET', '/auth/github/callback?code=' + encodeURIComponent(state + '|9641') + '&state=' + state, { cookie: b.header() })), r2, 'github'); b.take(r2);
  const sealed = b.get('__Host-dog_region');
  assert.ok(sealed);
  const press = async () => { const r = res(); await env.flow.regionContinue(fr(req('POST', '/auth/region/continue', { cookie: '__Host-dog_region=' + sealed, origin: ORIGIN, body: {} })), r); return r; };
  const first = await press();
  assert.ok([].concat(first.getHeader('Set-Cookie') || []).some((x) => x.startsWith(SESSION + '=') && !/Max-Age=0/.test(x)), 'the first press signs in');
  const replay = await press();
  assert.strictEqual(replay.getHeader('Location'), '/join?error=expired');
  assert.ok(![].concat(replay.getHeader('Set-Cookie') || []).some((x) => x.startsWith(SESSION + '=') && !/Max-Age=0/.test(x)), 'a replay makes no session');
});

// ---- PR 15, after its second review (R1 revoke on unlink, R2 the 90-day clock, R3 lock order) --------------------
// Each of these began as one of the reviewer's probes (A, C, D, B), which showed the flaw; they now show the fix.
const session = require('../signin/session');
const agents = require('../db/agents');
const delegation = require('../db/delegation');
const notices = require('../db/notify');
const runAs = (ctx, fn) => db.tx(web, ctx, fn);
// Who a browser is, exactly as every API handler finds it (session.current), and the actor it acts as.
const whoOf = async (browser) => session.current(req('GET', '/api/agents', { cookie: browser.header() }), runAs);
const as = async (browser) => { const w = await whoOf(browser); return { ...session.actorFor(w), fresh: w.fresh === true }; };
const latest = async (agent) => ({ ...(await q(`select post_mode, reply_mode, report_mode, daily_cap, reason, set_by from app.agent_rules
  where agent_id = '${agent}' order by version desc limit 1`))[0] });
const resolves = async (keyHash) => Boolean(await runAs({ actor: 'anon' }, (t) => agents.resolve(t, keyHash)));

test('PR 15 second review R1 (probes A and C): unlinking a method undoes what its sessions did: their agent keys and claims are revoked, what they raised to act drafts again, what they linked is unlinked, and the owner is told exactly that', async () => {
  const env = setup({ accounts: { 'x:9701': { accountId: '9701', level: 2, recheckAfter: null }, 'github:9702': { accountId: '9702', level: 1, recheckAfter: null },
    'github:9703': { accountId: '9703', level: 1, recheckAfter: null } } });
  const owner = await oauth(env, 'x', '9701');
  const id = (await me(env, owner.browser)).member_id;
  await promote(su, id); // level 2 is JEVs's promotion (021), not the X method
  // The owner's own agent, which the owner lets post on its own (fresh): nothing below should undo that.
  const mineKey = c.sha256hex('mine' + Math.random());
  const mine = await runAs(await as(owner.browser), (t) => agents.create(t, { name: 'mine', description: null, keyHash: mineKey }));
  assert.ok((await runAs(await as(owner.browser), (t) => delegation.setRules(t, { agent: mine.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 20 }))).rules);
  // An intruder copies the owner's fresh cookie, links their own GitHub with it, then signs in with that GitHub.
  const shared = twoBrowsers(owner.browser);
  assert.strictEqual((await oauth(env, 'github', '9702', { browser: shared, query: '?link=1' })).r.getHeader('Location'), '/join?linked=1');
  const intruder = await oauth(env, 'github', '9702');
  assert.strictEqual((await me(env, intruder.browser)).member_id, id);
  // From that session: a new agent with a key, raised to act; and the owner's agent re-saved with its cap raised.
  const keyHash = c.sha256hex('intruder-key-' + Math.random());
  const helper = await runAs(await as(intruder.browser), (t) => agents.create(t, { name: 'helper', description: null, keyHash }));
  assert.ok(helper.id);
  assert.ok((await runAs(await as(intruder.browser), (t) => delegation.setRules(t, { agent: helper.id, post: 'act', reply: 'act', report: 'draft', dailyCap: 20 }))).rules);
  assert.ok((await runAs(await as(intruder.browser), (t) => delegation.setRules(t, { agent: mine.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 200 }))).rules);
  // Probe C: the intruder's fresh session links yet another GitHub (which ends the owner's sessions), and from a
  // session of that one claims an outside agent whose key the intruder holds.
  assert.strictEqual((await oauth(env, 'github', '9703', { browser: intruder.browser, query: '?link=1' })).r.getHeader('Location'), '/join?linked=1');
  assert.deepStrictEqual(await me(env, owner.browser), { signed_in: false });
  const deeper = await oauth(env, 'github', '9703');
  const outsideKey = c.sha256hex('outside-key-' + Math.random());
  const claimCode = c.sha256hex('claim-' + Math.random());
  await runAs({ actor: 'anon' }, (t) => agents.register(t, { name: 'outside', description: null, keyHash: outsideKey, claimHash: claimCode }));
  const claimed = await runAs(await as(deeper.browser), (t) => agents.claim(t, claimCode));
  assert.ok(claimed, JSON.stringify(claimed));
  for (const k of [keyHash, outsideKey, mineKey]) assert.ok(await resolves(k), 'every key works before the unlink');
  const [g1] = await q(`select id from app.identities where member_id = '${id}' and provider = 'github' order by created_at limit 1`);

  // The owner signs back in with their older X and unlinks the intruder's first GitHub, as the notice says.
  const back = await oauth(env, 'x', '9701');
  const r = res();
  await env.flow.unlink(req('POST', '/auth/account/unlink', { cookie: back.browser.header(), origin: ORIGIN, body: { id: g1.id } }), r);
  assert.strictEqual(r.getHeader('Location'), '/account?saved=unlinked');

  // Without even signing out everywhere: both GitHubs are gone, every session of theirs ended, and their keys are dead.
  assert.deepStrictEqual((await q(`select provider from app.identities where member_id = '${id}'`)).map((x) => x.provider), ['x']);
  for (const b of [intruder.browser, deeper.browser, shared]) assert.deepStrictEqual(await me(env, b), { signed_in: false });
  assert.strictEqual(await resolves(keyHash), false, 'the key made from the linked method\'s session is revoked');
  assert.strictEqual(await resolves(outsideKey), false, 'the agent claimed from a session of a method it linked is revoked too');
  assert.strictEqual(await resolves(mineKey), true, 'the owner\'s own key still works');
  // What they raised to act drafts again (never off); the owner's own "act" stays, and the cap they raised goes back.
  assert.deepStrictEqual(await latest(helper.id), { post_mode: 'draft', reply_mode: 'draft', report_mode: 'draft', daily_cap: 20, reason: 'signin_unlinked', set_by: 'system' });
  assert.deepStrictEqual(await latest(mine.id), { post_mode: 'act', reply_mode: 'draft', report_mode: 'draft', daily_cap: 20, reason: 'signin_unlinked', set_by: 'system' });
  // One audit row and one notice say exactly what was undone, and send the owner to their agents.
  const au = await q(`select detail from app.audit_log where action = 'member.identity_unlinked' and subject_id = '${id}'`);
  assert.deepStrictEqual(au.map((x) => x.detail), [{ provider: 'github', sessions_ended: 1, also_unlinked: ['github'], keys_revoked: 2, agents_lowered: 2 }]);
  const ns = await q(`select title, body, link from app.notices where member_id = '${id}' and kind = 'signin_unlinked'`);
  assert.strictEqual(ns.length, 1);
  assert.strictEqual(ns[0].link, '/agents');
  assert.strictEqual(ns[0].body, 'GitHub can no longer sign in to your account, and every other session of yours was signed out. '
    + 'Also unlinked, because they were linked from its sessions: GitHub. 2 agent keys made or claimed from those sessions were revoked. '
    + '2 agents that those sessions let act on their own now draft for your approval again (nothing was switched off). '
    + 'Check your agents and your posts: anything else done from those sessions, such as a post or a deletion, isn\'t undone. '
    + 'If this wasn\'t you, sign in again and check how you sign in on your account page.');
  // The notice about the link now says what unlinking does, and what it doesn't.
  const [ln] = await q(`select body from app.notices where member_id = '${id}' and kind = 'signin_linked' order by created_at limit 1`);
  assert.match(ln.body, /revokes the keys of any agent made with it, puts anything it let act on its own back to drafting/);
  assert.match(ln.body, /isn't undone\.$/);
  // The record: the key names the method of the session that made it (the intruder's first GitHub, now gone).
  const [rec] = await q(`select by_identity from app.agent_keys where key_hash = '${keyHash}'`);
  assert.strictEqual(rec.by_identity, g1.id);
});

test('PR 15 second review R1: an agent paused by a containment when the method is unlinked stays drafting after the pause, instead of getting back what that method raised', async () => {
  const env = setup({ accounts: { 'x:9741': { accountId: '9741', level: 2, recheckAfter: null }, 'github:9742': { accountId: '9742', level: 1, recheckAfter: null } } });
  const owner = await oauth(env, 'x', '9741');
  const id = (await me(env, owner.browser)).member_id;
  await promote(su, id); // level 2 is JEVs's promotion (021), not the X method
  await oauth(env, 'github', '9742', { browser: twoBrowsers(owner.browser), query: '?link=1' });
  await oauth(env, 'x', '9741', { browser: owner.browser }); // the link signed the owner out too (R4)
  const intruder = await oauth(env, 'github', '9742');
  const ag = await runAs(await as(owner.browser), (t) => agents.create(t, { name: 'paused', description: null, keyHash: c.sha256hex('p' + Math.random()) }));
  assert.ok((await runAs(await as(intruder.browser), (t) => delegation.setRules(t, { agent: ag.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 20 }))).rules);
  // The watch contains the owner: every act goes back to draft for a while.
  await runAs({ actor: 'system' }, (t) => t`insert into app.containments (member_id, reason, measured, usual_x100, ends_at)
    values (${id}, 'volume', 1000, 100, now() + interval '2 seconds')`);
  assert.strictEqual((await latest(ag.id)).reason, 'containment');
  const back = await oauth(env, 'x', '9741');
  const [g] = await q(`select id from app.identities where member_id = '${id}' and provider = 'github'`);
  assert.strictEqual((await runAs(await as(back.browser), (t) => store.unlink(t, { identity: g.id, sessionHash: hashOf(back.browser) }))).agentsLowered, 1);
  // The pause ends: the containment's own version is no longer the latest, so the intruder's "act" isn't restored.
  await new Promise((r) => setTimeout(r, 2500));
  await runAs({ actor: 'system' }, (t) => t`update app.containments set lifted_at = now() where member_id = ${id} and lifted_at is null`);
  assert.deepStrictEqual(await latest(ag.id), { post_mode: 'draft', reply_mode: 'draft', report_mode: 'draft', daily_cap: 20, reason: 'signin_unlinked', set_by: 'system' });
});

test('PR 15 second review R1: the method a session made things with is read by the database from the request\'s own session; another member\'s session, or none, records nothing, and the site can\'t write the record', async () => {
  const env = setup({ accounts: { 'x:9711': { accountId: '9711', level: 2, recheckAfter: null }, 'x:9712': { accountId: '9712', level: 2, recheckAfter: null } } });
  const a = await oauth(env, 'x', '9711');
  const b = await oauth(env, 'x', '9712');
  const ida = (await me(env, a.browser)).member_id;
  await promote(su, ida); // level 2 is JEVs's promotion (021), not the X method
  const ident = async (ctx) => (await runAs(ctx, (t) => t`select app.current_identity() as i`))[0].i;
  const [own] = await q(`select identity_id from app.sessions where token_hash = '${hashOf(a.browser)}'`);
  assert.ok(own.identity_id);
  assert.strictEqual(await ident(await as(a.browser)), own.identity_id);
  // fix 3: these used to act as A and record no method; now the database refuses to act as A at all without A's own session.
  await assert.rejects(ident({ actor: 'member', memberId: ida, session: hashOf(b.browser) }), /not_acting/, 'another member\'s session counts for nothing');
  await assert.rejects(ident({ actor: 'member', memberId: ida }), /need the session that proves who is acting/);
  await assert.rejects(runAs({ actor: 'anon', session: hashOf(a.browser) }, async () => {}), /only member calls carry a session/);
  await assert.rejects(runAs({ actor: 'member', memberId: ida, session: 'not-a-hash' }, async () => {}), /session must be a session hash/);
  const ag = await runAs(await as(a.browser), (t) => agents.create(t, { name: 'rec', description: null, keyHash: c.sha256hex('rec' + Math.random()) }));
  const [made] = await q(`select created_by_identity from app.agents where id = '${ag.id}'`);
  assert.strictEqual(made.created_by_identity, own.identity_id, 'an agent records the method of the session that created it');
  await assert.rejects(runAs(await as(a.browser), (t) => t`insert into app.agents (name, created_by_identity) values ('w', null)`), /permission denied/);
  await assert.rejects(runAs(await as(a.browser), (t) => t`update app.agents set created_by_identity = null where id = ${ag.id}`), /permission denied/);
  await assert.rejects(runAs(await as(a.browser), (t) => t`insert into app.agent_keys (agent_id, key_hash, by_identity) values (${ag.id}, ${c.sha256hex('z' + Math.random())}, null)`), /permission denied/);
  await assert.rejects(runAs(await as(a.browser), (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason, restarts_clock)
    values (${ag.id}, 'draft', 'draft', 'draft', 20, 'owner', true)`), /permission denied/);
});

test('PR 15 second review R2 (probe D): the 90-day clock restarts only on a save made with a fresh sign-in; re-saving act rules without one is allowed but doesn\'t move it', async () => {
  const env = setup({ accounts: { 'x:9721': { accountId: '9721', level: 2, recheckAfter: null } } });
  const o = await oauth(env, 'x', '9721');
  await promote(su, (await me(env, o.browser)).member_id); // level 2 is JEVs's promotion (021)
  const made = await runAs(await as(o.browser), (t) => agents.create(t, { name: 'clock', description: null, keyHash: c.sha256hex('d' + Math.random()) }));
  assert.ok((await runAs(await as(o.browser), (t) => delegation.setRules(t, { agent: made.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 20 }))).rules);
  const age = (days) => q(`alter table app.agent_rules disable trigger agent_rules_guard;
    update app.agent_rules set created_at = created_at - interval '${days} days' where agent_id = '${made.id}';
    alter table app.agent_rules enable always trigger agent_rules_guard`);
  const daysAgo = async (browser) => Math.round((Date.now() - +(await runAs(await as(browser), (t) => notices.actClock(t, [made.id]))).get(made.id)) / 86400000);
  const ver = async () => (await q(`select max(version)::int as v from app.agent_rules where agent_id = '${made.id}'`))[0].v;
  await age(85);
  await ago(o.browser, 11); // the owner's session is no longer fresh
  const stale = await as(o.browser);
  assert.strictEqual(stale.fresh, false);
  assert.deepStrictEqual(await runAs(stale, async (t) => notices.reconfirm(t, { agent: made.id, version: await ver() })), { refused: 'fresh' });
  // The same rules re-saved without a fresh sign-in: accepted (no extra friction), but the clock stays at day 85.
  assert.ok((await runAs(stale, (t) => delegation.setRules(t, { agent: made.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 20 }))).rules, 'allowed');
  assert.strictEqual(await daysAgo(o.browser), 85, 'the 90-day clock did not restart');
  const [row] = await q(`select restarts_clock, set_by from app.agent_rules where agent_id = '${made.id}' order by version desc limit 1`);
  assert.deepStrictEqual({ ...row }, { restarts_clock: false, set_by: 'owner' });
  // Lowering one action without a fresh sign-in, leaving another on act, doesn't move it either.
  assert.ok((await runAs(stale, (t) => delegation.setRules(t, { agent: made.id, post: 'act', reply: 'off', report: 'draft', dailyCap: 20 }))).rules);
  assert.strictEqual(await daysAgo(o.browser), 85);
  // At day 91 the timer puts it back to drafting, whatever was re-saved since.
  await age(6);
  assert.ok((await runAs(stale, (t) => delegation.setRules(t, { agent: made.id, post: 'act', reply: 'off', report: 'draft', dailyCap: 20 }))).rules);
  await runAs({ actor: 'system' }, (t) => notices.runTimers(t));
  assert.deepStrictEqual(await latest(made.id), { post_mode: 'draft', reply_mode: 'off', report_mode: 'draft', daily_cap: 20, reason: 'act_expired', set_by: 'system' });
  // A fresh choice does restart it: raising it to act again, and later a fresh re-confirm.
  const fresh = await oauth(env, 'x', '9721');
  assert.ok((await runAs(await as(fresh.browser), (t) => delegation.setRules(t, { agent: made.id, post: 'act', reply: 'off', report: 'draft', dailyCap: 20 }))).rules);
  assert.strictEqual(await daysAgo(fresh.browser), 0);
  await age(85);
  assert.strictEqual(await daysAgo(fresh.browser), 85);
  const kept = await runAs(await as(fresh.browser), async (t) => notices.reconfirm(t, { agent: made.id, version: await ver() }));
  assert.ok(kept.version, JSON.stringify(kept));
  assert.strictEqual(await daysAgo(fresh.browser), 0);
});

test('PR 15 second review R3 (probe B): a link or an unlink at the same moment as a ban waits for it instead of deadlocking, and is refused cleanly', async () => {
  const env = setup({ accounts: { 'github:9731': { accountId: '9731', level: 1, recheckAfter: null }, 'github:9732': { accountId: '9732', level: 1, recheckAfter: null },
    'x:9733': { accountId: '9733', level: 1, recheckAfter: null } } });
  const race = async (browser, step) => {
    const id = (await me(env, browser)).member_id;
    const [ident] = await q(`select id from app.identities where member_id = '${id}' order by created_at limit 1`);
    // T0 stands in for a sign-in with the same method on another device (app.sign_in locks that row FOR UPDATE).
    let release0; const gate0 = new Promise((r) => { release0 = r; });
    let locked; const isLocked = new Promise((r) => { locked = r; });
    const t0 = su.begin(async (t) => { await t.unsafe(`select 1 from app.identities where id = '${ident.id}' for update`); locked(); await gate0; });
    await isLocked;
    const t1 = runAs({ actor: 'member', memberId: id, session: hashOf(browser) }, (t) => step(t));
    await new Promise((r) => setTimeout(r, 300));
    // T2: Aaron bans the member: the update locks the member row, then its trigger ends the sessions.
    const t2 = su.begin(async (t) => { await actAsSystem(t); await t.unsafe(`update app.members set status = 'banned' where id = '${id}'`); });
    await new Promise((r) => setTimeout(r, 300));
    release0();
    const out = await Promise.allSettled([t0, t1, t2]);
    for (const o of out) assert.strictEqual(o.status, 'fulfilled', o.reason && (o.reason.code + ' ' + o.reason.message));
    const [m] = await q(`select status from app.members where id = '${id}'`);
    assert.strictEqual(m.status, 'banned', 'the ban went through');
    return out[1].value;
  };
  const a = await oauth(env, 'github', '9731');
  const [fp] = await q(`select i.fingerprint from app.identities i join app.sessions s on s.member_id = i.member_id where s.token_hash = '${hashOf(a.browser)}'`);
  const linked = await race(a.browser, (t) => store.link(t, { provider: 'github', fingerprints: [fp.fingerprint], keyVersion: 1, level: 1, sessionHash: hashOf(a.browser) }));
  assert.deepStrictEqual(linked, { refused: 'banned' });
  const b = await oauth(env, 'github', '9732');
  await oauth(env, 'x', '9733', { browser: b.browser, query: '?link=1' });
  await oauth(env, 'github', '9732', { browser: b.browser }); // a link signs everyone out (R4): sign in again
  const bid = (await me(env, b.browser)).member_id;
  const [xid] = await q(`select id from app.identities where member_id = '${bid}' and provider = 'x'`);
  const unlinked = await race(b.browser, (t) => store.unlink(t, { identity: xid.id, sessionHash: hashOf(b.browser) }));
  assert.deepStrictEqual(unlinked, { refused: 'not_found' });
  assert.strictEqual(await countIds(bid), 2, 'nothing was unlinked');
});

test('PR 15 second review R3: a deadlock or serialization failure left in a link or unlink is a clean "try again", never an error page', async () => {
  for (const code of ['40P01', '40001', '55P03']) {
    const t = { savepoint: async () => { throw Object.assign(new Error('lost a race'), { code }); }, array: (x) => x };
    assert.deepStrictEqual(await store.unlink(t, { identity: crypto.randomUUID(), sessionHash: 'a'.repeat(64) }), { refused: 'busy' }, code);
    assert.deepStrictEqual(await store.link(t, { provider: 'x', fingerprints: ['b'.repeat(64)], keyVersion: 1, level: 1, sessionHash: 'a'.repeat(64) }), { refused: 'busy' }, code);
  }
  const other = { savepoint: async () => { throw Object.assign(new Error('boom'), { code: 'XX000' }); }, array: (x) => x };
  await assert.rejects(store.unlink(other, { identity: crypto.randomUUID(), sessionHash: 'a'.repeat(64) }), /boom/, 'anything else is still an error');
  // The account page says to try again.
  const who = { memberId: crypto.randomUUID(), trustLevel: 1, isAdmin: false, displayName: 'z', fresh: true };
  const cfg = { ready: true, sessionKey: key(), ipKey: crypto.randomBytes(32), fingerprintKeys: [{ version: 1, key: crypto.randomBytes(32) }] };
  const flow = make({ config: cfg, run: async (ctx) => (ctx.actor === 'anon' ? who : { refused: 'busy' }), providers: {}, sendEmail: async () => {} });
  const r = res();
  await flow.unlink(req('POST', '/auth/account/unlink', { cookie: SESSION + '=' + c.token(32), origin: ORIGIN, body: { id: crypto.randomUUID() } }), r);
  assert.strictEqual(r.getHeader('Location'), '/account?error=busy');
  const page = fs.readFileSync(path.join(root, 'account.js'), 'utf8');
  assert.match(page, /'error=busy': 'Nothing was changed: something else was changing your account at the same moment\. Please try again\.'/);
});

// ---- PR 15, after its re-review (probes E, E3, G) ------------------------------------------------------------------
// An owner on X (level 2); an intruder copies the owner's fresh cookie, links their own GitHub with it, and signs in
// with that GitHub.
async function takeover(tag) {
  const env = setup({ accounts: { ['x:' + tag + 'o']: { accountId: tag + 'o', level: 2, recheckAfter: null }, ['github:' + tag + 'g']: { accountId: tag + 'g', level: 1, recheckAfter: null } } });
  const owner = await oauth(env, 'x', tag + 'o');
  const id = (await me(env, owner.browser)).member_id;
  await promote(su, id); // level 2 is JEVs's promotion (021), not the X method
  const shared = twoBrowsers(owner.browser);
  const copied = shared.get(SESSION);
  const linked = await oauth(env, 'github', tag + 'g', { browser: shared, query: '?link=1' });
  // The intruder keeps the copied cookie whatever the response says to do with it.
  shared.set(SESSION, copied);
  const intruder = await oauth(env, 'github', tag + 'g');
  return { env, owner, id, shared, intruder, linked };
}
// A database call as a browser's session, as the probes made it (the session hash goes with it whether or not the
// session still exists, so this is what a site would send).
const viaSession = (browser, id, extra = {}) => ({ actor: 'member', memberId: id, session: hashOf(browser), ...extra });
const unlinkAs = async (env, browser, identity) => { const r = res(); await env.flow.unlink(req('POST', '/auth/account/unlink', { cookie: browser.header(), origin: ORIGIN, body: { id: identity } }), r); return r.getHeader('Location'); };
const githubOf = async (id) => (await q(`select id from app.identities where member_id = '${id}' and provider = 'github'`))[0].id;
// A containment starts (the watch does this when agents post far too much), ends by itself a moment later, and the
// owner's next read lifts it, which restores "act" as the system's own version (011).
async function containmentCycle(id, browser) {
  await runAs({ actor: 'system' }, (t) => t`insert into app.containments (member_id, reason, measured, usual_x100, ends_at)
    values (${id}, 'volume', 999, 100, now() + interval '1 second')`);
  await new Promise((r) => setTimeout(r, 1500));
  await runAs(viaSession(browser, id), (t) => notices.liftDue(t));
}

test('PR 15 re-review (probe E): the cascade can\'t be escaped by rotating the key from another session or by hiding the raise behind a containment\'s end', async () => {
  const { env, id, shared, intruder } = await takeover('9801');
  await q(`update app.sessions set created_at = now() - interval '20 minutes' where token_hash = '${hashOf(shared)}'`);
  const k1 = c.sha256hex('e-k1-' + Math.random());
  const k2 = c.sha256hex('e-k2-' + Math.random());
  const made = await runAs(viaSession(intruder.browser, id), (t) => agents.create(t, { name: 'e', description: null, keyHash: k1 }));
  // The key is rotated from the copied session, which signed in with the owner's own X, while the agent only drafts
  // (no fresh sign-in needed): K2 is not the intruder method's key.
  // fix 3: that copied session ended with the link (R4), so it can no longer act as anyone; the rotation comes from a
  // live session of the owner's X instead, no fresher than the copy was.
  await assert.rejects(runAs(viaSession(shared, id), (t) => agents.rotate(t, { agent: made.id, keyHash: k2 })), /not_acting/);
  const ownerX = await oauth(env, 'x', '9801o');
  await ago(ownerX.browser, 20);
  assert.strictEqual(await runAs(viaSession(ownerX.browser, id), (t) => agents.rotate(t, { agent: made.id, keyHash: k2 })), true);
  assert.ok((await runAs(viaSession(intruder.browser, id, { fresh: true }), (t) => delegation.setRules(t, { agent: made.id, post: 'act', reply: 'act', report: 'draft', dailyCap: 20 }))).rules);
  await containmentCycle(id, intruder.browser);
  assert.deepStrictEqual({ ...(await latest(made.id)), set_by: undefined }, { post_mode: 'act', reply_mode: 'act', report_mode: 'draft', daily_cap: 20, reason: 'containment_lifted', set_by: undefined });
  assert.strictEqual(await resolves(k2), true);
  const back = await oauth(env, 'x', '9801o');
  assert.strictEqual(await unlinkAs(env, back.browser, await githubOf(id)), '/account?saved=unlinked');
  assert.strictEqual(await resolves(k2), false, 'every key of an agent the removed method created is revoked, whoever made or rotated it');
  assert.strictEqual(await resolves(k1), false);
  assert.deepStrictEqual(await latest(made.id), { post_mode: 'draft', reply_mode: 'draft', report_mode: 'draft', daily_cap: 20, reason: 'signin_unlinked', set_by: 'system' },
    'what the removed method ever raised drafts again, even after the system restored it');
});

test('PR 15 re-review (probe E3): a raise kept only by a containment\'s end, or by an owner\'s re-save, still drafts again on unlink; the owner\'s own raise doesn\'t', async () => {
  const { env, id, intruder } = await takeover('9811');
  const back0 = await oauth(env, 'x', '9811o');
  const theirs = await runAs(viaSession(intruder.browser, id), (t) => agents.create(t, { name: 'e3', description: null, keyHash: c.sha256hex('e3' + Math.random()) }));
  const ours = await runAs(viaSession(back0.browser, id), (t) => agents.create(t, { name: 'ours', description: null, keyHash: c.sha256hex('o3' + Math.random()) }));
  assert.ok((await runAs(viaSession(intruder.browser, id, { fresh: true }), (t) => delegation.setRules(t, { agent: theirs.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 20 }))).rules);
  // On the owner's own agent the intruder raises "reply"; the owner's raise of "post" comes first.
  assert.ok((await runAs(viaSession(back0.browser, id, { fresh: true }), (t) => delegation.setRules(t, { agent: ours.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 20 }))).rules);
  assert.ok((await runAs(viaSession(intruder.browser, id, { fresh: true }), (t) => delegation.setRules(t, { agent: ours.id, post: 'act', reply: 'act', report: 'draft', dailyCap: 20 }))).rules);
  // The owner, not noticing, re-saves the same rules: that kept the intruder's raise, but raised nothing itself.
  assert.ok((await runAs(viaSession(back0.browser, id), (t) => delegation.setRules(t, { agent: ours.id, post: 'act', reply: 'act', report: 'draft', dailyCap: 20 }))).rules);
  await containmentCycle(id, intruder.browser);
  assert.strictEqual((await latest(theirs.id)).reason, 'containment_lifted');
  const back = await oauth(env, 'x', '9811o');
  assert.strictEqual(await unlinkAs(env, back.browser, await githubOf(id)), '/account?saved=unlinked');
  assert.deepStrictEqual(await latest(theirs.id), { post_mode: 'draft', reply_mode: 'draft', report_mode: 'draft', daily_cap: 20, reason: 'signin_unlinked', set_by: 'system' });
  assert.deepStrictEqual(await latest(ours.id), { post_mode: 'act', reply_mode: 'draft', report_mode: 'draft', daily_cap: 20, reason: 'signin_unlinked', set_by: 'system' },
    'the intruder\'s raise of reply is undone; the owner\'s own raise of post stands');
});

test('PR 15 re-review (probe G): a link ends the session that made it, so a copied cookie dies at the moment it is used to take an account over', async () => {
  const { env, id, owner, shared, linked } = await takeover('9821');
  assert.strictEqual(linked.r.getHeader('Location'), '/join?linked=1');
  // The copied cookie is the owner's own session: both are signed out, by design, and the owner is told why.
  for (const b of [shared, owner.browser]) { // the same session: the owner's own, and the intruder's copy of it
    assert.deepStrictEqual(await me(env, b), { signed_in: false });
    assert.strictEqual(await whoOf(b), null, 'no API request can use it any more');
  }
  assert.strictEqual((await q(`select 1 from app.sessions where token_hash = '${hashOf(shared)}'`)).length, 0);
  // Days later it is still dead: nothing made "from" it can be attributed to the owner's method.
  const kh = c.sha256hex('g' + Math.random());
  // fix 3: an ended session no longer acts as the owner at all (it used to, naming no method), so nothing is made from it.
  await assert.rejects(runAs(viaSession(shared, id), (t) => agents.create(t, { name: 'g', description: null, keyHash: kh })), /not_acting/);
  assert.strictEqual((await q(`select 1 from app.agent_keys where key_hash = '${kh}'`)).length, 0, 'an ended session makes nothing');
  // The owner signs in again with X, as the notice says, and the account page explains the sign-out.
  const back = await oauth(env, 'x', '9821o');
  assert.strictEqual((await me(env, back.browser)).member_id, id);
  const [n] = await q(`select body from app.notices where member_id = '${id}' and kind = 'signin_linked'`);
  assert.match(n.body, /every session of yours was signed out, the one that linked it too/);
  assert.match(fs.readFileSync(path.join(root, 'account.html'), 'utf8'), /Adding one signs you out everywhere, this browser too, so you sign in again with any of your methods/);
});

test('PR 15 re-review: a page read that loses a race is retried, and never becomes an error page', async () => {
  let calls = 0;
  const row = { member_id: crypto.randomUUID(), trust_level: 1, is_admin: false, display_name: 'z', fresh: false };
  const flaky = (fails, code = '40P01') => ({ savepoint: async () => { calls++; if (calls <= fails) throw Object.assign(new Error('lost a race'), { code }); return [row]; } });
  calls = 0;
  assert.strictEqual((await store.sessionResolve(flaky(2), 'a'.repeat(64), 7)).memberId, row.member_id, 'two lost races, then it reads');
  assert.strictEqual(calls, 3);
  for (const code of ['40P01', '40001', '55P03']) {
    calls = 0;
    assert.strictEqual(await store.sessionResolve(flaky(99, code), 'a'.repeat(64), 7), null, code + ': every try lost, so not signed in for this one request');
    assert.strictEqual(calls, 3, 'three tries, no more');
  }
  calls = 0;
  await assert.rejects(store.sessionResolve(flaky(1, 'XX000'), 'a'.repeat(64), 7), /lost a race/, 'anything else is still an error');
});

test('PR 15 final re-review, probe J: "sign out everywhere" never quietly ends only this browser when the session read loses its race', async () => {
  const env = setup({ accounts: { 'github:J1': { accountId: 'J1', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', 'J1');
  const b = await oauth(env, 'github', 'J1');
  const id = (await me(env, a.browser)).member_id;
  const before = (await q(`select count(*)::int as n from app.sessions where member_id = '${id}'`))[0].n;
  // The same flow, but every session_resolve loses a deadlock, as it would under contention; everything else is real.
  const losing = make({ config: env.cfg, providers: {}, sendEmail: async () => {}, run: (ctx, fn) => db.tx(web, ctx, (t) => {
    const orig = t.savepoint.bind(t);
    t.savepoint = (f) => orig((s) => {
      const tag = (strings, ...vals) => {
        if (strings.join('').includes('app.session_resolve')) { const e = new Error('deadlock detected'); e.code = '40P01'; throw e; }
        return s(strings, ...vals);
      };
      Object.assign(tag, s);
      return f(tag);
    });
    return fn(t);
  }) });
  const r = res();
  await losing.logout(req('POST', '/auth/logout-everywhere', { cookie: a.browser.header(), origin: ORIGIN }), r, true);
  assert.strictEqual(r.getHeader('Location'), '/account?error=busy', 'the member is told to try again');
  const after = (await q(`select count(*)::int as n from app.sessions where member_id = '${id}'`))[0].n;
  assert.strictEqual(after, before, 'nothing was ended, so nothing pretends to have worked');
  assert.strictEqual((await me(env, b.browser)).signed_in, true, 'the other device is still signed in, and the member knows to retry');
  // Without the race, the same button ends every session.
  const ok = res();
  await env.flow.logout(req('POST', '/auth/logout-everywhere', { cookie: a.browser.header(), origin: ORIGIN }), ok, true);
  assert.strictEqual((await q(`select count(*)::int as n from app.sessions where member_id = '${id}'`))[0].n, 0);
});

// The go-live gate (launch.js) at sign-in. "preview" is no longer a stage (Aaron, Oct 24: "NO preview systems"):
// LAUNCH_STAGE=preview counts as closed, so sign-in stays off even with every other setting present. The preview's
// allow-list paths in signin/flow.js are unreachable and go in the dormant-paths clean-up (R-14).
test('launch gate: LAUNCH_STAGE=preview keeps sign-in off, exactly as closed, even when fully set up', async () => {
  const saved = { ...process.env };
  const key = () => crypto.randomBytes(32).toString('base64');
  Object.assign(process.env, {
    SESSION_SECRET: key(), FINGERPRINT_KEY_1: key(), IP_HASH_KEY: key(),
    DATABASE_URL: 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres', LAUNCH_STAGE: 'preview' });
  try {
    assert.strictEqual(require('../signin/config').load().ready, true, 'every sign-in setting is present');
    delete require.cache[require.resolve('../api/auth.js')];
    const auth = require('../api/auth.js');
    for (const route of ['me', 'github/start']) {
      const r = res(); await auth({ ...req('GET', '/auth/' + route), query: { route } }, r);
      assert.strictEqual(r.statusCode, 503, 'off: ' + route);
    }
  } finally { process.env = saved; delete require.cache[require.resolve('../api/auth.js')]; }
});

// RK82 (migration 021): the site's own database login asks app.sign_in for level 2 directly, as an attacker holding it
// could. The database gives level 1 and records the cap; only JEVs's promotion makes level 2, and no level is raised
// by an identity update either.
test('RK82: a direct sign-in asking for level 2 gets level 1, recorded; JEVs alone makes level 2', async () => {
  const fp = c.sha256hex(crypto.randomUUID());
  const ask = (level) => runAs({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [fp], keyVersion: 1, level,
    displayName: 'Asks for 2', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
  const out = await ask(2);
  const [m] = await q(`select trust_level from app.members where id = '${out.memberId}'`);
  assert.strictEqual(m.trust_level, 1, 'the new member starts at level 1');
  const [i] = await q(`select level from app.identities where member_id = '${out.memberId}'`);
  assert.strictEqual(i.level, 1, 'the method is stored at level 1');
  const [a] = await q(`select detail from app.audit_log where action = 'signup.level_capped' and subject_id = '${out.memberId}'`);
  assert.deepStrictEqual(a.detail, { provider: 'github', asked: 2, given: 1 });
  const [joined] = await q(`select detail from app.audit_log where action = 'member.joined' and subject_id = '${out.memberId}'`);
  assert.strictEqual(joined.detail.level, 1, 'the record says the level given, not the one asked for');
  const alerts = await q(`select member_id, kind, link from app.notices where dedupe_key = 'signin:capped:${out.memberId}'`);
  assert.deepStrictEqual(alerts.map((r) => ({ ...r })), [{ member_id: null, kind: 'alert', link: '/controls' }], 'Aaron is alerted in-app, once');
  // Signing in again asking for 2 still can't raise it.
  await ask(2);
  assert.strictEqual((await q(`select trust_level from app.members where id = '${out.memberId}'`))[0].trust_level, 1);
  // The database owner writing a level-2 method or member directly is capped too: the trigger runs for every writer.
  await assert.doesNotReject(q(`update app.identities set level = 2 where member_id = '${out.memberId}'`));
  assert.strictEqual((await q(`select level from app.identities where member_id = '${out.memberId}'`))[0].level, 1);
  // Replication mode can't switch the cap off: both triggers fire always (the CSO's review).
  const [rep] = await su.begin(async (t) => {
    await t.unsafe(`set local session_replication_role = replica`);
    return t.unsafe(`insert into app.members (display_name, trust_level) values ('Replica', 2) returning id, trust_level`);
  });
  assert.strictEqual(rep.trust_level, 1, 'a new member is capped in replication mode too');
  await su.begin(async (t) => {
    await t.unsafe(`set local session_replication_role = replica`);
    await t.unsafe(`update app.identities set level = 2 where member_id = '${out.memberId}'`);
  });
  assert.strictEqual((await q(`select level from app.identities where member_id = '${out.memberId}'`))[0].level, 1, 'and a method too');
  // JEVs's own promotion is the one way to level 2.
  await promote(su, out.memberId);
  assert.strictEqual((await q(`select trust_level from app.members where id = '${out.memberId}'`))[0].trust_level, 2);
});

// A tripwire (the CLJO's and CSO's reviews, Oct 26): the cap is 1 in phase 1. Raising it brings back sign-in level 2
// (an X business account), and with it code no test covers today: agent_resolve's live-level check (RK58),
// session_resolve lowering a lapsed badge, and its lock order (probe H).
test('RK82 tripwire: the sign-in level cap is 1; raising it must bring back the tests removed in 7f99ed8', () => {
  const src = fs.readFileSync(path.join(root, 'db', 'migrations', '021_signup_level_cap.sql'), 'utf8');
  assert.strictEqual((src.match(/cap constant smallint := 1;/g) || []).length, 2,
    'a migration that raises the cap must restore the four tests removed in commit 7f99ed8 (git show 7f99ed8^:test/signin.test.js ' +
    'and test/agents.test.js: two X badge lapse tests, probe H, and the RK58 agent test) before it merges');
});
