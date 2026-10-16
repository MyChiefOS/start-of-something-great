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
  assert.ok(!s.includes('abc'));
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
    ['regionContinue'], ['regionCancel']]);
  assert.deepStrictEqual(Object.keys(ROUTES).filter((k) => k.startsWith('POST')),
    ['POST email/start', 'POST email/finish', 'POST logout', 'POST logout-all', 'POST account/name', 'POST account/delete', 'POST account/unlink',
      'POST region/continue', 'POST region/cancel'],
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

test('SF4, S5: the join page has one field and no password, and posts only to our own sign-in', () => {
  const html = fs.readFileSync(path.join(root, 'join.html'), 'utf8');
  // The bot-check field (PR 12) is one no person meets: off screen, hidden from screen readers, out of the tab order,
  // never filled in by the browser. Every other field counts.
  const hp = html.match(/<div class="hp" aria-hidden="true">([\s\S]*?)<\/div>/);
  assert.ok(hp, 'the bot-check field is wrapped so nobody meets it');
  assert.match(hp[1], /<input id="website" name="website" type="text" tabindex="-1" autocomplete="off">/);
  assert.match(fs.readFileSync(path.join(root, 'styles.css'), 'utf8'), /\.hp \{ position: absolute; left: -10000px;/);
  const fields = html.replace(hp[0], '').match(/<(input|select|textarea)\b(?![^>]*type="hidden")[^>]*>/g) || [];
  assert.ok(fields.length <= 5, fields.length + ' fields');
  assert.strictEqual(fields.length, 1);
  assert.ok(!/type="password"|autocomplete="(new|current)-password"/.test(html));
  for (const m of html.matchAll(/<form\b[^>]*action="([^"]+)"/g)) assert.match(m[1], /^\/auth\//);
  assert.match(html, /name="robots" content="noindex"/, 'not listed until the preview opens');
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

test('signing in again finds the same member and replaces the session; an X business account is level 2', async () => {
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
  assert.strictEqual((await me(env, x.browser)).trust_level, 2);
  const [row] = await q(`select level, recheck_after is not null as recheck from app.identities where provider = 'x'`);
  assert.deepStrictEqual({ ...row }, { level: 2, recheck: true });
  assert.ok(members[0].n >= 1);
});

test('linking: only while signed in, never by matching email, and never onto someone else\'s account', async () => {
  const env = setup({ accounts: { 'github:4001': { accountId: '4001', name: 'A', level: 1, recheckAfter: null },
    'x:4002': { accountId: '4002', name: 'A on X', level: 1, recheckAfter: null },
    'github:4003': { accountId: '4003', name: 'B', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '4001');
  const memberA = (await q(`select member_id from app.sessions where token_hash = '${c.sha256hex(a.browser.get(SESSION))}'`))[0].member_id;
  const linked = await oauth(env, 'x', '4002', { browser: a.browser, query: '?link=1' });
  assert.strictEqual(linked.r.getHeader('Location'), '/');
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
  await su.begin(async (t) => {
    await t`select set_config('app.actor', 'admin', true)`;
    await t.unsafe(`update app.members set status = 'banned' where id = (select member_id from app.sessions where token_hash = '${c.sha256hex(a.browser.get(SESSION))}')`);
  });
  assert.deepStrictEqual(await me(env, a.browser), { signed_in: false });
  const back = await oauth(env, 'github', '5001');
  assert.strictEqual(back.r.getHeader('Location'), '/join?error=unavailable');
  assert.ok(!back.browser.get(SESSION));
});

test('sessions end after a week idle or 30 days at most, and logging out is a same-site POST', async () => {
  const env = setup({ accounts: { 'github:6001': { accountId: '6001', name: 'L', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '6001');
  const hash = c.sha256hex(a.browser.get(SESSION));
  await q(`update app.sessions set last_seen_at = now() - interval '8 days' where token_hash = '${hash}'`);
  assert.deepStrictEqual(await me(env, a.browser), { signed_in: false }, 'idle');
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
  await su.begin(async (t) => { await t`select set_config('app.actor', 'admin', true)`; await t.unsafe(`update app.members set status = 'banned' where id = '${bannedId}'`); });
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
  await assert.rejects(call({ actor: 'member', memberId: otherId }, victim), /bad sign-in request/, 'one member linking to another');
  await assert.rejects(call({ actor: 'member', memberId: otherId }, null), /bad sign-in request/, 'a plain sign-in while acting as a member');
  const [lvl] = await q(`select trust_level from app.members where id = '${victim}'`);
  assert.strictEqual(lvl.trust_level, 1, 'the victim was not raised to level 2');
});

test('a lapsed X business badge drops back to level 1 at the next sign-in, and during a long session', async () => {
  const env = setup({ accounts: { 'x:9201': { accountId: '9201', level: 2, recheckAfter: new Date(Date.now() + 86400000).toISOString() },
    'github:9202': { accountId: '9202', level: 1, recheckAfter: null } } });
  const x = await oauth(env, 'x', '9201');
  const id = (await me(env, x.browser)).member_id;
  assert.strictEqual((await me(env, x.browser)).trust_level, 2);
  await oauth(env, 'github', '9202', { browser: x.browser, query: '?link=1' });
  await q(`update app.identities set recheck_after = now() - interval '1 day' where member_id = '${id}' and provider = 'x'`);
  await q(`update app.sessions set last_seen_at = now() - interval '2 hours' where member_id = '${id}'`);
  assert.strictEqual((await me(env, x.browser)).trust_level, 1, 'the long session sees the lapse');
  const audit = await q(`select count(*)::int as n from app.audit_log where subject_id = '${id}' and action = 'member.level_changed'`);
  assert.ok(audit[0].n >= 1);
});

test('a lapsed X business badge drops back to level 1 when the member next signs in another way', async () => {
  const env = setup({ accounts: { 'x:9211': { accountId: '9211', level: 2, recheckAfter: new Date(Date.now() + 86400000).toISOString() },
    'github:9212': { accountId: '9212', level: 1, recheckAfter: null } } });
  const x = await oauth(env, 'x', '9211');
  const id = (await me(env, x.browser)).member_id;
  await oauth(env, 'github', '9212', { browser: x.browser, query: '?link=1' });
  assert.strictEqual((await me(env, x.browser)).trust_level, 2, 'still level 2 while the badge is current');
  await q(`update app.identities set recheck_after = now() - interval '1 day' where member_id = '${id}' and provider = 'x'`);
  const g = await oauth(env, 'github', '9212');
  assert.strictEqual((await me(env, g.browser)).trust_level, 1);
});

test('a level Aaron lowers by hand survives the member\'s next sign-in, and no level is raised by hand', async () => {
  const env = setup({ accounts: { 'github:9401': { accountId: '9401', level: 1, recheckAfter: null }, 'github:9402': { accountId: '9402', level: 1, recheckAfter: null } } });
  const members = require('../db/members');
  const adminAct = (fn) => db.tx(web, { actor: 'admin', memberId: '018f3c2e-7b1a-7cde-8f00-0123456789ab' }, fn);
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
  await assert.rejects(db.tx(web, { actor: 'member', memberId: trustedId }, (t) => t`update app.members set level_set_by_admin = 3 where id = ${trustedId}`), /permission denied/);
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
  const asMember = (fn) => db.tx(web, { actor: 'member', memberId: id }, fn);
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
  assert.strictEqual(ok.r.getHeader('Location'), '/');
  assert.strictEqual(await countIds(id), 2);
});

test('PR 15: a link makes no new session (no freshness), ends every other session of the member, and leaves a notice and an audit row', async () => {
  const env = setup({ accounts: { 'github:9511': { accountId: '9511', level: 1, recheckAfter: null }, 'x:9512': { accountId: '9512', level: 1, recheckAfter: null } } });
  const a = await oauth(env, 'github', '9511');
  const otherDevice = await oauth(env, 'github', '9511');
  const id = (await me(env, a.browser)).member_id;
  const token = a.browser.get(SESSION);
  await ago(a.browser, 9);
  const [before] = await q(`select created_at from app.sessions where token_hash = '${hashOf(a.browser)}'`);
  const linked = await oauth(env, 'x', '9512', { browser: a.browser, query: '?link=1&return_to=/account' });
  assert.strictEqual(linked.r.getHeader('Location'), '/account');
  assert.strictEqual(linked.browser.get(SESSION), token, 'the browser keeps the session it had: no new session is made');
  assert.ok(![].concat(linked.r.getHeader('Set-Cookie') || []).some((x) => x.startsWith(SESSION + '=')), 'no session cookie is set');
  const sessions = await q(`select token_hash, created_at from app.sessions where member_id = '${id}'`);
  assert.deepStrictEqual(sessions.map((s) => s.token_hash), [hashOf(a.browser)], 'every other session of the member ended');
  assert.strictEqual(+sessions[0].created_at, +before.created_at, 'the session\'s start time, which decides freshness, is unchanged');
  assert.deepStrictEqual(await me(env, otherDevice.browser), { signed_in: false });
  // A minute later the session is no longer fresh: the link didn't extend it.
  await ago(a.browser, 11);
  assert.strictEqual((await db.tx(web, { actor: 'anon' }, (t) => store.sessionResolve(t, hashOf(a.browser), 7))).fresh, false);
  const notices = await q(`select kind, title, link, subject_kind from app.notices where member_id = '${id}'`);
  assert.deepStrictEqual(notices.map((n) => ({ ...n })), [{ kind: 'signin_linked', title: 'A new sign-in method was linked', link: '/account', subject_kind: 'identity' }]);
  const [au] = await q(`select actor_kind, actor_id, detail from app.audit_log where action = 'member.identity_linked' and subject_id = '${id}'`);
  assert.deepStrictEqual([au.actor_kind, au.actor_id, au.detail], ['member', id, { provider: 'x', sessions_ended: 1 }]);
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
  const ctx = { actor: 'member', memberId: id };
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
  await oauth(env, 'x', '9542', { browser: a.browser, query: '?link=1' });
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
  await assert.rejects(db.tx(web, { actor: 'member', memberId: id, fresh: true }, (t) => t`select * from app.identity_unlink(${xId}::uuid, ${hashOf(a.browser)})`), /fresh_sign_in/);
  assert.strictEqual(await countIds(id), 2);
  await ago(a.browser, 1);
  const stranger = await oauth(setup({ accounts: { 'github:9543': { accountId: '9543', level: 1, recheckAfter: null } } }), 'github', '9543');
  assert.strictEqual(await unlink(stranger.browser, { id: xId }), '/account?error=unlink', 'nobody unlinks another member\'s method');
  assert.strictEqual(await unlink(a.browser, { id: 'not-an-id' }), '/account?error=unlink');
  assert.strictEqual(await countIds(id), 2);
  assert.strictEqual(await unlink(a.browser, { id: xId }), '/account?saved=unlinked');
  assert.strictEqual(await countIds(id), 1);
  assert.strictEqual((await me(env, a.browser)).trust_level, 1, 'the level follows the methods that remain');
  assert.deepStrictEqual(await me(env, otherDevice.browser), { signed_in: false }, 'every other session ended');
  assert.strictEqual((await me(env, a.browser)).signed_in, true, 'this one stays');
  const [n] = await q(`select title from app.notices where member_id = '${id}' and kind = 'signin_unlinked'`);
  assert.strictEqual(n.title, 'A sign-in method was removed');
  const [au] = await q(`select actor_kind, detail from app.audit_log where action = 'member.identity_unlinked' and subject_id = '${id}'`);
  assert.deepStrictEqual([au.actor_kind, au.detail], ['member', { provider: 'x', sessions_ended: 1 }]);
  const githubId = signIns.find((s) => s.provider === 'github').id;
  assert.strictEqual(await unlink(a.browser, { id: githubId }), '/account?error=last_method');
  await assert.rejects(db.tx(web, { actor: 'member', memberId: id }, (t) => t`select * from app.identity_unlink(${githubId}::uuid, ${hashOf(a.browser)})`), /last_method/);
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
  assert.strictEqual((await oauth(env, 'x', '9602', { browser: shared, query: '?link=1' })).r.getHeader('Location'), '/');
  const [row] = await q(`select i.provider from app.sessions s join app.identities i on i.id = s.identity_id where s.token_hash = '${hashOf(owner.browser)}'`);
  assert.strictEqual(row.provider, 'github', 'each session records the method it signed in with; a link doesn\'t change it');
  const intruder = await oauth(env, 'x', '9602');
  assert.strictEqual((await me(env, intruder.browser)).member_id, id);
  const page = res();
  await env.flow.account(req('GET', '/auth/account', { cookie: intruder.browser.header() }), page);
  const ids = Object.fromEntries(JSON.parse(page.body).sign_ins.map((s) => [s.provider, s.id]));
  const unlink = async (b, identity) => { const r = res(); await env.flow.unlink(req('POST', '/auth/account/unlink', { cookie: b.header(), origin: ORIGIN, body: { id: identity } }), r); return r.getHeader('Location'); };
  assert.strictEqual(await unlink(intruder.browser, ids.github), '/account?error=senior', 'the later method can\'t remove the older one');
  assert.strictEqual(await unlink(shared, ids.github), '/account?error=senior', 'nor can the shared session remove the method it signed in with');
  await assert.rejects(db.tx(web, { actor: 'member', memberId: id }, (t) => t`select * from app.identity_unlink(${ids.github}::uuid, ${hashOf(intruder.browser)})`), /not_senior/);
  assert.strictEqual(await countIds(id), 2);
  assert.strictEqual((await me(env, owner.browser)).signed_in, true, 'the owner was not signed out');
  // The owner, signed in with the older method, removes the intruder's: the intruder's session ends.
  const back = await oauth(env, 'github', '9601');
  assert.strictEqual(await unlink(back.browser, ids.x), '/account?saved=unlinked');
  assert.deepStrictEqual(await me(env, intruder.browser), { signed_in: false });
  assert.strictEqual(await countIds(id), 1);
  const again = await oauth(env, 'x', '9602');
  assert.notStrictEqual((await me(env, again.browser)).member_id, id, 'the intruder\'s X no longer reaches the account');
  // A session with no recorded method (made before this migration) can't unlink anything until it signs in again.
  const third = await oauth(env, 'github', '9601');
  assert.strictEqual((await oauth(env, 'x', '9603', { browser: third.browser, query: '?link=1' })).r.getHeader('Location'), '/');
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
  const ctx = { actor: 'member', memberId: id };
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
  assert.deepStrictEqual((await q(`select token_hash from app.sessions where member_id = '${id}'`)).map((s) => s.token_hash), [hashOf(a.browser)]);
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
  const t1 = db.tx(web, { actor: 'member', memberId: ida }, async (t) => { const r = await store.link(t, args(a.browser)); await gate; return r; });
  await new Promise((r) => setTimeout(r, 300));
  const t2 = db.tx(web, { actor: 'member', memberId: idb }, (t) => store.link(t, args(b.browser)));
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
