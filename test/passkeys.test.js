// Release 2, PR 17: passkeys as the required proof for risky grants (requirement D5; criteria PK1 to PK12 in
// ACCEPTANCE.md). End to end against a real Postgres, with software passkeys that make real ES256 credentials and
// answer the way a phone or laptop does, so @simplewebauthn/server's real checks run (test/passkey-helpers.js). No real
// secrets anywhere. Needs TEST_DATABASE_URL like test/db.test.js.
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
const passkey = require('../signin/passkey');
const store = require('../db/signin');
const passkeys = require('../db/passkeys');
const delegation = require('../db/delegation');
const controls = require('../db/controls');
const posts = require('../db/posts');
const jevs = require('../db/jevs');
const { problems } = require('../db/checks');
const { migrate } = require('../scripts/migrate');
const { softAuthenticator } = require('./passkey-helpers');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';

// ---- Tests that need no database -------------------------------------------------------------------------------

test('PK9: passkeys are for dayonegreat.com only, unless Aaron sets a preview by name; no wildcard, no plain HTTP, nothing malformed', () => {
  assert.deepStrictEqual(passkey.relyingParty({}), { rpID: 'dayonegreat.com', origins: ['https://dayonegreat.com'] });
  assert.deepStrictEqual(passkey.relyingParty({ PASSKEY_RP_ID: 'preview-abc.vercel.app', PASSKEY_ORIGINS: 'https://preview-abc.vercel.app' }),
    { rpID: 'preview-abc.vercel.app', origins: ['https://preview-abc.vercel.app'] }, 'a preview, named exactly');
  for (const bad of [
    { PASSKEY_ORIGINS: 'https://*.vercel.app' }, // a wildcard
    { PASSKEY_ORIGINS: 'https://preview-abc.vercel.app' }, // not under the RP ID (dayonegreat.com)
    { PASSKEY_ORIGINS: 'http://dayonegreat.com' }, // plain HTTP
    { PASSKEY_ORIGINS: 'https://dayonegreat.com:8443' }, // a port
    { PASSKEY_ORIGINS: 'https://dayonegreat.com/path' }, // not an origin
    { PASSKEY_ORIGINS: 'https://dayonegreat.com.evil.example' },
    { PASSKEY_RP_ID: 'vercel.app', PASSKEY_ORIGINS: 'https://evil.vercel.app,https://a.vercel.app,https://b.vercel.app,https://c.vercel.app,https://d.vercel.app,https://e.vercel.app' },
    { PASSKEY_RP_ID: 'not a host' }, { PASSKEY_RP_ID: '*.dayonegreat.com' }
  ]) assert.strictEqual(passkey.relyingParty(bad), null, JSON.stringify(bad));
});

test('PK1: a passkey step-up is carried only by people\'s calls, as a fresh sign-in is', async () => {
  const m = '018f3c2e-7b1a-7cde-8f00-0123456789ab';
  const a = '018f3c2e-7b1a-7cde-9f00-0123456789ab';
  for (const bad of [{ actor: 'anon', stepUp: true }, { actor: 'system', stepUp: true }, { actor: 'agent', memberId: m, agentId: a, stepUp: true }]) {
    let reached = false;
    await assert.rejects(db.tx({ begin: async () => { reached = true; } }, bad, () => {}), (e) => !reached && /passkey step-up/.test(e.message), JSON.stringify(bad));
  }
});

test('PK1: the server pins @simplewebauthn/server to an exact version, and no page loads WebAuthn code from anywhere else', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.match(pkg.dependencies['@simplewebauthn/server'], /^\d+\.\d+\.\d+$/, 'an exact version, never a range');
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  assert.strictEqual(lock.packages['node_modules/@simplewebauthn/server'].version, pkg.dependencies['@simplewebauthn/server']);
  const js = fs.readFileSync(path.join(root, 'passkey.js'), 'utf8');
  assert.ok(!/import\s|require\(|https?:\/\//.test(js.replace(/\/\/.*$/gm, '')), 'the browser side is plain, self-contained JavaScript');
});

// ---- End to end against a real database ------------------------------------------------------------------------

if (!SERVER) {
  if (process.env.CI) test('passkey tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('passkeys (PK1 to PK12)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_passkey_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, flow, pk, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const CFG = { ipKey: crypto.randomBytes(32) };

// Fake GitHub and X (no network): the code names the account.
const ACCOUNTS = {};
const providers = Object.fromEntries(['github', 'x'].map((name) => [name, {
  authorizeUrl(cr, { state }) { return 'https://' + name + '.example/authorize?state=' + state; },
  async identify(cr, { code }) { return ACCOUNTS[name + ':' + code.split('|')[1]] || null; }
}]));

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  const cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: CFG.ipKey,
    fingerprintKeys: [{ version: 1, key: crypto.randomBytes(32) }], github: { clientId: 'g', clientSecret: 's' }, x: { clientId: 'x', clientSecret: 's' } };
  flow = make({ config: cfg, run, providers, sendEmail: null });
  pk = passkey.make({ run });
  aaron = await person({ name: 'Aaron' });
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${aaron.id}'`); });
  aaron.ctx = { actor: 'admin', memberId: aaron.id };
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

// ---- Requests, people and their passkeys ----
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, url, { cookie = '', json, form, origin = ORIGIN, site, query = {}, key } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '203.0.113.170', 'x-vercel-ip-country': 'US' };
  if (method === 'POST' && origin) headers.origin = origin;
  if (site) headers['sec-fetch-site'] = site;
  if (key) headers.authorization = 'Bearer ' + key;
  let body;
  if (json !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(json); }
  if (form !== undefined) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(form).toString(); }
  return { method, url, headers, query, body };
}
const out = (r) => ({ status: r.statusCode, json: r.body && /json/.test(String(r.getHeader('content-type'))) ? JSON.parse(r.body) : null, location: r.getHeader('location'), r });

// A member signed in (GitHub, level 2) with a session of their own; { stale: true } makes it an hour old.
async function person({ name = 'Member', stale = false, fp = c.sha256hex(crypto.randomUUID()) } = {}) {
  const token = c.token(32);
  const o = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [fp], keyVersion: 1, level: 2,
    displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await q(`update app.members set display_name = '${name}' where id = '${o.memberId}'`);
  if (stale) await q(`update app.sessions set created_at = now() - interval '1 hour' where token_hash = '${c.sha256hex(token)}'`);
  return { id: o.memberId, fp, cookie: SESSION + '=' + token, hash: c.sha256hex(token), ctx: { actor: 'member', memberId: o.memberId } };
}
// Another session for the same member (another device).
async function again(m, { stale = false } = {}) {
  const n = await person({ fp: m.fp, stale });
  return { ...m, cookie: n.cookie, hash: n.hash };
}
const ago = (m, minutes) => q(`update app.sessions set created_at = now() - interval '${minutes} minutes' where token_hash = '${m.hash}'`);
// Ends this session's step-up, as 6 minutes passing would.
const lapse = (m) => q(`update app.sessions set stepped_up_at = now() - interval '6 minutes' where member_id = '${m.id}' and stepped_up_at is not null`);

const pkCall = async (step, m, json, opts = {}) => { const r = res(); await pk[step](req(json === undefined ? 'GET' : 'POST', '/auth/passkey', { cookie: m.cookie, json, ...opts }), r); return out(r); };
async function enrol(m, device, { label = 'My phone', origin = ORIGIN, rpID, flags } = {}) {
  const o = await pkCall('enrolOptions', m, {});
  if (o.status !== 200) return o;
  return pkCall('enrolFinish', m, { response: device.create(o.json.options, { origin, rpID, flags }), label });
}
async function stepUp(m, device, opts = {}) {
  const o = await pkCall('assertOptions', m, {});
  if (o.status !== 200) return o;
  return pkCall('assertFinish', m, { response: device.get(o.json.options, { origin: ORIGIN, ...opts }) });
}
// A member with a passkey of their own, enrolled the real way.
async function withPasskey(opts) {
  const m = await person(opts);
  m.device = softAuthenticator();
  const e = await enrol(m, m.device);
  assert.strictEqual(e.status, 201, JSON.stringify(e.json));
  return m;
}

const agentsApi = async (m, method, route, json) => { const r = res(); await require('../api/agents.js').handle(req(method, '/api/agents/' + route, { cookie: m.cookie, json, query: { route } }), r, run, CFG); return out(r); };
const feedPost = async (m, json) => { const r = res(); await require('../api/feed.js').handle(req('POST', '/api/feed', { cookie: m.cookie, json }), r, run); return out(r); };
const agentSays = async (key, body) => { const r = res(); await require('../api/feed.js').handle(req('POST', '/api/feed', { key, json: { body } }), r, run); return out(r); };
const notifyPost = async (m, route, json) => { const r = res(); await require('../api/notify.js').handle(req('POST', '/api/notify/' + route, { cookie: m.cookie, json, query: { route } }), r, run, {}); return out(r); };
const form = async (step, m, url, body, opts = {}) => { const r = res(); await flow[step](req('POST', url, { cookie: m.cookie, form: body, ...opts }), r); return out(r); };
const audits = async (memberId, action) => q(`select actor_kind, detail from app.audit_log where subject_id = '${memberId}' and action = '${action}' order by at, id`);
const noticesOf = async (memberId, kind) => q(`select title, body, dedupe_key from app.notices where member_id = '${memberId}' and kind = '${kind}' order by created_at`);
const isStepUp = (r) => r.status === 403 && r.json && r.json.step_up && typeof r.json.step_up.has_passkey === 'boolean';

// The full GitHub or X round trip, as a browser would do it. browser: { cookie } of whoever is signed in already.
async function oauth(provider, account, { cookie = '', link = false } = {}) {
  const r1 = res();
  await flow.start(req('GET', '/auth/' + provider + '/start' + (link ? '?link=1&return_to=%2Faccount' : ''), { cookie, site: link ? 'same-origin' : undefined }), r1, provider);
  if (r1.statusCode !== 302) return { start: out(r1) };
  const state = new URL(r1.getHeader('Location')).searchParams.get('state');
  const jarCookies = [cookie, ...[].concat(r1.getHeader('Set-Cookie') || []).map((s) => s.split(';')[0])].filter(Boolean).join('; ');
  const r2 = res();
  await flow.callback(req('GET', '/auth/' + provider + '/callback?code=' + encodeURIComponent(state + '|' + account) + '&state=' + state, { cookie: jarCookies }), r2, provider);
  const set = [].concat(r2.getHeader('Set-Cookie') || []).map((s) => s.split(';')[0]).find((s) => s.startsWith(SESSION + '=') && s.length > SESSION.length + 1);
  return { start: out(r1), done: out(r2), cookie: set || cookie };
}
// As if a day had passed since the member's passkeys were added (the 24-hour wait before linking a method).
const ageKeys = (memberId) => q(`update app.passkeys set created_at = now() - interval '25 hours' where member_id = '${memberId}'`);
const sessionOf = async (cookie) => (await q(`select member_id, token_hash from app.sessions where token_hash = '${c.sha256hex(cookie.split('=')[1])}'`))[0];

test('S1: the database passes the coverage check with the passkey tables, and matches the reviewed snapshot', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('PK2: adding a passkey needs a fresh sign-in (the last 10 minutes, by the database clock), and keeps public keys only', async () => {
  const stale = await person({ name: 'Old session', stale: true });
  const o = await pkCall('enrolOptions', stale, {});
  assert.deepStrictEqual([o.status, o.json.reauth], [403, '/join?return_to=%2Faccount']);
  // Fresh when it asked, stale when it answered: the database refuses at the end too.
  const m = await person({ name: 'Slow to answer' });
  const device = softAuthenticator();
  const opts = await pkCall('enrolOptions', m, {});
  assert.strictEqual(opts.status, 200);
  assert.deepStrictEqual([opts.json.options.rp.id, opts.json.options.authenticatorSelection.userVerification, opts.json.options.authenticatorSelection.residentKey,
    opts.json.options.attestation], ['dayonegreat.com', 'required', 'preferred', 'none'], 'user verification required; discoverable keys preferred, not required');
  await ago(m, 11);
  const late = await pkCall('enrolFinish', m, { response: device.create(opts.json.options, { origin: ORIGIN }), label: 'Late' });
  assert.deepStrictEqual([late.status, late.json.reauth], [403, '/join?return_to=%2Faccount']);
  await ago(m, 0);
  // Fresh: one tap adds it.
  const ok = await enrol(m, device, { label: 'Kitchen laptop' });
  assert.strictEqual(ok.status, 201, JSON.stringify(ok.json));
  const [row] = await q(`select * from app.passkeys where member_id = '${m.id}'`);
  assert.deepStrictEqual(Object.keys(row).sort(), ['backed_up', 'created_at', 'credential_id', 'id', 'identity_id', 'label', 'last_used_at', 'member_id', 'public_key', 'sign_count', 'transports'],
    'a credential ID, a public key, a counter, transports, dates and a label: nothing private');
  assert.deepStrictEqual([row.credential_id, row.label, row.transports], [device.id, 'Kitchen laptop', 'hybrid,internal']);
  const list = await pkCall('list', m);
  assert.deepStrictEqual(list.json.passkeys.map((k) => k.label), ['Kitchen laptop']);
  assert.ok(!JSON.stringify(list.json).includes(row.public_key), 'the page is never sent a public key');
  // Recorded, told, with no key material and no label in the audit log.
  const [au] = await audits(m.id, 'passkey.enrolled');
  assert.deepStrictEqual([au.actor_kind, au.detail], ['member', { passkey: row.id, recovery: false, sessions_ended: 0 }]);
  assert.strictEqual((await noticesOf(m.id, 'passkey_added')).length, 1);
  // A member who already has one adds another only after confirming with it, so a stolen fresh cookie can't add a key.
  const second = softAuthenticator();
  const refused = await enrol(m, second, { label: 'Thief' });
  assert.ok(isStepUp(refused) && refused.json.step_up.has_passkey === true, JSON.stringify(refused.json));
  assert.strictEqual((await stepUp(m, device)).status, 200);
  assert.strictEqual((await enrol(m, second, { label: 'Work phone' })).status, 201);
  assert.strictEqual((await enrol(m, second, { label: 'Again' })).status, 409, 'the same passkey twice is refused (and excluded in the options)');
});

test('PK3: each risky grant is refused without a passkey check in the last 5 minutes, and allowed with one', async () => {
  const o = await withPasskey({ name: 'Grants' });
  const made = await agentsApi(o, 'POST', '', { name: 'Grant agent' });
  assert.strictEqual(made.status, 201, 'creating an agent (it starts at draft) needs none');
  const agent = made.json.agent_id;
  const rules = (set) => agentsApi(o, 'POST', 'rules', { agent, post: 'draft', reply: 'draft', report: 'draft', daily_cap: 20, ...set });
  // Letting it act on its own.
  let r = await rules({ post: 'act' });
  assert.ok(isStepUp(r), JSON.stringify(r.json));
  assert.strictEqual((await stepUp(o, o.device)).status, 200);
  assert.strictEqual((await rules({ post: 'act' })).status, 201);
  // Raising its cap, once the 5 minutes are over.
  await lapse(o);
  assert.ok(isStepUp(await rules({ post: 'act', daily_cap: 50 })));
  await stepUp(o, o.device);
  assert.strictEqual((await rules({ post: 'act', daily_cap: 50 })).status, 201);
  // A new key for an agent that acts.
  await lapse(o);
  assert.ok(isStepUp(await agentsApi(o, 'POST', 'key', { agent })));
  await stepUp(o, o.device);
  assert.strictEqual((await agentsApi(o, 'POST', 'key', { agent })).status, 201);
  // The day-90 keep.
  const version = (await run(o.ctx, (t) => delegation.current(t, agent))).version;
  await lapse(o);
  assert.ok(isStepUp(await agentsApi(o, 'POST', 'reconfirm', { agent, version })));
  await stepUp(o, o.device);
  assert.strictEqual((await agentsApi(o, 'POST', 'reconfirm', { agent, version })).status, 201);
  // The database holds the line even if the site forgets: without the step-up flag, it refuses each of them.
  const fresh = { ...o.ctx, fresh: true };
  assert.deepStrictEqual(await run(fresh, (t) => delegation.setRules(t, { agent, post: 'act', reply: 'act', report: 'draft', dailyCap: 50 })), { refused: 'step_up' });
  assert.deepStrictEqual(await run(fresh, (t) => delegation.setRules(t, { agent, post: 'act', reply: 'draft', report: 'draft', dailyCap: 60 })), { refused: 'step_up' });
  await assert.rejects(run(fresh, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${agent}, ${c.sha256hex('sneaky')})`), /step_up/);
  await assert.rejects(run(fresh, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${agent}, 'act', 'draft', 'draft', 50, 'reconfirmed')`), /step_up/);
  // A stale session is still told to sign in again first: the fresh rule stands, and the passkey is in addition.
  await ago(o, 30);
  await stepUp(o, o.device);
  const staleAsk = await rules({ post: 'act', reply: 'act' });
  assert.deepStrictEqual([staleAsk.status, staleAsk.json.reauth], [403, '/join?return_to=%2Fagents']);
});

test('PK3: deleting an account and linking a sign-in method need a passkey check too; unlinking a newer method needs only a fresh sign-in', async () => {
  // Deleting.
  const leaving = await withPasskey({ name: 'Leaving' });
  const ask = () => form('deleteAccount', leaving, '/auth/account/delete', { confirm: 'DELETE' });
  assert.strictEqual((await ask()).location, '/account?error=step_up#passkeys');
  assert.strictEqual(Number((await q(`select count(*) as n from app.jevs_decisions where member_id = '${leaving.id}' and action = 'account.delete'`))[0].n), 0,
    'refused before JEVs is even asked, so a stolen cookie can\'t start a deletion review');
  assert.deepStrictEqual(await run({ ...leaving.ctx, fresh: true }, (t) => store.deleteAccount(t)), { refused: 'step_up' }, 'the database refuses too');
  await stepUp(leaving, leaving.device);
  assert.strictEqual((await ask()).location, '/join?deleted=1');
  assert.strictEqual(Number((await q(`select count(*) as n from app.passkeys where member_id = '${leaving.id}'`))[0].n), 0, 'the passkey goes with the account');
  // Linking: GitHub first, then X.
  ACCOUNTS['github:pk-link'] = { accountId: 'pk-link', level: 1, recheckAfter: null };
  ACCOUNTS['x:pk-link'] = { accountId: 'pk-link', level: 1, recheckAfter: null };
  const g = await oauth('github', 'pk-link');
  const m = { cookie: g.cookie, id: (await sessionOf(g.cookie)).member_id, hash: (await sessionOf(g.cookie)).token_hash, device: softAuthenticator() };
  // No passkey yet: sent to add one (which needs only this fresh sign-in), never to a weaker check.
  const none = await oauth('x', 'pk-link', { cookie: m.cookie, link: true });
  assert.strictEqual(none.start.location, '/account?error=step_up#passkeys');
  const noKey = await pkCall('assertOptions', m, {});
  assert.deepStrictEqual([noKey.status, noKey.json.step_up.has_passkey, noKey.json.step_up.enrol], [403, false, '/account#passkeys']);
  assert.strictEqual((await enrol(m, m.device)).status, 201);
  assert.strictEqual((await oauth('x', 'pk-link', { cookie: m.cookie, link: true })).start.location, '/account?error=step_up#passkeys');
  await stepUp(m, m.device);
  // Not within 24 hours of the account's first passkey (the review, 1d), at the start and in the database.
  assert.strictEqual((await oauth('x', 'pk-link', { cookie: m.cookie, link: true })).start.location, '/account?error=link_wait');
  await assert.rejects(run({ actor: 'member', memberId: m.id, fresh: true, stepUp: true }, (t) => t`select * from app.identity_link('x',
    ${t.array([c.sha256hex('early')])}::text[], 1::smallint, 1::smallint, null::timestamptz, ${m.hash}, null)`), /passkey_new/);
  assert.match((await pkCall('list', m)).json.linking_from, /^\d{4}-/, 'the account page can say when linking opens');
  await ageKeys(m.id);
  const linked = await oauth('x', 'pk-link', { cookie: m.cookie, link: true });
  assert.strictEqual(linked.done.location, '/account');
  assert.strictEqual(Number((await q(`select count(*) as n from app.identities where member_id = '${m.id}'`))[0].n), 2);
  // The database refuses a link without the flag, even from a fresh session.
  await assert.rejects(run({ actor: 'member', memberId: m.id, fresh: true }, (t) => t`select * from app.identity_link('x', ${t.array([c.sha256hex('another')])}::text[],
    1::smallint, 1::smallint, null::timestamptz, ${m.hash}, null)`), /step_up/);
  // Unlinking a method added after this session's own needs no passkey (the review, 1e): PR 15's seniority rule and its
  // fresh sign-in decide, so whoever holds the older method can always remove a newer one, as before passkeys.
  const [xId] = await q(`select id from app.identities where member_id = '${m.id}' and provider = 'x'`);
  await lapse(m);
  await ago(m, 11);
  assert.strictEqual((await form('unlink', m, '/auth/account/unlink', { id: xId.id })).location, '/account?error=fresh_method', 'the fresh sign-in still counts');
  await ago(m, 0);
  assert.strictEqual((await form('unlink', m, '/auth/account/unlink', { id: xId.id })).location, '/account?saved=unlinked');
});

test('PK3: every one of Aaron\'s controls needs a passkey check: brakes, bans, deletion reviews, the review queue and appeals', async () => {
  aaron.device = softAuthenticator();
  assert.strictEqual((await enrol(aaron, aaron.device)).status, 201);
  const target = await person({ name: 'Target' });
  // Something for each control to act on: a post to review, a containment with an appeal, a deletion review.
  const p = await run(target.ctx, async (t) => {
    const made = await posts.create(t, { body: 'a post Aaron reviews' });
    made.jevs = await jevs.check(t, { action: 'post.create', subject: made.id, body: 'a post Aaron reviews' });
    return made;
  });
  const d = p.jevs;
  await su.begin(async (t) => { await t.unsafe('set local role dog_jevs'); await t.unsafe(`insert into app.deletion_reviews (member_id, decision_id) values ('${target.id}', '${d.decision}')`); });
  const [review] = await q(`select id from app.deletion_reviews where member_id = '${target.id}'`);
  const [cn] = await run({ actor: 'system' }, (t) => t`insert into app.containments (member_id, reason, measured, usual_x100, ends_at) values (${target.id}, 'volume', 600, 0, now() + interval '1 day') returning id`);
  assert.deepStrictEqual(await run(target.ctx, (t) => require('../db/notify').appeal(t, { containment: cn.id, note: 'please look again' })), { ok: true });
  const steps = [
    ['a brake', () => feedPost(aaron, { brake: { member: target.id, people_per_hour: 5, note: 'slow down' } }), 201],
    ['lifting it', async () => feedPost(aaron, { lift: (await q(`select id from app.brakes where member_id = '${target.id}' and lifted_at is null`))[0].id }), 200],
    ['a ban', () => feedPost(aaron, { ban: target.id, note: 'test' }), 200],
    ['an unban', () => feedPost(aaron, { unban: target.id, note: 'test' }), 200],
    ['a deletion review', () => feedPost(aaron, { deletion_review: review.id, decision: 'keep_disabled' }), 200],
    ['a review decision', () => feedPost(aaron, { review: p.id, decision: 'remove' }), 200],
    ['an appeal decision', () => notifyPost(aaron, 'appeals', { containment: cn.id, decision: 'keep' }), 200]
  ];
  for (const [what, step, ok] of steps) {
    await lapse(aaron);
    const refused = await step();
    assert.ok(isStepUp(refused), what + ': ' + JSON.stringify(refused.json));
    assert.strictEqual((await stepUp(aaron, aaron.device)).status, 200);
    const done = await step();
    assert.strictEqual(done.status, ok, what + ': ' + JSON.stringify(done.json));
  }
  // The database refuses Aaron's brakes, bans and deletion reviews without the flag, whatever the site does.
  await assert.rejects(run(aaron.ctx, (t) => controls.setBrake(t, { member: target.id, people_per_hour: 1, note: 'x' })), /step_up/);
  const active = await person({ name: 'Still active' });
  await assert.rejects(run({ ...aaron.ctx, note: 'x' }, (t) => controls.setStatus(t, { member: active.id, status: 'banned' })), /step_up/);
  await assert.rejects(run(aaron.ctx, (t) => controls.decideDeletion(t, { review: review.id, decision: 'restore' })), /step_up/);
  // Aaron renaming himself is not a control.
  assert.strictEqual(await run(aaron.ctx, (t) => store.rename(t, 'Aaron')), true);
});

test('PK4: drafting never needs a passkey, even for a member who has none', async () => {
  const o = await person({ name: 'No passkey' });
  const made = await agentsApi(o, 'POST', '', { name: 'Drafter' });
  assert.strictEqual(made.status, 201);
  const agent = made.json.agent_id;
  for (const set of [{ post: 'off' }, { post: 'draft' }, { post: 'draft', daily_cap: 10 }, { post: 'off', reply: 'off', report: 'off', daily_cap: 1 }, { post: 'draft', daily_cap: 1 }]) {
    const r = await agentsApi(o, 'POST', 'rules', { agent, post: 'draft', reply: 'draft', report: 'draft', daily_cap: 1, ...set });
    assert.strictEqual(r.status, 201, JSON.stringify(set) + ' ' + JSON.stringify(r.json));
  }
  const draft = await agentSays(made.json.key, 'Words waiting for my owner');
  assert.strictEqual(draft.status, 202);
  assert.strictEqual((await agentsApi(o, 'POST', 'approve', { draft: draft.json.draft_id, hash: c.sha256hex('Words waiting for my owner') })).status, 201, 'approving a draft');
  const another = await agentsApi(o, 'POST', '', { name: 'Second drafter' });
  const d2 = await agentSays(another.json.key, 'Something to decline');
  assert.strictEqual((await agentsApi(o, 'POST', 'decline', { draft: d2.json.draft_id })).status, 200, 'declining a draft');
  assert.strictEqual((await agentsApi(o, 'POST', 'key', { agent })).status, 201, 'a new key for an agent that only drafts');
  assert.strictEqual((await agentsApi(o, 'POST', 'revoke', { agent })).status, 200, 'revoking');
  assert.strictEqual((await feedPost(o, { body: 'A post of my own' })).status, 201, 'posting');
  assert.strictEqual(Number((await q(`select count(*) as n from app.passkeys where member_id = '${o.id}'`))[0].n), 0);
});

test('PK5: a challenge is used once, lasts 2 minutes, and belongs to the session that asked for it', async () => {
  const m = await withPasskey({ name: 'Challenges' });
  // Replayed: the same answer twice.
  const opts = await pkCall('assertOptions', m, {});
  const answer = m.device.get(opts.json.options, { origin: ORIGIN });
  assert.strictEqual((await pkCall('assertFinish', m, { response: answer })).status, 200);
  const replay = await pkCall('assertFinish', m, { response: answer });
  assert.strictEqual(replay.status, 409, 'used up');
  // Expired.
  const o2 = await pkCall('assertOptions', m, {});
  assert.strictEqual(o2.json.options.timeout, 120000);
  await q(`update app.passkey_challenges set expires_at = now() - interval '1 second' where session_id = (select id from app.sessions where token_hash = '${m.hash}')`);
  assert.strictEqual((await pkCall('assertFinish', m, { response: m.device.get(o2.json.options, { origin: ORIGIN }) })).status, 409);
  // Another session of the same member can't answer this one's challenge.
  const other = await again(m);
  const o3 = await pkCall('assertOptions', m, {});
  assert.strictEqual((await pkCall('assertFinish', other, { response: m.device.get(o3.json.options, { origin: ORIGIN }) })).status, 409);
  // A made-up challenge (signed properly, but never issued: the database has no such row), and one of ours after a
  // failed answer (failing uses it up too).
  assert.strictEqual((await pkCall('assertFinish', m, { response: m.device.get(o3.json.options, { origin: ORIGIN, challenge: c.token(32) }) })).status, 409);
  const o4 = await pkCall('assertOptions', m, {});
  assert.strictEqual((await pkCall('assertFinish', m, { response: m.device.get(o4.json.options, { origin: 'https://evil.example' }) })).status, 403);
  assert.strictEqual((await pkCall('assertFinish', m, { response: m.device.get(o4.json.options, { origin: ORIGIN }) })).status, 409, 'a failed answer used it up');
  // Only a hash is stored, and challenges end with their session.
  const [ch] = await q(`select challenge_hash from app.passkey_challenges where session_id = (select id from app.sessions where token_hash = '${m.hash}') limit 1`).then((x) => x.length ? x : [null]);
  if (ch) assert.match(ch.challenge_hash, /^[0-9a-f]{64}$/);
  await pkCall('assertOptions', m, {});
  const r = res(); await flow.logout(req('POST', '/auth/logout', { cookie: m.cookie, form: {} }), r);
  assert.strictEqual(Number((await q(`select count(*) as n from app.passkey_challenges c join app.sessions s on s.id = c.session_id where s.token_hash = '${m.hash}'`))[0].n), 0);
  assert.strictEqual(Number((await q(`select count(*) as n from app.passkey_challenges where session_id not in (select id from app.sessions)`))[0].n), 0, 'none left behind');
  // At most 5 waiting a session.
  const busy = await person({ name: 'Busy' });
  busy.device = softAuthenticator();
  await enrol(busy, busy.device);
  const codes = [];
  for (let i = 0; i < 6; i++) codes.push((await pkCall('assertOptions', busy, {})).status);
  assert.deepStrictEqual(codes, [200, 200, 200, 200, 200, 429]);
});

test('PK6: a wrong origin, a wrong RP ID or no user verification is refused, when adding a passkey and when using one', async () => {
  const m = await person({ name: 'Origins' });
  const device = softAuthenticator();
  assert.strictEqual((await enrol(m, device, { origin: 'https://dayonegreat.com.evil.example' })).status, 400);
  assert.strictEqual((await enrol(m, device, { origin: 'https://evil.example' })).status, 400);
  assert.strictEqual((await enrol(m, device, { rpID: 'evil.example' })).status, 400);
  assert.strictEqual((await enrol(m, device, { flags: 0x01 | 0x40 })).status, 400, 'no user verification on the device');
  assert.strictEqual(Number((await q(`select count(*) as n from app.passkeys where member_id = '${m.id}'`))[0].n), 0);
  assert.strictEqual((await enrol(m, device)).status, 201);
  for (const bad of [{ origin: 'https://evil.example' }, { origin: 'http://dayonegreat.com' }, { rpID: 'evil.example' }, { flags: 0x01 }]) {
    assert.strictEqual((await stepUp(m, device, bad)).status, 403, JSON.stringify(bad));
  }
  assert.strictEqual((await q(`select stepped_up_at from app.sessions where token_hash = '${m.hash}'`))[0].stepped_up_at, null);
  // From another site (a cross-origin post) nothing happens at all.
  const r = res(); await pk.assertOptions(req('POST', '/auth/passkey/assert/options', { cookie: m.cookie, json: {}, origin: 'https://evil.example' }), r);
  assert.strictEqual(r.statusCode, 403);
  // A preview configured by name accepts its own origin and nothing else.
  const preview = passkey.make({ run, rp: passkey.relyingParty({ PASSKEY_RP_ID: 'preview-pk.vercel.app', PASSKEY_ORIGINS: 'https://preview-pk.vercel.app' }) });
  const r2 = res(); await preview.assertOptions(req('POST', '/x', { cookie: m.cookie, json: {} }), r2);
  const opts = JSON.parse(r2.body).options;
  assert.strictEqual(opts.rpId, 'preview-pk.vercel.app');
  const r3 = res(); await preview.assertFinish(req('POST', '/x', { cookie: m.cookie, json: { response: device.get(opts, { origin: ORIGIN }) } }), r3);
  assert.strictEqual(r3.statusCode, 403, 'a passkey made for dayonegreat.com doesn\'t answer for the preview');
});

test('PK7: a sign counter that goes backwards is refused and recorded; a passkey that never counts (synced ones) keeps working', async () => {
  const m = await withPasskey({ name: 'Counter' });
  for (let i = 0; i < 3; i++) assert.strictEqual((await stepUp(m, m.device)).status, 200);
  const [k] = await q(`select id, sign_count from app.passkeys where member_id = '${m.id}'`);
  assert.strictEqual(Number(k.sign_count), 3);
  const back = await stepUp(m, m.device, { counter: 2 });
  assert.strictEqual(back.status, 403);
  assert.match(back.json.error, /copied/);
  const [au] = await audits(m.id, 'passkey.counter_regression');
  assert.deepStrictEqual(au.detail, { passkey: k.id, stored: 3, seen: 2 });
  assert.strictEqual((await noticesOf(m.id, 'passkey_counter')).length, 1, 'the member is told, with a notice of its own kind');
  assert.strictEqual((await noticesOf(m.id, 'passkey_removed')).length, 0);
  assert.strictEqual((await stepUp(m, m.device, { counter: 3 })).status, 403, 'the same count again is refused too');
  assert.strictEqual((await stepUp(m, m.device, { counter: 9 })).status, 200, 'moving on works');
  const synced = await withPasskey({ name: 'Never counts' });
  for (let i = 0; i < 3; i++) assert.strictEqual((await stepUp(synced, synced.device, { counter: 0 })).status, 200);
  // Two checks racing with the same count: only one wins (the passkey's row is locked).
  const racer = await withPasskey({ name: 'Racer' });
  const [o1, o2] = [await pkCall('assertOptions', racer, {}), await pkCall('assertOptions', racer, {})];
  const both = await Promise.all([o1, o2].map((o) => pkCall('assertFinish', racer, { response: racer.device.get(o.json.options, { origin: ORIGIN, counter: 5 }) })));
  assert.deepStrictEqual(both.map((x) => x.status).sort(), [200, 403]);
});

test('PK8: recovery: a fresh sign-in starts a 72-hour cool-off with a notice, risky grants stay blocked, any session can cancel it', async () => {
  const m = await withPasskey({ name: 'Lost phone' });
  const agent = (await agentsApi(m, 'POST', '', { name: 'Recovery agent' })).json.agent_id;
  assert.strictEqual((await stepUp(m, m.device)).status, 200);
  // A stale session can't start it.
  const old = await again(m, { stale: true });
  const staleStart = await pkCall('recoveryStart', old, {});
  assert.deepStrictEqual([staleStart.status, staleStart.json.reauth], [403, '/join?return_to=%2Faccount']);
  // Started: the step-up just given ends, a notice says what happens, risky grants are blocked.
  const started = await pkCall('recoveryStart', m, {});
  assert.strictEqual(started.status, 201);
  assert.ok(Math.abs(new Date(started.json.recovery.ends_at) - Date.now() - 72 * 3600000) < 60000, '72 hours');
  const blocked = await agentsApi(m, 'POST', 'rules', { agent, post: 'act', reply: 'draft', report: 'draft', daily_cap: 20 });
  assert.ok(isStepUp(blocked) && blocked.json.step_up.recovery_until, JSON.stringify(blocked.json));
  assert.strictEqual((await pkCall('assertOptions', m, {})).status, 403, 'no passkey check is offered meanwhile');
  const ch = c.token(32);
  await run(m.ctx, (t) => passkeys.challenge(t, { sessionHash: m.hash, purpose: 'step_up', challengeHash: c.sha256hex(ch) }));
  assert.deepStrictEqual(await run(m.ctx, (t) => passkeys.assert(t, { sessionHash: m.hash, challengeHash: c.sha256hex(ch), credentialId: m.device.id, signCount: 99 })),
    { refused: 'recovery' }, 'the database counts nothing as a step-up during the cool-off');
  assert.strictEqual((await enrol(m, softAuthenticator())).status, 403, 'no new passkey during the cool-off');
  assert.strictEqual((await pkCall('remove', m, { id: (await q(`select id from app.passkeys where member_id = '${m.id}'`))[0].id })).status, 403);
  assert.strictEqual((await pkCall('recoveryStart', m, {})).status, 409, 'one at a time');
  const [n] = await noticesOf(m.id, 'passkey_recovery');
  assert.match(n.body, /72 hours/);
  // Any session, even an old one, can cancel it; then the passkey works again.
  assert.strictEqual((await pkCall('recoveryCancel', old, {})).status, 200);
  assert.strictEqual((await pkCall('recoveryCancel', old, {})).status, 404);
  assert.strictEqual((await stepUp(m, m.device)).status, 200);
  assert.strictEqual((await agentsApi(m, 'POST', 'rules', { agent, post: 'act', reply: 'draft', report: 'draft', daily_cap: 20 })).status, 201);
  // Started again and left to run: still blocked when the 72 hours are over, until a new passkey is added, which
  // then needs no old one and completes the recovery.
  assert.strictEqual((await pkCall('recoveryStart', m, {})).status, 201);
  await q(`update app.passkey_recoveries set ends_at = now() - interval '1 minute' where member_id = '${m.id}' and cancelled_at is null`);
  assert.ok(isStepUp(await agentsApi(m, 'POST', 'key', { agent })));
  const fresh = softAuthenticator();
  const done = await enrol(m, fresh, { label: 'New phone' });
  assert.deepStrictEqual([done.status, done.json.recovery_completed], [201, true]);
  assert.strictEqual((await stepUp(m, fresh)).status, 200);
  assert.strictEqual((await agentsApi(m, 'POST', 'key', { agent })).status, 201);
  const trail = (await q(`select action from app.audit_log where subject_id = '${m.id}' and action like 'passkey.recovery%' order by at, id`)).map((x) => x.action);
  assert.deepStrictEqual(trail, ['passkey.recovery_started', 'passkey.recovery_cancelled', 'passkey.recovery_started', 'passkey.recovery_completed']);
  assert.deepStrictEqual((await noticesOf(m.id, 'passkey_recovery')).map((x) => x.title), ['Passkey recovery started', 'Passkey recovery cancelled', 'Passkey recovery started']);
});

test('PK10: removing a passkey needs a passkey check, never removes the last one, and always tells the member', async () => {
  const m = await withPasskey({ name: 'Remover' });
  const spare = softAuthenticator();
  await stepUp(m, m.device);
  assert.strictEqual((await enrol(m, spare, { label: 'Spare' })).status, 201);
  const [first, second] = await q(`select id from app.passkeys where member_id = '${m.id}' order by created_at`);
  await lapse(m);
  assert.ok(isStepUp(await pkCall('remove', m, { id: second.id })));
  assert.strictEqual(await run(m.ctx, (t) => passkeys.remove(t, { sessionHash: m.hash, passkey: second.id })), 'step_up', 'the database decides');
  await stepUp(m, spare);
  assert.strictEqual((await pkCall('remove', m, { id: second.id })).status, 200);
  assert.ok(isStepUp(await pkCall('remove', m, { id: first.id })), 'the step-up the removed passkey gave ended with it');
  await stepUp(m, m.device);
  assert.strictEqual((await pkCall('remove', m, { id: first.id })).status, 409, 'never the last one');
  const [au] = await audits(m.id, 'passkey.removed');
  assert.deepStrictEqual(au.detail, { passkey: second.id, reason: 'member' });
  assert.strictEqual((await noticesOf(m.id, 'passkey_removed')).length, 1);
  assert.strictEqual((await pkCall('remove', m, { id: crypto.randomUUID() })).status, 404);
});

test('PK11: whatever a linked method did dies with it: unlinking a method removes the passkeys added from its sessions, and seniority decides removal', async () => {
  ACCOUNTS['github:pk-owner'] = { accountId: 'pk-owner', level: 1, recheckAfter: null };
  ACCOUNTS['x:pk-owner'] = { accountId: 'pk-owner', level: 1, recheckAfter: null };
  // The owner signs in with GitHub (their oldest method), adds a passkey, and links X after confirming with it.
  const g = await oauth('github', 'pk-owner');
  const owner = { cookie: g.cookie, id: (await sessionOf(g.cookie)).member_id, hash: (await sessionOf(g.cookie)).token_hash, device: softAuthenticator() };
  assert.strictEqual((await enrol(owner, owner.device, { label: 'GitHub-era phone' })).status, 201);
  await ageKeys(owner.id);
  await stepUp(owner, owner.device);
  assert.strictEqual((await oauth('x', 'pk-owner', { cookie: owner.cookie, link: true })).done.location, '/account');
  // Someone signs in with X (a fresh session from the newer method). Alone, it can't add a passkey: one exists.
  const xs = await oauth('x', 'pk-owner');
  const viaX = { cookie: xs.cookie, id: owner.id, hash: (await sessionOf(xs.cookie)).token_hash, device: softAuthenticator() };
  assert.ok(isStepUp(await enrol(viaX, viaX.device, { label: 'X-era key' })), 'a linked method alone never adds a passkey to an account that has one');
  // With the owner's passkey (synced to that device) it can, and that passkey records the X method.
  assert.strictEqual((await stepUp(viaX, owner.device)).status, 200);
  assert.strictEqual((await enrol(viaX, viaX.device, { label: 'X-era key' })).status, 201);
  const [xIdent] = await q(`select id from app.identities where member_id = '${owner.id}' and provider = 'x'`);
  const keys = await q(`select id, identity_id, label from app.passkeys where member_id = '${owner.id}' order by created_at`);
  assert.deepStrictEqual(keys.map((k) => k.identity_id === xIdent.id), [false, true]);
  // Seniority: the X session can't remove the passkey added under GitHub; the GitHub session could remove the X one.
  const senior = await pkCall('remove', viaX, { id: keys[0].id });
  assert.strictEqual(senior.status, 403);
  assert.match(senior.json.error, /oldest method/);
  // The owner unlinks X (no passkey needed for a newer method): the passkey added from X's session goes with it,
  // recorded and told, in the same transaction.
  assert.strictEqual((await form('unlink', owner, '/auth/account/unlink', { id: xIdent.id })).location, '/account?saved=unlinked');
  assert.deepStrictEqual((await q(`select label from app.passkeys where member_id = '${owner.id}'`)).map((k) => k.label), ['GitHub-era phone']);
  const gone = await audits(owner.id, 'passkey.removed');
  assert.deepStrictEqual(gone.map((x) => x.detail), [{ passkey: keys[1].id, reason: 'method_unlinked' }]);
  const told = await noticesOf(owner.id, 'passkey_removed');
  assert.deepStrictEqual(told.map((x) => x.title), ['A passkey was removed with a sign-in method']);
  // A refused unlink removes nothing: the passkeys stay exactly as they were.
  assert.strictEqual(Number((await q(`select count(*) as n from app.passkeys where member_id = '${owner.id}'`))[0].n), 1);
});

test('PK12: one member can\'t read, use or remove another\'s passkeys, challenges or recovery (row-level security)', async () => {
  const a = await withPasskey({ name: 'A keys' });
  const b = await withPasskey({ name: 'B keys' });
  await pkCall('assertOptions', a, {});
  await pkCall('recoveryStart', a, {});
  const seen = await run(b.ctx, async (t) => ({
    keys: await t`select member_id from app.passkeys`, recs: await t`select member_id from app.passkey_recoveries`
  }));
  assert.deepStrictEqual([...seen.keys].map((k) => k.member_id), [b.id], 'B sees only B\'s passkey');
  assert.strictEqual(seen.recs.length, 0, 'and none of A\'s recovery');
  await assert.rejects(run(b.ctx, (t) => t`select * from app.passkey_challenges`), /permission denied/);
  await assert.rejects(run(b.ctx, (t) => t`insert into app.passkeys (member_id, identity_id, credential_id, public_key, label)
    select ${b.id}, id, 'aaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbb', 'forged' from app.identities limit 1`), /permission denied/);
  await assert.rejects(run(b.ctx, (t) => t`update app.passkeys set sign_count = 0`), /permission denied/);
  await assert.rejects(run(b.ctx, (t) => t`update app.sessions set stepped_up_at = now()`), /permission denied/);
  await assert.rejects(run(b.ctx, (t) => t`delete from app.passkeys`), /permission denied/);
  // B answering with A's passkey: it isn't one of B's.
  const opts = await pkCall('assertOptions', b, {});
  const use = await pkCall('assertFinish', b, { response: a.device.get({ ...opts.json.options }, { origin: ORIGIN }) });
  assert.strictEqual(use.status, 403);
  const ch = c.token(32);
  await run(b.ctx, (t) => passkeys.challenge(t, { sessionHash: b.hash, purpose: 'step_up', challengeHash: c.sha256hex(ch) }));
  assert.deepStrictEqual(await run(b.ctx, (t) => passkeys.assert(t, { sessionHash: b.hash, challengeHash: c.sha256hex(ch), credentialId: a.device.id, signCount: 50 })),
    { refused: 'unknown' }, 'the database refuses it too');
  // B's own session can't act for A's session, and B can't remove A's passkey or cancel A's recovery.
  const [aKey] = await q(`select id from app.passkeys where member_id = '${a.id}'`);
  await stepUp(b, b.device);
  assert.strictEqual((await pkCall('remove', b, { id: aKey.id })).status, 404);
  assert.deepStrictEqual(await run(b.ctx, (t) => passkeys.recoveryStart(t, { sessionHash: a.hash })), { refused: 'session' });
  assert.strictEqual(await run(b.ctx, (t) => passkeys.recoveryCancel(t, { sessionHash: a.hash })), 'session');
  assert.strictEqual(Number((await q(`select count(*) as n from app.passkey_recoveries where member_id = '${a.id}' and cancelled_at is null`))[0].n), 1);
  // Nobody signed in can read anything, and an agent can't either.
  await assert.rejects(run({ actor: 'anon' }, (t) => t`select * from app.passkey_challenges`), /permission denied/);
  assert.strictEqual((await run({ actor: 'anon' }, (t) => t`select * from app.passkeys`)).length, 0);
  // The audit log keeps IDs only: never a credential, a public key or a label.
  const trail = JSON.stringify(await q(`select detail from app.audit_log where action like 'passkey.%'`));
  for (const secretish of [a.device.id, b.device.id, 'My phone', 'A keys']) assert.ok(!trail.includes(secretish), secretish + ' is not in the audit log');
  const pub = (await q(`select public_key from app.passkeys limit 1`))[0].public_key;
  assert.ok(!trail.includes(pub));
});

// The browser side, run for real: /passkey.js in a sandbox whose navigator.credentials is a software passkey and whose
// fetch reaches the real handlers, so its encoding and the server's checks meet exactly as in a browser.
function browserFor(m, device) {
  const vm = require('vm');
  const toBuf = (s) => { const b = Buffer.from(s, 'base64url'); return b.buffer.slice(b.byteOffset, b.byteOffset + b.length); };
  const fromBuf = (ab) => Buffer.from(ab).toString('base64url');
  const cred = (j, kind) => ({ id: j.id, rawId: toBuf(j.rawId), type: j.type, authenticatorAttachment: j.authenticatorAttachment, getClientExtensionResults: () => ({}),
    response: kind === 'create'
      ? { clientDataJSON: toBuf(j.response.clientDataJSON), attestationObject: toBuf(j.response.attestationObject), getTransports: () => j.response.transports }
      : { clientDataJSON: toBuf(j.response.clientDataJSON), authenticatorData: toBuf(j.response.authenticatorData), signature: toBuf(j.response.signature), userHandle: null } });
  const handlers = { '/auth/passkey/enrol/options': pk.enrolOptions, '/auth/passkey/enrol/finish': pk.enrolFinish,
    '/auth/passkey/assert/options': pk.assertOptions, '/auth/passkey/assert/finish': pk.assertFinish, '/auth/passkey/remove': pk.remove };
  const sandbox = {
    window: { PublicKeyCredential: function () {} }, Uint8Array, String, JSON, Promise,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'), btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    navigator: { credentials: {
      create: async ({ publicKey }) => {
        assert.ok(publicKey.challenge instanceof ArrayBuffer && publicKey.user.id instanceof ArrayBuffer, 'the page hands the browser bytes, not text');
        return cred(device.create({ ...publicKey, challenge: fromBuf(publicKey.challenge) }, { origin: ORIGIN }), 'create');
      },
      get: async ({ publicKey }) => cred(device.get({ ...publicKey, challenge: fromBuf(publicKey.challenge) }, { origin: ORIGIN }), 'get')
    } },
    fetch: async (url, init) => {
      const r = res();
      const rq = req('POST', url, { cookie: m.cookie, json: JSON.parse(init.body) });
      if (handlers[url]) await handlers[url](rq, r);
      else if (url.startsWith('/api/agents/')) { rq.query = { route: url.slice('/api/agents/'.length) }; await require('../api/agents.js').handle(rq, r, run, CFG); }
      else throw new Error('unexpected ' + url);
      return { ok: r.statusCode < 300, status: r.statusCode, json: async () => JSON.parse(r.body) };
    }
  };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(root, 'passkey.js'), 'utf8'), sandbox);
  return sandbox.window.dogPasskey;
}

test('PK2, PK3: the page\'s own passkey code adds a passkey, confirms with it, and retries a risky step once after the check', async () => {
  const m = await person({ name: 'Browser' });
  const browser = browserFor(m, softAuthenticator());
  assert.strictEqual(browser.supported(), true);
  const added = await browser.enrol('This laptop');
  assert.deepStrictEqual([added.status, added.d.message], [201, 'Added. You’ll use it to confirm risky steps.']);
  const agent = (await agentsApi(m, 'POST', '', { name: 'Page agent' })).json.agent_id;
  // One call: the server asks for the passkey, the page asks the device, and the step goes ahead.
  const r = await browser.postJson('/api/agents/rules', { agent, post: 'act', reply: 'draft', report: 'draft', daily_cap: 20 });
  assert.deepStrictEqual([r.status, r.d.rules.post], [201, 'act']);
  assert.strictEqual((await audits(m.id, 'passkey.used')).length, 1);
  // A member with no passkey gets the server's answer as it is, with the way to add one: never a weaker check.
  const none = await person({ name: 'No key in browser' });
  const nb = browserFor(none, softAuthenticator());
  const a2 = (await agentsApi(none, 'POST', '', { name: 'Unconfirmed' })).json.agent_id;
  const refused = await nb.postJson('/api/agents/rules', { agent: a2, post: 'act', reply: 'draft', report: 'draft', daily_cap: 20 });
  assert.deepStrictEqual([refused.status, refused.d.step_up.has_passkey, refused.d.step_up.enrol], [403, false, '/account#passkeys']);
  const page = await agentsApi(none, 'GET', '');
  assert.strictEqual(page.json.has_passkey, false, 'the agents page can offer one before the first risky step');
});

test('PK2: a new member is offered a passkey once, in-app, at sign-up', async () => {
  ACCOUNTS['github:pk-new'] = { accountId: 'pk-new', level: 1, recheckAfter: null };
  const first = await oauth('github', 'pk-new');
  const id = (await sessionOf(first.cookie)).member_id;
  await oauth('github', 'pk-new');
  const offers = await noticesOf(id, 'passkey_offer');
  assert.strictEqual(offers.length, 1, 'once, not at every sign-in');
  assert.match(offers[0].body, /fingerprint, face or device PIN/);
  assert.strictEqual((await q(`select link from app.notices where member_id = '${id}' and kind = 'passkey_offer'`))[0].link, '/account#passkeys');
});
