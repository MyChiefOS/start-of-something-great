// 063: the buyer door (Aaron, Nov 11, 2026: a passkey and no GitHub account, for posting, funding, reviewing and
// disputing tasks only), against a real Postgres. A real authenticator is simulated with Node's crypto: the
// authenticator data, the COSE key and the ES256 signature are built byte for byte as WebAuthn defines them, so each
// check the database makes is exercised, right and wrong. ACCEPTANCE.md BK1 to BK9.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const work = require('../db/work');
const posts = require('../db/posts');
const { ORIGIN } = require('../signin/config');
const { migrate } = require('../scripts/migrate');
const { promote, shadowMode, asSignin } = require('./helpers');

const SERVER = process.env.TEST_DATABASE_URL;
const NAME = 'dog_063_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
const ANON = { actor: 'anon' };
let server, su, web, member;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const sha = (b) => crypto.createHash('sha256').update(b).digest();
const ctxOf = (m) => ({ actor: 'member', memberId: m.id, session: m.session, fresh: true });
const asPay = (fn) => su.begin(async (t) => { await t.unsafe('set local role dog_pay'); return fn(t); });

// ---- A simulated authenticator ----
const RP = new URL(ORIGIN).hostname;
function device() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { privateKey, spki, pub: c.p256FromSpki(spki), cred: crypto.randomBytes(32), count: 0 };
}
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
function cose(pub) {
  return Buffer.concat([Buffer.from('a50102032620012158 20'.replace(/ /g, ''), 'hex'), pub.subarray(1, 33), Buffer.from('225820', 'hex'), pub.subarray(33)]);
}
function authData(d, { flags = 0x05, rp = RP, attested = false, credId = d.cred, key = d.pub, count = d.count, coseKey = null } = {}) {
  const parts = [sha(Buffer.from(rp)), Buffer.from([flags | (attested ? 0x40 : 0)]), u32(count)];
  if (attested) {
    const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
    parts.push(Buffer.alloc(16), len, credId, coseKey || cose(key));
  }
  return Buffer.concat(parts);
}
const clientData = (type, challenge, origin = ORIGIN, extra = {}) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false, ...extra }));
const challenge = () => run(ANON, (t) => store.challengeIssue(t, ORIGIN));

async function register(d, over = {}) {
  const ch = over.challenge || await challenge();
  const token = c.token(32);
  const out = await run(ANON, (t) => store.buyerRegister(t, { credentialId: over.credentialId || d.cred, publicKey: over.publicKey || d.pub,
    clientData: over.clientData || clientData('webauthn.create', ch, over.origin), authData: over.authData || authData(d, { attested: true, ...(over.ad || {}) }),
    displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  return { ...out, session: c.sha256hex(token), challenge: ch };
}
async function signIn(d, over = {}, region = null) {
  const ch = over.challenge || await challenge();
  d.count += over.countStep === undefined ? 1 : over.countStep;
  const cd = over.clientData || clientData('webauthn.get', ch, over.origin);
  const ad = over.authData || authData(d, over.ad || {});
  const der = crypto.sign('sha256', Buffer.concat([ad, sha(cd)]), over.signWith || d.privateKey);
  const token = c.token(32);
  const out = await run(ANON, (t) => store.buyerSignIn(t, { credentialId: d.cred, clientData: cd, authData: ad, signature: over.signature || c.derToRaw(der),
    displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30, region }));
  return { ...out, session: c.sha256hex(token) };
}
async function buyer() {
  const d = device();
  const r = await register(d);
  assert.strictEqual(r.status, 'ok', JSON.stringify(r));
  return { d, id: r.memberId, session: r.session };
}

let n = 0;
async function githubMember(name) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('gh:' + name + (n++))], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  return { id: out.memberId, session: c.sha256hex(token) };
}

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  member = await githubMember('Worker');
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

test('BK1: a new buyer key opens a buyer account with a session; the key signs in again, checked by the database', async () => {
  const d = device();
  const r = await register(d);
  assert.strictEqual(r.status, 'ok', JSON.stringify(r));
  assert.strictEqual(r.isNew, true);
  assert.strictEqual(r.trustLevel, 1);
  const [ident] = await q(`select provider, fingerprint from app.identities where member_id = '${r.memberId}'`);
  assert.deepStrictEqual(ident, { provider: 'buyer', fingerprint: sha(d.pub).toString('hex') });
  const [k] = await q(`select public_key, credential_id from app.buyer_keys where member_id = '${r.memberId}'`);
  assert.ok(Buffer.from(k.public_key).equals(d.pub) && Buffer.from(k.credential_id).equals(d.cred));
  assert.strictEqual((await q(`select count(*)::int as n from app.sessions where token_hash = '${r.session}'`))[0].n, 1);
  const s = await signIn(d);
  assert.strictEqual(s.status, 'ok', JSON.stringify(s));
  assert.strictEqual(s.memberId, r.memberId);
  assert.strictEqual(s.isNew, false);
  // Nothing about the person or the device is kept: no name from the device, no attestation, no email.
  const cols = (await q(`select column_name from information_schema.columns where table_schema = 'app' and table_name = 'buyer_keys'`)).map((x) => x.column_name).sort();
  assert.deepStrictEqual(cols, ['created_at', 'credential_id', 'id', 'member_id', 'public_key', 'sign_count', 'used_at']);
});

test('BK2: every part of a new key is checked: type, challenge (once), address, this site, user verified, the credential and its key', async () => {
  const d = device();
  const bad = async (over, why) => {
    const r = await register(d, over);
    assert.strictEqual(r.status, 'bad_proof', why + ': ' + JSON.stringify(r));
  };
  await bad({ clientData: clientData('webauthn.get', await challenge()) }, 'a sign-in report, not a new key');
  await bad({ challenge: 'A'.repeat(43) }, 'a challenge we never made');
  await bad({ origin: 'https://dayonegreat.com.evil.example' }, 'another address');
  await bad({ clientData: clientData('webauthn.create', await challenge(), ORIGIN, { crossOrigin: true }) }, 'inside another site');
  await bad({ ad: { rp: 'evil.example' } }, 'another site’s name');
  await bad({ ad: { flags: 0x01 } }, 'user present but not verified');
  await bad({ ad: { flags: 0x04 } }, 'not present');
  await bad({ ad: { credId: crypto.randomBytes(32) } }, 'another credential in the data');
  await bad({ ad: { key: device().pub } }, 'another public key in the data');
  await bad({ authData: authData(d, { attested: false }) }, 'no credential in the data');
  // The fresh review of PR #3, L2: an RS256 key (kty 3, alg -257) with this key's bytes put after it is not this key.
  const rsa = Buffer.concat([Buffer.from('a401030339010020590100', 'hex'), crypto.randomBytes(256), Buffer.from('2143010001', 'hex')]);
  await bad({ ad: { coseKey: Buffer.concat([rsa, cose(d.pub)]) } }, 'another key type, with this key appended');
  // A challenge works once, even for a right answer.
  const first = await register(d);
  assert.strictEqual(first.status, 'ok');
  const d2 = device();
  const again = await register(d2, { challenge: first.challenge });
  assert.strictEqual(again.status, 'bad_proof');
  // And a key off the curve is refused before anything else.
  const off = Buffer.from(d2.pub); off[64] ^= 1;
  assert.strictEqual((await register(d2, { publicKey: off })).status, 'bad_key');
});

test('BK3: a sign-in needs this device’s signature over this site’s fresh challenge; the site’s own login can’t make one', async () => {
  const b = await buyer();
  const other = device();
  assert.strictEqual((await signIn(b.d, { signWith: other.privateKey })).status, 'bad_proof', 'another key’s signature');
  assert.strictEqual((await signIn(b.d, { signature: crypto.randomBytes(64) })).status, 'bad_proof', 'a made-up signature');
  assert.strictEqual((await signIn(b.d, { origin: 'https://evil.example' })).status, 'bad_proof', 'another address');
  assert.strictEqual((await signIn(b.d, { ad: { flags: 0x01 } })).status, 'bad_proof', 'not verified');
  assert.strictEqual((await signIn(b.d, { clientData: clientData('webauthn.create', await challenge()) })).status, 'bad_proof', 'the wrong kind');
  const ok = await signIn(b.d);
  assert.strictEqual(ok.status, 'ok');
  // A recorded sign-in can't be played again: its challenge is used up.
  const ch = await challenge();
  assert.strictEqual((await signIn(b.d, { challenge: ch })).status, 'ok');
  assert.strictEqual((await signIn(b.d, { challenge: ch })).status, 'bad_proof');
  const failures = await q(`select count(*)::int as n from app.audit_log where action = 'signin.failed' and subject_id = '${b.id}'`);
  assert.ok(failures[0].n >= 5, 'each failure is audited');
  assert.strictEqual((await signIn(device())).status, 'no_key');
});

test('BK4: a key is one account: the same key or credential again opens nothing, and nobody else gains a buyer key', async () => {
  const b = await buyer();
  const r = await register(b.d);
  assert.deepStrictEqual({ refused: r.refused }, { refused: 'taken' });
  // A buyer can't add GitHub, and a GitHub member can't gain a buyer method.
  await assert.rejects(asSignin(su)((t) => t`insert into app.identities (member_id, provider, fingerprint, key_version, level) values (${b.id}, 'github', ${c.sha256hex('x' + b.id)}, 1, 1)`), /buyer_scope/);
  await assert.rejects(asSignin(su)((t) => t`insert into app.identities (member_id, provider, fingerprint, key_version, level) values (${member.id}, 'buyer', ${c.sha256hex('y' + member.id)}, 1, 1)`), /buyer_scope/);
});

test('BK5: a buyer posts, funds, reviews and disputes; posts, reports, claims, work, agents, PINs, browser keys and payouts are refused', async () => {
  const b = await buyer();
  const as = (fn) => run(ctxOf(b), fn);
  const p = await as((t) => work.projectCreate(t, { title: 'A buyer project', description: '', room: '15-0000' }));
  const tk = await as((t) => work.taskCreate(t, { project: p.id, title: 'A buyer task', description: '', class: 'either', size: 1 }));
  assert.strictEqual((await q(`select status from app.work_tasks where id = '${tk.id}'`))[0].status, 'funding');
  await assert.rejects(as((t) => posts.create(t, { body: 'Hello from a buyer' })), /buyer_scope/);
  const scope = async (sql) => assert.rejects(q(sql), /buyer_scope/, sql);
  await scope(`insert into app.agents (owner_id, name) values ('${b.id}', 'scout')`);
  await scope(`insert into app.signin_pins (member_id, salt, pin_hash) values ('${b.id}', decode(repeat('ab', 16), 'hex'), decode(repeat('ab', 32), 'hex'))`);
  await scope(`insert into app.browser_keys (member_id, public_key, label) values ('${b.id}', '\\x${device().pub.toString('hex')}', 'Firefox on Linux')`);
  await scope(`insert into app.pay_accounts (member_id) values ('${b.id}')`);
  const [open] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member)
    select project_id, room_id, 'Open', 'either', 1, 'member', '${member.id}' from app.work_tasks where id = '${tk.id}' returning id`);
  await scope(`insert into app.work_claims (task_id, member_id, code_hash, expires_at) values ('${open.id}', '${b.id}', '${'c'.repeat(64)}', now() + interval '1 day')`);
  // Level 1 always, and never administrator.
  await q(`set role dog_jevs; update app.members set trust_level = 2, jevs_level2_at = now() where id = '${b.id}'; reset role`);
  assert.strictEqual((await q(`select trust_level from app.members where id = '${b.id}'`))[0].trust_level, 1);
  await scope(`update app.members set is_admin = true where id = '${b.id}'`);
});

test('BK6: a funding task is seen only by its poster and the administrator, can be funded, and opens when its bounty is', async () => {
  const b = await buyer();
  const p = await run(ctxOf(b), (t) => work.projectCreate(t, { title: 'Hidden until funded', description: '', room: '15-0000' }));
  const tk = await run(ctxOf(b), (t) => work.taskCreate(t, { project: p.id, title: 'Waits for money', description: '', class: 'either', size: 1 }));
  const seenBy = async (ctx) => { try { return Boolean(await run(ctx, (t) => work.task(t, tk.id))); } catch { return false; } };
  assert.strictEqual(await seenBy(ctxOf(b)), true, 'the poster sees it');
  assert.strictEqual(await seenBy(ctxOf(member)), false, 'another member doesn’t');
  assert.strictEqual(await seenBy(ANON), false, 'nor does anyone signed out');
  const listed = await run(ANON, (t) => work.tasks(t, {}));
  assert.ok(!JSON.stringify(listed).includes(tk.id), 'not in the public list');
  const projects = await run(ANON, (t) => work.projects(t, {}));
  assert.ok(!JSON.stringify(projects).includes(p.id), 'nor is its project, until a task is open');
  await assert.rejects(run(ctxOf(member), (t) => work.claim(t, tk.id)));
  // The poster can fund it (061's request, now for a funding task too); the payment function marks it funded.
  const [{ id: rid }] = await run(ctxOf(b), (t) => t`select app.bounty_fund_request(${tk.id}, 5000) as id`);
  assert.ok(rid);
  const [bounty] = await q(`select id from app.work_bounties where task_id = '${tk.id}'`);
  // Nobody opens it without the money.
  await assert.rejects(asPay((t) => t`update app.work_tasks set status = 'open' where id = ${tk.id}`));
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'funded', livemode = false, stripe_payment_intent_id = 'pi_${bounty.id.replace(/-/g, '')}',
    charged_cents = bounty_cents, funded_at = now() where id = '${bounty.id}'`));
  assert.strictEqual((await q(`select status from app.work_tasks where id = '${tk.id}'`))[0].status, 'open');
  assert.strictEqual((await q(`select listed from app.work_bounties where id = '${bounty.id}'`))[0].listed, true);
  assert.strictEqual(await seenBy(ctxOf(member)), true, 'open to everyone once funded');
});

test('BK7: a counter that goes backwards alerts and still signs in (checks alert, never lock out)', async () => {
  const b = await buyer();
  assert.strictEqual((await signIn(b.d, { countStep: 5 })).status, 'ok');
  assert.strictEqual((await signIn(b.d, { countStep: -3 })).status, 'ok');
  const [a] = await q(`select count(*)::int as n from app.audit_log where action = 'buyer.counter_backwards' and subject_id = '${b.id}'`);
  assert.strictEqual(a.n, 1);
  const [al] = await q(`select count(*)::int as n from app.notices where kind = 'alert' and dedupe_key like 'watch:buyer-counter:%'`);
  assert.ok(al.n >= 1);
});

test('BK8: a locked account tests nothing; a banned buyer can’t sign in', async () => {
  const b = await buyer();
  await q(`insert into app.signin_locks (member_id, until) values ('${b.id}', now() + interval '15 minutes')`);
  assert.strictEqual((await signIn(b.d)).refused, 'locked');
  await q(`delete from app.signin_locks where member_id = '${b.id}'`);
  // As a ban leaves it (the member guard lets only an administrator ban; the test sets the row directly).
  await su.begin(async (t) => {
    await t.unsafe('alter table app.members disable trigger members_guard');
    await t.unsafe(`update app.members set status = 'banned' where id = '${b.id}'`);
    await t.unsafe('alter table app.members enable always trigger members_guard');
  });
  assert.strictEqual((await signIn(b.d)).refused, 'banned');
});

test('BK9: the runner’s daily catalog checks still pass: no table or function is named like the removed passkeys', async () => {
  const core = await import('../supabase/functions/dog-migrate/core.mjs');
  const failed = await core.catalogChecks(su, { siteLogin: WEB });
  assert.deepStrictEqual(failed.filter((f) => /passkey/.test(f)), []);
});

// ---- The site's own door (signin/flow.js), as /join/buyer (buyer.js) sends it ----
const { make } = require('../signin/flow');
const { trustSystem } = require('./helpers');
const PAYMENTS = require.resolve('../payments.json');
const payments = (state) => { require(PAYMENTS); require.cache[PAYMENTS].exports = { payments: state }; };
let ipN = 0;
function req(body, { origin = ORIGIN, country } = {}) {
  ipN += 1;
  const headers = { host: 'dayonegreat.com', 'x-vercel-forwarded-for': '198.18.' + ipN + '.1', 'sec-fetch-site': 'same-origin', 'content-type': 'application/x-www-form-urlencoded' };
  if (origin) headers.origin = origin;
  if (country) headers['x-vercel-ip-country'] = country;
  return { method: 'POST', url: '/auth/buyer', headers, body: new URLSearchParams(body || {}).toString(), query: {} };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
async function door(flow, handler, body, opts) {
  const r = res();
  await flow[handler](req(body, opts), r);
  return { status: r.statusCode, cookie: [].concat(r.getHeader('set-cookie') || []).join('\n'), ...JSON.parse(r.body) };
}
const b64 = (b) => Buffer.from(b).toString('base64url');

test('BK10: the site’s buyer door: shut while payments are off, closed to declined regions and other sites, and a passkey signs up and in', async (t) => {
  await trustSystem(su);
  const cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: crypto.randomBytes(32), fingerprintKeys: [{ version: 1, key: crypto.randomBytes(32) }], github: null, x: null };
  const flow = make({ config: cfg, run: (ctx, fn) => db.tx(web, ctx, fn), providers: {}, sendEmail: null });
  t.after(() => payments('off'));
  const d = device();
  const newKey = async (opts) => {
    const ch = (await door(flow, 'challenge', {})).challenge;
    return { cred: b64(d.cred), cd: b64(clientData('webauthn.create', ch)), ad: b64(authData(d, { attested: true })), spki: b64(d.spki), alg: '-7', ...opts };
  };
  payments('off');
  assert.strictEqual((await door(flow, 'buyerRegister', await newKey())).status, 503, 'shut while payments are off');
  payments('on');
  assert.strictEqual((await door(flow, 'buyerRegister', await newKey(), { origin: 'https://evil.example' })).status, 403, 'only from our own pages');
  assert.strictEqual((await door(flow, 'buyerRegister', await newKey(), { country: 'DE' })).declined, true, 'a declined region gets no account');
  assert.match((await door(flow, 'buyerRegister', await newKey({ alg: '-257' }))).error, /kind of passkey/, 'ES256 only');
  const made = await door(flow, 'buyerRegister', await newKey());
  assert.strictEqual(made.signed_in, true, JSON.stringify(made));
  assert.strictEqual(made.go, '/projects');
  assert.match(made.cookie, /__Host-dog_session=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax/);
  // Signing in: the device's DER signature, checked by the site and then by the database.
  d.count += 1;
  const ch = (await door(flow, 'challenge', {})).challenge;
  const cd = clientData('webauthn.get', ch), ad = authData(d);
  const der = crypto.sign('sha256', Buffer.concat([ad, sha(cd)]), d.privateKey);
  const back = await door(flow, 'buyerSignIn', { cred: b64(d.cred), cd: b64(cd), ad: b64(ad), sig: b64(der) });
  assert.strictEqual(back.signed_in, true, JSON.stringify(back));
  const unknown = await door(flow, 'buyerSignIn', { cred: b64(crypto.randomBytes(32)), cd: b64(cd), ad: b64(ad), sig: b64(der) });
  assert.strictEqual(unknown.no_key, true);
  // From a declined region (Aaron, Oct 16): asked first, then signed in once the buyer confirms they live elsewhere.
  const sign = async (opts) => {
    d.count += 1;
    const c2 = (await door(flow, 'challenge', {})).challenge;
    const cd2 = clientData('webauthn.get', c2), ad2 = authData(d);
    return { cred: b64(d.cred), cd: b64(cd2), ad: b64(ad2), sig: b64(crypto.sign('sha256', Buffer.concat([ad2, sha(cd2)]), d.privateKey)), ...opts };
  };
  assert.ok((await door(flow, 'buyerSignIn', await sign(), { country: 'FR' })).region, 'asked where they live');
  const travelled = await door(flow, 'buyerSignIn', await sign({ confirm: '1' }), { country: 'FR' });
  assert.strictEqual(travelled.signed_in, true, JSON.stringify(travelled));
});

test('BK11 (the fresh review of PR #3, M2 and L1): a buyer withdraws a task never funded; a buyer\u2019s level is 1 wherever it is read', async () => {
  const b = await buyer();
  const p = await run(ctxOf(b), (t) => work.projectCreate(t, { title: 'Changed my mind', description: '', room: '15-0000' }));
  const tk = await run(ctxOf(b), (t) => work.taskCreate(t, { project: p.id, title: 'Not wanted after all', description: '', class: 'either', size: 1 }));
  assert.deepStrictEqual(await run(ctxOf(b), (t) => work.cancel(t, tk.id)), { result: 'closed' });
  assert.strictEqual((await q(`select status from app.work_tasks where id = '${tk.id}'`))[0].status, 'closed');
  // JEVs's level 2 mark doesn't lift a buyer: the sign-in reports 1, and writes no level change.
  await q(`set role dog_jevs; update app.members set jevs_level2_at = now() where id = '${b.id}'; reset role`);
  const before = (await q(`select count(*)::int as n from app.audit_log where action = 'member.level_changed' and subject_id = '${b.id}'`))[0].n;
  const s1 = await signIn(b.d);
  assert.strictEqual(s1.trustLevel, 1);
  await signIn(b.d);
  const after = (await q(`select count(*)::int as n from app.audit_log where action = 'member.level_changed' and subject_id = '${b.id}'`))[0].n;
  assert.strictEqual(after, before);
  assert.strictEqual((await q(`select app.verified_level('${b.id}') as l`))[0].l, 1);
});

test('BK12 (the fresh review of PR #3, M1; Aaron, Oct 16): a buyer travelling in a declined region confirms they live elsewhere and signs in, recorded (the site declines a new buyer there: BK10)', async () => {
  const b = await buyer();
  const s1 = await signIn(b.d, {}, 'DE');
  assert.strictEqual(s1.status, 'ok', JSON.stringify(s1));
  const [r] = await q(`select count(*)::int as n from app.audit_log where action = 'member.region_confirmed' and subject_id = '${b.id}'`);
  assert.strictEqual(r.n, 1);
});
