// Route B (Aaron, Oct 26; harness/PLAN.md fixes 5 and 8): the site gets its database login and keys from the key broker,
// which hands them only to a production function of our own Vercel project, proved by Vercel's identity token.
// These tests use made-up keys and tokens; nothing here reaches Vercel, Supabase or the network.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const { subtle } = globalThis.crypto;
const enc = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const root = path.join(__dirname, '..');

async function signer() {
  const oidc = await import('../supabase/functions/_shared/vercel-oidc.mjs');
  const gen = () => subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const pair = await gen();
  const other = await gen();
  const jwk = { ...(await subtle.exportKey('jwk', pair.publicKey)), kid: 'v1' };
  const fetched = [];
  const keys = async (issuer) => { fetched.push(issuer); return [jwk]; };
  const now = 1_800_000_000;
  const good = {
    iss: 'https://oidc.vercel.com/chief-os', aud: 'https://vercel.com/chief-os',
    sub: 'owner:chief-os:project:start-of-something-great:environment:production',
    iat: now - 10, nbf: now - 10, exp: now + 7190,
    owner: 'chief-os', owner_id: 'team_Hv5YS8LhIiKe06SSiDrUucd4',
    project: 'start-of-something-great', project_id: 'prj_cXnWySYVpJE9TVZaNPSocXMMzkZI', environment: 'production'
  };
  async function sign(claims, { header = { alg: 'RS256', kid: 'v1', typ: 'JWT' }, key = pair.privateKey } = {}) {
    const body = enc(header) + '.' + enc(claims);
    const sig = await subtle.sign('RSASSA-PKCS1-v1_5', key, Buffer.from(body));
    return body + '.' + Buffer.from(sig).toString('base64url');
  }
  return { oidc, sign, good, now, keys, fetched, other };
}

test('route B: a production token of our own Vercel project is accepted, in either issuer mode', async () => {
  const { oidc, sign, good, now, keys } = await signer();
  const claims = await oidc.verify(await sign(good), { now, keys });
  assert.strictEqual(claims.project_id, good.project_id);
  // The CSO's control 5: the global issuer is accepted too, so changing that project setting can't lock the site out.
  const g = await oidc.verify(await sign({ ...good, iss: 'https://oidc.vercel.com' }), { now, keys });
  assert.strictEqual(g.environment, 'production');
});

test('route B: a preview, another project or team, a forged, expired or long-lived token, and junk are all refused', async () => {
  const { oidc, sign, good, now, keys, fetched, other } = await signer();
  const refused = async (token, why) => {
    await assert.rejects(oidc.verify(token, { now, keys }), (e) => e instanceof oidc.Refused && e.message === why, why);
  };
  // Every branch push makes a preview deployment with its own token: it must get nothing.
  await refused(await sign({ ...good, environment: 'preview', sub: 'owner:chief-os:project:start-of-something-great:environment:preview' }), 'wrong environment');
  await refused(await sign({ ...good, sub: 'owner:chief-os:project:start-of-something-great:environment:preview' }), 'wrong subject');
  await refused(await sign({ ...good, project_id: 'prj_someoneelse' }), 'wrong project');
  await refused(await sign({ ...good, owner_id: 'team_someoneelse' }), 'wrong team');
  await refused(await sign({ ...good, aud: 'https://vercel.com/another-team' }), 'wrong audience');
  fetched.length = 0;
  await refused(await sign({ ...good, iss: 'https://evil.example' }), 'wrong issuer');
  assert.deepStrictEqual(fetched, [], 'an unknown issuer is refused before any key is fetched');
  await refused(await sign({ ...good, exp: now - 3600 }), 'expired');
  await refused(await sign({ ...good, iat: now + 3600, exp: now + 7200 }), 'from the future');
  await refused(await sign({ ...good, iat: now - 10, exp: now + 86400 }), 'lives too long');
  await refused(await sign(good, { key: other.privateKey }), 'signature does not match');
  await refused(await sign(good, { header: { alg: 'HS256', kid: 'v1' } }), 'wrong signature type');
  await refused(await sign(good, { header: { alg: 'RS256', kid: 'nope' } }), 'signed by an unknown key');
  await refused('', 'token missing or too large');
  await refused('x'.repeat(9000), 'token missing or too large');
  await refused('a.b', 'not a signed token');
});

test('route B, the broker: only POST, only our production token, and it hands out exactly the login and three keys', async () => {
  const core = await import('../supabase/functions/dog-keys/core.mjs');
  const { oidc, sign, good, now, keys } = await signer();
  const verify = (t) => oidc.verify(t, { now, keys });
  const vault = {
    dog_web_password: 'p'.repeat(64), dog_session_secret: 's'.repeat(44), dog_ip_hash_key: 'i'.repeat(44), dog_fingerprint_key_1: 'f'.repeat(44),
    // Other secrets in Vault are never asked for (the CSO's control 1): read() names exactly four.
  };
  const values = async () => vault;
  assert.strictEqual((await core.handle({ method: 'GET', token: await sign(good) }, { verify, Refused: oidc.Refused, values })).status, 405);
  const no = await core.handle({ method: 'POST', token: await sign({ ...good, environment: 'preview' }) }, { verify, Refused: oidc.Refused, values });
  assert.deepStrictEqual([no.status, no.body.error], [401, 'refused: wrong environment']);
  assert.ok(!JSON.stringify(no.body).includes('p'.repeat(64)), 'a refusal carries no value');
  const ok = await core.handle({ method: 'POST', token: await sign(good) }, { verify, Refused: oidc.Refused, values });
  assert.strictEqual(ok.status, 200);
  assert.deepStrictEqual(Object.keys(ok.body.keys).sort(), ['FINGERPRINT_KEY_1', 'IP_HASH_KEY', 'SESSION_SECRET']);
  assert.strictEqual(Buffer.from(ok.body.keys.FINGERPRINT_KEY_1, 'base64').toString(), 'f'.repeat(44), 'the same key bytes as the JEVs gate uses');
  assert.deepStrictEqual({ ...ok.body.database, password: undefined },
    { user: 'dog_web.nksagchwpyljvjiwolmp', password: undefined, hosts: core.POOLER_HOSTS, port: 6543, database: 'postgres' });
  // A missing or short value is named, never sent.
  const short = await core.handle({ method: 'POST', token: await sign(good) }, { verify, Refused: oidc.Refused, values: async () => ({ ...vault, dog_ip_hash_key: 'short' }) });
  assert.deepStrictEqual([short.status, short.body.missing], [503, ['dog_ip_hash_key']]);
  assert.ok(!JSON.stringify(short.body).includes('s'.repeat(44)));
  // read() asks Vault for exactly these four names.
  let asked;
  const sql = (strings, names) => { asked = names; return Promise.resolve([{ name: 'dog_web_password', v: 'x' }]); };
  await core.read(sql);
  assert.deepStrictEqual(asked.sort(), ['dog_fingerprint_key_1', 'dog_ip_hash_key', 'dog_session_secret', 'dog_web_password']);
});

test('route B, the site: Vercel settings win; closed asks nothing; open asks the broker once, keeps the answer, survives an outage', async () => {
  const sk = require('../db/sitekeys');
  const body = { ok: true, database: { user: 'dog_web.ref', password: 'pw/with@chars', hosts: ['aws-0-us-east-1.pooler.supabase.com', 'aws-1-us-east-1.pooler.supabase.com'], port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: 'c2Vzcw==', IP_HASH_KEY: 'aXA=', FINGERPRINT_KEY_1: 'ZnA=' } };
  const calls = [];
  const okFetch = async (url, init) => { calls.push({ url, auth: init.headers.authorization }); return { status: 200, json: async () => body }; };
  const TOKEN = 'header.' + 'x'.repeat(40) + '.sig';
  const fresh = () => ({ headers: { 'x-vercel-oidc-token': TOKEN } });
  const req = fresh();
  const pub = () => 'public';
  // The fallback to Vercel settings: never asks the broker.
  sk._reset();
  assert.deepStrictEqual(await sk.ensure(fresh(), { fetchImpl: okFetch, env: { DATABASE_URL: 'postgres://set/in/vercel' }, stage: pub }), { source: 'vercel' });
  assert.strictEqual(calls.length, 0);
  // Closed: nothing is fetched.
  assert.deepStrictEqual(await sk.ensure(fresh(), { fetchImpl: okFetch, env: {}, stage: () => 'closed' }), { source: 'closed' });
  assert.strictEqual(calls.length, 0);
  // Open, with no token: nothing to prove itself with.
  assert.deepStrictEqual(await sk.ensure({ headers: {} }, { fetchImpl: okFetch, env: {}, stage: pub }), { source: 'none', error: 'no_token' });
  // Open: asks the broker with the request's token, and puts the answer where the site reads it.
  const env = { SESSION_SECRET: 'already-set-in-vercel' };
  assert.strictEqual((await sk.ensure(req, { fetchImpl: okFetch, env, stage: pub })).source, 'broker');
  assert.deepStrictEqual(calls, [{ url: sk.BROKER, auth: 'Bearer ' + TOKEN }]);
  assert.strictEqual(req.headers['x-vercel-oidc-token'], undefined, 'M3: the token is removed from the request once read');
  const u = new URL(env.DATABASE_URL);
  assert.deepStrictEqual([u.hostname, u.port, decodeURIComponent(u.username), decodeURIComponent(u.password)],
    ['aws-0-us-east-1.pooler.supabase.com', '6543', 'dog_web.ref', 'pw/with@chars']);
  assert.strictEqual(env.SESSION_SECRET, 'already-set-in-vercel', 'a setting from Vercel is never overwritten');
  assert.strictEqual(env.FINGERPRINT_KEY_1, 'ZnA=');
  assert.doesNotThrow(() => require('../db').pooledUrl(env.DATABASE_URL), 'the address passes G1 (a pooler in transaction mode)');
  // Kept for this instance: the next request doesn't ask again.
  await sk.ensure(fresh(), { fetchImpl: okFetch, env, stage: pub });
  assert.strictEqual(calls.length, 1);
  // A broker outage before any answer: nothing; after one: the last good answer keeps working.
  sk._reset();
  const down = async () => ({ status: 500, json: async () => ({ ok: false, error: 'broker failed' }) });
  const none = await sk.ensure(fresh(), { fetchImpl: down, env: {}, stage: pub });
  assert.strictEqual(none.source, 'none');
  assert.match(none.error, /^broker 500/);
});

test('code sign-in, /api/ready: says whether the site hashes codes with the gate\'s own key, never the key (the CSO\'s finding 3)', async () => {
  const sk = require('../db/sitekeys');
  const ready = require('../api/ready.js');
  const body = { ok: true, database: { user: 'dog_web.ref', password: 'secret-password-value-1234567890abcdef', hosts: ['aws-0-us-east-1.pooler.supabase.com'], port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: 'c2Vzcw==', IP_HASH_KEY: 'aXA=', FINGERPRINT_KEY_1: 'ZnA=' } };
  const fetchImpl = async () => ({ status: 200, json: async () => body });
  const connect = () => { const sql = async () => [{ one: 1 }]; sql.end = async () => {}; return sql; };
  const ask = async (env) => {
    sk._reset(); ready._reset();
    return ready.check({ method: 'GET', headers: { 'x-vercel-oidc-token': 'header.' + 'x'.repeat(40) + '.sig' } }, { env, connect, fetchImpl });
  };
  assert.strictEqual((await ask({ LAUNCH_STAGE: 'closed' })).code_signin_keys, 'same_as_gate');
  const differs = await ask({ LAUNCH_STAGE: 'closed', FINGERPRINT_KEY_1: 'b3RoZXI=' });
  assert.strictEqual(differs.code_signin_keys, 'vercel_settings', 'a Vercel setting that wins over the broker\'s key is reported');
  assert.ok(!JSON.stringify(differs).includes('b3RoZXI=') && !JSON.stringify(differs).includes('ZnA='), 'never a key');
});

test('route B, /api/ready: says what is present and which step failed, never a value', async () => {
  const sk = require('../db/sitekeys');
  const ready = require('../api/ready.js');
  sk._reset(); ready._reset();
  const body = { ok: true, database: { user: 'dog_web.ref', password: 'secret-password-value-1234567890abcdef', hosts: ['aws-0-us-east-1.pooler.supabase.com', 'aws-1-us-east-1.pooler.supabase.com'], port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: 'c2Vzcw==', IP_HASH_KEY: 'aXA=', FINGERPRINT_KEY_1: 'ZnA=' } };
  const fetchImpl = async () => ({ status: 200, json: async () => body });
  // A fake pooler: one cluster serves the project, the other says so.
  const connect = (url) => {
    const host = new URL(url).hostname;
    const sql = async () => { if (host.startsWith('aws-1')) throw new Error('Tenant or user not found'); return [{ one: 1 }]; };
    sql.end = async () => {};
    return sql;
  };
  const env = { GITHUB_CLIENT_ID: 'id', GITHUB_CLIENT_SECRET: 'x', LAUNCH_STAGE: 'closed' };
  const req = { method: 'GET', headers: { 'x-vercel-oidc-token': 'header.' + 'x'.repeat(40) + '.sig' } };
  const out = await ready.check(req, { env, connect, fetchImpl });
  assert.deepStrictEqual(out, { identity_token: true, broker: 'ok', keys: true, github_signin: true, github_setting_names: ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'],
    database: { 'aws-0-us-east-1': 'reached' }, code_signin_keys: 'same_as_gate', stage: 'closed', stage_repo: 'public', vercel_env: null, launch_stage_set: true, timers: 'closed', rules: 'closed' }, 'stops at the first address that answers');
  assert.ok(!JSON.stringify(out).includes('"x"'), 'names only, never a value');
  // L2: while closed, the check's answer stays inside the check: nothing is written where the site reads settings.
  assert.deepStrictEqual(Object.keys(env).sort(), ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'LAUNCH_STAGE']);
  // M3: the token is gone from the request once read.
  assert.strictEqual(req.headers['x-vercel-oidc-token'], undefined);
  assert.ok(!JSON.stringify(out).includes(body.database.password), 'no password');
  assert.ok(!JSON.stringify(out).includes('c2Vzcw=='), 'no key');
  // Without a token, it says so, and the site stays exactly as closed as before.
  sk._reset(); ready._reset();
  const bare = await ready.check({ method: 'GET', headers: {} }, { env: {}, connect, fetchImpl });
  assert.deepStrictEqual([bare.identity_token, bare.broker, bare.keys, bare.github_signin, bare.github_setting_names, bare.database], [false, 'no_token', false, false, [], {}]);
  sk._reset(); ready._reset();
});

test('route B: the Supabase root certificate is bundled as a module, byte for byte the reviewed file', () => {
  assert.strictEqual(require('../db/certs/supabase-root'), fs.readFileSync(path.join(root, 'db', 'certs', 'supabase-root-2021.crt'), 'utf8'));
});

test('route B: the broker is deployed with Supabase\'s JWT check off (it checks Vercel\'s token itself), like the other functions', () => {
  const toml = fs.readFileSync(path.join(root, 'supabase', 'config.toml'), 'utf8');
  assert.match(toml, /\[functions\.dog-keys\]\nverify_jwt = false/);
});

test('route B: a rotated password reaches a running site; one bad token can\'t fail another request (the CSO\'s M1, L1)', async () => {
  const sk = require('../db/sitekeys');
  const db = require('../db');
  sk._reset();
  const body = (pw) => ({ ok: true, database: { user: 'dog_web.ref', password: pw, hosts: ['aws-0-us-east-1.pooler.supabase.com'], port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: 'c2Vzcw==', IP_HASH_KEY: 'aXA=', FINGERPRINT_KEY_1: 'ZnA=' } });
  let pw = 'first-password-0123456789abcdef0123';
  const fetchImpl = async (url, init) => (init.headers.authorization.endsWith('.good')
    ? { status: 200, json: async () => body(pw) } : { status: 401, json: async () => ({ ok: false, error: 'refused: wrong environment' }) });
  const tok = (t) => ({ headers: { 'x-vercel-oidc-token': 'header.' + 'x'.repeat(40) + t } });
  const env = {};
  const pub = () => 'public';
  // L1: a bad token and a good one at the same moment: only the bad one fails.
  const [bad, good] = await Promise.all([sk.ensure(tok('.bad'), { fetchImpl, env, stage: pub }), sk.ensure(tok('.good'), { fetchImpl, env, stage: pub })]);
  assert.strictEqual(good.source, 'broker');
  assert.ok(['none', 'broker'].includes(bad.source), 'the bad token never spoils the good one');
  assert.strictEqual(decodeURIComponent(new URL(env.DATABASE_URL).password), 'first-password-0123456789abcdef0123');
  // M1: after the refresh window the broker gives a new password, and the site uses it.
  pw = 'second-password-0123456789abcdef012';
  const realNow = Date.now;
  const realReplace = db.replaceAddress;
  let replaced = 0;
  db.replaceAddress = (url, e) => { replaced++; return realReplace(url, e); };
  try {
    Date.now = () => realNow() + 11 * 60_000;
    await sk.ensure(tok('.good'), { fetchImpl, env, stage: pub });
  } finally { Date.now = realNow; db.replaceAddress = realReplace; }
  assert.strictEqual(decodeURIComponent(new URL(env.DATABASE_URL).password), 'second-password-0123456789abcdef012');
  assert.strictEqual(replaced, 1, 'the old pool is ended once');
  sk._reset();
});

test('route B, /api/ready under load: one check at a time, its answer kept a minute, so a flood logs in once (the CSO\'s M2)', async () => {
  const sk = require('../db/sitekeys');
  const ready = require('../api/ready.js');
  sk._reset(); ready._reset();
  let logins = 0;
  const connect = () => { const sql = async () => { logins++; await new Promise((r) => setTimeout(r, 20)); return [{ one: 1 }]; }; sql.end = async () => {}; return sql; };
  const fetchImpl = async () => ({ status: 200, json: async () => ({ ok: true, database: { user: 'dog_web.ref', password: 'p'.repeat(40),
    hosts: ['aws-0-us-east-1.pooler.supabase.com', 'aws-1-us-east-1.pooler.supabase.com'], port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: 'a', IP_HASH_KEY: 'b', FINGERPRINT_KEY_1: 'c' } }) });
  const res = () => { const r = { statusCode: 0, headers: {}, body: '' }; r.setHeader = (k, v) => { r.headers[k] = v; }; r.end = (b) => { r.body = b; }; return r; };
  const reqs = Array.from({ length: 50 }, () => ({ method: 'GET', headers: { 'x-vercel-oidc-token': 'header.' + 'x'.repeat(40) + '.sig' } }));
  const outs = reqs.map(res);
  await Promise.all(reqs.map((q, i) => ready.handle(q, outs[i], { env: {}, connect, fetchImpl })));
  assert.strictEqual(logins, 1, '50 calls at once: one login');
  assert.ok(outs.every((o) => o.statusCode === 200 && o.headers['Cache-Control'] === 'no-store'));
  assert.ok(reqs.every((q) => q.headers['x-vercel-oidc-token'] === undefined), 'no request keeps the token');
  assert.ok(outs.every((o) => !o.body.includes('header.')), 'no reply carries the token');
  await ready.handle({ method: 'GET', headers: {} }, res(), { env: {}, connect, fetchImpl });
  assert.strictEqual(logins, 1, 'and a minute of answers from the one check');
  sk._reset(); ready._reset();
});
