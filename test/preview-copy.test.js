// The preview copy (RK141; Aaron, Nov 10: "Okay you can bring preview back", the separate copy with its own throwaway
// database and made-up data; design/preview-copy.md). Every refusal the design rests on:
//   * production's key broker refuses every preview token, and the branch's broker every production token;
//   * the branch's broker hands out nothing unless its own Vault carries the preview copy's mark, and its login is the
//     branch's own; which broker it is comes from its own SUPABASE_URL, never from a request;
//   * the site asks production's broker at its fixed address unless VERCEL_ENV says preview, and a preview asks only the
//     branch's fixed address, or nothing (nothing while PREVIEW_REF is null, as in this PR);
//   * a preview is never more open than the repository and LAUNCH_STAGE allow, and never open with route A's settings;
//   * the seed refuses any database that isn't a fresh, empty copy, and makes no usable credential.
// Made-up keys and tokens; nothing here reaches Vercel, Supabase or the network.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const { subtle } = globalThis.crypto;
const enc = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const PROD_REF = 'nksagchwpyljvjiwolmp';
const BRANCH_REF = 'qwertyuiopasdfghjklz'; // made up: 20 lowercase letters, as a Supabase reference is

async function signer() {
  const oidc = await import('../supabase/functions/_shared/vercel-oidc.mjs');
  const gen = () => subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const pair = await gen();
  const jwk = { ...(await subtle.exportKey('jwk', pair.publicKey)), kid: 'v1' };
  const keys = async () => [jwk];
  const now = 1_800_000_000;
  const base = {
    iss: 'https://oidc.vercel.com/chief-os', aud: 'https://vercel.com/chief-os', iat: now - 10, nbf: now - 10, exp: now + 7190,
    owner: 'chief-os', owner_id: 'team_Hv5YS8LhIiKe06SSiDrUucd4', project: 'start-of-something-great', project_id: 'prj_cXnWySYVpJE9TVZaNPSocXMMzkZI'
  };
  const as = (environment) => ({ ...base, environment, sub: 'owner:chief-os:project:start-of-something-great:environment:' + environment });
  async function sign(claims) {
    const body = enc({ alg: 'RS256', kid: 'v1', typ: 'JWT' }) + '.' + enc(claims);
    const sig = await subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, Buffer.from(body));
    return body + '.' + Buffer.from(sig).toString('base64url');
  }
  return { oidc, sign, as, now, keys };
}

const VAULT = { dog_web_password: 'p'.repeat(64), dog_session_secret: 's'.repeat(64), dog_ip_hash_key: 'i'.repeat(64), dog_fingerprint_key_1: 'f'.repeat(64) };

// The broker as index.ts builds it, for one SUPABASE_URL, with made-up Vercel keys and a made-up Vault.
async function broker(supabaseUrl, vault) {
  const core = await import('../supabase/functions/dog-keys/core.mjs');
  const { target, checksFor } = await import('../supabase/functions/dog-keys/target.mjs');
  const s = await signer();
  const asked = [];
  const read = async (sql, extra = []) => { asked.push([...Object.keys(VAULT), ...extra]); return vault; };
  const checks = checksFor(target(supabaseUrl), { verify: (t, o) => s.oidc.verify(t, { ...o, now: s.now, keys: s.keys }), read });
  const call = (token) => core.handle({ method: 'POST', token }, { verify: (t) => checks.verify(t), Refused: s.oidc.Refused,
    values: () => checks.read(null), ref: checks.ref, marker: checks.marker });
  return { ...s, call, asked, core };
}

// ---- The broker: which one it is, from its own SUPABASE_URL only ----

test('preview copy, broker: production\'s own address, or anything not a Supabase project address, is production exactly as before', async () => {
  const { target, PREVIEW_MARKER } = await import('../supabase/functions/dog-keys/target.mjs');
  const prod = { environment: 'production', ref: PROD_REF, marker: null };
  for (const u of ['https://' + PROD_REF + '.supabase.co', 'https://' + PROD_REF + '.supabase.co/', undefined, null, '', 'not a url',
    'http://kong:8000', 'https://api.dayonegreat.com', 'https://short.supabase.co', 'https://' + PROD_REF.toUpperCase() + '.supabase.co',
    'https://' + BRANCH_REF + '.supabase.co.evil.example', 'https://' + BRANCH_REF + 'x.supabase.co']) {
    assert.deepStrictEqual({ ...target(u) }, prod, String(u));
  }
  const branch = target('https://' + BRANCH_REF + '.supabase.co');
  assert.deepStrictEqual({ ...branch }, { environment: 'preview', ref: BRANCH_REF, marker: PREVIEW_MARKER });
  assert.ok(Object.isFrozen(branch), 'decided once, and not changed after');
  // Host names aren't case-sensitive: the same address in capitals is the same branch.
  assert.deepStrictEqual({ ...target('https://' + BRANCH_REF.toUpperCase() + '.supabase.co') }, { ...branch });
});

test('preview copy, broker: production\'s broker refuses every preview token, and serves production\'s login exactly as before', async () => {
  const b = await broker('https://' + PROD_REF + '.supabase.co', VAULT);
  const no = await b.call(await b.sign(b.as('preview')));
  assert.deepStrictEqual([no.status, no.body.error], [401, 'refused: wrong environment']);
  assert.ok(!JSON.stringify(no.body).includes('p'.repeat(64)), 'a refusal carries no value');
  assert.strictEqual(b.asked.length, 0, 'a refused token never reaches Vault');
  const dev = await b.call(await b.sign(b.as('development')));
  assert.strictEqual(dev.status, 401);
  const ok = await b.call(await b.sign(b.as('production')));
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(ok.body.database.user, 'dog_web.' + PROD_REF);
  assert.deepStrictEqual(b.asked, [Object.keys(VAULT)], 'production asks Vault for exactly the four names, no mark');
  // The same answer the broker gave before the preview copy existed (shape with no options).
  assert.deepStrictEqual(ok.body, { ok: true, ...b.core.shape(VAULT) });
});

test('preview copy, broker: the branch\'s broker refuses production and foreign tokens, and serves only its own login', async () => {
  const marked = { ...VAULT, dog_preview_copy: 'yes' };
  const b = await broker('https://' + BRANCH_REF + '.supabase.co', marked);
  const prod = await b.call(await b.sign(b.as('production')));
  assert.deepStrictEqual([prod.status, prod.body.error], [401, 'refused: wrong environment'], 'production can\'t reach the branch');
  for (const [claims, why] of [
    [{ ...b.as('preview'), project_id: 'prj_someoneelse' }, 'wrong project'],
    [{ ...b.as('preview'), owner_id: 'team_someoneelse' }, 'wrong team'],
    [{ ...b.as('preview'), sub: 'owner:chief-os:project:start-of-something-great:environment:production' }, 'wrong subject'],
    [{ ...b.as('development') }, 'wrong environment']
  ]) {
    const r = await b.call(await b.sign(claims));
    assert.deepStrictEqual([r.status, r.body.error], [401, 'refused: ' + why], why);
  }
  assert.strictEqual(b.asked.length, 0);
  const ok = await b.call(await b.sign(b.as('preview')));
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(ok.body.database.user, 'dog_web.' + BRANCH_REF, 'the branch\'s own pooler login, never production\'s');
  assert.deepStrictEqual(b.asked, [[...Object.keys(VAULT), 'dog_preview_copy']]);
  assert.ok(!('dog_preview_copy' in ok.body) && !JSON.stringify(ok.body.keys).includes('yes'), 'the mark is checked, not handed out');
});

test('preview copy, broker: a branch without the mark hands out nothing, so production told it was a branch still refuses', async () => {
  for (const vault of [VAULT, { ...VAULT, dog_preview_copy: 'no' }, { ...VAULT, dog_preview_copy: '' }]) {
    const b = await broker('https://' + BRANCH_REF + '.supabase.co', vault);
    const r = await b.call(await b.sign(b.as('preview')));
    assert.deepStrictEqual([r.status, r.body.error, r.body.missing], [503, 'not set up', ['dog_preview_copy']]);
    assert.ok(!JSON.stringify(r.body).includes('p'.repeat(64)) && !r.body.database && !r.body.keys, 'no value');
  }
});

test('preview copy, broker: the environment is the target\'s, whatever a caller passes', async () => {
  const { target, checksFor } = await import('../supabase/functions/dog-keys/target.mjs');
  const seen = [];
  const verify = async (t, o) => { seen.push(o.environment); return {}; };
  const prod = checksFor(target('https://' + PROD_REF + '.supabase.co'), { verify, read: async () => ({}) });
  const branch = checksFor(target('https://' + BRANCH_REF + '.supabase.co'), { verify, read: async () => ({}) });
  await prod.verify('t', { environment: 'preview' });
  await branch.verify('t', { environment: 'production' });
  assert.deepStrictEqual(seen, ['production', 'preview']);
});

test('preview copy, broker: index.ts decides once from SUPABASE_URL, never from the request; the pinned check changed only by 057\'s list of our projects', () => {
  const src = fs.readFileSync(path.join(root, 'supabase/functions/dog-keys/index.ts'), 'utf8');
  assert.match(src, /^const checks = checksFor\(target\(Deno\.env\.get\("SUPABASE_URL"\)\), \{ verify, read \}\);$/m, 'once, at start');
  const serve = src.slice(src.indexOf('Deno.serve('));
  assert.doesNotMatch(serve, /target\(|checksFor\(|SUPABASE_URL/, 'nothing in the request handler chooses the target');
  assert.match(serve, /verify: \(t: string\) => checks\.verify\(t, \{ projects: \["site", "looks"\] \}\)/);
  assert.match(serve, /return checks\.read\(sql, project\);/);
  assert.match(serve, /ref: checks\.ref,\s+marker: checks\.marker,/);
  // The pinned identity check (its digest is in dog-keys/source-digest.mjs). Not changed by the preview copy; changed once,
  // by 057, to accept a list of our projects (the looks project; Aaron, Nov 10), in PR 2, for its independent review.
  const sha = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'supabase/functions/_shared/vercel-oidc.mjs'))).digest('hex');
  assert.strictEqual(sha, '4f24bf0a1908ff058827ee929344b1050a17303697c23febe7dae535325d2fa3');
});

// ---- The site: which broker it asks ----

test('preview copy, site: every deployment but a preview asks production\'s broker at its fixed address, exactly as before', () => {
  const sk = require('../db/sitekeys');
  assert.strictEqual(sk.BROKER, 'https://' + PROD_REF + '.supabase.co/functions/v1/dog-keys');
  assert.strictEqual(sk.PREVIEW_REF, null, 'no branch exists yet: the PR after its creation fixes its reference here');
  for (const e of [undefined, '', 'production', ' PRODUCTION ', 'development', 'staging']) {
    for (const ref of [null, BRANCH_REF]) {
      // Settings that might look like an address are never read.
      const env = { VERCEL_ENV: e, BROKER: 'https://evil.example', DOG_KEYS_URL: 'https://evil.example', SUPABASE_URL: 'https://' + BRANCH_REF + '.supabase.co' };
      assert.strictEqual(sk.brokerFor(env, ref), sk.BROKER, String(e) + ' ' + ref);
    }
  }
});

test('preview copy, site: a preview asks only the branch\'s fixed address, or nothing; never production\'s', () => {
  const sk = require('../db/sitekeys');
  for (const e of ['preview', ' Preview ']) {
    assert.strictEqual(sk.brokerFor({ VERCEL_ENV: e }), null, 'PREVIEW_REF is null in this PR: nothing');
    assert.strictEqual(sk.brokerFor({ VERCEL_ENV: e }, BRANCH_REF), 'https://' + BRANCH_REF + '.supabase.co/functions/v1/dog-keys');
    for (const bad of [PROD_REF, 'evil.example/x', 'QWERTYUIOPASDFGHJKLZ', 'short', '', 7, undefined]) {
      assert.strictEqual(sk.brokerFor({ VERCEL_ENV: e }, bad), null, String(bad));
    }
  }
});

test('preview copy, site: ensure() on a preview asks the branch\'s broker or nothing, and production\'s is never asked', async () => {
  const sk = require('../db/sitekeys');
  const body = { ok: true, database: { user: 'dog_web.' + BRANCH_REF, password: 'x'.repeat(40), hosts: ['aws-0-us-east-1.pooler.supabase.com'], port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: 'c2Vzcw==', IP_HASH_KEY: 'aXA=', FINGERPRINT_KEY_1: 'ZnA=' } };
  const calls = [];
  const fetchImpl = async (url) => { calls.push(url); return { status: 200, json: async () => body }; };
  const TOKEN = 'header.' + 'x'.repeat(40) + '.sig';
  const req = () => ({ headers: { 'x-vercel-oidc-token': TOKEN } });
  const pub = () => 'public';
  sk._reset();
  const r1 = req();
  assert.deepStrictEqual(await sk.ensure(r1, { fetchImpl, env: { VERCEL_ENV: 'preview' }, stage: pub }), { source: 'none', error: 'no_broker' });
  assert.deepStrictEqual(calls, [], 'no branch fixed in code: nothing is asked');
  assert.strictEqual(r1.headers['x-vercel-oidc-token'], undefined, 'M3 still holds: the token is removed');
  assert.strictEqual(await sk.refetch({ fetchImpl, env: { VERCEL_ENV: 'preview' }, stage: pub }), false);
  sk._reset();
  const env = { VERCEL_ENV: 'preview' };
  assert.strictEqual((await sk.ensure(req(), { fetchImpl, env, stage: pub, previewRef: BRANCH_REF })).source, 'broker');
  assert.deepStrictEqual(calls, ['https://' + BRANCH_REF + '.supabase.co/functions/v1/dog-keys']);
  sk._reset(); calls.length = 0;
  assert.strictEqual((await sk.ensure(req(), { fetchImpl, env: { VERCEL_ENV: 'production' }, stage: pub, previewRef: BRANCH_REF })).source, 'broker');
  assert.deepStrictEqual(calls, [sk.BROKER], 'production asks production\'s broker even when a branch is fixed in code');
  sk._reset();
});

test('preview copy, site: no route, page or script passes a broker reference; the address is only ever the code\'s', () => {
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (['node_modules', '.git', 'test', 'research', 'design'].includes(e.name)) continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else if (/\.(js|mjs|ts)$/.test(e.name)) files.push(p);
    }
  };
  walk(root);
  for (const f of files) {
    const rel = path.relative(root, f);
    if (rel === 'db/sitekeys.js' || rel === 'launch.js') continue;
    const src = fs.readFileSync(f, 'utf8');
    assert.doesNotMatch(src, /previewRef|PREVIEW_REF|brokerFor\(/, rel);
  }
});

// ---- launch.js: what stage a preview runs ----

// launch.js's rule before the preview copy, for comparison.
function before(env, f) {
  const STAGES = ['closed', 'public'];
  const a = f == null ? 'closed' : (STAGES.includes(String(f.stage == null ? '' : f.stage).trim().toLowerCase()) ? String(f.stage).trim().toLowerCase() : 'closed');
  const vercel = env.VERCEL_ENV == null ? '' : String(env.VERCEL_ENV).trim().toLowerCase();
  const raw = env.LAUNCH_STAGE == null ? '' : String(env.LAUNCH_STAGE).trim().toLowerCase();
  const b = (vercel !== '' && vercel !== 'production') ? 'closed' : (raw === '' || raw === 'public' ? 'public' : 'closed');
  return STAGES.indexOf(a) <= STAGES.indexOf(b) ? a : b;
}
const VERCEL = [undefined, '', 'production', 'Production', 'preview', ' Preview ', 'development', 'staging'];
const LAUNCH = [undefined, '', 'public', 'PUBLIC', 'closed', 'preview', 'open', 'typo'];
const FILES = [{ stage: 'public' }, { stage: 'closed' }, null, { stage: 'preview' }];
const REFS = [null, BRANCH_REF, PROD_REF];
const BOOTS = [[], ['DATABASE_URL'], ['SESSION_SECRET'], ['IP_HASH_KEY'], ['FINGERPRINT_KEY_1'], ['CRON_SECRET']];

test('preview copy, launch: every deployment that isn\'t a preview gets exactly the stage it got before', () => {
  const launch = require('../launch');
  for (const v of VERCEL) for (const l of LAUNCH) for (const f of FILES) for (const previewRef of REFS) for (const boot of BOOTS) {
    if (String(v || '').trim().toLowerCase() === 'preview') continue;
    assert.strictEqual(launch.stage({ VERCEL_ENV: v, LAUNCH_STAGE: l }, f, { previewRef, boot }), before({ VERCEL_ENV: v, LAUNCH_STAGE: l }, f), [v, l, JSON.stringify(f)].join(' '));
  }
});

test('preview copy, launch: a preview is never more open than production\'s own rules allow with the same settings', () => {
  const launch = require('../launch');
  let opened = 0;
  for (const v of VERCEL) for (const l of LAUNCH) for (const f of FILES) for (const previewRef of REFS) for (const boot of BOOTS) {
    const got = launch.stage({ VERCEL_ENV: v, LAUNCH_STAGE: l }, f, { previewRef, boot });
    // The same settings on a production deployment (what a hand-set VERCEL_ENV=preview on production would otherwise get).
    const asProduction = before({ VERCEL_ENV: 'production', LAUNCH_STAGE: l }, f);
    if (got === 'public') {
      assert.strictEqual(asProduction, 'public', 'opened beyond production\'s rules: ' + [v, l, JSON.stringify(f), previewRef, boot].join(' '));
      opened++;
    }
    const isPreview = String(v || '').trim().toLowerCase() === 'preview';
    if (isPreview) {
      const want = previewRef === BRANCH_REF && boot.length === 0 && asProduction === 'public' ? 'public' : 'closed';
      assert.strictEqual(got, want, [v, l, JSON.stringify(f), previewRef, boot].join(' '));
    }
  }
  assert.ok(opened > 0);
});

test('preview copy, launch: in this PR every preview stays closed (no branch is fixed in code), and LAUNCH_STAGE=preview still closes', () => {
  const launch = require('../launch');
  for (const f of FILES) {
    assert.strictEqual(launch.stage({ VERCEL_ENV: 'preview' }, f), 'closed');
    assert.strictEqual(launch.previewCopy({ VERCEL_ENV: 'preview' }), 'closed');
  }
  assert.strictEqual(launch.stage({ VERCEL_ENV: 'preview', LAUNCH_STAGE: 'preview' }, { stage: 'public' }, { previewRef: BRANCH_REF, boot: [] }), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'preview' }, { stage: 'public' }), 'closed');
  assert.strictEqual(launch.previewCopy({ VERCEL_ENV: 'production' }, { previewRef: BRANCH_REF, boot: [] }), 'closed', 'only a preview');
});

test('preview copy, launch: route A\'s settings are read as Vercel gave them at start, so the copy\'s own values never count', () => {
  // A fresh Node process, as a Vercel function starts: the settings present when launch.js first loads are Vercel's.
  const run = (env, script) => execFileSync(process.execPath, ['-e', script], { cwd: root, env: { PATH: process.env.PATH, ...env }, encoding: 'utf8' }).trim();
  const ask = "const l = require('./launch'); process.env.DATABASE_URL = 'postgres://set-later-by-the-broker'; process.env.SESSION_SECRET = 'x';"
    + " console.log(l.previewCopy(process.env, { previewRef: '" + BRANCH_REF + "' }))";
  assert.strictEqual(run({ VERCEL_ENV: 'preview' }, ask), 'public', 'values put in place after start (by the broker) don\'t close it');
  for (const k of ['DATABASE_URL', 'SESSION_SECRET', 'IP_HASH_KEY', 'FINGERPRINT_KEY_1', 'CRON_SECRET']) {
    assert.strictEqual(run({ VERCEL_ENV: 'preview', [k]: 'from-vercel' }, ask), 'closed', k + ' set in Vercel closes the copy');
  }
});

// ---- The seed: made-up data, and only on a fresh, empty copy ----

const SERVER = process.env.TEST_DATABASE_URL;
const VAULT_STAND_IN = `create schema vault;
  create table vault.secrets (id uuid primary key default gen_random_uuid(), name text unique, description text, secret text);
  create view vault.decrypted_secrets as select id, name, description, secret, secret as decrypted_secret from vault.secrets;
  create function vault.create_secret(new_secret text, new_name text default null, new_description text default '', new_key_id uuid default null)
    returns uuid language sql as $$ insert into vault.secrets (name, description, secret) values (new_name, new_description, new_secret) returning id $$;
  insert into vault.secrets (name, secret) values ('dog_web_password', repeat('w', 64));`;

// A throwaway database built from the migrations, with a stand-in for Supabase's Vault added after them (so migration
// 022 doesn't change the shared test server's dog_web password), as 022 would leave it: the site login's password only.
async function withCopy(fn, { vault = true } = {}) {
  const postgres = require('postgres');
  const { migrate } = require('../scripts/migrate');
  const name = 'dog_preview_seed_' + crypto.randomBytes(4).toString('hex');
  const admin = postgres(SERVER, { max: 1, onnotice: () => {} });
  await admin.unsafe('create database ' + name);
  const u = new URL(SERVER); u.pathname = '/' + name;
  const su = postgres(u.toString(), { max: 1, onnotice: () => {} });
  try {
    await migrate(su);
    if (vault) await su.unsafe(VAULT_STAND_IN);
    await fn(su);
  } finally {
    await su.end({ timeout: 5 });
    await admin.unsafe('drop database if exists ' + name + ' with (force)');
    await admin.end({ timeout: 5 });
  }
}
const snapshot = async (su) => {
  const [r] = await su`select (select count(*) from app.members)::int as members, (select count(*) from app.agents)::int as agents,
    (select count(*) from app.posts)::int as posts, (select count(*) from app.work_tasks)::int as tasks`;
  const [{ v }] = await su`select to_regnamespace('vault') is not null as v`;
  return { ...r, vault: v ? (await su`select name from vault.secrets order by name`).map((x) => x.name) : null };
};

test('preview copy, seed: a fresh copy gets made-up members, an admin, agents, live posts, a project and tasks, its own keys and the mark', { skip: !SERVER && 'needs TEST_DATABASE_URL' }, async () => {
  const seedMod = await import('../supabase/functions/_shared/preview-seed.mjs');
  await withCopy(async (su) => {
    const out = await seedMod.seed(su);
    assert.deepStrictEqual(out, { members: 5, admins: 1, agents: 2, posts: 5, projects: 1, tasks: 3, keys: 3, marker: true }, 'counts only, never a value');
    const members = await su`select display_name, trust_level, is_admin from app.members order by display_name`;
    assert.deepStrictEqual(members.map((m) => [m.display_name, m.trust_level, m.is_admin]), [
      ['Copy Admin', 2, true], ['Copy Member Ada', 2, false], ['Copy Member Ben', 2, false], ['Copy Member Cy', 2, false], ['Copy Newcomer Dee', 1, false]]);
    const posts = await su`select status, count(*)::int as n from app.posts group by status`;
    assert.deepStrictEqual(posts.map((p) => [p.status, p.n]), [['live', 5]], 'live under JEVs in enforce mode, as production runs');
    const [mode] = await su`select value from app.jevs_settings where key = 'mode'`;
    assert.strictEqual(mode.value, 'enforce');
    const [d] = await su`select count(*) filter (where action = 'post.create')::int as posts, count(*) filter (where action = 'agent.create')::int as agents from app.jevs_decisions`;
    assert.deepStrictEqual({ ...d }, { posts: 5, agents: 2 }, 'every made-up post and agent has its JEVs decision');
    const [w] = await su`select (select count(*) from app.work_projects)::int as projects, (select count(*) from app.work_tasks where status = 'open')::int as open_tasks`;
    assert.deepStrictEqual({ ...w }, { projects: 1, open_tasks: 3 });
    const keys = await su`select name, char_length(secret) as n from vault.secrets where name like 'dog_%' order by name`;
    assert.deepStrictEqual(keys.map((k) => [k.name, k.n]), [['dog_fingerprint_key_1', 128], ['dog_ip_hash_key', 128], ['dog_preview_copy', 3], ['dog_session_secret', 128], ['dog_web_password', 64]]);
    const distinct = await su`select count(distinct secret)::int as n from vault.secrets where name in ('dog_fingerprint_key_1', 'dog_ip_hash_key', 'dog_session_secret')`;
    assert.strictEqual(distinct[0].n, 3, 'three different keys');
    // The branch broker, end to end on the seeded copy: it hands out the branch's login and the copy's own keys.
    const core = await import('../supabase/functions/dog-keys/core.mjs');
    const { target, checksFor } = await import('../supabase/functions/dog-keys/target.mjs');
    const checks = checksFor(target('https://' + BRANCH_REF + '.supabase.co'), { verify: async () => ({ our_project: 'site' }), read: core.read }); // the check names which of our projects (057)
    const r = await core.handle({ method: 'POST', token: 't' }, { verify: checks.verify, Refused: Error, values: () => checks.read(su), ref: checks.ref, marker: checks.marker });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.database.user, 'dog_web.' + BRANCH_REF);
    // The roles are as the migrations left them (the seed gives back anything it took).
    const [g] = await su`select pg_has_role(current_user, 'dog_app', 'MEMBER') as m, rolsuper from pg_roles where rolname = current_user`;
    assert.ok(g.rolsuper || !g.m);
  });
});

test('preview copy, seed: refused, with nothing changed, on any database that isn\'t a fresh, empty copy', { skip: !SERVER && 'needs TEST_DATABASE_URL' }, async () => {
  const seedMod = await import('../supabase/functions/_shared/preview-seed.mjs');
  const { asSignin } = require('./helpers');
  const store = require('../db/signin');
  const refused = async (su, why) => {
    const was = await snapshot(su);
    await assert.rejects(seedMod.seed(su), (e) => e.message === 'seed refused: ' + why, why);
    assert.deepStrictEqual(await snapshot(su), was, 'nothing changed: ' + why);
  };
  // Production-like: a member exists (and, separately, the site keys are in Vault).
  await withCopy(async (su) => {
    const m = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: ['a'.repeat(64)], keyVersion: 1, level: 1, displayName: 'Real', sessionHash: 'b'.repeat(64), sessionDays: 30 }));
    await su.begin(async (t) => {
      await t`set local role dog_app`;
      await t`select app.act_as('member', ${m.memberId}::uuid, null::uuid, false, ${'b'.repeat(64)}, null, null)`;
      const [p] = await t`insert into app.posts (body) values ('a real post') returning id`;
      await t`select * from app.jevs_decide('post.create', ${p.id}::uuid, ${t.json({})}, 'low', false, null::text[], null::bigint, null)`;
    });
    await refused(su, 'this database already has members, agents or posts: it is not a fresh copy');
    // Why the seed counts rows as the owner login and not as dog_owner: forced row-level security hides posts from it.
    const asOwner = await su.begin(async (t) => { await t`set local role dog_owner`; return t`select count(*)::int as n from app.posts`; });
    const [{ n }] = await su`select count(*)::int as n from app.posts`;
    assert.deepStrictEqual([asOwner[0].n, n], [0, 1], 'dog_owner counts 0 posts where there is 1');
    await su`insert into vault.secrets (name, secret) values ('dog_session_secret', repeat('k', 64))`;
    await refused(su, 'this database already has site keys in Vault: it is not a fresh copy');
  });
  await withCopy(async (su) => {
    await su`insert into vault.secrets (name, secret) values ('dog_fingerprint_key_1', repeat('k', 64))`;
    await refused(su, 'this database already has site keys in Vault: it is not a fresh copy');
  });
  // Seeded once: a second run is refused (reset and migrate first).
  await withCopy(async (su) => {
    await seedMod.seed(su);
    await refused(su, 'already a seeded preview copy: reset and migrate it first');
  });
  // Not Supabase (no Vault): refused.
  await withCopy(async (su) => { await refused(su, 'no Vault: the preview copy runs only on a Supabase database'); }, { vault: false });
});

test('preview copy, seed: refuses an unmigrated database, makes no usable credential, and runs no raw SQL', { skip: !SERVER && 'needs TEST_DATABASE_URL' }, async () => {
  const seedMod = await import('../supabase/functions/_shared/preview-seed.mjs');
  const postgres = require('postgres');
  const name = 'dog_preview_empty_' + crypto.randomBytes(4).toString('hex');
  const admin = postgres(SERVER, { max: 1, onnotice: () => {} });
  await admin.unsafe('create database ' + name);
  const u = new URL(SERVER); u.pathname = '/' + name;
  const su = postgres(u.toString(), { max: 1, onnotice: () => {} });
  try {
    await assert.rejects(seedMod.seed(su), /seed refused: not migrated/);
  } finally {
    await su.end({ timeout: 5 });
    await admin.unsafe('drop database if exists ' + name + ' with (force)');
    await admin.end({ timeout: 5 });
  }
  const src = fs.readFileSync(path.join(root, 'supabase/functions/_shared/preview-seed.mjs'), 'utf8');
  assert.doesNotMatch(src, /\.unsafe\(|require\(|from 'postgres'|process\.env|Deno\.env|console\./, 'no raw SQL, no settings read, nothing printed');
  assert.doesNotMatch(src, /crypto\.|randomBytes|token\b/i, 'no secret is made outside the database');
});
