// The preview copy's database runner (RK141; design/preview-copy.md, "Building and reseeding the copy"). The same
// runner code (supabase/functions/dog-migrate) is deployed to production and to the one Supabase preview branch; each
// decides once, at start, from its own SUPABASE_URL, which one it is (dog-migrate/target.mjs). Every refusal the
// design rests on:
//   * production's runner is unchanged: its code outside the preview copy's marked blocks is byte for byte the old
//     file, its core is untouched, and it accepts only database.yml on main at production's own address;
//   * the branch's runner accepts only preview-copy.yml on main at the branch's own address, and only "rebuild";
//   * a production token is refused by the branch, and a branch token by production;
//   * the reset (drop the copy's schema, its keys and its mark; migrate; seed) can't run on production: the code
//     refuses unless it is the branch, and the database refuses unless it is the marked copy or holds nothing;
//   * one transaction: a failure leaves the copy exactly as it was;
//   * the workflow does nothing, and says so, while PREVIEW_REF is empty, and never addresses production.
// Made-up tokens and keys; nothing here reaches GitHub, Supabase or the network.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const { subtle } = globalThis.crypto;
const enc = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const PROD_REF = 'nksagchwpyljvjiwolmp';
const BRANCH_REF = 'qwertyuiopasdfghjklz'; // made up: 20 lowercase letters, as a Supabase reference is
const OTHER_REF = 'zyxwvutsrqponmlkjihg'; // another made-up branch
const runnerAt = (ref) => 'https://' + ref + '.supabase.co/functions/v1/dog-migrate';
// The runner's index.ts and core.mjs before the preview copy (supabase/functions/dog-migrate/source-digest.mjs at 781ebbb).
const OLD_INDEX = '2b3d714b06173b8e5aed0cd3934cfc2f5649d30c9827a35dce8e1b74a46cfc7b';
const OLD_CORE = '3603bc10413fe8bc6d9f334256fa8af27b6d2ddb6ae770efe68b2914cadae8ae';

// GitHub identity tokens, signed with a made-up key, for either workflow at either address.
async function signer() {
  const oidc = await import('../supabase/functions/_shared/github-oidc.mjs');
  const pair = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await subtle.exportKey('jwk', pair.publicKey)), kid: 'k1' };
  const keys = async () => [jwk];
  const now = 1_800_000_000;
  const base = {
    iss: oidc.ISSUER, exp: now + 300, iat: now - 5, nbf: now - 5,
    repository_id: '1418125608', repository_owner_id: '304218593', repository: 'MyChiefOS/start-of-something-great',
    ref: 'refs/heads/main', event_name: 'push', sha: 'c'.repeat(40), run_id: '7', actor: 'MyChiefOS'
  };
  const wf = (file) => 'MyChiefOS/start-of-something-great/.github/workflows/' + file + '@refs/heads/main';
  // production: database.yml at production's address; branch: preview-copy.yml at the branch's address.
  const production = (extra = {}) => ({ ...base, aud: runnerAt(PROD_REF), workflow_ref: wf('database.yml'), jti: crypto.randomUUID(), ...extra });
  const branch = (extra = {}) => ({ ...base, aud: runnerAt(BRANCH_REF), workflow_ref: wf('preview-copy.yml'), jti: crypto.randomUUID(), ...extra });
  async function sign(claims) {
    const body = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' }) + '.' + enc(claims);
    const sig = await subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, Buffer.from(body));
    return body + '.' + Buffer.from(sig).toString('base64url');
  }
  // The real check, with the made-up key and clock; the options are the runner's own.
  const verify = (token, opts) => oidc.verify(token, { ...opts, now, keys });
  return { oidc, sign, production, branch, wf, verify, Refused: oidc.Refused };
}

// ---- Which runner it is: from its own SUPABASE_URL only ----

test('preview runner, target: production\'s address or anything odd is production; any other project address is the branch', async () => {
  const { target, PRODUCTION } = await import('../supabase/functions/dog-migrate/target.mjs');
  const keys = await import('../supabase/functions/dog-keys/target.mjs');
  assert.deepStrictEqual({ ...PRODUCTION, events: [...PRODUCTION.events], modes: [...PRODUCTION.modes] }, {
    environment: 'production', ref: PROD_REF, audience: runnerAt(PROD_REF),
    workflow: '.github/workflows/database.yml', events: ['push', 'workflow_dispatch', 'schedule'], modes: ['apply', 'status']
  });
  const inputs = ['https://' + PROD_REF + '.supabase.co', 'https://' + PROD_REF + '.supabase.co/', undefined, null, '', 'not a url',
    'http://kong:8000', 'https://api.dayonegreat.com', 'https://short.supabase.co', 'https://' + PROD_REF.toUpperCase() + '.supabase.co',
    'https://' + BRANCH_REF + '.supabase.co.evil.example', 'https://' + BRANCH_REF + 'x.supabase.co'];
  for (const u of inputs) assert.strictEqual(target(u), PRODUCTION, String(u));
  const b = target('https://' + BRANCH_REF + '.supabase.co');
  assert.deepStrictEqual({ ...b, events: [...b.events], modes: [...b.modes] }, {
    environment: 'preview', ref: BRANCH_REF, audience: runnerAt(BRANCH_REF),
    workflow: '.github/workflows/preview-copy.yml', events: ['push', 'workflow_dispatch'], modes: ['rebuild']
  });
  assert.ok(Object.isFrozen(b) && Object.isFrozen(b.events) && Object.isFrozen(PRODUCTION) && Object.isFrozen(PRODUCTION.events), 'decided once, not changed after');
  // The same choice the key broker makes for the same address (dog-keys/target.mjs), so the two never disagree.
  for (const u of [...inputs, 'https://' + BRANCH_REF + '.supabase.co', 'https://' + OTHER_REF + '.supabase.co/x']) {
    const k = keys.target(u);
    const m = target(u);
    assert.deepStrictEqual([m.environment, m.ref], [k.environment, k.ref], String(u));
  }
});

test('preview runner, production unchanged: index.ts outside the copy\'s marked blocks is byte for byte the old file, core.mjs untouched', async () => {
  const src = read('supabase/functions/dog-migrate/index.ts');
  const blocks = [...src.matchAll(/^[ \t]*\/\/ ---- The preview copy \(RK141\): begin\.[^\n]*\n([\s\S]*?)^[ \t]*\/\/ ---- The preview copy: end\.\n/gm)];
  assert.strictEqual(blocks.length, 3, 'three marked blocks: the imports, the choice and its handler, the one line that routes to it');
  const stripped = src.replace(/^[ \t]*\/\/ ---- The preview copy \(RK141\): begin\.[^\n]*\n[\s\S]*?^[ \t]*\/\/ ---- The preview copy: end\.\n/gm, '');
  assert.strictEqual(sha(stripped), OLD_INDEX, 'production\'s code is the old index.ts, byte for byte');
  assert.strictEqual(sha(read('supabase/functions/dog-migrate/core.mjs')), OLD_CORE, 'the runner\'s core (also the JEVs gate\'s) is untouched');
  // The only thing in production's request path is one line, taken only when the start-up choice said "preview".
  const route = blocks[2][1].split('\n').filter((l) => l.trim() && !l.trim().startsWith('//'));
  assert.deepStrictEqual(route.map((l) => l.trim()), ['if (where.environment === "preview") return copyRequest(req);']);
  // Decided once, at start, from SUPABASE_URL; never from a request.
  assert.strictEqual((src.match(/target\(/g) || []).length, 1);
  assert.match(blocks[1][1], /^const where = target\(Deno\.env\.get\("SUPABASE_URL"\)\);$/m);
  assert.doesNotMatch(blocks[1][1], /target\(req|SUPABASE_URL"\)\s*\|\||headers\.get\("(host|x-forwarded|origin)/i);
  // Production's own checks are exactly PRODUCTION's (target.mjs), so the cross-refusal tests below test production's.
  const { PRODUCTION } = await import('../supabase/functions/dog-migrate/target.mjs');
  assert.ok(src.includes('const AUDIENCE = "' + PRODUCTION.audience + '";'));
  assert.ok(src.includes('workflow: "' + PRODUCTION.workflow + '",'));
  assert.ok(src.includes('events: ' + JSON.stringify([...PRODUCTION.events]).replace(/,/g, ', ') + ','));
  assert.ok(src.includes('if (body && (body.mode === "apply" || body.mode === "status")) mode = body.mode;'));
});

// ---- Who each runner accepts ----

test('preview runner, audiences: the branch accepts only preview-copy.yml at its own address; production only database.yml at its own', async () => {
  const { target, PRODUCTION } = await import('../supabase/functions/dog-migrate/target.mjs');
  const s = await signer();
  const branch = target('https://' + BRANCH_REF + '.supabase.co');
  const opts = (w) => ({ audience: w.audience, workflow: w.workflow, events: [...w.events] });
  // Each accepts its own.
  assert.strictEqual((await s.verify(await s.sign(s.branch()), opts(branch))).sha, 'c'.repeat(40));
  assert.strictEqual((await s.verify(await s.sign(s.production()), opts(PRODUCTION))).sha, 'c'.repeat(40));
  assert.strictEqual((await s.verify(await s.sign(s.branch({ event_name: 'workflow_dispatch' })), opts(branch))).event_name, 'workflow_dispatch');
  const no = async (token, w, why, name) => assert.rejects(s.verify(token, opts(w)), (e) => e instanceof s.Refused && why.test(e.message), name);
  // A production token is refused by the branch; a branch token by production.
  await no(await s.sign(s.production()), branch, /audience/, 'production\'s token at the branch');
  await no(await s.sign(s.branch()), PRODUCTION, /audience/, 'the branch\'s token at production');
  // Even misaddressed, the workflow still separates them: neither accepts the other's workflow at its own address.
  await no(await s.sign(s.production({ aud: runnerAt(BRANCH_REF) })), branch, /workflow/, 'database.yml addressed to the branch');
  await no(await s.sign(s.branch({ aud: runnerAt(PROD_REF) })), PRODUCTION, /workflow/, 'preview-copy.yml addressed to production');
  // Only its own address: another branch's, or a look-alike, is refused.
  await no(await s.sign(s.branch({ aud: runnerAt(OTHER_REF) })), branch, /audience/, 'another branch');
  await no(await s.sign(s.branch({ aud: runnerAt(BRANCH_REF) + '/' })), branch, /audience/, 'a look-alike address');
  // On main only, by a push or by hand: never a schedule, a pull request or another branch.
  await no(await s.sign(s.branch({ event_name: 'schedule' })), branch, /event/, 'a scheduled run');
  await no(await s.sign(s.branch({ ref: 'refs/pull/9/merge', event_name: 'pull_request' })), branch, /main branch/, 'a pull request');
  await no(await s.sign(s.branch({ workflow_ref: 'MyChiefOS/start-of-something-great/.github/workflows/preview-copy.yml@refs/heads/x' })), branch, /workflow/, 'the copy\'s workflow on another branch');
  await no(await s.sign(s.branch({ workflow_ref: s.wf('checks.yml') })), branch, /workflow/, 'another workflow on main');
});

test('preview runner, requests: production\'s choice never reaches the copy\'s handler; the branch takes only "rebuild" and its own token', async () => {
  const { target, PRODUCTION } = await import('../supabase/functions/dog-migrate/target.mjs');
  const { handleCopy } = await import('../supabase/functions/dog-migrate/copy.mjs');
  const s = await signer();
  const calls = [];
  const deps = (where) => ({ where, sql: null, Refused: s.Refused,
    verify: (t, o) => { calls.push('verify'); return s.verify(t, o); },
    load: async () => { calls.push('load'); throw new Error('load must not be reached'); } });
  const good = await s.sign(s.branch());
  // Production, or anything that isn't a branch, gets nothing from the copy's handler: not even a token check.
  for (const w of [PRODUCTION, target(undefined), target('https://' + PROD_REF + '.supabase.co'), null, { environment: 'preview', ref: PROD_REF }]) {
    const r = await handleCopy({ body: { mode: 'rebuild' }, token: good }, deps(w));
    assert.deepStrictEqual([r.status, r.body.error], [500, 'refused: not the preview copy\'s runner']);
  }
  assert.deepStrictEqual(calls, [], 'no check made, nothing loaded');
  const branch = target('https://' + BRANCH_REF + '.supabase.co');
  for (const body of [{ mode: 'apply' }, { mode: 'status' }, {}, null, 'rebuild', { mode: 'REBUILD' }]) {
    const r = await handleCopy({ body, token: good }, deps(branch));
    assert.deepStrictEqual([r.status, r.body.error], [400, 'mode must be rebuild'], JSON.stringify(body));
  }
  assert.deepStrictEqual(calls, [], 'a wrong mode is refused before the token is checked');
  for (const [token, why] of [[await s.sign(s.production()), /^refused: wrong audience$/], ['', /^refused: token missing/], [await s.sign(s.branch({ event_name: 'schedule' })), /^refused: wrong event$/]]) {
    const r = await handleCopy({ body: { mode: 'rebuild' }, token }, deps(branch));
    assert.strictEqual(r.status, 401);
    assert.match(r.body.error, why);
  }
  assert.ok(!calls.includes('load'), 'a refused token loads nothing and changes nothing');
});

// ---- The reset: on the copy only ----

const SERVER = process.env.TEST_DATABASE_URL;
// A stand-in for Supabase's Vault (the real one encrypts; the names and functions are the same).
const VAULT_STAND_IN = `create schema vault;
  create table vault.secrets (id uuid primary key default gen_random_uuid(), name text unique, description text, secret text);
  create view vault.decrypted_secrets as select id, name, description, secret, secret as decrypted_secret from vault.secrets;
  create function vault.create_secret(new_secret text, new_name text default null, new_description text default '', new_key_id uuid default null)
    returns uuid language sql as $$ insert into vault.secrets (name, description, secret) values (new_name, new_description, new_secret) returning id $$;
  create function vault.update_secret(secret_id uuid, new_secret text default null, new_name text default null, new_description text default null, new_key_id uuid default null)
    returns void language sql as $$ update vault.secrets set secret = coalesce(new_secret, secret) where id = secret_id $$;`;

// A throwaway database standing in for the branch as Supabase creates it: Vault, and nothing of ours (or, with
// migrated, built from the migrations the way the local tests build production's).
async function withBranch(fn, { vault = true, migrated = false } = {}) {
  const postgres = require('postgres');
  const name = 'dog_preview_runner_' + crypto.randomBytes(4).toString('hex');
  const admin = postgres(SERVER, { max: 1, onnotice: () => {} });
  await admin.unsafe('create database ' + name);
  const u = new URL(SERVER); u.pathname = '/' + name;
  const su = postgres(u.toString(), { max: 1, prepare: false, onnotice: () => {} });
  try {
    if (vault) await su.unsafe(VAULT_STAND_IN);
    if (migrated) await require('../scripts/migrate').migrate(su);
    await fn(su);
  } finally {
    await su.end({ timeout: 5 });
    await admin.unsafe('drop database if exists ' + name + ' with (force)');
    await admin.end({ timeout: 5 });
  }
}

// Everything a reset would change, to prove a refusal changed nothing.
async function snapshot(su) {
  const [s] = await su`select to_regclass('app.members') is not null as app, to_regnamespace('vault') is not null as vault`;
  const out = { app: s.app };
  if (s.app) {
    Object.assign(out, (await su`select (select array_agg(id::text order by id) from app.members) as members,
      (select count(*) from app.posts)::int as posts, (select count(*) from app.schema_migrations)::int as ledger,
      (select count(*) from app.change_log)::int as changes`)[0]);
  }
  if (s.vault) out.vault = (await su`select name, md5(secret) as h from vault.secrets order by name`).map((r) => r.name + ':' + r.h);
  return out;
}

if (!SERVER) {
  if (process.env.CI) test('preview runner database tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('preview runner against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
} else {
  const local = (p) => read(p);
  const claims = (extra = {}) => ({ sha: 'c'.repeat(40), run_id: '7', actor: 'test', event_name: 'push', jti: crypto.randomUUID(), ...extra });
  const manifest = () => JSON.parse(read('db/manifest.json')).migrations.map((m) => [m.version, m.sha256]);

  test('preview runner, rebuild: a new branch is migrated and seeded; a second rebuild starts again from empty, through the real token check', async () => {
    const core = await import('../supabase/functions/dog-migrate/core.mjs');
    const { target } = await import('../supabase/functions/dog-migrate/target.mjs');
    const { handleCopy } = await import('../supabase/functions/dog-migrate/copy.mjs');
    const s = await signer();
    const branch = target('https://' + BRANCH_REF + '.supabase.co');
    await withBranch(async (su) => {
      const deps = { where: branch, sql: su, verify: s.verify, Refused: s.Refused, load: async (commit) => { assert.strictEqual(commit, 'c'.repeat(40)); return core.load(local); } };
      const t1 = await s.sign(s.branch());
      const r1 = await handleCopy({ body: { mode: 'rebuild' }, token: t1 }, deps);
      assert.strictEqual(r1.status, 200, JSON.stringify(r1.body));
      assert.deepStrictEqual(r1.body.failed, [], 'every catalog check passes');
      assert.deepStrictEqual([r1.body.ok, r1.body.rebuilt, r1.body.applied.length, r1.body.total], [true, true, manifest().length, manifest().length]);
      assert.deepStrictEqual(r1.body.seeded, { members: 5, admins: 1, agents: 2, posts: 5, projects: 1, tasks: 3, keys: 3, marker: true });
      assert.deepStrictEqual((await core.status(su)).map((x) => [x.version, x.sha256]), manifest(), 'the ledger is main\'s');
      const first = await snapshot(su);
      assert.strictEqual(first.members.length, 5);
      assert.deepStrictEqual(first.vault.map((v) => v.split(':')[0]), ['dog_fingerprint_key_1', 'dog_ip_hash_key', 'dog_preview_copy', 'dog_session_secret', 'dog_web_password']);
      // The same token can't be used again, though the reset dropped the table it was first recorded in.
      const again = await handleCopy({ body: { mode: 'rebuild' }, token: t1 }, deps);
      assert.deepStrictEqual([again.status, again.body.error], [401, 'refused: token already used']);
      assert.deepStrictEqual(await snapshot(su), first, 'a replayed token changes nothing');
      // A second rebuild: everything made fresh, nothing doubled.
      const r2 = await handleCopy({ body: { mode: 'rebuild' }, token: await s.sign(s.branch({ event_name: 'workflow_dispatch' })) }, deps);
      assert.strictEqual(r2.status, 200, JSON.stringify(r2.body));
      const second = await snapshot(su);
      assert.strictEqual(second.members.length, 5, 'five made-up members, not ten');
      assert.ok(second.members.every((id) => !first.members.includes(id)), 'new members: the old ones went with the reset');
      assert.deepStrictEqual([second.posts, second.ledger, second.changes], [5, manifest().length, 1], 'one change recorded: this rebuild');
      const keyOf = (snap, n) => snap.vault.find((v) => v.startsWith(n + ':'));
      for (const n of ['dog_session_secret', 'dog_ip_hash_key', 'dog_fingerprint_key_1']) assert.notStrictEqual(keyOf(second, n), keyOf(first, n), n + ' made new');
      assert.notStrictEqual(keyOf(second, 'dog_web_password'), keyOf(first, 'dog_web_password'), 'migration 022 gave the copy\'s login a new password');
      const [log] = await su`select event, reset, result, jsonb_array_length(applied)::int as n from app.change_log`;
      assert.deepStrictEqual({ ...log }, { event: 'workflow_dispatch', reset: false, result: 'ok', n: manifest().length });
    });
  });

  test('preview runner, reset on production: refused by the code unless it is the branch, with nothing changed', async () => {
    const core = await import('../supabase/functions/dog-migrate/core.mjs');
    const { target, PRODUCTION } = await import('../supabase/functions/dog-migrate/target.mjs');
    const { rebuild } = await import('../supabase/functions/dog-migrate/copy.mjs');
    await withBranch(async (su) => {
      // Even a marked, seeded copy is not touched by a runner that isn't the branch's.
      await rebuild(su, await core.load(local), claims(), target('https://' + BRANCH_REF + '.supabase.co'));
      const was = await snapshot(su);
      for (const w of [PRODUCTION, target('https://' + PROD_REF + '.supabase.co'), target(''), target('junk'), null, undefined,
        { environment: 'preview', ref: PROD_REF }, { environment: 'preview', ref: 'short' }, { ...PRODUCTION, environment: 'Preview' }]) {
        await assert.rejects(rebuild(su, await core.load(local), claims(), w), (e) => e.message === 'refused: not the preview copy\'s runner', JSON.stringify(w));
        assert.deepStrictEqual(await snapshot(su), was, 'nothing changed');
      }
    });
  });

  test('preview runner, reset on a database that isn\'t the copy: refused by the database, with nothing changed', async () => {
    const core = await import('../supabase/functions/dog-migrate/core.mjs');
    const { target } = await import('../supabase/functions/dog-migrate/target.mjs');
    const { rebuild, resetRefusal } = await import('../supabase/functions/dog-migrate/copy.mjs');
    const { asSignin } = require('./helpers');
    const store = require('../db/signin');
    const branch = target('https://' + BRANCH_REF + '.supabase.co');
    const refused = async (su, why) => {
      const was = await snapshot(su);
      await assert.rejects(rebuild(su, await core.load(local), claims(), branch), (e) => e.message === 'reset refused: ' + why, why);
      assert.deepStrictEqual(await snapshot(su), was, 'nothing changed: ' + why);
      assert.strictEqual(await su.begin(resetRefusal), why);
    };
    const KEYS = 'site keys in Vault and no preview mark: this is not the preview copy';
    const ROWS = 'members, agents or posts and no preview mark: this is not the preview copy';
    // Production-like: built, a real member and post, the three site keys in Vault, no mark. Refused for each reason.
    await withBranch(async (su) => {
      await su`insert into vault.secrets (name, secret) values ('dog_session_secret', repeat('k', 64)), ('dog_ip_hash_key', repeat('k', 64)), ('dog_fingerprint_key_1', repeat('k', 64))`;
      await refused(su, KEYS);
      const m = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: ['a'.repeat(64)], keyVersion: 1, level: 1, displayName: 'Real', sessionHash: 'b'.repeat(64), sessionDays: 30 }));
      await refused(su, KEYS);
      await su`delete from vault.secrets where name like 'dog\\_%' and name <> 'dog_web_password'`;
      await refused(su, ROWS);
      await su.begin(async (t) => {
        await t`set local role dog_app`;
        await t`select app.act_as('member', ${m.memberId}::uuid, null::uuid, false, ${'b'.repeat(64)}, null, null)`;
        const [p] = await t`insert into app.posts (body) values ('a real post') returning id`;
        await t`select * from app.jevs_decide('post.create', ${p.id}::uuid, ${t.json({})}, 'low', false, null::text[], null::bigint, null)`;
      });
      await refused(su, ROWS);
      // A mark that doesn't say "yes" is no mark (as the key broker reads it).
      await su`insert into vault.secrets (name, secret) values ('dog_preview_copy', 'no')`;
      await refused(su, ROWS);
    }, { migrated: true });
    // A new branch whose Vault came with site keys (if Supabase ever copied production's Vault): refused.
    await withBranch(async (su) => {
      await su`insert into vault.secrets (name, secret) values ('dog_session_secret', repeat('k', 64))`;
      await refused(su, KEYS);
    });
    // Not Supabase (no Vault): refused.
    await withBranch(async (su) => { await refused(su, 'no Vault: the preview copy runs only on a Supabase database'); }, { vault: false });
    // What the reset may start from: nothing built, a built but empty copy, or the marked copy.
    await withBranch(async (su) => { assert.strictEqual(await su.begin(resetRefusal), null, 'a new branch'); });
    await withBranch(async (su) => { assert.strictEqual(await su.begin(resetRefusal), null, 'built, empty'); }, { migrated: true });
  });

  test('preview runner, one transaction: a failed migration or seed leaves the copy exactly as it was', async () => {
    const core = await import('../supabase/functions/dog-migrate/core.mjs');
    const { target } = await import('../supabase/functions/dog-migrate/target.mjs');
    const { rebuild } = await import('../supabase/functions/dog-migrate/copy.mjs');
    const branch = target('https://' + BRANCH_REF + '.supabase.co');
    await withBranch(async (su) => {
      await rebuild(su, await core.load(local), claims(), branch);
      const was = await snapshot(su);
      const good = await core.load(local);
      const broken = { files: good.files.map((f, i) => (i === good.files.length - 1 ? { ...f, sql: f.sql + '\nselect 1/0;' } : f)), reset: null };
      await assert.rejects(rebuild(su, broken, claims(), branch), /division by zero/);
      assert.deepStrictEqual(await snapshot(su), was, 'a failed migration: the old copy stands');
      // The seed fails if a migration left a site key behind (it refuses a database that isn't fresh): all undone.
      const seeding = { files: good.files.map((f, i) => (i === good.files.length - 1 ? { ...f,
        sql: f.sql + "\nreset role;\nselect vault.create_secret('left by a migration', 'dog_session_secret');" } : f)), reset: null };
      await assert.rejects(rebuild(su, seeding, claims(), branch), /seed refused: this database already has site keys in Vault/);
      assert.deepStrictEqual(await snapshot(su), was, 'a failed seed: the old copy stands');
    });
  });
}

// ---- The workflow ----

// The run: script of the workflow's one step, as the runner's shell gets it.
function stepScript(y) {
  const lines = y.split('\n');
  const at = lines.findIndex((l) => /^\s+run: \|$/.test(l));
  const indent = lines[at].match(/^\s*/)[0].length;
  const body = [];
  for (const l of lines.slice(at + 1)) {
    if (l.trim() && l.match(/^\s*/)[0].length <= indent) break;
    body.push(l.slice(indent + 2));
  }
  return body.join('\n');
}

// Runs the step with a stand-in curl that records what it was asked and answers like GitHub and the runner.
function runStep(previewRef, { answer = 200 } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-preview-wf-'));
  try {
    const log = path.join(dir, 'curl.log');
    fs.writeFileSync(path.join(dir, 'curl'), `#!/bin/bash
printf '%s\\n' "$*" >> "${log}"
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
case "$*" in
  *"-X POST"*) printf '{"ok":true,"rebuilt":true,"applied":["001_foundation"],"total":1,"failed":[],"seeded":{"members":5}}' > "$out"; printf '${answer}' ;;
  *) printf '{"value":"made.up.token"}' ;;
esac
`, { mode: 0o755 });
    const summary = path.join(dir, 'summary.md');
    const r = spawnSync('bash', ['-e', '-c', stepScript(read('.github/workflows/preview-copy.yml'))], {
      cwd: dir, encoding: 'utf8',
      env: { PATH: dir + ':' + process.env.PATH, PREVIEW_REF: previewRef, GITHUB_STEP_SUMMARY: summary, GITHUB_SHA: 'd'.repeat(40),
        ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example/?x=1', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request-token' }
    });
    const calls = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : [];
    return { code: r.status, out: r.stdout + r.stderr, calls, summary: fs.existsSync(summary) ? fs.readFileSync(summary, 'utf8') : '' };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('preview runner, workflow: on merge to main and by hand only; least rights; its PREVIEW_REF is the site\'s', () => {
  const y = read('.github/workflows/preview-copy.yml');
  assert.match(y, /^on:\n  push:\n    branches: \[main\]\n  workflow_dispatch:\n\npermissions:\n  contents: read\n  id-token: write[^\n]*\n\n/m);
  assert.doesNotMatch(y, /schedule:|pull_request|issues:|pull-requests:|contents: write|secrets\.|uses:/, 'no schedule, no PR runs, no secret, no write rights, no outside action');
  assert.match(y, /if: github\.repository_id == 1418125608 && github\.ref == 'refs\/heads\/main'/);
  assert.match(y, /concurrency:\n\s+group: preview-copy\n\s+cancel-in-progress: false/, 'its own group: never queued with production\'s migrations');
  assert.doesNotMatch(y, /database-migrations/);
  // The branch's reference is fixed in code in one value, the same as db/sitekeys.js PREVIEW_REF (null there, '' here).
  const m = y.match(/^\s+PREVIEW_REF: '([a-z]*)'$/m);
  assert.ok(m, 'PREVIEW_REF is a fixed value in the workflow');
  assert.strictEqual(m[1] || null, require('../db/sitekeys').PREVIEW_REF, 'the workflow and the site name the same branch');
  assert.strictEqual(y.split('PREVIEW_REF:').length, 2, 'set in one place only');
  // Production's address appears only in the refusal: the runner's address is built from PREVIEW_REF.
  assert.match(stepScript(y), /RUNNER_URL="https:\/\/\$PREVIEW_REF\.supabase\.co\/functions\/v1\/dog-migrate"/);
  assert.deepStrictEqual(y.match(/nksagchwpyljvjiwolmp[^\s"']*/g), ['nksagchwpyljvjiwolmp'], 'named only to refuse it');
  // Production's workflow is untouched by this one.
  assert.doesNotMatch(read('.github/workflows/database.yml'), /preview|rebuild/i);
});

test('preview runner, workflow: an empty PREVIEW_REF does nothing and says so; a bad one is refused before any token', () => {
  const empty = runStep('');
  assert.strictEqual(empty.code, 0, empty.out);
  assert.deepStrictEqual(empty.calls, [], 'no token asked for, nothing called');
  assert.match(empty.summary, /PREVIEW_REF is empty[^\n]*nothing to rebuild/);
  for (const bad of [PROD_REF, 'short', BRANCH_REF.toUpperCase(), BRANCH_REF + '.evil.example', '$(id)']) {
    const r = runStep(bad);
    assert.strictEqual(r.code, 1, bad);
    assert.deepStrictEqual(r.calls, [], bad + ': no token asked for');
    assert.match(r.summary, /refused/i, bad);
  }
});

test('preview runner, workflow: with a branch fixed, the token is addressed to the branch\'s runner only, and the answer is reported', () => {
  const r = runStep(BRANCH_REF);
  assert.strictEqual(r.code, 0, r.out);
  assert.strictEqual(r.calls.length, 2, r.calls.join('\n'));
  assert.ok(r.calls[0].includes('audience=' + runnerAt(BRANCH_REF)), 'the token\'s audience is the branch\'s runner: ' + r.calls[0]);
  assert.ok(r.calls[1].includes('-X POST ' + runnerAt(BRANCH_REF)), r.calls[1]);
  assert.ok(r.calls[1].includes('{"mode":"rebuild"}'));
  assert.ok(!r.calls.join('\n').includes(PROD_REF), 'production is never addressed');
  assert.match(r.summary, /Result: passed/);
  const failed = runStep(BRANCH_REF, { answer: 500 });
  assert.notStrictEqual(failed.code, 0, 'a failed rebuild fails the run (GitHub tells the owner); it locks nothing');
});

// ---- What is deployed ----

test('preview runner, deploy: the runner\'s digest covers the copy\'s files, and they deploy byte for byte', () => {
  const digests = require('../scripts/function-digests');
  assert.deepStrictEqual(digests.sources('dog-migrate'), ['_shared/github-oidc.mjs', '_shared/preview-seed.mjs', 'dog-migrate/copy.mjs',
    'dog-migrate/core.mjs', 'dog-migrate/index.ts', 'dog-migrate/target.mjs']);
  assert.ok(!digests.sources('jevs').some((f) => /copy|target|preview/.test(f)), 'the JEVs gate deploys none of it');
  for (const f of digests.sources('dog-migrate')) {
    const s = read('supabase/functions/' + f);
    assert.ok(!/\\u[0-9A-Fa-f]{4}/.test(s), f + ' uses a \\uXXXX escape, which the deploy tool turns into the character');
    assert.deepStrictEqual([...new Set(s.match(/[^\x00-\x7F]/gu) || [])].filter((c) => !'—–’'.includes(c)), [], f);
  }
  // The copy's files run no raw SQL and read no setting: the address and the database come from index.ts.
  for (const f of ['supabase/functions/dog-migrate/copy.mjs', 'supabase/functions/dog-migrate/target.mjs']) {
    assert.doesNotMatch(read(f), /\.unsafe\(|Deno\.env|process\.env|fetch\(|console\./, f);
  }
});
