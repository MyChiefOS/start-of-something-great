// USE-CASES.md row 15: the fresh build, rehearsed on a throwaway copy before production.
// It rebuilds the live database as it is (the Oct 23 build: 001 to 017 from commit 9b1fcd7, the same fingerprints
// as the live ledger), then runs the runner's own code (supabase/functions/dog-migrate/core.mjs) against it and
// checks the result: passkeys gone, the ledger equal to main, the change recorded, a second run doing nothing.
// It also proves the refusals (a single real row, a different build) and the way back (rebuilding Oct 23 exactly).
// CI runs it twice: on plain Postgres 17 with the other tests, and on Supabase's own Postgres image, in place
// (RUNNER_TEST_IN_PLACE=1), where Vault and the gateway login exist as they do in production.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const postgres = require('postgres');
const { build, FILE } = require('../scripts/manifest');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const IN_PLACE = process.env.RUNNER_TEST_IN_PLACE === '1';
const LIVE_COMMIT = '9b1fcd769075033092c07d14fe668a11dac55a09';
// The live ledger, read from Supabase on Oct 24, 2026 (app.schema_migrations; the same list the Oct 23 runner held).
const LIVE = [
  ['001_foundation', '58d9bba8a8703bb3220b2e164e90bf616c67ead7315498038275a82afef4f737'],
  ['002_signin', 'f26d977343fb773b68122832eedf46f36fcd9cabd86ee31fda45df3d8b964408'],
  ['003_posts', 'ba4b47b5bc286ba4789dc468b24ba5c13fe31db13ca029d4b35c8a579b850c53'],
  ['004_review', '61ab05faf7c62770b57c26c1889f70ba4e7e71854c4ced57cf80f99e4d027ae9'],
  ['005_agents', 'd33e71eff1e4cd68d39336af1e99e6ef1151e05263b9723e7f7e803b0bd210c8'],
  ['006_owner_controls', '5806d73e03a4ec2f7ed565544178c040ba246db30cddc4516b5c93a71fae454c'],
  ['007_account_deletion', 'f5b0b58c269b605ee3811caee224e98b56da946cafe8bcd552d40e508941d28f'],
  ['008_delegated_agency', '3a29442e8021cbc9b929cae288b2a1238dda46cfa5efffcb640f29980780968e'],
  ['009_fresh_delete', '0f5d32eb8ff295c0c1a09e310d5eb498133fe78b6fb37bc0b1cc5b4b2ff77001'],
  ['010_jevs', '157d8fc66017e22898a985eb0923f89a7976696006ba877d3aa8a7521a461d59'],
  ['011_notifications', '9316ac0072037444de2667a348d9da6d8b5548d44f2dc405e5352b72c90316a4'],
  ['012_signin_fixes', '3291f5ccb763ef43f296bfb126337cb948cb2b036a5446145f28796d0d745acb'],
  ['013_setup_audit', '957e455c3a78a2f8010718ead0a24db2123f660677ecbbf0fa17bf852fb1f12f'],
  ['014_passkeys', '56e45811f334653cbd3cd40f10dd840f525c60e8758e852dc89fa99803c14854'],
  ['015_subagents', '58a93e2138dae621ef702e5ae59829b01b80a65859a85cac10e2b09e753f0f2e'],
  ['016_security_batch1', '1d601b0350c012e412da19c46c07e8b784d5c0f3fa508359a2f58b6d50c5b403'],
  ['017_gateway', '923890f214d3b2e5097e780596c48f42fc0ad84c1aa7c152249ae41f9a3176aa']
];

test('row 15: db/manifest.json lists every migration and the reset with their current fingerprints', () => {
  assert.strictEqual(fs.readFileSync(FILE, 'utf8'), build(), 'run node scripts/manifest.js');
  const m = JSON.parse(build());
  assert.deepStrictEqual(m.reset.when, { version: '014_passkeys', sha256: LIVE[13][1] }, 'the reset runs only against the Oct 23 build');
});

test('row 15: the passkey migrations are gone and sub-agents is unchanged byte for byte', () => {
  const names = fs.readdirSync(path.join(root, 'db', 'migrations')).filter((f) => f.endsWith('.sql'));
  assert.ok(!names.some((n) => /passkey|security_batch1|gateway/.test(n)), names.join(', '));
  const sub = fs.readFileSync(path.join(root, 'db', 'migrations', '014_subagents.sql'), 'utf8');
  assert.strictEqual(crypto.createHash('sha256').update(sub).digest('hex'), LIVE[14][1], 'old 015 moved to 014 without a single change');
});

if (!SERVER) {
  if (process.env.CI) test('runner tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('runner rehearsal against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run it' }, () => {});
} else {
  let core;
  const local = (p) => fs.readFileSync(path.join(root, p), 'utf8');
  const fromLive = (p) => execFileSync('git', ['show', LIVE_COMMIT + ':' + p], { cwd: root, encoding: 'utf8', maxBuffer: 1 << 24 });
  const liveManifest = (extra = {}) => JSON.stringify({ migrations: LIVE.map(([version, sha256]) => ({ version, sha256 })), ...extra });
  const claims = () => ({ sha: 'c'.repeat(40), run_id: '42', actor: 'test', event_name: 'push', jti: crypto.randomUUID() });

  // The Oct 23 build, exactly as production has it.
  async function buildLive(sql) {
    const v1 = await core.load((p) => (p === 'db/manifest.json' ? liveManifest() : fromLive(p)));
    const r = await core.run(sql, v1, claims());
    assert.deepStrictEqual(r.applied, LIVE.map((x) => x[0]));
  }
  const freshBuild = () => core.load(local);
  const ledgerIs = async (sql, list) => assert.deepStrictEqual((await core.status(sql)).map((x) => [x.version, x.sha256]), list);
  const newList = () => JSON.parse(build()).migrations.map((x) => [x.version, x.sha256]);

  // A throwaway database per test (or, in place, the given one emptied first).
  async function withDatabase(fn) {
    const admin = postgres(SERVER, { max: 1, onnotice: () => {} });
    let url = SERVER, name = null;
    try {
      if (IN_PLACE) {
        await admin.unsafe('drop schema if exists app cascade');
      } else {
        name = 'dog_runner_' + crypto.randomBytes(4).toString('hex');
        await admin.unsafe('create database ' + name);
        const u = new URL(SERVER); u.pathname = '/' + name; url = u.toString();
      }
      const sql = postgres(url, { max: 1, prepare: false, onnotice: () => {} });
      try { await fn(sql); } finally { await sql.end({ timeout: 5 }); }
    } finally {
      if (name) await admin.unsafe('drop database if exists ' + name + ' with (force)');
      await admin.end({ timeout: 5 });
    }
  }

  test.before(async () => {
    core = await import('../supabase/functions/dog-migrate/core.mjs');
    try { fromLive('db/migrations/014_passkeys.sql'); } catch {
      throw new Error('commit ' + LIVE_COMMIT + ' (the live Oct 23 build) is not in this checkout; fetch it with fetch-depth: 0');
    }
  });

  test('row 15: the fresh build turns the Oct 23 database into main: passkeys gone, every check passing, the change recorded', async () => {
    await withDatabase(async (sql) => {
      await buildLive(sql);
      await ledgerIs(sql, LIVE);
      const c = claims();
      const r = await core.run(sql, await freshBuild(), c);
      assert.deepStrictEqual(r.failed, [], 'every built-in check passes');
      assert.strictEqual(r.reset, true);
      assert.deepStrictEqual(r.applied, newList().map((x) => x[0]));
      await ledgerIs(sql, newList());
      const [gone] = await sql`select to_regclass('app.passkeys') as p, to_regprocedure('app.step_up_check()') as f,
        (select count(*) from pg_trigger where tgname like '%step_up%')::int as triggers,
        (select count(*) from pg_roles where rolname = 'dog_web' and rolcanlogin)::int as web`;
      assert.deepStrictEqual(gone, { p: null, f: null, triggers: 0, web: 0 });
      const log = await sql.begin(async (t) => { await t`set local role dog_owner`; return t`select commit_sha, actor, event, reset, applied, result from app.change_log`; });
      assert.strictEqual(log.length, 1);
      assert.deepStrictEqual({ ...log[0], applied: log[0].applied.length }, { commit_sha: c.sha, actor: 'test', event: 'push', reset: true, applied: newList().length, result: 'ok' });
      const seen = await core.tokenSeen(sql, c.jti);
      assert.strictEqual(seen, true, 'the token can never be used again');

      const again = await core.run(sql, await freshBuild(), claims());
      assert.deepStrictEqual({ reset: again.reset, applied: again.applied, failed: again.failed }, { reset: false, applied: [], failed: [] }, 'a second run changes nothing');
      const n = await sql.begin(async (t) => { await t`set local role dog_owner`; return t`select count(*)::int as n from app.change_log`; });
      assert.strictEqual(n[0].n, 1, 'a run that changes nothing writes no change record');
      await assert.rejects(sql.begin(async (t) => { await t`set local role dog_owner`; await t`delete from app.change_log`; }), /append-only/);
    });
  });

  test('row 15: one real row stops the fresh build, and nothing changes', async () => {
    await withDatabase(async (sql) => {
      await buildLive(sql);
      await sql`insert into app.members (display_name) values ('a real person')`;
      await assert.rejects(core.run(sql, await freshBuild(), claims()), /fresh build refused: app\.members has 1 row/);
      await ledgerIs(sql, LIVE);
      const [{ n }] = await sql`select count(*)::int as n from app.members`;
      assert.strictEqual(n, 1);
    });
  });

  test('row 15: a database that is not the Oct 23 build is never reset, and the run stops', async () => {
    await withDatabase(async (sql) => {
      await buildLive(sql);
      await sql.begin(async (t) => { await t`set local role dog_owner`; await t`update app.schema_migrations set sha256 = ${'0'.repeat(64)} where version = '014_passkeys'`; });
      await assert.rejects(core.run(sql, await freshBuild(), claims()), /missing from the merged commit: 014_passkeys, 015_subagents, 016_security_batch1, 017_gateway/);
      const [{ p }] = await sql`select to_regclass('app.passkeys') as p`;
      assert.ok(p, 'still the old build');
    });
  });

  test('row 15: a file that does not match its fingerprint stops the run before the database is touched', async () => {
    const core2 = await import('../supabase/functions/dog-migrate/core.mjs');
    await assert.rejects(core2.load((p) => (p === 'db/migrations/003_posts.sql' ? local(p) + '\n-- edited' : local(p))), /003_posts: file does not match/);
    await assert.rejects(core2.load((p) => (p === 'db/reset/fresh-build.sql' ? 'drop schema app cascade;' : local(p))), /reset file does not match/);
  });

  test('row 15: the way back works: the Oct 23 build can be rebuilt exactly over the fresh build', async () => {
    await withDatabase(async (sql) => {
      await buildLive(sql);
      await core.run(sql, await freshBuild(), claims());
      const back = newList().find((x) => x[0] === '015_change_log');
      const rollback = await core.load((p) => (p === 'db/manifest.json'
        ? liveManifest({ reset: { file: 'db/reset/fresh-build.sql', sha256: JSON.parse(build()).reset.sha256, when: { version: back[0], sha256: back[1] } } })
        : p.startsWith('db/reset/') ? local(p) : fromLive(p)));
      const r = await core.run(sql, rollback, claims());
      assert.strictEqual(r.reset, true);
      await ledgerIs(sql, LIVE);
    });
  });
}
