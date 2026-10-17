// The production setup run (scripts/setup-production.js): keys are made once and never replaced, the database
// password reaches Postgres only as a hash yet really works, nothing secret is ever logged, and every step refuses
// bad input. Vercel is faked here; Postgres is real.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const s = require('../scripts/setup-production');
const { migrate } = require('../scripts/migrate');

const SERVER = process.env.TEST_DATABASE_URL;

// A stand-in for Vercel that remembers what was set and lets a test see every value, so it can check none leaked.
function fakeVercel(existing = {}) {
  const env = new Map(Object.entries(existing).map(([k, v]) => [k, { value: v, type: 'sensitive' }]));
  return {
    env, redeploys: 0,
    async productionNames() { return new Set(env.keys()); },
    async set(key, value, { sensitive = true } = {}) { env.set(key, { value, type: sensitive ? 'sensitive' : 'plain' }); },
    async redeploy() { this.redeploys++; return 'dpl_test'; }
  };
}
const logger = () => { const lines = []; const log = (m) => lines.push(String(m)); log.lines = lines; return log; };
const leaked = (lines, values) => values.filter((v) => v && lines.some((l) => l.includes(v)));

test('steps run in a fixed order, and unknown steps are refused', () => {
  assert.deepStrictEqual(s.steps('redeploy, keys database'), ['database', 'keys', 'redeploy']);
  assert.deepStrictEqual(s.steps(''), []);
  assert.throws(() => s.steps('keys,drop-everything'), /unknown step/);
});

test('the site’s database address is the transaction pooler on the same host, as dog_web.<project>', () => {
  const u = new URL(s.siteDatabaseUrl('postgresql://postgres.nksagchwpyljvjiwolmp:x@aws-0-us-east-1.pooler.supabase.com:5432/postgres', 'pw-Abc_123'));
  assert.strictEqual(u.hostname, 'aws-0-us-east-1.pooler.supabase.com');
  assert.strictEqual(u.port, '6543');
  assert.strictEqual(u.username, 'dog_web.nksagchwpyljvjiwolmp');
  assert.strictEqual(u.password, 'pw-Abc_123');
  assert.strictEqual(u.pathname, '/postgres');
  assert.throws(() => s.siteDatabaseUrl('postgresql://postgres:x@db.example.com:5432/postgres', 'p'), /session pooler/);
});

test('keys: each is made only when missing; an existing key, FINGERPRINT_KEY_1 above all, is never replaced or logged', async () => {
  const v = fakeVercel({ FINGERPRINT_KEY_1: 'members-are-recognised-by-this' });
  const log = logger();
  await s.stepKeys(v, { log });
  assert.strictEqual(v.env.get('FINGERPRINT_KEY_1').value, 'members-are-recognised-by-this');
  for (const k of ['SESSION_SECRET', 'IP_HASH_KEY', 'CRON_SECRET']) {
    const e = v.env.get(k);
    assert.ok(e, k + ' was set');
    assert.strictEqual(e.type, 'sensitive');
    assert.strictEqual(Buffer.from(e.value, 'base64').length, 32, k + ' is 32 random bytes');
  }
  assert.notStrictEqual(v.env.get('SESSION_SECRET').value, v.env.get('IP_HASH_KEY').value);
  assert.deepStrictEqual(leaked(log.lines, [...v.env.values()].map((e) => e.value)), [], 'no value was logged');
  const before = JSON.stringify([...v.env]);
  await s.stepKeys(v, { log });
  assert.strictEqual(JSON.stringify([...v.env]), before, 'a second run changes nothing');
});

test('stage: closed, preview or public only; the preview needs an allow-list; the stage itself is not secret', async () => {
  const v = fakeVercel();
  const log = logger();
  await assert.rejects(s.stepStage(v, { stage: 'live', log }), /closed, preview or public/);
  await assert.rejects(s.stepStage(v, { stage: 'preview', allow: 'github:aaronc', log }), /at least one entry/);
  assert.strictEqual(v.env.size, 0, 'nothing set after a refusal');
  await s.stepStage(v, { stage: 'preview', allow: 'github:12345', log });
  assert.deepStrictEqual(v.env.get('LAUNCH_STAGE'), { value: 'preview', type: 'plain' });
  assert.deepStrictEqual(v.env.get('LAUNCH_PREVIEW_ALLOW'), { value: 'github:12345', type: 'sensitive' });
  assert.deepStrictEqual(leaked(log.lines, ['github:12345']), [], 'the allow-list isn’t logged');
  await s.stepStage(v, { stage: 'public', log });
  assert.strictEqual(v.env.get('LAUNCH_STAGE').value, 'public');
});

test('the Vercel client sends to the right project and team, upserts for Production only, and never echoes a value', async () => {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, opts });
    if (url.includes('/v10/') && opts.method === 'GET') return { ok: true, status: 200, text: async () => JSON.stringify({ envs: [{ key: 'A', target: ['production'] }, { key: 'B', target: ['preview'] }] }) };
    if (url.includes('FAIL')) return { ok: false, status: 403, text: async () => JSON.stringify({ error: { code: 'forbidden', message: 'Not authorized' } }) };
    return { ok: true, status: 200, text: async () => '{}' };
  };
  const v = s.vercel('tok_test', { fetchImpl });
  assert.deepStrictEqual([...(await v.productionNames())], ['A'], 'only Production names count');
  await v.set('SESSION_SECRET', 'super-secret-value');
  const post = calls[1];
  assert.strictEqual(post.opts.method, 'POST');
  assert.match(post.url, /^https:\/\/api\.vercel\.com\/v10\/projects\/prj_cXnWySYVpJE9TVZaNPSocXMMzkZI\/env\?upsert=true&teamId=team_Hv5YS8LhIiKe06SSiDrUucd4$/);
  assert.deepStrictEqual(JSON.parse(post.opts.body), { key: 'SESSION_SECRET', value: 'super-secret-value', type: 'sensitive', target: ['production'] });
  assert.strictEqual(post.opts.headers.authorization, 'Bearer tok_test');
  const bad = s.vercel('tok_test', { fetchImpl, project: 'FAIL' });
  await assert.rejects(bad.set('X', 'another-secret'), (e) => /403/.test(e.message) && !e.message.includes('another-secret'));
  assert.throws(() => s.vercel(''), /VERCEL_TOKEN/);
});

if (!SERVER) {
  if (process.env.CI) test('setup tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('setup against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_setup_test_' + crypto.randomBytes(4).toString('hex');
const ROLE = NAME + '_web';
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
let server, su;
const POOLER = 'postgresql://postgres.nksagchwpyljvjiwolmp:x@aws-0-us-east-1.pooler.supabase.com:5432/postgres';

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 1, ssl: false, onnotice: () => {} });
});
test.after(async () => {
  if (su) await su.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${ROLE}`);
    await server.end({ timeout: 5 });
  }
});

// Does this password match the role's stored SCRAM hash? Checked from the hash itself, so it holds on any server,
// including one that trusts every local connection (as the CI database does).
async function hashMatches(password) {
  const [row] = await server`select rolpassword from pg_authid where rolname = ${ROLE}`;
  const m = String(row && row.rolpassword).match(/^SCRAM-SHA-256\$(\d+):([^$]+)\$([^:]+):(.+)$/);
  if (!m) return false;
  return s.scramVerifier(password, { salt: Buffer.from(m[2], 'base64'), iterations: Number(m[1]) }) === row.rolpassword;
}
// Does the server check passwords at all here? (A trusting server lets any password in.)
async function serverChecksPasswords() { return !(await signsIn('definitely-not-the-password-' + crypto.randomBytes(6).toString('hex'))); }
// Can the role really sign in with the password inside the address that went to Vercel?
async function signsIn(password) {
  const c = postgres(at(SERVER, NAME, ROLE, password), { max: 1, ssl: false, onnotice: () => {}, connect_timeout: 5 });
  try { const [r] = await c`select current_user as u`; return r.u === ROLE; } catch { return false; } finally { await c.end({ timeout: 5 }); }
}

test('database: migrations, the login role with a hashed password that really works, the address in Vercel, and a passing check', async () => {
  const v = fakeVercel();
  const log = logger();
  let checked = 0;
  const check = async (x) => { checked++; return require('../db/checks').problems(x, { snapshot: require('fs').readFileSync(require('path').join(__dirname, '..', 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#')) }); };
  await s.stepDatabase(su, v, { migrationUrl: POOLER, ca: 'CA-PEM', rotate: false, log, migrate, check, role: ROLE });
  assert.strictEqual(checked, 1);
  const addr = new URL(v.env.get('DATABASE_URL').value);
  assert.strictEqual(addr.port, '6543');
  assert.strictEqual(v.env.get('DATABASE_URL').type, 'sensitive');
  assert.strictEqual(v.env.get('DATABASE_CA').value, 'CA-PEM');
  const password = decodeURIComponent(addr.password);
  assert.ok(password.length >= 40);
  assert.strictEqual(await hashMatches(password), true, 'the stored hash is of exactly the password that went to Vercel');
  assert.strictEqual(await signsIn(password), true, 'and the role signs in with it');
  const checks = await serverChecksPasswords();
  const [{ granted }] = await su`select pg_has_role(${ROLE}, 'dog_app', 'member') as granted`;
  assert.strictEqual(granted, true, 'it acts as dog_app');
  assert.deepStrictEqual(leaked(log.lines, [password, v.env.get('DATABASE_URL').value]), [], 'neither the password nor the address was logged');

  // Run again: nothing changes, and the site's password keeps working.
  const v2 = fakeVercel();
  await s.stepDatabase(su, v2, { migrationUrl: POOLER, ca: 'CA-PEM', rotate: false, log, migrate, check, role: ROLE });
  assert.strictEqual(v2.env.size, 0, 'Vercel untouched on a re-run');
  assert.strictEqual(await hashMatches(password), true, 'the password is unchanged');

  // Rotation: a new password works, the old one stops.
  const v3 = fakeVercel();
  await s.stepDatabase(su, v3, { migrationUrl: POOLER, ca: 'CA-PEM', rotate: true, log, migrate, check, role: ROLE });
  const fresh = decodeURIComponent(new URL(v3.env.get('DATABASE_URL').value).password);
  assert.notStrictEqual(fresh, password);
  assert.strictEqual(await hashMatches(fresh), true, 'the new password is the one stored');
  assert.strictEqual(await hashMatches(password), false, 'the old password no longer matches');
  if (checks) assert.strictEqual(await signsIn(password), false, 'and, where the server checks passwords, it no longer signs in');
});

test('database: if Vercel refuses, the database password is left alone', async () => {
  const log = logger();
  const broken = { ...fakeVercel(), async set() { throw new Error('Vercel POST failed (403)'); } };
  const [{ before }] = await server`select rolpassword as before from pg_authid where rolname = ${ROLE}`.catch(() => [{ before: 'n/a' }]);
  await assert.rejects(s.stepDatabase(su, broken, { migrationUrl: POOLER, rotate: true, log, migrate, check: async () => [], role: ROLE }), /403/);
  const [{ after }] = await server`select rolpassword as after from pg_authid where rolname = ${ROLE}`.catch(() => [{ after: 'n/a' }]);
  assert.strictEqual(after, before);
});

test('admin: sets exactly one active member as administrator, and refuses anything else', async () => {
  const log = logger();
  const id = crypto.randomUUID();
  await su`insert into app.members (id, display_name, trust_level) values (${id}, 'Aaron', 1)`;
  await assert.rejects(s.stepAdmin(su, { memberId: 'not-an-id', log }), /member_id/);
  await assert.rejects(s.stepAdmin(su, { memberId: crypto.randomUUID(), log }), /no active member/);
  await s.stepAdmin(su, { memberId: id, log });
  const [{ is_admin }] = await su`select is_admin from app.members where id = ${id}`;
  assert.strictEqual(is_admin, true);
});

test('the setup workflow starts by hand only, on main only, in the protected environment, with pinned actions and read-only rights', () => {
  const y = require('fs').readFileSync(require('path').join(__dirname, '..', '.github', 'workflows', 'setup.yml'), 'utf8');
  assert.match(y, /^on:\n  workflow_dispatch:/m, 'started by hand');
  assert.ok(!/^\s*(push|pull_request|pull_request_target|schedule|workflow_run):/m.test(y), 'no other trigger');
  assert.match(y, /^\s+environment: production$/m, 'the protected environment, so Aaron approves each run');
  assert.match(y, /^\s+if: github\.ref == 'refs\/heads\/main'$/m, 'main only');
  assert.match(y, /^permissions:\n  contents: read$/m);
  for (const m of y.matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, 'pinned to a commit: ' + m[1]);
  assert.match(y, /persist-credentials: false/);
  assert.ok(!/echo .*\$\{\{\s*secrets\./.test(y), 'no secret is echoed');
});

test('the keys the setup run makes are exactly what sign-in needs to switch on', async () => {
  const v = fakeVercel();
  await s.stepKeys(v, { log: () => {} });
  const env = Object.fromEntries([...v.env].map(([k, e]) => [k, e.value]));
  const cfg = require('../signin/config').load(env);
  assert.strictEqual(cfg.ready, true);
  assert.strictEqual(cfg.fingerprintKeys.length, 1);
  assert.strictEqual(cfg.fingerprintKeys[0].version, 1);
});

test('the setup run’s raw SQL is exactly these statements, built only from fixed text, a checked role name and a hash', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'scripts', 'setup-production.js'), 'utf8');
  const calls = [...src.matchAll(/\.unsafe\(([^;]*)\);/g)].map((m) => m[1].trim());
  assert.deepStrictEqual(calls, [
    "'drop event trigger if exists ensure_rls'",
    "'drop function if exists public.rls_auto_enable()'",
    "'create role ' + role + ' login noinherit'",
    "'grant dog_app to ' + role",
    `'alter role ' + role + " password '" + scramVerifier(password) + "'"`
  ]);
  assert.match(src, /if \(!\/\^\[a-z_\]\[a-z0-9_\]\{0,62\}\$\/\.test\(role\)\) throw/, 'the role name is checked before use');
  assert.match(s.scramVerifier('x'), /^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/, 'the hash has no quote to break out of');
});
