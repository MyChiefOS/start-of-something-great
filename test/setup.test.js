// The production setup run (scripts/setup-production.js): it makes no password and no key (Oct 23, 2026: the site's
// database login and keys live in Supabase Vault, made by migration 017), never touches the site's login role, needs
// Vercel only for the steps that change Vercel, and every step refuses bad input. Vercel is faked here; Postgres is real.
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
    async set(key, value, { sensitive = true, replace = true } = {}) {
      if (!replace && env.has(key)) return { existed: true };
      env.set(key, { value, type: sensitive ? 'sensitive' : 'plain' });
      return { existed: false };
    },
    async redeploy() { this.redeploys++; return 'dpl_test'; },
    async waitReady(id) { this.waited = id; return { readyState: 'READY' }; }
  };
}
const logger = () => { const lines = []; const log = (m) => lines.push(String(m)); log.lines = lines; return log; };
const leaked = (lines, values) => values.filter((v) => v && lines.some((l) => l.includes(v)));

test('steps run in a fixed order, unknown steps are refused, and the removed keys step says why', () => {
  assert.deepStrictEqual(s.steps('redeploy, admin database'), ['database', 'admin', 'redeploy']);
  assert.deepStrictEqual(s.steps(''), []);
  assert.throws(() => s.steps('stage,drop-everything'), /unknown step/);
  assert.throws(() => s.steps('database,keys'), /step keys was removed: .*Supabase Vault/);
  assert.deepStrictEqual(s.ORDER, ['database', 'stage', 'admin', 'redeploy']);
});

test('the old path is gone: nothing in the setup run makes or changes a password or a key', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'scripts', 'setup-production.js'), 'utf8');
  const code = src.split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
  for (const gone of ['randomBytes', 'scramVerifier', 'alter role', 'create role', 'DATABASE_URL\'', 'SESSION_SECRET', 'FINGERPRINT_KEY', 'CRON_SECRET', 'ROTATE']) {
    assert.ok(!code.includes(gone), 'no ' + gone + ' in the setup run');
  }
  for (const name of ['stepKeys', 'scramVerifier', 'siteDatabaseUrl', 'maskInActions', 'KEYS']) assert.strictEqual(s[name], undefined, name + ' is not exported');
});

test('stage: unchanged leaves everything alone; closed, preview or public only; the preview needs an allow-list; the stage itself is not secret', async () => {
  const v = fakeVercel();
  const log = logger();
  await s.stepStage(v, { stage: 'unchanged', log });
  assert.strictEqual(v.env.size, 0, 'unchanged sets nothing');
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

test('the Vercel client sends to the right project and team, for Production only, and never echoes a value', async () => {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, opts });
    if (url.includes('/v10/') && opts.method === 'GET') return { ok: true, status: 200, text: async () => JSON.stringify({ envs: [{ key: 'A', target: ['production'] }, { key: 'B', target: ['preview'] }] }) };
    if (url.includes('FAIL')) return { ok: false, status: 403, text: async () => JSON.stringify({ error: { code: 'forbidden', message: 'Not authorized' } }) };
    const body = JSON.parse(opts.body || '{}');
    // Vercel refuses a plain create of a key that exists (400), and, with upsert, can answer 201 with a `failed` list.
    if (body.key === 'EXISTS' && !url.includes('upsert=true')) return { ok: false, status: 400, text: async () => JSON.stringify({ error: { code: 'ENV_ALREADY_EXISTS', message: 'already exists' } }) };
    if (body.key === 'EXISTS_LISTED' && !url.includes('upsert=true')) return { ok: true, status: 201, text: async () => JSON.stringify({ created: [], failed: [{ error: { code: 'ENV_ALREADY_EXISTS', message: 'already exists', key: 'EXISTS_LISTED' } }] }) };
    if (body.key === 'HALF') return { ok: true, status: 201, text: async () => JSON.stringify({ created: [], failed: [{ error: { code: 'ENV_CONFLICT', message: 'conflict', key: 'HALF' } }] }) };
    return { ok: true, status: 200, text: async () => '{}' };
  };
  const v = s.vercel('tok_test', { fetchImpl });
  assert.deepStrictEqual([...(await v.productionNames())], ['A'], 'only Production names count');
  assert.deepStrictEqual(await v.set('SESSION_SECRET', 'super-secret-value'), { existed: false });
  const post = calls[1];
  assert.strictEqual(post.opts.method, 'POST');
  assert.match(post.url, /^https:\/\/api\.vercel\.com\/v10\/projects\/prj_cXnWySYVpJE9TVZaNPSocXMMzkZI\/env\?upsert=true&teamId=team_Hv5YS8LhIiKe06SSiDrUucd4$/);
  assert.deepStrictEqual(JSON.parse(post.opts.body), { key: 'SESSION_SECRET', value: 'super-secret-value', type: 'sensitive', target: ['production'] });
  assert.strictEqual(post.opts.headers.authorization, 'Bearer tok_test');
  // S1: a create (replace: false) never upserts, and an existing key is reported, not replaced.
  assert.deepStrictEqual(await v.set('NEW_KEY', 'v1', { replace: false }), { existed: false });
  assert.match(calls[calls.length - 1].url, /\/env\?teamId=/, 'no upsert on a create');
  assert.deepStrictEqual(await v.set('EXISTS', 'v2', { replace: false }), { existed: true });
  assert.deepStrictEqual(await v.set('EXISTS_LISTED', 'v3', { replace: false }), { existed: true });
  // S2: a 201 whose `failed` list isn't empty is a failure, reported without the value.
  await assert.rejects(v.set('HALF', 'half-secret'), (e) => /did not set HALF: ENV_CONFLICT/.test(e.message) && !e.message.includes('half-secret'));
  const bad = s.vercel('tok_test', { fetchImpl, project: 'FAIL' });
  await assert.rejects(bad.set('X', 'another-secret'), (e) => /403/.test(e.message) && !e.message.includes('another-secret'));
  await assert.rejects(bad.set('X', 'another-secret', { replace: false }), /403/, 'only "already exists" is swallowed on a create');
  assert.throws(() => s.vercel(''), /VERCEL_TOKEN/);
});

test('plan: says what a run will do from its inputs alone, and refuses bad input before anyone approves', () => {
  const base = { SETUP_STEPS: 'database,stage,redeploy', SETUP_STAGE: 'unchanged' };
  const lines = s.plan(base);
  assert.strictEqual(lines.length, 3);
  assert.match(lines[0], /^database: .*no login, password or key is made or changed/);
  assert.strictEqual(lines[1], 'stage: unchanged');
  assert.match(lines[2], /^redeploy: /);
  assert.match(s.plan({ ...base, SETUP_STAGE: 'public' })[1], /go-live decision/);
  assert.match(s.plan({ ...base, SETUP_STAGE: 'preview', SETUP_PREVIEW_ALLOW: 'github:1, x:2' })[1], /PREVIEW.*2 allow-listed accounts/);
  assert.throws(() => s.plan({ ...base, SETUP_STEPS: 'keys' }), /was removed/);
  assert.throws(() => s.plan({ ...base, SETUP_STAGE: 'preview' }), /at least one entry/);
  assert.throws(() => s.plan({ ...base, SETUP_STAGE: 'open' }), /unchanged, closed, preview or public/);
  assert.throws(() => s.plan({ ...base, SETUP_STEPS: 'admin' }), /member_id/);
  assert.throws(() => s.plan({ SETUP_STEPS: '' }), /nothing to do/);
  assert.match(s.plan({ SETUP_STEPS: 'admin', SETUP_ADMIN_MEMBER_ID: '11111111-2222-3333-4444-555555555555' })[0], /^admin: make member 1111/);
});

test('redeploy: rebuilds what production serves now (so it works after a rollback), waits for it, and checks the live stage', async () => {
  const calls = [];
  const states = ['BUILDING', 'READY'];
  const fetchImpl = async (url, opts) => {
    calls.push(opts.method + ' ' + url.replace('https://api.vercel.com', '').replace(/[?&]teamId=[^&]*/, ''));
    if (/\/v9\/projects\//.test(url)) return { ok: true, status: 200, text: async () => JSON.stringify({ name: 'start-of-something-great', targets: { production: { id: 'dpl_rolledback', name: 'start-of-something-great' } } }) };
    if (/\/v13\/deployments\?/.test(url) && opts.method === 'POST') { assert.strictEqual(JSON.parse(opts.body).deploymentId, 'dpl_rolledback', 'the production target, not the newest build'); return { ok: true, status: 200, text: async () => '{"id":"dpl_new"}' }; }
    if (/\/v13\/deployments\/dpl_new/.test(url)) return { ok: true, status: 200, text: async () => JSON.stringify({ readyState: states.shift() || 'READY' }) };
    if (/\/v13\/deployments\/dpl_bad/.test(url)) return { ok: true, status: 200, text: async () => '{"readyState":"ERROR"}' };
    if (/\/v13\/deployments\/dpl_slow/.test(url)) return { ok: true, status: 200, text: async () => '{"readyState":"BUILDING"}' };
    return { ok: true, status: 200, text: async () => '{}' };
  };
  const v = s.vercel('tok_test', { fetchImpl });
  assert.strictEqual(await v.redeploy(), 'dpl_new');
  assert.ok(calls.some((c) => c.startsWith('GET /v9/projects/prj_')), 'asks the project what production serves');
  let slept = 0;
  const d = await v.waitReady('dpl_new', { sleep: async () => { slept++; }, everyMs: 1 });
  assert.strictEqual(d.readyState, 'READY'); assert.strictEqual(slept, 1, 'polled until ready');
  await assert.rejects(v.waitReady('dpl_bad', { sleep: async () => {} }), /the redeploy error/);
  await assert.rejects(v.waitReady('dpl_slow', { sleep: async () => {}, timeoutMs: -1 }), /still building/);
  // verifyLive: a unique address, a 200, and the stage this run set.
  let seen;
  const site = async (url) => { seen = url; return { status: 200, text: async () => '{"name":"Day One Great","stage":"preview"}' }; };
  assert.strictEqual(await s.verifyLive({ site: 'https://x.test', stage: 'preview', fetchImpl: site, tag: 'dpl_new' }), 'preview');
  assert.match(seen, /^https:\/\/x\.test\/api\/status\?after=dpl_new$/);
  await assert.rejects(s.verifyLive({ site: 'https://x.test', stage: 'public', fetchImpl: site }), /reports stage "preview", not "public"/);
  assert.strictEqual(await s.verifyLive({ site: 'https://x.test', stage: null, fetchImpl: site }), 'preview', 'with no stage set this run, any real answer passes');
  await assert.rejects(s.verifyLive({ site: 'https://x.test', fetchImpl: async () => ({ status: 503, text: async () => '' }) }), /answered 503/);
});

test('the stage step records EXPECTED_STAGE in GitHub (created if missing), and a failure there is said, not hidden', async () => {
  const calls = [];
  const ghFetch = (first404) => async (url, opts) => { calls.push(opts.method + ' ' + url); return { ok: !(first404 && opts.method === 'PATCH'), status: first404 && opts.method === 'PATCH' ? 404 : 200 }; };
  const gh = s.github('ghs_test', 'MyChiefOS/start-of-something-great', { fetchImpl: ghFetch(false) });
  await gh.setVariable('EXPECTED_STAGE', 'closed');
  assert.deepStrictEqual(calls, ['PATCH https://api.github.com/repos/MyChiefOS/start-of-something-great/actions/variables/EXPECTED_STAGE']);
  calls.length = 0;
  await s.github('ghs_test', 'MyChiefOS/start-of-something-great', { fetchImpl: ghFetch(true) }).setVariable('EXPECTED_STAGE', 'closed');
  assert.deepStrictEqual(calls.map((c) => c.split(' ')[0]), ['PATCH', 'POST'], 'created when it does not exist yet');
  const v = fakeVercel(); const log = logger();
  const recorded = [];
  await s.stepStage(v, { stage: 'closed', log, gh: { async setVariable(n, val) { recorded.push(n + '=' + val); } } });
  assert.deepStrictEqual(recorded, ['EXPECTED_STAGE=closed']);
  await s.stepStage(v, { stage: 'public', log, gh: { async setVariable() { throw new Error('403'); } } });
  assert.strictEqual(v.env.get('LAUNCH_STAGE').value, 'public', 'the stage itself was still set');
  assert.ok(log.lines.some((l) => /EXPECTED_STAGE: could not be recorded .*by hand/.test(l)), 'and the run says what to do');
  const y = require('fs').readFileSync(require('path').join(__dirname, '..', '.github', 'workflows', 'setup.yml'), 'utf8');
  assert.match(y, /actions: write/, 'the setup job may write the variable');
  assert.match(y, /GITHUB_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}/);
});

test('main: the close-the-site run (stage, then a verified redeploy) runs in order against a fake Vercel, and the stage is checked live', async () => {
  const v = fakeVercel(); const log = logger(); const verified = [];
  await s.main({ SETUP_STEPS: 'redeploy,stage', SETUP_STAGE: 'closed', VERCEL_TOKEN: 'x' },
    { vercel: v, log, github: { async setVariable() {} }, verifyLive: async (o) => { verified.push(o); return 'closed'; } });
  assert.deepStrictEqual([...v.env.keys()], ['LAUNCH_STAGE'], 'only the stage');
  assert.strictEqual(v.redeploys, 1); assert.strictEqual(v.waited, 'dpl_test');
  assert.deepStrictEqual(verified.map((o) => [o.stage, o.tag]), [['closed', 'dpl_test']]);
  assert.deepStrictEqual(log.lines.filter((l) => l.startsWith('==')), ['== stage', '== redeploy']);
  const v2 = fakeVercel(); const verified2 = [];
  await s.main({ SETUP_STEPS: 'redeploy', VERCEL_TOKEN: 'x' }, { vercel: v2, log, verifyLive: async (o) => { verified2.push(o.stage); return 'public'; } });
  assert.deepStrictEqual(verified2, [null], 'no stage set this run, so none is demanded of the site');
  await assert.rejects(s.main({ SETUP_STEPS: 'stage', SETUP_STAGE: 'closed' }, { log }), /VERCEL_TOKEN/, 'stage still needs Vercel');
});

test('main: the database step alone needs no Vercel token and touches no Vercel setting', async () => {
  const log = logger(); const statements = [];
  const fakeSql = Object.assign(async () => [{ exists: true }], { unsafe: async (q) => { statements.push(q); } });
  await s.main({ SETUP_STEPS: 'database' }, { sql: fakeSql, log, migrate: async () => [], check: async () => [] });
  assert.deepStrictEqual(statements, ['drop event trigger if exists ensure_rls', 'drop function if exists public.rls_auto_enable()']);
  assert.ok(log.lines.some((l) => /dog_web: exists; this run never changes its password/.test(l)));
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

const passwordHash = async () => ((await server`select rolpassword from pg_authid where rolname = ${ROLE}`)[0] || {}).rolpassword;

test('database: migrations and a passing check; the login role is reported, never made, and its password never changes', async () => {
  const log = logger();
  let checked = 0;
  const check = async (x) => { checked++; return require('../db/checks').problems(x, { snapshot: require('fs').readFileSync(require('path').join(__dirname, '..', 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#')) }); };
  await s.stepDatabase(su, { log, migrate, check, role: ROLE });
  assert.strictEqual(checked, 1);
  const [{ made }] = await server`select exists (select 1 from pg_roles where rolname = ${ROLE}) as made`;
  assert.strictEqual(made, false, 'a missing login role is not created');
  assert.ok(log.lines.some((l) => l.includes(ROLE + ': missing') && /makes no logins or passwords/.test(l)), 'it is reported instead');

  // With the role there (as migration 017 makes it on Supabase), a run leaves its password exactly as it was.
  await server.unsafe('create role ' + ROLE + " login noinherit password 'made-elsewhere-1'");
  const before = await passwordHash();
  assert.ok(before, 'the role has a password');
  await s.stepDatabase(su, { log, migrate, check, role: ROLE });
  assert.strictEqual(await passwordHash(), before, 'the password is unchanged');
  assert.ok(log.lines.some((l) => l.includes(ROLE + ': exists; this run never changes its password')));
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
  // S8: the change left an audit row, written as the system; running it again changes nothing; a second
  // administrator is refused.
  const rows = await su`select actor_kind, actor_id, action, subject_id, detail from app.audit_log where action = 'admin.set'`;
  assert.strictEqual(rows.length, 1);
  assert.deepStrictEqual({ ...rows[0] }, { actor_kind: 'system', actor_id: null, action: 'admin.set', subject_id: id, detail: { by: 'production setup run' } });
  await s.stepAdmin(su, { memberId: id, log });
  assert.ok(log.lines.some((l) => /already this member/.test(l)));
  assert.strictEqual((await su`select count(*)::int as n from app.audit_log where action = 'admin.set'`)[0].n, 1, 'no second row for a no-op');
  const other = crypto.randomUUID();
  await su`insert into app.members (id, display_name, trust_level) values (${other}, 'Grace', 1)`;
  await assert.rejects(s.stepAdmin(su, { memberId: other, log }), /another member is already the administrator/);
  assert.strictEqual((await su`select is_admin from app.members where id = ${other}`)[0].is_admin, false);
});

test('the setup workflow starts by hand only, on main only, in the protected environment, with pinned actions and read-only rights', () => {
  const y = require('fs').readFileSync(require('path').join(__dirname, '..', '.github', 'workflows', 'setup.yml'), 'utf8');
  assert.match(y, /^on:\n  workflow_dispatch:/m, 'started by hand');
  // S6a: a plan job with no secrets and no environment runs first and writes the plan to the run's summary; the real
  // job needs it, so Aaron reads the plan before approving. S6b: the stage input defaults to "unchanged".
  const [planJob, setupJob] = y.split(/^  setup:$/m);
  assert.ok(planJob && setupJob, 'two jobs, plan then setup');
  assert.match(planJob, /^  plan:$/m);
  assert.ok(!/secrets\./.test(planJob), 'the plan job sees no secret');
  assert.ok(!/^\s+environment:/m.test(planJob), 'and needs no approval');
  assert.match(planJob, /setup-production\.js --plan/);
  assert.match(planJob, /GITHUB_STEP_SUMMARY/);
  assert.match(setupJob, /^    needs: plan$/m);
  assert.match(y, /options: \[unchanged, closed, preview, public\]\n        default: unchanged/);
  assert.ok(!/^\s*(push|pull_request|pull_request_target|schedule|workflow_run):/m.test(y), 'no other trigger');
  assert.match(y, /^\s+environment: production$/m, 'the protected environment, so Aaron approves each run');
  assert.match(y, /^\s+if: github\.ref == 'refs\/heads\/main'$/m, 'main only');
  assert.match(y, /^permissions:\n  contents: read$/m);
  for (const m of y.matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, 'pinned to a commit: ' + m[1]);
  assert.match(y, /persist-credentials: false/);
  assert.ok(!/echo .*\$\{\{\s*secrets\./.test(y), 'no secret is echoed');
  assert.ok(!/rotate_db_password|ROTATE/.test(y), 'no option to make a new database password');
  assert.match(y, /default: 'stage,redeploy'/, 'the default run makes nothing');
  assert.ok(!/\bkeys\b/.test(y.split('\n').filter((l) => !l.startsWith('#')).join('\n')), 'no keys step');
});

test('the setup run’s raw SQL is exactly these two fixed statements', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'scripts', 'setup-production.js'), 'utf8');
  const calls = [...src.matchAll(/\.unsafe\(([^;]*)\);/g)].map((m) => m[1].trim());
  assert.deepStrictEqual(calls, [
    "'drop event trigger if exists ensure_rls'",
    "'drop function if exists public.rls_auto_enable()'"
  ]);
});

test('the Supabase root certificate is in the repository, so no one copies it into a secret; a secret still overrides it', () => {
  const crypto = require('crypto');
  const pem = require('fs').readFileSync(s.SUPABASE_CA_FILE, 'utf8');
  const cert = new crypto.X509Certificate(pem);
  assert.match(cert.subject, /CN=Supabase Root 2021 CA/);
  assert.ok(new Date(cert.validTo) > new Date('2030-01-01'), 'valid for years yet');
  assert.ok(cert.ca, 'a certificate authority, not a server certificate');
  assert.strictEqual(s.databaseCa({}), pem);
  assert.strictEqual(s.databaseCa({ MIGRATION_DATABASE_CA: '  ' }), pem, 'an empty secret falls back to the file');
  assert.strictEqual(s.databaseCa({ MIGRATION_DATABASE_CA: 'override' }), 'override');
  assert.ok(!/BEGIN (RSA |EC )?PRIVATE KEY/.test(pem), 'only a public certificate');
});
