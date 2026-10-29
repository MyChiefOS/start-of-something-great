// The production setup run (scripts/setup-production.js): keys are made once and never replaced, nothing secret is
// ever logged, and every step refuses bad input. It has no database step (R-14): the database changes only through
// the runner. Vercel is faked here; Postgres is real (for the admin step).
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
const masker = () => { const seen = []; const mask = (v) => seen.push(v); mask.seen = seen; return mask; };
const logger = () => { const lines = []; const log = (m) => lines.push(String(m)); log.lines = lines; return log; };
const leaked = (lines, values) => values.filter((v) => v && lines.some((l) => l.includes(v)));

test('steps run in a fixed order, and unknown steps are refused', () => {
  assert.deepStrictEqual(s.steps('redeploy, keys stage'), ['keys', 'stage', 'redeploy']);
  // R-14: the database step, which migrated outside the runner, is gone.
  assert.throws(() => s.steps('database,keys'), /unknown step\(s\): database/);
  assert.deepStrictEqual(s.steps(''), []);
  assert.throws(() => s.steps('keys,drop-everything'), /unknown step/);
});

test('keys: each is made only when missing; an existing key, FINGERPRINT_KEY_1 above all, is never replaced or logged', async () => {
  const v = fakeVercel({ FINGERPRINT_KEY_1: 'members-are-recognised-by-this' });
  const log = logger(); const mask = masker();
  const sets = [];
  const spy = { ...v, async set(k, val, o) { sets.push({ k, replace: o && o.replace }); return v.set(k, val, o); } };
  await s.stepKeys(spy, { log, mask });
  assert.ok(sets.length === 4 && sets.every((x) => x.replace === false), 'every key is created, never upserted: ' + JSON.stringify(sets));
  assert.strictEqual(v.env.get('FINGERPRINT_KEY_1').value, 'members-are-recognised-by-this');
  assert.strictEqual(mask.seen.length, 4, 'every made value was masked before use');
  for (const k of ['SESSION_SECRET', 'IP_HASH_KEY', 'CRON_SECRET']) assert.ok(mask.seen.includes(v.env.get(k).value), k + ' masked');
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

test('stage: unchanged leaves everything alone; closed or public only (preview is refused); the stage itself is not secret', async () => {
  const v = fakeVercel();
  const log = logger();
  await s.stepStage(v, { stage: 'unchanged', log });
  assert.strictEqual(v.env.size, 0, 'unchanged sets nothing');
  await assert.rejects(s.stepStage(v, { stage: 'live', log }), /unchanged, closed or public/);
  await assert.rejects(s.stepStage(v, { stage: 'preview', log }), /unchanged, closed or public/);
  assert.strictEqual(v.env.size, 0, 'nothing set after a refusal');
  await s.stepStage(v, { stage: 'closed', log });
  assert.deepStrictEqual(v.env.get('LAUNCH_STAGE'), { value: 'closed', type: 'plain' });
  assert.strictEqual(v.env.has('LAUNCH_PREVIEW_ALLOW'), false, 'no allow-list is ever set');
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
  const base = { SETUP_STEPS: 'keys,stage,redeploy', SETUP_STAGE: 'unchanged' };
  const lines = s.plan(base);
  assert.strictEqual(lines.length, 3);
  assert.match(lines[0], /never replaced/);
  assert.strictEqual(lines[1], 'stage: unchanged');
  assert.match(s.plan({ ...base, SETUP_STAGE: 'public' })[1], /go-live decision/);
  assert.match(s.plan({ ...base, SETUP_STAGE: 'closed' })[1], /CLOSED/);
  assert.throws(() => s.plan({ ...base, SETUP_STEPS: 'database' }), /unknown step/);
  assert.throws(() => s.plan({ ...base, SETUP_STAGE: 'preview' }), /unchanged, closed or public/);
  assert.throws(() => s.plan({ ...base, SETUP_STAGE: 'open' }), /unchanged, closed or public/);
  assert.throws(() => s.plan({ ...base, SETUP_STEPS: 'admin' }), /member_id/);
  assert.throws(() => s.plan({ SETUP_STEPS: '' }), /nothing to do/);
  assert.match(s.plan({ SETUP_STEPS: 'admin', SETUP_ADMIN_MEMBER_ID: '11111111-2222-3333-4444-555555555555' })[0], /^admin: make member 1111/);
});

test('masking: inside GitHub Actions every made value is reported to the runner as a mask; elsewhere nothing is written', () => {
  const was = process.env.GITHUB_ACTIONS; const out = [];
  const write = process.stdout.write; process.stdout.write = (c) => { out.push(String(c)); return true; };
  try {
    delete process.env.GITHUB_ACTIONS; s.maskInActions('quiet-value');
    assert.deepStrictEqual(out, []);
    process.env.GITHUB_ACTIONS = 'true'; s.maskInActions('loud-value'); s.maskInActions('');
    assert.deepStrictEqual(out, ['::add-mask::loud-value\n']);
  } finally { process.stdout.write = write; if (was === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = was; }
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
  const site = async (url) => { seen = url; return { status: 200, text: async () => '{"name":"Day One Great","stage":"closed"}' }; };
  assert.strictEqual(await s.verifyLive({ site: 'https://x.test', stage: 'closed', fetchImpl: site, tag: 'dpl_new' }), 'closed');
  assert.match(seen, /^https:\/\/x\.test\/api\/status\?after=dpl_new$/);
  await assert.rejects(s.verifyLive({ site: 'https://x.test', stage: 'public', fetchImpl: site }), /reports stage "closed", not "public"/);
  assert.strictEqual(await s.verifyLive({ site: 'https://x.test', stage: null, fetchImpl: site }), 'closed', 'with no stage set this run, any real answer passes');
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

test('main: keys, stage and a verified redeploy run in order against a fake Vercel, and the stage is checked live', async () => {
  const v = fakeVercel(); const log = logger(); const verified = [];
  await s.main({ SETUP_STEPS: 'redeploy,stage,keys', SETUP_STAGE: 'closed', VERCEL_TOKEN: 'x' },
    { vercel: v, log, github: { async setVariable() {} }, verifyLive: async (o) => { verified.push(o); return 'closed'; } });
  assert.strictEqual(v.env.size, 5, 'four keys and the stage');
  assert.strictEqual(v.redeploys, 1); assert.strictEqual(v.waited, 'dpl_test');
  assert.deepStrictEqual(verified.map((o) => [o.stage, o.tag]), [['closed', 'dpl_test']]);
  assert.deepStrictEqual(log.lines.filter((l) => l.startsWith('==')), ['== keys', '== stage', '== redeploy']);
  const v2 = fakeVercel(); const verified2 = [];
  await s.main({ SETUP_STEPS: 'redeploy', VERCEL_TOKEN: 'x' }, { vercel: v2, log, verifyLive: async (o) => { verified2.push(o.stage); return 'public'; } });
  assert.deepStrictEqual(verified2, [null], 'no stage set this run, so none is demanded of the site');
});

if (!SERVER) {
  if (process.env.CI) test('setup tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('setup against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_setup_test_' + crypto.randomBytes(4).toString('hex');
const at = (base, d) => { const u = new URL(base); u.pathname = '/' + d; return u.toString(); };
let server, su;

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 1, ssl: false, onnotice: () => {} });
  await migrate(su, { log: () => {} });
});
test.after(async () => {
  if (su) await su.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.end({ timeout: 5 });
  }
});

test('admin: sets exactly one active member as administrator, and refuses anything else', async () => {
  const log = logger();
  const id = crypto.randomUUID();
  await su`insert into app.members (id, display_name, trust_level) values (${id}, 'Aaron', 1)`;
  // 025: the administrator needs exactly one sign-in method, GitHub, the one the account began with.
  await assert.rejects(s.stepAdmin(su, { memberId: id, log }), /exactly one sign-in method, GitHub/, 'no sign-in method yet');
  await su`insert into app.identities (member_id, provider, fingerprint, key_version, level) values (${id}, 'github', ${'a'.repeat(64)}, 1, 1)`;
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
  await su`insert into app.identities (member_id, provider, fingerprint, key_version, level) values (${other}, 'github', ${'b'.repeat(64)}, 1, 1)`;
  await assert.rejects(s.stepAdmin(su, { memberId: other, log }), /another member is already the administrator/);
  assert.strictEqual((await su`select is_admin from app.members where id = ${other}`)[0].is_admin, false);
});

test('the setup workflow starts by hand only, on main only, names the production environment, with pinned actions and read-only rights', () => {
  const y = require('fs').readFileSync(require('path').join(__dirname, '..', '.github', 'workflows', 'setup.yml'), 'utf8');
  assert.match(y, /^on:\n  workflow_dispatch:/m, 'started by hand');
  // S6a: a plan job with no secrets and no environment runs first, writes the plan to the run's summary and refuses bad
  // input before any secret is read; the real job needs it. S6b: the stage input defaults to "unchanged".
  const [planJob, setupJob] = y.split(/^  setup:$/m);
  assert.ok(planJob && setupJob, 'two jobs, plan then setup');
  assert.match(planJob, /^  plan:$/m);
  assert.ok(!/secrets\./.test(planJob), 'the plan job sees no secret');
  assert.ok(!/^\s+environment:/m.test(planJob), 'and needs no approval');
  assert.match(planJob, /setup-production\.js --plan/);
  assert.match(planJob, /GITHUB_STEP_SUMMARY/);
  assert.match(setupJob, /^    needs: plan$/m);
  assert.match(y, /options: \[unchanged, closed, public\]\n        default: unchanged/);
  assert.ok(!/^\s*(push|pull_request|pull_request_target|schedule|workflow_run):/m.test(y), 'no other trigger');
  assert.match(y, /^\s+environment: production$/m, 'the production environment (it has no approval rule yet: RISKS.md RK71)');
  assert.doesNotMatch(y, /after Aaron approves|Approve the "setup" job|rotate_db_password|database,keys/, 'R-14: no claimed approval gate and no database step');
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

test('R-14: the setup run runs no raw SQL and never migrates (the database changes only through the runner)', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'scripts', 'setup-production.js'), 'utf8');
  assert.deepStrictEqual([...src.matchAll(/\.unsafe\(/g)], [], 'no raw SQL');
  assert.ok(!/require\('\.\/migrate'\)|DATABASE_URL'|create role|alter role/.test(src), 'no migration, no login role, no database address');
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
