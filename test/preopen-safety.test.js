// Pre-opening safety (Aaron, Oct 29: "Lets finish so we can open the site"; harness/REVIEW-2026-10-26.md, the CSO's
// route B controls 2, 3, 4, 6 and 7, and R-8, R-9 and R-10). Each test fails without its fix:
//   * the timer slot (027): timers with no secret, at most once every 50 seconds, a failed run gives its slot back
//     and alerts, the site can't act as the site itself any other way, and /api/cron replies only {ok:true};
//   * the close switch: launch-cap.json (the stricter of it and LAUNCH_STAGE wins) and db/emergency/close-site-login.sql,
//     applied to a throwaway database, refusing the site's login, and reopen-site-login.sql undoing it;
//   * broker alerts: the broker counts hand-outs and failures, and the timers alert on an unusual hour and on failures;
//   * a refused password: the broker is asked again and the request retried once;
//   * the heartbeat (/api/ready and the uptime monitor) and the 90-day check on each agent post.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const delegation = require('../db/delegation');
const notices = require('../db/notify');
const posts = require('../db/posts');
const agentsDb = require('../db/agents');
const launch = require('../launch');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { promote } = require('./helpers');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}

// ---- The close switch, in code (no database) ----
test('R-10: launch-cap.json caps the stage, the stricter of it and LAUNCH_STAGE winning; this PR leaves it with no effect', () => {
  const pub = { LAUNCH_STAGE: 'public' };
  assert.strictEqual(launch.stage(pub, { max_stage: 'public' }), 'public', 'public cap: no effect');
  assert.strictEqual(launch.stage(pub, { max_stage: 'closed' }), 'closed', 'a closed cap closes an open site');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'closed' }, { max_stage: 'public' }), 'closed', 'the cap never opens a closed site');
  assert.strictEqual(launch.stage({}, { max_stage: 'public' }), 'closed');
  assert.strictEqual(launch.stage(pub, null), 'public', 'no file: no effect');
  for (const bad of [{ max_stage: 'preview' }, { max_stage: 'open' }, { max_stage: '' }, {}]) {
    assert.strictEqual(launch.stage(pub, bad), 'closed', 'a value that is not a stage counts as closed: ' + JSON.stringify(bad));
  }
  const file = JSON.parse(fs.readFileSync(path.join(root, 'launch-cap.json'), 'utf8'));
  assert.ok(launch.STAGES.includes(file.max_stage), 'the committed cap is a real stage');
  assert.strictEqual(file.max_stage, 'public', 'this PR closes and opens nothing: the cap has no effect');
  assert.strictEqual(launch.cap(), 'public');
  // launch.js reads the file with a plain require, so Vercel bundles it with every function that reads the stage.
  assert.match(fs.readFileSync(path.join(root, 'launch.js'), 'utf8'), /require\('\.\/launch-cap\.json'\)/);
});

test('R-10: nothing in db/migrations closes or opens the site login; the emergency files live outside it', () => {
  for (const f of fs.readdirSync(path.join(root, 'db', 'migrations'))) {
    assert.doesNotMatch(fs.readFileSync(path.join(root, 'db', 'migrations', f), 'utf8'), /alter role dog_web (no)?login\b/i, f);
  }
  const close = fs.readFileSync(path.join(root, 'db', 'emergency', 'close-site-login.sql'), 'utf8');
  assert.match(close, /alter role dog_web nologin/);
  assert.match(fs.readFileSync(path.join(root, 'db', 'emergency', 'reopen-site-login.sql'), 'utf8'), /alter role dog_web login/);
  const ops = fs.readFileSync(path.join(root, 'OPERATIONS.md'), 'utf8');
  assert.match(ops, /db\/emergency\/close-site-login\.sql/, 'the steps to use it are in OPERATIONS.md');
  assert.match(ops, /launch-cap\.json/);
});

// ---- The timer route (no database) ----
test('control 6: /api/cron needs no secret, replies only {ok:true}, skips the database within 25 seconds, and passes the user-agent as evidence only', async () => {
  const cron = require('../api/cron.js');
  cron._reset();
  let clock = 1_000_000;
  const seen = [];
  const run = async (ctx, fn) => {
    assert.deepStrictEqual(ctx, { actor: 'anon' }, 'the site asks as an anonymous visitor, with no proof');
    return fn({});
  };
  const notifyStore = require('../db/notify');
  const real = notifyStore.timerSlot;
  notifyStore.timerSlot = async (t, fromCron) => { seen.push(fromCron); return { ran: true, failed: false }; };
  try {
    const call = async (headers, r = run) => { const out = res(); await cron.handle({ method: 'GET', headers }, out, r, { now: () => clock }); return out; };
    let out = await call({ 'user-agent': 'vercel-cron/1.0' });
    assert.strictEqual(out.statusCode, 200);
    assert.strictEqual(out.body, '{"ok":true}', 'only {ok:true}, no counts');
    clock += 24_000;
    out = await call({});
    assert.strictEqual(out.body, '{"ok":true}');
    assert.deepStrictEqual(seen, [true], 'under 25 seconds: the database is not asked');
    clock += 2_000;
    await call({ 'user-agent': 'curl/8' });
    assert.deepStrictEqual(seen, [true, false], 'the user-agent is passed as evidence, and decides nothing');
    clock += 30_000;
    notifyStore.timerSlot = async () => ({ ran: false, failed: true });
    out = await call({});
    assert.deepStrictEqual([out.statusCode, out.body], [500, '{"ok":false}'], 'a failed run says only that');
    clock += 30_000;
    out = await call({}, async () => { throw new Error('connection refused at 10.0.0.1'); });
    assert.deepStrictEqual([out.statusCode, out.body], [500, '{"ok":false}'], 'no error text');
    out = await call({}, null);
    assert.deepStrictEqual([out.statusCode, out.body], [503, '{"ok":false}'], 'closed: no database');
    out = res();
    await cron.handle({ method: 'POST', headers: {} }, out, run);
    assert.strictEqual(out.statusCode, 405);
  } finally {
    notifyStore.timerSlot = real;
    cron._reset();
  }
  const src = fs.readFileSync(path.join(root, 'api', 'cron.js'), 'utf8');
  assert.doesNotMatch(src, /authorization|cronOk|process\.env\.CRON_SECRET/i, 'no secret is read by the timer route');
  assert.doesNotMatch(fs.readFileSync(path.join(root, 'notify', 'config.js'), 'utf8'), /cronOk|cronSecret/, 'the old check is gone');
});

// ---- A refused password (no database for the broker; a real Postgres refusal when one is set) ----
test('controls 2 and 4: after a refused password, sitekeys asks the broker again at once; only while open, with a recent token', async () => {
  const sitekeys = require('../db/sitekeys');
  sitekeys._reset();
  const body = (pw) => ({ ok: true, database: { user: 'dog_web.ref', password: pw, hosts: ['aws-0-us-east-1.pooler.supabase.com'], port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: 's'.repeat(44), IP_HASH_KEY: 'i'.repeat(44), FINGERPRINT_KEY_1: 'f'.repeat(44) } });
  let pw = 'first-password-0123456789abcdef0123';
  let asks = 0;
  const fetchImpl = async () => { asks++; return { status: 200, json: async () => body(pw) }; };
  const env = { LAUNCH_STAGE: 'public' };
  const open = () => 'public';
  const req = () => ({ headers: { 'x-vercel-oidc-token': 'a'.repeat(40) } });
  try {
    assert.strictEqual(await sitekeys.refetch({ fetchImpl, env, stage: open }), false, 'nothing applied yet: nothing to refetch');
    assert.strictEqual((await sitekeys.ensure(req(), { fetchImpl, env, stage: open })).source, 'broker');
    assert.match(env.DATABASE_URL, /first-password/);
    assert.strictEqual(asks, 1);
    pw = 'second-password-0123456789abcdef012';
    // Within the 10-minute cache ensure() wouldn't ask; refetch() does, at once.
    assert.strictEqual((await sitekeys.ensure(req(), { fetchImpl, env, stage: open })).source, 'broker');
    assert.strictEqual(asks, 1);
    const [a, b] = await Promise.all([sitekeys.refetch({ fetchImpl, env, stage: open }), sitekeys.refetch({ fetchImpl, env, stage: open })]);
    assert.ok(a && b);
    assert.strictEqual(asks, 2, 'concurrent refusals share one ask');
    assert.match(env.DATABASE_URL, /second-password/, 'the new password is in place');
    assert.strictEqual(await sitekeys.refetch({ fetchImpl, env, stage: () => 'closed' }), false, 'never while closed');
    const failing = async () => ({ status: 500, json: async () => ({ ok: false }) });
    assert.strictEqual(await sitekeys.refetch({ fetchImpl: failing, env, stage: open }), false, 'a failed broker: false, and the last good keys stay');
    assert.match(env.DATABASE_URL, /second-password/);
    sitekeys._reset();
    const vercel = { LAUNCH_STAGE: 'public', DATABASE_URL: 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres' };
    assert.strictEqual((await sitekeys.ensure(req(), { fetchImpl, env: vercel, stage: open })).source, 'vercel');
    assert.strictEqual(await sitekeys.refetch({ fetchImpl, env: vercel, stage: open }), false, "Vercel's settings: the broker isn't asked");
  } finally {
    sitekeys._reset();
  }
  assert.ok(db.passwordRefused({ code: '28P01' }) && db.passwordRefused(new Error('password authentication failed for user "dog_web"')));
  assert.ok(!db.passwordRefused({ code: '57014' }) && !db.passwordRefused(null));
});

test('controls 2 and 4 (the CSO\'s review, S3 and N1): refetch cools down for 30 seconds after one that gave the same address, and uses only a token the broker accepted', async () => {
  const sitekeys = require('../db/sitekeys');
  sitekeys._reset();
  const body = (pw) => ({ ok: true, database: { user: 'dog_web.ref', password: pw, hosts: ['aws-0-us-east-1.pooler.supabase.com'], port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: 's'.repeat(44), IP_HASH_KEY: 'i'.repeat(44), FINGERPRINT_KEY_1: 'f'.repeat(44) } });
  const pw = 'only-password-0123456789abcdef0123';
  const used = [];
  const fetchImpl = async (url, init) => { used.push(init.headers.authorization); return { status: 200, json: async () => body(pw) }; };
  const env = { LAUNCH_STAGE: 'public' };
  const open = () => 'public';
  let clock = 5_000_000;
  const now = () => clock;
  try {
    await sitekeys.ensure({ headers: { 'x-vercel-oidc-token': 'accepted-' + 'a'.repeat(40) } }, { fetchImpl, env, stage: open });
    // N1: a later request's token, never checked by the broker (the answer came from the 10-minute cache), isn't kept.
    await sitekeys.ensure({ headers: { 'x-vercel-oidc-token': 'unchecked-' + 'b'.repeat(40) } }, { fetchImpl, env, stage: open });
    assert.strictEqual(used.length, 1);
    used.length = 0;
    // S3: 30 refused requests in a row ask the broker once; it gives the same address, so the rest wait 30 seconds.
    for (let i = 0; i < 30; i++) { await sitekeys.refetch({ fetchImpl, env, stage: open, now }); clock += 500; }
    assert.strictEqual(used.length, 1, '30 refusals, one ask');
    assert.strictEqual(used[0], 'Bearer accepted-' + 'a'.repeat(40), 'the token the broker accepted (N1)');
    clock += 30_000;
    assert.strictEqual(await sitekeys.refetch({ fetchImpl, env, stage: open, now }), true, 'after 30 seconds it may ask again');
    assert.strictEqual(used.length, 2);
  } finally {
    sitekeys._reset();
  }
});

test('controls 2 and 4: db.run retries a refused password once on the new address, and nothing else', async () => {
  const env = { DATABASE_URL: 'old' };
  let tries = 0;
  const refused = Object.assign(new Error('password authentication failed for user "dog_web"'), { code: '28P01' });
  const attempt = async () => { tries++; if (env.DATABASE_URL === 'old') throw refused; return 'ok'; };
  assert.strictEqual(await db.retryRefused(attempt, { env, refetch: async () => { env.DATABASE_URL = 'new'; return true; } }), 'ok');
  assert.strictEqual(tries, 2, 'retried once');
  env.DATABASE_URL = 'old'; tries = 0;
  await assert.rejects(db.retryRefused(attempt, { env, refetch: async () => true }), /password authentication failed/, 'the same password back: no retry');
  assert.strictEqual(tries, 1);
  tries = 0;
  await assert.rejects(db.retryRefused(attempt, { env, refetch: async () => false }), /password authentication failed/);
  let asked = false;
  await assert.rejects(db.retryRefused(async () => { throw Object.assign(new Error('timeout'), { code: '57014' }); }, { env, refetch: async () => { asked = true; return true; } }), /timeout/);
  assert.ok(!asked, 'other errors never ask the broker');
  // Another request already put the new password in place: retried without asking.
  env.DATABASE_URL = 'old'; tries = 0; asked = false;
  const racing = async () => { tries++; if (tries === 1) { env.DATABASE_URL = 'new'; throw refused; } return 'ok'; };
  assert.strictEqual(await db.retryRefused(racing, { env, refetch: async () => { asked = true; return false; } }), 'ok');
  assert.ok(!asked);
});

// ---- The broker's counts, in its code ----
test('control 3: the broker counts each hand-out and each failure, never a refused token, and the count never changes the answer', async () => {
  const core = await import('../supabase/functions/dog-keys/core.mjs');
  class Refused extends Error {}
  const good = { dog_web_password: 'p'.repeat(40), dog_session_secret: 's'.repeat(40), dog_ip_hash_key: 'i'.repeat(40), dog_fingerprint_key_1: 'f'.repeat(40) };
  const noted = [];
  const deps = (over) => ({ verify: async () => {}, Refused, values: async () => good, note: async (o) => { noted.push(o); }, ...over });
  assert.strictEqual((await core.handle({ method: 'POST', token: 't' }, deps())).status, 200);
  assert.strictEqual((await core.handle({ method: 'POST', token: 't' }, deps({ values: async () => ({}) }))).status, 503);
  await assert.rejects(core.handle({ method: 'POST', token: 't' }, deps({ values: async () => { throw new Error('read failed'); } })), /read failed/);
  assert.strictEqual((await core.handle({ method: 'POST', token: 't' }, deps({ verify: async () => { throw new Refused('not ours'); } }))).status, 401);
  assert.strictEqual((await core.handle({ method: 'GET', token: 't' }, deps())).status, 405);
  assert.deepStrictEqual(noted, ['handed', 'failed', 'failed'], 'refusals and wrong methods are not counted');
  const out = await core.handle({ method: 'POST', token: 't' }, deps({ note: async () => { throw new Error('no table yet'); } }));
  assert.strictEqual(out.status, 200, 'a failed count leaves the answer alone');
  const ix = fs.readFileSync(path.join(root, 'supabase', 'functions', 'dog-keys', 'index.ts'), 'utf8');
  assert.match(ix, /select app\.broker_note\(\$\{outcome\}\)/, 'the deployed function counts through app.broker_note');
});

// ---- The heartbeat in the uptime monitor and /api/ready (no database) ----
test('R-9: the uptime monitor checks the heartbeat and the broker only while the site is open, and /api/ready reports them', async () => {
  const uptime = require('../scripts/uptime');
  const beat = uptime.CHECKS.find((x) => x.name === 'Timers heartbeat');
  const broker = uptime.CHECKS.find((x) => x.name === 'Key broker');
  assert.ok(beat && broker && beat.path === '/api/ready');
  const r = (json) => [{ status: 200 }, JSON.stringify(json)];
  assert.ok(!beat.when({ stage: 'closed' }) && beat.when({ stage: 'public' }) && !broker.when({ stage: 'closed' }));
  assert.ok(beat.test(...r({ timers: { last_run_s_ago: 70 } })));
  assert.ok(!beat.test(...r({ timers: { last_run_s_ago: uptime.HEARTBEAT_S + 1 } })), 'over 15 minutes: the issue opens');
  for (const t of ['never', 'unreadable', 'closed', null]) assert.ok(!beat.test(...r({ timers: t })), String(t));
  assert.ok(broker.test(...r({ broker: 'ok' })) && broker.test(...r({ broker: 'not_used' })));
  for (const b of ['stale', 'no_token', 'broker 500']) assert.ok(!broker.test(...r({ broker: b })), b);
  // While closed, /api/ready isn't fetched for these (it would ask the broker).
  const asked = [];
  const fetchImpl = async (url) => { asked.push(url); return { status: 200, headers: { get: () => '' }, text: async () => '{}' }; };
  const out = await uptime.checkAll(fetchImpl, async () => {});
  assert.ok(!asked.some((u) => u.endsWith('/api/ready')));
  assert.deepStrictEqual(out.filter((x) => ['Timers heartbeat', 'Key broker'].includes(x.name)).map((x) => [x.ok, x.status]), [[true, 'not asked'], [true, 'not asked']]);
  const ready = require('../api/ready.js');
  ready._reset();
  const body = await ready.check({ headers: {} }, { env: {}, timersAge: async () => { throw new Error('must not be asked while closed'); } });
  assert.deepStrictEqual([body.timers, body.stage, body.stage_cap], ['closed', 'closed', 'public']);
  const open = { LAUNCH_STAGE: 'public', DATABASE_URL: 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres' };
  const connect = () => { const f = async () => [{ one: 1 }]; f.end = async () => {}; return f; };
  for (const [age, want] of [[42, { last_run_s_ago: 42 }], [null, 'never']]) {
    ready._reset();
    assert.deepStrictEqual((await ready.check({ headers: {} }, { env: open, connect, timersAge: async () => age })).timers, want);
  }
  ready._reset();
  assert.strictEqual((await ready.check({ headers: {} }, { env: open, connect, timersAge: async () => { throw new Error('x'); } })).timers, 'unreadable');
  ready._reset();
});

// ---- Against a real Postgres ----
if (!SERVER) {
  if (process.env.CI) test('pre-opening safety tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('pre-opening safety against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_preopen_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const ANON = { actor: 'anon' };
const slot = (fromCron = true) => run(ANON, (t) => notices.timerSlot(t, fromCron));
async function asOwner(sql) { await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); }); }
const backdateSlot = () => asOwner("update app.timer_slot set last_at = now() - interval '51 seconds'");
const alerts = (prefix) => q(`select title, body, dedupe_key from app.notices where member_id is null and dedupe_key like '${prefix}%'`);
const QUIET_WATCH = 'update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000';

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  await asOwner(QUIET_WATCH);
  // No timer secret anywhere: the site holds none, and the database keeps no hash of one (route B).
  delete process.env.CRON_SECRET;
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(name) {
  const token = c.token(32);
  const out = await run(ANON, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}

// An agent's key made by its owner, as the site makes one (portable: no superuser needed, so it runs on Supabase's
// image too; the CSO's review of 027, S4).
async function ownerKey(owner, agentId) {
  const keyHash = c.sha256hex('key ' + crypto.randomUUID());
  await run(owner.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${agentId}, ${keyHash})`);
  return { actor: 'agent', memberId: owner.id, agentId, keyHash };
}

test('R-9: the heartbeat is empty before the timers first run (read by the site as anyone)', async () => {
  assert.strictEqual(await run(ANON, (t) => notices.timersAge(t)), null);
});

test('control 6: the timers run with no secret, at most once every 50 seconds, and the caller never keeps the site\'s own powers', async () => {
  const [k] = await q('select count(*)::int as n from app.actor_keys where system_hash is not null');
  assert.strictEqual(k.n, 0, 'no timer secret is stored');
  await assert.rejects(run({ actor: 'system' }, (t) => t`select 1`), /not_acting/, 'the site can\'t act as itself directly');
  const first = await run(ANON, async (t) => {
    const out = await notices.timerSlot(t, true);
    const [who] = await t`select app.actor_kind() as kind`;
    return { out, kind: who.kind };
  });
  assert.deepStrictEqual(first, { out: { ran: true, failed: false }, kind: 'anon' }, 'ran, and the caller is anonymous again afterwards');
  assert.deepStrictEqual(await slot(), { ran: false, why: 'early', failed: false }, 'a second call within 50 seconds does nothing');
  await q("update app.timer_slot set last_at = now() - interval '49 seconds'");
  assert.deepStrictEqual(await slot(), { ran: false, why: 'early', failed: false }, '49 seconds: still too early');
  await backdateSlot();
  assert.deepStrictEqual(await slot(), { ran: true, failed: false });
  const age = await run(ANON, (t) => notices.timersAge(t));
  assert.ok(age !== null && age >= 0 && age < 60, 'the heartbeat moved: ' + age);
  // The interval is fixed: the function takes no interval, and the site can't move the slot or read more than the time.
  const [fn] = await q("select pg_get_function_arguments('app.timers_run(boolean)'::regprocedure) as args");
  assert.strictEqual(fn.args, 'p_from_cron boolean');
  await assert.rejects(run(ANON, (t) => t`update app.timer_slot set last_at = null`), /permission denied/);
  await assert.rejects(run(ANON, (t) => t`select last_at from app.timer_slot`), /permission denied/);
  await assert.rejects(run(ANON, (t) => t`select app.run_timers()`), /only the site's own timers/);
  await assert.rejects(run(ANON, (t) => t`select app.actor_stamp('system', '', '', '', '')`), /permission denied/);
  await assert.rejects(run(ANON, (t) => t`set local role dog_timers`), /permission denied/);
  // A signed-in caller gets its own settings back, unchanged.
  const m = await member('Caller');
  await backdateSlot();
  const [still] = await run(m.ctx, async (t) => { await notices.timerSlot(t, true); return t`select app.actor_kind() as kind, app.current_member() as id`; });
  assert.deepStrictEqual({ ...still }, { kind: 'member', id: m.id });
});

test('control 6 (the CSO\'s review, S1): a failed run is undone, recorded and alerted once a day, and still holds the slot for 50 seconds', async () => {
  const [orig] = await q("select pg_get_functiondef('app.containment_lift_job()'::regprocedure) as def");
  await backdateSlot();
  const [before] = await q('select last_ok_at, failures from app.timer_slot');
  await asOwner(`create or replace function app.containment_lift_job() returns integer language plpgsql as $$
    begin perform app.require_system(); raise exception 'planted failure' using errcode = 'P0001'; end $$`);
  try {
    const started = Date.now();
    const outs = [];
    for (let i = 0; i < 20; i++) outs.push(await slot(false));
    assert.deepStrictEqual(outs[0], { ran: false, failed: true });
    assert.ok(outs.slice(1).every((o) => o.why === 'early' && !o.ran), '19 more calls at once: none runs the failing timers again');
    assert.ok(Date.now() - started < 30_000);
    const [after] = await q('select last_at, last_ok_at, failures, last_failure_state from app.timer_slot');
    assert.strictEqual(after.last_ok_at.getTime(), before.last_ok_at.getTime(), 'the heartbeat keeps the last good run');
    assert.ok(Date.now() - after.last_at.getTime() < 60_000, 'the slot was taken by the failed run');
    assert.deepStrictEqual([after.failures, after.last_failure_state], [before.failures + 1, 'P0001']);
    // The next slot, 50 seconds on (Vercel Cron's next call), tries again.
    await backdateSlot();
    assert.deepStrictEqual(await slot(), { ran: false, failed: true });
    assert.strictEqual((await q('select failures from app.timer_slot'))[0].failures, before.failures + 2);
    const a = await alerts('alert:timers:failed:');
    assert.strictEqual(a.length, 1, 'one alert a day');
    assert.match(a[0].body, /\(error P0001\)/);
    assert.doesNotMatch(a[0].body, /planted/, 'never the error message');
  } finally {
    await asOwner(orig.def);
  }
  assert.deepStrictEqual(await slot(), { ran: false, why: 'early', failed: false }, 'fixed, but within the failed run\'s 50 seconds: it waits');
  await backdateSlot();
  assert.deepStrictEqual(await slot(), { ran: true, failed: false }, 'at the next slot it runs');
  assert.strictEqual((await q('select failures from app.timer_slot'))[0].failures, 0);
});

test('control 6 (the CSO\'s review, S2): a run cut off by the statement timeout (57014) is recorded, alerts and holds the slot', async () => {
  const [orig] = await q("select pg_get_functiondef('app.containment_lift_job()'::regprocedure) as def");
  await q("delete from app.notices where dedupe_key like 'alert:timers:failed:%'");
  await backdateSlot();
  // db/index.js gives every request 5 seconds; this timer sleeps past that.
  await asOwner(`create or replace function app.containment_lift_job() returns integer language plpgsql as $$
    begin perform app.require_system(); perform pg_sleep(6); return 0; end $$`);
  try {
    assert.deepStrictEqual(await slot(), { ran: false, failed: true }, 'caught, not an aborted transaction');
    const [s] = await q('select last_failure_state, last_at from app.timer_slot');
    assert.strictEqual(s.last_failure_state, '57014');
    assert.ok(Date.now() - s.last_at.getTime() < 60_000, 'the slot is held');
    assert.deepStrictEqual(await slot(), { ran: false, why: 'early', failed: false });
    const a = await alerts('alert:timers:failed:');
    assert.strictEqual(a.length, 1);
    assert.match(a[0].body, /\(error 57014\)/);
  } finally {
    await asOwner(orig.def);
  }
});

test('control 6 (N3): a run that finds another holding the timers\' lock is "busy", not a success, and the heartbeat doesn\'t move', async () => {
  await backdateSlot();
  const [before] = await q('select last_ok_at from app.timer_slot');
  let out;
  await su.begin(async (t) => {
    await t`select pg_advisory_xact_lock(hashtext('dayonegreat.timers'), 0)`;
    out = await slot();
  });
  assert.deepStrictEqual(out, { ran: false, why: 'busy', failed: false });
  const [after] = await q('select last_ok_at from app.timer_slot');
  assert.strictEqual(after.last_ok_at.getTime(), before.last_ok_at.getTime());
});

test('control 6 (N2): the run clears the caller\'s app.note and puts it back after', async () => {
  const [orig] = await q("select pg_get_functiondef('app.containment_lift_job()'::regprocedure) as def");
  await backdateSlot();
  await asOwner(`create or replace function app.containment_lift_job() returns integer language plpgsql as $$
    begin perform app.require_system();
      if coalesce(current_setting('app.note', true), '') <> '' then raise exception 'a caller''s note reached the timers'; end if;
      return 0; end $$`);
  try {
    const got = await run(ANON, async (t) => {
      await t`select set_config('app.note', 'the caller''s note', true)`;
      const r = await notices.timerSlot(t, true);
      const [n] = await t`select current_setting('app.note', true) as note`;
      return { r, note: n.note };
    });
    assert.deepStrictEqual(got, { r: { ran: true, failed: false }, note: "the caller's note" });
  } finally {
    await asOwner(orig.def);
  }
});

test('control 6: runs not started by Vercel Cron are counted as evidence and alert past 30 a day; cron runs are not counted', async () => {
  await asOwner("update app.timer_slot set other_runs = 28, other_day = (now() at time zone 'UTC')::date");
  await backdateSlot();
  await slot(true);
  assert.strictEqual((await q('select other_runs from app.timer_slot'))[0].other_runs, 28, 'a cron run is not counted');
  await backdateSlot();
  await slot(false);
  assert.strictEqual((await alerts('alert:timers:other:')).length, 0, '29: no alert yet');
  await backdateSlot();
  assert.deepStrictEqual(await slot(false), { ran: true, failed: false }, 'it still runs: evidence decides nothing');
  const a = await alerts('alert:timers:other:');
  assert.strictEqual(a.length, 1);
  assert.match(a[0].title, /other than Vercel Cron/);
});

test('control 3: an hour of 100 hand-outs or any broker failure alerts Aaron through the timers, once per hour; the site can\'t count', async () => {
  const note = (o) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t`select app.broker_note(${o})`; });
  for (let i = 0; i < 99; i++) await note('handed');
  await backdateSlot();
  await slot();
  assert.strictEqual((await alerts('alert:broker:')).length, 0, '99 in an hour: quiet');
  await note('handed');
  await note('failed');
  await backdateSlot();
  await slot();
  await backdateSlot();
  await slot();
  const a = await alerts('alert:broker:');
  assert.deepStrictEqual(a.map((x) => x.dedupe_key.split(':')[2]).sort(), ['busy', 'failed'], 'one of each, not repeated');
  assert.match(a.find((x) => x.dedupe_key.includes('busy')).body, /^100 hand-outs in the hour from /);
  const [row] = await q('select handed, failed from app.broker_uses');
  assert.deepStrictEqual({ ...row }, { handed: 100, failed: 1 }, 'counts only');
  await assert.rejects(run(ANON, (t) => t`select app.broker_note('handed')`), /permission denied/, 'the site can\'t add to or hide the count');
  assert.strictEqual((await run(ANON, (t) => t`select handed from app.broker_uses`)).length, 0, 'only the timers read the counts');
  await assert.rejects(note('other'), /handed or failed/);
});

test('R-9: an agent past 90 days without its owner\'s re-confirmation drafts at its next post even if no timer ran; never off', async () => {
  const owner = await member('Long runner');
  const [a] = await run(owner.ctx, (t) => t`insert into app.agents (name) values ('Veteran') returning id`);
  const ag = { id: a.id, ctx: await ownerKey(owner, a.id) };
  await run({ ...owner.ctx, fresh: true }, (t) => delegation.setRules(t, { agent: a.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 1000 }));
  const age = (days) => su.begin(async (t) => {
    await t.unsafe('alter table app.agent_rules disable trigger agent_rules_guard');
    await t.unsafe(`update app.agent_rules set created_at = now() - interval '${days} days' where agent_id = '${a.id}'`);
    await t.unsafe('alter table app.agent_rules enable always trigger agent_rules_guard');
  });
  const say = (body) => run(ag.ctx, (t) => delegation.submit(t, { body }));
  await age(89);
  assert.ok((await say('day 89, on its own')).posted, 'day 89: it still acts on its own');
  await age(91);
  const out = await say('day 91, no timer has run');
  assert.ok(out.drafted, 'day 91: a draft for the owner, not a post and not a refusal: ' + JSON.stringify(out));
  const [rules] = await q(`select post_mode from app.agent_rules where agent_id = '${a.id}' order by version desc limit 1`);
  assert.strictEqual(rules.post_mode, 'act', 'no timer ran: the post itself was held, in the database');
  // Straight to the table, past db/delegation.js: the database refuses it as "drafts".
  await assert.rejects(run(ag.ctx, (t) => posts.create(t, { body: 'straight in' })), /agent_drafts/);
  // The timers then record it and tell the owner, as before.
  await backdateSlot();
  await slot();
  const [low] = await q(`select post_mode, reason from app.agent_rules where agent_id = '${a.id}' order by version desc limit 1`);
  assert.deepStrictEqual({ ...low }, { post_mode: 'draft', reason: 'act_expired' });
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id = '${owner.id}' and kind = 'act_expired'`))[0].n, 1);
  // A fresh re-confirmation restarts the clock: acting on its own again.
  await run({ ...owner.ctx, fresh: true }, (t) => delegation.setRules(t, { agent: a.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 1000 }));
  assert.ok((await say('confirmed again')).posted);
});

test('R-9 (the CSO\'s review, B1): a sub-agent is judged by its tree\'s 90-day clock: one made at day 91 drafts, and one made earlier drafts once its root passes 90 days', async () => {
  const owner = await member('Tree owner');
  const [a] = await run(owner.ctx, (t) => t`insert into app.agents (name) values ('Root') returning id`);
  const root = await ownerKey(owner, a.id);
  await run({ ...owner.ctx, fresh: true }, (t) => delegation.setRules(t, { agent: a.id, post: 'act', reply: 'act', report: 'act', dailyCap: 1000 }));
  const age = (days) => su.begin(async (t) => {
    await t.unsafe('alter table app.agent_rules disable trigger agent_rules_guard');
    await t.unsafe(`update app.agent_rules set created_at = now() - interval '${days} days' where agent_id = '${a.id}'`);
    await t.unsafe('alter table app.agent_rules enable always trigger agent_rules_guard');
  });
  const makeSub = async (name) => {
    const keyHash = c.sha256hex('sub ' + crypto.randomUUID());
    const out = await run(root, (t) => agentsDb.createSub(t, { name, keyHash, callerKeyHash: root.keyHash, rules: { post: 'act', reply: 'act', report: 'act' }, ttlHours: 168 }));
    assert.ok(out.id, JSON.stringify(out));
    return { out, ctx: { actor: 'agent', memberId: owner.id, agentId: out.id, keyHash } };
  };
  const say = (ctx, body) => run(ctx, (t) => delegation.submit(t, { body }));
  await age(89);
  const early = await makeSub('Made at day 89');
  assert.deepStrictEqual([early.out.rules.post, early.out.rules.reply, early.out.rules.report], ['act', 'act', 'act'], 'day 89: as asked');
  assert.ok((await say(early.ctx, 'sub-agent, day 89')).posted);
  await age(91);
  // No timer has run. The root drafts its own posts (above), and now its sub-agents too.
  const late = await makeSub('Made at day 91');
  assert.deepStrictEqual([late.out.rules.post, late.out.rules.reply, late.out.rules.report], ['draft', 'draft', 'draft'], 'made drafting, not refused, not off');
  const lateSays = await say(late.ctx, 'sub-agent made at day 91');
  assert.ok(lateSays.drafted, JSON.stringify(lateSays));
  const earlySays = await say(early.ctx, 'sub-agent made at day 89, now day 91');
  assert.ok(earlySays.drafted, 'judged by its root\'s clock, not its own rules (which never restart it): ' + JSON.stringify(earlySays));
  await assert.rejects(run(early.ctx, (t) => posts.create(t, { body: 'straight in' })), /agent_drafts/, 'the database refuses it as drafts');
  assert.ok((await say(root, 'the root at day 91')).drafted);
  // The agent can't read its root's rules itself: the clock runs as the sign-in role.
  const visible = await run(early.ctx, (t) => t`select count(*)::int as n from app.agent_rules where agent_id = ${a.id}`);
  assert.strictEqual(visible[0].n, 0);
  // The timers then lower the root, and its sub-agents with it.
  await backdateSlot();
  await slot();
  const [low] = await q(`select post_mode from app.agent_rules where agent_id = '${early.out.id}' order by version desc limit 1`);
  assert.strictEqual(low.post_mode, 'draft');
});

test('the coverage check and the runner report dog_timers made wider (a login, a role acting as it, another membership, a second function), and 027 leaves no role acting as it', async () => {
  assert.deepStrictEqual(await problems(su), []);
  const [held] = await q("select count(*)::int as n from pg_auth_members a join pg_roles r on r.oid = a.roleid where r.rolname = 'dog_timers' and (a.set_option or a.inherit_option)");
  assert.strictEqual(held.n, 0, 'the owner\'s membership, used only to hand over the function, was taken back (no dog_owner -> dog_timers -> dog_app chain)');
  const core = await import('../supabase/functions/dog-migrate/core.mjs');
  for (const [plant, want] of [
    ['grant dog_timers to dog_owner', /dog_owner can act as dog_timers; no role may/],
    ['alter role dog_timers login', /dog_timers can sign in directly/],
    [`grant dog_timers to ${WEB}`, new RegExp(WEB + ' can act as dog_timers')],
    ['grant dog_jevs to dog_timers', /dog_timers belongs to dog_app, dog_jevs/],
    // Portable (S4): the test's login takes the membership itself for this rolled-back transaction, which a superuser
    // and Supabase's postgres (its creator, holding the ADMIN option: N4) both may, instead of relying on SET ROLE rights.
    ['grant dog_timers to current_user with inherit false, set true; set local role dog_owner; grant create on schema app to dog_timers; '
      + "create function app.timers_extra() returns integer language sql as 'select 1'; reset role; alter function app.timers_extra() owner to dog_timers",
      /dog_timers owns [^;]*app\.timers_extra\(\)[^;]*; it must own app\.timers_run\(boolean\) only/]
  ]) {
    let found, runner;
    await su.begin(async (t) => {
      await t.unsafe(plant);
      found = await problems(t);
      runner = await core.catalogChecks(t);
      throw new Error('roll back');
    }).catch((e) => { if (e.message !== 'roll back') throw e; });
    assert.ok(found.some((p) => want.test(p)), plant + ': ' + JSON.stringify(found));
    if (plant.includes('login')) assert.ok(runner.includes('no database role of ours can sign in'), 'the runner\'s daily check sees a login too');
  }
  assert.deepStrictEqual(await problems(su), [], 'nothing was changed');
});

test('R-10: the emergency migration, applied to a throwaway database, refuses the site\'s login; reopening undoes it exactly', async () => {
  const close = fs.readFileSync(path.join(root, 'db', 'emergency', 'close-site-login.sql'), 'utf8');
  const reopen = fs.readFileSync(path.join(root, 'db', 'emergency', 'reopen-site-login.sql'), 'utf8');
  const pw = crypto.randomBytes(18).toString('base64url');
  const [{ before }] = await q("select rolcanlogin as before from pg_roles where rolname = 'dog_web'");
  assert.strictEqual(before, true, 'migration 022 made the site login');
  await q(`alter role dog_web password '${pw}'`); // tests only: the real password is made inside the database (022)
  const asSite = () => postgres(at(SERVER, NAME, 'dog_web', pw), { max: 1, ssl: false, connect_timeout: 5, onnotice: () => {} });
  const open = asSite();
  try {
    assert.strictEqual((await open`select 1 as one`)[0].one, 1, 'the site logs in');
    // Applied as the runner applies a migration: one transaction, as the migration login.
    await su.begin((t) => t.unsafe(close));
    const [{ after }] = await q("select rolcanlogin as after from pg_roles where rolname = 'dog_web'");
    assert.strictEqual(after, false);
    const late = asSite();
    await assert.rejects(late`select 1`, (e) => e.code === '28000' && /not permitted to log in/.test(e.message), 'a new login is refused');
    await late.end({ timeout: 1 }).catch(() => {});
    await assert.rejects(open`select 1`, 'the connection already open was ended');
    // The runner's checks still pass with the login closed, so closing raises no false alarm.
    const core = await import('../supabase/functions/dog-migrate/core.mjs');
    assert.deepStrictEqual(await core.catalogChecks(su), []);
    assert.deepStrictEqual(await problems(su), []);
    const [m] = await q("select count(*)::int as n from pg_auth_members a join pg_roles g on g.oid = a.roleid join pg_roles u on u.oid = a.member where u.rolname = 'dog_web' and g.rolname = 'dog_app'");
    assert.strictEqual(m.n, 1, 'its membership is kept');
    await su.begin((t) => t.unsafe(reopen));
    const again = asSite();
    assert.strictEqual((await again`select 1 as one`)[0].one, 1, 'reopened: the same password works again');
    await again.end({ timeout: 1 });
  } finally {
    await open.end({ timeout: 1 }).catch(() => {});
    await q('alter role dog_web login password null'); // as the other tests expect it: a login with no usable password here
  }
});
