// 053, audit logging to NIST SP 800-53 Rev 5 (AU, AC-7) and the DISA Application Security and Development STIG
// (Aaron, Nov 8; AUDIT-LOGGING.md; ACCEPTANCE.md AL1 to AL16). Against a Postgres built from the migrations, through the
// site's own code. Needs TEST_DATABASE_URL (skipped without it, required in CI).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');
const { promote, shadowMode, asSignin } = require('./helpers');

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('audit logging tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('audit logging against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_audit_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const q = (s) => su.unsafe(s);
const asOwner = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); });
// A request as Vercel hands it to a route: the database calls inside it carry its details.
const REQ = { method: 'POST', url: '/api/work/claim?code=secret', headers: { 'x-vercel-forwarded-for': '203.0.113.9', 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0', referer: 'https://dayonegreat.com/build', host: 'dayonegreat.com' } };
const inRequest = (ctx, fn, req = REQ) => db.withRequest(req, () => db.tx(web, ctx, fn));
const audit = async (subject, action) => [...await q(`select a.*, n.ip, n.user_agent, n.referer, n.method, n.path, n.host from app.audit_log a
  left join app.audit_net n on n.audit_id = a.id where a.subject_id = '${subject}' and a.action = '${action}' order by a.at, a.id`)];

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await asOwner('update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000');
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  aaron = await member('Aaron', { admin: true });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(name, { admin = false } = {}) {
  const token = c.token(32);
  const sessionHash = c.sha256hex(token);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash, sessionDays: 30 }));
  await promote(su, out.memberId);
  if (admin) await asOwner(`update app.members set is_admin = true where id = '${out.memberId}'`);
  return { id: out.memberId, name, sessionHash, ctx: { actor: admin ? 'admin' : 'member', memberId: out.memberId, session: sessionHash } };
}

test('AL1, AL2 (AU-3, V-222447, V-222448, V-222470, V-222473 to V-222477): every audit row says what, when, where, from where, its outcome and who, with the request behind it', async () => {
  const m = await member('Rena');
  await inRequest(m.ctx, (t) => store.rename(t, 'Rena B'));
  const [r] = await audit(m.id, 'member.renamed');
  assert.ok(r, 'a rename is recorded');
  assert.deepStrictEqual([r.actor_kind, r.actor_id, r.outcome, r.component], ['member', m.id, 'success', 'member']);
  assert.match(r.session_ref, /^[0-9a-f]{16}$/, 'the session, by reference');
  assert.notStrictEqual(r.session_ref, m.sessionHash.slice(0, 16), 'never the session itself');
  assert.ok(r.at instanceof Date, 'when, by the database clock (UTC, microseconds)');
  assert.deepStrictEqual([r.ip, r.user_agent, r.referer, r.method, r.path, r.host],
    ['203.0.113.9', REQ.headers['user-agent'], 'https://dayonegreat.com/build', 'POST', '/api/work/claim', 'dayonegreat.com'], 'the request; no query string');
  // A call outside any request (the timers) records none, and nothing breaks.
  await db.tx(web, m.ctx, (t) => store.rename(t, 'Rena C'));
  const rows = await audit(m.id, 'member.renamed');
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[1].ip, null);
});

test('AL3 (V-222462, AC-7, V-222432, V-222433): each failed sign-in is its own audit row; the third in 15 minutes locks the account, every way in; an administrator may release it, with a reason', async () => {
  const m = await member('Lockable');
  // A browser key for the member, with wrong PINs counted on it, as 037 counts them.
  const [k] = await q(`insert into app.browser_keys (member_id, public_key, label) values ('${m.id}', decode('04' || repeat(md5(random()::text), 4), 'hex'), 'Firefox on Linux') returning id`);
  const wrong = () => su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(`update app.browser_keys set failed = failed + 1 where id = '${k.id}'`); });
  await wrong();
  await wrong();
  assert.strictEqual((await audit(m.id, 'signin.failed')).length, 2);
  assert.ok((await audit(m.id, 'signin.failed')).every((r) => r.outcome === 'failure' && r.component === 'signin' && r.detail.lane === 'browser'));
  assert.strictEqual((await audit(m.id, 'signin.locked')).length, 0, 'two are not a lock');
  await wrong();
  const [lock] = await audit(m.id, 'signin.locked');
  assert.deepStrictEqual([lock.outcome, lock.detail.minutes], ['failure', 15]);
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id = '${m.id}' and title = 'Sign-in locked for 15 minutes'`))[0].n, 1, 'the member is told');
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id is null and subject_id = '${m.id}' and dedupe_key like 'watch:locked:%'`))[0].n, 1, 'Aaron is told');
  // Locked: no new session, by any lane (every lane makes one).
  const newSession = () => asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: 'x', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
  await assert.rejects(su.begin(async (t) => { await t.unsafe('set local role dog_signin');
    await t.unsafe(`insert into app.sessions (member_id, token_hash, expires_at) values ('${m.id}', '${c.sha256hex(c.token(32))}', now() + interval '1 day')`); }), /locked/);
  const other = await newSession();
  assert.ok(other.memberId && other.memberId !== m.id, 'another member signs in as usual');
  // Only an administrator releases it, with a reason; that too is recorded.
  const work = require('../db/work');
  await assert.rejects(db.tx(web, m.ctx, (t) => work.unlock(t, m.id, 'Let me in')), /administrator/);
  assert.deepStrictEqual(await inRequest(aaron.ctx, (t) => work.unlock(t, m.id, 'It was the member, on a new phone.')), { result: 'released' });
  const [rel] = await audit(m.id, 'signin.unlocked');
  assert.deepStrictEqual([rel.actor_kind, rel.actor_id, rel.detail.reason, rel.ip], ['admin', aaron.id, 'It was the member, on a new phone.', '203.0.113.9']);
  await su.begin(async (t) => { await t.unsafe('set local role dog_signin');
    await t.unsafe(`insert into app.sessions (member_id, token_hash, expires_at) values ('${m.id}', '${c.sha256hex(c.token(32))}', now() + interval '1 day')`); });
  // A good sign-in clears the count: the limit is three consecutive.
  await wrong();
  await wrong();
  assert.strictEqual((await audit(m.id, 'signin.locked')).length, 1, 'two after a good one: no new lock');
});

test('AL4 (V-222441, V-222442, V-222445, V-222464): sessions are recorded when made, ended and expired; the timer sweeps expired ones', async () => {
  const m = await member('Sessions');
  const [made] = await audit(m.id, 'session.created');
  assert.ok(made && made.session_ref === crypto.createHash('sha256').update(m.sessionHash).digest('hex').slice(0, 16));
  // Signed out.
  await inRequest(m.ctx, (t) => store.sessionEnd(t, m.sessionHash));
  const [ended] = await audit(m.id, 'session.ended');
  assert.ok(ended && ended.session_ref === made.session_ref && ended.ip === '203.0.113.9');
  // Expired, then swept by the timer route's call.
  const m2 = await member('Expiring');
  await q(`update app.sessions set expires_at = now() - interval '1 minute' where member_id = '${m2.id}'`);
  const [{ n }] = await db.tx(web, { actor: 'anon' }, (t) => t`select app.session_sweep() as n`);
  assert.ok(n >= 1);
  assert.strictEqual((await audit(m2.id, 'session.expired')).length, 1);
});

test('AL5 (V-222414, V-222467): PINs, browser keys and key files set, changed, removed and cancelled are recorded', async () => {
  const m = await member('Keys');
  const asSign = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(sql); });
  await asSign(`select app.pin_store('${m.id}', '135792')`);
  await asSign(`select app.pin_store('${m.id}', '864209')`);
  const [k] = await q(`insert into app.browser_keys (member_id, public_key, label) values ('${m.id}', decode('04' || repeat(md5(random()::text), 4), 'hex'), 'Firefox on Linux') returning id`);
  await asSign(`delete from app.browser_keys where id = '${k.id}'`);
  const actions = (await q(`select action from app.audit_log where subject_id = '${m.id}' and component = 'signin' order by at, id`)).map((r) => r.action);
  assert.deepStrictEqual(actions, ['signin.pin_set', 'signin.pin_changed', 'signin.browser_added', 'signin.browser_removed']);
});

test('AL6 (V-222431, V-222463, V-222472, V-222512): settings changes and Third Look\'s mode are recorded with what changed; the timers\' own bookkeeping is not', async () => {
  const before = (await q(`select count(*)::int as n from app.audit_log where action = 'settings.changed'`))[0].n;
  await q(`update app.work_settings set last_tick_at = now()`);
  assert.strictEqual((await q(`select count(*)::int as n from app.audit_log where action = 'settings.changed'`))[0].n, before, 'bookkeeping only');
  await q(`update app.work_settings set check_daily = check_daily + 1`);
  const [r] = await q(`select detail from app.audit_log where action = 'settings.changed' order by at desc, id desc limit 1`);
  assert.deepStrictEqual(Object.keys(r.detail.changed), ['check_daily']);
  assert.strictEqual(r.detail.table, 'work_settings');
  await q(`update app.tl_settings set mode = 'shadow'`);
  const [mode] = await q(`select detail from app.audit_log where action = 'thirdlook.mode' order by at desc, id desc limit 1`);
  assert.strictEqual(mode.detail.to, 'shadow');
});

test('AL7 (V-222465, V-222471): Aaron\'s reads of the work queue are recorded; nobody else\'s call records anything', async () => {
  const m = await member('Reader');
  const reads = async () => (await q(`select count(*)::int as n from app.audit_log where action = 'admin.read'`))[0].n;
  const was = await reads();
  await db.tx(web, m.ctx, (t) => t`select app.audit_admin_read('work_queue')`);
  assert.strictEqual(await reads(), was);
  await inRequest(aaron.ctx, (t) => t`select app.audit_admin_read('work_queue')`);
  assert.strictEqual(await reads(), was + 1);
});

test('AL8, AL9 (AU-9, V-222500 to V-222502, V-222621): audit rows and their request records can\'t be changed; request records go only after a year; erasure keeps audit rows and Aaron\'s alerts', async () => {
  const m = await member('Leaving');
  await inRequest(m.ctx, (t) => store.rename(t, 'Leaving soon'));
  const [r] = await audit(m.id, 'member.renamed');
  await assert.rejects(q(`update app.audit_log set outcome = 'failure' where id = '${r.id}'`), /audit/i);
  await assert.rejects(q(`update app.audit_net set ip = '198.51.100.1' where audit_id = '${r.id}'`), /can.t be changed/);
  await assert.rejects(asOwner(`delete from app.audit_log where id = '${r.id}'`), /audit|permission|row-level/i);
  // A request record under a year old can't be deleted, even by the owner role; past a year the upkeep deletes it.
  await asOwner(`delete from app.audit_net where audit_id = '${r.id}'`);
  assert.strictEqual((await q(`select count(*)::int as n from app.audit_net where audit_id = '${r.id}'`))[0].n, 1, 'still there');
  // Erasure: the member's inbox goes; the audit rows and Aaron's alerts about them stay.
  await q(`insert into app.notices (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key) values (null, 'alert', 'About Leaving', 'x', '/controls', 'member', '${m.id}', 'watch:test:${m.id}')`);
  await q(`update app.sessions set created_at = now() where member_id = '${m.id}'`);
  const out = await db.tx(web, { ...m.ctx, fresh: true }, (t) => store.deleteAccount(t));
  assert.ok(!out.refused, JSON.stringify(out));
  assert.ok((await audit(m.id, 'member.renamed')).length === 1, 'the audit row stays');
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id is null and subject_id = '${m.id}'`))[0].n, 1, 'Aaron\'s alert stays');
});

test('AL10 (V-222483, AU-5(1)): the hourly upkeep warns Aaron at 75% of the plan\'s storage, once a day, and deletes request records past a year', async () => {
  const [{ size }] = await q(`select pg_database_size(current_database()) as size`);
  await asOwner(`update app.audit_upkeep set capacity_bytes = ${Math.floor(Number(size) / 0.8)}, last_run_at = null`);
  await q(`insert into app.audit_net (audit_id, at, ip) values (gen_random_uuid(), now() - interval '400 days', '192.0.2.1')`);
  const [{ r }] = await db.tx(web, { actor: 'anon' }, (t) => t`select app.audit_upkeep_run() as r`);
  assert.ok(r.percent >= 75 && r.net_deleted === 1, JSON.stringify(r));
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id is null and dedupe_key like 'audit:capacity:%'`))[0].n, 1);
  const [{ r: again }] = await db.tx(web, { actor: 'anon' }, (t) => t`select app.audit_upkeep_run() as r`);
  assert.strictEqual(again, null, 'at most once an hour');
  await asOwner(`update app.audit_upkeep set capacity_bytes = 8589934592`);
});

test('AL16 (V-222444): audit records hold no secret: no PIN, session, key or post text, and request paths carry no query string', async () => {
  const rows = await q(`select a.detail::text as d, a.session_ref, n.path from app.audit_log a left join app.audit_net n on n.audit_id = a.id`);
  const text = rows.map((r) => r.d + ' ' + (r.path || '')).join('\n');
  for (const secret of ['135792', '864209', 'code=secret']) assert.ok(!text.includes(secret), secret);
  assert.ok(!/[0-9a-f]{64}/.test(text), 'no session or key hash');
  assert.ok(rows.every((r) => r.session_ref === null || /^[0-9a-f]{16}$/.test(r.session_ref)));
  assert.ok(rows.every((r) => !r.path || !r.path.includes('?')));
});

test('the review of 053, L1: two failed sign-ins at the same moment still make the third, and the lock', async () => {
  const m = await member('Racing');
  const keys = [];
  for (let i = 0; i < 2; i++) keys.push((await q(`insert into app.browser_keys (member_id, public_key, label) values ('${m.id}', decode('04' || repeat(md5(random()::text), 4), 'hex'), 'Browser ${'AB'[i]}') returning id`))[0].id);
  const wrong = (id) => su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(`update app.browser_keys set failed = failed + 1 where id = '${id}'`); });
  await wrong(keys[0]);
  await Promise.all([wrong(keys[0]), wrong(keys[1])]);
  assert.strictEqual((await audit(m.id, 'signin.failed')).length, 3);
  assert.strictEqual((await audit(m.id, 'signin.locked')).length, 1, 'counted one at a time: the third locks');
});

test('the review of 053, L2 to L4: the referrer keeps no query; a request with no address or browser is still recorded; an action named with digits is recorded', async () => {
  const m = await member('Searcher');
  const req = { method: 'POST', url: '/api/feed', headers: { referer: 'https://dayonegreat.com/feed?q=my+private+search#top', host: 'dayonegreat.com' } };
  await inRequest(m.ctx, (t) => store.rename(t, 'Searcher B'), req);
  const [r] = await audit(m.id, 'member.renamed');
  assert.deepStrictEqual([r.ip, r.user_agent, r.referer, r.method, r.path], [null, null, 'https://dayonegreat.com/feed', 'POST', '/api/feed']);
  await asOwner(`select app.audit_add('oauth2.example', 'member', '${m.id}', '{}'::jsonb)`);
  const [d] = await audit(m.id, 'oauth2.example');
  assert.strictEqual(d.component, 'oauth2');
  await asOwner(`select app.audit_add('averyveryveryverylongcomponentname.x', 'member', '${m.id}', '{}'::jsonb)`);
  const [long] = await audit(m.id, 'averyveryveryverylongcomponentname.x');
  assert.strictEqual(long.component, null, 'a name the column can\'t take is left out; the action is still recorded');
});

test('the review of 053, L6: a session\'s expiry keeps its time', async () => {
  const m = await member('Expiry');
  await q(`update app.sessions set expires_at = now() - interval '5 minutes' where member_id = '${m.id}'`);
  await db.tx(web, { actor: 'anon' }, (t) => t`select app.session_sweep()`);
  const [x] = await audit(m.id, 'session.expired');
  assert.ok(x.detail.expires && new Date(x.detail.expires) < x.at, 'when it expired, not only when it was swept');
});

test('the second review of 053, 3: request records can\'t be emptied, or deleted before a year, by any role, the owner and a superuser included', async () => {
  const m = await member('Kept');
  await inRequest(m.ctx, (t) => store.rename(t, 'Kept B'));
  const [r] = await audit(m.id, 'member.renamed');
  assert.ok(r.ip, 'a request record');
  await assert.rejects(asOwner('truncate app.audit_net'), /kept a year/);
  await assert.rejects(q('truncate app.audit_net'), /kept a year/, 'not even a superuser');
  await assert.rejects(q(`delete from app.audit_net where audit_id = '${r.id}'`), /kept a year/);
  assert.strictEqual((await q(`select count(*)::int as n from app.audit_net where audit_id = '${r.id}'`))[0].n, 1);
});

test('the second review of 053, 4: the Console lists the locks in force to an administrator only, each released with a reason', async () => {
  const m = await member('LockedOut');
  await asOwner(`insert into app.signin_locks (member_id, until) values ('${m.id}', now() + interval '15 minutes')`);
  const work = require('../db/work');
  const asAaron = await inRequest(aaron.ctx, (t) => work.console(t, { tab: 'admins' }));
  assert.ok(asAaron.locks.some((l) => l.member === m.id && l.name === 'LockedOut'), 'Aaron sees the lock');
  const other = await member('Nosy');
  assert.deepStrictEqual(await db.tx(web, other.ctx, (t) => t`select app.signin_locks_open() as l`).then((x) => x[0].l), [], 'nobody else does');
  assert.deepStrictEqual(await inRequest(aaron.ctx, (t) => work.unlock(t, m.id, 'Checked with the member.')), { result: 'released' });
  assert.ok(!(await inRequest(aaron.ctx, (t) => work.console(t, { tab: 'admins' }))).locks.some((l) => l.member === m.id), 'gone once released');
});

test('the third review of 053, L1: releasing a lock also ends the key-file pause the same failures started', async () => {
  const m = await member('Paused');
  const fp = (await q(`select fingerprint from app.identities where member_id = '${m.id}'`))[0].fingerprint;
  await su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(`insert into app.file_keys (member_id, fingerprint, login_hash, key_hash) values ('${m.id}', '${fp}', '${c.sha256hex(c.token(32))}', '${c.sha256hex(c.token(32))}')`); });
  await q(`update app.file_keys set paused_until = now() + interval '10 minutes' where member_id = '${m.id}'`);
  await asOwner(`insert into app.signin_locks (member_id, until) values ('${m.id}', now() + interval '15 minutes')`);
  const work = require('../db/work');
  assert.deepStrictEqual(await inRequest(aaron.ctx, (t) => work.unlock(t, m.id, 'Checked with the member.')), { result: 'released' });
  assert.strictEqual((await q(`select paused_until from app.file_keys where member_id = '${m.id}'`))[0].paused_until, null, 'the pause ended too');
  assert.strictEqual((await q(`select failed from app.file_keys where member_id = '${m.id}'`))[0].failed, 0, 'and its count');
});
