// Release 2, PR 1 (Foundation): S1, S7, S8, G1, G3, G4, run against a real Postgres built from the migrations.
// Each run makes a throwaway database, applies db/migrations, and connects the way production does: as a login role
// that holds no rights of its own and switches to dog_app inside each transaction.
// Needs TEST_DATABASE_URL (a server address with rights to create databases and roles). In CI it is required;
// on a laptop without Postgres these tests are skipped and say so.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const v = require('../db/validate');
const members = require('../db/members');
const audit = require('../db/audit');
const { problems } = require('../db/checks');
const { migrate } = require('../scripts/migrate');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;

// ---- Tests that need no database -------------------------------------------------------------------------------

test('G1: production connections must go through a pooler in transaction mode', () => {
  for (const ok of [
    'postgres://u:p@aws-0-us-west-1.pooler.supabase.com:6543/postgres',
    'postgresql://u:p@db.abcdefghijklmnop.supabase.co:6543/postgres',
    'postgres://u:p@ep-cool-name-123456-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require'
  ]) assert.strictEqual(db.pooledUrl(ok), ok);
  for (const bad of [
    'postgres://u:p@aws-0-us-west-1.pooler.supabase.com:5432/postgres', // session mode
    'postgres://u:p@db.abcdefghijklmnop.supabase.co:5432/postgres', // direct
    'postgres://u:p@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb', // direct
    'postgres://u:p@localhost:5432/postgres',
    'postgres://u:p@evil.com/x?host=aws-0.pooler.supabase.com',
    'mysql://u:p@aws-0-us-west-1.pooler.supabase.com:6543/x',
    'not a url'
  ]) assert.throws(() => db.pooledUrl(bad), /pooler|address/, bad);
});

test('G1: the site reads its database address in one place and never uses named prepared statements', () => {
  const sql = db.connect('postgres://u:p@aws-0-us-west-1.pooler.supabase.com:6543/postgres');
  assert.strictEqual(sql.options.prepare, false);
  const saved = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  try { assert.throws(() => db.fromEnv(), /DATABASE_URL is not set/); } finally { if (saved !== undefined) process.env.DATABASE_URL = saved; }
  const readers = sourceFiles().filter((f) => /\bDATABASE_URL/.test(read(f)) && !/^(test|db\/migrations)\//.test(f));
  assert.deepStrictEqual(readers, ['db/index.js'], 'only db/index.js may read DATABASE_URL');
});

test('S8 code check: raw SQL and the database driver appear only where allowed', () => {
  for (const f of sourceFiles()) {
    const s = read(f);
    if (/\.unsafe\s*\(/.test(s) && !f.startsWith('test/')) assert.strictEqual(f, 'scripts/migrate.js', f + ' uses raw SQL; only the migration runner may');
    if (/require\(['"]postgres['"]\)/.test(s) && !f.startsWith('test/')) {
      assert.ok(['db/index.js', 'scripts/migrate.js'].includes(f), f + ' loads the database driver directly; go through db/index.js');
    }
  }
  assert.match(read('.semgrep/database.yml'), /dayonegreat\.db\.no-raw-sql/, 'the same rule runs in Semgrep');
});

test('S8: every database call says who is acting, and the combination must make sense', () => {
  const m = '018f3c2e-7b1a-7cde-8f00-0123456789ab';
  const a = '018f3c2e-7b1a-7cde-9f00-0123456789ab';
  for (const bad of [undefined, null, {}, { actor: 'root' }, { actor: 'member' }, { actor: 'anon', memberId: m },
    { actor: 'agent', memberId: m }, { actor: 'member', memberId: m, agentId: a }, { actor: 'system', memberId: m },
    { actor: 'member', memberId: 'not-an-id' }, { actor: 'member', memberId: "x' or '1'='1" }]) {
    assert.rejects(db.tx({ begin: () => assert.fail('must not reach the database') }, bad, () => {}));
  }
});

test('S8: inputs are type-checked, size-limited and normalized, and errors never echo the value', () => {
  assert.strictEqual(v.text('n', '  Aaron  ', { max: 80 }), 'Aaron');
  assert.strictEqual(v.text('n', 'Café', { max: 4 }), 'Café'); // NFC: 5 code points become 4
  assert.strictEqual(v.text('n', '😀'.repeat(80), { max: 80 }).length, 160); // counts characters, not UTF-16 units
  for (const [value, re] of [[42, /must be text/], ['', /required/], ['   ', /required/], ['x'.repeat(81), /too long/],
    ['x'.repeat(10000), /too long/], ['a\u0000b', /control/], ['a\u001bb', /control/], ['\ud800', /not valid/]]) {
    assert.throws(() => v.text('displayName', value, { max: 80 }), (e) => e instanceof v.ValidationError && re.test(e.message) && (String(value).trim().length < 3 || !e.message.includes(String(value).slice(0, 3))));
  }
  assert.throws(() => v.text('x', 'a'), /needs a max/, 'a text field without a limit is a programming error');
  assert.throws(() => v.uuid('id', '1'), v.ValidationError);
  assert.throws(() => v.uuid('id', '018F3C2E-7B1A-7CDE-8F00-0123456789AB'), v.ValidationError);
  assert.throws(() => v.int('n', 1.5, { min: 0, max: 3 }), v.ValidationError);
  assert.throws(() => v.int('n', 4, { min: 0, max: 3 }), v.ValidationError);
  assert.throws(() => v.int('n', '1', { min: 0, max: 3 }), v.ValidationError);
  assert.throws(() => v.object('d', [], { maxBytes: 10 }), v.ValidationError);
  assert.throws(() => v.object('d', new Date(), { maxBytes: 100 }), v.ValidationError);
  assert.throws(() => v.object('d', { s: 'x'.repeat(20) }, { maxBytes: 10 }), /too large/);
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => v.object('d', cyclic, { maxBytes: 100 }), /plain data/);
});

test('migration files are numbered without gaps and never edited after they ship', () => {
  const files = fs.readdirSync(path.join(root, 'db', 'migrations'));
  files.forEach((f, i) => assert.match(f, new RegExp('^' + String(i + 1).padStart(3, '0') + '_[a-z0-9_]+\\.sql$')));
});

// ---- Tests against a real database -----------------------------------------------------------------------------

if (!SERVER) {
  if (process.env.CI) test('database tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set, so S1, S7 and S8 were not checked'));
  else test('database tests (S1, S3, S7, S8, G3, G4)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const WEB_PASSWORD = crypto.randomBytes(18).toString('base64url');
const at = (base, { db: d, user, password } = {}) => {
  const u = new URL(base);
  if (d) u.pathname = '/' + d;
  if (user) { u.username = user; u.password = password || ''; }
  return u.toString();
};
let server; // a superuser on the server, for setup only
let admin; // the same superuser on the test database: plays the migration runner and the attacker with owner rights
let web; // the site's login role on the test database, as in production
let one; // the same login with a single connection, to prove nothing carries between transactions

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server`select 1`;
  await server.unsafe('create database ' + NAME);
  admin = postgres(at(SERVER, { db: NAME }), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(admin);
  // Production setup (db/README.md): a login role with no rights of its own that may switch to dog_app.
  await admin.unsafe(`create role ${WEB} login noinherit password '${WEB_PASSWORD}'`);
  await admin.unsafe(`grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, { db: NAME, user: WEB, password: WEB_PASSWORD }), { ssl: false, max: 3 });
  one = db.connect(at(SERVER, { db: NAME, user: WEB, password: WEB_PASSWORD }), { ssl: false, max: 1 });
});

test.after(async () => {
  for (const c of [web, one, admin]) if (c) await c.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

const as = (ctx, fn, conn = web) => db.tx(conn, ctx, fn);
const SYSTEM = { actor: 'system' };
const ANON = { actor: 'anon' };
const member = (id) => ({ actor: 'member', memberId: id });
const AARON = (id) => ({ actor: 'admin', memberId: id });
async function newMember(name) { return as(SYSTEM, (t) => members.create(t, { displayName: name })); }
async function fails(promise, re) { await assert.rejects(promise, (e) => re.test(e.message) || re.test(e.code || '')); }

test('S1: the coverage check passes on the database the migrations build', async () => {
  assert.deepStrictEqual(await problems(admin), []);
});

test('S1: the coverage check fails the build for a table without forced row-level security, and for each other gap', async () => {
  const cases = [
    ['create table app.t1 (id uuid primary key default app.uuid_v7())', /app\.t1 does not have row-level security on/],
    ['create table app.t2 (id uuid primary key default app.uuid_v7()); alter table app.t2 enable row level security', /app\.t2 does not have row-level security forced/],
    ['create table public.t3 (id int)', /public\.t3 is in the public schema/],
    ['create view app.v1 as select id from app.members', /app\.v1 is a view without security_invoker/],
    ['create materialized view app.m1 as select id from app.members', /materialized view/],
    ['grant select on app.members to public', /grants SELECT to PUBLIC/],
    ['grant create on schema app to dog_app', /schema app grants CREATE to dog_app/],
    ['alter role dog_app bypassrls', /dog_app can bypass row-level security/],
    ['alter table app.audit_log disable trigger audit_log_no_change', /missing its audit_log_no_change trigger/],
    ['create table app.t4 (id bigserial primary key)', /counter|uuid/],
    ['create table app.t5 (id uuid primary key default app.uuid_v7(), note text); alter table app.t5 enable row level security; alter table app.t5 force row level security', /app\.t5\.note has no size limit/],
    ['create table app.t6 (id uuid primary key default app.uuid_v7(), note text check (char_length(note) >= 1)); alter table app.t6 enable row level security; alter table app.t6 force row level security', /app\.t6\.note has no size limit/],
    ['create table app.t7 (id uuid primary key default app.uuid_v7(), passport_number text check (char_length(passport_number) <= 9)); alter table app.t7 enable row level security; alter table app.t7 force row level security', /ID document/],
    ['create function app.f1() returns int language sql security definer as $$ select 1 $$', /security definer/]
  ];
  for (const [ddl, expect] of cases) {
    const found = await admin.begin(async (t) => {
      await t.unsafe(ddl);
      const p = await problems(t);
      throw Object.assign(new Error('rollback'), { found: p });
    }).catch((e) => { if (!e.found) throw e; return e.found; });
    assert.ok(found.some((p) => expect.test(p)), ddl + '\n  expected a problem matching ' + expect + '\n  got: ' + JSON.stringify(found));
  }
  assert.deepStrictEqual(await problems(admin), [], 'every case rolled back');
});

test('S1: the login role can reach nothing until it acts as dog_app inside a transaction', async () => {
  const raw = postgres(at(SERVER, { db: NAME, user: WEB, password: WEB_PASSWORD }), { max: 1, ssl: false, onnotice: () => {} });
  try { await fails(raw`select count(*) from app.members`, /permission denied|42501/); } finally { await raw.end({ timeout: 5 }); }
  const [r] = await as(ANON, (t) => t`select current_user as u, current_setting('statement_timeout') as timeout`);
  assert.deepStrictEqual({ ...r }, { u: 'dog_app', timeout: '5s' });
});

test('S3 groundwork: a member sees and changes only their own row; someone not signed in sees nothing', async () => {
  const a = await newMember('Member A');
  const b = await newMember('Member B');
  assert.strictEqual((await as(member(a.id), (t) => members.get(t, a.id))).display_name, 'Member A');
  assert.strictEqual(await as(member(a.id), (t) => members.get(t, b.id)), null);
  assert.strictEqual((await as(member(a.id), (t) => t`select id from app.members`)).length, 1);
  assert.strictEqual((await as(ANON, (t) => t`select id from app.members`)).length, 0);
  assert.strictEqual(await as(member(a.id), (t) => members.rename(t, b.id, 'Taken over')), false);
  assert.strictEqual(await as(member(a.id), (t) => members.rename(t, a.id, 'Renamed A')), true);
  const rows = await as(SYSTEM, (t) => t`select id, display_name from app.members where id in (${a.id}, ${b.id}) order by display_name`);
  assert.deepStrictEqual(rows.map((r) => r.display_name), ['Member B', 'Renamed A']);
});

test('S3 groundwork: only the site creates members, only Aaron changes trust levels, and nobody deletes yet', async () => {
  const a = await newMember('Member C');
  await fails(as(member(a.id), (t) => t`insert into app.members (display_name) values ('Sneaky')`), /row-level security/);
  await fails(as(ANON, (t) => t`insert into app.members (display_name) values ('Sneaky')`), /row-level security/);
  await fails(as(member(a.id), (t) => members.setTrustLevel(t, a.id, 2)), /only an administrator/);
  await fails(as(member(a.id), (t) => t`update app.members set id = app.uuid_v7() where id = ${a.id}`), /permission denied/);
  await fails(as(member(a.id), (t) => t`delete from app.members where id = ${a.id}`), /permission denied/);
  const aaron = await newMember('Aaron');
  assert.strictEqual(await as(AARON(aaron.id), (t) => members.setTrustLevel(t, a.id, 2)), true);
  assert.strictEqual((await as(member(a.id), (t) => members.get(t, a.id))).trust_level, 2);
});

test('S7, G4: the audit log takes new rows, shows them only to Aaron, and refuses every edit or deletion', async () => {
  const a = await newMember('Member D');
  const aaron = await newMember('Aaron again');
  const id = await as(member(a.id), (t) => audit.record(t, { action: 'test.member_did_something', subjectKind: 'member', subjectId: a.id, detail: { n: 1 } }));
  assert.strictEqual((await as(member(a.id), (t) => t`select id from app.audit_log`)).length, 0, 'members cannot read the log');
  const [row] = await as(AARON(aaron.id), (t) => t`select actor_kind, actor_id, action from app.audit_log where id = ${id}`);
  assert.deepStrictEqual({ ...row }, { actor_kind: 'member', actor_id: a.id, action: 'test.member_did_something' });

  // The site's own role: no right to change or remove anything.
  for (const attempt of [
    (t) => t`update app.audit_log set action = 'test.rewritten' where id = ${id}`,
    (t) => t`delete from app.audit_log where id = ${id}`,
    (t) => t`truncate app.audit_log`
  ]) await fails(as(AARON(aaron.id), attempt), /permission denied|append-only/);

  // Even the owner, and even a superuser, is stopped by the triggers.
  for (const stmt of [
    `set local role dog_owner; update app.audit_log set action = 'test.rewritten'`,
    `set local role dog_owner; delete from app.audit_log`,
    `set local role dog_owner; truncate app.audit_log`,
    `update app.audit_log set action = 'test.rewritten'`,
    `delete from app.audit_log`,
    `truncate app.audit_log`
  ]) await fails(admin.begin((t) => t.unsafe(stmt)), /append-only/);
  const [still] = await as(AARON(aaron.id), (t) => t`select action from app.audit_log where id = ${id}`);
  assert.strictEqual(still.action, 'test.member_did_something');
});

test('S7: nobody can write an audit row in someone else\'s name', async () => {
  const a = await newMember('Member E');
  const b = await newMember('Member F');
  await fails(as(member(a.id), (t) => t`insert into app.audit_log (actor_kind, actor_id, action) values ('admin', ${a.id}, 'test.forged')`), /row-level security/);
  await fails(as(member(a.id), (t) => t`insert into app.audit_log (actor_kind, actor_id, action) values ('member', ${b.id}, 'test.forged')`), /row-level security/);
  await fails(as(ANON, (t) => t`insert into app.audit_log (actor_kind, actor_id, action) values ('anon', ${b.id}, 'test.forged')`), /row-level security/);
  // A change and its audit row commit together or not at all.
  await fails(as(member(a.id), async (t) => { await members.rename(t, a.id, 'Half done'); throw new Error('boom'); }), /boom/);
  assert.strictEqual((await as(member(a.id), (t) => members.get(t, a.id))).display_name, 'Member E');
});

test('S8: values travel as parameters, and the database enforces the same limits as the code', async () => {
  const evil = "Robert'); drop table app.members; --";
  const m = await newMember(evil);
  assert.strictEqual((await as(member(m.id), (t) => members.get(t, m.id))).display_name, evil);
  assert.strictEqual((await as(SYSTEM, (t) => t`select to_regclass('app.members') is not null as ok`))[0].ok, true);
  await fails(as(SYSTEM, (t) => t`insert into app.members (display_name) values (${'x'.repeat(81)})`), /check constraint|23514/);
  await fails(as(SYSTEM, (t) => t`insert into app.members (display_name) values ('ok') returning id`).then(([r]) =>
    as(SYSTEM, (t) => t`insert into app.audit_log (action, detail) values ('test.big', ${t.json({ s: 'x'.repeat(5000) })})`)), /check constraint|23514/);
  await fails(as(SYSTEM, (t) => t`insert into app.audit_log (action) values ('Not An Action')`), /check constraint|23514/);
  await assert.rejects(as(SYSTEM, (t) => audit.record(t, { action: 'test.big', detail: { s: 'x'.repeat(3000) } })), v.ValidationError);
});

test('G3: IDs are UUIDv7, ordered by time, and unique', async () => {
  const ids = [];
  for (let i = 0; i < 5; i++) {
    ids.push((await as(SYSTEM, (t) => t`select app.uuid_v7() as id`))[0].id);
    await new Promise((r) => setTimeout(r, 2));
  }
  for (const id of ids) assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.deepStrictEqual([...ids].sort(), ids, 'later IDs sort after earlier ones');
  const ms = parseInt(ids[0].replace(/-/g, '').slice(0, 12), 16);
  assert.ok(Math.abs(ms - Date.now()) < 60000, 'the first 48 bits are the time in milliseconds');
  const many = await as(SYSTEM, (t) => t`select count(distinct app.uuid_v7())::int as n from generate_series(1, 10000)`);
  assert.strictEqual(many[0].n, 10000);
});

test('pooled connections never carry one request\'s identity into the next', async () => {
  const people = await Promise.all(Array.from({ length: 6 }, (_, i) => newMember('Pool ' + i)));
  // 60 overlapping requests over 3 connections, each pausing mid-transaction so others interleave.
  const results = await Promise.all(Array.from({ length: 60 }, (_, i) => {
    const p = people[i % people.length];
    return as(member(p.id), async (t) => {
      await t`select pg_sleep(${(i % 5) / 1000})`;
      const [r] = await t`select app.current_member() as me, (select count(*)::int from app.members) as visible`;
      return r.me === p.id && r.visible === 1;
    });
  }));
  assert.ok(results.every(Boolean), 'every request saw only itself');
  // One connection, used in turn: a member, then a plain query, then someone not signed in.
  await as(member(people[0].id), (t) => t`select 1`, one);
  const [plain] = await one`select current_user as u, current_setting('app.member_id', true) as me, current_setting('app.actor', true) as actor`;
  assert.notStrictEqual(plain.u, 'dog_app', 'the role switch ended with its transaction');
  assert.ok(!plain.me && !plain.actor, 'who was acting ended with the transaction');
  const [after] = await as(ANON, (t) => t`select app.actor_kind() as actor, app.current_member() as me, (select count(*)::int from app.members) as visible`, one);
  assert.deepStrictEqual({ ...after }, { actor: 'anon', me: null, visible: 0 });
});

test('migrations: running again changes nothing, and an edited migration stops the run', async () => {
  assert.deepStrictEqual(await migrate(admin), []);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-mig-'));
  try {
    const src = path.join(root, 'db', 'migrations', '001_foundation.sql');
    fs.writeFileSync(path.join(dir, '001_foundation.sql'), read(path.relative(root, src)) + '\n-- edited\n');
    await assert.rejects(migrate(admin, { dir }), /changed after it was applied/);
    fs.writeFileSync(path.join(dir, '003_skip.sql'), 'select 1;');
    await assert.rejects(migrate(admin, { dir }), /no gaps/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---- helpers ---------------------------------------------------------------------------------------------------
function read(f) { return fs.readFileSync(path.join(root, f), 'utf8'); }
function sourceFiles() {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true })) {
      const rel = d ? d + '/' + e.name : e.name;
      if (e.isDirectory()) { if (!['node_modules', '.git', 'research', 'fonts', '.vercel'].includes(e.name)) walk(rel); }
      else if (/\.(js|sql)$/.test(e.name)) out.push(rel);
    }
  };
  walk('');
  return out;
}
