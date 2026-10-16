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
const SNAPSHOT = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
const SERVER = process.env.TEST_DATABASE_URL;

// ---- Tests that need no database -------------------------------------------------------------------------------

test('G1: production connections must go through a pooler in transaction mode', () => {
  for (const ok of [
    'postgres://u:p@aws-0-us-west-1.pooler.supabase.com:6543/postgres',
    'postgres://u:p@ep-cool-name-123456-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require'
  ]) assert.strictEqual(db.pooledUrl(ok), ok);
  for (const bad of [
    'postgres://u:p@aws-0-us-west-1.pooler.supabase.com:5432/postgres', // session mode
    'postgres://u:p@db.abcdefghijklmnop.supabase.co:5432/postgres', // direct
    'postgresql://u:p@db.abcdefghijklmnop.supabase.co:6543/postgres', // dedicated pooler: IPv6 only, Vercel can't reach it
    'postgres://u:p@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb', // direct
    'postgres://u:p@localhost:5432/postgres',
    'postgres://u:p@evil.com/x?host=aws-0.pooler.supabase.com',
    'mysql://u:p@aws-0-us-west-1.pooler.supabase.com:6543/x',
    'not a url'
  ]) assert.throws(() => db.pooledUrl(bad), /pooler|address/, bad);
});

test('G1: the site reads its database address in one place, checks certificates, and never uses named prepared statements', async () => {
  const sql = db.connect('postgres://u:p@ep-cool-name-123456-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require&options=-crole%3Dpostgres');
  assert.strictEqual(sql.options.prepare, false);
  assert.strictEqual(sql.options.ssl.rejectUnauthorized, true, 'TLS must check the server certificate');
  assert.deepStrictEqual(Object.keys(sql.options.connection || {}).filter((k) => !['application_name'].includes(k)), [], 'settings in the address are dropped');
  assert.ok(!('fromEnv' in db), 'the shared pool is reachable only through run()');
  const saved = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  try { await assert.rejects(db.run({ actor: 'anon' }, () => {}), /DATABASE_URL is not set/); } finally { if (saved !== undefined) process.env.DATABASE_URL = saved; }
  const readers = sourceFiles().filter((f) => /\bDATABASE_URL/.test(read(f)) && !/^(test|db\/migrations)\//.test(f));
  assert.deepStrictEqual(readers, ['db/index.js'], 'only db/index.js may read DATABASE_URL');
});

test('S8 code check: raw SQL, the driver, and identity or session changes appear only where allowed', () => {
  for (const f of sourceFiles().filter((x) => x.endsWith('.js') && !x.startsWith('test/'))) {
    const s = read(f);
    if (/(\.unsafe\b|\[\s*['"`]unsafe['"`]\s*\])/.test(s)) assert.strictEqual(f, 'scripts/migrate.js', f + ' uses raw SQL; only the migration runner may');
    if (/(require\(\s*['"`]postgres['"`]\s*\)|from\s+['"`]postgres['"`]|import\(\s*['"`]postgres['"`])/.test(s)) assert.strictEqual(f, 'db/index.js', f + ' loads the database driver directly; go through db/index.js');
    // Who is acting is set in exactly one place; nothing else may change it or keep state on a pooled connection.
    if (f !== 'db/index.js') {
      assert.ok(!/set_config|app\.(actor|member_id|agent_id)\b/.test(s), f + ' sets who is acting; only db/index.js may');
      assert.ok(!/\b(set\s+(session|local\s+role|role)|reset\s+(role|session)|with\s+hold|create\s+temp)/i.test(s) || f === 'scripts/migrate.js', f + ' changes the session or keeps state past a transaction');
    }
  }
  const rules = read('.semgrep/database.yml');
  for (const id of ['no-raw-sql', 'driver-only-in-db', 'identity-only-in-db']) assert.match(rules, new RegExp('dayonegreat\\.db\\.' + id), id + ' also runs in Semgrep');
});

test('S8: every database call says who is acting, and the combination must make sense', async () => {
  const m = '018f3c2e-7b1a-7cde-8f00-0123456789ab';
  const a = '018f3c2e-7b1a-7cde-9f00-0123456789ab';
  for (const bad of [undefined, null, {}, { actor: 'root' }, { actor: 'member' }, { actor: 'anon', memberId: m },
    { actor: 'agent', memberId: m }, { actor: 'member', memberId: m, agentId: a }, { actor: 'system', memberId: m },
    { actor: 'member', memberId: 'not-an-id' }, { actor: 'member', memberId: "x' or '1'='1" }]) {
    let reached = false;
    await assert.rejects(db.tx({ begin: async () => { reached = true; } }, bad, () => {}), (e) => !reached && /acting|actor|ID|must/.test(e.message), JSON.stringify(bad));
  }
  let reached = false;
  await db.tx({ begin: async () => { reached = true; } }, { actor: 'member', memberId: m }, () => {});
  assert.ok(reached, 'a valid actor does reach the database');
});

test('S8: inputs are type-checked, size-limited and normalized, and errors never echo the value', () => {
  assert.strictEqual(v.text('n', '  Aaron  ', { max: 80 }), 'Aaron');
  assert.strictEqual(v.text('n', 'Café', { max: 4 }), 'Café'); // NFC: 5 code points become 4
  assert.strictEqual(v.text('n', '😀'.repeat(80), { max: 80 }).length, 160); // counts characters, not UTF-16 units
  for (const [value, re] of [[42, /must be text/], ['', /required/], ['   ', /required/], ['x'.repeat(81), /too long/],
    ['x'.repeat(10000), /too long/], ['a\u0000b', /control/], ['a\u001bb', /control/], ['\ud800', /not valid/]]) {
    assert.throws(() => v.text('displayName', value, { max: 80 }), (e) => e instanceof v.ValidationError && re.test(e.message) && (String(value).trim().length < 3 || !e.message.includes(String(value).slice(0, 3))));
  }
  for (const hidden of ['a\nb', 'a\rb', 'a\tb', 'a\u0085b', 'a\u202eb', 'a\u2066b', 'a\u200bb', 'a\ufeffb']) {
    assert.throws(() => v.text('displayName', hidden, { max: 80 }), v.ValidationError, JSON.stringify(hidden));
  }
  assert.strictEqual(v.text('n', '👨\u200d👩\u200d👧', { max: 9 }), '👨\u200d👩\u200d👧', 'emoji joiners are allowed');
  assert.strictEqual(v.text('post', 'line one\nline two', { max: 99, multiline: true }), 'line one\nline two');
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
  assert.throws(() => v.object('d', { toJSON() {} }, { maxBytes: 100 }), v.ValidationError);
  assert.throws(() => v.object('d', { s: 'a\u0000b' }, { maxBytes: 100 }), v.ValidationError);
});

test('migration files are numbered without gaps and never edited after they ship', () => {
  const files = fs.readdirSync(path.join(root, 'db', 'migrations'));
  files.forEach((f, i) => assert.match(f, new RegExp('^' + String(i + 1).padStart(3, '0') + '_[a-z0-9_]+\\.sql$')));
});

test('S8: a size limit counts only if it actually binds', () => {
  const { limited } = require('../db/checks');
  const ok = (def, col = 'note') => limited({ col, type: 'text', checks: [def] });
  assert.ok(ok('CHECK ((char_length(note) <= 80))'));
  assert.ok(ok('CHECK (((char_length(note) >= 1) AND (char_length(note) <= 80)))'));
  assert.ok(ok("CHECK (((jsonb_typeof(note) = 'object'::text) AND (octet_length((note)::text) <= 4096)))"));
  assert.ok(ok("CHECK ((note = ANY (ARRAY['a'::text, 'b'::text])))"));
  for (const def of ['CHECK ((NOT (char_length(note) <= 10)))', 'CHECK (CASE WHEN true THEN true ELSE (char_length(note) <= 10) END)',
    'CHECK (((char_length(note) <= 80) OR true))', 'CHECK ((char_length(note) <= 999999999))', 'CHECK (((char_length(note) <= 10) = false))',
    'CHECK ((char_length(note) >= 1))', 'CHECK (((char_length(note) <= 10) IS NOT FALSE))', 'CHECK ((char_length(other) <= 10))',
    'CHECK ((COALESCE(char_length(note), 0) <= 10))']) assert.ok(!ok(def), def);
});

// ---- Tests against a real database -----------------------------------------------------------------------------

if (!SERVER) {
  if (process.env.CI) test('database tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set, so S1, S7 and S8 were not checked'));
  else test('database tests (S1, S3, S7, S8, G3, G4)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const OWNER = NAME + '_owner';
const WEB_PASSWORD = crypto.randomBytes(18).toString('base64url');
const OWNER_PASSWORD = crypto.randomBytes(18).toString('base64url');
const at = (base, { db: d, user, password } = {}) => {
  const u = new URL(base);
  if (d) u.pathname = '/' + d;
  if (user) { u.username = user; u.password = password || ''; }
  return u.toString();
};
let server; // a superuser on the server, for setup only
let admin; // the migration login: not a superuser, but may create roles, as on Supabase and Neon
let su; // a superuser on the test database: the attacker with every right
let web; // the site's login role on the test database, as in production
let one; // the same login with a single connection, to prove nothing carries between transactions

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server`select 1`;
  // How Supabase and Neon set things up: the main login can create roles and owns the database, but is not a superuser.
  await server.unsafe(`create role ${OWNER} login createrole nosuperuser password '${OWNER_PASSWORD}'`);
  await server.unsafe(`create database ${NAME} owner ${OWNER}`);
  // On a server where an earlier run already made the roles, the migration login is given the admin right over
  // them that it would have had as their creator. On a fresh server (CI) it creates them itself.
  for (const r of await server`select rolname from pg_roles where rolname in ('dog_owner', 'dog_app', 'dog_signin', 'dog_public', 'dog_limits')`) await server.unsafe(`grant ${r.rolname} to ${OWNER} with admin true, inherit false, set false`);
  admin = postgres(at(SERVER, { db: NAME, user: OWNER, password: OWNER_PASSWORD }), { max: 2, ssl: false, onnotice: () => {} });
  su = postgres(at(SERVER, { db: NAME }), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(admin);
  // Production setup (db/README.md): a login role with no rights of its own that may switch to dog_app.
  await admin.unsafe(`create role ${WEB} login noinherit password '${WEB_PASSWORD}'`);
  await admin.unsafe(`grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, { db: NAME, user: WEB, password: WEB_PASSWORD }), { ssl: false, max: 3 });
  one = db.connect(at(SERVER, { db: NAME, user: WEB, password: WEB_PASSWORD }), { ssl: false, max: 1 });
});

test.after(async () => {
  for (const c of [web, one, admin, su]) if (c) await c.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    // Role grants the migration login made name it as grantor; hand them to the superuser first, then drop it.
    for (const g of await server`select r.rolname as role, m.rolname as member from pg_auth_members a join pg_roles r on r.oid = a.roleid join pg_roles m on m.oid = a.member where a.grantor = (select oid from pg_roles where rolname = ${OWNER})`) {
      await server.unsafe(`revoke ${g.role} from ${g.member} granted by ${OWNER} cascade`).catch(() => {});
      if (g.member !== OWNER) await server.unsafe(`grant ${g.role} to ${g.member}`);
    }
    await server.unsafe(`drop role if exists ${OWNER}`);
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

test('S1: the coverage check passes on the database the migrations build, which matches the reviewed snapshot', async () => {
  assert.deepStrictEqual(await problems(admin, { snapshot: SNAPSHOT }), [], 'if a migration changed on purpose, run npm run db:snapshot and review the diff');
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
    ['alter table app.audit_log disable trigger audit_log_no_change', /audit_log_no_change is not set to fire always/],
    ['create table app.t4 (id bigserial primary key)', /counter|uuid/],
    ['create table app.t5 (id uuid primary key default app.uuid_v7(), note text); alter table app.t5 enable row level security; alter table app.t5 force row level security', /app\.t5\.note has no size limit/],
    ['create table app.t6 (id uuid primary key default app.uuid_v7(), note text check (char_length(note) >= 1)); alter table app.t6 enable row level security; alter table app.t6 force row level security', /app\.t6\.note has no size limit/],
    ['create table app.t7 (id uuid primary key default app.uuid_v7(), passport_number text check (char_length(passport_number) <= 9)); alter table app.t7 enable row level security; alter table app.t7 force row level security', /ID document/],
    ['create function app.f1() returns int language sql security definer as $$ select 1 $$', /security definer/],
    ['set local role dog_owner; grant create on schema app to dog_signin; set local role dog_signin; create function app.session_end(p integer) returns void language sql security definer set search_path = pg_catalog as $$ select $$', /app\.session_end\(integer\) runs with its owner's rights/],
    // Found by the independent review of Oct 15: each of these passed the first version of the check.
    ['grant dog_owner to dog_app', /dog_app belongs to dog_owner/],
    ['grant pg_write_all_data to dog_app', /dog_app belongs to pg_write_all_data/],
    ['grant update, delete, truncate on app.audit_log to dog_app', /more rights on the audit log/],
    ['grant insert (at, id) on app.audit_log to dog_app', /can set audit log columns/],
    [`alter role ${WEB} bypassrls`, new RegExp(WEB + ' \\(which the site signs in as\\) can bypass')],
    [`grant dog_owner to ${WEB}`, new RegExp(WEB + ' \\(which the site signs in as\\) also belongs to dog_owner')],
    ['create schema side; create table side.t (id bigserial, note text); grant all on side.t to dog_app', /dog_app can reach side\.t/],
    ['create schema side2; create table side2.t (n int); grant select on side2.t to dog_app', /dog_app can reach side2\.t/],
    ['grant create on schema public to dog_app', /dog_app can create objects in schema public/],
    ['set local role dog_owner; create policy audit_extra on app.audit_log for select to dog_app using (true)', /it must have exactly audit_insert, audit_insert_signin, audit_select/],
    ['set local role dog_owner; drop policy audit_select on app.audit_log; create policy audit_select on app.audit_log for select to dog_app using (true)', /audit_select differs/],
    ['alter table app.audit_log enable trigger audit_log_no_change', /not set to fire always/],
    [`set local role dog_owner; create or replace function app.audit_log_append_only() returns trigger language plpgsql as $$ begin return null; end $$`, /no longer refuses/],
    ['set local role dog_owner; drop trigger audit_log_no_change on app.audit_log; create trigger audit_log_no_change before insert on app.audit_log for each statement execute function app.audit_log_append_only(); alter table app.audit_log enable always trigger audit_log_no_change', /no longer runs before every update/],
    ['alter table app.members disable trigger members_guard', /members_guard/],
    ['set local role dog_owner; create policy members_select2 on app.members for select to dog_app using (true)', /2 permissive policies/],
    ...[['text[]', /is an array/], ['xml', /has no size limit/], ['text check (char_length(note) <= 999999999)', /has no size limit/],
      ['text check (char_length(note) <= 80 or true)', /has no size limit/], ['varchar', /has no size limit/]
    ].map(([type, re]) => [`set local role dog_owner; create table app.c (id uuid primary key default app.uuid_v7(), note ${type}); alter table app.c enable row level security; alter table app.c force row level security`, re]),
    ['set local role dog_owner; create table app.k1 (post_no bigint primary key); alter table app.k1 enable row level security; alter table app.k1 force row level security', /k1\.post_no is a key/],
    ['set local role dog_owner; create table app.k2 (post_id uuid primary key default gen_random_uuid()); alter table app.k2 enable row level security; alter table app.k2 force row level security', /k2\.post_id is a key/],
    ['set local role dog_owner; create table app.k3 (id uuid primary key default app.uuid_v7(), m int, n int unique); alter table app.k3 add foreign key (m) references app.k3 (n); alter table app.k3 enable row level security; alter table app.k3 force row level security', /k3\.m points at another record/],
    ['set local role dog_owner; create function app.f2() returns int language sql as $$ select 1 $$; grant execute on function app.f2() to public', /app\.f2 can be called by every role/],
    ['create function app.f3() returns int language sql as $$ select 1 $$', /app\.f3 (can be called by every role|is owned by postgres)/],
    [`grant temporary on database ${NAME} to public`, /temporary tables/],
    // Found by the second review round, Oct 15.
    ['alter table app.members enable replica trigger members_guard', /members_guard is not set to fire always/],
    ['set local role dog_owner; drop trigger audit_log_no_change on app.audit_log; create trigger audit_log_no_change before update or delete on app.audit_log for each statement when (current_setting(\'x.go\', true) is distinct from \'yes\') execute function app.audit_log_append_only(); alter table app.audit_log enable always trigger audit_log_no_change', /audit_log_no_change no longer runs .* without conditions/],
    ['set local role dog_owner; alter policy members_select on app.members using (true)', /not in the reviewed snapshot: policy app\.members members_select/],
    ['set local role dog_owner; alter policy members_insert on app.members with check (true)', /not in the reviewed snapshot: policy app\.members members_insert/],
    ["set local role dog_owner; alter table app.audit_log alter column at set default '2001-01-01'", /not in the reviewed snapshot: default app\.audit_log\.at/],
    ['set local role dog_owner; create or replace function app.members_guard() returns trigger language plpgsql as $$ begin return new; end $$', /no longer refuses the change|not in the reviewed snapshot: function app\.members_guard/],
    ['create schema side3; create table side3.t (n int); grant usage on schema side3 to public; grant select on side3.t to public', /dog_app can reach side3\.t/],
    // PR 2: the sign-in role and its functions.
    ['grant dog_signin to dog_app', /dog_app belongs to dog_signin/],
    [`grant dog_signin to ${WEB}`, new RegExp(WEB + ' can act as dog_signin|' + WEB + ' \\(which the site signs in as\\) also belongs to dog_signin')],
    ['grant create on schema app to dog_signin', /dog_signin can create objects in schema app/],
    ['alter role dog_signin login', /dog_signin can sign in directly/],
    ['grant execute on function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid) to public', /app\.sign_in can be called by every role/],
    ['alter function app.session_resolve(text, integer) reset search_path', /app\.session_resolve must fix its search path/],
    ['set local role dog_owner; create function app.f4() returns int language sql security definer set search_path = pg_catalog as $$ select 1 $$', /app\.f4\(\) runs with its owner's rights/],
    ['set local role dog_owner; create policy members_public on app.members for select to public using (false)', /members_public applies to every role/],
    ['grant select on app.sessions to dog_app', /not in the reviewed snapshot: grant app\.sessions dog_app SELECT/],
    ['grant update (is_admin) on app.members to dog_signin', /not in the reviewed snapshot: grant app\.members\.is_admin dog_signin UPDATE/]
  ];
  for (const [ddl, expect] of cases) {
    const found = await su.begin(async (t) => {
      await t.unsafe(ddl);
      const p = await problems(t, { snapshot: SNAPSHOT });
      throw Object.assign(new Error('rollback'), { found: p });
    }).catch((e) => { if (!e.found) throw e; return e.found; });
    assert.ok(found.some((p) => expect.test(p)), ddl + '\n  expected a problem matching ' + expect + '\n  got: ' + JSON.stringify(found));
  }
  assert.deepStrictEqual(await problems(admin), [], 'every case rolled back');
  // Settings that should be allowed: the trigger set to fire always, and a limit written as varchar(n).
  const ok = await su.begin(async (t) => {
    await t.unsafe('set local role dog_owner; create table app.ok1 (id uuid primary key default app.uuid_v7(), code varchar(12), n numeric(10, 2), other uuid references app.members (id)); alter table app.ok1 enable row level security; alter table app.ok1 force row level security');
    // Found while building PR 2: a function created later is not callable by everyone, with no grant needed.
    await t.unsafe('set local role dog_owner; create function app.ok_f() returns int language sql as $$ select 1 $$');
    throw Object.assign(new Error('rollback'), { found: await problems(t) });
  }).catch((e) => { if (!e.found) throw e; return e.found; });
  assert.deepStrictEqual(ok, [], 'a well-formed table passes');
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
  await as(member(a.id), (t) => audit.record(t, { action: 'test.member_did_something', subjectKind: 'member', subjectId: a.id, detail: { n: 1 } }));
  assert.strictEqual((await as(member(a.id), (t) => t`select id from app.audit_log`)).length, 0, 'members cannot read the log');
  const [row] = await as(AARON(aaron.id), (t) => t`select id, actor_kind, actor_id, action, at from app.audit_log where subject_id = ${a.id} and action = 'test.member_did_something'`);
  assert.deepStrictEqual({ actor_kind: row.actor_kind, actor_id: row.actor_id, action: row.action }, { actor_kind: 'member', actor_id: a.id, action: 'test.member_did_something' });
  assert.ok(Math.abs(row.at - Date.now()) < 60000, 'the database stamps the time');
  const id = row.id;

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
    `truncate app.audit_log`,
    `set local session_replication_role = replica; delete from app.audit_log`,
    `set local session_replication_role = replica; truncate app.audit_log`
  ]) await fails(su.begin((t) => t.unsafe(stmt)), /append-only/);
  for (const stmt of [`set local role dog_owner; update app.audit_log set action = 'test.rewritten'`, `set local role dog_owner; truncate app.audit_log`]) {
    await fails(admin.begin((t) => t.unsafe(stmt)), /append-only/);
  }
  const [still] = await as(AARON(aaron.id), (t) => t`select action from app.audit_log where id = ${id}`);
  assert.strictEqual(still.action, 'test.member_did_something');
});

// PR 5 decided what an agent sees (001 left it open): its own owner's row, read-only, because posting checks the
// author's level and status. Nothing of any other member, and it can change nothing.
test('S3: an agent acting for its owner reads only its owner\'s row and can\'t change it', async () => {
  const owner = await newMember('Agent owner');
  const other = await newMember('Someone else');
  const agent = { actor: 'agent', memberId: owner.id, agentId: '018f3c2e-7b1a-7cde-9f00-0123456789ab' };
  assert.strictEqual((await as(agent, (t) => members.get(t, owner.id))).display_name, 'Agent owner');
  assert.strictEqual(await as(agent, (t) => members.get(t, other.id)), null);
  assert.strictEqual((await as(agent, (t) => t`select id from app.members`)).length, 1);
  assert.strictEqual(await as(agent, (t) => members.rename(t, owner.id, 'Renamed by my agent')), false);
  assert.strictEqual((await as(member(owner.id), (t) => members.get(t, owner.id))).display_name, 'Agent owner');
  // An agent's audit rows name the agent, not the owner.
  await as(agent, (t) => audit.record(t, { action: 'test.agent_acted' }));
  const aaron = await newMember('Aaron, agents');
  const [r] = await as(AARON(aaron.id), (t) => t`select actor_kind, actor_id from app.audit_log where action = 'test.agent_acted'`);
  assert.deepStrictEqual({ ...r }, { actor_kind: 'agent', actor_id: agent.agentId });
});

test('S1: nothing a request makes outlives its transaction on a pooled connection', async () => {
  await fails(as(SYSTEM, (t) => t`create temp table leak as select * from app.members`, one), /permission denied/);
  // A cursor kept open past its transaction, or a session lock, is cleared before the next request starts.
  const aaron = await newMember('Aaron, cursors');
  await as(AARON(aaron.id), async (t) => { await t`declare leak cursor with hold for select id, display_name from app.members`; await t`select pg_advisory_lock(42)`; }, one);
  await fails(as(ANON, (t) => t`fetch all from leak`, one), /cursor "leak" does not exist/);
  const [{ held }] = await as(ANON, (t) => t`select count(*)::int as held from pg_locks where locktype = 'advisory' and pid = pg_backend_pid()`, one);
  assert.strictEqual(held, 0);
});


test('S7: nobody can write an audit row in someone else\'s name', async () => {
  const a = await newMember('Member E');
  const b = await newMember('Member F');
  await fails(as(member(a.id), (t) => t`insert into app.audit_log (actor_kind, actor_id, action) values ('admin', ${a.id}, 'test.forged')`), /row-level security|permission denied/);
  await fails(as(member(a.id), (t) => t`insert into app.audit_log (actor_kind, actor_id, action) values ('member', ${b.id}, 'test.forged')`), /row-level security|permission denied/);
  await fails(as(ANON, (t) => t`insert into app.audit_log (actor_kind, actor_id, action) values ('anon', ${b.id}, 'test.forged')`), /row-level security|permission denied/);
  // Second lock: even if a later change granted those columns, the policy still refuses a row in another's name.
  const blocked = await su.begin(async (t) => {
    await t.unsafe('grant insert (actor_kind, actor_id) on app.audit_log to dog_app');
    await t`set local role dog_app`;
    await t`select set_config('app.actor', 'member', true), set_config('app.member_id', ${a.id}, true)`;
    await t`insert into app.audit_log (actor_kind, actor_id, action) values ('member', ${b.id}, 'test.forged')`;
  }).then(() => 'inserted', (e) => e.message);
  assert.match(blocked, /row-level security/);
  // The ID, the time and who acted can't be chosen at all.
  await fails(as(member(a.id), (t) => t`insert into app.audit_log (at, action) values ('2001-01-01', 'test.backdated')`), /permission denied/);
  await fails(as(member(a.id), (t) => t`insert into app.audit_log (id, action) values ('00000000-0000-7000-8000-000000000000', 'test.chosen_id')`), /permission denied/);
  await fails(as(SYSTEM, (t) => t`insert into app.members (id, display_name) values ('00000000-0000-7000-8000-000000000000', 'Chosen')`), /permission denied/);
  await fails(as(SYSTEM, (t) => t`insert into app.members (display_name, trust_level) values ('Self-promoted', 3)`), /permission denied/);
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
    for (const f of fs.readdirSync(path.join(root, 'db', 'migrations'))) fs.copyFileSync(path.join(root, 'db', 'migrations', f), path.join(dir, f));
    fs.appendFileSync(path.join(dir, '001_foundation.sql'), '\n-- edited\n');
    await assert.rejects(migrate(admin, { dir }), /changed after it was applied/);
    fs.writeFileSync(path.join(dir, '009_skip.sql'), 'select 1;');
    await assert.rejects(migrate(admin, { dir }), /no gaps/);
    fs.rmSync(path.join(dir, '009_skip.sql'));
    fs.copyFileSync(path.join(root, 'db', 'migrations', '001_foundation.sql'), path.join(dir, '001_foundation.sql'));
    fs.renameSync(path.join(dir, '002_signin.sql'), path.join(dir, '002_renamed.sql'));
    await assert.rejects(migrate(admin, { dir }), /missing from the repository: 002_signin/);
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
