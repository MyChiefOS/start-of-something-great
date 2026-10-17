// The backup restore test (scripts/restore-test.js, O2, RK12), run for real: a source database built from the
// migrations and given some rows is copied into a throwaway one, and every table must match.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const { migrate } = require('../scripts/migrate');
const r = require('../scripts/restore-test');

const SERVER = process.env.TEST_DATABASE_URL;

test('differences names every table whose count doesn’t match, including missing ones', () => {
  assert.deepStrictEqual(r.differences({ a: 1, b: 2 }, { a: 1, b: 2 }), []);
  assert.deepStrictEqual(r.differences({ a: 1, b: 2, c: 0 }, { a: 1, b: 3 }), ['b: live 2, restored 3', 'c: live 0, restored missing']);
});

test('connection details go to the tools as environment variables, never on a command line', () => {
  const e = r.pgEnv('postgresql://postgres.ref:p%40ss@aws-0-us-east-1.pooler.supabase.com:5432/postgres');
  assert.deepStrictEqual(e, { PGHOST: 'aws-0-us-east-1.pooler.supabase.com', PGPORT: '5432', PGUSER: 'postgres.ref', PGPASSWORD: 'p@ss', PGDATABASE: 'postgres' });
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'scripts', 'restore-test.js'), 'utf8');
  assert.ok(!/'--dbname=' \+ (sourceUrl|targetUrl)\b/.test(src), 'no address on a command line');
  assert.ok(!/upload-artifact/.test(require('fs').readFileSync(require('path').join(__dirname, '..', '.github', 'workflows', 'restore-test.yml'), 'utf8')), 'the copy is never uploaded');
});

if (!SERVER) {
  if (process.env.CI) test('restore tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('restore test against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const SRC = 'dog_restore_src_' + crypto.randomBytes(4).toString('hex');
const DST = 'dog_restore_dst_' + crypto.randomBytes(4).toString('hex');
const at = (d) => { const u = new URL(SERVER); u.pathname = '/' + d; return u.toString(); };
let server;

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + SRC);
  await server.unsafe('create database ' + DST);
});
test.after(async () => {
  for (const d of [SRC, DST]) await server.unsafe(`drop database if exists ${d} with (force)`);
  await server.end({ timeout: 5 });
});

test('a live database with rows restores into a throwaway one: every table’s count matches, and the check passes', async () => {
  const src = postgres(at(SRC), { max: 1, ssl: false, onnotice: () => {} });
  try {
    await migrate(src);
    const ids = [crypto.randomUUID(), crypto.randomUUID()];
    await src`insert into app.members (id, display_name, trust_level) values (${ids[0]}, 'Ada', 2), (${ids[1]}, 'Grace', 1)`;
  } finally { await src.end({ timeout: 5 }); }
  const lines = [];
  const out = await r.restoreTest({ sourceUrl: at(SRC), targetUrl: at(DST), log: (m) => lines.push(m), check: r.defaultCheck });
  assert.ok(out.tables > 10, 'every app table was compared: ' + out.tables);
  assert.ok(out.rows >= 2, 'the rows came across: ' + out.rows);
  const dst = postgres(at(DST), { max: 1, ssl: false, onnotice: () => {} });
  try {
    const names = (await dst`select display_name from app.members order by display_name`).map((x) => x.display_name);
    assert.ok(names.includes('Ada') && names.includes('Grace'), 'the very same rows: ' + names);
  } finally { await dst.end({ timeout: 5 }); }
  assert.ok(lines.some((l) => /row counts match in all \d+ tables/.test(l)));
  assert.ok(!lines.join('\n').includes('localtest'), 'no password in the log');
});

test('a restore that comes out short is reported as a failure, never as a pass', async () => {
  // A row lost on the way in (simulated after the copy loads) must fail the test.
  const lose = async (t) => { await t`delete from app.members where display_name = 'Grace'`; };
  await assert.rejects(r.restoreTest({ sourceUrl: at(SRC), targetUrl: at(DST), log: () => {}, check: r.defaultCheck, afterRestore: lose }),
    /the restored copy differs:\n- members: live 2, restored 1/);
});
