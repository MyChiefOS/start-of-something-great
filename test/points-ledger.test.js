// 048, the append-only points ledger: every change to a citizen's points is a new row, never an edit, in two buckets
// (pending, final), so the points can back payments later. Needs TEST_DATABASE_URL (skipped without it, required in CI).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const { migrate } = require('../scripts/migrate');

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('ledger tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the points ledger against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_ledger_test_' + crypto.randomBytes(4).toString('hex');
let server, su;
const q = (s) => su.unsafe(s);
const at = (base, d) => { const u = new URL(base); u.pathname = '/' + d; return u.toString(); };

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
});
test.after(async () => {
  if (su) await su.end({ timeout: 5 });
  if (server) { await server.unsafe(`drop database if exists ${NAME} with (force)`); await server.end({ timeout: 5 }); }
});

// A member and one passed piece of work with 12 points, as the work module writes them (as dog_work).
async function pass(name, status = 'pending') {
  const [m] = await q(`insert into app.members (display_name) values ('${name}') returning id`);
  const [r] = await q(`select id from app.work_rooms where code = '15-0000'`);
  const [pj] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('P', '${r.id}', 'member', '${m.id}') returning id`);
  const [tk] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, status) values ('${pj.id}', '${r.id}', 'T', 'either', 3, 'member', '${m.id}', 'approved') returning id`);
  const [sb] = await q(`insert into app.work_submissions (task_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, decided_by, decided_at, confidence)
    values ('${tk.id}', 'member', '${m.id}', 'link', 'https://example.org/l', decode(repeat('ab', 32), 'hex'), repeat('d', 64), 'passed', 'jevs', now(), 100) returning id`);
  const [p] = await su.begin(async (t) => {
    await t.unsafe('set local role dog_work');
    return t.unsafe(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, size, confidence, independence, points, status, final_at)
      values ('${sb.id}', '${tk.id}', '${r.id}', 'member', '${m.id}', 3, 100, 100, 12, '${status}', now() + interval '3 days') returning id`);
  });
  return { member: m.id, points: p.id };
}
const rows = async (pid) => (await q(`select kind, bucket, amount from app.work_point_entries where points_id = '${pid}' order by at, kind, bucket desc`)).map((r) => [r.kind, r.bucket, r.amount]);
const balance = async (mid) => Object.fromEntries((await q(`select bucket, sum(amount)::int as s from app.work_point_entries where citizen_member = '${mid}' group by bucket`)).map((r) => [r.bucket, r.s]));
const asWork = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_work'); return t.unsafe(sql); });

test('a pass, its dispute window ending, and a reversal after it: each a new row; the final bucket can go below zero', async () => {
  const a = await pass('LedgerAda');
  assert.deepStrictEqual(await rows(a.points), [['earned', 'pending', 12]]);
  await asWork(`update app.work_points set status = 'final' where id = '${a.points}'`);
  assert.deepStrictEqual(await rows(a.points), [['earned', 'pending', 12], ['final', 'pending', -12], ['final', 'final', 12]]);
  await asWork(`update app.work_points set status = 'removed' where id = '${a.points}'`);
  assert.deepStrictEqual((await rows(a.points)).slice(-1), [['reversed', 'final', -12]]);
  assert.deepStrictEqual(await balance(a.member), { pending: 0, final: 0 });
  // A reversal of pending points takes them out of pending.
  const b = await pass('LedgerBo');
  await asWork(`update app.work_points set status = 'removed' where id = '${b.points}'`);
  assert.deepStrictEqual(await rows(b.points), [['earned', 'pending', 12], ['reversed', 'pending', -12]]);
});

test('no edits and no deletes, by anyone; points change only by a new row; deleting an account deletes its rows', async () => {
  const a = await pass('LedgerCy');
  for (const sql of [`update app.work_point_entries set amount = 99 where points_id = '${a.points}'`, `delete from app.work_point_entries where points_id = '${a.points}'`, 'truncate app.work_point_entries cascade']) {
    await assert.rejects(q(sql), /append-only/, sql);
    await assert.rejects(asWork(sql), /append-only|permission denied/, sql);
  }
  await assert.rejects(asWork(`update app.work_points set points = 99 where id = '${a.points}'`), /only by a new row/);
  await asWork(`update app.work_points set status = 'removed' where id = '${a.points}'`);
  await assert.rejects(asWork(`update app.work_points set status = 'final' where id = '${a.points}'`), /can't go from removed to final/);
  await q(`delete from app.members where id = '${a.member}'`);
  assert.strictEqual((await q(`select count(*)::int as n from app.work_point_entries where citizen_member = '${a.member}'`))[0].n, 0);
});
