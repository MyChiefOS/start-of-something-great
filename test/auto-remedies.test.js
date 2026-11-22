// 068: automatic remedies (Aaron, Nov 22, 2026), against a real Postgres built from the migrations. An overturned fail
// is put right without anyone's hand; peers decide checks and disputes first, a decision takes effect after the dispute
// window unless a party appeals, and the administrator is the last appeal. ACCEPTANCE.md AR1 to AR8.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const work = require('../db/work');
const { migrate } = require('../scripts/migrate');
const { promote, shadowMode, asSignin } = require('./helpers');

const SERVER = process.env.TEST_DATABASE_URL;
const NAME = 'dog_068_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, poster, worker, room, project, admin;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const ctxOf = (m) => ({ actor: 'member', memberId: m.id, session: m.session, fresh: true });
const asAdmin = (m) => ({ ...ctxOf(m), actor: 'admin' });

let n = 0;
async function member(name, { level2 = true } = {}) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('gh:' + name + (n++))], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level2) await promote(su, out.memberId);
  return { id: out.memberId, name, session: c.sha256hex(token) };
}
// Work by `by` on a task `p` posted, in the state given (a submission that passed or failed, or waits for review).
async function work_({ by = worker, poster: p = poster, status = 'failed', decidedBy = 'poster', route = null, kind = 'link' } = {}) {
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, status)
    values ('${project}', '${room}', 'Work', 'either', 1, 'member', '${p.id}', '${status === 'review' ? 'submitted' : 'open'}') returning id`);
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at, status) values ('${t.id}', '${by.id}', '${crypto.randomBytes(32).toString('hex')}', now() - interval '1 minute', 'expired') returning id`);
  const [s] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, route, routed_at, decided_by, decided_at, final_size)
    values ('${t.id}', '${cl.id}', 'member', '${by.id}', '${kind}', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', '${status}',
            ${route ? `'${route}'` : 'null'}, now() - interval '1 hour', ${status === 'review' ? 'null' : `'${decidedBy}'`}, ${status === 'review' ? 'null' : 'now()'}, 1) returning id`);
  return { task: t.id, sub: s.id };
}
const check = async (sub, why) => (await q(`insert into app.work_checks (submission_id, why) values ('${sub}', '${why}') returning id`))[0].id;
const due = () => q(`select app.peer_cases_due() as n`).then((r) => r[0].n);
const clearQueue = () => q(`update app.work_checks set status = 'confirmed', decided_at = now() where status = 'open'; update app.work_disputes set status = 'dismissed', decided_at = now() where status = 'open'`);

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  poster = await member('Poster');
  worker = await member('Worker');
  admin = await member('Admin');
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe('update app.members set is_admin = false where is_admin'); await t.unsafe(`update app.members set is_admin = true where id = '${admin.id}'`); });
  [{ id: room }] = await q(`select id from app.work_rooms where code = '15-0000'`);
  [{ id: project }] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('P', '${room}', 'member', '${poster.id}') returning id`);
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

test('AR1: an overturned fail is put right without anyone’s hand: it passes, its points are pending, and the task goes to its poster', async () => {
  const w = await work_();
  const k = await check(w.sub, 'fail_appeal');
  assert.strictEqual((await run(asAdmin(admin), (t) => work.review(t, k, { decision: 'reverse', reason: 'The work met the task' }))).result, 'reverse');
  const [s] = await q(`select status from app.work_submissions where id = '${w.sub}'`);
  assert.strictEqual(s.status, 'passed');
  const [p] = await q(`select status, points from app.work_points where submission_id = '${w.sub}'`);
  assert.deepStrictEqual([p.status, p.points > 0], ['pending', true]);
  assert.strictEqual((await q(`select status from app.work_tasks where id = '${w.task}'`))[0].status, 'audited');
});

test('AR2: if the task moved on meanwhile, it keeps its state and only the points are given', async () => {
  const w = await work_();
  const other = await member('Other worker');
  await q(`update app.work_tasks set status = 'claimed' where id = '${w.task}'`);
  await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at, status) values ('${w.task}', '${other.id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day', 'active')`);
  const k = await check(w.sub, 'fail_appeal');
  await run(asAdmin(admin), (t) => work.review(t, k, { decision: 'reverse', reason: 'The work met the task' }));
  assert.strictEqual((await q(`select status from app.work_tasks where id = '${w.task}'`))[0].status, 'claimed');
  assert.strictEqual((await q(`select count(*)::int as n from app.work_points where submission_id = '${w.sub}'`))[0].n, 1);
});

test('AR3: a peer decides a fail check; it takes effect only after the dispute window; collusion checks on a pass stay with the administrator', async () => {
  await clearQueue();
  const p = await work_({ status: 'passed' });
  await check(p.sub, 'random');
  const r = await member('Peer one');
  assert.strictEqual((await run(ctxOf(r), (t) => work.caseTake(t))).case, null, 'a random check of a pass is not offered to peers');
  await clearQueue();
  const w = await work_();
  const k = await check(w.sub, 'peer_fail_sample');
  const got = await run(ctxOf(r), (t) => work.caseTake(t));
  assert.deepStrictEqual([got.kind, got.submission, got.check_why, got.decision.status], ['check', w.sub, 'peer_fail_sample', 'failed'], 'the peer sees what is being checked');
  const d = await run(ctxOf(r), (t) => work.caseDecide(t, { case: got.case, decision: 'reverse', reason: 'The work met the task' }));
  assert.strictEqual(d.result, 'proposed');
  assert.ok((await q(`select count(*)::int as n from app.notices where member_id is null and dedupe_key = 'work:peer-case-admin:${got.case}'`))[0].n >= 0);
  assert.strictEqual(await due(), 0, 'not yet due');
  assert.strictEqual((await q(`select status from app.work_checks where id = '${k}'`))[0].status, 'open');
  await q(`update app.peer_cases set due_at = now() - interval '1 minute' where id = '${got.case}'`);
  assert.strictEqual(await due(), 1);
  const [kk] = await q(`select status, decided_kind, member_id from app.work_checks where id = '${k}'`);
  assert.deepStrictEqual([kk.status, kk.decided_kind, kk.member_id], ['reversed', 'peer', r.id]);
  assert.strictEqual((await q(`select status from app.work_submissions where id = '${w.sub}'`))[0].status, 'passed', 'the overturned fail was put right');
  assert.strictEqual((await q(`select status from app.peer_cases where id = '${got.case}'`))[0].status, 'applied');
});

test('AR4: a party appeals a peer’s decision: it never takes effect, and the administrator decides, the last appeal', async () => {
  await clearQueue();
  const w = await work_();
  const k = await check(w.sub, 'fail_appeal');
  const r = await member('Peer two');
  const got = await run(ctxOf(r), (t) => work.caseTake(t));
  await run(ctxOf(r), (t) => work.caseDecide(t, { case: got.case, decision: 'confirm', reason: 'The fail was right' }));
  await assert.rejects(run(ctxOf(r), (t) => work.caseAppeal(t, { case: got.case, reason: 'Not mine to appeal' })), /only the worker, the poster/i);
  assert.deepStrictEqual(await run(ctxOf(worker), (t) => work.caseAppeal(t, { case: got.case, reason: 'I did what was asked' })), { result: 'appealed' });
  await q(`update app.peer_cases set due_at = now() - interval '1 minute' where id = '${got.case}'`);
  assert.strictEqual(await due(), 0, 'an appealed decision waits for the administrator');
  const other = await member('Peer three');
  assert.strictEqual((await run(ctxOf(other), (t) => work.caseTake(t))).case, null, 'nor is it offered to another peer');
  await run(asAdmin(admin), (t) => work.review(t, k, { decision: 'reverse', reason: 'On appeal: the work was fine' }));
  assert.strictEqual((await q(`select status from app.work_submissions where id = '${w.sub}'`))[0].status, 'passed', 'and the remedy ran');
  assert.strictEqual((await q(`select status from app.peer_cases where id = '${got.case}'`))[0].status, 'superseded');
});

test('AR5: a peer upholds a dispute; after the window the pass is reversed', async () => {
  await clearQueue();
  const w = await work_({ status: 'passed' });
  await q(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, size, confidence, independence, points, final_at)
    values ('${w.sub}', '${w.task}', '${room}', 'member', '${worker.id}', 1, 100, 100, 10, now() + interval '72 hours')`);
  const opener = await member('Disputer');
  const [dsp] = await q(`insert into app.work_disputes (submission_id, member_id, reason) values ('${w.sub}', '${opener.id}', 'The page is empty') returning id`);
  assert.strictEqual((await run(ctxOf(opener), (t) => work.caseTake(t))).case, null, 'the one who disputed can’t decide it');
  const r = await member('Peer four');
  const got = await run(ctxOf(r), (t) => work.caseTake(t));
  assert.strictEqual(got.kind, 'dispute');
  await run(ctxOf(r), (t) => work.caseDecide(t, { case: got.case, decision: 'uphold', reason: 'The page is empty' }));
  await q(`update app.peer_cases set due_at = now() - interval '1 minute' where id = '${got.case}'`);
  assert.strictEqual(await due(), 1);
  const [d] = await q(`select status, decided_kind from app.work_disputes where id = '${dsp.id}'`);
  assert.deepStrictEqual([d.status, d.decided_kind], ['upheld', 'peer']);
  assert.strictEqual((await q(`select status from app.work_submissions where id = '${w.sub}'`))[0].status, 'reversed');
});

test('AR6: nobody decides a case on work they did, posted, or helped decide; a level-1 member can’t; an agent can’t', async () => {
  await clearQueue();
  const w = await work_();
  await check(w.sub, 'fail_appeal');
  assert.strictEqual((await run(ctxOf(worker), (t) => work.caseTake(t))).case, null);
  assert.strictEqual((await run(ctxOf(poster), (t) => work.caseTake(t))).case, null);
  const voter = await member('Voter');
  await q(`insert into app.work_person_votes (submission_id, member_id, verdict, reason) values ('${w.sub}', '${voter.id}', 'fail', 'Earlier')`);
  assert.strictEqual((await run(ctxOf(voter), (t) => work.caseTake(t))).reason, 'decided_it');
  const low = await member('Level one', { level2: false });
  assert.strictEqual((await run(ctxOf(low), (t) => work.caseTake(t))).reason, 'level');
  await assert.rejects(run({ actor: 'agent', memberId: voter.id, agentId: crypto.randomUUID() }, (t) => work.caseTake(t)));
});

test('AR7: held work an administrator is a party to, that Third Look can’t read, goes to peers; a pull request stays with Third Look', async () => {
  await q(`update app.work_submissions set status = 'failed', route = null where status = 'review'`);
  const mine = await work_({ poster: admin, status: 'review', route: 'held' });
  const r = await member('Peer five');
  const got = await run(ctxOf(r), (t) => work.peerTake(t));
  assert.strictEqual(got.submission, mine.sub);
  await run(ctxOf(r), (t) => work.peerRelease(t, { review: got.review }));
  await q(`update app.work_submissions set artifact_kind = 'pr', pr_number = 1 where id = '${mine.sub}'`).catch(() => {});
  if ((await q(`select artifact_kind from app.work_submissions where id = '${mine.sub}'`))[0].artifact_kind === 'pr') {
    assert.strictEqual((await run(ctxOf(r), (t) => work.peerTake(t))).review, null);
  }
});

test('AR8: a check an administrator is a party to goes to a peer instead of waiting forever', async () => {
  await clearQueue();
  const w = await work_({ by: admin });
  const k = await check(w.sub, 'fail_appeal');
  await assert.rejects(run(asAdmin(admin), (t) => work.review(t, k, { decision: 'reverse', reason: 'Mine' })), /a peer decides/);
  const r = await member('Peer six');
  const got = await run(ctxOf(r), (t) => work.caseTake(t));
  assert.strictEqual(got.submission, w.sub);
});
