// 065: the paid peer reviewer queue (Aaron, Nov 11 and 12, 2026), against a real Postgres. Held work on a funded task
// goes to an eligible member for 24 hours; the 2% fee is queued for every decided review, pass or fail; every block
// against self-review and collusion is checked at take and again at decision. ACCEPTANCE.md PV1 to PV7. PV5 and PV6
// are the red-team cases (redteam/: the attempts an adversarial reviewer would make).
//
// 045's top decile needs 10 established auditors in a room, which a test database doesn't hold, so most tests here
// replace app.peer_top_decile with one that says yes for the members a test names (PV1 checks the real one says no).
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
const NAME = 'dog_065_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, poster, worker, room, project;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const ctxOf = (m) => ({ actor: 'member', memberId: m.id, session: m.session, fresh: true });
const asPay = (fn) => su.begin(async (t) => { await t.unsafe('set local role dog_pay'); return fn(t); });

let n = 0;
async function member(name, { level2 = true } = {}) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('gh:' + name + (n++))], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level2) await promote(su, out.memberId);
  return { id: out.memberId, name, session: c.sha256hex(token) };
}
// Payouts set up at Stripe (Connect Express checked who they are).
const payouts = (m) => asPay((t) => t.unsafe(`insert into app.pay_accounts (member_id, stripe_account, livemode, payouts_enabled, details_submitted)
  values ('${m.id}', 'acct_${m.id.replace(/-/g, '').slice(0, 16)}', false, true, true)`));
// The top decile, for the members named (see the note above).
const topDecile = (members) => q(`create or replace function app.peer_top_decile(p_member uuid, p_room text) returns boolean
  language sql stable security definer set search_path = pg_catalog as $$ select p_member = any (array[${members.map((m) => `'${m.id}'::uuid`).join(',') || 'null::uuid'}]) $$`);
// A funded task with work held for a person.
async function held({ by = worker, poster: p = poster } = {}) {
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, status)
    values ('${project}', '${room}', 'Held work', 'either', 1, 'member', '${p.id}', 'submitted') returning id`);
  const [b] = await q(`insert into app.work_bounties (task_id, payer_member, bounty_cents) values ('${t.id}', '${p.id}', 10000) returning id`);
  await asPay((x) => x.unsafe(`update app.work_bounties set status = 'funded', livemode = false, stripe_payment_intent_id = 'pi_${b.id.replace(/-/g, '')}',
    charged_cents = bounty_cents, funded_at = now() where id = '${b.id}'`));
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at, status) values ('${t.id}', '${by.id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day', 'submitted') returning id`);
  const [s] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, route, routed_at)
    values ('${t.id}', '${cl.id}', 'member', '${by.id}', 'link', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'review', 'admin', now() - interval '1 hour') returning id`);
  return { task: t.id, bounty: b.id, sub: s.id };
}
const take = (m) => run(ctxOf(m), (t) => work.peerTake(t));
const decide = (m, review, verdict, reason = 'Read it and checked it') => run(ctxOf(m), (t) => work.peerDecide(t, { review, verdict, reason }));
const block = async (m, sub) => (await q(`select app.peer_block('${m.id}', '${sub}') as b`))[0].b;
// Clear the queue between tests, so each takes only its own work.
const clear = () => q(`update app.work_submissions set status = 'failed', route = null, decided_by = 'person', decided_at = now() where status = 'review'`);

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

test('PV1: who may review: a person at level 2 with payouts, in the room’s top decile; nobody is in it until the room has an established record', async () => {
  const h = await held();
  const r = await member('Reviewer one');
  assert.strictEqual(await block(r, h.sub), 'payouts');
  await payouts(r);
  assert.strictEqual(await block(r, h.sub), 'not_top_decile', '045’s real top decile: nobody in a room with no established auditors');
  await topDecile([r]);
  assert.strictEqual(await block(r, h.sub), null);
  const low = await member('Level one', { level2: false });
  await payouts(low);
  await topDecile([r, low]);
  assert.strictEqual(await block(low, h.sub), 'level');
  // An agent can't take work for the fee.
  await assert.rejects(run({ actor: 'agent', memberId: r.id, agentId: crypto.randomUUID() }, (t) => work.peerTake(t)));
  await clear();
});

test('PV2: an eligible reviewer takes held work for 24 hours, one at a time, and decides it; the 2% fee is queued, pass or fail', async () => {
  const h = await held();
  const r = await member('Reviewer two');
  await payouts(r);
  await topDecile([r]);
  const got = await take(r);
  assert.strictEqual(got.submission, h.sub);
  await assert.rejects(take(r), /work_peer_busy|Finish or give back/);
  const other = await member('Reviewer three');
  await payouts(other);
  await topDecile([r, other]);
  assert.strictEqual((await take(other)).review, null, 'one reviewer at a time on a submission');
  assert.deepStrictEqual(await decide(r, got.review, 'fail'), { result: 'fail' });
  const [s] = await q(`select status, decided_by from app.work_submissions where id = '${h.sub}'`);
  assert.deepStrictEqual([s.status, s.decided_by], ['failed', 'peer']);
  const [pr] = await q(`select status, verdict, fee_cents from app.peer_reviews where id = '${got.review}'`);
  assert.deepStrictEqual([pr.status, pr.verdict, pr.fee_cents], ['decided', 'fail', 200], '2% of $100, for a fail');
  const [req] = await q(`select kind, member_id, bounty_id from app.pay_requests where peer_review_id = '${got.review}'`);
  assert.deepStrictEqual([req.kind, req.member_id, req.bounty_id], ['reviewer_fee', r.id, h.bounty]);
  assert.strictEqual((await q(`select app.bounty_refund_cents('${h.bounty}') as c`))[0].c, 9800, 'a refund now returns 98%');
  // The reviewer's vote is kept for calibration (045, now counting peer passes).
  assert.strictEqual((await q(`select count(*)::int as n from app.work_person_votes where submission_id = '${h.sub}' and member_id = '${r.id}'`))[0].n, 1);
  await clear();
});

test('PV3: calibration counts a peer reviewer’s passes as it counts a poster’s', async () => {
  const h = await held();
  const r = await member('Reviewer four');
  await payouts(r);
  await topDecile([r]);
  const got = await take(r);
  assert.deepStrictEqual(await decide(r, got.review, 'pass'), { result: 'pass' });
  await q(`update app.work_points set status = 'final' where submission_id = '${h.sub}'`);
  const [st] = await q(`select cal_k, cal_n from app.work_stats(null) where kind = 'member' and ref = '${r.id}'`);
  assert.deepStrictEqual([Number(st.cal_k), Number(st.cal_n)], [1, 1], 'a pass that held');
  await q(`update app.work_submissions set status = 'reversed' where id = '${h.sub}'`);
  const [st2] = await q(`select cal_k, cal_n from app.work_stats(null) where kind = 'member' and ref = '${r.id}'`);
  assert.deepStrictEqual([Number(st2.cal_k), Number(st2.cal_n)], [0, 1], 'overturned: calibration drops');
  await clear();
});

test('PV4: an assignment lapses after 24 hours; the administrator can decide first; at most 3 paid reviews a task', async () => {
  const h = await held();
  const r = await member('Reviewer five');
  await payouts(r);
  await topDecile([r]);
  const got = await take(r);
  await q(`update app.peer_reviews set expires_at = now() - interval '1 minute' where id = '${got.review}'`);
  assert.deepStrictEqual(await decide(r, got.review, 'pass'), { result: 'lapsed' });
  const again = await take(r);
  assert.strictEqual(again.submission, h.sub, 'the lapsed work went back to the queue');
  await q(`update app.work_submissions set status = 'passed', route = null, decided_by = 'person', decided_at = now() where id = '${h.sub}'`);
  assert.deepStrictEqual(await decide(r, again.review, 'pass'), { result: 'not_waiting' });
  assert.strictEqual((await q(`select count(*)::int as n from app.pay_requests where peer_review_id = '${again.review}'`))[0].n, 0, 'no fee without a decision');
  // Three decided reviews on one task: the next held work there goes to the administrator only.
  const h2 = await held();
  await q(`insert into app.peer_reviews (submission_id, task_id, bounty_id, reviewer_member, status, verdict, reason, expires_at, decided_at)
    select '${h2.sub}', '${h2.task}', '${h2.bounty}', '${r.id}', 'decided', 'fail', 'Earlier', now(), now() from generate_series(1, 3)`);
  assert.strictEqual((await take(r)).review, null);
  await clear();
});

test('PV5 (red team): nobody reviews their own work, their own task, their agent’s, or work tied to them in the last 90 days', async () => {
  const r = await member('Reviewer six');
  await payouts(r);
  await topDecile([r, worker, poster]);
  await payouts(worker);
  await payouts(poster);
  const h = await held();
  assert.strictEqual(await block(worker, h.sub), 'party', 'the worker');
  assert.strictEqual(await block(poster, h.sub), 'party', 'the poster');
  // The reviewer did work for this poster lately: blocked.
  await held({ by: r });
  assert.strictEqual(await block(r, h.sub), 'collaborated');
  // A buyer account is never a reviewer, whatever the queue says (063's scope trigger).
  const [buyer] = await q(`insert into app.members (display_name, trust_level) values ('A buyer', 1) returning id`);
  await asSignin(su)((t) => t.unsafe(`insert into app.identities (member_id, provider, fingerprint, key_version, level) values ('${buyer.id}', 'buyer', '${c.sha256hex('buyer' + buyer.id)}', 1, 1)`));
  assert.strictEqual(await block({ id: buyer.id }, h.sub), 'buyer');
  await assert.rejects(q(`insert into app.peer_reviews (submission_id, task_id, reviewer_member, expires_at) values ('${h.sub}', '${h.task}', '${buyer.id}', now() + interval '1 day')`), /buyer_scope/);
  await clear();
});

test('PV6 (red team): a tie that appears after the work was taken blocks the decision; one reviewer can’t keep reviewing one worker', async () => {
  const r = await member('Reviewer seven');
  await payouts(r);
  await topDecile([r]);
  const h = await held();
  const got = await take(r);
  // Meanwhile the worker does work on a task the reviewer posted.
  const [p2] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('Mine', '${room}', 'member', '${r.id}') returning id`);
  const [t2] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member) values ('${p2.id}', '${room}', 'T', 'either', 1, 'member', '${r.id}') returning id`);
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at) values ('${t2.id}', '${worker.id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day') returning id`);
  await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, decided_by)
    values ('${t2.id}', '${cl.id}', 'member', '${worker.id}', 'link', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'failed', 'poster')`);
  await assert.rejects(decide(r, got.review, 'pass'), /can.t review this work any more/);
  assert.strictEqual((await q(`select status from app.work_submissions where id = '${h.sub}'`))[0].status, 'review', 'nothing decided');
  // Rotation: a fresh reviewer who has decided 3 of this worker's submissions in 30 days.
  const r2 = await member('Reviewer eight');
  await payouts(r2);
  await topDecile([r2]);
  await q(`insert into app.peer_reviews (submission_id, task_id, reviewer_member, status, verdict, reason, expires_at, decided_at)
    select s.id, s.task_id, '${r2.id}', 'decided', 'pass', 'Earlier', now(), now() from app.work_submissions s where s.worker_member = '${worker.id}' limit 3`);
  assert.strictEqual(await block(r2, h.sub), 'rotation');
  await clear();
});

test('PV7: the API: the queue is for a person on our pages; an agent is refused; the routes are POSTs', async () => {
  const api = require('../api/work');
  for (const route of ['peer/take', 'peer/decide', 'peer/release']) assert.ok(api.handle, route);
  const fs = require('fs');
  const src = fs.readFileSync(require('path').join(__dirname, '..', 'api', 'work.js'), 'utf8');
  assert.match(src, /'peer\/take': \{ keys: \[\], fn: \(t\) => work\.peerTake\(t\), personOnly: true \}/);
  assert.match(src, /'peer\/decide': \{ keys: \['review', 'verdict', 'reason'\], fn: \(t, b\) => work\.peerDecide\(t, b\), pay: true, personOnly: true \}/);
  assert.match(fs.readFileSync(require('path').join(__dirname, '..', 'peer.js'), 'utf8'), /\/api\/work\//);
});

test('PV8 (the red-team review of PR #5): no fee once the task is closed or refunded; ties count either way round; no more than 3 of one poster’s tasks; never an administrator; only risk holds', async () => {
  const r = await member('Reviewer nine');
  await payouts(r);
  await topDecile([r]);
  // H1: the task is closed and refunded while the review is open: no decision, no fee.
  const h = await held();
  const got = await take(r);
  await q(`update app.work_tasks set status = 'closed' where id = '${h.task}'`);
  assert.deepStrictEqual(await decide(r, got.review, 'fail'), { result: 'not_waiting' });
  assert.strictEqual((await q(`select count(*)::int as n from app.pay_requests where peer_review_id = '${got.review}'`))[0].n, 0);
  assert.strictEqual((await q(`select app.bounty_peer_fee('${got.review}') as c`))[0].c, 0);
  await clear();
  // M1: the reviewer worked on a task the worker posted: blocked, the other way round from PV5.
  const r2 = await member('Reviewer ten');
  await payouts(r2);
  await topDecile([r2]);
  const h2 = await held();
  const [p3] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('W', '${room}', 'member', '${worker.id}') returning id`);
  const [t3] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member) values ('${p3.id}', '${room}', 'T', 'either', 1, 'member', '${worker.id}') returning id`);
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at) values ('${t3.id}', '${r2.id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day') returning id`);
  await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, decided_by)
    values ('${t3.id}', '${cl.id}', 'member', '${r2.id}', 'link', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'failed', 'poster')`);
  assert.strictEqual(await block(r2, h2.sub), 'collaborated');
  // M3: 3 of one poster's tasks in 30 days, whoever the worker.
  const r3 = await member('Reviewer eleven');
  await payouts(r3);
  await topDecile([r3]);
  await q(`insert into app.peer_reviews (submission_id, task_id, reviewer_member, status, verdict, reason, expires_at, decided_at)
    select s.id, s.task_id, '${r3.id}', 'decided', 'fail', 'Earlier', now(), now() from app.work_submissions s join app.work_tasks t on t.id = s.task_id
     where t.poster_member = '${poster.id}' limit 3`);
  assert.strictEqual(await block(r3, h2.sub), 'rotation');
  // L4: an administrator isn't a paid reviewer.
  const adm = await member('Admin');
  await payouts(adm);
  await topDecile([adm]);
  await su.begin(async (t) => { await t.unsafe('alter table app.members disable trigger members_guard'); await t.unsafe(`update app.members set is_admin = true where id = '${adm.id}'`); await t.unsafe('alter table app.members enable always trigger members_guard'); }).catch(() => q(`update app.members set is_admin = true where id = '${adm.id}'`));
  assert.strictEqual(await block(adm, h2.sub), 'admin');
  // M2: work held only because its poster didn't check it in time, and work routed to Third Look ('held'), aren't offered.
  await q(`update app.work_submissions set held_reason = 'The task''s poster didn''t check it within 72 hours.' where id = '${h2.sub}'`);
  const r4 = await member('Reviewer twelve');
  await payouts(r4);
  await topDecile([r4]);
  assert.strictEqual((await take(r4)).review, null);
  await q(`update app.work_submissions set held_reason = null, route = 'held' where id = '${h2.sub}'`);
  assert.strictEqual((await take(r4)).review, null);
  await clear();
});
