// 061: funded bounties, the money rails under Build (Aaron, Nov 11, 2026: separate charges and transfers, Stripe only,
// private earnings), against a real Postgres. What the database itself guarantees, whatever the payment function does:
// who may fund, the state machine, one release or refund per bounty, the payee from the final points, private amounts,
// and an append-only ledger. ACCEPTANCE.md PM1 to PM9.
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
const NAME = 'dog_061_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, poster, worker, other, agentOwner, room, project;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const ctxOf = (m) => ({ actor: 'member', memberId: m.id, session: m.session, fresh: true });
// The payment function's role, as dog-pay acts.
const asPay = (fn) => su.begin(async (t) => { await t.unsafe('set local role dog_pay'); return fn(t); });

let n = 0;
async function member(name) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('gh:' + name + (n++))], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  return { id: out.memberId, name, session: c.sha256hex(token), cookie: '__Host-dog_session=' + token };
}
async function task(by, status = 'open') {
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, status)
    values ('${project}', '${room}', 'A task', 'either', 1, 'member', '${by.id}', '${status}') returning id`);
  return t.id;
}
const fund = (m, taskId, cents) => run(ctxOf(m), (t) => t`select app.bounty_fund_request(${taskId}, ${cents}) as id`).then((r) => r[0].id);
const bountyOf = async (taskId) => (await q(`select * from app.work_bounties where task_id = '${taskId}'`))[0];
// Stripe's signed event said the payment succeeded: dog-pay marks the bounty funded.
const markFunded = (b) => asPay((t) => t.unsafe(`update app.work_bounties set status = 'funded', livemode = false, stripe_payment_intent_id = 'pi_${b.id.replace(/-/g, '')}',
  charged_cents = bounty_cents, funded_at = now() where id = '${b.id}'`));
// Work done and passed on a task, with points pending: the worker is a member, or an agent of agentOwner.
async function points(taskId, { by = worker, agent = null } = {}) {
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, agent_id, code_hash, expires_at) values ('${taskId}', '${by.id}', ${agent ? `'${agent}'` : 'null'}, '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day') returning id`);
  const [sb] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, worker_agent, artifact_kind, artifact_url, seal_key, seal, status, decided_by)
    values ('${taskId}', '${cl.id}', '${agent ? 'agent' : 'member'}', '${by.id}', ${agent ? `'${agent}'` : 'null'}, 'link', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'passed', 'poster') returning id`);
  const [p] = await q(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, citizen_agent, size, confidence, independence, points, final_at)
    values ('${sb.id}', '${taskId}', '${room}', '${agent ? 'agent' : 'member'}', ${agent ? 'null' : `'${by.id}'`}, ${agent ? `'${agent}'` : 'null'}, 1, 100, 100, 10, now() + interval '3 days') returning id`);
  return p.id;
}
const setPoints = (id, status) => q(`update app.work_points set status = '${status}' where id = '${id}'`);
const requests = async (b, kind) => q(`select * from app.pay_requests where bounty_id = '${b.id}'${kind ? ` and kind = '${kind}'` : ''}`);

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
  other = await member('Other');
  agentOwner = await member('Owner');
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

test('PM1: only the poster funds an open task, $10 to $10,000, and only once', async () => {
  const t1 = await task(poster);
  await assert.rejects(fund(other, t1, 5000), /only the task's poster/);
  await assert.rejects(fund(poster, t1, 999), /\$10 to \$10,000/);
  await assert.rejects(fund(poster, t1, 1000001), /\$10 to \$10,000/);
  await assert.rejects(fund(poster, await task(poster, 'claimed'), 5000), /work_pay_not_open/);
  const rid = await fund(poster, t1, 5000);
  const b = await bountyOf(t1);
  assert.equal(b.status, 'funding');
  assert.equal(b.payer_member, poster.id);
  assert.equal(b.platform_fee_bps, 1500);
  assert.deepEqual((await requests(b)).map((r) => [r.id, r.kind, r.status]), [[rid, 'fund_task', 'queued']]);
  await assert.rejects(fund(poster, t1, 5000), /work_pay_funded/);
  // Nobody signed in, and an agent, fund nothing.
  await assert.rejects(run({ actor: 'anon' }, (t) => t`select app.bounty_fund_request(${t1}, 5000)`), /only a person|permission denied/);
});

test('PM2: a failed payment can be tried again; the failed bounty stays, detached, for the record', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  const b = await bountyOf(t1);
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'failed' where id = '${b.id}'`));
  await asPay((t) => t.unsafe(`update app.pay_requests set status = 'failed' where bounty_id = '${b.id}'`));
  await fund(poster, t1, 6000);
  assert.equal((await bountyOf(t1)).bounty_cents, 6000);
  const [old] = await q(`select task_id, status from app.work_bounties where id = '${b.id}'`);
  assert.deepEqual([old.task_id, old.status], [null, 'failed']);
});

test('PM3: the state machine refuses every move it doesn\'t list, and freezes the amount, fees and payer', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  const b = await bountyOf(t1);
  const bad = async (sql, re) => assert.rejects(asPay((t) => t.unsafe(sql)), re);
  await bad(`update app.work_bounties set status = 'released' where id = '${b.id}'`, /can't go from funding to released/);
  await bad(`update app.work_bounties set bounty_cents = 100000 where id = '${b.id}'`, /fixed/);
  await bad(`update app.work_bounties set platform_fee_bps = 0 where id = '${b.id}'`, /fixed/);
  await bad(`update app.work_bounties set payer_member = '${other.id}' where id = '${b.id}'`, /fixed/);
  await bad(`insert into app.work_bounties (task_id, payer_member, bounty_cents, status) values ('${await task(poster)}', '${poster.id}', 5000, 'funded')`, /starts as funding/);
  // Funded needs Stripe's payment on the row.
  await bad(`update app.work_bounties set status = 'funded' where id = '${b.id}'`, /violates check constraint/);
  await markFunded(b);
  assert.equal((await bountyOf(t1)).status, 'funded');
  // A release needs final points.
  await bad(`update app.work_bounties set status = 'releasing', payee_member = '${worker.id}' where id = '${b.id}'`, /only when its points are final/);
});

test('PM4: points going final release the bounty to the worker, once; an agent\'s work pays its owner', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  await markFunded(await bountyOf(t1));
  const p = await points(t1);
  await setPoints(p, 'final');
  const b = await bountyOf(t1);
  assert.equal(b.status, 'releasing');
  assert.equal(b.payee_member, worker.id);
  const rel = await requests(b, 'release');
  assert.equal(rel.length, 1);
  assert.equal(rel[0].member_id, worker.id);
  // dog-pay can't redirect the money.
  await assert.rejects(asPay((t) => t.unsafe(`update app.work_bounties set payee_member = '${other.id}' where id = '${b.id}'`)), /citizen of its final points|fixed/);
  // Transferred: never more than the bounty less the platform fee.
  // The transfer is in flight (transferring) before it is recorded (released).
  await assert.rejects(asPay((t) => t.unsafe(`update app.work_bounties set status = 'released', stripe_transfer_id = 'tr_X', transferred_cents = 4250 where id = '${b.id}'`)), /can't go from releasing to released/);
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'transferring' where id = '${b.id}'`));
  await assert.rejects(asPay((t) => t.unsafe(`update app.work_bounties set status = 'released', stripe_transfer_id = 'tr_X', transferred_cents = 5000 where id = '${b.id}'`)), /check constraint/);
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'released', stripe_transfer_id = 'tr_X', transferred_cents = 4250, released_at = now() where id = '${b.id}'`));
  assert.equal((await bountyOf(t1)).status, 'released');

  // An agent's work.
  const [ag] = await run(ctxOf(agentOwner), (t) => t`insert into app.agents (name) values ('Paid agent') returning id`);
  const t2 = await task(poster);
  await fund(poster, t2, 2000);
  await markFunded(await bountyOf(t2));
  await setPoints(await points(t2, { by: agentOwner, agent: ag.id }), 'final');
  assert.equal((await bountyOf(t2)).payee_member, agentOwner.id);
});

test('PM5: points removed before final refund the payer; after the transfer, a reversal; one request each', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  await markFunded(await bountyOf(t1));
  const p = await points(t1);
  await setPoints(p, 'removed');
  let b = await bountyOf(t1);
  assert.equal(b.status, 'refunding');
  assert.equal((await requests(b, 'refund')).length, 1);

  const t2 = await task(poster);
  await fund(poster, t2, 5000);
  await markFunded(await bountyOf(t2));
  const p2 = await points(t2);
  await setPoints(p2, 'final');
  b = await bountyOf(t2);
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'transferring' where id = '${b.id}'`));
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'released', stripe_transfer_id = 'tr_Y', transferred_cents = 4250 where id = '${b.id}'`));
  await setPoints(p2, 'removed');
  b = await bountyOf(t2);
  assert.equal(b.status, 'reversing');
  assert.equal((await requests(b, 'reverse')).length, 1);
  // Stripe reverses only what the worker's balance covers: a failed reversal is its own state.
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'reversal_failed' where id = '${b.id}'`));
  // Transferred and refunded at once is impossible.
  await assert.rejects(asPay((t) => t.unsafe(`update app.work_bounties set stripe_refund_id = 're_Z' where id = '${b.id}'`)), /check constraint/);
});

test('PM6: a funded task removed with no final points refunds its payer', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  await markFunded(await bountyOf(t1));
  await q(`update app.work_tasks set status = 'removed' where id = '${t1}'`);
  const b = await bountyOf(t1);
  assert.equal(b.status, 'refunding');
  assert.equal((await requests(b, 'refund')).length, 1);
});

test('PM7: amounts are private: to signed-in people only while the task is open and funded (064, Aaron, Nov 12); else the payer, the payee and the administrator', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  const see = (m) => run(m ? ctxOf(m) : { actor: 'anon' }, (t) => t`select bounty_cents from app.work_bounties where task_id = ${t1}`);
  assert.equal((await see(null)).length, 0, 'not yet funded: nobody but the payer');
  assert.equal((await see(poster)).length, 1);
  await markFunded(await bountyOf(t1));
  assert.equal((await see(null)).length, 0, 'open and funded: signed out, still no price (064)');
  assert.equal((await see(other)).length, 1);
  await q(`update app.work_tasks set status = 'claimed' where id = '${t1}'`);
  assert.equal((await see(null)).length, 0, 'claimed: private');
  assert.equal((await see(other)).length, 0);
  assert.equal((await see(poster)).length, 1);
  // Requests and connected accounts: each member's own only. The site never reads Stripe's ids.
  assert.equal((await run(ctxOf(other), (t) => t`select id from app.pay_requests`)).length, 0);
  await assert.rejects(run(ctxOf(poster), (t) => t`select stripe_payment_intent_id from app.work_bounties`), /permission denied/);
});

test('PM8: the money ledger and Stripe\'s events take each object once, and the ledger is never changed', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  const b = await bountyOf(t1);
  await asPay((t) => t.unsafe(`insert into app.pay_ledger (bounty_id, member_id, kind, amount_cents, stripe_object_id) values ('${b.id}', '${poster.id}', 'charge', 5000, 'ch_ONE')`));
  await assert.rejects(asPay((t) => t.unsafe(`insert into app.pay_ledger (bounty_id, member_id, kind, amount_cents, stripe_object_id) values ('${b.id}', '${poster.id}', 'charge', 5000, 'ch_ONE')`)), /duplicate key/);
  await assert.rejects(asPay((t) => t.unsafe(`insert into app.pay_ledger (bounty_id, kind, amount_cents, stripe_object_id) values ('${b.id}', 'transfer', 4250, 'tr_ONE')`)), /check constraint/, 'a transfer is money out');
  await assert.rejects(q(`update app.pay_ledger set amount_cents = 1 where stripe_object_id = 'ch_ONE'`), /append-only/);
  await assert.rejects(q(`delete from app.pay_ledger where stripe_object_id = 'ch_ONE'`), /append-only/);
  await asPay((t) => t.unsafe(`insert into app.pay_events (stripe_event_id, type, livemode, object_id) values ('evt_ONE', 'checkout.session.completed', false, 'cs_test_ONE')`));
  await assert.rejects(asPay((t) => t.unsafe(`insert into app.pay_events (stripe_event_id, type, livemode) values ('evt_ONE', 'checkout.session.completed', false)`)), /duplicate key/);
});

test('PM9: the site\'s role can\'t write money rows, and dog_pay can\'t act as the site', async () => {
  const t1 = await task(poster);
  await assert.rejects(run(ctxOf(poster), (t) => t`insert into app.work_bounties (task_id, payer_member, bounty_cents) values (${t1}, ${poster.id}, 5000)`), /permission denied/);
  await assert.rejects(run(ctxOf(poster), (t) => t`insert into app.pay_requests (member_id, kind) values (${poster.id}, 'connect_onboard')`), /permission denied/);
  await assert.rejects(run(ctxOf(poster), (t) => t`update app.work_bounties set status = 'released'`), /permission denied/);
  const [r] = await q(`select pg_has_role('dog_app', 'dog_pay', 'member') as app_is_pay, pg_has_role('dog_pay', 'dog_app', 'member') as pay_is_app,
    (select rolcanlogin from pg_roles where rolname = 'dog_pay') as login`);
  assert.deepEqual([r.app_is_pay, r.pay_is_app, r.login], [false, false, false]);
});

// The site's routes (api/work.js): fund, payouts and payment, through the real handler, as a browser on our own pages.
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
async function call(m, method, route, body, query = '') {
  const out = res();
  await require('../api/work.js').handle({ method, url: '/api/work?route=' + route + query, query: { route }, headers: { host: 'dayonegreat.com', origin: 'https://dayonegreat.com',
    cookie: m.cookie, 'content-type': 'application/json', 'sec-fetch-site': 'same-origin', 'x-vercel-forwarded-for': '203.0.113.9' },
    body: body === undefined ? undefined : JSON.stringify(body) }, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
const SWITCH = require.resolve('../payments.json');
function payments(on) { require.cache[SWITCH] = { id: SWITCH, filename: SWITCH, loaded: true, exports: { payments: on ? 'on' : 'off' } }; }

test('PM17: with payments off (as merged), nobody can fund or set up payouts; the site says so', async () => {
  delete require.cache[SWITCH];
  assert.equal(require('../payments.json').payments, 'off', 'payments stay off until Aaron merges a change that turns them on');
  const t1 = await task(poster);
  const r = await call(poster, 'POST', 'fund', { task: t1, dollars: 50 });
  assert.equal(r.status, 503);
  assert.match(r.json.error, /aren't switched on yet/);
  assert.equal((await call(worker, 'POST', 'payouts', {})).status, 503);
  assert.equal(await bountyOf(t1), undefined);
});

test('PM18: with payments on: fund in whole dollars, poke the payment function with nothing attached, read only your own request', async () => {
  payments(true);
  const pay = require('../db/pay');
  const pokes = [];
  const real = pay.poke;
  pay.poke = async () => { pokes.push(1); };
  try {
    const t1 = await task(poster);
    assert.equal((await call(poster, 'POST', 'fund', { task: t1, dollars: 9 })).status, 400);
    assert.equal((await call(poster, 'POST', 'fund', { task: t1, dollars: 50.5 })).status, 400);
    assert.equal((await call(other, 'POST', 'fund', { task: t1, dollars: 50 })).status, 403);
    const ok = await call(poster, 'POST', 'fund', { task: t1, dollars: 50 });
    assert.equal(ok.status, 201, JSON.stringify(ok.json));
    assert.equal((await bountyOf(t1)).bounty_cents, 5000);
    assert.equal(pokes.length, 1);
    assert.equal((await call(poster, 'POST', 'fund', { task: t1, dollars: 50 })).status, 409, 'funded once');
    const mine = await call(poster, 'GET', 'payment', undefined, '&request=' + ok.json.request);
    assert.deepEqual([mine.status, mine.json.kind, mine.json.status, mine.json.url], [200, 'fund_task', 'queued', null]);
    assert.equal((await call(other, 'GET', 'payment', undefined, '&request=' + ok.json.request)).status, 404, 'another member\'s request is not found');
    assert.equal((await call(worker, 'POST', 'payouts', {})).status, 201);
  } finally {
    pay.poke = real;
    delete require.cache[SWITCH];
  }
  // The poke itself: the fixed address, POST, nothing attached.
  const seen = [];
  await require('../db/pay').poke(async (url, init) => { seen.push([url, init]); });
  assert.equal(seen[0][0], 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-pay/tick');
  assert.deepEqual(Object.keys(seen[0][1]).sort(), ['method', 'redirect', 'signal']);
});

test('PM19: points removed while a transfer is in flight never refund: the transfer is recorded, then reversed (the fresh review, C1)', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  await markFunded(await bountyOf(t1));
  const p = await points(t1);
  await setPoints(p, 'final');
  let b = await bountyOf(t1);
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'transferring' where id = '${b.id}'`));
  await setPoints(p, 'removed');
  b = await bountyOf(t1);
  assert.deepEqual([b.status, b.undo_requested], ['transferring', true], 'no refund while the transfer is in flight');
  assert.equal((await requests(b, 'refund')).length, 0);
  // Recording the transfer is still allowed, though the points are no longer final: Stripe made it.
  await asPay((t) => t.unsafe(`update app.work_bounties set status = 'released', stripe_transfer_id = 'tr_R', transferred_cents = 4250 where id = '${b.id}'`));
  assert.equal((await bountyOf(t1)).status, 'released');
});

test('PM20: money never stops points going final, and a deleted funded task refunds its payer first', async () => {
  const t1 = await task(poster);
  await fund(poster, t1, 5000);
  await markFunded(await bountyOf(t1));
  const p = await points(t1);
  // Break the bounty's state on purpose: the guard would refuse funded to releasing without a payee check passing.
  await q(`alter table app.work_bounties disable trigger work_bounties_guard`);
  await q(`update app.work_bounties set status = 'refunded', stripe_refund_id = 're_X' where task_id = '${t1}'`);
  await q(`alter table app.work_bounties enable always trigger work_bounties_guard`);
  await q(`update app.work_bounties set status = 'refunded' where task_id = '${t1}'`).catch(() => {});
  await setPoints(p, 'final');
  assert.equal((await q(`select status from app.work_points where id = '${p}'`))[0].status, 'final', 'the points went final');

  const t2 = await task(poster);
  await fund(poster, t2, 5000);
  const b2 = await bountyOf(t2);
  await markFunded(b2);
  await q(`delete from app.work_tasks where id = '${t2}'`);
  const [after] = await q(`select task_id, status from app.work_bounties where id = '${b2.id}'`);
  assert.deepEqual([after.task_id, after.status], [null, 'refunding']);
  assert.equal((await requests(b2, 'refund')).length, 1);
});
