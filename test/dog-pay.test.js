// dog-pay (061): the payment function's work against a real Postgres and a fake Stripe that keeps Stripe's own
// promise on Idempotency-Key (the same key returns the same object). ACCEPTANCE.md PM10 to PM16.
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
const { migrate } = require('../scripts/migrate');
const { promote, shadowMode, asSignin } = require('./helpers');

const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
const SERVER = process.env.TEST_DATABASE_URL;
const NAME = 'dog_061p_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
const SECRET = 'whsec_testsecret123';
let P, server, su, web, poster, worker, room, project, stripe, fake;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const ctxOf = (m) => ({ actor: 'member', memberId: m.id, session: m.session, fresh: true });

// A fake Stripe: objects by id, the same answer for a repeated Idempotency-Key, and every call recorded.
function fakeStripe() {
  const objects = new Map(), byKey = new Map(), calls = [];
  let n = 0;
  const id = (p) => p + '_' + (++n).toString(36).padStart(6, '0');
  const f = { objects, calls, failNext: null, accounts: new Map() };
  f.fetch = async (url, init) => {
    const u = new URL(url);
    assert.equal(u.origin, 'https://api.stripe.com');
    assert.equal(init.redirect, 'error');
    const params = Object.fromEntries(new URLSearchParams(init.body || u.search.slice(1)));
    const key = init.headers['idempotency-key'];
    calls.push({ method: init.method, path: u.pathname, params, key });
    const json = (status, body) => ({ ok: status < 300, status, json: async () => body });
    if (f.failNext) { const e = f.failNext; f.failNext = null; return json(e.status, { error: { code: e.code } }); }
    if (key && byKey.has(init.method + u.pathname + key)) return json(200, byKey.get(init.method + u.pathname + key));
    let out;
    const p = u.pathname;
    const meta = params['metadata[bounty]'] ? { bounty: params['metadata[bounty]'] } : {};
    // Lists Stripe answers before a retry makes anything (find, in core.mjs).
    if (init.method === 'GET' && (p === '/v1/transfers' || p === '/v1/refunds' || /\/reversals$/.test(p))) {
      const data = [...objects.values()].filter((o) => o.list === p && (!params.transfer_group || o.transfer_group === params.transfer_group)
        && (!params.payment_intent || o.payment_intent === params.payment_intent));
      return json(200, { data });
    }
    if (init.method === 'POST' && p === '/v1/accounts') out = { id: id('acct') + 'XXXXXX', payouts_enabled: false };
    else if (p === '/v1/account_links') out = { url: 'https://connect.stripe.com/setup/e/' + id('x') };
    else if (p === '/v1/checkout/sessions') out = { id: 'cs_test_' + id('s').slice(2), url: 'https://checkout.stripe.com/c/pay/' + id('x'), amount_total: Number(params['line_items[0][price_data][unit_amount]']),
      currency: 'usd', client_reference_id: params.client_reference_id, payment_status: 'unpaid', livemode: false };
    else if (p === '/v1/transfers') out = { id: id('tr'), amount: Number(params.amount), transfer_group: params.transfer_group, metadata: meta, list: p };
    else if (p === '/v1/refunds') out = { id: id('re'), amount: 5000, payment_intent: params.payment_intent, metadata: meta, list: p };
    else if (/^\/v1\/transfers\/tr_[a-z0-9_]+\/reversals$/.test(p)) out = { id: id('trr'), amount: 4250, metadata: meta, list: p };
    else if (init.method === 'GET' && objects.has(p.split('/').pop())) return json(200, objects.get(p.split('/').pop()));
    else return json(404, { error: { code: 'resource_missing' } });
    objects.set(out.id, out);
    if (key) byKey.set(init.method + p + key, out);
    return json(200, out);
  };
  return f;
}
async function signed(ev, { secret = SECRET, t = Math.floor(Date.now() / 1000) } = {}) {
  const body = JSON.stringify(ev);
  return { body, header: 't=' + t + ',v1=' + await P.signature(secret, String(t), body) };
}
let evn = 0;
const event = (type, object, livemode = false) => ({ id: 'evt_' + (++evn) + 'x', type, livemode, data: { object } });
async function deliver(ev, opts) {
  const s = await signed(ev, opts);
  return P.webhook(su, stripe, await P.verifyEvent(SECRET, s.header, s.body));
}

let n = 0;
async function member(name) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('gh:' + name + (n++))], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  return { id: out.memberId, name, session: c.sha256hex(token) };
}
async function task() {
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member) values ('${project}', '${room}', 'A task', 'either', 1, 'member', '${poster.id}') returning id`);
  return t.id;
}
const bountyOf = async (taskId) => (await q(`select * from app.work_bounties where task_id = '${taskId}'`))[0];
const fund = (taskId, cents = 5000) => run(ctxOf(poster), (t) => t`select app.bounty_fund_request(${taskId}, ${cents}) as id`).then((r) => r[0].id);
const requestOf = async (id) => (await q(`select * from app.pay_requests where id = '${id}'`))[0];
async function paidSession(taskId) {
  await fund(taskId);
  await P.tick(su, stripe);
  const b = await bountyOf(taskId);
  const s = fake.objects.get(b.stripe_checkout_session_id);
  s.payment_status = 'paid';
  s.payment_intent = { id: 'pi_' + b.id.replace(/-/g, ''), latest_charge: { id: 'ch_' + b.id.replace(/-/g, '') } };
  return deliver(event('checkout.session.completed', { id: s.id }));
}
async function finalPoints(taskId) {
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at) values ('${taskId}', '${worker.id}', '${crypto.randomBytes(32).toString('hex')}', now() + interval '1 day') returning id`);
  const [sb] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, decided_by)
    values ('${taskId}', '${cl.id}', 'member', '${worker.id}', 'link', 'https://example.org/w', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'passed', 'poster') returning id`);
  const [p] = await q(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, size, confidence, independence, points, final_at)
    values ('${sb.id}', '${taskId}', '${room}', 'member', '${worker.id}', 1, 100, 100, 10, now() + interval '3 days') returning id`);
  await q(`update app.work_points set status = 'final' where id = '${p.id}'`);
  return p.id;
}

test.before(async () => {
  P = await import('../supabase/functions/dog-pay/core.mjs');
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
  fake = fakeStripe();
  stripe = P.stripeClient('rk_test_abc123', fake.fetch);
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

test('PM10: funding: Checkout on the platform account, paid only by Stripe\'s signed and re-read answer, once', async () => {
  const t1 = await task();
  const rid = await fund(t1);
  assert.deepEqual(await P.tick(su, stripe), { done: 1, failed: 0, retry: 0 });
  const r = await requestOf(rid);
  assert.equal(r.status, 'done');
  assert.match(r.hosted_url, /^https:\/\/checkout\.stripe\.com\//);
  const call = fake.calls.find((x) => x.path === '/v1/checkout/sessions');
  assert.equal(call.key, rid, 'the request row is the Idempotency-Key');
  assert.equal(call.params['line_items[0][price_data][unit_amount]'], '5000');
  assert.equal(call.params['payment_intent_data[transfer_group]'], (await bountyOf(t1)).id);
  assert.equal((await bountyOf(t1)).status, 'funding');
  // Not paid yet: an event says completed but Stripe's own copy says unpaid.
  const b = await bountyOf(t1);
  assert.equal((await deliver(event('checkout.session.completed', { id: b.stripe_checkout_session_id }))).handled, 'not_paid');
  assert.equal((await bountyOf(t1)).status, 'funding');
  // Paid.
  const s = fake.objects.get(b.stripe_checkout_session_id);
  s.payment_status = 'paid';
  s.payment_intent = { id: 'pi_one', latest_charge: { id: 'ch_one' } };
  const ev = event('checkout.session.completed', { id: s.id });
  assert.equal((await deliver(ev)).handled, 'funded');
  const f = await bountyOf(t1);
  assert.deepEqual([f.status, f.charged_cents, f.stripe_charge_id, f.listed], ['funded', 5000, 'ch_one', true]);
  // The same event again does nothing; a second event for the same session doesn't fund twice.
  assert.equal((await deliver(ev)).duplicate, true);
  assert.equal((await deliver(event('checkout.session.completed', { id: s.id }))).handled, 'already');
  assert.equal((await q(`select count(*)::int as n from app.pay_ledger where bounty_id = '${f.id}' and kind = 'charge'`))[0].n, 1);
});

test('PM11: a forged, stale, unsigned or other-mode event changes nothing', async () => {
  const ev = event('checkout.session.completed', { id: 'cs_test_x' });
  const s = await signed(ev, { secret: 'whsec_wrongsecret' });
  await assert.rejects(P.verifyEvent(SECRET, s.header, s.body), /bad_signature/);
  const old = await signed(ev, { t: Math.floor(Date.now() / 1000) - 3600 });
  await assert.rejects(P.verifyEvent(SECRET, old.header, old.body), /stale_signature/);
  await assert.rejects(P.verifyEvent(SECRET, '', '{}'), /bad_signature/);
  await assert.rejects(P.verifyEvent('', 't=1,v1=x', '{}'), /webhook_secret_missing/);
  assert.equal((await deliver(event('checkout.session.completed', { id: 'cs_test_x' }, true))).handled, 'wrong_mode');
});

test('PM12: a release waits for the worker\'s payouts, then transfers the bounty less 15%, once', async () => {
  const t1 = await task();
  await paidSession(t1);
  await finalPoints(t1);
  assert.equal((await bountyOf(t1)).status, 'releasing');
  // The worker has no Stripe account yet: the bounty waits, nothing is lost.
  await P.tick(su, stripe);
  assert.equal((await bountyOf(t1)).status, 'awaiting_payee');
  // The worker onboards.
  const [{ id: onb }] = await run(ctxOf(worker), (t) => t`select app.connect_onboard_request() as id`);
  await P.tick(su, stripe);
  const ob = await requestOf(onb);
  assert.match(ob.hosted_url, /^https:\/\/connect\.stripe\.com\//);
  const [acct] = await q(`select stripe_account from app.pay_accounts where member_id = '${worker.id}'`);
  fake.objects.set(acct.stripe_account, { id: acct.stripe_account, payouts_enabled: true, details_submitted: true });
  assert.equal((await deliver(event('account.updated', { id: acct.stripe_account }))).released, 1);
  assert.equal((await bountyOf(t1)).status, 'releasing');
  await P.tick(su, stripe);
  const b = await bountyOf(t1);
  assert.deepEqual([b.status, b.transferred_cents, b.payee_member], ['released', 4250, worker.id]);
  const tr = fake.calls.filter((x) => x.method === 'POST' && x.path === '/v1/transfers');
  assert.equal(tr.length, 1);
  assert.equal(tr[0].params.destination, acct.stripe_account);
  assert.equal(tr[0].params.source_transaction, b.stripe_charge_id);
  const [l] = await q(`select amount_cents from app.pay_ledger where bounty_id = '${b.id}' and kind = 'transfer'`);
  assert.equal(Number(l.amount_cents), -4250);
});

test('PM13: a Stripe failure is tried again with the same key, and a repeat never pays twice', async () => {
  const t1 = await task();
  await paidSession(t1);
  await finalPoints(t1);
  fake.failNext = { status: 500, code: 'api_error' };
  const r1 = await P.tick(su, stripe);
  assert.equal(r1.retry, 1);
  const [waiting] = await q(`select next_at > now() + interval '1 minute' as later from app.pay_requests where kind = 'release' and status = 'queued'`);
  assert.equal(waiting.later, true, 'a retry backs off');
  await q(`update app.pay_requests set next_at = now() where status = 'queued'`);
  await P.tick(su, stripe);
  const b = await bountyOf(t1);
  assert.equal(b.status, 'released');
  const keys = fake.calls.filter((x) => x.method === 'POST' && x.path === '/v1/transfers' && x.params['metadata[bounty]'] === b.id).map((x) => x.key);
  assert.equal(new Set(keys).size, 1, 'every try used the same Idempotency-Key');
  // A card error is final, not retried.
  const t2 = await task();
  await fund(t2);
  fake.failNext = { status: 402, code: 'card_declined' };
  assert.equal((await P.tick(su, stripe)).failed, 1);
  assert.equal((await bountyOf(t2)).status, 'failed');
});

test('PM14: removed work refunds the payer; after a payout, a reversal, and one that fails says so', async () => {
  const t1 = await task();
  await paidSession(t1);
  await q(`update app.work_tasks set status = 'removed' where id = '${t1}'`);
  await P.tick(su, stripe);
  assert.equal((await bountyOf(t1)).status, 'refunded');

  const t2 = await task();
  await paidSession(t2);
  const p = await finalPoints(t2);
  await P.tick(su, stripe);
  assert.equal((await bountyOf(t2)).status, 'released');
  await q(`update app.work_points set status = 'removed' where id = '${p}'`);
  fake.failNext = { status: 400, code: 'balance_insufficient' };
  await P.tick(su, stripe);
  assert.equal((await bountyOf(t2)).status, 'reversal_failed');
});

test('PM15: a chargeback marks the bounty and the ledger', async () => {
  const t1 = await task();
  await paidSession(t1);
  const b = await bountyOf(t1);
  fake.objects.set('dp_one', { id: 'dp_one', charge: b.stripe_charge_id, amount: 5000 });
  assert.equal((await deliver(event('charge.dispute.created', { id: 'dp_one' }))).handled, 'chargeback');
  assert.equal((await bountyOf(t1)).status, 'chargeback');
});

test('PM16: the code: Stripe only, no token, two named secrets, nothing logged, a restricted key only', async () => {
  assert.throws(() => P.stripeClient('sk_live_abc', fake.fetch), /stripe_key_missing/, 'a secret key is refused: restricted keys only');
  assert.throws(() => P.stripeClient('', fake.fetch), /stripe_key_missing/);
  const ix = read('supabase/functions/dog-pay/index.ts'), core = read('supabase/functions/dog-pay/core.mjs');
  for (const src of [ix, core]) {
    assert.doesNotMatch(src, /authorization["']?\)|x-vercel-oidc-token|vercel-oidc|console\.(log|error|info)/i);
  }
  assert.doesNotMatch(ix, /req\.headers\.get\("authorization"\)/);
  assert.match(ix, /name = any\(\$\{\["dog_pay_stripe_key", "dog_pay_webhook_secret", "dog_pay_connect_secret"\]\}\)/);
  assert.match(ix, /enabled_events: CONNECT_EVENTS, connect: true/, 'workers\' account events come only to an endpoint made with connect=true');
  assert.match(ix, /return reply\(200, \{ ok: true \}\); \/\/ nothing about the work/);
  assert.match(read('supabase/config.toml'), /\[functions\.dog-pay\]\nverify_jwt = false/);
  await assert.rejects(stripe.call('POST', '/v1/../../evil', {}), /bad_path/);
});

test('PM21: a retry under a new request finds the transfer or refund Stripe already made, and never makes a second', async () => {
  const t1 = await task();
  await paidSession(t1);
  await finalPoints(t1);
  await P.tick(su, stripe);
  const b = await bountyOf(t1);
  assert.equal(b.status, 'released');
  // As if the record had been lost after Stripe acted: back to transferring, with a fresh request.
  await q(`alter table app.work_bounties disable trigger work_bounties_guard`);
  await q(`update app.work_bounties set status = 'transferring' where id = '${b.id}'`);
  await q(`alter table app.work_bounties enable always trigger work_bounties_guard`);
  await q(`update app.pay_requests set status = 'failed' where bounty_id = '${b.id}' and kind = 'release'`);
  await q(`insert into app.pay_requests (member_id, kind, bounty_id) values ('${worker.id}', 'release', '${b.id}')`);
  const before = fake.calls.filter((x) => x.method === 'POST' && x.path === '/v1/transfers').length;
  await P.tick(su, stripe);
  assert.equal(fake.calls.filter((x) => x.method === 'POST' && x.path === '/v1/transfers').length, before, 'no second transfer');
  assert.equal((await bountyOf(t1)).status, 'released');
});

test('PM22: a payment that arrives after its task closed goes back; one whose work went final meanwhile is paid out', async () => {
  const t1 = await task();
  await fund(t1);
  await P.tick(su, stripe);
  await q(`update app.work_tasks set status = 'closed' where id = '${t1}'`);
  const b = await bountyOf(t1);
  const s = fake.objects.get(b.stripe_checkout_session_id);
  s.payment_status = 'paid';
  s.payment_intent = { id: 'pi_late', latest_charge: { id: 'ch_late' } };
  assert.equal((await deliver(event('checkout.session.completed', { id: s.id }))).handled, 'funded_then_refunding');
  assert.equal((await bountyOf(t1)).status, 'refunding');
});

test('PM23: a chargeback while a transfer is in flight waits for Stripe to send it again', async () => {
  const t1 = await task();
  await paidSession(t1);
  const b = await bountyOf(t1);
  await finalPoints(t1);
  await q(`update app.work_bounties set status = 'transferring' where id = '${b.id}'`);
  fake.objects.set('dp_two', { id: 'dp_two', charge: b.stripe_charge_id, amount: 5000 });
  await assert.rejects(deliver(event('charge.dispute.created', { id: 'dp_two' })), /busy/);
  assert.equal((await q(`select count(*)::int as n from app.pay_events where object_id = 'dp_two'`))[0].n, 0, 'not recorded, so Stripe\'s next try is handled');
});
