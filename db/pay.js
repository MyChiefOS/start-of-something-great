// Funded bounties (061), the site's side: a person asks to fund a task or to set up payouts, and reads back the address
// of Stripe's own page when the payment function (supabase/functions/dog-pay) has made it. The site never talks to
// Stripe, never holds a Stripe key, and never sees a card or a bank account: those stay on Stripe's pages.
'use strict';

const v = require('./validate');
const c = require('../signin/crypto');
const store = require('./signin');
const { call, WorkError } = require('./work');

const DOG_PAY = 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-pay/tick';
// Per person, as every route limits: 20 fundings and 10 payout set-ups an hour.
const LIMITS = { pay_fund: { windowSeconds: 3600, max: 20 }, pay_onboard: { windowSeconds: 3600, max: 10 } };

async function limited(t, bucket, memberId) {
  return !(await store.rateLimitHit(t, { bucket, keyHash: c.sha256hex(bucket + ' ' + memberId), ...LIMITS[bucket] }));
}
// payments.json: "on" only by a pull request Aaron merges (his go-live decision for money). Anything else is off.
function switchedOn() {
  try { return require('../payments.json').payments === 'on'; } catch { return false; }
}
function person(ctx) {
  if (!switchedOn()) throw new WorkError(503, 'Payments aren\'t switched on yet. Funded tasks are coming; nothing is charged until they are.', 'payments_off');
  if (!ctx || ctx.actor === 'agent' || !ctx.memberId) throw new WorkError(403, 'Only a person signed in on the site funds a task or sets up payouts; an agent can\'t.', 'forbidden');
}

// { request }: fund an open task you posted, in whole dollars ($10 to $10,000).
async function fund(t, ctx, { task, dollars }) {
  person(ctx);
  const id = v.uuid('task', task);
  if (!Number.isInteger(dollars) || dollars < 10 || dollars > 10000) throw new WorkError(400, 'A bounty is a whole number of dollars, $10 to $10,000.', 'bad_request');
  if (await limited(t, 'pay_fund', ctx.memberId)) throw new WorkError(429, 'Too many payments started in the last hour. Try again later.', 'slow');
  const [r] = await call(t, (s) => s`select app.bounty_fund_request(${id}::uuid, ${dollars * 100}::integer) as id`);
  return { request: r.id };
}
// { request }: set up payouts (Stripe Express onboarding).
async function payouts(t, ctx) {
  person(ctx);
  if (await limited(t, 'pay_onboard', ctx.memberId)) throw new WorkError(429, 'Too many tries in the last hour. Try again later.', 'slow');
  const [r] = await call(t, (s) => s`select app.connect_onboard_request() as id`);
  return { request: r.id };
}
// One of your own requests: its state, and Stripe's page once it is ready (row-level security: only your own).
async function request(t, id) {
  const [r] = await t`select id, kind, status, hosted_url, error_code from app.pay_requests where id = ${v.uuid('request', id)}::uuid`;
  if (!r) return null;
  return { id: r.id, kind: r.kind, status: r.status, url: r.status === 'done' ? r.hosted_url : null, error: r.error_code };
}
// Tell the payment function there is work. No header, no body, no token (control 8); a failure only delays the work
// until the minute timer pokes it.
async function poke(fetchImpl = fetch) {
  try { await fetchImpl(DOG_PAY, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(3000) }); } catch { /* the timer will */ }
}

module.exports = { fund, payouts, request, poke, switchedOn, DOG_PAY, LIMITS };
