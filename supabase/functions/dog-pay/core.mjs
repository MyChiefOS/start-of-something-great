// dog-pay: the only code that talks to Stripe (061; Aaron, Nov 11, 2026). Shared by the Supabase function (index.ts)
// and the tests, so the code CI tests is the code that runs.
//
// It is reached with no token at all (control 8: the site's Vercel identity token goes only to the key broker):
//   * tick: "there may be work". No header, no body. It acts only on request rows the database wrote
//     (app.pay_requests), under its own narrow role (dog_pay), oldest first, a few at a time.
//   * webhook: Stripe's event, trusted only when its signature checks with the endpoint's secret; then the object is
//     read again from Stripe before anything is written, because Stripe does not promise the order of events.
// Every Stripe call that creates something carries the request row's id as its Idempotency-Key, so a retry can never
// charge or pay twice; every event is recorded once by its id. Outbound calls go to api.stripe.com and nowhere else.
// It never logs a value, a key or a person: only the outcome's kind.

export const STRIPE = 'https://api.stripe.com';
export const SITE = 'https://dayonegreat.com';
const TOLERANCE = 300; // seconds: Stripe's own default for a signature's age
const BATCH = 10;

export class PayError extends Error {
  constructor(code, status) { super(code); this.code = code; this.status = status; }
}

// ---- Stripe's API: form-encoded, one fixed host, no redirects ----
export function form(obj, prefix = '', out = []) {
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    const key = prefix ? prefix + '[' + k + ']' : k;
    if (Array.isArray(v)) v.forEach((x, i) => (typeof x === 'object' ? form(x, key + '[' + i + ']', out) : out.push([key + '[' + i + ']', String(x)])));
    else if (typeof v === 'object') form(v, key, out);
    else out.push([key, String(v)]);
  }
  return out;
}
export function stripeClient(key, fetchImpl = fetch) {
  // Anchored, one character class, no nesting: linear time (Semgrep's regex_dos is a heuristic); the key comes from Vault.
  if (!/^rk_(live|test)_[A-Za-z0-9]+$/.test(key || '')) throw new PayError('stripe_key_missing'); // nosemgrep: semgrep.ajinabraham.njsscan.dos.regex_dos.regex_dos
  const call = async (method, path, params, idem) => {
    if (!/^\/v1\/[a-z_]+(\/[A-Za-z0-9_]+){0,3}$/.test(path)) throw new PayError('bad_path');
    const url = new URL(path, STRIPE);
    if (url.origin !== STRIPE) throw new PayError('bad_host');
    // No Stripe-Version header: the account's own API version, pinned when Aaron opens it.
    const headers = { authorization: 'Bearer ' + key };
    let body;
    if (method === 'GET') { for (const [k, v] of form(params || {})) url.searchParams.append(k, v); }
    else { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(form(params || {})).toString(); }
    if (idem) headers['idempotency-key'] = idem;
    const r = await fetchImpl(url.toString(), { method, headers, body, redirect: 'error', signal: AbortSignal.timeout(20000) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new PayError((j.error && (j.error.code || j.error.type)) || 'stripe_' + r.status, r.status);
    return j;
  };
  return { call, live: key.startsWith('rk_live_') };
}

// ---- Stripe's signature (Stripe-Signature: t=<time>,v1=<hex HMAC-SHA256 of "t.body">) ----
const sha256hex = async (text) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, '0')).join('');
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
export async function signature(secret, t, body) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(t + '.' + body)));
}
// secret: one secret, or a list (the platform endpoint's and the connected accounts' endpoint's).
export async function verifyEvent(secret, header, body, now = Date.now() / 1000) {
  const secrets = (Array.isArray(secret) ? secret : [secret]).filter((x) => /^whsec_[A-Za-z0-9]+$/.test(x || ''));
  if (!secrets.length) throw new PayError('webhook_secret_missing', 503);
  const parts = Object.create(null);
  for (const p of String(header || '').split(',')) {
    const [k, v] = p.split('=');
    if (k === 't') parts.t = v;
    if (k === 'v1') (parts.v1 = parts.v1 || []).push(v);
  }
  const t = Number(parts.t);
  if (!Number.isInteger(t) || !parts.v1) throw new PayError('bad_signature', 400);
  if (Math.abs(now - t) > TOLERANCE) throw new PayError('stale_signature', 400);
  // Constant time over equal lengths.
  const same = (a, b) => a.length === b.length && [...a].reduce((d, ch, i) => d | (ch.charCodeAt(0) ^ b.charCodeAt(i)), 0) === 0;
  let ok = false;
  for (const sec of secrets) { const want = await signature(sec, parts.t, body); if (parts.v1.some((v) => same(v, want))) ok = true; }
  if (!ok) throw new PayError('bad_signature', 400);
  let ev;
  try { ev = JSON.parse(body); } catch { throw new PayError('bad_body', 400); }
  if (!ev || typeof ev.id !== 'string' || !/^evt_[A-Za-z0-9]+$/.test(ev.id) || typeof ev.type !== 'string' || !/^[a-z_.]{1,100}$/.test(ev.type)) throw new PayError('bad_body', 400);
  return ev;
}

// ---- Work on the database, as dog_pay ----
const asPay = (sql, fn) => sql.begin(async (t) => { await t`set local role dog_pay`; await t`set local statement_timeout = '15s'`; return fn(t); });
const fee = (b) => Math.floor(b.bounty_cents * b.platform_fee_bps / 10000);

// Claims up to BATCH requests that are due (each once, even with two ticks at once; one taken up more than 10 minutes
// ago and never finished is taken up again) and does them. Answers nothing about them.
export async function tick(sql, stripe, { site = SITE } = {}) {
  const rows = await asPay(sql, (t) => t`update app.pay_requests r set status = 'working', attempts = attempts + 1, claimed_at = now()
    where r.id in (select id from app.pay_requests
                   where (status = 'queued' and next_at <= now()) or (status = 'working' and claimed_at < now() - interval '10 minutes')
                   order by next_at limit ${BATCH} for update skip locked)
    returning r.*`);
  const out = { done: 0, failed: 0, retry: 0 };
  for (const r of rows) {
    try {
      await doRequest(sql, stripe, r, site);
      out.done++;
    } catch (e) {
      const code = String((e && e.code) || 'error').toLowerCase().replace(/[^a-z_]/g, '_').slice(0, 64) || 'error';
      // A Stripe, network or database failure is tried again, backing off over hours (Stripe replays a saved error for
      // the same key for 24 hours; the fresh review of PR #2, H2). Before any retry creates something at Stripe, the
      // request first asks Stripe whether it already exists (find, below), so a retry can't make it twice.
      const transient = !(e instanceof PayError) || e.status === 429 || e.status >= 500;
      const final = !transient || r.attempts >= 30;
      const wait = Math.min(360, 2 ** Math.min(r.attempts, 9)); // minutes: 2, 4, ... 6 hours
      await asPay(sql, (t) => t`update app.pay_requests set status = ${final ? 'failed' : 'queued'}, error_code = ${code},
        next_at = now() + make_interval(mins => ${wait}), done_at = case when ${final} then now() end where id = ${r.id}`);
      if (final) await onFailed(sql, r, code);
      out[final ? 'failed' : 'retry']++;
    }
  }
  await check(sql);
  return out;
}

const alert = (t, title, body, key) => t`select app.notify(null, 'alert', ${title}, ${body}, '/admin/controls', null, null, ${key})`;

// A request that failed for good puts its bounty back where a new request can take it, and tells the administrators.
async function onFailed(sql, r, code) {
  await asPay(sql, async (t) => {
    if (r.kind === 'fund_task' && r.bounty_id) await t`update app.work_bounties set status = 'failed' where id = ${r.bounty_id} and status = 'funding'`;
    if (r.kind === 'release' && r.bounty_id) {
      await t`update app.work_bounties set status = ${code === 'payee_not_ready' ? 'awaiting_payee' : 'releasing'} where id = ${r.bounty_id} and status = 'transferring'`;
      if (code === 'payee_not_ready') await t`update app.work_bounties set status = 'awaiting_payee' where id = ${r.bounty_id} and status = 'releasing'`;
    }
    if (r.kind === 'refund' && r.bounty_id) await t`update app.work_bounties set status = 'refunding' where id = ${r.bounty_id} and status = 'sending_refund'`;
    if (r.kind === 'reverse' && r.bounty_id) await t`update app.work_bounties set status = 'reversal_failed' where id = ${r.bounty_id} and status = 'reversing'`;
    if (code !== 'payee_not_ready' && r.kind !== 'fund_task' && r.kind !== 'connect_onboard') {
      await alert(t, 'A payment step failed', 'A ' + r.kind + ' for a funded task failed at Stripe (' + code + '). The daily check tries it again; see Owner controls.',
        'pay:' + r.kind + ':' + r.bounty_id);
    }
  });
}

// The daily check (every tick, cheap): money that is waiting with no request working on it gets one, once an hour at
// most, and the administrators are told, once a day. Nothing is lost if a request failed or a trigger was skipped.
async function check(sql) {
  await asPay(sql, async (t) => {
    const stuck = await t`select b.id, b.status, b.payer_member, b.payee_member from app.work_bounties b
      where b.status = any (array['releasing', 'refunding']) and b.updated_at < now() - interval '1 hour'
        and not exists (select 1 from app.pay_requests r where r.bounty_id = b.id and r.status <> 'failed'
                          and r.kind = case when b.status = 'releasing' then 'release' else 'refund' end)
        and not exists (select 1 from app.pay_requests r where r.bounty_id = b.id and r.created_at > now() - interval '1 hour')
      limit 20`;
    for (const b of stuck) {
      await t`insert into app.pay_requests (member_id, kind, bounty_id) values (${b.status === 'releasing' ? b.payee_member : b.payer_member},
        ${b.status === 'releasing' ? 'release' : 'refund'}, ${b.id}) on conflict do nothing`;
    }
    if (stuck.length) await alert(t, 'Payments waiting', stuck.length + ' funded task' + (stuck.length > 1 ? 's were' : ' was') + ' waiting for a release or a refund; each has been asked again.',
      'pay:stuck:' + new Date().toISOString().slice(0, 10));
  });
}

const done = (t, r, fields = {}) => t`update app.pay_requests set status = 'done', done_at = now(), error_code = null,
  hosted_url = ${fields.url || null}, stripe_object_id = ${fields.object || null} where id = ${r.id}`;

// What Stripe already has for this bounty, so a retry under a new key never makes it twice.
async function find(stripe, path, params, bountyId) {
  const list = await stripe.call('GET', path, { ...params, limit: 10 });
  return ((list && list.data) || []).find((x) => x.metadata && x.metadata.bounty === bountyId) || null;
}
// Moves a bounty from one state to the next only if it is still in the first; false if something else moved it.
async function move(t, id, from, to) {
  const r = await t`update app.work_bounties set status = ${to} where id = ${id} and status = ${from} returning id`;
  return r.length === 1;
}

async function doRequest(sql, stripe, r, site) {
  if (r.kind === 'connect_onboard') {
    let [acct] = await asPay(sql, (t) => t`select stripe_account from app.pay_accounts where member_id = ${r.member_id}`);
    if (!acct) {
      // The key is a hash, not the member's ID (Stripe advises against personal identifiers as keys).
      const key = 'acct-' + await sha256hex('dog-pay account ' + r.member_id);
      const a = await stripe.call('POST', '/v1/accounts', {
        type: 'express', country: 'US', capabilities: { transfers: { requested: true } },
        business_profile: { product_description: 'Audited work on Day One Great' },
        metadata: { request: r.id }
      }, key);
      await asPay(sql, (t) => t`insert into app.pay_accounts (member_id, stripe_account, livemode) values (${r.member_id}, ${a.id}, ${stripe.live})
        on conflict (member_id) do nothing`);
      [acct] = await asPay(sql, (t) => t`select stripe_account from app.pay_accounts where member_id = ${r.member_id}`);
    }
    const link = await stripe.call('POST', '/v1/account_links', {
      account: acct.stripe_account, type: 'account_onboarding',
      refresh_url: site + '/account?payouts=retry', return_url: site + '/account?payouts=done'
    }, r.id);
    return asPay(sql, (t) => done(t, r, { url: link.url, object: acct.stripe_account }));
  }
  const [b] = await asPay(sql, (t) => t`select * from app.work_bounties where id = ${r.bounty_id}`);
  if (!b) throw new PayError('no_bounty');
  if (r.kind === 'fund_task') {
    if (b.status !== 'funding') return asPay(sql, (t) => done(t, r));
    const s = await stripe.call('POST', '/v1/checkout/sessions', {
      mode: 'payment', client_reference_id: b.id,
      line_items: [{ quantity: 1, price_data: { currency: 'usd', unit_amount: b.bounty_cents, product_data: { name: 'Funded task on Day One Great' } } }],
      payment_intent_data: { transfer_group: b.id, metadata: { bounty: b.id } },
      metadata: { bounty: b.id },
      billing_address_collection: 'required',
      success_url: site + '/build?funded=' + b.task_id, cancel_url: site + '/build?funded=cancel'
    }, r.id);
    return asPay(sql, async (t) => {
      await t`update app.work_bounties set stripe_checkout_session_id = ${s.id} where id = ${b.id} and status = 'funding'`;
      await done(t, r, { url: s.url, object: s.id });
    });
  }
  if (r.kind === 'release') {
    if (b.status !== 'releasing' && b.status !== 'transferring') return asPay(sql, (t) => done(t, r));
    let [acct] = await asPay(sql, (t) => t`select stripe_account, payouts_enabled from app.pay_accounts where member_id = ${b.payee_member}`);
    if (!acct) throw new PayError('payee_not_ready', 409);
    if (!acct.payouts_enabled) {
      // Ask Stripe, not only its events (the fresh review of PR #2, H1).
      const a = await stripe.call('GET', '/v1/accounts/' + acct.stripe_account, {});
      await asPay(sql, (t) => t`update app.pay_accounts set payouts_enabled = ${Boolean(a.payouts_enabled)}, details_submitted = ${Boolean(a.details_submitted)}, updated_at = now()
        where stripe_account = ${acct.stripe_account}`);
      if (!a.payouts_enabled) throw new PayError('payee_not_ready', 409);
    }
    // In flight: from here the triggers can't refund it. Points removed now ask for a reversal once it is recorded (C1).
    if (b.status === 'releasing' && !(await asPay(sql, (t) => move(t, b.id, 'releasing', 'transferring')))) return asPay(sql, (t) => done(t, r));
    const amount = b.bounty_cents - fee(b);
    const tr = (await find(stripe, '/v1/transfers', { transfer_group: b.id }, b.id)) || await stripe.call('POST', '/v1/transfers', {
      amount, currency: 'usd', destination: acct.stripe_account, transfer_group: b.id, source_transaction: b.stripe_charge_id || undefined,
      metadata: { bounty: b.id }
    }, r.id);
    return asPay(sql, async (t) => {
      await t`update app.work_bounties set status = 'released', stripe_transfer_id = ${tr.id}, transferred_cents = ${tr.amount}, released_at = now() where id = ${b.id}`;
      await t`insert into app.pay_ledger (bounty_id, member_id, kind, amount_cents, stripe_object_id) values (${b.id}, ${b.payee_member}, 'transfer', ${-tr.amount}, ${tr.id})
        on conflict do nothing`;
      const [u] = await t`select undo_requested from app.work_bounties where id = ${b.id}`;
      if (u.undo_requested) {
        await t`update app.work_bounties set status = 'reversing' where id = ${b.id}`;
        await t`insert into app.pay_requests (member_id, kind, bounty_id) values (${b.payee_member}, 'reverse', ${b.id}) on conflict do nothing`;
      }
      await done(t, r, { object: tr.id });
    });
  }
  if (r.kind === 'refund') {
    if (b.status !== 'refunding' && b.status !== 'sending_refund') return asPay(sql, (t) => done(t, r));
    if (b.status === 'refunding' && !(await asPay(sql, (t) => move(t, b.id, 'refunding', 'sending_refund')))) return asPay(sql, (t) => done(t, r));
    const re = (await find(stripe, '/v1/refunds', { payment_intent: b.stripe_payment_intent_id }, b.id))
      || await stripe.call('POST', '/v1/refunds', { payment_intent: b.stripe_payment_intent_id, metadata: { bounty: b.id } }, r.id);
    return asPay(sql, async (t) => {
      await t`update app.work_bounties set status = 'refunded', stripe_refund_id = ${re.id}, refunded_at = now() where id = ${b.id}`;
      await t`insert into app.pay_ledger (bounty_id, member_id, kind, amount_cents, stripe_object_id) values (${b.id}, ${b.payer_member}, 'refund', ${-re.amount}, ${re.id})
        on conflict do nothing`;
      await done(t, r, { object: re.id });
    });
  }
  if (r.kind === 'reverse') {
    if (b.status !== 'reversing') return asPay(sql, (t) => done(t, r));
    const rv = (await find(stripe, '/v1/transfers/' + b.stripe_transfer_id + '/reversals', {}, b.id))
      || await stripe.call('POST', '/v1/transfers/' + b.stripe_transfer_id + '/reversals', { metadata: { bounty: b.id } }, r.id);
    return asPay(sql, async (t) => {
      await t`update app.work_bounties set status = 'reversed' where id = ${b.id}`;
      await t`insert into app.pay_ledger (bounty_id, member_id, kind, amount_cents, stripe_object_id) values (${b.id}, ${b.payee_member}, 'reversal', ${rv.amount}, ${rv.id})
        on conflict do nothing`;
      await done(t, r, { object: rv.id });
    });
  }
  throw new PayError('unknown_kind');
}

// ---- Stripe's events ----
// Returns { ok, duplicate?, handled } with no data. The event is recorded first, once; a repeat does nothing.
export async function webhook(sql, stripe, ev) {
  const obj = (ev.data && ev.data.object) || {};
  const objectId = typeof obj.id === 'string' && /^[a-z]+_[A-Za-z0-9_]+$/.test(obj.id) ? obj.id : null;
  if (Boolean(ev.livemode) !== stripe.live) return { ok: true, handled: 'wrong_mode' };
  const [seen] = await asPay(sql, (t) => t`select 1 from app.pay_events where stripe_event_id = ${ev.id}`);
  if (seen) return { ok: true, duplicate: true };
  // Done first, recorded after: if the work fails, Stripe sends the event again and it is done then. Doing it twice is
  // harmless: each step checks the bounty's state first, and the ledger takes each Stripe object once.
  const result = await handleEvent(sql, stripe, ev, obj, objectId);
  await asPay(sql, (t) => t`insert into app.pay_events (stripe_event_id, type, livemode, object_id) values (${ev.id}, ${ev.type}, ${Boolean(ev.livemode)}, ${objectId})
    on conflict (stripe_event_id) do nothing`);
  return result;
}

async function handleEvent(sql, stripe, ev, obj, objectId) {

  if (ev.type === 'checkout.session.completed' || ev.type === 'checkout.session.async_payment_succeeded') {
    // Read the session again from Stripe: the event's copy may be old, and only Stripe's own answer counts.
    const s = await stripe.call('GET', '/v1/checkout/sessions/' + objectId, { expand: ['payment_intent.latest_charge'] });
    const bounty = s.client_reference_id;
    if (s.payment_status !== 'paid' || !bounty) return { ok: true, handled: 'not_paid' };
    const pi = s.payment_intent || {};
    const charge = pi.latest_charge || {};
    return asPay(sql, async (t) => {
      const [b] = await t`select id, task_id, status, bounty_cents, payer_member, stripe_checkout_session_id from app.work_bounties where id = ${bounty} for update`;
      if (!b || b.stripe_checkout_session_id !== s.id) return { ok: true, handled: 'unknown_session' };
      if (b.status !== 'funding') return { ok: true, handled: 'already' };
      await t`update app.work_bounties set status = 'funded', livemode = ${Boolean(s.livemode)}, stripe_payment_intent_id = ${pi.id},
        stripe_charge_id = ${charge.id || null}, charged_cents = ${s.amount_total}, funded_at = now() where id = ${b.id}`;
      await t`insert into app.pay_ledger (bounty_id, member_id, kind, amount_cents, stripe_object_id) values (${b.id}, ${b.payer_member}, 'charge', ${s.amount_total}, ${charge.id || pi.id})
        on conflict do nothing`;
      // The money arrived, but is it still wanted? A payment of the wrong amount, or for a task that closed or was removed
      // while the poster was paying, goes back; one whose work went final meanwhile is paid out (the fresh review, M2).
      const [task] = await t`select x.status, (select p.status from app.work_points p where p.task_id = x.id and p.status = 'final' limit 1) as final
        from app.work_tasks x where x.id = ${b.task_id}`;
      const back = s.amount_total !== b.bounty_cents || s.currency !== 'usd' || !task || (task.status !== 'open' && !task.final);
      if (back) {
        await t`update app.work_bounties set status = 'refunding' where id = ${b.id}`;
        await t`insert into app.pay_requests (member_id, kind, bounty_id) values (${b.payer_member}, 'refund', ${b.id}) on conflict do nothing`;
        return { ok: true, handled: 'funded_then_refunding' };
      }
      if (task.final) {
        const [p] = await t`select coalesce(p.citizen_member, a.owner_id) as member from app.work_points p left join app.agents a on a.id = p.citizen_agent
          where p.task_id = ${b.task_id} and p.status = 'final' order by p.created_at desc limit 1`;
        await t`update app.work_bounties set status = 'releasing', payee_member = ${p.member} where id = ${b.id}`;
        await t`insert into app.pay_requests (member_id, kind, bounty_id) values (${p.member}, 'release', ${b.id}) on conflict do nothing`;
        return { ok: true, handled: 'funded_then_releasing' };
      }
      return { ok: true, handled: 'funded' };
    });
  }
  if (ev.type === 'checkout.session.expired' || ev.type === 'checkout.session.async_payment_failed') {
    await asPay(sql, (t) => t`update app.work_bounties set status = 'failed' where stripe_checkout_session_id = ${objectId} and status = 'funding'`);
    return { ok: true, handled: 'failed' };
  }
  if (ev.type === 'account.updated') {
    const a = await stripe.call('GET', '/v1/accounts/' + objectId, {});
    return asPay(sql, async (t) => {
      const [acct] = await t`update app.pay_accounts set payouts_enabled = ${Boolean(a.payouts_enabled)}, details_submitted = ${Boolean(a.details_submitted)}, updated_at = now()
        where stripe_account = ${a.id} returning member_id`;
      if (!acct || !a.payouts_enabled) return { ok: true, handled: 'account' };
      // Bounties that waited for this worker's payouts go out now.
      const waiting = await t`update app.work_bounties set status = 'releasing' where payee_member = ${acct.member_id} and status = 'awaiting_payee' returning id`;
      for (const w of waiting) await t`insert into app.pay_requests (member_id, kind, bounty_id) values (${acct.member_id}, 'release', ${w.id}) on conflict do nothing`;
      return { ok: true, handled: 'account', released: waiting.length };
    });
  }
  if (ev.type === 'charge.dispute.created') {
    const d = await stripe.call('GET', '/v1/disputes/' + objectId, {});
    // A transfer or refund in flight finishes first: Stripe sends the event again later (it retries until we answer 200).
    const [busy] = await asPay(sql, (t) => t`select 1 from app.work_bounties where stripe_charge_id = ${d.charge} and status = any (array['transferring', 'sending_refund'])`);
    if (busy) throw new PayError('busy', 503);
    return asPay(sql, async (t) => {
      const [b] = await t`update app.work_bounties set status = 'chargeback'
        where stripe_charge_id = ${d.charge} and status = any (array['funded', 'releasing', 'awaiting_payee', 'refunding', 'released']) returning id, payer_member`;
      if (!b) return { ok: true, handled: 'unknown_charge' };
      await t`insert into app.pay_ledger (bounty_id, member_id, kind, amount_cents, stripe_object_id) values (${b.id}, ${b.payer_member}, 'chargeback', ${-d.amount}, ${d.id})
        on conflict do nothing`;
      return { ok: true, handled: 'chargeback' };
    });
  }
  return { ok: true, handled: 'ignored' };
}
