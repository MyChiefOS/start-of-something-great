// Notifications (PR 13). The rules live in the database (011_notifications.sql); this file checks inputs and turns
// refusals into plain outcomes. Every query is a tagged template (S8), under the caller's own row-level security.
// Members read and mark their own notices; the site itself (actor "system") runs the timers and the outbox drain.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;
const KINDS = ['draft_waiting', 'draft_expired', 'report_upheld', 'brake_on', 'contained', 'containment_lifted', 'appeal_decided',
  'act_reconfirm', 'act_expired', 'challenge', 'alert'];
const DEDUPE = /^[a-z0-9_:.-]{1,160}$/;
const LINK = /^\/[A-Za-z0-9/?=&#._~%-]{0,199}$/;
const TZ = /^[A-Za-z]+(\/[A-Za-z0-9_+-]+){0,2}$/;

// ---- Leaving a notice (for JEVs and anything else that needs to tell someone) ----
// In the caller's own transaction, so the notice and its email copy exist exactly when the event does.
// memberId null means Aaron's inbox (kind 'alert' only). Returns true if new, false if this event already left one.
async function notify(t, { memberId, kind, title, body = '', link = null, subjectKind = null, subjectId = null, dedupeKey, email = false }) {
  const m = memberId === null ? null : v.uuid('memberId', memberId);
  const k = v.oneOf('kind', kind, KINDS);
  if (m === null && k !== 'alert') throw new v.ValidationError('memberId', 'can be empty only for an alert to Aaron');
  const args = [m, k, v.text('title', title, { max: 120 }), body === '' ? '' : v.text('body', body, { max: 2000, multiline: true }),
    link === null ? null : v.text('link', link, { max: 200, pattern: LINK }),
    subjectKind === null ? null : v.text('subjectKind', subjectKind, { max: 32, pattern: /^[a-z][a-z_]*$/ }),
    subjectId === null ? null : v.uuid('subjectId', subjectId), v.text('dedupeKey', dedupeKey, { max: 160, pattern: DEDUPE }), email === true];
  const [r] = await t`select app.notify(${args[0]}::uuid, ${args[1]}, ${args[2]}, ${args[3]}, ${args[4]}, ${args[5]}, ${args[6]}::uuid, ${args[7]}, ${args[8]}) as fresh`;
  return r.fresh === true;
}
const challenge = (t, { memberId, title, body, link = null, subjectKind = null, subjectId = null, dedupeKey }) =>
  notify(t, { memberId, kind: 'challenge', title, body, link, subjectKind, subjectId, dedupeKey, email: true });
const alertAaron = (t, { title, body, link = null, subjectKind = null, subjectId = null, dedupeKey }) =>
  notify(t, { memberId: null, kind: 'alert', title, body, link, subjectKind, subjectId, dedupeKey, email: true });

// ---- The inbox ----
const shapeNotice = (n) => ({ id: n.id, kind: n.kind, title: n.title, body: n.body, link: n.link, created_at: n.created_at,
  read: n.read_at !== null, for_admins: n.member_id === null });

// The signed-in member's newest notices (Aaron's include the administrators' inbox) and how many are unread.
async function inbox(t, { limit = 50 } = {}) {
  const n = v.int('limit', limit, { min: 1, max: 100 });
  const rows = await t`select id, member_id, kind, title, body, link, created_at, read_at from app.notices
                       where member_id = app.current_member() or member_id is null order by created_at desc, id desc limit ${n}`;
  const [u] = await t`select count(*)::int as n from app.notices where (member_id = app.current_member() or member_id is null) and read_at is null`;
  return { unread: u.n, notices: rows.map(shapeNotice) };
}

async function unread(t) {
  const [u] = await t`select count(*)::int as n from app.notices where (member_id = app.current_member() or member_id is null) and read_at is null`;
  return u.n;
}

// Marks some notices read (ids), or all of them. Returns how many changed.
async function markRead(t, { ids = null, all = false } = {}) {
  if (all === true) {
    const r = await t`update app.notices set read_at = now() where read_at is null and (member_id = app.current_member() or member_id is null)`;
    return r.count;
  }
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > 100) throw new v.ValidationError('ids', 'must list 1 to 100 notices');
  const list = ids.map((x) => v.uuid('ids', x));
  const r = await t`update app.notices set read_at = now() where read_at is null and id in ${t(list)}`;
  return r.count;
}

// ---- Email copies (the member's own) ----
async function contact(t) {
  const [c] = await t`select id, address_sealed, status, quiet_start, quiet_end, time_zone, confirmed_at
                      from app.email_contacts where member_id = app.current_member()`;
  return c || null;
}

const tz = (s) => v.text('time_zone', s, { max: 64, pattern: TZ });
const hour = (f, x) => v.int(f, x, { min: 0, max: 23 });

// Adds or changes the member's address (already sealed and fingerprinted by the caller), and queues the confirmation
// email. { contactId } or { refused: 'time_zone' }.
async function setAddress(t, { sealed, fp, timeZone = 'America/Los_Angeles' }) {
  const s = v.text('sealed', sealed, { max: 800, pattern: /^[A-Za-z0-9_-]+$/ });
  if (typeof fp !== 'string' || !HEX64.test(fp)) throw new v.ValidationError('fingerprint', 'is not in the expected format');
  const z = tz(timeZone);
  try {
    return await t.savepoint(async (x) => {
      const [had] = await x`select id from app.email_contacts where member_id = app.current_member() for update`;
      let id;
      if (had) {
        await x`update app.email_contacts set address_sealed = ${s}, address_fp = ${fp}, time_zone = ${z}, status = 'pending' where id = ${had.id}`;
        id = had.id;
      } else {
        const [n] = await x`insert into app.email_contacts (member_id, address_sealed, address_fp, time_zone) values (app.current_member(), ${s}, ${fp}, ${z}) returning id`;
        id = n.id;
      }
      // One confirmation per request; the key includes the time so asking again sends again (rate limited by the caller).
      await x`insert into app.outbox (member_id, purpose, idempotency_key) values (app.current_member(), 'confirm_email', ${'confirm:' + id + ':' + Date.now()})`;
      return { contactId: id };
    });
  } catch (e) {
    if (e.code === '22023' && /time zone/.test(e.message)) return { refused: 'time_zone' };
    throw e;
  }
}

async function setPrefs(t, { quietStart, quietEnd, timeZone }) {
  const a = hour('quiet_start', quietStart), b = hour('quiet_end', quietEnd), z = tz(timeZone);
  try {
    const r = await t.savepoint((x) => x`update app.email_contacts set quiet_start = ${a}::smallint, quiet_end = ${b}::smallint, time_zone = ${z}
                                         where member_id = app.current_member()`);
    return r.count === 1 ? { ok: true } : { refused: 'no_address' };
  } catch (e) {
    if (e.code === '22023' && /time zone/.test(e.message)) return { refused: 'time_zone' };
    throw e;
  }
}

// Switch copies off, or back on for an address already confirmed. { status } or { refused }.
async function setCopies(t, on) {
  try {
    const r = await t.savepoint((x) => x`update app.email_contacts set status = ${on ? 'active' : 'off'}
                                         where member_id = app.current_member() returning status`);
    return r.length ? { status: r[0].status } : { refused: 'no_address' };
  } catch (e) {
    if (e.code === '42501') return { refused: 'confirm_first' };
    throw e;
  }
}

async function removeAddress(t) {
  const r = await t`delete from app.email_contacts where member_id = app.current_member()`;
  return r.count === 1;
}

// ---- Safe one-tap links (R16, R33, confirming an address) ----
// What a link is for, before it is used. Changes nothing (a GET-safe look). null if it isn't this member's, or is
// unknown; { used: true } or { expired: true } otherwise where that applies.
async function previewLink(t, tokenHash) {
  if (typeof tokenHash !== 'string' || !HEX64.test(tokenHash)) return null;
  const [l] = await t`select id, purpose, subject_id, bound_hash, expires_at, used_at from app.action_links
                      where token_hash = ${tokenHash} and member_id = app.current_member()`;
  if (!l) return null;
  const base = { purpose: l.purpose, expiresAt: l.expires_at };
  if (l.used_at) return { ...base, used: true };
  if (l.expires_at <= new Date()) return { ...base, expired: true };
  if (l.purpose === 'approve_draft') {
    const [d] = await t`select d.body, d.status, d.expires_at, a.name from app.agent_drafts d join app.agents a on a.id = d.agent_id
                        where d.id = ${l.subject_id}`;
    if (!d) return null;
    return { ...base, draft: { id: l.subject_id, body: d.body, status: d.status, agentName: d.name } };
  }
  if (l.purpose === 'keep_acting') {
    const [r] = await t`select a.name, x.version, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap from app.agents a
                        join app.agent_rules x on x.agent_id = a.id where a.id = ${l.subject_id} order by x.version desc limit 1`;
    if (!r) return null;
    return { ...base, agent: { id: l.subject_id, name: r.name }, rules: { version: r.version, post: r.post_mode, reply: r.reply_mode, report: r.report_mode, daily_cap: r.daily_cap } };
  }
  return base;
}

// Uses a link, once, from the owner's own session. The approval must name the exact words the page showed (hash).
// { done: purpose, ... } or { refused: 'not_found' | 'used' | 'expired' | 'changed' | ... }. A refusal uses nothing up.
async function useLink(t, { tokenHash, hash = null }) {
  if (typeof tokenHash !== 'string' || !HEX64.test(tokenHash)) return { refused: 'not_found' };
  const [l] = await t`select id, purpose, subject_id, bound_hash, expires_at, used_at from app.action_links
                      where token_hash = ${tokenHash} and member_id = app.current_member() for update`;
  if (!l) return { refused: 'not_found' };
  if (l.used_at) return { refused: 'used' };
  if (l.expires_at <= new Date()) return { refused: 'expired' };
  try {
    return await t.savepoint(async (x) => {
      const spend = () => x`update app.action_links set used_at = now() where id = ${l.id}`;
      if (l.purpose === 'approve_draft') {
        if (typeof hash !== 'string' || !HEX64.test(hash) || hash !== l.bound_hash) return { refused: 'changed' };
        const [p] = await x`select * from app.approve_draft(${l.subject_id}::uuid, ${hash})`;
        await spend();
        return { done: 'approve_draft', post: { id: p.post_id, status: p.status } };
      }
      if (l.purpose === 'keep_acting') {
        const [r] = await x`select version, post_mode, reply_mode, report_mode, daily_cap from app.agent_rules
                            where agent_id = ${l.subject_id} order by version desc limit 1`;
        const [h] = await x`select app.keep_hash(${l.subject_id}::uuid, ${r ? r.version : 0}::integer) as h`;
        if (!r || h.h !== l.bound_hash) return { refused: 'changed' };
        const [n] = await x`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
                            values (${l.subject_id}, ${r.post_mode}, ${r.reply_mode}, ${r.report_mode}, ${r.daily_cap}::integer, 'reconfirmed') returning version`;
        await spend();
        return { done: 'keep_acting', agent: l.subject_id, version: n.version };
      }
      await spend();
      const r = await x`update app.email_contacts set status = 'active' where id = ${l.subject_id} and address_fp = ${l.bound_hash} and status = 'pending'`;
      if (r.count !== 1) throw Object.assign(new Error('changed'), { refusal: 'changed' });
      return { done: 'confirm_email' };
    });
  } catch (e) {
    if (e.refusal) return { refused: e.refusal };
    if (e.code === 'P0002') return { refused: 'not_found' };
    if (e.code === 'P0001' && ['stale', 'expired', 'changed', 'not_allowed', 'agent_off'].includes(e.message)) return { refused: e.message === 'stale' ? 'decided' : e.message };
    if (e.code === 'P0001' && e.message === 'brake') return { refused: 'brake', message: e.hint };
    if (e.code === 'P0001' && (e.message === 'link_used' || e.message === 'link_expired')) return { refused: e.message.slice(5) };
    if (e.code === '42501') return { refused: 'changed' };
    throw e;
  }
}

// ---- Keeping an agent acting on its own (R33), from the agents page ----
// The rules version the owner saw must still be the current one. { version } or { refused }.
async function reconfirm(t, { agent, version }) {
  const id = v.uuid('agent', agent);
  const ver = v.int('version', version, { min: 1, max: 1000000 });
  const [r] = await t`select x.version, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap from app.agent_rules x
                      join app.agents a on a.id = x.agent_id where x.agent_id = ${id} and a.owner_id = app.current_member() and a.status = 'active'
                      order by x.version desc limit 1`;
  if (!r) return { refused: 'not_found' };
  if (r.version !== ver) return { refused: 'changed' };
  try {
    const [n] = await t.savepoint((x) => x`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
      values (${id}, ${r.post_mode}, ${r.reply_mode}, ${r.report_mode}, ${r.daily_cap}::integer, 'reconfirmed') returning version`);
    return { version: n.version };
  } catch (e) {
    if (e.code === '42501') return { refused: 'not_acting' };
    throw e;
  }
}

// When each of the owner's agents that acts on its own was last confirmed, and when it needs confirming (R33).
async function actClock(t, agentIds) {
  if (!agentIds.length) return new Map();
  const rows = await t`select agent_id, max(created_at) as since from app.agent_rules
                       where agent_id in ${t(agentIds)} and set_by = 'owner' group by agent_id`;
  return new Map(rows.map((r) => [r.agent_id, r.since]));
}

// ---- Containment: the owner's view and appeal; Aaron's view and decision ----
async function myContainment(t) {
  const [c] = await t`select id, reason, measured, started_at, ends_at, appealed_at, appeal_decision from app.containments
                      where member_id = app.current_member() and lifted_at is null`;
  return c ? { id: c.id, reason: c.reason, measured: c.measured, startedAt: c.started_at, endsAt: c.ends_at,
    appealed: c.appealed_at !== null, decision: c.appeal_decision } : null;
}

async function appeal(t, { containment, note = null }) {
  const id = v.uuid('containment', containment);
  const n = note === null || note === undefined || note === '' ? null : v.text('note', note, { max: 500, multiline: true });
  try {
    const r = await t.savepoint((x) => x`update app.containments set appeal_note = ${n} where id = ${id} and member_id = app.current_member() and lifted_at is null`);
    return r.count === 1 ? { ok: true } : { refused: 'not_found' };
  } catch (e) {
    if (e.code === 'P0001' && e.message === 'already_appealed') return { refused: 'already' };
    throw e;
  }
}

// Aaron: open containments, appealed first.
async function appeals(t) {
  const rows = await t`select c.id, c.member_id, m.display_name, c.reason, c.measured, c.usual_x100, c.started_at, c.ends_at, c.appeal_note, c.appealed_at, c.appeal_decision
                       from app.containments c join app.members m on m.id = c.member_id where c.lifted_at is null
                       order by c.appealed_at is null, c.appealed_at, c.started_at limit 100`;
  return rows.map((r) => ({ id: r.id, member: { id: r.member_id, name: r.display_name }, reason: r.reason, measured: r.measured,
    usual: r.usual_x100 / 100, startedAt: r.started_at, endsAt: r.ends_at, appeal: r.appealed_at ? { note: r.appeal_note, at: r.appealed_at } : null,
    decision: r.appeal_decision }));
}

// Aaron decides: 'lift' (the agents go back to their rules now) or 'keep' (it ends by itself on time).
async function decideAppeal(t, { containment, decision }) {
  const id = v.uuid('containment', containment);
  const d = v.oneOf('decision', decision, ['lift', 'keep']);
  try {
    const r = await t.savepoint((x) => (d === 'lift'
      ? x`update app.containments set appeal_decision = case when appealed_at is not null then 'lifted' end, lifted_at = now() where id = ${id} and lifted_at is null`
      : x`update app.containments set appeal_decision = 'kept' where id = ${id} and lifted_at is null`));
    return r.count === 1 ? { ok: true } : { refused: 'not_found' };
  } catch (e) {
    if (e.code === '42501' || e.code === '23514') return { refused: 'stale' };
    throw e;
  }
}

// ---- The site itself: timers, the drain, unsubscribing and suppressing ----
async function runTimers(t) {
  const [r] = await t`select app.run_timers() as out`;
  return r.out;
}

async function unsubscribe(t, contactId) {
  const id = v.uuid('contact', contactId);
  const r = await t`update app.email_contacts set status = 'off' where id = ${id} and status in ('active', 'pending')`;
  return r.count;
}

async function suppress(t, { fp, reason }) {
  if (typeof fp !== 'string' || !HEX64.test(fp)) throw new v.ValidationError('fingerprint', 'is not in the expected format');
  const why = v.oneOf('reason', reason, ['bounce', 'complaint']);
  await t`insert into app.email_suppressions (address_fp, reason) values (${fp}, ${why}) on conflict (address_fp) do nothing`;
  const r = await t`update app.email_contacts set status = 'suppressed' where address_fp = ${fp} and status <> 'suppressed'`;
  return r.count;
}

// Claims the next emails to send: at most one email an hour per member (all their waiting notices go together), none
// in their quiet hours, none to an address that is off, unconfirmed, suppressed or a banned member's. A confirmation
// goes straight away. Links are minted here, in the same transaction that claims the rows; the raw tokens live only
// in what this returns and in the email. Returns { busy } if another drain holds the lock.
async function claim(t, { limit = 200, mint }) {
  const n = v.int('limit', limit, { min: 1, max: 1000 });
  const [lock] = await t`select pg_try_advisory_xact_lock(hashtext('dayonegreat.drain'), 0) as ok`;
  if (!lock.ok) return { busy: true, batches: [] };
  // Rows claimed by a run that never reported back: the email may or may not have gone, so they are never resent.
  const reaped = await t`update app.outbox set status = 'failed', last_error = 'unknown_outcome'
                         where status = 'sending' and claimed_at < now() - interval '15 minutes'`;
  const rows = await t`select id, member_id, purpose, notice_id, attempts from app.outbox
                       where status = 'pending' and next_attempt_at <= now() order by created_at limit ${n} for update skip locked`;
  const [admin] = await t`select id from app.members where is_admin and status = 'active' order by id limit 1`;
  const groups = new Map();
  for (const r of rows) {
    const to = r.member_id || (admin && admin.id) || null;
    const key = (to || 'none') + ' ' + r.purpose;
    if (!groups.has(key)) groups.set(key, { to, purpose: r.purpose, rows: [] });
    groups.get(key).rows.push(r);
  }
  const batches = [];
  const skip = (ids, why) => t`update app.outbox set status = 'skipped', last_error = ${why} where id in ${t(ids)}`;
  const later = (ids, at) => t`update app.outbox set next_attempt_at = ${at} where id in ${t(ids)}`;
  for (const g of groups.values()) {
    const ids = g.rows.map((r) => r.id);
    if (!g.to) { await skip(ids, 'no_recipient'); continue; }
    const [c] = await t`select c.id, c.member_id, c.address_sealed, c.address_fp, c.status, c.next_email_at,
                               app.quiet_until(c.quiet_start, c.quiet_end, c.time_zone) as quiet_until, m.status as member_status,
                               exists (select 1 from app.email_suppressions s where s.address_fp = c.address_fp) as suppressed
                        from app.email_contacts c join app.members m on m.id = c.member_id where c.member_id = ${g.to}
                        for update of c skip locked`;
    if (!c) {
      const [exists] = await t`select 1 as x from app.email_contacts where member_id = ${g.to}`;
      if (exists) continue; // another run has it; try next minute
      await skip(ids, 'no_address');
      continue;
    }
    if (c.member_status !== 'active') { await skip(ids, 'member_inactive'); continue; }
    if (c.suppressed || c.status === 'suppressed') {
      if (c.status !== 'suppressed') await t`update app.email_contacts set status = 'suppressed' where id = ${c.id}`;
      await skip(ids, 'suppressed');
      continue;
    }
    if (g.purpose === 'confirm_email') {
      if (c.status !== 'pending') { await skip(ids, 'not_pending'); continue; }
    } else {
      if (c.status !== 'active') { await skip(ids, c.status === 'off' ? 'email_off' : 'unconfirmed'); continue; }
      if (c.next_email_at > new Date()) { await later(ids, c.next_email_at); continue; }
      if (c.quiet_until) { await later(ids, c.quiet_until); continue; }
      // The hourly limit is reserved now, so a second run can't send another email within the hour.
      await t`update app.email_contacts set next_email_at = now() + interval '1 hour' where id = ${c.id}`;
    }
    const [b] = await t`select app.uuid_v7() as id`;
    await t`update app.outbox set status = 'sending', batch_id = ${b.id} where id in ${t(ids)}`;
    const items = [];
    if (g.purpose === 'confirm_email') {
      const token = await mintLink(t, mint, 'confirm_email', c.id);
      if (token) items.push({ kind: 'confirm_email', token });
    } else {
      const notices = await t`select id, kind, title, body, link, subject_id from app.notices where id in ${t(g.rows.map((r) => r.notice_id))} order by created_at`;
      for (const x of notices) {
        const item = { kind: x.kind, title: x.title, body: x.body, link: x.link };
        if (x.kind === 'draft_waiting' && x.subject_id) {
          const [d] = await t`select d.body, a.name from app.agent_drafts d join app.agents a on a.id = d.agent_id
                              where d.id = ${x.subject_id} and d.status = 'pending' and d.expires_at > now()`;
          if (d) {
            const token = await mintLink(t, mint, 'approve_draft', x.subject_id);
            if (token) item.approve = { words: d.body, agentName: d.name, token };
          } else item.decided = true;
        }
        if (x.kind === 'act_reconfirm' && x.subject_id) {
          const token = await mintLink(t, mint, 'keep_acting', x.subject_id);
          if (token) item.keep = { token };
        }
        items.push(item);
      }
    }
    batches.push({ batchId: b.id, ids, purpose: g.purpose, memberId: c.member_id, contactId: c.id, sealed: c.address_sealed, items,
      attempts: Math.max(...g.rows.map((r) => r.attempts)) });
  }
  return { busy: false, reaped: reaped.count, batches };
}

// A link for one email: the caller's mint() gives { token, hash }; the database fills in and checks the rest.
async function mintLink(t, mint, purpose, subjectId) {
  const { token, hash } = mint();
  try {
    await t.savepoint((x) => x`insert into app.action_links (purpose, subject_id, token_hash) values (${purpose}, ${subjectId}, ${hash})`);
    return token;
  } catch (e) {
    if (e.code === '22023') return null; // the draft was decided, the agent stopped, or the address changed meanwhile
    throw e;
  }
}

// Records what happened to each batch. ok: sent. retry: back to waiting, later (and the hourly reservation released).
// Otherwise, or after 5 tries: failed, never resent.
async function finish(t, outcomes) {
  for (const o of outcomes) {
    if (o.ok) {
      await t`update app.outbox set status = 'sent', provider_id = ${String(o.id || '').slice(0, 200) || null} where batch_id = ${o.batchId} and status = 'sending'`;
    } else if (o.retry && o.attempts < 4) {
      const minutes = [1, 5, 30, 120][o.attempts] || 120;
      await t`update app.outbox set status = 'pending', attempts = attempts + 1, last_error = ${String(o.error).slice(0, 200)},
              next_attempt_at = now() + make_interval(mins => ${minutes}::integer) where batch_id = ${o.batchId} and status = 'sending'`;
      if (o.purpose === 'notice') await t`update app.email_contacts set next_email_at = now() where id = ${o.contactId}`;
    } else {
      await t`update app.outbox set status = 'failed', attempts = least(attempts + 1, 20), last_error = ${String(o.error || 'failed').slice(0, 200)}
              where batch_id = ${o.batchId} and status = 'sending'`;
    }
  }
}

module.exports = { KINDS, notify, challenge, alertAaron, inbox, unread, markRead, contact, setAddress, setPrefs, setCopies, removeAddress,
  previewLink, useLink, reconfirm, actClock, myContainment, appeal, appeals, decideAppeal, runTimers, unsubscribe, suppress, claim, finish };
