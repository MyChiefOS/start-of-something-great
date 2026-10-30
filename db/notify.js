// Notifications (PR 13), in-app only (Aaron, Oct 16, 2026: no member email addresses are stored). The rules live in
// the database (011_notifications.sql); this file checks inputs and turns refusals into plain outcomes. Every query is
// a tagged template (S8), under the caller's own row-level security. Members read and mark their own notices; the
// site itself (actor "system") runs the timers and records addresses that bounced, as keyed fingerprints only.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;

// Notices are left by the database itself, in the transaction of the event that causes them (app.notify, 011).

// ---- The inbox ----
// The subject says what the notice is about, so the page can offer its one-tap answer on the notice itself (a draft
// to approve, a held post to confirm, an agent to keep acting).
const shapeNotice = (n) => ({ id: n.id, kind: n.kind, title: n.title, body: n.body, link: n.link, created_at: n.created_at,
  read: n.read_at !== null, for_admins: n.member_id === null, subject: n.subject_kind ? { kind: n.subject_kind, id: n.subject_id } : null });

// The signed-in member's newest notices (Aaron's include the administrators' inbox) and how many are unread.
async function inbox(t, { limit = 50 } = {}) {
  const n = v.int('limit', limit, { min: 1, max: 100 });
  const rows = await t`select id, member_id, kind, title, body, link, subject_kind, subject_id, created_at, read_at from app.notices
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

// ---- Keeping an agent acting on its own (R33), from the agents page ----
// The rules version the owner saw must still be the current one, and (PR 15) the owner must have signed in within the
// last 10 minutes: the call carries fresh, and the database decides. { version } or { refused }.
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
    if (e.code === 'P0001' && e.message === 'fresh_sign_in') return { refused: 'fresh' };
    throw e;
  }
}

// When each of the owner's agents that acts on its own was last confirmed, and when it needs confirming (R33): the
// owner's last choice made with a fresh sign-in (PR 15's second review, R2), not any save.
async function actClock(t, agentIds) {
  if (!agentIds.length) return new Map();
  const rows = await t`select agent_id, max(created_at) as since from app.agent_rules
                       where agent_id in ${t(agentIds)} and set_by = 'owner' and restarts_clock group by agent_id`;
  return new Map(rows.map((r) => [r.agent_id, r.since]));
}

// ---- Containment: the owner's view and appeal; Aaron's view and decision ----
// A containment whose time is up ends when the owner's rules are read or written, as the timer would end it, so a
// missed timer run never makes a pause longer. Call it in the owner's own transaction before reading or changing
// their agents' rules. Returns true if it ended one.
async function liftDue(t) {
  const r = await t`update app.containments set lifted_at = now()
                    where member_id = app.current_member() and lifted_at is null and ends_at <= now()`;
  return r.count === 1;
}

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

// ---- The site itself: the timers ----
async function runTimers(t) {
  const [r] = await t`select app.run_timers() as out`;
  return r.out;
}

// The timer slot (027, the CSO's control 6): the timers as the site itself, called by anyone (the site acts as an
// anonymous visitor here), at most once every 50 seconds; no secret. fromCron is evidence only (Vercel Cron's
// user-agent): it never decides anything, and runs without it are counted and alert. { ran, why?, failed }.
async function timerSlot(t, fromCron) {
  const [r] = await t`select app.timers_run(${fromCron === true}) as out`;
  return r.out;
}

// The heartbeat (027, R-9): seconds since the timers last finished, or null if they never have. A time, nothing else.
async function timersAge(t) {
  const [r] = await t`select floor(extract(epoch from now() - last_ok_at))::int as age from app.timer_slot limit 1`; // one row; the site may read only last_ok_at
  return r && r.age != null ? r.age : null;
}

// The rules' heartbeat (032): seconds since the hourly never-break checks last finished, or null if they never have.
async function rulesAge(t) {
  const [r] = await t`select floor(extract(epoch from now() - last_ok_at))::int as age from app.invariant_slot limit 1`; // the site may read only last_ok_at
  return r && r.age != null ? r.age : null;
}

// ---- Addresses that bounced for good or complained (the site itself), as keyed fingerprints only ----
// Recorded from a verified SNS message; true if it is new.
async function suppress(t, { fp, reason }) {
  if (typeof fp !== 'string' || !HEX64.test(fp)) throw new v.ValidationError('fingerprint', 'is not in the expected format');
  const why = v.oneOf('reason', reason, ['bounce', 'complaint']);
  const r = await t`insert into app.email_suppressions (address_fp, reason) values (${fp}, ${why}) on conflict (address_fp) do nothing`;
  return r.count === 1;
}

// Whether an address (by its fingerprint under each key still in use) must not be mailed: checked before every
// sign-in email.
async function suppressed(t, fps) {
  if (!Array.isArray(fps) || fps.length < 1 || fps.length > 5 || !fps.every((f) => typeof f === 'string' && HEX64.test(f))) {
    throw new v.ValidationError('fingerprints', 'is not in the expected format');
  }
  const [r] = await t`select exists (select 1 from app.email_suppressions where address_fp in ${t(fps)}) as yes`;
  return r.yes === true;
}

module.exports = { inbox, unread, markRead, reconfirm, actClock, liftDue, myContainment, appeal, appeals, decideAppeal, runTimers,
  timerSlot, timersAge, rulesAge, suppress, suppressed };
