// The review queue and reports (PR 4: F6, F7, G5, O3). The rules live in the database (004_review.sql); this file
// checks inputs and turns the database's refusals into plain outcomes. Every decision and report is written to
// the audit log by the database itself.
'use strict';

const v = require('./validate');

const REASONS = ['spam', 'abuse', 'private_info', 'illegal', 'other'];
const DECISIONS = ['approve', 'keep', 'remove', 'restore'];

// A member reports someone else's live post. Returns { status: 'reported' } (also when their earlier report on it
// is still open, so reporting twice changes nothing), or { refused: 'not_found' } for a post that isn't live, is
// their own, is by a banned member, or doesn't exist; they all look the same, so reporting can't find hidden posts.
async function report(t, { post, reason, note = null }) {
  const id = v.uuid('post', post);
  const r = v.oneOf('reason', reason, REASONS);
  const n = note === null || note === undefined || note === '' ? null : v.text('note', note, { max: 500, multiline: true });
  try {
    await t.savepoint((s) => s`insert into app.review_flags (post_id, source, reason, note, reporter_id)
                               values (${id}, 'report', ${r}, ${n}, app.current_member())`);
    return { status: 'reported' };
  } catch (e) {
    if (e.code === '23505') return { status: 'reported' };
    // 42501: the row-level rule refused it; 23503: no such post; not_reportable: removed while the report was on its way.
    if (e.code === '42501' || e.code === '23503' || (e.code === 'P0001' && e.message === 'not_reportable')) return { refused: 'not_found' };
    throw e;
  }
}

// The reviewer's queue: every post with an open flag, with what was flagged and why.
// questions (UX PR G; the UI/UX review, finding 12): for a post JEVs held or hid, the public question IDs that scored
// above pass_max on the decision that flagged it, highest first. IDs only, never scores: the site shows each one's
// public title. That decision is the latest one that held or hid the post, made no later than its open JEVs flag (the
// two are written in the same transaction, 032). Only Aaron reads the queue, and only he can read the decisions and
// pass_max (010's policies), so this adds nothing anyone else can see.
// A decision records its scores but not the pass_max of its day, so the IDs are those above today's pass_max: if Aaron
// changes it, older items name questions by the new line. Read without a cast that could fail: a value that isn't a
// whole number (010's trigger allows none) counts as 10, the seeded value, and never stops the queue loading.
// 041 (the design handoff of Nov 5, 2026, phase 4): each item also carries its tier (3 sensitive, 2 held: worked out by
// the database, app.review_tier), its kind (held, hidden, reported, appealed or sampled), the SHA-256 of its stored words
// (the bytes a decision binds), and its author's record on this queue (their other posts decided here: published or
// kept, removed). Highest tier first, then oldest first. The answer also says today's budget and how much of it is used.
// Before 041 is applied, the queue loads as it did (no tiers), so a deploy that arrives first never stops it.
const QUEUE_ROWS = (t, n, tiers) => t`
    select p.id, p.lane, p.body, p.status, p.created_at, p.published_at,
           m.id as author_id, m.display_name as author_name, m.trust_level as author_level, m.status as author_status,
           (select count(*) from app.posts x where x.author_id = p.author_id and x.status = 'live') as author_live_posts,
           f.first_at, f.first_posts, f.reports, f.reasons, f.notes, f.classifiers, f.appeals,
           coalesce((select array_agg(e.key order by (e.value)::numeric desc, e.key)
                     from (select d.scores from app.jevs_decisions d
                           where d.subject_kind = 'post' and d.subject_id = p.id and d.applied and d.effect in ('hold', 'hide')
                             and d.created_at <= f.jevs_at
                           order by d.created_at desc, d.id desc limit 1) h
                     cross join lateral jsonb_each(h.scores) e
                     where e.key ~ '^J[0-9]{2}$' and jsonb_typeof(e.value) = 'number'
                       and (e.value)::numeric > coalesce((select case when s.value ~ '^[0-9]{1,4}$' then s.value::integer end
                                                          from app.jevs_settings s where s.key = 'pass_max'), 10)), '{}') as questions,
           ${tiers ? t`app.review_tier(p.id) as tier, app.review_item_type(p.id) as item_type,
             encode(sha256(convert_to(p.body, 'UTF8')), 'hex') as sha256,
             (select jsonb_build_object('decided', count(*), 'approved', count(*) filter (where d.decision in ('approve', 'keep')),
                                        'removed', count(*) filter (where d.decision = 'remove'))
                from app.review_decisions d join app.posts x on x.id = d.post_id
               where x.author_id = p.author_id and x.id <> p.id and d.decision <> 'restore') as history`
             : t`null::smallint as tier, null::text as item_type, null::text as sha256, null::jsonb as history`}
    from (
      select post_id, min(created_at) as first_at,
             bool_or(source = 'first_posts') as first_posts,
             count(*) filter (where source = 'report') as reports,
             coalesce(array_agg(distinct reason) filter (where reason is not null), '{}') as reasons,
             coalesce((array_agg(note order by created_at) filter (where note is not null))[1:3], '{}') as notes,
             coalesce(array_agg(distinct classifier) filter (where classifier is not null), '{}') as classifiers,
             count(*) filter (where source = 'appeal') as appeals,
             min(created_at) filter (where source = 'classifier' and classifier = 'jevs') as jevs_at
      from app.review_flags where resolved_at is null group by post_id
    ) f
    join app.posts p on p.id = f.post_id
    join app.members m on m.id = p.author_id
    order by ${tiers ? t`app.review_tier(p.id) desc,` : t``} f.first_at, p.id
    limit ${n}`;
const MISSING = (e) => e && (e.code === '42883' || e.code === '42P01');

async function queue(t, { limit = 50 } = {}) {
  const n = v.int('limit', limit, { min: 1, max: 100 });
  let rows, budget = null;
  try {
    rows = await t.savepoint((s) => QUEUE_ROWS(s, n, true));
    const [b] = await t.savepoint((s) => s`select (select daily_budget from app.review_settings) as daily,
      (select count(*) from app.review_decisions d where d.created_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC'
         and d.tier >= 2 and d.reason <> 'undo' and d.decided_by = app.current_member()) as used`);
    budget = { daily: Number(b.daily), used: Number(b.used) };
  } catch (e) {
    if (!MISSING(e)) throw e;
    rows = await QUEUE_ROWS(t, n, false);
  }
  const [{ open }] = await t`select count(distinct post_id) as open from app.review_flags where resolved_at is null`;
  return {
    open: Number(open),
    budget,
    items: rows.map((r) => ({
      id: r.id, lane: r.lane, body: r.body, status: r.status, createdAt: r.created_at, publishedAt: r.published_at,
      author: { id: r.author_id, name: r.author_name, level: r.author_level, status: r.author_status, livePosts: Number(r.author_live_posts) },
      flaggedAt: r.first_at, firstPosts: r.first_posts, reports: Number(r.reports), reasons: r.reasons, notes: r.notes, classifiers: r.classifiers,
      appeals: Number(r.appeals), questions: r.questions,
      tier: r.tier === null ? null : Number(r.tier), itemType: r.item_type, sha256: r.sha256,
      history: r.history ? { decided: Number(r.history.decided), approved: Number(r.history.approved), removed: Number(r.history.removed) } : null
    }))
  };
}

// The reasons a decision may give (041, app.review_decisions), by decision. 'other' needs a typed note (1 to 300
// characters); 'undo' is only the reviewer's own removal of this post in the last 2 minutes, put back.
const DECISION_REASONS = {
  approve: ['ordinary', 'checked', 'other'],
  keep: ['not_upheld', 'ordinary', 'checked', 'other'],
  remove: ['spam', 'abuse', 'private_info', 'illegal', 'other'],
  restore: ['mistake', 'undo', 'other']
};

// One decision on one post, closing all of its open flags. Returns { status } (the post's new status), or
// { refused: 'not_found' | 'stale' | 'changed' | 'reason' | 'read' }: the post is gone; it was already decided (another
// tap, another device) or there is nothing to undo; its words aren't the ones the hash names; the reason doesn't fit;
// a sensitive item was decided before 10 seconds on screen.
// Undoing a removal ('restore' with the reason 'undo') puts the post back exactly as it was (041, app.review_record).
// 041: the decision names a reason and binds the SHA-256 of the words read (app.review_record), and 004's
// app.review_decide is no longer the site's to call. Only before 041 is applied (the function isn't there yet) is a
// decision made the old way, so the queue never stops working; that alerts Aaron and is recorded, every time.
async function decide(t, { post, decision, reason, note = null, sha256, seenMs = null }) {
  const id = v.uuid('post', post);
  const d = v.oneOf('decision', decision, DECISIONS);
  const why = v.oneOf('reason', reason, DECISION_REASONS[d]);
  const n = why === 'other' ? v.text('note', note, { max: 300 }) : null;
  const hash = v.text('sha256', sha256, { min: 64, max: 64, pattern: /^[0-9a-f]{64}$/ });
  const seen = seenMs === null || seenMs === undefined ? null : v.int('seen_ms', seenMs, { min: 0, max: 86400000 });
  try {
    const [r] = await t.savepoint((s) => s`select app.review_record(${id}, ${d}, ${why}, ${n}, ${hash}, ${seen}) as status`);
    return { status: r.status };
  } catch (e) {
    if (e.code === 'P0002') return { refused: 'not_found' };
    if (e.code === 'P0001' && ['stale', 'changed', 'reason', 'read'].includes(e.hint)) return { refused: e.hint };
    if (e.code === '42883') {
      try {
        const [r] = await t.savepoint((s) => s`select app.review_decide(${id}, ${d}) as status`);
        // The fallback ran: say so in the log, the audit log and Aaron's notices (best effort; the decision stands).
        console.error('review: decided without app.review_record (041 not applied yet)');
        await t.savepoint(async (s) => {
          await s`insert into app.audit_log (action, subject_kind, subject_id, detail) values ('review.fallback', 'post', ${id}, ${s.json({ decision: d, reason: why })})`;
          await s`select app.notify(null, 'alert', 'A review decision was made the old way', ${'A decision on a post was made without its reason and hash being checked, because migration 041 isn\u2019t applied yet. Apply it; until then every decision does this.'}, '/admin/review', 'post', ${id}, ${'review:fallback:' + id + ':' + Date.now()})`;
        }).catch(() => {});
        return { status: r.status };
      } catch (e2) {
        if (e2.code === 'P0002') return { refused: 'not_found' };
        if (e2.code === 'P0001' && e2.hint === 'stale') return { refused: 'stale' };
        throw e2;
      }
    }
    throw e;
  }
}

module.exports = { report, queue, decide, REASONS, DECISIONS, DECISION_REASONS };
