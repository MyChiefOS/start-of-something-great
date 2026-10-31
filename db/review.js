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

// The reviewer's queue: every post with an open flag, the oldest flag first, with what was flagged and why.
// questions (UX PR G; the UI/UX review, finding 12): for a post JEVs held or hid, the public question IDs that scored
// above pass_max on the decision that flagged it, highest first. IDs only, never scores: the site shows each one's
// public title. That decision is the latest one that held or hid the post, made no later than its open JEVs flag (the
// two are written in the same transaction, 032). Only Aaron reads the queue, and only he can read the decisions and
// pass_max (010's policies), so this adds nothing anyone else can see.
// A decision records its scores but not the pass_max of its day, so the IDs are those above today's pass_max: if Aaron
// changes it, older items name questions by the new line. Read without a cast that could fail: a value that isn't a
// whole number (010's trigger allows none) counts as 10, the seeded value, and never stops the queue loading.
async function queue(t, { limit = 50 } = {}) {
  const n = v.int('limit', limit, { min: 1, max: 100 });
  const rows = await t`
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
                                                          from app.jevs_settings s where s.key = 'pass_max'), 10)), '{}') as questions
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
    order by f.first_at, p.id
    limit ${n}`;
  const [{ open }] = await t`select count(distinct post_id) as open from app.review_flags where resolved_at is null`;
  return {
    open: Number(open),
    items: rows.map((r) => ({
      id: r.id, lane: r.lane, body: r.body, status: r.status, createdAt: r.created_at, publishedAt: r.published_at,
      author: { id: r.author_id, name: r.author_name, level: r.author_level, status: r.author_status, livePosts: Number(r.author_live_posts) },
      flaggedAt: r.first_at, firstPosts: r.first_posts, reports: Number(r.reports), reasons: r.reasons, notes: r.notes, classifiers: r.classifiers,
      appeals: Number(r.appeals), questions: r.questions
    }))
  };
}

// One decision on one post, closing all of its open flags. Returns { status } (the post's new status), or
// { refused: 'not_found' | 'stale' } when the post is gone or was already decided (another tap, another device).
// Undoing a removal ('restore') returns 'live' for a post that had been approved and 'waiting' for one that never was.
async function decide(t, { post, decision }) {
  const id = v.uuid('post', post);
  const d = v.oneOf('decision', decision, DECISIONS);
  try {
    const [r] = await t.savepoint((s) => s`select app.review_decide(${id}, ${d}) as status`);
    return { status: r.status };
  } catch (e) {
    if (e.code === 'P0002') return { refused: 'not_found' };
    if (e.code === 'P0001' && e.hint === 'stale') return { refused: 'stale' };
    throw e;
  }
}

module.exports = { report, queue, decide, REASONS, DECISIONS };
