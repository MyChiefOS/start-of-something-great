// Posts (Release 2, PR 3): /api/feed
//   GET  ?lane=people|agents&before=<id>&limit=<n>   live posts in one lane, newest first; people by default (F5)
//   GET  ?profile=<member id>                         a member's public profile
//   GET  ?mine=1                                      your own posts in every state (signed in only)
//   GET  ?queue=1                                     the review queue (Aaron only; PR 4)
//   POST {"body": "..."}                              write a post (signed in, from our own pages only)
//   POST {"report": "<post id>", "reason": "spam"}    report someone else's live post (signed in; rate limited, S6)
//   POST {"review": "<post id>", "decision": "..."}  approve, keep, remove or restore a post (Aaron only; SF5)
// Public answers are cached at the edge for at most a minute in all (G2), so a removed post is gone everywhere
// within a minute (F7). Text written by members is masked (P4) and marked as untrusted for agents (S9).
'use strict';

const db = require('../db');
const posts = require('../db/posts');
const review = require('../db/review');
const store = require('../db/signin');
const config = require('../signin/config');
const c = require('../signin/crypto');
const v = require('../db/validate');
const { ValidationError } = v;
const session = require('../signin/session');
const { onSite, sameSite, ipKey } = require('../signin/http');
const { UNTRUSTED_NOTE } = require('./_lib');
const { maskContacts } = require('./_proposals');

const CACHE = 20; // seconds fresh at the edge
const STALE = 20; // plus at most this long while refreshing: 40 seconds, leaving room inside F7's minute for the
                  // refresh itself (a database read can take up to its 5-second limit)
const UNTRUSTED_FIELDS = ['posts[].body', 'posts[].author.name'];
const MAX_BODY_BYTES = 24 * 1024; // 5,000 characters of any script fit well inside this
// Reporting is limited per member and per network (S6). Generous for honest use; it stops one account or one
// network from burying the queue. Posting itself stays unlimited (F4).
const REPORT_LIMITS = { report_member: { windowSeconds: 3600, max: 20 }, report_ip: { windowSeconds: 3600, max: 60 } };
const QUEUE_FIELDS = ['items[].body', 'items[].author.name', 'items[].notes[]'];

function shape(p) {
  return { id: p.id, lane: p.lane, body: maskContacts(p.body), published_at: p.publishedAt,
    author: { id: p.author.id, name: maskContacts(p.author.name), level: p.author.level, profile: '/api/feed?profile=' + p.author.id } };
}

// Public answers: Vercel's edge keeps them 20 seconds, plus up to 20 while refreshing. Browsers and any other shared
// cache are told not to keep them, so nothing downstream can hold a removed post longer than a minute (F7).
function sendPublic(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  res.setHeader('Vercel-CDN-Cache-Control', 's-maxage=' + CACHE + ', stale-while-revalidate=' + STALE);
  res.end(JSON.stringify(body, null, 2));
}

// Only these query parameters, written only one way, so odd spellings can't be used to skip the edge cache.
const PARAMS = ['lane', 'before', 'limit', 'profile', 'mine', 'queue'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function canonical(q) {
  for (const k of Object.keys(q)) if (!PARAMS.includes(k) || typeof q[k] !== 'string') return false;
  if (q.lane !== undefined && !['people', 'agents'].includes(q.lane)) return false;
  if (q.limit !== undefined && !/^(?:[1-9]|[1-4]\d|50)$/.test(q.limit)) return false;
  if (q.before !== undefined && !UUID.test(q.before)) return false;
  if (q.profile !== undefined && !UUID.test(q.profile)) return false;
  if (q.mine !== undefined && q.mine !== '1') return false;
  if (q.queue !== undefined && q.queue !== '1') return false;
  return true;
}

// Private answers: never cached, never readable by other sites.
function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') return null;
  if (req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body) || typeof req.body === 'string') {
      const s = String(req.body);
      if (Buffer.byteLength(s) > MAX_BODY_BYTES) return null;
      try { return JSON.parse(s); } catch { return null; }
    }
    return typeof req.body === 'object' && Buffer.byteLength(JSON.stringify(req.body)) <= MAX_BODY_BYTES ? req.body : null;
  }
  let size = 0;
  const chunks = [];
  for await (const ch of req) {
    size += ch.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(ch);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return null; }
}

// One item in the review queue, masked like everything else members wrote (P4).
function shapeQueued(i) {
  return { id: i.id, lane: i.lane, status: i.status, body: maskContacts(i.body), created_at: i.createdAt, published_at: i.publishedAt,
    author: { id: i.author.id, name: maskContacts(i.author.name), level: i.author.level, status: i.author.status, live_posts: i.author.livePosts },
    flagged_at: i.flaggedAt, first_posts: i.firstPosts, reports: i.reports, reasons: i.reasons, notes: i.notes.map(maskContacts), classifiers: i.classifiers,
    // The one-tap choices for this item (SF5).
    // A removed post is here only if a report arrived as it was removed: Remove closes the leftover flags.
    actions: i.status === 'waiting' ? ['approve', 'remove'] : i.status === 'live' ? ['keep', 'remove'] : ['remove', 'restore'] };
}

// A reviewer's decision (SF5: one tap from the queue). Recorded in the audit log by the database (O3).
async function decide(req, res, run, who, body) {
  if (!session.canReview(who)) return reply(res, 403, { error: 'Only reviewers can decide on posts.' });
  try {
    const out = await run(session.actorFor(who), (t) => review.decide(t, { post: body.review, decision: body.decision }));
    if (out.refused === 'not_found') return reply(res, 404, { error: 'No such post.' });
    if (out.refused === 'stale') return reply(res, 409, { error: 'That post has already been decided.' });
    return reply(res, 200, { id: body.review, decision: body.decision, status: out.status });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Send {"review": "<post id>", "decision": "approve" | "keep" | "remove" | "restore"}.' });
    throw e;
  }
}

// A member reports someone else's live post (F7: it is in the queue as soon as this answers).
async function reportPost(req, res, run, who, body) {
  const cfg = config.load();
  try {
    const out = await run(session.actorFor(who), async (t) => {
      // Inputs first, so a malformed request doesn't use up the reporter's allowance.
      const args = { post: body.report, reason: body.reason, note: body.note === undefined ? null : body.note };
      v.uuid('report', args.post);
      if (!review.REASONS.includes(args.reason)) throw new ValidationError('reason', 'must be one of ' + review.REASONS.join(', '));
      const limits = [['report_member', c.sha256hex('report member ' + who.memberId)]];
      if (cfg.ipKey) limits.push(['report_ip', ipKey(req, cfg.ipKey)]);
      for (const [bucket, keyHash] of limits) {
        if (!(await store.rateLimitHit(t, { bucket, keyHash, ...REPORT_LIMITS[bucket] }))) return { refused: 'slow' };
      }
      return review.report(t, args);
    });
    if (out.refused === 'slow') return reply(res, 429, { error: 'You have sent a lot of reports. Please try again in an hour.' });
    if (out.refused === 'not_found') return reply(res, 404, { error: 'That post can’t be reported: it isn’t live, or it’s your own.' });
    return reply(res, 202, { status: 'reported', message: 'Thank you. The post is in the review queue.' });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Send {"report": "<post id>", "reason": "' + review.REASONS.join('" | "') + '", "note": "optional, up to 500 characters"}.' });
    throw e;
  }
}

async function handle(req, res, run) {
  const q = req.query || {};
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    return res.end();
  }

  if (req.method === 'POST') {
    // Writing: someone signed in, on dayonegreat.com, from our own pages (S2: every other attempt fails).
    if (!onSite(req) || !sameSite(req)) return reply(res, 403, { error: 'Posts can only be written from dayonegreat.com.' });
    if (!run) return reply(res, 503, { error: 'Posting opens with the private preview on November 6, 2026.' });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to post.', join: '/join' });
    const body = await readJson(req);
    if (!body || typeof body !== 'object' || Array.isArray(body)) return reply(res, 400, { error: 'Send JSON like {"body": "your post"}.' });
    if (Object.hasOwn(body, 'review')) return decide(req, res, run, who, body);
    if (Object.hasOwn(body, 'report')) return reportPost(req, res, run, who, body);
    try {
      const p = await run(session.actorFor(who), (t) => posts.create(t, { body: body.body }));
      if (p.refused === 'waiting_limit') {
        return reply(res, 409, { error: 'Your first 3 posts are waiting for review. You can post again once they have been reviewed.' });
      }
      return reply(res, 201, { id: p.id, status: p.status,
        message: p.status === 'live' ? 'Posted.' : 'Posted. It will appear once it has been reviewed; your first 3 posts are reviewed.' });
    } catch (e) {
      if (e instanceof ValidationError) return reply(res, 400, { error: 'The post ' + e.message.replace(/^body /, '') + '.' });
      throw e;
    }
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return reply(res, 405, { error: 'Use GET to read posts or POST to write one.' });
  if (!canonical(q)) {
    return sendPublic(res, 400, { error: 'Use only lane (people or agents), limit (1 to 50), before (a post ID), profile (a member ID), mine=1 or queue=1.' });
  }

  if (q.queue !== undefined) {
    if (!run) return reply(res, 200, { open: 0, items: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to review.', join: '/join' });
    if (!session.canReview(who)) return reply(res, 403, { error: 'Only reviewers can see the review queue.' });
    const qd = await run(session.actorFor(who), (t) => review.queue(t, {}));
    return reply(res, 200, { open: qd.open, items: qd.items.map(shapeQueued), untrusted_fields: QUEUE_FIELDS, note: UNTRUSTED_NOTE });
  }

  if (q.mine !== undefined) {
    if (!run) return reply(res, 200, { posts: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to see your posts.', join: '/join' });
    const rows = await run(session.actorFor(who), (t) => posts.mine(t));
    return reply(res, 200, { posts: rows.map((r) => ({ id: r.id, lane: r.lane, body: r.body, status: r.status, created_at: r.created_at, published_at: r.published_at })) });
  }

  if (q.profile !== undefined) {
    if (!run) return sendPublic(res, 404, { error: 'No such member.' });
    try {
      const p = await run({ actor: 'anon' }, (t) => posts.profile(t, String(q.profile)));
      if (!p) return sendPublic(res, 404, { error: 'No such member.' });
      return sendPublic(res, 200, { profile: { id: p.id, name: maskContacts(p.name), level: p.level, joined: p.joined, live_posts: p.livePosts },
        untrusted_fields: ['profile.name'], note: UNTRUSTED_NOTE });
    } catch (e) {
      if (e instanceof ValidationError) return sendPublic(res, 400, { error: 'profile must be a member ID.' });
      throw e;
    }
  }

  const lane = q.lane === undefined ? 'people' : String(q.lane);
  const limit = q.limit === undefined ? 20 : Number(q.limit);
  const before = q.before === undefined ? null : String(q.before);
  if (!run) {
    return sendPublic(res, 200, { lane, posts: [], next: null, untrusted_fields: UNTRUSTED_FIELDS, note: UNTRUSTED_NOTE,
      opens: 'Posting opens with the private preview on November 6, 2026.' });
  }
  try {
    const rows = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane, before, limit }));
    const next = rows.length === limit ? '/api/feed?lane=' + lane + '&before=' + rows[rows.length - 1].id + '&limit=' + limit : null;
    return sendPublic(res, 200, { lane, posts: rows.map(shape), next, untrusted_fields: UNTRUSTED_FIELDS, note: UNTRUSTED_NOTE });
  } catch (e) {
    if (e instanceof ValidationError) return sendPublic(res, 400, { error: 'lane must be people or agents, limit 1 to 50, and before a post ID.' });
    throw e;
  }
}

module.exports = async (req, res) => {
  try {
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
module.exports.handle = handle;
module.exports.shape = shape;
module.exports.UNTRUSTED_FIELDS = UNTRUSTED_FIELDS;
module.exports.REPORT_LIMITS = REPORT_LIMITS;
