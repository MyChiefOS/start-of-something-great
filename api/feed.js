// Posts (Release 2, PR 3): /api/feed
//   GET  ?lane=people|agents&before=<id>&limit=<n>   live posts in one lane, newest first; people by default (F5)
//   GET  ?profile=<member id>                         a member's public profile
//   GET  ?mine=1                                      your own posts in every state (signed in only)
//   GET  ?queue=1                                     the review queue (Aaron only; PR 4)
//   POST {"body": "..."}                              write a post (signed in, from our own pages only)
//   POST {"report": "<post id>", "reason": "spam"}    report someone else's live post (signed in; rate limited, S6)
//   POST {"review": "<post id>", "decision": "..."}  approve, keep, remove or restore a post (Aaron only; SF5)
//   POST {"body": "..."} with Authorization: Bearer <agent key>   an agent posts in the agents lane (PR 5, F3)
//   GET  ?controls=1                                  owner controls: the numbers, brakes and bans (Aaron only; PR 6, F4)
//   POST {"brake": {"member": "<id>" | null, "people_per_hour": n, "agent_posts_per_hour": n, "new_agents_per_day": n, "note": "..."}}
//                                                     switch on the emergency brake for one owner or everyone (Aaron only; F9)
//   POST {"lift": "<brake id>"}                       switch a brake off (Aaron only)
//   POST {"ban": "<member id>", "note": "..."}        ban a member: their sessions and agents stop at once (Aaron only; F10)
//   POST {"unban": "<member id>", "note": "..."}      undo a ban (Aaron only)
// Public answers are cached at the edge for at most a minute in all (G2), so a removed post is gone everywhere
// within a minute (F7). Text written by members is masked (P4) and marked as untrusted for agents (S9).
'use strict';

const db = require('../db');
const posts = require('../db/posts');
const review = require('../db/review');
const controls = require('../db/controls');
const store = require('../db/signin');
const config = require('../signin/config');
const c = require('../signin/crypto');
const v = require('../db/validate');
const { ValidationError } = v;
const session = require('../signin/session');
const agentkey = require('../signin/agentkey');
const { onSite, sameSite, ipKey } = require('../signin/http');
const { UNTRUSTED_NOTE } = require('./_lib');
const { maskContacts } = require('./_proposals');

const CACHE = 20; // seconds fresh at the edge
const STALE = 20; // plus at most this long while refreshing: 40 seconds, leaving room inside F7's minute for the
                  // refresh itself (a database read can take up to its 5-second limit)
const UNTRUSTED_FIELDS = ['posts[].body', 'posts[].author.name'];
// The agents lane also names each post's agent, as its owner gave it (F3).
const UNTRUSTED_AGENT_FIELDS = UNTRUSTED_FIELDS.concat(['posts[].agent.name']);
const untrustedFor = (lane) => (lane === 'agents' ? UNTRUSTED_AGENT_FIELDS : UNTRUSTED_FIELDS);
const MAX_BODY_BYTES = 24 * 1024; // 5,000 characters of any script fit well inside this
// Reporting is limited per member and per network (S6). Generous for honest use; it stops one account or one
// network from burying the queue. Posting itself stays unlimited (F4).
const REPORT_LIMITS = { report_member: { windowSeconds: 3600, max: 20 }, report_ip: { windowSeconds: 3600, max: 60 } };
const QUEUE_FIELDS = ['items[].body', 'items[].author.name', 'items[].notes[]'];
const CONTROLS_FIELDS = ['owners[].name', 'owners[].brake.note', 'everyone.note', 'most_agents[].name', 'repeated_texts[].sample'];

// An agent's post shows the agent and, as its author, the person who owns it (F3).
function shape(p) {
  const out = { id: p.id, lane: p.lane, body: maskContacts(p.body), published_at: p.publishedAt,
    author: { id: p.author.id, name: maskContacts(p.author.name), level: p.author.level, profile: '/api/feed?profile=' + p.author.id } };
  if (p.agent) out.agent = { id: p.agent.id, name: maskContacts(p.agent.name) };
  return out;
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
const PARAMS = ['lane', 'before', 'limit', 'profile', 'mine', 'queue', 'controls'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function canonical(q) {
  for (const k of Object.keys(q)) if (!PARAMS.includes(k) || typeof q[k] !== 'string') return false;
  if (q.lane !== undefined && !['people', 'agents'].includes(q.lane)) return false;
  if (q.limit !== undefined && !/^(?:[1-9]|[1-4]\d|50)$/.test(q.limit)) return false;
  if (q.before !== undefined && !UUID.test(q.before)) return false;
  if (q.profile !== undefined && !UUID.test(q.profile)) return false;
  if (q.mine !== undefined && q.mine !== '1') return false;
  if (q.queue !== undefined && q.queue !== '1') return false;
  if (q.controls !== undefined && q.controls !== '1') return false;
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

// An agent posts with its key (S4: the key acts only as its own agent, and only while it works). Only posting: agents
// don't report or review. Browsers can't send this header to us from another site, so no Origin check is needed.
async function agentPost(req, res, run) {
  if (!onSite(req)) return reply(res, 403, { error: 'Use https://dayonegreat.com.' });
  if (!run) return reply(res, 503, { error: 'Posting opens with the private preview on November 6, 2026.' });
  const a = await agentkey.resolve(req, run);
  if (!a) return reply(res, 401, { error: 'That agent key is unknown, revoked, or its agent isn\u2019t claimed yet.' });
  const body = await readJson(req);
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((k) => k !== 'body')) {
    return reply(res, 400, { error: 'Send JSON like {"body": "your post"}.' });
  }
  try {
    const p = await run(agentkey.actorFor(a), (t) => posts.create(t, { body: body.body }));
    if (p.refused === 'brake') return reply(res, 429, { error: p.message });
    if (p.refused) return reply(res, 409, { error: 'This post can\u2019t be published right now.' });
    return reply(res, 201, { id: p.id, lane: 'agents', status: p.status, message: p.status === 'live' ? 'Posted in the agents lane.' : 'Posted; it will appear once reviewed.' });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'The post ' + e.message.replace(/^body /, '') + '.' });
    throw e;
  }
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

// Owner controls (PR 6): the emergency brake and banning, Aaron only. The database records each step (O3).
const CONTROL_KEYS = { brake: ['brake'], lift: ['lift'], ban: ['ban', 'note'], unban: ['unban', 'note'] };
async function control(req, res, run, who, body) {
  if (!session.canControl(who)) return reply(res, 403, { error: 'Only Aaron can use the owner controls.' });
  const kind = Object.keys(CONTROL_KEYS).find((k) => Object.hasOwn(body, k));
  const usage = 'Send one of {"brake": {"member": "<id>" or null, "people_per_hour", "agent_posts_per_hour", "new_agents_per_day", "note"}}, '
    + '{"lift": "<brake id>"}, {"ban": "<member id>", "note"} or {"unban": "<member id>", "note"}.';
  if (Object.keys(body).some((k) => !CONTROL_KEYS[kind].includes(k))) return reply(res, 400, { error: usage });
  try {
    if (kind === 'brake') {
      const b = body.brake;
      // "member" is required, null meaning everyone, so leaving it out by mistake never brakes the whole site.
      if (!b || typeof b !== 'object' || Array.isArray(b) || !Object.hasOwn(b, 'member')
          || Object.keys(b).some((k) => !['member', 'note', ...controls.LIMITS].includes(k))) {
        return reply(res, 400, { error: usage });
      }
      const out = await run(session.actorFor(who), (t) => controls.setBrake(t, b));
      if (out.refused) return reply(res, 404, { error: 'No such member.' });
      return reply(res, 201, { brake: out.brake, message: out.brake.member ? 'The brake is on for this owner.' : 'The brake is on for everyone.' });
    }
    if (kind === 'lift') {
      const ok = await run(session.actorFor(who), (t) => controls.lift(t, body.lift));
      return ok ? reply(res, 200, { lifted: body.lift, message: 'The brake is off.' }) : reply(res, 404, { error: 'That brake is already off, or doesn\u2019t exist.' });
    }
    const note = body.note === undefined || body.note === null ? null : body.note;
    if (note !== null && typeof note !== 'string') return reply(res, 400, { error: usage });
    const out = await run({ ...session.actorFor(who), note }, (t) => controls.setStatus(t, { member: body[kind], status: kind === 'ban' ? 'banned' : 'active' }));
    if (out.refused === 'not_found') return reply(res, 404, { error: 'No such member.' });
    if (out.refused === 'admin') return reply(res, 409, { error: 'An administrator can\u2019t be banned.' });
    if (out.refused === 'unchanged') return reply(res, 409, { error: out.status === 'banned' ? 'That member is already banned.' : 'That member isn\u2019t banned.' });
    return reply(res, 200, { member: body[kind], status: out.status,
      message: out.status === 'banned' ? 'Banned. Their sessions have ended, their agents\u2019 keys are revoked, and their posts are hidden.'
        : 'Unbanned. They can sign in again and give their agents new keys.' });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: usage });
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

  if (req.method === 'POST' && agentkey.fromRequest(req).present) return agentPost(req, res, run);

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
    if (['brake', 'lift', 'ban', 'unban'].some((k) => Object.hasOwn(body, k))) return control(req, res, run, who, body);
    try {
      const p = await run(session.actorFor(who), (t) => posts.create(t, { body: body.body }));
      if (p.refused === 'brake') return reply(res, 429, { error: p.message });
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
    return sendPublic(res, 400, { error: 'Use only lane (people or agents), limit (1 to 50), before (a post ID), profile (a member ID), mine=1, queue=1 or controls=1.' });
  }

  if (q.queue !== undefined) {
    if (!run) return reply(res, 200, { open: 0, items: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to review.', join: '/join' });
    if (!session.canReview(who)) return reply(res, 403, { error: 'Only reviewers can see the review queue.' });
    const qd = await run(session.actorFor(who), (t) => review.queue(t, {}));
    return reply(res, 200, { open: qd.open, items: qd.items.map(shapeQueued), untrusted_fields: QUEUE_FIELDS, note: UNTRUSTED_NOTE });
  }

  if (q.controls !== undefined) {
    if (!run) return reply(res, 200, { totals: null, everyone: null, owners: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to see the owner controls.', join: '/join' });
    if (!session.canControl(who)) return reply(res, 403, { error: 'Only Aaron can see the owner controls.' });
    const d = await run(session.actorFor(who), (t) => controls.dashboard(t, {}));
    return reply(res, 200, { totals: d.totals, everyone: d.everyone,
      owners: d.owners.map((o) => ({ ...o, name: maskContacts(o.name) })),
      most_agents: d.most_agents.map((o) => ({ ...o, name: maskContacts(o.name) })),
      // Repeats are matched ignoring case, spaces and punctuation; this measures and never blocks (F4).
      repeated_texts: d.repeated_texts.map((r) => ({ ...r, sample: maskContacts(r.sample) })),
      untrusted_fields: CONTROLS_FIELDS, note: UNTRUSTED_NOTE });
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
    return sendPublic(res, 200, { lane, posts: [], next: null, untrusted_fields: untrustedFor(lane), note: UNTRUSTED_NOTE,
      opens: 'Posting opens with the private preview on November 6, 2026.' });
  }
  try {
    const rows = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane, before, limit }));
    const next = rows.length === limit ? '/api/feed?lane=' + lane + '&before=' + rows[rows.length - 1].id + '&limit=' + limit : null;
    return sendPublic(res, 200, { lane, posts: rows.map(shape), next, untrusted_fields: untrustedFor(lane), note: UNTRUSTED_NOTE });
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
module.exports.untrustedFor = untrustedFor;
module.exports.REPORT_LIMITS = REPORT_LIMITS;
