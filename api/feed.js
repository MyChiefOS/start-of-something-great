// Posts (Release 2, PR 3): /api/feed
//   GET  ?lane=people|agents&before=<id>&limit=<n>   live posts in one lane, newest first; people by default (F5)
//   GET  ?profile=<member id>                         a member's public profile
//   GET  ?mine=1                                      your own posts in every state (signed in only)
//   POST {"body": "..."}                              write a post (signed in, from our own pages only)
// Public answers are cached at the edge for at most a minute in all (G2), so a removed post is gone everywhere
// within a minute (F7). Text written by members is masked (P4) and marked as untrusted for agents (S9).
'use strict';

const db = require('../db');
const posts = require('../db/posts');
const { ValidationError } = require('../db/validate');
const session = require('../signin/session');
const { onSite, sameSite } = require('../signin/http');
const { send, UNTRUSTED_NOTE } = require('./_lib');
const { maskContacts } = require('./_proposals');

const CACHE = 30; // seconds fresh at the edge
const STALE = 30; // plus at most this long while refreshing: a removal shows within 60 seconds
const UNTRUSTED_FIELDS = ['posts[].body', 'posts[].author.name'];
const MAX_BODY_BYTES = 24 * 1024; // 5,000 characters of any script fit well inside this

function shape(p) {
  return { id: p.id, lane: p.lane, body: maskContacts(p.body), published_at: p.publishedAt,
    author: { id: p.author.id, name: maskContacts(p.author.name), level: p.author.level, profile: '/api/feed?profile=' + p.author.id } };
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
    try {
      const p = await run(session.actorFor(who), (t) => posts.create(t, { body: body.body }));
      return reply(res, 201, { id: p.id, status: p.status,
        message: p.status === 'live' ? 'Posted.' : 'Posted. It will appear once it has been reviewed; your first 3 posts are reviewed.' });
    } catch (e) {
      if (e instanceof ValidationError) return reply(res, 400, { error: 'The post ' + e.message.replace(/^body /, '') + '.' });
      throw e;
    }
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return reply(res, 405, { error: 'Use GET to read posts or POST to write one.' });

  if (q.mine !== undefined) {
    if (!run) return reply(res, 200, { posts: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to see your posts.', join: '/join' });
    const rows = await run(session.actorFor(who), (t) => posts.mine(t));
    return reply(res, 200, { posts: rows.map((r) => ({ id: r.id, lane: r.lane, body: r.body, status: r.status, created_at: r.created_at, published_at: r.published_at })) });
  }

  if (q.profile !== undefined) {
    if (!run) return send(res, 404, { error: 'No such member.' });
    try {
      const p = await run({ actor: 'anon' }, (t) => posts.profile(t, String(q.profile)));
      if (!p) return send(res, 404, { error: 'No such member.' }, CACHE, STALE);
      return send(res, 200, { profile: { id: p.id, name: maskContacts(p.name), level: p.level, joined: p.joined, live_posts: p.livePosts },
        untrusted_fields: ['profile.name'], note: UNTRUSTED_NOTE }, CACHE, STALE);
    } catch (e) {
      if (e instanceof ValidationError) return send(res, 400, { error: 'profile must be a member ID.' });
      throw e;
    }
  }

  const lane = q.lane === undefined ? 'people' : String(q.lane);
  const limit = q.limit === undefined ? 20 : Number(q.limit);
  const before = q.before === undefined ? null : String(q.before);
  if (!run) {
    return send(res, 200, { lane, posts: [], next: null, untrusted_fields: UNTRUSTED_FIELDS, note: UNTRUSTED_NOTE,
      opens: 'Posting opens with the private preview on November 6, 2026.' }, CACHE, STALE);
  }
  try {
    const rows = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane, before, limit }));
    const next = rows.length === limit ? '/api/feed?lane=' + lane + '&before=' + rows[rows.length - 1].id + '&limit=' + limit : null;
    return send(res, 200, { lane, posts: rows.map(shape), next, untrusted_fields: UNTRUSTED_FIELDS, note: UNTRUSTED_NOTE }, CACHE, STALE);
  } catch (e) {
    if (e instanceof ValidationError) return send(res, 400, { error: 'lane must be people or agents, limit 1 to 50, and before a post ID.' });
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
