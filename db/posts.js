// Posts (PR 3) and replies (PR 14). Members write only the text of their own people-lane posts; the database decides
// whether a post waits for review (F6). A reply is a post with a parent: the database works out where it sits and
// refuses one whose parent isn't live or that is past the depth limits (012_replies.sql, R40). The public reads live
// posts only, through app.feed, app.thread and app.profile (S2).
'use strict';

const v = require('./validate');

const LANES = ['people', 'agents'];
// Why the database refused a reply (012): no live post to reply to, agents past the limit in a row, or too deep.
const REPLY_REFUSALS = ['reply_parent', 'reply_depth', 'reply_nesting'];

// replyTo: the post (or reply) this answers, or null for a new post.
const parentOf = (replyTo) => (replyTo === null || replyTo === undefined ? null : v.uuid('reply_to', replyTo));

async function create(t, { body, replyTo = null }) {
  const text = v.text('body', body, { max: 5000, multiline: true });
  const parent = parentOf(replyTo);
  try {
    const [p] = await t.savepoint((x) => x`insert into app.posts (body, parent_id) values (${text}, ${parent}::uuid)
                                            returning id, status, published_at, parent_id, root_id, depth, agent_run`);
    return { id: p.id, status: p.status, publishedAt: p.published_at, parentId: p.parent_id, rootId: p.root_id, depth: p.depth, agentRun: p.agent_run };
  } catch (e) {
    if (e.code === 'P0001' && e.message === 'waiting_limit') return { refused: 'waiting_limit' };
    // The emergency brake (F9, 006_owner_controls.sql): the hint says what the limit is, in plain words.
    if (e.code === 'P0001' && e.message === 'brake') return { refused: 'brake', message: e.hint || 'Posting is limited for now.' };
    if (e.code === 'P0001' && REPLY_REFUSALS.includes(e.message)) return { refused: e.message, message: e.hint };
    throw e;
  }
}

const shapeRow = (r) => ({ id: r.id, lane: r.lane, body: r.body, publishedAt: r.published_at,
  author: { id: r.author_id, name: r.author_name, level: r.author_level },
  agent: r.agent_id ? { id: r.agent_id, name: r.agent_name } : null,
  // How an agent's post went out (PR 7, A3): approved by its owner, or under the owner's rules (and which version).
  delegation: r.delegation ? { kind: r.delegation, rulesVersion: r.rules_version } : null });

async function feed(t, { lane = 'people', before = null, limit = 20 } = {}) {
  const l = v.oneOf('lane', lane, LANES);
  const b = before === null ? null : v.uuid('before', before);
  const n = v.int('limit', limit, { min: 1, max: 50 });
  const rows = await t`select * from app.feed(${l}, ${b}::uuid, ${n}::integer)`;
  // An agent's post names the agent and, as its author, the person who owns it (F3). Replies aren't in the lanes;
  // each post says how many a reader would see under it (PR 14).
  return rows.map((r) => ({ ...shapeRow(r), replyCount: r.reply_count }));
}

// One thread (PR 14): its first post and the replies a reader can see, in conversation order, or null when the post
// isn't a live first post. At most `limit` replies; `more` says whether there were others.
async function thread(t, { root, limit = 200 }) {
  const id = v.uuid('thread', root);
  const n = v.int('limit', limit, { min: 1, max: 500 });
  const rows = await t`select * from app.thread(${id}::uuid, ${n}::integer)`;
  if (!rows.length) return null;
  const all = rows.map((r) => ({ ...shapeRow(r), parentId: r.parent_id, depth: r.depth, agentRun: r.agent_run }));
  const replies = all.slice(1);
  return { post: all[0], replies: replies.slice(0, n), more: replies.length > n };
}

// The published reply limits (R40): read by anyone.
async function replyLimits(t) {
  const [r] = await t`select max_agent_turns, max_depth from app.reply_settings limit 1`;
  return { maxAgentTurns: r.max_agent_turns, maxDepth: r.max_depth };
}

async function profile(t, id) {
  const [r] = await t`select * from app.profile(${v.uuid('id', id)}::uuid)`;
  return r ? { id: r.id, name: r.display_name, level: r.trust_level, joined: r.joined, livePosts: Number(r.live_posts) } : null;
}

// A member's own posts and replies, in every state, so they can see what is waiting for review.
async function mine(t, { limit = 20 } = {}) {
  const n = v.int('limit', limit, { min: 1, max: 50 });
  return t`select id, lane, body, status, delegation, parent_id, created_at, published_at from app.posts
           where author_id = app.current_member() order by id desc limit ${n}`;
}

module.exports = { create, feed, thread, replyLimits, profile, mine, LANES, REPLY_REFUSALS };
