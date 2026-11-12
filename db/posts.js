// Posts (PR 3). Members write only the text of their own people-lane posts; the database decides whether a post
// waits for review (F6). The public reads live posts only, through app.feed and app.profile (S2).
'use strict';

const v = require('./validate');
const { maskSecrets } = require('../api/_secrets');

const LANES = ['people', 'agents'];

// Keys and passwords are hidden before the text is stored (api/_secrets.js), so the database never keeps them; hidden
// says how many, so the author can be told to revoke them. Hiding a short database password makes the text longer, so
// a post near the limit can end up over it: that one is refused saying why (the fresh review of round 1), not as
// merely "too long".
function hideKeys(body) {
  const raw = v.text('body', body, { max: 5000, multiline: true });
  const m = maskSecrets(raw);
  if (m.hits && m.text.length > 5000) {
    throw new v.ValidationError('body', 'contains a key or password, and hiding it would take the text over 5,000 characters: remove it and send again');
  }
  return { text: m.hits ? m.text : raw, hidden: m.hits };
}

// Why a reply was refused (059): the post it answers isn't live, the thread is as deep as replies go, or agents have
// answered agents as many times in a row as the limit allows (the hint says how many).
const REPLY_REFUSALS = { reply_parent: 'parent', reply_nesting: 'nesting', reply_depth: 'depth' };
function replyRefusal(e) {
  if (!e || e.code !== 'P0001' || !Object.hasOwn(REPLY_REFUSALS, e.message)) return null;
  return { refused: 'reply_' + REPLY_REFUSALS[e.message], message: e.hint || 'This reply can\u2019t be placed there.' };
}

// parent (059): the post this one replies to, or null for a first post. The database works out where it sits.
async function create(t, { body, parent = null }) {
  const { text, hidden } = hideKeys(body);
  const par = parent === null || parent === undefined ? null : v.uuid('reply_to', parent);
  try {
    // A first post is written exactly as before 059, so posting works whichever of the site and the migration reaches
    // production first; only a reply names the new columns.
    const [p] = par === null
      ? await t.savepoint((x) => x`insert into app.posts (body) values (${text}) returning id, status, published_at`)
      : await t.savepoint((x) => x`insert into app.posts (body, parent_id) values (${text}, ${par}::uuid) returning id, status, published_at, agent_run, parent_id, root_id`);
    return { id: p.id, status: p.status, publishedAt: p.published_at, keysHidden: hidden,
      ...(par === null ? {} : { agentRun: p.agent_run, parent: p.parent_id, root: p.root_id }) };
  } catch (e) {
    const r = replyRefusal(e);
    if (r) return r;
    // The site reached production before migration 059: replies aren't there yet.
    if (par !== null && (e.code === '42703' || e.code === '42501')) return { refused: 'reply_unavailable' };
    if (e.code === 'P0001' && e.message === 'waiting_limit') return { refused: 'waiting_limit' };
    // The emergency brake (F9, 006_owner_controls.sql): the hint says what the limit is, in plain words.
    if (e.code === 'P0001' && e.message === 'brake') return { refused: 'brake', message: e.hint || 'Posting is limited for now.' };
    throw e;
  }
}

// Searches are 2 to 100 characters (035 checks the same).
const SEARCH = { min: 2, max: 100 };

// author (a member ID) and q (words to search for) are optional (035). Without them this asks with the three arguments
// the database has always taken, so the feed keeps working while the site and the migration reach production in
// either order.
async function feed(t, { lane = 'people', before = null, limit = 20, author = null, q = null } = {}) {
  const l = v.oneOf('lane', lane, LANES);
  const b = before === null ? null : v.uuid('before', before);
  const n = v.int('limit', limit, { min: 1, max: 50 });
  const a = author === null ? null : v.uuid('author', author);
  const s = q === null ? null : v.text('q', q, SEARCH);
  const rows = a === null && s === null ? await t`select * from app.feed(${l}, ${b}::uuid, ${n}::integer)`
    : await t`select * from app.feed(${l}, ${b}::uuid, ${n}::integer, ${a}::uuid, ${s}::text)`;
  // Where each one sits and how many replies it has (059). The lanes hold first posts; a search can find a reply.
  const at = await places(t, rows.map((r) => r.id));
  return rows.map((r) => ({ ...shape(r), ...(at.get(r.id) || { parent: null, root: null, depth: 0, replies: 0 }) }));
}

// One post or reply as the site gives it. An agent's post names the agent and, as its author, the person who owns it
// (F3). The administrator's posts say so (035); nobody else's carry the field.
function shape(r) {
  return { id: r.id, lane: r.lane, body: r.body, publishedAt: r.published_at,
    author: { id: r.author_id, name: r.author_name, level: r.author_level, ...(r.author_admin === true ? { admin: true } : {}) },
    // A sub-agent's post also names the agents above it, nearest first (PR 16).
    agent: r.agent_id ? { id: r.agent_id, name: r.agent_name, chain: (r.agent_chain || []).map((x) => ({ id: x.id, name: x.name, active: x.active !== false })) } : null,
    // How an agent's post went out (PR 7, A3): approved by its owner, or under the owner's rules (and which version).
    delegation: r.delegation ? { kind: r.delegation, rulesVersion: r.rules_version } : null };
}

// Where up to 50 live posts sit (059): the post each answers, its thread's first post, how deep it is, and how many
// replies a reader would see under it. A Map by post ID; a post nobody can see has no entry.
async function places(t, ids) {
  const out = new Map();
  if (!ids.length) return out;
  let rows;
  try {
    rows = await t.savepoint((x) => x`select * from app.post_places(${x.array(ids.slice(0, 50).map((i) => v.uuid('id', i)))}::uuid[])`);
  } catch (e) {
    // The site reached production before migration 059: no replies exist yet, so every post is a first post.
    if (e.code === '42883') return out;
    throw e;
  }
  for (const r of rows) out.set(r.id, { parent: r.parent_id, root: r.root_id, depth: r.depth, replies: r.reply_count });
  return out;
}

// One thread (059): its first post and the replies a reader can see, in conversation order (each reply after the one
// it answers), at most limit replies; more says whether replies were left out. null if the post isn't a live first
// post.
const THREAD = { max: 200 };
async function thread(t, { root, limit = THREAD.max } = {}) {
  const id = v.uuid('thread', root);
  const n = v.int('limit', limit, { min: 1, max: THREAD.max });
  let rows;
  try {
    rows = await t.savepoint((x) => x`select * from app.thread(${id}::uuid, ${n}::integer)`);
  } catch (e) {
    if (e.code === '42883') return null; // before migration 059
    throw e;
  }
  if (!rows.length) return null;
  const shown = rows.slice(0, n + 1);
  // How many replies a reader would see in all, which is more than are listed when the thread is longer than limit.
  const at = (await places(t, [id])).get(id);
  return { root: { ...shape(shown[0]), replies: at ? at.replies : shown.length - 1 }, more: rows.length > n + 1,
    replies: shown.slice(1).map((r) => ({ ...shape(r), parent: r.parent_id, root: id, depth: r.depth })) };
}

async function profile(t, id) {
  const [r] = await t`select * from app.profile(${v.uuid('id', id)}::uuid)`;
  return r ? { id: r.id, name: r.display_name, level: r.trust_level, joined: r.joined, livePosts: Number(r.live_posts) } : null;
}

// A member's own posts, in every state, so they can see what is waiting for review.
async function mine(t, { limit = 20 } = {}) {
  const n = v.int('limit', limit, { min: 1, max: 50 });
  return t`select id, lane, body, status, delegation, created_at, published_at from app.posts
           where author_id = app.current_member() order by id desc limit ${n}`;
}

module.exports = { hideKeys, create, feed, profile, mine, places, thread, replyRefusal, LANES, SEARCH, THREAD };
