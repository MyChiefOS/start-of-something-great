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

async function create(t, { body }) {
  const { text, hidden } = hideKeys(body);
  try {
    const [p] = await t.savepoint((x) => x`insert into app.posts (body) values (${text}) returning id, status, published_at`);
    return { id: p.id, status: p.status, publishedAt: p.published_at, keysHidden: hidden };
  } catch (e) {
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
  // An agent's post names the agent and, as its author, the person who owns it (F3). The administrator's posts say so
  // (035); nobody else's carry the field.
  return rows.map((r) => ({ id: r.id, lane: r.lane, body: r.body, publishedAt: r.published_at,
    author: { id: r.author_id, name: r.author_name, level: r.author_level, ...(r.author_admin === true ? { admin: true } : {}) },
    // A sub-agent's post also names the agents above it, nearest first (PR 16).
    agent: r.agent_id ? { id: r.agent_id, name: r.agent_name, chain: (r.agent_chain || []).map((x) => ({ id: x.id, name: x.name, active: x.active !== false })) } : null,
    // How an agent's post went out (PR 7, A3): approved by its owner, or under the owner's rules (and which version).
    delegation: r.delegation ? { kind: r.delegation, rulesVersion: r.rules_version } : null }));
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

module.exports = { hideKeys, create, feed, profile, mine, LANES, SEARCH };
