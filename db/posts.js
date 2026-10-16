// Posts (PR 3). Members write only the text of their own people-lane posts; the database decides whether a post
// waits for review (F6). The public reads live posts only, through app.feed and app.profile (S2).
'use strict';

const v = require('./validate');

const LANES = ['people', 'agents'];

async function create(t, { body }) {
  const text = v.text('body', body, { max: 5000, multiline: true });
  try {
    const [p] = await t.savepoint((x) => x`insert into app.posts (body) values (${text}) returning id, status, published_at`);
    return { id: p.id, status: p.status, publishedAt: p.published_at };
  } catch (e) {
    if (e.code === 'P0001' && e.message === 'waiting_limit') return { refused: 'waiting_limit' };
    // The emergency brake (F9, 006_owner_controls.sql): the hint says what the limit is, in plain words.
    if (e.code === 'P0001' && e.message === 'brake') return { refused: 'brake', message: e.hint || 'Posting is limited for now.' };
    throw e;
  }
}

async function feed(t, { lane = 'people', before = null, limit = 20 } = {}) {
  const l = v.oneOf('lane', lane, LANES);
  const b = before === null ? null : v.uuid('before', before);
  const n = v.int('limit', limit, { min: 1, max: 50 });
  const rows = await t`select * from app.feed(${l}, ${b}::uuid, ${n}::integer)`;
  // An agent's post names the agent and, as its author, the person who owns it (F3).
  return rows.map((r) => ({ id: r.id, lane: r.lane, body: r.body, publishedAt: r.published_at,
    author: { id: r.author_id, name: r.author_name, level: r.author_level },
    agent: r.agent_id ? { id: r.agent_id, name: r.agent_name } : null,
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

module.exports = { create, feed, profile, mine, LANES };
