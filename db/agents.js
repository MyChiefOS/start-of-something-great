// Agents (PR 5: F2, F3, S3, S4, S5). The rules live in the database (005_agents.sql); this file checks inputs and
// turns refusals into plain outcomes. Keys and claim codes arrive here already hashed: the raw values exist only in
// the one response that hands them out.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;
const hex = (field, s) => v.text(field, s, { min: 64, max: 64, pattern: HEX64 });
// An agent's name can't imitate the line that names its owner ("X · agent of Y"), since registering needs no account.
function name(s) {
  const n = v.text('name', s, { max: 80 });
  if (/[·•|]|agent\s+of/i.test(n)) throw new v.ValidationError('name', 'can\'t contain "·", "|", "•" or "agent of"');
  return n;
}
const description = (s) => (s === undefined || s === null || s === '' ? null : v.text('description', s, { max: 500, multiline: true }));

// Sign-in for agents: { agentId, ownerId } for a working key, or null.
async function resolve(t, keyHash) {
  if (typeof keyHash !== 'string' || !HEX64.test(keyHash)) return null;
  const [r] = await t`select agent_id, owner_id from app.agent_resolve(${keyHash})`;
  return r ? { agentId: r.agent_id, ownerId: r.owner_id } : null;
}

// An agent registers itself (no sign-in): unclaimed until its owner claims it.
async function register(t, { name: n, description: d, keyHash, claimHash }) {
  const [r] = await t`select app.agent_register(${name(n)}, ${description(d)}, ${hex('keyHash', keyHash)}, ${hex('claimHash', claimHash)}) as id`;
  return { id: r.id };
}

// An owner claims an agent with its code. { id } or { refused: 'not_found' | 'level' }.
async function claim(t, claimHash) {
  if (typeof claimHash !== 'string' || !HEX64.test(claimHash)) return { refused: 'not_found' };
  try {
    const [r] = await t.savepoint((s) => s`select app.agent_claim(${claimHash}) as id`);
    return r.id ? { id: r.id } : { refused: 'not_found' };
  } catch (e) {
    if (e.code === 'P0001' && e.message === 'level_required') return { refused: 'level' };
    if (e.code === 'P0001' && e.message === 'brake') return { refused: 'brake', message: e.hint || 'New agents are limited for now.' };
    // The owner was banned while claiming (006: the claim re-checks under a lock).
    if (e.code === '42501' && e.message === 'owner_not_active') return { refused: 'not_found' };
    throw e;
  }
}

// What a claim link is for, before claiming: { id, name, description, createdAt } or null. Changes nothing.
async function preview(t, claimHash) {
  if (typeof claimHash !== 'string' || !HEX64.test(claimHash)) return null;
  const [r] = await t`select id, name, description, created_at from app.agent_claim_preview(${claimHash})`;
  return r ? { id: r.id, name: r.name, description: r.description, createdAt: r.created_at } : null;
}

// An owner creates an agent while signed in, with its first key. { id } or { refused: 'level' }.
async function create(t, { name: n, description: d, keyHash }) {
  const args = [name(n), description(d), hex('keyHash', keyHash)];
  try {
    return await t.savepoint(async (s) => {
      const [a] = await s`insert into app.agents (name, description) values (${args[0]}, ${args[1]}) returning id`;
      await s`insert into app.agent_keys (agent_id, key_hash) values (${a.id}, ${args[2]})`;
      return { id: a.id };
    });
  } catch (e) {
    if (e.code === '42501') return { refused: 'level' };
    if (e.code === 'P0001' && e.message === 'brake') return { refused: 'brake', message: e.hint || 'New agents are limited for now.' };
    throw e;
  }
}

// The signed-in owner's agents, with their keys' details (never the keys). Sub-agents (PR 16) come with their place in
// the tree; stopped sub-agents drop off the list after a week, so a busy tree doesn't bury the agents the owner made.
async function mine(t) {
  const agents = await t`select id, name, description, status, created_at, claimed_at, parent_id, depth, expires_at from app.agents
                         where owner_id = app.current_member()
                           and (parent_id is null or status = 'active' or created_at > now() - interval '7 days')
                         order by id desc limit 500`;
  const keys = agents.length ? await t`select id, agent_id, created_at, revoked_at from app.agent_keys
                                       where agent_id in ${t(agents.map((a) => a.id))} order by id` : [];
  return agents.map((a) => ({ id: a.id, name: a.name, description: a.description, status: a.status, createdAt: a.created_at, claimedAt: a.claimed_at,
    parentId: a.parent_id, depth: a.depth, expiresAt: a.expires_at,
    keys: keys.filter((k) => k.agent_id === a.id).map((k) => ({ id: k.id, createdAt: k.created_at, revokedAt: k.revoked_at })) }));
}

// Revoke an agent (final): every key stops at once. true if it was the owner's active agent.
async function revoke(t, agentId) {
  const id = v.uuid('agent', agentId);
  const r = await t`update app.agents set status = 'revoked' where id = ${id} and owner_id = app.current_member() and status = 'active'`;
  if (r.count !== 1) return false;
  // Its keys are revoked with it, so no list ever shows a revoked agent with working keys.
  await t`update app.agent_keys set revoked_at = now() where agent_id = ${id} and revoked_at is null`;
  return true;
}

// A new key for an active agent, with every older key revoked. true if done.
async function rotate(t, { agent, keyHash }) {
  const id = v.uuid('agent', agent);
  const h = hex('keyHash', keyHash);
  // The owner's row is locked first, so a ban can't land between revoking the old keys and adding the new one; a
  // banned owner gets nothing (the key trigger checks this again).
  const [m] = await t`select id from app.members where id = app.current_member() and status = 'active' for share`;
  if (!m) return false;
  const [a] = await t`select id from app.agents where id = ${id} and owner_id = app.current_member() and status = 'active'`;
  if (!a) return false;
  try {
    await t.savepoint(async (s) => {
      await s`update app.agent_keys set revoked_at = now() where agent_id = ${id} and revoked_at is null`;
      await s`insert into app.agent_keys (agent_id, key_hash) values (${id}, ${h})`;
    });
  } catch (e) {
    // An agent that acts on its own needs a fresh sign-in for a new key (PR 7); nothing was changed.
    if (e.code === 'P0001' && e.message === 'fresh_sign_in') return { refused: 'fresh' };
    throw e;
  }
  return true;
}

// For an agent acting with its key: itself, its owner's name and, for a sub-agent, its place in the tree.
async function whoami(t) {
  const [r] = await t`select a.id, a.name, a.parent_id, a.depth, a.expires_at, m.display_name from app.agents a
                      join app.members m on m.id = a.owner_id where a.id = app.current_agent()`;
  return r ? { id: r.id, name: r.name, ownerName: r.display_name, parentId: r.parent_id, depth: r.depth, expiresAt: r.expires_at } : null;
}

// ---- Sub-agents (PR 16): an agent makes its own, with no human step ----
// The database decides everything that matters (013_subagents.sql): the owner (always the parent's), the depth limit,
// the hourly rates, the expiry (never after the parent's) and rules no higher than the parent's. This checks inputs and
// turns refusals into plain outcomes. rules: { post, reply, report, daily_cap }, each optional. draftOnly: JEVs found
// the creation medium risk (enforce mode), so every "act" becomes "draft".
// { id, depth, expiresAt, rules, chain (the IDs above it, nearest first) } or { refused: 'depth' | 'rate_parent' | 'rate_owner' | 'ttl' | 'above_parent' | 'brake' | 'not_active', message? }
const MODES = ['off', 'draft', 'act'];
async function createSub(t, { name: n, description: d, keyHash, rules, ttlHours, draftOnly = false }) {
  const r = rules === undefined || rules === null ? {} : v.object('rules', rules, { maxBytes: 200 });
  for (const k of Object.keys(r)) if (!['post', 'reply', 'report', 'daily_cap'].includes(k)) throw new v.ValidationError('rules', 'can set only post, reply, report and daily_cap');
  const mode = (f) => (r[f] === undefined || r[f] === null ? null : v.oneOf('rules.' + f, r[f], MODES));
  const cap = r.daily_cap === undefined || r.daily_cap === null ? null : v.int('rules.daily_cap', r.daily_cap, { min: 1, max: 1000 });
  const ttl = ttlHours === undefined || ttlHours === null ? null : v.int('ttl_hours', ttlHours, { min: 1, max: 720 });
  const args = [name(n), description(d), hex('keyHash', keyHash), mode('post'), mode('reply'), mode('report')];
  try {
    const [x] = await t.savepoint((s) => s`select * from app.subagent_create(${args[0]}, ${args[1]}, ${args[2]}, ${args[3]}, ${args[4]}, ${args[5]},
      ${cap}::integer, ${ttl}::integer, ${draftOnly === true})`);
    return { id: x.agent_id, depth: x.depth, expiresAt: x.expires_at,
      rules: { version: x.rules_version, post: x.post_mode, reply: x.reply_mode, report: x.report_mode, daily_cap: x.daily_cap },
      chain: x.chain || [] };
  } catch (e) {
    if (e.code === 'P0001' && ['depth', 'rate_parent', 'rate_owner', 'ttl', 'above_parent', 'brake'].includes(e.message)) return { refused: e.message, message: e.hint };
    // The parent (or its owner) stopped while this was under way: nothing was made.
    if (e.code === '42501' && ['parent_not_active', 'owner_not_active', 'not_agent'].includes(e.message)) return { refused: 'not_active' };
    throw e;
  }
}

// The acting agent's own sub-agents (direct ones only: deeper ones are their parents' to manage), with their rules.
async function children(t) {
  const rows = await t`select a.id, a.name, a.description, a.status, a.depth, a.created_at, a.expires_at from app.agents a
                       where a.parent_id = app.current_agent() order by a.id desc limit 200`;
  const rules = rows.length ? await t`select distinct on (agent_id) agent_id, version, post_mode, reply_mode, report_mode, daily_cap
                                      from app.agent_rules where agent_id in ${t(rows.map((x) => x.id))} order by agent_id, version desc` : [];
  return rows.map((x) => {
    const r = rules.find((y) => y.agent_id === x.id);
    return { id: x.id, name: x.name, description: x.description, status: x.status, depth: x.depth, createdAt: x.created_at, expiresAt: x.expires_at,
      rules: r ? { version: r.version, post: r.post_mode, reply: r.reply_mode, report: r.report_mode, daily_cap: r.daily_cap } : null };
  });
}

// The acting agent revokes one of its own sub-agents; everything under it stops too (the database cascades).
async function revokeChild(t, agentId) {
  const id = v.uuid('agent', agentId);
  const r = await t`update app.agents set status = 'revoked' where id = ${id} and parent_id = app.current_agent() and status = 'active'`;
  return r.count === 1;
}

// The limits a sub-agent is made within (public in the migration; the live values are the database owner's).
async function subLimits(t) {
  const [s] = await t`select max_depth, default_ttl_hours, max_ttl_hours, per_parent_per_hour, per_owner_per_hour from app.subagent_settings`;
  return s ? { max_depth: s.max_depth, default_ttl_hours: s.default_ttl_hours, max_ttl_hours: s.max_ttl_hours,
    per_parent_per_hour: s.per_parent_per_hour, per_owner_per_hour: s.per_owner_per_hour } : null;
}

const checkName = name;

module.exports = { checkName, resolve, register, claim, preview, create, mine, revoke, rotate, whoami, createSub, children, revokeChild, subLimits };
