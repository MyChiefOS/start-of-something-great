// Agents (PR 5: F2, F3, S3, S4, S5). The rules live in the database (005_agents.sql); this file checks inputs and
// turns refusals into plain outcomes. Keys and claim codes arrive here already hashed: the raw values exist only in
// the one response that hands them out.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;
const hex = (field, s) => v.text(field, s, { min: 64, max: 64, pattern: HEX64 });
// An agent's name can't imitate the line that names its owner ("X · agent of Y"), since registering needs no account,
// nor the chain a sub-agent's posts show ("X · sub-agent of Y — owned by Z", PR 16), since agents name sub-agents.
// Checked on the NFKC form (so full-width and styled letters count as plain ones), refusing every dash, the minus
// sign and the dots and bars the labels use, characters that show as nothing, and a "skeleton" in which common
// Cyrillic, Greek and other lookalikes of Latin letters are read as those letters (the review of PR 16, F4). A small
// built-in map, not the whole Unicode confusables list: it covers the letters of "agent of" and "owned by".
const NAME_MARKS = /[\p{Pd}\u2212\u00b7\u0387\u2022\u2027\u2219\u22c5\u30fb\uff65|]/u;
// Shown as nothing, or as a blank: soft hyphen, combining grapheme joiner, zero-width (non-)joiner, Mongolian vowel
// separator, Hangul fillers, and every other invisible "format" character (\p{Cf}).
const NAME_HIDDEN = /[\p{Cf}\u00ad\u034f\u115f\u1160\u180e\u200c\u200d\u3164\uffa0]/u;
const LOOKALIKE = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g',
  'ո': 'n', 'ց': 'g', 'ս': 'u', 'օ': 'o', 'α': 'a', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'β': 'b', 'η': 'n',
  'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r',
  'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z', 'ı': 'i', 'ɑ': 'a', 'ɵ': 'o', '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };
function skeleton(n) {
  return [...n.normalize('NFKC').toLowerCase().normalize('NFD').replace(/\p{M}/gu, '')].map((ch) => LOOKALIKE[ch] || ch).join('')
    .replace(/[^\p{L}\p{N}]+/gu, ' ');
}
function name(s) {
  const n = v.text('name', s, { max: 80 });
  const k = n.normalize('NFKC');
  if (NAME_MARKS.test(k) || NAME_HIDDEN.test(n) || NAME_HIDDEN.test(k) || /agent\s*of|owned\s*by/.test(skeleton(n))) {
    throw new v.ValidationError('name', 'can\'t contain "·", "|", "•", any dash, invisible characters, "agent of" or "owned by" (in any lettering)');
  }
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

// The signed-in owner's agents, with their keys' details (never the keys). The agents the owner made or claimed always
// come first, in a query of their own, so no tree can push them (and their Revoke buttons) off the list (the review of
// PR 16, F3). Then sub-agents (PR 16), with their place in the tree, newest first, up to SUB_LISTED; stopped ones drop
// off after a week. trees: per top-level agent, how many sub-agents are active and how many are listed.
const SUB_LISTED = 300;
async function listMine(t) {
  const roots = await t`select id, name, description, status, created_at, claimed_at, parent_id, depth, expires_at from app.agents
                        where owner_id = app.current_member() and parent_id is null order by id desc limit 500`;
  const subs = await t`select id, name, description, status, created_at, claimed_at, parent_id, depth, expires_at, root_id from app.agents
                       where owner_id = app.current_member() and parent_id is not null
                         and (status = 'active' or created_at > now() - interval '7 days')
                       order by id desc limit ${SUB_LISTED + 1}`;
  const trees = await t`select root_id, count(*) filter (where status = 'active')::int as active from app.agents
                        where owner_id = app.current_member() and parent_id is not null group by root_id`;
  const agents = roots.concat(subs.slice(0, SUB_LISTED));
  const keys = agents.length ? await t`select id, agent_id, created_at, revoked_at from app.agent_keys
                                       where agent_id in ${t(agents.map((a) => a.id))} order by id` : [];
  const shaped = agents.map((a) => ({ id: a.id, name: a.name, description: a.description, status: a.status, createdAt: a.created_at, claimedAt: a.claimed_at,
    parentId: a.parent_id, depth: a.depth, expiresAt: a.expires_at,
    keys: keys.filter((k) => k.agent_id === a.id).map((k) => ({ id: k.id, createdAt: k.created_at, revokedAt: k.revoked_at })) }));
  const listed = subs.slice(0, SUB_LISTED);
  return {
    agents: shaped,
    trees: trees.map((x) => ({ rootId: x.root_id, active: x.active, listed: listed.filter((a) => a.root_id === x.root_id).length })),
    truncated: subs.length > SUB_LISTED
  };
}
const mine = async (t) => (await listMine(t)).agents;

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
    // PR 17: a risky grant needs a passkey check in the last 5 minutes (the database decides, by its clock).
    if (e.code === 'P0001' && e.message === 'step_up') return { refused: 'step_up' };
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
// The database decides everything that matters (015_subagents.sql): the owner (always the parent's), the depth limit,
// the hourly rates, the expiry (never after the parent's) and rules no higher than the parent's. This checks inputs and
// turns refusals into plain outcomes. rules: { post, reply, report, daily_cap }, each optional. draftOnly: JEVs found
// the creation medium risk (enforce mode), so every "act" becomes "draft".
// { id, depth, expiresAt, rules, chain (the IDs above it, nearest first) } or { refused: 'depth' | 'rate_parent' | 'rate_owner' | 'ttl' | 'above_parent' | 'brake' | 'not_active', message? }
const MODES = ['off', 'draft', 'act'];
// The request's own fields, checked before anything else (so a malformed request uses up no allowance and reaches
// neither JEVs nor the database): { name, description, post, reply, report, cap, ttl }.
function subArgs({ name: n, description: d, rules, ttlHours }) {
  const r = rules === undefined || rules === null ? {} : v.object('rules', rules, { maxBytes: 200 });
  for (const k of Object.keys(r)) if (!['post', 'reply', 'report', 'daily_cap'].includes(k)) throw new v.ValidationError('rules', 'can set only post, reply, report and daily_cap');
  const mode = (f) => (r[f] === undefined || r[f] === null ? null : v.oneOf('rules.' + f, r[f], MODES));
  return { name: name(n), description: description(d), post: mode('post'), reply: mode('reply'), report: mode('report'),
    cap: r.daily_cap === undefined || r.daily_cap === null ? null : v.int('rules.daily_cap', r.daily_cap, { min: 1, max: 1000 }),
    ttl: ttlHours === undefined || ttlHours === null ? null : v.int('ttl_hours', ttlHours, { min: 1, max: 720 }) };
}
// The cheap refusals, as the acting agent, before JEVs scores anything (the review of PR 16, F6): its depth against the
// limit, and the sub-agents it made in the last hour against the per-parent rate. The database checks both again, with
// the per-owner rate, when it makes the sub-agent. null, or { refused, message } worded as the database words them.
async function subPrecheck(t) {
  const [r] = await t`select a.depth, s.max_depth, s.per_parent_per_hour,
                        (select count(*)::int from app.agents c where c.parent_id = a.id and c.created_at > now() - interval '1 hour') as made
                      from app.agents a cross join app.subagent_settings s where a.id = app.current_agent()`;
  if (!r) return { refused: 'not_active' };
  if (r.depth + 1 > r.max_depth) {
    return { refused: 'depth', message: 'Sub-agents go at most ' + r.max_depth + ' levels below the agent their owner made, and this agent is already at level ' + r.depth + '.' };
  }
  if (r.made >= r.per_parent_per_hour) return { refused: 'rate_parent', message: 'One agent can make at most ' + r.per_parent_per_hour + ' sub-agents an hour.' };
  return null;
}
// callerKeyHash: the SHA-256 of the key the request came with; the database locks and re-checks it (F2).
async function createSub(t, { keyHash, callerKeyHash, draftOnly = false, ...input }) {
  const x0 = subArgs(input);
  const args = [x0.name, x0.description, hex('keyHash', keyHash), x0.post, x0.reply, x0.report];
  const cap = x0.cap;
  const ttl = x0.ttl;
  const caller = hex('callerKeyHash', callerKeyHash);
  try {
    const [x] = await t.savepoint((s) => s`select * from app.subagent_create(${args[0]}, ${args[1]}, ${args[2]}, ${args[3]}, ${args[4]}, ${args[5]},
      ${cap}::integer, ${ttl}::integer, ${draftOnly === true}, ${caller})`);
    return { id: x.agent_id, depth: x.depth, expiresAt: x.expires_at,
      rules: { version: x.rules_version, post: x.post_mode, reply: x.reply_mode, report: x.report_mode, daily_cap: x.daily_cap },
      chain: x.chain || [] };
  } catch (e) {
    if (e.code === 'P0001' && ['depth', 'rate_parent', 'rate_owner', 'ttl', 'above_parent', 'brake'].includes(e.message)) return { refused: e.message, message: e.hint };
    // Lock order is fixed (member, agent, key) so this shouldn't happen; if Postgres still finds a deadlock with some
    // other change, nothing was made, and the agent is told to try again rather than given an error.
    if (e.code === '40P01') return { refused: 'busy', message: 'Something else changed this agent or its owner at the same moment; nothing was made. Please try again.' };
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

module.exports = { checkName, skeleton, resolve, register, claim, preview, create, mine, listMine, revoke, rotate, whoami, subArgs, subPrecheck, createSub,
  children, revokeChild, subLimits };
