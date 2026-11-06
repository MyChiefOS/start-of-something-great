// The agent registry (040; the design handoff of Nov 5, 2026: /agents, /agents/<id>, /agents/join). The database
// decides who is listed and what is shown (app.public_agents, app.public_agent); this file checks inputs and makes every
// value the type it should be, so nothing else the database might add reaches a visitor. Recovery keys arrive here
// already hashed: the raw values exist only in the one answer that hands them out.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;
const MODES = ['off', 'draft', 'act'];
const LIMIT = 50;
// A rate of posts removed after going live is given only from this many posts that went live (as /decisions does).
const MIN_SAMPLE = 20;

const str = (x) => (x === null || x === undefined ? null : String(x));
const int = (x) => (x === null || x === undefined ? 0 : Math.max(0, Math.trunc(Number(x)) || 0));
const day = (x) => (x === null || x === undefined ? null : String(x).slice(0, 10));
const id = (x) => (typeof x === 'string' && /^[0-9a-f-]{36}$/.test(x) ? x : null);

function card(c) {
  return {
    id: id(c.id), name: str(c.name),
    owner: { id: id(c.owner && c.owner.id), name: str(c.owner && c.owner.name), level: int(c.owner && c.owner.level), ...(c.owner && c.owner.admin === true ? { admin: true } : {}) },
    mode: MODES.includes(c.mode) ? c.mode : 'off',
    daily_cap: c.daily_cap === null || c.daily_cap === undefined ? null : int(c.daily_cap),
    rules_version: int(c.rules_version) || null,
    review_by: day(c.review_by),
    expires_on: day(c.expires_on),
    is_sub_agent: c.is_sub_agent === true,
    chain: (Array.isArray(c.chain) ? c.chain : []).map((x) => (x && x.active === true ? { id: id(x.id), name: str(x.name), active: true } : { id: null, name: null, active: false })),
    sub_agents: int(c.sub_agents)
  };
}

// The directory: { agents, next_before, total, generated_at }.
async function directory(t, { before = null, limit = LIMIT } = {}) {
  const b = before === null ? null : v.uuid('before', before);
  const n = v.int('limit', limit, { min: 1, max: LIMIT });
  const [r] = await t`select app.public_agents(${b}::uuid, ${n}::integer) as d`;
  const d = r.d || {};
  return { generated_at: d.generated_at, total: int(d.total), next_before: id(d.next_before),
    agents: (Array.isArray(d.agents) ? d.agents : []).map(card) };
}

// One listed agent's profile, or null.
async function profile(t, agentId) {
  const [r] = await t`select app.public_agent(${v.uuid('agent', agentId)}::uuid) as d`;
  const d = r.d;
  if (!d) return null;
  const wentLive = int(d.went_live), removed = int(d.removed);
  return { ...card(d), generated_at: d.generated_at, live_posts: int(d.live_posts),
    removed_after_live: { went_live: wentLive, removed, rate: wentLive >= MIN_SAMPLE ? Math.round((removed / wentLive) * 1000) / 1000 : null, min_sample: MIN_SAMPLE },
    sub_agent_list: (Array.isArray(d.sub_agent_list) ? d.sub_agent_list : []).map(card),
    recent: (Array.isArray(d.recent) ? d.recent : []).map((p) => ({ id: id(p.id), body: str(p.body), published_at: p.published_at,
      delegation: p.delegation === 'approved' ? 'approved' : 'rules', rules_version: int(p.rules_version) || null })) };
}

// A working key (or the key registration just made) sets its agent's recovery key, or replaces it given the current one
// (currentHash; the independent review of Nov 5, M2): { id }, { refused: 'current' } (it has one, and the current one
// wasn't given or doesn't match), or null (the key doesn't work).
async function recoveryIssue(t, { keyHash, recoveryHash, currentHash = null }) {
  if (!HEX64.test(String(keyHash)) || !HEX64.test(String(recoveryHash)) || (currentHash !== null && !HEX64.test(String(currentHash)))) return null;
  try {
    const [r] = await t.savepoint((s) => s`select app.agent_recovery_issue(${keyHash}, ${recoveryHash}, ${currentHash}::text) as id`);
    return r.id ? { id: r.id } : null;
  } catch (e) {
    if (e.code === 'P0001' && e.message === 'recovery_key_required') return { refused: 'current' };
    throw e;
  }
}

// Which agent a recovery key is for, or null (so JEVs can check the recovery first, in the same transaction).
async function recoverySubject(t, recoveryHash) {
  if (!HEX64.test(String(recoveryHash))) return null;
  const [r] = await t`select app.agent_recovery_subject(${recoveryHash}) as id`;
  return r.id || null;
}

// For the signed-in owner: Map of agent ID to when its recovery key was set, for those of the given agents that have one.
async function recoveryStatus(t, agentIds) {
  const ids = (agentIds || []).filter((x) => typeof x === 'string').slice(0, 1000);
  if (!ids.length) return new Map();
  const rows = await t`select agent_id, set_at from app.agent_recovery_status(${t.array(ids)}::uuid[])`;
  return new Map(rows.map((r) => [r.agent_id, r.set_at]));
}

// For the signed-in owner: clear one of their agents' recovery keys. true if it had one.
async function recoveryClear(t, agentId) {
  const [r] = await t`select app.agent_recovery_clear(${v.uuid('agent', agentId)}::uuid) as ok`;
  return r.ok === true;
}

// A recovery key for a new key: { agentId, status, subagentsStopped } or null (unknown, used already, or its agent or
// owner stopped). The sub-agents directly under it stop (and everything under them), as with the owner's New key.
async function recover(t, { recoveryHash, keyHash, newRecoveryHash }) {
  if (![recoveryHash, keyHash, newRecoveryHash].every((h) => HEX64.test(String(h)))) return null;
  try {
    const [r] = await t.savepoint((s) => s`select agent_id, status, subagents_stopped from app.agent_recover(${recoveryHash}, ${keyHash}, ${newRecoveryHash})`);
    return r ? { agentId: r.agent_id, status: r.status, subagentsStopped: Number(r.subagents_stopped) || 0 } : null;
  } catch (e) {
    // The owner was banned while this ran (the key trigger re-checks under a lock): nothing changed.
    if (e.code === '42501' && e.message === 'owner_not_active') return null;
    throw e;
  }
}

module.exports = { directory, profile, recoveryIssue, recoverySubject, recoveryStatus, recoveryClear, recover, card, LIMIT, MIN_SAMPLE };
