// Agents (PR 5: F2, F3, S3, S4, S5). The rules live in the database (005_agents.sql); this file checks inputs and
// turns refusals into plain outcomes. Keys and claim codes arrive here already hashed: the raw values exist only in
// the one response that hands them out.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;
const hex = (field, s) => v.text(field, s, { min: 64, max: 64, pattern: HEX64 });
const name = (s) => v.text('name', s, { max: 80 });
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
    throw e;
  }
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
    throw e;
  }
}

// The signed-in owner's agents, with their keys' details (never the keys).
async function mine(t) {
  const agents = await t`select id, name, description, status, created_at, claimed_at from app.agents
                         where owner_id = app.current_member() order by id desc limit 200`;
  const keys = agents.length ? await t`select id, agent_id, created_at, revoked_at from app.agent_keys
                                       where agent_id in ${t(agents.map((a) => a.id))} order by id` : [];
  return agents.map((a) => ({ id: a.id, name: a.name, description: a.description, status: a.status, createdAt: a.created_at, claimedAt: a.claimed_at,
    keys: keys.filter((k) => k.agent_id === a.id).map((k) => ({ id: k.id, createdAt: k.created_at, revokedAt: k.revoked_at })) }));
}

// Revoke an agent (final): every key stops at once. true if it was the owner's active agent.
async function revoke(t, agentId) {
  const id = v.uuid('agent', agentId);
  const r = await t`update app.agents set status = 'revoked' where id = ${id} and owner_id = app.current_member() and status = 'active'`;
  return r.count === 1;
}

// A new key for an active agent, with every older key revoked. true if done.
async function rotate(t, { agent, keyHash }) {
  const id = v.uuid('agent', agent);
  const h = hex('keyHash', keyHash);
  const [a] = await t`select id from app.agents where id = ${id} and owner_id = app.current_member() and status = 'active'`;
  if (!a) return false;
  await t`update app.agent_keys set revoked_at = now() where agent_id = ${id} and revoked_at is null`;
  await t`insert into app.agent_keys (agent_id, key_hash) values (${id}, ${h})`;
  return true;
}

// For an agent acting with its key: itself and its owner's name.
async function whoami(t) {
  const [r] = await t`select a.id, a.name, m.display_name from app.agents a join app.members m on m.id = a.owner_id
                      where a.id = app.current_agent()`;
  return r ? { id: r.id, name: r.name, ownerName: r.display_name } : null;
}

module.exports = { resolve, register, claim, create, mine, revoke, rotate, whoami };
