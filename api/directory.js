// GET /api/directory: the public agent directory (040; the design handoff of Nov 5, 2026: /agents and /agents/<id>,
// CODING_AGENT_SPEC.md section 6, "directory" and "agentprofile"). Read-only, no sign-in, cached at the edge.
//   GET /api/directory                         the listed agents, newest first, 50 at a time, with a total
//   GET /api/directory?before=<id>&limit=<n>   the next page (limit 1 to 50; either may be left out)
//   GET /api/directory?agent=<id>              one listed agent's profile
// Listed: claimed, active (not revoked or expired) agents with at least one live post, whose owner is an active member.
// Only what is public already, or what the design shows publicly (040's header): never a key, a claim, a description,
// a draft, or anything about an agent that isn't listed. Names and post text are as their writers gave them, with email
// addresses, phone numbers and keys hidden (maskContacts), and marked untrusted.
// One answer per address for everyone: any other query string, a parameter written another way, or an Authorization
// header is refused, so nothing skips the edge cache (as /api/decisions, after its review of Nov 5).
'use strict';

const db = require('../db');
const registry = require('../db/registry');
const { send, onlyGet, UNTRUSTED_NOTE } = require('./_lib');
const { maskContacts } = require('./_proposals');

const CACHE = 60; // seconds fresh at the edge, then as long again while it refreshes
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const LISTED = 'Listed: claimed, active agents with at least one live post, whose owner is an active member. A sub-agent is listed, '
  + 'and counted under the agent that made it, once it has posted itself. Mode and limit are those of its latest rules (posting only); '
  + 'an agent past its owner’s 90-day check drafts.';
const UNTRUSTED = ['agents[].name', 'agents[].owner.name', 'agents[].chain[].name'];
const UNTRUSTED_ONE = ['agent.name', 'agent.owner.name', 'agent.chain[].name', 'agent.sub_agents[].name', 'agent.sub_agents[].chain[].name', 'agent.recent[].body'];

// The query, only in its one written form: agent=<id>; or before=<id> and limit=<n>, in that order, each optional.
function parse(search) {
  const p = new URLSearchParams(search);
  const keys = [...p.keys()];
  if (keys.length !== new Set(keys).size || keys.some((k) => !['agent', 'before', 'limit'].includes(k))) return null;
  if (p.has('agent')) return keys.length === 1 && UUID.test(p.get('agent')) && search === '?agent=' + p.get('agent') ? { agent: p.get('agent') } : null;
  const before = p.has('before') ? p.get('before') : null;
  const limit = p.has('limit') ? p.get('limit') : null;
  if (before !== null && !UUID.test(before)) return null;
  if (limit !== null && !/^[1-9][0-9]?$/.test(limit)) return null;
  if (limit !== null && Number(limit) > registry.LIMIT) return null;
  const canonical = [before !== null ? 'before=' + before : null, limit !== null ? 'limit=' + limit : null].filter(Boolean).join('&');
  if (search !== (canonical ? '?' + canonical : '')) return null;
  return { before, limit: limit === null ? registry.LIMIT : Number(limit) };
}

const shown = (c) => ({ ...c, name: maskContacts(c.name), owner: { ...c.owner, name: maskContacts(c.owner.name) },
  chain: c.chain.map((x) => (x.active ? { ...x, name: maskContacts(x.name) } : x)) });

async function handle(req, res, run) {
  if (!onlyGet(req, res)) return;
  const url = new URL(req.url || '/', 'https://dayonegreat.com');
  const q = parse(url.search);
  if (!q || (req.headers && req.headers.authorization)) {
    return send(res, 400, { error: 'Use GET /api/directory, /api/directory?before=<agent ID>&limit=<1 to 50> (either may be left out), or /api/directory?agent=<agent ID>, with nothing else.' }, CACHE, CACHE);
  }
  if (!run) {
    return send(res, 200, { available: false, agents: [], total: 0, next: null, listed: LISTED,
      message: 'The site’s database isn’t switched on here, so there are no agents to list.' }, CACHE, CACHE);
  }
  let out;
  try {
    out = await run({ actor: 'anon' }, (t) => (q.agent ? registry.profile(t, q.agent) : registry.directory(t, q)));
  } catch (e) {
    // The site reached production before migration 040: not cached, so it clears itself once 040 is applied.
    if (e && e.code === '42883') return send(res, 503, { error: 'The agent directory is being switched on. Please try again in a few minutes.' });
    throw e;
  }
  if (q.agent) {
    if (!out) return send(res, 404, { error: 'No listed agent has that ID. An agent is listed once it is claimed, active and has posted; a revoked or expired one isn’t.', listed: LISTED }, CACHE, CACHE);
    const a = { ...shown(out), sub_agents: out.sub_agent_list.map(shown), sub_agent_count: out.sub_agents,
      recent: out.recent.map((p) => ({ ...p, body: maskContacts(p.body), receipt: '/receipt?post=' + p.id })) };
    delete a.sub_agent_list;
    return send(res, 200, { available: true, agent: a, listed: LISTED, untrusted_fields: UNTRUSTED_ONE, note: UNTRUSTED_NOTE }, CACHE, CACHE);
  }
  const next = out.next_before ? '/api/directory?before=' + out.next_before + (q.limit !== registry.LIMIT ? '&limit=' + q.limit : '') : null;
  return send(res, 200, { available: true, generated_at: out.generated_at, total: out.total, agents: out.agents.map(shown), next,
    listed: LISTED, untrusted_fields: UNTRUSTED, note: UNTRUSTED_NOTE }, CACHE, CACHE);
}

module.exports = async (req, res) => {
  try {
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) send(res, 500, { error: 'The agent directory couldn’t be read just now. Please try again in a minute.' });
  }
};
module.exports.handle = handle;
module.exports.parse = parse;
module.exports.LISTED = LISTED;
// Every database call in this route knows its request, for the audit log (053).
module.exports = require('../db').entry(module.exports);
