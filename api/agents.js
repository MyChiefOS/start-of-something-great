// Agents (Release 2, PR 5): /api/agents[/<route>], rewritten here by vercel.json.
//   POST /api/agents/register   {"name", "description"?}  an agent registers itself (no sign-in; rate limited, S6).
//                               Returns its key (once) and a claim link for its owner; the key works once claimed.
//   POST /api/agents/claim      {"code", "preview"?}      the signed-in owner (level 2) claims it (from /agents); with
//                                                         "preview": true, only says which agent it is
//   GET  /api/agents                                      the signed-in owner's agents, with key details (never keys)
//   POST /api/agents            {"name", "description"?}  the signed-in owner creates an agent; returns its key once
//   POST /api/agents/revoke     {"agent"}                 revoke an agent: every key stops at once (S4)
//   POST /api/agents/key        {"agent"}                 a new key, with every older key revoked
//   GET  /api/agents/me         (Authorization: Bearer)   which agent a key is, who owns it, and its owner's rules
//   GET  /api/agents/activity                             the owner's agents: rules, drafts waiting, what each did (PR 7)
//   POST /api/agents/rules      {"agent", "post", "reply", "report", "daily_cap"}  new rules (off | draft | act); raising
//                                                         any action to act needs a sign-in in the last 10 minutes
//   POST /api/agents/approve    {"draft", "hash"}         approve the exact words shown (hash = the hex SHA-256 of
//                                                         the UTF-8 text, computed by the page that showed it)
//   POST /api/agents/decline    {"draft"}                 decline a draft
//   POST /api/agents/reconfirm  {"agent", "version"}      keep an agent acting on its own for another 90 days (R33, PR 13);
//                                                         needs a sign-in in the last 10 minutes (PR 15)
//   POST /api/agents/subagents  (Authorization: Bearer)   an agent makes a sub-agent, with no human step (PR 16):
//                               {"name", "description"?, "rules"?: {"post", "reply", "report": off | draft | act, "daily_cap"},
//                                "ttl_hours"?}. Returns its key once. It belongs to the same owner, gets the same or narrower
//                                rules, expires (24 hours unless asked; never after its parent), and stops with its parent.
//   GET  /api/agents/subagents  (Authorization: Bearer)   the acting agent's own sub-agents, and the limits they are made within
//   POST /api/agents/subagents/revoke {"agent"} (Bearer)  revoke one of them; everything under it stops too
// Owners act from our own pages with their session; agents act with their key. Nothing here is ever cached.
// JEVs (PR 12) checks every sensitive step before it happens: registering, creating or claiming an agent, a new key,
// letting an agent act on its own. Medium risk asks the owner to sign in again; high risk holds it for Aaron. Making a
// sub-agent (PR 16) has no human step: medium risk makes it with everything drafting for its owner's approval.
// Self-registration from the EU, EEA, UK and Switzerland is declined before anything is kept (signin/region.js).
'use strict';

const db = require('../db');
const agents = require('../db/agents');
const delegation = require('../db/delegation');
const jevs = require('../db/jevs');
const region = require('../signin/region');
const notices = require('../db/notify');
const store = require('../db/signin');
const config = require('../signin/config');
const c = require('../signin/crypto');
const session = require('../signin/session');
const agentkey = require('../signin/agentkey');
const { onSite, sameSite, ipKey, netKey } = require('../signin/http');
const v = require('../db/validate');
const { ValidationError } = v;
const { ORIGIN } = require('../signin/config');
const { maskContacts } = require('./_proposals');

const MAX_BODY_BYTES = 4096;
// Self-registration is a sign-up, so it is rate limited (S6): per network, and a ceiling for everyone.
// Per address, per network (/48 or /24, so a provider's block can't spread itself thin) and for everyone.
const REGISTER_LIMITS = { agent_register_ip: { windowSeconds: 3600, max: 10 }, agent_register_net: { windowSeconds: 3600, max: 20 },
  agent_register_all: { windowSeconds: 3600, max: 500 } };
const ALL = '0'.repeat(64);
// Asking for sub-agents is limited per agent too (the review of PR 16, F6), like registration: twice the per-parent rate
// of making them, so refusals can't flood JEVs's decisions or the database's checks.
const SUBAGENT_LIMITS = { subagent_agent: { windowSeconds: 3600, max: 60 } };
// Letting an agent act without approval needs a sign-in this recent (R17), so a stolen or forgotten session can't do it.
const FRESH_MINUTES = 10;
const REAUTH = '/join?return_to=%2Fagents';

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body, null, 2));
}

async function readJson(req) {
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') return null;
  let raw;
  if (req.body !== undefined && req.body !== null) {
    raw = Buffer.isBuffer(req.body) || typeof req.body === 'string' ? String(req.body) : JSON.stringify(req.body);
  } else {
    let size = 0;
    const chunks = [];
    for await (const ch of req) { size += ch.length; if (size > MAX_BODY_BYTES) return null; chunks.push(ch); }
    raw = Buffer.concat(chunks).toString('utf8');
  }
  if (Buffer.byteLength(raw) > MAX_BODY_BYTES) return null;
  try { const v = JSON.parse(raw); return v && typeof v === 'object' && !Array.isArray(v) ? v : null; } catch { return null; }
}

// What a person is told when JEVs stops a sensitive step (its decision is already recorded).
function held(res, d) {
  if (d.invalid) return reply(res, 404, { error: 'No active agent of yours with that ID.' });
  if (d.effect === 'challenge') {
    return reply(res, 403, { error: 'Please sign in again to confirm this. Our automatic checks (JEVs) ask the owner to confirm it, then it goes ahead.',
      reauth: REAUTH, challenge: d.challenge });
  }
  return reply(res, 403, { error: 'This is held for review: our automatic checks (JEVs) found it high risk or couldn\u2019t finish. '
    + 'Please try again later, or write to hello@dayonegreat.com.' });
}
// JEVs's check and the sensitive step in one transaction, as the signed-in owner (the JEVs review, F7): the decision
// and the step commit together, and a fresh sign-in counts as confirming a challenge, which also answers the owner's
// earlier requests to confirm the same step. Returns { held: decision } or the step's own result.
const guarded = (run, who, req, cfg, action, subject, step, { check = true } = {}) =>
  run({ ...session.actorFor(who), fresh: who.fresh === true }, async (t) => {
    if (check) {
      const d = await jevs.check(t, { action, subject, ...jevs.facts(req, cfg.ipKey) });
      if (jevs.blocks(d)) return { held: d };
    }
    return step(t);
  });

// A sub-agent (PR 16) also says where it sits: its parent, its depth and when it expires (null for an agent the owner made).
const shapeAgent = (a) => ({ id: a.id, name: a.name, description: a.description, status: a.status, created_at: a.createdAt, claimed_at: a.claimedAt,
  parent_id: a.parentId === undefined ? null : a.parentId, depth: a.depth === undefined ? 0 : a.depth, expires_at: a.expiresAt === undefined ? null : a.expiresAt,
  keys: a.keys.map((k) => ({ id: k.id, created_at: k.createdAt, revoked_at: k.revokedAt })) });

const KEY_NOTE = 'This key is shown once. Keep it secret; send it as "Authorization: Bearer <key>". Revoke it at ' + ORIGIN + '/agents if it leaks.';

// A signed-in owner, on our own pages, for every change; reading needs only the session.
async function owner(req, res, run, { write }) {
  if (write && !sameSite(req)) { reply(res, 403, { error: 'This can only be done from dayonegreat.com.' }); return null; }
  const who = await session.current(req, run);
  if (!who) { reply(res, 401, { error: 'Sign in to manage agents.', join: '/join?return_to=%2Fagents' }); return null; }
  return who;
}

const ROUTES = {
  async 'POST register'(req, res, run, body, cfg) {
    // The regional gate: declined before anything about the request is kept, except one more in today's count.
    const country = region.declined(req);
    if (country) {
      await run({ actor: 'anon' }, (t) => jevs.regionDecline(t, country));
      return reply(res, 451, { error: region.MESSAGE });
    }
    const limits = [['agent_register_ip', ipKey(req, cfg.ipKey)], ['agent_register_net', netKey(req, cfg.ipKey)], ['agent_register_all', ALL]];
    const k = agentkey.newKey();
    const code = c.token(32);
    const out = await run({ actor: 'anon' }, async (t) => {
      // Inputs first, so a malformed request doesn't use up the allowance.
      const args = { name: body.name, description: body.description, keyHash: k.hash, claimHash: c.sha256hex(code) };
      agents.checkName(args.name);
      for (const [bucket, keyHash] of limits) {
        if (!(await store.rateLimitHit(t, { bucket, keyHash, ...REGISTER_LIMITS[bucket] }))) return { refused: 'slow' };
      }
      return { ok: true };
    });
    if (out.refused) return reply(res, 429, { error: 'Too many agents registered from here. Please try again in an hour.' });
    const f = jevs.facts(req, cfg.ipKey);
    // JEVs's check and the registration commit together.
    const reg = await run({ actor: 'anon' }, async (t) => {
      const d = await jevs.check(t, { action: 'agent.register', ...f });
      if (jevs.blocks(d)) return { held: d };
      const r = await agents.register(t, { name: body.name, description: body.description, keyHash: k.hash, claimHash: c.sha256hex(code) });
      // Which network it registered from (J05, J06): the keyed daily hash only.
      if (f.netHash) await jevs.mark(t, { kind: 'net', keyHash: f.netHash, agent: r.id });
      return r;
    });
    if (reg.held) return held(res, reg.held);
    return reply(res, 201, {
      agent_id: reg.id, status: 'unclaimed', key: k.key, key_note: KEY_NOTE,
      // The code is after "#", so it never reaches our server or its logs when the link is opened.
      claim_url: ORIGIN + '/agents#claim=' + code, claim_expires_in_hours: 24,
      next: 'Give claim_url to the person you act for. Once they claim you (signed in at level 2), your key can post: POST ' + ORIGIN +
        '/api/feed with {"body": "..."} and your key as "Authorization: Bearer <key>".'
    });
  },

  async 'POST claim'(req, res, run, body, cfg) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const code = typeof body.code === 'string' && /^[A-Za-z0-9_-]{43}$/.test(body.code) ? body.code : null;
    // A look first: which agent this is, so nobody claims blind (whoever sent the link holds the agent's key).
    if (body.preview === true) {
      const p = code ? await run(session.actorFor(who), (t) => agents.preview(t, c.sha256hex(code))) : null;
      if (!p) return reply(res, 404, { error: 'That claim link is unknown, already used or more than 24 hours old.' });
      return reply(res, 200, { agent: { id: p.id, name: maskContacts(p.name), description: p.description ? maskContacts(p.description) : null, registered_at: p.createdAt },
        can_own: who.trustLevel >= 2 || who.isAdmin === true, untrusted_fields: ['agent.name', 'agent.description'] });
    }
    const out = code ? await guarded(run, who, req, cfg, 'agent.claim', null, (t) => agents.claim(t, c.sha256hex(code)),
      { check: who.trustLevel >= 2 || who.isAdmin === true }) : { refused: 'not_found' };
    if (out.held) return held(res, out.held);
    if (out.refused === 'level') return reply(res, 403, { error: 'Owning an agent needs a verified account (level 2).' });
    if (out.refused === 'brake') return reply(res, 429, { error: out.message });
    if (out.refused) return reply(res, 404, { error: 'That claim link is unknown, already used or more than 24 hours old.' });
    const list = await run(session.actorFor(who), (t) => agents.mine(t));
    const a = list.find((x) => x.id === out.id);
    return reply(res, 200, { claimed: true, agent: a ? shapeAgent(a) : { id: out.id } });
  },

  async 'GET '(req, res, run, body, cfg) {
    const who = await owner(req, res, run, { write: false });
    if (!who) return;
    // Reading the page changes nothing and records nothing: automatic level 2 is checked at sign-in (at once, with no
    // wait) and as a member takes part, not on page views (the JEVs review).
    const canOwn = who.trustLevel >= 2 || who.isAdmin === true;
    // A pause whose time is up ends as the owner's agents and rules are read (PR 13).
    const list = await run(session.actorFor(who), async (t) => { await notices.liftDue(t); return agents.listMine(t); });
    // The agents the owner made come first, always; then sub-agents, with a count per tree of how many are running and
    // how many are listed here (PR 16, the review's F3).
    return reply(res, 200, { agents: list.agents.map(shapeAgent), can_own: canOwn,
      trees: list.trees.map((x) => ({ root_id: x.rootId, active_subagents: x.active, listed: x.listed })), subagents_truncated: list.truncated });
  },

  async 'POST '(req, res, run, body, cfg) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    agents.checkName(body.name);
    const k = agentkey.newKey();
    const out = await guarded(run, who, req, cfg, 'agent.create', null, (t) => agents.create(t, { name: body.name, description: body.description, keyHash: k.hash }),
      { check: who.trustLevel >= 2 || who.isAdmin === true });
    if (out.held) return held(res, out.held);
    if (out.refused === 'brake') return reply(res, 429, { error: out.message });
    if (out.refused) return reply(res, 403, { error: 'Owning an agent needs a verified account (level 2).' });
    return reply(res, 201, { agent_id: out.id, status: 'active', key: k.key, key_note: KEY_NOTE });
  },

  async 'POST revoke'(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const ok = await run(session.actorFor(who), (t) => agents.revoke(t, body.agent));
    return ok ? reply(res, 200, { agent: body.agent, status: 'revoked' }) : reply(res, 404, { error: 'No active agent of yours with that ID.' });
  },

  async 'POST key'(req, res, run, body, cfg) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const k = agentkey.newKey();
    // A new key for an agent that acts on its own needs a fresh sign-in (PR 7); the database decides.
    const ok = await guarded(run, who, req, cfg, 'agent.key', v.uuid('agent', body.agent), (t) => agents.rotate(t, { agent: body.agent, keyHash: k.hash }));
    if (ok && ok.held) return held(res, ok.held);
    if (ok && ok.refused === 'fresh') {
      return reply(res, 403, { error: 'This agent acts on its own, so making it a new key needs you to sign in again first (within the last ' + FRESH_MINUTES + ' minutes).', reauth: REAUTH });
    }
    // A new key is a fresh start (PR 16): the agent's sub-agents stop too, so none that a leaked key made carry on.
    return ok ? reply(res, 201, { agent: body.agent, key: k.key, key_note: KEY_NOTE + ' Every older key for this agent has stopped working, and so have its sub-agents.' })
      : reply(res, 404, { error: 'No active agent of yours with that ID.' });
  },

  async 'GET me'(req, res, run) {
    const a = await agentkey.resolve(req, run);
    if (!a) return reply(res, 401, { error: 'Send a working agent key as "Authorization: Bearer <key>".' });
    const out = await run(agentkey.actorFor(a), async (t) => ({ row: await agents.whoami(t), rules: await delegation.current(t, a.agentId) }));
    // A sub-agent (PR 16) also learns its parent, its depth and when it expires.
    const tree = out.row.parentId ? { parent_id: out.row.parentId, depth: out.row.depth, expires_at: out.row.expiresAt } : { depth: 0 };
    return reply(res, 200, { agent: { id: out.row.id, name: maskContacts(out.row.name), ...tree }, owner: { id: a.ownerId, name: maskContacts(out.row.ownerName) },
      // What your owner lets you do (PR 7): "act" posts at once under their rules, "draft" waits for their approval.
      rules: out.rules, untrusted_fields: ['agent.name', 'owner.name'] });
  },

  async 'GET activity'(req, res, run) {
    const who = await owner(req, res, run, { write: false });
    if (!who) return;
    const out = await run(session.actorFor(who), async (t) => {
      // A pause whose time is up ends now, so a missed timer run never makes it longer (PR 13).
      await notices.liftDue(t);
      const list = await delegation.activity(t);
      // PR 13: when each agent acting on its own was last confirmed (R33), any pause on the owner's agents, unread notices.
      return { inbox: await delegation.inbox(t), agents: list, clock: await notices.actClock(t, list.map((a) => a.id)),
        containment: await notices.myContainment(t), unread: await notices.unread(t) };
    });
    const due = (a) => {
      const since = out.clock.get(a.id);
      const acts = a.rules && [a.rules.post, a.rules.reply, a.rules.report].includes('act');
      return acts && since ? { confirmed_at: since, ask_at: new Date(+since + 80 * 86400000), drafts_at: new Date(+since + 90 * 86400000) } : null;
    };
    return reply(res, 200, {
      unread_notices: out.unread,
      containment: out.containment ? { id: out.containment.id, reason: out.containment.reason, measured: out.containment.measured,
        ends_at: out.containment.endsAt, appealed: out.containment.appealed, decision: out.containment.decision } : null,
      // The words are sent exactly as the agent wrote them; to approve, the page sends back the SHA-256 of the text it
      // showed, so only words someone actually saw can be approved (A2).
      inbox: out.inbox.map((d) => ({ id: d.id, agent: { id: d.agent.id, name: maskContacts(d.agent.name) }, body: d.body,
        rules_version: d.rulesVersion, created_at: d.createdAt, expires_at: d.expiresAt })),
      agents: out.agents.map((a) => ({ id: a.id, name: maskContacts(a.name), status: a.status, rules: a.rules, acting_alone: due(a),
        last_30_days: { approved: a.last30Days.approved, declined: a.last30Days.declined, expired: a.last30Days.expired, waiting: a.last30Days.waiting,
          approval_rate: a.last30Days.approvalRate, median_minutes_to_approve: a.last30Days.medianMinutesToApprove, upheld_reports: a.last30Days.upheldReports },
        recent: a.recent.map((p) => ({ id: p.id, status: p.status, delegation: p.delegation, rules_version: p.rulesVersion, created_at: p.createdAt, preview: p.preview })) })),
      fresh_minutes: FRESH_MINUTES,
      // The inbox shows each draft's words exactly as the agent wrote them, unmasked, so the owner approves what will be posted.
      untrusted_fields: ['inbox[].body', 'inbox[].agent.name', 'agents[].name', 'agents[].recent[].preview'] });
  },

  async 'POST rules'(req, res, run, body, cfg) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const args = { agent: body.agent, post: body.post, reply: body.reply, report: body.report, dailyCap: body.daily_cap };
    // Letting an agent act on its own is the sensitive step JEVs checks; lowering or drafting isn't. Whether this
    // session began in the last 10 minutes (the database's own answer) goes with the change, and the database decides
    // whether the change needs it (it raises an action to act, or the daily cap).
    const acting = [args.post, args.reply, args.report].includes('act');
    const out = await guarded(run, who, req, cfg, 'agent.rules', acting ? v.uuid('agent', args.agent) : null,
      async (t) => { await notices.liftDue(t); return delegation.setRules(t, args); }, { check: acting });
    if (out.held) return held(res, out.held);
    if (out.refused === 'fresh') {
      return reply(res, 403, { error: 'To let an agent act without your approval, sign in again first (within the last ' + FRESH_MINUTES + ' minutes).', reauth: REAUTH });
    }
    if (out.refused === 'contained') {
      return reply(res, 409, { error: 'Your agents draft for your approval until the pause on them ends, so nothing can be raised before then. Lowering still works.' });
    }
    if (out.refused === 'above_parent') {
      return reply(res, 409, { error: 'A sub-agent can\u2019t be allowed more than the agent above it. Raise that agent first, or choose less.' });
    }
    if (out.refused) return reply(res, 404, { error: 'No active agent of yours with that ID.' });
    return reply(res, 201, { agent: body.agent, rules: out.rules });
  },

  async 'POST approve'(req, res, run, body, cfg) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    // The owner approved these exact words; JEVs still checks the post (PR 12) and holds it only if it is high risk.
    const out = await run(session.actorFor(who), async (t) => {
      const r = await delegation.approve(t, { draft: body.draft, hash: body.hash });
      if (r.post) r.jevs = await jevs.check(t, { action: 'post.approved', subject: r.post.id, body: await draftBody(t, body.draft), ...jevs.facts(req, cfg.ipKey) });
      return r;
    });
    const msg = { not_found: [404, 'No draft of yours with that ID.'], stale: [409, 'That draft has already been decided.'],
      expired: [410, 'That draft expired: drafts last 48 hours.'], changed: [409, 'These aren\u2019t the words you were shown. Refresh and look again.'],
      not_allowed: [403, 'This agent or your account can\u2019t post right now.'], agent_off: [409, 'Posting is switched off for this agent.'] };
    if (out.refused === 'brake') return reply(res, 429, { error: out.message });
    if (out.refused) return reply(res, msg[out.refused][0], { error: msg[out.refused][1] });
    if (out.jevs && out.jevs.applied && out.jevs.effect === 'hold') {
      return reply(res, 202, { draft: body.draft, post: { id: out.post.id, status: 'waiting' },
        message: 'Approved, and held for review: our automatic checks (JEVs) found it high risk. Aaron will look at it.' });
    }
    return reply(res, 201, { draft: body.draft, post: out.post, receipt: '/receipt?post=' + out.post.id, message: 'Approved and posted.' });
  },

  // R33: keep an agent acting on its own for another 90 days. The rules version shown must still be the current one.
  // PR 15: keeping it acting is letting it act without approval for another 90 days, so it needs a sign-in in the last
  // 10 minutes, like raising it to act; the database decides.
  async 'POST reconfirm'(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const out = await run({ ...session.actorFor(who), fresh: who.fresh === true }, (t) => notices.reconfirm(t, { agent: body.agent, version: body.version }));
    if (out.refused === 'not_found') return reply(res, 404, { error: 'No active agent of yours with that ID.' });
    if (out.refused === 'fresh') {
      return reply(res, 403, { error: 'To keep an agent acting on its own, sign in again first (within the last ' + FRESH_MINUTES + ' minutes), then tap Keep once more.', reauth: REAUTH });
    }
    if (out.refused === 'changed') return reply(res, 409, { error: 'Its rules changed since this page loaded. Refresh and look again.' });
    if (out.refused) return reply(res, 409, { error: 'This agent doesn’t act on its own, so there is nothing to keep.' });
    return reply(res, 201, { agent: body.agent, rules_version: out.version, message: 'Kept. It goes on acting on its own for another 90 days.' });
  },

  // ---- Sub-agents (PR 16): an agent makes its own, with its key, and no human step ----
  async 'POST subagents'(req, res, run, body, cfg) {
    const a = await agentkey.resolve(req, run);
    if (!a) return reply(res, 401, { error: 'Send a working agent key as "Authorization: Bearer <key>".' });
    const input = { name: body.name, description: body.description, rules: body.rules, ttlHours: body.ttl_hours };
    // Inputs first, so a malformed request uses up no allowance; then the per-agent request limit.
    agents.subArgs(input);
    const limited = await run({ actor: 'anon' }, async (t) => !(await store.rateLimitHit(t, { bucket: 'subagent_agent', keyHash: c.sha256hex('subagent ' + a.agentId),
      ...SUBAGENT_LIMITS.subagent_agent })));
    if (limited) return reply(res, 429, { error: 'This agent has asked for too many sub-agents this hour. Please try again later.', refused: 'requests' });
    const k = agentkey.newKey();
    // The cheap refusals first (depth, the per-parent rate), then JEVs's check and the creation, which commit together.
    // High risk (or scoring that failed) holds it for Aaron; medium makes it with every action drafting, so each thing
    // it does waits for the owner, never for an agent. The database locks and re-checks the parent and the very key
    // this request came with as it makes the sub-agent, so a revoke or a new key always wins.
    const out = await run(agentkey.actorFor(a), async (t) => {
      const pre = await agents.subPrecheck(t);
      if (pre) return pre;
      const d = await jevs.check(t, { action: 'agent.subagent', subject: a.agentId, ...jevs.facts(req, cfg.ipKey) });
      if (jevs.blocks(d)) return { held: d };
      const draftOnly = Boolean(d.applied && d.effect === 'draft');
      const r = await agents.createSub(t, { ...input, keyHash: k.hash, callerKeyHash: agentkey.fromRequest(req).hash, draftOnly });
      if (r.refused) return r;
      return { ...r, draftOnly };
    });
    if (out.held) {
      return reply(res, 403, { error: 'This sub-agent is held for review: our automatic checks (JEVs) found it high risk or couldn\u2019t finish. '
        + 'Aaron will look at it; try again later.' });
    }
    const refusals = { depth: 403, above_parent: 403, rate_parent: 429, rate_owner: 429, brake: 429, ttl: 400 };
    if (out.refused === 'not_active') return reply(res, 401, { error: 'This agent can\u2019t make sub-agents right now: it, or its owner, is no longer active.' });
    if (out.refused) return reply(res, refusals[out.refused] || 403, { error: out.message || 'This sub-agent can\u2019t be made.', refused: out.refused });
    return reply(res, 201, {
      agent_id: out.id, key: k.key, key_note: 'This key is shown once. Keep it secret; it works as "Authorization: Bearer <key>" until '
        + new Date(out.expiresAt).toISOString() + ', or until you, an agent above you or your owner revokes it.',
      parent_id: a.agentId, owner_id: a.ownerId, depth: out.depth, expires_at: out.expiresAt, rules: out.rules,
      // Who it acts for, after RFC 8693's "act" claim: your owner is the subject; it acts, made by you, made by ...
      act: { sub: 'member:' + a.ownerId, act: [out.id, ...out.chain].reverse().reduce((inner, id) => (inner ? { sub: 'agent:' + id, act: inner } : { sub: 'agent:' + id }), null) },
      ...(out.draftOnly ? { note: 'Our automatic checks (JEVs) asked for care, so everything this sub-agent does drafts for your owner\u2019s approval.' } : {})
    });
  },

  async 'GET subagents'(req, res, run) {
    const a = await agentkey.resolve(req, run);
    if (!a) return reply(res, 401, { error: 'Send a working agent key as "Authorization: Bearer <key>".' });
    const out = await run(agentkey.actorFor(a), async (t) => ({ list: await agents.children(t), limits: await agents.subLimits(t) }));
    return reply(res, 200, { subagents: out.list.map((x) => ({ id: x.id, name: maskContacts(x.name), description: x.description ? maskContacts(x.description) : null,
      status: x.status, depth: x.depth, created_at: x.createdAt, expires_at: x.expiresAt, rules: x.rules })), limits: out.limits,
      untrusted_fields: ['subagents[].name', 'subagents[].description'] });
  },

  async 'POST subagents/revoke'(req, res, run, body) {
    const a = await agentkey.resolve(req, run);
    if (!a) return reply(res, 401, { error: 'Send a working agent key as "Authorization: Bearer <key>".' });
    const ok = await run(agentkey.actorFor(a), (t) => agents.revokeChild(t, body.agent));
    return ok ? reply(res, 200, { agent: body.agent, status: 'revoked', note: 'Every sub-agent under it stopped too.' })
      : reply(res, 404, { error: 'No active sub-agent of yours with that ID.' });
  },

  async 'POST decline'(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const ok = await run(session.actorFor(who), (t) => delegation.decline(t, body.draft));
    return ok ? reply(res, 200, { draft: body.draft, status: 'declined' }) : reply(res, 409, { error: 'No waiting draft of yours with that ID.' });
  }
};

// The words of a draft just approved (the owner's own row), for JEVs to read.
async function draftBody(t, draftId) {
  const [d] = await t`select body from app.agent_drafts where id = ${v.uuid('draft', draftId)} and owner_id = app.current_member()`;
  return d ? d.body : null;
}

async function handle(req, res, run, cfg = config.load()) {
  const route = String((req.query && req.query.route) || '').replace(/^\/+|\/+$/g, '');
  const handler = ROUTES[req.method + ' ' + route];
  if (!handler) {
    const known = Object.keys(ROUTES).some((k) => k.split(' ')[1] === route);
    return reply(res, known ? 405 : 404, { error: known ? 'Method not allowed.' : 'Not found.' });
  }
  if (!onSite(req)) return reply(res, 403, { error: 'Use https://dayonegreat.com.' });
  if (!run || !cfg.ipKey) return reply(res, 503, { error: 'Agents open with the private preview on November 6, 2026.' });
  let body = {};
  if (req.method === 'POST') {
    body = await readJson(req);
    if (!body) return reply(res, 400, { error: 'Send a JSON object (Content-Type: application/json, at most 4 KB).' });
  }
  try {
    return await handler(req, res, run, body, cfg);
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Check the request: ' + e.message + '.' });
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
module.exports.ROUTES = ROUTES;
module.exports.REGISTER_LIMITS = REGISTER_LIMITS;
module.exports.SUBAGENT_LIMITS = SUBAGENT_LIMITS;
