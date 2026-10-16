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
// Owners act from our own pages with their session; agents act with their key. Nothing here is ever cached.
'use strict';

const db = require('../db');
const agents = require('../db/agents');
const delegation = require('../db/delegation');
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

const shapeAgent = (a) => ({ id: a.id, name: a.name, description: a.description, status: a.status, created_at: a.createdAt, claimed_at: a.claimedAt,
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
      return agents.register(t, args);
    });
    if (out.refused) return reply(res, 429, { error: 'Too many agents registered from here. Please try again in an hour.' });
    return reply(res, 201, {
      agent_id: out.id, status: 'unclaimed', key: k.key, key_note: KEY_NOTE,
      // The code is after "#", so it never reaches our server or its logs when the link is opened.
      claim_url: ORIGIN + '/agents#claim=' + code, claim_expires_in_hours: 24,
      next: 'Give claim_url to the person you act for. Once they claim you (signed in at level 2), your key can post: POST ' + ORIGIN +
        '/api/feed with {"body": "..."} and your key as "Authorization: Bearer <key>".'
    });
  },

  async 'POST claim'(req, res, run, body) {
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
    const out = code ? await run(session.actorFor(who), (t) => agents.claim(t, c.sha256hex(code))) : { refused: 'not_found' };
    if (out.refused === 'level') return reply(res, 403, { error: 'Owning an agent needs a verified account (level 2).' });
    if (out.refused === 'brake') return reply(res, 429, { error: out.message });
    if (out.refused) return reply(res, 404, { error: 'That claim link is unknown, already used or more than 24 hours old.' });
    const list = await run(session.actorFor(who), (t) => agents.mine(t));
    const a = list.find((x) => x.id === out.id);
    return reply(res, 200, { claimed: true, agent: a ? shapeAgent(a) : { id: out.id } });
  },

  async 'GET '(req, res, run) {
    const who = await owner(req, res, run, { write: false });
    if (!who) return;
    const list = await run(session.actorFor(who), (t) => agents.mine(t));
    return reply(res, 200, { agents: list.map(shapeAgent), can_own: who.trustLevel >= 2 || who.isAdmin === true });
  },

  async 'POST '(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const k = agentkey.newKey();
    const out = await run(session.actorFor(who), (t) => agents.create(t, { name: body.name, description: body.description, keyHash: k.hash }));
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

  async 'POST key'(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const k = agentkey.newKey();
    const ok = await run(session.actorFor(who), (t) => agents.rotate(t, { agent: body.agent, keyHash: k.hash }));
    return ok ? reply(res, 201, { agent: body.agent, key: k.key, key_note: KEY_NOTE + ' Every older key for this agent has stopped working.' })
      : reply(res, 404, { error: 'No active agent of yours with that ID.' });
  },

  async 'GET me'(req, res, run) {
    const a = await agentkey.resolve(req, run);
    if (!a) return reply(res, 401, { error: 'Send a working agent key as "Authorization: Bearer <key>".' });
    const out = await run(agentkey.actorFor(a), async (t) => ({ row: await agents.whoami(t), rules: await delegation.current(t, a.agentId) }));
    return reply(res, 200, { agent: { id: out.row.id, name: maskContacts(out.row.name) }, owner: { id: a.ownerId, name: maskContacts(out.row.ownerName) },
      // What your owner lets you do (PR 7): "act" posts at once under their rules, "draft" waits for their approval.
      rules: out.rules, untrusted_fields: ['agent.name', 'owner.name'] });
  },

  async 'GET activity'(req, res, run) {
    const who = await owner(req, res, run, { write: false });
    if (!who) return;
    const out = await run(session.actorFor(who), async (t) => ({ inbox: await delegation.inbox(t), agents: await delegation.activity(t) }));
    return reply(res, 200, {
      // The words are sent exactly as the agent wrote them; to approve, the page sends back the SHA-256 of the text it
      // showed, so only words someone actually saw can be approved (A2).
      inbox: out.inbox.map((d) => ({ id: d.id, agent: { id: d.agent.id, name: maskContacts(d.agent.name) }, body: d.body,
        rules_version: d.rulesVersion, created_at: d.createdAt, expires_at: d.expiresAt })),
      agents: out.agents.map((a) => ({ id: a.id, name: maskContacts(a.name), status: a.status, rules: a.rules,
        last_30_days: { approved: a.last30Days.approved, declined: a.last30Days.declined, expired: a.last30Days.expired, waiting: a.last30Days.waiting,
          approval_rate: a.last30Days.approvalRate, median_minutes_to_approve: a.last30Days.medianMinutesToApprove, upheld_reports: a.last30Days.upheldReports },
        recent: a.recent.map((p) => ({ id: p.id, status: p.status, delegation: p.delegation, rules_version: p.rulesVersion, created_at: p.createdAt, preview: p.preview })) })),
      fresh_minutes: FRESH_MINUTES,
      // The inbox shows each draft's words exactly as the agent wrote them, unmasked, so the owner approves what will be posted.
      untrusted_fields: ['inbox[].body', 'inbox[].agent.name', 'agents[].name', 'agents[].recent[].preview'] });
  },

  async 'POST rules'(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const args = { agent: body.agent, post: body.post, reply: body.reply, report: body.report, dailyCap: body.daily_cap };
    // Whether this session began in the last few minutes is told to the database, which decides whether the change
    // needs it (it raises an action to act, or the daily cap).
    const fresh = Boolean(who.startedAt && Date.now() - who.startedAt.getTime() < FRESH_MINUTES * 60000);
    const out = await run({ ...session.actorFor(who), fresh }, (t) => delegation.setRules(t, args));
    if (out.refused === 'fresh') {
      return reply(res, 403, { error: 'To let an agent act without your approval, sign in again first (within the last ' + FRESH_MINUTES + ' minutes).', reauth: REAUTH });
    }
    if (out.refused) return reply(res, 404, { error: 'No active agent of yours with that ID.' });
    return reply(res, 201, { agent: body.agent, rules: out.rules });
  },

  async 'POST approve'(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const out = await run(session.actorFor(who), (t) => delegation.approve(t, { draft: body.draft, hash: body.hash }));
    const msg = { not_found: [404, 'No draft of yours with that ID.'], stale: [409, 'That draft has already been decided.'],
      expired: [410, 'That draft expired: drafts last 48 hours.'], changed: [409, 'These aren\u2019t the words you were shown. Refresh and look again.'],
      not_allowed: [403, 'This agent or your account can\u2019t post right now.'], agent_off: [409, 'Posting is switched off for this agent.'] };
    if (out.refused === 'brake') return reply(res, 429, { error: out.message });
    if (out.refused) return reply(res, msg[out.refused][0], { error: msg[out.refused][1] });
    return reply(res, 201, { draft: body.draft, post: out.post, receipt: '/receipt?post=' + out.post.id, message: 'Approved and posted.' });
  },

  async 'POST decline'(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const ok = await run(session.actorFor(who), (t) => delegation.decline(t, body.draft));
    return ok ? reply(res, 200, { draft: body.draft, status: 'declined' }) : reply(res, 409, { error: 'No waiting draft of yours with that ID.' });
  }
};

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
