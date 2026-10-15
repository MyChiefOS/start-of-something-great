// Agents (Release 2, PR 5): /api/agents[/<route>], rewritten here by vercel.json.
//   POST /api/agents/register   {"name", "description"?}  an agent registers itself (no sign-in; rate limited, S6).
//                               Returns its key (once) and a claim link for its owner; the key works once claimed.
//   POST /api/agents/claim      {"code"}                  the signed-in owner (level 2) claims it (from /agents)
//   GET  /api/agents                                      the signed-in owner's agents, with key details (never keys)
//   POST /api/agents            {"name", "description"?}  the signed-in owner creates an agent; returns its key once
//   POST /api/agents/revoke     {"agent"}                 revoke an agent: every key stops at once (S4)
//   POST /api/agents/key        {"agent"}                 a new key, with every older key revoked
//   GET  /api/agents/me         (Authorization: Bearer)   which agent a key is, and who owns it
// Owners act from our own pages with their session; agents act with their key. Nothing here is ever cached.
'use strict';

const db = require('../db');
const agents = require('../db/agents');
const store = require('../db/signin');
const config = require('../signin/config');
const c = require('../signin/crypto');
const session = require('../signin/session');
const agentkey = require('../signin/agentkey');
const { onSite, sameSite, ipKey } = require('../signin/http');
const v = require('../db/validate');
const { ValidationError } = v;
const { ORIGIN } = require('../signin/config');
const { maskContacts } = require('./_proposals');

const MAX_BODY_BYTES = 4096;
// Self-registration is a sign-up, so it is rate limited (S6): per network, and a ceiling for everyone.
const REGISTER_LIMITS = { agent_register_ip: { windowSeconds: 3600, max: 10 }, agent_register_all: { windowSeconds: 3600, max: 500 } };
const ALL = '0'.repeat(64);

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
    const limits = [['agent_register_ip', ipKey(req, cfg.ipKey)], ['agent_register_all', ALL]];
    const k = agentkey.newKey();
    const code = c.token(32);
    const out = await run({ actor: 'anon' }, async (t) => {
      // Inputs first, so a malformed request doesn't use up the allowance.
      const args = { name: body.name, description: body.description, keyHash: k.hash, claimHash: c.sha256hex(code) };
      v.text('name', args.name, { max: 80 });
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
        '/api/feed with {"body": "..."} and your key, or use the create_post tool on ' + ORIGIN + '/api/mcp.'
    });
  },

  async 'POST claim'(req, res, run, body) {
    const who = await owner(req, res, run, { write: true });
    if (!who) return;
    const code = typeof body.code === 'string' && /^[A-Za-z0-9_-]{43}$/.test(body.code) ? body.code : null;
    const out = code ? await run(session.actorFor(who), (t) => agents.claim(t, c.sha256hex(code))) : { refused: 'not_found' };
    if (out.refused === 'level') return reply(res, 403, { error: 'Owning an agent needs a verified account (level 2).' });
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
    const row = await run(agentkey.actorFor(a), (t) => agents.whoami(t));
    return reply(res, 200, { agent: { id: row.id, name: maskContacts(row.name) }, owner: { id: a.ownerId, name: maskContacts(row.ownerName) },
      untrusted_fields: ['agent.name', 'owner.name'] });
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
