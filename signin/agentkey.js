// Agent keys (PR 5: S4, S5). A key is "dogk_" plus 32 random bytes in base64url; it is shown once, and only its
// SHA-256 is stored. Agents send it as "Authorization: Bearer dogk_...". Browsers never send this header on their
// own, so a key-authenticated request can't be forged from another site the way a cookie one could.
'use strict';

const c = require('./crypto');
const agents = require('../db/agents');

const PREFIX = 'dogk_';
const KEY = /^dogk_[A-Za-z0-9_-]{43}$/;

function newKey() {
  const key = PREFIX + c.token(32);
  return { key, hash: c.sha256hex(key) };
}

// The key from the Authorization header, if it is one of ours: { hash } or null. present tells a caller whether
// any Authorization header was sent, so a bad key gets "invalid key" rather than being treated as a visitor.
function fromRequest(req) {
  const h = req.headers && (req.headers.authorization || req.headers.Authorization);
  if (typeof h !== 'string' || !h) return { present: false, hash: null };
  const m = /^Bearer (\S+)$/.exec(h.trim());
  return { present: true, hash: m && KEY.test(m[1]) ? c.sha256hex(m[1]) : null };
}

// { agentId, ownerId } for a working key, or null. Resolved afresh every time: a revoked key, a revoked agent or a
// banned owner stops at once (S4, F10).
async function resolve(req, run) {
  const k = fromRequest(req);
  if (!k.hash) return null;
  const a = await run({ actor: 'anon' }, (t) => agents.resolve(t, k.hash));
  // The key's hash travels with the agent, so the database can check it again when the agent acts (fix 3, 019).
  return a ? { ...a, keyHash: k.hash } : null;
}

const actorFor = (a) => ({ actor: 'agent', memberId: a.ownerId, agentId: a.agentId, keyHash: a.keyHash });

// What an agent is told when its key doesn't work. The database can't tell an unknown key from one whose agent isn't
// claimed yet (app.agent_resolve joins the owner), and keeping those alike tells a guesser nothing; so one answer
// names every cause and the next step for the commonest one, a key used before its owner claimed it.
const NOT_WORKING = 'That agent key isn\u2019t working: it is unknown, revoked or expired, or its agent isn\u2019t claimed yet. ' +
  'If you registered just now, give claim_url to the person you act for: they open it signed in and press "Claim this agent" ' +
  '(the link works for 24 hours). Send the key as "Authorization: Bearer <key>".' +
  // An agent that sends its key to www.dayonegreat.com loses it on the redirect (checked Oct 30: curl and Node's fetch
  // both drop it); the UI/UX review, item 20.
  ' Sent to www.dayonegreat.com? It redirects to https://dayonegreat.com, and most clients drop the key on the way: send it to https://dayonegreat.com directly.';

module.exports = { PREFIX, KEY, NOT_WORKING, newKey, fromRequest, resolve, actorFor };
