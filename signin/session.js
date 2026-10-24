// Who is signed in, from the session cookie (S5: the cookie holds a random token; only its SHA-256 is looked up).
'use strict';

const c = require('./crypto');
const h = require('./http');
const { IDLE_DAYS } = require('./config');
const store = require('../db/signin');

const SESSION = '__Host-dog_session';
// Every token we hand out is 32 random bytes in base64url: exactly 43 of these characters.
const isToken = (s) => typeof s === 'string' && s.length === 43 && Buffer.from(s, 'base64url').toString('base64url') === s;

function sessionHash(req) {
  const tok = h.cookies(req)[SESSION];
  return isToken(tok) ? c.sha256hex(tok) : null;
}

// { memberId, trustLevel, isAdmin, displayName, fresh, sessionHash } or null.
async function current(req, run) {
  const hash = sessionHash(req);
  const who = hash ? await run({ actor: 'anon' }, (t) => store.sessionResolve(t, hash, IDLE_DAYS)) : null;
  return who ? { ...who, sessionHash: hash } : null;
}

// The database actor for a signed-in member, with the session the request came from (PR 15's second review, R1: what
// a session makes records the sign-in method it signed in with, so unlinking that method can undo it).
const actorFor = (who) => ({ actor: who.isAdmin ? 'admin' : 'member', memberId: who.memberId, session: who.sessionHash || null });
// The same, carrying the session's fresh sign-in (the database's own answer), for the steps whose rules ask for it.
// The database decides; this only passes on what it said.
const strongActorFor = (who) => ({ ...actorFor(who), fresh: who.fresh === true });

// Who may use the review queue (PR 4). Today only Aaron. Adding reviewers means changing this, actorFor and
// app.is_reviewer() in the database together (004_review.sql explains the pipeline).
const canReview = (who) => Boolean(who && who.isAdmin === true);
// Who may use the owner controls: the numbers, the emergency brake and banning (PR 6). Only Aaron, and unlike
// reviewing it stays that way: the database allows these to the admin actor alone.
const canControl = (who) => Boolean(who && who.isAdmin === true);

module.exports = { SESSION, isToken, sessionHash, current, actorFor, strongActorFor, canReview, canControl };
