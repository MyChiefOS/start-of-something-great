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

// { memberId, trustLevel, isAdmin, displayName } or null.
async function current(req, run) {
  const hash = sessionHash(req);
  return hash ? run({ actor: 'anon' }, (t) => store.sessionResolve(t, hash, IDLE_DAYS)) : null;
}

// The database actor for a signed-in member.
const actorFor = (who) => ({ actor: who.isAdmin ? 'admin' : 'member', memberId: who.memberId });

// Who may use the review queue (PR 4). Today only Aaron. Adding reviewers means changing this, actorFor and
// app.is_reviewer() in the database together (004_review.sql explains the pipeline).
const canReview = (who) => Boolean(who && who.isAdmin === true);

module.exports = { SESSION, isToken, sessionHash, current, actorFor, canReview };
