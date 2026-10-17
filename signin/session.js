// Who is signed in, from the session cookie (S5: the cookie holds a random token; only its SHA-256 is looked up).
'use strict';

const c = require('./crypto');
const h = require('./http');
const { IDLE_DAYS } = require('./config');
const store = require('../db/signin');
const passkeys = require('../db/passkeys');

const SESSION = '__Host-dog_session';
// Every token we hand out is 32 random bytes in base64url: exactly 43 of these characters.
const isToken = (s) => typeof s === 'string' && s.length === 43 && Buffer.from(s, 'base64url').toString('base64url') === s;

function sessionHash(req) {
  const tok = h.cookies(req)[SESSION];
  return isToken(tok) ? c.sha256hex(tok) : null;
}

// { memberId, trustLevel, isAdmin, displayName, fresh, stepUp, passkeys, recoveryUntil } or null.
// PR 17: stepUp is the database's own answer (by its clock) to whether this session passed a passkey check in the last
// 5 minutes, with no recovery open; passkeys is how many the member has. Both come in the same transaction as the
// session itself.
async function current(req, run) {
  const hash = sessionHash(req);
  if (!hash) return null;
  return run({ actor: 'anon' }, async (t) => {
    const who = await store.sessionResolve(t, hash, IDLE_DAYS);
    if (!who) return null;
    const s = await passkeys.sessionStepUp(t, hash);
    return { ...who, stepUp: Boolean(s && s.stepUp), passkeys: s ? s.passkeys : 0, recoveryUntil: s ? s.recoveryUntil : null,
      linkingFrom: s ? s.linkingFrom : null };
  });
}

// The database actor for a signed-in member.
const actorFor = (who) => ({ actor: who.isAdmin ? 'admin' : 'member', memberId: who.memberId });
// The same, carrying the session's fresh sign-in and passkey step-up (both the database's own answers), for the steps
// whose rules ask for them. The database decides; this only passes on what it said.
const strongActorFor = (who) => ({ ...actorFor(who), fresh: who.fresh === true, stepUp: who.stepUp === true });

// PR 17: what a page is told when a risky grant needs a passkey check first. A member with no passkey is sent to add
// one (which itself needs a fresh sign-in); one in recovery is told it is blocked until the cool-off ends. Never a
// weaker fallback.
function stepUpNeeded(who) {
  const recovery = who && who.recoveryUntil ? new Date(who.recoveryUntil).toISOString() : null;
  const has = Boolean(who && who.passkeys > 0);
  return {
    error: recovery ? 'Passkey recovery is under way on your account, so risky steps are blocked until ' + recovery + '. You can cancel it on your account page.'
      : has ? 'Confirm it’s you with your passkey, then try again.'
        : 'This needs a passkey. Add one on your account page (it takes one tap), then try again.',
    step_up: { has_passkey: has, recovery_until: recovery, options: '/auth/passkey/assert/options', finish: '/auth/passkey/assert/finish', enrol: '/account#passkeys' }
  };
}

// Who may use the review queue (PR 4). Today only Aaron. Adding reviewers means changing this, actorFor and
// app.is_reviewer() in the database together (004_review.sql explains the pipeline).
const canReview = (who) => Boolean(who && who.isAdmin === true);
// Who may use the owner controls: the numbers, the emergency brake and banning (PR 6). Only Aaron, and unlike
// reviewing it stays that way: the database allows these to the admin actor alone.
const canControl = (who) => Boolean(who && who.isAdmin === true);

module.exports = { SESSION, isToken, sessionHash, current, actorFor, strongActorFor, stepUpNeeded, canReview, canControl };
