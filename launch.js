// The go-live gate (LAUNCH_STAGE), so setting up the database can never open Release 2 by itself.
//
//   closed  (the default, and any unknown value): every Release 2 route stays off, exactly as before the database
//           existed. db.configured() reports false.
//   preview: Release 2 runs, but only for people Aaron allow-lists. New accounts are made only for an allow-listed
//           GitHub or X account ID or email address; existing members sign in as usual. Reading posts, receipts and
//           profiles needs a signed-in member, and nothing is cached publicly. Agents can't register themselves.
//   public : open to everyone. Setting it is Aaron's go-live decision (CHARTER.md: nothing goes live without it).
//
// LAUNCH_PREVIEW_ALLOW lists who may make an account during the preview, separated by commas or spaces:
//   github:<numeric account id>, x:<numeric account id>, email:<address>
// Account IDs, not user names, because a user name can be changed and then taken by someone else.
'use strict';

const STAGES = ['closed', 'preview', 'public'];
const PREVIEW_MESSAGE = 'Day One Great is in a private preview. It opens to everyone on November 20, 2026.';

function stage(env = process.env) {
  const s = String(env.LAUNCH_STAGE || '').trim().toLowerCase();
  return STAGES.includes(s) ? s : 'closed';
}

function allowList(env = process.env) {
  const out = new Set();
  for (const raw of String(env.LAUNCH_PREVIEW_ALLOW || '').split(/[\s,]+/)) {
    const m = raw.trim().match(/^(github|x|email):(.+)$/i);
    if (!m) continue;
    const provider = m[1].toLowerCase();
    const id = provider === 'email' ? m[2].trim().toLowerCase() : m[2].trim();
    if (provider !== 'email' && !/^\d{1,30}$/.test(id)) continue;
    if (provider === 'email' && !/^[^@\s]+@[^@\s]+$/.test(id)) continue;
    out.add(provider + ':' + id);
  }
  return out;
}

// May this person make a new account now? In preview, only if allow-listed. Outside the preview this says yes: while
// closed, db.configured() already keeps sign-in off entirely, so there is nothing to sign up to.
function mayJoin(provider, id, env = process.env) {
  if (stage(env) !== 'preview') return true;
  if (!id) return false;
  const key = provider + ':' + (provider === 'email' ? String(id).trim().toLowerCase() : String(id));
  return allowList(env).has(key);
}

module.exports = { stage, allowList, mayJoin, STAGES, PREVIEW_MESSAGE };
