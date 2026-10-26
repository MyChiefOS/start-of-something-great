// The go-live gate (LAUNCH_STAGE), so setting up the database can never open Release 2 by itself.
//
//   closed  (the default, and any unknown value): every Release 2 route stays off, exactly as before the database
//           existed. db.configured() reports false.
//   preview: no longer a stage (Aaron, Oct 24: "NO preview systems"). LAUNCH_STAGE=preview now counts as closed, so
//           setting it can only close the site, never open it. The preview-only code paths it used to switch on
//           (an allow-list for new accounts, signed-in-only reading) are unreachable and go in the dormant-paths
//           clean-up (harness/REVIEW-2026-10-26.md, R-14).
//   public : open to everyone. Setting it is Aaron's go-live decision (CHARTER.md: nothing goes live without it).
//
// LAUNCH_PREVIEW_ALLOW (no longer read by any reachable path; removed in R-14) listed who could make an account during
// the preview: github:<numeric account id>, x:<numeric account id>, email:<address>.
'use strict';

const STAGES = ['closed', 'public'];
// Shown only by the unreachable preview paths; kept true in case one is ever reached.
const PREVIEW_MESSAGE = 'This part of Day One Great isn’t open yet.';

function stage(env = process.env) {
  const s = String(env.LAUNCH_STAGE || '').trim().toLowerCase();
  return STAGES.includes(s) ? s : 'closed';
}

function allowList(env = process.env) {
  const out = new Set();
  for (const raw of String(env.LAUNCH_PREVIEW_ALLOW || '').replace(/:\s+/g, ':').split(/[\s,;]+/)) {
    const m = raw.trim().match(/^(github|x|email):(.+)$/i);
    if (!m) continue;
    const provider = m[1].toLowerCase();
    // Account IDs are compared as the providers send them: digits, no leading zeros.
    const id = provider === 'email' ? m[2].trim().toLowerCase() : m[2].trim().replace(/^0+(?=\d)/, '');
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
