// The go-live gate (LAUNCH_STAGE), so setting up the database can never open Release 2 by itself.
//
//   closed  (the default, and any unknown value): every Release 2 route stays off, exactly as before the database
//           existed. db.configured() reports false.
//   public : open to everyone. Setting it is Aaron's go-live decision (CHARTER.md: nothing goes live without it).
//
// "preview" is not a stage (Aaron, Oct 24: "NO preview systems"): LAUNCH_STAGE=preview counts as closed, so setting it
// can only close the site, never open it. The preview-only paths it once switched on (an allow-list for new accounts,
// LAUNCH_PREVIEW_ALLOW, and signed-in-only reading) were removed in the dormant-paths clean-up
// (harness/REVIEW-2026-10-26.md, R-14).
//
// The close switch (the CSO's control 7, R-10): two settings, the stricter winning, so either one alone can close the
// site and neither alone can open it.
//   * launch-cap.json, in the repository: { "max_stage": "public" } has no effect (the default); "closed" closes the
//     site at the next deploy, so a pull request Aaron merges can close it with nothing done by hand. A missing file
//     has no effect; a value that isn't a stage counts as closed.
//   * LAUNCH_STAGE, the Vercel setting: the emergency setting, as before.
// The database side of the switch is db/emergency/close-site-login.sql (OPERATIONS.md, "Runbook: close the site now").
'use strict';

const STAGES = ['closed', 'public'];

let CAP = null;
try { CAP = require('./launch-cap.json'); } catch { CAP = null; }

// The highest stage the repository allows.
function cap(c = CAP) {
  if (c == null) return 'public';
  const s = String(c.max_stage == null ? '' : c.max_stage).trim().toLowerCase();
  return STAGES.includes(s) ? s : 'closed';
}

function stage(env = process.env, c = CAP) {
  const s = String(env.LAUNCH_STAGE || '').trim().toLowerCase();
  const want = STAGES.includes(s) ? s : 'closed';
  const max = cap(c);
  return STAGES.indexOf(want) <= STAGES.indexOf(max) ? want : max;
}

module.exports = { stage, cap, STAGES };
