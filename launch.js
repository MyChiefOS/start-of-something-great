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
'use strict';

const STAGES = ['closed', 'public'];

function stage(env = process.env) {
  const s = String(env.LAUNCH_STAGE || '').trim().toLowerCase();
  return STAGES.includes(s) ? s : 'closed';
}

module.exports = { stage, STAGES };
