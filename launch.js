// The go-live gate (launch.json, and LAUNCH_STAGE to close), so setting up the database can never open Release 2 by itself.
//
//   closed  (the default, and any unknown value): every Release 2 route stays off, exactly as before the database
//           existed. db.configured() reports false.
//   public : open to everyone. Choosing it is Aaron's go-live decision (CHARTER.md: nothing goes live without it).
//
// "preview" is not a stage (Aaron, Oct 24: "NO preview systems"): LAUNCH_STAGE=preview counts as closed, so setting it
// can only close the site, never open it. The preview-only paths it once switched on (an allow-list for new accounts,
// LAUNCH_PREVIEW_ALLOW, and signed-in-only reading) were removed in the dormant-paths clean-up
// (harness/REVIEW-2026-10-26.md, R-14).
//
// The stage is the repository's (harness/PLAN.md: Aaron's merge of the go-live release is the go-live decision): launch.json { "stage": "public" | "closed" }, changed only by a pull request he merges. A missing
// file, or a value that isn't a stage, counts as closed.
// LAUNCH_STAGE, the Vercel setting, can only close it (the close switch, the CSO's control 7, R-10): unset or empty has
// no effect, "public" has no effect, and anything else ("closed", a stale "preview", a typo) closes the site. So either
// one alone can close the site, and only the repository can open it. Opening never needs a hand change in Vercel.
// The database side of the switch is db/emergency/close-site-login.sql (OPERATIONS.md, "Runbook: close the site now").
'use strict';

const STAGES = ['closed', 'public'];

let FILE = null;
try { FILE = require('./launch.json'); } catch { FILE = null; }

// The repository's stage.
function repoStage(f = FILE) {
  if (f == null) return 'closed';
  const s = String(f.stage == null ? '' : f.stage).trim().toLowerCase();
  return STAGES.includes(s) ? s : 'closed';
}

// What the Vercel settings allow: everything when LAUNCH_STAGE is unset, empty or public; closed otherwise. And a
// deployment Vercel marks as anything but production (a preview) is always closed (no preview systems, Aaron, Oct 24;
// the CSO's review of the go-live release, S2), whatever the repository says. Outside Vercel VERCEL_ENV is unset.
function envCap(env = process.env) {
  const vercel = env.VERCEL_ENV == null ? '' : String(env.VERCEL_ENV).trim().toLowerCase();
  if (vercel !== '' && vercel !== 'production') return 'closed';
  const raw = env.LAUNCH_STAGE == null ? '' : String(env.LAUNCH_STAGE).trim().toLowerCase();
  return raw === '' || raw === 'public' ? 'public' : 'closed';
}

function stage(env = process.env, f = FILE) {
  const a = repoStage(f), b = envCap(env);
  return STAGES.indexOf(a) <= STAGES.indexOf(b) ? a : b;
}

module.exports = { stage, repoStage, envCap, STAGES };
