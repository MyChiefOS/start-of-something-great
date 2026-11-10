// The go-live gate (launch.json, and LAUNCH_STAGE to close), so setting up the database can never open Release 2 by itself.
//
//   closed  (the default, and any unknown value): every Release 2 route stays off, exactly as before the database
//           existed. db.configured() reports false.
//   public : open to everyone. Choosing it is Aaron's go-live decision (CHARTER.md: nothing goes live without it).
//
// "preview" is not a stage (Aaron, Oct 24: "NO preview systems"): LAUNCH_STAGE=preview counts as closed, so setting it
// can only close the site, never open it. The preview-only paths it once switched on (an allow-list for new accounts,
// LAUNCH_PREVIEW_ALLOW, and signed-in-only reading) were removed in the dormant-paths clean-up
// (harness/REVIEW-2026-10-26.md, R-14). That stage of the live site stays dropped (Aaron, Nov 10).
//
// The separate red-team copy (RK141; Aaron, Nov 10) may run open only under previewCopy's conditions below; the rule,
// and why it can never open production, is in design/preview-copy.md ("When a deployment of the copy may run open").
//
// The stage is the repository's (harness/PLAN.md: Aaron's merge of the go-live release is the go-live decision): launch.json { "stage": "public" | "closed" }, changed only by a pull request he merges. A missing
// file, or a value that isn't a stage, counts as closed.
// LAUNCH_STAGE, the Vercel setting, can only close it (the close switch, the CSO's control 7, R-10): unset or empty has
// no effect, "public" has no effect, and anything else ("closed", a stale "preview", a typo) closes the site. So either
// one alone can close the site, and only the repository can open it. Opening never needs a hand change in Vercel.
// The database side of the switch is db/emergency/close-site-login.sql (OPERATIONS.md, "Runbook: close the site now").
'use strict';

const STAGES = ['closed', 'public'];
// Route A's settings (CHARTER.md section 2, Oct 26): a database address, or one of the site's keys or the timer secret.
// If Vercel gives a preview any of these, the preview copy stays closed. Read once, when this file is first loaded,
// which is always before db/sitekeys.js puts the broker's answer in the same environment (it asks the stage first), so
// the copy's own values never count as Vercel's. Whether an address is set is asked of db/index.js, the one place
// that reads it (G1).
const ROUTE_A_KEYS = ['SESSION_SECRET', 'IP_HASH_KEY', 'FINGERPRINT_KEY_1', 'CRON_SECRET'];
const routeA = (env) => [...(require('./db').hasAddress(env) ? ['database address'] : []),
  ...ROUTE_A_KEYS.filter((k) => env[k] != null && String(env[k]) !== '')];
const BOOT = Object.freeze(routeA(process.env));
const lower = (x) => (x == null ? '' : String(x).trim().toLowerCase());

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
  const vercel = lower(env.VERCEL_ENV);
  if (vercel !== '' && vercel !== 'production') return 'closed';
  const raw = lower(env.LAUNCH_STAGE);
  return raw === '' || raw === 'public' ? 'public' : 'closed';
}

// What a preview deployment of the preview copy allows (the conditions above); closed for anything else.
// previewRef and boot are for the tests: the branch's reference (db/sitekeys.js PREVIEW_REF) and the route A settings
// Vercel gave (read at load for the live environment; from the given object otherwise).
function previewCopy(env = process.env, { previewRef, boot } = {}) {
  if (lower(env.VERCEL_ENV) !== 'preview') return 'closed';
  const sitekeys = require('./db/sitekeys');
  if (!sitekeys.brokerFor(env, previewRef === undefined ? sitekeys.PREVIEW_REF : previewRef)) return 'closed';
  if ((boot || (env === process.env ? BOOT : routeA(env))).length) return 'closed';
  const raw = lower(env.LAUNCH_STAGE);
  return raw === '' || raw === 'public' ? 'public' : 'closed';
}

const least = (a, b) => (STAGES.indexOf(a) <= STAGES.indexOf(b) ? a : b);
function stage(env = process.env, f = FILE, opts = {}) {
  const a = repoStage(f);
  if (lower(env.VERCEL_ENV) === 'preview') return least(a, previewCopy(env, opts));
  return least(a, envCap(env));
}

module.exports = { stage, repoStage, envCap, previewCopy, STAGES };
