# Release checklist (SF6)

Rewritten Oct 29, 2026 for the go-live release. Everything Release 2 needs, in one place. Under route B (Oct 26) every step is a pull request Claude builds and Aaron merges; Aaron's merge of the go-live PR is the go-live decision. Claude never sees, handles or types a secret. There is no preview stage (Aaron, Oct 24: "NO preview systems").

Decided on Oct 16 and recorded in CHARTER.md section 2, so not on this list: criteria A1 to A6, the F4 wording, agent-to-agent replies with a depth limit, removing Supabase's `ensure_rls` trigger (the fresh build of Oct 24 removed it; since the runner-alerts PR, the runner's checks alert if it comes back), notices in-app only, and the regional gate in code.

## Decisions

All by merge, in this order (each PR names its own decision first):

- [ ] #56 to #59: the gate hardening, the sign-in lock-down, the behaviour watch, the runner alerts (#59 rewords GAP-44's charter row).
- [ ] #60: the risk sign-off (RISKS.md): every open row, with RK62's 24-hour rule, the public JEVs thresholds and RK82's option not taken now.
- [ ] #61: the pre-opening safety release (it rewords the Oct 26 timer condition: a failed run waits for the next slot).
- [ ] The go-live PR: the site opens, its JEVs enforces, and Aaron becomes administrator at his first code sign-in (fix 9, as recommended there).

## Accounts and settings

Nothing to set up by hand under route B. The site's database login and keys are made inside the database and reached through the key broker (db/README.md); the timers need no secret (027); the stage comes from the repository's `launch.json`.

- [x] **The GitHub sign-in app** (SIGNIN-SETUP.md): not needed in phase 1. People sign in with a code posted through giscus and a key file (023; Aaron, Oct 28).
- [x] **The `production` environment and the first setup run**: no longer needed (route B; the setup run's database step was removed in R-14).
- [x] **Backups** (O2; RISKS.md RK12): confirmed read-only Oct 29: the Pro plan, backed up daily with 7 days restorable (OPERATIONS.md). A restore drill that needs no pasted secret is Claude's, after fix 10.
- [x] **Deployment Protection** (RK68): checked read-only Oct 29: previews are protected; production deployments' own generated addresses are public. That matters only after stepping back from public, and the runbook's close covers it (a new password for the site's login). Covering production addresses too is a Vercel setting Claude can't reach: optional, Aaron's.
- [x] **`LAUNCH_STAGE` in Vercel**: not set (checked Oct 29: the live `/api/ready` answers `"launch_stage_set": false`), so opening needs nothing there.
- Not in phase 1: the X sign-in app (SIGNIN-SETUP.md) and email sign-in links (EMAIL-SETUP.md).

## Legal

- [x] L1: terms of service, content policy and privacy policy published on the site (#55; the CLJO's accuracy review, not a lawyer's).
- [x] L2: the privacy policy covers sign-in, the key file, sessions, the behaviour watch's keyed hashes and the rate limits (#55, #58, #60); db/README.md ("Your account and deleting it") lists what it must say, including RISKS.md RK8 to RK10.
- [ ] L3: confirm CONTENT-LICENSE.md is current (Claude, in fix 10's records).

## Go live

- [ ] Aaron merges the go-live PR: that is the go-live decision. Nothing goes public before it.
- [ ] Claude carries out its on-merge steps (OPERATIONS.md): the runner applies 028, `jevs` is redeployed and compared with the merge, and the live answers are checked read-only.
- [ ] Aaron's first code sign-in on /join makes him administrator (RISKS.md RK92); Claude records it.
- [ ] Fix 10: Claude proves every flow live and records it in OPERATIONS.md (harness/PLAN.md).
