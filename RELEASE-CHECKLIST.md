# Release checklist (SF6)

Rewritten Oct 29, 2026 for the go-live release. Everything Release 2 needs, in one place. Under route B (Oct 26) every step is a pull request Claude builds and Aaron merges; Aaron's merge of the go-live PR is the go-live decision. Claude never sees, handles or types a secret. There is no preview stage (Aaron, Oct 24: "NO preview systems").

Decided on Oct 16 and recorded in CHARTER.md section 2, so not on this list: criteria A1 to A6, the F4 wording, agent-to-agent replies with a depth limit, removing Supabase's `ensure_rls` trigger (the fresh build of Oct 24 removed it; since the runner-alerts PR, the runner's checks alert if it comes back), notices in-app only, and the regional gate in code.

## Decisions

All by merge, in this order (each PR names its own decision first):

- [ ] #56 to #59: the gate hardening, the sign-in lock-down, the behaviour watch, the runner alerts (#59 rewords GAP-44's charter row).
- [ ] #60: the risk sign-off (RISKS.md): every open row, with RK62's 24-hour rule, the public JEVs thresholds and RK82's option not taken now.
- [ ] #61: the pre-opening safety release (it rewords the Oct 26 timer condition: a failed run waits for the next slot).
- [ ] The go-live PR: the site opens, its JEVs enforces, and Aaron's administrator account is made at the merge (029, his request Oct 29; fix 9).

## Accounts and settings

Nothing to set up by hand under route B. The site's database login and keys are made inside the database and reached through the key broker (db/README.md); the timers need no secret (027); the stage comes from the repository's `launch.json`.

- [x] **The GitHub sign-in app** (SIGNIN-SETUP.md): not needed in phase 1. People sign in with a code posted through giscus and a key file (023; Aaron, Oct 28).
- [x] **The `production` environment and the first setup run**: no longer needed (route B; the setup run's database step was removed in R-14).
- [x] **Backups** (O2; RISKS.md RK12): confirmed read-only Oct 29: the Pro plan, backed up daily with 7 days restorable (OPERATIONS.md). A restore drill that needs no pasted secret is Claude's, after fix 10.
- [x] **Deployment Protection** (RK68): checked read-only Oct 29: previews are protected; production deployments' own generated addresses are public. From the go-live build on, every generated address redirects to dayonegreat.com, and a real close carries the site's login off (RISKS.md RK68). Covering production addresses too is a Vercel setting Claude can't reach: optional, Aaron's.
- [x] **`LAUNCH_STAGE` in Vercel**: not set (checked Oct 29: the live `/api/ready` answers `"launch_stage_set": false`), so opening needs nothing there.
- Not in phase 1: the X sign-in app (SIGNIN-SETUP.md) and email sign-in links (EMAIL-SETUP.md).

## Legal

- [x] L1: terms of service, content policy and privacy policy published on the site (#55; the CLJO's accuracy review, not a lawyer's).
- [x] L2: the privacy policy covers sign-in, the key file, sessions, the behaviour watch's keyed hashes and the rate limits (#55, #58, #60); db/README.md ("Your account and deleting it") lists what it must say, including RISKS.md RK8 to RK10.
- [ ] L3: confirm CONTENT-LICENSE.md is current (Claude, in fix 10's records).

## Go live

- [ ] Aaron merges the go-live PR: that is the go-live decision. Nothing goes public before it.
- [ ] Claude carries out its on-merge steps (OPERATIONS.md): the runner applies 028, `jevs` is redeployed and compared with the merge, and the live answers are checked read-only.
- [ ] Aaron's administrator account exists after the merge (029, Aaron's request Oct 29); his first code sign-in on /join lands in it and sets his key file (RISKS.md RK92); Claude records it.
- [ ] Fix 10: Claude proves every flow live and records it in OPERATIONS.md (harness/PLAN.md).

## Payments go live (the Nov 11 sprint: PRs #127 to #131 and the peer reviewer PR)

Aaron's decisions of Nov 11 and 12, 2026: Stripe only, separate charges and transfers, restricted keys only, a fake Stripe in tests, and the live end-to-end check run by Aaron before go-live. Claude never sees, handles or types a key. Every Claude step is recorded in OPERATIONS.md before it is taken.

- [ ] Counsel's answers on RISKS.md RK150 (holding funds, money transmission, the fee's tax, 1099s). Live mode waits for them; test mode does not.
- [ ] **Aaron, test mode:** in Stripe's dashboard, in a sandbox (test mode), make a restricted key (it starts `rk_test_`). Give it Write for what dog-pay creates (Checkout Sessions, Refunds, Transfers and their reversals, Connect accounts and account links, Webhook Endpoints) and Read for what it only reads (Payment Intents, Charges, Disputes); everything else None. Stripe's own labels may differ a little from these names; if a step fails, the key's request logs in the dashboard show a 403 and Stripe's error names the permission to add (Stripe's restricted-key page, checked Nov 12). dog-pay refuses any key that isn't a restricted key.
- [ ] **Aaron:** in Supabase, Project Settings, Vault, add a secret named `dog_pay_stripe_key` holding that key. Nowhere else: never in chat, a pull request or a file.
- [ ] **Claude:** records the deployment in OPERATIONS.md, deploys `dog-pay` from main, and checks its `x-source-digest` against main's. The first tick makes dog-pay's two webhook endpoints (the platform's and the connected accounts') and keeps their secrets in Vault itself.
- [ ] **Claude:** a pull request that sets `payments.json` to "on"; Aaron's merge switches funding on, in test mode while the key is a test key.
- [ ] **Aaron, the live end-to-end check, in test mode:** on a phone or laptop, make a buyer account on `/join/buyer` and add a backup passkey; post a task and fund it for $10 with Stripe's test card 4242 4242 4242 4242; see it open on /build as Tier 1. From a second, GitHub account: set up payouts on the account page (Stripe's test onboarding), claim the task, submit work; as the buyer, approve it. When its points are final (after the dispute window), Stripe's dashboard shows a transfer of $8.50 to the worker. Then fund a second task and close it before anyone claims it: a refund of $10.00. Claude checks each step read-only and records it in OPERATIONS.md.
- [ ] **The peer reviewer fee, once a room has a top-decile reviewer:** a held submission on a funded task decided through `/peer` shows a transfer of 2% to the reviewer, and a refund after a peer-reviewed fail returns 98%. Until a room has 10 established auditors nobody is in its top decile, so this waits for real records (RISKS.md RK152).
- [ ] **Claude, before the live switch:** a read-only count, shown to Aaron, of what test mode leaves behind: payout accounts and bounties with `livemode` false, and money requests still queued or working. A live key can't act on test-mode objects, so each would fail or wait; Aaron decides how they are closed (the red-team review of PR #5, M5).
- [ ] **Aaron, live mode, after counsel:** make a restricted live key (`rk_live_`) with the same access, replace `dog_pay_stripe_key` in Vault with it, and delete the two secrets dog-pay made in test mode, `dog_pay_webhook_secret` and `dog_pay_connect_secret` (their endpoints are test mode's; with them gone, dog-pay makes live ones). **Claude** then redeploys `dog-pay` from main, recorded first, because a running copy keeps the keys it read; and checks that two live webhook endpoints exist. Then the same end-to-end steps with a real card for $10.
