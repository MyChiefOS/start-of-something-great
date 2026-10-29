# Day One Great: production status and delegated authority (D1–D8)

Oct 26, 2026, after PR #49 · written by Claude for Aaron Chandler · earlier copy: the doc https://claude.ai/artifact/FvigrYxEXZBqW33GLyPwS2 (Oct 25). **Next agent: read this after INTEGRITY.md, CHARTER.md and harness/PLAN.md; update it in the same PR as any step it lists.**

Every line is checked (with its source), or labelled inferred or unknown.

## Bottom line

**It isn't production-ready yet.** Of the 10 fixes, none is done in INTEGRITY.md's sense for every path. 4 are merged: 1 is deployed and proven live for an ordinary post only; 2 is deployed and switched off; 3 and 4 are merged and applied but not yet proven in use. Fix 6 is in progress (PR #50); 5 others are not started. The public site, the read API, MCP and the GitHub path (giscus on /join and /talk, with JEVs in enforce mode) are live. The site's own system (sign-in, posting, agents, timers) is built but switched off: it has no database login and no keys.

The critical path is now the site's login and keys under route B (fixes 5 and 8), after the PRs that make them safe to switch on (RK82 and the gate hardening). Every step is a PR from Claude; Aaron only approves (Oct 26).

On delegated authority (D1–D8), the live GitHub path meets 1 of 8 (D3) in its deployed code. The site's own system meets 4 of 8 (D2, D3, D4, D7) in code and tests. None of it is proven live.

## Bad news first

- **The production system Aaron asked for isn't delivered.** Everything the site's own features need is still ahead.
- **Fix 4's new check hasn't run live.** The runner that applied 019 and 020 was version 4; version 5, with fix 4, was deployed after (OPERATIONS.md). It runs at the next migration.
- **The v5 deploy was logged late, and its files were compared by reading, not by script** (inferred). R-3's source digest replaces this.
- **No real agent has used either path.** Fix 1's live proof covers an ordinary post only (Aaron's, Oct 25 20:16 UTC). How Claude runs the agent test without Aaron is unknown; it's Claude's to solve before fix 10.
- **PR flow settled (Oct 28):** PRs queue up, each built on the one before and targeting `main`, as CHARTER §3 says (Aaron, Oct 17; Claude's reading of his Oct 28 "not having to be the bottleneck", inferred). Until then Claude had followed one open at a time, which made each merge a wait; harness/RULES.md rule 1 now matches the charter.
- **`dog-probe` (v2, answers 410; GET checked Oct 29) is still deployed, and the `setup-probe` and `oidc-probe` branches still exist.** The daily watch (runner-alerts PR) reports `dog-probe` while it answers. Claude's session can't delete branches. Claude will propose the deletions in a PR whose merge is Aaron's approval; whether a workflow can delete those branches is unknown until tried.
- **SETUP.md and RELEASE-CHECKLIST.md still describe route A's manual steps.** SETUP.md is marked superseded (PR #50). Both are rewritten in the open PR (5b below), when route B's steps are final; the connection PR didn't, as first promised.

## What is live today

Read on Oct 26 through GitHub's REST API and read-only Supabase calls, unless marked; rows marked Oct 29 re-read then.

| Part | State | Basis |
| --- | --- | --- |
| `main` | `ce55487` (#55 merged Oct 29 03:31 UTC) | Verified Oct 29, GitHub REST |
| `main`'s rules | Ruleset 25064724, active, no bypass: no deletion, no force-push, PR required, `checks` must pass, 0 approvals | Verified Oct 26 |
| Site pages, read API, MCP, proposals, daily queue | Live | Verified Oct 24–25 (PLAN.md §2) |
| GitHub path: giscus on /join and /talk; JEVs workflow | Live, enforce mode since #42 (Oct 24 23:10 UTC) | Verified |
| JEVs gate `jevs` | Version 5, from `e05ea6e` (#53); all five files match the merge by SHA-256; refusals 405, 401, 401 | Verified Oct 29 |
| Runner `dog-migrate` | Version 6 (after #52) | Verified version Oct 29; file match compared by reading, not by script (OPERATIONS.md) |
| `dog-probe` | Version 2; answers 410 "switched off" | Verified; not in the repo |
| Database ledger | 001 to 023 (`023_code_signin` last, applied on #53's merge) | Verified Oct 29 from the runner's answer in the workflow log |
| Fix 3 in the database | `actor_keys` 1 row, `system_hash` null; functions owned and granted as designed | Verified (OPERATIONS.md, Oct 26) |
| Site's own tables | 0 members, 0 agents | Verified |
| Site JEVs mode | `shadow` (set Oct 24 19:01 UTC) | Verified Oct 25 |
| Site login `dog_web` | Exists (022, route B); its password in Vault | Verified Oct 27 (OPERATIONS.md) |
| Site's own system | Built and tested; switched off: `/api/ready` says `stage: closed`, and sign-in answers 503 | Verified Oct 29 |
| Public text | True: no preview promised, Release 2 "not yet" (#50, read live Oct 26) | Verified live |

## The fix list

"Done" means tested, reviewed where it matters, merged by Aaron and proven live (INTEGRITY.md).

| Fix | What | Status | Basis |
| --- | --- | --- | --- |
| 1 | GitHub holes in the gate | **Merged and deployed (#45, `jevs` v4); proven live for an ordinary post only.** The machine-account, untagged and agent paths are built, not proven | Verified |
| 2 | Posts JEVs hid are kept from agents | **Merged and live, switched off** until the site has its database (#47) | Verified |
| 3 | The database decides who is acting (019); each policy asks once per query (020) | **Merged and applied (#49).** Idle until the site has a login: no session or key has gone through `act_as` live | Verified |
| 4 | The runner checks that the one site login is narrow. It applies the migrations in one transaction, then checks and reports; a failed check doesn't undo or refuse them (R-2). The runner-alerts PR makes a failed check alert | **Merged; runner v5 deployed.** The check hasn't run live yet | Verified |
| 5 | A migration creates the site login | **Built (connection PR, migration 022)**: made inside the database, password in Vault; tested on Supabase's image (the CI rehearsal); not live | test/runner.test.js |
| 6 | Sign-in link on /join; true public text; `/terms` and `/privacy` | Public text done (#50, live); the rest not started. The legal part needs an independent review and Aaron's approval | PLAN.md fix 6 |
| 7 | Site JEVs mode to enforce | 028, built Oct 29 on branch `go-live` (the go-live PR), not merged or proven live | Verified (`shadow` today) |
| 8 | The site's keys and timers, route B (Aaron, Oct 26) | **Keys built (connection PR):** the broker `dog-keys` and `db/sitekeys.js`; `/api/ready` will prove them after merge, with the site still closed. **Timers built** (control 6, the pre-opening safety PR, 027; not merged; proven live only after go-live) | PLAN.md fix 8; RISKS.md RK88 |
| 9 | Aaron becomes administrator | 028, built Oct 29 on branch `go-live` (the go-live PR), not merged or proven live: at his first code sign-in after the gate's redeploy, if nobody is yet (recommended in the go-live PR, decided by its merge) | `app.founder_promote`, `app.code_sign_in` (028) |
| 10 | Live proof of every flow | Not started | Needs fixes 5 to 9 |

## Delegated authority: D1–D8

The live GitHub path meets 1 of 8 in code (D3); sub-agents escape the parent's daily cap (R-4). The site's own system meets 4 of 8 (D2, D3, D4, D7) in code and tests; D8 fails open while the timers are off (R-9). It is switched off, so none of its ratings are proven live.

| Requirement | GitHub path (live) | Site's own system (built, off) | What closes the gap |
| --- | --- | --- | --- |
| **D1** A verified human principal stands behind the agent | Partly: a GitHub account scored by JEVs; no identity check | Partly: GitHub sign-in, JEVs promotes to level 2; no identity check | Stripe Identity for agent owners: a spend decision, Aaron's |
| **D2** The agent has its own identity | Partly: a linked machine account is its own identity; the tag-line route posts from the owner's account | Meets: own ID and key; only the hash is stored | Site keys once live; the tag line stays "partly" by design |
| **D3** Each agent is bound to one accountable person | Meets: one owner fixed in the database | Meets: one level-2 owner, checked on every request | Link the two agent registries after fix 10 |
| **D4** The person consents to what the agent may do, scoped | Partly: a machine account may only narrow its limits; untagged posts alert, never hide (Oct 25) | Meets: off, draft or act, a daily cap, approval bound to the exact words | Nothing planned beyond the alert |
| **D5** Riskier grants need the person to authenticate again | **Gap** | Partly: a sign-in in the last 10 minutes; since fix 3 the database judges "fresh" | A second factor; none planned while passkeys stay out. R-12 adds a step-up prompt |
| **D6** Credentials short-lived or scoped, revocable, checked every request | Partly | Partly: keys hashed, revoked at once; **fix 3 (merged)** makes the database check the key itself. No expiry, no proof of possession | Key expiry and DPoP, after fix 10 |
| **D7** Sub-agents stay within the person's limits, revocable as a tree | Partly: sub-agents escape the parent's daily cap (R-4); otherwise bounded, depth 3, expiring. Never run live | Meets | R-4 in the gate-hardening PR; a live test |
| **D8** The grant expires or is re-confirmed | Partly: sub-agents expire; agents don't | Partly, fails open while timers are off (R-9) | Fix 8, R-9, then key expiry |

## What is left for production, in order

PRs queue up, each built on the one before and targeting `main` (harness rule 1, Oct 28). Each opens when it is built and checked (the suite, the Supabase-image rehearsal, Semgrep, gitleaks, and independent review). Aaron's only step is the merge.

1. **PR #50: true public text (R-5). Done:** merged Oct 26 22:57 UTC and read live.
2. **The route B probe: done Oct 26, on branch `oidc-probe` (no PR).** Vercel's identity token is issued to the project's builds, in team issuer mode, with the claims route B checks (OPERATIONS.md). Production at run time is inferred until fix 5 runs there.
3. **RK82 (migration 021, PR #51). Done in code, checked live Oct 27 00:22 UTC (OPERATIONS.md); the cap is exercised live only once the site's login exists:** every sign-in level is capped at 1 in the database, with an alert to Aaron; level 2 only through JEVs. This reduces RK82 but doesn't close it (a forged caller can still pass JEVs, about 50 an hour). GitHub-only isn't enforced in code today (it rests on X and email settings being absent); Claude adds a provider allowlist in a later PR. Changed from the plan: neither GitHub-only nor the regional decline can be enforced in the database (RISKS.md RK82).
4. **5a, the route B connection (moved ahead of the gate hardening, Oct 27):** migration 022 (the site's login), the broker `dog-keys`, `db/sitekeys.js`, `/api/ready`. It delivers the CSO's controls 1, 4, 5 and 8 and R-8's stripping; the site stays closed. Why first: it keeps the site closed and proves the database connection, the biggest unknown; the hardening protects the GitHub path and still merges before 5b. **Done:** #52 merged Oct 27 00:45 UTC; proven live the same day (OPERATIONS.md).
5. **Sign-in (Aaron, Oct 28), merged in #53 on Oct 29:** 023 applied and `jevs` v5 deployed and verified (OPERATIONS.md); off until go-live, not yet proven live (fix 10). the GitHub username and a key file (hashed in the browser; the file never leaves the device), a one-time code posted through giscus on /join that the JEVs gate confirms, then a 30-day session; later, the same username and file sign in again with no post. Ten wrong files, or "Sign out everywhere", cancel the key file; starting again with a new code returns the person to the same account. Sessions a flat 30 days (023), R-16's speed fix with over-long posts flagged. Stays off until the go-live merge opens the site.
5b. **JEVs behaviour watch (Aaron, Oct 28), queued after the lock-down:** 026, built and tested, not proven live: many sessions at once, a new country (and for the administrator a new network), the 5th wrong key file and a cancellation (with its own title when it is Aaron's), a member reaching for the review queue or owner controls, and a member's first agent key or rules change. Alerts only, to Aaron's inbox; nothing is refused. The privacy policy describes its keyed hashes. The privacy page must describe the new sign-in data before go-live (fix 6).
6. **Gate hardening, the open PR (Claude had parked it; Aaron, Oct 29: "Lets finish so we can open the site"):** R-4 (a tree of sub-agents counts against its top agent's daily limit; over it alerts), R-15 (a level-1 owner of agents alerts), R-6 (agent tag lines named and marked not verified in the read API), R-13 (hidden markup removed from proposals). R-11 dropped by Aaron; R-16 shipped in #53. Then redeploy `jevs`.
6a. **Sign-in lock-down (the CSO's blocking finding, Oct 29), queued after the gate hardening:** 025 (built and tested, not proven live): `app.sign_in` refuses an administrator, and making someone administrator waits for sign-ins in progress, ends their sessions, revokes their agents' keys and needs exactly one GitHub method, so the site's login can't make or keep Aaron's administrator session; the code and key-file sign-ins are unchanged. The rest of RK82 (non-administrator members) stays open. Also the stale records here, in PLAN.md and FACTS.md. R-8: header stripping (#52) and the last good keys kept when the broker fails (db/sitekeys.js) are done; `system_hash` set in the same transaction goes with the timers in the go-live release.
7. **Pre-opening safety (built Oct 29 on branch `preopen-safety`, stacked on `runner-alerts`; not yet merged, deployed or proven live; the site stays closed):** the timer slot (control 6, 027: `app.timers_run`, no timer secret, at most once every 50 seconds, every run holds the slot 50 seconds, a failed one too, which is recorded and alerts, Vercel Cron's user-agent counted as evidence only, `/api/cron` replies only `{ok:true}`); the close switch (control 7, R-10: `launch-cap.json`, the stricter of it and `LAUNCH_STAGE` winning, and `db/emergency/close-site-login.sql` with its reopen file, tested on a throwaway database; steps in OPERATIONS.md); broker alerts (control 3: hand-out and failure counts, alerts through the timers, and the uptime monitor's broker check); a refused password refetches from the broker and retries once (controls 2 and 4; two-role rotation not built, RK88 says why); the R-9 heartbeat (`/api/ready` `timers`, the uptime monitor every 15 minutes) and the 90-day check in the database on each agent post and each new sub-agent, judged by the tree's clock (until the timers run, the rules still read "act" and the owner isn't told). Proof: test/preopen-safety.test.js. On merge Claude redeploys `dog-keys`, `dog-migrate` and `jevs` (OPERATIONS.md).
7b. **The go-live release (built Oct 29 on branch `go-live` (the go-live PR), not merged or proven live; stacked on #61):** 028: the site's JEVs enforces (fix 7), at most one administrator, and Aaron made administrator at his first code sign-in after the gate's redeploy by the gate's founder flag (fix 9); `launch.json` decides the stage and `LAUNCH_STAGE` can only close it (so opening needs nothing in Vercel; `LAUNCH_STAGE` isn't set there, checked Oct 29 through `/api/ready`); the uptime monitor compares the live stage with the repository's; after a code or key-file sign-in the person returns to the page that sent them; the public text, RELEASE-CHECKLIST.md and SETUP.md rewritten; RK92. R-12 (step-up through OAuth) is not in phase 1: phase 1 has no OAuth sign-in, and a fresh session comes from a new code or key-file sign-in (fresh for 10 minutes, 012). Aaron's merge is the go-live decision.
8. **Runner and workflow alerts (built Oct 29 on branch `runner-alerts`, stacked on the sign-in lock-down; not yet merged, deployed or proven live):** R-2: the records corrected (the runner applies, then checks and reports), a failed runner check or run comments on the "JEVs alerts" issue, and the daily drift check runs the runner's catalog checks on the live database. R-3: each function returns `x-source-digest` (its `source-digest.mjs`, written by scripts/function-digests.js, a test fails if stale), and the daily watch (watch.yml) compares it with main's and reports `dog-probe` (RK91 states the limit). R-7: Semgrep scans supabase/ and the workflows (a rule for the workflows; 0 findings), actionlint 1.7.7 report-only, and a daily npm audit of the site and the functions' npm imports that alerts by comment. R-14: the setup's database step removed (it migrated outside the runner), the inert reset entry removed from the manifest, the workflow comments that claimed an approval gate corrected, and the dead preview paths removed. On merge Claude redeploys all three functions with their digest files (OPERATIONS.md). **Not in it:** deleting `dog-probe` (Supabase deletions need Aaron's approval, review decision 3) and the `setup-probe` and `oidc-probe` branches (Claude's session can't delete branches).
9. **Fix 10:** live proof of every flow, recorded in OPERATIONS.md.

After fix 10, each needs Aaron's yes or no: linking the agent registries, the legal hold (RK22) and erasure runbook, the daily JEVs summary, an outside uptime check, Dependabot, a separate GitHub identity for Claude (RK71), agent replies on the site, and toward D1, D5 and D6.

## Open for Aaron

**Merges:** each PR, in order; the route B connection PR next.

**Decisions** (each recorded in FACTS.md when answered):

- [x] Route B for the site's login and keys (Oct 26), with the open, slot-limited timer address and the CSO's conditions.
- [ ] How Aaron becomes administrator (fix 9): recommended in the go-live PR (at his first code sign-in after the gate's redeploy), decided by its merge.
- [ ] JEVs thresholds (RK16): today the public seed values.
- [ ] RK1 (giscus): /talk shows email addresses and phone numbers in GitHub comments unmasked.
- [ ] How email erasure requests are carried out.
- [ ] What the regional decline means for posts made directly on GitHub.
- [ ] CHARTER §3 versus RULES.md rule 1 on PR flow (asked Oct 23).
- [ ] **RK82's real close (the CSO's review, Oct 26):** move sign-in into an Edge Function that checks the person's GitHub token itself and is the only caller of `app.sign_in`. It changes the Oct 24 direct-connection decision, so it is yours; Claude recommends deciding before go-live.

No manual action is asked of Aaron in the plan above. Older records that still describe manual steps are rewritten in the PRs named: RELEASE-CHECKLIST.md and SETUP.md (the open PR, 5b), db/README.md's and controls.html's "change thresholds in the SQL editor" step (with RK16). Unknown: how Claude deletes the probe branches (its session can't), and how fix 10 proves the flows that need a real person signed in.

## Notes for the next agent

Start with INTEGRITY.md, then CHARTER.md (the engagement checklist in §5), harness/PLAN.md and FACTS.md. Don't trust a summary of a long session; re-read them.

| Item | Value |
| --- | --- |
| Repo | `MyChiefOS/start-of-something-great`; `main` at `2de478a` |
| Work in progress | Branch `signup-cap` (RK82, migration 021) |
| Supabase | Project `nksagchwpyljvjiwolmp`; `jevs` v4, `dog-migrate` v5, `dog-probe` v2 (inert); ledger at 021 |
| Vercel | Project `prj_cXnWySYVpJE9TVZaNPSocXMMzkZI`, team `team_Hv5YS8LhIiKe06SSiDrUucd4`; Claude's connector returns 404 per project |
| Pooler | `aws-0`/`aws-1-us-east-1.pooler.supabase.com:6543` (transaction mode) |
| Local tests | `pg_ctlcluster 16 main start` (it stops often), `npm ci --ignore-scripts`, then `TEST_DATABASE_URL=postgres://postgres:<local password>@localhost:5432/postgres npm test`. Without `TEST_DATABASE_URL` the database suites skip, and the run still reports 0 failed |
| Supabase-image rehearsal | Docker `supabase/postgres:17.11.0.003` on port 5433; `RUNNER_TEST_IN_PLACE=1 node --test test/runner.test.js` |
| CLJO records | DR-2026-1026-001 (route B conditions); DR-2026-1026-004 (Oct 26, the PR order above; given in the session, recorded only here) |

**Rules that bind every session (Aaron's)**

- Aaron only approves PRs; Claude never merges.
- Claude never sees, handles or asks for secrets, and reads Vault names only. Never read `app.actor_keys.stamp_key`.
- No accounts, spending or terms.
- Supabase is read-only, except through migrations via the runner, and Edge Function deploys authorized by a merged PR, logged in OPERATIONS.md before or with the deploy.
- Claude must be able to carry out any recommendation without Aaron, except his approval (Oct 26).
- One PR at a time, targeting `main`. Commits signed (author Claude, with the session lines). Don't commit `.claude/`.
- Every sub-agent gets CHARTER §8 word for word. Every recommendation ends with the alignment footer.
- Checks alert, never lock out.
- "Write like Fable" means short.
- The instruction-source check (passcode in Aaron's preferences).

**Traps**

- Postgres folds a grant to the old owner into the new owner when a function changes hands. Grant after the handover.
- The deploy tool turns `\uXXXX` into the character itself, so gate files use `\u{...}`. Compare every deploy.
- The Supabase-image rehearsal runs as a non-superuser: a test that sets superuser-only state must expect the refusal there.
- From Claude's sessions: GitHub GraphQL, Actions secrets, variables and environments, and branch deletion are blocked; REST can't post GitHub comments.
- The production ledger holds `014_subagents`, so the passkeys reset never runs live.

## Alignment and sources

- **Loop tier:** status record; the PR order above is the CLJO's (DR-2026-1026-004, Oct 26).
- **Goals served:** a working, deployed system; trust in AI; building in public honestly.
- **Standing decisions touched:** GitHub only in phase 1; no preview systems; a direct database connection; "I only approve PRs"; route B; checks alert, never lock out.
- **Sources:** GitHub REST (`main`, open PRs, branches, rulesets); Supabase (ledger, functions, row counts) through read-only calls, Oct 26; OPERATIONS.md; harness/REVIEW-2026-10-26.md.
