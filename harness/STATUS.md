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
- **Records disagree on PR flow:** CHARTER §3 says PRs queue up; harness/RULES.md rule 1 says one stays open. Claude follows one at a time. The question has been open for Aaron since Oct 23 (FACTS.md, "Open for Aaron"); it isn't asked again.
- **`dog-probe` (v2, answers 410) is still deployed, and the `setup-probe` and `oidc-probe` branches still exist.** Claude's session can't delete branches. Claude will propose the deletions in a PR whose merge is Aaron's approval; whether a workflow can delete those branches is unknown until tried.
- **SETUP.md and RELEASE-CHECKLIST.md still describe route A's manual steps.** SETUP.md is marked superseded (PR #50); the checklist's step list is rewritten in the route B PR.

## What is live today

Read on Oct 26 through GitHub's REST API and read-only Supabase calls, unless marked.

| Part | State | Basis |
| --- | --- | --- |
| `main` | `e11e796` (#49 merged 19:43 UTC) | Verified, GitHub REST |
| `main`'s rules | Ruleset 25064724, active, no bypass: no deletion, no force-push, PR required, `checks` must pass, 0 approvals | Verified Oct 26 |
| Site pages, read API, MCP, proposals, daily queue | Live | Verified Oct 24–25 (PLAN.md §2) |
| GitHub path: giscus on /join and /talk; JEVs workflow | Live, enforce mode since #42 (Oct 24 23:10 UTC) | Verified |
| JEVs gate `jevs` | Version 4, from `f450b9d`; refusals 401, 401, 405 (re-checked Oct 26). Bundles an older, behaviour-identical copy of `dog-migrate/core.mjs` | Verified |
| Runner `dog-migrate` | Version 5, from `e11e796` (fix 4) | Verified version; file match inferred |
| `dog-probe` | Version 2; answers 410 "switched off" | Verified; not in the repo |
| Database ledger | 001 to 020 (20 rows; `020_policy_initplan` last) | Verified |
| Fix 3 in the database | `actor_keys` 1 row, `system_hash` null; functions owned and granted as designed | Verified (OPERATIONS.md, Oct 26) |
| Site's own tables | 0 members, 0 agents | Verified |
| Site JEVs mode | `shadow` (set Oct 24 19:01 UTC) | Verified Oct 25 |
| Site login `dog_web` | Doesn't exist | Verified |
| Site's own system | Built and tested; switched off (`LAUNCH_STAGE` closed, no database login, no `CRON_SECRET`, no sign-in link on any page) | Verified Oct 25 |
| Public text | Still promises a "private preview on November 6" until PR #50 merges and deploys | Verified in code |

## The fix list

"Done" means tested, reviewed where it matters, merged by Aaron and proven live (INTEGRITY.md).

| Fix | What | Status | Basis |
| --- | --- | --- | --- |
| 1 | GitHub holes in the gate | **Merged and deployed (#45, `jevs` v4); proven live for an ordinary post only.** The machine-account, untagged and agent paths are built, not proven | Verified |
| 2 | Posts JEVs hid are kept from agents | **Merged and live, switched off** until the site has its database (#47) | Verified |
| 3 | The database decides who is acting (019); each policy asks once per query (020) | **Merged and applied (#49).** Idle until the site has a login: no session or key has gone through `act_as` live | Verified |
| 4 | The runner allows exactly one narrow site login | **Merged; runner v5 deployed.** The check hasn't run live yet | Verified |
| 5 | A migration creates the site login | Not started; route B, after RK82 and the gate hardening | REVIEW-2026-10-26.md |
| 6 | Sign-in link on /join; true public text; `/terms` and `/privacy` | Public text in PR #50; the rest not started. The legal part needs an independent review and Aaron's approval | PLAN.md fix 6 |
| 7 | Site JEVs mode to enforce | In the go-live release | Verified (`shadow` today) |
| 8 | The site's keys and timers, route B (Aaron, Oct 26) | Not started; Claude's | CHARTER §2; PLAN.md fix 8 |
| 9 | Aaron becomes administrator before sign-up opens | In the go-live release; how is Aaron's decision | `app.set_administrator` (013) |
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

One PR open at a time. Each opens when it is built and checked (the suite, the Supabase-image rehearsal, Semgrep, gitleaks, and independent review). Aaron's only step is the merge.

1. **PR #50: true public text (R-5).** No served page promises a preview; the status page no longer says Release 2 is done; `preview` counts as closed; the records after #49.
2. **The route B probe: done Oct 26, on branch `oidc-probe` (no PR).** Vercel's identity token is issued to the project's builds, in team issuer mode, with the claims route B checks (OPERATIONS.md). Production at run time is inferred until fix 5 runs there.
3. **RK82:** `app.sign_in` caps new members at level 1; GitHub only and the regional decline enforced in the database.
4. **Gate hardening:** R-4, R-11, R-15, R-16, R-6, R-13; then redeploy `jevs`, compared by script.
5. **Fixes 5 and 8 under route B,** with the CSO's controls 1 to 8, the timer conditions, the fallback to Vercel settings, and R-8.
6. **Runner and workflow alerts:** R-2, R-3 (source digest), R-7, R-14 (also removes the dead preview code and the setup's database step); the `dog-probe`, `setup-probe` and `oidc-probe` deletions.
7. **Before go-live:** R-9 heartbeat, R-10 close switch, R-12 step-up prompt.
8. **Fix 6:** the sign-in link and the legal pages.
9. **The go-live release:** fix 7, fix 9, then `LAUNCH_STAGE` public, with the text that changes at go-live (feed.html's sign-in hint and its first-posts line; agents.html's present-tense description of switched-off features). The mechanism isn't built yet: today the only path is a Production setup run started by hand (SETUP.md §6). Claude's to design so that Aaron's merge is the go-live decision.
10. **Fix 10:** live proof of every flow, recorded in OPERATIONS.md.

After fix 10, each needs Aaron's yes or no: linking the agent registries, the legal hold (RK22) and erasure runbook, the daily JEVs summary, an outside uptime check, Dependabot, a separate GitHub identity for Claude (RK71), agent replies on the site, and toward D1, D5 and D6.

## Open for Aaron

**Merges:** each PR, in order; #50 next.

**Decisions** (each recorded in FACTS.md when answered):

- [x] Route B for the site's login and keys (Oct 26), with the open, slot-limited timer address and the CSO's conditions.
- [ ] How Aaron becomes administrator before sign-up opens (fix 9).
- [ ] JEVs thresholds (RK16): today the public seed values.
- [ ] RK1 (giscus): /talk shows email addresses and phone numbers in GitHub comments unmasked.
- [ ] How email erasure requests are carried out.
- [ ] What the regional decline means for posts made directly on GitHub.
- [ ] CHARTER §3 versus RULES.md rule 1 on PR flow (asked Oct 23).

No manual action is asked of Aaron in the plan above. Older records that still describe manual steps are rewritten in the PRs named: RELEASE-CHECKLIST.md and SETUP.md (route B PR), db/README.md's and controls.html's "change thresholds in the SQL editor" step (with RK16). Unknown: how Claude deletes the probe branches (its session can't), and how fix 10 proves the flows that need a real person signed in.

## Notes for the next agent

Start with INTEGRITY.md, then CHARTER.md (the engagement checklist in §5), harness/PLAN.md and FACTS.md. Don't trust a summary of a long session; re-read them.

| Item | Value |
| --- | --- |
| Repo | `MyChiefOS/start-of-something-great`; `main` at `e11e796` |
| Work in progress | Branch `public-text`, PR #50 |
| Supabase | Project `nksagchwpyljvjiwolmp`; `jevs` v4, `dog-migrate` v5, `dog-probe` v2 (inert); ledger at 020 |
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
