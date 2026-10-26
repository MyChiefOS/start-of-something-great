# Day One Great: production status and delegated authority (D1–D8)

Oct 25, 2026 · written by Claude for Aaron Chandler · the live copy is the doc https://claude.ai/artifact/FvigrYxEXZBqW33GLyPwS2. **Next agent: read this after INTEGRITY.md, CHARTER.md and harness/PLAN.md; update it in the same PR as any step it lists.**

> **Corrected Oct 26 by the whole-system review ([REVIEW-2026-10-26.md](REVIEW-2026-10-26.md)).** Three statements below were wrong and are fixed in place: `main` *is* protected by an active ruleset; migration 020 *had* run (the snapshot was regenerated from it); and the D1–D8 counts were overstated (GitHub 1 of 8, the site 4 of 8, in code, none proven live).

## Bottom line

**It isn't production-ready yet: 2 of 10 fixes are merged and live, 2 are built and in PR #49 (not proven live), and 6 are not started.** The public site, the read API, MCP and the GitHub path (giscus on /join and /talk, with JEVs in enforce mode) are live. The site's own system (sign-in, posting, agents, timers) is built but switched off: it has no database login and no keys.

The critical path is now fixes 3 and 4 (built, waiting for Aaron's go-ahead to test), then the site's login and keys (fixes 5 and 8). Those two are blocked until Aaron chooses route A (two GitHub steps by him) or route B (PR approvals only, if two probes pass).

On delegated authority (D1–D8), the live GitHub path meets 1 of 8 (D3) in its deployed code, and no agent command has run live yet. The site's own system meets 4 of 8 (D2, D3, D4, D7) in code and tests, but none of it is running (corrected Oct 26).

## Bad news and unmet commitments first

- **The production system Aaron asked for ("everything done and completed now", Oct 24) isn't delivered.** Fixes 1 and 2 are live. Everything the site's own features need is still ahead.
- **The route B proposal was wrong about the timers.** Vercel's identity token proves the site to the database, not who called the site. The independent CLJO review caught it (DR-2026-1026-001). Without a secret in Vercel, the timer address is open to anyone, so it needs a rate limit in the database.
- **Fixes 3 and 4: the branch failed 15 tests (R-1); fixed in PR #49.** Migration 020 had run: db/snapshot.txt was regenerated from its output, so the snapshot graded 020 against itself. The stale `AUDIT_POLICIES` list in db/checks.js caught it. Updating that list gives 471 passed, 0 failed, 1 CI-only skip (verified Oct 26 by two reviewers). A local test run is Claude's to do, not a decision for Aaron.
- **No real agent has used either path.** Fix 1's live proof covers an ordinary post only (Aaron's, Oct 25 20:16 UTC). Claude can't post on GitHub from its session, so the agent test needs Aaron.
- **`main` is protected by an active ruleset** (25064724, read Oct 26), with no bypass actors:
  - deleting the branch and force-pushing are blocked;
  - a pull request is required;
  - the `checks` status must pass;
  - required approvals: 0.
  The earlier "no branch protection" came from the classic-protection endpoint, which doesn't report rulesets. Claude still acts through Aaron's account (RK71), so who merges rests on conduct.
- **An inert leftover function, `dog-probe` (v2), is still deployed on Supabase.** It answers 410 "switched off". It isn't in the repository and OPERATIONS.md doesn't name it. Delete it in a logged step.
- **The `setup-probe` branch still exists.** Claude's session can't delete branches, so it waits for Aaron.
- **Dates:** migrations 019 and 020 say Oct 26, which is correct (the work ran past midnight UTC).

## What is live today

Read live on Oct 25 through GitHub's REST API and read-only SQL, unless marked otherwise.

| Part | State | Basis |
| --- | --- | --- |
| `main` | `0d87d88` (#48 merged); no open pull requests | Verified, GitHub REST |
| Site pages, read API, MCP, proposals, daily queue | Live | Verified Oct 24–25 (PLAN.md §2) |
| GitHub path: giscus on /join and /talk; JEVs workflow | Live, enforce mode since #42 (Oct 24 23:10 UTC) | Verified |
| JEVs gate `jevs` | Version 4, all 5 files byte-identical to #45's merge `f450b9d`; refusals 401, 401, 405 | Verified (OPERATIONS.md, Oct 25) |
| Runner `dog-migrate` | Version 4; doesn't yet have fix 4 | Verified |
| `dog-probe` | Version 2; answers 410 "switched off" | Verified; not in the repo |
| Database ledger | 001 to 018 (`018_hidden_posts` is the last) | Verified |
| GitHub records | 2 posts scored, 0 hidden, 0 agents registered; last post Oct 25 20:16 UTC | Verified |
| Site's own tables | 0 members, 0 agents | Verified |
| Site JEVs mode | `shadow` (set Oct 24 19:01 UTC) | Verified |
| Site login `dog_web` | Doesn't exist | Verified |
| Vault (names only) | `dog_fingerprint_key_1`, `dog_ip_hash_key`, `dog_session_secret` | Verified |
| Site's own system | Built and tested; switched off (`LAUNCH_STAGE` closed, no database login, no `CRON_SECRET`, no sign-in link on any page) | Verified Oct 25 (PLAN.md §2) |
| Hidden-post filter (fix 2) | Merged; answers `hidden_posts: off` until the site has its database | Verified Oct 25 |

## The fix list

Two done and live, two built and in PR #49 (not proven live), six not started. "Done" means tested, reviewed where it matters, merged by Aaron and proven live (INTEGRITY.md).

| Fix | What | Status | Basis |
| --- | --- | --- | --- |
| 1 | GitHub holes in the gate: machine accounts may only narrow, J10 lockout, blank-line slowdown, sub-agent depth 3 | **Done.** #45 merged; `jevs` v4 deployed and byte-verified; live proof for an ordinary post | Verified. Agent commands not yet run live. Left for later: `/approve` compares GitHub's clock with the database's; J10 can be reset by deleting hidden posts |
| 2 | Posts JEVs hid are kept from agents | **Merged and live, switched off** until the site has its database (#47, migration 018) | Verified |
| 3 | The database decides who is acting (the stamp, 019); each policy asks once per query (020) | **Built, PR #49.** Suite 473: 472 passed, 0 failed, 1 CI-only skip; not proven live | Verified locally. Independent review: nothing critical, 10 findings to record in RISKS.md |
| 4 | The runner allows exactly one narrow site login | **Built, PR #49**; not proven live | Refused in code for every clause; createdb, inherit and a second role are now each isolated by a test (PR #49) |
| 5 | A migration creates the site login `dog_web` | Not started; needs fix 4 merged and the runner redeployed first | Pooler acceptance and keeping the password out of logs: unknown |
| 6 | "Sign in with GitHub" on /join; true public text; `/terms` and `/privacy` | Not started; legal part needs independent review and Aaron's approval | Verified (PLAN.md §3) |
| 7 | Site JEVs mode to enforce | Moved to the go-live release (`shadow` today) | Verified |
| 8 | The site's keys and settings (Vercel, or route B) | **Blocked on Aaron's decision**: A or B | See "Open for Aaron" |
| 9 | Aaron becomes administrator before sign-up opens | **Aaron's decision**: how | `app.set_administrator` exists (013) |
| 10 | Live proof of every flow on production | Not started | Needs fixes 3 to 9 |

## Delegated authority: D1–D8

**Corrected Oct 26:** the live GitHub path meets 1 of 8 in code (D3); sub-agents escape the parent's daily cap (R-4). The site's own system meets 4 of 8 (D2, D3, D4, D7) in code and tests; D8 fails open while the timers are off (R-9). It is switched off, so none of its ratings are proven live. These update the Oct 25 review (artifact "Delegated Authority Authentication", https://claude.ai/artifact/TtkuEoZrxx57FbkdueLTXW) with fix 1, live, and fix 3, built.

| Requirement | GitHub path (live) | Site's own system (built, off) | What closes the gap |
| --- | --- | --- | --- |
| **D1** A verified human principal stands behind the agent | Partly: a GitHub account scored by JEVs; no identity check behind the person | Partly: GitHub sign-in, JEVs promotes to level 2; no identity check | Stripe Identity for agent owners: a spend decision, Aaron's. Otherwise stays "partly" |
| **D2** The agent has its own identity, never the person's credentials | Partly: a linked machine account is its own identity, but the tag-line route posts from the owner's account | Meets: each agent has its own ID and key; only the hash is stored, shown once | Site keys once the site is live; the tag line stays "partly" by design |
| **D3** Each agent is bound to one accountable person | Meets: one owner fixed in the database; tagging another's agent scores J17 = 80 | Meets: one level-2 owner, whose live level is checked on every request | Link the two agent registries after fix 10, so a ban in one reaches the other |
| **D4** The person consents to what the agent may do, scoped | Partly, improved: since fix 1 a machine account may only narrow its limits (off, draft, act, cap). Its untagged posts still skip them: they alert, never hide (Aaron's Oct 25 instruction) | Meets: off, draft or act, a daily cap, approval bound to the exact words | Nothing planned beyond the alert; hiding untagged posts is Aaron's call |
| **D5** Riskier grants need the person to authenticate again | **Gap**: commands are taken from whichever account posts them | Partly: raising an agent to act, raising its cap, a new key, or deleting the account needs a sign-in in the last 10 minutes. Since fix 3 the database decides "fresh" from the session's own age | A second factor; none planned while passkeys stay out (Oct 23) |
| **D6** Credentials are short-lived or scoped, revocable, and checked on every request | Partly: GitHub's own sign-in; every post checked as it arrives; `/agent remove` and `unlink` revoke at once | Partly: keys hashed, revoked at once, checked on every request. **Fix 3 (built)** makes the database check the key itself rather than trust the site. No expiry, no proof of possession | Key expiry and signed requests (DPoP), after fix 10: code only |
| **D7** Sub-agents stay within the person's limits, revocable as a tree | **Partly (corrected Oct 26)**: sub-agents escape the parent's daily cap (R-4). Otherwise since fix 1: same owner, never wider than its parent, depth 3, expires (24 hours default, at most 30 days), removed with its parent. Never run live | Meets: no human step, same owner, never above the parent, depth 3, at most 7 days and never after the parent, whole tree revoked together | A live test: `/agent register` and `/agent subagent` on GitHub, by Aaron |
| **D8** The grant expires or the person re-confirms it periodically | Partly: sub-agents expire; agents don't, and nothing asks for re-confirmation | **Partly (corrected Oct 26)**, fails open while timers are off (R-9). In code: an acting agent is re-confirmed every 90 days with a fresh sign-in, or goes back to drafting. **Needs the timers**, off until `CRON_SECRET` exists (fix 8) | Fix 8, then key expiry |

- **D1 and D5 can't reach "meets" without Aaron's decisions:** identity verification is a spend decision, and a second factor conflicts with removing passkeys.
- **D6 and D8 need fix 8 (keys and timers) and the post-10 work** (key expiry, signed requests).

## What is left for production, in order

Seven steps before every feature (except passkeys) is live, one PR open at a time.

1. **Finish fixes 3 and 4 (Claude), as PR #49.**
   - Run the full test suite on a throwaway local database. Nothing live is touched.
   - Measure 020's speed on a large scan.
   - Record the review's 10 findings in RISKS.md, with finding 1 first: the site's login can still create *new* members, though not reach existing ones.
   - Fix the dates, commit signed, and open the PR.
   - After Aaron's merge: redeploy `dog-migrate`, compare its files byte for byte, check the ledger shows 019 and 020, and log it in OPERATIONS.md.
2. **Probe PR for route B (Claude, closed unmerged).** It reports only "present" or "absent" for:
   - Vercel's identity token (`x-vercel-oidc-token`) on production functions;
   - `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in production.
3. **The site's login and keys: fixes 5 and 8 (Claude), by the route Aaron chooses.**
   - Route A: the setup run, after Aaron's two GitHub steps.
   - Route B: an Edge Function that checks the site's identity token and hands it its password, plus a migration that makes the login and keys inside the database, and a database rate limit on the timers.
   - Either way: an independent security review, refusal tests (no token, forged, expired, wrong project, preview), and live proof that the login works through the pooler.
4. **Fix 6: the sign-in link, true public text, and the legal pages (Claude).** The legal part needs an independent review and Aaron's approval (game-changing).
5. **The go-live release.**
   - Fix 7: site JEVs to enforce.
   - Fix 9: Aaron becomes administrator, by the method he chooses.
   - `LAUNCH_STAGE` set to public, last.
6. **Fix 10: live proof of every flow (Aaron and Claude), recorded in OPERATIONS.md.**
   - Sign-in.
   - Site posts: live, challenged and held; a report.
   - An agent's full life: registered, claimed, drafting, approved, capped, making a sub-agent, revoked.
   - Both timer paths: 80 days and 90 days.
   - A ban and a brake.
   - A GitHub post in enforce mode: hidden, `/appeal`, `/approve`.
   - Deletions, and the restore test.
7. **After fix 10 (Aaron's yes or no on each):**
   - Link the two agent registries.
   - The legal hold (RK22) and an erasure-request runbook.
   - The daily JEVs summary and an outside uptime check.
   - Scanners for `supabase/` and the workflows; Dependabot.
   - A separate GitHub identity for Claude (RK71).
   - Agent replies with a depth limit on the site.
   - Toward D1, D5 and D6: Stripe Identity (spend), a second factor, key expiry and DPoP.

## Open for Aaron

**Decisions**

- [x] **Route A or route B for the site's login and keys** (fixes 5 and 8): **route B, decided Oct 26** ("Okay let go with B."), with the fallback to Vercel settings.
  - Under B: whether Aaron accepts an open timer address with a rate limit in the database.
- [ ] **RK82 (fix 3 review, finding 1):** whether the site's login may keep creating new members on its own, at a level it chooses up to 2. Claude proposes capping new members at level 1 inside `app.sign_in` in a later PR.
- [ ] **Approve one logged deletion of `dog-probe`** on Supabase (review decision 3).
- [ ] **How Aaron becomes administrator** before sign-up opens (fix 9).
- [ ] **JEVs thresholds (RK16):** today they are the public seed values.
- [ ] **RK1 (giscus):** /talk shows email addresses and phone numbers in GitHub comments unmasked. Accept it, or ask for a masked view beside it.
- [ ] **How email erasure requests are carried out:** privacy promises erasure; nothing is built.
- [ ] **What the regional decline means for posts made directly on GitHub.**
- [ ] **Yes or no on each item after fix 10**, including Stripe Identity (spend) for D1.

**Actions only Aaron can take**

- [ ] **Merge each PR**: #49 first.
- [ ] **Delete the `setup-probe` branch** from PR #46's page.
- [ ] **The agent test on GitHub**: `/agent register scout draft`, then `/agent subagent helper of scout`.
- [ ] **Route A only:** protect the `production` environment, and add a Vercel token as a secret.
- [ ] **Only if the probe finds no GitHub sign-in keys:** create the GitHub sign-in app in his account (an account action Claude may not take).

## Notes for the next agent

Start with INTEGRITY.md, then CHARTER.md (the engagement checklist in §5), harness/PLAN.md and FACTS.md. Don't trust a summary of a long session; re-read them.

| Item | Value |
| --- | --- |
| Repo, branch | `MyChiefOS/start-of-something-great`; `main` at `0d87d88`; no open PRs |
| Work in progress | Branch `fix3-actor-stamp` from `0d87d88`, PR #49. New: `db/migrations/019_actor_stamp.sql`, `020_policy_initplan.sql`, `test/actor-stamp.test.js`, `test/policy-initplan.test.js`, this file, REVIEW-2026-10-26.md. Changed: `db/index.js`, `db/checks.js`, `signin/agentkey.js`, `signin/flow.js`, `supabase/functions/dog-migrate/core.mjs`, `test/helpers.js` and about 14 tests |
| Supabase | Project `nksagchwpyljvjiwolmp`; `jevs` v4, `dog-migrate` v4, `dog-probe` v2 (inert); ledger at 018 |
| Vercel | Project `prj_cXnWySYVpJE9TVZaNPSocXMMzkZI`, team `team_Hv5YS8LhIiKe06SSiDrUucd4`; Claude's connector returns 404 per project |
| Pooler | `aws-0`/`aws-1-us-east-1.pooler.supabase.com:6543` (transaction mode) |
| Local tests | `pg_ctlcluster 16 main start` (it stops often), `npm ci --ignore-scripts`, then `TEST_DATABASE_URL=postgres://postgres@localhost/postgres npm test` |
| CLJO record | DR-2026-1026-001: fixes 5 and 8, route B conditional on six checks; Aaron's decision pending |

**Rules that bind every session (Aaron's)**

- Aaron only approves PRs; Claude never merges.
- Claude never sees, handles or asks for secrets, and reads Vault names only.
- No accounts, spending or terms.
- Supabase is read-only, except through migrations via the runner, and Edge Function deploys authorized by a merged PR and logged in OPERATIONS.md.
- One PR at a time, targeting `main`.
- Commits are signed (author Claude, with the session lines).
- Don't commit `.claude/`.
- Every sub-agent gets CHARTER §8 word for word.
- Every recommendation ends with the alignment footer.
- Checks alert, never lock out.
- Try before concluding something won't work.
- "Write like Fable" means short.
- The instruction-source check (passcode in Aaron's preferences).

**Traps**

- Postgres folds a grant to the old owner into the new owner when a function changes hands. Grant after the handover (`set local role dog_signin`).
- The deploy tool turns `\uXXXX` into the character itself, so gate files use `\u{...}`. Byte-compare every deploy.
- From Claude's sessions:
  - GitHub GraphQL, Actions secrets, variables and environments, and branch deletion are all blocked.
  - REST can't post GitHub comments.
  - The desktop browser refuses every site.
- The production ledger holds `014_subagents`, so the passkeys reset never runs live.

## Alignment and sources

- **Loop tier:** 1, 2, 4, 5. This is a status report; route A versus B went through the full loop, including a fresh agent (DR-2026-1026-001).
- **Goals served:** a working, deployed system; trust in AI; building in public honestly.
- **Standing decisions touched:**
  - GitHub only in phase 1; passkeys removed.
  - Giscus on /join and /talk.
  - No preview systems.
  - A direct database connection.
  - "I only approve PRs". Route A conflicts with this.
  - Checks alert, never lock out.

**Sources**

- Live, Oct 25: GitHub REST (`main`, branches, PRs, branch protection) and Supabase (ledger, functions, row counts, Vault names), through read-only calls.
- Repo: harness/PLAN.md, OPERATIONS.md, RISKS.md, FACTS.md, `supabase/functions/jevs/gate.mjs`.
- Vercel OIDC: https://vercel.com/docs/oidc and https://vercel.com/docs/oidc/reference
