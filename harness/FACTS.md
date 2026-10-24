# Facts ledger

What every session needs to know, written down so no summary can lose it (harness rule 4). Each fact says how sure we are:

- **stated**: Aaron said it (quoted, with the date).
- **checked**: Claude checked it live, on the date shown, and how.
- **assumed**: believed but not checked. Check it before relying on it, or say "not checked".

Append; don't rewrite history. When a fact changes, mark the old row "replaced" and add the new one.

## Goal

| Fact | Status | Source | Date |
|---|---|---|---|
| The goal is a fully functional production site with easy sign-up now; more requirements later | stated | Aaron: "I want a production system delivered today. Easy and friction free. We will add more requirements later." | 2026-10-22 |
| Usability is a requirement: no control Claude adds may break the site or make it unusable for Aaron, members or agents ("A denial of service against our selves is not the goal"). Monitors and checks alert; they never block, lock or shut anything down on their own | stated | Aaron: "When i ask you to take the lead on what you think you sometime break and/or make things not usable. A denial of service against our selves is not the goal." | 2026-10-23 |
| No plan may hand Aaron an action that blocks the work or puts him on the critical path; Claude carries the work, to an approach Aaron outlines | stated | Aaron: "no action will be shifted back to me to address that creates a road block or puts me on the critical path... we're going to do something that gets results that I outline." | 2026-10-23 |
| dayonegreat.com/talk is live with giscus (repo MyChiefOS/start-of-something-great, discussion #1 "Welcome to Day One Great: say hello"), on main since Oct 14. GitHub sign-in and commenting there work today with no database; Aaron commented on Oct 23 | checked | curl of /talk (giscus client.js, data-repo, mapping number, term 1); GitHub REST discussions/1; Aaron's screenshot of /talk signed in through giscus (Sign out, Comment) | 2026-10-23 |
| Sign-up never refuses on JEVs risk: high-risk sign-ups get in at level 1 and go to Aaron's queue, so real people aren't turned away. Closes the red team's "no refuse outcome" finding as intended | stated | Aaron: "That is okay because we could very easily turn people away that should not be. This structure makes sure that does not happen." | 2026-10-23 |
| Sign-in simulation on a throwaway database (real signin/flow.js, JEVs and migrations; GitHub stood in): new sign-in, return, UK decline, unconfirmed account, forged return, 12-account burst (2 promoted, 3 low, 5 medium, 2 high and queued, all at level 1 after the first 2), ban, and rate limit at the 31st start all behaved as designed. The real GitHub connection is not tested | checked | scratchpad sim/signin-sim.js run | 2026-10-23 |
| Vercel history from the records: repository created Oct 13 23:22 UTC; Vercel's first deployment of start-of-something-great (team chief-os) at 23:36 UTC, built by Vercel's GitHub app; every deployment since comes from GitHub pushes, never from the Vercel connector. Who created the Vercel project (Aaron in the dashboard, or Claude through the connector) is not in any surviving record: this session's transcript starts Oct 14 06:02 UTC. The connector already answered "Deployment not found" for this project on Oct 15 15:51 UTC, so its narrow access dates from at least then, not Oct 22. chief-os-labs, the one project it sees, was created Jul 23 | checked | GitHub commit statuses (2fc96c4 onward); session transcript of Oct 14 to 15; Vercel list_projects | 2026-10-23 |
| The database trusts the caller to say who is acting: app.actor_kind() and app.current_member() read settings the site sets each transaction (001_foundation.sql; db/index.js set_config). Anyone holding the site's database login could claim to be the admin. Fix planned: migration 017 derives the actor from the session or agent-key hash inside the database | checked | code read; security architect review of the gateway plan | 2026-10-23 |
| The migration user is granted only dog_owner (001: grant dog_owner to current_user); dog_app is granted only to dog_web by the setup workflow, so a gateway connecting as Supabase's main user could not switch to the site role without a new grant | checked | code read | 2026-10-23 |
| Phase 1 admits GitHub users only; passkeys are removed from the design. Replaces the passkey-only plan | stated | Aaron: "the owners already have Github accounts and you cannot post of GitHub with out it. We will only allow Github users in phase 1. Update that design and remove pass key." | 2026-10-23 |
| Passkey-only sign-up is not built: a passkey needs an account first made through GitHub, X or email (migration 014; signin/passkey.js). Red and blue team reviews found 8 launch blockers in the passkey plan | checked | code read; reviews of Oct 23 | 2026-10-23 |
| Launch the product system in the easiest way possible, with Claude operating as a can-do co-founder | stated | Aaron: "Goal - 1.) Launch the product system in the easiest way possible today. Goal - 2.) you will operate as a co founder..." | 2026-10-22 |

## Systems

| Fact | Status | Source | Date |
|---|---|---|---|
| GitHub sign-in app exists and its keys are in Vercel | stated | Aaron: "it is in vercel for git hub" (Oct 17); "I gave you everything to set up sign in with GitHub" (Oct 23) | 2026-10-23 |
| X sign-in app exists; its OAuth 2.0 Client ID and Secret are in Vercel, but not under the names the code reads (X_CLIENT_ID, X_CLIENT_SECRET) | stated | Aaron: "Those bother are in Vercel They Just are not named that way." | 2026-10-23 |
| Claude set up the start-of-something-great project in Vercel for Aaron when the site was first built (Oct 13 to 15), so the Vercel connector could reach that project then; by Oct 22 it could not. When and how the grant narrowed is not known; the Vercel audit log or Anthropic support can tell | stated | Aaron: "You set everything up with vercel for this project." | 2026-10-23 |
| Vercel team ChiefOS (chief-os) is on the Pro plan, which the every-minute timers need | checked | Aaron's screenshot of the project overview | 2026-10-23 |
| Claude's Vercel connection is the official claude.ai Vercel connector (directory, standard address), and its grant covers only the project chief-os-labs: project lists, team-wide deployment lists and direct lookups all exclude start-of-something-great. Fix: Aaron disconnects and reconnects it choosing all ChiefOS projects, then starts a new session. Whether it could see the project earlier is unknown | checked | ListConnectors; list_projects, list_deployments (team-wide), get_deployment, filter_project_envs | 2026-10-23 |
| Production deployments of start-of-something-great are served from the chief-os team | checked | GitHub deployment statuses (…-chief-os.vercel.app) | 2026-10-23 |
| The live site is closed: sign-in answers "Sign-in is not switched on here yet." because no database is set | checked | curl https://dayonegreat.com/auth/github/start (503) | 2026-10-23 |
| The public pages, API and MCP server work on the live site | checked | curl of /, /api/status, /api/proposals; MCP tools/call | 2026-10-23 |
| Production setup has never run, so no database is connected to the live site | checked | GitHub API: the Production setup workflow has 0 runs; sign-in is off | 2026-10-23 |
| The database no longer needs any secret: from PR 2 it changes only through the runner, which checks GitHub's identity token (db/README.md) | checked | .github/workflows/database.yml, supabase/functions/dog-migrate | 2026-10-24 |
| Aaron's GitHub account ID is 304218593 | checked | GitHub API, repository owner | 2026-10-23 |
| Claude's GitHub access: admin on the repository; can read PRs, issues, contents, deployments, rulesets and workflow runs and push branches; the session proxy refuses secrets, variables, environments and collaborators (403) | checked | GitHub API path by path; push dry-run | 2026-10-23 |
| main has one active ruleset ("The Start of Something Great Rule Set") and no classic branch protection | checked | GitHub API rulesets; branches/main/protection 404 | 2026-10-23 |
| Supabase project "Day One Great" (nksagchwpyljvjiwolmp, us-east-1) is healthy and has no migrations applied: the database is empty | checked | Supabase get_project and list_migrations | 2026-10-23 |
| The terms of service and privacy policy were approved by Aaron in his doc on Oct 14 and updated for Release 2 as /terms and /privacy in PR #36 | checked | Claude Docs "Day One Great: Terms and Privacy (draft for counsel)"; commit 708722d | 2026-10-23 |
| PR #36 (security-batch-1 → main) holds all Release 2 work; checks green; nothing else is open | checked | GitHub API | 2026-10-23 |
| 15 commits on Oct 17 carry Aaron's name (MyChiefOS) but were made by a Claude session (Fable 5.1); GitHub shows them Unverified. Three reviews found no harmful change | checked | GitHub API commit verification; red, blue and scalability reviews | 2026-10-22 |

## Launch path (what is left, in order)

The giscus and JEVs plan (USE-CASES.md), from Oct 24. The previous launch path (setup secrets, Production setup, PK13) is replaced and kept in git history.

| Step | Who | Status |
|---|---|---|
| PR 1: plan and guards (USE-CASES.md rows 14 and 19, giscus origin lock) | Claude builds; Aaron merges | done: PR #37, merged Oct 24 |
| PR 2: database fresh build without passkeys, and the JEVs gate (rows 15 and 16) | Claude builds; Aaron merges | open |
| After PR 2: deploy the runner and gate from the merged commit; reset; verify | Claude, from the merge | open |
| PR 3: JEVs live in shadow mode, alerts only (rows 3 to 10, 12, 13, 17, 18) | Claude builds; Aaron merges | open |
| PR 4: JEVs enforce mode (Aaron's go-live merge) | Claude builds; Aaron merges | open |

## Aaron's instructions (status)

Every instruction Aaron gives that changes the build, with its status, so none is quietly left undone (USE-CASES.md row 14). Status: done, in plan (with the PR), or open.

| Instruction (Aaron's words) | Date | Status |
|---|---|---|
| "We will only allow Github users in phase 1. Update that design and remove pass key." | 2026-10-23 | in plan: PR 2 removes them from the code and, on its run after merge, from the live database (not carried out on Oct 23) |
| "Can you use the same capability for Join as you do for giscus on/talk?" | 2026-10-23 | done: PR #36 |
| "put the Jevs between the dayongreat.com site and database login" / "wapp it around the database" | 2026-10-23 | in plan: the GitHub token check that guards the database ships in PR 2; the JEVs gate's routes ship with their first caller, PR 3 |
| "A denial of service against our selves is not the goal." (checks alert, never lock out) | 2026-10-23 | in plan: JEVs never refuses; shadow first (PR 3) |
| "NO preview systems" | 2026-10-24 | done: preview dropped from the roadmap and status (PR #37) |
| "Auth needs to throught giscus on /talk and /join" | 2026-10-24 | done for posting; JEVs on giscus posts in PR 3 |
| "Can you clear the database tables and start over with a fresh build" | 2026-10-24 | in plan: PR 2 (the reset runs on merge, refuses if any real row exists) |
| "I only approve PRs" | 2026-10-24 | in force |
| "I want the it corrected from your side. So when you send a PR its verified without failures." | 2026-10-24 | done: push guard; CI PR guards (PR #37) |
| "I want a PR that spells out any chages." | 2026-10-24 | in force: every PR description lists every file changed and what happens on merge |

## Open for Aaron (ask once; record the answer here)

| Question | Asked | Answer |
|---|---|---|
| Keep the 24-hour deletion rule (RK62), or switch to the oldest-method rule | 2026-10-22 | |
| Charter section 3 says each PR "is built on the one before it". Change it to "every PR targets main" (harness rule 1) | 2026-10-23 | |
| Is PK13 (two passkeys, one a hardware key) required for today's launch, or is one synced passkey enough until a hardware key arrives | 2026-10-23 | |

## Parking list (no named owner yet; not built until one is named)

| Item | Raised by | Date |
|---|---|---|
| Security batch 2 (recording refused attacks, RK13 test rewrite, RK40 check, timer heartbeat) | Claude and the blue team | 2026-10-22 |
| Stage-drift check that needs no GitHub permission | Claude | 2026-10-22 |
| Redeploy promotes after a Vercel rollback; passkey "busy" crash fix | Claude (scalability and red team reviews) | 2026-10-22 |
| A separate GitHub identity for Claude (RK71) | Claude | 2026-10-17 |
| Agent card (what an agent discloses about its owner) | Claude | 2026-10-22 |
| Duet-like brief and inbox tool | Claude | 2026-10-22 |
| Google indexing fixes (/shipped and /proposals rendered in the page) | Claude | 2026-10-22 |
