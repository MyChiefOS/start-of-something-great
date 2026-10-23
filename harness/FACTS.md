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
| Launch the product system in the easiest way possible, with Claude operating as a can-do co-founder | stated | Aaron: "Goal - 1.) Launch the product system in the easiest way possible today. Goal - 2.) you will operate as a co founder..." | 2026-10-22 |

## Systems

| Fact | Status | Source | Date |
|---|---|---|---|
| GitHub sign-in app exists and its keys are in Vercel | stated | Aaron: "it is in vercel for git hub" (Oct 17); "I gave you everything to set up sign in with GitHub" (Oct 23) | 2026-10-23 |
| X sign-in app exists; its OAuth 2.0 Client ID and Secret are in Vercel, but not under the names the code reads (X_CLIENT_ID, X_CLIENT_SECRET) | stated | Aaron: "Those bother are in Vercel They Just are not named that way." | 2026-10-23 |
| Vercel team ChiefOS (chief-os) is on the Pro plan, which the every-minute timers need | checked | Aaron's screenshot of the project overview | 2026-10-23 |
| Claude's Vercel connection is the official claude.ai Vercel connector (directory, standard address), and its grant covers only the project chief-os-labs: project lists, team-wide deployment lists and direct lookups all exclude start-of-something-great. Fix: Aaron disconnects and reconnects it choosing all ChiefOS projects, then starts a new session. Whether it could see the project earlier is unknown | checked | ListConnectors; list_projects, list_deployments (team-wide), get_deployment, filter_project_envs | 2026-10-23 |
| Production deployments of start-of-something-great are served from the chief-os team | checked | GitHub deployment statuses (…-chief-os.vercel.app) | 2026-10-23 |
| The live site is closed: sign-in answers "Sign-in is not switched on here yet." because no database is set | checked | curl https://dayonegreat.com/auth/github/start (503) | 2026-10-23 |
| The public pages, API and MCP server work on the live site | checked | curl of /, /api/status, /api/proposals; MCP tools/call | 2026-10-23 |
| Production setup has never run, so no database is connected to the live site | checked | GitHub API: the Production setup workflow has 0 runs; sign-in is off | 2026-10-23 |
| The three repository secrets for Production setup (MIGRATION_DATABASE_URL, MIGRATION_DATABASE_CA, VERCEL_TOKEN) are not set yet | assumed | Claude can't see them: the session's GitHub proxy refuses the secrets API (403) | 2026-10-23 |
| Aaron's GitHub account ID is 304218593 | checked | GitHub API, repository owner | 2026-10-23 |
| Claude's GitHub access: admin on the repository; can read PRs, issues, contents, deployments, rulesets and workflow runs and push branches; the session proxy refuses secrets, variables, environments and collaborators (403) | checked | GitHub API path by path; push dry-run | 2026-10-23 |
| main has one active ruleset ("The Start of Something Great Rule Set") and no classic branch protection | checked | GitHub API rulesets; branches/main/protection 404 | 2026-10-23 |
| Supabase project "Day One Great" (nksagchwpyljvjiwolmp, us-east-1) is healthy and has no migrations applied: the database is empty | checked | Supabase get_project and list_migrations | 2026-10-23 |
| The terms of service and privacy policy were approved by Aaron in his doc on Oct 14 and updated for Release 2 as /terms and /privacy in PR #36 | checked | Claude Docs "Day One Great: Terms and Privacy (draft for counsel)"; commit 708722d | 2026-10-23 |
| PR #36 (security-batch-1 → main) holds all Release 2 work; checks green; nothing else is open | checked | GitHub API | 2026-10-23 |
| 15 commits on Oct 17 carry Aaron's name (MyChiefOS) but were made by a Claude session (Fable 5.1); GitHub shows them Unverified. Three reviews found no harmful change | checked | GitHub API commit verification; red, blue and scalability reviews | 2026-10-22 |

## Launch path (what is left, in order)

| Step | Who | Status |
|---|---|---|
| Merge PR #36 | Aaron | open |
| Add the three repository secrets | Aaron | open |
| Run Production setup: steps database,keys,stage,redeploy, stage public | Aaron (the go-live decision) | open |
| Sign in at /join, then run setup with step admin and the member_id from /auth/me | Aaron, then Claude gives the exact inputs | open |
| PK13: at least two passkeys on Aaron's account before go-live (one synced, one hardware key), recorded in OPERATIONS.md | Aaron | open |
| Approve the pending criteria (N1 to N11, R16, R33, SA1 to SA12; ROADMAP.md) | Aaron | open |
| Smoke test: a second GitHub account signs up and posts. First-post review stays on while JEVs is in shadow mode (standing decision) | Aaron or a friend | open |
| Update ROADMAP.md with the actual launch date next to the Nov 6 and Nov 20 targets | Claude | open |
| Optional, not blocking: X keys under the names X_CLIENT_ID and X_CLIENT_SECRET (or tell Claude the names, and the code accepts them); /join already says X is coming soon | Aaron | open |

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
