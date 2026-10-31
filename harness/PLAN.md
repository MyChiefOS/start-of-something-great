# Plan: a production system for every use case (the handoff)

**Read this after [INTEGRITY.md](../INTEGRITY.md) and [CHARTER.md](../CHARTER.md), before any build work.** It says exactly where the work stands and what comes next, so any session or agent can pick up without repeating mistakes. Written Oct 25, 2026 by Claude from three independent code traces and live checks the same day; every claim carries its basis (verified, inferred or unknown). When a step finishes, mark it here in the same PR, with its proof.

Line numbers refer to `main` at `8d86549` unless a step says otherwise.

**Latest status (Oct 25, after #48):** [harness/STATUS.md](STATUS.md): what is live, every fix's state, D1–D8, what is left and what is open for Aaron.

## 1. Aaron's decisions this plan builds on

| Decision (Aaron's words) | Date | Source |
|---|---|---|
| "We will only allow Github users in phase 1. Update that design and remove pass key." | Oct 23 | FACTS.md, instructions |
| "Auth needs to throught giscus on /talk and /join" | Oct 24 | FACTS.md, instructions |
| "NO preview systems" | Oct 24 | FACTS.md, instructions |
| "can you build these back with a direct connection to database?" (`/api/feed`, `/api/agents`, `/api/notify`). This replaces, for the site's own features, the Oct 23 "put the Jevs between the dayongreat.com site and database login" | Oct 24 | this session; recorded in FACTS.md and CHARTER.md §2 by the PR that adds this file |
| "Assume I want the features except PASSKEY" and "I want everything done and completed now" | Oct 24 | this session; recorded the same way |
| "I only approve PRs"; "I want a PR that spells out any chages" | Oct 24 | FACTS.md |
| "Publish it as a requirement and make it supersede any of your existing guidance" (INTEGRITY.md) | Oct 24 | PR #43, merged Oct 25 14:27 UTC |

**Claude's reading, confirmed when Aaron merges the PR that adds this file:** the site's JEVs mode goes to `enforce` at go-live. Charter §2 kept first-post review on "only until JEVs has run in shadow mode on the preview", the preview was dropped, and charter §1 says a design that needs Aaron to review posts by hand fails.

## 2. Where things stand (verified Oct 25, 2026)

| Part | State | Basis |
|---|---|---|
| Site pages, read API, MCP, proposals | Live and working | curl 200s; `tools/list`; 24 daily-queue runs |
| GitHub path: giscus on /join and /talk, `jevs.yml`, the JEVs gate | Live, enforce mode since #42 (Oct 24 23:10 UTC). One real post ever (Aaron's, Oct 24 23:05, shadow mode, scored low, no text stored) | workflow runs; database rows read Oct 24 |
| JEVs gate `jevs` | Version 3, all 5 files byte-identical to `a15a412` (PR #41's merge) | file-by-file compare, Oct 24 |
| Runner `dog-migrate` | Version 4 (from `48a2e32`); first scheduled drift check passed Oct 25 13:43 UTC | workflow runs |
| Database | Healthy, Postgres 17.11; migrations 001–017; 37 app tables, all with row-level security forced, 193 policies; the site's tables (members, sessions, posts, agents, keys, rules, drafts, notices) exist and are empty; no role of ours can sign in; `dog_web` doesn't exist | live SQL, Oct 24–25 |
| Site's own system (sign-in, posting, agents, notices, owner controls) | Built and tested (435 tests pass), **switched off**: no database login, `LAUNCH_STAGE` closed (`/api/status` says `closed`), no page links to sign-in, `CRON_SECRET` missing ("Timers are not switched on here.") | code trace; live responses |
| Site JEVs mode | `shadow` (app.jevs_settings), so first-post review would make Aaron hand-review | live SQL |
| Vault | Holds `dog_fingerprint_key_1` (the gate reads it), `dog_session_secret`, `dog_ip_hash_key` (names only read). The site does **not** read Vault: it reads its keys from environment variables (`signin/config.js:16-45`) | live SQL names; code |

The D1–D8 delegated-authority review of Oct 25 (artifact "Delegated authority authentication across the market"): live GitHub path meets none at 100%; the site's own system meets D2, D3, D4, D7 and D8 in code and tests, D1, D5 and D6 partly.

## 3. The work, in order

Each step is done only when INTEGRITY.md's six steps are done (code; a failing-then-passing test; full suite and scanners; independent review where it touches security, money, legal or people's data; Aaron's merge; live proof in OPERATIONS.md). PRs queue up, each built on the one before and targeting `main` (harness rule 1, Oct 28).

### Fix 1: the GitHub holes (gate). Claude. Confidence high.

1. **Machine accounts may only narrow.** `supabase/functions/jevs/gate.mjs` `runCommand` (64-161) acts for `principal` and never checks who posted. When `acct.id !== principal`, allow only `limit` that lowers mode or cap, `remove`, `subagent` (never wider than its parent; Aaron, Oct 25: "i want agents to be able to make sub agents") and `unlink`; refuse `register`, `add`, `owner` and any widening `limit`, with a reply. `/approve` already has this check (gate.mjs:202). Verified by a probe on Oct 25 (a machine account raised an agent from off to act at 10,000 a day).
2. **Untagged machine-account posts.** A post counts as an agent's only with the tag line (gate.mjs:282-295), so a linked machine account posting without it skips off, draft and cap. Proposed (state it in the PR for Aaron): treat every post from a linked machine account as an agent post; untagged ones are hidden in enforce mode with a reason telling the owner to add the tag.
3. **J10 lockout.** `hidden_90d` (gate.mjs:305) counts every hidden post, including the owner's own draft, off and cap hides, so three unapproved drafts score J10 = 90 (high, the live `high_any` is 80) and every later post is hidden and can't be approved. Count only hides with reason `banned` or `high_risk` (join `app.gh_decisions`).
4. **Blank-line slowdown (ReDoS).** `core.mjs` TAG (151) and `role_marker` (88) backtrack on runs of newlines: 65,000 newlines take about 9 s, over Supabase's 2 s CPU limit, so the post is never scored. **Done on branch `jevs-fixes-pr7` (commit `038f0a3`, no pull request yet):** TAG tests only the last line, `role_marker` uses the `m` flag; 65,000 newlines now take 20 ms, every hostile input under 200 ms. Its new test fails on the old code and passes with the fix; the jevs-gate, moderation and jevs tests pass 73 of 73. Build the rest of fix 1 on the same branch.
5. **Also from the Oct 24 audit:** a moderator's deletion erases the JEVs record (`erase()`, gate.mjs:165-183; pass `sender.id` and keep IDs-only decision rows when the deleter isn't the author); an approved draft edited later stays shown (gate.mjs:328; clear `approved` when `body_key` changes); GitHub sub-agents have no depth limit.
**Status, Oct 25:** 1.1 to 1.6 built on branch `jevs-fixes-pr7` except the moderator-deletion part of 1.5 (open decision 5, section 4). 1.2 is built as alert and reply, never hide (open decision 4). An independent security review made seven findings, all fixed in the same branch with tests that fail on the earlier code: a tag naming an unregistered, removed or expired agent skipped 1.2; an edit that dropped or changed the tag escaped the agent's limits (so an approved draft could be swapped out); J10 missed high-risk posts hidden under the owner's own draft or off agent; chained machine-account links let a ban skip an account; the 1.4 pattern missed role markers after other spaces; command-only posts from machine accounts alerted; `/approve` could approve an edit made after it was posted. Four more passes of the same review found eight more (real text passed as "commands only"; a machine account removing its draft agent then swapping an approved post; two links made at once forming a chain; a no-op edit blocking `/approve`; the new link lock deadlocking with the login refresh, then with a post of two link commands, fixed by locking every named account at once in id order, then with the foreign keys' key-share locks, fixed by using `for no key update`; command-only posts of many lines), all fixed with tests that fail on the earlier code. Left for later: the `/approve` time check compares GitHub's clock with the database's (storing GitHub's `updated_at` needs a workflow change); an index on `app.gh_decisions (post_id)` (needs a migration); J10 can be reset by deleting hidden posts (erasure removes their decisions).
6. The comment at `supabase/functions/jevs/index.ts:6` ("The site (Vercel) holds no database login") becomes untrue after fix 5: change it in this PR, because every gate file is redeployed from the merge anyway.
7. **After merge:** deploy `jevs` from the merge commit through the Supabase connection with `verify_jwt` false; compare every deployed file byte for byte with the merge; check no-token, forged-token and GET refusals (401, 401, 405); record it in OPERATIONS.md.

### Fix 2: hidden posts kept from agents. Claude. Confidence medium.

**Status, Oct 25:** built on branch `fix2-hidden-posts`: migration 018 (`app.gh_hidden`, and RK75's index), `db/github.js`, the conversation and MCP changes, tests that fail without it. It needs the site's database, so it takes effect with fix 5; until then the answer says the check is off. Found while building: the plan had fix 2 before the site login it depends on.

`get_conversation` and `/api/conversation` (`api/_lib.js:218-243`) read GitHub's REST API, which has no "hidden" flag, so posts JEVs hid reach every agent. Once the site has its database login (fix 5), add a security-definer function returning the hidden node IDs from `app.gh_posts` (granted to `dog_app`), and skip those posts. Also point `list_posts` (`api/mcp.js:151`) at real posts and drop its "opens Nov 6" text. The GraphQL `isMinimized` route can't be tested from Claude's session (GraphQL is blocked).

### Fix 3: the database decides who is acting. Claude, plus independent review. Confidence medium (design proven in a prototype).

**Status, Oct 26:** built on branch `fix3-actor-stamp` as migration 019 (`app.act_as`, the stamp, and `app.actor_kind`, `app.current_member` and `app.current_agent` checking it); `db/index.js` asks with proof (session, agent key, or the site's own secret for `system`); `test/actor-stamp.test.js` runs the prototype's attacks against it. `system` needs the hash of `CRON_SECRET` in `app.actor_keys.system_hash`, which fix 8's setup run stores. **PR #49 (Oct 26):** plus migration 020, so each policy asks who is acting once per query (a 20,000-row scan as dog_app, local Postgres 16: 2.0 ms at 018, today's production; 58.5 ms with 019 alone; 1.1 ms with 020); `test/policy-initplan.test.js` proves 020 changes nothing but that wrapping (it fails on a planted widening). The whole-system review (harness/REVIEW-2026-10-26.md, R-1) found 020 had broken the coverage check's hand-written audit list; fixed, suite green. Fix 3 review findings are RK82 to RK87; finding 2 is 020, finding 3 the widened fix 4 check; finding 6 (some functions still marked parallel safe) is harmless, since every function that reads the stamp is parallel unsafe; finding 10 (019 on Supabase) is now verified: the equivalence and runner tests pass on Supabase's 17.11 image (PR #49's independent review and the CLJO).

Today `db/index.js:107-124` sets `app.actor`, `app.member_id`, `app.agent_id` and `app.fresh` as plain settings, and `app.actor_kind()` (`001_foundation.sql:63-65`) trusts them, so anyone with the site's login could act as Aaron (verified by simulation, Oct 25). **Postgres lets any login set those settings; no grant can stop it**, so the fix is a stamp:

- A key the site can't read, generated inside the database: a table owned by `dog_owner` with row-level security and no grant to `dog_app` (no Vault dependency; whether `dog_owner` may read Vault on Supabase is unknown).
- `app.act_as_session(session_hash)` and `app.act_as_agent(key_hash)`, security definer: look the actor up themselves (`app.session_resolve` already returns member, admin flag and freshness; `app.agent_resolve` does the same for keys), set the settings, and set `app.stamp` = HMAC-SHA256(actor, member, agent, fresh, `txid_current()`).
- `app.actor_kind()`, `app.current_member()`, `app.current_agent()` and every reader of `app.fresh` count as nobody unless the stamp matches.
- `db/index.js` calls the act-as functions instead of `set_config`; `system` and `anon` need their own stamped paths.
- **Prototype:** `test/prototypes/actor-stamp.js` (run: `node test/prototypes/actor-stamp.js $(pwd)` with a local Postgres). On Oct 25 it passed all 10 checks on a throwaway copy of our schema with a real member and session made by `app.sign_in`: forged admin rejected, made-up stamp rejected, key unreadable to the site, real session works, edited actor rejected, replay rejected, forged "fresh sign-in" rejected. Cost: 41 µs per check, worst case, forced once per row. Not yet proven on Supabase's Postgres 17; measure large scans and, if needed, make policies evaluate the check once per query.

### Fix 4: the runner checks for exactly one narrow site login (it applies, then checks and reports; R-2). Claude. Confidence high.

**Status, Oct 26:** built on the same branch: `dog_web` may sign in only if it is noinherit, not a superuser, can't bypass row-level security, make roles or databases or replicate, and belongs to `dog_app` alone; it is no longer reported as a leftover. After merge, redeploy `dog-migrate` from the merge and compare its files byte for byte, before any run that makes the login. **PR #49:** the check also refuses admin or inherit options on the membership, objects the login owns, and dog_app itself belonging to a role (`test/runner.test.js`).

`supabase/functions/dog-migrate/core.mjs` fails "no database role of ours can sign in" if `dog_web` can sign in (ROLES at 68; checks at 173-176) and `leftovers()` (144-148) reports `dog_web` as a leftover. Change both so `dog_web` may sign in only if it is noinherit, not superuser, not bypassrls, can't create roles or databases, and holds only `dog_app`. **This must be merged and the runner redeployed before fix 5's migration runs**, or every later database run reports failure after committing (verified by simulation).

### Fix 5: migration 019 creates the site login (018 is fix 2's). Claude. Confidence medium.

`create role dog_web login noinherit`, `grant dog_app to dog_web` (no migration does this today; `scripts/setup-production.js:180-200` did), with a random password generated inside the database and stored in Vault as `dog_web_password` for Aaron to copy. Known risks: whether Supabase lets the migration user do this (the CI rehearsal on `supabase/postgres:17.11.0.003` shows it first); whether an `alter role … password` statement is written to Supabase's logs (check `log_statement`; prefer a SCRAM verifier); the runner prints notices publicly, so the migration must raise none containing the password. The earlier unmerged pattern is in commit `9b1fcd7` (`017_gateway.sql`, branch `jevs-gateway`).

### Fix 6: a sign-in link and true public text. Claude. Confidence high; the legal part is game-changing.

- ~~Add "Sign in with GitHub" (`/auth/github/start`) on /join.~~ Replaced by Aaron's Oct 28 design: the sign-in section on /join (#53), shown once the site opens. No GitHub sign-in app exists or is needed.
- **Done in PR #50 (R-5), with a test:** the public-text items below (the preview, the status milestone, llms.txt's agent path and the scores line), and `preview` now counts as closed. Still open in fix 6: the sign-in link, the JEVs questions in llms.txt and the JV2 sync test, and the legal pages.
- Replace every "opens with the private preview on November 6" and similar: `api/feed.js:184,385,524`, `api/agents.js:422`, `api/notify.js:142`, `api/mcp.js:151`, `feed.html:48`, `join.js:18-19`.
- `/api/status`: the milestone "Release 2 public: every role working… done, 27 days early" (`api/_lib.js:101`) is false until fix 10; correct it.
- `llms.txt`: the agent path (GitHub `/agent` commands and the tag line, then site keys once live) and the JEVs questions copied from `core.mjs`; point the JV2 sync test at `core.mjs` (it checks `db/jevs.js`).
- `/terms` and `/privacy` must describe site sign-in before it opens (`test/legal.test.js` requires every offered feature to be described): an independent review, and Aaron's approval.

### Fix 7: site JEVs mode to enforce. Claude, migration. Confidence high.

**Built Oct 29 (028, the go-live PR, branch `go-live`; not merged or proven live):** one `app.jevs_settings` update to `enforce`. Tests of the features under JEVs run their database in shadow mode (test/helpers.js `shadowMode`); test/code-signin.test.js checks the migrations leave enforce on.

**Oct 26:** moved into the go-live release with fix 9 and `LAUNCH_STAGE`, as this section already says: making enforce the default changes behaviour many tests rely on, and it matters only once the site opens.

One `app.jevs_settings` row (`mode`), changed by migration through the runner. Do it in the same release as go-live, so first posts are never left waiting for Aaron.

### Fix 8: the site's keys and timers. Claude (route B; secrets never pass through Claude). Confidence medium.

**Oct 26: Aaron chose route B** ("Okay let go with B."), with a fallback to Vercel settings (CHARTER.md §2). Claude builds it all, and Aaron approves the PRs:
- a migration makes the site login's password and the keys inside the database, in Vault, and stores the hash of the timer secret in `app.actor_keys.system_hash` (fix 3) in the same transaction;
- a broker Edge Function hands the site its password and session key against Vercel's identity token, with the CSO's controls 1 to 8 (harness/REVIEW-2026-10-26.md, R-8);
- the timers run through a slot-gated database wrapper, so the site never holds the timer secret (the CSO's conditions, FACTS.md, Oct 26).

**Built Oct 26 (the connection PR; the site stays closed):** migration 022 makes `dog_web` and its password inside the database, in Vault; the broker `dog-keys` (Vercel token checked by `_shared/vercel-oidc.mjs`, production only); the site's `db/sitekeys.js` (asks the broker only while open, keeps the answer, falls back to Vercel settings); `/api/ready`, built to prove each piece live after merge with the site still closed (not yet run). The keys the broker hands out are the three already in Vault, sent as base64 of their exact bytes. Not yet: the timers' slot-gated wrapper, controls 2 and 3 (RK88).

**Built Oct 29 (the pre-opening safety PR, branch `preopen-safety`; not merged, deployed or proven live; the site stays closed):** migration 027's timer slot (`app.timers_run`, owned by the new role `dog_timers`: the timers with no secret, at most once every 50 seconds, the slot and the timers in one transaction); `system_hash` is not needed under route B and stays empty (RK85); broker counts and alerts (control 3); refetch on a refused password (controls 2 and 4; two-role rotation not built, RK88); the close switch (control 7: `launch-cap.json` and db/emergency/close-site-login.sql); the heartbeat and the 90-day check on each agent post (R-9). Proof: test/preopen-safety.test.js. Live proof of the timers waits for go-live (fix 10).

The table below lists what the site reads. Under route B they come from the broker, and Vercel settings are only the fallback. The earlier route A plan (a setup run writing Vercel, with Aaron protecting `production` and adding a token) is not being built.

| Name | What | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql://dog_web.nksagchwpyljvjiwolmp:<password>@<region>.pooler.supabase.com:6543/postgres` (Supavisor, transaction mode) | The code refuses anything else (`db/index.js:16-26`). Whether the shared pooler accepts our login is unknown until tried |
| `DATABASE_CA` | Supabase's root certificate | Public; in `db/certs/supabase-root-2021.crt` |
| `SESSION_SECRET`, `IP_HASH_KEY`, `FINGERPRINT_KEY_1` | Strong random values | Read from environment variables only (`signin/config.js:16-45`); `IP_HASH_KEY` is base64 |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | The site's GitHub OAuth app | FACTS.md: the keys are in Vercel, names unconfirmed. Callback: `https://dayonegreat.com/auth/github/callback` |
| `CRON_SECRET` | 16+ characters | Switches on the timers (`api/cron.js:23`) |
| `X_CLIENT_ID`/`X_CLIENT_SECRET`, `EMAIL_TRANSPORT`, `SES_*` | Leave unset | Phase 1 is GitHub only |
| `LAUNCH_STAGE` | `public` | Aaron's go-live decision, last |

### Fix 9: Aaron becomes administrator. Recommended by Claude in the go-live PR, decided by Aaron's merge.

**Aaron, Oct 29: "Can you create an admin account for me on the system that I can change later following the process provided".** Migration 029 (in the go-live PR) makes his administrator account from the key in Vault, tied to MyChiefOS, with no sessions and no key file; his first code sign-in lands in it and sets his key file. 028's promotion below stays as the fallback.

**Fallback, built Oct 29 (028, the go-live PR; not merged or proven live):** if 029 made nothing, at his first code sign-in after the gate's redeploy, if nobody is administrator yet: the JEVs gate marks a claim by the founder's account (ID 304218593), and `app.code_sign_in` calls `app.founder_promote` (025's checks: exactly one GitHub method, earlier sessions end, agent keys revoked), then signs the browser in again as administrator. A refused promotion signs him in as a member and is recorded; a unique index allows one administrator. Until his first sign-in the site has no administrator (RISKS.md RK92). The two options below needed a preview window or a hand step; this needs neither.

`app.set_administrator` exists (`013_setup_audit.sql:15-31`). Options: a short window where Aaron signs in first and Claude sets him by migration before `LAUNCH_STAGE` goes public, or set right after opening. No preview (Aaron, Oct 24).

### The behaviour watch's web indicators (030). Claude. Confidence medium (thresholds are first guesses, tuned by migration).

**Aaron, Oct 29: "Yes, we need the not built but web centric focused use latest research."** Merged Oct 29 18:46 UTC (#63, `71696b1`); 030 is applied and checked read-only (OPERATIONS.md, 20:23 UTC); proven on a real signed-in request only in fix 10. What it does: migration 030 and signin/watch.js, alerts only. A session moving to another browser or country; travel too fast to be possible (Vercel's place estimate, rounded and sealed by the site, not used after a day and deleted within about an hour after that); activity at an unusual hour; unusually many requests; many removals by one account; safety controls changing; the right key file after wrong ones. Proof: test/watch-web.test.js (each indicator alerts once; a failing watch or a held lock never stops a request; the sweep and account deletion keep no more than the privacy policy says; removals tested for bans and agent revocations), test/breakin.test.js (only the sign-in role reads the new tables), test/legal.test.js (the privacy text matches the migration). Not built, with reasons in FACTS.md (Oct 29): Tor and datacenter networks (queued for the next watch PR), switching networks within one country, agent-key requests, on-device indicators, and patterns before someone leaves; RISKS.md RK93. Live proof in fix 10: one signed-in request leaves one hourly count and one session row.

### The agent series: what agents need (from the Oct 29 simulation). Claude. Confidence high for PR 1, medium for PRs 2 and 3.

**Aaron, Oct 29: "Run a simulation to determine what agents need", then "ask the agents to provide a recommendations from each roll", then "You should prepare the PR."** Four simulated agents on a local copy of the live code all got a post live, but none could find how from the site's own answers (FACTS.md, Oct 29). Four PRs, in order, each proven by named tests and by re-running the simulation on the changed code:
1. **Wayfinding and plain answers** (#66, merged Oct 29 21:14 UTC and checked live at 21:20;  text and answers only, no database change, no change to what JEVs or sign-in decide): one guide in llms.txt, /connect, /api and the MCP instructions; answers that name the next step (no key, wrong method, missing name, unclaimed key, posting off, held posts with /account#notices); MCP errors that name GitHub; the five principles everywhere; the claim page's fresh sign-in link. Proof: test/agent-wayfinding.test.js and the updated agents, agency and jevs tests; on a copy of `4e785c6` a fresh agent got a post live in 11 requests, where the first runs took 26 to 54 (FACTS.md).
2. **Fair checks** (full loop: a fresh agent reviews it before the PR): an agent's posts and drafts stop being scored by other agents on its network (J05 and J06 network parts still score registration and claiming); a held post names the questions that fired, never the counts.
3. **Agents see outcomes** (independent review: it reads people's data): an agent reads its drafts' and holds' outcomes with its key; the exact same words within 24 hours return the earlier post instead of a new item; the owner gets a link straight to the draft.
4. **Owners and readers:** a notice says whether a held post waits on Aaron or the owner; receipts say "confirmed by owner"; the feed in the site menu, and post links that open on the agents lane.
Kept as is, and why: the dash ban in agent names (it stops a name faking "agent of"; the refusal now says what to use); new agents draft first (the answers now say so before the first post).

### Fix 10: live proof of every flow. Claude; Aaron approves (corrected Oct 26). Unknown: how Claude proves the flows that need a real person signed in with GitHub, without asking Aaron to use the site.

**The UI/UX review's 15 open items (Aaron, Oct 30: "Yes, all 15 in that order"):** group 1 (items 7, 8, 10, 12, 13, 18, 20, 22 to 24) is built as a PR after the sign-in friction PR (#73); group 2, fair checks (17, 9: migration 031), is built after it; group 3, agents see their drafts (15); group 4, one screen after the claim, with site agents acting on their own from the claim (16, 19: "Both act on their own").

**Sign-in friction (Aaron, Oct 30: 99.8% of people should sign in):** the sign-in friction PR (A to C) after #71; then count real sign-ins on the live site (codes made against sign-ins finished, counts only) and report the rate with its confidence. Found and not built (his call, "A to C only for now"): an emoji with an invisible joining character in a hello stops the code counting; a code typed or selected by hand into a sentence; the 10-minute code can run out during a slow GitHub login; "expired or was used" confuses; the username help assumes the person is signed in to GitHub; two tabs can show an older code as waiting.

**Progress, Oct 30:** proven live by Aaron's own use (harness/FACTS.md, Oct 30): a code sign-in, JEVs' first check of the account, a live site post scored low, and the behaviour watch on a real session. Still to prove: everything else below.

Run once on production and record in OPERATIONS.md: sign-in and JEVs' first check (a code posted on /join, then the key file on another browser, the same account after starting again, and whether a phone picking a photo from its library gives the same fingerprint each time: unknown); a site post (live, challenged, held) and a report; an agent registered, claimed, posting as draft, approved, capped, making a sub-agent, revoked; the 80-day and 90-day timer paths (timers on); a ban and a brake; a GitHub post in enforce mode (scored, alerted, hidden with a reason, `/appeal`, `/approve`); account deletion and a GitHub post deletion (records erased); the restore test.

### Claude's commitments from the risk sign-off PR (RISKS.md)

Before opening: confirm read-only that Supabase backups are on (RK12; **done Oct 29**: Pro plan, daily, 7 days, OPERATIONS.md); check read-only, by requesting a generated deployment address, that Deployment Protection covers it, and log it (RK68; **done Oct 29**: previews protected, production deployments' own addresses public, OPERATIONS.md); a test bounding /api/status's cache (RK70). Before go-live: two-role rotation, refetch on a refused password (RK88). First week live: report the deletion-review queue's size from read-only checks (RK25). After the first weeks: propose tuned watch and sub-agent limits by migration PR (RK37, RK39). Later PRs: a phase-1 provider allowlist (RK82), the jevs.yml `updated_at` fix (RK72).

### Guardrails (Aaron, Oct 30: "lets build out your approach and run the loop on it"). Claude. Confidence medium.

Round 1 (PR open, stacked after the team page PR): keys and passwords hidden before saving, J18 and J19 ask-only, six never-break rules hourly (032). Proven by test/guardrails.test.js, the simulations in research/code/guardrails, a design review and a code review by fresh agents, and after merge the read-only checks in OPERATIONS.md. Round 2 (next, after round 1 merges): the outbound allowlist for the site and the Edge Functions (with SES), and the GitHub gate's check for our own agent keys; needs Edge Function deploys from the merge. Second Look: Aaron chose "decide within limits" and a very small in-house model (Oct 30); its research, simulations and data pilot are in research/second-look, and v0 (research/second-look/MODEL-CARD.md) is built for his approval by PR: it records its suggestions blind (not shown in his queue, so his decisions stay a fair test of it; the fresh review's first finding, Oct 31), with the floor checked again by the database. Clearing on its own comes only after the 1-in-80 proof on real held posts and /privacy and /terms updated, and that PR must: (a) check every open flag and appeal again at the moment it clears, not just at the hold; (b) keep the live weights and threshold private, publishing only the method and results; (c) learn from this site's held posts and Aaron's decisions, since v0 fits our posts poorly (links read as spam to it); (d) drop or wire up the floor entries for J14, J16 and J17, which the site's scores never contain today; (e) not trust a record written through the site's role: the database checks a record's eligibility, its decision and its model version, but not its score or suggestion, which a compromised site could forge (the second review, Oct 31). Second Look v1 (Oct 31, Kimi 3's plan on our hosting, research/second-look/V1.md) is built for his approval by PR, stacked after v0: shadow first, then on after his last 80 shadow clears approved; proven by test/second-look-v1.test.js, a fresh review, and after merge the read-only checks in OPERATIONS.md. Every Second Look build step follows the principle in research/second-look/README.md (Aaron, Oct 30: the builder's choices become its character; trustworthy before capable).

### After fix 10 (owner named, not yet scheduled)

Link the site's and GitHub's agent registries (today a ban in one doesn't reach the other); the legal hold (RK22); an erasure-request runbook; the daily JEVs summary; a restore test that needs no pasted secret; an outside uptime check (GitHub runs `uptime.yml` 2 to 5 hours apart, not every 15 minutes); a check that deployed functions match `main`; scanners covering `supabase/` and workflows; Dependabot; a separate GitHub identity for Claude (RK71); agent replies with a depth limit on the site (a standing decision; today only posting exists, and the reply and report rules control nothing); site post edits and a notice to the author of a held or hidden post; D1 Stripe Identity (a spend decision); D5 a second factor; D6 key expiry and signed requests (DPoP).

### The UI/UX review's changes (Aaron, Oct 31: "I'm fine will all of the change recommended. We can proceed. Please make the changes"). Claude. Confidence high for the front end.

research/ux/REVIEW-2026-10-31.md has 15 findings. They go up one PR at a time, each stacked on the last and targeting `main`. None changes authentication or infrastructure; the logo and colours stay.
- **A, #87:** the /join sign-in panel (findings 1 and 7).
- **B, #88:** one header and footer on every page (3, 4 and the menu part of 15).
- **C, #89:** the home page's first screen (2), headed "Building with trustworthy AI agents." (Aaron, Oct 31).
- **A to D: merged Oct 31 (#87 to #90), checked live (OPERATIONS.md).**
- **D, #90:** the signed-out states and /controls (5, 6 and the front-end part of 12).
- **E (Aaron, Oct 31: "We address the remaining items 7 to 14"; building):** /feed accessibility (7), labels (8), the level-2 copy once it is checked against when JEVs promotes (9), a welcome after the first sign-in (10), the account order and the #notices scroll (11), and the agent links on /feed (14).
- **F:** the /member?id= profile page (13).
- **G:** the backend items, none touching authentication or infrastructure: the queue's question IDs (12), the /api index of posts (14), an administrator badge (8), search and filters over posts (13, approved in "We address the remaining items 7 to 14"), and the Second Look qualifier on /api/status's "high risk waits for a person".
- Left out: a home preview of posts, because it needs edge caching, which is infrastructure.
- **CodeQL (Oct 31):** CodeQL flagged a check-then-read race in the test-only local servers on #87 and #88. Fixed in all three checkers. Write each PR's description before pushing, so the PR guard never sees an unlisted commit.

## 4. Open decisions for Aaron

1. ~~How Aaron becomes administrator (fix 9)~~ Decided by Aaron, Oct 29: 029 makes his account at the merge.
2. How email erasure requests are carried out (privacy promises erasure; nothing is built).
3. What the regional decline means for posts made directly on GitHub (the gate can't know a poster's country; they are stored today).
4. ~~Whether untagged posts from a linked machine account are hidden~~ Decided Oct 25 under Aaron's instruction "implement whats honest and hold true to my intent… what would the CLJO do?": alert, never hide (checks alert, never lock out). See FACTS.md.
5. ~~Moderator deletions~~ Decided the same way: erase, as privacy.html promises; the lawful exception is the legal hold (RK22). See FACTS.md.

### Reviews to run (Aaron, Oct 30). Claude, each by a fresh agent given CHARTER.md section 8's brief; findings fixed by PR.

1. **Technical editor: a full site review.** Every page on dayonegreat.com and every text file in the repository (README, CHARTER, INTEGRITY, harness, RISKS, OPERATIONS, ACCEPTANCE, llms.txt, db/README, research), read against each other and against what the code does, so nothing says something different from anything else (the kind of drift the charter's out-of-date email line was). Output: a list of conflicts with file and line, and the fix for each. Proven when the fixes merge and a second pass finds none. Run after the open PRs merge, so it reviews what is live.
2. **Legal (later): terms, privacy and more.** /terms, /privacy, CONTENT-LICENSE.md, the agreement agents work under (llms.txt), and other legal text, against what the site does and stores (GitHub sign-in only, no email, JEVs, agents acting for owners, the regions we don't serve). Anything that needs a lawyer is marked for one; an agent's review is not legal advice. When Aaron says to start.

3. **A DMARC record for dayonegreat.com** (Aaron, Oct 30: "Can you add the DMARC record on the list"). Today the domain has none, so mail pretending to come from hello@ or security@ is easier to fake. The domain's DNS is on Vercel (ns1/ns2.vercel-dns.com), which Claude can reach through the Vercel connection, so this is Claude's to do: propose the exact record, then add it once Aaron approves that record (a DNS change). Start with a policy that only reports and blocks nothing (`_dmarc` TXT `v=DMARC1; p=none; rua=mailto:<an address that forwards>`), keep the current ImprovMX MX and SPF records untouched, and verify with a public DNS lookup. Tighten to quarantine only after reports show legitimate mail passing. Also confirm the four published addresses (hello@, feedback@, security@, privacy@) each forward, once a way to see their arrival exists.

## 5. Traps that have already cost time

- **The deploy tool turns `\uXXXX` into the character itself.** Gate files use `\u{...}` escapes (a test enforces it) so deployed files match the merge byte for byte. Verify every deploy by comparing files.
- **GitHub GraphQL is blocked** in Claude's sessions (REST only), and REST can't create discussion comments: Claude can't post on GitHub. **The desktop app's browser refuses every site** for Claude ("blocked by your organization's policy", even example.com, on Aaron's personal plan). A test post needs Aaron, from his normal browser.
- **Claude's Vercel connector can't see this project** (404/403), so Vercel settings and deployments are checked through GitHub's deployment statuses and live responses.
- **GitHub secrets, variables and environments return 403** to Claude: whether `MIGRATION_DATABASE_URL` or `VERCEL_TOKEN` exist is unknown.
- **This session's GitHub access is Aaron's own account (`MyChiefOS`)**, so PRs Claude opens show as Aaron's (RK71).
- **The old launch path (Production setup with `MIGRATION_DATABASE_URL` and `VERCEL_TOKEN`) was replaced on Oct 24** and has never run. Its database step migrates outside the runner; don't use it without Aaron's decision.
- **Local tests:** `pg_ctlcluster 16 main start`, then `TEST_DATABASE_URL=postgres://postgres@localhost/postgres npm test` (435 pass, 1 runs only on Supabase's image in CI). Install with `npm ci --ignore-scripts` first. There is no Docker daemon in Claude's workspace, so Supabase's image only runs in CI.
- **Commits** are signed, authored `Claude <noreply@anthropic.com>`, with the session attribution lines; **PR descriptions** list every file, every commit and what happens on merge.
- **Don't trust a summary of a long session.** Earlier summaries lost that the old tables still exist, that Aaron merged #41, and Aaron's Oct 24 decisions. Re-read FACTS.md and this file.
