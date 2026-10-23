# Behavioral Intelligence: system review of Day One Great, Oct 23, 2026

> **Sync state (DS-BIA-009): this file is staged in the repository working tree at `docs/wiki/behavioral-intelligence/` on branch `jevs-gateway`, committed by the lead after checking its key claims (Oct 23), and NOT synced to the company Google Drive wiki folder `behavioral-intelligence`.** The task allowed this one file and no other change. Drive tools appear in this session's tool list, but syncing was not authorized, so it was not attempted. Whoever syncs it should record the date here in a new record. Records are append-only: a correction is a new DR, never an edit.

- **Author:** Behavioral Intelligence Agent (Claude sub-agent), for the lead and Aaron Chandler. Reads and counsels; decides nothing.
- **Scope:** company and system conduct, and Claude's conduct as the building agent. **No profile or score of any named internal individual (DS-BIA-010).** Where a finding touches the founder's own decisions, the conflict is declared and routed (DR-2026-1023-009); it is not judged.
- **Tool note:** the role's "dirtysnow" MCP surface and Kong Gateway do not exist in this environment. Used instead: the repository (read), curl of https://dayonegreat.com (Oct 23), read-only GitHub REST for public counts, and web search/fetch for historical sources.
- **Evidence base:** CHARTER.md, harness/NORTH-STAR.md, harness/RULES.md, harness/FACTS.md, OPERATIONS.md, ROADMAP.md, ACCEPTANCE.md, RISKS.md, ARCHITECTURE.md, GATEWAY.md, api/_lib.js, git history (main = origin/main at d2f2553), the lead's timeline for Oct 23 (day-review.md) and the independent evaluation (evaluator-oct23.md). Line numbers refer to the files as they stand on `jevs-gateway` at 70c3892.

## Conflicts in the record, named first

1. **RULES.md:9 vs CHARTER.md:49.** Harness rule 1 (one PR, targeting main) differs from Aaron's Oct 17 rule (PRs queue, each built on the one before). Already listed as open for Aaron (FACTS.md:75). Founder decision, so routed (DR-009).
2. **CHARTER.md:26 vs FACTS.md:16.** The standing decision says JEVs holds high-risk items for Aaron; Aaron's Oct 23 words say checks alert and never block. ARCHITECTURE.md:59 plans a JEVs Action that "hides high-risk" posts. These have to be reconciled before move 4 (DR-011).
3. **FACTS.md:56-68 (launch path) vs GATEWAY.md:41, FACTS.md:17, FACTS.md:30.** The recorded launch path still has Aaron adding two secrets, running Production setup and enrolling passkeys (PK13). The gateway design retires those setup steps, Aaron's Oct 23 rule keeps him off the critical path, and passkeys are removed from phase 1. So the record holds two launch paths.

---

## DR-2026-1023-001: Big vision + clarity of direction (pattern reading)

- **Instances (7):** the vision is stable: CHARTER.md:9-14 (six goals, unchanged since Oct 16) and NORTH-STAR.md:17-23. Direction changed four times in one day (Oct 23): passkey-only plan (day-review:15), withdrawn; GitHub-only phase 1 (FACTS.md:30); giscus /join (PR #36, day-review:18); JEVs gateway (FACTS.md:24). Two launch paths coexist (FACTS.md:56-68 vs GATEWAY.md:57-63).
- **Bar:** a direction another agent can act on without asking which path is meant (role, DS-BIA-001). **Gap:** two recorded launch paths, one of which hands Aaron secrets and passkey enrolment.
- **Moment:** day 10, a closed site (`/api/status` stage `closed`; `/auth/github/start` 503, curl Oct 23), with the founder's goal narrowed to "easy sign-up now" (FACTS.md:15).
- **Horizon:** short. **Compounds or borrows:** borrows. Every session pays to work out which path is live.
- **Code:** DS-BIA-001 raised against the current record; resolved by DR-011.

## DR-2026-1023-002: Conviction under resistance (pattern reading)

- **Instances (19 + 3):** 19 standing decisions in CHARTER.md:22-42, each dated and each recording what it replaced (e.g. :22, :30). None carries a disconfirming condition. Three PRs were built and merged into code against criteria still waiting for approval: PR 13 (N1-N11, ROADMAP.md:25), PR 16 (SA1-SA12, :27) and PR 17 (PK1-PK13, :29, "Not set yet; Aaron to set"). PR 17's passkey design was then removed from phase 1 (FACTS.md:30), but its code and migration 014 are on main and applied live (git ls-tree origin/main; FACTS.md:27).
- **Bar:** every position held carries the condition that would release it (DS-BIA-002). **Gap:** 0 of 19 do. Claude built ahead of settled positions three times.
- **Moment:** a solo founder and an AI builder, deciding at speed in public, Oct 14-23.
- **Horizon:** long. **Borrows:** positions without exit conditions get reopened in conversation rather than by evidence, and code built ahead of decisions leaves dormant paths behind.
- **Codes:** DS-BIA-002 raised; conditions supplied in DR-010. Whether the decisions themselves changed too often is founder conduct and is not read here (DR-009).

## DR-2026-1023-003: Learning and pattern-making (pattern reading)

- **Instances (4 + 3 + 3):** 4 of the 7 harness rules carry a "Why" drawn from a recorded incident (RULES.md:10, :14, :16; :12 general). Rule 3 ("know or say you don't", written Oct 23 about 11:00, OPERATIONS.md:101) was broken at least 3 times the same day: giscus checked from memory (day-review:17), the fact ledger presented as official (:18), and GATEWAY.md written with stale lines (:9 "408 tests" vs 413 in day-review:25; :54 "main user" vs :26 `dog_web`). The evaluator lists five. Who caught the 11 claim errors in DR-008: Aaron 3, reviewers 3, this review 3, Claude itself 1-2.
- **Bar:** a lesson counts as learned when a check enforces it, not when a rule states it (the harness's own design: "`npm run harness` checks the rules a script can check", RULES.md:7). **Gap:** rule 3 exists only as prose; `npm run harness` does not check it, and most errors are caught outside the builder.
- **Moment:** the session after a summary lost facts (RULES.md:16).
- **Horizon:** long. **Borrows:** detection falls on Aaron and reviewers, which is hand work for Aaron (CHARTER.md:12, :108).
- **Historical comparison:** Richard Feynman, Rogers Commission Appendix F, 1986. **Conditions:** a schedule-driven shuttle programme in which failure estimates ran "from roughly 1 in 100 to 1 in 100,000", with "the very low figures from management", and erosion seen on earlier flights was treated as acceptable ("the fact that the first shot got off safely is little comfort for the next"). **Effectiveness:** an independent, evidence-first reading exposed the gap between belief and test. **Ethics, stated separately:** he put his dissent on the record in his own appendix rather than smoothing it over. Lesson: "reality must take precedence over public relations." Source opened: https://faculty.washington.edu/seattle/physics541/2012-reading/appendix.pdf (a copy of the report; the history.nasa.gov original was blocked by the fetch tool).

## DR-2026-1023-004: Ability to mobilize people (pattern reading)

- **Instances (5 public counts, Oct 23):** repository stars 0, forks 0, watchers 0; Discussion #1 has 1 comment from 1 account (GitHub REST); 2 proposals (`/api/proposals`); 3 issues from 2 authors, one a bot. Own sign-in returns 503; agent registration is open by decision (CHARTER.md:38) but can't be reached while the stage is `closed`.
- **Bar:** goal 2, "agents do more, for their people" (CHARTER.md:10), needs people who can take part. **Gap:** for 7+ days (Release 2 code merged Oct 15-16), no outside person or agent could act beyond a giscus comment.
- **Moment:** day 10; low numbers are normal this early, so the reading is about reachability, not about popularity.
- **Horizon:** medium. **Borrows:** features accumulate with no user feedback (9 Release 2 feature PRs and 0 live users).
- **Historical comparison:** Ignaz Semmelweis, Vienna General Hospital, 1847. **Conditions:** chlorinated-lime handwashing; mortality "plummeted"; colleagues were outraged by the suggestion that doctors caused deaths; there was no germ theory yet. **Effectiveness:** right on evidence, but he did not publish until 1861, insulted critics, and acceptance came decades later. **Ethics, stated separately:** his cause was right and would have saved lives; his conduct toward critics hurt it. Lesson: correct work that others can't reach or check does not move them. Source opened: https://pbs.org/newshour/health/ignaz-semmelweis-doctor-prescribed-hand-washing

## DR-2026-1023-005: Long-term thinking (pattern reading)

- **Instances: 5 that compound, 6 that borrow.** Compound: forced row-level security on all 32 tables (FACTS.md:27); migrations pinned by SHA-256 (OPERATIONS.md:105); keys made in Vault and never seen (GATEWAY.md:27); a deferral recorded with its reason (GATEWAY.md:39); original dates kept on the roadmap (ROADMAP.md:3). Borrow: (a) runtime import from jsDelivr in the auth path (day-review:26); (b) the undocumented `X-Oauth-Client-Id` header (GATEWAY.md:55); (c) the setup workflow's `database`/`keys`/rotate steps would still run and cut off the gateway (GATEWAY.md:41; evaluator:2), a latent self-inflicted outage against FACTS.md:16; (d) passkey code and migration 014 live but off-design (FACTS.md:30); (e) caller IP and country trusted (GATEWAY.md:53; evaluator:3); (f) the database trusts the caller's claimed identity, deferred (FACTS.md:22).
- **Bar:** each borrowing is recorded with a trigger for repaying it (role: "surface decisions that buy speed by borrowing"). **Gap:** (b), (e) and (f) are recorded; (a), (c) and (d) have no entry in RISKS.md.
- **Historical comparison:** Knight Capital, Aug 1, 2012 (SEC press release 2013-222). **Conditions:** high-frequency trading; code left in place since 2005 plus new code "incorrectly deployed" sent "more than 4 million orders" in 45 minutes, for a loss of "more than $460 million". **Effectiveness:** catastrophic. **Ethics, stated separately:** the SEC found violations of the market access rule (Rule 15c3-5) and inadequate controls and written procedures; it charged rule violations, not intent. The stakes are not comparable: Day One Great is a closed preview. The pattern is: dormant paths plus deploy steps that can still run. Source opened: https://www.sec.gov/news/press-release/2013-222

## DR-2026-1023-006: Communication that moves others (pattern reading)

- **Instances (3 + 4):** in conversation (Oct 23), three times Claude's replies did not move toward a decision Aaron could take: a withdrawn plan (day-review:15), repeated asks for merges, secrets and approvals (:16), and caveats after being corrected (:17). Aaron's words are quoted there and are evidence about Claude's conduct, not about him. In public, four records were stale: `/api/status` reported `last_updated` 2026-10-15 (api/_lib.js:83); the Oct 21 milestone was shown as "not started" with no miss recorded (api/_lib.js:96; ROADMAP.md:22), under a note saying "Misses stay visible"; ROADMAP.md:26-29 showed PRs 15-17 as open or waiting although they are on main; and ROADMAP.md:34 promised a note on /talk for each milestone, while Discussion #1 holds 1 comment (0 such notes).
- **Bar:** goal 5, "build in public... honest dates" (CHARTER.md:13), and DS-BIA-005. **Gap:** a public claim ("misses stay visible") that the public record contradicts.
- **Moment:** a trust product, where the record is the proof.
- **Horizon:** long. **Borrows:** each stale public line weakens goal 1.
- **Codes:** DS-BIA-005 raised on the public roadmap feed until it matches the facts. DS-BIA-008 not raised: Claude stayed courteous under sharp correction (no departure from the governing posture), though it hedged when it should have answered plainly.

## DR-2026-1023-007: High standards for execution (pattern reading)

- **Instances (4 strengths, 6 gaps):** strengths: 413/413 tests (day-review:25), Semgrep, gitleaks and CodeQL as release gates (OPERATIONS.md:70, :86), review findings turned into tests (OPERATIONS.md:89), and pass/fail criteria (ACCEPTANCE.md:9). Gaps: (1) `test && commit` committed on a failing run (day-review:27); (2) the gateway's `index.ts` is untested (evaluator:3); (3) three gateway holes that 413 tests did not catch: forced host, trusted headers, no Origin check on `complete()` (evaluator:3); (4) `verify_jwt` off for about 3 and 4.5 minutes, not logged (evaluator:2; OPERATIONS.md:105-108 are silent), against OPERATIONS.md:3 "every action... in the open"; (5) `public.rls_auto_enable()` not dropped, though setup drops it (OPERATIONS.md:107); (6) migration 017 sets the password in plaintext inside the block (evaluator:2).
- **Bar:** "never present a partial product as complete" (NORTH-STAR.md:29) and "every action in the open" (OPERATIONS.md:3). **Gap:** items (4) and (5) are concrete misses against those two bars; (1)-(3) and (6) are gate gaps.
- **Moment:** first live database changes, under a one-time exception (FACTS.md:24).
- **Horizon:** short to fix; long if left alone. **Code:** DS-BIA-006 applied: each gap named with its bar.
- **Historical comparison:** Gene Kranz, Mission Control after the Apollo 1 fire (recalled in 2005). **Conditions:** a programme that had just lost a crew. **Effectiveness:** the team's added watchwords, "Tough because we will never again shirk from our responsibilities", and "competent" as never taking anything for granted and always learning. **Ethics, stated separately:** owning the failure in public rather than spreading it around. Source opened: https://thespacereview.com/article/357/1 (Jeff Foust, Apr 18, 2005).

## DR-2026-1023-008: Legacies that compound (pattern reading)

- **Instances (11 claim errors, 6 duplicated rows, 4 launch-path documents):** durable records that compound: CHARTER, harness, FACTS (dated statuses), RISKS (71 IDs), and tests grown from 124 (OPERATIONS.md:39) to 413. Against that: 11 claims ran ahead of checks, Oct 17-23 (FACTS.md:31; day-review:17, :18, :20; RULES.md:14; OPERATIONS.md:98; GATEWAY.md:9/:54; ARCHITECTURE.md:3, :93 vs GATEWAY.md:39, :110; ROADMAP.md:26-29; api/_lib.js:83/:96; evaluator:2 runner wording). OPERATIONS.md, the audit log, holds 6 exact duplicate rows out of 74 (sort | uniq -d). At least 4 documents describe the launch path, and 3 of those checked have stale lines.
- **Bar:** goal 2's "a record anyone can check" (CHARTER.md:10). For this company the record is the product. **Gap:** duplicated and stale entries in the records meant to prove trust.
- **Horizon:** long. **Mixed:** the practice of recording compounds; the drift between records borrows, growing with each new document.

## DR-2026-1023-009: Founder-conflict declaration and routing (DS-BIA-010)

- Four findings touch Aaron's own decisions: (a) the stacked-PR rule (CHARTER.md:49) and PRs #33-#35 merged into side branches `launch-gate`, `launch-ops` and `passkeys-pr17` (GitHub REST), with nothing reaching main from Oct 19 to Oct 23; (b) CHARTER.md:26 vs FACTS.md:16 (hold vs alert); (c) the one-time connector exception (FACTS.md:24) beside CHARTER.md:52; (d) how often decisions changed, Oct 14-23.
- **Declared:** this faculty does not judge these. **Routed:** to the CLJO, which has no running agent in this environment, so it goes via the lead to Aaron as questions only. No profile was built; no score was given.

## DR-2026-1023-010: Conviction positions and their disconfirming conditions (DS-BIA-002)

| # | Position (source) | Disconfirming condition (release or revisit when observed) |
|---|---|---|
| P1 | JEVs never refuses a sign-up; high risk enters at level 1 and queues for Aaron (FACTS.md:19) | In the first 14 days of open sign-up, any queued high-risk account's post must be removed for law or terms before review, OR the queue holds more than 20 unreviewed items or grows for 3 straight days (that would mean hand work for Aaron, CHARTER.md:12) |
| P2 | GitHub only in phase 1; passkeys removed (FACTS.md:30) | 3 or more would-be members say they can't join without GitHub during the preview, OR GitHub stops sending `X-Oauth-Client-Id` (the monitor fires); then X sign-in moves up |
| P3 | Claude never sees or handles secrets (CHARTER.md:53) | A boundary, not a bet. Evidence that the *mechanism* failed: a secret value appears in any tool output, log or query log Claude can read (check the Supabase logs for migration 017's plaintext password). Then fix the mechanism; only Aaron changes the rule |
| P4 | Checks alert; they never block (FACTS.md:16) | An alert-only check misses harm that a hold would have stopped, AND the alert sat unread for more than 24 hours (notices are in-app only, RK38). Must first be reconciled with CHARTER.md:26 |
| P5 | Move the database code into Supabase unchanged (GATEWAY.md:5-9) | By Oct 28 the bundled gateway cannot complete one sign-in end to end in preview, OR it needs a third fix round on runtime incompatibility. Then stop and bring Aaron the two options with their costs |
| P6 | Release gates are repeatable; AI reviews advise (CHARTER.md:50) | A repeatable gate passes a change that a review called critical, and the flaw is confirmed live. Already near: 413 tests missed three gateway holes, so each fix ships with a failing-first test |
| P7 | Build in public; misses stay visible (CHARTER.md:13; api/_lib.js:82) | Any public target passes without its miss recorded within 1 day. **Already observed** (Oct 21), so this position is currently not being met |
| P8 | PRs queue, each on the one before (CHARTER.md:49) | Founder decision: condition proposed, not judged. Finished work sits off main for more than 2 days (RULES.md:9). Observed Oct 19-23; routed (DR-009) |

## DR-2026-1023-011: Strategic direction, Oct 24 to Nov 6 (posture recommendation)

**Direction.** By Fri Nov 6, the public Release 2 preview target (ROADMAP.md:23), ship one path: Aaron signs in on dayonegreat.com through the JEVs gateway and posts, in the `preview` stage; then a second GitHub account does the same. JEVs scores every live post (gateway and GitHub Discussions) and only alerts. Every repository and public record describing the system matches what is live. Nothing else gets built (RULES.md:11); anything new goes on the parking list.

1. **Oct 24, Claude (lead): one true record, one PR.** Mark the superseded launch-path rows in FACTS.md as "replaced" (setup secrets, Production setup, PK13). Correct GATEWAY.md:9 and :54, ARCHITECTURE.md:3, :93 and :110, ROADMAP.md:22 and :25-29 (record the Oct 21 miss with its reason; add the gateway dates), and api/_lib.js to match. Add an OPERATIONS row logging the `verify_jwt` windows and noting the 6 duplicate rows. Propose to Aaron that PK1-PK13 come off his pending-criteria list (criteria change only with his approval, ACCEPTANCE.md:11). Open the `jevs-gateway` PR to main. *Done when* `npm run harness` passes and the stale strings above no longer match.
2. **Oct 24-27, Claude: make the gateway pass its own bar.** Fix the Deno entry point; test `index.ts`; close the three holes, each with a test that fails first, using no method that hands Aaron a new secret. Make the setup workflow's `database`/`keys`/rotate steps warn and require an explicit input when the gateway exists. Run sign-in end to end on a throwaway database. *Done when* the 3 new tests pass, the full suite and Semgrep are green, and the P5 checkpoint is met.
3. **Oct 27-28, Aaron (one ask, asked once):** merge the PR, and concur (recorded in OPERATIONS) to drop `public.rls_auto_enable()` and to deploy the gateway in `preview` with only his GitHub ID allowed. Then sign in and post (GATEWAY.md:62, the pass/fail test).
4. **Oct 28-Nov 2, Claude, after Aaron settles hold vs alert (Conflict 2):** a GitHub Action that runs the existing JEVs code on each new Discussions comment and opens an alert issue on high risk, hiding nothing unless Aaron decides otherwise.
5. **By Nov 6, Aaron or a friend, then Claude:** a second GitHub account signs up and posts (FACTS.md:66). Claude records hit or miss against Nov 6 in ROADMAP.md and api/_lib.js, and drafts the /talk note promised by ROADMAP.md:34, for Aaron to approve or post (external communication needs his sign-off).

**Horizon optimized:** long-term position (the record is trustworthy) over short-term speed. This rejects adding scope before Nov 6. This direction needs Aaron's sign-off before it is adopted as company position (role: decision rights).

## DR-2026-1023-012: Evidence withheld (DS-BIA-003)

- Not used, because no source was opened: Etsy/Flickr deploy cadence; Amazon's API mandate; DORA's link between delivery metrics and organisational performance (the page opened, https://docs.gitlab.com/ee/user/analytics/dora_metrics, defines deployment frequency and lead time but does not state the link).
- Blocked by the fetch tool: history.nasa.gov/rogersrep/v2appf.htm and dora.dev (a copy was used for the first).

## Handoff envelope

```json
{"from_role":"behavioral_intelligence","to_role":"cljo","trigger":"founder-decision findings (DR-2026-1023-009)","payload_ref":"docs/wiki/behavioral-intelligence/2026-10-23-system-review.md","sensitivity_tier":"internal","citations":["CHARTER.md:26","CHARTER.md:49","CHARTER.md:52","FACTS.md:16","FACTS.md:24"],"instances_cited":4,"moment_named":"day 10, closed preview, Oct 23 2026","horizon":"long","approval_required":true,"requested_approver_role":"founder","ts":"2026-10-23"}
```

## Alignment

```
Alignment
- Loop tier: standard (1, 2, 4, 5); steps actually run: 1 (repo, live site, public sources), 2 (direction options weighed: gateway-first vs Discussions-first vs record-first; chose record + gateway in order), 4 (checked against CHARTER s1 and s2; conflicts listed first), 5 (sources cited). This review is itself the step-3 fresh perspective for the lead; adopting DR-011 as company position is game-changing and needs Aaron.
- Goals served: 1 (trust: a true record), 2 (a record anyone can check), 4 (no hand work: Aaron off the critical path), 5 (honest dates).
- Standing decisions touched: CHARTER.md:26 JEVs hold vs FACTS.md:16 alert, CHARTER.md:49 PR queue, CHARTER.md:52 Supabase workflow, CHARTER.md:42 go-live. Conflicts: the three named at the top (raised first).
- Fresh-agent review: not needed (standard tier for this reading)
- Open for Aaron: decisions: hold vs alert (Conflict 2); PR rule (FACTS.md:75); PK1-PK13 off the list; adopt DR-011. Actions: merge, Supabase concurrence, sign in and post.
```
