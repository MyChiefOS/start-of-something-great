# The trust Engine, steps E1 to E3: the design note

Written Nov 10, 2026 by Claude, before any code, for PR 2. Migration 056, `db/engine.js`, `api/engine.js` and the `/engine` page.

## Where this comes from (Aaron's sources; his words win)

- **Rev 4.2, section 12** of the Builder technical plan (Aaron's chat "Agent marketplaces research", Sep 29, 2026; read again Nov 10): licenses from verified outcomes with the 95% Wilson lower bound and Brier calibration, levels climbed in order, an append-only history; forecasts fixed before acting and resolved once; precedents set only by people with authority, never edited, overturned by a newer one, cited by agents, "no applicable precedent" always going to a person, a citation to another organisation's precedent refused; work orders that pause when spending runs more than 20 points ahead of progress, when the budget is spent or the deadline passes, resumed only by someone with authority; immune-system findings by OWASP agentic attack class (ASI01 to ASI10) that drop the agent's license to 0 until the red team, and not the fixer or the database owner, confirms the fix. Thresholds "To confirm".
- **harness/PLAN.md, Nov 7**: before launch E1 licenses and forecasts, E2 precedents and the immune system, E3 work orders; after launch E4 and E5.
- **FACTS.md, Nov 6 and 7**: only Postgres, Supabase, Vercel and our own code ("We won't be adding know outside software or services"); no shadow-only, read-only or show-first modes; checks alert, never lock out.
- **FACTS.md, Nov 10 (Q4)**: no sample tables, no spend figures, no post-quantum claim; existing features are never relabelled as Engine parts.
- **What it builds on**: the work module (042 to 054): tasks in 23 rooms, claims, submissions, the JEVs auditor, the poster's check, the check after, disputes, reversals and points; the audit log (053).

## A conflict, named first

Aaron, Nov 6 (FACTS.md row of Nov 7): "no shadow-only, read-only or show-first modes; every part ships working". PLAN.md (Claude's plan of Nov 7, from Rev 4.2's own build order) says licenses and forecasts are "shown first", before they are enforced. Aaron's decision wins over Claude's plan. But INTEGRITY.md, which supersedes both, says checks alert and never lock out, and every agent starts at level 0 because nobody has a verified record yet: a license that refused work at level 0 would stop every agent on the site on the day it ships.

So the parts here work end to end: they compute from real outcomes, record, refuse what Rev 4.2 refuses in their own records, and alert. **What a level holds up (Aaron, Nov 10: "Okay, for 1"):** the size of task the agent may claim in that room on its own: up to size 2 at level 0, 5 at level 1, any size from level 2. Only a claim above the cap is refused, with the reason. A claim handed on to a sub-agent keeps the size its first claimer was allowed. In a room with no small tasks, a new agent earns its level elsewhere first: a slow start there, not a lockout. The only administrator may confirm a fix on their own agent with a reason of at least 10 characters.

## Choices the sources leave open (each is Claude's)

1. **The task type is the room.** Rev 4.2 licenses per task type; the work module classes every task by one of the 23 rooms (SOC 2018 major groups). A license is per agent per room.
2. **A verified outcome** is a submission by the agent, on a task not removed, that is settled: passed with its points final (the 72-hour dispute window over, nothing open), or failed, or reversed. A pass whose points are pending isn't counted yet. Nobody grades their own work in the work module, so no outcome is the agent's own claim.
3. **The levels** are Rev 4.2's, to confirm: level 1 at 5 verified outcomes with a lower bound of 0.50; level 2 at 20 with 0.80, and 10 resolved forecasts with a Brier score of 0.15 or less; level 3 at 50 with 0.90, and 30 forecasts with 0.10 or less. Level 4 is "set by the organisation" in Rev 4.2, so it has no row until Aaron sets one, and the climb stops at 3. Rev 4.2's spend caps aren't used: there is no spending here.
4. **What is shown.** A lower bound is shown from 5 verified outcomes (level 1's minimum), a Brier score from 10 resolved forecasts (level 2's); below that the page says "not enough data yet" with the count. Every rate is shown with its sample size.
5. **A forecast** is an agent's, filed with its key, for a task it has claimed, before any work is submitted under that claim: one per claim, the chance in basis points (0 to 10,000). It resolves once, automatically, at the first settled verdict on that claim: "held" (passed, points final) is a success; failed, reversed, or the claim released or run out with nothing submitted are failures; a claim handed to a sub-agent closes its forecast as "handed", not scored.
6. **Precedents** are set by an administrator (the site's "people with authority"), per room: the facts, the decision and a reason of at least 10 characters. They can't be edited; one is overturned by a newer one in the same room, once. Rev 4.2's "another organisation" is another room here. Retrieval by embeddings (gte-small and pgvector) isn't in this step: precedents are listed by room.
7. **Citations** go with the forecast. Where a room has current precedents, the forecast must cite at least one, or say none applies; a cited precedent must be current and in the task's room. "None applies" is recorded and shown.
8. **The red team** is the administrator, directing it (Aaron, Nov 10: the red-team copy is for him and the agents he directs). An administrator records a finding; a successful one drops the agent's license in that room to 0 at once and tells the agent's owner. Only an administrator who isn't the agent's owner confirms the fix (the owner is the one who fixes the agent). The finding's regression test ("vaccine") is named, and shown publicly only once the finding is fixed.
9. **A work order** is made by an agent's owner, for one of their agents on one open project: the goal in verified task size (the sizes the audits confirmed), a budget of actions (the agent's claims and submissions on that project), a deadline in hours, and a rollback plan (required). Its state is worked out from the facts every time it is read, so it can't be edited around the rules: done when the goal is reached; paused when spending (actions used against the budget) runs more than 20 points ahead of progress, or the budget is spent, or the deadline passes; active otherwise. The owner who made it, or an administrator, resumes it by adding budget or hours. A reversal lowers progress (the work wasn't verified after all), which Rev 4.2's "only forward" didn't foresee.
10. **The role.** Everything runs as `dog_work`, the work module's narrow role, which already reads the work tables. A role of its own would need test/db.test.js's role list changed, which this PR may not touch.
11. **Records that go with an account.** Licenses, their history, forecasts, findings and work orders are deleted with the agent's account (F8), and only then. Precedents are written by the administrator and never deleted (Rev 4.2); contact details and keys are hidden in them before they are stored. Only someone holding the owner's login could remove the guard, as for the audit log.

## E1: licenses and forecasts

**What it is.** Each agent has a level from 0 to 3 in each room where it has a verified outcome, a forecast or a finding, worked out by one function from the evidence and nothing else. Every change of level is added to a history nobody can edit, and the agent's owner gets a notice. Agents file forecasts before they work; each resolves once from the audit's verdict and feeds a Brier score that higher levels need.

**Tables.** `app.engine_policy` (levels 1 to 3, to confirm), `app.engine_licenses` (one row per agent and room: level, the counts, the lower bound, forecasts and Brier, suspended, when), `app.engine_license_history` (append-only), `app.engine_forecasts` (immutable but for its one resolution).

**Functions.** `app.engine_wilson_lb(k, n)` and `app.engine_brier_term(bp, outcome)`, plain maths; `app.engine_level(n, k, forecasts, brier)`, the climb; `app.engine_license_refresh(agent, room)`, the only writer of licenses and history; `app.engine_forecast(task, bp, cites, none)`, for an agent; triggers after a submission's status, a point's status and a claim's status change, which refresh the license, resolve the forecast and watch work orders. A trigger never stops the work it follows: any error inside is caught, and Aaron gets one alert a day.

**What it reads.** `work_submissions`, `work_tasks`, `work_points`, `work_claims`, `agents`, `members`, `work_rooms`.

**What the page shows.** The policy (to confirm); every license with its level, verified outcomes (k of n), lower bound or "not enough data yet", forecasts and Brier or "not enough data yet"; the latest changes; the latest forecasts with their result; each agent's calibration.

**What it must never do.** Write a license anywhere but the refresh function; count an agent's own claim, a pending pass, or a removed task; hold up or refuse any agent's work; show a lower bound or a Brier score the counts can't support; let a forecast change after it is filed, or be filed after work is submitted.

## E2: precedents and the immune system

**What it is.** An administrator records how a kind of case in a room was decided, and agents' forecasts in that room must cite one that applies or say none does. An administrator records successful attacks on an agent; the agent's license in that room goes to 0 until another administrator than its owner confirms the fix.

**Tables.** `app.engine_precedents` (immutable), `app.engine_citations`, `app.engine_findings` (only the fix can be added, once).

**Functions.** `app.engine_precedent_add`, `app.engine_finding_add`, `app.engine_finding_fix` (administrators only, each written to the audit log); the citation rules inside `app.engine_forecast`.

**What it reads.** `work_rooms`, `agents`, `members`, and its own tables; findings feed `app.engine_license_refresh`.

**What the page shows.** Current precedents by room, and overturned ones with what overturned them; findings: agent, room, attack class, open or fixed, and the vaccine once fixed.

**What it must never do.** Let anyone but an administrator set a precedent or record a finding; edit a precedent; accept a citation of an overturned precedent or one from another room; let an agent's owner, or the database owner directly, clear a finding; publish an open finding's vaccine.

## E3: work orders

**What it is.** A long job for an agent on a project, with a goal, a budget of actions, a deadline and a rollback plan, that pauses itself when the agent spends faster than it delivers, and alerts the owner.

**Tables.** `app.engine_orders` (immutable), `app.engine_order_resumes` (append-only).

**Functions.** `app.engine_order_add`, `app.engine_order_resume`, `app.engine_order_state` (the derived state), and the watch in the work triggers, which tells the owner once each time an order pauses.

**What it reads.** `work_projects`, `work_tasks`, `work_claims`, `work_submissions`, `agents`.

**What the page shows.** Each order: agent, project, goal and progress, budget and spend, deadline, state and why, and its resumes.

**What it must never do.** Stop or slow the agent's work (a pause alerts); let anyone but the agent's owner make one, or anyone but its maker or an administrator resume one; show money.

## The threat model

| Threat | What stops it, or what's left |
|---|---|
| An agent raises its own level | Licenses are written only by the refresh function, from settled outcomes decided by someone else (the work module refuses self-review); the site's role holds no right on any Engine table. |
| Two owners pass each other's agents' work to raise levels (a ring) | Not stopped: a poster's pass counts once its points are final; the check after samples 5%, and disputes can reverse. Today a level holds nothing up, so a ring gains a number on a page. To record as a risk before any level gates anything. |
| A forecast is changed or backdated after the result is known | A guard trigger refuses every update but the one resolution, and every delete but the account's; the forecast is refused once anything is submitted on the claim (the claim row is locked while it is filed). |
| A forecast is filed to game the Brier score (always 0% and fail on purpose) | The lower bound falls with every failure, and higher levels need both. |
| Forecast or order spam | One forecast per claim (claims are capped by the work module's limits); 10 work orders per member a day, one open per agent and project. |
| A citation of a precedent that doesn't apply | Refused if overturned or in another room; whether it truly applies is not checked by code (as in Rev 4.2). |
| Someone other than an administrator sets a precedent or records or clears a finding | The functions check the database's own actor stamp (019); the guard trigger refuses any change made outside `dog_work`, the owner's included. |
| The agent's owner clears their own agent's finding | Refused (`engine_fixer`). The one administrator can't clear a finding on his own agent: only a reviewed migration can. |
| Publishing an open finding helps an attacker | The vaccine stays hidden until the fix is confirmed; the page shows the class and that it is open. |
| A trigger error breaks the work flow | Every Engine step inside a work trigger is caught; Aaron gets one alert a day. |
| Text in precedents, orders and findings carries contact details, keys or markup | Keys and contact details are hidden before saving (as the work module does) and again when shown; the page writes text, never HTML. |
| Public reads cost too much | Each list is at most 100 rows, one call per page view, cached 30 seconds at the edge. |
| A banned member's agents stay on show | Rows of agents whose owner isn't active are left out of the public lists. |

OWASP and CWE: A01 and CWE-862 (every write checks the actor in the database), A03 and CWE-79 (text only), A04 (rules in the database, not the page), A09 (each write in the audit log). OWASP's LLM Top 10 is not touched: no model is called.

## What "proven live" means for each

- **E1.** After the merge: 056 applied by the runner with its hash (`app.change_log`); `GET /api/engine/summary` answers 200 with the policy and real lists, or empty lists; /engine shows them or its empty states. Then, when it first happens on the site: an agent's forecast filed and resolved by a real verdict, and a license row from a real settled outcome, read with a GET. Until those happen, E1 is "built, not proven" for them.
- **E2.** The GETs and page as above. Then Aaron's first precedent and its first citation, and the first finding and its fix, each read back with a GET. These need Aaron's own decisions; nothing is posted to production by Claude.
- **E3.** The GETs and page as above. Then an owner's first work order, read back with its state.
