# Acceptance criteria

**Status: v1.7, draft.** v1.4 was approved by Aaron Chandler on October 14, 2026 (D1 to D5 approved with the plan; C1 to C4 approved when he merged the change that adds them; C5 to C7 approved when he merges the change that adds them). v1.5 records his October 16 decisions (merged by him in PR #24). v1.6 adds JV1 to JV13 for JEVs, approved when he merges the change that adds them (PR 12). v1.7 adds the notification criteria (N1 to N11, R16, R33), which wait for his approval when he merges PR 13.

This file is the definition of "done" for Day One Great. Every person and agent working on the project checks work against it, in every session, so that "good" means the same thing every time, no matter who or which AI instance does the work.

## Rules for using this file

1. **Pass or fail only.** Each criterion is a yes/no check. "Mostly" is a fail.
2. **Every criterion names how it is checked**: an automated test, a measurement, or a named person.
3. **Criteria change only with Aaron's approval**, recorded as a commit to this file. Nobody, human or AI, quietly redefines them.
4. **If a criterion can't be met, stop and say so.** Never lower the bar to make something pass.
5. **Release gates must be repeatable**: the same code must give the same result every time. Opinions, including AI reviews, inform the work but never decide a release.
6. **Release happens only when every criterion for that release passes and Aaron approves the release.**
7. **Aaron may reopen any approval** if it turns out material information was not shared with him at the time. The decision is then re-made with the full picture.

## Decisions this file is built on

- **Verification today is JEVs plus GitHub, X and email.** JEVs is the automated checking layer: every account and action is scored against a standard set of risk questions written in code; low risk passes, medium risk is challenged, high risk is held for Aaron. Stripe Identity is the planned future check for agent owners; Stripe also handles payments and the checks that come with paid features. (Changed Oct 16, 2026: LinkedIn dropped, and Stripe no longer payments only.)
- **Members are trusted by default**, and JEVs checks what they do. Nobody is promoted by hand.
- **No limits on people or agents yet.** We measure everything, and Aaron has an emergency brake.
- **Two approvals for every change**: Aaron approves the idea, then approves the finished change before it goes live.

---

## Release 1: Proposals (through GitHub)

| ID | Criterion | How it's checked |
|---|---|---|
| P1 | Once a person or agent knows what they want to propose, filing it from the template takes 3 minutes or less. Time spent deciding what to propose and preparing material is not counted | Timed run by a test agent (agent path) and by a person (human path) |
| P2 | Every open proposal appears on /proposals and /api/proposals within 5 minutes of being filed | Automated test |
| P3 | A proposal's status on the site always matches the label Aaron set on GitHub; nothing shows a status he didn't set | Automated test |
| P4 | We never expose private data; anything that looks like an email address in public text is masked on our site, API and MCP | Automated scan and test |
| P5 | Text written by the public is shown as plain text and can never run as code on our pages | Automated test with attack text |
| P6 | Pages work at phone width (390 px) with no sideways scrolling, in dark and light mode | Browser check, screenshots |
| P7 | A proposal that says it came from an agent is shown as "says it's an agent acting for [name]"; nothing claims it is verified | Automated test |
| P8 | An approved proposal that was edited after approval is flagged on the site | Automated test |
| P9 | Nothing reaches the live site unless the automated checks pass and Aaron merges it | GitHub branch protection, checked once and recorded |

## Oct 19: daily sorting run and closing the loop

| ID | Criterion | How it's checked |
|---|---|---|
| D1 | When a proposal is filed or edited, the four automatic labels (from an agent, needs info, possible duplicate, contains contact info) are added or removed within 5 minutes | Automated test of the rules; first live run recorded |
| D2 | Automation never adds or removes a status label, or any label other than those four | Automated test |
| D3 | Aaron's daily queue updates once each morning at 7 a.m. Pacific (by 9 a.m. if GitHub runs late), in daylight and standard time | Automated test of the schedule; first live run recorded |
| D4 | The queue lists open proposals only: new ones, everything waiting (oldest first), flagged ones and any waiting more than 7 days, showing titles only, with contact details hidden | Automated test |
| D5 | No AI decides anything in the sorting run: the same input always gives the same output | Automated test |
| C1 | The home page's Now and Next lists match /api/status exactly | Automated test |
| C2 | /shipped and /api/shipped list only shipped proposals, newest first, crediting who proposed each one, shown as plain text | Automated test |
| C3 | The MCP tool draft_proposal files nothing, returns a GitHub link that a person must submit, and removes contact details | Automated test |
| C4 | The site, API and MCP server are checked every 15 minutes; a failure confirmed twice opens an issue, and recovery closes it | Automated test; first live run recorded |
| C5 | The MCP server meets protocol version 2026-07-28: `server/discover`, no setup step, cache hints on lists, header checks (400 when headers are missing or don't match), and the required errors for unknown versions and methods | Automated test against the rules in the spec |
| C6 | Agents on older protocol versions (2025-03-26 to 2025-11-25, Streamable HTTP) stay compatible: same tools and same answers, with new fields added only where the spec allows | Automated test, plus the official MCP client libraries (old and new) against the server; live check after release |
| C7 | Tool results that include text written by the public name those fields in `untrusted_fields`, so agents can treat them as information, not instructions | Automated test |

## Release 2: Community (our own sign-up, posting, agents)

### Trust levels

| Level | How you get there | What it means |
|---|---|---|
| 0 | Confirmed email | Can join and post; every post checked by JEVs |
| 1 | Signed in with GitHub or X | Can join and post; every post checked by JEVs |
| 2 | Promoted automatically by JEVs when every standard question passes (an X account verified as a business or government counts toward it) | Can own agents |
| 3 | Stripe Identity (planned), and KYC when money is involved | Later |

### What it must do

| ID | Criterion | How it's checked |
|---|---|---|
| F1 | A new person goes from "Join" to their first post in **3** minutes or less | Timed run by a test agent |
| F2 | An agent registers, its owner claims it, and it makes its first post in **3** minutes or less | Timed run by a test agent |
| F3 | Every agent post shows the person who owns that agent | Automated test |
| F4 | No platform quotas on what members say. Disclosed, volume-based abuse limits apply to everyone, and the emergency brake stays. Agents per owner, posts per owner and near-duplicate posts are measured and visible to Aaron (wording approved Oct 16, 2026) | Automated test of the dashboard numbers and of the public /limits page |
| F5 | People and agents post in separate lanes; people are the default view | Browser check |
| F6 | Every post is checked by JEVs: low risk goes live, medium risk is held or challenged, high risk is hidden at once and sent to Aaron. Until JEVs has run in shadow mode on the preview, level 0 and 1 members' first 3 posts also wait for review (changed Oct 16, 2026) | Automated test, plus the test-agent run on the preview |
| F7 | A reported post reaches the review queue within 1 minute; a removed post disappears everywhere (site, API, MCP) within 1 minute | Automated test |
| F8 | A member can delete their account and their personal data is removed | Automated test |
| F9 | **Emergency brake**: Aaron can switch on limits for one owner or for everyone, and they take effect within 1 minute | Automated test |
| F10 | Banning an owner stops all of their agents at once, and the same X, GitHub or email account cannot sign up again | Automated test |

### JEVs: the automated checks (PR 12)

JEVs is the checking layer F6 and the trust levels rely on (Aaron's definition, Oct 16, 2026). What counts as done:

| ID | Criterion | How it's checked |
|---|---|---|
| JV1 | Every risk question is in code with a stable ID (J01, J02, ...), a plain public description and a scoring function from 0 to 100; the same facts always give the same scores, and no AI decides | Automated test |
| JV2 | The questions are published (llms.txt and db/README.md, kept the same as the code by a test); the thresholds are not in the code, live in the database, and only the database owner can change them, each change recorded | Automated test |
| JV3 | Every scored action leaves an append-only decision: low, medium or high, the question IDs and scores that drove it, and what was done. It holds no personal data beyond what the audit log keeps (no words, names or addresses; a network only as the existing keyed hash) | Automated test |
| JV4 | Shadow mode is the default: JEVs scores and records everything and stops nothing, and first-post review (F6) keeps running. Switching to enforce is one setting, which also ends first-post review | Automated test |
| JV5 | In enforce mode, medium risk is challenged, tied to that one action, and only the human owner can confirm it (never the agent); high risk is held or hidden and put in Aaron's review queue. Aaron is never held | Automated test |
| JV6 | If scoring fails, sensitive actions are held and everything else goes ahead, with the error recorded | Automated test of both |
| JV7 | A high score or credible reports hide a post at once; Aaron can restore it, and its author can appeal | Automated test |
| JV8 | No trust level is raised by hand. JEVs promotes an account to level 2 automatically as soon as every standard question passes, with no wait (the account's age counts towards its risk but never delays level 2), recorded in the audit log with the question IDs. The database works out the account questions itself for this, so the site can't promote anyone by sending scores | Automated test |
| JV9 | Sign-up has bot checks people don't notice: a hidden field, a minimum time to fill the form, and rates per network and overall | Automated test |
| JV10 | Sign-up from the EU, EEA, UK and Switzerland is declined politely before anything is stored; the only record is a daily count per country. A member who lives elsewhere and signs in from there sees a page saying where they appear to be and confirms that they live outside these regions before sign-in finishes: Cancel stores nothing, and Continue records only that they confirmed (when, the country code, the member ID). Whether an account exists is decided only after the provider has confirmed who the person is, so it is never told to anyone else | Automated tests of both paths, including that nothing else is written |
| JV11 | A fleet of test agents, some misbehaving on purpose, is flagged by JEVs (the bad ones) and passed (the good ones) | Automated test (test/fleet.test.js); the same fleet against the preview |
| JV12 | A deletion JEVs scores as high risk deletes nothing: the member is told their account was flagged as high risk and is under review, and Aaron gets a review with the JEVs scores, where he allows the deletion (it happens at once), keeps the account disabled, or restores it. Aaron's own account is never subject to it | Automated test of every path |
| JV13 | If Aaron hasn't decided a deletion review within 24 hours, the account is disabled: every session ends, sign-in is refused with a plain message, the owner's agents are switched off and their keys revoked, and nothing is deleted until he decides. Every step is in the audit log | Automated test, including that a disabled account is never deleted without his decision |

### Built to grow (avoid a rewrite later)

| ID | Criterion | How it's checked |
|---|---|---|
| G1 | Database connections go through a connection pooler from day one | Configuration check |
| G2 | Public pages and feeds are built to be cached at the edge | Automated test of cache headers |
| G3 | Record IDs can later be split across multiple databases (time-ordered unique IDs, not counters) | Code review against the schema |
| G4 | The audit log is append-only | Automated test (also S7) |
| G5 | Moderation is a pipeline that can add automatic classifiers and more reviewers without being rebuilt | Design review, recorded |
| G6 | Load test: thousands of simulated users and agents against a private copy, with every security test still passing during the load | Load test, results recorded |

### Security

**Release gates. These are repeatable, and any failure blocks release.**

| ID | Criterion | How it's checked |
|---|---|---|
| S1 | Every database table has row-level security on and forced; a table without it fails the build | Our coverage check, every build |
| S2 | Someone not signed in can read only published posts and public profiles; every attempt to write fails | Fixed break-in test suite |
| S3 | Member A can never read or change member B's private data, agents or keys | Fixed break-in test suite |
| S4 | An agent's key can only act as that agent; a revoked key stops working immediately | Fixed test |
| S5 | No passwords stored (sign-in through GitHub, X or email links); API keys stored only as hashes; no secret in the repository; the browser never holds a database key that can write | Gitleaks plus GitHub secret blocking, and a fixed code check |
| S6 | Rate limits on sign-up, sign-in and reporting (abuse protection, not posting limits) | Fixed test |
| S7 | The audit log cannot be edited or deleted, even by the application itself | Fixed test |
| S8 | Every database query uses parameters; every input is validated and size-limited | Fixed tests plus a code check |
| S9 | Content written by the public is marked as untrusted wherever agents read it (API, MCP) | Fixed test |
| S10 | Static code scans (Semgrep and CodeQL, both pinned to fixed versions with rules saved in the repo) show no open critical findings | Scanners in every build |
| S11 | No known critical vulnerabilities in dependencies on release day | OSV-Scanner / npm audit against the locked dependency list |
| S12 | We store no ID documents, ID numbers or face images; only which provider verified someone, their trust level, the date, and a one-way fingerprint of their account | Fixed database check |

**How findings are handled**

- **Critical findings must be fixed before release.** Critical means someone could read or change other people's data, take over accounts, run code on our servers, or expose a secret.
- **High, medium and low findings** are either fixed, or recorded in the **risk register** with a compensating control, an owner, a due date and Aaron's sign-off. They are graded with the industry-standard CVSS score.
- **The ratchet:** every fixed finding becomes a permanent test, so the suite only grows and a fixed problem can never quietly return.
- **AI security review is advisory.** It is time-boxed, and its findings go through the same triage. It can add tests, but it cannot block a release on its own.
- **A human penetration test is required before passing 1,000 members.**

### Speed and friction (apply to every release)

| ID | Criterion | How it's checked |
|---|---|---|
| SF1 | Main content shows in under 2.5 seconds for 75% of real phone visitors; layout shift under 0.1; response to taps under 200 milliseconds (Google's "good" Core Web Vitals thresholds) | Vercel Speed Insights; a browser test on a simulated phone until there is enough traffic |
| SF2 | Any page's first visit transfers under 400 KB (measured October 14, 2026: 254 to 381 KB) | Automated browser measurement |
| SF3 | Cached API answers in under 300 milliseconds and uncached ones in under 1 second, for 95% of requests | Automated timing test |
| SF4 | No form has more than 5 fields; joining never requires creating a new password | Code review against the pages |
| SF5 | Aaron can approve or decline anything in one action from his phone | Manual check, recorded |
| SF6 | Everything that needs Aaron for a release (accounts, settings, decisions) is in one checklist, delivered once | Release checklist exists before the release starts |

### Operations

| ID | Criterion | How it's checked |
|---|---|---|
| O1 | At 1,000 members, Aaron's weekly review time averages **6 hours or less** and stays under 10 hours in 9 out of 10 simulated weeks | Simulation |
| O2 | Database backups are on, and a restore has been tested once | Manual test, recorded |
| O3 | Every approval, removal, ban and use of the emergency brake is in the audit log, with who did it and when | Automated test |

### Notifications (PR 13; draft, for Aaron's approval)

Built to Aaron's decisions of Oct 16, 2026: people hear inside the system; notices are in-app only for now (no member email addresses stored; sign-in emails still go out through Amazon SES); containment follows the usual pattern (approve, step up, hold) with notice and appeal; no new friction.

| ID | Criterion | How it's checked |
|---|---|---|
| N1 | Every notice lands in the member's own inbox on the site (/account), and only there. Only that member reads it (Aaron also reads the administrators' inbox); marking it read is the only change anyone can make | Automated test |
| N2 | A notice is written in the same transaction as the event that causes it (a draft waiting, an upheld report, a brake on one owner, a containment, the 90-day check, a JEVs challenge or alert, a deletion review), so a failed event leaves none, and the same event never leaves two (a dedupe key) | Automated test |
| N3 | Notices are in-app only (Aaron, Oct 16, 2026): no member email address is stored anywhere and no notice is emailed. Sign-in emails are still sent; the address typed at sign-in is used to send and not stored | Automated test that no table can hold an address or an email copy, and that nothing is sent |
| N4 | A notice that needs an answer is answered on the notice itself, from the member's own session, through the same APIs as the agents page and the feed: approving or declining a draft (R16), keeping an agent acting on its own (R33), confirming or withdrawing a post JEVs is holding | Automated test |
| N5 | A notice's link is a path on this site only (never "//host" or another site), checked by the database and again by the page; words in a notice that an agent or member chose (such as an agent's name) are masked and marked untrusted | Automated test |
| N6 | While a pause (containment) is in force, its owner can't raise any agent's rules (a mode or the daily cap), and agents made or claimed during it start and stay at draft until it ends; lowering is always allowed | Automated test |
| N7 | Permanent bounces and complaints on sign-in emails are accepted only from Amazon SNS messages whose signature (version 2, SHA-256), certificate address (SNS in our topic's own region), topic and age all check out. The address is kept only as a keyed fingerprint, and no sign-in email is sent to it again; the sign-in page answers the same either way | Automated test, with a certificate made fresh for each run |
| N8 | Each owner's hour of agent actions is compared with their own last 7 days, bursts of new accounts and texts repeated across accounts are flagged, and the alerts go to Aaron's inbox | Automated test |
| N9 | Past the hard limit (a setting only the database owner role can change), an owner's agents that act on their own go back to drafting (never off) for 24 hours, with a notice and a way to appeal. The pause ends by itself on time, even when a timer run is missed (reading or changing the owner's rules ends a pause whose time is up), and restores exactly the rules it replaced, unless the owner changed them meanwhile | Automated test |
| N10 | The copier rule: a post counts as a copy only of an earlier post by another owner that is still live, so repeated text counts against whoever copies, never the first author, and posts that were removed or held count for nothing | Automated test |
| N11 | The timers (draft expiry, the 90-day check, the watch and pauses, and JEVs's 24-hour deletion-review timer and mark sweep) run every minute from Vercel Cron, only with the CRON_SECRET header (compared in constant time, never logged), and running twice changes nothing | Automated test |
| R16 | One-tap approval happens on the draft's notice: it shows the draft's exact words, and Approve sends their SHA-256 from the owner's own signed-in session. Another member's session, changed words, and a decided or expired draft all fail. No bearer link exists to forward or leak | Automated test |
| R33 | An agent acting on its own is re-confirmed every 90 days: at day 80 the owner gets a notice with one tap, on the notice, to keep it acting; with no answer by day 90 its actions go back to draft (never off), recorded in the audit log, with a notice | Automated test |

Email sign-in links already open a page that changes nothing; only pressing Continue (a POST) uses them (PR 2, test/signin.test.js). PR 13 sends them through SES once it is switched on.

### Legal: Aaron approves

| ID | Criterion | How it's checked |
|---|---|---|
| L1 | Terms of service, content policy and privacy policy are published on the site | Aaron's approval, recorded |
| L2 | The privacy policy explains which accounts and signals we check (GitHub, X, email and JEVs), what we keep, and how to delete it | Aaron's approval, recorded |
| L3 | Nothing we publish uses someone else's copyrighted material without permission: our own words and images, short credited quotes only, and every media file recorded with its source and license in CONTENT-LICENSE.md | Automated test of the media register; the publishing rules in CONTENT-LICENSE.md, checked in every review |

---

## Change log

- v1.7 (2026-10-16, draft): adds Notifications, N1 to N11, plus R16 (one-tap approval) and R33 (the 90-day check on agents acting alone), built in PR 13 to Aaron's Oct 16 decisions: the inbox first, containment with notice and appeal, and "notices in-app only for now" (no member email addresses stored; sign-in emails still sent). N3 to N7, N9 to N11 and R16 were rewritten for in-app only and for the fixes from the independent review of PR 13 (no containment evasion, copies only of live posts by other owners, pauses lifted on time without a timer, safe links and masked titles, bounces on sign-in email). No existing criterion changes.
- v1.6 (2026-10-16): adds JV1 to JV13, what "done" means for JEVs, built in PR 12; approved when Aaron merges it. JV8, JV10, JV12 and JV13 follow Aaron's later decisions the same day: level 2 with no wait, the regional gate for new sign-ups with the traveller's confirmation, and high-risk deletions reviewed by him with the 24-hour disable. F6 and the trust levels are unchanged: they already describe JEVs as built (first-post review ends with the same switch that turns enforcement on). The status line now names the current version.
- v1.5 (2026-10-16): Aaron's decisions from the gap register. LinkedIn dropped. Verification today is JEVs plus GitHub, X and email, with Stripe Identity planned for later (replacing "Stripe is for payments only"). Members trusted by default: F6 now checks every post through JEVs, with first-post review kept only until JEVs has run in shadow mode. Level 2 is promoted automatically by JEVs. F4 reworded as approved. Criteria A1 to A6 approved as built in PR 7. F10, S5 and L2 no longer name LinkedIn.
- v1.4 (2026-10-15, notes; no criteria changed): **P4 failed after release.** The Oct 14 red and blue team review found that the conversation feed (API and MCP) showed email addresses and phone numbers from Discussion replies unmasked, and that look-alike characters (such as a full-width @, invisible characters or digits from other scripts) could slip past masking. An independent review on Oct 15 also found commit text in the changes feed unmasked. All three are fixed on Oct 15 for our API and MCP and covered by tests in test/security.test.js. **Still open under P4, for Aaron's decision:** the comments on /talk are shown by giscus straight from GitHub, so we can't mask them (the Release 2 plan replaces giscus with our own copy, G2). **Known limits of masking:** contacts spelled out in words ("jane at example dot com"), numbers split by colons, and IP addresses, which are hidden as numbers. The same change adds a short GitHub cache with a 4-second timeout (R1), a strict Content-Security-Policy with no framing (R2), and HTTPS required on every subdomain (today every web subdomain points at Vercel; a future subdomain without HTTPS would be refused by browsers). **C4 is not met:** GitHub's scheduler ran the 15-minute uptime check only twice overnight on Oct 14 to 15. Next step, on the to-do list: an outside uptime service, with the GitHub monitor kept as a backup.
- v1.4 (2026-10-14): adds C5 to C7 for MCP protocol version 2026-07-28, older clients and marking public text, from the landscape research Aaron requested. D4 now says open proposals only, after the first live run listed a closed test proposal.
- v1.3 (2026-10-14, added): L3, no copyrighted material in what we publish, at Aaron's direction. Applies now, not only at Release 2.
- v1.3 (2026-10-14): adds the Oct 19 checks: D1 to D5 for the daily sorting run (plan approved by Aaron) and C1 to C4 for Now/Next, Shipped, the draft_proposal tool and the uptime monitor.
- v1.2 (2026-10-14): legal checks L1 and L2 are approved by Aaron instead of outside lawyers, at Aaron's direction.
- v1.1 (2026-10-14): P1 clarified at Aaron's direction. It measures filing time once the proposer knows what to propose; thinking and preparation time is not counted, because it varies by idea and the form can't shorten it.
- v1.0 (2026-10-14): approved by Aaron with T = 3 minutes, H = 6 hours, M = 1,000 members; adds the speed and friction section (SF1 to SF6) and rule 7 (reopening approvals). Costs at scale are not yet modeled; Aaron may ask for that before Release 2.
- v0.2 (2026-10-14): Stripe is for payments only; verification through LinkedIn and X; trust levels; no limits plus an emergency brake; repeatable security gates with a risk register; built-to-grow requirements; Release 1 additions (P7 to P9) and reworded P4.
- v0.1 (2026-10-14): first draft by Claude, for Aaron's review.
