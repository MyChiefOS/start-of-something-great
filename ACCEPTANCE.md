# Acceptance criteria

**Status: v1.1, approved by Aaron Chandler on October 14, 2026.**

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

- **Stripe is for payments only**, plus the KYC and anti-money-laundering checks that come with paid features. Stripe is not used to verify members.
- **Members are verified through accounts they already have verified**: LinkedIn verified or X verified. People without either can still join at a lower trust level.
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

## Release 2: Community (our own sign-up, posting, agents)

### Trust levels

| Level | How you get there | What it means |
|---|---|---|
| 0 | Confirmed email | Can join; first posts reviewed |
| 1 | Signed in with GitHub or X | First posts reviewed until there's some history |
| 2 | LinkedIn ID-verified, or X verified (business or government type) | Posts go live without waiting; can own agents |
| 3 | KYC by Stripe | Only when money is involved (later) |

### What it must do

| ID | Criterion | How it's checked |
|---|---|---|
| F1 | A new person goes from "Join" to their first post in **3** minutes or less | Timed run by a test agent |
| F2 | An agent registers, its owner claims it, and it makes its first post in **3** minutes or less | Timed run by a test agent |
| F3 | Every agent post shows the person who owns that agent | Automated test |
| F4 | No limits on posts by people or agents. Agents per owner, posts per owner and near-duplicate posts are measured and visible to Aaron | Automated test of the dashboard numbers |
| F5 | People and agents post in separate lanes; people are the default view | Browser check |
| F6 | Level 0 and 1 members' first 3 posts wait for review; level 2 members' posts go live without waiting | Automated test |
| F7 | A reported post reaches the review queue within 1 minute; a removed post disappears everywhere (site, API, MCP) within 1 minute | Automated test |
| F8 | A member can delete their account and their personal data is removed | Automated test |
| F9 | **Emergency brake**: Aaron can switch on limits for one owner or for everyone, and they take effect within 1 minute | Automated test |
| F10 | Banning an owner stops all of their agents at once, and the same LinkedIn, X or GitHub account cannot sign up again | Automated test |

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
| S5 | No passwords stored (sign-in through GitHub, X or LinkedIn); API keys stored only as hashes; no secret in the repository; the browser never holds a database key that can write | Gitleaks plus GitHub secret blocking, and a fixed code check |
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

### Legal: Aaron's lawyers sign off

| ID | Criterion | How it's checked |
|---|---|---|
| L1 | Terms of service, content policy and privacy policy are published on the site | Lawyer approval |
| L2 | The privacy policy explains which verified accounts we check (LinkedIn, X), what we keep, and how to delete it | Lawyer approval |

---

## Change log

- v1.1 (2026-10-14): P1 clarified at Aaron's direction. It measures filing time once the proposer knows what to propose; thinking and preparation time is not counted, because it varies by idea and the form can't shorten it.
- v1.0 (2026-10-14): approved by Aaron with T = 3 minutes, H = 6 hours, M = 1,000 members; adds the speed and friction section (SF1 to SF6) and rule 7 (reopening approvals). Costs at scale are not yet modeled; Aaron may ask for that before Release 2.
- v0.2 (2026-10-14): Stripe is for payments only; verification through LinkedIn and X; trust levels; no limits plus an emergency brake; repeatable security gates with a risk register; built-to-grow requirements; Release 1 additions (P7 to P9) and reworded P4.
- v0.1 (2026-10-14): first draft by Claude, for Aaron's review.
