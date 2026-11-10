# The standards Claude builds to

Aaron, Nov 10, 2026, the core: "Moving forward use this standards as part of your framework for developing code for this project". These are NIST's SSDF, ISO/IEC 27001, OWASP, CISSP and CISA Secure by Design.

Aaron's additions, later the same day: "Add those additional worth adding standards. Also add HIPPA and FedRAMP processes mentioned for coding". These are the CWE Top 25, OWASP's Top 10 for LLM apps, SLSA, WCAG 2.2 AA, PCI DSS, a code style checker, and the coding practices of HIPAA's Security Rule and FedRAMP (CHARTER.md section 2).

HIPAA and FedRAMP are used for their coding practices only. Day One Great holds no health data and serves no government agency, so it is neither HIPAA-covered nor FedRAMP-authorized, and no page may say it is.

INTEGRITY.md still supersedes this file, and Aaron's standing decisions still stand. Where a standard asks for something one of them rules out, the conflict is named in the PR, not worked around.

## How they are used

- **The first "Bad news first" bullet of every PR** (Aaron, Nov 10: "acknowledge that you don't apply these coding principle unless specifically asked to for coding as the first line in the next few PR bad first bullet. Until the system is reasonably cleaned up with JEVs concurrence") says: "Claude doesn't follow a secure development process before it codes unless it is specifically asked to. Aaron asked on Nov 10, 2026, for these standards; until the code is cleaned up to them, with JEVs's concurrence, parts of it fall short, and there is still no safe copy of the site to red team (RK141)." It stays until the gaps below, 1 to 11, are fixed and an independent reviewer for JEVs agrees the code is reasonably cleaned up; that agreement is recorded in FACTS.
- **Before building, in the PR, before its code:** a short threat model (what could go wrong, who could do it, what stops it) and the change's security requirements (SSDF PW.1), naming the standard's controls it touches (the tables below). Claude didn't do this before Nov 10 unless asked, and didn't say so (Aaron, Nov 10).
- **A safe copy to red team:** none has ever existed (RK141); Claude owns building one (gap 1 below).
- **In every PR:** the alignment footer's "Standards" line names them and says how each was met, or why not.
- **A gap found** goes to RISKS.md like any other risk, with its control named (for example "OWASP A01", "CWE-862").
- **Release gates stay repeatable** (Aaron, Oct 2026): scanners and tests gate; AI-based security reviews and penetration tests find things and report them, never gate.
- **The versions** are those current on Nov 10, 2026 (sources in FACTS). A new version is checked before it is used.

## What each asks, and where the project stands

Verified means read in the repository on Nov 10; inferred means Claude's judgment.

### The core

| Standard | What it asks | Where the project stands |
|---|---|---|
| NIST SSDF, SP 800-218 (1.1 final; 1.2 a draft since Dec 17, 2025) | Prepare the organization; protect the software; produce well-secured software; respond to vulnerabilities | Prepare: CHARTER, RULES, INTEGRITY (verified). Protect: migrations are recorded with their sha256, every Action is pinned by commit, unverified commits are refused (verified); main needs 0 approvals and merges come from the MyChiefOS account, which Claude's sessions also use, so "only Aaron merges" is a convention (RK71), and a PR can edit its own required check (RK146, inferred). Produce: the full suite, Semgrep and CodeQL on every PR, independent reviews for big changes (verified). Respond: RISKS.md, a daily dependency watch (verified: watch.yml). Gap: no way to receive vulnerability reports (RK147). Gap: no software bill of materials (verified: none in the repository) |
| ISO/IEC 27001:2022, Annex A 8.25 to 8.31 | A secure development life cycle; security requirements; secure architecture; secure coding; security testing; oversight of outsourced work; separate development, test and production | Met by the above, and outside agents' work passes JEVs and Third Look before a merge, which isn't checked to be Aaron's (RK135; verified). Production is kept apart from development only by Claude's local throwaway databases, which nobody else can reach. Claude never built a safe copy for Aaron or his agents to red team (RK141, Claude's to fix). The private preview dropped on Oct 24 was a stage of the live site, not a separate copy |
| OWASP Top 10 (2025: a draft in Nov 2025, reported final since; inferred, not read on owasp.org) and ASVS | The ten most common ways web apps are broken; ASVS, a checklist for verifying an app | A01 broken access control: RK140 and RK135 open, fix next (verified). A03 supply chain: `npm ci --ignore-scripts`, a lockfile, `npm audit` at critical in CI, the weekly watch (verified). A09 logging and alerting: audit logging part 2 not built (verified, PLAN). ASVS: no full check yet (verified) |
| CISSP, Domain 8 (ISC2) | Security in every stage of development, DevSecOps, judging the security of code and third-party software, secure coding | Covered by the SSDF and OWASP rows (inferred) |
| CISA Secure by Design, and Product Security Bad Practices (Jan 17, 2025) | The maker owns its customers' security; radical transparency; lead from the top; avoid the listed bad practices | Transparency: the public risks page, the public log, the public build (verified). Memory-safe language: JavaScript and SQL (verified). Unknown: every bad practice on CISA's list, one by one |

### The additions

| Standard | What it asks | Where the project stands |
|---|---|---|
| CWE Top 25 (MITRE and CISA, Dec 11, 2025) | The most dangerous coding mistakes; the top four are cross-site scripting (CWE-79), SQL injection (CWE-89), cross-site request forgery (CWE-352) and missing authorization (CWE-862) | CWE-79: a Content-Security-Policy header on every path (verified: vercel.json), checked by the uptime monitor. CWE-89: queries are parameterized tagged templates (verified). CWE-352: session cookies are SameSite=Lax, and every POST checks Origin (verified: signin/http.js, signin/flow.js); some administrator reads that write audit rows are GETs (RK145). CWE-862: RK140 and RK135 open (verified). Unknown: the other 21, one by one |
| OWASP Top 10 for LLM apps (2025) | Prompt injection; sensitive data disclosure; supply chain; data poisoning; improper output handling; excessive agency; system prompt leakage; vector weaknesses; misinformation; unbounded consumption | Second and Third Look: text is masked before the model sees it; fixed checks catch hidden instructions; only the exact JSON answer is accepted; the model only decides within code's limits and can't merge; daily caps; the token goes only to Vercel's gateway (verified: their tests). Corrected Nov 10 by an independent review: Third Look's model reads only the first 5,000 characters of a change (RK142), and the fixed checks run before Unicode normalisation, so look-alike letters and invisible tag characters get past them (RK143); the real ceiling on model calls is about 400 a day (RK100). Met: LLM02, 04, 05, 07; partly: 01, 03, 06, 09, 10; not applicable: 08 |
| SLSA (v1.2) | Proof of where each release came from and how it was built, at rising levels | The site: 99 of 99 production deploys are commits on main (verified by an independent review, Nov 10). The three Supabase functions are deployed from a Claude session, not by a build service. Gap: no signed provenance for a release, and no releases or tags (verified) |
| WCAG 2.2, level AA | Accessibility: what people with disabilities need to use the site | The browser checks test contrast, field edges and phone widths, dark and light (verified: scripts/check-join-panel.js, check-shell.js). Gap: no full WCAG 2.2 AA check (verified) |
| PCI DSS (v4.0.1, inferred current) | The card industry's security rules for any system that touches card data | Payments are not built (verified, PLAN). Planned: cards typed only on Stripe's own pages, so card data never reaches the site and its share of the rules stays small (inferred) |
| A code style checker (ESLint) | One consistent, checked style that also catches common bugs | None in the repository (verified). Gap |
| HIPAA Security Rule, technical safeguards (45 CFR 164.312; the update proposed Jan 2025 moved to July 2027) | Access control with unique IDs and automatic logoff; audit controls; integrity; authentication; transmission security. The proposed update adds encryption, MFA, network segmentation, an annual penetration test and a written incident response plan tested every year | Unique IDs (GitHub accounts) and HSTS on every page (verified). Integrity: the public log's signed checkpoints (verified). Audit controls: part 2 not built (verified). Automatic logoff: sessions last 30 days unused (verified: signin/config.js), far longer than health systems use; named as a difference, not changed, since usability comes first (Aaron, Oct 23). Gaps: no written incident response plan (verified: none found); no penetration test (verified) |
| FedRAMP, the Vulnerability Detection and Response standard (in its 2026 rules) | Find vulnerabilities persistently, not once a month; fix CISA's Known Exploited Vulnerabilities by CISA's due dates; judge each by whether the internet can reach it and whether it's likely exploitable; record anything left over 192 days as an accepted vulnerability, with why | Persistent: Semgrep on every PR (required), CodeQL on every PR (not required, and its scope skips supabase/, secondlook/, thirdlook/, notify/ and verifier/: RK146), the daily dependency watch (verified). Accepted vulnerabilities: RISKS.md does this job (verified). Gaps: no check of dependencies against CISA's KEV list; findings below critical have no first-seen dates for the 192-day rule (verified) |

## Gaps, in the order they're fixed

Updated Nov 10 with four independent reviews (#123, the web app, the AI parts, the process; their findings verified by Claude and recorded in RISKS.md). Nothing critical or high was found.

1. **RK141, a safe copy to red team (Claude, before Release 2):**
   - GitHub Actions builds the site and a throwaway database with test accounts, on demand and on every PR. First, so the fixes below are red teamed before Aaron merges them.
   - It runs Claude's own attack suite against it. Its first check: every definer function the site's role can run must check who is acting or carry a recorded reason; on Nov 10, 68 had no check of their own, and the review found five of them to be findings (RK140, RK135, RK144, RK112).
   - Then every route against every role, injection, cross-site scripting and request forgery.
   - It also runs any attack plan Aaron or an agent he directs writes in an issue, and posts the report.
   - The suite's repeatable results gate; anything found by hand goes to RISKS.md.
   - Outside tools such as OWASP ZAP only with Aaron's OK (no outside sources without discussion).
   - The preview (approved Nov 10, about $10 a month): Vercel's preview of each PR on a Supabase preview branch built only from the migrations and made-up data, created only after Aaron merges the PR that builds it.
2. **#123's review findings, in #123 with Aaron's yes:** the token check requires the claims back; the key fetch gets a time limit; the uptime check confirms against a fresh read; the two-clocks comment and test corrected; the RK134 tests run without a database; the description brought to this guide.
3. **The AI fixes:** RK142 (Third Look counts anything over what the model reads as cut), then RK143 (checks on normalised text; tag characters stripped except in flags).
4. **Broken access control (OWASP A01, CWE-862):** RK140, then RK135, then RK144 and RK112, then RK100's sl_claim and sl_decide (the same pattern for Second Look), then RK145.
5. **Taking in vulnerability reports (RK147):** SECURITY.md with a disclosure policy and response times, linked from security.txt; private vulnerability reporting and Dependabot alerts turned on (approved Nov 10; Claude's session can't write repository settings, so these are Aaron's clicks).
6. **The required gate (RK146):** a guard on PRs that change .github/workflows; CodeQL's scope widened; CodeQL made required and the log-witness ruleset applied (approved Nov 10; Aaron's clicks, for the same reason).
7. **OWASP A09, HIPAA audit controls:** audit logging part 2, waiting on Aaron's OK for the Vercel Blob store's cost (already planned).
8. **Supply chain (SSDF, OWASP A03, SLSA, FedRAMP):** in one PR, with no new service:
   - a software bill of materials from the lockfile;
   - the daily watch flags anything on CISA's KEV list;
   - findings carry first-seen dates;
   - signed build records and tagged releases;
   - a report-only scan with the newest rules beside the pinned gate.
9. **ESLint:** errors only at first, so no file is restyled in bulk. Claude.
10. **Before go-live, one pass each, findings to RISKS.md:**
   - OWASP ASVS;
   - the rest of the CWE Top 25;
   - WCAG 2.2 AA, with the browser checks made repeatable in CI (Playwright in the lockfile) and the PIN fields' autocomplete fixed;
   - CISA's bad practices.
   Claude.
11. **A written incident response plan,** built on the close-the-site runbook, with a yearly test. Claude, before go-live.
12. **With payments:** PCI DSS, card data only on Stripe's pages.
13. **After go-live:** a yearly penetration test, findings to RISKS.md, never a gate; until then the attack suite of gap 1 runs on every PR. Off-site backups or point-in-time recovery (RK148). Both cost money, so Claude prepares each as a costed choice for Aaron.
