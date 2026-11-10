# The standards Claude builds to

Aaron, Nov 10, 2026: "Moving forward use this standards as part of your framework for developing code for this project." The standards are NIST's SSDF, ISO/IEC 27001, OWASP, CISSP and CISA Secure by Design (CHARTER.md section 2). INTEGRITY.md still supersedes this file, and Aaron's standing decisions still stand: where a standard asks for something one of them rules out, the conflict is named in the PR, not worked around.

## How they are used

- **Before building:** name the standard's controls the change touches (the table below).
- **In every PR:** the alignment footer's "Standards" line names them and says how each was met, or why not.
- **A gap found** goes to RISKS.md like any other risk, with its control named (for example "OWASP A01").
- **The versions** are those current on Nov 10, 2026 (sources in FACTS). A new version is checked before it is used.

## What each asks, and where the project stands

Verified means read in the repository on Nov 10; inferred means Claude's judgment.

| Standard | What it asks | Where the project stands |
|---|---|---|
| NIST SSDF, SP 800-218 (1.1 final; 1.2 a draft since Dec 17, 2025) | Prepare the organization; protect the software; produce well-secured software; respond to vulnerabilities | Prepare: CHARTER, RULES, INTEGRITY (verified). Protect: the main branch is changed only by Aaron's merge, migrations are recorded with their sha256 (verified). Produce: the full suite, Semgrep and CodeQL on every PR, independent reviews for big changes (verified). Respond: RISKS.md, a weekly dependency watch (verified). Gap: no software bill of materials (verified: none in the repository) |
| ISO/IEC 27001:2022, Annex A 8.25 to 8.31 | A secure development life cycle; security requirements; secure architecture; secure coding; security testing; oversight of outsourced work; separate development, test and production | Met by the above, and outside agents' work passes JEVs, Third Look and Aaron's merge (verified). Production is kept apart from development by local throwaway databases; there is no shared test environment, by Aaron's decision (Oct 24, "no preview systems"), named here and not reopened |
| OWASP Top 10 (2025, a draft in Nov 2025, final expected 2026) and ASVS | The ten most common ways web apps are broken; ASVS, a checklist for verifying an app | A01 broken access control: RK140 and RK135 open, fix next (verified). A03 supply chain: `npm ci --ignore-scripts`, a lockfile, `npm audit` at critical in CI, the weekly watch (verified). A09 logging and alerting: audit logging part 2 not built (verified, PLAN). ASVS: no full check yet (verified) |
| CISSP, Domain 8 (ISC2) | Security in every stage of development, DevSecOps, judging the security of code and third-party software, secure coding | Covered by the SSDF and OWASP rows (inferred) |
| CISA Secure by Design, and Product Security Bad Practices (Jan 17, 2025) | The maker owns its customers' security; radical transparency; lead from the top; avoid the listed bad practices | Transparency: the public risks page, the public log, the public build (verified). Memory-safe language: JavaScript and SQL (verified). Unknown: every bad practice on CISA's list, one by one |

## Gaps, in the order they're fixed

1. **OWASP A01:** RK140, then RK135, the next two PRs (already planned).
2. **OWASP A09:** audit logging part 2, waiting on Aaron's OK for the Vercel Blob store's cost (already planned).
3. **SSDF and OWASP A03:** a software bill of materials made by CI from the lockfile. Claude, after RK135; small, no new service.
4. **OWASP ASVS and CISA's bad practices:** one pass over each before go-live, findings to RISKS.md. Claude.
