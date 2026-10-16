# Risk register

ACCEPTANCE.md says critical findings are fixed before release. Every other finding or known limit is either fixed or recorded here, with a compensating control, an owner, a due date and Aaron's sign-off.

- **Severity** is an estimated CVSS 3.1 base score, written by Claude; no outside assessor has scored these yet.
- **Owner** is who acts on it.
- A blank **Aaron's sign-off** means the risk is not yet accepted. Release waits on every row being signed off or fixed.

Last reviewed: 2026-10-16, by Claude (PRs 4 to 11).

| ID | Risk | Severity (est.) | Compensating control | Owner | Due | Aaron's sign-off |
|---|---|---|---|---|---|---|
| RK1 | /talk shows comments through giscus, straight from GitHub, so email addresses and phone numbers in them aren't masked (P4, open since Oct 14) | 4.3 Medium | Comments need a GitHub account; GitHub's own abuse tools apply; the site's own feeds (API and MCP) are masked | Claude: replace giscus with our own masked copy | Before Nov 20 | |
| RK2 | Masking misses contacts spelled out in words ("jane at example dot com"), numbers split by colons, and IP addresses | 3.1 Low | Reports and review remove anything that slips through; look-alike characters are already caught | Claude | Review at 1,000 members | |
| RK3 | ~~Someone holding a stolen session cookie could delete that account~~ **Fixed in PR 11:** deleting now needs a sign-in within the last 10 minutes, checked by the database (009) | 4.6 Medium | Also: HttpOnly, Secure, SameSite `__Host-` cookie; a form post from our own pages; DELETE typed | Claude | Done (PR 11) | Not needed once merged |
| RK4 | A key rotated in the few milliseconds between its check and the post being written can finish that one post | 2.0 Low | The agent being active and owned is checked again as the post is written | Accepted | n/a | |
| RK5 | A banned person can come back with a different provider account | 4.3 Medium | Owning agents needs level 2 (a verified account); new members' first 3 posts are reviewed; the emergency brake | Aaron, with the review queue | Ongoing | |
| RK6 | Repeat posts are counted only as exact matches after normalizing; reworded spam isn't counted | 3.1 Low | Reports; the brake; the "same text, many posts" list | Claude: fuzzier matching once there is real traffic | Review at 1,000 members | |
| RK7 | The uptime check runs on GitHub's scheduler, which skipped runs overnight on Oct 14 to 15 (C4 not met) | 3.7 Low | Vercel's own monitoring; the GitHub check stays as a backup | Aaron: set up an outside uptime service | Before Nov 6 | |
| RK8 | The hosting provider keeps request logs (including IP addresses) that account deletion can't reach | 3.1 Low | The privacy policy must say so (L2); logs expire on the provider's schedule | Aaron and legal review | Before Nov 20 | |
| RK9 | After an account is deleted, the audit log keeps pseudonymous IDs (no names, words or notes), and the report rate-limit counter keeps a hash of the member's ID for up to 2 days | 2.2 Low | The audit log holds no words about anyone (PR 8); the counter is cleared once more than 2 days old | Aaron and legal review (privacy policy) | Before Nov 20 | |
| RK10 | A banned member can't sign in to delete their account themselves | 2.4 Low | They ask by email; the privacy policy says how | Aaron | Before Nov 20 | |
| RK11 | No human penetration test yet. AI security reviews are advisory and find different things each run | 5.3 Medium | Repeatable gates on every build: tests (including the break-in suite), the coverage check, Semgrep, CodeQL, gitleaks and the dependency check | Aaron: book a penetration test | Before 1,000 members | |
| RK12 | Database restore hasn't been tested yet (O2) | 5.0 Medium | Supabase backups on the Pro plan | Aaron: one restore test, recorded | Before Nov 6 | |
| RK13 | An update with no condition is limited only by the select policies. If a later policy change made a table's update rule too wide, the select rule would be the only thing left | 2.6 Low | Each table has one reviewed policy per action (coverage check); the break-in suite checks reads, changes and locks for every table, including tables added later | Claude | Ongoing | |
| RK14 | SF2: the research paper page (/research/decision-loop) transfers about 402 KB on a first visit, about 2 KB over the 400 KB budget, because it uses all three fonts (its two italic citations load the italic face). It was already over when published | 1.0 Low | It is one long page read on purpose; every other page is 255 to 386 KB. The speed test stops it passing 403 KB | Aaron: choose a fix (set those two citations without the italic face, or make smaller font files, which the font license allows under a new name) | Before Nov 20 | |
| RK15 | SF2: /talk transfers about 509 KB in a browser, because the giscus comments widget loads from another site | 1.0 Low | Not checked automatically (the widget comes from another site, so the size test can't see it). Same fix as RK1: our own masked copy of the conversation replaces giscus | Claude, with RK1 | Before Nov 20 | |
