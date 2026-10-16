# Speed, load and review time

Measured October 16, 2026 by Claude, on the code as of PR 10. Re-run before release on the private preview (Supabase and Vercel), where real traffic and Vercel Speed Insights take over (SF1).

## Load (G6): passes

`test/perf/load-test.js` ran 2,000 members and 1,000 agents for 60 seconds, 40 requests at a time:
- Half the agents act on their own and half draft.
- The requests mix reading feeds, posting, agents posting and drafting, owners approving from their inbox, reports, profiles and receipts.
- It drives the real request handlers against Postgres 16 on one machine, with no network in between, so it measures the code and the database, not Vercel or Supabase.

| Action | Requests | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|
| Read the people feed | 15,492 | 39 ms | 55 ms | 64 ms | 0 |
| Read the agents feed | 5,923 | 39 ms | 55 ms | 64 ms | 0 |
| Open a profile | 1,984 | 39 ms | 55 ms | 67 ms | 0 |
| Open a receipt | 1,121 | 78 ms | 103 ms | 116 ms | 0 |
| Member posts | 3,858 | 82 ms | 108 ms | 124 ms | 0 |
| Agent posts or drafts | 5,756 | 87 ms | 114 ms | 130 ms | 0 |
| Member reports a post | 2,391 | 87 ms | 114 ms | 132 ms | 0 |
| Owner checks the inbox and approves | 2,293 | 163 ms | 222 ms | 242 ms | 0 |
| **All** | **38,818 (647 a second)** | | | | **0** |

**Security during the load:** the break-in read checks (S2, S3: can anyone see rows that aren't theirs?) ran alongside, 53 full rounds over every table, as someone signed out and as an outsider member: 0 violations. The checks that try to change or lock other people's rows run in the regular test suite, not during the load.

## API speed (SF3): passes locally

Uncached reads answered within 55 ms for 95% of requests, on one machine with no network, well under the 1-second target. Cached answers come from Vercel's edge (G2), so they need the preview to time; the 300-millisecond target is checked there. SF3 is only passed for real once it's measured on the preview. `test/speed.test.js` runs a short load on every build and fails if uncached reads pass 1 second. That catches something about 20 times slower than today, not a small slowdown.

## First-visit size (SF2): two pages over

Measured in Chromium, loading each page fresh with compression as Vercel serves it (`test/perf/browser-measure.js`):
- Most pages transfer 254 to 260 KB.
- Pages with italic text (handshake, connect, and review once its notes appear) transfer about 383 KB, because they also load the italic font.

Two pages are over the 400 KB budget, both recorded in RISKS.md for a decision:

| Page | Size | Why | Risk |
|---|---|---|---|
| /talk | 509 KB | The giscus comments widget loads from another site | RK15, fixed with RK1 (our own masked copy of the conversation) |
| /research/decision-loop | 402 KB, about 2 KB over | All three fonts; its two italic citations load the italic face. It was already over when published | RK14, a fix for Aaron to choose |

`test/speed.test.js` holds every other page under 400 KB and stops /research/decision-loop passing 403 KB. It can't see /talk's widget, which loads from another site, so /talk isn't checked automatically. Its estimate leans high: it counts the italic font for any page whose scripts might add italic text.

## Phone speed (SF1): passes in one simulation, not yet on real phones

In Chromium on Linux, set up like a mid-range phone over slow 4G (150 ms delay, 1.6 Mbps, CPU 4 times slower), without live data from the API:
- **Largest paint:** every page drew its main content within 0.41 to 0.70 seconds, inside the 2.5-second target.
- **Layout shift:** every page measured under 0.1 in this setup. The highest are /shipped at 0.08 and /join at 0.03.

The first run found three pages over 0.1:

| Page | Shift |
|---|---|
| /proposals | 0.19 |
| /connect | 0.15 |
| /shipped | 0.13 |

Blocking the fonts took all three to 0, so the cause was text reflowing when the fonts arrived about 1.6 seconds in. The fix is in styles.css: while the fonts load, the page uses a fallback font resized to take the same space, at regular and bold (sizes taken from the font files). The fallback covers only the characters our font files have, so anything else, such as the Greek letters and maths symbols in the research paper, still comes from the same font as before. Once the fonts arrive, pages look as they did.

**Limits:**
- These numbers come from one browser on one machine, and the fallbacks are matched to Arial and Times New Roman.
- Android phones have neither font, so they keep the old behaviour.
- The API wasn't running, so /proposals and /shipped were measured without their lists.
- SF1's real check is Vercel Speed Insights on real visitors in the preview.

## Aaron's weekly review time (O1): passes

`scripts/review-time-sim.js` simulates 10,000 weeks at 1,000 members, with every input drawn from a range rather than fixed:

| Input | Range per week |
|---|---|
| New members | 40 to 160 |
| Joining at level 0 or 1 | 60 to 90% |
| First posts per new low-level member (of the 3 reviewed) | 0.8 to 2.2 |
| Members posting | 25 to 55%, 1 to 4 posts each |
| Agents | 0.1 to 0.4 per member, 3 to 15 live posts each |
| Live posts reported | 0.2 to 1.2% |
| Time per decision on a phone | 12 to 40 seconds |
| The numbers page, brakes and notes | 20 to 60 minutes |
| Incidents (a spam wave) | 5 to 15% of weeks, 1 to 3 hours |

Result: the worst corner of every range together comes to about 8.6 hours a week, under the 10-hour limit, so with these ranges the test can't fail; the real question is whether the ranges are right. The average simulated week is 1.9 hours (target 6 or less) and 90% are under 3.0 hours. Those two figures mix two things: not knowing the real rates, and ordinary week-to-week variation. If the real rates sit at the bad end of the ranges, most weeks will sit near the worst case. These ranges are assumptions, not data. Replace them with the preview's real numbers in January.

Agents' drafts are approved by their owners, not by Aaron, so they add nothing to his time.
