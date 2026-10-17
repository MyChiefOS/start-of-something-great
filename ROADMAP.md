# Roadmap

We publish every target date and whether we hit it. If a date slips, the original target stays here next to the new one, with the reason. Nothing is quietly edited.

"Done" means every check for that milestone in [ACCEPTANCE.md](ACCEPTANCE.md) passes.

_Last updated: October 16, 2026_

| Milestone | Target | Actual | Result | Depends on |
|---|---|---|---|---|
| Site, stories, domains and email | Oct 13 to 14 | Oct 14 | ✅ Done | |
| Public API and MCP server for AI agents | Oct 14 | Oct 14 | ✅ Done | |
| Acceptance criteria v1.0 | Oct 14 | Oct 14 | ✅ Done | |
| Release 1: proposals (checks P1 to P9 passing) | Fri, Oct 16 | Wed, Oct 14 | ✅ Done, 2 days early. Correction, Oct 15: the Oct 14 security review found P4 failing in the conversation feed (email addresses and phone numbers in Discussion replies weren't hidden); fixed Oct 15 | Claude |
| Decide on blocking EU, EEA, UK and Swiss traffic (Vercel firewall) | Thu, Oct 15 | Wed, Oct 14 | ✅ Done, 1 day early: block once the full production system is live | Aaron's decision |
| Daily sorting run and GitHub automations | Mon, Oct 19 | Wed, Oct 14 | ✅ Done, 5 days early | Claude |
| Closing the loop: Now/Next, Shipped page, agent drafts, Connect page, uptime monitor | Mon, Oct 19 | Wed, Oct 14 | ✅ Done, 5 days early | Claude |
| Terms of service and privacy policy written | Wed, Oct 21 | Wed, Oct 14 | ✅ Done, 7 days early | Claude, with Aaron's decisions |
| MCP protocol 2026-07-28 support, public text marked, queue fix | Wed, Oct 14 (added that day) | Wed, Oct 14 | ✅ Done, same day | Claude |
| Security fixes from the red and blue team review | Thu, Oct 15 (added that day) | Thu, Oct 15 | ✅ Done, same day | Claude |
| Research section and Working Paper No. 1 published | Thu, Oct 15 (added that day) | Thu, Oct 15 | ✅ Done, same day | Claude, with Aaron's approval |
| Discuss automatic deletion of email after 7 years (privacy policy) | Wed, Oct 21 | | Not started | Aaron's decision; Google Workspace plan |
| Release 2 built on a private preview, all automated checks passing | Fri, Nov 6 | | In progress: PRs 1–6 merged (PR 3 a week early, PR 4 ten days early, PR 5 twelve days early, PR 6 six days early); PR 8 (your account and deleting it, target Fri, Oct 30) merged Oct 16, two weeks early; PR 7 (agents acting for their owners, criteria A1–A6 approved Oct 16) merged Oct 16; PR 9 (security gates) merged Oct 16; PR 10 (speed) in review | Claude, plus Aaron's account checklist |
| PR 12: JEVs core (the automated checks: questions in code, private thresholds, shadow and enforce modes, automatic level 2, sign-up bot checks, the regional gate in code, the test-agent fleet) | Fri, Nov 6 (part of Release 2) | Fri, Oct 16 | Built, waits its turn | Claude; Aaron sets the thresholds and switches to enforce |
| PR 13: notifications (in-app only: the inbox, one tap on the notice, the 90-day check, containment with appeal; sign-in email through Amazon SES) | Fri, Nov 6 (with the preview) | | Built, waits its turn: one PR open at a time, after PR 12 (JEVs). Criteria N1 to N11, R16 and R33 wait for Aaron's approval | Claude; Aaron's AWS setup (EMAIL-SETUP.md) |
| PR 15: sign-in fixes (linking a method needs a fresh sign-in and makes no session; unlink on /account; agents follow their owner's live verified level; the 90-day keep needs a fresh sign-in) | Fri, Nov 6 (added Oct 16; blocks go-live) | | Built, waits its turn: one PR open at a time. R33 changed (ACCEPTANCE.md v1.8), waiting for Aaron's approval | Claude |
| PR 17: passkeys as the proof for risky grants (D5, step 2 of the sign-in plan): a passkey check in the last 5 minutes to let an agent act on its own, raise the cap of one that acts, make a key for one that acts, keep one acting at day 90, link or unlink a sign-in method, delete an account, and for every one of Aaron's controls; 72-hour recovery; a linked method's passkeys go with it | Not set yet (added Oct 17; Aaron to set) | | Built on PR 15, waits its turn: one PR open at a time, after PRs 15 and 16. Criteria PK1 to PK12 (ACCEPTANCE.md v1.9) wait for Aaron's approval | Claude |
| Block EU, EEA, UK and Swiss traffic at the Vercel firewall | Fri, Nov 20 | | Not started | Release 2 public (full production system) |
| Release 2 public | Fri, Nov 20 | | Not started | **Outside approvals:** independent review. (LinkedIn API approval removed Oct 16, 2026: LinkedIn dropped.) |

## How we report

- When a milestone is reached or missed, this file is updated and a short note goes in [the conversation](https://dayonegreat.com/talk): hit or missed, by how much, and why.
- Agents can read the same roadmap from [dayonegreat.com/api/status](https://dayonegreat.com/api/status) or the MCP tool `get_status`.
