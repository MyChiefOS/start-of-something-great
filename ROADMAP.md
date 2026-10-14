# Roadmap

We publish every target date and whether we hit it. If a date slips, the original target stays here next to the new one, with the reason. Nothing is quietly edited.

"Done" means every check for that milestone in [ACCEPTANCE.md](ACCEPTANCE.md) passes.

_Last updated: October 14, 2026_

| Milestone | Target | Actual | Result | Depends on |
|---|---|---|---|---|
| Site, stories, domains and email | Oct 13 to 14 | Oct 14 | ✅ Done | |
| Public API and MCP server for AI agents | Oct 14 | Oct 14 | ✅ Done | |
| Acceptance criteria v1.0 | Oct 14 | Oct 14 | ✅ Done | |
| Release 1: proposals (checks P1 to P9 passing) | Fri, Oct 16 | Wed, Oct 14 | ✅ Done, 2 days early | Claude |
| Decide on blocking EU, EEA, UK and Swiss traffic (Vercel firewall) | Thu, Oct 15 | Wed, Oct 14 | ✅ Done, 1 day early: block once the full production system is live | Aaron's decision |
| Daily sorting run and GitHub automations | Mon, Oct 19 | Wed, Oct 14 | ✅ Done, 5 days early | Claude |
| Closing the loop: Now/Next, Shipped page, agent drafts, Connect page, uptime monitor | Mon, Oct 19 | Wed, Oct 14 | ✅ Done, 5 days early | Claude |
| Terms of service and privacy policy written | Wed, Oct 21 | Wed, Oct 14 | ✅ Done, 7 days early | Claude, with Aaron's decisions |
| Discuss automatic deletion of email after 7 years (privacy policy) | Wed, Oct 21 | | Not started | Aaron's decision; Google Workspace plan |
| Release 2 built on a private preview, all automated checks passing | Fri, Nov 6 | | Not started | Claude, plus Aaron's account checklist |
| Block EU, EEA, UK and Swiss traffic at the Vercel firewall | Fri, Nov 20 | | Not started | Release 2 public (full production system) |
| Release 2 public | Fri, Nov 20 | | Not started | **Outside approvals:** LinkedIn API approval, independent review |

## How we report

- When a milestone is reached or missed, this file is updated and a short note goes in [the conversation](https://dayonegreat.com/talk): hit or missed, by how much, and why.
- Agents can read the same roadmap from [dayonegreat.com/api/status](https://dayonegreat.com/api/status) or the MCP tool `get_status`.
