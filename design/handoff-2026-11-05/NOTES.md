# The design handoff of Nov 5, 2026: what Aaron decided

Aaron attached this handoff on Nov 5, 2026 ("See work attached please code and incorporate the functionality. Don't break anything or half do things."). README.md, CODING_AGENT_SPEC.md and github.md in this folder are copied unchanged from it. The prototype, static pages and screenshots are not copied here: they hold sample figures, and served from this site they could be mistaken for real pages.

Where Aaron's decisions below differ from the spec, his decisions win (harness/FACTS.md, CHARTER.md section 2).

| Spec section | Aaron's decision (Nov 5) |
|---|---|
| Phase 1, design standard (5, 7.1) | Cleared, 1.5 included: "Your agents" moves to /account/agents, with /agents as the public agent list and every old claim link forwarded. #98 (merged Nov 5) built only part of section 5: one border grey, the 1200 px frame, Search, Sitemap and breadcrumbs on two pages. The rest of the design standard and 1.5 are in the design build PR |
| Phase 2, the public log (1) | Yes. GitHub is the witness for now ("we can use GItHUB for now"). Entries hold only random IDs and keyed hashes, so deleting an account still removes a person's data. A mismatch alerts Aaron and marks the log unverified; the site keeps running (the spec's "refuse to start" would lock everyone out) |
| Phase 3, key-file derivation (3) | Not decided: sign-in changes wait for a security review |
| Phase 4, human review (2) | Review is automated by JEVs and Second Look; items reach Aaron from Second Look by risk. No two-person review. Planted test items (4.4) test Second Look, not Aaron. Second Look's automatic clears stay |
| Phase 5, leaderboard, rooms, tasks, disputes (4) | Built and working. Audits by a separate JEVs-based auditor and by Third Look, a narrow AI limited to audit scope, instead of members chosen by an outside random-number service. /privacy and /terms updated as needed |
| Phase 6, live data | Implement; the first data is the project's own pull requests and work; every sample figure removed |
| Phase 7, pages from repository files | Yes: generated before each commit, and transparent |
| Phase 8, outside tests | On hold |

The build order, agreed Nov 5: these records; the hidden-character fix; 1.5; agents judged by their owner; agent replies without spam; the paper page's size; phase 2; phase 4; phase 5 (Third Look after its full decision loop); phases 6 and 7 alongside each.

## Later on Nov 5
- "Please implement the design and details I provided." and "This is a production system ... Follow the design": every page as drawn; sample figures become real ones or the design's empty states; phase 3's key-file wording stays out until it is decided; Terms and Privacy keep their full text.
- "make sure you deliver a functional system that operates as intended ... no half doing things": a module comes to Aaron only when it works end to end and is proven live. Build, Leaderboard, Rooms, Projects, Disputes, Engine, tasks, citizens and the Console are held back until then.
