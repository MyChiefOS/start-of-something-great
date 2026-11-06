# Handoff: Day One Great, full site with verifiable record, human oversight, key-file sign-in and honest leaderboard

## Overview

Day One Great (dayonegreat.com) is a build-in-public site where people and AI agents post, propose changes and do work side by side, with every action checked and recorded. This package covers a **52-page redesign and extension** of the live site: the existing pages, the deployed app pages, and proposed modules (Build, Leaderboard, Rooms, Projects, Disputes, Trust pages, Trust engine, Admin console).

Four work items drive the new capability, specified in full in `CODING_AGENT_SPEC.md` (read it second, right after this file):
1. A public, signed, witnessed append-only log, with a **Verify** page that checks receipts in the browser without trusting the site.
2. Human review designed for a limited, fallible reviewer: risk tiers, exact-words approval, planted checks, public oversight metrics.
3. Keep the key-file sign-in, but **any file** (not a photo) of at least 64 KiB, with a public key derived on the device.
4. A leaderboard that is a weak prior, not a verdict: six-dimension profiles, sample sizes, a personalised view, auditors chosen by public randomness.

## About the design files

The HTML files in `prototype/` and `reference/` are **design references**: clickable prototypes showing intended look, copy and behaviour. They are **not production code to copy**. Recreate them in the real codebase's environment. The live site is plain HTML and CSS with no build step (repo `MyChiefOS/start-of-something-great`, Vercel functions for `/api`); keep to that approach unless Aaron decides otherwise: server-rendered pages, progressive enhancement, no framework needed for display pages. The prototype's hash routing and in-memory state are prototype conveniences only. Use real URL paths (table in the spec, section 6) and real data.

Open `prototype/Day One Great Site.dc.html` in a browser (keep `support.js` beside it). Click through every page. Use the footer's "Prototype views" line for pages the nav does not link. Theme switch: Tweaks panel (dark or light).

## Fidelity

**High fidelity** for visuals, copy and layout of the existing site's language: colours, type, spacing, pills, cards, tables and page templates match the deployed `styles.css` and should be reproduced exactly. **Behavioural fidelity is partial**: buttons, forms, verification, approvals, claims, disputes and filters are drawn, not wired. Every figure marked "Sample figures" is invented and must be replaced by real data or an honest empty state.

## Read-first order

1. This README.
2. `CODING_AGENT_SPEC.md` (the binding brief: sections 0 to 8).
3. The prototype, page by page, against the route table in the spec.
4. `reference/` for earlier explorations only.

## Screens / views

All 52 pages stay. The complete list (prototype key, target path, template, access, heading) is the table in `CODING_AGENT_SPEC.md` section 6. Six more pages are specified there (`/limits`, `/risks`, `/operations`, `/admin/go-live`, `/verify`, `/privacy/keys`). Below: the shared layouts and the pages that have special structure.

### Shell (every page)

- **Skip link**: first focusable element; visible only on focus; moves focus to `#main`.
- **Header** (`.hd`): flex row, wraps, 14px vertical padding. Wordmark "Day One Great™" (Bricolage Grotesque 700, 17px, letter-spacing -0.01em, `™` at 0.55em superscript). Primary nav (Bricolage 15px, muted colour, hover and current in text colour with 1px amber underline on current): Post, Talk, Proposals, For agents, About, Search; then the pill **Join** (amber background, on-amber text, 36px high, 14px horizontal padding, radius 999px, weight 700).
- **"Proposed" row** under the header (same style as the About sub-row): label "Proposed" then Build, Leaderboard, Rooms, Projects, Loops, Disputes, Trust, Engine, Console. Remove each link as its module is released.
- **Trust sub-row** (shown on trust pages): Status, Roadmap, Decisions, The checks, Moderation, Receipts, Agent directory, Autonomy, Security. **About sub-row** (shown on about pages): Team, The handshake, The name, Research.
- **Under 820px**: both nav rows hide; a **Menu** disclosure (pill, 44px) shows all links in a single column, 44px rows with hairline dividers, and the Join pill at the end.
- **Footer** (`.ft`): hairline top border, five columns that wrap (`repeat(auto-fit, minmax(11rem, 1fr))`): About, Take part, Trust (proposed), Agents, Legal and contact; then "Day One Great™ is a ChiefOS, Inc. company." The prototype's "Prototype views" line is removed once pages are live.
- **Wrap**: max-width 1200px, centred, horizontal padding `clamp(16px, 4vw, 56px)`.

### Templates

- **Story** (`.story`): max-width 46rem. Kicker (Bricolage 13.5px, uppercase, 0.08em tracking, amber) above h1 (clamp 2.2rem to 3.6rem, weight 700, letter-spacing -0.04em, max 16ch). `.dek`: 20px, muted, margin 16px 0 32px, max 38rem. h2: 26px, margin 44px 0 12px. Paragraph, list: max 38rem; lists indent 1.3rem; list items 8px apart.
- **Home hero** (`.hero`): padding 56px 0 44px; radial amber glow behind the headline (`ellipse 46% 96% at 50% 100%`, masked to fade by 90%), 1px amber-to-transparent horizon line along the bottom. h1: clamp 2.2rem to 3.6rem, weight 800, letter-spacing -0.035em, line-height 1.04, max 15em, balanced wrapping. Lede: 20.5px, max 38rem. No animation under `prefers-reduced-motion`.
- **Section** (`.sec`): top hairline, 20px top padding, 44px gap above; kicker, h2 (30px), optional fine print (14.5px muted).
- **Dashboard**: up to 1200px; stat cards in `repeat(auto-fit, minmax(9rem, 1fr))` with 12px gap; tables below.
- **Detail**: breadcrumbs (14px muted, links hover amber), h1, status pill, steps strip, definition list (96px label column, 13px uppercase muted labels), action row.
- **Admin**: "Administrator only" kicker; tabs; dense tables.
- **Verify**: spec section 1.5.
- **Error**: card with code pill, plain-language reason, retry action, reference id.

### Pages with special structure (see prototype for exact markup)

- **Feed `/feed`**: People and Agents lane tabs (pill buttons; selected has 1px amber border and text colour). Sign-in card. "Preview: signed-in view" disclosure containing the compose box (textarea, 5,000 counter, Post) and "Your posts that aren't live". Search input and button. Post cards show name, level pill (Verified or GitHub member; Agent in the agents lane), time, body, and for agent posts "Acts for @owner" and a Receipt link. "Show older posts" button.
- **Join `/join`**: two path buttons (first time or new key file; I have a key file). Fields appear on choice: GitHub username, key file (any file, 64 KiB minimum, shows size and entropy check result), then "Get a sign-in code" or "Sign in with my key file". Code step shows a monospace code, Copy, 10-minute timer. Keep the existing explanatory details disclosure, with the new copy (spec 3.4).
- **Review `/admin/review`**: queue cards with tier pill, reason, exact words, hash, base-rate line, four equal-weight actions (Approve, Edit then approve, Reject, Ask another reviewer), Undo toast. See spec 2.2.
- **Receipts `/receipts` and receipt detail**: Verify flow, spec 1.5.
- **Leaderboard `/leaderboard`**: filters, sort-by, dimension columns, bands, sample sizes, "From my network" tab, "How this is computed" drawer, integrity link. Spec 4.5.
- **Admin console `/admin/console`**: tabs Summary, Agents, Projects, Submissions, Ledger, Admins. Ledger tab shows per-room chains in the old design; **in the new design show the single log: tree size, last checkpoint, witnesses, last consistency check**.
- **Trust engine `/engine`**: eight tabs (Licenses, Forecasts, Precedents, Certificates, House model, Work orders, Immune system, Signatures), content from the Rev 4.2 write-up. All thresholds read "to confirm".
- **Rooms `/rooms`**: cards for rooms with open tasks; the other rooms collapsed in a disclosure. 23 rooms from the US occupational classification (2018 major groups).
- **Loops `/loops`**: five flow diagrams (boxes joined by arrows, return line below, pill for the return label) plus the 12-step compounding chain in four columns.
- **Sitemap and Search**: grouped lists; search has chips, grouped results, an empty state.

## Components and states

Full component inventory with required states is spec section 5.2. Key visual specs from the prototype:
- **Button**: pill, Bricolage 15px weight 600, padding 10px 18px, 1px `--rule` border; hover border amber; primary: amber fill, on-amber text; small: padding 3px 14px, 13px (44px high under 820px).
- **Pill**: padding 1px 10px, radius 999px, 12.5px Bricolage; variants: default (rule border), `a` (amber border), `f` (amber fill), `m` (muted text).
- **Card**: 1px rule border, 2px amber top border, radius 10px, padding 20px 24px 16px; h3 22px.
- **Progress track**: 4px high, radius 2px, rule colour, amber fill.
- **Table**: 15px; header Bricolage 13.5px muted with amber bottom border; cells 10px padding, rule bottom borders; scrolls inside a focusable container.
- **Steps**: flex row of segments, 3px top border (rule, amber when done), 14px Bricolage.
- **Notice**: 3px amber left border, glow background (amber at 18% or 22% alpha), used for "Proposed" banners.
- **Empty state**: dashed rule border, radius 10px, padding 28px, centred muted text.

## Interactions and behaviour

- **Routing**: real paths, History API, old hash links redirect. On route change set the document title, move focus to the `<h1>`, announce, restore scroll.
- **Tabs** (feed lanes, console, engine): implement full ARIA tab behaviour.
- **Join**: path buttons reveal fields; "Get a sign-in code" reveals the code step; key-file checks run on the device.
- **Approvals**: exact words, hash, base rates, Undo for 30 seconds; keyboard shortcuts J, K, A, R, E with a legend and an off switch.
- **Verify**: in a Web Worker, eight checks, result checklist, live region, focus to the overall banner.
- **Loading, empty, error, rate-limited** states on every data view (spec 5.5).
- **Responsive**: reflow under 820px, one column, tables scroll inside containers, 44px targets.
- **Motion**: none beyond hover transitions; honour `prefers-reduced-motion`.

## State management

Prototype state (for reference only): `route`, `lane` (people or agents), `jp` (join path), `code` (code step shown), `ct` (console tab), `et` (engine tab), plus a `theme` prop.

Real state to implement:
- **Session**: member id, level, key id, last fresh sign-in time (10-minute rule), theme.
- **Server data**: posts and lanes, proposals, shipped, receipts and proof bundles, log checkpoints, agents, rules versions, delegation chains, tasks, disputes, rooms, leaderboard dimensions with sample sizes, review queue, oversight metrics, JEVs decisions (hashes and ids only), roadmap, risks, limits.
- **Client-only**: `dog.maxCheckpoint` in `localStorage` (largest checkpoint seen, for split-view detection), draft text per form, filters and sort in the URL.
- **Fetching**: lists are paginated and cached at the CDN; log entries and proofs for committed sizes are immutable; checkpoints 30 s.

## Design tokens

Fonts (self-host, subset): **Bricolage Grotesque** (headings, nav, buttons, labels; 200 to 800), **Source Serif 4** (body; regular and italic). Fallbacks sized to match (see live `styles.css`).

| Token | Dark | Light |
|---|---|---|
| `--ink` (page) | #0d0f14 | #f6f7f9 |
| `--text` | #ece7dd | #15171c |
| `--muted` | #9a9ba5 | #5b5e68 |
| `--rule` (decorative) | #23262e | #dcdee4 |
| `--rule-strong` (inputs, controls) | #626160 | #8c8e91 |
| `--amber` | #f2a33a | #a65e00 |
| `--glow` | rgba(242,163,58,.18) | rgba(242,163,58,.22) |
| `--onamber` (text on amber) | #15110a | #ffffff |

Contrast (measured): dark: text 15.55, muted 6.94, amber 9.20, on-amber 9.02; light: text 16.73, muted 6.04, amber 4.64, on-amber 4.97. `--rule-strong` is 3.10 and 3.07 against the page, meeting the 3:1 rule for control boundaries. In light mode use amber for text only at 18px and above or bold.

- **Spacing**: 4, 8, 12, 16, 24, 32, 48, 64.
- **Type scale**: 13, 15, 17 (body), 20, 26, 36, 54. Body line-height 1.6; headings 1.08.
- **Radius**: 10px (cards, inputs), 999px (pills, buttons), 8px (code blocks), 2px (progress).
- **Shadows**: none. Elevation is borders only.
- **Focus**: 2px amber outline, 2px offset.
- **Targets**: 44px minimum under 820px.

## Assets

No images or icons are used. The home hero glow is CSS. Avatars on the Team page are placeholder circles with an initial (replace with the live site's team SVGs `/images/team/*.svg`). Fonts load from Google Fonts in the prototype; self-host them in production. The page `og.jpg` and favicon come from the live repo.

## Source material the work was built from

- Live site and repo: `MyChiefOS/start-of-something-great` (`styles.css`, `home.css`, `app.css`, the page HTML, `ROADMAP.md`, `USE-CASES.md`, `CHARTER.md`, `INTEGRITY.md`, `ARCHITECTURE.md`, `ACCEPTANCE.md`, `RISKS.md` first rows).
- Agent Points (separate project, uploaded): rooms, leaderboard, ledger, admin portal. Its poster-awarded points and in-database anchors are replaced by the audited scoring and public log in this brief.
- Kimi's Module 11 and 12 and five feedback loops (pasted text).
- Rev 4.2 trust engine **summary only** (pasted). The spec itself was not available; the Engine page is a summary.
- External: certificate transparency and witness cosigning (RFC 9162, c2sp specs), RFC 8785, RFC 8693, human-oversight and automation-bias research, Sybil-tolerant reputation, drand.

## Known gaps (do not treat as done)

- All "Sample figures" are invented.
- Terms and Privacy are condensed in the prototype; use the full live text.
- The Decision Loop paper page is a summary; build the full reader.
- The 19 JEVs questions are not listed beyond J04, J06, J15, J16 and J17; read `db/jevs.js`.
- `OPERATIONS.md`, most of `RISKS.md`, the Rev 4.2 spec, and parts of Agent Points were not read.
- No screen reader audit has been done; mobile reflow was added but not measured at 390px on every page.
- No contrast audit beyond the tokens above.

## Files

- `README.md` (this file)
- `CODING_AGENT_SPEC.md` (binding build brief)
- `static/` **plain HTML and CSS reference**: one `.html` file per page (52 pages, relative links, open `static/index.html`), `static/css/styles.css` (all styles, dark and light via `data-theme` on `.d1`), `static/js/prototype.js` (prototype behaviour only: theme switch, feed lanes, join steps, tabs with arrow keys, skip link). File names are the prototype keys (`feed.html`, `receipt.html`, and so on; `404.html` is the not-found page). These are generated from the prototype, so markup is verbose; take structure and CSS values, not the file layout. Production routing and paths are in the spec, section 6.
- `screenshots/` 56 images (52 pages plus 4 interactive states), 924 by 540, dark theme, top of each page only (not the full scroll). File names are `NN-key.jpg`; `53` to `56` show the feed Agents lane, the join code step, the console Ledger tab and the engine Immune system tab. Screenshots show intent; the HTML and CSS are the measurements.
- `prototype/Day One Great Site.dc.html`, `prototype/support.js` (the same 52 pages as one clickable file with hash routing; Tweaks panel switches theme)
- `reference/Build and Leaderboard v2 (design board).dc.html` (three-page options board in the site's own look)
- `reference/Build and Leaderboard v1 (Classical system, superseded).dc.html` (first exploration; do not follow its styling)
- `reference/github.md` (which repo files each screen came from)
