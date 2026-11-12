# Security and intent review of two designs (Chief Security Officer role, Nov 11, 2026)

**Two of Aaron's instructions conflict in Design 1:** "Second and Third Look in the key broker" with no new project or key (harness/FACTS.md:366, 370), and route B's control 8, "Vercel's identity token never forwarded" (harness/REVIEW-2026-10-26.md:114; FACTS.md:350-351).

Read-only; nothing was run or sent to production. Labels: **V** verified (file:line), **I** inferred, **U** unknown. "057" is db/migrations/057_access_holes.sql.

## Bad news first

1. **Design 1 forwards the site's token:** the dog-looks move, inside the existing function (H1).
2. **Its fail-safe can be held open by the attacker it targets,** and with no traffic it stays open (H2).
3. **It closes one of three ways that attacker gets content published** (M1).
4. **Design 2: "the same handler code" is not callable code today,** and `register_agent` puts a permanent key into a chat (H4, H5).
5. **Not verified:** the MCP specification's main authorization page (fetch blocked); the AI Gateway accepting the token from Supabase's network; Supabase's request time limit; which clients need OAuth.

## Design 1

**Recommendation: do not build as written. Build with the named changes, after Aaron answers the forwarding question.**

One honest sentence for Aaron: *"To close this without a new project or key, the key broker stops only checking your site's token and starts using it: it sends the token on to the AI Gateway itself, which is the forwarding control 8 forbids and the same move you rejected in dog-looks, done inside the function you already trust instead of a new one."*

**The constraints cannot all be met (I).** The gateway call needs a Vercel token, and only the site's functions get one. Either the site makes the call and can forge the verdict, or something else presents the site's token. What gives is control 8, by a named exception like the one he gave for the gateway (V: db/sitekeys.js:79-82), or the closure, leaving RK100 and RK135 open at 3.0 and 2.0. Unknown: whether the plan he check-marked said this plainly. A weaker alternative forwards nothing: the broker, after checking the token, returns a one-use value the decide functions require. It stops a leaked login, not code running in the site.

### High

**H1. Forwarding.** The design restates control 8 by destination; the record is about forwarding, and the solution Aaron approved on Nov 10 said "no token is forwarded between services" (V: FACTS.md:351). No code rule would catch misuse: the Semgrep rule matches the `x-vercel-oidc-token` header in site JavaScript (V: .semgrep/database.yml:40-54); the broker reads `authorization` (V: supabase/functions/dog-keys/index.ts:23). Fix: Aaron's yes recorded first; a test pinning the broker's outbound hosts to Vercel's key addresses and the gateway, redirects refused.

**H2. The one-way switch can be starved.** Until it trips, the site's role keeps `sl_claim`. A post is claimed once (V: 057:137; db/secondlook.js:26), and a claim takes the 50-second slot (V: 057:110-113; Third Look 057:396-397). Failing case: a holder of the site's role calls `app.sl_claim(3)` every 50 seconds. The broker never gets an item, the switch never trips, and the attacker records forged clears. With no attacker, each Look has 0 reviews ever (V as recorded: FACTS.md:372): the hole waits for traffic. If a fail-closed record counts as the first verdict, the switch trips while the gateway refuses the broker, and both Looks stop.
Fix: **a probe that records no verdict.** On the first timer tick after deploy the broker makes one fixed, harmless gateway call. A parsed answer sets a one-way flag the claim and decide functions read; a refusal alerts Aaron and the site keeps running the Looks. The window is about a minute, needs no held item, and cannot be starved. Use a flag row, not a runtime REVOKE: the reviewed snapshot records each function's callers (V: db/snapshot.txt:1445-1446, 1458-1459), so a revoke at run time makes production differ from every fresh build.

**H3. The broker gains a second job.** It connects with Supabase's administrator login and reads Vault (V: index.ts:30; core.mjs:30-33). `set local role dog_looks` limits the SQL it sends; it is no wall against a bug in that function (I). Fix, same function: one fixed route with no parameters (the broker reads no body today, V: index.ts:22-26), so a caller picks nothing; the Look path never reads Vault; static SQL only; the database gate is `current_setting('role') = 'dog_looks'` (existing pattern, V: 057:329), not `actor_kind`, which lets the site's role in today (V: 057:103, 200, 444); a time budget; no post text or token in any log; the route returns only `{ok}` (control 1).

### Medium

**M1. Say what stays open.** The site computes JEVs's scores and the database decides from them (V: db/jevs.js:296-304; db/migrations/040_agent_registry.sql:377; RISKS.md RK17), so the same attacker with any member session posts unheld, with no verdict to forge. Code in a site function sees signed-in sessions, the administrator's included (I). What closes: other people's held posts, and held work (Third Look's gate reads GitHub's facts, V: 057:12-14). Fix: RK100 and RK135 say "forged verdict closed", not "the site's role can't publish".

**M2. Replay and timing.** The token is reusable for two hours, with one audience for both recipients and no one-use check (V: supabase/functions/_shared/vercel-oidc.mjs:14-16, 63-72). A holder can start Look runs; the 50-second gate and daily caps bound it (V: 057:110, 133-134, 402-405). Items are oldest first, never caller-chosen (V: 057:138). No function edits a post's text after a claim (I: migrations searched); Third Look's task text: U. Prompt injection is unchanged and becomes the only outside path to a false clear (V: secondlook/v1.js:36-45, 185-191; 057:207-212).

### What would stop the Looks working

- The Look code is CommonJS, with Node's `crypto` and three site modules (V: secondlook/v1.js:23-25, 113; thirdlook/v1.js:24-27): port once and load that file from the site (pattern: db/sitekeys.js:131), or the masking drifts.
- The site's broker call gives up at 3 seconds (V: db/sitekeys.js:42); a run can wait 54 on models. Supabase's limit: U.
- Decisions must land within 2 minutes (Second) or 3 (Third) of the claim (V: 057:249, 459).
- Samples and planted tests use the same claim (V: 057:121-178).
- `app.broker_note` takes only "handed" or "failed", and "failed" alerts (V: db/migrations/027_preopen_safety.sql:98, 125).

## Design 2

**Recommendation: build part 1 with the named changes; do not build `register_agent` as written; build OAuth only as its own reviewed pull request.**

### High

**H4. No shared core.** Posting's checks are composed inside the HTTP handler: host check, key resolved afresh, request facts for JEVs, the owner's rules, then JEVs in the same transaction (V: api/feed.js:275-293). For "the same checks" to hold: (a) each action is one function that both the route and the tool call; (b) the actor is always `agentkey.actorFor` from a key resolved in that request (V: signin/agentkey.js), never a session. `actor()` in api/work.js:113-122 and api/engine.js:88-97 falls back to the cookie, so a keyless acting call is refused, never passed to it; (c) `jevs.facts(req)` and `onSite(req)` apply; (d) a parity test per tool: the same input through both gives the same rows and refusals.

**H5. `register_agent` returns a permanent key into the model's conversation** (transcripts, logs, injected text asking for it), and the client cannot send it as a header until the person copies it into settings (I). Fix: no key through a tool result; the keyless server points to /agents/join.

### Medium

- Post reads and tool lists are cached as public (V: api/mcp.js:24, 164-176, 261-263). Keyed results never enter them.
- Old-style batches run 20 calls at once (V: mcp.js:396): refuse acting tools there.
- Every tool is labeled read-only (V: mcp.js:48); clients use that to skip confirmation.
- A bad key gets 401, as the API gives (V: feed.js:241), never a quiet drop to read-only. `Authorization` is not an allowed header today (V: mcp.js:367).
- Registration allows 10 an hour per address and 20 per network, and the regional decline reads the caller's address (V: api/agents.js:65-66, 181-184). Hosted clients share addresses.

### Words that change, once proven live

"No sign-in" and "never changes anything": index.html:88; connect.html:7, 18, 37; llms.txt:30; README.md:62; USE-CASES.md:16; api/mcp.js:36, 376; agents/join.html:52. Without `register_agent` a narrower promise stays true: "Without a key it changes nothing." With it, a keyless call writes rows (V: agents.js:191-210).

### OAuth: must not get wrong

Read: the 2026-07-28 client-registration and security-considerations pages. Not read: the main authorization page (discovery, `resource` rules, scopes: U).

1. Hand-written; the specification's guide says not to write token validation yourself.
2. Approval is a same-origin POST bound to one stored request. A GET never approves. No silent approval; no framing.
3. Exact redirect match; show the redirect host; guard client metadata fetches against server-side request forgery.
4. Codes: one use, seconds-lived, bound to client, redirect, S256 challenge and resource; stored hashed.
5. The access token is never the permanent agent key: short-lived, bound to this server, refresh rotated, owner-revocable.
6. An open server never answers 401, so the flow never starts: use a separate signed-in address.
7. Approval is no new sign-up path: the regional decline, level 2 and JEVs's claim check apply.

```
Alignment
- Loop tier: full (1–5); steps actually run: 1 in part (three MCP pages read: client registration, security considerations, the authorization guide; the main authorization page was blocked), 2 (attack cases walked against the code; nothing executed), 3 (this review is the fresh-agent step), 4, 5
- Goals served: show that AI can be trusted; let agents do more, carefully, with the owner's consent and a record (section 1)
- Standing decisions touched: route B and its control 8 (Oct 26); MCP sign-in, keeping the site's own sign-in (Nov 4); automated review with Second Look required, and Third Look (Nov 5); regional decline (Oct 16); open agent registration (Oct 14) — conflicts: Design 1 forwards the site's token, against control 8 and the Nov 10 "no token is forwarded between services" (raised first); Design 2 changes the public "no sign-in, never changes anything" wording
- Fresh-agent review: yes, this is it; it proposes: the forwarding put to Aaron before any build, a probe and flag in place of the one-way switch, register_agent dropped, OAuth split into its own pull request
- Standards: OWASP A01 and CWE-862 (who may call the verdict functions), OWASP LLM01 and LLM06 (injection; agents acting), NIST AC-6 and SC-7 (the broker's reach), OAuth 2.1 and the MCP authorization pages read; reviewed only, nothing built, so none is met yet
- Open for Aaron: decisions: (1) allow the broker to forward the token, or keep RK100 and RK135 open; (2) no agent key through a chat; (3) OAuth as its own pull request | actions: none
```
