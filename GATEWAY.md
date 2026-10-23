# JEVs gateway, slice 1: scope

Approved by Aaron on Oct 23, 2026 ("yes" to building the database and deploying the gateway through the Supabase connector; OPERATIONS.md). Reviewed by a security architect and a delivery reviewer the same day (harness/FACTS.md). This page says exactly what moves, what stays, what is checked before anything goes live, and the date.

## The approach: move the code that touches the database into Supabase, unchanged

Six of the site's handlers touch the database: `api/auth.js` (sign-in), `api/feed.js` (posts), `api/agents.js`, `api/notify.js`, `api/cron.js` and part of `api/mcp.js`. Everything else (the pages, proposals, shipped, search, status, handshake) reads only GitHub and stays on Vercel.

Supabase Edge Functions run Node code and npm packages (Supabase: "NPM compatibility", generally available). So instead of rewriting those handlers, slice 1 bundles them, with JEVs and the database layer, into one Edge Function: the JEVs gateway. Vercel forwards `/auth/*` and `/api/feed` to it. The same code and the same 408 tests, running in a different place. Cookies keep working because visitors still only ever talk to dayonegreat.com.

## What moves in slice 1

| Route | What it does | Where it runs |
|---|---|---|
| `/auth/github/start`, `/auth/github/callback` | The GitHub step: send the person to GitHub, take the code back, exchange it for a token | Vercel (it holds the GitHub keys) |
| `/auth/complete` (new) | Checks the token with GitHub (whose it is, and that our app issued it), JEVs-1, creates or resumes the member and the session | Gateway |
| `/auth/me`, `/auth/signout`, `/account` reads | Who is signed in; sign out | Gateway |
| `/api/feed` | Read and post; JEVs-2 on every post | Gateway |

Agents, controls, notifications, deletion and the timers stay switched off in slice 1, exactly as they are today, and move in later slices, one group per pull request.

## Keys and settings, with nobody handling a secret

| Setting | Slice 1 |
|---|---|
| Database login | Requests go through the narrow login `dog_web`, whose password is made inside the database and kept in Vault; Supabase's main login is used only at start-up to read it; never in Vercel |
| Session, network and fingerprint keys | Made inside the database with `gen_random_bytes` and kept in Supabase Vault (encrypted on disk and in backups; the encryption key is kept outside the database by Supabase). Read once by the gateway at start-up. Nobody sees them |
| GitHub keys | Stay in Vercel, where Aaron put them. The Vercel side seals its short-lived sign-in cookie with a key derived from the GitHub secret it already has, so it needs no new setting |
| GitHub client ID (public) | Read from the live sign-in link and written into the gateway's settings |
| Go-live stage | In the database. Starts at `preview` with only Aaron (GitHub ID 304218593) allowed; Claude changes it only on Aaron's words, recorded in OPERATIONS.md |
| Administrator | Aaron's GitHub ID becomes the administrator on his first sign-in |

## Migration 017 (in the database)

1. On Supabase, makes the narrow login `dog_web` (it can only become the site role), with a random password generated inside the database and stored straight into Vault. The gateway uses Supabase's main login once, at start-up, to read that password and the keys from Vault, and serves every request through `dog_web`. The coverage check (S1) stays as strict as before. Tested Oct 23 on a fresh server as a non-superuser admin, with a stand-in Vault: the narrow login signs in and becomes the site role, is refused the owner role, the coverage check passes, and a second run replaces nothing.
2. Makes the session, network and fingerprint keys the same way, in Vault, once, never replaced.
3. Anywhere without Vault (the tests; a database the protected workflow sets up) it does nothing.

Deferred, with the reason: the security review's "the database works out who is acting itself" fix. It mattered most when a site on Vercel would hold a database login. In this design only the gateway, inside Supabase, holds one, so it protects much less here, and it touches every timer and notification path. It comes back with the slice that moves the timers.

The protected setup workflow's `database` and `keys` steps are retired by this design: running them would replace the narrow login's password and cut off the gateway.

## Checked before anyone uses it (health checks report; nothing blocks on its own)

- The gateway can switch to the restricted site role, and every query runs as it.
- Migrations 001–017 match the repository's fingerprints; row-level security is on for every table; Supabase's security advisor is clean.
- GitHub still sends the `X-Oauth-Client-Id` header; if not, new sign-ins stop with a clear message and an alert.
- Connection count stays low under a burst (load test against the pooler).
- The whole test suite passes against a database built the same way as production, through the same bundled gateway.

## Known limits (in RISKS.md with the pull request)

- Visitor IP and country reach the gateway through Vercel's forwarding headers; someone calling the gateway directly could fake them. Rate limits are kept per member and per network, and the regional decline also runs on the Vercel side.
- The gateway connects as Supabase's main user and switches to the restricted role for every query; its code is the existing tested code, deployed only from this repository.
- The `X-Oauth-Client-Id` header works but isn't in GitHub's documentation.

## Order and date

1. Migration 017 and the bundled gateway, tested here against a fresh database: Oct 24.
2. Build the Supabase database (001–017) and deploy the gateway through the connector; run the checks above: Oct 24.
3. Pull request with the Vercel side (forwarding, the `/auth/complete` hand-off, the cookie key): Oct 25.
4. Aaron merges; Aaron signs in to the site itself (a "Sign in to your account" link on /account, since /join now uses giscus) and makes a post. That is the pass/fail test.
5. Later slices: agents, controls, notifications and deletion, timers in the database; one pull request each.
