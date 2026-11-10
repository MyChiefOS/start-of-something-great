# The preview copy: design (RK141)

**Status (Nov 10, 2026):** design, plus the code it needs on the site, the key broker and the database runner, built in PR 2 and tested; **not live**. Nothing here is created or changed outside the repository until Aaron merges PR 2.

Aaron, Nov 10: "Okay you can bring preview back"; asked which, "The version that complies with NIST, HIPPA, and MITRE standards". Then "Yes" to its cost (about $10 a month for one Supabase preview branch on Micro compute, $0.01344 an hour, outside the spend cap), turning on Supabase's preview branches, and Vercel's Preview settings, all carried out only after he merges the PR that builds it (CHARTER section 2; harness/FACTS.md, Nov 10). The private preview stage of the live site stays dropped: `LAUNCH_STAGE=preview` still counts as closed.

## Bad news first: what merging PR 2 alone does not give

1. **The copy won't run yet after PR 2.** One piece can't be in PR 2:
   - **The branch's address.** The site's address for the branch broker, and the preview-copy workflow's address for the branch's runner, are fixed in code (below), and a branch's project reference exists only once the branch is made. Until a follow-up commit sets it (`db/sitekeys.js` `PREVIEW_REF` and `.github/workflows/preview-copy.yml` `PREVIEW_REF`, which a test keeps equal), every preview stays closed, exactly as today, and the workflow does nothing and says so.
   - **The branch's schema** is built in PR 2 (track M): a function deployed only to the branch (`dog-copy`, since Nov 10; production's `dog-migrate` is unchanged) makes the same production-or-branch choice as the key broker, and a new workflow, `preview-copy.yml`, has it empty, migrate and reseed the copy (below, "Building and reseeding the copy"). Claude's Supabase tools can't carry the 54 migrations' 1.5 MB of SQL, and shouldn't try: retyped SQL wouldn't match the manifest's fingerprints. So the runner does it, from the merged commit, as it does for production.
2. **Nobody can sign in on the copy yet.** Code sign-in is claimed by the JEVs gate (`jevs.yml` calls production's `jevs` function), which writes to production's database, not the branch's. On the copy, people can browse and attack every route as a visitor. Attacks as members, agents and the administrator run on the GitHub Actions copy (`redteam/copy.js`), which already has real sessions in-process. A sign-in path for the deployed copy (for example, the JEVs gate claiming the copy's codes on the branch) is a later step with its own design.
3. **A preview's own generated address sends visitors to production.** `vercel.json` redirects `start-of-something-great-<id>-chief-os.vercel.app` to dayonegreat.com (RK68), and every deployment's unique address, previews included, has that shape (inferred from the pattern; not yet tested on a preview). Only the branch address (`start-of-something-great-git-<branch>-chief-os.vercel.app`) serves the copy (inferred: the pattern doesn't match a name with `git-` and more hyphens). An agent pointed at the wrong one would attack production. The control belongs in the red-team runner: it refuses redirects and refuses any host but a branch address. A later PR builds that, and fixes the redirect for previews if Vercel's rules allow it.
4. **Production's key broker and production's runner must be redeployed after the merge.** Their code changes (production's behaviour unchanged, proven by tests), so their source digests change. Until each is redeployed, the daily watch alerts that it isn't main's. It never blocks anything. (The JEVs gate shares the runner's `core.mjs`, which is untouched, so its digest doesn't change.)
5. **The copy holds main's schema, not each pull request's.** The branch is rebuilt from main, on each merge and by hand, because the runner accepts only tokens from a workflow on main (the shared identity check, `_shared/github-oidc.mjs`, refuses any other branch). A pull request that adds a migration is red-teamed on a copy without it until it is merged. The earlier draft of this note said "reset and reseeded per pull request"; that would need the runner to accept a pull request's own code, which would let any pull request change the copy's database. Main only is the safer choice, and it is the brief's.

## How it works

```
Vercel preview of PR N                                   Supabase preview branch (one, persistent)
  VERCEL_ENV=preview                                       dog-keys (the same code as production's)
  db/sitekeys.js brokerFor: the branch's address,  ---->     target.mjs: its own SUPABASE_URL says "branch"
  fixed in code (PREVIEW_REF), or none                       -> accepts only tokens saying environment "preview",
  x-vercel-oidc-token: signed by Vercel,                        our team, our project (the pinned check)
  environment "preview"                                      -> hands out nothing unless Vault has the mark
                                                             -> the branch's own login dog_web.<branch ref> + keys
  connects to the branch's pooler  <-------------------------
Production (unchanged): VERCEL_ENV=production -> production's fixed address -> production's broker accepts only
  "production" tokens, exactly as before.
```

### Key choices

1. **The signed token separates them, not a setting.** Vercel signs each function's identity token with the environment it runs in (`environment` and `sub` end in `preview` or `production`; verified: Vercel's OIDC reference, read Nov 10). Production's broker refuses every preview token (it already did: `test/routeb.test.js`), and the branch's broker refuses every production token. No Vercel or Supabase setting can change a token's environment. `VERCEL_ENV` only picks which address to ask. That matters because `VERCEL_ENV` isn't on Vercel's reserved list (verified: Vercel's reserved-variables page, Nov 10), so a person with Vercel access might be able to set it by hand (unknown).
2. **Addresses are fixed in code.** `brokerFor` returns production's fixed address for every deployment that isn't a preview, exactly as today. A preview gets only the branch's address, built from the fixed `PREVIEW_REF` (20 lowercase letters, never production's reference), or nothing. Nothing comes from a request, and nothing from another setting (tested: settings named `BROKER`, `DOG_KEYS_URL` and `SUPABASE_URL` are ignored; no other file mentions the reference).
3. **One broker code, two places, chosen by the place.** `supabase/functions/dog-keys/target.mjs` reads the function's own `SUPABASE_URL` once, at start. Supabase sets it for every function, and no one can set a secret starting with `SUPABASE_` (verified: Supabase's secrets page, Nov 10). Production's address, or anything that isn't a Supabase project address, means production, exactly as before, so a missing or odd setting can't lock production out. Any other project address means the branch. The pinned identity check (`_shared/vercel-oidc.mjs`, digest `178678d3…`) is untouched: its `environment` option, which production leaves at its default, is the only thing chosen. A caller can't override it (tested).
4. **A second, independent check on the branch: the mark.** The branch's broker hands out nothing unless the branch's own Vault holds `dog_preview_copy = yes`. Only the seed makes the mark, and only on an empty database. If production's broker were ever told it was a branch, it would still hand out nothing: production's Vault has no mark (tested).
5. **A preview is never more open than production's own rules allow.** `launch.js` keeps every non-preview deployment exactly as it was (tested against the old rule over every combination). A preview runs open only when all of these hold: the branch's address is fixed in code; Vercel gave it none of route A's settings (`DATABASE_URL`, `SESSION_SECRET`, `IP_HASH_KEY`, `FINGERPRINT_KEY_1`, `CRON_SECRET`), any of which could connect it to production's database; `LAUNCH_STAGE` doesn't close it; and the repository's stage is public. Production with `VERCEL_ENV` set to `preview` by hand would therefore get at most what production's own rules give, never more (tested over every combination), and its production token would be refused by the branch anyway. Route A's settings are read once, when `launch.js` first loads, which is always before the broker's answer is put in the same environment (tested in a fresh process). "preview" as a value of `LAUNCH_STAGE` still closes.
6. **The seed makes made-up data, and only on a fresh copy** (`supabase/functions/_shared/preview-seed.mjs`). It works in one transaction and refuses, changing nothing, any database that holds a member, agent, post, site key or the mark, or that has no Vault or no schema. Production holds members and the three site keys, two independent reasons. It makes the branch's three site keys and the mark inside the database (Postgres's own strong random, `gen_random_uuid`), then five made-up members (one administrator, three at level 2, one newcomer at level 1), two agents, five posts with their JEVs decisions (JEVs stays in enforce mode, as production runs), a project and three tasks. It uses the same database functions and roles the site, sign-in and JEVs use. No usable credential is made: every session and agent key is a random hash whose secret never existed. It lives under `supabase/functions/` because a function can be deployed only with files from there (`scripts/function-digests.js`), and the branch's runner will run it. Migration 022 makes the branch's `dog_web` password inside the branch, as it did production's.
7. **One persistent branch, rebuilt from main on each merge and by hand,** not one branch per pull request. A per-PR branch would have a new reference every time, which can't be fixed in code without a PR per PR, and costs more (arithmetic below). Every preview deployment shares the one copy; anyone red-teaming starts from a clean copy by running the workflow by hand.

## Building and reseeding the copy

The rebuild lives in its own function, `supabase/functions/dog-copy`, deployed **only** to the branch (Aaron, Nov 10: production carries none of the copy's code). Production's runner, `dog-migrate`, is main's own code, byte for byte. `dog-copy` still decides once, at start, from its own `SUPABASE_URL` (`dog-copy/target.mjs`, the broker's rule, tested to agree with it), and on production's address it refuses every request before reading it:

| | Production's runner, `dog-migrate` (main's code) | The branch's `dog-copy` |
|---|---|---|
| Accepts | `database.yml` on main, by push, by hand or (status only) on schedule | `preview-copy.yml` on main, by push or by hand |
| Token audience | `https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-migrate` | `https://<branch ref>.supabase.co/functions/v1/dog-copy`, its own |
| Requests | `apply`, `status` | `rebuild` only |
| Work | apply the merged commit's new migrations | empty the copy, apply every migration of the merged commit, reseed |

- **Production is unchanged and carries none of it.** `dog-migrate/index.ts` and `core.mjs` are byte for byte main's (checked by SHA-256 in `test/preview-migrate.test.js`), and the runner's folder holds only those and its digest. The reset and seed exist only in `dog-copy`, which is never deployed to production, and the daily watch skips it there.
- **Each refuses the other's token twice.** By address (the audience) and by workflow: a `database.yml` token addressed to the branch is refused, and a `preview-copy.yml` token addressed to production is refused (tested with the real identity check).
- **Reseeding starts from empty.** The seed refuses any database that holds data, and keeps doing so. So each rebuild, in one transaction under the runner's lock: (1) the database's own guard: only a copy whose Vault holds the mark (`dog_preview_copy` = `yes`), or a database with no site keys in Vault and no members, agents or posts, may be reset; production has members and its site keys and no mark, so it is refused for two independent reasons; (2) the reset: the `app` schema dropped as `dog_owner` (as the Oct 24 fresh build did) and the seed's three site keys and mark deleted from Vault, nothing else; (3) every migration, by the runner's own unchanged code, which checks the result and records the run; (4) the seed. Any failure undoes all of it, and the old copy stands (tested).
- **The reset can't run on production, two independent ways.** In code: `dog-copy` is never deployed to production, and if it were, `dog-copy/index.ts` and `dog-copy/copy.mjs` refuse unless the start-up choice is the branch (production's address, anything odd, or a hand-made look-alike is refused, tested). In the database: the guard above (tested on a production-like database).
- **The workflow** (`.github/workflows/preview-copy.yml`): runs on each merge to main and by hand, only in this repository; rights are `contents: read` and `id-token: write` only; its own queue, separate from production's migrations. While `PREVIEW_REF` is empty it does nothing and says so; a malformed or production reference is refused before any token is asked for (tested by running its script with a stand-in `curl`). A separate workflow rather than a job in `database.yml`, so production's migrations keep their own triggers, rights, queue and failure alerts, and the workflow name in the token separates the two runners even if an address were wrong.
- **Each rebuild changes the copy's secrets.** Migration 022 gives the copy's `dog_web` a new password, and the seed makes new site keys. A preview running across a rebuild loses its database connections and its visitors' sessions until it next asks the branch's broker (within 10 minutes). That is acceptable for a test copy.

## No secret passes through Claude

| Value | Made where | Who ever holds it |
|---|---|---|
| The branch's `dog_web` password | Inside the branch's database, by migration 022 | The branch's Vault; the branch broker hands it to the copy's preview functions |
| The branch's three site keys | Inside the branch's database, by the seed | The same |
| Vercel identity tokens | Vercel, per request | The preview function, which sends it only to the branch's fixed address |
| The mark (`yes`) and the branch reference | Not secrets | Code and Vault |
| Production's values | Unchanged | Production's Vault and production's functions only |

Claude's steps use Supabase's and Vercel's own tools, which never show a value. Claude never runs a query that returns a Vault value, never decrypts a Vercel setting, and never handles Vercel's Protection Bypass secret (below).

## Isolation, both ways

- **A preview can't reach production's database or keys.** It never asks production's broker (address choice, tested). If it did, production's broker refuses its token (`wrong environment`, tested). It stays closed if Vercel gave it route A's settings (tested). The branch is a separate database instance ("Branches are completely isolated from each other", Supabase's branching documents, read Nov 10).
- **Production can't reach the branch.** Production never chooses the branch's address (tested), and the branch's broker refuses production tokens (tested).
- **Made-up data only.** The seed refuses any database with data (tested). Whether `create_branch` copies anything from production is unknown until it runs. Supabase's documents call a new branch "a fresh clone of your base project", reseeded from a seed file, and don't say whether data is copied. The first read-only check after creating it is that the branch holds no `app` schema and no `dog_*` Vault names.

## Who can reach it

- **Aaron:** Vercel's Deployment Protection (Vercel Authentication) covers every preview. He signs in to Vercel. (Verified Oct 29: a preview's generated address answered 302 to Vercel's sign-in; OPERATIONS.md. Rechecked after the merge.)
- **Agents Aaron directs, default and no secret: GitHub Actions through Vercel's Trusted Sources.** A rule on the project lets a GitHub Actions job reach protected deployments with its own short-lived GitHub identity token, sent as `x-vercel-trusted-oidc-idp-token`, matched on issuer, audience and claims, and limited to chosen environments (verified: Vercel's Trusted Sources page, Nov 10). The rule: issuer `https://token.actions.githubusercontent.com`, audience `https://github.com/MyChiefOS`, `repository` `MyChiefOS/start-of-something-great`, `workflow_ref` the red-team workflow on main, environments **Preview only**. It's a Vercel Preview setting, inside what Aaron approved. Claude sets it through Vercel's project API if Claude's Vercel connection allows (unknown). If not, it is one dashboard form for Aaron.
- **Aaron's choice, not recommended: Protection Bypass for Automation.** It is a secret Aaron would create in Vercel and store himself. Claude never handles it. It opens every deployment of the project to whoever holds it, and Vercel also gives it to every deployment as a system setting (`VERCEL_AUTOMATION_BYPASS_SECRET`; verified: Vercel's bypass page), so any PR's code could read it.
- **Always available, needs nothing: the GitHub Actions copy** (`redteam/copy.js`, `.github/workflows/red-team.yml`): the real API handlers on a throwaway database, with sessions for every role, on every PR and from Aaron's issue plans.

## Cost

The rate is $0.01344 an hour for a branch on Micro compute (verified: Supabase docs, FACTS Nov 10).

- **One persistent branch:** $0.01344 × 24 = $0.32 a day. Over a 30-day month that is $9.68; over an average month of 730 hours, $9.81; over a 31-day month, $10.00. Rebuilding and reseeding it adds no compute charge (inferred: the branch's compute is billed by the hour, whatever it does).
- **One branch per PR (rejected):** $0.32 per PR per day open. If 3 PRs were open at a time on average (an assumption, not measured), that's 3 × $9.81 = $29.43 a month; with 5, $49.06. On top of the cost, each new branch would need its own broker deploy, its own seed, and its reference in code by another PR.
- Not included: disk beyond what a branch includes, and egress (unknown, not priced; expected small for made-up data).

## Threat model

| Threat | Path | Control | Left over |
|---|---|---|---|
| A preview reaches production's keys | Asks production's broker | Address fixed by `VERCEL_ENV`; production's broker refuses `preview` tokens (signed by Vercel) | None found |
| A preview reaches production's database | Route A settings set for all environments in Vercel | `launch.js` keeps the preview closed if any is present at start; after-merge check lists Preview setting names | A setting added later only closes the copy |
| Production reaches the branch | Wrong address, or production told it's a branch | Fixed address; branch refuses `production` tokens; production's Vault has no mark | None found |
| Someone opens production through the preview path | `VERCEL_ENV=preview` set by hand on production | A preview is never more open than the repository and `LAUNCH_STAGE` allow (tested over every combination); its production token is refused by the branch | A hand-set `VERCEL_ENV` could shut production's database off (a self-inflicted outage by someone with Vercel access, who could do worse) |
| Real data in the copy | Branch created with data; seed run on a real database | Seed refuses any non-empty database; read-only check after creation | Whether `create_branch` copies data: unknown until run |
| A PR's own code misuses the copy | Any same-repo PR's preview gets the branch's login and keys | Made-up data only; the branch is emptied and reseeded on each merge to main and by hand | Accepted: that is what a red-team copy is. Vercel's Git Fork Protection holds a fork's PR for a team member's approval when the project has environment variables or the PR changes `vercel.json` (verified: Vercel's changelog); whether it is on for this project: unknown, checked after the merge |
| Red-team traffic lands on production | A preview's generated address redirects to dayonegreat.com | The runner refuses redirects and any host but a branch address (a later PR) | Until then, people must use the branch address |
| The branch is merged into production | Supabase's `merge_branch` would push the branch's migrations and functions to production | Claude never calls `merge_branch` or `rebase_branch` on this branch (OPERATIONS rule) | Conduct, not a control: Aaron's dashboard could still do it |
| A leaked bypass secret | Protection Bypass for Automation | Not used by default; Trusted Sources instead | If Aaron chooses it: readable by every deployment's code |
| The copy's reset runs on production | Production's runner told it is the branch; the branch's runner pointed at production's database | The choice is the runner's own `SUPABASE_URL`, which no one can set; `copy.mjs` refuses unless it is the branch; the database refuses without the mark when it has members or site keys (each tested alone) | Both guards would have to fail together: a hand-made mark in production's Vault (only the database's owner could write one) and a wrong `SUPABASE_URL` (set by Supabase). A daily alert if the mark appears in production's Vault is suggested, not built |
| A production token rebuilds the copy, or a copy token changes production | A token sent to the wrong runner | Each runner checks its own audience and its own workflow (tested both ways, with the real identity check) | None found |
| A pull request changes the copy's database | A PR's workflow asks the branch's runner | Only `preview-copy.yml` on main is accepted; the shared check refuses any other branch or a pull request's ref (tested) | A PR's own preview still holds the copy's login (row above) |
| A failed rebuild leaves a broken copy | A migration or the seed fails halfway | One transaction: the old copy stands (tested) | A rebuild longer than the function's time limit (unknown for 54 migrations plus the seed) is cut off, and Postgres undoes it; the run says so |
| Supabase's login can't take `dog_app` | Postgres 16 gives the role's creator ADMIN only | The seed grants itself `dog_app` for its transaction and gives it back. Untested: the tests run as a superuser, which never needs the grant; proven on the branch's first seed | The coverage check reports a membership left behind |

## After the merge of PR 2 (Claude; Aaron's merge is the concurrence, recorded in OPERATIONS.md first)

1. **Redeploy production's broker** from the merge commit: Supabase `deploy_edge_function`, project `nksagchwpyljvjiwolmp`, `dog-keys` (index.ts, core.mjs, target.mjs, source-digest.mjs, `_shared/vercel-oidc.mjs`), `verify_jwt` false. Proof: `get_edge_function` file hashes equal the merge commit's; a GET answers 405 with the new `x-source-digest`; the next daily watch reports it as main's; `/api/ready` on dayonegreat.com still says `broker: ok`, `database` reached.
2. **Create the branch:** Supabase `create_branch` on `nksagchwpyljvjiwolmp`, named `preview-copy`, Micro compute (the approved cost). Proof: `list_branches` shows it, its reference and status. On the branch, `list_tables` shows no `app` schema, and a names-only query shows no `dog_*` Vault names.
3. **Deploy the broker to the branch:** `deploy_edge_function` with the branch's reference, the same files, `verify_jwt` false. Proof: a GET answers 405 with the same digest as production's. Until the branch is migrated and seeded, any preview token would get 503 `not set up`.
4. **Vercel, read-only:** list the Preview environment's setting names (never values). None of route A's five names may apply to Preview; if any does, the copy stays closed by code and Claude reports it.
5. **Production's runner needs no redeploy:** `dog-migrate` is main's code, unchanged (its digest is main's).
6. **Deploy `dog-copy` to the branch only:** `deploy_edge_function` with the branch's reference, `dog-copy` (index.ts, copy.mjs, target.mjs, source-digest.mjs, `dog-migrate/core.mjs`, `_shared/github-oidc.mjs`, `_shared/preview-seed.mjs`), `verify_jwt` false. Never to production. Proof: a GET answers 405 with its digest; a POST of `{"mode":"rebuild"}` with no token answers 401 `refused: token missing or too large`; and `list_edge_functions` on production shows no `dog-copy`.
7. **A follow-up commit (Claude builds, Aaron merges):** `PREVIEW_REF` set to the branch's reference in both `db/sitekeys.js` and `.github/workflows/preview-copy.yml` (a test keeps them equal). Its merge runs the workflow: the first rebuild. Then prove: the run's summary says passed, every migration applied, seeded 5 members, 2 agents, 5 posts; on a preview's branch address, `/api/ready` says `vercel_env: preview`, `stage: public`, `broker: ok`, `database` reached, `keys: true`, and the feed shows the five made-up posts; production's `/api/ready` and the next drift check are unchanged. Each result goes in OPERATIONS.md.
8. **Still to build, later:** the red-team runner reaching the branch address through Trusted Sources, refusing redirects and other hosts; the Trusted Sources rule above; a daily alert if the copy's mark ever appears in production's Vault.

Claude never calls `merge_branch`, `rebase_branch` or `delete_branch` on the copy without Aaron's word, never pauses or deletes production, and never reads a Vault value.

## Aaron's standing rules

- **Checks alert, never lock out.** Production's paths are unchanged. Anything wrong with the copy (no address, a refused token, a missing mark, a setting from route A) only keeps the copy closed. The redeploy of production's broker is the one production change. If it went wrong, running instances keep their last good answer (control 4), and the previous files can be deployed again.
- **Nothing runs from Aaron's computer.** Supabase, Vercel and GitHub Actions only.
- **No outside services.** Supabase and Vercel are already in use; Trusted Sources is a Vercel feature.

## Standards

NIST SP 800-53 SA-3 (a separate test environment in the life cycle) and SA-11 (developer testing); NIST SSDF PO.5 (separate and protect the environments); ISO/IEC 27002 8.31 (development, test and production kept apart) and 8.33 (no real data in tests); HIPAA practice (no real people's data in test systems; practice only, Day One Great isn't covered); MITRE's CWE Top 25 and ATT&CK as the red team's catalog of what to try. How each is met is in the choices above; nothing here claims a certification.

## When a deployment of the copy may run open

(Moved from launch.js's comments, so the served file says less; the independent review of PR 2, F4.)

The preview copy (RK141; Aaron, Nov 10: "Okay you can bring preview back", the separate copy with its own throwaway
database and made-up data; design/preview-copy.md) is something else: Vercel's preview deployments of a pull request,
each getting its database login and keys from the preview branch's own key broker (db/sitekeys.js brokerFor), never
production's. A preview deployment may run open only when all of these hold (previewCopy below), and otherwise stays
closed exactly as before:
   * the preview branch's address is fixed in the code (db/sitekeys.js PREVIEW_REF; until the PR that sets it, it
     isn't, so every preview stays closed);
   * Vercel gave this deployment none of route A's settings (a database address or a site key): with any of them it
     could reach production's database with production's login, so it stays closed;
   * LAUNCH_STAGE doesn't close it, and the repository's stage is public: a preview is never more open than the
     repository and the close switch allow. So nothing here can open production, or any deployment the repository or
     LAUNCH_STAGE closes, even if a deployment's VERCEL_ENV were set to "preview" by hand (test/preview-copy.test.js
     checks every combination). VERCEL_ENV only chooses; the real control is the broker's check of Vercel's signed
     token, whose environment no setting changes.
