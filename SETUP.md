# Production setup: Aaron's steps

**Changed Oct 23, 2026 (Aaron: "remove the Old Path").** Launching needs no secret from you and no setup run. The old path (you paste a database password and a Vercel token into GitHub, a setup run makes keys and a database login and copies them into Vercel, you enrol two passkeys) is removed. The site's database login (`dog_web`), its password and the sign-in keys are made inside the database by migration 017 and kept in Supabase Vault, where the JEVs gateway reads them; nobody sees them, Claude included. The launch path is in GATEWAY.md ("Order and date") and harness/FACTS.md ("Launch path"): you merge the pull request, then sign in and post.

The **Production setup** workflow (`.github/workflows/setup.yml`, code in `scripts/setup-production.js`) stays for four jobs that don't have another home yet. It makes no password and no key. None of them is needed to launch, and each needs a secret only on the day you choose to run it.

| Job | Steps | Secret it needs, only when run |
|---|---|---|
| Close the site in an emergency (OPERATIONS.md, "Runbook: close the site now") | `stage,redeploy` with stage `closed` | `VERCEL_TOKEN` |
| Make yourself the administrator (or, with no secret, Claude runs the same database function through the Supabase connector once you agree, recorded in OPERATIONS.md) | `admin` | `MIGRATION_DATABASE_URL` |
| Remove Supabase's `ensure_rls` leftovers, apply new migrations, run the coverage check | `database` | `MIGRATION_DATABASE_URL` |
| Go live on the Vercel side | `stage,redeploy` with stage `public` | `VERCEL_TOKEN` |

New migrations go through the **Database migrations** workflow (standing decision: migrations only through the protected GitHub workflow), and backups are tested by **Restore test**; both use `MIGRATION_DATABASE_URL` the same way.

Everything in **[PLACEHOLDER: …]** is a value only you can supply.

## How every run works

1. You start it from the Actions tab and fill in the inputs.
2. A first job, **plan**, reads the inputs alone (no secrets) and writes what the run will do into the run's summary. Bad input (a stage that doesn't exist, a preview with nobody allow-listed, a step that was removed) stops it here.
3. GitHub asks you to approve the **setup** job. Read the plan first; approve, or cancel the run.
4. The setup job does exactly what the plan said and stops at the first problem.

## 1. The protected environment (once, about 2 minutes)

GitHub → the repository → Settings → Environments → `production` (create it if it isn't there):

1. **Required reviewers:** add yourself. Every run waits for your approval.
2. **"Allow administrators to bypass configured protection rules":** turn it **off**, so an administrator token can't skip your approval. (Leave "Prevent self-review" off: you start the runs and you approve them.)
3. **Deployment branches and tags:** "Selected branches and tags", allow only `main`.

## 2. The secrets, only for the run you choose

Add a secret only when you're about to run a job that needs it, under the `production` environment's "Environment secrets". Supabase's certificate is public, so it is already in the repository (db/certs/supabase-root-2021.crt).

| Name | Where to get it |
|---|---|
| `MIGRATION_DATABASE_URL` | **[PLACEHOLDER: Supabase → Connect → "Session pooler" connection string, port 5432, with your database password filled in]**. It looks like `postgresql://postgres.nksagchwpyljvjiwolmp:…@aws-0-us-east-1.pooler.supabase.com:5432/postgres`. |
| `VERCEL_TOKEN` | **[PLACEHOLDER: Vercel → Account Settings → Tokens → Create. Scope: the chief-os team. Expiration: 1 day]**. Vercel has no project-only tokens, so the team is the narrowest scope; delete the token after the run rather than waiting for it to expire. |

## 3. Make yourself the administrator

1. While signed in, open https://dayonegreat.com/auth/me and copy `member_id`.
2. Either tell Claude to make you the administrator (it runs `app.set_administrator` through the Supabase connector, recorded in OPERATIONS.md; no secret), or run **Production setup** with steps `admin` and admin_member_id: **[PLACEHOLDER: your member_id]**.

## 4. Close the site, or go live on the Vercel side

Run **Production setup** with steps `stage,redeploy` and stage `closed` (or `public` for the go-live decision). The run sets `LAUNCH_STAGE` in Vercel, redeploys, and checks the live site reports the stage before it says done. Any re-run with the stage input at `unchanged` (the default) leaves the stage as it is.

Once the gateway is live it has its own stage setting (GATEWAY.md, "Go-live stage"), so closing the whole of Release 2 also means closing the gateway; the runbook gains that step with the gateway's pull request.

Always step back with a run, never with Vercel's Instant Rollback (RISKS.md RK68): an older deployment keeps the stage it was built with.

## 5. Test that the backup really restores (O2)

Run **Restore test** (Actions tab, on `main`) and approve it. It rebuilds the live data in a throwaway database inside the run, checks that every table's row count matches the live one, and runs the coverage check on the copy. The copy never leaves the run and is deleted when it ends. Separately, confirm in Supabase that daily backups are on. Record both in OPERATIONS.md.

## Later, as needed

- **X sign-in:** `X_CLIENT_ID` and `X_CLIENT_SECRET` (SIGNIN-SETUP.md) **[PLACEHOLDER: from console.x.com, after you register the app and set its spending limit]**.
- **Email sign-in links:** EMAIL-SETUP.md (Amazon SES) **[PLACEHOLDER: your AWS account, SES production access, and the DNS records]**.

## If a run stops

It stops at the first problem and says what it was. Nothing after that point has run. Fix the cause and run it again: migrations already applied are skipped, and `unchanged` leaves the stage alone.

## Your way back in

Every control below is one you hold. Be clear about what that does and doesn't mean today: Claude's session acts on GitHub as your own account (`MyChiefOS`, an administrator), and it holds write tools for Vercel and Supabase through its connections. The rules in CHARTER.md (you merge, Claude changes Supabase only with your approval, nothing goes live without your decision) are followed by Claude's conduct and recorded in OPERATIONS.md; they become real permissions only when you set the three things in RISKS.md RK71. What no setting can take from you:

- **GitHub.** You own the repository and the `production` environment. Once the environment has you as required reviewer and the administrator bypass is off, only your approval lets a setup run go ahead; until then an administrator token could run it. The branch rules on `main` are yours to change (today main requires 0 approvals). If a Claude session misbehaves, revoke the connection it uses (Claude's GitHub connector in your Claude settings, or the token under your GitHub account's Applications) and the workflows still work for you.
- **Vercel.** You own the chief-os team. Every variable is visible by name under the project's Settings → Environment Variables, and you can change or delete any of them there; `LAUNCH_STAGE` is plain text, so you can read it and set it to `closed` by hand at any time, then redeploy. Delete `VERCEL_TOKEN`s you no longer need under Account Settings → Tokens. Claude's Vercel connection can also change variables; it is used read-only by rule, and you can revoke it in your Claude settings.
- **Supabase.** You own the project. `dog_web` is the site's lesser login, made by migration 017 with its password in Vault. Resetting its password from the dashboard (Project Settings → Database) cuts the gateway off from the database at once (it fails closed); bringing it back means storing a new password in both the database and Vault, which is not automated yet and is done only with your agreement, recorded in OPERATIONS.md. Resetting the `postgres` password invalidates `MIGRATION_DATABASE_URL` if you have set it. Claude's Supabase connection can run SQL and migrations; it is used only with your approval, and you can revoke it in your Claude settings.
- **The site.** With `LAUNCH_STAGE` at `closed`, Release 2 is off on the Vercel side and the site serves exactly what it did before, from the code alone.
