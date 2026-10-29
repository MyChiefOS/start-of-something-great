# Production setup

Rewritten Oct 29, 2026 for the go-live release. **There is nothing to set up by hand.** Aaron chose route B on Oct 26 (CHARTER.md §2). Under it:
- the site's database login and its keys are made inside the database and handed to the site by the key broker (`dog-keys`; db/README.md);
- the timers need no secret (027);
- the go-live stage is the repository's own `launch.json`.

Every change is a pull request Claude builds and Aaron merges. Claude never sees a secret.

## How the site opens and closes

- **Opening** is Aaron's merge of the go-live PR, which sets `launch.json` to `public`. Vercel's production deploy of that merge opens Release 2.
- **Closing** (OPERATIONS.md, "Runbook: close the site now"):
  - a PR setting `launch.json` to `closed`, which Aaron merges;
  - or, for the immediate close by hand, `LAUNCH_STAGE` set to `closed` in Vercel, then a redeploy. `LAUNCH_STAGE` can only close the site, never open it;
  - and, if the database itself must be cut off, the emergency migration in `db/emergency/`.
- **Rolling back** to an older deployment never closes the site safely: it keeps the stage its own commit said (RISKS.md RK68).

## How Aaron becomes administrator

At his first code sign-in on /join after opening (028; fix 9). He types his GitHub username, chooses a key file, and posts the code from MyChiefOS. That sign-in makes him administrator, and later the same username and key file sign him in with no post (db/README.md, "Making Aaron the administrator"). Until then the site has no administrator (RISKS.md RK92).

## Backups and the restore test (O2)

Supabase backups are on: the Pro plan, daily, with 7 days restorable (confirmed read-only Oct 29, OPERATIONS.md); after a restore, the site's login needs a new password (runbook step 3b). The **Restore test** workflow needs `MIGRATION_DATABASE_URL`, which doesn't exist, so it can't run. A restore drill that needs no pasted secret is Claude's, after fix 10 (harness/PLAN.md).

## The Production setup workflow

`.github/workflows/setup.yml` (`scripts/setup-production.js`) is route A's fallback (CHARTER.md §2) and isn't needed. What it can still do:
- **keys:** writes the site's keys into Vercel if they are missing. These would override the broker's, so don't run it under route B.
- **stage:** sets `LAUNCH_STAGE` in Vercel. Since the go-live release, that setting can only close the site.
- **admin:** needs `MIGRATION_DATABASE_URL`, which doesn't exist.
- **redeploy.**

Its `production` environment has no approval rule (found Oct 25, OPERATIONS.md), so a run wouldn't wait for anyone.

## Your way back in

If Aaron can't sign in, he gets a new code on /join and posts it from MyChiefOS with a new key file. That gives him back his same account, as administrator, for every account the same (Aaron, Oct 28). Ten wrong key files, or "Sign out everywhere", cancel the key file; a new code always works.
