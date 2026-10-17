# Production setup: Aaron's steps

Release 2 is set up from GitHub by one workflow, **Production setup** (`.github/workflows/setup.yml`, code in `scripts/setup-production.js`). Nothing runs on your computer. Every key and password is made inside the run and goes straight to Vercel or to the database as a hash, so nobody sees them, Claude included.

Setting things up never opens the site. Release 2 stays off until **you** set the go-live stage (`LAUNCH_STAGE`, below). Setting it to `public` is the go-live decision.

Everything in **[PLACEHOLDER: …]** is a value only you can supply.

## 1. The protected environment (once, about 2 minutes)

GitHub → the repository → Settings → Environments → `production` (create it if it isn't there):

1. **Required reviewers:** add yourself. Every run waits for your approval.
2. **Deployment branches and tags:** "Selected branches and tags", allow only `main`.

## 2. Three secrets in that environment (once)

Add each one under the `production` environment's "Environment secrets", not as a repository secret.

| Name | Where to get it |
|---|---|
| `MIGRATION_DATABASE_URL` | **[PLACEHOLDER: Supabase → Connect → "Session pooler" connection string, port 5432, with your database password filled in]**. It looks like `postgresql://postgres.nksagchwpyljvjiwolmp:…@aws-0-us-east-1.pooler.supabase.com:5432/postgres`. |
| `MIGRATION_DATABASE_CA` | **[PLACEHOLDER: Supabase → Project Settings → Database → SSL Configuration → Download certificate; paste the whole file]**. It's public, not secret, but connections check the server against it. |
| `VERCEL_TOKEN` | **[PLACEHOLDER: Vercel → Account Settings → Tokens → Create. Scope: the chief-os team. Expiration: 1 day]**. Make a new one when you next need a run; the old one expires by itself. |

## 3. First run: set everything up, still closed

Actions → **Production setup** → Run workflow, on `main`:

- steps: `database,keys,stage,redeploy` (the default)
- stage: `closed` (the default)

Approve it when GitHub asks. It:

1. removes Supabase's `ensure_rls` trigger (you approved this; it's owned by the same user as the migration address, so the run can remove it);
2. applies the migrations, 001 onwards;
3. creates the site's login role `dog_web` with a password made in the run, sent to the database only as a hash;
4. puts `DATABASE_URL` (the transaction pooler, port 6543) and `DATABASE_CA` in Vercel;
5. runs the database coverage check;
6. makes `SESSION_SECRET`, `IP_HASH_KEY`, `FINGERPRINT_KEY_1` and `CRON_SECRET`, but only those that aren't already there (it never replaces one);
7. sets `LAUNCH_STAGE=closed`;
8. redeploys, so Vercel uses the new settings.

The site looks exactly as before. That's the point of `closed`.

## 4. Open the private preview (when you're ready)

Run **Production setup** again:

- steps: `stage,redeploy`
- stage: `preview`
- preview_allow: **[PLACEHOLDER: `github:<your numeric GitHub account ID>`]**. Your numeric ID is the `id` at `https://api.github.com/users/<your GitHub user name>`. Add more people the same way, separated by commas: `github:<id>`, `x:<id>`, or `email:<address>`. The run's inputs are visible in the Actions log, so prefer account IDs to email addresses.

Then sign in at https://dayonegreat.com/join with GitHub. Only the people on that list can make an account. Signed-out visitors see no posts. Agents can't register themselves; you add them on /agents.

## 5. Make yourself the administrator

1. While signed in, open https://dayonegreat.com/auth/me and copy `member_id`.
2. Run **Production setup** with steps `admin` and admin_member_id: **[PLACEHOLDER: your member_id]**.

## 6. Go live

When you've tested the preview and decided, run **Production setup** with steps `stage,redeploy` and stage `public`. To close it again at any time, run the same steps with stage `closed`.

## 7. Test that the backup really restores (O2)

Run **Restore test** (Actions tab, on `main`) and approve it. It rebuilds the live data in a throwaway database inside the run, checks that every table's row count matches the live one, and runs the coverage check on the copy. The copy never leaves the run and is deleted when it ends. Separately, confirm in Supabase that daily backups are on. Record both in OPERATIONS.md.

## Later, as needed

- **X sign-in:** `X_CLIENT_ID` and `X_CLIENT_SECRET` (SIGNIN-SETUP.md) **[PLACEHOLDER: from console.x.com, after you register the app and set its spending limit]**.
- **Email sign-in links:** EMAIL-SETUP.md (Amazon SES) **[PLACEHOLDER: your AWS account, SES production access, and the DNS records]**.
- **A new database password:** run `database,redeploy` with "rotate_db_password" ticked.

## If a run stops

It stops at the first problem and says what it was, without showing any secret. Nothing after that point has run. Fix the cause and run it again: every step is safe to repeat, and keys that already exist are never replaced.
