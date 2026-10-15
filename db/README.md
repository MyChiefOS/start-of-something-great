# The database

Release 2 keeps its data in one Postgres database (15 or newer), with row-level security forced on every table.
Nothing here is tied to one provider: it runs the same on Supabase or Neon.

## How it fits together

- **Schema `app`** holds every table. It is not `public`, so a provider's automatic web API never sees it.
- **Two roles, neither able to sign in:**
  - `dog_owner` owns everything, and only migrations act as it.
  - `dog_app` is what the site acts as for every request. It can't bypass row-level security, owns nothing, and can't create objects, so it can't switch off a policy or a trigger.
- **The site's login role** (`dog_web`) has no rights of its own. Inside each transaction it switches to `dog_app` and states who is acting: someone not signed in, a member, an agent, Aaron, or the site itself. The policies decide what that actor may see or change. When the transaction ends, all of this ends with it, so nothing carries over to the next request on a pooled connection. Temporary tables are switched off for the same reason.
- **Who is acting is set in one place**: `db/index.js`, from what sign-in has verified. The database trusts it, so a code check (`.semgrep/database.yml`, repeated in `test/db.test.js`) fails the build if any other file sets it or changes the session. That catches mistakes. Code written to hide such a change could get past it, which is why every pull request is also reviewed. Each transaction also starts by closing leftover cursors, releasing session locks and fixing the search path.
- **Queries** go through `db/index.js` as tagged templates, so every value is sent as a parameter (S8). The code check `.semgrep/database.yml` bans raw SQL outside `scripts/migrate.js`.
- **IDs** are UUIDv7 from `app.uuid_v7()`: ordered by time and unique across databases (G3).
- **The audit log** accepts new rows and only Aaron can read them. Its ID, time and actor always come from the database, so a row can't be backdated or written in another actor's name. Nobody can edit, delete or truncate a row: the site's role has no right to, and triggers that fire always stop every attempt, including by the owner, a superuser, or replication mode. Only someone holding the owner's login could remove the triggers, and the coverage check would then fail (S7, G4).
- **The coverage check** (`db/checks.js`) reads Postgres's own catalog and fails if anything drifts from the rules above. That covers:
  - row-level security on and forced on every table, with one permissive policy per action
  - the rights each role holds, inside and outside `app`, and the roles each belongs to
  - the audit log's exact policies, rights and triggers
  - who may call our functions
  - size limits on every text and JSON column
  - UUIDv7 keys

  It also fails for any column that looks like it stores ID documents or passwords.
- **The reviewed snapshot** (`db/snapshot.txt`) lists every policy, right, default, constraint, trigger and function in plain text, built from the migrations. Every build checks the database against it, and so does the migration workflow on production, so any change made outside a reviewed migration fails. After writing a migration, run `TEST_DATABASE_URL=... npm run db:snapshot` and commit the result; the pull request shows exactly what changed.

## Setting it up (Aaron; Claude never sees these values)

1. **Create the database project** with the provider you approve.
2. **Add the migration address to GitHub, locked to `main` and to your approval.** This address can change anything in the database, so it lives in a protected environment, not a plain repository secret:
   1. Go to repository Settings, then Environments. Create `production`.
   2. Under Required reviewers, add yourself. Under Deployment branches, choose "Selected branches" and allow only `main`.
   3. In the same environment, add the secret `MIGRATION_DATABASE_URL`. Its value is the provider's session-mode or direct connection string for the main database user (for Supabase, the "Session pooler" string on port 5432).
   4. For Supabase, also add `MIGRATION_DATABASE_CA` with the contents of the SSL certificate from the database settings page. It's public, not a secret, but connections check the server against it.
3. **Run the migrations.** On the Actions tab, open "Database migrations" and click Run workflow on `main`, then approve it when GitHub asks. It applies the migrations, then runs the coverage check against the real database. Both steps must be green.
4. **Create the site's login role.** In the provider's SQL editor, run:

   ```sql
   create role dog_web login noinherit;
   grant dog_app to dog_web;
   ```

   Then give it a long random password without typing it into the SQL editor, which keeps a history of queries. Use `\password dog_web` in `psql`, which sends only a hash. Keep the password only in step 5.

5. **Add the site's address to Vercel.** Go to project Settings, then Environment Variables, and add `DATABASE_URL` for Production. Its value is the transaction pooler address for `dog_web`:
   - Supabase: the shared "Transaction pooler" string on port 6543, with user `dog_web.<project-ref>`. Supabase's dedicated pooler address is reachable only over IPv6, which Vercel's functions don't have.
   - Neon: the "-pooler" address.

   For Supabase, also add `DATABASE_CA` with the same certificate as in step 2. The site refuses any address that isn't a transaction pooler (G1), and checks the server's certificate. Nothing reads any of this until sign-in arrives in PR 2.

For Supabase, leave the Data API's exposed schemas as they are (`public` only). Never add `app`.

## Changing the schema

- Add a new file `db/migrations/NNN_name.sql`, numbered after the last one, starting with `set local role dog_owner;`.
- Never edit a file that has shipped: the runner refuses to continue if an applied file has changed.
- Every new table needs `enable` and `force row level security`, one policy per action, and size limits on its text columns. Otherwise the coverage check fails the build.
- Rebuild the snapshot (`npm run db:snapshot`) and commit it with the migration.

## What this does not protect against

- **A bug in our own server code.** Postgres trusts the actor that `db/index.js` sets. A bug that set the wrong actor, or code that ran its own SQL, could act as someone else. The code checks above keep that to one reviewed file. Agents and people never get SQL access; they reach the database only through our functions. A stronger lock, where the database itself verifies a signed claim from sign-in, is on the list for review before 1,000 members.
- **Someone holding the owner or superuser login** (the migration secret). They could remove the triggers. That login stays in the protected environment, and only the manual migration workflow, with your approval, uses it.
- **Changes made by hand in production.** These are caught when the coverage check runs after each migration, not continuously.

## Sign-in (Release 2, PR 2)

People join with GitHub, X or an email link, and nobody has a password. The site asks GitHub or X only who someone is, and throws the provider's access token away straight after. What it keeps:
- which kind of account was used, and the trust level it verified
- when it was checked
- a keyed fingerprint of the account (HMAC-SHA256 under a key kept outside the database)

Names and usernames from GitHub and X are not kept; everyone starts as "New member". Sessions are random tokens in a `__Host-` cookie, and only their SHA-256 is stored. Joining, creating sessions and using email links all happen in six reviewed functions that run as their own role, `dog_signin`. The site's everyday role can call them, but it can't read sessions, fingerprints or email links itself.

### Known limits of sign-in (accepted for the preview, on the list for the review before launch)

- **Server code can still act as anyone.** As with everything in this database, if our server code ran SQL of its own, it could claim to be any member and create a working session for them. The checks inside the sign-in functions stop honest mistakes, not deliberate code. That's why the stronger lock (a signed claim from sign-in that the database verifies) is on the list before 1,000 members.
- **Someone could switch email sign-in off for an hour.** There's a cap of 500 sign-in emails an hour for the whole site, so nobody can use the form to flood inboxes. An attacker with many addresses could use the cap up. GitHub and X sign-in keep working. The fix, if it happens, is an alert when the cap is reached.
- **The GitHub or X sign-in state can be replayed.** For its 10 minutes, someone who already has that browser's cookie could reuse it with a new code from the provider. Provider codes are single use, and the cookie never leaves the browser.
- **The function's own address answers too.** `/api/auth?route=...` reaches the same code as `/auth/...`. It's harmless, since the checks are the same, but untidy.
- **The email Continue page hasn't been tried in a real browser yet.** It's tested in code, and gets a browser check before email sign-in is switched on.

### What Aaron sets up (Claude never sees these values)

All of these are Vercel environment variables for **Production only**, so preview deployments never get them and sign-in stays off there.

1. **Keys.** Generate each one with `openssl rand -base64 32`:
   - `SESSION_SECRET`: protects the short-lived sign-in state.
   - `FINGERPRINT_KEYS`: written as `1:<key>`. To rotate later, put the new key first (`2:<new>,1:<old>`). Each person moves to the new key at their next sign-in, so never delete an old key while it's still listed.
   - `IP_HASH_KEY`: used only for rate limits.
2. **GitHub.** Under Settings, then Developer settings, then OAuth Apps, create a new app. Set the callback URL to exactly `https://dayonegreat.com/auth/github/callback`. Then set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in Vercel.
3. **X.** In the developer console, create an app with OAuth 2.0 as a confidential client (a "web app"). Set the callback to exactly `https://dayonegreat.com/auth/x/callback` and the scopes to `tweet.read` and `users.read`. Buy a small prepaid credit and set a spend cap: each X sign-in reads the account once, about $0.01. If the credit runs out, X sign-in fails safely and GitHub and email still work. Then set `X_CLIENT_ID` and `X_CLIENT_SECRET`.
4. **Email links** switch on once the email service is chosen, a later small PR. Until then, the email form says "Sign-in by email isn't switched on yet."
5. **LinkedIn** ("Verified on LinkedIn", level 2) switches on once LinkedIn approves the app.

### Making Aaron the administrator

1. Sign in once.
2. Open `https://dayonegreat.com/auth/me` and copy your `member_id`.
3. Run this in the SQL editor, with your ID in place of `PASTE-YOUR-MEMBER-ID`. Only the owner role can change administrator rights, and the site can't.

```sql
begin;
set local role dog_owner;
update app.members set is_admin = true where id = 'PASTE-YOUR-MEMBER-ID';
commit;
```

The editor should report `UPDATE 1`. Anything else means the ID didn't match, and nothing changed.
