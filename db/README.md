# The database

Release 2 keeps its data in one Postgres database (15 or newer), with row-level security forced on every table.
Nothing here is tied to one provider: it runs the same on Supabase or Neon.

## How it fits together

- **Schema `app`** holds every table. It is not `public`, so a provider's automatic web API never sees it.
- **Two roles, neither able to sign in:**
  - `dog_owner` owns everything, and only migrations act as it.
  - `dog_app` is what the site acts as for every request. It can't bypass row-level security, owns nothing, and can't create objects, so it can't switch off a policy or a trigger.
- **The site's login role** (`dog_web`) has no rights of its own. Inside each transaction it switches to `dog_app` and states who is acting: someone not signed in, a member, an agent, Aaron, or the site itself. The policies decide what that actor may see or change. When the transaction ends, all of this ends with it, so nothing carries over to the next request on a pooled connection. Temporary tables are switched off for the same reason.
- **Who is acting is set in one place**: `db/index.js`, from what sign-in has verified. The database trusts it, so a code check (`.semgrep/database.yml`, repeated in `test/db.test.js`) fails the build if any other file sets it or changes the session.
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

  It also fails for any column that looks like it stores ID documents or passwords. Every build runs it on a fresh database built from the migrations (`test/db.test.js`), and the migration workflow runs it on production afterwards.

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

## What this does not protect against

- **A bug in our own server code.** Postgres trusts the actor that `db/index.js` sets. A bug that set the wrong actor, or code that ran its own SQL, could act as someone else. The code checks above keep that to one reviewed file. Agents and people never get SQL access; they reach the database only through our functions. A stronger lock, where the database itself verifies a signed claim from sign-in, is on the list for review before 1,000 members.
- **Someone holding the owner or superuser login** (the migration secret). They could remove the triggers. That login stays in the protected environment, and only the manual migration workflow, with your approval, uses it.
- **Changes made by hand in production.** These are caught when the coverage check runs after each migration, not continuously.
