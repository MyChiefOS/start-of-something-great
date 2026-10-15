# The database

Release 2 keeps its data in one Postgres database (15 or newer), with row-level security forced on every table.
Nothing here is tied to one provider: it runs the same on Supabase or Neon.

## How it fits together

- **Schema `app`** holds every table. It is not `public`, so a provider's automatic web API never sees it.
- **Two roles, neither able to sign in:**
  - `dog_owner` owns everything, and only migrations act as it.
  - `dog_app` is what the site acts as for every request. It can't bypass row-level security, owns nothing, and can't create objects, so it can't switch off a policy or a trigger.
- **The site's login role** (`dog_web`) has no rights of its own. Inside each transaction it switches to `dog_app` and states who is acting: someone not signed in, a member, an agent, Aaron, or the site itself. The policies decide what that actor may see or change. When the transaction ends, all of this ends with it, so nothing carries over to the next request on a pooled connection.
- **Queries** go through `db/index.js` as tagged templates, so every value is sent as a parameter (S8). The code check `.semgrep/database.yml` bans raw SQL outside `scripts/migrate.js`.
- **IDs** are UUIDv7 from `app.uuid_v7()`: ordered by time and unique across databases (G3).
- **The audit log** accepts new rows and only Aaron can read them. Nobody can edit, delete or truncate it, not even the owner or a superuser, because statement triggers stop every attempt (S7, G4). An audit row always names whoever is really acting.
- **The coverage check** (`db/checks.js`) reads Postgres's own catalog and fails the build if any of these is missing: row-level security on and forced on every table, the rights limits above, size limits on text and JSON columns, UUIDv7 IDs, the audit log's triggers. It also fails for any column that looks like it stores ID documents or passwords. Every build runs it on a fresh database built from the migrations (`test/db.test.js`).

## Setting it up (Aaron; Claude never sees these values)

1. **Create the database project** with the provider you approve.
2. **Add the migration address to GitHub.** Go to repository Settings, then Secrets and variables, then Actions, and add a new secret named `MIGRATION_DATABASE_URL`. Its value is the provider's direct or session-mode connection string for the main database user (for Supabase, the "Session pooler" string on port 5432).
3. **Run the migrations.** On the Actions tab, open "Database migrations" and click Run workflow. It applies the migrations, then runs the coverage check against the real database. Both steps must be green.
4. **Create the site's login role.** In the provider's SQL editor, run the lines below. Replace the password with a long random one, and keep it only in step 5.

   ```sql
   create role dog_web login noinherit password 'a-long-random-password';
   grant dog_app to dog_web;
   ```

5. **Add the site's address to Vercel.** Go to project Settings, then Environment Variables, and add `DATABASE_URL` for Production. Its value is the transaction pooler address for `dog_web`:
   - Supabase: the "Transaction pooler" string on port 6543, with user `dog_web.<project-ref>`.
   - Neon: the "-pooler" address.

   The site refuses any address that isn't a transaction pooler (G1). Nothing reads it until sign-in arrives in PR 2.

For Supabase, leave the Data API's exposed schemas as they are (`public` only). Never add `app`.

## Changing the schema

- Add a new file `db/migrations/NNN_name.sql`, numbered after the last one, starting with `set local role dog_owner;`.
- Never edit a file that has shipped: the runner refuses to continue if an applied file has changed.
- Every new table needs `enable` and `force row level security`, one policy per action, and size limits on its text columns. Otherwise the coverage check fails the build.

## What this does not protect against

- **Our own server code.** It is the boundary that decides who is acting. Agents and people never get SQL access; they reach the database only through our functions.
- **Someone holding the owner or superuser login** (the migration secret). They could remove the triggers. That login stays with Aaron, and only the manual migration workflow uses it.
- **Changes made by hand in production.** These are caught when the coverage check runs after each migration, not continuously.
