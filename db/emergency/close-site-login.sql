-- EMERGENCY ONLY: turns off the site's database login (dog_web), the database side of the close switch (the CSO's
-- control 7, R-10). Kept outside db/migrations, so nothing runs it by itself. To use it (OPERATIONS.md, "Runbook: close
-- the site now"): Claude copies this file unchanged into db/migrations as the next number (for example
-- 028_close_site_login.sql), runs `node scripts/manifest.js` and `npm run db:snapshot`, and opens a pull request; Aaron
-- merges it, and the runner applies it like any migration. test/preopen-safety.test.js applies this file to a
-- throwaway database and shows the site's login refused.
--   * The login is made unable to sign in (nologin). Its password, its membership of dog_app and every table stay as
--     they are, so nothing is lost and reopen-site-login.sql undoes it exactly.
--   * Connections already open as dog_web are ended where the runner's login may end them (on Supabase it may end
--     sessions of roles it administers; if it can't, they end within 30 minutes, the site's pool's longest
--     connection life, db/index.js). A refusal there doesn't stop the rest.
--   * Nothing else: the JEVs gate on GitHub, the public pages and the read API keep working. To take the site's own
--     pages off as well, launch.json goes to "closed" in the same pull request.
do $close$
begin
  if exists (select 1 from pg_roles where rolname = 'dog_web') then
    execute 'alter role dog_web nologin';
  end if;
end
$close$;
do $kick$
begin
  perform pg_terminate_backend(a.pid) from pg_stat_activity a where a.usename = 'dog_web' and a.pid <> pg_backend_pid();
exception when others then
  raise notice 'close-site-login: open dog_web connections were not ended (%); they end within 30 minutes', sqlstate;
end
$kick$;
