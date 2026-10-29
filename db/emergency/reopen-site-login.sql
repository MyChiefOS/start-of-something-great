-- Undoes close-site-login.sql: the site's database login (dog_web) may sign in again, with the same password it had,
-- which the key broker still hands out. Kept outside db/migrations, so nothing runs it by itself. To use it: Claude
-- copies it unchanged into db/migrations as the next number (for example 029_reopen_site_login.sql), runs
-- `node scripts/manifest.js` and `npm run db:snapshot`, and opens a pull request; Aaron merges it. Reopening is Aaron's
-- decision, as opening was. If the reason for closing was a leaked password, give dog_web a new one instead: a
-- migration that runs 022's block again (OPERATIONS.md).
do $reopen$
begin
  if exists (select 1 from pg_roles where rolname = 'dog_web') then
    execute 'alter role dog_web login';
  end if;
end
$reopen$;
