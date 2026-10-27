-- 022 The site's own database login, made inside the database (route B, Aaron, Oct 26; harness/PLAN.md fixes 5 and 8).
--   dog_web may log in, inherits nothing, and is a member of dog_app only: the narrow login the runner's fix-4 check
--   allows (supabase/functions/dog-migrate/core.mjs, wide_site_login). Every request still runs as dog_app, and since
--   fix 3 (019) the database decides who is acting from proof, so holding this login lets no one act as a member.
--   Its password is made here, at random, and kept in Supabase Vault as 'dog_web_password'. Nobody types or sees it:
--   the site gets it from the key broker (supabase/functions/dog-keys), which hands it only to a production function
--   of our own Vercel project, proved by Vercel's identity token.
--   The password never appears in any statement's text, so the database's statement log (log_statement = ddl) holds
--   only this file: it is made and used inside the block below (EXECUTE runs it there, and only top-level statements
--   are logged).
--   If dog_web already exists, this gives it a new password. A later rotation would do the same in a new migration;
--   until two-role rotation is built (RISKS.md RK88), a running site picks the new password up at its next refresh from
--   the broker, within 10 minutes, and its new connections fail until then. Where Vault isn't
--   installed (plain Postgres in the local tests) the password is made and dropped: the login can't be used there.
--   This part runs as the runner's own login (postgres on Supabase), which may create logins and write to Vault;
--   dog_owner may do neither. A new role has no other attributes by default; one wider than this is caught by the
--   runner's fix-4 check, which alerts (Supabase's login can't remove superuser or bypassrls itself).
do $site_login$
declare
  pw text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  existing uuid;
begin
  if exists (select 1 from pg_roles where rolname = 'dog_web') then
    execute format('alter role dog_web with login noinherit password %L', pw);
  else
    execute format('create role dog_web with login noinherit password %L', pw);
  end if;
  -- Exactly one membership, with no admin option and no inheritance (fix 4 refuses anything wider).
  if not exists (select 1 from pg_auth_members m join pg_roles r on r.oid = m.roleid join pg_roles u on u.oid = m.member
                 where r.rolname = 'dog_app' and u.rolname = 'dog_web') then
    execute 'grant dog_app to dog_web with inherit false';
  end if;
  if to_regnamespace('vault') is not null then
    execute 'select id from vault.secrets where name = $1' into existing using 'dog_web_password';
    if existing is null then
      perform vault.create_secret(pw, 'dog_web_password', 'The site''s database login (dog_web), made by migration 022');
    else
      perform vault.update_secret(existing, pw);
    end if;
  end if;
  pw := null;
end
$site_login$;
