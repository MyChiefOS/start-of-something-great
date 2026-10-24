-- Fresh build (Aaron, Oct 24, 2026: "clear the database tables and start over with a fresh build", passkeys removed).
-- Not a numbered migration. The runner (supabase/functions/dog-migrate/core.mjs) runs this file only when
-- db/manifest.json names it and the live ledger holds the exact migration the manifest's "when" names
-- (for PR 2: 014_passkeys at its Oct 23 fingerprint), so it can only ever run against the Oct 23 build, once.
-- It runs in one transaction: if any statement fails, nothing changes. Then the runner applies 001 onward.
--
-- What it does:
--   1. Refuses if any member, identity, session, post, agent or audit row exists (row-level security switched off
--      for the count, so a hidden row makes it fail loudly instead of being missed).
--   2. Drops the app schema and everything in it (the passkey tables and triggers included).
--   3. Removes dog_web, the unused login made by migration 017, and its password in Vault. The other dog_* roles
--      can't sign in, own nothing outside app, and are reused by 001 onward. The three site keys in Vault are kept.
--   4. Removes public.rls_auto_enable(), left over from the project's creation (IT audit F5, GAP-44).

set local row_security = off;
do $guard$
declare
  t text;
  n bigint;
begin
  foreach t in array array['members', 'identities', 'sessions', 'posts', 'agents', 'audit_log'] loop
    if to_regclass('app.' || t) is not null then
      execute format('select count(*) from app.%I', t) into n;
      if n > 0 then
        raise exception 'fresh build refused: app.% has % row(s); nothing changed', t, n;
      end if;
    end if;
  end loop;
end
$guard$;
reset row_security;

set local role dog_owner;
drop schema if exists app cascade;
reset role;

do $cleanup$
begin
  if exists (select 1 from pg_roles where rolname = 'dog_web') then
    begin
      drop role dog_web;
    exception when others then
      -- If the role can't be dropped here, it is made unable to sign in instead, which is what matters.
      alter role dog_web nologin password null;
      raise notice 'dog_web could not be dropped (%); it can no longer sign in', sqlerrm;
    end;
  end if;
  if to_regclass('vault.secrets') is not null then
    begin
      delete from vault.secrets where name = 'dog_web_password';
    exception when others then
      raise notice 'the unused dog_web_password could not be removed from Vault (%)', sqlerrm;
    end;
  end if;
  if to_regprocedure('public.rls_auto_enable()') is not null then
    begin
      drop function public.rls_auto_enable();
    exception when others then
      raise notice 'public.rls_auto_enable() could not be removed (%)', sqlerrm;
    end;
  end if;
end
$cleanup$;
