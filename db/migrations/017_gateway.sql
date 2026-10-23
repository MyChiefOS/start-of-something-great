-- 017 The JEVs gateway, slice 1 (GATEWAY.md; Aaron's approval, Oct 23, 2026, OPERATIONS.md).
-- The code that touches the database moves into a Supabase Edge Function, the JEVs gateway. Supabase gives that
-- function its main database login. The gateway uses it once, at start-up, to read what this migration keeps in
-- Supabase Vault, and serves every request through the narrow login dog_web, which can only become dog_app (the
-- coverage check, S1, keeps it that way). Nobody, Claude included, ever sees a password or key made here.
--
-- On Supabase (Vault present):
--   1. dog_web exists (as the setup workflow would make it) and is granted dog_app.
--   2. Its password is made here from Postgres's own secure random generator, set on the role (the server keeps
--      only a SCRAM hash) and stored in Vault for the gateway. Statements run inside this block aren't written to
--      the statement log, which records only the block itself.
--   3. The site's keys (sessions, network hashing, account fingerprints) are made the same way and stored in Vault.
--   Vault keeps every secret encrypted on disk and in every backup; Supabase holds the encryption key outside the
--   database. Each is created once and never replaced: a new fingerprint key would orphan every account, and a new
--   password would cut off a running gateway. If dog_web already has a password from the setup workflow (whose
--   database step is retired by this design), nothing here touches it.
-- Anywhere else (the tests, or a database the protected workflow set up, whose keys live in Vercel) there is no
-- Vault and this migration does nothing.

do $gateway$
declare
  k text;
  pw text;
begin
  if to_regclass('vault.secrets') is null then
    return;
  end if;

  if not exists (select 1 from pg_roles where rolname = 'dog_web') then
    create role dog_web login noinherit nocreatedb nocreaterole nobypassrls connection limit 20;
  end if;
  grant dog_app to dog_web;

  if not exists (select 1 from vault.secrets where name = 'dog_web_password') then
    pw := encode(extensions.gen_random_bytes(24), 'hex');
    execute format('alter role dog_web password %L', pw);
    perform vault.create_secret(pw, 'dog_web_password', 'Password of the gateway''s narrow login; made in place by migration 017');
    pw := null;
  end if;

  foreach k in array array['dog_session_secret', 'dog_ip_hash_key', 'dog_fingerprint_key_1'] loop
    if not exists (select 1 from vault.secrets where name = k) then
      -- 32 random bytes in base64, which is what signin/config.js expects.
      perform vault.create_secret(encode(extensions.gen_random_bytes(32), 'base64'), k,
        'Day One Great site key, made in place by migration 017; never shown, never replaced');
    end if;
  end loop;
end
$gateway$;
