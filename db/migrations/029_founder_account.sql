-- 029 Aaron's administrator account, made with the go-live release (Aaron, Oct 29: "Can you create an admin account
--   for me on the system that I can change later following the process provided"). The site opens with its
--   administrator already there (RISKS.md RK92), so nothing waits on a promotion at his first sign-in.
--
--   The account is a member tied to his GitHub account (ID 304218593, MyChiefOS) by the same keyed fingerprint every
--   sign-in uses: HMAC-SHA256 of 'github:304218593' with the first fingerprint key (Vault, dog_fingerprint_key_1), the
--   key the JEVs gate and the site already hold. The fingerprint is made here, inside the database; the key is read from
--   Vault into this block and never appears in any statement's text, as in 022. Nobody types or sees it.
--   It has no sessions and no key file. Following his process (Oct 28): his first code sign-in on /join (post the code
--   from MyChiefOS) signs into this same account and sets his key file; later the username and key file sign him in
--   with no post; and "doing the process over" (a new code and a new key file) changes the file, the same for every
--   account. 025 still stands: the site's own role can't sign an administrator in by naming the fingerprint.
--
--   It is made as an administrator the way app.set_administrator does it (025's app.admin_prepare: exactly one sign-in
--   method, GitHub, the one the account began with), and only if nobody is administrator yet (the unique index, 028).
--   If the key or pgcrypto isn't here (plain Postgres in the tests), or anything fails, nothing is made and the runner's
--   log notes why; 028's promotion at his first code sign-in is then the way in, as before. Nobody is locked out.
set local role dog_owner;
grant create on schema app to dog_signin;
set local role dog_signin;

-- The member and its GitHub sign-in method, for a fingerprint; returns the member (the existing one if the fingerprint
-- already has an account). The sign-in role's, as sign-in itself is; only the database owner may call it.
create function app.founder_account(p_fingerprint text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  m uuid;
begin
  if p_fingerprint is null or p_fingerprint !~ '^[0-9a-f]{64}$' then
    raise exception 'bad fingerprint' using errcode = '22023';
  end if;
  select i.member_id into m from app.identities i where i.provider = 'github' and i.fingerprint = p_fingerprint;
  if found then
    return m;
  end if;
  insert into app.members (display_name, trust_level) values ('Aaron Chandler', 1) returning id into m;
  insert into app.identities (member_id, provider, fingerprint, key_version, level) values (m, 'github', p_fingerprint, 1, 1);
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.joined', 'member', m, jsonb_build_object('provider', 'github', 'level', 1, 'by', 'migration 029'));
  return m;
end
$$;
-- Revoked and granted as its owner (a revoke by any other role does nothing).
revoke execute on function app.founder_account(text) from public;
grant execute on function app.founder_account(text) to dog_owner;

set local role dog_owner;
revoke create on schema app from dog_signin;

-- Made here, as the runner's own login (it may read Vault; dog_owner may not), then as the database owner.
reset role;
do $founder$
declare
  k text;
  fp text;
  m uuid;
begin
  if to_regnamespace('vault') is null or to_regprocedure('extensions.hmac(bytea,bytea,text)') is null then
    raise notice 'founder account not made: no Vault or pgcrypto here; 028''s promotion at the first code sign-in stands';
    return;
  end if;
  execute 'select decrypted_secret from vault.decrypted_secrets where name = $1' into k using 'dog_fingerprint_key_1';
  if k is null then
    raise notice 'founder account not made: no dog_fingerprint_key_1 in Vault; 028''s promotion stands';
    return;
  end if;
  execute 'select encode(extensions.hmac(convert_to($1, ''UTF8''), convert_to($2, ''UTF8''), ''sha256''), ''hex'')'
    into fp using 'github:304218593', k;
  k := null;
  begin
    execute 'set local role dog_owner';
    perform set_config('app.actor', 'system', true), set_config('app.member_id', '', true), set_config('app.agent_id', '', true),
            set_config('app.fresh', '', true), set_config('app.session', '', true);
    perform set_config('app.stamp', app.actor_stamp('system', '', '', '', ''), true);
    m := app.founder_account(fp);
    if not exists (select 1 from app.members x where x.is_admin) then
      perform app.admin_prepare(m);
      update app.members x set is_admin = true where x.id = m and x.status = 'active';
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('admin.set', 'member', m, jsonb_build_object('by', 'migration 029 (Aaron, Oct 29)'));
    end if;
  exception when others then
    raise notice 'founder account not made (%); 028''s promotion at the first code sign-in stands', sqlstate;
  end;
  perform set_config('app.actor', '', true), set_config('app.stamp', '', true);
  execute 'reset role';
end
$founder$;
