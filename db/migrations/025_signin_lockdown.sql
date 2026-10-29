-- 025 The site can't sign in an administrator directly (the CSO's review, Oct 29; RISKS.md RK82; Aaron, Oct 29: "Lets
--   finish so we can open the site").
--   Until now the site's everyday role (dog_app) could call app.sign_in itself, naming any GitHub fingerprint. That is
--   the path the switched-off GitHub, X and email sign-ins use. The CSO showed, on a throwaway database, that with the
--   site's login and the first fingerprint key (what the key broker hands the site) and Aaron's public GitHub ID, it
--   makes a session for Aaron: once he is administrator, that session is the administrator's.
--   Now: app.sign_in's work moves to app.sign_in_core, which only the sign-in role's own functions call. app.sign_in
--   stays for the site's role but refuses an administrator ('admin_code_only'): an administrator signs in only by a
--   code the JEVs gate confirmed, or by the key file a code sign-in recorded (023). The code and key-file sign-ins call
--   app.sign_in_core, so they are unchanged. Nothing is refused to members, so nobody is locked out.
--   Making someone administrator (app.set_administrator, fix 9) now also ends every session the member had, so a
--   session made before the promotion, by any path, can't become the administrator's (the CSO's review of this PR,
--   B1); and it refuses unless the member has exactly one sign-in method, GitHub, the one the account began with, so
--   an account someone else linked Aaron's GitHub to can't be made administrator (B2). Aaron then signs in once more by
--   code or key file. Nobody is locked out.
--   Still open (RISKS.md RK82): the site's role can sign in an existing member who isn't administrator by naming their
--   fingerprint, and link a fingerprint nobody has used yet to its own fresh session; retiring those calls, with the
--   switched-off GitHub, X and email sign-ins that use them, is a later PR.
set local role dog_owner;
grant create on schema app to dog_signin;
set local role dog_signin;

alter function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid, text) rename to sign_in_core;
revoke execute on function app.sign_in_core(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid, text) from dog_app;

create function app.sign_in(p_provider text, p_fingerprints text[], p_key_version smallint, p_level smallint,
                            p_display_name text, p_session_hash text, p_session_days integer,
                            p_recheck_after timestamptz, p_link_member uuid, p_region text)
returns table (member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
begin
  select * into s from app.sign_in_core(p_provider, p_fingerprints, p_key_version, p_level, p_display_name, p_session_hash,
                                        p_session_days, p_recheck_after, p_link_member, p_region);
  -- Raising undoes the whole call, the session it made included.
  if s.is_admin then
    raise exception 'admin_code_only' using errcode = 'P0001';
  end if;
  return query select s.member_id, s.is_new, s.trust_level, s.is_admin;
end
$$;
revoke execute on function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid, text) from public;
grant execute on function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid, text) to dog_app;

-- The code and key-file sign-ins (023), unchanged except that they call app.sign_in_core.
create or replace function app.code_sign_in(p_browser_hash text, p_display_name text, p_session_hash text, p_session_days integer,
                                 p_region text)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  c app.code_signins%rowtype;
  s record;
begin
  if p_browser_hash is null or p_browser_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad code request' using errcode = '22023';
  end if;
  select * into c from app.code_signins x
    where x.browser_hash = p_browser_hash and x.status = 'claimed' and x.expires_at > now()
    order by x.claimed_at desc limit 1 for update;
  if not found then
    if exists (select 1 from app.code_signins x where x.browser_hash = p_browser_hash and x.status = 'waiting' and x.expires_at > now()) then
      return query select 'waiting'::text, null::uuid, null::boolean, null::smallint, null::boolean;
    else
      return query select 'expired'::text, null::uuid, null::boolean, null::smallint, null::boolean;
    end if;
    return;
  end if;
  update app.code_signins x set status = 'used', used_at = now() where x.id = c.id;
  -- Key version 1: the gate holds the first fingerprint key (dog_fingerprint_key_1). A rotation must move the gate too.
  begin
    select * into s from app.sign_in_core('github', array[c.fingerprint], 1::smallint, 1::smallint, p_display_name,
                                     p_session_hash, p_session_days, null::timestamptz, null::uuid, p_region);
  exception when sqlstate 'P0001' then
    if sqlerrm <> 'region' then
      raise;
    end if;
    delete from app.code_signins x where x.id = c.id;
    return query select 'region'::text, null::uuid, null::boolean, null::smallint, null::boolean;
    return;
  end;
  -- The key file chosen with this code becomes the member's, replacing any earlier one.
  -- A fresh row, so the wrong-file count starts at 0: any earlier key file for this member, this GitHub account or this
  -- username goes (a username another account used before a rename keeps no key file).
  delete from app.file_keys f where f.member_id = s.member_id or f.fingerprint = c.fingerprint or f.login_hash = c.login_hash;
  insert into app.file_keys (member_id, fingerprint, login_hash, key_hash) values (s.member_id, c.fingerprint, c.login_hash, c.file_key);
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin;
end
$$;

create or replace function app.file_sign_in(p_login_hash text, p_key_hash text, p_display_name text, p_session_hash text,
                                 p_session_days integer, p_region text)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  k app.file_keys%rowtype;
  s record;
begin
  if p_login_hash is null or p_login_hash !~ '^[0-9a-f]{64}$' or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad key file request' using errcode = '22023';
  end if;
  select * into k from app.file_keys f where f.login_hash = p_login_hash and f.key_hash = p_key_hash for update;
  if not found then
    -- A wrong file for a username that has a key file counts; the 10th cancels it and tells the member, who then
    -- starts again with a new code (Aaron, Oct 28).
    update app.file_keys f set failed = f.failed + 1 where f.login_hash = p_login_hash returning * into k;
    if found and k.failed >= 10 then
      delete from app.file_keys f where f.id = k.id;
      perform app.notify(k.member_id, 'signin_keyfile', 'Your key file was cancelled',
        'Someone tried 10 wrong key files with your GitHub username, so your key file no longer works. Your account is '
        || 'safe. To sign in, get a new code on the join page, post it, and choose a new key file.', '/join', 'member',
        k.member_id, 'signin:keyfile:cancelled:' || k.id::text);
      return query select 'start_again'::text, null::uuid, null::boolean, null::smallint, null::boolean;
      return;
    end if;
    return query select 'no_match'::text, null::uuid, null::boolean, null::smallint, null::boolean;
    return;
  end if;
  select * into s from app.sign_in_core('github', array[k.fingerprint], 1::smallint, 1::smallint, p_display_name,
                                   p_session_hash, p_session_days, null::timestamptz, null::uuid, p_region);
  update app.file_keys f set used_at = now(), failed = 0 where f.id = k.id;
  perform app.notify(s.member_id, 'signin_keyfile', 'Signed in with your key file',
    'Your key file was used to sign in to Day One Great. If that wasn''t you, sign out everywhere from your account page '
    || 'and sign in again with a new code and a new key file.', '/account', 'member', s.member_id,
    'signin:keyfile:' || p_session_hash);
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin;
end
$$;

-- Getting a member ready to be administrator (B1, B2): they must have exactly one sign-in method, GitHub, the one the
-- account began with; every session they have ends, and every key of their agents is revoked, so nothing made before
-- the promotion acts with the administrator's standing (the re-check, N2). Only the database owner calls it, from
-- app.set_administrator. It first locks the member's sign-in methods and then the member, in the order sign-in itself
-- takes them, so a sign-in still running finishes first and its session is ended too (the re-check, N1).
create function app.admin_prepare(p_member uuid)
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
begin
  perform 1 from app.identities i where i.member_id = p_member order by i.id for update;
  perform 1 from app.members m where m.id = p_member for update;
  if (select count(*) from app.identities i where i.member_id = p_member) <> 1
     or not exists (select 1 from app.identities i where i.member_id = p_member and i.provider = 'github' and i.linked_by is null) then
    raise exception 'the administrator must have exactly one sign-in method, GitHub, the one the account began with; nothing changed'
      using errcode = '42501';
  end if;
  delete from app.sessions s where s.member_id = p_member;
  get diagnostics n = row_count;
  update app.agent_keys k set revoked_at = now() where k.revoked_at is null
    and k.agent_id in (select a.id from app.agents a where a.owner_id = p_member);
  return n;
end
$$;
revoke execute on function app.admin_prepare(uuid) from public;
grant execute on function app.admin_prepare(uuid) to dog_owner;

set local role dog_owner;
revoke create on schema app from dog_signin;

-- app.set_administrator is 019's, except that it first gets the member ready (above).
create or replace function app.set_administrator(p_member uuid)
returns text
language plpgsql set search_path = pg_catalog
as $$
declare
  other uuid;
  n integer;
begin
  if p_member is null then raise exception 'member required' using errcode = '22023'; end if;
  perform set_config('app.actor', 'system', true), set_config('app.member_id', '', true), set_config('app.agent_id', '', true),
          set_config('app.fresh', '', true), set_config('app.session', '', true);
  perform set_config('app.stamp', app.actor_stamp('system', '', '', '', ''), true);
  if exists (select 1 from app.members where id = p_member and is_admin) then return 'already'; end if;
  select id into other from app.members where is_admin limit 1;
  if other is not null then
    raise exception 'another member is already the administrator (%); nothing changed', other using errcode = '23505';
  end if;
  if not exists (select 1 from app.members where id = p_member and status = 'active') then
    raise exception 'no active member with that ID; nothing changed' using errcode = '02000';
  end if;
  perform app.admin_prepare(p_member);
  update app.members set is_admin = true where id = p_member and status = 'active';
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'no active member with that ID; nothing changed' using errcode = '02000'; end if;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('admin.set', 'member', p_member, jsonb_build_object('by', 'production setup run'));
  return 'set';
end
$$;
