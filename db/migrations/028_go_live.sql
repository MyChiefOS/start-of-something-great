-- 028 Go-live (Aaron, Oct 29: "Lets finish so we can open the site"; harness/PLAN.md fixes 7 and 9). Aaron's merge of
--   the pull request carrying it is the go-live decision. Nothing here locks anyone out.
--
--   1. The site's JEVs enforces (fix 7; confirmed by Aaron's merge of #44, Oct 25): every post, draft, report and
--      account check is scored and acted on, so first-post review ends (RISKS.md RK5, RK20). In enforce mode a post
--      whose decision can't be recorded at all is refused at commit (RK19); every other failure still lets it through.
--   2. At most one administrator, in the database itself: a unique index on the administrator flag. Before this only
--      app.set_administrator's own check stood between two promotions racing each other.
--   3. Aaron becomes administrator at his first code sign-in (fix 9; the setup run's administrator step needs a secret
--      that doesn't exist, harness/PLAN.md). The JEVs gate already knows a code was claimed by the founder's account
--      (GitHub ID 304218593, MyChiefOS; gate.mjs FOUNDER_ID): it now says so in app.code_claim, and the claimed code
--      keeps it. When that code signs its browser in and no administrator exists yet, app.founder_promote makes the
--      member administrator the way app.set_administrator does (025's app.admin_prepare: exactly one sign-in method,
--      GitHub, the one the account began with; every earlier session ends; every agent key revoked), and the browser
--      gets a fresh session as administrator. If the promotion is refused, the sign-in stands as a member's and the
--      refusal is recorded (admin.founder_refused): nobody is locked out. Once an administrator exists, a founder claim
--      is an ordinary code sign-in. Only the gate (dog_jevs) can mark a claim as the founder's; the site's role can't.
--      The risk this carries is RISKS.md RK89 (a): a code the founder's account posts, whoever asked for it, signs that
--      browser in as him, and before this migration's first promotion, as the first administrator.
set local role dog_owner;

-- 1. The site's JEVs enforces.
update app.jevs_settings set value = 'enforce' where key = 'mode';

-- 2. At most one administrator.
create unique index members_one_admin on app.members (is_admin) where is_admin;

-- 3. The founder's claim.
alter table app.code_signins add column founder boolean not null default false;
alter table app.code_signins add constraint code_signins_founder_claimed check (not founder or status <> 'waiting');
-- The sign-in role sets it with the claim, as it does the claim's other columns (023).
grant update (founder) on app.code_signins to dog_signin;

-- Making the founder administrator: app.set_administrator's steps, for app.code_sign_in only. It is the database
-- owner's, because only the owner may change the administrator flag (members_guard); only the sign-in role may call it.
-- It changes no actor setting, so the sign-in that called it carries on as the visitor it was.
create function app.founder_promote(p_member uuid)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_member is null then raise exception 'member required' using errcode = '22023'; end if;
  if exists (select 1 from app.members m where m.is_admin) then
    raise exception 'another member is already the administrator; nothing changed' using errcode = '23505';
  end if;
  if not exists (select 1 from app.members m where m.id = p_member and m.status = 'active') then
    raise exception 'no active member with that ID; nothing changed' using errcode = '02000';
  end if;
  perform app.admin_prepare(p_member);
  update app.members m set is_admin = true where m.id = p_member and m.status = 'active';
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('admin.set', 'member', p_member, jsonb_build_object('by', 'founder code sign-in'));
end
$$;
revoke execute on function app.founder_promote(uuid) from public;
grant execute on function app.founder_promote(uuid) to dog_signin;

grant create on schema app to dog_signin;
set local role dog_signin;

-- The gate's claim, now saying whether the founder's account posted it. A repeat by the same account changes nothing.
create function app.code_claim(p_code_hash text, p_fingerprint text, p_login_hash text, p_founder boolean)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_code_hash is null or p_code_hash !~ '^[0-9a-f]{64}$' or p_fingerprint is null or p_fingerprint !~ '^[0-9a-f]{64}$'
     or p_login_hash is null or p_login_hash !~ '^[0-9a-f]{64}$' or p_founder is null then
    return false;
  end if;
  update app.code_signins c set fingerprint = p_fingerprint, status = 'claimed', claimed_at = now(), founder = p_founder
    where c.code_hash = p_code_hash and c.login_hash = p_login_hash and c.status = 'waiting' and c.expires_at > now();
  if found then
    return true;
  end if;
  return exists (select 1 from app.code_signins c where c.code_hash = p_code_hash and c.login_hash = p_login_hash
                   and c.fingerprint = p_fingerprint and c.expires_at > now());
end
$$;
revoke execute on function app.code_claim(text, text, text, boolean) from public;
grant execute on function app.code_claim(text, text, text, boolean) to dog_jevs;

-- 023's three-argument claim stays until the gate is redeployed from this merge (OPERATIONS.md), so claims keep working
-- in between; it never marks the founder.
create or replace function app.code_claim(p_code_hash text, p_fingerprint text, p_login_hash text)
returns boolean
language sql security definer set search_path = pg_catalog
as $$ select app.code_claim(p_code_hash, p_fingerprint, p_login_hash, false) $$;

-- 025's code sign-in, with the founder's promotion added after the key file is kept.
create or replace function app.code_sign_in(p_browser_hash text, p_display_name text, p_session_hash text, p_session_days integer,
                                 p_region text)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  c app.code_signins%rowtype;
  s record;
  fresh boolean;
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
  -- The founder's first code sign-in makes him administrator (fix 9), if nobody is yet. The promotion ends every
  -- session he had, the one just made too, so the browser is signed in again, now as administrator. If the promotion
  -- is refused (a second sign-in method, a race with another promotion), it is undone alone: the sign-in stands as a
  -- member's, and the refusal is recorded with its error code only.
  if c.founder and not exists (select 1 from app.members m where m.is_admin) then
    fresh := s.is_new;
    begin
      perform app.founder_promote(s.member_id);
      select * into s from app.sign_in_core('github', array[c.fingerprint], 1::smallint, 1::smallint, p_display_name,
                                       p_session_hash, p_session_days, null::timestamptz, null::uuid, null::text);
      s.is_new := fresh;
    exception when sqlstate '42501' or sqlstate '23505' or sqlstate '02000' then
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('admin.founder_refused', 'member', s.member_id, jsonb_build_object('code', sqlstate));
    end;
  end if;
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin;
end
$$;

set local role dog_owner;
revoke create on schema app from dog_signin;
