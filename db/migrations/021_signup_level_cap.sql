-- 021 Sign-in levels are capped at 1 in the database; level 2 comes only through JEVs (RISKS.md RK82; Oct 26, 2026).
--   Before this, app.sign_in and app.identity_link took the starting level from their caller (0 to 2,
--   012_signin_fixes.sql), so whoever held the site's database login could make a member at level 2, who may own
--   agents, in one silent call. Now two triggers, set to fire always (even in replication mode), lower every level
--   written from now on to app.identities, and every new member's level, to 1, whoever writes it. A higher level is
--   lowered, never refused, so the person still signs in (checks alert, never lock out). Each one is recorded in the
--   audit log as 'signup.level_capped' and alerts Aaron in-app, once per member.
--   This REDUCES RK82; it doesn't close it. Level 2 now comes only through JEVs's promotion, and a caller holding the
--   site's login can still pass JEVs's sign-up check with made-up facts, at about 50 accounts an hour before JEVs's
--   burst rule stops promotions (the CSO's review, Oct 26, verified on a throwaway database). Each such promotion
--   leaves a JEVs decision and an audit row, and the watch's "burst of new accounts" alert (011) fires.
--   NOT done here, because the database can't check them:
--     * GitHub-only (Aaron, Oct 23). It isn't a rule in the site's code either: X and email stay off only because
--       their Vercel settings are absent. A database rule wouldn't stop a forged caller (it would just say "github");
--       it would stop a settings change from opening X or email. Recorded in RK82 as Claude's to close.
--     * The regional decline: the database refuses a new member when the site reports a declined region (012), but
--       it can't detect where a request came from itself.
--   Also: app.sign_in's 'member.joined' audit row now records the level the member was given, not the one asked for.
set local role dog_owner;

-- The cap is the constant 1 in both triggers below. A migration changes it by replacing them; nothing else can, and
-- there is no table for the site to read.
-- Runs as whoever writes the row (not a definer): in production that is dog_signin, inside app.sign_in or
-- app.identity_link.
create function app.identities_level_cap() returns trigger
language plpgsql set search_path = pg_catalog as $$
declare
  cap constant smallint := 1; -- phase 1's cap
begin
  if new.level > cap then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('signup.level_capped', 'member', new.member_id,
              jsonb_build_object('provider', new.provider, 'asked', new.level, 'given', cap));
    -- Aaron's inbox, once per member. In phase 1 only a forged caller asks for more than 1 (GitHub asks for 1). An
    -- alert that can't be written never stops the sign-in.
    begin
      perform app.notify(null, 'alert', 'A sign-in asked for a level above 1',
        'The database gave level 1 instead (RISKS.md RK82). Look at this member in the controls.', '/controls',
        'member', new.member_id, 'signin:capped:' || new.member_id::text);
    exception when others then
      null;
    end;
    new.level := cap;
  end if;
  return new;
end
$$;

create function app.members_level_cap() returns trigger
language plpgsql set search_path = pg_catalog as $$
declare
  cap constant smallint := 1; -- phase 1's cap, as above
begin
  if new.trust_level > cap then
    new.trust_level := cap;
  end if;
  return new;
end
$$;

revoke execute on function app.identities_level_cap(), app.members_level_cap() from public;

create trigger identities_level_cap before insert or update of level on app.identities
  for each row execute function app.identities_level_cap();
-- Only a new member's starting level: later raises come from app.verified_level (capped identities, or JEVs).
create trigger members_level_cap before insert on app.members
  for each row execute function app.members_level_cap();
-- Every guard trigger fires always, so replication mode can't switch them off (the CSO's review, Oct 26: Supabase lets
-- its main login set session_replication_role).
alter table app.identities enable always trigger identities_level_cap;
alter table app.members enable always trigger members_level_cap;

-- The alert above, from inside the sign-in functions (dog_signin): 012's policy plus Aaron's own alerts of this kind
-- only. One policy, as the coverage check requires.
drop policy notices_signin_insert on app.notices;
create policy notices_signin_insert on app.notices for insert to dog_signin
  with check ((member_id is not null and kind in ('signin_linked', 'signin_unlinked'))
              or (member_id is null and kind = 'alert' and dedupe_key like 'signin:capped:%'));

-- ---- app.sign_in: the same as 012, except that 'member.joined' records the level given (the CSO's review) ----
grant create on schema app to dog_signin;
set local role dog_signin;

create or replace function app.sign_in(p_provider text, p_fingerprints text[], p_key_version smallint, p_level smallint,
                                       p_display_name text, p_session_hash text, p_session_days integer,
                                       p_recheck_after timestamptz, p_link_member uuid, p_region text)
returns table (member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  ident app.identities%rowtype;
  mem app.members%rowtype;
  fresh boolean := false;
  used uuid;
begin
  if p_provider is null or not (p_provider = any (array['github', 'x', 'email', 'linkedin']))
     or p_fingerprints is null or cardinality(p_fingerprints) not between 1 and 5
     or exists (select 1 from unnest(p_fingerprints) f where f is null or f !~ '^[0-9a-f]{64}$')
     or p_key_version is null or p_key_version not between 1 and 999
     or p_level is null or p_level not between 0 and 2 or p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$'
     or p_session_days is null or p_session_days not between 1 and 30
     or p_display_name is null or char_length(p_display_name) not between 1 and 80
     or (p_region is not null and p_region !~ '^[A-Z]{2}$') then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  -- Signing in is for someone not signed in, and never links a method (PR 15: app.identity_link does, with no session).
  if p_link_member is not null or app.actor_kind() <> 'anon' then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;

  select * into ident from app.identities i where i.provider = p_provider and i.fingerprint = any (p_fingerprints)
    order by i.created_at limit 1 for update;

  if found then
    select * into mem from app.members m where m.id = ident.member_id for update;
    update app.identities i set fingerprint = p_fingerprints[1], key_version = p_key_version, level = p_level,
                                verified_at = now(), recheck_after = p_recheck_after
      where i.id = ident.id;
    used := ident.id;
  elsif p_region is not null then
    -- Nobody signs up from a declined region, whatever they confirm.
    raise exception 'region' using errcode = 'P0001';
  else
    insert into app.members (display_name, trust_level) values (p_display_name, p_level) returning * into mem;
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (mem.id, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after) returning id into used;
    fresh := true;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.joined', 'member', mem.id, jsonb_build_object('provider', p_provider, 'level', mem.trust_level));
  end if;

  if mem.status = 'banned' then
    raise exception 'banned' using errcode = 'P0001';
  end if;
  if mem.status = 'disabled' or app.deletion_overdue(mem.id) then
    raise exception 'disabled' using errcode = 'P0001';
  end if;

  if app.verified_level(mem.id) is distinct from mem.trust_level then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_changed', 'member', mem.id,
              jsonb_build_object('provider', p_provider, 'from', mem.trust_level, 'to', app.verified_level(mem.id)));
    update app.members m set trust_level = app.verified_level(mem.id) where m.id = mem.id;
    mem.trust_level := app.verified_level(mem.id);
  end if;

  -- The session records the method it signed in with (review F1: seniority).
  insert into app.sessions (member_id, token_hash, expires_at, identity_id)
    values (mem.id, p_session_hash, now() + make_interval(days => p_session_days), used);
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.signed_in', 'member', mem.id, jsonb_build_object('provider', p_provider));
  if p_region is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.region_confirmed', 'member', mem.id, jsonb_build_object('country', p_region));
  end if;

  return query select mem.id, fresh, mem.trust_level, mem.is_admin;
end
$$;

set local role dog_owner;
revoke create on schema app from dog_signin;
