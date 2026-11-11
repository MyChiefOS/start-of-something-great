-- 060 The legal hold (RK22), linked bans, and the daily summary (Aaron's checks of Nov 10, 2026: part 8 of the
--   one large PR; decided Oct 16 and on the list "after fix 10" since Oct 25).
-- 1. A legal hold (CHARTER.md section 2, Oct 16: "A legal hold (for example a suspected crime) can keep and hide an
--    account instead of deleting it"). An administrator places a hold on an account, with a reason only
--    administrators read. While it is open nothing erases the account: the one function that deletes a member
--    (app.erase_member) refuses, whoever asks. If the member asks to be deleted, the account is disabled (hidden,
--    signed out, its agents stopped; nothing deleted) and the request is recorded on the hold; lifting the hold then
--    deletes the account. The site stores no email address for a member, so there is none to delete or keep.
-- 2. Linked bans. A ban on the site now reaches the same person's posts on GitHub: the JEVs gate asks whether the
--    poster's fingerprint (the keyed hash the gate already makes for sign-in codes) belongs to a banned member
--    (app.gh_site_banned). A ban on GitHub (moderation/bans.json, changed only by a merged pull request) reaches the
--    site: the gate hands the list's fingerprints to app.gh_bans_apply, which bans the members they belong to and
--    unbans the ones it banned that are no longer listed. It never touches an administrator, and never ends a ban an
--    administrator made on the site. Each one alerts the administrators.
-- 3. One in-app summary a day for the administrators (app.daily_summary): counts from the last 24 hours and what is
--    waiting. Run from the site's timer route like the other daily alerts; it sends at most one a UTC day.

set local role dog_owner;

-- ---- 1. The legal hold ----
create table app.legal_holds (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id),
  -- Why, in the administrator's words. Read only by administrators (through app.legal_holds_list).
  reason text not null check (char_length(reason) between 10 and 500),
  placed_by uuid not null,
  placed_at timestamptz not null default now(),
  -- When the member asked to be deleted while the hold was open (app.delete_account). Lifting the hold then deletes.
  deletion_requested_at timestamptz,
  lifted_at timestamptz,
  lifted_by uuid,
  lift_reason text check (char_length(lift_reason) between 10 and 500),
  check ((lifted_at is null) = (lifted_by is null) and (lifted_at is null) = (lift_reason is null))
);
-- One open hold for an account.
create unique index legal_holds_open on app.legal_holds (member_id) where lifted_at is null;
alter table app.legal_holds enable row level security;
alter table app.legal_holds force row level security;
create policy legal_holds_owner on app.legal_holds for all to dog_owner using (true) with check (true);
-- The deletion role alone works with holds, inside the functions below; the site's role has no right on the table.
create policy legal_holds_erase on app.legal_holds for all to dog_erase using (true) with check (true);
grant select, insert, update, delete on app.legal_holds to dog_erase;
-- JEVs's role counts open holds for the daily summary: whether one is open and whether deletion was asked, no more.
create policy legal_holds_jevs_select on app.legal_holds for select to dog_jevs using (true);
grant select (id, lifted_at, deletion_requested_at) on app.legal_holds to dog_jevs;

-- The one function that deletes a member, with the hold's check. Same as 011 otherwise. It runs with its caller's
-- rights (dog_erase).
create or replace function app.erase_member(p_member uuid)
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql
as $$
declare
  me uuid := p_member;
  n_posts integer; n_flags integer; n_my_reports integer; n_agents integer; n_keys integer; n_sessions integer; n_ids integer; n_brakes integer;
  n_drafts integer; n_jevs integer; n_reviews integer; n_notices integer;
begin
  if me is null then
    raise exception 'not_active' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  perform 1 from app.identities i where i.member_id = me for update;
  perform 1 from app.members m where m.id = me and not m.is_admin for update;
  if not found then
    raise exception 'not_active' using errcode = '42501';
  end if;
  -- 060: a legal hold keeps the account. Nothing is erased while one is open, whoever asks.
  if exists (select 1 from app.legal_holds h where h.member_id = me and h.lifted_at is null) then
    raise exception 'legal_hold' using errcode = 'P0001';
  end if;
  perform 1 from app.posts p where p.author_id = me for update;
  delete from app.deletion_reviews r where r.member_id = me;
  get diagnostics n_reviews = row_count;
  delete from app.jevs_challenges c where c.owner_id = me;
  delete from app.jevs_decisions d where d.member_id = me or d.agent_id in (select a.id from app.agents a where a.owner_id = me);
  get diagnostics n_jevs = row_count;
  delete from app.jevs_marks k where k.member_id = me or k.agent_id in (select a.id from app.agents a where a.owner_id = me);
  delete from app.jevs_prints r where r.author_id = me;
  delete from app.jevs_post_domains d where d.post_id in (select p.id from app.posts p where p.author_id = me);
  delete from app.review_flags f where f.post_id in (select p.id from app.posts p where p.author_id = me);
  get diagnostics n_flags = row_count;
  delete from app.review_flags f where f.reporter_id = me;
  get diagnostics n_my_reports = row_count;
  delete from app.posts p where p.author_id = me;
  get diagnostics n_posts = row_count;
  -- PR 13: the member's notices (and the alerts to Aaron about them) and containments.
  delete from app.notices x where x.member_id = me or (x.member_id is null and x.subject_kind = 'member' and x.subject_id = me);
  get diagnostics n_notices = row_count;
  delete from app.containments c where c.member_id = me;
  delete from app.agent_drafts d where d.owner_id = me;
  get diagnostics n_drafts = row_count;
  delete from app.agent_rules r where r.agent_id in (select a.id from app.agents a where a.owner_id = me);
  delete from app.agent_keys k where k.agent_id in (select a.id from app.agents a where a.owner_id = me);
  get diagnostics n_keys = row_count;
  delete from app.agents a where a.owner_id = me;
  get diagnostics n_agents = row_count;
  delete from app.brakes b where b.member_id = me;
  get diagnostics n_brakes = row_count;
  delete from app.admin_notes x where x.member_id = me;
  delete from app.sessions s where s.member_id = me;
  get diagnostics n_sessions = row_count;
  delete from app.identities i where i.member_id = me;
  get diagnostics n_ids = row_count;
  -- 060: the member's lifted holds go with the account.
  delete from app.legal_holds h where h.member_id = me;
  delete from app.members m where m.id = me;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.deleted', 'member', me, jsonb_build_object('posts', n_posts, 'reports_on_posts', n_flags, 'reports_made', n_my_reports,
            'agents', n_agents, 'keys', n_keys, 'drafts', n_drafts, 'brakes', n_brakes, 'sessions', n_sessions, 'identities', n_ids,
            'jevs_decisions', n_jevs, 'deletion_reviews', n_reviews, 'notices', n_notices));
  return query select n_posts, n_my_reports, n_agents, n_keys, n_sessions, n_ids;
end
$$;

grant create on schema app to dog_erase;
set local role dog_erase;

-- A member deletes their own account. Same as 010 otherwise.
create or replace function app.delete_account()
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
begin
  if app.actor_kind() <> 'member' or me is null then
    raise exception 'not_member' using errcode = '42501';
  end if;
  if coalesce(current_setting('app.fresh', true), '') <> '1' then
    raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to delete your account.';
  end if;
  if exists (select 1 from app.deletion_reviews r where r.member_id = me and (r.decision is null or r.decision = 'keep_disabled')) then
    raise exception 'under_review' using errcode = 'P0001';
  end if;
  perform 1 from app.members m where m.id = me and m.status = 'active' and not m.is_admin;
  if not found then
    raise exception 'not_active' using errcode = '42501';
  end if;
  -- 060: under a legal hold the account is kept and hidden instead of deleted (Aaron, Oct 16, 2026). The request is
  -- recorded on the hold, so lifting the hold deletes the account then. The answer is a row of nulls: nothing was
  -- deleted (db/account.js tells the member so).
  if exists (select 1 from app.legal_holds h where h.member_id = me and h.lifted_at is null) then
    update app.legal_holds h set deletion_requested_at = coalesce(h.deletion_requested_at, now()) where h.member_id = me and h.lifted_at is null;
    update app.members m set status = 'disabled' where m.id = me and m.status = 'active';
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('legal_hold.deletion_deferred', 'member', me, '{}'::jsonb);
    return query select null::integer, null::integer, null::integer, null::integer, null::integer, null::integer;
    return;
  end if;
  return query select * from app.erase_member(me);
end
$$;

-- An administrator places a hold. Refusals: not_admin (42501), bad request (22023), not_found (P0002), admin (an
-- administrator's account is never held), stale (a hold is already open). Returns the hold's ID.
create function app.legal_hold_place(p_member uuid, p_reason text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  admin boolean;
  hid uuid;
begin
  if app.actor_kind() <> 'admin' then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  if p_member is null or p_reason is null or char_length(btrim(p_reason)) not between 10 and 500 then
    raise exception 'bad legal hold request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(p_member::text));
  select m.is_admin into admin from app.members m where m.id = p_member for update;
  if not found then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  if admin then
    raise exception 'admin' using errcode = 'P0001';
  end if;
  if exists (select 1 from app.legal_holds h where h.member_id = p_member and h.lifted_at is null) then
    raise exception 'stale' using errcode = 'P0001';
  end if;
  insert into app.legal_holds (member_id, reason, placed_by) values (p_member, btrim(p_reason), app.current_member()) returning id into hid;
  -- The audit log names the hold, never its reason.
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('legal_hold.placed', 'member', p_member, jsonb_build_object('hold', hid));
  return hid;
end
$$;

-- An administrator lifts a hold, with a reason. If the member asked to be deleted while it was open, the account is
-- deleted now. Returns 'lifted' or 'lifted_deleted'. Refusals: not_admin, bad request, not_found, stale (already lifted).
create function app.legal_hold_lift(p_hold uuid, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  h app.legal_holds%rowtype;
begin
  if app.actor_kind() <> 'admin' then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  if p_hold is null or p_reason is null or char_length(btrim(p_reason)) not between 10 and 500 then
    raise exception 'bad legal hold request' using errcode = '22023';
  end if;
  select * into h from app.legal_holds x where x.id = p_hold for update;
  if not found then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  if h.lifted_at is not null then
    raise exception 'stale' using errcode = 'P0001';
  end if;
  update app.legal_holds x set lifted_at = now(), lifted_by = app.current_member(), lift_reason = btrim(p_reason) where x.id = h.id;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('legal_hold.lifted', 'member', h.member_id, jsonb_build_object('hold', h.id, 'deletion_requested', h.deletion_requested_at is not null));
  if h.deletion_requested_at is not null then
    perform app.erase_member(h.member_id);
    return 'lifted_deleted';
  end if;
  return 'lifted';
end
$$;

-- The open holds, for administrators: whose, why, since when, and whether the member has asked to be deleted. The
-- member's name is read by the site as the administrator (db/controls.js): the deletion role can't read names.
create function app.legal_holds_list()
returns table (id uuid, member_id uuid, reason text, placed_at timestamptz, deletion_requested_at timestamptz)
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() <> 'admin' then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  return query
    select h.id, h.member_id, h.reason, h.placed_at, h.deletion_requested_at
      from app.legal_holds h
     where h.lifted_at is null order by h.placed_at;
end
$$;
revoke execute on function app.legal_hold_place(uuid, text), app.legal_hold_lift(uuid, text), app.legal_holds_list() from public;
grant execute on function app.legal_hold_place(uuid, text), app.legal_hold_lift(uuid, text), app.legal_holds_list() to dog_app;

set local role dog_owner;
revoke create on schema app from dog_erase;

-- ---- 2. Linked bans ----
-- Who banned: null for a ban an administrator made on the site, 'github' for one carried from moderation/bans.json.
alter table app.members add column banned_via text check (banned_via = 'github') check (char_length(banned_via) <= 10);
alter table app.members add constraint members_banned_via_shape check (banned_via is null or status = 'banned');
grant select (banned_via), update (status, banned_via) on app.members to dog_jevs;
-- The gate matches a GitHub account to a member by the fingerprint sign-in stored, the same keyed hash it already
-- makes when a sign-in code is claimed (023). It reads the fingerprint only inside the two functions below.
grant select (fingerprint) on app.identities to dog_jevs;
-- An administrator sees which bans came from GitHub, and may make one a site ban (which then ends only on the site).
grant select (banned_via), update (banned_via) on app.members to dog_app;

-- The guard on a member's level and status, with the ban link. Same as 010 otherwise.
create or replace function app.members_guard() returns trigger
language plpgsql
as $$
begin
  if (new.trust_level is distinct from old.trust_level or new.status is distinct from old.status)
     and app.actor_kind() not in ('admin', 'system') and current_user not in ('dog_signin', 'dog_jevs')
     -- 060: the deletion role closes a held account when its owner asks to delete it (app.delete_account). It
     -- changes a status only, and only between active and disabled (the check on 'disabled' below).
     and not (current_user = 'dog_erase' and new.trust_level is not distinct from old.trust_level) then
    raise exception 'only an administrator can change trust level or status' using errcode = '42501';
  end if;
  if new.trust_level > old.trust_level and current_user not in ('dog_signin', 'dog_jevs') then
    raise exception 'levels go up only through a verified sign-in or JEVs, never by hand' using errcode = '42501';
  end if;
  -- 060: JEVs's role also carries a ban made on GitHub to the site and back (app.gh_bans_apply): active to banned
  -- marked 'github', and banned marked 'github' to active. Nothing else about a status.
  if current_user = 'dog_jevs' and new.status is distinct from old.status
     and not coalesce((old.status = 'active' and new.status = 'banned' and new.banned_via is not distinct from 'github')
              or (old.status = 'banned' and old.banned_via is not distinct from 'github' and new.status = 'active' and new.banned_via is null), false) then
    raise exception 'JEVs changes a status only to carry a GitHub ban' using errcode = '42501';
  end if;
  if current_user = 'dog_jevs' and new.trust_level is distinct from old.trust_level and new.trust_level <> 2 then
    raise exception 'JEVs only promotes to level 2' using errcode = '42501';
  end if;
  if current_user <> 'dog_jevs' then
    -- A ban made on GitHub ends on GitHub (moderation/bans.json), or an administrator first makes it a site ban.
    if old.status = 'banned' and old.banned_via = 'github' and new.status = 'active' and new.banned_via = 'github' then
      raise exception 'banned on GitHub' using errcode = '42501';
    end if;
    if new.banned_via is not null and new.banned_via is distinct from old.banned_via then
      raise exception 'only the ban link records a GitHub ban' using errcode = '42501';
    end if;
    -- Making a GitHub ban a site ban (clearing the mark) is an administrator's alone.
    if new.banned_via is distinct from old.banned_via and new.status = old.status and app.actor_kind() <> 'admin' then
      raise exception 'only an administrator makes a GitHub ban a site ban' using errcode = '42501';
    end if;
    if new.status is distinct from old.status then
      new.banned_via := null;
    end if;
  end if;
  if new.status = 'banned' and old.status <> 'banned' and old.is_admin then
    raise exception 'an administrator can''t be banned' using errcode = '42501';
  end if;
  -- Disabling an account and restoring it belong to a deletion review alone (dog_erase, below), and only between
  -- active and disabled. Aaron is never disabled.
  if new.status is distinct from old.status and (current_user = 'dog_erase' or 'disabled' in (new.status, old.status)) then
    if current_user <> 'dog_erase' or not ((old.status = 'active' and new.status = 'disabled') or (old.status = 'disabled' and new.status = 'active')) then
      raise exception 'only a deletion review disables or restores an account' using errcode = '42501';
    end if;
    if old.is_admin then
      raise exception 'an administrator can''t be disabled' using errcode = '42501';
    end if;
  end if;
  if new.trust_level is distinct from old.trust_level and current_user not in ('dog_signin', 'dog_jevs') then
    new.level_set_by_admin := new.trust_level;
  elsif new.level_set_by_admin is distinct from old.level_set_by_admin and current_user <> 'dog_owner' then
    raise exception 'the hand-set level changes only through the trust level' using errcode = '42501';
  end if;
  if new.jevs_level2_at is distinct from old.jevs_level2_at and current_user <> 'dog_jevs' then
    raise exception 'only JEVs records its own promotion' using errcode = '42501';
  end if;
  if new.is_admin is distinct from old.is_admin and current_user <> 'dog_owner' then
    raise exception 'only the database owner can change administrator rights' using errcode = '42501';
  end if;
  return new;
end
$$;

grant create on schema app to dog_jevs;
set local role dog_jevs;

-- Is this GitHub account's owner banned on the site? The gate gives the poster's fingerprint and, for a machine
-- account, the fingerprint of the account it is linked to: at most 4 are looked at.
create function app.gh_site_banned(p_fps text[])
returns boolean
language sql stable security definer set search_path = pg_catalog
as $$
  select exists (select 1 from app.identities i join app.members m on m.id = i.member_id
                  where i.provider = 'github' and i.fingerprint = any (p_fps[1:4]) and m.status = 'banned')
$$;

-- Carries the GitHub ban list to the site: p_fps are the fingerprints of every account on moderation/bans.json, as
-- the gate made them from the list on main. Members they belong to are banned (never an administrator); members
-- this function banned earlier who are no longer listed are unbanned. A ban an administrator made on the site is
-- never ended here. Each change is in the audit log and alerts the administrators. Returns the two counts.
create function app.gh_bans_apply(p_fps text[])
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r record;
  n_ban integer := 0;
  n_unban integer := 0;
begin
  if p_fps is null or coalesce(array_length(p_fps, 1), 0) > 10000
     or exists (select 1 from unnest(p_fps) f where f is null or f !~ '^[0-9a-f]{64}$') then
    raise exception 'bad ban list' using errcode = '22023';
  end if;
  for r in select m.id from app.members m
            where m.status = 'active' and not m.is_admin
              and exists (select 1 from app.identities i where i.member_id = m.id and i.provider = 'github' and i.fingerprint = any (p_fps))
            order by m.id for update of m loop
    update app.members m set status = 'banned', banned_via = 'github' where m.id = r.id;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.ban_linked', 'member', r.id, jsonb_build_object('source', 'github'));
    perform app.notify(null, 'alert', 'A member banned on GitHub is now banned on the site',
      'Their GitHub account is on the ban list (moderation/bans.json), so their sessions have ended, their agents'' keys are revoked and their posts are hidden. '
      || 'Taking the account off the list unbans them here.',
      '/admin/controls', 'member', r.id, 'banlink:on:' || r.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
    n_ban := n_ban + 1;
  end loop;
  for r in select m.id from app.members m
            where m.status = 'banned' and m.banned_via = 'github'
              and not exists (select 1 from app.identities i where i.member_id = m.id and i.provider = 'github' and i.fingerprint = any (p_fps))
            order by m.id for update of m loop
    update app.members m set status = 'active', banned_via = null where m.id = r.id;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.unban_linked', 'member', r.id, jsonb_build_object('source', 'github'));
    perform app.notify(null, 'alert', 'A member is unbanned: their GitHub account is off the ban list',
      'The ban list (moderation/bans.json) no longer has their GitHub account, and that list was the only reason they were banned here. They can sign in again and give their agents new keys.',
      '/admin/controls', 'member', r.id, 'banlink:off:' || r.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
    n_unban := n_unban + 1;
  end loop;
  return jsonb_build_object('banned', n_ban, 'unbanned', n_unban);
end
$$;
revoke execute on function app.gh_site_banned(text[]), app.gh_bans_apply(text[]) from public;

-- ---- 3. The daily summary ----
set local role dog_owner;
create table app.summary_state (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  last_day date
);
alter table app.summary_state enable row level security;
alter table app.summary_state force row level security;
create policy summary_state_owner on app.summary_state for all to dog_owner using (true) with check (true);
create policy summary_state_jevs on app.summary_state for all to dog_jevs using (true) with check (true);
grant select, update on app.summary_state to dog_jevs;
-- The summary counts posts and replies apart (059).
grant select (parent_id) on app.posts to dog_jevs;
insert into app.summary_state default values;
set local role dog_jevs;

-- One in-app notice a day to the administrators: what happened in the last 24 hours and what is waiting. Counts
-- only: no names, no text. At most one a UTC day; called from the site's timer route every minute, where every call
-- but the day's first returns at once. It changes nothing else and blocks nothing.
create function app.daily_summary()
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  today date := (now() at time zone 'UTC')::date;
  since timestamptz := now() - interval '24 hours';
  n_members integer; n_agents integer; n_posts integer; n_replies integer;
  n_site integer; n_site_high integer; n_site_medium integer;
  n_gh integer; n_gh_hidden integer;
  n_waiting integer; n_reviews integer; n_holds integer; n_holds_asked integer; n_linked integer;
begin
  if (select st.last_day = today from app.summary_state st where st.singleton) then
    return null;
  end if;
  update app.summary_state st set last_day = today where st.singleton and st.last_day is distinct from today;
  if not found then
    return null;
  end if;
  select count(*) into n_members from app.members m where m.created_at > since;
  select count(*) into n_agents from app.agents a where a.created_at > since;
  select count(*) filter (where p.parent_id is null), count(*) filter (where p.parent_id is not null) into n_posts, n_replies
    from app.posts p where p.created_at > since;
  select count(*), count(*) filter (where d.level = 'high'), count(*) filter (where d.level = 'medium')
    into n_site, n_site_high, n_site_medium from app.jevs_decisions d where d.created_at > since;
  select count(*), count(*) filter (where d.effect = 'hide') into n_gh, n_gh_hidden from app.gh_decisions d where d.at > since;
  select count(*) into n_waiting from app.posts p where p.status = 'waiting';
  select count(*) into n_reviews from app.deletion_reviews r where r.decision is null;
  select count(*), count(*) filter (where h.deletion_requested_at is not null) into n_holds, n_holds_asked from app.legal_holds h where h.lifted_at is null;
  select count(*) into n_linked from app.members m where m.status = 'banned' and m.banned_via = 'github';
  perform app.notify(null, 'alert', 'Daily summary, ' || to_char(today, 'FMMonth FMDD, YYYY'),
    'In the last 24 hours: ' || n_members || ' new members, ' || n_agents || ' new agents, ' || n_posts || ' posts and ' || n_replies || ' replies. '
    || 'Checks on the site: ' || n_site || ' decisions, ' || n_site_high || ' high risk and ' || n_site_medium || ' medium. '
    || 'Checks on GitHub: ' || n_gh || ' decisions, ' || n_gh_hidden || ' posts hidden. '
    || 'Waiting now: ' || n_waiting || ' posts for review, ' || n_reviews || ' deletion reviews, ' || n_holds || ' legal holds ('
    || n_holds_asked || ' with a deletion asked for). Bans carried from GitHub: ' || n_linked || '.',
    '/admin/controls', null, null, 'daily:' || to_char(today, 'YYYY-MM-DD'));
  return true;
end
$$;
revoke execute on function app.daily_summary() from public;
grant execute on function app.daily_summary() to dog_app;

set local role dog_owner;
revoke create on schema app from dog_jevs;
