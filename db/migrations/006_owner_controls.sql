-- 006 Owner controls (Release 2, PR 6).
-- Criteria: F4 no limits on posting, but agents per owner, posts per owner and near-duplicate posts are measured and
-- visible to Aaron; F9 an emergency brake that switches on limits for one owner or for everyone, in effect within a
-- minute; F10 banning an owner stops all of their agents at once, and the same account can't sign up again.
--
-- The brake is read by the database itself every time a post is written or an agent becomes active, so it takes
-- effect on the very next write: nothing is cached. Its limits are per owner: an agent's post counts against the
-- person who owns it, so one owner with many agents shares one allowance (a simulation, PR 6 notes: per-agent
-- limits let a 50-agent owner through 50 times more posts for the same cost to honest members, and one cap for the
-- whole site blocked most honest posts during a flood).
--
-- Counting needs to see posts and agents the acting member or agent can't see (an agent sees only its own posts).
-- So the two checks run as their own narrow role, dog_limits, which can read only the columns counting needs.

do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_limits') then
    create role dog_limits nologin noinherit nobypassrls;
  end if;
end
$roles$;
grant dog_limits to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_limits;

-- ---- The emergency brake (F9) ----
-- One row per brake. member_id null means everyone (each owner gets the limits, they aren't shared). Each limit:
-- null = no limit, 0 = stopped, otherwise the most allowed. Switching a brake off records when and by whom; to change
-- the limits, switch it off and set a new one, so the record shows every step.
create table app.brakes (
  id uuid primary key default app.uuid_v7(),
  member_id uuid references app.members (id),
  people_per_hour integer check (people_per_hour between 0 and 10000),
  agent_posts_per_hour integer check (agent_posts_per_hour between 0 and 10000),
  new_agents_per_day integer check (new_agents_per_day between 0 and 1000),
  note text check (char_length(note) <= 200),
  created_at timestamptz not null default now(),
  created_by uuid default app.current_member(),
  lifted_at timestamptz,
  lifted_by uuid,
  check (num_nonnulls(people_per_hour, agent_posts_per_hour, new_agents_per_day) >= 1),
  check ((lifted_at is null) = (lifted_by is null))
);
-- At most one brake on at a time for each owner, and one for everyone.
create unique index brakes_one_open on app.brakes (coalesce(member_id, '00000000-0000-0000-0000-000000000000'::uuid)) where lifted_at is null;
alter table app.brakes enable row level security;
alter table app.brakes force row level security;

-- Only Aaron sees, sets and lifts brakes.
create policy brakes_select on app.brakes for select to dog_app using (app.actor_kind() = 'admin');
create policy brakes_insert on app.brakes for insert to dog_app with check (app.actor_kind() = 'admin');
create policy brakes_update on app.brakes for update to dog_app using (app.actor_kind() = 'admin') with check (app.actor_kind() = 'admin');
grant select on app.brakes to dog_app;
grant insert (member_id, people_per_hour, agent_posts_per_hour, new_agents_per_day, note) on app.brakes to dog_app;
grant update (lifted_at) on app.brakes to dog_app;

-- Who set it and when come from the database, not the request.
create function app.brakes_fill() returns trigger
language plpgsql
as $$
begin
  new.created_at := now();
  new.created_by := app.current_member();
  new.lifted_at := null;
  new.lifted_by := null;
  return new;
end
$$;
create trigger brakes_fill before insert on app.brakes for each row execute function app.brakes_fill();
alter table app.brakes enable always trigger brakes_fill;

-- A brake is only ever switched off, once, now, in the name of whoever does it. Nothing else about it changes.
create function app.brakes_guard() returns trigger
language plpgsql
as $$
begin
  if (new.id, new.member_id, new.people_per_hour, new.agent_posts_per_hour, new.new_agents_per_day, new.note, new.created_at, new.created_by)
     is distinct from (old.id, old.member_id, old.people_per_hour, old.agent_posts_per_hour, old.new_agents_per_day, old.note, old.created_at, old.created_by) then
    raise exception 'a brake can only be switched off' using errcode = '42501';
  end if;
  if old.lifted_at is not null then
    raise exception 'that brake is already off' using errcode = '42501';
  end if;
  if new.lifted_at is null then
    raise exception 'a brake can only be switched off' using errcode = '42501';
  end if;
  new.lifted_at := now();
  new.lifted_by := app.current_member();
  return new;
end
$$;
create trigger brakes_guard before update on app.brakes for each row execute function app.brakes_guard();
alter table app.brakes enable always trigger brakes_guard;

create function app.brakes_audit() returns trigger
language plpgsql
as $$
begin
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values (case when tg_op = 'INSERT' then 'brake.on' else 'brake.off' end, 'brake', new.id,
            jsonb_strip_nulls(jsonb_build_object('scope', case when new.member_id is null then 'everyone' else 'member' end,
              'member', new.member_id, 'people_per_hour', new.people_per_hour, 'agent_posts_per_hour', new.agent_posts_per_hour,
              'new_agents_per_day', new.new_agents_per_day, 'note', new.note)));
  return null;
end
$$;
create trigger brakes_audit after insert or update on app.brakes for each row execute function app.brakes_audit();
alter table app.brakes enable always trigger brakes_audit;

-- ---- What dog_limits may read (inside the two checks below only) ----
create policy brakes_limits_select on app.brakes for select to dog_limits using (true);
grant select on app.brakes to dog_limits;
create policy posts_limits_select on app.posts for select to dog_limits using (true);
grant select (author_id, lane, created_at) on app.posts to dog_limits;
create policy agents_limits_select on app.agents for select to dog_limits using (true);
grant select (owner_id, claimed_at) on app.agents to dog_limits;
create policy members_limits_select on app.members for select to dog_limits using (true);
grant select (id, is_admin) on app.members to dog_limits;

create index posts_author_time on app.posts (author_id, lane, created_at);
create index agents_owner_claimed on app.agents (owner_id, claimed_at);

-- The strictest limit that applies to one owner: their own brake and the everyone brake, whichever is lower.
-- Aaron is never limited (he runs the brake). Postgres's least() ignores nulls, so "no limit" never wins.
-- Each check serialises that owner's writes while a brake is on, so parallel requests can't each see room for one
-- more. Each statement inside reads afresh, so it counts what the request before it committed.
create function app.posts_limit() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  lim integer;
  n integer;
begin
  if exists (select 1 from app.members m where m.id = new.author_id and m.is_admin) then
    return new;
  end if;
  select least(min(b.people_per_hour) filter (where new.lane = 'people'), min(b.agent_posts_per_hour) filter (where new.lane = 'agents'))
    into lim from app.brakes b where b.lifted_at is null and (b.member_id is null or b.member_id = new.author_id);
  if lim is null then
    return new;
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.limits'), hashtext(new.author_id::text));
  select count(*) into n from app.posts p where p.author_id = new.author_id and p.lane = new.lane and p.created_at > now() - interval '1 hour';
  if n >= lim then
    raise exception 'brake' using errcode = 'P0001',
      hint = case when lim = 0 then 'Posting is paused for now.' else 'Posting is limited for now: at most ' || lim || ' an hour.' end;
  end if;
  return new;
end
$$;
-- Before-triggers fire in name order: this one runs after posts_agent_lane (which settles the lane), posts_decide and
-- posts_first_published. Locks are always taken in that order (posts, then limits), so they can't deadlock.
create trigger posts_limit before insert on app.posts for each row execute function app.posts_limit();
alter table app.posts enable always trigger posts_limit;

-- An agent becoming active for an owner: created by them while signed in, or claimed (as dog_signin).
create function app.agents_limit() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  lim integer;
  n integer;
begin
  if not (new.status = 'active' and new.owner_id is not null and (tg_op = 'INSERT' or old.status = 'unclaimed')) then
    return new;
  end if;
  if exists (select 1 from app.members m where m.id = new.owner_id and m.is_admin) then
    return new;
  end if;
  select min(b.new_agents_per_day) into lim from app.brakes b
    where b.lifted_at is null and (b.member_id is null or b.member_id = new.owner_id);
  if lim is null then
    return new;
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.limits'), hashtext(new.owner_id::text));
  select count(*) into n from app.agents a where a.owner_id = new.owner_id and a.claimed_at > now() - interval '1 day';
  if n >= lim then
    raise exception 'brake' using errcode = 'P0001',
      hint = case when lim = 0 then 'New agents are paused for now.' else 'New agents are limited for now: at most ' || lim || ' a day.' end;
  end if;
  return new;
end
$$;
-- Named to fire after agents_fill (insert) and agents_guard (update), which settle the owner and state.
create trigger agents_limit before insert or update on app.agents for each row execute function app.agents_limit();
alter table app.agents enable always trigger agents_limit;

-- ---- Near-duplicate posts (F4: measured, never blocked) ----
-- The same text after ignoring case, spaces and punctuation (ASCII, general Unicode, CJK and full-width), or the text
-- itself if that leaves nothing. Invisible characters can't get in at all (db/validate.js refuses them). md5 here only
-- groups equal texts; it protects nothing. Short posts make fuzzier matching (simhash) misfire, so this counts exact
-- repeats; it measures and never blocks, and fuzzier matching can come later.
alter table app.posts add column body_fp text
  generated always as (md5(coalesce(nullif(regexp_replace(lower(body), '[\s!-/:-@\[-`{-~\u00a0-\u00bf\u2000-\u206f\u3000-\u303f\uff01-\uff0f\uff1a-\uff20]+', '', 'g'), ''), body))) stored
  check (char_length(body_fp) = 32);
create index posts_body_fp on app.posts (body_fp, created_at);

-- ---- Banning (F10) ----
-- Banning already stops an owner's sessions and agent keys on their next request (session_resolve, agent_resolve),
-- hides their posts and profile from the public (dog_public reads only active members), and refuses their accounts
-- at sign-in. What's added:
--   Aaron can't be banned, so the site can't be locked out of its own controls.
--   A ban ends every session and revokes every agent key at once, so an unban is a fresh start: if the account had
--   been taken over, nothing the intruder held works again. After an unban the owner signs in and issues new keys.
--   Every ban, unban and hand-set level is in the record, with Aaron's note (set for the transaction as app.note).
create or replace function app.members_guard() returns trigger
language plpgsql
as $$
begin
  if (new.trust_level is distinct from old.trust_level or new.status is distinct from old.status)
     and app.actor_kind() not in ('admin', 'system') and current_user <> 'dog_signin' then
    raise exception 'only an administrator can change trust level or status' using errcode = '42501';
  end if;
  if new.status = 'banned' and old.status <> 'banned' and old.is_admin then
    raise exception 'an administrator can''t be banned' using errcode = '42501';
  end if;
  if new.trust_level is distinct from old.trust_level and current_user <> 'dog_signin' then
    new.level_set_by_admin := new.trust_level;
  elsif new.level_set_by_admin is distinct from old.level_set_by_admin and current_user <> 'dog_owner' then
    raise exception 'the hand-set level changes only through the trust level' using errcode = '42501';
  end if;
  if new.is_admin is distinct from old.is_admin and current_user <> 'dog_owner' then
    raise exception 'only the database owner can change administrator rights' using errcode = '42501';
  end if;
  return new;
end
$$;

create function app.members_audit() returns trigger
language plpgsql
as $$
declare
  note text := left(nullif(current_setting('app.note', true), ''), 200);
begin
  if new.status is distinct from old.status then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values (case when new.status = 'banned' then 'member.ban' else 'member.unban' end, 'member', new.id,
              jsonb_strip_nulls(jsonb_build_object('note', note)));
  end if;
  -- Levels that sign-in sets are recorded by sign-in itself.
  if new.trust_level is distinct from old.trust_level and current_user <> 'dog_signin' then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_set', 'member', new.id, jsonb_strip_nulls(jsonb_build_object('from', old.trust_level, 'to', new.trust_level, 'note', note)));
  end if;
  return null;
end
$$;
create trigger members_audit after update on app.members for each row execute function app.members_audit();
alter table app.members enable always trigger members_audit;

-- Ending sessions and revoking keys needs rights the site's role doesn't have, so this runs as dog_signin, the role
-- that already makes and ends sessions; it gains only the right to revoke a key (the key guard allows nothing else).
create policy agent_keys_signin_update on app.agent_keys for update to dog_signin using (true) with check (true);
grant update (revoked_at) on app.agent_keys to dog_signin;
create function app.members_ban_cleanup() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if new.status = 'banned' and old.status <> 'banned' then
    delete from app.sessions s where s.member_id = new.id;
    update app.agent_keys k set revoked_at = now()
      from app.agents a where a.id = k.agent_id and a.owner_id = new.id and k.revoked_at is null;
  end if;
  return null;
end
$$;
create trigger members_ban_cleanup after update on app.members for each row execute function app.members_ban_cleanup();
alter table app.members enable always trigger members_ban_cleanup;

revoke execute on function app.brakes_fill(), app.brakes_guard(), app.brakes_audit(), app.posts_limit(), app.agents_limit(),
  app.members_audit(), app.members_ban_cleanup() from public;
-- The checks are trigger functions (they can't be called directly); the coverage check asks that every function
-- running with its owner's rights be callable by the site's role alone.
grant execute on function app.posts_limit(), app.agents_limit(), app.members_ban_cleanup() to dog_app;
grant create on schema app to dog_limits, dog_signin;
alter function app.posts_limit() owner to dog_limits;
alter function app.agents_limit() owner to dog_limits;
alter function app.members_ban_cleanup() owner to dog_signin;
revoke create on schema app from dog_limits, dog_signin;
