-- 079 The agent track (Aaron, Nov 24): a parallel path for agents that mirrors the one people take, so an agent works
--   fully from its first call, claimed before, during, after or never ("I want a solo agent to come to the site and be
--   able to work fully"; "I don't want blockers for the agent and subagent"). Levels move with behavior, quickly
--   ("Agent should move up based on behavior ... Moving up should be quick"), with the numbers Aaron approved:
--     level 1 on registering; 2 after 3 clean passes; 3 after 10; 4 after 25 with none overturned in 72 hours.
--     A clear violation drops one level at once and its progress restarts at that level's start.
--   How: a registering agent gets its own account, marked kind 'agent' (not a person). It owns the agent, so every
--   existing rule that asks "which account acts" works unchanged, and it is never shown or counted as a person.
--   Agent accounts skip what is only for people (identity levels, the deletion deadline, draft mode and its 90-day
--   clock). A person may claim the agent at any time with its claim link; the link no longer runs out, and the
--   24-hour clearing of unclaimed agents ends. On an agent account's own tree, a daily or hourly limit alerts the
--   administrators and lets the work go on (Aaron, Oct 23: checks alert, never lock out). Depth, lifetime and "never
--   more than its parent" stay as they are: they are the tree's shape, not a limit on work.

set local role dog_owner;
alter table app.members add column kind text not null default 'person' check (kind = any (array['person', 'agent']));
alter table app.agents add column self_owned boolean not null default false;
alter table app.agents drop constraint agents_check1, drop constraint agents_check2;
alter table app.agents add constraint agents_claim_code check ((claim_hash is not null) = (status = 'unclaimed' or (self_owned and status = 'active')));
alter table app.agents add constraint agents_claim_expiry check (claim_expires_at is null or claim_hash is not null);
alter table app.agents add constraint agents_self_owned_root check (not self_owned or parent_id is null);

-- Each agent account's standing: its level and its progress toward the next.
create table app.agent_standing (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null unique references app.members (id) on delete cascade,
  level smallint not null default 1 check (level between 1 and 4),
  clean_passes integer not null default 0 check (clean_passes between 0 and 100000000),
  violations integer not null default 0 check (violations between 0 and 100000000),
  last_violation_at timestamptz,
  updated_at timestamptz not null default now()
);
alter table app.agent_standing enable row level security;
alter table app.agent_standing force row level security;
create policy agent_standing_read on app.agent_standing for select to dog_app, dog_public, dog_work, dog_signin using (true);
create policy agent_standing_signin_insert on app.agent_standing for insert to dog_signin with check (true);
create policy agent_standing_signin_update on app.agent_standing for update to dog_signin using (true) with check (true);
grant select on app.agent_standing to dog_app, dog_public, dog_work, dog_signin;
grant insert, update on app.agent_standing to dog_signin;

grant select (kind) on app.members to dog_signin, dog_public, dog_work, dog_jevs, dog_limits, dog_delegate, dog_erase, dog_pay;
grant insert (kind) on app.members to dog_signin;
grant select (self_owned) on app.agents to dog_signin, dog_work, dog_public, dog_delegate, dog_jevs, dog_limits, dog_erase;
grant insert (self_owned, owner_id, status) on app.agents to dog_signin;
grant update (self_owned) on app.agents to dog_signin;

-- 005 and 014's rule for the sign-in role, and 079's third case: an agent account may own exactly one agent, the one it
-- was made for, as an active, self-owned root.
drop policy agents_signin_insert on app.agents;
create policy agents_signin_insert on app.agents for insert to dog_signin with check (
  (status = 'unclaimed' and owner_id is null and parent_id is null and not self_owned)
  or (status = 'active' and parent_id is not null and (select app.actor_kind()) = 'agent'
      and parent_id = (select app.current_agent()) and owner_id = (select app.current_member()) and not self_owned)
  or (status = 'active' and self_owned and parent_id is null
      and exists (select 1 from app.members m where m.id = owner_id and m.kind = 'agent')
      and not exists (select 1 from app.agents x where x.owner_id = agents.owner_id)));

-- Is this an agent's own account (not a person's)?
create function app.is_agent_account(p_member uuid) returns boolean
language sql stable set search_path = pg_catalog
as $$ select coalesce((select m.kind = 'agent' from app.members m where m.id = p_member), false) $$;
revoke execute on function app.is_agent_account(uuid) from public;
grant execute on function app.is_agent_account(uuid) to dog_app, dog_signin, dog_work, dog_public, dog_jevs, dog_delegate, dog_limits, dog_erase, dog_pay, dog_timers;

-- A limit reached on an agent account's tree: one alert a day per agent and limit, and the work goes on.
create function app.agent_limit_alert(p_agent uuid, p_what text) returns void
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  perform app.notify(null, 'alert', 'Agent track: an agent passed a limit and kept working',
    'Agent ' || p_agent::text || ' ' || left(p_what, 300) || '. Agents with no owner aren''t stopped by limits; this alert is for the reviewers (079).',
    null, 'agent', p_agent, 'agentlimit:' || p_agent::text || ':' || md5(p_what) || ':' || to_char(now(), 'YYYY-MM-DD'));
end
$$;
revoke execute on function app.agent_limit_alert(uuid, text) from public;
grant execute on function app.agent_limit_alert(uuid, text) to dog_app, dog_signin, dog_work, dog_jevs;
reset role;

grant create on schema app to dog_signin;
set local role dog_signin;
CREATE OR REPLACE FUNCTION app.agent_register(p_name text, p_description text, p_key_hash text, p_claim_hash text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  aid uuid;
  mid uuid;
begin
  if app.actor_kind() <> 'anon' or p_name is null or char_length(p_name) not between 1 and 80
     or char_length(p_description) > 500 or p_key_hash !~ '^[0-9a-f]{64}$' or p_claim_hash !~ '^[0-9a-f]{64}$'
     or p_key_hash is null or p_claim_hash is null or p_key_hash = p_claim_hash then
    raise exception 'bad agent registration' using errcode = '22023';
  end if;
  -- 079: the agent gets its own account and works at once; its claim link lasts until a person uses it. Nothing is
  -- cleared after a day any more.
  insert into app.members (display_name, trust_level, kind) values (p_name, 1, 'agent') returning id into mid;
  insert into app.agent_standing (member_id) values (mid);
  insert into app.agents (name, description, claim_hash, owner_id, status, self_owned)
    values (p_name, nullif(p_description, ''), p_claim_hash, mid, 'active', true) returning id into aid;
  insert into app.agent_keys (agent_id, key_hash) values (aid, p_key_hash);
  return aid;
end
$function$;
CREATE OR REPLACE FUNCTION app.agent_resolve(p_key_hash text)
 RETURNS TABLE(agent_id uuid, owner_id uuid)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query
    select a.id, m.id
    from app.agent_keys k join app.agents a on a.id = k.agent_id join app.members m on m.id = a.owner_id
    where k.key_hash = p_key_hash and k.revoked_at is null and a.status = 'active' and (a.expires_at is null or a.expires_at > now())
      and m.status = 'active'
      -- 079: an agent's own account needs no person's identity level and has no deletion deadline.
      and (m.kind = 'agent' or ((app.verified_level(m.id) >= 2 or m.is_admin) and not app.deletion_overdue(m.id)))
      and not exists (
        with recursive up (id, lvl) as (
          select a.parent_id, 1 where a.parent_id is not null
          union all
          select p.parent_id, up.lvl + 1 from app.agents p join up on p.id = up.id where p.parent_id is not null and up.lvl < 11)
        select 1 from up join app.agents x on x.id = up.id where x.status <> 'active' or (x.expires_at is not null and x.expires_at <= now()));
end
$function$;
CREATE OR REPLACE FUNCTION app.agent_claim(p_claim_hash text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  aid uuid;
  prev uuid;
begin
  if app.actor_kind() not in ('member', 'admin') or p_claim_hash is null or p_claim_hash !~ '^[0-9a-f]{64}$' then
    return null;
  end if;
  if not exists (select 1 from app.members m where m.id = app.current_member() and m.status = 'active' and (m.trust_level >= 2 or m.is_admin)) then
    raise exception 'level_required' using errcode = 'P0001';
  end if;
  update app.agents a set owner_id = app.current_member(), status = 'active', claimed_at = now(), claim_hash = null, claim_expires_at = null
    where a.claim_hash = p_claim_hash and a.status = 'unclaimed' and a.claim_expires_at > now()
    returning a.id into aid;
  -- 079: an agent working on its own account is claimed at any time; its sub-agents come with it. Its record stays
  -- with its account (the agent's history), which keeps its standing.
  if aid is null then
    select a.id, a.owner_id into aid, prev from app.agents a
      where a.claim_hash = p_claim_hash and a.self_owned and a.status = 'active' for update;
    if aid is not null then
      update app.agents a set owner_id = app.current_member() where a.owner_id = prev and a.id <> aid;
      update app.agents a set owner_id = app.current_member(), self_owned = false, claimed_at = now(), claim_hash = null
        where a.id = aid;
    end if;
  end if;
  return aid;
end
$function$;
CREATE OR REPLACE FUNCTION app.agent_claim_preview(p_claim_hash text)
 RETURNS TABLE(id uuid, name text, description text, created_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
begin
  if app.actor_kind() not in ('member', 'admin') or p_claim_hash is null or p_claim_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query select a.id, a.name, a.description, a.created_at from app.agents a
    where a.claim_hash = p_claim_hash and ((a.status = 'unclaimed' and a.claim_expires_at > now()) or (a.self_owned and a.status = 'active'));
end
$function$;
-- One pass or one violation for an agent account. Levels: 1, then 2 at 3 clean passes, 3 at 10, 4 at 25 with no
-- violation in 72 hours. A violation drops one level now, and progress restarts at that level's start.
create function app.agent_standing_event(p_member uuid, p_event text) returns smallint
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  lvl smallint;
  start constant integer[] := array[0, 3, 10, 25];
begin
  if p_member is null or not app.is_agent_account(p_member) or p_event not in ('pass', 'violation') then
    return null;
  end if;
  insert into app.agent_standing (member_id) values (p_member) on conflict (member_id) do nothing;
  select * into s from app.agent_standing x where x.member_id = p_member for update;
  if p_event = 'pass' then
    lvl := case when s.clean_passes + 1 >= 25 and (s.last_violation_at is null or s.last_violation_at < now() - interval '72 hours') then 4
                when s.clean_passes + 1 >= 10 then 3 when s.clean_passes + 1 >= 3 then 2 else 1 end;
    lvl := greatest(lvl, s.level);
    update app.agent_standing x set clean_passes = s.clean_passes + 1, level = lvl, updated_at = now() where x.member_id = p_member;
  else
    lvl := greatest(1, s.level - 1);
    update app.agent_standing x set level = lvl, clean_passes = start[lvl], violations = s.violations + 1,
      last_violation_at = now(), updated_at = now() where x.member_id = p_member;
  end if;
  -- The account's level, in the scale everything else reads (0 to 3).
  update app.members m set trust_level = least(lvl, 3) where m.id = p_member and m.trust_level is distinct from least(lvl, 3);
  return lvl;
end
$$;

-- What changes an agent account's standing: a pass, a pass overturned, and a Wall hold that's enforced.
create function app.agent_standing_from_work() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if new.worker_member is not null and new.status is distinct from old.status then
    if new.status = 'passed' then perform app.agent_standing_event(new.worker_member, 'pass');
    elsif new.status = 'reversed' and old.status = 'passed' then perform app.agent_standing_event(new.worker_member, 'violation');
    end if;
  end if;
  return null;
end
$$;
create function app.agent_standing_from_wall() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if new.member_id is not null and new.decision = 'hold' and new.mode = 'enforce' then
    perform app.agent_standing_event(new.member_id, 'violation');
  end if;
  return null;
end
$$;
reset role;
revoke create on schema app from dog_signin;

revoke execute on function app.agent_standing_event(uuid, text) from public;
revoke execute on function app.agent_standing_from_work() from public;
revoke execute on function app.agent_standing_from_wall() from public;
create trigger work_submissions_agent_standing after update on app.work_submissions
  for each row execute function app.agent_standing_from_work();
create trigger wall_decisions_agent_standing after insert on app.wall_decisions
  for each row execute function app.agent_standing_from_wall();

grant create on schema app to dog_owner;
set local role dog_owner;
CREATE OR REPLACE FUNCTION app.verified_level(p_member uuid)
 RETURNS smallint
 LANGUAGE sql
 STABLE
AS $function$
  select case when app.is_agent_account(p_member) then (select least(s.level, 3) from app.agent_standing s where s.member_id = p_member)::smallint else (case when exists (select 1 from app.identities i where i.member_id = p_member and i.provider = 'buyer') then least(x.v, 1) else x.v end)::smallint end
  from (select coalesce((select m.level_set_by_admin from app.members m where m.id = p_member),
    greatest(
      (select coalesce(max(case when i.recheck_after is not null and i.recheck_after <= now() then least(i.level, 1) else i.level end), 0)
       from app.identities i where i.member_id = p_member),
      (select case when m.jevs_level2_at is not null then 2 else 0 end from app.members m where m.id = p_member))) as v) x
$function$;
CREATE OR REPLACE FUNCTION app.agents_fill()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
declare
  p_id uuid; p_owner uuid; p_status text; p_depth smallint; p_root uuid; p_expires timestamptz;
  s_depth smallint; s_ttl integer;
begin
  if current_user = 'dog_signin' and app.actor_kind() = 'agent' then
    select a.id, a.owner_id, a.status, a.depth, a.root_id, a.expires_at into p_id, p_owner, p_status, p_depth, p_root, p_expires
      from app.agents a where a.id = app.current_agent();
    if p_id is null or p_status <> 'active' or p_owner is distinct from app.current_member()
       or (p_expires is not null and p_expires <= now()) then
      raise exception 'parent_not_active' using errcode = '42501';
    end if;
    select s.max_depth, s.max_ttl_hours into s_depth, s_ttl from app.subagent_settings s;
    if p_depth + 1 > s_depth then
      raise exception 'depth' using errcode = 'P0001';
    end if;
    if new.expires_at is null or new.expires_at <= now() or new.expires_at > now() + make_interval(hours => s_ttl)
       or (p_expires is not null and new.expires_at > p_expires) then
      raise exception 'ttl' using errcode = 'P0001';
    end if;
    new.owner_id := p_owner;
    new.parent_id := p_id;
    new.depth := p_depth + 1;
    new.root_id := coalesce(p_root, p_id);
    new.status := 'active';
    new.claimed_at := now();
    new.claim_hash := null;
    new.claim_expires_at := null;
  elsif current_user = 'dog_signin' and new.self_owned then
    -- 079: an agent registering on its own account (the policy checks the account is an agent's and new).
    new.status := 'active';
    new.claimed_at := null;
    new.claim_expires_at := null;
    new.parent_id := null;
    new.depth := 0;
    new.root_id := null;
    new.expires_at := null;
  elsif current_user = 'dog_signin' then
    new.self_owned := false;
    new.owner_id := null;
    new.status := 'unclaimed';
    new.claimed_at := null;
    new.parent_id := null;
    new.depth := 0;
    new.root_id := null;
    new.expires_at := null;
  elsif app.actor_kind() in ('member', 'admin') then
    new.self_owned := false;
    new.owner_id := app.current_member();
    new.status := 'active';
    new.claimed_at := now();
    new.claim_hash := null;
    new.claim_expires_at := null;
    new.parent_id := null;
    new.depth := 0;
    new.root_id := null;
    new.expires_at := null;
  else
    raise exception 'only a signed-in owner creates an agent here' using errcode = '42501';
  end if;
  new.created_at := now();
  return new;
end
$function$;
CREATE OR REPLACE FUNCTION app.agents_guard()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin
  if (new.id, new.parent_id, new.depth, new.root_id, new.expires_at, new.created_at)
     is distinct from (old.id, old.parent_id, old.depth, old.root_id, old.expires_at, old.created_at) then
    raise exception 'an agent''s place in its tree never changes' using errcode = '42501';
  end if;
  if current_user = 'dog_signin' then
    -- 079: claiming an agent that worked on its own account: the person becomes the owner of it and its sub-agents.
    if old.status = 'active' and app.is_agent_account(old.owner_id) and new.owner_id = app.current_member()
       and app.actor_kind() in ('member', 'admin') and (new.name, new.description, new.status) is not distinct from (old.name, old.description, old.status)
       and ((old.self_owned and not new.self_owned and new.claim_hash is null) or (not old.self_owned and new.self_owned = old.self_owned)) then
      return new;
    end if;
    if new.self_owned is distinct from old.self_owned then
      raise exception 'only a claim ends an agent''s own account' using errcode = '42501';
    end if;
    if old.status = 'unclaimed' then
      if not (new.status = 'active' and new.owner_id is not null) or (new.name, new.description) is distinct from (old.name, old.description) then
        raise exception 'a claim only gives an unclaimed agent its owner' using errcode = '42501';
      end if;
      return new;
    end if;
    if (new.owner_id, new.name, new.description, new.claimed_at, new.claim_hash, new.claim_expires_at)
       is distinct from (old.owner_id, old.name, old.description, old.claimed_at, old.claim_hash, old.claim_expires_at)
       or old.status <> 'active' or old.parent_id is null
       or not ((new.status = 'revoked' and exists (select 1 from app.agents p where p.id = old.parent_id and p.status <> 'active'))
               or (new.status = 'expired' and old.expires_at <= now())
               or (new.status = 'revoked' and app.actor_kind() in ('member', 'admin') and old.owner_id = app.current_member())
               -- 040: or its parent's keys stopped in this same transaction (a recovery, app.agent_recover): the
               -- sub-agents its old key made stop with that key, as they do when the owner makes a new key.
               or (new.status = 'revoked' and exists (select 1 from app.agent_keys k where k.agent_id = old.parent_id and k.revoked_at = now()))) then
      raise exception 'a sub-agent stops only with its parent or when its time is up' using errcode = '42501';
    end if;
    return new;
  end if;
  if (new.owner_id, new.claimed_at, new.claim_hash, new.claim_expires_at, new.self_owned)
     is distinct from (old.owner_id, old.claimed_at, old.claim_hash, old.claim_expires_at, old.self_owned) then
    raise exception 'an agent''s owner and history can''t be changed' using errcode = '42501';
  end if;
  if app.actor_kind() = 'agent'
     and ((new.name, new.description) is distinct from (old.name, old.description) or new.status is not distinct from old.status) then
    raise exception 'an agent can only revoke its own sub-agents' using errcode = '42501';
  end if;
  if new.status is distinct from old.status and not (old.status = 'active' and new.status = 'revoked') then
    raise exception 'an agent can only go from active to revoked' using errcode = '42501';
  end if;
  return new;
end
$function$;
CREATE OR REPLACE FUNCTION app.agent_rules_fill()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
declare
  prev app.agent_rules%rowtype;
  before app.agent_rules%rowtype;
  par app.agent_rules%rowtype;
  ow uuid;
  par_id uuid;
  rank_of constant jsonb := '{"off": 0, "draft": 1, "act": 2}';
begin
  -- Which agent this is, and the agent above it (013). One owner's rules change one version at a time, so a parent
  -- and its sub-agents can't pass each other (a parent lowered while a sub-agent is raised).
  select a.owner_id, a.parent_id into ow, par_id from app.agents a where a.id = new.agent_id;
  if not found then
    raise exception 'this agent has no rules yet' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.ruletree'), hashtext(coalesce(ow, new.agent_id)::text));
  perform pg_advisory_xact_lock(hashtext('dayonegreat.rules'), hashtext(new.agent_id::text));
  if par_id is not null then
    select r.post_mode, r.reply_mode, r.report_mode, r.daily_cap into par.post_mode, par.reply_mode, par.report_mode, par.daily_cap
      from app.agent_rules r where r.agent_id = par_id order by r.version desc limit 1;
    if par.post_mode is null then
      raise exception 'this agent''s parent has no rules' using errcode = '42501';
    end if;
  end if;
  -- Only the columns the sign-in role may read too (it writes first rules on a claim and lowered ones on a ban).
  select r.id, r.version, r.post_mode, r.reply_mode, r.report_mode, r.daily_cap
    into prev.id, prev.version, prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap
    from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  new.version := coalesce(prev.version, 0) + 1;
  new.created_at := now();
  new.set_by := case when new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment', 'containment_lifted',
                                         'signin_unlinked', 'parent_lowered') then 'system'
                     when new.reason = 'created' and par_id is not null then 'agent' else 'owner' end;
  -- PR 15: who set it and whether it restarts the clock come from the database, never from the request. A first
  -- version (an owner's all-drafts, or a sub-agent's from its parent) restarts nothing; the system's versions are
  -- nobody's session.
  new.by_identity := null;
  new.restarts_clock := false;
  if new.set_by = 'owner' and new.reason <> 'created' then
    new.by_identity := app.current_identity();
    new.restarts_clock := coalesce(current_setting('app.fresh', true), '') = '1';
  end if;
  if new.reason = 'created' then
    if prev.id is not null then
      raise exception 'an agent''s first rules are set once' using errcode = '42501';
    end if;
    if par_id is not null then
      -- A sub-agent's first rules (013): what app.subagent_create asked for, never above its parent's. No fresh
      -- sign-in is needed: nothing is allowed that its owner hadn't already allowed the agent above it.
      if current_user <> 'dog_signin' or new.post_mode is null or new.reply_mode is null or new.report_mode is null or new.daily_cap is null then
        raise exception 'a sub-agent''s first rules come from the agent that makes it' using errcode = '42501';
      end if;
      if (rank_of ->> new.post_mode)::int > (rank_of ->> par.post_mode)::int or (rank_of ->> new.reply_mode)::int > (rank_of ->> par.reply_mode)::int
         or (rank_of ->> new.report_mode)::int > (rank_of ->> par.report_mode)::int or new.daily_cap > par.daily_cap then
        raise exception 'above_parent' using errcode = 'P0001', hint = 'A sub-agent can''t be allowed more than the agent above it.';
      end if;
      return new;
    end if;
    -- 079: an agent on its own account has nobody to approve drafts, so it acts, with the highest daily figure; reaching
    -- it alerts and doesn't stop the agent (posts_delegation, work_cap).
    if app.is_agent_account(ow) then
      new.post_mode := 'act';
      new.reply_mode := 'act';
      new.report_mode := 'act';
      new.daily_cap := 1000;
      new.set_by := 'system';
      return new;
    end if;
    new.post_mode := 'draft';
    new.reply_mode := 'draft';
    new.report_mode := 'draft';
    new.daily_cap := coalesce(new.daily_cap, 20);
    return new;
  end if;
  if prev.id is null then
    raise exception 'this agent has no rules yet' using errcode = '42501';
  end if;
  if new.reason = 'parent_lowered' then
    -- Exactly the lower of its own rules and its parent's, per setting, and only ever lower (013).
    if par_id is null
       or (new.post_mode, new.reply_mode, new.report_mode, new.daily_cap) is distinct from
          (case when (rank_of ->> prev.post_mode)::int <= (rank_of ->> par.post_mode)::int then prev.post_mode else par.post_mode end,
           case when (rank_of ->> prev.reply_mode)::int <= (rank_of ->> par.reply_mode)::int then prev.reply_mode else par.reply_mode end,
           case when (rank_of ->> prev.report_mode)::int <= (rank_of ->> par.report_mode)::int then prev.report_mode else par.report_mode end,
           least(prev.daily_cap, par.daily_cap))
       or (new.post_mode, new.reply_mode, new.report_mode, new.daily_cap) is not distinct from (prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap) then
      raise exception 'a sub-agent is lowered only to match its parent' using errcode = '42501';
    end if;
    return new;
  end if;
  -- Attenuation (013): whoever writes them, and whatever the reason, a sub-agent's rules are never above its parent's.
  if par_id is not null and ((rank_of ->> new.post_mode)::int > (rank_of ->> par.post_mode)::int or (rank_of ->> new.reply_mode)::int > (rank_of ->> par.reply_mode)::int
         or (rank_of ->> new.report_mode)::int > (rank_of ->> par.report_mode)::int or new.daily_cap > par.daily_cap) then
    raise exception 'above_parent' using errcode = 'P0001', hint = 'A sub-agent can''t be allowed more than the agent above it.';
  end if;
  if new.reason = 'reconfirmed' then
    if (new.post_mode, new.reply_mode, new.report_mode, new.daily_cap) is distinct from (prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap)
       or 'act' <> all (array[prev.post_mode, prev.reply_mode, prev.report_mode]) then
      raise exception 'a confirmation keeps rules that act exactly as they are' using errcode = '42501';
    end if;
    -- PR 15: keeping an agent acting on its own for another 90 days needs a fresh sign-in.
    if coalesce(current_setting('app.fresh', true), '') <> '1' then
      raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to keep an agent acting on its own.';
    end if;
    return new;
  end if;
  if new.reason = 'containment_lifted' then
    -- Written only by the site or Aaron (as dog_app), which may read every column.
    select r.reason into prev.reason from app.agent_rules r where r.id = prev.id;
    select * into before from app.agent_rules r where r.agent_id = new.agent_id and r.version = prev.version - 1;
    if prev.reason is distinct from 'containment' or before.id is null
       or (new.post_mode, new.reply_mode, new.report_mode, new.daily_cap) is distinct from (before.post_mode, before.reply_mode, before.report_mode, before.daily_cap)
       or exists (select 1 from app.containments c join app.agents a on a.owner_id = c.member_id
                  where a.id = new.agent_id and c.lifted_at is null) then
      raise exception 'lifting a containment only restores the rules it replaced' using errcode = '42501';
    end if;
    return new;
  end if;
  if (rank_of ->> new.post_mode)::int > (rank_of ->> prev.post_mode)::int
     or (rank_of ->> new.reply_mode)::int > (rank_of ->> prev.reply_mode)::int
     or (rank_of ->> new.report_mode)::int > (rank_of ->> prev.report_mode)::int
     or new.daily_cap > prev.daily_cap then
    if new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment', 'signin_unlinked') then
      raise exception 'an upheld report, a ban, a disabled account, an expiry, a containment or an unlinked sign-in method can only lower an agent''s rules' using errcode = '42501';
    end if;
    -- While a containment is in force (until its time is up), the owner can't raise any agent's rules, existing or
    -- new: everything drafts for their approval until it ends. Lowering stays open (the notifications review,
    -- finding 1).
    if exists (select 1 from app.containments c join app.agents a on a.owner_id = c.member_id
               where a.id = new.agent_id and c.lifted_at is null and c.ends_at > now()) then
      raise exception 'contained' using errcode = 'P0001', hint = 'Your agents draft for your approval until the pause ends.';
    end if;
    if ((new.post_mode = 'act' and prev.post_mode <> 'act') or (new.reply_mode = 'act' and prev.reply_mode <> 'act')
        or (new.report_mode = 'act' and prev.report_mode <> 'act') or new.daily_cap > prev.daily_cap)
       and coalesce(current_setting('app.fresh', true), '') <> '1' then
      raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to let an agent do more without your approval.';
    end if;
  end if;
  return new;
end
$function$;
CREATE OR REPLACE FUNCTION app.posts_delegation()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
declare
  cur app.agent_rules%rowtype;
  mode text;
begin
  if current_user = 'dog_delegate' then
    return new;
  end if;
  if app.actor_kind() <> 'agent' then
    new.delegation := null;
    new.rules_version := null;
    new.draft_id := null;
    return new;
  end if;
  select * into cur from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  -- 059: a reply follows the owner's reply setting, a post the posting one.
  mode := case when new.parent_id is null then cur.post_mode else cur.reply_mode end;
  if cur.id is null or mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  if mode <> 'act' then
    raise exception 'agent_drafts' using errcode = 'P0001';
  end if;
  -- 027: the 90-day clock, even if the timers haven't run: the post waits for the owner as a draft.
  if app.act_clock_expired(new.agent_id) then
    raise exception 'agent_drafts' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.agentcap'), hashtext(new.agent_id::text));
  if app.agent_actions_today(new.agent_id) >= cur.daily_cap then
    if app.is_agent_account(app.current_member()) then
      perform app.agent_limit_alert(new.agent_id, 'passed its daily figure of ' || cur.daily_cap || ' posts and replies');
    else
      raise exception 'agent_cap' using errcode = 'P0001', hint = 'This agent has reached its daily limit of ' || cur.daily_cap || '.';
    end if;
  end if;
  new.delegation := 'rules';
  new.rules_version := cur.version;
  new.draft_id := null;
  return new;
end
$function$;
CREATE OR REPLACE FUNCTION app.agent_drafts_fill()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
declare
  cur app.agent_rules%rowtype;
  mode text;
begin
  if app.actor_kind() <> 'agent' then
    raise exception 'only an agent writes drafts' using errcode = '42501';
  end if;
  new.agent_id := app.current_agent();
  new.owner_id := app.current_member();
  new.action := case when new.parent_id is null then 'post' else 'reply' end;
  new.body_hash := encode(sha256(convert_to(new.body, 'UTF8')), 'hex');
  new.status := 'pending';
  new.created_at := now();
  new.expires_at := now() + interval '48 hours';
  new.decided_at := null;
  select * into cur from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  -- 059: a reply's draft follows the owner's reply setting.
  mode := case when new.action = 'reply' then cur.reply_mode else cur.post_mode end;
  if cur.id is null or mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  if mode <> 'draft' and not (mode = 'act' and app.act_clock_expired(new.agent_id)) then
    raise exception 'agent_acts' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.agentcap'), hashtext(new.agent_id::text));
  if app.agent_actions_today(new.agent_id) >= cur.daily_cap and not app.is_agent_account(app.current_member()) then
    raise exception 'agent_cap' using errcode = 'P0001', hint = 'This agent has reached its daily limit of ' || cur.daily_cap || '.';
  end if;
  new.rules_version := cur.version;
  return new;
end
$function$;
reset role;
revoke create on schema app from dog_owner;

grant create on schema app to dog_work;
set local role dog_work;
CREATE OR REPLACE FUNCTION app.work_cap(p_agent uuid, p_root uuid, p_kind text, p_new_claim boolean)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  x record;
  n integer;
  s record;
begin
  perform pg_advisory_xact_lock(hashtext('dayonegreat.workcap'), hashtext(p_root::text));
  select * into s from app.work_settings where singleton;
  for x in with recursive up (id, parent_id, lvl) as (
             select g.id, g.parent_id, 0 from app.agents g where g.id = p_agent
             union all
             select g.id, g.parent_id, up.lvl + 1 from app.agents g join up on g.id = up.parent_id where up.lvl < 11)
           select up.id, (select r.daily_cap from app.agent_rules r where r.agent_id = up.id order by r.version desc limit 1) as cap
           from up order by up.lvl loop
    with recursive down (id, lvl) as (
      select x.id, 0
      union all
      select g.id, down.lvl + 1 from app.agents g join down on g.parent_id = down.id where down.lvl < 11)
    select count(*) into n from app.work_actions w where w.agent_id in (select id from down) and w.created_at > now() - interval '1 day';
    if x.cap is not null and n >= x.cap and app.is_agent_account((select g.owner_id from app.agents g where g.id = p_agent)) then
      perform app.agent_limit_alert(p_agent, 'passed its tree''s daily figure of ' || x.cap || ' work actions');
    elsif x.cap is not null and n >= x.cap then
      raise exception 'work_cap' using errcode = 'P0001', hint = case when x.id = p_agent
        then 'This agent has reached its daily limit of ' || x.cap || ' work actions, which counts its sub-agents too.'
        else 'This agent''s tree has reached the daily limit of ' || x.cap || ' its owner set for the agent above it.' end;
    end if;
  end loop;
  if p_new_claim then
    select count(*) into n from app.work_claims c where c.tree_root = p_root and c.status = 'active';
    if n >= s.tree_active_claims and app.is_agent_account((select g.owner_id from app.agents g where g.id = p_agent)) then
      perform app.agent_limit_alert(p_agent, 'holds ' || n || ' live claims across its tree');
    elsif n >= s.tree_active_claims then
      raise exception 'work_cap' using errcode = 'P0001', hint = 'This agent''s tree already holds ' || n || ' live claims, the most one tree may hold.';
    end if;
  end if;
end
$function$;
CREATE OR REPLACE FUNCTION app.work_display(p_member uuid, p_agent uuid, p_github text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
  select case
    when p_github is not null then jsonb_build_object('kind', 'github', 'github', p_github,
      'name', coalesce((select n.name from app.work_github_names n where n.login = p_github), '@' || p_github))
    when p_agent is not null then (select jsonb_build_object('kind', 'agent', 'id', g.id, 'name', g.name,
                                     'owner', case when m.kind = 'agent' then null else jsonb_build_object('id', m.id, 'name', m.display_name) end)
                                   from app.agents g join app.members m on m.id = g.owner_id where g.id = p_agent)
    when p_member is not null then (select jsonb_build_object('kind', 'member', 'id', m.id, 'name', m.display_name) from app.members m where m.id = p_member)
  end
$function$;
reset role;
revoke create on schema app from dog_work;

grant create on schema app to dog_signin;
set local role dog_signin;
CREATE OR REPLACE FUNCTION app.subagent_create(p_name text, p_description text, p_key_hash text, p_post text, p_reply text, p_report text, p_daily_cap integer, p_ttl_hours integer, p_draft_only boolean, p_caller_key text)
 RETURNS TABLE(agent_id uuid, depth smallint, expires_at timestamp with time zone, rules_version integer, post_mode text, reply_mode text, report_mode text, daily_cap integer, chain jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  me uuid := app.current_member();
  par uuid := app.current_agent();
  s app.subagent_settings%rowtype;
  p_status text; p_depth smallint; p_expires timestamptz; p_owner uuid;
  r_post text; r_reply text; r_report text; r_cap integer;
  m_post text; m_reply text; m_report text; m_cap integer;
  rank_of constant jsonb := '{"off": 0, "draft": 1, "act": 2}';
  n integer;
  exp timestamptz;
  aid uuid;
  ver integer;
begin
  if app.actor_kind() <> 'agent' or me is null or par is null then
    raise exception 'not_agent' using errcode = '42501';
  end if;
  if p_name is null or char_length(p_name) not between 1 and 80 or char_length(p_description) > 500
     or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$'
     or (p_post is not null and p_post not in ('off', 'draft', 'act')) or (p_reply is not null and p_reply not in ('off', 'draft', 'act'))
     or (p_report is not null and p_report not in ('off', 'draft', 'act'))
     or (p_daily_cap is not null and p_daily_cap not between 1 and 1000) or (p_ttl_hours is not null and p_ttl_hours not between 1 and 720)
     or p_draft_only is null or p_caller_key is null or p_caller_key !~ '^[0-9a-f]{64}$' or p_caller_key = p_key_hash then
    raise exception 'bad sub-agent request' using errcode = '22023';
  end if;
  -- One owner's tree grows one sub-agent at a time, so the rates can't be raced.
  perform pg_advisory_xact_lock(hashtext('dayonegreat.subagents'), hashtext(me::text));
  -- The owner's row first, then the parent's, then the key's: the order a ban, a disabled account and deleting the
  -- account take them (member, then keys), and a new key (member, then keys), so none of them can deadlock with this
  -- (the re-review of PR 16, N1). The new agent's own owner check (app.agents_owner_active) then finds it held.
  perform 1 from app.members m where m.id = me for share;
  select * into s from app.subagent_settings limit 1;
  select a.status, a.depth, a.expires_at, a.owner_id into p_status, p_depth, p_expires, p_owner from app.agents a where a.id = par for share;
  perform 1 from app.agent_keys k where k.key_hash = p_caller_key and k.agent_id = par and k.revoked_at is null for share;
  if not found then
    raise exception 'parent_not_active' using errcode = '42501';
  end if;
  if p_status is distinct from 'active' or p_owner is distinct from me or (p_expires is not null and p_expires <= now())
     -- The owner's live verified level, as app.agent_resolve checks it (PR 15, RK58), never the level last stored.
     -- 079: an agent's own account needs no person's identity level and has no deletion deadline.
     or not exists (select 1 from app.members m where m.id = me and m.status = 'active'
                    and (m.kind = 'agent' or ((app.verified_level(m.id) >= 2 or m.is_admin) and not app.deletion_overdue(m.id)))) then
    raise exception 'parent_not_active' using errcode = '42501';
  end if;
  if p_depth + 1 > s.max_depth then
    raise exception 'depth' using errcode = 'P0001',
      hint = 'Sub-agents go at most ' || s.max_depth || ' levels below the agent their owner made, and this agent is already at level ' || p_depth || '.';
  end if;
  select count(*) into n from app.agents a where a.parent_id = par and a.created_at > now() - interval '1 hour';
  if n >= s.per_parent_per_hour and app.is_agent_account(me) then
    perform app.agent_limit_alert(par, 'made more than ' || s.per_parent_per_hour || ' sub-agents in an hour');
  elsif n >= s.per_parent_per_hour then
    raise exception 'rate_parent' using errcode = 'P0001', hint = 'One agent can make at most ' || s.per_parent_per_hour || ' sub-agents an hour.';
  end if;
  select count(*) into n from app.agents a where a.owner_id = me and a.parent_id is not null and a.created_at > now() - interval '1 hour';
  if n >= s.per_owner_per_hour and app.is_agent_account(me) then
    perform app.agent_limit_alert(par, 'its tree made more than ' || s.per_owner_per_hour || ' sub-agents in an hour');
  elsif n >= s.per_owner_per_hour then
    raise exception 'rate_owner' using errcode = 'P0001',
      hint = 'One owner''s agents can make at most ' || s.per_owner_per_hour || ' sub-agents an hour between them.';
  end if;
  if p_ttl_hours is not null and p_ttl_hours > s.max_ttl_hours then
    raise exception 'ttl' using errcode = 'P0001', hint = 'A sub-agent lasts at most ' || s.max_ttl_hours || ' hours.';
  end if;
  exp := now() + make_interval(hours => coalesce(p_ttl_hours, s.default_ttl_hours));
  if p_expires is not null and exp > p_expires then
    exp := p_expires;
  end if;

  -- Its rules: what it asks for, or draft (lower if its parent is lower); never above its parent's.
  select r.post_mode, r.reply_mode, r.report_mode, r.daily_cap into r_post, r_reply, r_report, r_cap
    from app.agent_rules r where r.agent_id = par order by r.version desc limit 1;
  if r_post is null then
    raise exception 'parent_not_active' using errcode = '42501';
  end if;
  m_post := coalesce(p_post, case when r_post = 'off' then 'off' else 'draft' end);
  m_reply := coalesce(p_reply, case when r_reply = 'off' then 'off' else 'draft' end);
  m_report := coalesce(p_report, case when r_report = 'off' then 'off' else 'draft' end);
  m_cap := coalesce(p_daily_cap, least(20, r_cap));
  -- 079: on an agent's own account nobody would approve a draft, so a sub-agent takes its parent's rules unless it asks
  -- for less.
  if app.is_agent_account(me) then
    m_post := coalesce(p_post, r_post);
    m_reply := coalesce(p_reply, r_reply);
    m_report := coalesce(p_report, r_report);
    m_cap := coalesce(p_daily_cap, r_cap);
  end if;
  if (rank_of ->> m_post)::int > (rank_of ->> r_post)::int or (rank_of ->> m_reply)::int > (rank_of ->> r_reply)::int
     or (rank_of ->> m_report)::int > (rank_of ->> r_report)::int or m_cap > r_cap then
    raise exception 'above_parent' using errcode = 'P0001',
      hint = 'A sub-agent can''t be allowed more than the agent making it: posting ' || r_post || ', replies ' || r_reply
             || ', reports ' || r_report || ', at most ' || r_cap || ' actions a day.';
  end if;
  if p_draft_only then
    m_post := case when m_post = 'act' then 'draft' else m_post end;
    m_reply := case when m_reply = 'act' then 'draft' else m_reply end;
    m_report := case when m_report = 'act' then 'draft' else m_report end;
  end if;
  -- 027 (the CSO's review, B1): past its tree's 90-day clock, a sub-agent is made drafting where it asked to act,
  -- never refused and never off (checks alert, never lock out).
  if app.act_clock_expired(par) then
    m_post := case when m_post = 'act' then 'draft' else m_post end;
    m_reply := case when m_reply = 'act' then 'draft' else m_reply end;
    m_report := case when m_report = 'act' then 'draft' else m_report end;
  end if;

  insert into app.agents (name, description, expires_at) values (p_name, nullif(p_description, ''), exp) returning id into aid;
  insert into app.agent_keys (agent_id, key_hash) values (aid, p_key_hash);
  insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
    values (aid, m_post, m_reply, m_report, m_cap, 'created') returning version into ver;
  return query select aid, (p_depth + 1)::smallint, exp, ver, m_post, m_reply, m_report, m_cap,
    (with recursive up (id, parent_id, lvl) as (
       select a.id, a.parent_id, 1 from app.agents a where a.id = par
       union all
       select a.id, a.parent_id, up.lvl + 1 from app.agents a join up on a.id = up.parent_id where up.lvl < 11)
     select jsonb_agg(up.id order by up.lvl) from up);
end
$function$;
reset role;
revoke create on schema app from dog_signin;

grant create on schema app to dog_jevs;
set local role dog_jevs;
CREATE OR REPLACE FUNCTION app.jevs_decide(p_action text, p_subject uuid, p_scores jsonb, p_impact text, p_error boolean, p_domains text[], p_simhash bigint, p_net text)
 RETURNS TABLE(decision_id uuid, level text, effect text, applied boolean, mode text, challenge_id uuid, challenge_status text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  kind text := app.actor_kind();
  s_mode text; s_medium_any integer; s_high_any integer; s_medium_total integer; s_high_total integer; s_pass integer;
  s_challenge integer;
  subj_kind text;
  judged uuid;
  agent uuid;
  v_post uuid; post_author uuid; post_agent uuid; post_status text; post_created timestamptz;
  mem_level smallint; mem_status text; mem_admin boolean; mem_hand smallint; mem_jevs timestamptz;
  total integer := 0;
  top integer := 0;
  ask integer := 0; -- 032
  lvl text;
  eff text;
  did uuid;
  cid uuid;
  cstatus text;
  rid uuid;
  questions text[];
  ok boolean;
begin
  if p_action is null or p_impact is null or p_impact not in ('low', 'high') or p_error is null or p_scores is null
     or jsonb_typeof(p_scores) <> 'object' or (select count(*) from jsonb_object_keys(p_scores)) > 20
     or exists (select 1 from jsonb_each(p_scores) e where e.key !~ '^J[0-9]{2}$' or jsonb_typeof(e.value) <> 'number'
                or (e.value)::numeric <> floor((e.value)::numeric) or (e.value)::numeric not between 0 and 100)
     or (p_domains is not null and (cardinality(p_domains) > 50 or exists (select 1 from unnest(p_domains) x where x is null or x !~ '^[0-9a-f]{64}$')))
     or (p_net is not null and p_net !~ '^[0-9a-f]{64}$') then
    raise exception 'bad JEVs request' using errcode = '22023';
  end if;

  -- What is being decided, and about whom. The subject must be the actor's own, made in this transaction where it is
  -- something new, so the site can't point JEVs at someone else's post or agent. A post is locked the way an ordinary
  -- update locks it (no key update), which doesn't wait on the key-share locks that reports on it hold, so members
  -- reporting the same post at once don't deadlock (found by the load test).
  case
    when p_action in ('post.create', 'post.approved') then
      select p.id, p.author_id, p.agent_id, p.status, p.created_at into v_post, post_author, post_agent, post_status, post_created
        from app.posts p where p.id = p_subject for no key update;
      if not found or post_author is distinct from me or post_created <> now()
         or (ag is not null and post_agent is distinct from ag) or kind not in ('member', 'admin', 'agent') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'post'; judged := me; agent := post_agent;
    when p_action = 'post.reported' then
      select p.id, p.author_id, p.agent_id, p.status, p.created_at into v_post, post_author, post_agent, post_status, post_created
        from app.posts p where p.id = p_subject for no key update;
      if not found or kind not in ('member', 'admin')
         or not exists (select 1 from app.review_flags f where f.post_id = p_subject and f.source = 'report' and f.reporter_id = me and f.resolved_at is null) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'post'; judged := post_author; agent := post_agent;
    when p_action = 'draft.create' then
      if kind <> 'agent' or not exists (select 1 from app.agent_drafts d where d.id = p_subject and d.agent_id = ag and d.created_at = now()) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'draft'; judged := me; agent := ag;
    when p_action in ('signup', 'account.check', 'account.delete', 'agent.create', 'agent.claim') then
      if kind not in ('member', 'admin') or (p_subject is not null and p_subject is distinct from me) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'member'; judged := me;
    when p_action in ('agent.key', 'agent.rules') then
      if kind not in ('member', 'admin')
         or not exists (select 1 from app.agents a where a.id = p_subject and a.owner_id = me and a.status = 'active') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; judged := me; agent := p_subject;
    when p_action = 'agent.subagent' then
      -- An agent making a sub-agent (013): about the acting agent, which must be the owner's and active.
      if kind <> 'agent' or p_subject is distinct from ag
         or not exists (select 1 from app.agents a where a.id = ag and a.owner_id = me and a.status = 'active') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; judged := me; agent := ag;
    when p_action = 'agent.register' then
      if kind <> 'anon' or p_subject is not null then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := null; judged := null;
    -- 040: a recovery key used for a new key: anyone holding it, signed in or not. About the agent it is for, which must
    -- be unclaimed or active, judged as its owner (if it has one).
    when p_action = 'agent.recover' then
      if kind <> 'anon' or p_subject is null
         or not exists (select 1 from app.agents a where a.id = p_subject and a.status in ('unclaimed', 'active')) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; agent := p_subject;
      select a.owner_id into judged from app.agents a where a.id = p_subject;
    -- 040: an agent setting or replacing its recovery key with its key: a claimed agent acting with its key, or (before
    -- its claim) anyone holding the key registration gave.
    when p_action = 'agent.recovery_issue' then
      if p_subject is null or kind not in ('agent', 'anon') or (kind = 'agent' and p_subject is distinct from ag)
         or not exists (select 1 from app.agents a where a.id = p_subject and a.status in ('unclaimed', 'active')
                        and (kind = 'agent') = (a.owner_id is not null)) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; agent := p_subject;
      select a.owner_id into judged from app.agents a where a.id = p_subject;
    else
      raise exception 'bad JEVs request' using errcode = '22023';
  end case;

  select max(case when s.key = 'mode' then s.value end),
         max(case when s.key = 'medium_any' then s.value end)::integer, max(case when s.key = 'high_any' then s.value end)::integer,
         max(case when s.key = 'medium_total' then s.value end)::integer, max(case when s.key = 'high_total' then s.value end)::integer,
         max(case when s.key = 'pass_max' then s.value end)::integer, max(case when s.key = 'challenge_hours' then s.value end)::integer
    into s_mode, s_medium_any, s_high_any, s_medium_total, s_high_total, s_pass, s_challenge
    from app.jevs_settings s;

  -- Sign-up and account checks can promote: the database works out their account questions itself (all but J13, the
  -- request's country), whatever the site sent.
  if p_action in ('signup', 'account.check') and not p_error then
    p_scores := (p_scores - array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10'])
                || app.jevs_account_scores(app.jevs_signals(p_action, null, p_net, null, null));
  end if;
  -- 032: J18 and J19 ask only. They are left out of the total and the top score, and on their own raise low to medium,
  -- never to high (below).
  select coalesce(sum((e.value)::integer), 0), coalesce(max((e.value)::integer), 0) into total, top from jsonb_each(p_scores) e
    where e.key not in ('J18', 'J19');
  select coalesce(max((e.value)::integer), 0) into ask from jsonb_each(p_scores) e where e.key in ('J18', 'J19');
  questions := array(select k from jsonb_object_keys(p_scores) k order by k);

  if p_error then
    lvl := case when p_impact = 'high' then 'high' else 'low' end;
  elsif top >= s_high_any or total >= s_high_total then
    lvl := 'high';
  elsif top >= s_medium_any or total >= s_medium_total or ask >= s_medium_any then
    lvl := 'medium';
  else
    lvl := 'low';
  end if;

  -- What each level means for each kind of action.
  if p_error then
    eff := case when p_impact = 'high' then 'hold' else 'none' end;
  elsif p_action = 'post.create' then
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  elsif p_action = 'post.approved' then
    -- The owner already confirmed these exact words; only high risk holds them.
    eff := case lvl when 'high' then 'hold' else 'none' end;
  elsif p_action = 'post.reported' then
    eff := case lvl when 'high' then 'hide' else 'none' end;
  elsif p_action = 'draft.create' then
    -- Every draft already waits for its owner.
    eff := 'none';
  elsif p_action in ('agent.register', 'agent.recover', 'agent.recovery_issue') then
    -- The owner's claim is the human check; only high risk holds a registration. 040: the same for a recovery and for a
    -- recovery key set or replaced, whose owner is told each time.
    eff := case lvl when 'high' then 'hold' else 'none' end;
  elsif p_action in ('signup', 'account.check') then
    eff := 'none';
    if lvl = 'high' then
      eff := 'queue';
    elsif lvl = 'low' then
      -- Automatic level 2, with no wait (Aaron, Oct 16, 2026): every standard account question was asked, and every
      -- one but the account's age (J01) passed. J01 still counts towards the level above.
      select x.trust_level, x.status, x.is_admin, x.level_set_by_admin, x.jevs_level2_at
        into mem_level, mem_status, mem_admin, mem_hand, mem_jevs from app.members x where x.id = judged;
      ok := p_scores ?& array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10', 'J13']
            and (select coalesce(max((e.value)::integer), 0) from jsonb_each(p_scores) e where e.key <> 'J01') <= s_pass
            and mem_status = 'active' and not mem_admin and mem_level < 2 and mem_hand is null and mem_jevs is null;
      if ok then
        eff := 'promote';
      end if;
    end if;
  elsif p_action = 'agent.subagent' then
    -- A sub-agent needs no human step to be made (Aaron, Oct 16, 2026). Medium makes it with every action drafting, so
    -- each thing it does waits for its human owner (never an agent); high holds it for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'draft' else 'none' end;
  else
    -- Sensitive actions: medium asks the owner to confirm by signing in again; high holds the action for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  end if;

  -- 079: an agent on its own account has no owner to confirm or approve, so a challenge or a "draft" alerts the
  -- reviewers and the action goes ahead. High risk still holds, as for everyone.
  if judged is not null and eff in ('challenge', 'draft') and app.is_agent_account(judged) then
    perform app.agent_limit_alert(coalesce(agent, judged), 'met a JEVs ' || eff || ' on ' || p_action || ' (' || lvl || ' risk), which went ahead with no owner to ask');
    eff := 'none';
  end if;
  -- Aaron is never held or challenged: he runs the controls, as the brake never limits him (006).
  if judged is not null and exists (select 1 from app.members x where x.id = judged and x.is_admin) then
    eff := 'none';
  end if;

  -- Shadow mode carries out nothing that stops anyone. Promotion and Aaron's list never stop anyone, so they apply in
  -- both modes.
  insert into app.jevs_decisions (action, subject_kind, subject_id, member_id, agent_id, level, mode, effect, applied, error, total, scores)
    values (p_action, subj_kind, coalesce(p_subject, judged), judged, agent, lvl, s_mode, eff,
            eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), p_error, least(total, 10000), p_scores)
    returning id into did;

  if eff in ('promote', 'queue') or (eff <> 'none' and s_mode = 'enforce') then
    if subj_kind = 'post' and eff in ('challenge', 'hold') and post_status = 'live' then
      update app.posts p set status = 'waiting' where p.id = v_post;
    elsif subj_kind = 'post' and eff = 'hide' and post_status in ('live', 'waiting') then
      update app.posts p set status = 'removed' where p.id = v_post;
    end if;
    if subj_kind = 'post' and eff in ('hold', 'hide')
       and not exists (select 1 from app.review_flags f where f.post_id = v_post and f.source = 'classifier' and f.classifier = 'jevs' and f.resolved_at is null) then
      insert into app.review_flags (post_id, source, classifier, score) values (v_post, 'classifier', 'jevs', least(total, 100) / 100.0);
    end if;
    if eff = 'challenge' then
      -- A sensitive action is confirmed by a fresh sign-in (the site marks the transaction); a post waits for its owner.
      cstatus := case when subj_kind <> 'post' and coalesce(current_setting('app.fresh', true), '') = '1' then 'confirmed' else 'pending' end;
      insert into app.jevs_challenges (decision_id, owner_id, action, subject_kind, subject_id, status, expires_at, decided_at)
        values (did, judged, p_action, subj_kind, coalesce(p_subject, judged), cstatus, now() + make_interval(hours => s_challenge),
                case when cstatus = 'confirmed' then now() end)
        returning id into cid;
      -- A fresh sign-in that confirms this action also answers the owner's earlier requests to confirm the same action,
      -- so nothing is left waiting for an answer that has already been given.
      if cstatus = 'confirmed' then
        update app.jevs_challenges c set status = 'confirmed'
          where c.owner_id = judged and c.action = p_action and c.subject_id is not distinct from coalesce(p_subject, judged)
            and c.status = 'pending' and c.id <> cid;
      end if;
    end if;
    -- A held account deletion goes to Aaron as a deletion review (Oct 16, 2026): nothing is deleted, the member is told,
    -- and the account is disabled (never deleted) if he hasn't decided within 24 hours. Only from a fresh sign-in, so
    -- a stolen session cookie can't start the clock on someone else's account; one open review per member.
    if p_action = 'account.delete' and eff = 'hold' and coalesce(current_setting('app.fresh', true), '') = '1'
       and not exists (select 1 from app.deletion_reviews r where r.member_id = judged and (r.decision is null or r.decision = 'keep_disabled')) then
      insert into app.deletion_reviews (member_id, decision_id) values (judged, did) returning id into rid;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('deletion_review.opened', 'member', judged, jsonb_build_object('review', rid, 'decision', did, 'error', p_error));
    end if;
    if eff = 'promote' then
      update app.members x set jevs_level2_at = now(), trust_level = 2 where x.id = judged;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('member.level_changed', 'member', judged, jsonb_build_object('reason', 'jevs', 'from', mem_level, 'to', 2,
                'decision', did, 'questions', to_jsonb(questions)));
    elsif subj_kind is distinct from 'post' and eff in ('hold', 'challenge', 'queue', 'draft') then
      -- The effect only: which questions scored stay in the decision row, deleted with the account (the JEVs review, F10).
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('jevs.' || eff, coalesce(subj_kind, 'member'), coalesce(p_subject, judged), jsonb_build_object('action', p_action, 'decision', did, 'level', lvl));
    end if;
  end if;

  -- What later posts are compared with: every post's text print, and the link domains of low-risk posts.
  if subj_kind = 'post' and p_action <> 'post.reported' then
    if p_simhash is not null then
      insert into app.jevs_prints (post_id, author_id, simhash) values (v_post, post_author, p_simhash) on conflict (post_id) do nothing;
    end if;
    if lvl = 'low' and not p_error and p_domains is not null then
      insert into app.jevs_post_domains (post_id, domain_hash) select v_post, x from unnest(p_domains) x on conflict do nothing;
    end if;
  end if;

  return query select did, lvl, eff, eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), s_mode, cid, cstatus;
end
$function$;
CREATE OR REPLACE FUNCTION app.jevs_mark(p_kind text, p_key_hash text, p_token text, p_agent uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  kind text := app.actor_kind();
begin
  if p_kind is null or p_kind not in ('net', 'email_domain', 'disposable') or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$'
     or (p_token is not null and p_token !~ '^[0-9a-f]{64}$') or (p_token is not null and p_agent is not null) then
    raise exception 'bad JEVs mark' using errcode = '22023';
  end if;
  if p_agent is not null then
    if kind <> 'anon' or not exists (select 1 from app.agents a where a.id = p_agent and (a.status = 'unclaimed' or (a.self_owned and a.status = 'active')) and a.created_at > now() - interval '10 minutes') then
      raise exception 'bad JEVs mark' using errcode = '22023';
    end if;
    insert into app.jevs_marks (agent_id, kind, key_hash)
      select p_agent, p_kind, p_key_hash where not exists (select 1 from app.jevs_marks k where k.agent_id = p_agent and k.kind = p_kind);
  elsif p_token is not null then
    if kind <> 'anon' or (select count(*) from app.jevs_marks k where k.token_hash = p_token) >= 3 then
      raise exception 'bad JEVs mark' using errcode = '22023';
    end if;
    insert into app.jevs_marks (token_hash, kind, key_hash) values (p_token, p_kind, p_key_hash);
  else
    if kind not in ('member', 'admin') then
      raise exception 'bad JEVs mark' using errcode = '22023';
    end if;
    insert into app.jevs_marks (member_id, kind, key_hash)
      select app.current_member(), p_kind, p_key_hash
      where not exists (select 1 from app.jevs_marks k where k.member_id = app.current_member() and k.kind = p_kind and k.key_hash = p_key_hash);
  end if;
end
$function$;
reset role;
revoke create on schema app from dog_jevs;

grant create on schema app to dog_owner;
set local role dog_owner;
CREATE OR REPLACE FUNCTION app.agents_audit()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin
  if tg_op = 'INSERT' then
    if new.parent_id is not null then
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('agent.subagent', 'agent', new.id, jsonb_build_object('owner', new.owner_id, 'parent', new.parent_id, 'depth', new.depth,
                'root', new.root_id, 'expires_at', new.expires_at));
    else
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values (case when new.status = 'unclaimed' or new.self_owned then 'agent.register' else 'agent.create' end, 'agent', new.id,
                jsonb_strip_nulls(jsonb_build_object('owner', new.owner_id)));
    end if;
  elsif new.status is distinct from old.status then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values (case when new.status = 'active' then 'agent.claim' when new.status = 'expired' then 'agent.expire' else 'agent.revoke' end,
              'agent', new.id, jsonb_strip_nulls(jsonb_build_object('owner', new.owner_id, 'from', old.status, 'to', new.status,
              'parent', new.parent_id, 'cascade', case when current_user = 'dog_signin' and new.status = 'revoked' then true end)));
  end if;
  return null;
end
$function$;
CREATE OR REPLACE FUNCTION app.posts_decide()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
declare
  lvl smallint;
  admin boolean;
  live integer;
  reviewed boolean;
begin
  select m.trust_level, m.is_admin into lvl, admin from app.members m where m.id = new.author_id and m.status = 'active';
  if not found then
    raise exception 'only active members can post' using errcode = '42501';
  end if;
  select count(*) into live from app.posts p where p.author_id = new.author_id and p.status = 'live';
  -- 079: an agent's own account posts at once; JEVs and the reviewers check it after, as they check everyone.
  reviewed := not (admin or lvl >= 2 or live >= 3 or app.is_agent_account(new.author_id));
  if reviewed then
    reviewed := not app.jevs_enforcing();
  end if;
  if reviewed then
    perform pg_advisory_xact_lock(hashtext('dayonegreat.posts'), hashtext(new.author_id::text));
    if (select count(*) from app.posts p where p.author_id = new.author_id and p.status = 'waiting') >= 3 then
      raise exception 'waiting_limit' using errcode = 'P0001',
        hint = 'Your first 3 posts are waiting for review; you can post again once they have been reviewed.';
    end if;
    new.status := 'waiting';
    new.published_at := null;
  else
    new.status := 'live';
    new.published_at := now();
  end if;
  new.created_at := now();
  return new;
end
$function$;
reset role;
revoke create on schema app from dog_owner;

