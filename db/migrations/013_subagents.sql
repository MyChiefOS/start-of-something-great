-- 013 Sub-agents (Release 2, PR 16).
-- Aaron's decision (Oct 16, 2026): "Agents need to bring up sub-agents all of the time; we should support that."
-- It replaces "no sub-delegation" (R22 / C9 in the Delegated Agency plan). Agents create sub-agents through the API
-- with no human step; each stays bound to the same owner, gets the same or narrower permissions, expires by default,
-- and the whole tree can be revoked. Criteria SA1 to SA12 (ACCEPTANCE.md).
--
-- How it fits together (after RFC 8693's "act" claim and the IETF agent delegation-chain drafts: a child's authority
-- is the meet of its parent's and what it asks for, its expiry is never after its parent's, and depth is bounded):
--   A sub-agent is an ordinary agent with a parent (parent_id), its depth (its parent's plus one; an agent its owner
--   made or claimed is depth 0), the agent at the top of its tree (root_id) and an expiry (expires_at). Its owner is
--   always its parent's owner, so everything that already follows the owner follows the whole tree: a ban, a disabled
--   account or a lapsed level stops every one of the owner's agents on its next request, the brake and the watch
--   count every agent's actions toward the owner, and deleting the account deletes the tree.
--   Attenuation is enforced here, whoever writes the rules: a sub-agent's rules are never above its parent's current
--   rules (off < draft < act for each action, and the daily cap); lowering a parent lowers its sub-agents in the same
--   transaction ('parent_lowered'), so every receipt names rules that really were in force; and a parent's daily cap
--   counts everything its whole subtree does, so making sub-agents never multiplies what the owner allowed.
--   Revoking an agent, or its time running out, stops every agent under it in the same transaction.
--   An agent sees and revokes only its own direct sub-agents; the owner sees and revokes any of them on /agents.
--   The depth limit, the expiry and the rates are one row only the database owner changes.

set local role dog_owner;

-- ---- The tree ----
alter table app.agents add column parent_id uuid references app.agents (id);
alter table app.agents add column depth smallint not null default 0 check (depth between 0 and 10);
alter table app.agents add column root_id uuid references app.agents (id);
alter table app.agents add column expires_at timestamptz;
-- A sub-agent has a parent, a root, a depth of at least 1, an owner and an expiry; any other agent has none of these.
alter table app.agents add constraint agents_tree_parent check ((parent_id is null) = (root_id is null));
alter table app.agents add constraint agents_tree_depth check ((parent_id is null) = (depth = 0));
alter table app.agents add constraint agents_tree_expiry check ((parent_id is null) = (expires_at is null));
alter table app.agents add constraint agents_tree_owner check (parent_id is null or owner_id is not null);
-- 'expired': a sub-agent whose time ran out (the timer, or its parent's expiry).
alter table app.agents drop constraint agents_status_check;
alter table app.agents add constraint agents_status_check check (status = any (array['unclaimed', 'active', 'revoked', 'expired']));
create index agents_parent on app.agents (parent_id, created_at) where parent_id is not null;
create index agents_root on app.agents (root_id) where root_id is not null;
create index agents_owner_sub on app.agents (owner_id, created_at) where parent_id is not null;
create index agents_expiring on app.agents (expires_at) where status = 'active' and parent_id is not null;
-- A tree's actions in the last day, for a parent's daily cap (app.agent_tree_cap).
create index posts_agent_created on app.posts (agent_id, created_at) where agent_id is not null;

-- ---- The settings: one row, changed only by the database owner (db/README.md shows how) ----
--   max_depth 3: an agent its owner made (depth 0) can have sub-agents, theirs, and theirs again. That covers the
--     usual shapes (an orchestrator, its workers, and a worker's helper) while every receipt stays short enough to
--     read; the IETF delegation-chain draft suggests "low (e.g. 5)", and each level multiplies how far rates can fan out.
--   default_ttl_hours 24, max_ttl_hours 168: a sub-agent is for a task, so it lasts a day unless it asks for more,
--     and at most a week. The hard ceiling is 720 hours (30 days), well inside the 90-day check (R33), so a
--     sub-agent never outlives its owner's consent unasked. Never after its parent's own expiry.
--   per_parent_per_hour 30, per_owner_per_hour 200: room for an orchestrator to fan out to its workers several times
--     an hour, while a runaway loop is stopped long before the watch's hard limit of 500 actions an hour.
create table app.subagent_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  max_depth smallint not null default 3 check (max_depth between 1 and 10),
  default_ttl_hours integer not null default 24 check (default_ttl_hours between 1 and 720),
  max_ttl_hours integer not null default 168 check (max_ttl_hours between 1 and 720),
  per_parent_per_hour integer not null default 30 check (per_parent_per_hour between 1 and 100000),
  per_owner_per_hour integer not null default 200 check (per_owner_per_hour between 1 and 1000000),
  updated_at timestamptz not null default now(),
  check (default_ttl_hours <= max_ttl_hours)
);
alter table app.subagent_settings enable row level security;
alter table app.subagent_settings force row level security;
create policy subagent_settings_owner on app.subagent_settings for all to dog_owner using (true) with check (true);
-- Anyone signed in (members, agents, Aaron, the site) may read the limits; they are public in this file anyway.
create policy subagent_settings_select on app.subagent_settings for select to dog_app using (app.actor_kind() <> 'anon');
create policy subagent_settings_narrow_select on app.subagent_settings for select to dog_signin, dog_jevs using (true);
grant select on app.subagent_settings to dog_app, dog_signin, dog_jevs;
insert into app.subagent_settings default values;

-- ---- Who sees and changes the tree ----
-- An agent also sees, and may revoke, its own direct sub-agents (nothing deeper: their parents look after them, and
-- revoking cascades). Owners and Aaron as before; the site itself (timers) reads every agent.
drop policy agents_select on app.agents;
create policy agents_select on app.agents for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member())
         or (app.actor_kind() = 'agent' and (id = app.current_agent() or parent_id = app.current_agent()))
         or app.actor_kind() in ('admin', 'system'));
drop policy agents_update on app.agents;
create policy agents_update on app.agents for update to dog_app
  using ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member()) or app.actor_kind() = 'admin'
         or (app.actor_kind() = 'agent' and parent_id = app.current_agent()))
  with check ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member()) or app.actor_kind() = 'admin'
              or (app.actor_kind() = 'agent' and parent_id = app.current_agent()));
grant select (parent_id, depth, root_id, expires_at) on app.agents to dog_app;
drop policy agent_rules_select on app.agent_rules;
create policy agent_rules_select on app.agent_rules for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member()))
         or (app.actor_kind() = 'agent' and (agent_id = app.current_agent()
             or exists (select 1 from app.agents a where a.id = agent_id and a.parent_id = app.current_agent())))
         or app.actor_kind() in ('admin', 'system'));

-- The sign-in role (which registers, claims and resolves agents) also makes sub-agents, stops them with their parent
-- or when their time is up, and lowers them with their parent, inside the reviewed functions below only.
drop policy agents_signin_insert on app.agents;
create policy agents_signin_insert on app.agents for insert to dog_signin
  with check ((status = 'unclaimed' and owner_id is null and parent_id is null)
              or (status = 'active' and parent_id is not null and app.actor_kind() = 'agent' and parent_id = app.current_agent()
                  and owner_id = app.current_member()));
-- Active agents too, because locking a parent's row while its sub-agent is made (app.subagent_create, FOR SHARE) needs
-- this policy to pass as well; app.agents_guard still lets the sign-in role change nothing about an agent that isn't
-- unclaimed or a sub-agent whose parent has stopped or whose time is up.
drop policy agents_signin_update on app.agents;
create policy agents_signin_update on app.agents for update to dog_signin
  using (status = any (array['unclaimed', 'active'])) with check (true);
grant insert (expires_at) on app.agents to dog_signin;

-- ---- Rules versions: who set them, and why ----
--   set_by 'agent': a sub-agent's first rules, which its parent asked for (never above the parent's own)
--   reason 'parent_lowered': its parent was lowered, so it was lowered to match (the lower of the two, per setting)
alter table app.agent_rules drop constraint agent_rules_set_by_check;
alter table app.agent_rules add constraint agent_rules_set_by_check check (set_by = any (array['owner', 'system', 'agent']));
alter table app.agent_rules drop constraint agent_rules_reason_check;
alter table app.agent_rules add constraint agent_rules_reason_check
  check (reason = any (array['created', 'owner', 'report_upheld', 'ban', 'disabled', 'reconfirmed', 'act_expired', 'containment',
                             'containment_lifted', 'parent_lowered']));
alter policy agent_rules_signin_insert on app.agent_rules with check (reason in ('created', 'ban', 'disabled', 'parent_lowered'));

-- ---- What the narrow roles read for the tree ----
-- dog_limits counts a tree's actions against each daily cap above it (app.agent_tree_cap).
grant select (id, parent_id, root_id) on app.agents to dog_limits;
grant select (agent_id, delegation) on app.posts to dog_limits;
create policy agent_rules_limits_select on app.agent_rules for select to dog_limits using (true);
grant select (agent_id, version, daily_cap) on app.agent_rules to dog_limits;
create policy agent_drafts_limits_select on app.agent_drafts for select to dog_limits using (true);
grant select (agent_id, created_at) on app.agent_drafts to dog_limits;
-- dog_jevs scores where a new sub-agent would sit (J15).
grant select (parent_id, depth, root_id) on app.agents to dog_jevs;
-- dog_public names the agents above a sub-agent on its posts and receipts, only while they are active (it reads whether
-- they are, inside app.feed and app.receipt only).
grant select (parent_id, status, expires_at) on app.agents to dog_public;

-- ---- Making an agent: who it belongs to, and where it sits ----
-- Same as 005 for owners and self-registration. A sub-agent (013) is made by the acting agent, as the sign-in role,
-- inside app.subagent_create only: it belongs to its parent's owner, one level below its parent, and expires no later
-- than its parent. These are set here, never by the request, and checked again whatever the caller checked.
create or replace function app.agents_fill() returns trigger
language plpgsql
as $$
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
  elsif current_user = 'dog_signin' then
    new.owner_id := null;
    new.status := 'unclaimed';
    new.claimed_at := null;
    new.parent_id := null;
    new.depth := 0;
    new.root_id := null;
    new.expires_at := null;
  elsif app.actor_kind() in ('member', 'admin') then
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
$$;

-- An agent's place in its tree never changes. Owners rename, describe and revoke their agents (005); an agent may
-- only revoke its own direct sub-agents; the sign-in role claims (005), and stops a sub-agent only when its parent has
-- stopped (the cascade below) or its time is up (the timer).
create or replace function app.agents_guard() returns trigger
language plpgsql
as $$
begin
  if (new.id, new.parent_id, new.depth, new.root_id, new.expires_at, new.created_at)
     is distinct from (old.id, old.parent_id, old.depth, old.root_id, old.expires_at, old.created_at) then
    raise exception 'an agent''s place in its tree never changes' using errcode = '42501';
  end if;
  if current_user = 'dog_signin' then
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
               or (new.status = 'expired' and old.expires_at <= now())) then
      raise exception 'a sub-agent stops only with its parent or when its time is up' using errcode = '42501';
    end if;
    return new;
  end if;
  if (new.owner_id, new.claimed_at, new.claim_hash, new.claim_expires_at)
     is distinct from (old.owner_id, old.claimed_at, old.claim_hash, old.claim_expires_at) then
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
$$;

-- The record: a sub-agent's creation names its owner, parent, depth, root and expiry; a sub-agent stopped with its
-- parent is marked as a cascade; one whose time ran out is 'agent.expire'.
create or replace function app.agents_audit() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    if new.parent_id is not null then
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('agent.subagent', 'agent', new.id, jsonb_build_object('owner', new.owner_id, 'parent', new.parent_id, 'depth', new.depth,
                'root', new.root_id, 'expires_at', new.expires_at));
    else
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values (case when new.status = 'unclaimed' then 'agent.register' else 'agent.create' end, 'agent', new.id,
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
$$;

-- An agent its owner made or claimed starts with draft for everything (008). A sub-agent's first rules come from
-- app.subagent_create, which asks for them (never above its parent's).
create or replace function app.agents_first_rules() returns trigger
language plpgsql
as $$
begin
  if new.parent_id is null and new.status = 'active' and (tg_op = 'INSERT' or old.status = 'unclaimed') then
    insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
      values (new.id, 'draft', 'draft', 'draft', 20, 'created');
  end if;
  return null;
end
$$;


-- ---- The rules: attenuation in the database (011's version, with the parts marked 013) ----
create or replace function app.agent_rules_fill() returns trigger
language plpgsql
as $$
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
  new.set_by := case when new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment', 'containment_lifted', 'parent_lowered') then 'system'
                     when new.reason = 'created' and par_id is not null then 'agent' else 'owner' end;
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
    if new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment') then
      raise exception 'an upheld report, a ban, a disabled account, an expiry or a containment can only lower an agent''s rules' using errcode = '42501';
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
$$;


-- ---- Revoking cascades: an agent that stops takes every agent under it with it ----
-- When an agent leaves "active" (revoked by its owner, Aaron or its parent, or its time is up), every active
-- sub-agent directly under it is revoked in the same transaction (or marked expired if its own time is up too), which
-- fires this again one level down. A sub-agent that stops also has its keys revoked and its waiting drafts declined,
-- so nothing it left behind can be used. Runs as the sign-in role, which already revokes keys for a ban, so the
-- cascade reaches the whole tree whoever started it (an owner, Aaron, a parent agent or the timer).
create function app.agents_cascade() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if old.status = 'active' and new.status in ('revoked', 'expired') then
    if new.parent_id is not null then
      update app.agent_keys k set revoked_at = now() where k.agent_id = new.id and k.revoked_at is null;
      update app.agent_drafts d set status = 'declined' where d.agent_id = new.id and d.status = 'pending';
    end if;
    update app.agents a set status = case when a.expires_at <= now() then 'expired' else 'revoked' end
      where a.parent_id = new.id and a.status = 'active';
  end if;
  return null;
end
$$;
create trigger agents_tree_cascade after update on app.agents for each row execute function app.agents_cascade();
alter table app.agents enable always trigger agents_tree_cascade;

-- ---- A new key is a fresh start: it also stops the agent's sub-agents ----
-- Giving an agent a new key (its owner, on /agents) revokes every sub-agent under it, so sub-agents a leaked key made
-- stop with that key, as an unban leaves nothing an intruder held working (006). The agent makes new ones with its new
-- key. A sub-agent's own first key, made with it, has nothing under it.
create function app.agent_keys_fresh_start() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() in ('member', 'admin') then
    update app.agents a set status = 'revoked' where a.parent_id = new.agent_id and a.status = 'active';
  end if;
  return null;
end
$$;
create trigger agent_keys_fresh_start after insert on app.agent_keys for each row execute function app.agent_keys_fresh_start();
alter table app.agent_keys enable always trigger agent_keys_fresh_start;

-- ---- Lowering a parent lowers its sub-agents ----
-- After any new rules version, each active sub-agent directly under that agent whose rules are above the new ones
-- gets a version of its own: per setting, the lower of its rules and its parent's ('parent_lowered'), which repeats
-- one level down. A containment, a ban and a disabled account already lower every agent of the owner in their own
-- loop (011, 010), so they aren't repeated here. Chosen over taking min(parent, child) at use time: the version an
-- action names on its receipt is then always what was really in force, and every reader of an agent's current rules
-- (posting, drafting, approving, the watch, the 90-day check) stays right without knowing about trees.
create function app.agent_rules_cascade() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  c record;
  rank_of constant jsonb := '{"off": 0, "draft": 1, "act": 2}';
begin
  if new.reason in ('containment', 'ban', 'disabled') then
    return null;
  end if;
  for c in select distinct on (x.agent_id) x.agent_id, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap
           from app.agent_rules x join app.agents a on a.id = x.agent_id
           where a.parent_id = new.agent_id and a.status = 'active' order by x.agent_id, x.version desc loop
    if (rank_of ->> c.post_mode)::int > (rank_of ->> new.post_mode)::int or (rank_of ->> c.reply_mode)::int > (rank_of ->> new.reply_mode)::int
       or (rank_of ->> c.report_mode)::int > (rank_of ->> new.report_mode)::int or c.daily_cap > new.daily_cap then
      insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
        values (c.agent_id,
                case when (rank_of ->> c.post_mode)::int <= (rank_of ->> new.post_mode)::int then c.post_mode else new.post_mode end,
                case when (rank_of ->> c.reply_mode)::int <= (rank_of ->> new.reply_mode)::int then c.reply_mode else new.reply_mode end,
                case when (rank_of ->> c.report_mode)::int <= (rank_of ->> new.report_mode)::int then c.report_mode else new.report_mode end,
                least(c.daily_cap, new.daily_cap), 'parent_lowered');
    end if;
  end loop;
  return null;
end
$$;
create trigger agent_rules_cascade after insert on app.agent_rules for each row execute function app.agent_rules_cascade();
alter table app.agent_rules enable always trigger agent_rules_cascade;

-- ---- A parent's daily cap counts its whole subtree ----
-- Before an agent's post under the rules or its draft: if the agent is in a tree, then for the agent and each agent
-- above it, everything under that agent in the last 24 hours (posts under the rules and drafts, as the daily cap
-- counts them, 008) must be below that agent's own daily cap. So a parent allowed 20 actions a day can't become
-- 20 sub-agents with 20 each. One tree's actions are taken one at a time (a lock on its root), after the agent's own
-- lock (posts_delegation, agent_drafts_fill) and the brake's (posts_limit), always in that order. Counting needs rows
-- the acting agent can't see, so this runs as dog_limits, the role that counts for the brake. An approved draft isn't
-- counted again (its draft was), as in 008.
create function app.agent_tree_cap() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  par uuid;
  rt uuid;
  x record;
  n integer;
begin
  if new.agent_id is null or (tg_table_name = 'posts' and coalesce(to_jsonb(new) ->> 'delegation', '') <> 'rules') then
    return new;
  end if;
  select a.parent_id, coalesce(a.root_id, a.id) into par, rt from app.agents a where a.id = new.agent_id;
  if par is null and not exists (select 1 from app.agents c where c.parent_id = new.agent_id) then
    return new;
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.treecap'), hashtext(rt::text));
  for x in with recursive up (id, parent_id, lvl) as (
             select a.id, a.parent_id, 0 from app.agents a where a.id = new.agent_id
             union all
             select a.id, a.parent_id, up.lvl + 1 from app.agents a join up on a.id = up.parent_id where up.lvl < 11)
           select up.id, (select r.daily_cap from app.agent_rules r where r.agent_id = up.id order by r.version desc limit 1) as cap
           from up order by up.lvl loop
    with recursive down (id, lvl) as (
      select x.id, 0
      union all
      select a.id, down.lvl + 1 from app.agents a join down on a.parent_id = down.id where down.lvl < 11)
    select (select count(*) from app.posts p where p.agent_id in (select id from down) and p.delegation = 'rules' and p.created_at > now() - interval '1 day')
         + (select count(*) from app.agent_drafts d where d.agent_id in (select id from down) and d.created_at > now() - interval '1 day')
      into n;
    if x.cap is not null and n >= x.cap then
      raise exception 'agent_cap' using errcode = 'P0001', hint = case when x.id = new.agent_id
        then 'This agent has reached its daily limit of ' || x.cap || ', which counts its sub-agents too.'
        else 'This agent''s tree has reached the daily limit of ' || x.cap || ' its owner set for the agent above it.' end;
    end if;
  end loop;
  return new;
end
$$;
-- Named to fire after posts_delegation and posts_limit (before-triggers fire in name order), and after agent_drafts_fill.
create trigger posts_tree_cap before insert on app.posts for each row execute function app.agent_tree_cap();
alter table app.posts enable always trigger posts_tree_cap;
create trigger agent_drafts_tree_cap before insert on app.agent_drafts for each row execute function app.agent_tree_cap();
alter table app.agent_drafts enable always trigger agent_drafts_tree_cap;

-- ---- An agent makes a sub-agent (POST /api/agents/subagents) ----
-- No human step (Aaron, Oct 16, 2026), and every safeguard automatic: the acting agent must be active and unexpired,
-- its owner active at level 2 (or Aaron); the new agent sits one level below it, within max_depth; the parent may
-- make per_parent_per_hour an hour, and all the owner's agents together per_owner_per_hour; it expires after
-- p_ttl_hours (default default_ttl_hours, at most max_ttl_hours, and never after its parent); and each of its rules is
-- what it asks for (default: draft, or lower if its parent is lower), never above its parent's. With p_draft_only (JEVs
-- found the creation medium risk, in enforce mode) every "act" becomes "draft", so its owner approves what it does.
-- The emergency brake's new-agents limit counts it toward the owner (app.agents_limit). Keys arrive hashed, as ever.
-- p_caller_key: the SHA-256 of the key the request came with. The parent's row and that key's row are locked (in that
-- order, the order revoking and a new key take them) and checked again here, in the transaction that makes the
-- sub-agent, so a revoke or a new key that is under way or has just committed always wins (the review of PR 16,
-- F1 and F2): the request is refused, never left with a sub-agent made by a stopped agent or a stopped key.
-- Returns the new agent, and the chain above it (the IDs of its parent and every agent above, nearest first), which the
-- acting agent can't read for itself. Refusals (P0001 unless noted): depth, rate_parent, rate_owner, ttl, above_parent;
-- parent_not_active (42501); brake; bad requests (22023).
create function app.subagent_create(p_name text, p_description text, p_key_hash text, p_post text, p_reply text, p_report text,
                                    p_daily_cap integer, p_ttl_hours integer, p_draft_only boolean, p_caller_key text)
returns table (agent_id uuid, depth smallint, expires_at timestamptz, rules_version integer, post_mode text, reply_mode text,
               report_mode text, daily_cap integer, chain jsonb)
language plpgsql security definer set search_path = pg_catalog
as $$
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
  select * into s from app.subagent_settings limit 1;
  select a.status, a.depth, a.expires_at, a.owner_id into p_status, p_depth, p_expires, p_owner from app.agents a where a.id = par for share;
  perform 1 from app.agent_keys k where k.key_hash = p_caller_key and k.agent_id = par and k.revoked_at is null for share;
  if not found then
    raise exception 'parent_not_active' using errcode = '42501';
  end if;
  if p_status is distinct from 'active' or p_owner is distinct from me or (p_expires is not null and p_expires <= now())
     or not exists (select 1 from app.members m where m.id = me and m.status = 'active' and (m.trust_level >= 2 or m.is_admin)
                    and not app.deletion_overdue(m.id)) then
    raise exception 'parent_not_active' using errcode = '42501';
  end if;
  if p_depth + 1 > s.max_depth then
    raise exception 'depth' using errcode = 'P0001',
      hint = 'Sub-agents go at most ' || s.max_depth || ' levels below the agent their owner made, and this agent is already at level ' || p_depth || '.';
  end if;
  select count(*) into n from app.agents a where a.parent_id = par and a.created_at > now() - interval '1 hour';
  if n >= s.per_parent_per_hour then
    raise exception 'rate_parent' using errcode = 'P0001', hint = 'One agent can make at most ' || s.per_parent_per_hour || ' sub-agents an hour.';
  end if;
  select count(*) into n from app.agents a where a.owner_id = me and a.parent_id is not null and a.created_at > now() - interval '1 hour';
  if n >= s.per_owner_per_hour then
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
$$;

-- ---- The timer: sub-agents whose time is up ----
-- Each is marked expired (its keys revoked, its waiting drafts declined, and everything under it stopped, by the
-- cascade above). An expired sub-agent already stops at once whenever this runs: app.agent_resolve refuses it from its
-- expiry on. Run by the site's scheduled job (app.run_timers) or Aaron. Returns how many it marked.
create function app.subagents_expire()
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
  m integer;
begin
  if app.actor_kind() not in ('system', 'admin') then
    raise exception 'not_system' using errcode = '42501';
  end if;
  update app.agents a set status = 'expired' where a.status = 'active' and a.parent_id is not null and a.expires_at <= now();
  get diagnostics n = row_count;
  -- Defence in depth (the review of PR 16, F1): a sub-agent left active under a parent that has stopped, however that
  -- happened, is revoked now (and everything under it with it, by the cascade).
  update app.agents a set status = 'revoked' where a.status = 'active' and a.parent_id is not null
    and exists (select 1 from app.agents p where p.id = a.parent_id and p.status <> 'active');
  get diagnostics m = row_count;
  return n + m;
end
$$;


-- ---- Containment lifts restore parents first (011's version, with the part marked 013) ----
create or replace function app.containments_after() returns trigger
language plpgsql
as $$
declare
  r record;
  before app.agent_rules%rowtype;
  n integer := 0;
  pr_post text; pr_reply text; pr_report text; pr_cap integer;
  rank_of constant jsonb := '{"off": 0, "draft": 1, "act": 2}';
begin
  if old.appealed_at is null and new.appealed_at is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('containment.appeal', 'member', new.member_id, jsonb_build_object('containment', new.id));
    perform app.notify(null, 'alert', 'An owner appealed a containment',
      'An owner whose agents were set back to drafting has appealed. It ends by itself at '
      || to_char(new.ends_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC whatever you decide.',
      '/review#appeals', 'member', new.member_id, 'appeal:' || new.id);
  end if;
  if old.appeal_decision is null and new.appeal_decision is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('containment.decide', 'member', new.member_id, jsonb_build_object('containment', new.id, 'decision', new.appeal_decision));
    perform app.notify(new.member_id, 'appeal_decided',
      case when new.appeal_decision = 'lifted' then 'Your appeal was upheld' else 'Your appeal was reviewed' end,
      case when new.appeal_decision = 'lifted' then 'Your agents are back on your own rules now.'
           else 'The pause stays until ' || to_char(new.ends_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC, then ends by itself.' end,
      '/agents', 'containment', new.id, 'appeal_decided:' || new.id);
  end if;
  if old.lifted_at is null and new.lifted_at is not null then
    -- Parents first (013), so each sub-agent goes back only as far as its parent now is.
    for r in select q.* from (select distinct on (x.agent_id) x.agent_id, x.version, x.reason, x.created_at, a.depth, a.parent_id
             from app.agent_rules x join app.agents a on a.id = x.agent_id
             where a.owner_id = new.member_id and a.status = 'active' order by x.agent_id, x.version desc) q
             order by q.depth, q.agent_id loop
      -- Only agents still on the containment's own version: anything the owner changed since stays as they set it.
      if r.reason = 'containment' and r.created_at >= new.started_at then
        select * into before from app.agent_rules x where x.agent_id = r.agent_id and x.version = r.version - 1;
        pr_post := null;
        if r.parent_id is not null then
          select x.post_mode, x.reply_mode, x.report_mode, x.daily_cap into pr_post, pr_reply, pr_report, pr_cap
            from app.agent_rules x where x.agent_id = r.parent_id order by x.version desc limit 1;
        end if;
        if r.parent_id is null or (pr_post is not null and (rank_of ->> before.post_mode)::int <= (rank_of ->> pr_post)::int
            and (rank_of ->> before.reply_mode)::int <= (rank_of ->> pr_reply)::int and (rank_of ->> before.report_mode)::int <= (rank_of ->> pr_report)::int
            and before.daily_cap <= pr_cap) then
          insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
            values (r.agent_id, before.post_mode, before.reply_mode, before.report_mode, before.daily_cap, 'containment_lifted');
          n := n + 1;
        end if;
      end if;
    end loop;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('containment.lift', 'member', new.member_id, jsonb_build_object('containment', new.id, 'by', new.lifted_by, 'agents', n));
    perform app.notify(new.member_id, 'containment_lifted', 'Your agents are back on your rules',
      'The pause on your agents has ended' || case when new.lifted_by = 'admin' then ' early' else '' end || '. '
      || n || case when n = 1 then ' agent is' else ' agents are' end || ' acting on your rules again.',
      '/agents', 'containment', new.id, 'lifted:' || new.id);
  end if;
  return null;
end
$$;


-- ---- The timers, with sub-agents' expiry (011's version, with the part marked PR 16) ----
create or replace function app.run_timers() returns jsonb
language plpgsql
as $$
declare
  out jsonb;
begin
  perform app.require_system();
  if not pg_try_advisory_xact_lock(hashtext('dayonegreat.timers'), 0) then
    return jsonb_build_object('busy', true);
  end if;
  out := jsonb_build_object('lifted', app.containment_lift_job(), 'expired_drafts', app.drafts_expire_job());
  out := out || app.act_reconfirm_job() || app.watch_job();
  -- JEVs (PR 12): the 24-hour timer on deletion reviews Aaron hasn't decided, and the sweep that keeps marks no
  -- longer than promised.
  out := out || jsonb_build_object('deletion_reviews_disabled', app.deletion_reviews_expire(), 'marks_swept', app.jevs_sweep());
  -- PR 16: sub-agents whose time is up (each takes everything under it with it).
  out := out || jsonb_build_object('subagents_expired', app.subagents_expire());
  return out;
end
$$;


-- ---- JEVs scores making a sub-agent (J15; db/jevs.js) ----
-- 'agent.subagent': about the acting agent and its owner. Effect 'draft' (medium): the sub-agent is made with every
-- action drafting for its owner's approval.
alter table app.jevs_decisions drop constraint jevs_decisions_action_check;
alter table app.jevs_decisions add constraint jevs_decisions_action_check check (action = any (array['signup', 'account.check', 'post.create',
  'post.approved', 'post.reported', 'draft.create', 'agent.register', 'agent.create', 'agent.claim', 'agent.key', 'agent.rules', 'account.delete',
  'agent.subagent']));
alter table app.jevs_decisions drop constraint jevs_decisions_effect_check;
alter table app.jevs_decisions add constraint jevs_decisions_effect_check check (effect = any (array['none', 'challenge', 'hold', 'hide', 'promote',
  'queue', 'draft']));

grant create on schema app to dog_jevs;
set local role dog_jevs;
-- 010's version, with the parts marked 013.
create or replace function app.jevs_signals(p_action text, p_subject uuid, p_net text, p_domains text[], p_simhash bigint)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  judged uuid;
  m_created timestamptz; m_level smallint; m_admin boolean; m_status text; m_hand smallint; m_jevs timestamptz;
  fp text;
  subject_at timestamptz := now();
  credible_hours integer;
  res jsonb := '{}'::jsonb;
begin
  if p_action is null or p_action !~ '^[a-z]+\.?[a-z_]*$' or char_length(p_action) > 32
     or (p_net is not null and p_net !~ '^[0-9a-f]{64}$')
     or (p_domains is not null and (cardinality(p_domains) > 50 or exists (select 1 from unnest(p_domains) x where x is null or x !~ '^[0-9a-f]{64}$'))) then
    raise exception 'bad JEVs request' using errcode = '22023';
  end if;
  judged := me;
  if p_action in ('post.create', 'post.approved', 'post.reported') then
    select p.author_id, p.body_fp, p.created_at into judged, fp, subject_at from app.posts p where p.id = p_subject;
    if not found then
      raise exception 'bad JEVs request' using errcode = '22023';
    end if;
    if p_action = 'post.reported' then
      if not exists (select 1 from app.review_flags f where f.post_id = p_subject and f.source = 'report' and f.reporter_id = me) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
    elsif judged is distinct from me then
      raise exception 'bad JEVs request' using errcode = '22023';
    end if;
  end if;

  if judged is not null then
    select x.created_at, x.trust_level, x.is_admin, x.status, x.level_set_by_admin, x.jevs_level2_at
      into m_created, m_level, m_admin, m_status, m_hand, m_jevs from app.members x where x.id = judged;
    res := res || jsonb_build_object(
      'account', true,
      'age_hours', floor(extract(epoch from now() - m_created) / 3600),
      'trust_level', m_level, 'admin', m_admin, 'banned', m_status = 'banned',
      'hand_level', m_hand is not null, 'jevs_level2', m_jevs is not null,
      'best_identity', (select coalesce(max(case when i.recheck_after is not null and i.recheck_after <= now() then least(i.level, 1) else i.level end), -1)
                        from app.identities i where i.member_id = judged),
      'providers', (select count(distinct i.provider) from app.identities i where i.member_id = judged),
      'email_only', not exists (select 1 from app.identities i where i.member_id = judged and i.provider <> 'email')
                    and exists (select 1 from app.identities i where i.member_id = judged),
      'disposable', exists (select 1 from app.jevs_marks k where k.member_id = judged and k.kind = 'disposable'),
      -- J05: an account made in the last 7 days is "new"; an established one is never judged by its neighbours (the
      -- JEVs review, F3). Network marks are left at sign-up only (signin/flow.js). Counted: other new accounts that
      -- signed up from the same network in the last 24 hours, or with the same uncommon email domain in the last 7 days.
      'established', m_created <= now() - interval '7 days',
      'net_members_24h', (select count(distinct k2.member_id) from app.jevs_marks k1 join app.jevs_marks k2
                            on k2.kind = 'net' and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                            and k2.created_at > now() - interval '24 hours'
                            join app.members n on n.id = k2.member_id and n.created_at > now() - interval '7 days'
                          where k1.member_id = judged and k1.kind = 'net' and k1.created_at > now() - interval '24 hours'),
      'domain_members_7d', (select count(distinct k2.member_id) from app.jevs_marks k1 join app.jevs_marks k2
                              on k2.kind = 'email_domain' and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                              and k2.created_at > now() - interval '7 days'
                              join app.members n on n.id = k2.member_id and n.created_at > now() - interval '7 days'
                            where k1.member_id = judged and k1.kind = 'email_domain'),
      -- J06: agents this owner created or claimed in the last 24 hours (not sub-agents, which J15 looks at, 013).
      'owner_agents_24h', (select count(*) from app.agents a where a.owner_id = judged and a.parent_id is null
                           and a.claimed_at > now() - interval '24 hours'),
      -- J10: upheld reports on their posts (90 days) and a brake on them now. Nothing about neighbours: a banned member
      -- on the same network or email domain says nothing about this one (the JEVs review, F4), and a banned person's
      -- own sign-in methods are refused at sign-in already (F10).
      'upheld_90d', (select count(*) from app.review_flags f join app.posts p on p.id = f.post_id
                     where p.author_id = judged and f.source = 'report' and f.decision = 'remove' and f.resolved_at > now() - interval '90 days'),
      'braked', exists (select 1 from app.brakes b where b.member_id = judged and b.lifted_at is null)
    );
    -- J04: the acting agent's own posting rate, or the member's people posts, against its own last two weeks.
    if ag is not null and p_action <> 'post.reported' then
      res := res || jsonb_build_object(
        'posts_1h', (select count(*) from app.posts p where p.agent_id = ag and p.created_at > now() - interval '1 hour'),
        'posts_before', (select count(*) from app.posts p where p.agent_id = ag and p.created_at between now() - interval '15 days' and now() - interval '1 day'));
    else
      res := res || jsonb_build_object(
        'posts_1h', (select count(*) from app.posts p where p.author_id = judged and p.lane = 'people' and p.created_at > now() - interval '1 hour'),
        'posts_before', (select count(*) from app.posts p where p.author_id = judged and p.lane = 'people'
                         and p.created_at between now() - interval '15 days' and now() - interval '1 day'));
    end if;
  else
    res := res || jsonb_build_object('account', false);
  end if;

  -- Sign-up bursts: from this network in the last hour (members and agents), and across the whole site.
  res := res || jsonb_build_object(
    'net_signups_1h', case when p_net is null then 0 else (select count(*) from app.jevs_marks k where k.kind = 'net' and k.key_hash = p_net
                                                              and k.token_hash is null and k.created_at > now() - interval '1 hour') end,
    'net_agents_24h', case when p_net is null then 0 else (select count(distinct k.agent_id) from app.jevs_marks k where k.kind = 'net' and k.key_hash = p_net
                                                              and k.agent_id is not null and k.created_at > now() - interval '24 hours') end,
    'site_signups_1h', (select count(*) from app.members x where x.created_at > now() - interval '1 hour'),
    'site_signups_7d', (select count(*) from app.members x where x.created_at > now() - interval '7 days'));

  -- J07 and J09: what a post links to, and how many other members wrote the same or nearly the same words this week.
  -- A domain counts as seen once a low-risk post linking it has stayed live for 24 hours; removing that post unsees
  -- it (the JEVs review, F6). A copy is an earlier live post by another member, so whoever wrote it first is never
  -- the one judged, and held or removed copies count for nothing; text too short to compare fairly (under 8 words
  -- or 40 characters, when db/jevs.js gives no print) is never counted as copied (the JEVs review, F1 and F2).
  if p_action in ('post.create', 'post.approved', 'post.reported', 'draft.create') then
    res := res || jsonb_build_object(
      'new_domains', case when p_domains is null then 0 else
                       (select count(distinct x) from unnest(p_domains) x where not exists (
                          select 1 from app.jevs_post_domains d join app.posts p on p.id = d.post_id
                          where d.domain_hash = x and p.status = 'live' and p.created_at <= now() - interval '24 hours')) end,
      'copies', case when p_simhash is null then 0 else (select count(distinct a) from (
                   select p.author_id as a from app.posts p
                   where fp is not null and p.body_fp = fp and p.author_id is distinct from judged and p.status = 'live'
                     and p.created_at < subject_at and p.created_at > now() - interval '7 days'
                   union
                   select p.author_id from app.jevs_prints r join app.posts p on p.id = r.post_id
                   where p.author_id is distinct from judged and p.status = 'live' and p.created_at < subject_at
                     and r.created_at > now() - interval '7 days' and bit_count(int8send(r.simhash # p_simhash)) <= 10) c) end);
  end if;

  -- J14: credible members with an open report on this post: level 2, not made in the last credible_reporter_age_hours
  -- (7 days as seeded), and independent of each other: a reporter who shares a sign-up network or an uncommon email
  -- domain with an earlier credible reporter counts with them as one (the JEVs review, F1).
  if p_action = 'post.reported' then
    select s.value::integer into credible_hours from app.jevs_settings s where s.key = 'credible_reporter_age_hours';
    res := res || jsonb_build_object('credible_reports', (
      with cr as (
        select f.reporter_id as rid, min(f.created_at) as at from app.review_flags f join app.members r on r.id = f.reporter_id
        where f.post_id = p_subject and f.source = 'report' and f.resolved_at is null
          and r.status = 'active' and r.trust_level >= 2 and r.created_at <= now() - make_interval(hours => coalesce(credible_hours, 168))
        group by f.reporter_id)
      select count(*) from cr a
      where not exists (select 1 from cr b join app.jevs_marks kb on kb.member_id = b.rid
                        join app.jevs_marks ka on ka.member_id = a.rid and ka.kind = kb.kind and ka.key_hash = kb.key_hash
                        where (b.at, b.rid) < (a.at, a.rid) and ka.kind in ('net', 'email_domain'))));
  end if;
  -- J15 (013): where the sub-agent the acting agent wants to make would sit, and how many sub-agents its tree made in
  -- the last hour.
  if p_action = 'agent.subagent' and ag is not null then
    res := res || (select jsonb_build_object('subagent_depth', a.depth + 1, 'subagent_max_depth', (select s.max_depth from app.subagent_settings s),
                     'tree_subagents_1h', (select count(*) from app.agents t where t.root_id = coalesce(a.root_id, a.id)
                                           and t.created_at > now() - interval '1 hour'))
                   from app.agents a where a.id = ag);
  end if;
  return res;
end
$$;


-- 010's version, with the parts marked 013.
create or replace function app.jevs_decide(p_action text, p_subject uuid, p_scores jsonb, p_impact text, p_error boolean, p_domains text[], p_simhash bigint,
                                 p_net text)
returns table (decision_id uuid, level text, effect text, applied boolean, mode text, challenge_id uuid, challenge_status text)
language plpgsql security definer set search_path = pg_catalog
as $$
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
  select coalesce(sum((e.value)::integer), 0), coalesce(max((e.value)::integer), 0) into total, top from jsonb_each(p_scores) e;
  questions := array(select k from jsonb_object_keys(p_scores) k order by k);

  if p_error then
    lvl := case when p_impact = 'high' then 'high' else 'low' end;
  elsif top >= s_high_any or total >= s_high_total then
    lvl := 'high';
  elsif top >= s_medium_any or total >= s_medium_total then
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
  elsif p_action = 'agent.register' then
    -- The owner's claim is the human check; only high risk holds a registration.
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
$$;

set local role dog_owner;
revoke create on schema app from dog_jevs;

-- ---- Sign-in for agents: an expired sub-agent stops at once ----
-- Same as 010, and two conditions more: a sub-agent past its expiry resolves to nothing from that moment, whenever the
-- timer next runs; and so does one with any agent above it (at most 10 levels) not active or past its expiry. Revoking
-- already cascades in the same transaction (agents_cascade) and a sub-agent never outlives its parent; the second
-- condition is defence in depth (the review of PR 16, F1).
grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.agent_resolve(p_key_hash text)
returns table (agent_id uuid, owner_id uuid)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query
    select a.id, m.id
    from app.agent_keys k join app.agents a on a.id = k.agent_id join app.members m on m.id = a.owner_id
    where k.key_hash = p_key_hash and k.revoked_at is null and a.status = 'active' and (a.expires_at is null or a.expires_at > now())
      and m.status = 'active' and (m.trust_level >= 2 or m.is_admin) and not app.deletion_overdue(m.id)
      and not exists (
        with recursive up (id, lvl) as (
          select a.parent_id, 1 where a.parent_id is not null
          union all
          select p.parent_id, up.lvl + 1 from app.agents p join up on p.id = up.id where p.parent_id is not null and up.lvl < 11)
        select 1 from up join app.agents x on x.id = up.id where x.status <> 'active' or (x.expires_at is not null and x.expires_at <= now()));
end
$$;
set local role dog_owner;
revoke create on schema app from dog_signin;

-- ---- Every post and receipt by a sub-agent shows its chain (after RFC 8693's "act" claim) ----
-- agent_chain: the agents above the one that acted, nearest first ([{id, name, active}], empty for an agent its owner
-- made). An agent above that has stopped (revoked or expired) is not named: its id and name are null, and the site says
-- "an agent of <owner>" (Aaron, the review of PR 16, F5), so a name chosen for a private purpose leaves with its agent.
-- The site shows "<agent> · sub-agent of <parent> — owned by <owner>" and, for machines, the chain as nested "act"
-- claims. A sub-agent's post whose chain can't be shown is still shown with its agent and owner (F3).
drop function app.feed(text, uuid, integer);
create function app.feed(p_lane text, p_before uuid, p_limit integer)
returns table (id uuid, lane text, body text, published_at timestamptz, author_id uuid, author_name text, author_level smallint,
               agent_id uuid, agent_name text, delegation text, rules_version integer, agent_chain jsonb)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_lane is null or not (p_lane = any (array['people', 'agents'])) or p_limit is null or p_limit not between 1 and 50 then
    raise exception 'bad feed request' using errcode = '22023';
  end if;
  return query
    select p.id, p.lane, p.body, p.published_at, m.id, m.display_name, m.trust_level, a.id, a.name, p.delegation, p.rules_version,
           coalesce(ch.chain, '[]'::jsonb)
    from app.posts p join app.members m on m.id = p.author_id
    left join app.agents a on a.id = p.agent_id
    left join lateral (
      with recursive up (id, name, parent_id, lvl, live) as (
        select g.id, g.name, g.parent_id, 1, g.status = 'active' and (g.expires_at is null or g.expires_at > now()) from app.agents g where g.id = a.parent_id
        union all
        select g.id, g.name, g.parent_id, up.lvl + 1, g.status = 'active' and (g.expires_at is null or g.expires_at > now()) from app.agents g join up on g.id = up.parent_id where up.lvl < 11)
      select jsonb_agg(jsonb_build_object('id', case when up.live then up.id end, 'name', case when up.live then up.name end, 'active', up.live)
                       order by up.lvl) as chain from up) ch on true
    where p.status = 'live' and p.lane = p_lane
      and (p.agent_id is null or a.id is not null)
      and (p_before is null or (p.published_at, p.id) < (select b.published_at, b.id from app.posts b where b.id = p_before and b.status = 'live'))
    order by p.published_at desc, p.id desc
    limit p_limit;
end
$$;

drop function app.receipt(uuid);
create function app.receipt(p_post uuid)
returns table (post_id uuid, published_at timestamptz, agent_id uuid, agent_name text, owner_id uuid, owner_name text,
               delegation text, rules_version integer, post_mode text, daily_cap integer, minutes_to_approve integer, agent_chain jsonb)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_post is null then
    return;
  end if;
  return query
    select p.id, p.published_at, a.id, a.name, m.id, m.display_name, p.delegation, p.rules_version, r.post_mode, r.daily_cap,
           case when d.id is null then null else (round(extract(epoch from d.decided_at - d.created_at) / 300) * 5)::integer end,
           coalesce(ch.chain, '[]'::jsonb)
    from app.posts p join app.members m on m.id = p.author_id
    join app.agents a on a.id = p.agent_id
    left join app.agent_rules r on r.agent_id = p.agent_id and r.version = p.rules_version
    left join app.agent_drafts d on d.id = p.draft_id
    left join lateral (
      with recursive up (id, name, parent_id, lvl, live) as (
        select g.id, g.name, g.parent_id, 1, g.status = 'active' and (g.expires_at is null or g.expires_at > now()) from app.agents g where g.id = a.parent_id
        union all
        select g.id, g.name, g.parent_id, up.lvl + 1, g.status = 'active' and (g.expires_at is null or g.expires_at > now()) from app.agents g join up on g.id = up.parent_id where up.lvl < 11)
      select jsonb_agg(jsonb_build_object('id', case when up.live then up.id end, 'name', case when up.live then up.name end, 'active', up.live)
                       order by up.lvl) as chain from up) ch on true
    where p.id = p_post and p.status = 'live' and p.lane = 'agents';
end
$$;

-- ---- Who may call what ----
revoke execute on function app.agent_keys_fresh_start() from public;
revoke execute on function app.agents_cascade(), app.agent_rules_cascade(), app.agent_tree_cap(),
  app.subagent_create(text, text, text, text, text, text, integer, integer, boolean, text), app.subagents_expire(),
  app.feed(text, uuid, integer), app.receipt(uuid) from public;
-- The trigger functions can't be called directly; the coverage check asks that every function running with its
-- owner's rights be callable by the site's role alone.
grant execute on function app.agents_cascade(), app.agent_rules_cascade(), app.agent_tree_cap(),
  app.subagent_create(text, text, text, text, text, text, integer, integer, boolean, text), app.subagents_expire(),
  app.feed(text, uuid, integer), app.receipt(uuid) to dog_app;
grant create on schema app to dog_signin, dog_limits, dog_public;
alter function app.agents_cascade() owner to dog_signin;
alter function app.agent_rules_cascade() owner to dog_signin;
alter function app.subagent_create(text, text, text, text, text, text, integer, integer, boolean, text) owner to dog_signin;
alter function app.subagents_expire() owner to dog_signin;
alter function app.agent_tree_cap() owner to dog_limits;
alter function app.feed(text, uuid, integer) owner to dog_public;
alter function app.receipt(uuid) owner to dog_public;
revoke create on schema app from dog_signin, dog_limits, dog_public;
