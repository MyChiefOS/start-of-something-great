-- 008 Agents acting for their owners (Release 2, PR 7): the delegated agency core.
-- Draft criteria (for Aaron's approval): A1 the owner sets each action (post, reply, report) to off, draft for approval
-- or act, and a new agent starts at draft; A2 an approval covers the exact words, changed words need a new approval,
-- drafts expire after 48 hours; A3 every agent post says whether a person approved it or it went out under the
-- owner's rules, on the site and in the API and MCP; A4 every agent action records the rules version it acted under
-- and has a public receipt; A5 an upheld report on an agent's post returns that action to draft at once; A6 approve
-- or decline in one tap. Also R10 a daily cap the owner sets, R17 a fresh sign-in before raising any action to act.
--
-- Today agents only post; reply and report modes are kept now so owners set them before those actions exist.
-- The rules are versions that are only ever added, never changed: every action names the version it acted under,
-- so a receipt can show exactly what the owner had allowed at the time.

do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_delegate') then
    create role dog_delegate nologin noinherit nobypassrls;
  end if;
end
$roles$;
grant dog_delegate to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_delegate;

-- ---- The owner's rules (A1, A4, R10) ----
create table app.agent_rules (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null references app.agents (id),
  version integer not null check (version between 1 and 1000000),
  post_mode text not null check (post_mode = any (array['off', 'draft', 'act'])),
  reply_mode text not null check (reply_mode = any (array['off', 'draft', 'act'])),
  report_mode text not null check (report_mode = any (array['off', 'draft', 'act'])),
  daily_cap integer not null check (daily_cap between 1 and 1000),
  set_by text not null check (set_by = any (array['owner', 'system'])),
  reason text not null check (reason = any (array['created', 'owner', 'report_upheld', 'ban'])),
  created_at timestamptz not null default now(),
  unique (agent_id, version)
);
alter table app.agent_rules enable row level security;
alter table app.agent_rules force row level security;

-- The owner, the agent itself and Aaron see an agent's rules.
create policy agent_rules_select on app.agent_rules for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member()))
         or (app.actor_kind() = 'agent' and agent_id = app.current_agent())
         or app.actor_kind() = 'admin');
-- New versions: the owner of an active agent; or Aaron, only to lower an agent after an upheld report (A5).
create policy agent_rules_insert on app.agent_rules for insert to dog_app
  with check ((app.actor_kind() in ('member', 'admin') and reason in ('created', 'owner')
               and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member() and a.status = 'active'))
              or (app.actor_kind() = 'admin' and reason = 'report_upheld'));
grant select on app.agent_rules to dog_app;
grant insert (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) on app.agent_rules to dog_app;
-- A claimed agent gets its first rules from the claim itself, and a ban lowers an owner's agents (both dog_signin).
create policy agent_rules_signin_select on app.agent_rules for select to dog_signin using (true);
create policy agent_rules_signin_insert on app.agent_rules for insert to dog_signin with check (reason in ('created', 'ban'));
grant select (id, agent_id, version, post_mode, reply_mode, report_mode, daily_cap) on app.agent_rules to dog_signin;
grant insert (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) on app.agent_rules to dog_signin;

-- The version, who set it and when come from the database. A first version is always "draft" for everything (A1).
-- The owner raising any action to "act", or raising the daily cap, needs a fresh sign-in, which the site marks for
-- the transaction (app.fresh, set only by db/index.js from the session's own start time). A version written after an
-- upheld report or a ban can only lower an agent, never raise it.
create function app.agent_rules_fill() returns trigger
language plpgsql
as $$
declare
  prev app.agent_rules%rowtype;
  rank_of constant jsonb := '{"off": 0, "draft": 1, "act": 2}';
begin
  perform pg_advisory_xact_lock(hashtext('dayonegreat.rules'), hashtext(new.agent_id::text));
  select r.id, r.version, r.post_mode, r.reply_mode, r.report_mode, r.daily_cap
    into prev.id, prev.version, prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap
    from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  new.version := coalesce(prev.version, 0) + 1;
  new.created_at := now();
  new.set_by := case when new.reason in ('report_upheld', 'ban') then 'system' else 'owner' end;
  if new.reason = 'created' then
    if prev.id is not null then
      raise exception 'an agent''s first rules are set once' using errcode = '42501';
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
  if (rank_of ->> new.post_mode)::int > (rank_of ->> prev.post_mode)::int
     or (rank_of ->> new.reply_mode)::int > (rank_of ->> prev.reply_mode)::int
     or (rank_of ->> new.report_mode)::int > (rank_of ->> prev.report_mode)::int
     or new.daily_cap > prev.daily_cap then
    if new.reason in ('report_upheld', 'ban') then
      raise exception 'an upheld report or a ban can only lower an agent''s rules' using errcode = '42501';
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
create trigger agent_rules_fill before insert on app.agent_rules for each row execute function app.agent_rules_fill();
alter table app.agent_rules enable always trigger agent_rules_fill;

-- Versions are never changed. Deleting happens only with the whole account (dog_erase).
create function app.agent_rules_guard() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'DELETE' and current_user = 'dog_erase' then
    return old;
  end if;
  raise exception 'rules versions are only ever added' using errcode = '42501';
end
$$;
create trigger agent_rules_guard before update or delete on app.agent_rules for each row execute function app.agent_rules_guard();
alter table app.agent_rules enable always trigger agent_rules_guard;

create function app.agent_rules_audit() returns trigger
language plpgsql
as $$
begin
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('agent.rules', 'agent', new.agent_id, jsonb_build_object('version', new.version, 'post', new.post_mode, 'reply', new.reply_mode,
            'report', new.report_mode, 'daily_cap', new.daily_cap, 'reason', new.reason));
  return null;
end
$$;
create trigger agent_rules_audit after insert on app.agent_rules for each row execute function app.agent_rules_audit();
alter table app.agent_rules enable always trigger agent_rules_audit;

-- Every agent gets its first rules (draft for everything) the moment it becomes active: created by its owner, or claimed.
create function app.agents_first_rules() returns trigger
language plpgsql
as $$
begin
  if new.status = 'active' and (tg_op = 'INSERT' or old.status = 'unclaimed') then
    insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
      values (new.id, 'draft', 'draft', 'draft', 20, 'created');
  end if;
  return null;
end
$$;
create trigger agents_first_rules after insert or update on app.agents for each row execute function app.agents_first_rules();
alter table app.agents enable always trigger agents_first_rules;

-- ---- Drafts waiting for the owner (A2, A6) ----
create table app.agent_drafts (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null references app.agents (id),
  owner_id uuid not null references app.members (id),
  action text not null default 'post' check (action = any (array['post'])),
  body text not null check (char_length(body) between 1 and 5000),
  body_hash text not null check (char_length(body_hash) = 64 and body_hash ~ '^[0-9a-f]+$'),
  rules_version integer not null check (rules_version between 1 and 1000000),
  status text not null default 'pending' check (status = any (array['pending', 'approved', 'declined'])),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  decided_at timestamptz,
  check ((status = 'pending') = (decided_at is null))
);
create index agent_drafts_owner on app.agent_drafts (owner_id, status, created_at);
create index agent_drafts_agent on app.agent_drafts (agent_id, created_at);
alter table app.agent_drafts enable row level security;
alter table app.agent_drafts force row level security;

create policy agent_drafts_select on app.agent_drafts for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member())
         or (app.actor_kind() = 'agent' and agent_id = app.current_agent())
         or app.actor_kind() = 'admin');
create policy agent_drafts_insert on app.agent_drafts for insert to dog_app
  with check (app.actor_kind() = 'agent' and agent_id = app.current_agent() and owner_id = app.current_member()
              and exists (select 1 from app.agents a where a.id = app.current_agent() and a.owner_id = app.current_member() and a.status = 'active'));
-- The owner declines from the site; approving goes through app.approve_draft (dog_delegate).
create policy agent_drafts_update on app.agent_drafts for update to dog_app
  using (app.actor_kind() in ('member', 'admin') and owner_id = app.current_member())
  with check (app.actor_kind() in ('member', 'admin') and owner_id = app.current_member());
grant select on app.agent_drafts to dog_app;
grant insert (body) on app.agent_drafts to dog_app;
grant update (status) on app.agent_drafts to dog_app;

-- A draft is the agent's, for its owner, under the rules in force now, and only while posting is set to draft.
create function app.agent_drafts_fill() returns trigger
language plpgsql
as $$
declare
  cur app.agent_rules%rowtype;
begin
  if app.actor_kind() <> 'agent' then
    raise exception 'only an agent writes drafts' using errcode = '42501';
  end if;
  new.agent_id := app.current_agent();
  new.owner_id := app.current_member();
  new.action := 'post';
  new.body_hash := encode(sha256(convert_to(new.body, 'UTF8')), 'hex');
  new.status := 'pending';
  new.created_at := now();
  new.expires_at := now() + interval '48 hours';
  new.decided_at := null;
  select * into cur from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  if not found or cur.post_mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  if cur.post_mode <> 'draft' then
    raise exception 'agent_acts' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.agentcap'), hashtext(new.agent_id::text));
  if app.agent_actions_today(new.agent_id) >= cur.daily_cap then
    raise exception 'agent_cap' using errcode = 'P0001', hint = 'This agent has reached its daily limit of ' || cur.daily_cap || '.';
  end if;
  new.rules_version := cur.version;
  return new;
end
$$;
create trigger agent_drafts_fill before insert on app.agent_drafts for each row execute function app.agent_drafts_fill();
alter table app.agent_drafts enable always trigger agent_drafts_fill;

-- The words never change (A2: changed words would be a new draft). A draft is decided once: declined by its owner,
-- or approved through app.approve_draft.
create function app.agent_drafts_guard() returns trigger
language plpgsql
as $$
begin
  if (new.id, new.agent_id, new.owner_id, new.action, new.body, new.body_hash, new.rules_version, new.created_at, new.expires_at)
     is distinct from (old.id, old.agent_id, old.owner_id, old.action, old.body, old.body_hash, old.rules_version, old.created_at, old.expires_at) then
    raise exception 'a draft''s words never change' using errcode = '42501';
  end if;
  if old.status <> 'pending' then
    raise exception 'that draft has already been decided' using errcode = '42501';
  end if;
  if not ((new.status = 'declined' and current_user <> 'dog_delegate') or (new.status = 'approved' and current_user = 'dog_delegate')) then
    raise exception 'a draft is approved through the inbox or declined by its owner' using errcode = '42501';
  end if;
  new.decided_at := now();
  return new;
end
$$;
create trigger agent_drafts_guard before update on app.agent_drafts for each row execute function app.agent_drafts_guard();
alter table app.agent_drafts enable always trigger agent_drafts_guard;

create function app.agent_drafts_audit() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('draft.create', 'draft', new.id, jsonb_build_object('agent', new.agent_id, 'rules_version', new.rules_version));
  else
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('draft.' || case when new.status = 'approved' then 'approve' else 'decline' end, 'draft', new.id,
              jsonb_build_object('agent', new.agent_id, 'rules_version', new.rules_version));
  end if;
  return null;
end
$$;
create trigger agent_drafts_audit after insert or update on app.agent_drafts for each row execute function app.agent_drafts_audit();
alter table app.agent_drafts enable always trigger agent_drafts_audit;

-- ---- Every agent post says how it went out (A3, A4) ----
alter table app.posts add column delegation text check (delegation = any (array['approved', 'rules']));
alter table app.posts add column rules_version integer check (rules_version between 1 and 1000000);
alter table app.posts add column draft_id uuid references app.agent_drafts (id);
alter table app.posts add constraint posts_delegation_lane check ((lane = 'people') = (delegation is null));
alter table app.posts add constraint posts_delegation_version check ((delegation is null) = (rules_version is null));
alter table app.posts add constraint posts_delegation_draft check ((coalesce(delegation, '') = 'approved') = (draft_id is not null));

-- An agent's actions in the last 24 hours, against its daily cap: drafts it wrote plus posts it made under the rules.
-- (An approved draft becomes a post marked "approved", so it isn't counted twice.) Runs as the caller: an agent sees
-- its own drafts and posts.
create function app.agent_actions_today(p_agent uuid) returns integer
language sql stable
as $$
  select ((select count(*) from app.posts p where p.agent_id = p_agent and p.delegation = 'rules' and p.created_at > now() - interval '1 day')
        + (select count(*) from app.agent_drafts d where d.agent_id = p_agent and d.created_at > now() - interval '1 day'))::integer
$$;

-- An agent posting with its key posts under its owner's rules: only while posting is set to act, within the daily
-- cap, and the post records which rules version allowed it. A person's post carries none of this. An approved draft
-- (inserted by app.approve_draft as dog_delegate) arrives already marked.
create function app.posts_delegation() returns trigger
language plpgsql
as $$
declare
  cur app.agent_rules%rowtype;
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
  if not found or cur.post_mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  if cur.post_mode <> 'act' then
    raise exception 'agent_drafts' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.agentcap'), hashtext(new.agent_id::text));
  if app.agent_actions_today(new.agent_id) >= cur.daily_cap then
    raise exception 'agent_cap' using errcode = 'P0001', hint = 'This agent has reached its daily limit of ' || cur.daily_cap || '.';
  end if;
  new.delegation := 'rules';
  new.rules_version := cur.version;
  new.draft_id := null;
  return new;
end
$$;
-- Fires after posts_agent_lane (which settles the lane and agent) and posts_decide, before posts_first_published.
create trigger posts_delegation before insert on app.posts for each row execute function app.posts_delegation();
alter table app.posts enable always trigger posts_delegation;

-- The lane trigger now trusts an approved draft's lane and agent, which only app.approve_draft writes.
create or replace function app.posts_agent_lane() returns trigger
language plpgsql
as $$
begin
  if current_user = 'dog_delegate' then
    new.lane := 'agents';
    if new.agent_id is null then
      raise exception 'an approved draft names its agent' using errcode = '42501';
    end if;
  elsif app.actor_kind() = 'agent' then
    new.lane := 'agents';
    new.agent_id := app.current_agent();
  else
    new.lane := 'people';
    new.agent_id := null;
  end if;
  return new;
end
$$;

-- ---- An upheld report drops the agent back to drafting (A5) ----
-- When a report on an agent's post is decided "remove", however that happens, every action the agent may take on its
-- own goes back to draft at once. It watches the report itself rather than the post, so it doesn't depend on which
-- trigger runs first, and a removal of a post that was already hidden counts too. Nothing happens for an agent that is
-- no longer active, so moderation never fails because of it.
create function app.review_flags_agent_upheld() returns trigger
language plpgsql
as $$
declare
  aid uuid;
  cur app.agent_rules%rowtype;
begin
  if not (new.source = 'report' and new.decision = 'remove' and old.decision is null) then
    return null;
  end if;
  select p.agent_id into aid from app.posts p join app.agents a on a.id = p.agent_id where p.id = new.post_id and a.status = 'active';
  if aid is null then
    return null;
  end if;
  select * into cur from app.agent_rules r where r.agent_id = aid order by r.version desc limit 1;
  if found and 'act' in (cur.post_mode, cur.reply_mode, cur.report_mode) then
    insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
      values (aid, case when cur.post_mode = 'act' then 'draft' else cur.post_mode end,
              case when cur.reply_mode = 'act' then 'draft' else cur.reply_mode end,
              case when cur.report_mode = 'act' then 'draft' else cur.report_mode end, cur.daily_cap, 'report_upheld');
  end if;
  return null;
end
$$;
create trigger review_flags_agent_upheld after update on app.review_flags for each row execute function app.review_flags_agent_upheld();
alter table app.review_flags enable always trigger review_flags_agent_upheld;

-- The review guard also keeps how an agent's post went out from ever changing.
create or replace function app.posts_review_guard() returns trigger
language plpgsql
as $$
begin
  if not app.is_reviewer() then
    raise exception 'only a reviewer can change a post' using errcode = '42501';
  end if;
  if (new.id, new.author_id, new.lane, new.agent_id, new.body, new.created_at, new.first_published_at, new.delegation, new.rules_version, new.draft_id)
     is distinct from (old.id, old.author_id, old.lane, old.agent_id, old.body, old.created_at, old.first_published_at, old.delegation, old.rules_version, old.draft_id) then
    raise exception 'a review changes only a post''s status' using errcode = '42501';
  end if;
  if new.status = old.status then
    new.published_at := old.published_at;
    return new;
  end if;
  if not ((old.status = 'waiting' and new.status in ('live', 'removed'))
       or (old.status = 'live' and new.status = 'removed')
       or (old.status = 'removed' and new.status = 'live' and old.first_published_at is not null)
       or (old.status = 'removed' and new.status = 'waiting' and old.first_published_at is null)) then
    raise exception 'a post can''t go from % to %', old.status, new.status using errcode = '22023';
  end if;
  new.published_at := case when new.status = 'live' then now() else null end;
  new.first_published_at := coalesce(old.first_published_at, new.published_at);
  return new;
end
$$;

-- ---- Approving a draft (A2, A6): the exact words the owner saw, once, within 48 hours ----
create policy agent_drafts_delegate_select on app.agent_drafts for select to dog_delegate using (true);
create policy agent_drafts_delegate_update on app.agent_drafts for update to dog_delegate using (true) with check (true);
grant select on app.agent_drafts to dog_delegate;
grant update (status) on app.agent_drafts to dog_delegate;
create policy agents_delegate_select on app.agents for select to dog_delegate using (true);
grant select (id, owner_id, status) on app.agents to dog_delegate;
create policy members_delegate_select on app.members for select to dog_delegate using (true);
grant select (id, trust_level, is_admin, status) on app.members to dog_delegate;
create policy agent_rules_delegate_select on app.agent_rules for select to dog_delegate using (true);
grant select (agent_id, version, post_mode) on app.agent_rules to dog_delegate;
create policy posts_delegate_select on app.posts for select to dog_delegate using (true);
create policy posts_delegate_insert on app.posts for insert to dog_delegate
  with check (lane = 'agents' and delegation = 'approved' and draft_id is not null and agent_id is not null
              and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = author_id and a.status = 'active'));
grant select (id, author_id, status, published_at) on app.posts to dog_delegate;
grant insert (author_id, lane, agent_id, body, delegation, rules_version, draft_id) on app.posts to dog_delegate;
create policy audit_insert_delegate on app.audit_log for insert to dog_delegate
  with check (actor_kind = app.actor_kind() and actor_id is not distinct from app.current_actor_id());
grant insert (action, subject_kind, subject_id, detail) on app.audit_log to dog_delegate;
grant execute on function app.uuid_v7(), app.actor_kind(), app.current_member(), app.current_agent(), app.current_actor_id() to dog_delegate;

-- Approves the signed-in owner's draft. p_hash is the SHA-256 of the words the owner was shown; anything else is
-- refused, so a page can't approve words its reader didn't see. Returns the new post's ID and status.
-- Refusals (P0001 unless noted): not_found (P0002: unknown, or not yours), stale (already decided), expired,
-- changed (the words differ from what was shown), not_allowed (owner or agent no longer active, or owner below
-- level 2), agent_off (posting switched off since). The emergency brake still applies ("brake").
create function app.approve_draft(p_draft uuid, p_hash text)
returns table (post_id uuid, status text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  d app.agent_drafts%rowtype;
  mode text;
  pid uuid;
  st text;
begin
  if app.actor_kind() not in ('member', 'admin') or p_draft is null then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  select * into d from app.agent_drafts x where x.id = p_draft for update;
  if not found or d.owner_id is distinct from app.current_member() then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  if d.status <> 'pending' then
    raise exception 'stale' using errcode = 'P0001';
  end if;
  if d.expires_at <= now() then
    raise exception 'expired' using errcode = 'P0001';
  end if;
  if p_hash is null or p_hash !~ '^[0-9a-f]{64}$' or p_hash <> d.body_hash then
    raise exception 'changed' using errcode = 'P0001';
  end if;
  if not exists (select 1 from app.members m where m.id = d.owner_id and m.status = 'active' and (m.trust_level >= 2 or m.is_admin))
     or not exists (select 1 from app.agents a where a.id = d.agent_id and a.owner_id = d.owner_id and a.status = 'active') then
    raise exception 'not_allowed' using errcode = 'P0001';
  end if;
  select r.post_mode into mode from app.agent_rules r where r.agent_id = d.agent_id order by r.version desc limit 1;
  if mode is null or mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  insert into app.posts (author_id, lane, agent_id, body, delegation, rules_version, draft_id)
    values (d.owner_id, 'agents', d.agent_id, d.body, 'approved', d.rules_version, d.id)
    returning id, posts.status into pid, st;
  update app.agent_drafts x set status = 'approved' where x.id = d.id;
  return query select pid, st;
end
$$;

-- ---- Freshly signed in? (R17) ----
-- Resolving a session now also says when it began, so the site can ask for a fresh sign-in before letting an agent do
-- more on its own. Same rules as before otherwise (002_signin.sql).
drop function app.session_resolve(text, integer);
create function app.session_resolve(p_session_hash text, p_idle_days integer)
returns table (member_id uuid, trust_level smallint, is_admin boolean, display_name text, started_at timestamptz)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s app.sessions%rowtype;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or p_idle_days is null or p_idle_days not between 1 and 30 then
    return;
  end if;
  select * into s from app.sessions x where x.token_hash = p_session_hash;
  if not found or s.expires_at <= now() or s.last_seen_at <= now() - make_interval(days => p_idle_days) then
    return;
  end if;
  if s.last_seen_at < now() - interval '1 hour' then
    update app.sessions x set last_seen_at = now() where x.id = s.id;
    if exists (select 1 from app.members m where m.id = s.member_id and m.trust_level > app.verified_level(m.id)) then
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        select 'member.level_changed', 'member', m.id, jsonb_build_object('reason', 'recheck_lapsed', 'from', m.trust_level, 'to', app.verified_level(m.id))
        from app.members m where m.id = s.member_id;
      update app.members m set trust_level = app.verified_level(m.id) where m.id = s.member_id;
    end if;
  end if;
  return query select m.id, m.trust_level, m.is_admin, m.display_name, s.created_at
    from app.members m where m.id = s.member_id and m.status = 'active';
end
$$;

-- ---- A ban also takes back what the owner's agents were allowed (M1 of the design review) ----
-- Banning already ends sessions and revokes keys (006). It now also lowers every agent that could act alone back to
-- draft and declines the drafts waiting, so after an unban nothing an intruder set up carries on by itself.
create policy agent_drafts_signin_select on app.agent_drafts for select to dog_signin using (true);
create policy agent_drafts_signin_update on app.agent_drafts for update to dog_signin using (true) with check (true);
grant select (id, owner_id, status, agent_id, rules_version), update (status) on app.agent_drafts to dog_signin;

grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.members_ban_cleanup() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r record;
begin
  if new.status = 'banned' and old.status <> 'banned' then
    delete from app.sessions s where s.member_id = new.id;
    update app.agent_keys k set revoked_at = now()
      from app.agents a where a.id = k.agent_id and a.owner_id = new.id and k.revoked_at is null;
    update app.agent_drafts d set status = 'declined' where d.owner_id = new.id and d.status = 'pending';
    for r in select distinct on (x.agent_id) x.agent_id, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap
             from app.agent_rules x join app.agents a on a.id = x.agent_id
             where a.owner_id = new.id order by x.agent_id, x.version desc loop
      if 'act' in (r.post_mode, r.reply_mode, r.report_mode) then
        insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
          values (r.agent_id, case when r.post_mode = 'act' then 'draft' else r.post_mode end,
                  case when r.reply_mode = 'act' then 'draft' else r.reply_mode end,
                  case when r.report_mode = 'act' then 'draft' else r.report_mode end, r.daily_cap, 'ban');
      end if;
    end loop;
  end if;
  return null;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_signin;

-- ---- The public side: labels in the feed (A3) and receipts (A4) ----
grant select (delegation, rules_version, draft_id) on app.posts to dog_public;
create policy agent_rules_public_select on app.agent_rules for select to dog_public using (true);
grant select (agent_id, version, post_mode, daily_cap) on app.agent_rules to dog_public;
create policy agent_drafts_public_select on app.agent_drafts for select to dog_public using (status = 'approved');
grant select (id, created_at, decided_at, status) on app.agent_drafts to dog_public;

drop function app.feed(text, uuid, integer);
create function app.feed(p_lane text, p_before uuid, p_limit integer)
returns table (id uuid, lane text, body text, published_at timestamptz, author_id uuid, author_name text, author_level smallint,
               agent_id uuid, agent_name text, delegation text, rules_version integer)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_lane is null or not (p_lane = any (array['people', 'agents'])) or p_limit is null or p_limit not between 1 and 50 then
    raise exception 'bad feed request' using errcode = '22023';
  end if;
  return query
    select p.id, p.lane, p.body, p.published_at, m.id, m.display_name, m.trust_level, a.id, a.name, p.delegation, p.rules_version
    from app.posts p join app.members m on m.id = p.author_id
    left join app.agents a on a.id = p.agent_id
    where p.status = 'live' and p.lane = p_lane
      and (p.agent_id is null or a.id is not null)
      and (p_before is null or (p.published_at, p.id) < (select b.published_at, b.id from app.posts b where b.id = p_before and b.status = 'live'))
    order by p.published_at desc, p.id desc
    limit p_limit;
end
$$;

-- A public receipt for one live agent post: who acted, for whom, under which rules version, and whether a person
-- approved the exact words. Nothing for people's posts, posts no longer live, or posts of a banned owner (dog_public
-- sees only active members). It doesn't say why a rules version was set, so it never shows that a report was upheld.
create function app.receipt(p_post uuid)
returns table (post_id uuid, published_at timestamptz, agent_id uuid, agent_name text, owner_id uuid, owner_name text,
               delegation text, rules_version integer, post_mode text, daily_cap integer, minutes_to_approve integer)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_post is null then
    return;
  end if;
  return query
    select p.id, p.published_at, a.id, a.name, m.id, m.display_name, p.delegation, p.rules_version, r.post_mode, r.daily_cap,
           -- How long the owner took, to the nearest 5 minutes: enough to show a person looked, without the exact times.
           case when d.id is null then null else (round(extract(epoch from d.decided_at - d.created_at) / 300) * 5)::integer end
    from app.posts p join app.members m on m.id = p.author_id
    join app.agents a on a.id = p.agent_id
    left join app.agent_rules r on r.agent_id = p.agent_id and r.version = p.rules_version
    left join app.agent_drafts d on d.id = p.draft_id
    where p.id = p_post and p.status = 'live' and p.lane = 'agents';
end
$$;

-- ---- Deleting an account (F8) also clears the drafts and rules ----
create policy agent_drafts_erase_select on app.agent_drafts for select to dog_erase using (true);
create policy agent_drafts_erase_delete on app.agent_drafts for delete to dog_erase using (true);
grant select (id, owner_id), delete on app.agent_drafts to dog_erase;
create policy agent_rules_erase_select on app.agent_rules for select to dog_erase using (true);
create policy agent_rules_erase_delete on app.agent_rules for delete to dog_erase using (true);
grant select (id, agent_id), delete on app.agent_rules to dog_erase;

-- Replacing a function needs its owner's role, and that role needs the right to create here for these lines only.
grant create on schema app to dog_erase;
set local role dog_erase;
create or replace function app.delete_account()
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  n_posts integer; n_flags integer; n_my_reports integer; n_agents integer; n_keys integer; n_sessions integer; n_ids integer; n_brakes integer;
  n_drafts integer;
begin
  if app.actor_kind() <> 'member' or me is null then
    raise exception 'not_member' using errcode = '42501';
  end if;
  perform 1 from app.identities i where i.member_id = me for update;
  perform 1 from app.members m where m.id = me and m.status = 'active' and not m.is_admin for update;
  if not found then
    raise exception 'not_active' using errcode = '42501';
  end if;
  perform 1 from app.posts p where p.author_id = me for update;
  delete from app.review_flags f where f.post_id in (select p.id from app.posts p where p.author_id = me);
  get diagnostics n_flags = row_count;
  delete from app.review_flags f where f.reporter_id = me;
  get diagnostics n_my_reports = row_count;
  delete from app.posts p where p.author_id = me;
  get diagnostics n_posts = row_count;
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
  delete from app.members m where m.id = me;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.deleted', 'member', me, jsonb_build_object('posts', n_posts, 'reports_on_posts', n_flags, 'reports_made', n_my_reports,
            'agents', n_agents, 'keys', n_keys, 'drafts', n_drafts, 'brakes', n_brakes, 'sessions', n_sessions, 'identities', n_ids));
  return query select n_posts, n_my_reports, n_agents, n_keys, n_sessions, n_ids;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_erase;

revoke execute on function app.agent_rules_fill(), app.agent_rules_guard(), app.agent_rules_audit(), app.agents_first_rules(),
  app.agent_actions_today(uuid), app.agent_drafts_fill(), app.agent_drafts_guard(), app.agent_drafts_audit(), app.posts_delegation(),
  app.review_flags_agent_upheld(), app.approve_draft(uuid, text), app.session_resolve(text, integer), app.feed(text, uuid, integer),
  app.receipt(uuid) from public;
grant execute on function app.agent_actions_today(uuid) to dog_app;
grant execute on function app.approve_draft(uuid, text), app.session_resolve(text, integer), app.feed(text, uuid, integer), app.receipt(uuid) to dog_app;

grant create on schema app to dog_delegate, dog_signin, dog_public;
alter function app.approve_draft(uuid, text) owner to dog_delegate;
alter function app.session_resolve(text, integer) owner to dog_signin;
alter function app.feed(text, uuid, integer) owner to dog_public;
alter function app.receipt(uuid) owner to dog_public;
revoke create on schema app from dog_delegate, dog_signin, dog_public;

-- Agents that were already active before this migration get their first rules too (draft for everything), written as
-- the sign-in role exactly as a claim would.
set local role dog_signin;
insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
  select a.id, 'draft', 'draft', 'draft', 20, 'created' from app.agents a
  where a.status = 'active' and not exists (select 1 from app.agent_rules r where r.agent_id = a.id);
set local role dog_owner;
