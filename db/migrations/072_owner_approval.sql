-- 072 Owner approval for agents' work (Aaron, Nov 21, 2026: "Owner approval and validation by the system is still
--   important"; Nov 22: "continue until the system is ready"). Until now an agent in draft mode was simply refused at
--   the work steps (067), and no agent could check or dispute work.
--
--   1. A draft agent's claim, submission, task, project or milestone becomes a request its owner sees on
--      /account/agents. Once the owner approves the exact request (its hash), the agent sends the same request again
--      with "Owner-Approval: <request id>" and it goes through, once, within 24 hours. The agent finishes the step with
--      its own key, so every check that applies to it still applies (its caps, its licence, the brake, JEVs).
--   2. Any agent may propose a check of work or a dispute of a pass. Its owner approves or declines it; on approval the
--      site carries it out as the owner, so a person stands behind every verdict and every dispute, as before.
--   3. Draft agents can no longer add or move milestones without that approval (RK153).

set local role dog_owner;
create table app.work_requests (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null references app.agents (id) on delete cascade,
  owner_id uuid not null references app.members (id) on delete cascade,
  route text not null check (route = any (array['claim', 'submit', 'tasks', 'projects', 'milestones', 'reschedule', 'check', 'dispute'])),
  body jsonb not null check (octet_length(body::text) <= 8000),
  body_hash text not null check (char_length(body_hash) = 64 and body_hash ~ '^[0-9a-f]+$'),
  summary text not null check (char_length(summary) between 1 and 600),
  status text not null default 'waiting' check (status = any (array['waiting', 'approved', 'declined', 'used', 'expired', 'done', 'failed'])),
  created_at timestamptz not null default now(),
  decided_at timestamptz,
  used_at timestamptz,
  result text check (char_length(result) <= 600)
);
create index work_requests_owner on app.work_requests (owner_id, created_at desc);
create index work_requests_agent on app.work_requests (agent_id, created_at desc);
alter table app.work_requests enable row level security;
alter table app.work_requests force row level security;
create policy work_requests_work on app.work_requests for all to dog_work using (true) with check (true);
grant select, insert, update, delete on app.work_requests to dog_work;
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- The agent (with its key) asks. At most 20 waiting a day per agent; nothing is done.
create function app.work_request_put(p_route text, p_body jsonb, p_hash text, p_summary text) returns uuid
language plpgsql security definer set search_path = pg_catalog as $$
declare ag uuid := app.current_agent(); own uuid; rid uuid;
begin
  if app.actor_kind() <> 'agent' or ag is null then raise exception 'only an agent asks its owner' using errcode = '42501'; end if;
  select g.owner_id into own from app.agents g where g.id = ag and g.status = 'active';
  if own is null then raise exception 'work_off' using errcode = 'P0001', hint = 'This agent isn''t active.'; end if;
  if (select count(*) from app.work_requests r where r.agent_id = ag and r.created_at > now() - interval '1 day') >= 20 then
    raise exception 'work_cap' using errcode = 'P0001', hint = 'At most 20 requests a day wait for your owner.';
  end if;
  update app.work_requests r set status = 'expired' where r.agent_id = ag and r.status in ('waiting', 'approved') and r.created_at < now() - interval '1 day';
  -- Kept 30 days, then gone (the fresh review, L4).
  delete from app.work_requests r where r.agent_id = ag and r.created_at < now() - interval '30 days';
  -- The same request, already waiting, is the one answered again: no second request, no second notice (M4).
  select r.id into rid from app.work_requests r where r.agent_id = ag and r.body_hash = p_hash and r.route = p_route and r.status = 'waiting'
     and r.created_at > now() - interval '1 day' limit 1;
  if rid is not null then return rid; end if;
  insert into app.work_requests (agent_id, owner_id, route, body, body_hash, summary) values (ag, own, p_route, p_body, p_hash, left(p_summary, 600)) returning id into rid;
  perform app.notify(own, 'work_submitted', 'Your agent asks you to approve a step', left(p_summary, 300), '/account/agents#work', 'agent', ag, 'work:request:' || rid);
  return rid;
end $$;

-- The owner's list: what their agents asked, newest first.
create function app.work_requests_mine() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'agent', r.agent_id, 'agent_name', g.name, 'route', r.route, 'body', r.body, 'hash', r.body_hash,
           'summary', r.summary, 'status', case when r.status in ('waiting', 'approved') and r.created_at < now() - interval '1 day' then 'expired' else r.status end,
           'created_at', r.created_at, 'result', r.result,
           -- The task the request is about, so the owner can look before deciding (the fresh review, M2).
           'task', coalesce(r.body ->> 'task', (select s.task_id::text from app.work_submissions s where s.id::text = r.body ->> 'submission'))) order by r.created_at desc), '[]'::jsonb)
    from (select * from app.work_requests x where x.owner_id = app.current_member() order by x.created_at desc limit 50) r
    join app.agents g on g.id = r.agent_id
   where app.actor_kind() in ('member', 'admin')
$$;

-- The owner decides the exact request (its hash). For a check or a dispute the site then carries it out as the owner;
-- anything else waits for the agent to send it again.
create function app.work_request_decide(p_id uuid, p_decision text, p_hash text) returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare r record;
begin
  if app.actor_kind() not in ('member', 'admin') then raise exception 'only the owner decides' using errcode = '42501'; end if;
  if p_decision is null or p_decision <> all (array['approve', 'decline']) then raise exception 'bad decision' using errcode = '22023'; end if;
  select * into r from app.work_requests x where x.id = p_id for update;
  if r.id is null or r.owner_id <> app.current_member() then raise exception 'not your agent''s request' using errcode = '42501'; end if;
  if r.status <> 'waiting' or r.created_at < now() - interval '1 day' then return jsonb_build_object('result', 'not_waiting'); end if;
  if p_hash is distinct from r.body_hash then raise exception 'work_changed' using errcode = 'P0001', hint = 'The request changed since you saw it; reload and look again.'; end if;
  update app.work_requests x set status = case when p_decision = 'approve' then 'approved' else 'declined' end, decided_at = now() where x.id = r.id;
  perform app.audit_add('work.request_' || p_decision, 'member', r.owner_id, jsonb_build_object('request', r.id, 'agent', r.agent_id, 'route', r.route), 'success');
  return jsonb_build_object('result', p_decision, 'route', r.route, 'body', r.body, 'agent', r.agent_id);
end $$;

-- The agent, sending an approved request again: one use, the same agent, route and body, within 24 hours. Marks it
-- used and lets the draft check pass for this transaction only.
create function app.work_request_use(p_id uuid, p_route text, p_hash text) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
declare r record;
begin
  if app.actor_kind() <> 'agent' then return false; end if;
  select * into r from app.work_requests x where x.id = p_id for update;
  if r.id is null or r.agent_id is distinct from app.current_agent() or r.status <> 'approved' or r.route <> p_route or r.body_hash <> p_hash
     or r.created_at < now() - interval '1 day' then
    return false;
  end if;
  update app.work_requests x set status = 'used', used_at = now() where x.id = r.id;
  perform set_config('app.owner_approved', r.id::text, true);
  return true;
end $$;

-- What happened, for the owner's list.
create function app.work_request_result(p_id uuid, p_ok boolean, p_result text) returns void
language plpgsql security definer set search_path = pg_catalog as $$
begin
  update app.work_requests x set status = case when p_ok then 'done' else 'failed' end, result = left(p_result, 600)
   where x.id = p_id and x.owner_id = app.current_member() and x.status = 'approved' and x.route in ('check', 'dispute');
end $$;

-- Whether the acting agent's owner's rules are in draft mode now (the work steps that commit ask the owner first).
create function app.work_agent_draft() returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce((select r.post_mode = 'draft' from app.agent_rules r where r.agent_id = app.current_agent() order by r.version desc limit 1), false)
   where app.actor_kind() = 'agent'
$$;

-- An agent asks about its own request.
create function app.work_request_status(p_id uuid) returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object('id', r.id, 'route', r.route, 'status', case when r.status in ('waiting', 'approved') and r.created_at < now() - interval '1 day' then 'expired' else r.status end,
           'decided_at', r.decided_at, 'result', r.result)
    from app.work_requests r where r.id = p_id and r.agent_id = app.current_agent()
$$;

revoke execute on function app.work_request_put(text, jsonb, text, text), app.work_requests_mine(), app.work_request_decide(uuid, text, text),
  app.work_request_use(uuid, text, text), app.work_request_result(uuid, boolean, text), app.work_request_status(uuid), app.work_agent_draft() from public;
grant execute on function app.work_request_put(text, jsonb, text, text), app.work_requests_mine(), app.work_request_decide(uuid, text, text),
  app.work_request_use(uuid, text, text), app.work_request_result(uuid, boolean, text), app.work_request_status(uuid), app.work_agent_draft() to dog_app;
reset role;
revoke create on schema app from dog_work;

-- ---- The draft check, now with the owner's approval ----
set local role dog_owner;
create or replace function app.work_action_rules() returns trigger
language plpgsql set search_path = pg_catalog as $$
declare mode text;
begin
  if new.agent_id is not null then
    select r.version, r.post_mode into new.rules_version, mode from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
    -- 072: the owner approved this exact step (app.work_request_use set it for this transaction only).
    -- The approval must be a request of this very agent, just used (the fresh review, M3).
    if mode = 'draft' and not exists (select 1 from app.work_requests q
         where q.id::text = coalesce(current_setting('app.owner_approved', true), '') and q.agent_id = new.agent_id and q.status = 'used'
           and q.used_at > now() - interval '1 minute') then
      raise exception 'work_draft' using errcode = 'P0001', hint = 'Your owner''s rules are in draft mode: this step is now a request for your owner to approve on /account/agents; send it again with "Owner-Approval: <request id>" once they do.';
    end if;
  end if;
  return new;
end $$;
reset role;
