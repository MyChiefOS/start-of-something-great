-- 056 The trust Engine, steps E1 to E3 (harness/PLAN.md, the Engine's order of Nov 7: before launch E1 licenses and
--   forecasts, E2 precedents and the immune system, E3 work orders), from Revision 4.2 of the Builder technical plan,
--   section 12 (Aaron's chat "Agent marketplaces research", Sep 29, 2026), on Postgres and our own code only (Aaron,
--   Nov 6: "We won't be adding know outside software or services"). The design note: design/engine-e1-e3.md.
--   * E1, licenses: each agent's level, 0 to 3, in each room (a room is the task type), from verified outcomes only: its
--     submissions there that are settled (passed with points final, failed, or reversed) on tasks not removed. The
--     measure is the 95% Wilson lower bound; levels 2 and 3 also need resolved forecasts and a Brier score (Rev 4.2's
--     thresholds, to confirm); level 4 is the organisation's to set, so it has no row and the climb stops at 3. One
--     function writes licenses, and every change goes into a history nobody can edit, with a notice to the owner.
--   * E1, forecasts: an agent, with its key, records its chance of success (basis points) for a task it has claimed,
--     before any work is submitted under the claim; one per claim; never edited; resolved once, by the first settled
--     verdict on the claim (held, failed, reversed, or the claim released or run out with nothing submitted; a claim
--     handed to a sub-agent closes it as handed, unscored).
--   * E2, precedents: an administrator records how a case in a room was decided (facts, decision, a reason of at least
--     10 characters); never edited; overturned once, by a newer one in the same room. Where a room has current
--     precedents, a forecast there cites at least one, or says none applies; a citation of an overturned precedent or
--     one from another room is refused.
--   * E2, the immune system: an administrator records an attack on an agent by OWASP agentic class (ASI01 to ASI10),
--     with its regression test (the vaccine). A successful one drops the agent's license in that room to 0 at once,
--     until an administrator who isn't the agent's owner confirms the fix. The vaccine is public once fixed.
--   * E3, work orders: an owner gives one of their agents a goal (verified task size) on a project, a budget of actions
--     (its claims and submissions there), a deadline and a rollback plan. Its state is worked out from the facts each
--     time: done, paused (spending more than 20 points ahead of progress, the budget spent, or the deadline passed;
--     to confirm) or active. Its maker or an administrator resumes it by adding budget or hours.
--   * What a level does (Aaron, Nov 10: "Okay, for 1"): it caps the size of task the agent may claim in that room on
--     its own: level 0 up to size 2, level 1 up to size 5, level 2 and up any size. Nothing is refused but a claim
--     above the cap, with the reason and how to earn more (INTEGRITY.md: checks alert, never lock out). A claim handed
--     on to a sub-agent keeps the size its first claimer was allowed. Nothing here moves points or money.
-- Everything runs as dog_work, the work module's narrow role, which already reads the work tables. The site's role
-- holds no right on any Engine table; it calls the functions, which check who is acting. The triggers on the work
-- tables catch their own errors, so a failure here never stops the work it follows (Aaron gets one alert a day).

set local role dog_owner;

-- ---- The license policy (Rev 4.2, section 12.1; to confirm). Level 4 is set by the organisation: no row yet. ----
create table app.engine_policy (
  id uuid primary key default app.uuid_v7(),
  level smallint not null unique check (level between 1 and 4),
  min_verified integer not null check (min_verified between 1 and 100000),
  min_lower_bound numeric(5,4) not null check (min_lower_bound between 0 and 1),
  min_forecasts integer not null check (min_forecasts between 0 and 100000),
  max_brier numeric(5,4) check (max_brier between 0 and 1)
);
insert into app.engine_policy (level, min_verified, min_lower_bound, min_forecasts, max_brier) values
  (1, 5, 0.50, 0, null), (2, 20, 0.80, 10, 0.15), (3, 50, 0.90, 30, 0.10);

-- ---- E1: licenses, their history, forecasts ----
create table app.engine_licenses (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null references app.agents (id) on delete cascade,
  room_id uuid not null references app.work_rooms (id),
  level smallint not null check (level between 0 and 4),
  verified integer not null check (verified >= 0),
  succeeded integer not null check (succeeded >= 0),
  lower_bound numeric(6,5) not null check (lower_bound between 0 and 1),
  forecasts integer not null check (forecasts >= 0),
  brier numeric(6,5) check (brier between 0 and 1),
  suspended boolean not null default false,
  computed_at timestamptz not null default now(),
  unique (agent_id, room_id),
  check (succeeded <= verified)
);
create index engine_licenses_level on app.engine_licenses (level desc, verified desc);

create table app.engine_license_history (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null references app.agents (id) on delete cascade,
  room_id uuid not null references app.work_rooms (id),
  old_level smallint check (old_level between 0 and 4),
  new_level smallint not null check (new_level between 0 and 4),
  reason text not null check (reason = any (array['evidence', 'suspended', 'fix_confirmed'])),
  verified integer not null check (verified >= 0),
  succeeded integer not null check (succeeded >= 0),
  lower_bound numeric(6,5) not null check (lower_bound between 0 and 1),
  forecasts integer not null check (forecasts >= 0),
  brier numeric(6,5) check (brier between 0 and 1),
  changed_at timestamptz not null default now()
);
create index engine_license_history_at on app.engine_license_history (changed_at desc, id desc);
create index engine_license_history_agent on app.engine_license_history (agent_id, changed_at desc);

create table app.engine_forecasts (
  id uuid primary key default app.uuid_v7(),
  claim_id uuid not null unique references app.work_claims (id) on delete cascade,
  task_id uuid not null references app.work_tasks (id) on delete cascade,
  room_id uuid not null references app.work_rooms (id),
  agent_id uuid not null references app.agents (id) on delete cascade,
  chance_bp integer not null check (chance_bp between 0 and 10000),
  no_precedent boolean not null default false,
  created_at timestamptz not null default now(),
  resolution text check (resolution = any (array['held', 'failed', 'reversed', 'released', 'expired', 'handed'])),
  submission_id uuid,
  resolved_at timestamptz,
  check ((resolution is null) = (resolved_at is null))
);
create index engine_forecasts_at on app.engine_forecasts (created_at desc, id desc);
create index engine_forecasts_agent on app.engine_forecasts (agent_id, room_id) where resolution is not null;

-- ---- E2: precedents, citations, findings ----
create table app.engine_precedents (
  id uuid primary key default app.uuid_v7(),
  room_id uuid not null references app.work_rooms (id),
  facts text not null check (char_length(facts) between 10 and 2000),
  decision text not null check (char_length(decision) between 3 and 300),
  reason text not null check (char_length(reason) between 10 and 1000),
  decided_by uuid not null,
  overturns uuid unique references app.engine_precedents (id),
  created_at timestamptz not null default now()
);
create index engine_precedents_room on app.engine_precedents (room_id, created_at desc);

create table app.engine_citations (
  id uuid primary key default app.uuid_v7(),
  forecast_id uuid not null references app.engine_forecasts (id) on delete cascade,
  precedent_id uuid not null references app.engine_precedents (id) on delete cascade,
  unique (forecast_id, precedent_id)
);
create index engine_citations_precedent on app.engine_citations (precedent_id);

create table app.engine_findings (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null references app.agents (id) on delete cascade,
  room_id uuid not null references app.work_rooms (id),
  attack_class text not null check (attack_class = any (array['ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05', 'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10'])),
  succeeded boolean not null,
  vaccine text not null check (char_length(vaccine) between 3 and 200),
  found_by uuid not null,
  found_at timestamptz not null default now(),
  fixed_at timestamptz,
  fixed_by uuid,
  fix_note text check (char_length(fix_note) <= 300),
  check ((fixed_at is null) = (fixed_by is null))
);
create index engine_findings_open on app.engine_findings (agent_id, room_id) where fixed_at is null and succeeded;
create index engine_findings_at on app.engine_findings (found_at desc, id desc);

-- ---- E3: work orders and their resumes ----
create table app.engine_orders (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null references app.agents (id) on delete cascade,
  project_id uuid not null references app.work_projects (id) on delete cascade,
  created_by uuid not null references app.members (id) on delete cascade,
  goal_size integer not null check (goal_size between 1 and 1000),
  budget integer not null check (budget between 1 and 10000),
  deadline timestamptz not null,
  rollback text not null check (char_length(rollback) between 10 and 1000),
  created_at timestamptz not null default now()
);
create index engine_orders_agent on app.engine_orders (agent_id, project_id);
create index engine_orders_maker on app.engine_orders (created_by, created_at);
create index engine_orders_at on app.engine_orders (created_at desc, id desc);

create table app.engine_order_resumes (
  id uuid primary key default app.uuid_v7(),
  order_id uuid not null references app.engine_orders (id) on delete cascade,
  member_id uuid not null,
  add_budget integer not null check (add_budget between 0 and 10000),
  add_hours integer not null check (add_hours between 0 and 2160),
  created_at timestamptz not null default now(),
  check (add_budget > 0 or add_hours > 0)
);
create index engine_order_resumes_order on app.engine_order_resumes (order_id);

-- ---- Row-level security: the work module's role only; the site's role has no right on any of these ----
do $rls$
declare
  t text;
begin
  foreach t in array array['engine_policy', 'engine_licenses', 'engine_license_history', 'engine_forecasts', 'engine_precedents',
    'engine_citations', 'engine_findings', 'engine_orders', 'engine_order_resumes'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('alter table app.%I force row level security', t);
    execute format('create policy %I on app.%I for all to dog_work using (true) with check (true)', t || '_work', t);
  end loop;
end
$rls$;
grant select on app.engine_policy to dog_work;
grant select, insert, update on app.engine_licenses to dog_work;
grant select, insert on app.engine_license_history, app.engine_precedents, app.engine_citations, app.engine_orders,
  app.engine_order_resumes to dog_work;
grant select, insert on app.engine_forecasts, app.engine_findings to dog_work;
grant update (resolution, submission_id, resolved_at) on app.engine_forecasts to dog_work;
grant update (fixed_at, fixed_by, fix_note) on app.engine_findings to dog_work;

-- ---- The guards: what Rev 4.2 says can't change, can't, for any role, the owner included ----
-- A row goes only with what it belongs to: an agent's account (F8), its claim or task. A precedent is never deleted
-- (Rev 4.2). During a cascade the parent row is already gone, so the test is plain.
create function app.engine_history_guard() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'DELETE' and not exists (select 1 from app.agents g where g.id = old.agent_id) then return old; end if;
  raise exception 'engine_history_append_only' using errcode = '42501';
end $$;

create function app.engine_forecasts_guard() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'DELETE' then
    if not exists (select 1 from app.work_claims c where c.id = old.claim_id) or not exists (select 1 from app.agents g where g.id = old.agent_id)
       or not exists (select 1 from app.work_tasks t where t.id = old.task_id) then
      return old;
    end if;
    raise exception 'engine_forecast_fixed' using errcode = '42501';
  end if;
  if (new.id, new.claim_id, new.task_id, new.room_id, new.agent_id, new.chance_bp, new.no_precedent, new.created_at)
     is distinct from (old.id, old.claim_id, old.task_id, old.room_id, old.agent_id, old.chance_bp, old.no_precedent, old.created_at) then
    raise exception 'engine_forecast_fixed' using errcode = '42501';
  end if;
  if old.resolution is not null then raise exception 'engine_forecast_resolved' using errcode = '42501'; end if;
  if new.resolution is null or current_user <> 'dog_work' then raise exception 'engine_forecast_resolution' using errcode = '42501'; end if;
  return new;
end $$;

create function app.engine_citations_guard() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'DELETE' and (not exists (select 1 from app.engine_forecasts f where f.id = old.forecast_id)
                           or not exists (select 1 from app.engine_precedents p where p.id = old.precedent_id)) then
    return old;
  end if;
  raise exception 'engine_citation_fixed' using errcode = '42501';
end $$;

create function app.engine_precedents_guard() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  raise exception 'engine_precedent_fixed' using errcode = '42501';
end $$;

create function app.engine_findings_guard() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'DELETE' then
    if not exists (select 1 from app.agents g where g.id = old.agent_id) then return old; end if;
    raise exception 'engine_finding_fixed' using errcode = '42501';
  end if;
  if (new.id, new.agent_id, new.room_id, new.attack_class, new.succeeded, new.vaccine, new.found_by, new.found_at)
     is distinct from (old.id, old.agent_id, old.room_id, old.attack_class, old.succeeded, old.vaccine, old.found_by, old.found_at) then
    raise exception 'engine_finding_fixed' using errcode = '42501';
  end if;
  if old.fixed_at is not null then raise exception 'engine_finding_already_fixed' using errcode = '42501'; end if;
  -- Only the Engine's own function confirms a fix (as dog_work), after its checks; never the owner directly.
  if new.fixed_at is null or not old.succeeded or current_user <> 'dog_work' then
    raise exception 'engine_finding_fix_only' using errcode = '42501';
  end if;
  return new;
end $$;

create function app.engine_orders_guard() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'DELETE' and (not exists (select 1 from app.agents g where g.id = old.agent_id)
                           or not exists (select 1 from app.work_projects p where p.id = old.project_id)
                           or not exists (select 1 from app.members m where m.id = old.created_by)) then
    return old;
  end if;
  raise exception 'engine_order_fixed' using errcode = '42501';
end $$;

create function app.engine_resumes_guard() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'DELETE' and not exists (select 1 from app.engine_orders o where o.id = old.order_id) then return old; end if;
  raise exception 'engine_resume_fixed' using errcode = '42501';
end $$;

create trigger engine_license_history_guard before update or delete on app.engine_license_history for each row execute function app.engine_history_guard();
create trigger engine_forecasts_guard before update or delete on app.engine_forecasts for each row execute function app.engine_forecasts_guard();
create trigger engine_citations_guard before update or delete on app.engine_citations for each row execute function app.engine_citations_guard();
create trigger engine_precedents_guard before update or delete on app.engine_precedents for each row execute function app.engine_precedents_guard();
create trigger engine_findings_guard before update or delete on app.engine_findings for each row execute function app.engine_findings_guard();
create trigger engine_orders_guard before update or delete on app.engine_orders for each row execute function app.engine_orders_guard();
create trigger engine_order_resumes_guard before update or delete on app.engine_order_resumes for each row execute function app.engine_resumes_guard();
alter table app.engine_license_history enable always trigger engine_license_history_guard;
alter table app.engine_forecasts enable always trigger engine_forecasts_guard;
alter table app.engine_citations enable always trigger engine_citations_guard;
alter table app.engine_precedents enable always trigger engine_precedents_guard;
alter table app.engine_findings enable always trigger engine_findings_guard;
alter table app.engine_orders enable always trigger engine_orders_guard;
alter table app.engine_order_resumes enable always trigger engine_order_resumes_guard;
revoke execute on function app.engine_history_guard(), app.engine_forecasts_guard(), app.engine_citations_guard(),
  app.engine_precedents_guard(), app.engine_findings_guard(), app.engine_orders_guard(), app.engine_resumes_guard() from public;

-- ---- The maths: plain functions, the same everywhere ----
-- The 95% Wilson lower bound (z = 1.96), as Rev 4.2 wrote it: 0 with no outcomes. 20 of 21 gives about 0.773.
create function app.engine_wilson_lb(k bigint, n bigint)
returns numeric
language sql immutable set search_path = pg_catalog
as $$
  select case when n is null or n <= 0 then 0::numeric else
    greatest(0::numeric, least(1::numeric,
      ((k::numeric / n) + 1.9208 / n - 1.96 * sqrt(((k::numeric / n) * (1 - k::numeric / n) + 0.9604 / n) / n)) / (1 + 3.8416 / n))) end
$$;
-- One forecast's Brier term: (chance - outcome)^2, the chance in basis points. The score is their mean: 0 is perfect,
-- 0.25 is always saying 50%.
create function app.engine_brier_term(chance_bp integer, held boolean)
returns numeric
language sql immutable set search_path = pg_catalog
as $$
  select power(chance_bp::numeric / 10000 - case when held then 1 else 0 end, 2)
$$;
-- The level the evidence earns: levels are climbed in order and the first unmet one stops the climb (Rev 4.2).
create function app.engine_level(p_verified bigint, p_succeeded bigint, p_forecasts bigint, p_brier numeric)
returns smallint
language plpgsql stable set search_path = pg_catalog
as $$
declare
  r record;
  lvl smallint := 0;
  lb numeric := app.engine_wilson_lb(p_succeeded, p_verified);
begin
  for r in select * from app.engine_policy order by level loop
    exit when r.level <> lvl + 1 or coalesce(p_verified, 0) < r.min_verified or lb < r.min_lower_bound
      or coalesce(p_forecasts, 0) < r.min_forecasts or (r.max_brier is not null and (p_brier is null or p_brier > r.max_brier));
    lvl := r.level;
  end loop;
  return lvl;
end
$$;
revoke execute on function app.engine_wilson_lb(bigint, bigint), app.engine_brier_term(integer, boolean),
  app.engine_level(bigint, bigint, bigint, numeric) from public;
grant execute on function app.engine_wilson_lb(bigint, bigint), app.engine_brier_term(integer, boolean),
  app.engine_level(bigint, bigint, bigint, numeric) to dog_work;

-- ---- Notices: the Engine's own kind, for owners; alerts for Aaron as before ----
-- The kinds are widened from what is there (042's way): any kind an earlier migration added stays.
do $$
declare
  kinds text[];
begin
  select array(select distinct m[1] from regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_]+)''', 'g') m) into kinds
    from pg_constraint c where c.conrelid = 'app.notices'::regclass and c.conname = 'notices_kind_check';
  kinds := array(select distinct k from unnest(kinds || array['engine']) k order by k);
  alter table app.notices drop constraint notices_kind_check;
  execute format('alter table app.notices add constraint notices_kind_check check (kind = any (array[%s]))',
                 (select string_agg(quote_literal(k), ', ' order by k) from unnest(kinds) k));
end
$$;
drop policy notices_work_insert on app.notices;
create policy notices_work_insert on app.notices for insert to dog_work
  with check (kind = any (array['work_claimed', 'work_submitted', 'work_decided', 'engine']) or (member_id is null and kind = 'alert'));
-- Administrators' Engine writes go into the audit log, as the one acting (053's helper, which pins the actor).
grant execute on function app.audit_add(text, text, uuid, jsonb, text) to dog_work;

grant create on schema app to dog_work;
set local role dog_work;

-- ---- Inside pieces (called by the functions and triggers below, never by the site) ----

-- An agent as the pages show it: its name and its owner's; null if it isn't claimed or its owner isn't active (a ban
-- hides a member's agents from the public, as it hides their posts).
create function app.engine_agent_card(p_agent uuid)
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select jsonb_build_object('id', g.id, 'name', g.name, 'status', g.status, 'owner', jsonb_build_object('id', m.id, 'name', m.display_name))
    from app.agents g join app.members m on m.id = g.owner_id
   where g.id = p_agent and g.status <> 'unclaimed' and m.status = 'active'
$$;

-- One alert a day to Aaron when an Engine step inside a work trigger fails; the work itself went through.
create function app.engine_trouble(p_state text)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  perform app.notify(null, 'alert', 'The trust Engine missed an update',
    'An Engine step failed after a change in the work module (code ' || left(coalesce(p_state, '?'), 5) || '). The work itself went through; '
    || 'the license, forecast or work order it touched is updated at its next change.', '/engine', null, null,
    'engine:trouble:' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
exception when others then
  null;
end
$$;

-- The only writer of licenses and their history (Rev 4.2's app.recompute_license). From the evidence alone: settled
-- outcomes, resolved forecasts, open successful findings. A change of level, or of suspension, adds a history row and
-- tells the agent's owner.
create function app.engine_license_refresh(p_agent uuid, p_room uuid)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n bigint;
  k bigint;
  fn bigint;
  br numeric;
  sus boolean;
  lb numeric;
  lvl smallint;
  prev app.engine_licenses;
  why text;
  hid uuid;
  g record;
  room text;
begin
  if p_agent is null or p_room is null then return; end if;
  select count(*), count(*) filter (where x.ok) into n, k from (
    select s.status = 'passed' as ok
      from app.work_submissions s join app.work_tasks t on t.id = s.task_id
     where s.worker_agent = p_agent and t.room_id = p_room and t.status <> 'removed'
       and (s.status = any (array['failed', 'reversed'])
            or (s.status = 'passed' and exists (select 1 from app.work_points p where p.submission_id = s.id and p.status = 'final')))) x;
  select count(*), avg(app.engine_brier_term(f.chance_bp, f.resolution = 'held')) into fn, br
    from app.engine_forecasts f
   where f.agent_id = p_agent and f.room_id = p_room and f.resolution is not null and f.resolution <> 'handed';
  sus := exists (select 1 from app.engine_findings x where x.agent_id = p_agent and x.room_id = p_room and x.succeeded and x.fixed_at is null);
  lb := round(app.engine_wilson_lb(k, n), 5);
  lvl := case when sus then 0 else app.engine_level(n, k, fn, br) end;
  br := round(br, 5);
  select * into prev from app.engine_licenses l where l.agent_id = p_agent and l.room_id = p_room for update;
  if prev.id is null then
    if n = 0 and fn = 0 and not sus then return; end if;
    insert into app.engine_licenses (agent_id, room_id, level, verified, succeeded, lower_bound, forecasts, brier, suspended)
      values (p_agent, p_room, lvl, n, k, lb, fn, br, sus)
      on conflict (agent_id, room_id) do nothing;
    select * into prev from app.engine_licenses l where l.agent_id = p_agent and l.room_id = p_room for update;
    -- A first row counts as a change from level 0, not suspended.
    prev.level := 0;
    prev.suspended := false;
  end if;
  update app.engine_licenses l set level = lvl, verified = n, succeeded = k, lower_bound = lb, forecasts = fn, brier = br,
         suspended = sus, computed_at = now()
   where l.id = prev.id;
  if prev.level = lvl and prev.suspended = sus then return; end if;
  why := case when sus then 'suspended' when prev.suspended then 'fix_confirmed' else 'evidence' end;
  insert into app.engine_license_history (agent_id, room_id, old_level, new_level, reason, verified, succeeded, lower_bound, forecasts, brier)
    values (p_agent, p_room, prev.level, lvl, why, n, k, lb, fn, br) returning id into hid;
  select a.name, a.owner_id into g from app.agents a where a.id = p_agent;
  select r.name into room from app.work_rooms r where r.id = p_room;
  if g.owner_id is not null then
    perform app.notify(g.owner_id, 'engine',
      case why when 'suspended' then 'Your agent''s license is suspended' when 'fix_confirmed' then 'Your agent''s license is back'
               else 'Your agent''s license changed' end,
      left(g.name, 80) || ' is now at level ' || lvl || ' in ' || room || ' (it was ' || prev.level || '). '
      || case why when 'suspended' then 'The red team recorded a successful attack on it there; the level stays 0 until the fix is confirmed. '
                  when 'fix_confirmed' then 'The fix was confirmed, so its level comes from its record again. '
                  else 'Levels come only from verified results and forecasts. ' end
      || 'Its level sets the largest task it may claim there on its own: size 2 at level 0, 5 at level 1, any at 2 and up.',
      '/engine', 'agent', p_agent, 'engine:license:' || hid::text);
  end if;
end
$$;

-- Resolve a claim's forecast, once, and recount its agent's license there.
create function app.engine_forecast_settle(p_claim uuid, p_resolution text, p_submission uuid)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  f record;
begin
  update app.engine_forecasts x set resolution = p_resolution, resolved_at = now(), submission_id = p_submission
   where x.claim_id = p_claim and x.resolution is null
   returning x.agent_id, x.room_id into f;
  if f.agent_id is not null then perform app.engine_license_refresh(f.agent_id, f.room_id); end if;
end
$$;

-- A work order's state, worked out from the facts every time (so nothing can set it): spend is the agent's claims and
-- submissions on the project's tasks since the order was made; progress is the verified size of its passed work there
-- (the size its audit confirmed). Paused: the budget spent, the deadline passed, or spend more than 20 points ahead
-- of progress (Rev 4.2's margin, to confirm).
create function app.engine_order_state(p_order uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  o app.engine_orders;
  b bigint;
  h bigint;
  n bigint;
  spend bigint;
  progress bigint;
  sp numeric;
  pp numeric;
  until timestamptz;
  st text;
  why text;
begin
  select * into o from app.engine_orders x where x.id = p_order;
  if o.id is null then return null; end if;
  select coalesce(sum(r.add_budget), 0), coalesce(sum(r.add_hours), 0), count(*) into b, h, n from app.engine_order_resumes r where r.order_id = o.id;
  b := o.budget + b;
  until := o.deadline + make_interval(hours => h::integer);
  select (select count(*) from app.work_claims c join app.work_tasks t on t.id = c.task_id
           where c.agent_id = o.agent_id and t.project_id = o.project_id and c.created_at >= o.created_at)
       + (select count(*) from app.work_submissions s join app.work_tasks t on t.id = s.task_id
           where s.worker_agent = o.agent_id and t.project_id = o.project_id and s.created_at >= o.created_at)
    into spend;
  select coalesce(sum(coalesce(s.final_size, t.size)), 0) into progress
    from app.work_submissions s join app.work_tasks t on t.id = s.task_id
   where s.worker_agent = o.agent_id and t.project_id = o.project_id and s.status = 'passed' and t.status <> 'removed'
     and s.created_at >= o.created_at;
  sp := round(100.0 * spend / b, 1);
  pp := least(100, round(100.0 * progress / o.goal_size, 1));
  if progress >= o.goal_size then st := 'done';
  elsif spend > b then st := 'paused'; why := 'budget';
  elsif now() > until then st := 'paused'; why := 'deadline';
  elsif sp - pp > 20 then st := 'paused'; why := 'ahead';
  else st := 'active';
  end if;
  return jsonb_build_object('state', st, 'why', why, 'goal', o.goal_size, 'progress', progress, 'progress_pct', pp,
    'budget', b, 'spend', spend, 'spend_pct', sp, 'deadline', until, 'resumes', n, 'margin', 20);
end
$$;

-- After the agent acts or its work is decided: each of its work orders that has just paused tells its maker, once per
-- pause and reason (a resume starts a new one).
create function app.engine_order_watch(p_agent uuid)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  o record;
  s jsonb;
begin
  for o in select x.id, x.created_by, g.name from app.engine_orders x join app.agents g on g.id = x.agent_id where x.agent_id = p_agent loop
    s := app.engine_order_state(o.id);
    if s ->> 'state' = 'paused' then
      perform app.notify(o.created_by, 'engine', 'A work order paused',
        left(o.name, 80) || '''s work order paused: ' || case s ->> 'why' when 'budget' then 'its budget of actions is spent'
          when 'deadline' then 'its deadline passed' else 'it is spending faster than it delivers verified work' end
        || ' (spent ' || (s ->> 'spend_pct') || '%, done ' || (s ->> 'progress_pct') || '%). Its work isn''t stopped; '
        || 'resume it on the Engine page by adding budget or hours, or let it go.',
        '/engine', 'work_order', o.id, 'engine:order:' || o.id::text || ':' || (s ->> 'resumes') || ':' || (s ->> 'why'));
    end if;
  end loop;
end
$$;

-- ---- The triggers on the work module's tables. Each catches its own errors: the work always goes through. ----
create function app.engine_on_submission()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  rid uuid;
begin
  begin
    if tg_op = 'UPDATE' and old.status is not distinct from new.status then return null; end if;
    if new.status = any (array['failed', 'reversed']) and new.claim_id is not null then
      perform app.engine_forecast_settle(new.claim_id, new.status, new.id);
    end if;
    select t.room_id into rid from app.work_tasks t where t.id = new.task_id;
    perform app.engine_license_refresh(new.worker_agent, rid);
    perform app.engine_order_watch(new.worker_agent);
  exception when others then
    perform app.engine_trouble(sqlstate);
  end;
  return null;
end
$$;

create function app.engine_on_points()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
begin
  begin
    if new.status = 'final' then
      select x.id, x.claim_id, x.status into s from app.work_submissions x where x.id = new.submission_id;
      if s.claim_id is not null and s.status = 'passed' then perform app.engine_forecast_settle(s.claim_id, 'held', s.id); end if;
    end if;
    perform app.engine_license_refresh(new.citizen_agent, new.room_id);
  exception when others then
    perform app.engine_trouble(sqlstate);
  end;
  return null;
end
$$;

create function app.engine_on_claim()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  begin
    if tg_op = 'UPDATE' and old.status is not distinct from new.status then return null; end if;
    -- A claim that ends with nothing submitted settles its forecast as a failure; once work is submitted, its verdict does.
    if new.status = any (array['released', 'expired']) and not exists (select 1 from app.work_submissions s where s.claim_id = new.id) then
      perform app.engine_forecast_settle(new.id, new.status, null);
    elsif new.status = 'handed' then
      perform app.engine_forecast_settle(new.id, 'handed', null);
    end if;
    if tg_op = 'INSERT' then perform app.engine_order_watch(new.agent_id); end if;
  exception when others then
    perform app.engine_trouble(sqlstate);
  end;
  return null;
end
$$;

-- ---- E1: an agent's forecast, with its citations (E2) ----
-- p_cites: a JSON array of precedent IDs (at most 10); p_none: "no precedent applies". Only for the agent's own live
-- claim, before anything is submitted under it; one per claim.
create function app.engine_forecast(p_task uuid, p_bp integer, p_cites jsonb, p_none boolean)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  c record;
  t record;
  cites uuid[];
  pid uuid;
  p record;
  fid uuid;
  current_n bigint;
begin
  select * into w from app.work_who();
  if w.kind <> 'agent' then
    raise exception 'engine_agents_only' using errcode = 'P0001', hint = 'Only an agent files a forecast, with its key, for a task it has claimed.';
  end if;
  if p_bp is null or p_bp < 0 or p_bp > 10000 then raise exception 'the chance is in basis points, 0 to 10000' using errcode = '22023'; end if;
  if p_cites is not null and (jsonb_typeof(p_cites) <> 'array' or jsonb_array_length(p_cites) > 10) then
    raise exception 'cites is a list of at most 10 precedent IDs' using errcode = '22023';
  end if;
  begin
    cites := array(select distinct (e #>> '{}')::uuid from jsonb_array_elements(coalesce(p_cites, '[]'::jsonb)) e);
  exception when invalid_text_representation then
    raise exception 'cites is a list of precedent IDs' using errcode = '22023';
  end;
  if coalesce(p_none, false) and cardinality(cites) > 0 then
    raise exception 'cite precedents or say none applies, not both' using errcode = '22023';
  end if;
  select * into c from app.work_claims x
   where x.task_id = p_task and x.agent_id = w.agent_id and x.status = any (array['active', 'submitted', 'done'])
   order by x.created_at desc limit 1 for update;
  if c.id is null then
    raise exception 'engine_no_claim' using errcode = 'P0001', hint = 'File a forecast for a task you have claimed, before you submit work for it.';
  end if;
  if c.status <> 'active' or exists (select 1 from app.work_submissions s where s.claim_id = c.id) then
    raise exception 'engine_late' using errcode = 'P0001', hint = 'A forecast comes before the work: this claim already has a submission.';
  end if;
  if exists (select 1 from app.engine_forecasts f where f.claim_id = c.id) then
    raise exception 'engine_already' using errcode = 'P0001', hint = 'This claim already has its forecast, and a forecast can''t be changed.';
  end if;
  select x.id, x.room_id, x.status into t from app.work_tasks x where x.id = p_task;
  -- Citations (E2): each must be a current precedent of the task's room.
  foreach pid in array cites loop
    select x.id, x.room_id, exists (select 1 from app.engine_precedents o where o.overturns = x.id) as overturned into p
      from app.engine_precedents x where x.id = pid;
    if p.id is null then
      raise exception 'engine_cite_unknown' using errcode = 'P0001', hint = 'A precedent you cited doesn''t exist.';
    elsif p.room_id <> t.room_id then
      raise exception 'engine_cite_room' using errcode = 'P0001', hint = 'A precedent you cited belongs to another room; cite only this room''s.';
    elsif p.overturned then
      raise exception 'engine_cite_overturned' using errcode = 'P0001', hint = 'A precedent you cited was overturned; cite the one that overturned it, if it applies.';
    end if;
  end loop;
  select count(*) into current_n from app.engine_precedents x
   where x.room_id = t.room_id and not exists (select 1 from app.engine_precedents o where o.overturns = x.id);
  if current_n > 0 and cardinality(cites) = 0 and not coalesce(p_none, false) then
    raise exception 'engine_cite_needed' using errcode = 'P0001',
      hint = 'This room has precedents: cite at least one that applies, or say none applies.';
  end if;
  insert into app.engine_forecasts (claim_id, task_id, room_id, agent_id, chance_bp, no_precedent)
    values (c.id, p_task, t.room_id, w.agent_id, p_bp, coalesce(p_none, false) and current_n > 0) returning id into fid;
  insert into app.engine_citations (forecast_id, precedent_id) select fid, x from unnest(cites) x;
  perform app.audit_add('engine.forecast', 'forecast', fid, jsonb_build_object('chance_bp', p_bp, 'cites', cardinality(cites),
    'no_precedent', coalesce(p_none, false) and current_n > 0));
  return jsonb_build_object('forecast', fid, 'claim', c.id, 'task', p_task, 'chance_bp', p_bp, 'cites', to_jsonb(cites),
    'no_precedent', coalesce(p_none, false) and current_n > 0, 'precedents_in_room', current_n);
end
$$;

-- ---- E2: precedents, by an administrator ----
create function app.engine_precedent_add(p_room text, p_facts text, p_decision text, p_reason text, p_overturns uuid)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  rid uuid;
  o record;
  pid uuid;
begin
  if app.actor_kind() is distinct from 'admin' then
    raise exception 'engine_admin_only' using errcode = 'P0001', hint = 'Only an administrator sets a precedent.';
  end if;
  select r.id into rid from app.work_rooms r where r.code = p_room;
  if rid is null then raise exception 'no room has that code' using errcode = '22023'; end if;
  if p_overturns is not null then
    select x.id, x.room_id into o from app.engine_precedents x where x.id = p_overturns;
    if o.id is null then raise exception 'engine_unknown_precedent' using errcode = 'P0001', hint = 'No precedent has that ID.'; end if;
    if o.room_id <> rid then
      raise exception 'engine_overturn_room' using errcode = 'P0001', hint = 'A precedent is overturned only by one in its own room.';
    end if;
    if exists (select 1 from app.engine_precedents x where x.overturns = o.id) then
      raise exception 'engine_overturned_already' using errcode = 'P0001', hint = 'That precedent was already overturned; overturn the one that replaced it.';
    end if;
  end if;
  insert into app.engine_precedents (room_id, facts, decision, reason, decided_by, overturns)
    values (rid, p_facts, p_decision, p_reason, app.current_member(), p_overturns) returning id into pid;
  perform app.audit_add('engine.precedent', 'precedent', pid, jsonb_build_object('room', p_room, 'overturns', p_overturns));
  return jsonb_build_object('precedent', pid, 'room', p_room, 'overturns', p_overturns);
end
$$;

-- ---- E2: the immune system: findings recorded, and fixes confirmed, by an administrator for the red team ----
create function app.engine_finding_add(p_agent uuid, p_room text, p_class text, p_succeeded boolean, p_vaccine text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  rid uuid;
  g record;
  fid uuid;
begin
  if app.actor_kind() is distinct from 'admin' then
    raise exception 'engine_admin_only' using errcode = 'P0001', hint = 'Only an administrator records a finding, for the red team.';
  end if;
  select r.id into rid from app.work_rooms r where r.code = p_room;
  if rid is null then raise exception 'no room has that code' using errcode = '22023'; end if;
  if p_succeeded is null then raise exception 'say whether the attack succeeded' using errcode = '22023'; end if;
  select a.id, a.owner_id, a.name into g from app.agents a where a.id = p_agent and a.status <> 'unclaimed';
  if g.id is null then raise exception 'engine_unknown_agent' using errcode = 'P0001', hint = 'No claimed agent has that ID.'; end if;
  insert into app.engine_findings (agent_id, room_id, attack_class, succeeded, vaccine, found_by)
    values (g.id, rid, p_class, p_succeeded, p_vaccine, app.current_member()) returning id into fid;
  perform app.audit_add('engine.finding', 'finding', fid, jsonb_build_object('agent', g.id, 'room', p_room, 'class', p_class, 'succeeded', p_succeeded));
  if p_succeeded then perform app.engine_license_refresh(g.id, rid); end if;
  return jsonb_build_object('finding', fid, 'agent', g.id, 'room', p_room, 'class', p_class, 'succeeded', p_succeeded,
    'license', (select l.level from app.engine_licenses l where l.agent_id = g.id and l.room_id = rid));
end
$$;

create function app.engine_finding_fix(p_finding uuid, p_note text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  f record;
begin
  if app.actor_kind() is distinct from 'admin' then
    raise exception 'engine_admin_only' using errcode = 'P0001', hint = 'Only an administrator confirms a fix, for the red team.';
  end if;
  select x.id, x.agent_id, x.room_id, x.succeeded, x.fixed_at, g.owner_id into f
    from app.engine_findings x join app.agents g on g.id = x.agent_id where x.id = p_finding for update of x;
  if f.id is null then raise exception 'engine_unknown_finding' using errcode = 'P0001', hint = 'No finding has that ID.'; end if;
  if not f.succeeded or f.fixed_at is not null then
    raise exception 'engine_not_open' using errcode = 'P0001', hint = 'Only an open, successful attack has a fix to confirm.';
  end if;
  -- The one who fixes an agent is its owner; they can't confirm their own fix (Rev 4.2: not the people who fixed it),
  -- unless no other administrator exists (Aaron, Nov 10: the site has one), and then only with a reason of at least 10
  -- characters, recorded in the audit log as the owner's own confirmation.
  if f.owner_id = app.current_member() then
    if exists (select 1 from app.members m where m.is_admin and m.id <> f.owner_id) then
      raise exception 'engine_fixer' using errcode = 'P0001', hint = 'The agent''s owner fixes it, so another administrator confirms the fix.';
    end if;
    if char_length(btrim(coalesce(p_note, ''))) < 10 then
      raise exception 'engine_fixer' using errcode = 'P0001', hint = 'You are the only administrator: confirm your own agent''s fix with a reason of at least 10 characters.';
    end if;
  end if;
  update app.engine_findings x set fixed_at = now(), fixed_by = app.current_member(), fix_note = nullif(p_note, '') where x.id = f.id;
  perform app.audit_add('engine.fixed', 'finding', f.id, jsonb_build_object('agent', f.agent_id, 'by_owner', f.owner_id = app.current_member()));
  perform app.engine_license_refresh(f.agent_id, f.room_id);
  return jsonb_build_object('finding', f.id, 'fixed', true,
    'license', (select l.level from app.engine_licenses l where l.agent_id = f.agent_id and l.room_id = f.room_id));
end
$$;

-- ---- E3: work orders, by the agent's owner; resumed by its maker or an administrator ----
create function app.engine_order_add(p_agent uuid, p_project uuid, p_goal integer, p_budget integer, p_hours integer, p_rollback text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  g record;
  pj record;
  oid_ uuid;
  x record;
begin
  select * into w from app.work_who();
  if w.kind <> 'member' then
    raise exception 'engine_people_only' using errcode = 'P0001', hint = 'An agent''s owner makes its work orders, signed in on the site.';
  end if;
  if p_goal is null or p_goal < 1 or p_goal > 1000 then raise exception 'the goal is a verified size of 1 to 1000' using errcode = '22023'; end if;
  if p_budget is null or p_budget < 1 or p_budget > 10000 then raise exception 'the budget is 1 to 10000 actions' using errcode = '22023'; end if;
  if p_hours is null or p_hours < 1 or p_hours > 2160 then raise exception 'the deadline is 1 to 2160 hours away' using errcode = '22023'; end if;
  select a.id, a.owner_id, a.status into g from app.agents a where a.id = p_agent;
  if g.id is null or g.owner_id is distinct from w.member_id then
    raise exception 'engine_not_owner' using errcode = 'P0001', hint = 'You make work orders only for your own agents.';
  end if;
  if g.status <> 'active' then raise exception 'engine_agent_inactive' using errcode = 'P0001', hint = 'That agent isn''t active.'; end if;
  select p.id, p.status into pj from app.work_projects p where p.id = p_project;
  if pj.id is null or pj.status <> 'open' then
    raise exception 'engine_unknown_project' using errcode = 'P0001', hint = 'No open project has that ID.';
  end if;
  -- One member's orders are counted one at a time, so parallel requests can't pass the cap.
  perform pg_advisory_xact_lock(hashtextextended('engine:order:' || w.member_id::text, 0));
  if (select count(*) from app.engine_orders o where o.created_by = w.member_id and o.created_at > now() - interval '24 hours') >= 10 then
    raise exception 'engine_order_cap' using errcode = 'P0001', hint = 'At most 10 work orders a day.';
  end if;
  for x in select o.id from app.engine_orders o where o.agent_id = p_agent and o.project_id = p_project loop
    if app.engine_order_state(x.id) ->> 'state' <> 'done' then
      raise exception 'engine_order_open' using errcode = 'P0001', hint = 'This agent already has a work order on this project that isn''t done: resume it instead.';
    end if;
  end loop;
  insert into app.engine_orders (agent_id, project_id, created_by, goal_size, budget, deadline, rollback)
    values (p_agent, p_project, w.member_id, p_goal, p_budget, now() + make_interval(hours => p_hours), p_rollback) returning id into oid_;
  perform app.audit_add('engine.order', 'work_order', oid_, jsonb_build_object('agent', p_agent, 'project', p_project, 'goal', p_goal,
    'budget', p_budget, 'hours', p_hours));
  return jsonb_build_object('order', oid_) || app.engine_order_state(oid_);
end
$$;

create function app.engine_order_resume(p_order uuid, p_budget integer, p_hours integer)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  o record;
begin
  select * into w from app.work_who();
  if w.kind <> 'member' then
    raise exception 'engine_people_only' using errcode = 'P0001', hint = 'A work order is resumed by the person who made it, or an administrator.';
  end if;
  if coalesce(p_budget, 0) < 0 or coalesce(p_budget, 0) > 10000 or coalesce(p_hours, 0) < 0 or coalesce(p_hours, 0) > 2160 then
    raise exception 'add 0 to 10000 actions and 0 to 2160 hours' using errcode = '22023';
  end if;
  if coalesce(p_budget, 0) = 0 and coalesce(p_hours, 0) = 0 then
    raise exception 'a resume adds budget, hours or both' using errcode = '22023';
  end if;
  select x.id, x.created_by into o from app.engine_orders x where x.id = p_order;
  if o.id is null then raise exception 'engine_unknown_order' using errcode = 'P0001', hint = 'No work order has that ID.'; end if;
  if o.created_by <> w.member_id and not w.is_admin then
    raise exception 'engine_not_maker' using errcode = 'P0001', hint = 'Only the person who made a work order, or an administrator, resumes it.';
  end if;
  insert into app.engine_order_resumes (order_id, member_id, add_budget, add_hours) values (o.id, w.member_id, coalesce(p_budget, 0), coalesce(p_hours, 0));
  perform app.audit_add('engine.resume', 'work_order', o.id, jsonb_build_object('budget', coalesce(p_budget, 0), 'hours', coalesce(p_hours, 0)));
  return jsonb_build_object('order', o.id) || app.engine_order_state(o.id);
end
$$;

-- ---- The public reads: everything the Engine page shows (at most 100 rows a list), and one agent's record ----
create function app.engine_summary()
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  with lic as (
    select l.*, app.engine_agent_card(l.agent_id) as agent, r.code, r.name as room_name
      from app.engine_licenses l join app.work_rooms r on r.id = l.room_id),
  fc as (
    select f.*, app.engine_agent_card(f.agent_id) as agent, r.code, r.name as room_name, t.title, t.status as task_status
      from app.engine_forecasts f join app.work_rooms r on r.id = f.room_id join app.work_tasks t on t.id = f.task_id),
  pr as (
    select p.*, r.code, r.name as room_name, (select o.id from app.engine_precedents o where o.overturns = p.id) as overturned_by
      from app.engine_precedents p join app.work_rooms r on r.id = p.room_id),
  fi as (
    select x.*, app.engine_agent_card(x.agent_id) as agent, r.code, r.name as room_name
      from app.engine_findings x join app.work_rooms r on r.id = x.room_id),
  od as (
    select o.*, app.engine_agent_card(o.agent_id) as agent, p.title as project_title, p.status as project_status
      from app.engine_orders o join app.work_projects p on p.id = o.project_id)
  select jsonb_build_object(
    'generated_at', now(),
    'policy', jsonb_build_object('levels', (select jsonb_agg(jsonb_build_object('level', p.level, 'min_verified', p.min_verified,
        'min_lower_bound', p.min_lower_bound, 'min_forecasts', p.min_forecasts, 'max_brier', p.max_brier) order by p.level) from app.engine_policy p),
      'shown_from', jsonb_build_object('lower_bound', 5, 'brier', 10), 'order_margin', 20, 'to_confirm', true,
      'size_cap', jsonb_build_object('0', 2, '1', 5, '2', 8, '3', 8),
      'holds_up', 'claims above the level''s size cap in that room; every agent can always claim small tasks; changes are told to the owner'),
    'counts', jsonb_build_object(
      'licenses', (select count(*) from lic where lic.agent is not null),
      'levels', (select coalesce(jsonb_object_agg(q.level, q.n), '{}'::jsonb) from (select lic.level, count(*) as n from lic where lic.agent is not null group by lic.level) q),
      'suspended', (select count(*) from lic where lic.agent is not null and lic.suspended),
      'forecasts', (select count(*) from fc where fc.agent is not null),
      'forecasts_open', (select count(*) from fc where fc.agent is not null and fc.resolution is null),
      'precedents', (select count(*) from pr),
      'precedents_current', (select count(*) from pr where pr.overturned_by is null),
      'findings', (select count(*) from fi where fi.agent is not null),
      'findings_open', (select count(*) from fi where fi.agent is not null and fi.succeeded and fi.fixed_at is null),
      'orders', (select count(*) from od where od.agent is not null and od.project_status <> 'removed')),
    'licenses', coalesce((select jsonb_agg(jsonb_build_object('agent', q.agent, 'room', jsonb_build_object('code', q.code, 'name', q.room_name),
        'level', q.level, 'suspended', q.suspended, 'verified', jsonb_build_object('k', q.succeeded, 'n', q.verified),
        'lower_bound', case when q.verified >= 5 then q.lower_bound end,
        'forecasts', jsonb_build_object('n', q.forecasts, 'brier', case when q.forecasts >= 10 then q.brier end),
        'computed_at', q.computed_at) order by q.level desc, q.verified desc, q.computed_at desc)
      from (select * from lic where lic.agent is not null order by lic.level desc, lic.verified desc, lic.computed_at desc limit 100) q), '[]'::jsonb),
    'changes', coalesce((select jsonb_agg(jsonb_build_object('agent', q.agent, 'room', jsonb_build_object('code', q.code, 'name', q.room_name),
        'old_level', q.old_level, 'new_level', q.new_level, 'reason', q.reason, 'verified', jsonb_build_object('k', q.succeeded, 'n', q.verified),
        'forecasts', q.forecasts, 'at', q.changed_at) order by q.changed_at desc, q.id desc)
      from (select h.*, app.engine_agent_card(h.agent_id) as agent, r.code, r.name as room_name
              from app.engine_license_history h join app.work_rooms r on r.id = h.room_id
             where app.engine_agent_card(h.agent_id) is not null order by h.changed_at desc, h.id desc limit 50) q), '[]'::jsonb),
    'forecasts', coalesce((select jsonb_agg(jsonb_build_object('id', q.id, 'agent', q.agent,
        'task', jsonb_build_object('id', q.task_id, 'title', case when q.task_status <> 'removed' then q.title end),
        'room', jsonb_build_object('code', q.code, 'name', q.room_name), 'chance_bp', q.chance_bp,
        'cites', coalesce((select jsonb_agg(c.precedent_id order by c.precedent_id) from app.engine_citations c where c.forecast_id = q.id), '[]'::jsonb),
        'no_precedent', q.no_precedent, 'created_at', q.created_at, 'resolution', q.resolution, 'resolved_at', q.resolved_at)
        order by q.created_at desc, q.id desc)
      from (select * from fc where fc.agent is not null order by fc.created_at desc, fc.id desc limit 100) q), '[]'::jsonb),
    'calibration', coalesce((select jsonb_agg(jsonb_build_object('agent', q.agent, 'resolved', q.n, 'held', q.k,
        'brier', case when q.n >= 10 then round(q.b, 4) end) order by q.n desc)
      from (select app.engine_agent_card(f.agent_id) as agent, count(*) as n, count(*) filter (where f.resolution = 'held') as k,
                   avg(app.engine_brier_term(f.chance_bp, f.resolution = 'held')) as b
              from app.engine_forecasts f where f.resolution is not null and f.resolution <> 'handed'
             group by f.agent_id having app.engine_agent_card(f.agent_id) is not null order by count(*) desc limit 100) q), '[]'::jsonb),
    'precedents', coalesce((select jsonb_agg(jsonb_build_object('id', q.id, 'room', jsonb_build_object('code', q.code, 'name', q.room_name),
        'facts', q.facts, 'decision', q.decision, 'reason', q.reason, 'created_at', q.created_at, 'overturns', q.overturns,
        'overturned_by', q.overturned_by, 'cited', (select count(*) from app.engine_citations c where c.precedent_id = q.id))
        order by q.created_at desc, q.id desc)
      from (select * from pr order by pr.created_at desc, pr.id desc limit 100) q), '[]'::jsonb),
    'findings', coalesce((select jsonb_agg(jsonb_build_object('id', q.id, 'agent', q.agent, 'room', jsonb_build_object('code', q.code, 'name', q.room_name),
        'attack_class', q.attack_class, 'succeeded', q.succeeded, 'found_at', q.found_at, 'fixed_at', q.fixed_at,
        'vaccine', case when q.fixed_at is not null or not q.succeeded then q.vaccine end) order by q.found_at desc, q.id desc)
      from (select * from fi where fi.agent is not null order by fi.found_at desc, fi.id desc limit 100) q), '[]'::jsonb),
    'orders', coalesce((select jsonb_agg(jsonb_build_object('id', q.id, 'agent', q.agent, 'project', jsonb_build_object('id', q.project_id, 'title', q.project_title),
        'rollback', q.rollback, 'created_at', q.created_at) || app.engine_order_state(q.id) order by q.created_at desc, q.id desc)
      from (select * from od where od.agent is not null and od.project_status <> 'removed' order by od.created_at desc, od.id desc limit 100) q), '[]'::jsonb))
$$;

-- One agent's record: its licenses in every room, their history, its forecasts, findings and work orders.
create function app.engine_agent(p_agent uuid)
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select case when app.engine_agent_card(p_agent) is null then null else jsonb_build_object(
    'agent', app.engine_agent_card(p_agent),
    'licenses', coalesce((select jsonb_agg(jsonb_build_object('room', jsonb_build_object('code', r.code, 'name', r.name), 'level', l.level,
        'suspended', l.suspended, 'verified', jsonb_build_object('k', l.succeeded, 'n', l.verified),
        'lower_bound', case when l.verified >= 5 then l.lower_bound end,
        'forecasts', jsonb_build_object('n', l.forecasts, 'brier', case when l.forecasts >= 10 then l.brier end), 'computed_at', l.computed_at)
        order by r.ord)
      from app.engine_licenses l join app.work_rooms r on r.id = l.room_id where l.agent_id = p_agent), '[]'::jsonb),
    'changes', coalesce((select jsonb_agg(jsonb_build_object('room', q.code, 'old_level', q.old_level, 'new_level', q.new_level, 'reason', q.reason,
        'verified', jsonb_build_object('k', q.succeeded, 'n', q.verified), 'forecasts', q.forecasts, 'at', q.changed_at) order by q.changed_at desc, q.id desc)
      from (select h.*, r.code from app.engine_license_history h join app.work_rooms r on r.id = h.room_id
             where h.agent_id = p_agent order by h.changed_at desc, h.id desc limit 100) q), '[]'::jsonb),
    'forecasts', coalesce((select jsonb_agg(jsonb_build_object('id', q.id, 'task', q.task_id, 'room', q.code, 'chance_bp', q.chance_bp,
        'no_precedent', q.no_precedent, 'created_at', q.created_at, 'resolution', q.resolution, 'resolved_at', q.resolved_at) order by q.created_at desc, q.id desc)
      from (select f.*, r.code from app.engine_forecasts f join app.work_rooms r on r.id = f.room_id
             where f.agent_id = p_agent order by f.created_at desc, f.id desc limit 100) q), '[]'::jsonb),
    'findings', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'room', r.code, 'attack_class', x.attack_class, 'succeeded', x.succeeded,
        'found_at', x.found_at, 'fixed_at', x.fixed_at, 'vaccine', case when x.fixed_at is not null or not x.succeeded then x.vaccine end)
        order by x.found_at desc)
      from app.engine_findings x join app.work_rooms r on r.id = x.room_id where x.agent_id = p_agent), '[]'::jsonb),
    'orders', coalesce((select jsonb_agg(jsonb_build_object('id', o.id, 'project', o.project_id, 'created_at', o.created_at) || app.engine_order_state(o.id)
        order by o.created_at desc)
      from app.engine_orders o join app.work_projects p on p.id = o.project_id where o.agent_id = p_agent and p.status <> 'removed'), '[]'::jsonb)) end
$$;

-- ---- What a level does: the size of task an agent may claim in a room on its own (Aaron, Nov 10) ----
-- Before an agent's claim is made: refused, with the reason, if the task is larger than its level allows in that room.
-- A hand-off to a sub-agent, at any depth, is not capped again: the task's size was allowed when its first claimer
-- claimed it, and a hand-off only passes that claim down its own tree (the review of fix 1, finding 2).
create function app.engine_claim_cap()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  t record;
  lvl integer;
  cap smallint;
begin
  if new.handed_from is not null then return new; end if;
  select x.size, x.room_id, r.code into t from app.work_tasks x join app.work_rooms r on r.id = x.room_id where x.id = new.task_id;
  select l.level into lvl from app.engine_licenses l where l.agent_id = new.agent_id and l.room_id = t.room_id;
  cap := case when coalesce(lvl, 0) >= 2 then 8 when lvl = 1 then 5 else 2 end;
  if t.size > cap then
    raise exception 'work_license' using errcode = 'P0001', hint = 'This agent''s license in ' || t.code || ' is level ' || coalesce(lvl, 0)
      || ', which allows tasks up to size ' || cap || '; this one is size ' || t.size || '. Verified work in this room raises the level.';
  end if;
  return new;
end
$$;

-- Who may call what: the site's role calls the reads and the writes (which check who is acting); the rest nobody.
revoke execute on function app.engine_agent_card(uuid), app.engine_trouble(text), app.engine_license_refresh(uuid, uuid),
  app.engine_forecast_settle(uuid, text, uuid), app.engine_order_state(uuid), app.engine_order_watch(uuid),
  app.engine_on_submission(), app.engine_on_points(), app.engine_on_claim(), app.engine_claim_cap(),
  app.engine_forecast(uuid, integer, jsonb, boolean), app.engine_precedent_add(text, text, text, text, uuid),
  app.engine_finding_add(uuid, text, text, boolean, text), app.engine_finding_fix(uuid, text),
  app.engine_order_add(uuid, uuid, integer, integer, integer, text), app.engine_order_resume(uuid, integer, integer),
  app.engine_summary(), app.engine_agent(uuid) from public;
grant execute on function app.engine_forecast(uuid, integer, jsonb, boolean), app.engine_precedent_add(text, text, text, text, uuid),
  app.engine_finding_add(uuid, text, text, boolean, text), app.engine_finding_fix(uuid, text),
  app.engine_order_add(uuid, uuid, integer, integer, integer, text), app.engine_order_resume(uuid, integer, integer),
  app.engine_summary(), app.engine_agent(uuid) to dog_app;

-- The triggers below are made by the tables' owner, which needs to run their functions for that moment only (038's way).
grant execute on function app.engine_on_submission(), app.engine_on_points(), app.engine_on_claim(), app.engine_claim_cap() to dog_owner;

set local role dog_owner;
revoke create on schema app from dog_work;

-- ---- The triggers on the work module's tables (after each change, never refusing it; and the size cap before a claim) ----
create trigger engine_after_submission after insert or update of status on app.work_submissions
  for each row when (new.worker_agent is not null) execute function app.engine_on_submission();
create trigger engine_after_points after update of status on app.work_points
  for each row when (new.citizen_agent is not null and old.status is distinct from new.status) execute function app.engine_on_points();
create trigger engine_after_claim after insert or update of status on app.work_claims
  for each row when (new.agent_id is not null) execute function app.engine_on_claim();
-- The one trigger that refuses: an agent's claim above its level's size cap in that room (Aaron, Nov 10).
create trigger engine_before_claim before insert on app.work_claims
  for each row when (new.agent_id is not null) execute function app.engine_claim_cap();

-- ---- The record so far: every agent's settled outcomes on the site today ----
set local role dog_work;
revoke execute on function app.engine_on_submission(), app.engine_on_points(), app.engine_on_claim(), app.engine_claim_cap() from dog_owner;
do $backfill$
declare
  x record;
begin
  for x in select distinct s.worker_agent as agent, t.room_id as room
             from app.work_submissions s join app.work_tasks t on t.id = s.task_id
            where s.worker_agent is not null loop
    perform app.engine_license_refresh(x.agent, x.room);
  end loop;
end
$backfill$;
set local role dog_owner;
