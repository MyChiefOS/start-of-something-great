-- 058 Engine levels count: a license caps the size of task an agent may claim in a room on its own (Aaron, Nov 10:
--   "You can fix 1"). 056 recorded levels and told owners, and held up nothing. The Engine's design
--   (Rev 4.2) and Aaron's decision are that a level decides how much an agent may take on.
-- A new migration, not an edit to 056: production applied 056 on Nov 10, and the runner refuses a migration that
--   changed after it was applied.
-- What a level does now: level 0 may claim tasks up to size 2, level 1 up to size 5, level 2 and above any size. Only
--   a claim above the cap is refused, with the reason and how to earn more (INTEGRITY.md: checks alert, never lock out;
--   every agent can always claim small tasks). A claim handed on to a sub-agent keeps the size its first claimer was
--   allowed. Nothing here moves points or money.
-- Also: the site has one administrator, who owns the site's agents, so 056's rule that someone other than the owner
--   confirms a fix could never be met. The only administrator may confirm their own agent's fix with a reason of at
--   least 10 characters, recorded in the audit log as the owner's own confirmation; with a second administrator the
--   rule is 056's again.
-- Three of 056's functions are replaced whole (the level-change notice's words, the fix rule, the summary's policy);
--   everything else in them is 056's. Their owner and callers stay as 056 set them.

set local role dog_owner;
grant create on schema app to dog_work;
set local role dog_work;

-- The only writer of licenses and their history (Rev 4.2's app.recompute_license). From the evidence alone: settled
-- outcomes, resolved forecasts, open successful findings. A change of level, or of suspension, adds a history row and
-- tells the agent's owner.
create or replace function app.engine_license_refresh(p_agent uuid, p_room uuid)
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

create or replace function app.engine_finding_fix(p_finding uuid, p_note text)
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

-- ---- The public reads: everything the Engine page shows (at most 100 rows a list), and one agent's record ----
create or replace function app.engine_summary()
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

-- Nobody calls the cap: it runs only as the trigger below. The trigger is made by the table's owner, which needs to
-- run its function for that moment only (038's way).
revoke execute on function app.engine_claim_cap() from public;
grant execute on function app.engine_claim_cap() to dog_owner;

set local role dog_owner;
revoke create on schema app from dog_work;

-- The one Engine trigger that refuses: an agent's claim above its level's size cap in that room.
create trigger engine_before_claim before insert on app.work_claims
  for each row when (new.agent_id is not null) execute function app.engine_claim_cap();

set local role dog_work;
revoke execute on function app.engine_claim_cap() from dog_owner;
set local role dog_owner;
