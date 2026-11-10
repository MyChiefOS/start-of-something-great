-- 054 The design alignment (Aaron, Nov 9: "Why don't the page align to design ... the design should align" and "Make a
-- large PR that has all of these items. Address it ALL in the 1 PR."; harness/PLAN.md, "Design alignment"). What the
-- pages built to his design need from the database:
--   * A project's task count, and its tasks a page at a time. 042's app.work_project put the list of its newest 100
--     tasks under the same key, "tasks", as the card's count, so the count was lost and the page read "108 of 0 tasks
--     approved", and the page drew every task at once (10,700 px). Now "task_count" is the count, "tasks" holds the
--     newest 25, and "next" is the cursor for the next 25 (app.work_project_tasks), as the Console pages.
--   * Each milestone's finish date in a project's plan ("done_on"), for the canvas's "Planned and actual dates".

set local role dog_owner;
grant create on schema app to dog_work;
set local role dog_work;

-- One page of a project's tasks, newest first: 25, before the task named (its id), and the cursor for the next page.
create function app.work_project_tasks(p_project uuid, p_before uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  rows uuid[];
  more boolean;
begin
  if not exists (select 1 from app.work_projects x where x.id = p_project and x.status <> 'removed') then
    return null;
  end if;
  select coalesce(array_agg(q.id order by q.id desc), '{}') into rows from (
    select t.id from app.work_tasks t
     where t.project_id = p_project and t.status <> 'removed' and (p_before is null or t.id < p_before)
     order by t.id desc limit 26) q;
  more := coalesce(array_length(rows, 1), 0) > 25;
  if more then rows := rows[1:25]; end if;
  return jsonb_build_object(
    'tasks', coalesce((select jsonb_agg(app.work_card(r.id) order by r.id desc) from unnest(rows) as r(id)), '[]'::jsonb),
    'next', case when more then rows[25] end);
end
$$;

create or replace function app.work_project(p_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  p record;
  page jsonb;
begin
  select * into p from app.work_projects x where x.id = p_id and x.status <> 'removed';
  if p.id is null then return null; end if;
  page := app.work_project_tasks(p_id, null);
  return app.work_project_card(p_id) || jsonb_build_object('description', p.description, 'generated_at', now(),
    'task_count', (select count(*) from app.work_tasks t where t.project_id = p.id and t.status <> 'removed'),
    'tasks', page -> 'tasks', 'next', page -> 'next',
    'latest', (select jsonb_build_object('task', app.work_card(s.task_id), 'worker', app.work_display(case when s.worker_kind = 'member' then s.worker_member end, s.worker_agent, s.worker_github),
                                         'status', s.status, 'created_at', s.created_at, 'note', s.note)
               from app.work_submissions s join app.work_tasks t on t.id = s.task_id where t.project_id = p.id order by s.created_at desc limit 1));
end
$$;

-- 050's plan, the same but for each milestone's finish date ("done_on"), for the project page's "Planned and actual dates"
-- (Aaron's chart canvas of Nov 7).
create or replace function app.work_plan(p_project uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  p record;
  today date := (now() at time zone 'utc')::date;
  anchored bigint := app.work_anchored_through();
  sz integer[];
  ad date[];
  dn date[];
  mi uuid[];
  d0 date;
  d1 date;
  ms jsonb;
  days jsonb;
  gate date;
  gate_now date;
  scope integer;
  verified integer;
  verified_planned integer;
  planned integer;
  recent integer;
  unplanned integer;
  pace numeric;
  fc date;
begin
  select x.* into p from app.work_projects x where x.id = p_project and x.status <> 'removed';
  if p.id is null then return null; end if;
  -- Each task once: its size (the audit's confirmed size once passed), the day it was posted, the day its work was done
  -- (approved, with its receipt in a signed checkpoint; a merged pull request on the day it was merged, which its receipt
  -- attests) and its milestone: the first whose first target is on or after the day it was posted.
  select coalesce(array_agg(q.size order by q.id), '{}'), coalesce(array_agg(q.added order by q.id), '{}'),
         coalesce(array_agg(q.done order by q.id), '{}'), coalesce(array_agg(q.milestone order by q.id), '{}')
    into sz, ad, dn, mi
    from (select t.id,
                 coalesce((select s.final_size::integer from app.work_submissions s where s.task_id = t.id and s.status = 'passed' and s.final_size is not null
                            order by s.decided_at desc limit 1), t.size::integer) as size,
                 (t.created_at at time zone 'utc')::date as added,
                 case when t.status = 'approved' and t.approved_seq is not null and t.approved_seq < anchored
                      then (least(t.approved_at, (select g.merged_at from app.work_github_prs g where t.github_kind = 'pr' and g.number = t.github_number)) at time zone 'utc')::date end as done,
                 (select m.id from app.work_milestones m where m.project_id = p.id and m.first_target >= (t.created_at at time zone 'utc')::date
                   order by m.first_target, m.code limit 1) as milestone
            from app.work_tasks t where t.project_id = p.id and t.status not in ('removed', 'closed')) q;
  select coalesce(sum(x.size), 0), coalesce(sum(x.size) filter (where x.done <= today), 0),
         coalesce(sum(x.size) filter (where x.done <= today and x.milestone is not null), 0),
         coalesce(sum(x.size) filter (where x.done > today - 7 and x.done <= today), 0), coalesce(sum(x.size) filter (where x.milestone is null), 0)
    into scope, verified, verified_planned, recent, unplanned
    from unnest(sz, ad, dn, mi) x(size, added, done, milestone);
  select coalesce(sum(x.size), 0) into planned
    from unnest(sz, mi) x(size, milestone) join app.work_milestones m on m.id = x.milestone where m.first_target <= today;
  select coalesce(min(m.first_target) filter (where m.gate), max(m.first_target)),
         coalesce(min(m.target) filter (where m.gate), max(m.target))
    into gate, gate_now from app.work_milestones m where m.project_id = p.id;
  pace := recent / 7.0;
  -- What's left at the last seven days' pace, in whole days (exact: left * 7 / recent, not through the rounded pace).
  if scope > verified and recent > 0 then fc := today + ceil((scope - verified) * 7.0 / recent)::integer; end if;
  select coalesce(jsonb_agg(app.work_milestone_card(m.id) || jsonb_build_object(
           'size', coalesce(a.size, 0), 'done_size', coalesce(a.done_size, 0), 'tasks', coalesce(a.tasks, 0), 'tasks_done', coalesce(a.tasks_done, 0),
           'share', case when coalesce(a.size, 0) > 0 then round(a.done_size::numeric / a.size, 4) end,
           -- 054: the day it was finished (its last task done), once every task in it is done; the canvas's actual date.
           'done_on', case when coalesce(a.tasks, 0) > 0 and a.tasks_done = a.tasks then a.last_done end) order by m.first_target, m.code), '[]'::jsonb)
    into ms
    from app.work_milestones m
    left join (select x.milestone, sum(x.size) as size, coalesce(sum(x.size) filter (where x.done <= today), 0) as done_size,
                      count(*) as tasks, count(*) filter (where x.done <= today) as tasks_done, max(x.done) filter (where x.done <= today) as last_done
                 from unnest(sz, ad, dn, mi) x(size, added, done, milestone) group by x.milestone) a on a.milestone = m.id
   where m.project_id = p.id;
  -- The days: from a week before the first task or first target to a week after the last target, the forecast or today;
  -- at most 400, and never more than a year back. Each line is a running sum of what each day added (one pass, so the
  -- cost grows with days plus tasks, not days times tasks); anything before the first day counts on the first day.
  select least((select min(x.added) from unnest(ad) x(added)), (select min(m.first_target) - 7 from app.work_milestones m where m.project_id = p.id), today) into d0;
  d0 := greatest(d0, today - 365);
  d1 := least(greatest((select max(greatest(m.target, m.first_target)) from app.work_milestones m where m.project_id = p.id), fc, today) + 7, d0 + 399);
  select coalesce(jsonb_agg(jsonb_build_object('day', s.d, 'scope', s.sc, 'planned', s.pl, 'verified', case when s.d <= today then s.ve end) order by s.d), '[]'::jsonb)
    into days
    from (select g.d,
                 (sum(coalesce(a.s, 0)) over (order by g.d))::integer as sc,
                 (sum(coalesce(b.s, 0)) over (order by g.d))::integer as pl,
                 (sum(coalesce(v.s, 0)) over (order by g.d))::integer as ve
            from (select x::date as d from generate_series(d0, d1, interval '1 day') x) g
            left join (select greatest(x.added, d0) as d, sum(x.size) as s from unnest(sz, ad) x(size, added) group by 1) a on a.d = g.d
            left join (select greatest(m.first_target, d0) as d, sum(x.size) as s from unnest(sz, mi) x(size, milestone)
                         join app.work_milestones m on m.id = x.milestone group by 1) b on b.d = g.d
            left join (select greatest(x.done, d0) as d, sum(x.size) as s from unnest(sz, dn) x(size, done) where x.done is not null group by 1) v on v.d = g.d) s;
  return jsonb_build_object('project', app.work_project_card(p.id), 'today', today, 'milestones', ms, 'days', days,
    'figures', jsonb_build_object('scope', scope, 'planned', planned, 'verified', verified, 'verified_planned', verified_planned,
      'variance', verified_planned - planned,
      'index', case when planned > 0 then round(verified_planned::numeric / planned, 2) end,
      'left', scope - verified, 'pace', round(pace, 2), 'forecast', fc, 'gate', gate, 'gate_target', gate_now,
      'days_to_gate', gate_now - today, 'slip_days', fc - gate,
      'need', case when gate_now > today then round((scope - verified)::numeric / (gate_now - today), 2) end,
      'unplanned', unplanned, 'tasks', cardinality(sz), 'tasks_done', (select count(*) from unnest(dn) x(done) where x.done <= today)),
    'generated_at', now());
end
$$;

revoke execute on function app.work_project_tasks(uuid, uuid) from public;
grant execute on function app.work_project_tasks(uuid, uuid) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
