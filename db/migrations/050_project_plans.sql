-- 050 Project plans: milestones with target dates, and planned against verified work, for every project (Aaron, Nov 7:
-- "I want the detailed design that was provided"; "use the current project as a basis for the data needed. All of that
-- is already published"; "New data can be added as we go and the system should auto populate as more data comes in on
-- this project and as new projects join").
--   * app.work_milestones: a project's milestones. Each has a code (M1, M2, ...), a title, a target date and the first
--     target it was given: moving a date keeps the first one beside it (CHARTER section 1: "A slipped date keeps its
--     original target beside the new one"). One may be the project's release gate.
--   * Who sets them: a member's project, its poster (or the poster's agent) or an administrator; a project from this
--     repository, an administrator. At most 12 a project.
--   * No task is filed by hand: a task belongs to the first milestone whose first target is on or after the day it was
--     posted, so every new task and every new project lands in the plan as it arrives. A task posted after the last
--     target is unplanned until a later milestone is added.
--   * app.work_plan(project): scope (the size of the tasks posted), planned (the size due by each day: the tasks of the
--     milestones whose first target has come; a moved target never rewrites the plan), and verified (the size approved
--     with its receipt in a signed checkpoint), day by day; each milestone's share done; and the schedule figures:
--     variance and the schedule index (planned work only), the pace of the last seven days and the forecast against the
--     gate's first target. A pull request from this repository counts as verified on the day it was
--     merged, which is what its receipt attests (the repository's history was given receipts on Nov 6).
--   * The site's own build gets the milestones ROADMAP.md publishes, with their published targets: Release 1 (Oct 16);
--     PRs 12, 13, 15 and 16, Release 2's checks, notices, sign-in fixes and sub-agents (Nov 6); and Release 2 public,
--     every role working, the release gate (Nov 20).
--   * app.work_featured(): the project the Build page shows: this repository's own build.
--   * app.work_pr_changes(number): a merged pull request's additions, deletions and merge commit, as GitHub publishes
--     them and the module already keeps; the Build page's receipt shows them.

set local role dog_owner;

create table app.work_milestones (
  id uuid primary key default app.uuid_v7(),
  project_id uuid not null references app.work_projects (id) on delete cascade,
  code text not null check (char_length(code) <= 3 and code ~ '^M[1-9][0-9]?$'),
  title text not null check (char_length(title) between 3 and 80),
  first_target date not null,
  target date not null,
  gate boolean not null default false,
  source text not null check (source = any (array['member', 'roadmap'])),
  created_at timestamptz not null default now(),
  moved_at timestamptz,
  unique (project_id, code)
);
create index work_milestones_project on app.work_milestones (project_id, target);
create unique index work_milestones_one_gate on app.work_milestones (project_id) where gate;
alter table app.work_milestones enable row level security;
alter table app.work_milestones force row level security;
create policy work_milestones_work on app.work_milestones for all to dog_work using (true) with check (true);
grant select, insert, update on app.work_milestones to dog_work;
grant create on schema app to dog_work;

set local role dog_work;

-- Who may plan a project: its poster (a member, or the agent that posted it, or that agent's owner) or an administrator;
-- for a project from this repository, an administrator only.
create function app.work_plan_check(p_project uuid)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  p record;
  poster uuid;
begin
  select * into w from app.work_who();
  perform app.work_brake_check(w.member_id);
  select x.* into p from app.work_projects x where x.id = p_project and x.status = 'open';
  if p.id is null then raise exception 'no such project' using errcode = 'P0002'; end if;
  if w.is_admin then return; end if;
  if p.source = 'github' then
    raise exception 'work_own' using errcode = 'P0001', hint = 'Only an administrator plans a project from this repository.';
  end if;
  -- The poster: the member who posted it, or the owner of the agent that did. A project whose poster is gone has none,
  -- and only an administrator plans it (NULL never matches: the fresh review of Nov 7 found a stranger got through).
  poster := coalesce(p.poster_member, (select g.owner_id from app.agents g where g.id = p.poster_agent));
  if poster is null or poster is distinct from w.member_id then
    raise exception 'work_own' using errcode = 'P0001', hint = 'Only the project''s poster (or an administrator) plans its milestones.';
  end if;
end
$$;

-- A milestone, as the pages show it.
create function app.work_milestone_card(p_id uuid)
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select jsonb_build_object('id', m.id, 'code', m.code, 'title', m.title, 'target', m.target, 'first_target', m.first_target,
                            'gate', m.gate, 'moved', m.target <> m.first_target)
    from app.work_milestones m where m.id = p_id
$$;

-- Add a milestone: the next code, a title, a target within a year back and two years ahead, and whether it's the gate.
create function app.work_milestone_add(p_project uuid, p_title text, p_target date, p_gate boolean)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
  mid uuid;
begin
  perform app.work_plan_check(p_project);
  perform 1 from app.work_projects x where x.id = p_project for update;  -- two adds at once take turns (the cap, the gate)
  if p_title is null or char_length(btrim(p_title)) not between 3 and 80 or btrim(p_title) ~ '[[:cntrl:]]' then
    raise exception 'a milestone''s title is 3 to 80 characters on one line' using errcode = '22023';
  end if;
  if p_target is null or p_target < current_date - 365 or p_target > current_date + 730 then
    raise exception 'a target date is within a year back and two years ahead' using errcode = '22023';
  end if;
  select count(*) into n from app.work_milestones m where m.project_id = p_project;
  if n >= 12 then
    raise exception 'work_cap' using errcode = 'P0001', hint = 'A project has at most 12 milestones.';
  end if;
  if coalesce(p_gate, false) and exists (select 1 from app.work_milestones m where m.project_id = p_project and m.gate) then
    raise exception 'work_gate' using errcode = 'P0001', hint = 'This project already has a release gate.';
  end if;
  insert into app.work_milestones (project_id, code, title, first_target, target, gate, source)
    values (p_project, 'M' || (coalesce((select max(substr(m.code, 2)::integer) from app.work_milestones m where m.project_id = p_project), 0) + 1),
            btrim(p_title), p_target, p_target, coalesce(p_gate, false), 'member')
    returning id into mid;
  return app.work_milestone_card(mid);
end
$$;

-- Move a milestone's target. Its first target stays, and both show.
create function app.work_milestone_move(p_milestone uuid, p_target date)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  pid uuid;
begin
  select m.project_id into pid from app.work_milestones m where m.id = p_milestone;
  if pid is null then raise exception 'no such milestone' using errcode = 'P0002'; end if;
  perform app.work_plan_check(pid);
  if p_target is null or p_target < current_date - 365 or p_target > current_date + 730 then
    raise exception 'a target date is within a year back and two years ahead' using errcode = '22023';
  end if;
  update app.work_milestones set target = p_target, moved_at = now() where id = p_milestone;
  return app.work_milestone_card(p_milestone);
end
$$;

-- The plan of one project: its milestones, its days, and its figures (all sizes are task sizes: 1, 2, 3, 5 or 8). The
-- plan is the baseline: each milestone's first target. A moved target is shown beside it (the pills, gate_target), but
-- it never rewrites what was planned for a day (CHARTER section 1; the fresh review of Nov 7 found the first version did).
create function app.work_plan(p_project uuid)
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
           'share', case when coalesce(a.size, 0) > 0 then round(a.done_size::numeric / a.size, 4) end) order by m.first_target, m.code), '[]'::jsonb)
    into ms
    from app.work_milestones m
    left join (select x.milestone, sum(x.size) as size, coalesce(sum(x.size) filter (where x.done <= today), 0) as done_size,
                      count(*) as tasks, count(*) filter (where x.done <= today) as tasks_done
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

-- The project the Build page features: this repository's own build when it has a plan (a member can't take the page
-- over by planning their own project; the fresh review of Nov 7), else the most recently active open project with
-- milestones, else the most recently active open project.
create function app.work_featured()
returns uuid
language sql stable security definer set search_path = pg_catalog
as $$
  select p.id from app.work_projects p
   where p.status = 'open'
   order by (p.source = 'github' and p.github_milestone = 0 and exists (select 1 from app.work_milestones m where m.project_id = p.id)) desc,
            exists (select 1 from app.work_milestones m where m.project_id = p.id) desc, p.updated_at desc, p.id desc
   limit 1
$$;

-- A merged pull request's changes, as GitHub publishes them (the module keeps them from its GitHub reads).
create function app.work_pr_changes(p_number integer)
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select jsonb_build_object('number', g.number, 'additions', g.additions, 'deletions', g.deletions, 'merge_sha', g.merge_sha,
                            'merged_by', g.merged_by, 'merged_at', g.merged_at, 'base', g.base)
    from app.work_github_prs g where g.number = p_number and g.merged_at is not null
$$;

-- The site's own build: the milestones ROADMAP.md publishes, written once (running it again adds nothing).
create function app.work_roadmap_milestones()
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  pid uuid;
  n integer;
begin
  select p.id into pid from app.work_projects p where p.source = 'github' and p.github_milestone = 0;
  if pid is null then return 0; end if;
  insert into app.work_milestones (project_id, code, title, first_target, target, gate, source)
  select pid, x.code, x.title, x.target, x.target, x.gate, 'roadmap'
    from (values ('M1', 'Release 1: proposals', date '2026-10-16', false),
                 ('M2', 'Release 2''s checks, notices, sign-in fixes and sub-agents', date '2026-11-06', false),
                 ('M3', 'Release 2 public: every role working', date '2026-11-20', true)) x(code, title, target, gate)
   where not exists (select 1 from app.work_milestones m where m.project_id = pid)
  on conflict (project_id, code) do nothing;
  get diagnostics n = row_count;
  return n;
end
$$;

revoke execute on function app.work_plan_check(uuid), app.work_milestone_card(uuid), app.work_roadmap_milestones() from public;
revoke execute on function app.work_milestone_add(uuid, text, date, boolean), app.work_milestone_move(uuid, date), app.work_plan(uuid),
  app.work_featured(), app.work_pr_changes(integer) from public;
grant execute on function app.work_milestone_add(uuid, text, date, boolean), app.work_milestone_move(uuid, date), app.work_plan(uuid),
  app.work_featured(), app.work_pr_changes(integer) to dog_app;

select app.work_roadmap_milestones();

set local role dog_owner;
revoke create on schema app from dog_work;
