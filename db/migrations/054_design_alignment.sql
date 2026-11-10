-- 054 The design alignment (Aaron, Nov 9: "Why don't the page align to design ... the design should align" and "Make a
-- large PR that has all of these items. Address it ALL in the 1 PR."; harness/PLAN.md, "Design alignment"). What the
-- pages built to his design need from the database:
--   * A project's task count, and its tasks a page at a time. 042's app.work_project put the list of its newest 100
--     tasks under the same key, "tasks", as the card's count, so the count was lost and the page read "108 of 0 tasks
--     approved", and the page drew every task at once (10,700 px). Now "task_count" is the count, "tasks" holds the
--     newest 25, and "next" is the cursor for the next 25 (app.work_project_tasks), as the Console pages.
--   * Each milestone's finish date in a project's plan ("done_on"), for the canvas's "Planned and actual dates".
--   * A merged pull request's task read "merged into main on 2026-11-09. 1798 lines changed.", and the public pages'
--     phone-number mask (api/_proposals.js) read the date and the count together as one 12-digit number, so the page
--     showed "merged into main on [number hidden] lines changed." 043's app.work_github_sync, the same but for "; "
--     in place of ". " (the mask never joins digits across ";"), and the tasks already written that way, rewritten.

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

-- 043's GitHub sync, the same but for the "; " in a merged pull request's description (see the header).
create or replace function app.work_github_sync(p jsonb)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  x jsonb;
  st record;
  pr record;
  proj uuid;
  rid uuid;
  tid uuid;
  cl record;
  added integer := 0;
  tasks integer := 0;
  closed integer := 0;
  sub uuid;
  title text;
  def_room uuid := (select r.id from app.work_rooms r where r.code = '15-0000');
begin
  if p is null or jsonb_typeof(p) <> 'object' or jsonb_array_length(coalesce(p -> 'prs', '[]')) > 100 or jsonb_array_length(coalesce(p -> 'issues', '[]')) > 100
     or jsonb_array_length(coalesce(p -> 'details', '[]')) > 100 then
    raise exception 'bad GitHub sync' using errcode = '22023';
  end if;
  -- The repository's own project (milestone 0), made on first use.
  insert into app.work_projects (title, description, room_id, source, github_milestone)
    values ('The site''s own build', 'Pull requests and issues in MyChiefOS/start-of-something-great, the public repository of this site, read through GitHub''s public API. A merged pull request is finished work; an open issue is an open task.',
            def_room, 'github', 0) on conflict do nothing;
  for x in select * from jsonb_array_elements(coalesce(p -> 'prs', '[]')) loop
    if (x ->> 'number') !~ '^[1-9][0-9]{0,6}$' or coalesce(x ->> 'author', '') !~ '^[a-z0-9-]{1,39}$' or x ->> 'state' <> all (array['open', 'closed']) then continue; end if;
    insert into app.work_github_prs (number, title, author, state, merged_at, base, merge_sha, refs, milestone, milestone_title, room_code, created_at)
      values ((x ->> 'number')::integer, left(coalesce(nullif(btrim(x ->> 'title'), ''), 'Pull request'), 140), x ->> 'author', x ->> 'state',
              (x ->> 'merged_at')::timestamptz, left(coalesce(x ->> 'base', ''), 100), case when x ->> 'merge_sha' ~ '^[0-9a-f]{40}$' then x ->> 'merge_sha' end,
              case when coalesce(x ->> 'refs', '') ~ '^[0-9,]*$' and char_length(x ->> 'refs') <= 400 then coalesce(x ->> 'refs', '') else '' end,
              case when x ->> 'milestone' ~ '^[1-9][0-9]{0,6}$' then (x ->> 'milestone')::integer end, left(x ->> 'milestone_title', 140),
              case when x ->> 'room' ~ '^[0-9]{2}-0000$' then x ->> 'room' end, (x ->> 'created_at')::timestamptz)
    on conflict (number) do update set title = excluded.title, state = excluded.state, merged_at = excluded.merged_at, base = excluded.base,
      merge_sha = excluded.merge_sha, refs = excluded.refs, milestone = excluded.milestone, milestone_title = excluded.milestone_title,
      room_code = excluded.room_code, seen_at = now();
    delete from app.work_github_codes c where c.pr_number = (x ->> 'number')::integer;
    insert into app.work_github_codes (pr_number, code_hash)
      select (x ->> 'number')::integer, h from jsonb_array_elements_text(coalesce(x -> 'codes', '[]')) h where h ~ '^[0-9a-f]{64}$' limit 20
      on conflict do nothing;
    added := added + 1;
  end loop;
  for x in select * from jsonb_array_elements(coalesce(p -> 'details', '[]')) loop
    if (x ->> 'number') !~ '^[1-9][0-9]{0,6}$' or (x ->> 'additions') !~ '^[0-9]{1,8}$' or (x ->> 'deletions') !~ '^[0-9]{1,8}$' then continue; end if;
    update app.work_github_prs g set additions = (x ->> 'additions')::integer, deletions = (x ->> 'deletions')::integer,
      merged_by = case when x ->> 'merged_by' ~ '^[a-z0-9-]{1,39}$' then x ->> 'merged_by' end, detail_at = now()
     where g.number = (x ->> 'number')::integer;
  end loop;
  -- Merged pull requests with their detail: finished work. A pull request whose description carries a live claim's
  -- code is that claim's submission; any other is submitted by its author, as the repository's history.
  for pr in select g.* from app.work_github_prs g where g.merged_at is not null and g.detail_at is not null and g.base = 'main'
             and not exists (select 1 from app.work_submissions s where s.pr_number = g.number and s.status not in ('failed', 'reversed'))
             and not exists (select 1 from app.work_tasks t where t.github_kind = 'pr' and t.github_number = g.number)
             order by g.number limit 100 loop
    select c.* into cl from app.work_claims c join app.work_github_codes k on k.code_hash = c.code_hash and k.pr_number = pr.number
     where c.status = 'active' limit 1;
    if cl.id is not null then
      update app.work_claims c set status = 'submitted' where c.id = cl.id;
      sub := app.work_record(cl.task_id, cl.id, case when cl.agent_id is null then 'member' else 'agent' end, cl.member_id, cl.agent_id, null,
                             case when cl.agent_id is not null then 'member:' || cl.member_id end, 'pr',
                             'https://github.com/MyChiefOS/start-of-something-great/pull/' || pr.number, null, pr.number, '', 0);
      continue;
    end if;
    if pr.milestone is not null then
      insert into app.work_projects (title, description, room_id, source, github_milestone)
        values (left(coalesce(pr.milestone_title, 'Milestone ' || pr.milestone), 140), 'A milestone in MyChiefOS/start-of-something-great, read through GitHub''s public API.',
                def_room, 'github', pr.milestone) on conflict do nothing;
    end if;
    select p2.id into proj from app.work_projects p2 where p2.source = 'github' and p2.github_milestone = coalesce(pr.milestone, 0);
    rid := coalesce((select r.id from app.work_rooms r where r.code = pr.room_code), def_room);
    insert into app.work_tasks (project_id, room_id, title, description, class, size, source, github_kind, github_number, github_author, status, created_at)
      values (proj, rid, pr.title, 'Pull request #' || pr.number || ' in this site''s repository, merged into main on '
              || to_char(pr.merged_at at time zone 'UTC', 'YYYY-MM-DD') || '; ' || (pr.additions + pr.deletions) || ' lines changed.',
              'either', app.work_size_band(pr.additions + pr.deletions), 'github', 'pr', pr.number, pr.author, 'submitted', pr.created_at)
      on conflict (github_kind, github_number) do nothing returning id into tid;
    if tid is null then continue; end if;
    perform app.work_record(tid, null, 'github', null, null, pr.author, null, 'pr', 'https://github.com/MyChiefOS/start-of-something-great/pull/' || pr.number,
                            null, pr.number, '', 0);
    update app.work_projects x2 set updated_at = now() where x2.id = proj;
    tasks := tasks + 1;
  end loop;
  -- Issues: open ones are open tasks; a closed issue's task closes if nobody is working on it.
  for x in select * from jsonb_array_elements(coalesce(p -> 'issues', '[]')) loop
    if (x ->> 'number') !~ '^[1-9][0-9]{0,6}$' or coalesce(x ->> 'author', '') !~ '^[a-z0-9-]{1,39}$' or x ->> 'state' <> all (array['open', 'closed']) then continue; end if;
    if x ->> 'state' = 'closed' then
      update app.work_tasks t set status = 'closed', updated_at = now() where t.github_kind = 'issue' and t.github_number = (x ->> 'number')::integer and t.status = 'open';
      if found then closed := closed + 1; end if;
      continue;
    end if;
    if exists (select 1 from app.work_tasks t where t.github_kind = 'issue' and t.github_number = (x ->> 'number')::integer) then
      update app.work_tasks t set title = left(coalesce(nullif(btrim(x ->> 'title'), ''), t.title), 140)
       where t.github_kind = 'issue' and t.github_number = (x ->> 'number')::integer and t.status = 'open';
      continue;
    end if;
    if x ->> 'milestone' ~ '^[1-9][0-9]{0,6}$' then
      insert into app.work_projects (title, description, room_id, source, github_milestone)
        values (left(coalesce(x ->> 'milestone_title', 'Milestone ' || (x ->> 'milestone')), 140), 'A milestone in MyChiefOS/start-of-something-great, read through GitHub''s public API.',
                def_room, 'github', (x ->> 'milestone')::integer) on conflict do nothing;
    end if;
    select p2.id into proj from app.work_projects p2 where p2.source = 'github'
      and p2.github_milestone = coalesce(case when x ->> 'milestone' ~ '^[1-9][0-9]{0,6}$' then (x ->> 'milestone')::integer end, 0);
    rid := coalesce((select r.id from app.work_rooms r where r.code = x ->> 'room'), def_room);
    title := left(coalesce(nullif(btrim(x ->> 'title'), ''), 'Issue'), 140);
    insert into app.work_tasks (project_id, room_id, title, description, class, size, source, github_kind, github_number, github_author, created_at)
      values (proj, rid, title, 'Issue #' || (x ->> 'number') || ' in this site''s repository. Claim it, open a pull request that names the issue (#'
              || (x ->> 'number') || ') and carries your claim''s code in its description, and submit it once it is merged into main.',
              'either', 2, 'github', 'issue', (x ->> 'number')::integer, x ->> 'author', coalesce((x ->> 'created_at')::timestamptz, now()))
      on conflict (github_kind, github_number) do nothing;
    tasks := tasks + 1;
  end loop;
  -- GitHub refused some of this run's reads (its rate limit): nothing changes; Aaron is told in-app, once a day.
  if coalesce(p ->> 'refused', '0') ~ '^[1-9][0-9]{0,2}$' then
    perform app.notify(null, 'alert', 'GitHub is limiting the work module''s reads', (p ->> 'refused') || ' of the work module''s reads from GitHub were refused (its rate limit). '
      || 'Pull requests and issues update on a later run; nothing else stops. A read-only GITHUB_TOKEN raises the limit.', '/build', null, null,
      'work:github-limit:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end if;
  -- Submissions that were waiting for GitHub's facts.
  for sub in select s.id from app.work_submissions s join app.work_github_prs g on g.number = s.pr_number
              where s.status = 'waiting' and (g.merged_at is not null or g.state = 'closed') limit 100 loop
    perform app.work_jevs_run(sub);
  end loop;
  return jsonb_build_object('prs', added, 'tasks', tasks, 'closed', closed);
end
$$;

-- The pull request tasks already written: only the site's own sentence, only that one character.
update app.work_tasks t
   set description = regexp_replace(t.description, '(merged into main on \d{4}-\d{2}-\d{2})\. (\d+ lines changed\.)$', '\1; \2')
 where t.source = 'github' and t.github_kind = 'pr'
   and t.description ~ '^Pull request #\d+ in this site''s repository, merged into main on \d{4}-\d{2}-\d{2}\. \d+ lines changed\.$';

revoke execute on function app.work_project_tasks(uuid, uuid) from public;
grant execute on function app.work_project_tasks(uuid, uuid) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
