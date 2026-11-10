-- 055 GitHub's facts come only from GitHub (RISKS.md RK140, and the facts RK135's gate reads; harness/FACTS.md, Nov 10,
--   "The order of the fix"; harness/STANDARDS.md gap 4, OWASP A01, CWE-862).
-- Since 042, app.work_github_sync was open to the site's role (dog_app) and checked no actor, so whoever held that role
-- (a leaked site login, or code running in any site function) could record a pull request GitHub never saw as merged
-- into main, credited to any login, and JEVs's rules then passed it as finished work, with points. Now:
--   * The pull request and issue facts come only from GitHub. The "GitHub facts" workflow
--     (.github/workflows/github-facts.yml) reads them from GitHub's API inside GitHub and sends them to the Supabase
--     function dog-github, which accepts only that workflow on main, proved by GitHub's identity token (the same check as
--     the database runner and the JEVs gate, supabase/functions/_shared/github-oidc.mjs). It records them acting as
--     dog_ghsync, a narrow role made here: no sign-in, no password, no table rights of its own, the right to run these two
--     functions and nothing else. It takes the role inside its own transaction, as the JEVs gate takes dog_jevs.
--   * The site's role can no longer run app.work_github_sync or app.work_github_wanted, and both refuse any caller but
--     dog_ghsync (the role in force when they are called, which the site's login can never switch to).
--   * A merged pull request passes by rule only when GitHub's own read of it says Aaron's account merged it, matched by
--     its GitHub ID (304218593, MyChiefOS, as 028 and 029 know it), which a rename doesn't change: rule W14. Merged by
--     anyone else, or with who merged it not yet read from GitHub, it goes to a person; nothing fails for it. Third Look
--     takes only pull requests whose merge GitHub credits to that account. The approval stays labelled with the merger's
--     login, as 042 does ("github:<login>", by "merge").
--   * Who merged it, and the merge itself, are read from GitHub's own read of that one pull request (the detail), and
--     recorded with the time of that read (merge_read_at). Rows written before 055 (by the site) have none, so none of
--     them can pass by rule or reach Third Look until GitHub's read confirms them; the workflow reads them again, 20 a
--     run, newest work first. A merged pull request becomes the repository's task only once that read is in.
--   * If GitHub's facts stop arriving (the workflow or the function down), work waits: a pull request's claim running
--     out no longer fails it (W13) while no fact has arrived for 6 hours, nothing passes, and nobody is locked out.
--     The workflow alerts on the "JEVs alerts" issue when a run fails.
-- Everything else 054's sync does is unchanged: the same shapes and limits, the repository's project and milestones,
-- claims found by their code, issues labelled "task" as open tasks, closed issues closing idle tasks, the rate-limit
-- notice (its words corrected: the site no longer reads these), and waiting submissions re-read.

-- ---- The role, made by the runner's own login (like dog_jevs in 010 and dog_work in 042) ----
do $ghsync_role$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_ghsync') then
    create role dog_ghsync nologin noinherit nobypassrls;
  end if;
end
$ghsync_role$;
grant dog_ghsync to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_ghsync;

-- ---- What GitHub's own read of a pull request says ----
alter table app.work_github_prs add column merged_by_id bigint check (merged_by_id between 1 and 100000000000);
alter table app.work_github_prs add column merge_read_at timestamptz;
comment on column app.work_github_prs.merged_by_id is 'The GitHub ID of the account that merged it, from GitHub''s own read of this pull request (055).';
comment on column app.work_github_prs.merge_read_at is 'When GitHub''s own read of this pull request, through the GitHub facts workflow, last gave its merge and who merged it (055). Null for rows from before 055.';
create index work_github_prs_unread on app.work_github_prs (number) where merged_at is not null and merge_read_at is null;
-- The account whose merge into main lets JEVs's rules pass a pull request: Aaron's (MyChiefOS), by GitHub ID. Changed
-- only by a migration.
alter table app.work_settings add column merger_github_id bigint not null default 304218593 check (merger_github_id between 1 and 100000000000);
comment on column app.work_settings.merger_github_id is 'The GitHub ID whose merge into main lets JEVs''s rules pass a pull request (055, RK140): Aaron''s account, MyChiefOS.';

-- The JEVs auditor's rules (043's, owned by dog_owner) with W14. db/work-audit.js has the same rules, in the same order.
-- facts: as 043, and pr.merged_by_owner (GitHub's read says the merger_github_id account merged it).
create or replace function app.work_jevs_rules(f jsonb) returns jsonb
language plpgsql immutable
as $$
declare
  fired text[] := '{}';
  hard boolean := false;
  machine boolean := false;
  waiting boolean := false;
  fixable boolean := false;
  pr jsonb := f -> 'pr';
begin
  -- W01: the task's class says who may do it.
  if (f ->> 'class' = 'agent' and f ->> 'worker_kind' = 'member') or (f ->> 'class' = 'person' and f ->> 'worker_kind' = 'agent') then
    fired := fired || 'W01'::text; hard := true;
  end if;
  -- W02: nobody audits or is paid for their own task: the worker's owner posted it.
  if coalesce((f ->> 'own')::boolean, false) then fired := fired || 'W02'::text; hard := true; end if;
  -- W03: submitted after the claim's hold ran out.
  if coalesce((f ->> 'late')::boolean, false) then fired := fired || 'W03'::text; hard := true; end if;
  -- W04: the same artifact was already submitted for another task.
  if coalesce((f ->> 'reused')::boolean, false) then fired := fired || 'W04'::text; hard := true; end if;
  -- W05: a task from this repository's GitHub is done by a pull request in this repository.
  if f ->> 'github_task' is not null and f ->> 'artifact' <> 'pr' then fired := fired || 'W05'::text; hard := true; end if;
  if f ->> 'artifact' = 'pr' then
    if pr is null or jsonb_typeof(pr) <> 'object' then
      waiting := true;  -- GitHub hasn't been read for this pull request yet
    else
      -- W06: the pull request was closed without being merged, or merged somewhere other than main.
      if pr ->> 'state' = 'closed' and not coalesce((pr ->> 'merged')::boolean, false) then fired := fired || 'W06'::text; hard := true;
      elsif coalesce((pr ->> 'merged')::boolean, false) and pr ->> 'base' <> 'main' then fired := fired || 'W06'::text; hard := true;
      elsif not coalesce((pr ->> 'merged')::boolean, false) then waiting := true;  -- still open: wait for the merge
      end if;
      -- W07: the pull request's description carries the claim's code (or, for the repository's own history, the
      -- worker is its author): otherwise who wrote it can't be checked by code.
      if not (coalesce((pr ->> 'code_ok')::boolean, false) or coalesce((pr ->> 'author_ok')::boolean, false)) then fired := fired || 'W07'::text; fixable := true; end if;
      -- W08: for an issue's task, the pull request names the issue (#N).
      if f ->> 'github_task' = 'issue' and not coalesce((pr ->> 'refs_issue')::boolean, false) then fired := fired || 'W08'::text; fixable := true; end if;
      -- W12: a member's task done by a pull request: whether it does that task is a person's call (the fresh review of
      -- Nov 6: a merged pull request with the claim's code otherwise passed any member's task).
      if f ->> 'task_source' = 'member' then fired := fired || 'W12'::text; end if;
      -- W14 (055, RK140): merged into main, but GitHub's own read doesn't say Aaron's account merged it: a person decides.
      if coalesce((pr ->> 'merged')::boolean, false) and pr ->> 'base' = 'main' and not coalesce((pr ->> 'merged_by_owner')::boolean, false) then
        fired := fired || 'W14'::text;
      end if;
      if coalesce((pr ->> 'merged')::boolean, false) and pr ->> 'base' = 'main' and not ('W07' = any (fired)) and not ('W08' = any (fired))
         and not ('W12' = any (fired)) and not ('W14' = any (fired)) then
        machine := true;
      end if;
    end if;
  end if;
  -- W13: a pull request still not merged into main (or not found) when the claim's hold and the audit's time after it
  -- have both run out: it fails, so the task reopens (the fresh review of #110, H1).
  if f ->> 'artifact' = 'pr' and coalesce((f ->> 'wait_over')::boolean, false)
     and (pr is null or jsonb_typeof(pr) <> 'object' or not coalesce((pr ->> 'merged')::boolean, false)) then
    fired := fired || 'W13'::text; hard := true;
  end if;
  -- W09: a link that isn't https, points at a bare address, or goes through a link shortener: refused, with how to fix it
  -- (an https link to the page itself).
  if f ->> 'artifact' = 'link' and (not coalesce((f ->> 'url_https')::boolean, false) or coalesce((f ->> 'url_ip')::boolean, false)
                                    or coalesce((f ->> 'url_short')::boolean, false)) then
    fired := fired || 'W09'::text; hard := true;
  end if;
  -- W10: a file is known only by its SHA-256: a person checks what it is.
  if f ->> 'artifact' = 'file' then fired := fired || 'W10'::text; end if;
  -- W11: the note had contact details or keys, which were hidden: a person checks it.
  if coalesce((f ->> 'note_hits')::integer, 0) > 0 then fired := fired || 'W11'::text; machine := false; end if;
  -- W07 and W08 the worker can fix (the code or "#N" in the pull request's description, read again on each GitHub
  -- sync): it waits while the claim holds, and fails after.
  return jsonb_build_object('verdict', case when hard then 'fail' when waiting then 'waiting'
                                            when fixable then case when coalesce((f ->> 'claim_open')::boolean, false) then 'waiting' else 'fail' end
                                            when machine then 'pass' else 'person' end,
                            'rules', to_jsonb(fired));
end
$$;

grant create on schema app to dog_work;
set local role dog_work;

-- The facts the JEVs auditor reads for one submission (043's), with GitHub's own read: a merged pull request counts
-- only once GitHub's read of it is in (until then it waits), merged_by_owner says whether that read credits the merge to
-- the merger_github_id account, and the claim's time running out (wait_over, W13) counts only while GitHub's facts are
-- arriving: if none has arrived for 6 hours, the work waits instead of failing.
create or replace function app.work_facts(p_sub uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  s record;
  t record;
  c record;
  p record;
  poster uuid;
  worker uuid;
  host text;
begin
  select * into s from app.work_submissions x where x.id = p_sub;
  select * into t from app.work_tasks x where x.id = s.task_id;
  select * into c from app.work_claims x where x.id = s.claim_id;
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  worker := s.worker_member;
  -- Always selected (no row for anything but a pull request), so the record is set either way.
  select * into p from app.work_github_prs x where x.number = s.pr_number;
  host := lower(substring(coalesce(s.artifact_url, '') from '^https?://([^/:?#]+)'));
  return jsonb_build_object(
    'class', t.class, 'worker_kind', s.worker_kind,
    'own', poster is not null and worker is not null and poster = worker,
    'late', c.id is not null and s.created_at > c.expires_at,
    'claim_open', c.id is not null and c.expires_at > now(),
    'wait_over', c.id is not null and c.expires_at + make_interval(hours => (select x.audit_hours from app.work_settings x where x.singleton)) <= now()
                 and exists (select 1 from app.work_github_prs g where g.seen_at > now() - interval '6 hours'),
    'reused', exists (select 1 from app.work_submissions o where o.id <> s.id and o.task_id <> s.task_id and o.status <> 'failed'
                       and ((s.artifact_url is not null and o.artifact_url = s.artifact_url) or (s.artifact_sha256 is not null and o.artifact_sha256 = s.artifact_sha256))),
    'artifact', s.artifact_kind,
    'github_task', t.github_kind,
    'task_source', t.source,
    'issue', case when t.github_kind = 'issue' then t.github_number end,
    'pr', case when s.artifact_kind = 'pr' and p.id is not null and (p.merged_at is null or p.merge_read_at is not null) then jsonb_build_object(
      'state', p.state, 'merged', p.merged_at is not null, 'base', p.base,
      'merged_by_owner', p.merge_read_at is not null and p.merged_by_id is not null
                         and p.merged_by_id = (select x.merger_github_id from app.work_settings x where x.singleton),
      'code_ok', c.id is not null and exists (select 1 from app.work_github_codes g where g.pr_number = p.number and g.code_hash = c.code_hash),
      'author_ok', s.worker_kind = 'github' and s.worker_github = p.author,
      'refs_issue', t.github_kind = 'issue' and (',' || p.refs || ',') like ('%,' || t.github_number || ',%')) end,
    'url_https', s.artifact_url like 'https://%',
    'url_ip', host ~ '^[0-9.]+$' or host like '[%' or host = 'localhost',
    'url_short', host = any (array['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy']),
    'note_hits', s.note_hits);
end
$$;

-- The pull requests whose GitHub read is wanted: merged ones with no detail yet (new work, first), then those whose
-- merge GitHub hasn't confirmed since 055; within each, those GitHub's listing showed most recently first, so a number
-- GitHub doesn't have (it answers "not found", and the row is never confirmed) can't crowd out real work. At most 20 a
-- call. Only for the GitHub facts function.
create or replace function app.work_github_wanted(p_n integer)
returns table (number integer)
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function reads this (dog_ghsync)' using errcode = '42501';
  end if;
  return query select x.number from app.work_github_prs x
    where x.merged_at is not null and (x.detail_at is null or x.merge_read_at is null)
    order by (x.detail_at is not null), x.seen_at desc, x.number limit least(greatest(coalesce(p_n, 1), 1), 20);
end
$$;

-- p: {prs: [...], issues: [...], details: [...], refused: n} (at most 100 of each; the shapes are db/workjobs.js's, read
-- from GitHub by the GitHub facts workflow). Everything is public GitHub data, checked here again. Returns counts.
-- 054's sync, with: only dog_ghsync may call it; a detail is GitHub's own read of one pull request and also gives its
-- merge (state, merged_at, base, merge commit) and who merged it, by login and GitHub ID; a merged pull request becomes
-- a task only once that read is in.
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
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function records GitHub''s facts (dog_ghsync)' using errcode = '42501';
  end if;
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
  -- GitHub's own read of one pull request: its changed lines, its merge and who merged it (login and GitHub ID).
  for x in select * from jsonb_array_elements(coalesce(p -> 'details', '[]')) loop
    if (x ->> 'number') !~ '^[1-9][0-9]{0,6}$' or (x ->> 'additions') !~ '^[0-9]{1,8}$' or (x ->> 'deletions') !~ '^[0-9]{1,8}$'
       or coalesce(x ->> 'state', '') <> all (array['open', 'closed'])
       or (x ->> 'merged_by_id' is not null and (x ->> 'merged_by_id') !~ '^[1-9][0-9]{0,10}$') then
      continue;
    end if;
    update app.work_github_prs g set additions = (x ->> 'additions')::integer, deletions = (x ->> 'deletions')::integer,
      merged_by = case when x ->> 'merged_by' ~ '^[a-z0-9-]{1,39}$' then x ->> 'merged_by' end,
      merged_by_id = case when x ->> 'merged_by_id' ~ '^[1-9][0-9]{0,10}$' then (x ->> 'merged_by_id')::bigint end,
      state = x ->> 'state', merged_at = (x ->> 'merged_at')::timestamptz, base = left(coalesce(x ->> 'base', ''), 100),
      merge_sha = case when x ->> 'merge_sha' ~ '^[0-9a-f]{40}$' then x ->> 'merge_sha' end,
      detail_at = now(), merge_read_at = now()
     where g.number = (x ->> 'number')::integer;
  end loop;
  -- Merged pull requests whose merge GitHub's read confirms: finished work. A pull request whose description carries a
  -- live claim's code is that claim's submission; any other is submitted by its author, as the repository's history.
  for pr in select g.* from app.work_github_prs g where g.merged_at is not null and g.detail_at is not null and g.merge_read_at is not null and g.base = 'main'
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
      || 'Pull requests and issues update on a later run of the GitHub facts workflow; nothing else stops.', '/build', null, null,
      'work:github-limit:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end if;
  -- Submissions that were waiting for GitHub's facts (a merge counts once GitHub's read of it is in).
  for sub in select s.id from app.work_submissions s join app.work_github_prs g on g.number = s.pr_number
              where s.status = 'waiting' and ((g.merged_at is not null and g.merge_read_at is not null) or (g.merged_at is null and g.state = 'closed'))
              limit 100 loop
    perform app.work_jevs_run(sub);
  end loop;
  return jsonb_build_object('prs', added, 'tasks', tasks, 'closed', closed);
end
$$;

-- Third Look (052's picker) takes only pull requests whose merge into main GitHub's read credits to the
-- merger_github_id account: a pass of a merged pull request needs Aaron's merge, whoever passes it. Anything else
-- stays with a person.
create or replace function app.tl_claim(p_n integer)
returns table (submission_id uuid, task_title text, task_description text, note text, pr_number integer, pr_title text, jevs_rules text, model text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  today integer;
begin
  if p_n is null or p_n < 1 or p_n > 3 then raise exception 'bad Third Look claim' using errcode = '22023'; end if;
  select * into s from app.tl_settings where singleton for update skip locked;
  if not found or s.mode = 'off' or (s.last_claim_at is not null and s.last_claim_at > now() - interval '50 seconds') then return; end if;
  update app.tl_settings set last_claim_at = now() where singleton;
  select count(*) into today from app.tl_reviews r where r.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  if today >= s.daily_call_cap then return; end if;
  return query
    with picked as (
      select x.id from app.work_submissions x join app.work_github_prs g on g.number = x.pr_number
       where ((x.status = 'review' and x.route in ('admin', 'held'))
              -- A disputed pass it hasn't read: its review goes beside the dispute (Aaron: "Third look can weigh in").
              -- At most 10 a day, after the work that waits, so disputes can't use up its daily limit.
              or (x.status = 'passed' and exists (select 1 from app.work_disputes d where d.submission_id = x.id and d.status = 'open')
                  and (select count(*) from app.tl_reviews r join app.work_submissions y on y.id = r.submission_id
                        where r.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC' and y.decided_at < r.claimed_at) < 10))
         and x.artifact_kind = 'pr' and g.merged_at is not null and g.base = 'main'
         and g.merge_read_at is not null and g.merged_by_id = (select w.merger_github_id from app.work_settings w where w.singleton)
         and not exists (select 1 from app.tl_reviews r where r.submission_id = x.id)
       order by (x.status = 'passed'), x.created_at, x.id
       limit least(p_n, s.daily_call_cap - today)
       for update of x skip locked),
    claimed as (insert into app.tl_reviews (submission_id) select id from picked returning tl_reviews.submission_id)
    select x.id, t.title, t.description, x.note, x.pr_number, g.title, x.jevs_rules, s.model
      from claimed c join app.work_submissions x on x.id = c.submission_id join app.work_tasks t on t.id = x.task_id
      join app.work_github_prs g on g.number = x.pr_number;
end
$$;

-- The site's role no longer reads or records GitHub's facts; only the GitHub facts function's role does.
revoke execute on function app.work_github_sync(jsonb), app.work_github_wanted(integer) from dog_app;
revoke execute on function app.work_github_sync(jsonb), app.work_github_wanted(integer) from public;
grant execute on function app.work_github_sync(jsonb), app.work_github_wanted(integer) to dog_ghsync;

set local role dog_owner;
revoke create on schema app from dog_work;
