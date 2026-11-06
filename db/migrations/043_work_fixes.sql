-- 043 The work module, as its fresh review of Nov 6 found it (#110 merged before these fixes, which were written into
--   042 on its branch; 042 shipped as merged, so they come here). Each finding has a test in test/work.test.js:
--   * H1: a pull request that never merges, or doesn't exist, no longer freezes a task: once the claim's hold and
--     audit_hours after it have run out it fails (rule W13, app.work_jevs_rules and db/work-audit.js), its claim expires
--     and the task reopens. The timer re-reads such submissions (app.work_tick).
--   * M1: nothing waits for a person forever. Work past a poster's limit goes to an administrator unless one is a
--     party (then it waits for Third Look); a poster who doesn't check within audit_hours is passed over to an
--     administrator; whatever no one decides within audit_hours of reaching them fails ("timeout"), never passes.
--     Each submission records when it reached whoever decides it (routed_at).
--   * M2: a task left without its work by an account's deletion reopens (or, for the repository's history, closes); an
--     open task whose poster deleted their account closes; work on a claimed one goes to an administrator, with no error.
--   * M3: the repository's own tasks, and the GitHub accounts credited to an administrator (app.work_github_names), are
--     theirs: an administrator never decides a dispute or a check on them. As the repository's poster, an
--     administrator still decides its tasks' work, never work credited to them.
--   * M4: a person may claim member_daily_claims tasks a day (20): each claim is a public log entry and a notice.
--   * L1: a failed or reversed submission of a pull request no longer keeps it from its real author's credit.
--   * A reversal closes any check or dispute still open on that pass.
-- Rights, owners and who may call each function stay as 042 set them: each function is replaced in place by its owner
-- (the rules by dog_owner, the rest by dog_work), with the same signature.
set local role dog_owner;
alter table app.work_settings add column member_daily_claims integer not null default 20 check (member_daily_claims between 1 and 1000);
alter table app.work_submissions add column routed_at timestamptz;
alter table app.work_submissions drop constraint work_submissions_decided_by_check;
alter table app.work_submissions add constraint work_submissions_decided_by_check check (decided_by = any (array['jevs', 'poster', 'person', 'timeout']));

-- The rules are a pure function the database owner made in 042 (owned by dog_owner, like the size band and points).
-- The JEVs auditor (db/work-audit.js has the same rules, in the same order; test/work.test.js keeps them the same).
-- facts: class, worker_kind, own (worker and poster share an owner), late (submitted after the claim's hold), reused
-- (the artifact was submitted for another task), artifact (pr, link or file), github_task (pr or issue, or null),
-- issue (the task's issue number or null), task_source (member or github), claim_open (a claim that still holds), wait_over
-- (the claim's hold and the audit's hours after it have run out), pr (null if GitHub hasn't been read yet: {merged, state, base, code_ok,
-- author_ok, refs_issue}), url_https, url_ip, url_short, note_hits.
-- Returns {verdict: pass | fail | person | waiting, rules: [...]}: the rules that fired, in order.
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
      if coalesce((pr ->> 'merged')::boolean, false) and pr ->> 'base' = 'main' and not ('W07' = any (fired)) and not ('W08' = any (fired))
         and not ('W12' = any (fired)) then
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
-- Work already waiting for someone starts its time now.
update app.work_submissions set routed_at = now() where status = 'review' and routed_at is null;

-- The facts the JEVs auditor reads for one submission.
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
    'wait_over', c.id is not null and c.expires_at + make_interval(hours => (select x.audit_hours from app.work_settings x where x.singleton)) <= now(),
    'reused', exists (select 1 from app.work_submissions o where o.id <> s.id and o.task_id <> s.task_id and o.status <> 'failed'
                       and ((s.artifact_url is not null and o.artifact_url = s.artifact_url) or (s.artifact_sha256 is not null and o.artifact_sha256 = s.artifact_sha256))),
    'artifact', s.artifact_kind,
    'github_task', t.github_kind,
    'task_source', t.source,
    'issue', case when t.github_kind = 'issue' then t.github_number end,
    'pr', case when s.artifact_kind = 'pr' and p.id is not null then jsonb_build_object(
      'state', p.state, 'merged', p.merged_at is not null, 'base', p.base,
      'code_ok', c.id is not null and exists (select 1 from app.work_github_codes g where g.pr_number = p.number and g.code_hash = c.code_hash),
      'author_ok', s.worker_kind = 'github' and s.worker_github = p.author,
      'refs_issue', t.github_kind = 'issue' and (',' || p.refs || ',') like ('%,' || t.github_number || ',%')) end,
    'url_https', s.artifact_url like 'https://%',
    'url_ip', host ~ '^[0-9.]+$' or host like '[%' or host = 'localhost',
    'url_short', host = any (array['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy']),
    'note_hits', s.note_hits);
end
$$;


-- Whether a member is a party to a submission: did the work (or owns the agent that did) or posted the task (or owns
-- the agent that did); for an administrator, also the repository's own tasks and the GitHub accounts credited to them.
create or replace function app.work_party(p_sub uuid, p_member uuid)
returns boolean
language sql stable security definer set search_path = pg_catalog
as $$
  select exists (select 1 from app.work_submissions s join app.work_tasks t on t.id = s.task_id where s.id = p_sub
                 and (s.worker_member = p_member or coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) = p_member
                      -- The repository's own tasks and pull requests are its owner's (Aaron's account on GitHub), and so is
                      -- any GitHub account credited to him: an administrator is a party to them (the fresh review of #110, M3).
                      or (exists (select 1 from app.members m where m.id = p_member and m.is_admin)
                          and (t.source = 'github' or exists (select 1 from app.work_github_names n where n.login = s.worker_github)))))
$$;


-- The JEVs auditor on one submission: its verdict, logged once it has one, and the next step.
create or replace function app.work_jevs_run(p_sub uuid)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  r jsonb;
  v text;
  rules text;
begin
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.status not in ('waiting') then return s.jevs_verdict; end if;
  r := app.work_jevs_rules(app.work_facts(p_sub));
  v := r ->> 'verdict';
  rules := coalesce((select string_agg(e, ',') from jsonb_array_elements_text(r -> 'rules') e), '');
  update app.work_submissions x set jevs_verdict = v, jevs_rules = rules where x.id = p_sub;
  if v = 'waiting' then return v; end if;
  perform app.log_work('audit.verdict', 'jevs-audit', null, 'submission:' || p_sub::text,
    jsonb_build_object('task', s.task_id::text, 'verdict', v, 'rules', rules));
  if v = 'pass' then
    perform app.work_finish(p_sub, 'pass', 'jevs', 100, 'The JEVs auditor confirmed it: ' || rules);
  elsif v = 'fail' then
    perform app.work_finish(p_sub, 'fail', 'jevs', 100, 'The JEVs auditor''s rules ' || rules || ' refused it.');
  else
    -- What its rules can't decide goes to the task's poster: the worker never approves their own work (four eyes; Aaron,
    -- Nov 6: "Use logic to determine the flow based on simulation and industry best practices"). The repository's own
    -- tasks were posted by its owner account, so an administrator decides those, unless an administrator did the work;
    -- then it waits for Third Look.
    if (select t.source = 'member' and coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) is not null
        from app.work_tasks t where t.id = s.task_id) then
      update app.work_submissions x set status = 'review', route = 'poster', routed_at = now() where x.id = p_sub;
      perform app.notify((select coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) from app.work_tasks t where t.id = s.task_id),
        'work_submitted', 'Work on your task waits for your check', 'The JEVs auditor''s rules couldn''t decide the work submitted on your task (rules ' || rules
        || '), so you do, as its poster: pass it, or fail it with a reason. A sample of passes is checked again.', '/tasks/' || s.task_id, 'task', s.task_id, 'work:check:' || p_sub);
    elsif exists (select 1 from app.members m where m.id = s.worker_member and m.is_admin) then
      update app.work_submissions x set status = 'review', route = 'held', routed_at = now(),
        held_reason = 'An administrator did this work, so none decides it: it waits for Third Look.' where x.id = p_sub;
    else
      -- The repository's own tasks, and a member's task whose poster deleted their account: an administrator decides.
      update app.work_submissions x set status = 'review', route = 'admin', routed_at = now() where x.id = p_sub;
      perform app.notify(null, 'alert', 'Work on the repository''s task waits for you', 'The JEVs auditor''s rules couldn''t decide work on one of the repository''s own tasks (rules '
        || rules || '). Decide it on Review, as the repository''s owner.', '/admin/review#work', 'submission', p_sub, 'work:person:' || p_sub);
    end if;
  end if;
  return v;
end
$$;


-- Claims an open task for 72 hours. p_code_hash: the SHA-256 of the claim code the site made (shown to the claimer
-- once; written in a pull request's description, it shows who wrote the pull request).
create or replace function app.work_claim(p_task uuid, p_code_hash text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  t record;
  st record;
  cid uuid;
  exp timestamptz;
  n integer;
  seq bigint;
  poster uuid;
begin
  if p_code_hash is null or p_code_hash !~ '^[0-9a-f]{64}$' then raise exception 'bad claim' using errcode = '22023'; end if;
  select * into w from app.work_who();
  perform app.work_brake_check(w.member_id);
  select * into st from app.work_settings where singleton;
  if w.agent_id is not null then perform app.work_cap(w.agent_id, w.tree_root, 'claim', true); end if;
  select * into t from app.work_tasks x where x.id = p_task for update;
  if t.id is null or t.status = 'removed' then raise exception 'no such task' using errcode = 'P0002'; end if;
  if t.status <> 'open' then raise exception 'work_taken' using errcode = 'P0001', hint = 'This task isn''t open: it is ' || t.status || '.'; end if;
  if (t.class = 'agent' and w.agent_id is null) or (t.class = 'person' and w.agent_id is not null) then
    raise exception 'work_class' using errcode = 'P0001', hint = case when t.class = 'agent' then 'Only an agent may claim this task.' else 'Only a person may claim this task.' end;
  end if;
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if poster = w.member_id then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You (or your agents) posted this task, so you can''t claim it: nobody does or audits their own task.';
  end if;
  if w.agent_id is null then
    -- A person's claims a day (the fresh review of #110, M4: each is a public log entry and a notice to the poster).
    select count(*) into n from app.work_actions x where x.member_id = w.member_id and x.agent_id is null and x.kind = 'claim' and x.created_at > now() - interval '1 day';
    if n >= st.member_daily_claims then
      raise exception 'work_cap' using errcode = 'P0001', hint = 'You have claimed ' || n || ' tasks today, the most for one day.';
    end if;
    select count(*) into n from app.work_claims c where c.member_id = w.member_id and c.agent_id is null and c.status = 'active';
    if n >= st.member_active_claims then
      raise exception 'work_cap' using errcode = 'P0001', hint = 'You already hold ' || n || ' live claims, the most one person may hold.';
    end if;
  end if;
  exp := now() + make_interval(hours => st.claim_hours);
  insert into app.work_claims (task_id, member_id, agent_id, tree_root, code_hash, expires_at)
    values (t.id, w.member_id, w.agent_id, w.tree_root, p_code_hash, exp) returning id into cid;
  update app.work_tasks x set status = 'claimed', updated_at = now() where x.id = t.id;
  insert into app.work_actions (member_id, agent_id, kind) values (w.member_id, w.agent_id, 'claim');
  seq := app.log_work('task.claimed', w.citizen, case when w.agent_id is not null then 'member:' || w.member_id end, 'task:' || t.id::text,
           jsonb_build_object('claim', cid::text, 'room', (select r.code from app.work_rooms r where r.id = t.room_id), 'expires', app.log_ts(exp)));
  update app.work_claims x set log_seq = seq where x.id = cid;
  if poster is not null then
    perform app.notify(poster, 'work_claimed', 'Your task was claimed', '"' || left(t.title, 80) || '" was claimed. It holds for '
      || st.claim_hours || ' hours, then reopens if nothing is submitted.', '/tasks/' || t.id, 'task', t.id, 'work:claimed:' || cid);
  end if;
  return jsonb_build_object('claim', cid, 'task', t.id, 'expires_at', exp, 'seq', seq);
end
$$;


-- p: {prs: [...], issues: [...], details: [...]} (at most 100 of each; the shapes are db/workjobs.js's). Everything is
-- public GitHub data, checked here again. Returns counts.
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
              || to_char(pr.merged_at at time zone 'UTC', 'YYYY-MM-DD') || '. ' || (pr.additions + pr.deletions) || ' lines changed.',
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


-- ---- The timer: claims that ran out, points whose dispute window closed, and Aaron's daily alert of work waiting for him ----
create or replace function app.work_tick()
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  st record;
  n_exp integer := 0;
  n_final integer := 0;
  n_fixed integer := 0;
  x record;
  waiting integer;
begin
  select * into st from app.work_settings where singleton for update skip locked;
  if not found or (st.last_tick_at is not null and st.last_tick_at > now() - interval '50 seconds') then return null; end if;
  update app.work_settings set last_tick_at = now() where singleton;
  for x in select c.id, c.task_id from app.work_claims c where c.status = 'active' and c.expires_at <= now() order by c.expires_at limit 500 for update skip locked loop
    update app.work_claims c set status = 'expired', ended_at = now() where c.id = x.id;
    update app.work_tasks t set status = 'open', updated_at = now() where t.id = x.task_id and t.status = 'claimed';
    n_exp := n_exp + 1;
  end loop;
  -- Work the worker could fix (W07, W08) that wasn't fixed while the claim held: the rules decide it again, and it fails.
  for x in select s.id from app.work_submissions s join app.work_claims c on c.id = s.claim_id
           where s.status = 'waiting' and s.jevs_verdict = 'waiting' and c.expires_at <= now()
             and (s.jevs_rules like '%W07%' or s.jevs_rules like '%W08%' or c.expires_at + make_interval(hours => st.audit_hours) <= now())
           order by s.created_at limit 100 loop
    perform app.work_jevs_run(x.id);
    n_fixed := n_fixed + 1;
  end loop;
  -- Nothing waits for a person forever (the fresh review of #110, M1). A poster who hasn't checked within audit_hours
  -- is passed over: an administrator decides, unless one is a party. Whatever an administrator, or no one (held), hasn't
  -- decided within audit_hours of reaching them fails: it isn't passed to clear a backlog; the task reopens and the
  -- worker may try again.
  for x in select s.id, s.route, s.worker_member, t.poster_member, t.poster_agent from app.work_submissions s join app.work_tasks t on t.id = s.task_id
           where s.status = 'review' and coalesce(s.routed_at, s.created_at) + make_interval(hours => st.audit_hours) <= now() order by s.created_at limit 100 loop
    if x.route = 'poster' and not exists (select 1 from app.members m where m.is_admin
         and m.id in (x.worker_member, coalesce(x.poster_member, (select g.owner_id from app.agents g where g.id = x.poster_agent)))) then
      update app.work_submissions y set route = 'admin', routed_at = now(), held_reason = 'The task''s poster didn''t check it within ' || st.audit_hours || ' hours.' where y.id = x.id;
      perform app.notify(null, 'alert', 'Work a poster didn''t check waits for you', 'A poster didn''t check work on their task in time. Decide it on Review.', '/admin/review#work',
        'submission', x.id, 'work:escalated:' || x.id);
    else
      perform app.work_finish(x.id, 'fail', 'timeout', 100, 'No one could decide it within ' || st.audit_hours || ' hours, so it isn''t passed. You may claim the task again.');
    end if;
    n_fixed := n_fixed + 1;
  end loop;
  -- Tasks left without their work by an account's deletion (the review, M2): a claimed or submitted task with no live
  -- claim and nothing waiting reopens (a pull request of the repository's history closes); an open task whose poster
  -- deleted their account closes, since no one is left to approve it.
  update app.work_tasks t set status = case when t.source = 'github' and t.github_kind = 'pr' then 'closed' else 'open' end, updated_at = now()
   where t.status in ('claimed', 'submitted')
     and not exists (select 1 from app.work_claims c where c.task_id = t.id and c.status in ('active', 'submitted'))
     and not exists (select 1 from app.work_submissions s where s.task_id = t.id and s.status in ('waiting', 'review'));
  update app.work_tasks t set status = 'closed', updated_at = now()
   where t.status = 'open' and t.source = 'member' and t.poster_member is null and t.poster_agent is null;
  -- Points become final after the dispute window, unless a dispute or the check after is still open on them.
  update app.work_points p set status = 'final' where p.status = 'pending' and p.final_at <= now()
    and not exists (select 1 from app.work_disputes d where d.submission_id = p.submission_id and d.status = 'open')
    and not exists (select 1 from app.work_checks k where k.submission_id = p.submission_id and k.status = 'open');
  get diagnostics n_final = row_count;
  -- Aaron's daily alert while anything waits for him (in-app, once a day).
  select (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'admin')
       + (select count(*) from app.work_checks k where k.status = 'open') + (select count(*) from app.work_disputes d where d.status = 'open') into waiting;
  if waiting > 0 and st.last_alert_day is distinct from (now() at time zone 'UTC')::date then
    update app.work_settings set last_alert_day = (now() at time zone 'UTC')::date where singleton;
    perform app.notify(null, 'alert', 'Work waits for you', waiting || case when waiting = 1 then ' item of work waits' else ' items of work wait' end
      || ' for you on Review: checks after a poster''s pass, disputes, or the repository''s own tasks. Points under a check or a dispute stay pending; nothing else stops.', '/admin/review#work', null, null,
      'work:waiting:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end if;
  return jsonb_build_object('expired', n_exp, 'finalised', n_final, 'unfixed', n_fixed);
end
$$;


-- ---- Administrator: work that waits for a person, and decisions with a reason ----
create or replace function app.work_admin()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator' using errcode = '42501'; end if;
  -- Each item says whether the administrator reading it is a party to it (did the work, posted the task or opened the
  -- dispute): those wait for Third Look, and the page doesn't offer to decide them.
  return jsonb_build_object('generated_at', now(),
    'waiting', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('submission', s.id, 'jevs_rules', s.jevs_rules, 'note', s.note, 'held_reason', s.held_reason,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256), 'party', app.work_party(s.id, me))
                         order by s.created_at)
                        from app.work_submissions s where s.status = 'review' and s.route = 'admin'), '[]'::jsonb),
    'checks', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('check', k.id, 'submission', s.id, 'why', k.why, 'note', s.note,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256),
                           'decided_by', s.decided_by, 'reason', s.reason, 'party', app.work_party(s.id, me)) order by k.created_at)
                       from app.work_checks k join app.work_submissions s on s.id = k.submission_id where k.status = 'open'), '[]'::jsonb),
    'disputes', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('dispute', d.id, 'submission', s.id, 'dispute_reason', d.reason,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256),
                           'decided_by', s.decided_by, 'reason', s.reason, 'party', app.work_party(s.id, me) or d.member_id = me) order by d.created_at)
                         from app.work_disputes d join app.work_submissions s on s.id = d.submission_id where d.status = 'open'), '[]'::jsonb),
    'held', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'held'));
end
$$;


-- An administrator decides work on the repository's own tasks that the rules couldn't, with a reason.
create or replace function app.work_person_decide(p_sub uuid, p_verdict text, p_size integer, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides this' using errcode = '42501'; end if;
  if p_verdict is null or p_verdict <> all (array['pass', 'fail']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300
     or (p_size is not null and p_size <> all (array[1, 2, 3, 5, 8])) then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.id is null or s.status <> 'review' or s.route <> 'admin' then return 'not_waiting'; end if;
  -- He decides the repository's own tasks as their poster (the maker-checker's checker), never work he did: his own
  -- member account, or a GitHub account credited to him.
  if s.worker_member = app.current_member() or exists (select 1 from app.work_github_names n where n.login = s.worker_github) then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You did this work, so you can''t decide its audit: it waits for Third Look.';
  end if;
  insert into app.work_person_votes (submission_id, member_id, verdict, size, reason) values (p_sub, app.current_member(), p_verdict, p_size, btrim(p_reason));
  perform app.work_finish(p_sub, p_verdict, 'person', 100, btrim(p_reason));
  return p_verdict;
end
$$;


-- Reverses a pass whose points are still pending (an upheld dispute, or the check after found it wrong): the points
-- are removed, the log says so, the task reopens (a pull request of the repository's history closes), and the worker
-- and poster are told.
create or replace function app.work_reverse(p_sub uuid, p_by text, p_reason text)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  t record;
  poster uuid;
begin
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.status <> 'passed' then return; end if;
  select * into t from app.work_tasks x where x.id = s.task_id for update;
  update app.work_points x set status = 'removed' where x.submission_id = p_sub;
  update app.work_submissions x set status = 'reversed', reason = left(p_reason, 300) where x.id = p_sub;
  -- A check or dispute still open on it has nothing left to decide.
  update app.work_checks k set status = 'reversed', reason = 'The pass was reversed (' || p_by || ').', decided_at = now() where k.submission_id = p_sub and k.status = 'open';
  update app.work_disputes d set status = 'upheld', decision = 'The pass was reversed (' || p_by || ').', decided_at = now() where d.submission_id = p_sub and d.status = 'open';
  perform app.log_work('audit.verdict', 'work-audit', null, 'submission:' || p_sub::text,
    jsonb_build_object('task', s.task_id::text, 'verdict', 'reversed', 'by', p_by, 'points', 0));
  update app.work_tasks x set status = case when t.source = 'github' and t.github_kind = 'pr' then 'closed' else 'open' end,
    approved_at = null, approved_seq = null, updated_at = now() where x.id = t.id;
  update app.work_claims c set status = 'expired', ended_at = coalesce(c.ended_at, now()) where c.id = s.claim_id and c.status in ('active', 'submitted', 'done');
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if s.worker_member is not null then
    perform app.notify(s.worker_member, 'work_decided', 'A pass on your work was reversed', 'The pass on your work for "' || left(t.title, 80) || '" was reversed ('
      || p_by || '): ' || left(p_reason, 200) || ' Its points are removed.', '/tasks/' || t.id, 'task', t.id, 'work:reversed:' || p_sub);
  end if;
  if poster is not null and poster is distinct from s.worker_member then
    perform app.notify(poster, 'work_decided', 'A pass on your task was reversed', 'The pass on "' || left(t.title, 80) || '" was reversed (' || p_by || '). The task is open again.',
      '/tasks/' || t.id, 'task', t.id, 'work:reversed-poster:' || p_sub);
  end if;
end
$$;


-- The poster's check of work the rules couldn't decide (maker-checker; Aaron, Nov 6). A pass is limited the way a
-- bank limits one approver: the same poster and worker (by owner) at most pair_limit passes in 30 days, at most
-- poster_daily_points a day to one worker, and both at JEVs's poster_level. Past a limit it waits for Third Look. A
-- pass also approves the task. A sample of passes is checked again (the check after), at most check_daily a day.
create or replace function app.work_poster_decide(p_sub uuid, p_verdict text, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  s record;
  t record;
  st record;
  poster uuid;
  pairs integer;
  today integer;
  pts integer;
  size smallint;
  why text;
  held text;
begin
  select * into w from app.work_who();
  if w.agent_id is not null then raise exception 'a person checks work, not an agent: your owner does' using errcode = '42501'; end if;
  if p_verdict is null or p_verdict <> all (array['pass', 'fail']) or (p_verdict = 'fail' and (p_reason is null or char_length(btrim(p_reason)) not between 3 and 300))
     or char_length(coalesce(p_reason, '')) > 300 then
    raise exception 'bad check' using errcode = '22023';
  end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  select * into t from app.work_tasks x where x.id = s.task_id for update;
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if poster is distinct from w.member_id then raise exception 'only the task''s poster checks its work' using errcode = '42501'; end if;
  if s.status <> 'review' or s.route <> 'poster' then
    raise exception 'work_state' using errcode = 'P0001', hint = 'This work doesn''t wait for your check.';
  end if;
  if p_verdict = 'fail' then
    perform app.work_finish(p_sub, 'fail', 'poster', 100, btrim(p_reason));
    return 'fail';
  end if;
  select * into st from app.work_settings where singleton;
  size := app.work_confirmed_size(p_sub, 'poster');
  pts := app.work_points_of(size, 100, 100, st.points_cap);
  select count(*) into pairs from app.work_submissions x join app.work_tasks y on y.id = x.task_id
   where x.decided_by = 'poster' and x.status = 'passed' and x.decided_at > now() - interval '30 days' and x.worker_member = s.worker_member
     and coalesce(y.poster_member, (select g.owner_id from app.agents g where g.id = y.poster_agent)) = poster;
  select coalesce(sum(p.points), 0) into today from app.work_points p join app.work_submissions x on x.id = p.submission_id
   where x.decided_by = 'poster' and p.status <> 'removed' and x.worker_member = s.worker_member and p.created_at > now() - interval '1 day';
  if (select m.trust_level from app.members m where m.id = poster) < st.poster_level
     or (select m.trust_level from app.members m where m.id = s.worker_member) < st.poster_level then
    held := 'The poster or the worker isn''t yet at JEVs''s level ' || st.poster_level || ', so a poster''s pass waits for Third Look.';
  elsif pairs >= st.pair_limit then
    held := 'This poster has passed this worker''s work ' || pairs || ' times in 30 days, the most one pair may, so it waits for Third Look.';
  elsif today + pts > st.poster_daily_points then
    held := 'This worker has ' || today || ' points from posters'' passes today; this would pass ' || st.poster_daily_points || ', so it waits for Third Look.';
  end if;
  if held is not null then
    -- Past a poster's limit, as a bank escalates past an approver's: to an administrator, unless one is a party; then it
    -- waits for Third Look. Either way it has audit_hours before it fails (app.work_tick).
    if exists (select 1 from app.members m where m.is_admin and m.id in (poster, s.worker_member)) then
      update app.work_submissions x set route = 'held', held_reason = held, routed_at = now() where x.id = p_sub;
      return 'held';
    end if;
    update app.work_submissions x set route = 'admin', held_reason = held, routed_at = now() where x.id = p_sub;
    perform app.notify(null, 'alert', 'Work past a poster''s limit waits for you', held || ' Decide it on Review.', '/admin/review#work', 'submission', p_sub, 'work:held:' || p_sub);
    return 'held';
  end if;
  perform app.work_finish(p_sub, 'pass', 'poster', 100, coalesce(nullif(btrim(p_reason), ''), 'Passed by the task''s poster.'));
  perform app.work_approve_as(t.id, w.citizen, null);
  -- The check after: at random, and the riskiest (the biggest size, a pair at its limit, a note that had contact details).
  why := case when size = 8 then 'size' when pairs + 1 >= st.pair_limit then 'pair' when s.note_hits > 0 then 'note'
              when random() < st.check_rate then 'random' end;
  if why is not null and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now())) < st.check_daily
     and not exists (select 1 from app.members m where m.is_admin and m.id in (poster, s.worker_member)) then
    insert into app.work_checks (submission_id, why) values (p_sub, why);
  end if;
  return 'pass';
end
$$;


set local role dog_owner;
revoke create on schema app from dog_work;
