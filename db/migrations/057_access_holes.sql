-- 057 Access holes: the functions that record an outside system's answer leave the site's role (RISKS.md RK144, RK112;
--   the independent reviews of Nov 10; harness/STANDARDS.md, OWASP A01, CWE-862), and Third Look reads only GitHub's
--   facts (RK135, in part). Built on 055 (RK140), whose GitHub facts they now read.
-- Until now whoever held the site's role (dog_app: a leaked site login, or code running in any site function) could
--   report the witness's status (app.log_witness_report), so show the log as witnessed when the witness had stopped,
--   or raise an alarm only a migration clears; and add any number of permanent proposal decisions in Aaron's name
--   (app.log_proposal), for any number up to 10,000,000, flipping between approved and declined on every call.
-- Second and Third Look stay where they run today, in the site's timer with the site's role (Aaron, Nov 10: "Go back to
--   making it work using the infrastructure as constructed"), so the site's role can still record their verdicts
--   (RK135 and RK100 stay open for that part). Their functions keep 041's and 044's callers.
-- Now:
--   * Third Look judges only what the site can't forge: pull requests whose merge GitHub's own read credits to
--     Aaron's account (055), with the changed files the GitHub facts workflow read from GitHub (app.tl_files, recorded
--     as dog_ghsync). A claim has a time limit of 3 minutes; an answer after it changes nothing. A refused or failed
--     model call (the gateway's refusal, a timeout, the network) or a missing read of GitHub releases the item: its
--     try isn't spent, it can be claimed again after 10 minutes, and the release counts against the day's calls, so a
--     failing gateway can't loop. A claim left undecided past its limit is released the same way. From the third
--     release in a day, Aaron is told in-app, once a day. Nothing passes while any of this is failing: the work waits
--     for an administrator, as it does when Third Look is off (052: Aaron is told halfway through its wait, and what
--     nobody decides within it fails, never passes).
--   * The witness reports itself: the log-witness workflow sends its own result to dog-github, proved by GitHub's
--     identity token from that file on main, which records it as dog_witness. The site no longer reads or reports the
--     witness's copy. Since the site no longer reports, the "witness has stopped" check (12 hours, 039) runs on its own
--     from the timer, with no input from the caller: app.log_witness_check.
--   * Proposal decisions come from the same GitHub facts path (dog-github, dog_ghsync): only a status change along the
--     labels' flow is logged at once (none to approved, declined or shipped; approved to shipped), any other change
--     (a reversal) at most once a day for each proposal; only numbers GitHub has (not a pull request, and within what
--     GitHub has shown the database); and at most 30 an hour, with Aaron told once a day if the cap holds some back.
--     The workflow reads everything afresh each run, so anything held back is logged on a later run.
-- Everything else in the replaced functions is unchanged.

-- ---- The witness's role, made by the runner's own login (as dog_ghsync in 055) ----
do $witness_role$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_witness') then
    create role dog_witness nologin noinherit nobypassrls;
  end if;
end
$witness_role$;
grant dog_witness to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_witness;

-- ---- What Third Look reads: the changed files GitHub gave the GitHub facts workflow ----
create table app.tl_files (
  id uuid primary key default app.uuid_v7(),
  number integer not null unique check (number between 1 and 10000000),
  files jsonb not null check (octet_length(files::text) <= 100000) check (jsonb_typeof(files) = 'array'),
  read_at timestamptz not null default now()
);
comment on table app.tl_files is 'The changed files of a pull request Third Look will read, from GitHub''s API through the GitHub facts workflow and dog-github (057). Deleted once Third Look has answered, and after 14 days.';
-- A claim given back: by a refused or failed model call, a missing read of GitHub, or its time limit running out.
create table app.tl_releases (
  id uuid primary key default app.uuid_v7(),
  submission_id uuid not null references app.work_submissions (id) on delete cascade,
  why text not null check (char_length(why) <= 40),
  released_at timestamptz not null default now()
);
create index tl_releases_at on app.tl_releases (released_at);
create index tl_releases_sub on app.tl_releases (submission_id, released_at);
do $rls$
declare
  t text;
begin
  foreach t in array array['tl_files', 'tl_releases'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('alter table app.%I force row level security', t);
    execute format('create policy %I on app.%I for all to dog_work using (true) with check (true)', t || '_work', t);
  end loop;
end
$rls$;
grant select, insert, update, delete on app.tl_files to dog_work;
grant select, insert, delete on app.tl_releases to dog_work;
-- A claim given back is deleted (044 granted select, insert and update only).
grant delete on app.tl_reviews to dog_work;

-- When each proposal's last decision was logged. Rows from before 057 are dated 25 hours back, so they count neither
-- toward the first hour's cap of 30 (which would hold back new decisions and send a false alert) nor as a reversal
-- made in the last day (the independent review of PR 2, F3).
alter table app.log_proposals_seen add column logged_at timestamptz not null default now();
update app.log_proposals_seen set logged_at = now() - interval '25 hours';
create index log_proposals_seen_logged on app.log_proposals_seen (logged_at);

-- ---- Second Look (034, 041): unchanged callers (the site's timer) ----
grant create on schema app to dog_jevs;
set local role dog_jevs;

create or replace function app.sl_claim(p_n integer)
returns table (post_id uuid, body text, held text[], account_days integer, sign_in text, model text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  r record;
  today_calls integer;
  v_rows jsonb := '[]'::jsonb;
  v_part jsonb;
  v_held integer := 0;
  v_room integer;
  v_can record;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer hands posts to Second Look' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 3 then
    raise exception 'bad Second Look claim' using errcode = '22023';
  end if;
  select * into s from app.sl_settings where singleton for update skip locked;
  if not found or s.mode = 'off' or (s.last_claim_at is not null and s.last_claim_at > now() - interval '50 seconds') then
    return;
  end if;
  update app.sl_settings set last_claim_at = now() where singleton;
  if s.last_report_at is null or s.last_report_at < now() - interval '7 days' then
    perform app.sl_weekly_report();
  end if;
  perform app.sl_try_unlock();
  select * into r from app.review_settings where singleton;
  v_room := p_n;
  -- 041: a sample that has waited 6 hours takes one slot first, so held posts can't starve the sample.
  with picked as (
    select x.post_id from app.review_samples x join app.posts p on p.id = x.post_id
     where x.claimed_at is null and p.status = 'live' and x.sampled_at > now() - interval '24 hours' and x.sampled_at <= now() - interval '6 hours'
     order by x.sampled_at, x.id limit 1 for update of x skip locked),
  claimed as (update app.review_samples y set claimed_at = now() from picked where y.post_id = picked.post_id returning y.post_id)
  select coalesce(jsonb_agg(jsonb_build_object('post_id', p.id, 'body', p.body, 'held', '[]'::jsonb,
           'account_days', greatest(0, extract(day from now() - m.created_at))::integer,
           'sign_in', case when p.agent_id is not null then 'an agent posting for its owner, level ' || m.trust_level else 'a member, level ' || m.trust_level end)), '[]'::jsonb)
    into v_part from claimed c join app.posts p on p.id = c.post_id join app.members m on m.id = p.author_id;
  v_rows := v_rows || v_part;
  v_room := v_room - jsonb_array_length(v_part);
  -- The held posts, as 034.
  select count(*) into today_calls from app.sl_claims c where c.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  if today_calls < s.daily_call_cap and v_room > 0 then
    with picked as (
      select p.id from app.posts p
       where p.status = 'waiting' and not exists (select 1 from app.sl_claims c where c.post_id = p.id) and app.sl_eligible(p.id)
       order by p.created_at, p.id
       limit least(v_room, s.daily_call_cap - today_calls)
       for update of p skip locked),
    claimed as (insert into app.sl_claims (post_id) select id from picked returning sl_claims.post_id)
    select coalesce(jsonb_agg(jsonb_build_object('post_id', p.id, 'body', p.body,
             'held', (select coalesce(jsonb_agg(e.key order by e.key), '[]'::jsonb) from (select d.scores from app.jevs_decisions d
                where d.subject_kind = 'post' and d.subject_id = p.id and d.effect = 'hold' and d.applied
                order by d.created_at desc, d.id desc limit 1) h, jsonb_each(h.scores) e
               where jsonb_typeof(e.value) = 'number' and (e.value::text)::numeric >= 25),
             'account_days', greatest(0, extract(day from now() - m.created_at))::integer,
             'sign_in', case when p.agent_id is not null then 'an agent posting for its owner, level ' || m.trust_level else 'a member, level ' || m.trust_level end)), '[]'::jsonb)
      into v_part from claimed c join app.posts p on p.id = c.post_id join app.members m on m.id = p.author_id;
    v_held := jsonb_array_length(v_part);
    v_rows := v_rows || v_part;
    v_room := v_room - v_held;
  end if;
  -- 041: the sample fills the slots left, oldest first, only posts drawn in the last 24 hours that are still live.
  if v_room > 0 then
    with picked as (
      select x.post_id from app.review_samples x join app.posts p on p.id = x.post_id
       where x.claimed_at is null and p.status = 'live' and x.sampled_at > now() - interval '24 hours'
       order by x.sampled_at, x.id limit v_room for update of x skip locked),
    claimed as (update app.review_samples y set claimed_at = now() from picked where y.post_id = picked.post_id returning y.post_id)
    select coalesce(jsonb_agg(jsonb_build_object('post_id', p.id, 'body', p.body, 'held', '[]'::jsonb,
             'account_days', greatest(0, extract(day from now() - m.created_at))::integer,
             'sign_in', case when p.agent_id is not null then 'an agent posting for its owner, level ' || m.trust_level else 'a member, level ' || m.trust_level end)), '[]'::jsonb)
      into v_part from claimed c join app.posts p on p.id = c.post_id join app.members m on m.id = p.author_id;
    v_rows := v_rows || v_part;
  end if;
  -- 041: a canary, made ahead of time, with the chance that at least one of the held posts handed over would carry one,
  -- placed among them at random.
  if v_held > 0 and r.canary_rate > 0 and random() < 1 - power(1 - r.canary_rate::double precision, v_held) then
    select * into v_can from app.review_canaries c where c.claimed_at is null and c.created_at <= now() - interval '5 minutes'
     order by c.created_at limit 1 for update skip locked;
    if found then
      update app.review_canaries set claimed_at = now() where id = v_can.id;
      v_rows := jsonb_insert(v_rows, array[floor(random() * (jsonb_array_length(v_rows) + 1))::int::text],
        jsonb_build_object('post_id', v_can.id, 'body', v_can.body, 'held', to_jsonb(string_to_array(v_can.held, ',')),
          'account_days', v_can.account_days, 'sign_in', v_can.sign_in));
    end if;
  end if;
  return query
    select (e ->> 'post_id')::uuid, e ->> 'body', array(select jsonb_array_elements_text(e -> 'held')), (e ->> 'account_days')::integer,
           e ->> 'sign_in', s.model
      from jsonb_array_elements(v_rows) with ordinality as x(e, i) order by x.i;
end
$$;

create or replace function app.sl_decide(p_post uuid, p_version text, p_model text, p_decision text, p_answers jsonb, p_risk integer,
                                         p_reason text, p_fail_closed boolean, p_error text, p_latency integer)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  did uuid;
  author uuid;
  v_decision text := p_decision;
  v_reason text := p_reason;
  today integer;
  v_can record;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records Second Look''s decisions' using errcode = '42501';
  end if;
  if p_post is null or p_version is distinct from 'v1' or p_decision is null or p_risk is null or p_reason is null
     or p_fail_closed is null or p_latency is null then
    raise exception 'bad Second Look decision' using errcode = '22023';
  end if;
  -- A clear must be what the nine answers say: Q1 to Q8 "no" and Q9 "yes" (the table checks the rest).
  if v_decision = 'clear' and not coalesce(p_answers ?& array['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9']
      and (select bool_and(p_answers ->> k = 'no') from unnest(array['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8']) k)
      and p_answers ->> 'q9' = 'yes', false) then
    raise exception 'a clear that its answers don''t support' using errcode = '22023';
  end if;
  if v_decision <> all (array['clear', 'leave', 'reject']) then
    raise exception 'bad Second Look decision' using errcode = '22023';
  end if;
  -- 041: a canary it was handed in the last 2 minutes, once. The truth is revealed with its nonce and text hash;
  -- nothing is published.
  select * into v_can from app.review_canaries x where x.id = p_post for update;
  if found then
    if v_can.decided_at is not null or v_can.claimed_at is null or v_can.claimed_at < now() - interval '2 minutes' then
      return 'refused';
    end if;
    update app.review_canaries set decision = v_decision, fail_closed = p_fail_closed, decided_at = now() where id = v_can.id;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('review.canary_result', 'canary', v_can.id, jsonb_build_object('truth', v_can.truth, 'nonce', v_can.nonce,
              'text_sha256', v_can.text_sha256, 'commitment', v_can.commitment, 'decision', v_decision, 'no_answer', p_fail_closed,
              'caught', case when p_fail_closed then null when v_can.truth = 'bad' then v_decision <> 'clear' else v_decision = 'clear' end));
    if v_can.truth = 'bad' and v_decision = 'clear' then
      perform app.notify(null, 'alert', 'A planted test slipped through Second Look',
        'Here is what it was: a known-bad test post that Second Look would have cleared. Nothing was published: planted tests are '
        || 'never posts. The text: "' || left(v_can.body, 600) || '"', '/admin/controls', null, null, 'review:canary:' || v_can.id);
    end if;
    return 'logged';
  end if;
  -- 041: a sampled live post it was handed in the last 2 minutes, once. A reject puts it in Aaron's queue; it stays up.
  if exists (select 1 from app.review_samples x where x.post_id = p_post and x.decided_at is null and x.claimed_at > now() - interval '2 minutes') then
    update app.review_samples set decision = v_decision, fail_closed = p_fail_closed, decided_at = now(),
      flagged = (v_decision = 'reject' and exists (select 1 from app.posts p where p.id = p_post and p.status = 'live'))
     where post_id = p_post;
    if v_decision = 'reject' and exists (select 1 from app.posts p where p.id = p_post and p.status = 'live')
       and not exists (select 1 from app.review_flags f where f.post_id = p_post and f.resolved_at is null and f.classifier = 'secondlook') then
      insert into app.review_flags (post_id, source, classifier) values (p_post, 'classifier', 'secondlook');
    end if;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('secondlook.sample', 'post', p_post, jsonb_build_object('decision', v_decision, 'no_answer', p_fail_closed, 'risk', p_risk));
    return 'logged';
  end if;
  -- Only a post it was given in the last 2 minutes, and only once.
  if not exists (select 1 from app.sl_claims c where c.post_id = p_post and c.claimed_at > now() - interval '2 minutes')
     or exists (select 1 from app.sl_decisions d where d.post_id = p_post) then
    return 'refused';
  end if;
  select * into s from app.sl_settings where singleton for update;
  -- The gate again: anything that changed since it was given the post (a report, an appeal, Aaron's own decision) means
  -- it leaves the post.
  if v_decision = 'clear' and not app.sl_eligible(p_post) then
    v_decision := 'leave';
    v_reason := left('the post changed while it was checked; ' || v_reason, 1000);
  end if;
  insert into app.sl_decisions (post_id, version, model, mode, decision, answers, risk, reason, fail_closed, error, latency_ms)
    values (p_post, p_version, p_model, case when s.mode = 'on' then 'on' else 'shadow' end, v_decision, p_answers, p_risk,
            v_reason, p_fail_closed, left(p_error, 80), least(p_latency, 600000))
    returning id into did;
  if v_decision <> 'clear' or s.mode <> 'on' or s.paused_reason is not null then
    return 'logged';
  end if;
  today := case when s.clears_day = (now() at time zone 'UTC')::date then s.clears_today else 0 end;
  if today >= s.daily_clear_cap then
    return 'logged';
  end if;
  update app.sl_settings set clears_day = (now() at time zone 'UTC')::date, clears_today = today + 1,
    published_total = published_total + 1 where singleton;
  -- Publish: the release row first (the post and flag guards look for it), then the post, then JEVs's hold.
  insert into app.sl_releases (post_id, decision_id) values (p_post, did);
  update app.posts set status = 'live' where id = p_post and status = 'waiting' returning author_id into author;
  if author is null then
    raise exception 'the post was no longer waiting' using errcode = '40001';
  end if;
  update app.review_flags set decision = 'approve'
   where post_id = p_post and source = 'classifier' and classifier = 'jevs' and resolved_at is null;
  update app.sl_decisions set published = true where id = did;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('secondlook.release', 'post', p_post, jsonb_build_object('decision', did, 'model', p_model, 'risk', p_risk));
  perform app.notify(author, 'post_published', 'Your post was reviewed and published',
    'Your post was held for a check. Second Look, the site''s automated reviewer, checked it and published it.',
    '/talk', 'post', p_post, 'secondlook:published:' || p_post);
  perform app.notify(null, 'alert', 'Second Look published a held post',
    'Reason: ' || left(v_reason, 300) || '. You can remove it from the review page; if you do, Second Look pauses itself.',
    '/review', 'post', p_post, 'secondlook:release:' || p_post);
  return 'published';
end
$$;

revoke execute on function app.sl_claim(integer), app.sl_decide(uuid, text, text, text, jsonb, integer, text, boolean, text, integer) from public;
grant execute on function app.sl_claim(integer), app.sl_decide(uuid, text, text, text, jsonb, integer, text, boolean, text, integer) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_jevs;

-- ---- Third Look (044, 047, 052, 055): the site's timer, on GitHub's facts ----
grant create on schema app to dog_work;
set local role dog_work;

-- Whether Third Look still wants to read this pull request: work on it is waiting for a person (an administrator's
-- or held), or a pass of it is disputed; GitHub's read credits its merge into main to Aaron's account; and Third Look
-- hasn't answered on it. For the GitHub facts function's two calls below.
create function app.tl_wants(p_number integer)
returns boolean
language sql stable security definer set search_path = pg_catalog
as $$
  select exists (
    select 1 from app.work_submissions x join app.work_github_prs g on g.number = x.pr_number
     where x.pr_number = p_number
       and ((x.status = 'review' and x.route in ('admin', 'held'))
            or (x.status = 'passed' and exists (select 1 from app.work_disputes d where d.submission_id = x.id and d.status = 'open')))
       and x.artifact_kind = 'pr' and g.merged_at is not null and g.base = 'main'
       and g.merge_read_at is not null and g.merged_by_id = (select w.merger_github_id from app.work_settings w where w.singleton)
       and not exists (select 1 from app.tl_reviews r where r.submission_id = x.id and r.decided_at is not null))
  and (select s.mode from app.tl_settings s where s.singleton) <> 'off'
$$;

-- The pull requests whose changed files Third Look wants read, oldest work first: at most 5 a call. Only for the
-- GitHub facts function.
create function app.tl_files_wanted(p_n integer)
returns table (number integer)
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function reads this (dog_ghsync)' using errcode = '42501';
  end if;
  return query select x.pr_number from app.work_submissions x
    where x.artifact_kind = 'pr' and x.pr_number is not null and x.status in ('review', 'passed')
      and not exists (select 1 from app.tl_files f where f.number = x.pr_number) and app.tl_wants(x.pr_number)
    group by x.pr_number order by min(x.created_at), x.pr_number limit least(greatest(coalesce(p_n, 1), 1), 5);
end
$$;

-- p: [{number, files: [{filename, status, changes, patch}]}], at most 10, each as GitHub's API gave it to the GitHub
-- facts workflow (db/workjobs.js shapes it). Only for a pull request Third Look wants. Returns how many were recorded.
-- Only for the GitHub facts function.
create function app.tl_files_record(p jsonb)
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  x jsonb;
  added integer := 0;
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function records GitHub''s facts (dog_ghsync)' using errcode = '42501';
  end if;
  if p is null or jsonb_typeof(p) <> 'array' or jsonb_array_length(p) > 10 then
    raise exception 'bad changed files' using errcode = '22023';
  end if;
  delete from app.tl_files f where f.read_at < now() - interval '14 days';
  for x in select * from jsonb_array_elements(p) loop
    if jsonb_typeof(x) <> 'object' or coalesce(x ->> 'number', '') !~ '^[1-9][0-9]{0,6}$' or jsonb_typeof(x -> 'files') is distinct from 'array'
       or jsonb_array_length(x -> 'files') > 100 or octet_length((x -> 'files')::text) > 100000 then
      continue;
    end if;
    if exists (select 1 from jsonb_array_elements(x -> 'files') f
                where jsonb_typeof(f) <> 'object' or jsonb_typeof(f -> 'filename') is distinct from 'string' or char_length(f ->> 'filename') > 300
                   or (f ? 'status' and (jsonb_typeof(f -> 'status') <> 'string' or char_length(f ->> 'status') > 20))
                   or (f ? 'changes' and jsonb_typeof(f -> 'changes') <> 'number')
                   or (f ? 'patch' and jsonb_typeof(f -> 'patch') <> 'string')
                   or exists (select 1 from jsonb_object_keys(f) k where k <> all (array['filename', 'status', 'changes', 'patch']))) then
      continue;
    end if;
    if not app.tl_wants((x ->> 'number')::integer) then continue; end if;
    insert into app.tl_files (number, files) values ((x ->> 'number')::integer, x -> 'files')
      on conflict (number) do update set files = excluded.files, read_at = now();
    added := added + 1;
  end loop;
  return added;
end
$$;

-- 055's picker, for the site's timer, with a time limit on each claim and the changed files to read. Claims
-- past their limit are released first; released work waits 10 minutes; releases count against the day's calls.
drop function app.tl_claim(integer);
create function app.tl_claim(p_n integer)
returns table (submission_id uuid, task_title text, task_description text, note text, pr_number integer, pr_title text, jevs_rules text, model text,
               files jsonb)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  today integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer hands work to Third Look' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 3 then raise exception 'bad Third Look claim' using errcode = '22023'; end if;
  select * into s from app.tl_settings where singleton for update skip locked;
  if not found or s.mode = 'off' or (s.last_claim_at is not null and s.last_claim_at > now() - interval '50 seconds') then return; end if;
  update app.tl_settings set last_claim_at = now() where singleton;
  -- A claim nobody answered within its time limit (the function stopped or ran out of time) is released, not spent.
  with gone as (delete from app.tl_reviews r where r.decided_at is null and r.claimed_at < now() - interval '3 minutes' returning r.submission_id)
  insert into app.tl_releases (submission_id, why) select g.submission_id, 'timed out' from gone g;
  delete from app.tl_releases r where r.released_at < now() - interval '2 days';
  select (select count(*) from app.tl_reviews r where r.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC')
       + (select count(*) from app.tl_releases r where r.released_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC')
    into today;
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
         and exists (select 1 from app.tl_files f where f.number = x.pr_number)
         and not exists (select 1 from app.tl_reviews r where r.submission_id = x.id)
         and not exists (select 1 from app.tl_releases r where r.submission_id = x.id and r.released_at > now() - interval '10 minutes')
       order by (x.status = 'passed'), x.created_at, x.id
       limit least(p_n, s.daily_call_cap - today)
       for update of x skip locked),
    claimed as (insert into app.tl_reviews (submission_id) select id from picked returning tl_reviews.submission_id)
    select x.id, t.title, t.description, x.note, x.pr_number, g.title, x.jevs_rules, s.model, f.files
      from claimed c join app.work_submissions x on x.id = c.submission_id join app.work_tasks t on t.id = x.task_id
      join app.work_github_prs g on g.number = x.pr_number join app.tl_files f on f.number = x.pr_number;
end
$$;

-- Third Look's answer (052's), for the site's timer, within its claim's time limit, with the gate checked
-- again at a pass.
create or replace function app.tl_decide(p_sub uuid, p_version text, p_model text, p_suggestion text, p_answers jsonb, p_reason text,
                                         p_fail_closed boolean, p_truncated boolean, p_latency_ms integer)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r record;
  s record;
  t record;
  st record;
  mode text;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records Third Look''s answers' using errcode = '42501';
  end if;
  if p_suggestion is null or p_suggestion <> all (array['pass', 'person']) or p_version is null or char_length(p_version) > 20
     or (p_model is not null and p_model <> all (array['mistral/ministral-14b'])) or p_latency_ms is null or p_latency_ms not between 0 and 600000
     or (p_answers is not null and (jsonb_typeof(p_answers) <> 'object' or octet_length(p_answers::text) > 400)) then
    raise exception 'bad Third Look answer' using errcode = '22023';
  end if;
  if p_suggestion = 'pass' and (p_answers is null or p_answers ->> 'a1' is distinct from 'yes' or p_answers ->> 'a2' is distinct from 'yes'
                                or p_answers ->> 'a3' is distinct from 'no' or coalesce(p_fail_closed, true) or coalesce(p_truncated, true) or p_model is null) then
    raise exception 'bad Third Look answer' using errcode = '22023';
  end if;
  select * into r from app.tl_reviews x where x.submission_id = p_sub for update;
  if r.id is null or r.decided_at is not null then return 'not_claimed'; end if;
  -- 057: an answer only within its claim's time limit; a later one changes nothing (the next claim releases the item).
  if r.claimed_at < now() - interval '3 minutes' then return 'expired'; end if;
  update app.tl_reviews x set version = p_version, model = p_model, suggestion = p_suggestion, answers = p_answers, reason = left(p_reason, 600),
    fail_closed = coalesce(p_fail_closed, true), truncated = coalesce(p_truncated, false), latency_ms = p_latency_ms, decided_at = now()
   where x.id = r.id;
  select x.mode into mode from app.tl_settings x where x.singleton;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  -- 057: the changed files it read are no longer needed (a later dispute asks GitHub again).
  delete from app.tl_files f where f.number = s.pr_number;
  if mode = 'on' and p_suggestion = 'person' and s.status = 'review' and s.route = 'admin' then
    perform app.notify(null, 'alert', 'Work waits for you', 'Third Look couldn''t pass this work, so it is yours to decide. '
      || coalesce(s.held_reason, ''), '/admin/review#work', 'submission', p_sub, 'work:held:' || p_sub);
  end if;
  -- Held work (an administrator is a party) that Third Look doubts isn't established, and no one else can decide it: the
  -- worker and the poster are told now, not left to find out when its wait ends.
  if mode = 'on' and p_suggestion = 'person' and s.status = 'review' and s.route = 'held' then
    select * into t from app.work_tasks x where x.id = s.task_id;
    perform app.notify(m.id, 'work_decided', 'This work can''t pass',
      'Third Look couldn''t confirm it, and no administrator who isn''t a party can decide it, so it won''t pass. It closes when its wait ends; then the task can be claimed again.',
      '/tasks/' || s.task_id, 'submission', p_sub, 'work:doubted:' || p_sub || ':' || m.id)
      from app.members m where m.id in (s.worker_member, coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)));
  end if;
  if mode <> 'on' or p_suggestion <> 'pass' then return p_suggestion; end if;
  if s.status <> 'review' or s.route is null or s.route <> all (array['admin', 'held']) then return 'decided_first'; end if;
  -- 057: the gate again at the pass: GitHub's own read still says Aaron's account merged it into main.
  if not exists (select 1 from app.work_github_prs g where g.number = s.pr_number and g.merged_at is not null and g.base = 'main'
                 and g.merge_read_at is not null and g.merged_by_id = (select w.merger_github_id from app.work_settings w where w.singleton)) then
    return 'not_owner_merged';
  end if;
  perform app.work_finish(p_sub, 'pass', 'third_look', 90, 'Passed by Third Look.');
  select * into t from app.work_tasks x where x.id = s.task_id;
  select * into st from app.work_settings where singleton;
  if app.work_pair_watch(p_sub, coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)))
     and not exists (select 1 from app.members m where m.is_admin
                     and m.id in (s.worker_member, coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent))))
     and not (t.source = 'github') then
    insert into app.work_checks (submission_id, why) values (p_sub, 'pair');
  elsif random() < st.tl_check_rate and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now()) and k.why = 'third_look') < st.tl_check_daily
     and not exists (select 1 from app.members m where m.is_admin
                     and m.id in (s.worker_member, coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent))))
     and not (t.source = 'github') then
    insert into app.work_checks (submission_id, why) values (p_sub, 'third_look');
  end if;
  return 'passed';
end
$$;

-- A claim given back: the model call was refused or failed, or GitHub's read of the change is missing. The work isn't
-- spent: it can be claimed again after 10 minutes. From the third release in a day, Aaron is told, once a day.
create function app.tl_release(p_sub uuid, p_why text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer gives Third Look''s work back' using errcode = '42501';
  end if;
  if p_sub is null or p_why is null or p_why !~ '^[a-z0-9 ():_-]{1,40}$' then
    raise exception 'bad Third Look release' using errcode = '22023';
  end if;
  delete from app.tl_reviews r where r.submission_id = p_sub and r.decided_at is null;
  if not found then return 'not_claimed'; end if;
  insert into app.tl_releases (submission_id, why) values (p_sub, p_why);
  select count(*) into n from app.tl_releases r where r.released_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  if n >= 3 then
    perform app.notify(null, 'alert', 'Third Look can''t reach its model', n || ' of Third Look''s calls today were given back unanswered (the latest: '
      || p_why || '). Nothing passes while this lasts: the work waits for an administrator to decide it.',
      '/admin/controls', null, null, 'thirdlook:released:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end if;
  return 'released';
end
$$;

-- Whether a number can be one of this repository's issues: not a pull request GitHub has shown the database, and at
-- most 100 past the newest one (GitHub numbers issues and pull requests in one sequence). For the log's proposals.
create function app.work_github_issue_ok(p_number integer)
returns boolean
language sql stable security definer set search_path = pg_catalog
as $$
  select p_number between 1 and 10000000
     and not exists (select 1 from app.work_github_prs g where g.number = p_number)
     and p_number <= coalesce((select max(g.number) from app.work_github_prs g), 0) + 100
$$;

revoke execute on function app.tl_claim(integer), app.tl_decide(uuid, text, text, text, jsonb, text, boolean, boolean, integer),
  app.tl_release(uuid, text), app.tl_wants(integer), app.tl_files_wanted(integer), app.tl_files_record(jsonb),
  app.work_github_issue_ok(integer) from public;
grant execute on function app.tl_claim(integer), app.tl_decide(uuid, text, text, text, jsonb, text, boolean, boolean, integer),
  app.tl_release(uuid, text) to dog_app;
grant execute on function app.tl_files_wanted(integer), app.tl_files_record(jsonb) to dog_ghsync;
grant execute on function app.work_github_issue_ok(integer) to dog_log;

set local role dog_owner;
revoke create on schema app from dog_work;

-- ---- The public log (038, 039): the witness reports itself; proposals from GitHub's facts ----
grant create on schema app to dog_log;
set local role dog_log;

create or replace function app.log_witness_report(p_size bigint, p_root bytea, p_witnessed_at timestamptz, p_alarm text) returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n bigint;
  w record;
  why text;
begin
  -- 057 (RK144): only the witness's own report, through dog-github, proved by GitHub's identity token from
  -- log-witness.yml on main, acting as dog_witness. A run can't be reported as later than now.
  if current_setting('role') is distinct from 'dog_witness' then
    raise exception 'only the witness workflow reports the witness (dog_witness)' using errcode = '42501';
  end if;
  if p_witnessed_at > now() then p_witnessed_at := now(); end if;
  select x.size into n from app.log_head x where x.singleton;
  select * into w from app.log_witness x where x.singleton for update;
  -- An alarm or a mismatch stays until a reviewed migration clears it (app.log_clear_alarm): nothing the site's login
  -- reports clears it, so a copy of the right root sent by the site itself can't mark the log verified (M3).
  if w.alarm then
    update app.log_witness x set witnessed_at = coalesce(p_witnessed_at, x.witnessed_at), checked_at = now() where x.singleton;
    return 'unverified';
  end if;
  if p_alarm is not null and p_alarm <> '' then
    why := 'The witness on GitHub raised an alarm: ' || left(regexp_replace(p_alarm, '[^ -~]', '', 'g'), 200);
  elsif p_size is null or p_root is null then
    update app.log_witness x set status = case when x.status = 'unverified' then x.status else 'unknown' end, checked_at = now() where x.singleton;
    return (select x.status from app.log_witness x where x.singleton);
  elsif octet_length(p_root) <> 32 or p_size < 1 then
    why := 'The witness''s copy on GitHub isn''t a checkpoint of this log.';
  elsif p_size > n then
    why := 'The witness on GitHub has a checkpoint of ' || p_size || ' entries, but the log has only ' || n || '.';
  elsif app.log_root(p_size) <> p_root then
    why := 'The witness''s copy of checkpoint ' || p_size || ' on GitHub doesn''t match this log''s tree.';
  end if;
  if why is not null then
    update app.log_witness x set witness_size = case when octet_length(p_root) = 32 then p_size else x.witness_size end,
      witnessed_at = p_witnessed_at, alarm = true where x.singleton;
    perform app.log_unverified(why);
    return 'unverified';
  end if;
  -- Once unverified, the log stays so until the reason is gone: a witness copy that matches again, and the tree
  -- reaching its own checkpoints. A witness that hasn't run for 12 hours is "stale": an alert, once a day (039).
  update app.log_witness x set status = case when not x.self_ok then 'unverified'
                                             when p_witnessed_at < now() - interval '12 hours' then 'stale' else 'ok' end,
    reason = case when not x.self_ok then x.reason when p_witnessed_at < now() - interval '12 hours'
                  then 'The witness on GitHub last ran ' || to_char(p_witnessed_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC.' else '' end,
    witness_size = p_size, witness_root = p_root, witnessed_at = p_witnessed_at, checked_at = now()
  where x.singleton;
  if p_witnessed_at < now() - interval '12 hours' then
    perform app.notify(null, 'alert', 'The public log''s witness has stopped', 'The witness job on GitHub last ran '
      || to_char(p_witnessed_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC, so new receipts show as not yet witnessed. The site keeps running.',
      '/security#log', null, null, 'log.stale.' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
  end if;
  return (select x.status from app.log_witness x where x.singleton);
end
$$;

-- The witness has stopped: no report for 12 hours (039's rule, which the site's own reports used to apply). Run by the
-- timer; it takes nothing from its caller and only reads the time, so an early or extra call changes nothing.
create function app.log_witness_check() returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
begin
  select * into w from app.log_witness x where x.singleton for update skip locked;
  if not found then return null; end if;
  if w.alarm or w.witnessed_at is null or w.witnessed_at >= now() - interval '12 hours' then return w.status; end if;
  if w.status <> all (array['stale', 'unverified']) then
    update app.log_witness x set status = 'stale', reason = 'The witness on GitHub last ran ' || to_char(w.witnessed_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC.',
      checked_at = now() where x.singleton;
  end if;
  perform app.notify(null, 'alert', 'The public log''s witness has stopped', 'The witness job on GitHub last ran '
    || to_char(w.witnessed_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC, so new receipts show as not yet witnessed. The site keeps running.',
    '/security#log', null, null, 'log.stale.' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
  return (select x.status from app.log_witness x where x.singleton);
end
$$;

-- Aaron's decision on a proposal, as GitHub's labels show it to the GitHub facts workflow (038's, for dog_ghsync only):
-- logged when it differs from the last one logged, and only as a real change (see the top of this file).
create or replace function app.log_proposal(p_number integer, p_decision text) returns bigint
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  last text;
  last_at timestamptz;
  recent integer;
  n bigint;
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function records proposal decisions (dog_ghsync)' using errcode = '42501';
  end if;
  if p_number is null or p_number < 1 or p_number > 10000000 or p_decision is null or p_decision <> all (array['approved', 'declined', 'shipped']) then
    raise exception 'a proposal number and approved, declined or shipped' using errcode = '22023';
  end if;
  -- Only a number that can be one of this repository's issues.
  if not app.work_github_issue_ok(p_number) then return null; end if;
  select s.decision, s.logged_at into last, last_at from app.log_proposals_seen s where s.number = p_number for update;
  if last is not distinct from p_decision then return null; end if;
  -- Along the labels' flow at once; a reversal at most once a day for each proposal.
  if last is not null and not (last = 'approved' and p_decision = 'shipped') and last_at > now() - interval '24 hours' then return null; end if;
  -- At most 30 an hour; the rest wait for a later run, and Aaron is told once a day.
  select count(*) into recent from app.log_proposals_seen s where s.logged_at > now() - interval '1 hour';
  if recent >= 30 then
    perform app.notify(null, 'alert', 'Proposal decisions are waiting', 'More than 30 proposal decisions arrived in an hour, so the public log takes the rest on later runs of the GitHub facts workflow.',
      '/security#log', null, null, 'log.proposals.cap.' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
    return null;
  end if;
  n := app.log_append('proposal.decided', now(), 'github:mychiefos', null, 'proposal:' || p_number::text,
         jsonb_build_object('proposal', p_number, 'decision', p_decision));
  insert into app.log_proposals_seen (number, decision, seq, logged_at) values (p_number, p_decision, n, now())
    on conflict (number) do update set decision = excluded.decision, seq = excluded.seq, logged_at = excluded.logged_at;
  return n;
end
$$;

-- p: [{number, status}], at most 100, from GitHub's labels as the GitHub facts workflow read them. Anything malformed
-- is skipped. Returns how many entries were added. Only for the GitHub facts function.
create function app.log_proposals_record(p jsonb) returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  x jsonb;
  added integer := 0;
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function records proposal decisions (dog_ghsync)' using errcode = '42501';
  end if;
  if p is null or jsonb_typeof(p) <> 'array' or jsonb_array_length(p) > 100 then
    raise exception 'bad proposal decisions' using errcode = '22023';
  end if;
  for x in select * from jsonb_array_elements(p) loop
    if jsonb_typeof(x) <> 'object' or coalesce(x ->> 'number', '') !~ '^[1-9][0-9]{0,6}$'
       or coalesce(x ->> 'status', '') <> all (array['approved', 'declined', 'shipped']) then
      continue;
    end if;
    if app.log_proposal((x ->> 'number')::integer, x ->> 'status') is not null then added := added + 1; end if;
  end loop;
  return added;
end
$$;

revoke execute on function app.log_witness_report(bigint, bytea, timestamptz, text), app.log_proposal(integer, text) from public, dog_app;
revoke execute on function app.log_witness_check(), app.log_proposals_record(jsonb) from public;
grant execute on function app.log_witness_report(bigint, bytea, timestamptz, text) to dog_witness;
grant execute on function app.log_proposals_record(jsonb) to dog_ghsync;
grant execute on function app.log_witness_check() to dog_app;

set local role dog_owner;
revoke create on schema app from dog_log;

