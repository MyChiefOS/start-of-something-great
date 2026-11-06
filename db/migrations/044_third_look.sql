-- 044 Third Look, a narrow AI for audits only, in shadow (Aaron, Nov 5: "Create an JEVs based auditor that separate and a
--   Third look limited only doing audit scope"; its decision loop ran Nov 6: the design, its fresh review, and Aaron's
--   "yes"). What it is, and what it is not:
--   * Scope: work the JEVs auditor's rules couldn't decide that waits for the task's poster or an administrator, and
--     only work it can actually read: a pull request in this repository, merged into main. It reads the task's title
--     and words, the worker's note and the pull request's title and changed lines (fetched from GitHub's public API by
--     the timer, at most 30,000 characters). Links and files are out of its scope: it opens nothing.
--   * It never decides. In shadow (the only mode this migration allows), its suggestion (pass, or leave it to a person)
--     is recorded and nothing else changes. The people deciding never see it before they decide (the fresh review of
--     its design, M2: a suggestion would bias the answers it is measured against). After they decide, the agreement
--     on its would-be passes is counted, publicly.
--   * Code decides its suggestion, never the model (the review, M1; Second Look's way): the model answers three fixed
--     questions about data between markers it can't know, and code suggests a pass only when all three answers say so,
--     no fixed check found anything, and nothing was cut short. Any failure suggests "a person".
--   * Mode "on" (it deciding, within limits, with a stop on reversals) is not here: it comes in its own change, once
--     its shadow record is long enough (at least 80 agreeing passes, the bar Second Look uses) and disputes have run.
--   * A model on Vercel's AI Gateway (mistral/ministral-14b, $0.20 per million tokens, a 32,000-token window), signed in
--     with the site's own Vercel identity token: no key. At most daily_call_cap (30) calls a day, so with Second Look it
--     stays within the gateway's $5 a month of free usage (inferred from those prices; the stop is the cap).
-- Who may do what: the timer (the site's role, as an anonymous visitor) asks for the next items (app.tl_claim) and
-- records an answer on an item it was given, once (app.tl_decide). Both are this module's (dog_work) and check the
-- gate again. An administrator may switch it off and on (app.tl_set_mode). The figures are public (app.tl_figures).

set local role dog_owner;
create table app.tl_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  mode text not null default 'shadow' check (mode = any (array['off', 'shadow'])),
  model text not null default 'mistral/ministral-14b' check (model = any (array['mistral/ministral-14b'])),
  daily_call_cap integer not null default 30 check (daily_call_cap between 0 and 200),
  last_claim_at timestamptz,
  updated_at timestamptz not null default now()
);
insert into app.tl_settings default values;
-- One row per submission it was given (one try each), with its answer once it has one.
create table app.tl_reviews (
  id uuid primary key default app.uuid_v7(),
  submission_id uuid not null unique references app.work_submissions (id) on delete cascade,
  claimed_at timestamptz not null default now(),
  version text check (char_length(version) <= 20),
  model text check (char_length(model) <= 80),
  suggestion text check (suggestion = any (array['pass', 'person'])),
  answers jsonb check (octet_length(answers::text) <= 400) check (jsonb_typeof(answers) = 'object'),  -- null when there is no answer
  reason text check (char_length(reason) <= 600),
  fail_closed boolean,
  truncated boolean,
  latency_ms integer check (latency_ms between 0 and 600000),
  decided_at timestamptz
);
create index tl_reviews_claimed on app.tl_reviews (claimed_at);
do $rls$
declare
  t text;
begin
  foreach t in array array['tl_settings', 'tl_reviews'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('alter table app.%I force row level security', t);
    execute format('create policy %I on app.%I for all to dog_work using (true) with check (true)', t || '_work', t);
  end loop;
end
$rls$;
grant select, update (mode, last_claim_at, updated_at) on app.tl_settings to dog_work;
grant select, insert, update on app.tl_reviews to dog_work;

grant create on schema app to dog_work;
set local role dog_work;

-- The next items for Third Look: at most p_n (1 to 3), at most once every 50 seconds, within the daily cap, never in
-- off mode, each once. Only work waiting for a person that is a merged pull request in this repository.
create function app.tl_claim(p_n integer)
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
       where x.status = 'review' and x.route in ('poster', 'admin') and x.artifact_kind = 'pr' and g.merged_at is not null and g.base = 'main'
         and not exists (select 1 from app.tl_reviews r where r.submission_id = x.id)
       order by x.created_at, x.id
       limit least(p_n, s.daily_call_cap - today)
       for update of x skip locked),
    claimed as (insert into app.tl_reviews (submission_id) select id from picked returning tl_reviews.submission_id)
    select x.id, t.title, t.description, x.note, x.pr_number, g.title, x.jevs_rules, s.model
      from claimed c join app.work_submissions x on x.id = c.submission_id join app.work_tasks t on t.id = x.task_id
      join app.work_github_prs g on g.number = x.pr_number;
end
$$;

-- Records Third Look's answer on an item it was given, once. In shadow nothing else changes.
create function app.tl_decide(p_sub uuid, p_version text, p_model text, p_suggestion text, p_answers jsonb, p_reason text,
                              p_fail_closed boolean, p_truncated boolean, p_latency_ms integer)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r record;
begin
  if p_suggestion is null or p_suggestion <> all (array['pass', 'person']) or p_version is null or char_length(p_version) > 20
     or (p_model is not null and p_model <> all (array['mistral/ministral-14b'])) or p_latency_ms is null or p_latency_ms not between 0 and 600000
     or (p_answers is not null and (jsonb_typeof(p_answers) <> 'object' or octet_length(p_answers::text) > 400)) then
    raise exception 'bad Third Look answer' using errcode = '22023';
  end if;
  -- A pass needs the model's three answers, each what a pass needs: the suggestion can't claim more than they say.
  if p_suggestion = 'pass' and (p_answers is null or p_answers ->> 'a1' is distinct from 'yes' or p_answers ->> 'a2' is distinct from 'yes'
                                or p_answers ->> 'a3' is distinct from 'no' or coalesce(p_fail_closed, true) or coalesce(p_truncated, true) or p_model is null) then
    raise exception 'bad Third Look answer' using errcode = '22023';
  end if;
  select * into r from app.tl_reviews x where x.submission_id = p_sub for update;
  if r.id is null or r.decided_at is not null then return 'not_claimed'; end if;
  update app.tl_reviews x set version = p_version, model = p_model, suggestion = p_suggestion, answers = p_answers, reason = left(p_reason, 600),
    fail_closed = coalesce(p_fail_closed, true), truncated = coalesce(p_truncated, false), latency_ms = p_latency_ms, decided_at = now()
   where x.id = r.id;
  return p_suggestion;
end
$$;

-- The public figures: how many it checked, and on its would-be passes, how the people deciding decided (agreed: they
-- passed it and it wasn't reversed; disagreed: they failed it, or it was reversed). Counts of 1 to 4 show as null.
create function app.tl_figures()
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  with n as (
    select count(*) filter (where r.decided_at is not null) as checked,
           count(*) filter (where r.suggestion = 'pass') as would_pass,
           count(*) filter (where r.suggestion = 'pass' and s.status = 'passed') as agreed,
           count(*) filter (where r.suggestion = 'pass' and s.status in ('failed', 'reversed')) as disagreed,
           count(*) filter (where r.fail_closed) as no_answer
      from app.tl_reviews r join app.work_submissions s on s.id = r.submission_id)
  select jsonb_build_object('mode', (select x.mode from app.tl_settings x where x.singleton), 'scope', 'merged pull requests waiting for a person',
    'checked', case when n.checked between 1 and 4 then null else n.checked end,
    'would_pass', case when n.would_pass between 1 and 4 then null else n.would_pass end,
    'agreed', case when n.agreed between 1 and 4 then null else n.agreed end,
    'disagreed', case when n.disagreed between 1 and 4 then null else n.disagreed end,
    'no_answer', case when n.no_answer between 1 and 4 then null else n.no_answer end)
  from n
$$;

-- An administrator switches Third Look off, or back to shadow.
create function app.tl_set_mode(p_mode text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator' using errcode = '42501'; end if;
  if p_mode is null or p_mode <> all (array['off', 'shadow']) then raise exception 'bad mode' using errcode = '22023'; end if;
  update app.tl_settings set mode = p_mode, updated_at = now() where singleton;
  return p_mode;
end
$$;

-- The Build page's figures gain Third Look's (042's app.work_summary otherwise word for word).
create or replace function app.work_summary()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  anchored bigint := app.work_anchored_through();
  latest record;
begin
  select s.* into latest from app.work_submissions s join app.work_tasks t on t.id = s.task_id
   where s.status = 'passed' and t.status <> 'removed' order by s.decided_at desc, s.id desc limit 1;
  return jsonb_build_object(
    'generated_at', now(),
    'tasks', (select count(*) from app.work_tasks t where t.status not in ('closed', 'removed')),
    'approved', (select count(*) from app.work_tasks t where t.status = 'approved'),
    'anchored', (select count(*) from app.work_tasks t where t.status = 'approved' and t.approved_seq < anchored),
    'open', (select count(*) from app.work_tasks t where t.status = 'open'),
    'in_progress', (select count(*) from app.work_tasks t where t.status in ('claimed', 'submitted', 'audited')),
    'projects', (select count(*) from app.work_projects p where p.status = 'open'),
    'points_final', (select coalesce(sum(x.points), 0) from app.work_points x where x.status = 'final'),
    'points_pending', (select coalesce(sum(x.points), 0) from app.work_points x where x.status = 'pending'),
    'waiting_for_poster', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'poster'),
    'waiting_for_admin', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'admin')
                         + (select count(*) from app.work_checks k where k.status = 'open') + (select count(*) from app.work_disputes d where d.status = 'open'),
    'held_for_third_look', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'held'),
    -- Third Look, in shadow (044): how many it checked, and on the ones it would have passed, whether the people who
    -- decided agreed. Counts of 1 to 4 show as null ("fewer than 5"), as the other public oversight figures do (041).
    'third_look', app.tl_figures(),
    'checkpoint', anchored,
    'packages', coalesce((select jsonb_agg(app.work_project_card(q.id) order by q.updated_at desc, q.id desc) from (
        select p.id, p.updated_at from app.work_projects p where p.status = 'open' order by p.updated_at desc, p.id desc limit 6) q), '[]'::jsonb),
    'board', coalesce((select jsonb_agg(app.work_card(q.id) order by q.updated_at desc, q.id desc) from (
        select t.id, t.updated_at from app.work_tasks t where t.status not in ('closed', 'removed') order by t.updated_at desc, t.id desc limit 8) q), '[]'::jsonb),
    'weeks', coalesce((select jsonb_agg(jsonb_build_object('week', w.d, 'scope', (select count(*) from app.work_tasks t where t.created_at < w.d + interval '7 days' and t.status <> 'removed'),
                                                          'verified', (select count(*) from app.work_tasks t where t.status = 'approved' and t.approved_at < w.d + interval '7 days'
                                                                       and t.approved_seq < anchored)) order by w.d)
                       from (select generate_series(date_trunc('week', now()) - interval '5 weeks', date_trunc('week', now()), interval '1 week') as d) w), '[]'::jsonb),
    'latest_receipt', case when latest.id is null then null else jsonb_build_object(
        'task', app.work_card(latest.task_id), 'submission', latest.id, 'seq', latest.decided_seq, 'anchored', latest.decided_seq < anchored,
        'worker', app.work_display(case when latest.worker_kind = 'member' then latest.worker_member end, latest.worker_agent, latest.worker_github),
        'artifact', jsonb_build_object('kind', latest.artifact_kind, 'url', latest.artifact_url, 'sha256', latest.artifact_sha256),
        'decided_by', latest.decided_by, 'confidence', latest.confidence, 'decided_at', latest.decided_at,
        'points', (select x.points from app.work_points x where x.submission_id = latest.id),
        'approved_seq', (select t.approved_seq from app.work_tasks t where t.id = latest.task_id)) end,
    'live', coalesce((select jsonb_agg(jsonb_build_object('seq', e.seq, 'type', e.type, 'at', e.created_at, 'actor', e.actor,
                                                          'subject', e.subject, 'anchored', e.seq < anchored) order by e.seq desc)
                      from (select x.seq, x.type, x.created_at, x.actor, x.subject from app.log_entries x
                            where x.type = any (array['task.claimed', 'task.submitted', 'audit.verdict', 'task.approved'])
                            order by x.seq desc limit 6) e), '[]'::jsonb));
end
$$;


revoke execute on function app.tl_claim(integer), app.tl_decide(uuid, text, text, text, jsonb, text, boolean, boolean, integer),
  app.tl_figures(), app.tl_set_mode(text) from public;
grant execute on function app.tl_claim(integer), app.tl_decide(uuid, text, text, text, jsonb, text, boolean, boolean, integer),
  app.tl_figures(), app.tl_set_mode(text) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
