-- 077 The model reviewers, the random auditor and the Fable 5.2 oversight report (Aaron, Nov 24: the diagram's exploit
--   researcher, penetration tester, quality assurance, solution architect, random auditors, and "A Fable 5.2 Box around
--   everything ... an oversight roll ... to create the report we agreed to"; "do not [take] steps to generate lots of
--   cost [that] are not required"). Recorded in harness/FACTS.md: every paid part is built with its switch off until
--   Aaron sets a monthly cap.
--
--   1. Model reviewers (exploit researcher, penetration tester reading only, quality assurance, solution architect):
--      each reads one finished piece of work and answers "ok" or "concern" with a reason. They advise only: they never
--      pass, fail, hold or score work. Each role's switch starts off, and the monthly cap starts at $0, so no model is
--      called until Aaron turns a role on and sets a cap. Spending is counted per call at the role's price; a call that
--      would pass the month's cap is not made.
--   2. The random auditor (free: no model): samples 1 in 20 of the Wall's allowed decisions and of passed work, for a
--      person to look at in the audit queue. On.
--   3. The oversight report (free part on): each day, a read-only report of facts: the Wall's chain, the wiki's age, the
--      checks' counts, the lanes, the watchtower's alerts, the timer's failures. The model narrative (Fable 5.2, checked
--      weekly by a model from a different maker) is a role like the others: off, $0.

set local role dog_owner;

create table app.oversight_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  -- US dollars a month for every model role together; 0 means no model call at all.
  monthly_cap_cents integer not null default 0 check (monthly_cap_cents between 0 and 1000000),
  audit_one_in integer not null default 20 check (audit_one_in between 1 and 1000),
  report_on boolean not null default true
);
insert into app.oversight_settings (singleton) values (true);

create table app.oversight_roles (
  id uuid primary key default app.uuid_v7(),
  role text not null unique check (role = any (array['exploit_researcher', 'penetration_tester', 'quality_assurance', 'solution_architect', 'fable_report', 'fable_crosscheck'])),
  mode text not null default 'off' check (mode = any (array['off', 'on'])),
  model text not null check (char_length(model) between 3 and 80 and model ~ '^[a-z0-9-]+/[a-z0-9.:-]+$'),
  -- The price of one call, in hundredths of a cent, for the spending count.
  call_price_centi_cents integer not null check (call_price_centi_cents between 1 and 100000),
  daily_call_cap integer not null default 50 check (daily_call_cap between 0 and 5000)
);
-- Claude's plan of Nov 24 (open to Aaron, harness/FACTS.md): a candidate per role, mixed makers. IDs and per-token
-- prices checked in the AI Gateway catalog on Nov 24; a call's price is an estimate (about 10,000 tokens in and 300 out
-- for a review, 30,000 in and 2,000 out for the report), rounded up. Quality not yet measured (the $20 benchmark is
-- Aaron's decision).
insert into app.oversight_roles (role, model, call_price_centi_cents) values
  ('exploit_researcher', 'anthropic/claude-haiku-5.5', 12),
  ('penetration_tester', 'alibaba/qwen3-coder-30b-a3b', 17),
  ('quality_assurance', 'mistral/ministral-14b', 10),
  ('solution_architect', 'deepseek/deepseek-v3.2', 68),
  ('fable_report', 'anthropic/claude-fable-5.2', 3200),
  ('fable_crosscheck', 'openai/gpt-5-mini', 115);

create table app.oversight_calls (
  id uuid primary key default app.uuid_v7(),
  role text not null check (role = any (array['exploit_researcher', 'penetration_tester', 'quality_assurance', 'solution_architect', 'fable_report', 'fable_crosscheck'])),
  submission_id uuid references app.work_submissions (id) on delete cascade,
  model text not null check (char_length(model) <= 80),
  verdict text check (verdict = any (array['ok', 'concern'])),
  reason text check (char_length(reason) <= 300),
  error text check (char_length(error) <= 40),
  centi_cents integer not null check (centi_cents between 0 and 100000),
  created_at timestamptz not null default now()
);
create index oversight_calls_at on app.oversight_calls (created_at);
create index oversight_calls_sub on app.oversight_calls (submission_id, role);

create table app.audit_samples (
  id uuid primary key default app.uuid_v7(),
  kind text not null check (kind = any (array['wall_allow', 'passed_work'])),
  ref uuid not null,
  status text not null default 'open' check (status = any (array['open', 'looked', 'concern'])),
  note text check (char_length(note) <= 300),
  created_at timestamptz not null default now(),
  unique (kind, ref)
);

create table app.oversight_reports (
  id uuid primary key default app.uuid_v7(),
  day date not null unique,
  facts jsonb not null check (jsonb_typeof(facts) = 'object' and octet_length(facts::text) <= 20000),
  narrative text check (char_length(narrative) <= 4000),
  created_at timestamptz not null default now()
);

do $rls$
declare t text;
begin
  foreach t in array array['oversight_settings', 'oversight_roles', 'oversight_calls', 'audit_samples', 'oversight_reports'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('alter table app.%I force row level security', t);
    execute format('create policy %I on app.%I for all to dog_work using (true) with check (true)', t || '_work', t);
    execute format('create policy %I on app.%I for select to dog_owner using (true)', t || '_owner', t);
    execute format('grant select, insert, update on app.%I to dog_work', t);
  end loop;
end
$rls$;
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- The timer asks for work for one model role. Nothing when the role is off, the month's cap is reached (or $0), or the
-- day's calls are used. Returns the items (submission, model) and reserves the price of each against the cap.
create function app.oversight_claim(p_role text, p_n integer) returns table (submission_id uuid, model text)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  r record;
  spent bigint;
  today integer;
  k integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the model reviewers' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 3 then raise exception 'bad claim' using errcode = '22023'; end if;
  select * into s from app.oversight_settings x where x.singleton;
  select * into r from app.oversight_roles x where x.role = p_role for update;
  if r.id is null or r.mode = 'off' or s.monthly_cap_cents = 0 or r.role in ('fable_report', 'fable_crosscheck') then return; end if;
  select coalesce(sum(c.centi_cents), 0) into spent from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC';
  select count(*) into today from app.oversight_calls c where c.role = p_role and c.created_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  k := least(p_n, r.daily_call_cap - today, ((s.monthly_cap_cents::bigint * 100 - spent) / r.call_price_centi_cents)::integer);
  if k < 1 then return; end if;
  return query
    with picked as (
      select x.id from app.work_submissions x
       where x.status in ('waiting', 'review', 'passed') and x.created_at > now() - interval '2 days'
         and not exists (select 1 from app.oversight_calls c where c.submission_id = x.id and c.role = p_role)
       order by x.created_at limit k),
    booked as (insert into app.oversight_calls (role, submission_id, model, centi_cents, error)
               select p_role, picked.id, r.model, r.call_price_centi_cents, 'pending' from picked returning oversight_calls.submission_id)
    select b.submission_id, r.model from booked b;
end $$;

-- What a claimed reviewer reads: the task's words, the worker's note and link, and a pull request's changed files.
-- Only for an item claimed for that role and not yet answered.
create function app.oversight_item(p_role text, p_sub uuid) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer reads work for the model reviewers' using errcode = '42501';
  end if;
  if not exists (select 1 from app.oversight_calls c where c.role = p_role and c.submission_id = p_sub and c.error = 'pending') then return null; end if;
  return (select jsonb_build_object('title', t.title, 'description', t.description, 'note', x.note, 'link', x.artifact_url,
            'files', (select f.files from app.tl_files f where f.number = x.pr_number))
            from app.work_submissions x join app.work_tasks t on t.id = x.task_id where x.id = p_sub);
end $$;

-- The answer for one claimed item (or the failure). Advisory: nothing about the work changes.
create function app.oversight_record(p_role text, p_sub uuid, p_verdict text, p_reason text, p_error text) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records the model reviewers' using errcode = '42501';
  end if;
  update app.oversight_calls c set verdict = case when p_error is null then p_verdict end, reason = left(p_reason, 300), error = left(p_error, 40)
   where c.role = p_role and c.submission_id = p_sub and c.error = 'pending';
  return found;
end $$;

-- The random auditor and the day's oversight report. Free: no model.
create function app.oversight_run() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  n integer := 0;
  today date := (now() at time zone 'UTC')::date;
  f jsonb;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the auditor and the report' using errcode = '42501';
  end if;
  select * into s from app.oversight_settings x where x.singleton;
  -- 1 in N, chosen by a hash of the row's ID, so the choice can't be steered by timing and is the same on every run.
  insert into app.audit_samples (kind, ref)
    select 'wall_allow', d.id from app.wall_decisions d
     where d.decision = 'allow' and d.created_at > now() - interval '1 day'
       and ('x' || substr(encode(sha256(convert_to(d.id::text, 'UTF8')), 'hex'), 1, 8))::bit(32)::bigint % s.audit_one_in = 0
    on conflict do nothing;
  get diagnostics n = row_count;
  insert into app.audit_samples (kind, ref)
    select 'passed_work', x.id from app.work_submissions x
     where x.status = 'passed' and x.decided_at > now() - interval '1 day'
       and ('x' || substr(encode(sha256(convert_to(x.id::text, 'UTF8')), 'hex'), 1, 8))::bit(32)::bigint % s.audit_one_in = 0
    on conflict do nothing;
  if s.report_on and not exists (select 1 from app.oversight_reports r where r.day = today) then
    f := jsonb_build_object(
      'wall_chain_ok', app.wall_chain_ok(),
      'wall_mode', (select w.mode from app.wall_settings w where w.singleton),
      'wall_last_day', (select jsonb_build_object('allow', count(*) filter (where d.decision = 'allow'), 'hold', count(*) filter (where d.decision = 'hold'))
                          from app.wall_decisions d where d.created_at > now() - interval '1 day'),
      'wall_reviews_last_7_days', (select jsonb_build_object('false_positive', count(*) filter (where r.verdict = 'false_positive'), 'confirmed', count(*) filter (where r.verdict = 'confirmed'))
                          from app.wall_reviews r where r.created_at > now() - interval '7 days'),
      'wiki_active_since', (select v.created_at from app.wiki_versions v where v.status = 'active'),
      'wiki_last_run_at', (select w.last_run_at from app.wiki_settings w where w.singleton),
      'wiki_refused_last_7_days', (select count(*) from app.wiki_versions v where v.status = 'refused' and v.created_at > now() - interval '7 days'),
      'watchtower_alerts_last_day', (select count(*) from app.notices n where n.member_id is null and n.dedupe_key like 'watchtower:%' and n.created_at > now() - interval '1 day'),
      'submissions_last_day', (select jsonb_build_object('total', count(*), 'passed', count(*) filter (where x.status = 'passed'), 'failed', count(*) filter (where x.status = 'failed'),
                          'review', count(*) filter (where x.status = 'review')) from app.work_submissions x where x.created_at > now() - interval '1 day'),
      'audit_samples_open', (select count(*) from app.audit_samples a where a.status = 'open'),
      'model_spend_this_month_cents', (select coalesce(sum(c.centi_cents), 0) / 100 from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC'),
      'model_roles_on', (select coalesce(jsonb_agg(r.role order by r.role), '[]'::jsonb) from app.oversight_roles r where r.mode = 'on'));
    insert into app.oversight_reports (day, facts) values (today, f) on conflict (day) do nothing;
  end if;
  return n;
end $$;

-- For an administrator: the newest reports, the open audit samples, the model roles and this month's spending.
create function app.oversight_admin() returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator reads the oversight report' using errcode = '42501'; end if;
  return jsonb_build_object(
    'reports', coalesce((select jsonb_agg(jsonb_build_object('day', r.day, 'facts', r.facts, 'narrative', r.narrative) order by r.day desc)
                 from (select * from app.oversight_reports x order by x.day desc limit 7) r), '[]'::jsonb),
    'samples', coalesce((select jsonb_agg(jsonb_build_object('id', a.id, 'kind', a.kind, 'ref', a.ref, 'at', a.created_at) order by a.created_at)
                 from (select * from app.audit_samples x where x.status = 'open' order by x.created_at limit 100) a), '[]'::jsonb),
    'roles', (select jsonb_agg(jsonb_build_object('role', r.role, 'mode', r.mode, 'model', r.model, 'daily_call_cap', r.daily_call_cap) order by r.role) from app.oversight_roles r),
    'monthly_cap_cents', (select s.monthly_cap_cents from app.oversight_settings s where s.singleton),
    'spent_this_month_cents', (select coalesce(sum(c.centi_cents), 0) / 100 from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC'),
    'concerns', coalesce((select jsonb_agg(jsonb_build_object('role', c.role, 'submission', c.submission_id, 'reason', c.reason, 'at', c.created_at) order by c.created_at desc)
                 from (select * from app.oversight_calls x where x.verdict = 'concern' order by x.created_at desc limit 50) c), '[]'::jsonb));
end $$;

-- An administrator closes an audit sample: looked at, or a concern (with a note).
create function app.audit_sample_close(p_id uuid, p_status text, p_note text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator closes an audit sample' using errcode = '42501'; end if;
  if p_status is null or p_status <> all (array['looked', 'concern']) or (p_note is not null and char_length(p_note) > 300) then
    raise exception 'bad audit sample' using errcode = '22023';
  end if;
  update app.audit_samples a set status = p_status, note = p_note where a.id = p_id and a.status = 'open';
  if not found then raise exception 'no such open sample' using errcode = 'P0002'; end if;
  perform app.audit_add('audit_sample', 'audit_sample', p_id, jsonb_build_object('status', p_status));
  return p_status;
end $$;

revoke execute on function app.oversight_item(text, uuid), app.oversight_claim(text, integer), app.oversight_record(text, uuid, text, text, text), app.oversight_run(),
  app.oversight_admin(), app.audit_sample_close(uuid, text, text) from public;
grant execute on function app.oversight_item(text, uuid), app.oversight_claim(text, integer), app.oversight_record(text, uuid, text, text, text), app.oversight_run(),
  app.oversight_admin(), app.audit_sample_close(uuid, text, text) to dog_app;
reset role;
revoke create on schema app from dog_work;
