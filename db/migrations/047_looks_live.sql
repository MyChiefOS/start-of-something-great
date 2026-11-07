-- 047 Second Look and Third Look live (Aaron, Nov 6: "I do not want blockers. So, make things read only and not live
-- till later etc. I don't agree with that approach. Make sure we are doing things to create a fully functional
-- production system"; and his earlier "Live, plus reversal").
--   * Second Look: on. It publishes the easy held posts itself (at most its daily cap, a notice to the administrator for
--     each), as it would have after its unlock (034). Its own safeguard stays: if removals of what it publishes go above
--     1 in 80, it pauses itself back to shadow and says so.
--     Its re-read of a 5% sample of posts that went live as low risk (041) is switched on too.
--   * Third Look: a new mode, on, and on now. When it suggests a pass, the work passes: decided_by third_look, confidence
--     90, the points pending for the dispute window as any pass, the task's poster told to approve as after any audit.
--     "A person" changes nothing: the poster or an administrator decides, as before. Its scope gains held work (an
--     administrator is a party, so no administrator may decide it): a merged pull request there no longer waits out
--     the clock to fail.
--   * Reversal, the safety net: every Third Look pass can be disputed while its points are pending, an administrator who
--     isn't a party can reverse it, and one in five is checked again after (why third_look, within the day's checks),
--     unless an administrator is a party. Its public figures count its passes and how many were reversed.
-- 044's tl_claim, tl_decide, tl_figures and tl_set_mode are re-created; nothing else changes.

set local role dog_owner;
alter table app.tl_settings drop constraint tl_settings_mode_check;
alter table app.tl_settings add constraint tl_settings_mode_check check (mode = any (array['off', 'shadow', 'on']));
alter table app.work_submissions drop constraint work_submissions_decided_by_check;
alter table app.work_submissions add constraint work_submissions_decided_by_check check (decided_by = any (array['jevs', 'poster', 'person', 'timeout', 'third_look']));
alter table app.work_checks drop constraint work_checks_why_check;
alter table app.work_checks add constraint work_checks_why_check check (why = any (array['random', 'size', 'pair', 'note', 'third_look']));
alter table app.work_settings add column tl_check_rate numeric(4, 3) not null default 0.200 check (tl_check_rate between 0 and 1);
grant select (tl_check_rate) on app.work_settings to dog_work;

-- Second Look on, as its unlock would (034's app.sl_unlock), recorded in the audit log.
set local role dog_jevs;
update app.sl_settings set mode = 'on', counted_since = now(), paused_reason = null, updated_at = now() where singleton and mode <> 'on';
insert into app.audit_log (action, subject_kind, subject_id, detail)
  values ('secondlook.mode', null, null, jsonb_build_object('from', 'shadow', 'to', 'on', 'by', 'migration 047, on Aaron''s decision of Nov 6'));
-- And its re-read of a sample of posts that went live as low risk (041's review_set_sample): on, at 5%, as the
-- administrator's switch would set it. Its owner writes it, with row-level security lifted inside this transaction only.
set local role dog_owner;
alter table app.review_settings no force row level security;
update app.review_settings set sample_rate = 0.05, updated_at = now() where singleton and sample_rate = 0;
alter table app.review_settings force row level security;
set local role dog_jevs;
insert into app.audit_log (action, subject_kind, subject_id, detail)
  values ('review.settings', null, null, jsonb_build_object('sample_rate', 0.05, 'by', 'migration 047, on Aaron''s decision of Nov 6'));

set local role dog_owner;
grant create on schema app to dog_work;
set local role dog_work;

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
       where x.status = 'review' and x.route in ('poster', 'admin', 'held') and x.artifact_kind = 'pr' and g.merged_at is not null and g.base = 'main'
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

-- Records Third Look's answer on an item it was given, once. On: a pass passes the work, if it still waits for its
-- person; then one in five is checked again after. In shadow, only the record.
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
  select x.mode into mode from app.tl_settings x where x.singleton;
  if mode <> 'on' or p_suggestion <> 'pass' then return p_suggestion; end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  -- Someone decided it first: the record stays, nothing else.
  if s.status <> 'review' or s.route is null or s.route <> all (array['poster', 'admin', 'held']) then return 'decided_first'; end if;
  perform app.work_finish(p_sub, 'pass', 'third_look', 90, left('Passed by Third Look: ' || coalesce(p_reason, ''), 300));
  select * into t from app.work_tasks x where x.id = s.task_id;
  select * into st from app.work_settings where singleton;
  if random() < st.tl_check_rate and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now())) < st.check_daily
     and not exists (select 1 from app.members m where m.is_admin
                     and m.id in (s.worker_member, coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent))))
     and not (t.source = 'github') then
    insert into app.work_checks (submission_id, why) values (p_sub, 'third_look');
  end if;
  return 'passed';
end
$$;

-- The public figures: how many it checked, how many it passed (on) or would have passed (shadow), and how those
-- passes held up (agreed: passed and not reversed; disagreed: failed by the person deciding, or reversed). Counts of 1 to
-- 4 show as null.
create or replace function app.tl_figures()
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  with n as (
    select count(*) filter (where r.decided_at is not null) as checked,
           count(*) filter (where r.suggestion = 'pass') as would_pass,
           count(*) filter (where r.suggestion = 'pass' and s.decided_by = 'third_look') as passed,
           count(*) filter (where r.suggestion = 'pass' and s.status = 'passed') as agreed,
           count(*) filter (where r.suggestion = 'pass' and s.status in ('failed', 'reversed')) as disagreed,
           count(*) filter (where r.fail_closed) as no_answer
      from app.tl_reviews r join app.work_submissions s on s.id = r.submission_id)
  select jsonb_build_object('mode', (select x.mode from app.tl_settings x where x.singleton), 'scope', 'merged pull requests waiting for a person',
    'checked', case when n.checked between 1 and 4 then null else n.checked end,
    'would_pass', case when n.would_pass between 1 and 4 then null else n.would_pass end,
    'passed', case when n.passed between 1 and 4 then null else n.passed end,
    'agreed', case when n.agreed between 1 and 4 then null else n.agreed end,
    'disagreed', case when n.disagreed between 1 and 4 then null else n.disagreed end,
    'no_answer', case when n.no_answer between 1 and 4 then null else n.no_answer end)
  from n
$$;

-- An administrator switches Third Look off, to shadow, or on.
create or replace function app.tl_set_mode(p_mode text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator' using errcode = '42501'; end if;
  if p_mode is null or p_mode <> all (array['off', 'shadow', 'on']) then raise exception 'bad mode' using errcode = '22023'; end if;
  update app.tl_settings set mode = p_mode, updated_at = now() where singleton;
  return p_mode;
end
$$;

-- 045's app.work_network, word for word but for one change: a pass by Third Look is an audit by a third party too.
-- From my network: trust from the signed-in viewer (a person with their agents, or an agent with its owner) along
-- audited collaborations, halved at each hop, at most 3 hops, split by each citizen's collaborations; then the board's
-- figures for each citizen it reaches, highest trust first (at most 100). Trust is shown out of 100 (the most trusted).
create or replace function app.work_network()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  w record;
  seeds text[];
  nodes text[];
  mass float8[];
  tot_nodes text[] := '{}';
  tot_mass float8[] := '{}';
  hop integer;
  top float8;
begin
  select * into w from app.work_who();
  seeds := array(select 'member:' || w.member_id::text
                 union select 'agent:' || g.id::text from app.agents g where g.owner_id = w.member_id);
  nodes := seeds;
  mass := array(select (1.0 / cardinality(seeds))::float8 from unnest(seeds));
  for hop in 1..3 loop
    with e0 as (
      -- An audited collaboration: work a third party passed (the JEVs auditor's rules or an administrator), between the
      -- task's poster and its worker, who have different owners.
      select case when t.poster_agent is not null then 'agent:' || t.poster_agent::text else 'member:' || t.poster_member::text end as a,
             case when s.worker_kind = 'agent' then 'agent:' || s.worker_agent::text else 'member:' || s.worker_member::text end as b
        from app.work_submissions s join app.work_tasks t on t.id = s.task_id
       where s.status = 'passed' and s.decided_by in ('jevs', 'person', 'third_look') and s.worker_kind in ('member', 'agent') and t.status <> 'removed'
         and (t.poster_member is not null or t.poster_agent is not null)
         and coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) <> s.worker_member),
    e as (select a as src, b as dst from e0 union all select b, a from e0),
    ew as (select src, dst, count(*)::float8 / sum(count(*)) over (partition by src) as p from e group by src, dst),
    step as (select ew.dst as node, sum(f.m * 0.5 * ew.p) as m
               from unnest(nodes, mass) f(node, m) join ew on ew.src = f.node group by ew.dst)
    select coalesce(array_agg(step.node), '{}'), coalesce(array_agg(step.m), '{}') into nodes, mass from step;
    exit when cardinality(nodes) = 0;
    tot_nodes := tot_nodes || nodes;
    tot_mass := tot_mass || mass;
  end loop;
  select max(q.m) into top from (select sum(m) as m from unnest(tot_nodes, tot_mass) f(node, m) where node <> all (seeds) group by node) q;
  return jsonb_build_object('generated_at', now(), 'hops', 3, 'decay', 0.5,
    'citizens', coalesce((select jsonb_agg(app.work_profile(x) || jsonb_build_object('trust', round((100 * t.m / top)::numeric, 1)) order by t.m desc, x.ref)
        from (select split_part(node, ':', 1) as kind, split_part(node, ':', 2) as ref, sum(m) as m
                from unnest(tot_nodes, tot_mass) f(node, m) where node <> all (seeds) group by node order by 3 desc limit 100) t
        join app.work_stats(null) x on x.kind = t.kind and x.ref = t.ref), '[]'::jsonb));
end
$$;

update app.tl_settings set mode = 'on', updated_at = now() where singleton;

set local role dog_owner;
revoke create on schema app from dog_work;
