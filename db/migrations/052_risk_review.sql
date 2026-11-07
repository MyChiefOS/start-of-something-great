-- 052 Review by risk, not by count; two witnesses for risky work; no one judges their own case (the fresh review of
-- #112 to #116, Nov 7: H1, M1, M2, L1, L2, L3; Aaron's answers the same day).
--   Aaron, Nov 7, on what goes to Third Look: "the data coming to Third look should be risky for an additional review.
--   Not data because of a daily limit if all the people and agents say hello I should not get hello messages if the
--   agent is not spamming so change that requirement to meet my clear intent." And on work he is a party to: "Don't
--   implement behaviors that harm the system. If what your proposing does that don't behave like Jesus. Go look that up."
--   What that gives, in the words it was looked up in:
--   * Small matters are decided where they arise; only the great ones go up ("Every great matter they shall bring to
--     you, but any small matter they shall decide themselves", Exodus 18:22). A poster's pass stands unless the work is
--     risky. A count alone is no longer a risk: the pair limit and the daily points limit stop sending work for review.
--   * Risky work is established by two witnesses, not one ("A matter must be established by the testimony of two or
--     three witnesses", Deuteronomy 19:15): the poster's pass and Third Look's. If Third Look can't pass it, or can't
--     read it, it goes to Aaron. The risks: either party below JEVs's level (new accounts passing each other's work),
--     hidden contact details in the note, the largest size (8), a pair who pass each other's work (collusion), and a
--     burst of work (more than burst_hourly pieces from one worker in an hour: spam).
--   * Third Look sees only that: work sent for review by a risk, or work its poster never checked. It no longer passes
--     work still waiting for its poster, and its passes count when pairs are judged.
--   * No one judges their own case (Luke 12:14; 043's rule, kept): an administrator who is a party decides neither its
--     check nor its dispute; such a dispute stays open, and its points pending, until someone who isn't a party does.
--     The pages now say exactly that (Matthew 5:37), instead of promising a reversal no one can make.
--   * The check after a Third Look pass gets its own daily limit, so posters' checks don't crowd it out.
--   * The poster's decision is recorded as a person's vote, so calibration and the reciprocal-pairs figure count posters.
--   * The task page says "Passed by Third Look." and no longer prints the model's words (they stay in tl_reviews).
--   * The network leaves out banned and disabled members, as the board does.
--   * Every timer run compares the points with the points ledger, row by row, and alerts Aaron once a day if they
--     differ; it never blocks anything.

set local role dog_owner;

alter table app.work_settings
  add column burst_hourly integer not null default 20 check (burst_hourly between 1 and 1000),
  add column tl_check_daily integer not null default 5 check (tl_check_daily between 0 and 100);
comment on column app.work_settings.pair_limit is 'Since 052: no longer sends work for review by itself (Aaron, Nov 7: review by risk, not by count).';
comment on column app.work_settings.poster_daily_points is 'Since 052: no longer sends work for review (Aaron, Nov 7: review by risk, not by count).';

grant create on schema app to dog_work;
set local role dog_work;

-- Is this work risky enough for a second witness? The reasons, in words, or null.
create function app.work_risks(p_sub uuid, p_poster uuid, p_size smallint)
returns text
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  s record;
  st record;
  wm uuid;
  why text[] := '{}';
begin
  select * into s from app.work_submissions x where x.id = p_sub;
  -- The worker as a person: the member, or the owner of the agent that did it.
  wm := coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent));
  select * into st from app.work_settings where singleton;
  if (select m.trust_level from app.members m where m.id = p_poster) < st.poster_level
     or (select m.trust_level from app.members m where m.id = wm) < st.poster_level then
    why := why || ('the poster or the worker isn''t yet at JEVs''s level ' || st.poster_level);
  end if;
  if s.note_hits > 0 then why := why || 'the note had contact details, hidden'::text; end if;
  if p_size = 8 then why := why || 'it is the largest size'::text; end if;
  -- Collusion: the worker has also passed this poster's work, as its poster or by Third Look, in the last 30 days.
  if exists (select 1 from app.work_submissions x join app.work_tasks y on y.id = x.task_id
              where x.status = 'passed' and x.decided_by in ('poster', 'third_look') and x.decided_at > now() - interval '30 days'
                and coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) = p_poster
                and coalesce(y.poster_member, (select g.owner_id from app.agents g where g.id = y.poster_agent)) = wm) then
    why := why || 'these two pass each other''s work'::text;
  end if;
  -- Spam: a burst of work from one worker.
  if (select count(*) from app.work_submissions x where x.created_at > now() - interval '1 hour'
        and coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) = wm) > st.burst_hourly then
    why := why || ('this worker sent more than ' || st.burst_hourly || ' pieces of work in an hour');
  end if;
  return case when cardinality(why) = 0 then null else array_to_string(why, '; ') end;
end
$$;

-- The poster's check (043, now by risk): a pass stands unless the work is risky; risky work waits for a second witness.
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
  size smallint;
  risks text;
  held text;
  party boolean;
  readable boolean;
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
  select * into st from app.work_settings where singleton;
  size := app.work_confirmed_size(p_sub, 'poster');
  if p_verdict = 'fail' then
    insert into app.work_person_votes (submission_id, member_id, verdict, size, reason) values (p_sub, w.member_id, 'fail', size, btrim(p_reason));
    perform app.work_finish(p_sub, 'fail', 'poster', 100, btrim(p_reason));
    return 'fail';
  end if;
  risks := app.work_risks(p_sub, poster, size);
  party := exists (select 1 from app.members m where m.is_admin and m.id in (poster, s.worker_member));
  -- Third Look can be the second witness only for a merged pull request into main, while it is on.
  readable := (select x.mode from app.tl_settings x where x.singleton) = 'on' and s.artifact_kind = 'pr'
              and exists (select 1 from app.work_github_prs g where g.number = s.pr_number and g.merged_at is not null and g.base = 'main');
  -- Risky work waits for a second witness: Third Look, or Aaron when Third Look can't read it or can't pass it. When an
  -- administrator is a party and Third Look can't read it, no second witness exists yet: the poster's pass stands, as
  -- before 052, rather than failing an honest worker for want of one (the golden rule, Matthew 7:12); anyone may still
  -- dispute it.
  if risks is not null and (readable or not party) then
    held := 'The poster passed it, and it waits for a second look because ' || risks || '.';
    update app.work_submissions x set route = case when party then 'held' else 'admin' end, held_reason = held, routed_at = now() where x.id = p_sub;
    -- Aaron hears of it now only if it is his (Third Look can't read it); otherwise only if Third Look can't pass it.
    if not party and not readable then
      perform app.notify(null, 'alert', 'Risky work waits for you', held || ' Decide it on Review.', '/admin/review#work', 'submission', p_sub, 'work:held:' || p_sub);
    end if;
    return 'held';
  end if;
  insert into app.work_person_votes (submission_id, member_id, verdict, size, reason)
    values (p_sub, w.member_id, 'pass', size, coalesce(nullif(btrim(p_reason), ''), 'Passed by the task''s poster.'));
  perform app.work_finish(p_sub, 'pass', 'poster', 100, coalesce(nullif(btrim(p_reason), ''), 'Passed by the task''s poster.'));
  perform app.work_approve_as(t.id, w.citizen, null);
  -- The check after: a random sample of plain passes, by an administrator who isn't a party.
  if random() < st.check_rate and not party
     and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now()) and k.why <> 'third_look') < st.check_daily then
    insert into app.work_checks (submission_id, why) values (p_sub, 'random');
  end if;
  return 'pass';
end
$$;

-- Third Look takes only work sent for a second look by a risk, or work whose poster never checked it (043's timer
-- passes that to an administrator, or holds it when one is a party). Never work still waiting for its poster.
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
       where x.status = 'review' and x.route in ('admin', 'held') and x.artifact_kind = 'pr' and g.merged_at is not null and g.base = 'main'
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

-- Third Look's answer (047): a pass passes the work, published as "Passed by Third Look." (the model's words stay in
-- tl_reviews); one in five passes is checked again after, by an administrator who isn't a party, under its own daily
-- limit. If it can't pass work waiting for an administrator, Aaron is told: that is a great matter.
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
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if mode = 'on' and p_suggestion = 'person' and s.status = 'review' and s.route = 'admin' then
    perform app.notify(null, 'alert', 'Work waits for you', 'Third Look couldn''t pass this work, so it is yours to decide. '
      || coalesce(s.held_reason, ''), '/admin/review#work', 'submission', p_sub, 'work:held:' || p_sub);
  end if;
  if mode <> 'on' or p_suggestion <> 'pass' then return p_suggestion; end if;
  if s.status <> 'review' or s.route is null or s.route <> all (array['admin', 'held']) then return 'decided_first'; end if;
  perform app.work_finish(p_sub, 'pass', 'third_look', 90, 'Passed by Third Look.');
  select * into t from app.work_tasks x where x.id = s.task_id;
  select * into st from app.work_settings where singleton;
  if random() < st.tl_check_rate and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now()) and k.why = 'third_look') < st.tl_check_daily
     and not exists (select 1 from app.members m where m.is_admin
                     and m.id in (s.worker_member, coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent))))
     and not (t.source = 'github') then
    insert into app.work_checks (submission_id, why) values (p_sub, 'third_look');
  end if;
  return 'passed';
end
$$;

-- The network (047), leaving out members who aren't active, as the board does.
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
        join app.work_stats(null) x on x.kind = t.kind and x.ref = t.ref
       where case x.kind when 'member' then exists (select 1 from app.members m where m.id = x.ref::uuid and m.status = 'active')
                         when 'agent' then exists (select 1 from app.agents g where g.id = x.ref::uuid) else true end), '[]'::jsonb));
end
$$;

-- The points against the points ledger, row by row (051's check), on every timer run: an alert to Aaron, at most once a
-- day, if any row differs. It changes nothing and blocks nothing.
create function app.work_ledger_alert()
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  l jsonb := app.work_console_integrity();
begin
  if (l ->> 'intact')::boolean then return true; end if;
  perform app.notify(null, 'alert', 'The points and the points ledger differ',
    (l ->> 'rows_wrong') || ' of ' || (l ->> 'points_rows') || ' points rows don''t match their ledger rows. Nothing was changed or stopped; see the Console''s Ledger tab.',
    '/admin/console', null, null, 'work:ledger:' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
  return false;
end
$$;

revoke execute on function app.work_risks(uuid, uuid, smallint), app.work_ledger_alert() from public;
grant execute on function app.work_ledger_alert() to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
