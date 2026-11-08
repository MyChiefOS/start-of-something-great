-- 052 Review by risk, not by count; two witnesses for risky work; no one judges their own case (the fresh review of
-- #112 to #116, Nov 7: H1, M1, M2, L1, L2, L3; Aaron's answers the same day).
--   Aaron, Nov 7, on what goes to Third Look: "the data coming to Third look should be risky for an additional review.
--   Not data because of a daily limit if all the people and agents say hello I should not get hello messages if the
--   agent is not spamming so change that requirement to meet my clear intent." And on work he is a party to: "Don't
--   implement behaviors that harm the system. If what your proposing does that don't behave like Jesus. Go look that up."
--   And, asked how disputes of his own tasks should end, how the terms should read, and how to stop points farming
--   without holding back legitimate work: "Disputes that are about my task specifically will be decided by me. No outside
--   admin is needed. Third look can weigh in alss." "Third looks passes could be reversed if I agree that is should be for
--   my work also." "Its not clear the risk. We want points earned honest. Second look and the review of third look etc.
--   should catch behavior that designed to game the system. Implement a fix that supports that why not refusing legit
--   messages."
--   What that gives, with the scripture it was looked up in (INTEGRITY.md: the New Testament, KJV):
--   * Routine matters are handled by trusted others, so the few who lead aren't drawn from their work ("It is not reason
--     that we should leave the word of God, and serve tables. Wherefore, brethren, look ye out among you seven men of
--     honest report", Acts 6:2-3). A poster's pass stands unless the work is risky; how many people say hello is not a
--     risk, and no legitimate work is held back for a count.
--   * Risky work is established by two witnesses, not one ("that in the mouth of two or three witnesses every word may be
--     established", Matthew 18:16): the poster's pass and Third Look's. If Third Look can't pass it, or can't read it,
--     it goes to Aaron. The risks: either party below JEVs's level or unknown to the site, hidden contact details in the
--     note, the largest size (8), and a burst (more than burst_hourly pieces from one worker in the hour before it was
--     sent: spam).
--   * Gaming is caught by review after, not by refusing work: a poster who has passed the same worker pair_limit times in
--     30 days, or two who pass each other's work, keep their pass, and the work is picked for the check after, outside
--     the daily limit. Its points can't become final until that check is done, so farmed points never count; Aaron sees
--     these in his daily summary, never one message an item.
--   * Third Look sees only risky work, and work whose poster never checked it. It no longer passes work still waiting for
--     its poster, and its passes count when pairs are judged. Aaron hears of work only when it is his to decide: Third
--     Look can't read it, can't pass it, or hasn't looked at it halfway through its wait.
--   * Disputes of Aaron's own tasks (his posts, and the repository's, work credited to him there included) are his to
--     decide, as he chose; Third Look reads every disputed merged pull request and its review shows beside the dispute,
--     a second witness on the record; every decision has its reason and is public. On his own work for someone else's
--     task he may only uphold a dispute (give up the pass), and a dispute he opened he may only withdraw: no dispute is
--     left with no one to end it. So Third Look's passes can be disputed and reversed like any other, his work included
--     (Matthew 5:37: the words say what is true).
--   * Where an administrator is a party and Third Look can't read the work, no second witness can exist: the poster's
--     pass stands, as before 052, rather than failing an honest worker for want of one (Matthew 7:12). Where Third Look
--     can read it and doubts it, it isn't established: the worker and the poster are told at once, and it closes when
--     its wait ends.
--   * The check after a Third Look pass gets its own daily limit, so posters' checks don't crowd it out.
--   * The poster's final decision is recorded as a person's vote, so calibration and the reciprocal-pairs figure count
--     posters. (A pass sent for a second look is recorded by whoever decides it, one vote a submission; the poster's
--     pass stays in the held reason.)
--   * The task page says "Passed by Third Look." and no longer prints the model's words (they stay in tl_reviews, and
--     Aaron sees them on Review).
--   * The network leaves out banned and disabled members before it picks its 100, as the board does.
--   * At most once an hour the timer compares the points with the points ledger, row by row, and alerts Aaron once a
--     day if they differ; it never blocks anything.

set local role dog_owner;

alter table app.work_settings
  add column burst_hourly integer not null default 20 check (burst_hourly between 1 and 1000),
  add column tl_check_daily integer not null default 5 check (tl_check_daily between 0 and 100),
  add column ledger_checked_at timestamptz;
grant update (ledger_checked_at) on app.work_settings to dog_work;
comment on column app.work_settings.pair_limit is 'Since 052: from this many passes of the same worker by one poster in 30 days, each further pass is checked after, outside the daily limit; nothing is held back.';
-- The pair watch reads the last 30 days of passes.
create index work_submissions_passed_at on app.work_submissions (decided_at) where status in ('passed', 'reversed');
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
  -- Unknown to the site (a deleted account, or a GitHub account with no member) counts as below the level.
  if coalesce((select m.trust_level from app.members m where m.id = p_poster), 0) < st.poster_level
     or coalesce((select m.trust_level from app.members m where m.id = wm), 0) < st.poster_level then
    why := why || ('the poster or the worker isn''t yet at JEVs''s level ' || st.poster_level);
  end if;
  if s.note_hits > 0 then why := why || 'the note had contact details, hidden'::text; end if;
  if p_size = 8 then why := why || 'it is the largest size'::text; end if;
  -- Spam: a burst of work from one worker, in the hour before this piece was sent (waiting to check doesn't hide it).
  if (select count(*) from app.work_submissions x where x.created_at > s.created_at - interval '1 hour' and x.created_at <= s.created_at
        and coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) = wm) > st.burst_hourly then
    why := why || ('this worker sent more than ' || st.burst_hourly || ' pieces of work in an hour');
  end if;
  return case when cardinality(why) = 0 then null else array_to_string(why, '; ') end;
end
$$;

-- Gaming, caught by review after (Aaron, Nov 7): the poster has passed this worker's work pair_limit times in 30 days,
-- the worker has passed the poster's, or a ring of three (by owner; passes by a poster or by Third Look). Farming split
-- over many accounts isn't caught here (RK137).
create function app.work_pair_watch(p_sub uuid, p_poster uuid)
returns boolean
language sql stable security definer set search_path = pg_catalog
as $$
  with w as (select coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)) as wm
               from app.work_submissions s where s.id = p_sub),
  p as (select coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) as worker,
               coalesce(y.poster_member, (select g.owner_id from app.agents g where g.id = y.poster_agent)) as poster
          from app.work_submissions x join app.work_tasks y on y.id = x.task_id
         where x.status in ('passed', 'reversed') and x.decided_by in ('poster', 'third_look') and x.decided_at > now() - interval '30 days' and x.id <> p_sub)
  select (select count(*) from p, w where p.worker = w.wm and p.poster = p_poster) >= (select st.pair_limit from app.work_settings st where st.singleton)
      or exists (select 1 from p, w where p.worker = p_poster and p.poster = w.wm)
      -- A ring of three: the worker passed someone's work who passed the poster's.
      or exists (select 1 from p a, p b, w where a.poster = w.wm and b.worker = p_poster and a.worker = b.poster and a.worker <> p_poster)
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
    held := left('The poster passed it, and it waits for a second look because ' || risks || '.', 200);
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
  -- The check after, by an administrator who isn't a party: every pass between a pair that may be gaming (outside the
  -- daily limit; its points stay pending until it is done), and a random sample of the rest.
  if not party and app.work_pair_watch(p_sub, poster) then
    insert into app.work_checks (submission_id, why) values (p_sub, 'pair');
  elsif random() < st.check_rate and not party
     and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now()) and k.why not in ('third_look', 'pair')) < st.check_daily then
    insert into app.work_checks (submission_id, why) values (p_sub, 'random');
  end if;
  return 'pass';
end
$$;

-- Third Look takes only work sent for a second look by a risk, or work whose poster never checked it (043's timer
-- passes that to an administrator, or holds it when one is a party), and a disputed pass, to weigh in beside the
-- dispute (its answer then changes nothing). Never work still waiting for its poster.
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
                from unnest(tot_nodes, tot_mass) f(node, m)
               where node <> all (seeds)
                 and case split_part(node, ':', 1) when 'member' then exists (select 1 from app.members m where m.id = split_part(node, ':', 2)::uuid and m.status = 'active')
                                                   when 'agent' then exists (select 1 from app.agents g where g.id = split_part(node, ':', 2)::uuid) else true end
               group by node order by 3 desc limit 100) t
        join app.work_stats(null) x on x.kind = t.kind and x.ref = t.ref), '[]'::jsonb));
end
$$;

-- The points against the points ledger, row by row (051's check), at most once an hour: an alert to Aaron, at most once a
-- day, if any row differs. It changes nothing and blocks nothing.
create function app.work_ledger_alert()
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  l jsonb;
begin
  -- The hour is read without a lock, and the row is touched only after the scan, so the timer is never held up by it.
  if (select st.ledger_checked_at > now() - interval '1 hour' from app.work_settings st where st.singleton) then return null; end if;
  l := app.work_console_integrity();
  update app.work_settings set ledger_checked_at = now() where singleton;
  if (l ->> 'intact')::boolean then return true; end if;
  perform app.notify(null, 'alert', 'The points and the points ledger differ',
    (l ->> 'rows_wrong') || ' of ' || (l ->> 'points_rows') || ' points rows don''t match their ledger rows. Nothing was changed or stopped; see the Console''s Ledger tab.',
    '/admin/console', null, null, 'work:ledger:' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
  return false;
end
$$;

-- Which way may this administrator decide this dispute? (Aaron, Nov 7: "Disputes that are about my task specifically will
-- be decided by me" and "Third looks passes could be reversed if I agree that is should be for my work also.") 'any' on
-- his own tasks (his posts, his agents' posts and the repository's, work credited to him there included, and disputes
-- he opened about them) and on work he has no part in; 'uphold' only, on his own work for someone else's task (he may
-- give up its pass, never keep it); and 'dismiss' only, on a dispute he opened about someone else's task (he may
-- withdraw it, never win it). So no dispute is left with no one to end it,
-- and he never decides one in his own favour on another's task.
create function app.work_may_settle(p_dispute uuid, p_member uuid)
returns text
language sql stable security definer set search_path = pg_catalog
as $$
  select case when t.source = 'github' or coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) = p_member then 'any'
              when d.member_id = p_member then 'dismiss'
              when app.work_party(s.id, p_member) then 'uphold'
              else 'any' end
    from app.work_disputes d join app.work_submissions s on s.id = d.submission_id join app.work_tasks t on t.id = s.task_id
   where d.id = p_dispute
$$;

-- The dispute decision (046), now under app.work_may_settle.
create or replace function app.work_dispute_decide(p_dispute uuid, p_decision text, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  d record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides disputes' using errcode = '42501'; end if;
  if p_decision is null or p_decision <> all (array['uphold', 'dismiss']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into d from app.work_disputes x where x.id = p_dispute for update;
  if d.id is null or d.status <> 'open' then return 'not_open'; end if;
  -- Aaron, Nov 7: disputes of his own tasks are his to decide, with Third Look's review beside them when it read the
  -- work (app.work_admin); against himself only, on his work for another's task or a dispute he opened.
  if app.work_may_settle(p_dispute, app.current_member()) is distinct from 'any' and app.work_may_settle(p_dispute, app.current_member()) is distinct from p_decision then
    raise exception 'work_own' using errcode = 'P0001', hint = 'On your own work for someone else''s task you may only uphold the dispute (give up the pass); a dispute you opened you may only dismiss (withdraw).';
  end if;
  update app.work_disputes x set status = case when p_decision = 'uphold' then 'upheld' else 'dismissed' end, decided_by = app.current_member(),
    decision = btrim(p_reason), decided_at = now() where x.id = p_dispute;
  if p_decision = 'uphold' then perform app.work_reverse(d.submission_id, 'dispute', btrim(p_reason)); end if;
  perform app.notify(d.member_id, 'work_decided', 'Your dispute was decided', 'Your dispute was ' || case when p_decision = 'uphold' then 'upheld: the pass is reversed.' else 'dismissed.' end
    || ' ' || left(btrim(p_reason), 200), '/tasks/' || (select s.task_id from app.work_submissions s where s.id = d.submission_id), 'submission', d.submission_id, 'work:dispute-decided:' || d.id);
  return p_decision;
end
$$;

-- The administrator's list (043), with who may decide each dispute, and Third Look's review beside each item.
create or replace function app.work_admin()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator' using errcode = '42501'; end if;
  -- Each item says whether the administrator reading it may decide it ('party': he did the work or opened the dispute;
  -- since 052 a dispute of his own task is his). A dispute carries Third Look's review of the work, as Aaron asked
  -- ("Third look can weigh in"); work still to be decided doesn't, so the person deciding it isn't swayed by it (047).
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
                           'decided_by', s.decided_by, 'reason', s.reason, 'party', app.work_may_settle(d.id, me) <> 'any', 'may', app.work_may_settle(d.id, me), 'third_look', (select jsonb_build_object('suggestion', r.suggestion, 'answers', r.answers, 'reason', r.reason, 'at', r.decided_at) from app.tl_reviews r where r.submission_id = s.id and r.decided_at is not null)) order by d.created_at)
                         from app.work_disputes d join app.work_submissions s on s.id = d.submission_id where d.status = 'open'), '[]'::jsonb),
    'held', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'held'));
end
$$;

-- The timer (043), carried over unchanged except where a poster's silence sends the work, and the halfway notice.
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
  party boolean;
  readable boolean;
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
  -- is passed over (052): to Third Look when it can read the work (held, if an administrator is a party), otherwise to an
  -- administrator who isn't a party, and Aaron is told only then. Whatever no one decides within audit_hours of reaching
  -- them fails: it isn't passed to clear a backlog; the task reopens and the worker may try again.
  for x in select s.id, s.route, s.worker_member, s.artifact_kind, s.pr_number, t.poster_member, t.poster_agent from app.work_submissions s join app.work_tasks t on t.id = s.task_id
           where s.status = 'review' and coalesce(s.routed_at, s.created_at) + make_interval(hours => st.audit_hours) <= now() order by s.created_at limit 100 loop
    party := exists (select 1 from app.members m where m.is_admin
               and m.id in (x.worker_member, coalesce(x.poster_member, (select g.owner_id from app.agents g where g.id = x.poster_agent))));
    readable := (select y.mode from app.tl_settings y where y.singleton) = 'on' and x.artifact_kind = 'pr'
                and exists (select 1 from app.work_github_prs g where g.number = x.pr_number and g.merged_at is not null and g.base = 'main');
    if x.route = 'poster' and (readable or not party) then
      update app.work_submissions y set route = case when party then 'held' else 'admin' end, routed_at = now(),
        held_reason = 'The task''s poster didn''t check it within ' || st.audit_hours || ' hours.' where y.id = x.id;
      if not readable then
        perform app.notify(null, 'alert', 'Work a poster didn''t check waits for you', 'A poster didn''t check work on their task in time. Decide it on Review.', '/admin/review#work',
          'submission', x.id, 'work:escalated:' || x.id);
      end if;
    else
      perform app.work_finish(x.id, 'fail', 'timeout', 100, 'No one could decide it within ' || st.audit_hours || ' hours, so it isn''t passed. You may claim the task again.');
    end if;
    n_fixed := n_fixed + 1;
  end loop;
  -- Work sent to Third Look for an administrator that it hasn't answered halfway through its wait (Third Look off,
  -- at its daily limit, or failing): Aaron is told once, so it never fails unseen.
  for x in select s.id from app.work_submissions s join app.work_github_prs g on g.number = s.pr_number
           where s.status = 'review' and s.route = 'admin' and s.artifact_kind = 'pr' and g.merged_at is not null and g.base = 'main'
             and s.routed_at + make_interval(hours => st.audit_hours) / 2 <= now()
             and s.routed_at + make_interval(hours => st.audit_hours) / 2 > now() - interval '6 hours'
             and not exists (select 1 from app.tl_reviews r where r.submission_id = s.id and r.decided_at is not null)
           order by s.routed_at limit 100 loop
    perform app.notify(null, 'alert', 'Work waits for you', 'Third Look hasn''t looked at this work, and half its wait has passed. Decide it on Review.',
      '/admin/review#work', 'submission', x.id, 'work:held:' || x.id);
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
  -- Only what an administrator can decide now (052): work Third Look still has to look at waits for it; a check of work
  -- every administrator is a party to, or a dispute none may decide, doesn't bring him back each day.
  select (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'admin'
            and (exists (select 1 from app.tl_reviews r where r.submission_id = s.id and r.decided_at is not null)
                 or s.artifact_kind <> 'pr' or (select y.mode from app.tl_settings y where y.singleton) <> 'on'
                 or not exists (select 1 from app.work_github_prs g where g.number = s.pr_number and g.merged_at is not null and g.base = 'main')))
       + (select count(*) from app.work_checks k where k.status = 'open'
            and exists (select 1 from app.members m where m.is_admin and not app.work_party(k.submission_id, m.id)))
       + (select count(*) from app.work_disputes d where d.status = 'open'
            and exists (select 1 from app.members m where m.is_admin and app.work_may_settle(d.id, m.id) is not null)) into waiting;
  if waiting > 0 and st.last_alert_day is distinct from (now() at time zone 'UTC')::date then
    update app.work_settings set last_alert_day = (now() at time zone 'UTC')::date where singleton;
    perform app.notify(null, 'alert', 'Work waits for you', waiting || case when waiting = 1 then ' item of work waits' else ' items of work wait' end
      || ' for you on Review: risky work, work a poster didn''t check, checks after a pass, or disputes. Points under a check or a dispute stay pending; nothing else stops.', '/admin/review#work', null, null,
      'work:waiting:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end if;
  return jsonb_build_object('expired', n_exp, 'finalised', n_final, 'unfixed', n_fixed);
end
$$;

revoke execute on function app.work_risks(uuid, uuid, smallint), app.work_pair_watch(uuid, uuid), app.work_may_settle(uuid, uuid), app.work_ledger_alert() from public;
grant execute on function app.work_ledger_alert() to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
