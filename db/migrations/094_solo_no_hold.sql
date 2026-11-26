-- 094: solo work isn't held for being new (Aaron, Nov 24, 2026: "I don't want blockers for the agent and subagent";
-- Nov 26: "SOLO would have its own path without blockers. As long as the code or what the Agent is not malware").
-- The live proof on Nov 26 found every pass between two solo agents waited for an administrator, because agent
-- accounts are below level 2 by birth. Only that reason changes; contact details, the largest size and a burst still
-- hold, and nothing about people's work changes.
-- Also (Aaron, Nov 26: "I should only look at high risk cases after several reviews and sandbox testing"): held work
-- goes to the model reviewers first, and only what they, the Wall or the sandbox find reaches him.
grant create on schema app to dog_work;
set local role dog_work;

create or replace function app.work_risks(p_sub uuid, p_poster uuid, p_size smallint)
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
  -- 094 (Aaron, Nov 24: solo agents and sub-agents work without blockers): when both sides are agent accounts (the
  -- solo track, 079), being new is not a reason to hold. Their levels don't rise from each other's passes (092 part 3),
  -- the pair watch and random checks still look after, and the Wall and JEVs still refuse malware before this point.
  if not (app.is_agent_account(p_poster) and app.is_agent_account(wm))
     and (coalesce((select m.trust_level from app.members m where m.id = p_poster), 0) < st.poster_level
     or coalesce((select m.trust_level from app.members m where m.id = wm), 0) < st.poster_level) then
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


CREATE OR REPLACE FUNCTION app.work_poster_decide(p_sub uuid, p_verdict text, p_reason text)
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
  -- 092 (the audit's finding 3): an agent on its own account (a solo agent, 079) checks work on the tasks it posted, as a
  -- person poster does, with the same four eyes, risk holds, pair watch and random checks; an agent a person owns still
  -- leaves the check to its owner. Before, work on a solo agent's task waited, then went to an administrator.
  if w.agent_id is not null and not app.is_agent_account(w.member_id) then
    raise exception 'a person checks work, not an agent: your owner does' using errcode = '42501';
  end if;
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
    -- 094 (Aaron, Nov 26: "I should only look at high risk cases after several reviews and sandbox testing"): Aaron
    -- isn't told now. The model reviewers read it first (app.work_reviewers_settle): all clear, the poster's pass stands;
    -- a concern from any of them, or a Wall or sandbox finding, is the high-risk case he hears of.
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

-- 094: held link work after the reviewers. Every minute, from the timer (oversight/roles.js run). For each piece the
-- poster passed that waits for a second look and that Third Look can't read: when every model reviewer that is on has
-- had its turn, at least two answered ok and none raised a concern, and neither the Wall nor the sandbox found anything, the poster's pass stands;
-- when any of them did, Aaron hears of it once, as a high-risk case. Nothing is passed with fewer than two reviewers'
-- readings, and what nobody clears in 72 hours still fails, as before.
create function app.work_reviewers_settle() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  x record;
  t record;
  need integer;
  ok integer;
  tried integer;
  bad boolean;
  poster uuid;
  n integer := 0;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer settles held work' using errcode = '42501';
  end if;
  select count(*) into need from app.oversight_roles r
   where r.mode <> 'off' and r.role <> all (array['fable_report', 'fable_crosscheck', 'classifier']);
  -- 094 review: only what work_poster_decide held after the poster's pass and Third Look can't read (not a poster's
  -- timeout, not a pull request), with no open dispute, and not already sent to Aaron; filtered here so 20 held pieces
  -- with a concern can't stall everyone else's.
  for x in select s.* from app.work_submissions s
            where s.status = 'review' and s.route = 'admin' and s.artifact_kind <> 'pr'
              and s.held_reason like 'The poster passed it, and it waits for a second look because %'
              and not exists (select 1 from app.work_disputes d where d.submission_id = s.id and d.status = 'open')
              and not exists (select 1 from app.notices n where n.dedupe_key = 'work:highrisk:' || s.id)
            order by s.routed_at limit 20 for update skip locked loop
    begin
    bad := exists (select 1 from app.oversight_calls c where c.submission_id = x.id and c.verdict = 'concern')
        or exists (select 1 from app.wall_decisions d where d.kind = 'submission' and d.ref = x.id
                    and (d.decision <> 'allow' or jsonb_array_length(d.flags) > 0));
    if bad then
      perform app.notify(null, 'alert', 'High-risk work waits for you',
        left('After the reviewers and the Wall: ' || x.held_reason, 200), '/admin/review#work', 'submission', x.id, 'work:highrisk:' || x.id);
      continue;
    end if;
    -- Every reviewer that is on has had its turn (an answer or an error, never still pending), at least two answered
    -- ok, and none raised a concern: a reviewer's outage (a gateway 429) can't leave honest work waiting forever.
    -- 095's link sandbox has its turn too (it opens each link once; after 6 hours an outage no longer holds the work).
    if to_regprocedure('app.wall_link_waiting(uuid)') is not null and app.wall_link_waiting(x.id) then continue; end if;
    select count(distinct c.role) filter (where c.verdict = 'ok'), count(distinct c.role) filter (where c.error is distinct from 'pending')
      into ok, tried from app.oversight_calls c where c.submission_id = x.id
       and c.role <> all (array['fable_report', 'fable_crosscheck', 'classifier']);
    if ok < 2 or tried < need then
      -- Two days without enough readings (reviewers off, at their limits, or failing): Aaron hears of it once, so it
      -- never fails unseen at 72 hours.
      if x.routed_at < now() - interval '48 hours' then
        perform app.notify(null, 'alert', 'High-risk work waits for you', left('The reviewers couldn''t finish reading this work in two days: ' || x.held_reason, 200),
          '/admin/review#work', 'submission', x.id, 'work:highrisk:' || x.id);
      end if;
      continue;
    end if;
    select * into t from app.work_tasks w where w.id = x.task_id for update;
    poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
    insert into app.work_person_votes (submission_id, member_id, verdict, size, reason)
      values (x.id, poster, 'pass', app.work_confirmed_size(x.id, 'poster'), 'Passed by the task''s poster; cleared by ' || ok || ' model reviewers.');
    perform app.work_finish(x.id, 'pass', 'poster', 100, 'Passed by the task''s poster; cleared by ' || ok || ' model reviewers.');
    perform app.work_approve_as(t.id, case when t.poster_agent is not null then 'agent:' || t.poster_agent else 'member:' || poster end, null);
    -- The same checks after as any poster's pass: the pair watch, and the random sample under its daily limit.
    if app.work_pair_watch(x.id, poster) then
      insert into app.work_checks (submission_id, why) values (x.id, 'pair');
    elsif random() < (select st.check_rate from app.work_settings st where st.singleton)
       and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now()) and k.why not in ('third_look', 'pair'))
           < (select st.check_daily from app.work_settings st where st.singleton) then
      insert into app.work_checks (submission_id, why) values (x.id, 'random');
    end if;
    n := n + 1;
    exception when others then
      -- One bad row never stops the rest: it is skipped, and Aaron hears of it once.
      perform app.notify(null, 'alert', 'High-risk work waits for you', left('The reviewers'' settle couldn''t finish this work: ' || sqlerrm, 200),
        '/admin/review#work', 'submission', x.id, 'work:highrisk:' || x.id);
    end;
  end loop;
  return n;
end $$;
revoke execute on function app.work_reviewers_settle() from public;
grant execute on function app.work_reviewers_settle() to dog_app;


-- 094 review: the reviewers read held work first.
create or replace function app.oversight_claim(p_role text, p_n integer) returns table (submission_id uuid, model text)
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
  if r.id is null or r.mode = 'off' or s.monthly_cap_cents = 0 or r.role in ('fable_report', 'fable_crosscheck', 'classifier') then return; end if;
  select count(*) into today from app.oversight_calls c where c.role = p_role and c.created_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  k := least(p_n, r.daily_call_cap - today);
  if s.monthly_cap_cents is not null then
    select coalesce(sum(c.centi_cents), 0) into spent from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC';
    k := least(k, ((s.monthly_cap_cents::bigint * 100 - spent) / r.call_price_centi_cents)::integer);
  end if;
  if k < 1 then return; end if;
  return query
    with picked as (
      select x.id from app.work_submissions x
       where x.status in ('waiting', 'review', 'passed') and (x.created_at > now() - interval '2 days' or (x.status = 'review' and x.route = 'admin'))
         and not exists (select 1 from app.oversight_calls c where c.submission_id = x.id and c.role = p_role)
       -- 094 review: held work waits on these readings, so it is read first, and while it waits, however old.
       order by (x.status = 'review' and x.route = 'admin') desc, x.created_at limit k),
    booked as (insert into app.oversight_calls (role, submission_id, model, centi_cents, error)
               select p_role, picked.id, r.model, r.call_price_centi_cents, 'pending' from picked returning oversight_calls.submission_id)
    select b.submission_id, r.model from booked b;
end $$;

-- 094 review: the daily alert counts only what is his.
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
  -- 094: held link work the model reviewers are still reading isn't his yet; only what they sent him (a high-risk
  -- notice) counts.
  select (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'admin'
            and not (s.artifact_kind <> 'pr' and s.held_reason like 'The poster passed it, and it waits for a second look because %'
                     and not exists (select 1 from app.notices n where n.dedupe_key = 'work:highrisk:' || s.id))
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

-- 094: the SOLO card shows the agent's own name (public already: posts and the directory show it).
create or replace function app.work_portfolio(p_agent uuid) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  c jsonb;
  g record;
  k bigint;
  n bigint;
begin
  select a.id, a.owner_id, a.self_owned, a.name into g from app.agents a where a.id = p_agent and a.status in ('active', 'revoked');
  if g.id is null then return null; end if;
  c := app.work_citizen('agent', p_agent::text);
  if c is null then return null; end if;
  select count(*) filter (where s.status = 'passed'), count(*) into k, n from app.work_submissions s
   where s.worker_agent = p_agent and s.status = any (array['passed', 'failed', 'reversed']);
  return jsonb_build_object(
    'agent', p_agent, 'name', g.name, 'generated_at', now(),
    'claimed', g.owner_id is not null and not coalesce(g.self_owned, false),
    'band', c ->> 'band', 'audited', c -> 'audited',
    'pass_rate', app.work_wilson(k, n),
    'provisional', coalesce((c ->> 'audited')::integer, 0) < 10,
    'events', coalesce((select jsonb_agg(e.j order by e.at desc) from (
        select s.decided_at as at, jsonb_build_object('kind', case when s.status = 'passed' then 'pass' else 'miss' end,
                 'task', s.task_id, 'title', t.title, 'size', coalesce(s.final_size, t.size), 'at', s.decided_at) as j
          from app.work_submissions s join app.work_tasks t on t.id = s.task_id
         where s.worker_agent = p_agent and s.status = any (array['passed', 'failed', 'reversed']) and t.status <> 'removed'
        union all
        select p.approved_at, jsonb_build_object('kind', 'team', 'task', p.id, 'title', p.title, 'size', p.size, 'at', p.approved_at,
                 'crew', (select count(distinct s.worker_agent) from app.work_tasks x join app.work_submissions s on s.task_id = x.id and s.status = 'passed'
                          where x.parent_task_id = p.id))
          from app.work_tasks p
         where p.status = 'approved' and exists (select 1 from app.work_tasks x where x.parent_task_id = p.id)
           and exists (select 1 from app.work_claims cl where cl.task_id = p.id and cl.agent_id = p_agent and cl.status = 'done')
        order by 1 desc limit 50) e), '[]'::jsonb));
end $$;

reset role;
revoke create on schema app from dog_work;
