-- 089 The rest of the oversight diagram (Aaron, Nov 24: "Build whats on diagram fully"; Nov 26, with 3213, the
--   attached plan, Phase 1 items 10-12):
--     the blue team lead, a step before the Wall decides: an account the watchtower alerted on today gets W50 (flag);
--     both random auditors feed lanes A and B (a sampled Wall allow to A, sampled passed work to B), and the model
--       reviewers' concerns go to lane B;
--     appeals and rechecks: a worker appeals a Wall block (W-rule refusals); the timer rechecks it against today's rules
--       and wiki. Clear now: it goes back to staging as a verified false positive. Still blocked: lane A, a person decides;
--     the zero-day filter and CWE links in the security wiki;
--     the Fable 5.2 report: each day's facts written up by Fable 5.2 (read-only), in the digest; and the weekly
--       cross-check by a different maker's model, an alert on a concern. Both on, pay-as-you-go (088).

reset role;
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W50', 'flag', 'The blue team lead: the watchtower alerted on this account today (spam, points-gaming, a swarm of agents, repeated Wall flags)');
alter table app.wall_rules enable row level security;
alter table app.oversight_roles disable row level security;
update app.oversight_roles set mode = 'on' where role = any (array['fable_report', 'fable_crosscheck']);
alter table app.oversight_roles enable row level security;

set local role dog_owner;
-- Appeals of the Wall's blocks: one per decision.
create table app.wall_appeals (
  id uuid primary key default app.uuid_v7(),
  decision_id uuid not null unique references app.wall_decisions (id) on delete cascade,
  member_id uuid references app.members (id) on delete set null,
  reason text not null check (char_length(reason) between 3 and 500),
  status text not null default 'open' check (status = any (array['open', 'cleared', 'upheld', 'decided'])),
  recheck_flags jsonb check (recheck_flags is null or jsonb_typeof(recheck_flags) = 'array'),
  rechecked_at timestamptz,
  created_at timestamptz not null default now()
);
alter table app.wall_appeals enable row level security;
alter table app.wall_appeals force row level security;
create policy wall_appeals_work on app.wall_appeals for all to dog_work using (true) with check (true);
create policy wall_appeals_owner on app.wall_appeals for select to dog_owner using (true);
grant select, insert, update on app.wall_appeals to dog_work;
grant select on app.wall_appeals to dog_owner;

-- The weekly cross-check of the Fable 5.2 reports, by another maker's model.
create table app.oversight_crosschecks (
  id uuid primary key default app.uuid_v7(),
  week date not null unique,
  model text not null check (char_length(model) <= 80),
  verdict text check (verdict = any (array['ok', 'concern'])),
  reason text check (char_length(reason) <= 300),
  error text check (char_length(error) <= 40),
  created_at timestamptz not null default now()
);
alter table app.oversight_crosschecks enable row level security;
alter table app.oversight_crosschecks force row level security;
create policy oversight_crosschecks_work on app.oversight_crosschecks for all to dog_work using (true) with check (true);
grant select, insert, update on app.oversight_crosschecks to dog_work;

-- The blue team lead: the watchtower's alerts on this account (an agent counts for its owner) today, as flags.
create function app.blue_team_lead(p_member uuid, p_agent uuid) returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce((select jsonb_agg('W50 blue team lead: ' || left(n.title, 160)) from (
      select x.title from app.notices x
       where x.member_id is null and x.kind = 'alert' and x.dedupe_key like 'watchtower:%'
         and x.subject_kind = 'member' and x.subject_id = coalesce(p_member, (select g.owner_id from app.agents g where g.id = p_agent))
         and x.created_at > now() - interval '1 day'
       order by x.created_at desc limit 3) n), '[]'::jsonb)
$$;
revoke execute on function app.blue_team_lead(uuid, uuid) from public;

CREATE OR REPLACE FUNCTION app.wall_gate()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  k text := tg_argv[0];
  r jsonb := to_jsonb(new);
  st record;
  txt text;
  flags jsonb := '[]'::jsonb;
  hosts text[];
  host text;
  mem uuid;
  ag uuid;
  ref uuid;
  prev text;
  h text;
  dec text;
  tsk uuid;
begin
  select * into st from app.wall_settings;
  if st.mode = 'off' then return null; end if;
  if k = 'task' then
    txt := coalesce(r ->> 'title', '') || E'\n' || coalesce(r ->> 'description', '');
    mem := (r ->> 'poster_member')::uuid; ag := (r ->> 'poster_agent')::uuid; ref := new.id;
  elsif k = 'submission' then
    txt := coalesce(r ->> 'note', '') || E'\n' || coalesce(r ->> 'artifact_url', '') || E'\n' || coalesce(r ->> 'artifact_sha256', '');
    mem := (r ->> 'worker_member')::uuid; ag := (r ->> 'worker_agent')::uuid; ref := new.id; tsk := (r ->> 'task_id')::uuid;
    -- Declared hosts: a link outside them is flagged.
    if r ->> 'artifact_kind' = 'link' then
      select coalesce(array_agg(s.value), '{}') into hosts from app.work_task_scope s where s.task_id = tsk and s.kind = 'host';
      host := lower(substring(r ->> 'artifact_url' from '^https?://([^/:?#]+)'));
      if cardinality(hosts) > 0 and host is not null and not exists (select 1 from unnest(hosts) x where host = lower(x) or host like '%.' || lower(x)) then
        flags := flags || jsonb_build_array('W24 link outside the task''s declared hosts: ' || left(host, 100));
      end if;
    end if;
  elsif k = 'dispute' then
    txt := r ->> 'reason'; mem := (r ->> 'member_id')::uuid; ref := new.id;
  elsif k = 'evidence' then
    txt := r ->> 'note'; mem := (r ->> 'member_id')::uuid; ref := new.id;
  elsif k = 'pr_files' then
    -- GitHub's changed files for a pull request: check them against each submission of that pull request.
    for tsk, ref, mem, ag in select s.task_id, s.id, s.worker_member, s.worker_agent from app.work_submissions s where s.pr_number = (r ->> 'number')::integer loop
      flags := app.wall_files_flags(tsk, r -> 'files');
      dec := app.wall_decide(flags);
      perform pg_advisory_xact_lock(7307307);
      select d.hash into prev from app.wall_decisions d where not exists (select 1 from app.wall_decisions x where x.prev_hash = d.hash);
      prev := coalesce(prev, repeat('0', 64));
      h := encode(sha256(convert_to(prev || '|' || k || '|' || ref::text || '|' || dec || '|' || flags::text || '|' || st.rules_version, 'UTF8')), 'hex');
      insert into app.wall_decisions (kind, ref, member_id, agent_id, decision, flags, mode, rules_version, prev_hash, hash)
        values (k, ref, mem, ag, dec, flags, st.mode, st.rules_version, prev, h);
      -- 081: a clear breach in the code fails that submission (it was staged, waiting, while the checks ran).
      if dec = 'block' and st.mode = 'enforce' then
        update app.work_submissions s set status = 'failed', decided_by = 'wall', decided_at = now(),
          reason = left('Refused by the Agentic Wall: ' || (select string_agg(x, '; ') from jsonb_array_elements_text(flags) x), 300)
          where s.id = ref and s.status in ('waiting', 'review');
      end if;
    end loop;
    return null;
  end if;
  if ag is not null and mem is null then mem := (select g.owner_id from app.agents g where g.id = ag); end if;
  -- 089: the blue team lead, a step before the Wall decides: what the watchtower saw of this account today.
  flags := flags || app.wall_text_flags(txt) || app.wall_intel_flags(txt) || app.blue_team_lead(mem, ag);
  dec := app.wall_decide(flags);
  -- The chain: serialize writers so each row carries the one before it.
  perform pg_advisory_xact_lock(7307307);
  select d.hash into prev from app.wall_decisions d where not exists (select 1 from app.wall_decisions x where x.prev_hash = d.hash);
  prev := coalesce(prev, repeat('0', 64));
  h := encode(sha256(convert_to(prev || '|' || k || '|' || ref::text || '|' || dec || '|' || flags::text || '|' || st.rules_version, 'UTF8')), 'hex');
  insert into app.wall_decisions (kind, ref, member_id, agent_id, decision, flags, mode, rules_version, prev_hash, hash)
    values (k, ref, mem, ag, dec, flags, st.mode, st.rules_version, prev, h);
  -- 081: a clear breach is refused in enforce mode: the submission fails, the task is removed.
  if dec = 'block' and st.mode = 'enforce' then
    if k = 'submission' then
      update app.work_submissions s set status = 'failed', decided_by = 'wall', decided_at = now(),
        reason = left('Refused by the Agentic Wall: ' || (select string_agg(x, '; ') from jsonb_array_elements_text(flags) x), 300)
        where s.id = ref and s.status in ('waiting', 'review');
    elsif k = 'task' then
      insert into app.wall_removed_tasks (task_id, prior_status, decision_id)
        select t.id, t.status, (select d.id from app.wall_decisions d where d.hash = h) from app.work_tasks t
         where t.id = ref and t.status in ('open', 'funding') on conflict (task_id) do nothing;
      update app.work_tasks t set status = 'removed' where t.id = ref and t.status in ('open', 'funding');
    end if;
  end if;
  return null;
end $function$;

-- A recheck: the subject's flags under today's rules and wiki (submissions, their pull request files, tasks).
create function app.wall_recheck_flags(p_decision uuid) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  d record;
  f jsonb := '[]'::jsonb;
  txt text;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer rechecks' using errcode = '42501'; end if;
  select * into d from app.wall_decisions x where x.id = p_decision;
  if d.id is null then return null; end if;
  if d.kind = 'submission' then
    select coalesce(x.note, '') || ' ' || coalesce(x.artifact_url, '') into txt from app.work_submissions x where x.id = d.ref;
    f := app.wall_text_flags(txt) || app.wall_intel_flags(txt);
  elsif d.kind = 'pr_files' then
    f := app.wall_files_flags((select x.task_id from app.work_submissions x where x.id = d.ref),
                              (select t.files from app.tl_files t join app.work_submissions x on x.pr_number = t.number where x.id = d.ref limit 1));
  elsif d.kind = 'task' then
    select coalesce(t.title, '') || ' ' || coalesce(t.description, '') into txt from app.work_tasks t where t.id = d.ref;
    f := app.wall_text_flags(txt) || app.wall_intel_flags(txt);
  else
    return d.flags;
  end if;
  return coalesce(f, '[]'::jsonb);
end $$;
revoke execute on function app.wall_recheck_flags(uuid) from public;
grant execute on function app.wall_recheck_flags(uuid) to dog_work;
grant execute on function app.wall_decide(jsonb) to dog_work;

-- The security wiki's public summary, with (089) a zero-day mark and a link to each weakness's CWE entry. A zero-day
-- here is an advisory CISA lists as exploited in the wild that was published in the last 30 days.
reset role;
grant create on schema app to dog_work;
set local role dog_work;
create or replace function app.wiki_summary() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object(
    'versions', coalesce((select jsonb_agg(jsonb_build_object('id', v.id, 'status', v.status, 'entries', v.entries, 'packages', v.packages,
                   'sources', v.sources, 'reason', v.reason, 'at', v.created_at) order by v.created_at desc) from app.wiki_versions v), '[]'::jsonb),
    'last_run_at', (select s.last_run_at from app.wiki_settings s where s.singleton),
    'newest', coalesce((select jsonb_agg(jsonb_build_object('ident', e.ident, 'title', e.title, 'severity', e.severity, 'cwe', e.cwe, 'kev', e.kev, 'published', e.published,
                   'zero_day', e.kev and e.published >= (now() at time zone 'UTC')::date - 30,
                   'cwe_url', case when e.cwe ~ '^CWE-[0-9]{1,5}$' then 'https://cwe.mitre.org/data/definitions/' || substr(e.cwe, 5) || '.html' end)
                   order by e.published desc nulls last, e.ident) from (select * from app.wiki_entries e join app.wiki_versions v on v.id = e.version_id and v.status = 'active'
                   where e.source = 'nvd' order by e.published desc nulls last, e.ident limit 50) e), '[]'::jsonb),
    'zero_days', coalesce((select jsonb_agg(jsonb_build_object('ident', e.ident, 'title', e.title, 'cwe', e.cwe, 'published', e.published,
                   'cwe_url', case when e.cwe ~ '^CWE-[0-9]{1,5}$' then 'https://cwe.mitre.org/data/definitions/' || substr(e.cwe, 5) || '.html' end)
                   order by e.published desc, e.ident) from (select * from app.wiki_entries e join app.wiki_versions v on v.id = e.version_id and v.status = 'active'
                   where e.source = 'nvd' and e.kev and e.published >= (now() at time zone 'UTC')::date - 30 order by e.published desc, e.ident limit 100) e), '[]'::jsonb))
$$;

CREATE OR REPLACE FUNCTION app.review_lanes()
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator reads the lanes' using errcode = '42501'; end if;
  return jsonb_build_object(
    'a', coalesce((select jsonb_agg(jsonb_build_object('decision', d.id, 'kind', d.kind, 'ref', d.ref, 'flags', d.flags, 'mode', d.mode, 'at', d.created_at)
                    order by d.created_at desc) from (select * from app.wall_decisions x where x.decision in ('hold', 'block')
                    and not exists (select 1 from app.wall_reviews w where w.decision_id = x.id) order by x.created_at desc limit 100) d), '[]'::jsonb),
    'b', coalesce((select jsonb_agg(jsonb_build_object('submission', z.id, 'task', z.task_id, 'status', z.status) || app.work_final_score(z.id) order by z.created_at desc)
                    from (select x.id, x.task_id, x.status, x.created_at from app.work_submissions x where x.created_at > now() - interval '7 days'
                          order by x.created_at desc limit 500) z
                   where (app.work_final_score(z.id) ->> 'passes')::boolean is false), '[]'::jsonb),
    -- 089: the random auditors feed the lanes: a sampled allow of the Wall's to lane A, sampled passed work to lane B.
    'a_audits', coalesce((select jsonb_agg(jsonb_build_object('sample', s.id, 'ref', s.ref, 'at', s.created_at) order by s.created_at desc)
                    from (select * from app.audit_samples x where x.kind = 'wall_allow' and x.status = 'open' order by x.created_at desc limit 100) s), '[]'::jsonb),
    'b_audits', coalesce((select jsonb_agg(jsonb_build_object('sample', s.id, 'ref', s.ref, 'at', s.created_at) order by s.created_at desc)
                    from (select * from app.audit_samples x where x.kind = 'passed_work' and x.status = 'open' order by x.created_at desc limit 100) s), '[]'::jsonb),
    -- 089: the model reviewers' concerns (exploit researcher, penetration tester, QA, solution architect) go to lane B.
    'b_concerns', coalesce((select jsonb_agg(jsonb_build_object('submission', c.submission_id, 'role', c.role, 'reason', c.reason, 'at', c.created_at) order by c.created_at desc)
                    from (select * from app.oversight_calls x where x.verdict = 'concern' and x.submission_id is not null and x.created_at > now() - interval '7 days'
                          order by x.created_at desc limit 100) c), '[]'::jsonb),
    -- 089: appeals of the Wall's blocks, with what the recheck found, in lane A for a person to decide.
    'a_appeals', coalesce((select jsonb_agg(jsonb_build_object('appeal', p.id, 'decision', p.decision_id, 'status', p.status, 'reason', p.reason, 'recheck', p.recheck_flags, 'at', p.created_at)
                    order by p.created_at desc) from (select * from app.wall_appeals x where x.status in ('open', 'upheld') order by x.created_at desc limit 100) p), '[]'::jsonb));
end $function$;

CREATE OR REPLACE FUNCTION app.review_digest_run()
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  s record;
  d record;
  n integer := 0;
  a_total integer;
  a_groups text;
  b_total integer;
  b_groups text;
  today date := (now() at time zone 'UTC')::date;
  extra text;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer sends the review digest' using errcode = '42501';
  end if;
  select * into s from app.lanes_settings x where x.singleton for update;
  for d in select x.id, x.kind, x.flags from app.wall_decisions x
            where x.decision in ('hold', 'block') and x.created_at > s.incidents_checked_at
              and exists (select 1 from jsonb_array_elements_text(x.flags) f where split_part(f, ' ', 1) = any (array['W11', 'W22', 'W13']))
            order by x.created_at limit 20 loop
    if app.notify(null, 'alert', 'Incident: the Agentic Wall flagged a ' || d.kind, left(d.flags::text, 300) || ' Review it in lane A.', '/admin',
                  'wall_decision', d.id, 'wall:incident:' || d.id) then
      n := n + 1;
    end if;
  end loop;
  update app.lanes_settings x set incidents_checked_at = now() where x.singleton;
  if (s.digest_last_day is not null and s.digest_last_day >= today) or extract(hour from now() at time zone 'UTC') < s.digest_hour then return n; end if;
  update app.lanes_settings x set digest_last_day = today where x.singleton;
  select count(*), string_agg(g.code || ' ' || g.c, ', ' order by g.c desc, g.code) into a_total, a_groups
    from (select split_part(f, ' ', 1) as code, count(*) as c from app.wall_decisions x, jsonb_array_elements_text(x.flags) f
           where x.decision in ('hold', 'block') and x.created_at > now() - interval '1 day'
             and not exists (select 1 from app.wall_reviews w where w.decision_id = x.id) group by 1) g;
  select coalesce(sum(g.c), 0), string_agg(g.r || ' ' || g.c, ', ' order by g.c desc, g.r) into b_total, b_groups
    from (select r as r, count(*) as c from (select x.id, app.work_final_score(x.id) as sc from app.work_submissions x where x.created_at > now() - interval '1 day') z,
           jsonb_array_elements_text(z.sc -> 'reasons') r where (z.sc ->> 'passes')::boolean is false group by 1) g;
  a_total := (select count(*) from app.wall_decisions x where x.decision in ('hold', 'block') and x.created_at > now() - interval '1 day'
                and not exists (select 1 from app.wall_reviews w where w.decision_id = x.id));
  b_total := (select count(*) from app.work_submissions x where x.created_at > now() - interval '1 day' and (app.work_final_score(x.id) ->> 'passes')::boolean is false);
  -- 089: the auditors' samples, the reviewers' concerns, appeals, and the Fable 5.2 report and its cross-check.
  extra := ' Random auditors: ' || (select count(*) from app.audit_samples x where x.status = 'open' and x.kind = 'wall_allow') || ' open in lane A, '
        || (select count(*) from app.audit_samples x where x.status = 'open' and x.kind = 'passed_work') || ' in lane B. Reviewers'' concerns (last 24 hours): '
        || (select count(*) from app.oversight_calls x where x.verdict = 'concern' and x.submission_id is not null and x.created_at > now() - interval '1 day')
        || '. Appeals waiting for a person: ' || (select count(*) from app.wall_appeals x where x.status = 'upheld') || '.'
        || coalesce(' Fable 5.2 report: ' || (select left(r.narrative, 600) from app.oversight_reports r where r.narrative is not null order by r.day desc limit 1), '')
        || coalesce((select ' Weekly cross-check: concern, ' || left(c.reason, 200) from app.oversight_crosschecks c where c.verdict = 'concern' and c.week > (now() at time zone 'UTC')::date - 8 order by c.week desc limit 1), '');
  if app.notify(null, 'alert', 'Daily review digest: ' || a_total || ' in lane A, ' || b_total || ' in lane B',
       left('Lane A (the Agentic Wall''s unreviewed flags, last 24 hours): ' || coalesce(a_groups, 'none') || '. Lane B (work under the 70% line, last 24 hours): '
       || coalesce(b_groups, 'none') || '.' || extra, 2000), '/admin', null, null, 'review:digest:' || today) then
    n := n + 1;
  end if;
  return n;
end $function$;

-- A worker's appeal of a Wall block on their own work (the member it was about, or the owner of the agent it was
-- about). One per block. The timer rechecks it.
create function app.wall_appeal(p_decision uuid, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  d record;
  w record;
begin
  if app.actor_kind() <> all (array['member', 'agent']) then raise exception 'sign in to appeal' using errcode = '42501'; end if;
  select * into w from app.work_who();
  select * into d from app.wall_decisions x where x.id = p_decision;
  if d.id is null or d.decision <> 'block' then raise exception 'no such block' using errcode = 'P0002'; end if;
  if w.member_id is null or w.member_id is distinct from coalesce(d.member_id, (select g.owner_id from app.agents g where g.id = d.agent_id)) then
    raise exception 'only the account the block was about can appeal it' using errcode = '42501';
  end if;
  if p_reason is null or char_length(btrim(p_reason)) not between 3 and 500 then raise exception 'bad appeal' using errcode = '22023'; end if;
  if exists (select 1 from app.wall_reviews r where r.decision_id = p_decision) then
    raise exception 'work_wall_reviewed' using errcode = 'P0001', hint = 'A person already decided this block.';
  end if;
  insert into app.wall_appeals (decision_id, member_id, reason) values (p_decision, w.member_id, btrim(p_reason))
    on conflict (decision_id) do nothing;
  if not found then raise exception 'work_wall_appealed' using errcode = 'P0001', hint = 'This block was already appealed.'; end if;
  perform app.audit_add('wall_appeal', 'wall_decision', p_decision, '{}'::jsonb);
  return 'appealed';
end $$;

-- The timer: each open appeal rechecked under today's rules and wiki. Clear now: a verified false positive (as an
-- administrator's would be), and the work goes back to staging. Still blocked: it waits in lane A for a person.
create function app.wall_recheck_run() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  p record;
  f jsonb;
  n integer := 0;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer rechecks' using errcode = '42501'; end if;
  for p in select x.* from app.wall_appeals x where x.status = 'open' order by x.created_at limit 20 for update skip locked loop
    f := app.wall_recheck_flags(p.decision_id);
    if f is not null and app.wall_decide(f) <> 'block' then
      insert into app.wall_reviews (decision_id, verdict, reason, reviewed_by)
        values (p.decision_id, 'false_positive', 'Recheck on appeal: today''s rules and security wiki no longer block it', null) on conflict (decision_id) do nothing;
      update app.work_submissions s set status = 'waiting', decided_by = null, decided_at = null, reason = null
        from app.wall_decisions d where d.id = p.decision_id and d.decision = 'block' and d.kind in ('submission', 'pr_files')
          and s.id = d.ref and s.status = 'failed' and s.decided_by = 'wall'
          and not exists (select 1 from app.wall_decisions o where o.ref = d.ref and o.id <> d.id and o.decision = 'block'
                           and not exists (select 1 from app.wall_reviews v where v.decision_id = o.id and v.verdict = 'false_positive'));
      update app.wall_appeals x set status = 'cleared', recheck_flags = f, rechecked_at = now() where x.id = p.id;
    else
      update app.wall_appeals x set status = 'upheld', recheck_flags = coalesce(f, '[]'::jsonb), rechecked_at = now() where x.id = p.id;
      perform app.notify(null, 'alert', 'An appeal of the Agentic Wall waits for a person',
        'The recheck under today''s rules still blocks it. Decide it in lane A.', '/admin', 'wall_decision', p.decision_id, 'wall:appeal:' || p.id);
    end if;
    n := n + 1;
  end loop;
  -- A person's decision on an appealed block closes the appeal.
  update app.wall_appeals x set status = 'decided' where x.status = 'upheld' and exists (select 1 from app.wall_reviews r where r.decision_id = x.decision_id);
  return n;
end $$;

-- The Fable 5.2 report: the day's facts (077), for Fable 5.2 to write up, read-only. Once a day.
create function app.oversight_report_claim() returns table (day date, facts jsonb, model text)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  r record;
  spent bigint;
  rep record;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer writes the report' using errcode = '42501'; end if;
  select * into s from app.oversight_settings x where x.singleton;
  select * into r from app.oversight_roles x where x.role = 'fable_report' for update;
  if r.id is null or r.mode = 'off' or s.monthly_cap_cents = 0 then return; end if;
  if s.monthly_cap_cents is not null then
    select coalesce(sum(c.centi_cents), 0) into spent from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC';
    if spent + r.call_price_centi_cents > s.monthly_cap_cents::bigint * 100 then return; end if;
  end if;
  select * into rep from app.oversight_reports x where x.narrative is null and x.day >= (now() at time zone 'UTC')::date - 1 order by x.day desc limit 1 for update skip locked;
  if rep.id is null then return; end if;
  if exists (select 1 from app.oversight_calls c where c.role = 'fable_report' and c.created_at > now() - interval '20 hours') then return; end if;
  insert into app.oversight_calls (role, model, centi_cents, error) values ('fable_report', r.model, r.call_price_centi_cents, 'pending');
  return query select rep.day, rep.facts, r.model;
end $$;
create function app.oversight_report_record(p_day date, p_narrative text, p_error text) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer writes the report' using errcode = '42501'; end if;
  update app.oversight_calls c set error = left(p_error, 40), verdict = case when p_error is null then 'ok' end
   where c.id = (select x.id from app.oversight_calls x where x.role = 'fable_report' and x.error = 'pending' order by x.created_at desc limit 1);
  if p_error is not null then return false; end if;
  update app.oversight_reports r set narrative = left(p_narrative, 4000) where r.day = p_day and r.narrative is null;
  return found;
end $$;

-- The weekly cross-check: on Mondays, the last 7 reports, read by another maker's model (fable_crosscheck).
create function app.oversight_crosscheck_claim() returns table (week date, reports jsonb, model text)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  r record;
  wk date := date_trunc('week', now() at time zone 'UTC')::date;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer runs the cross-check' using errcode = '42501'; end if;
  select * into s from app.oversight_settings x where x.singleton;
  select * into r from app.oversight_roles x where x.role = 'fable_crosscheck' for update;
  if r.id is null or r.mode = 'off' or s.monthly_cap_cents = 0 then return; end if;
  if exists (select 1 from app.oversight_crosschecks c where c.week = wk) then return; end if;
  if not exists (select 1 from app.oversight_reports x where x.narrative is not null and x.day >= wk - 7) then return; end if;
  insert into app.oversight_crosschecks (week, model, error) values (wk, r.model, 'pending');
  insert into app.oversight_calls (role, model, centi_cents, error) values ('fable_crosscheck', r.model, r.call_price_centi_cents, 'pending');
  return query select wk, coalesce((select jsonb_agg(jsonb_build_object('day', x.day, 'facts', x.facts, 'narrative', x.narrative) order by x.day)
                                    from app.oversight_reports x where x.day >= wk - 7 and x.day < wk + 1), '[]'::jsonb), r.model;
end $$;
create function app.oversight_crosscheck_record(p_week date, p_verdict text, p_reason text, p_error text) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer runs the cross-check' using errcode = '42501'; end if;
  if p_verdict is not null and p_verdict <> all (array['ok', 'concern']) then raise exception 'bad verdict' using errcode = '22023'; end if;
  update app.oversight_crosschecks c set verdict = case when p_error is null then p_verdict end, reason = left(p_reason, 300), error = left(p_error, 40)
   where c.week = p_week and c.error = 'pending';
  if not found then return false; end if;
  update app.oversight_calls c set error = left(p_error, 40), verdict = case when p_error is null then p_verdict end
   where c.id = (select x.id from app.oversight_calls x where x.role = 'fable_crosscheck' and x.error = 'pending' order by x.created_at desc limit 1);
  if p_error is null and p_verdict = 'concern' then
    perform app.notify(null, 'alert', 'The weekly cross-check disagrees with the Fable 5.2 reports',
      left(coalesce(p_reason, 'It found the reports and their facts don''t agree.'), 300), '/admin', null, null, 'oversight:crosscheck:' || p_week);
  end if;
  return true;
end $$;

revoke execute on function app.wall_appeal(uuid, text), app.wall_recheck_run(), app.oversight_report_claim(), app.oversight_report_record(date, text, text),
  app.oversight_crosscheck_claim(), app.oversight_crosscheck_record(date, text, text, text) from public;
grant execute on function app.wall_appeal(uuid, text), app.wall_recheck_run(), app.oversight_report_claim(), app.oversight_report_record(date, text, text),
  app.oversight_crosscheck_claim(), app.oversight_crosscheck_record(date, text, text, text) to dog_app;

reset role;
revoke create on schema app from dog_work;

