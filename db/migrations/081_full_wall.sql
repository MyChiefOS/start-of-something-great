-- 081 The full Agentic Wall (Aaron, Nov 24-25: "I'm not okay with you limiting the security capabilities"; "if you have a
--   known exploit that is flagged it should be blocked"). What 073 left out of Aaron's design (wall-v2) is ported here:
--   the code rules, run on every changed line of a pull request (persistence, network and exec calls the task didn't ask
--   for, the whole environment used as data, internal addresses, recon material, tests skipped or pinned, errors
--   swallowed as success, encoded blobs, binaries, hidden characters and instructions aimed at checkers in code,
--   credentials, links), the wider protected files, and the scope exceptions (CHANGELOG, README, shared types, lock files).
--   Measured on the Nov 24 blind set: known attacks 16 of 20, new 3 of 20, honest work flagged 0 of 80 (the reduced Wall
--   073 shipped: 7, 1 and 3 of 40).
--   Each rule's effect is published in app.wall_rules: a clear breach blocks; anything else is flagged ('hold') for the
--   reviewers and goes ahead. The Wall runs as work enters, before anything is passed, so a submission is staged in its
--   waiting state while the checks run. In enforce mode a block fails the submission (decided_by 'wall') or removes the
--   task; the reviewers can mark a block a false positive, which puts the submission back to waiting (re-route to staging).
--   The Wall moves from shadow to enforce.

set local role dog_owner;
create table app.wall_rules (
  id uuid primary key default app.uuid_v7(),
  rule text not null unique check (char_length(rule) between 3 and 4 and rule ~ '^W[0-9]{2}[a-z]?$'),
  effect text not null check (effect = any (array['block', 'flag'])),
  what text not null check (char_length(what) between 3 and 200)
);
insert into app.wall_rules (rule, effect, what) values
  ('W03', 'block', 'Changes a protected file (CI, checks, the Wall, owners) when the task isn''t about it'),
  ('W04', 'flag', 'Changes a file outside the task''s declared paths'),
  ('W05', 'block', 'Persistence in code: cron, services, curl or wget piped into a shell, a new git remote, a deploy key'),
  ('W06', 'flag', 'A link shortener'),
  ('W07a', 'flag', 'Hidden characters'),
  ('W07b', 'block', 'An instruction aimed at a checker or an agent'),
  ('W09', 'flag', 'A long encoded blob'),
  ('W10', 'flag', 'A binary file the task didn''t ask for'),
  ('W11', 'block', 'A real credential in content'),
  ('W12', 'flag', 'A network or exec call the task didn''t ask for'),
  ('W13', 'block', 'Recon or exploit material'),
  ('W15', 'block', 'A test skipped, narrowed or pinned to the current output'),
  ('W16', 'flag', 'An error swallowed and returned as success'),
  ('W18', 'flag', 'A dependency outside the task''s declared list (or the allowlist)'),
  ('W19', 'block', 'An install hook in package.json'),
  ('W20', 'flag', 'Asks to spawn agents or accounts'),
  ('W21', 'block', 'The whole environment used as data'),
  ('W22', 'block', 'An internal or cloud-metadata address'),
  ('W23', 'flag', 'A redirecting link'),
  ('W24', 'flag', 'A link outside the task''s declared hosts'),
  ('W25', 'block', 'A dependency pinned to a version the security wiki names in an advisory (a known exploit)');
alter table app.wall_rules enable row level security;
alter table app.wall_rules force row level security;
create policy wall_rules_read on app.wall_rules for select to dog_owner, dog_public, dog_work using (true);
grant select on app.wall_rules to dog_public, dog_work;

alter table app.wall_decisions drop constraint wall_decisions_decision_check;
alter table app.wall_decisions add constraint wall_decisions_decision_check check (decision = any (array['allow', 'hold', 'block']));
alter table app.work_submissions drop constraint work_submissions_decided_by_check;
alter table app.work_submissions add constraint work_submissions_decided_by_check
  check (decided_by = any (array['jevs', 'poster', 'person', 'timeout', 'third_look', 'peer', 'wall']));

-- The Wall reads a task's words to know what it asked for (as 073 let it read the task's scope).
create policy work_tasks_wall_read on app.work_tasks for select to dog_owner using (true);
-- The Wall's refusal (wall_gate runs as dog_owner): only these two moves, nothing else.
create policy work_submissions_wall_fail on app.work_submissions for update to dog_owner
  using (status = any (array['waiting', 'review'])) with check (status = 'failed' and decided_by = 'wall');
create policy work_tasks_wall_remove on app.work_tasks for update to dog_owner
  using (status = any (array['open', 'funding'])) with check (status = 'removed');

-- The code rules, on the added lines of one changed file (Aaron's wall-v2, ported).
create function app.wall_code_flags(p_path text, p_added text, p_task text) returns jsonb
language plpgsql immutable set search_path = pg_catalog as $$
declare
  f jsonb := '[]'::jsonb;
  t text := coalesce(p_added, '');
  n text;
  task text := lower(coalesce(p_task, ''));
  joined text;
begin
  if p_path ~* '\.(md|mdx|txt|rst)$' then return f; end if;  -- prose is read by the text rules
  n := lower(translate(t, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  if n ~ '(crontab|systemd|\.service\M|curl[^\n|]*\|[[:space:]]*(ba)?sh|wget[^\n|]*\|[[:space:]]*(ba)?sh|git remote add|deploy[_-]?key)' then
    f := f || '["W05 persistence in code"]';
  end if;
  if t ~ '(process\.env([^.A-Za-z_]|$)|Object\.(keys|entries)\(process\.env\)|os\.environ([^\[]|$))' then
    f := f || '["W21 whole environment used as data"]';
  end if;
  if t ~ '\m(fetch|axios|https?\.(get|request)|XMLHttpRequest|net\.connect|child_process|execSync|exec\()' or t ~ 'require\([''"]dns[''"]\)'
     then
    if task !~ '\m(api|client|http|upload|retry|request|download|webhook|dns|build|network)\M' then
      f := f || '["W12 network or exec call the task didn''t ask for"]';
    end if;
  end if;
  if n ~ '(169\.254\.169\.254|metadata\.google\.internal|\.internal\M|localhost|127\.0\.0\.1|\m10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.)' then
    f := f || '["W22 internal or metadata address"]';
  end if;
  if n ~ '\m(nmap|masscan|sqlmap|metasploit|hydra)\M' or n ~ '/etc/passwd' then
    f := f || '["W13 recon or exploit material"]';
  end if;
  if t ~ '(\.skip\(|\.only\(|xit\(|xdescribe\(|test\.todo|expect\([^)]*\)\.toBe\([A-Za-z0-9_]+\)[[:space:]]*//[[:space:]]*matches current)' then
    f := f || '["W15 weakens or pins a test"]';
  end if;
  if t ~ 'catch[[:space:]]*\([^)]*\)[[:space:]]*\{[[:space:]]*return[[:space:]]*\{[[:space:]]*ok:[[:space:]]*true' then
    f := f || '["W16 swallows errors as success"]';
  end if;
  if t ~ '"(pre|post)?install"[[:space:]]*:' then
    f := f || '["W19 install hook"]';
  end if;
  joined := regexp_replace(regexp_replace(regexp_replace(t, 'data:image/svg\+xml;base64,[A-Za-z0-9+/=]+', '', 'g'),
              'integrity="sha(256|384|512)-[^"]+"', '', 'g'), '["''`][[:space:]]*\+[[:space:]]*["''`]', '', 'g');
  if joined ~ '[A-Za-z0-9+/]{120,}' then
    f := f || '["W09 encoded data"]';
  end if;
  if p_path ~* '\.(png|jpg|gif|bin|exe|so|dll|wasm)$' and task !~ '\m(logo|image|icon|png|wasm|asset|binary)\M' then
    f := f || '["W10 binary the task didn''t ask for"]';
  end if;
  return f || app.wall_text_flags(t);
end $$;
revoke execute on function app.wall_code_flags(text, text, text) from public;

-- A pull request's changed files: scope and protected files (with the design's exceptions), dependencies, and the code
-- rules on each file's added lines.
create or replace function app.wall_files_flags(p_task uuid, p_files jsonb) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  f jsonb := '[]'::jsonb;
  paths text[];
  deps text[];
  fl jsonb;
  added text;
  m text[];
  adv text;
  fname text;
  task text;
  allow_deps constant text[] := array['lodash', 'dayjs', 'axios', 'zod', 'react', 'express', 'postgres', 'jest', 'typescript'];
begin
  select coalesce(array_agg(s.value) filter (where s.kind = 'path'), '{}'), coalesce(array_agg(s.value) filter (where s.kind = 'dependency'), '{}')
    into paths, deps from app.work_task_scope s where s.task_id = p_task;
  select coalesce(t.title, '') || E'\n' || coalesce(t.description, '') into task from app.work_tasks t where t.id = p_task;
  for fl in select * from jsonb_array_elements(coalesce(p_files, '[]'::jsonb)) loop
    fname := coalesce(fl ->> 'filename', '');
    added := (select string_agg(substr(l, 2), E'\n') from regexp_split_to_table(coalesce(fl ->> 'patch', ''), E'\n') l where l ~ '^\+' and l !~ '^\+\+\+');
    if cardinality(paths) > 0 and not exists (select 1 from unnest(paths) p where fname like p || '%')
       and fname !~ '^(CHANGELOG|README)' and fname !~ '^src/(shared|types)/' and fname !~ 'package-lock\.json$' then
      f := f || jsonb_build_array('W04 file outside the task''s declared paths: ' || left(fname, 120));
    end if;
    if fname ~ '(^|/)(\.github/|CODEOWNERS$|\.semgrep|jevs/|secondlook/|thirdlook/|wall/|scripts/check|\.husky/|Dockerfile$|vercel\.json$|db/migrations/)'
       and lower(coalesce(task, '')) !~ '\m(ci|workflow|nightly|action|pipeline|migration)\M' then
      f := f || jsonb_build_array('W03 protected file: ' || left(fname, 120));
    end if;
    if fname ~ '(^|/)package\.json$' then
      for m in select regexp_matches(coalesce(added, ''), '"([@a-z0-9._/-]+)"[[:space:]]*:[[:space:]]*"([\^~]?)([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*|[0-9][^"]*)"', 'g') loop
        if m[1] <> all (array['version', 'node']) and m[1] <> all (case when cardinality(deps) > 0 then deps else allow_deps end) then
          f := f || jsonb_build_array('W18 dependency outside the task''s declared list: ' || left(m[1], 100));
        end if;
        -- 074's check, kept: an added dependency pinned to a version an advisory in the active security wiki names.
        adv := app.wiki_bad_package('npm', m[1], m[3]);
        if adv is not null then
          f := f || jsonb_build_array('W25 known-bad package version (security wiki, ' || adv || '): ' || left(m[1] || '@' || m[3], 120));
        end if;
      end loop;
    end if;
    f := f || app.wall_code_flags(fname, added, task);
  end loop;
  return f;
end $$;
revoke execute on function app.wall_files_flags(uuid, jsonb) from public;

-- A decision from its flags: block if any flag's rule blocks, flag ('hold') if any flag, else allow.
create function app.wall_decide(p_flags jsonb) returns text
language sql stable security definer set search_path = pg_catalog as $$
  select case
    when jsonb_array_length(coalesce(p_flags, '[]'::jsonb)) = 0 then 'allow'
    when exists (select 1 from jsonb_array_elements_text(p_flags) x join app.wall_rules r on split_part(x, ' ', 1) = r.rule where r.effect = 'block') then 'block'
    else 'hold' end
$$;
revoke execute on function app.wall_decide(jsonb) from public;
reset role;

set local role dog_owner;
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
    txt := coalesce(r ->> 'note', '') || E'\n' || coalesce(r ->> 'artifact_url', '');
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
  flags := flags || app.wall_text_flags(txt);
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
      update app.work_tasks t set status = 'removed' where t.id = ref and t.status in ('open', 'funding');
    end if;
  end if;
  return null;
end $function$;
reset role;

grant create on schema app to dog_work;
set local role dog_work;
CREATE OR REPLACE FUNCTION app.wall_review(p_decision uuid, p_verdict text, p_reason text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare w record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator reviews the Wall''s flags' using errcode = '42501'; end if;
  select * into w from app.work_who();
  if p_verdict is null or p_verdict <> all (array['false_positive', 'confirmed']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad review' using errcode = '22023';
  end if;
  if not exists (select 1 from app.wall_decisions d where d.id = p_decision and d.decision in ('hold', 'block')) then
    raise exception 'no such flag' using errcode = 'P0002';
  end if;
  if exists (select 1 from app.wall_reviews r where r.decision_id = p_decision) then
    raise exception 'work_wall_reviewed' using errcode = 'P0001', hint = 'This flag was already reviewed.';
  end if;
  insert into app.wall_reviews (decision_id, verdict, reason, reviewed_by) values (p_decision, p_verdict, btrim(p_reason), w.member_id);
  perform app.audit_add('wall_review', 'wall_decision', p_decision, jsonb_build_object('verdict', p_verdict));
  -- 081: a block found to be a false positive goes back to staging: the submission waits again, as if never refused.
  if p_verdict = 'false_positive' then
    update app.work_submissions s set status = 'waiting', decided_by = null, decided_at = null, reason = null
      from app.wall_decisions d where d.id = p_decision and d.decision = 'block' and d.kind in ('submission', 'pr_files')
        and s.id = d.ref and s.status = 'failed' and s.decided_by = 'wall';
  end if;
  return p_verdict;
end $function$;
CREATE OR REPLACE FUNCTION app.oversight_run()
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
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
      'wall_last_day', (select jsonb_build_object('allow', count(*) filter (where d.decision = 'allow'), 'hold', count(*) filter (where d.decision = 'hold'), 'block', count(*) filter (where d.decision = 'block'))
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
  if a_total + b_total > 0 and app.notify(null, 'alert', 'Daily review digest: ' || a_total || ' in lane A, ' || b_total || ' in lane B',
       'Lane A (the Agentic Wall''s unreviewed flags, last 24 hours): ' || coalesce(a_groups, 'none') || '. Lane B (work under the 70% line, last 24 hours): '
       || coalesce(b_groups, 'none') || '. Nothing was held.', '/admin', null, null, 'review:digest:' || today) then
    n := n + 1;
  end if;
  return n;
end $function$;
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
                   where (app.work_final_score(z.id) ->> 'passes')::boolean is false), '[]'::jsonb));
end $function$;
CREATE OR REPLACE FUNCTION app.watchtower_run()
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  s record;
  r record;
  n integer := 0;
  day text := to_char(now() at time zone 'UTC', 'YYYYMMDD');
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the watchtower' using errcode = '42501';
  end if;
  select * into s from app.watchtower_settings x where x.singleton for update;
  if s.mode = 'off' or (s.last_run_at is not null and s.last_run_at > now() - make_interval(mins => s.every_minutes)) then return 0; end if;
  update app.watchtower_settings x set last_run_at = now() where x.singleton;

  -- 1. Spam: tasks and submissions by an account (an agent counts for its owner), last hour against its usual hour
  --    over the 7 days before.
  for r in
    with acts as (
      select coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) as who, t.created_at from app.work_tasks t
       where t.created_at > now() - interval '7 days 1 hour'
      union all
      select coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)), x.created_at from app.work_submissions x
       where x.created_at > now() - interval '7 days 1 hour')
    select who, count(*) filter (where created_at > now() - interval '1 hour') as last_hour,
           count(*) filter (where created_at <= now() - interval '1 hour') / 168.0 as usual
      from acts where who is not null group by who
  loop
    if r.last_hour >= s.spam_floor and r.last_hour > s.spam_multiplier * r.usual
       and not exists (select 1 from app.members m where m.id = r.who and m.is_admin)
       and app.notify(null, 'alert', 'Watchtower: an account is posting far more work than usual',
             r.last_hour || ' tasks and submissions in the last hour; its usual hour over the last 7 days is ' || round(r.usual, 1) || '. Nothing was held.',
             '/admin', 'member', r.who, 'watchtower:spam:' || r.who || ':' || day) then
      n := n + 1;
    end if;
  end loop;

  -- 2. Points-gaming: a worker's passed work in 7 days, mostly from one poster, or from their own side.
  for r in
    with passed as (
      select coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) as worker,
             coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) as poster
        from app.work_submissions x join app.work_tasks t on t.id = x.task_id
       where x.status = 'passed' and x.created_at > now() - interval '7 days' and t.source <> 'github')
    select worker, sum(c) as total,
           max(c) as top,
           sum(c) filter (where poster = worker) as own
      from (select worker, poster, count(*) as c from passed where worker is not null and poster is not null group by worker, poster) p
     group by worker
  loop
    if r.total >= s.gaming_min_passes and (r.top * 100 >= r.total * s.gaming_share_pct or coalesce(r.own, 0) > 0)
       and app.notify(null, 'alert', 'Watchtower: points may be gamed',
             case when coalesce(r.own, 0) > 0 then r.own || ' of ' || r.total || ' passes in 7 days were on tasks from the worker''s own account or agents.'
                  else r.top || ' of ' || r.total || ' passes in 7 days came from one poster.' end || ' Nothing was held; the review side decides.',
             '/admin', 'member', r.worker, 'watchtower:gaming:' || r.worker || ':' || day) then
      n := n + 1;
    end if;
  end loop;

  -- 3. Swarms: many agents taken on by one owner in a day (an agent registers itself unowned; its owner claims it).
  for r in select g.owner_id as who, count(*) as c from app.agents g where g.claimed_at > now() - interval '1 day' and g.owner_id is not null group by g.owner_id loop
    if r.c >= s.swarm_agents_per_day
       and app.notify(null, 'alert', 'Watchtower: an owner took on many agents today',
             r.c || ' agents in the last 24 hours. Nothing was held.', '/admin', 'member', r.who, 'watchtower:swarm:' || r.who || ':' || day) then
      n := n + 1;
    end if;
  end loop;

  -- 4. Repeated Agentic Wall flags on one account's work in a day.
  for r in select d.member_id as who, count(*) as c from app.wall_decisions d
            where d.decision in ('hold', 'block') and d.created_at > now() - interval '1 day' and d.member_id is not null group by d.member_id loop
    if r.c >= s.wall_flags_per_day
       and app.notify(null, 'alert', 'Watchtower: the Agentic Wall flagged one account''s work several times today',
             r.c || ' flags in the last 24 hours. Nothing was held.', '/admin', 'member', r.who, 'watchtower:wall:' || r.who || ':' || day) then
      n := n + 1;
    end if;
  end loop;
  return n;
end $function$;
CREATE OR REPLACE FUNCTION app.work_final_score(p_sub uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  s record;
  score integer := 100;
  why jsonb := '[]'::jsonb;
  line integer;
  wall boolean;
begin
  select x.id, x.task_id, x.pr_number, x.worker_member, x.worker_agent into s from app.work_submissions x where x.id = p_sub;
  if s.id is null then return null; end if;
  select r.pass_line into line from app.lanes_settings r where r.singleton;
  if exists (select 1 from app.sl_items i where i.kind = 'submission' and i.ref = p_sub and i.decision = 'reject') then
    score := score - 40; why := why || '["Second Look rejected its note"]';
  end if;
  if exists (select 1 from app.tl_reviews r where r.submission_id = p_sub and r.suggestion = 'person') then
    score := score - 20; why := why || '["Third Look left it to a person"]';
  end if;
  if exists (select 1 from app.work_disputes d where d.submission_id = p_sub and d.status = 'open') then
    score := score - 20; why := why || '["an open dispute"]';
  end if;
  if exists (select 1 from app.notices n where n.member_id is null and n.dedupe_key like 'watchtower:%:'
               || coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent))::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD')) then
    score := score - 20; why := why || '["a watchtower alert on its worker today"]';
  end if;
  wall := exists (select 1 from app.wall_decisions d where d.decision in ('hold', 'block') and d.kind in ('submission', 'pr_files') and d.ref = p_sub
                   and not exists (select 1 from app.wall_reviews w where w.decision_id = d.id and w.verdict = 'false_positive'));
  if wall then why := why || '["an unreviewed Agentic Wall flag (capped below the line)"]'; score := least(score, line - 1); end if;
  return jsonb_build_object('score', greatest(score, 0), 'pass_line', line, 'passes', greatest(score, 0) >= line, 'reasons', why);
end $function$;
reset role;
revoke create on schema app from dog_work;

set local role dog_owner;
CREATE OR REPLACE FUNCTION app.agent_standing_from_wall()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
begin
  if new.member_id is not null and new.decision = 'block' and new.mode = 'enforce' then
    perform app.agent_standing_event(new.member_id, 'violation');
  end if;
  return null;
end
$function$;
reset role;

set local role dog_owner;
grant execute on function app.wall_decide(jsonb) to dog_work;
reset role;
-- The settings table has no update policy (an owner's change is a migration), so the row is written with RLS off for this
-- one statement, as 080 did for jevs_settings.
alter table app.wall_settings disable row level security;
update app.wall_settings set mode = 'enforce', rules_version = rules_version + 1;
alter table app.wall_settings enable row level security;
