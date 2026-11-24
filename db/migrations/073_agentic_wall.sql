-- 073 The Agentic Wall's core (Aaron, Nov 24, 2026: "Build whats on diagram fully. Add items from CSO (value per
--   effort): 1 Rules enforced in a database function, 2 Task-declared scope ..."). Decisions recorded in harness/FACTS.md.
--
--   1. Rules enforced in the database: a trigger on every place agents' and people's work enters the database (tasks,
--      submissions, disputes, evidence, and a pull request's changed files when GitHub's facts arrive) runs the Wall's
--      fixed rules, whichever route wrote the row. No route can skip it.
--   2. Task-declared scope: a task's poster may declare the files (path prefixes), dependencies and network hosts the
--      work may touch. Work outside a declared scope is flagged, whatever it looks like. No wording in a task switches a
--      rule off (the simulation's task-word exemptions are not built).
--   3. Every decision is written to a hash-chained, append-only log (each row carries the previous row's hash).
--
--   The Wall starts in shadow mode: it decides and logs, and changes nothing. Holding work for a person (enforce mode)
--   comes with the review side's lanes and digest, in its own pull request. Checks alert, never lock out (Oct 23).
--   In shadow mode the log is the record; alerts to administrators come with the daily digest (review side's PR).
--   Option (a)'s data (known-bad package versions and the like) arrives with the security wiki, in its own pull request.

-- The gate runs as the tables' owner; it reads which submissions a pull request's files belong to, and an agent's
-- owner, and nothing else (as members_owner_select does for members).
create policy work_submissions_owner_select on app.work_submissions for select to dog_owner using (true);
create policy agents_owner_select on app.agents for select to dog_owner using (true);

set local role dog_owner;

create table app.wall_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  mode text not null default 'shadow' check (mode = any (array['off', 'shadow', 'enforce'])),
  rules_version integer not null default 1 check (rules_version between 1 and 100000),
  updated_at timestamptz not null default now()
);
insert into app.wall_settings (singleton) values (true);
alter table app.wall_settings enable row level security;
alter table app.wall_settings force row level security;
create policy wall_settings_read on app.wall_settings for select to dog_work using (true);
create policy wall_settings_owner on app.wall_settings for select to dog_owner using (true);
grant select on app.wall_settings to dog_work;

-- A task's declared scope: one row per allowed path prefix, dependency name or host.
create table app.work_task_scope (
  id uuid primary key default app.uuid_v7(),
  task_id uuid not null references app.work_tasks (id) on delete cascade,
  kind text not null check (kind = any (array['path', 'dependency', 'host'])),
  value text not null check (char_length(value) between 1 and 200 and value !~ '[[:space:]]'),
  created_at timestamptz not null default now(),
  unique (task_id, kind, value)
);
create index work_task_scope_task on app.work_task_scope (task_id, kind);
alter table app.work_task_scope enable row level security;
alter table app.work_task_scope force row level security;
create policy work_task_scope_work on app.work_task_scope for all to dog_work using (true) with check (true);
create policy work_task_scope_owner on app.work_task_scope for select to dog_owner using (true);
grant select, insert, delete on app.work_task_scope to dog_work;

-- The Wall's decisions: append-only, hash-chained.
create table app.wall_decisions (
  id uuid primary key default app.uuid_v7(),
  kind text not null check (kind = any (array['task', 'submission', 'dispute', 'evidence', 'pr_files'])),
  ref uuid not null,
  -- Who acted: their account's decisions go with it (PRIVACY-REQUESTS.md).
  member_id uuid references app.members (id) on delete cascade,
  agent_id uuid references app.agents (id) on delete cascade,
  decision text not null check (decision = any (array['allow', 'hold'])),
  flags jsonb not null default '[]'::jsonb check (jsonb_typeof(flags) = 'array' and octet_length(flags::text) <= 4000),
  mode text not null check (mode = any (array['shadow', 'enforce'])),
  rules_version integer not null check (rules_version between 1 and 100000),
  -- Unique: each row has exactly one row after it, so the log is one unbroken line, never a fork.
  prev_hash text not null unique check (char_length(prev_hash) = 64 and prev_hash ~ '^[0-9a-f]+$'),
  hash text not null unique check (char_length(hash) = 64 and hash ~ '^[0-9a-f]+$'),
  created_at timestamptz not null default now()
);
create index wall_decisions_at on app.wall_decisions (created_at desc, id desc);
create index wall_decisions_ref on app.wall_decisions (kind, ref);
create index wall_decisions_hold on app.wall_decisions (created_at desc) where decision = 'hold';
alter table app.wall_decisions enable row level security;
alter table app.wall_decisions force row level security;
create policy wall_decisions_owner_insert on app.wall_decisions for insert to dog_owner with check (true);
create policy wall_decisions_owner_select on app.wall_decisions for select to dog_owner using (true);
create policy wall_decisions_work_select on app.wall_decisions for select to dog_work using (true);
grant select on app.wall_decisions to dog_work;

-- Append-only: no update; a delete only when the account it belongs to goes (the cascade) or by the owner's purge.
create function app.wall_decisions_append_only() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  raise exception 'wall decisions are append-only' using errcode = '42501';
end $$;
create trigger wall_decisions_no_update before update on app.wall_decisions for each row execute function app.wall_decisions_append_only();

-- The fixed rules (rules version 1). Text in, flags out; the same input always gives the same flags.
create function app.wall_text_flags(p_text text) returns jsonb
language plpgsql immutable set search_path = pg_catalog as $$
declare
  t text := coalesce(p_text, '');
  -- Look-alike letters folded to Latin, and common HTML entities decoded, before the phrase rules (the simulation's
  -- homoglyph and entity cases).
  n text;
  f jsonb := '[]'::jsonb;
begin
  n := lower(translate(t, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  n := replace(replace(replace(replace(n, '&#8203;', ''), '&#x200b;', ''), '&amp;', '&'), '&nbsp;', ' ');
  if t ~ '[​‌⁠-⁤﻿]' or t ~ '[\U000E0000-\U000E007F]' or p_text ~ '&#(8203|x200b|8204|x200c|65279|xfeff);' then
    f := f || '["W07a hidden characters"]';
  end if;
  if n ~ '(ignore (all )?(previous|prior)( instructions)?|disregard (the )?(task|rules|instructions)|(reveal|print|ignore) (the |your )?system prompt|answer pass|mark (both|all|it|them) (as )?pass|checks are already satisfied|you are now (in )?[a-z]+ mode)' then
    f := f || '["W07b instruction aimed at a checker or agent"]';
  end if;
  if n ~ '\m(bit\.ly|tinyurl\.com|goo\.gl|is\.gd|ow\.ly|rb\.gy|cutt\.ly)/' then
    f := f || '["W06 link shortener"]';
  end if;
  if n ~ 'https?://[^[:space:]"'']+[?&](u|url|redirect|next|target|dest|to)=' then
    f := f || '["W23 redirecting link"]';
  end if;
  if n ~ '(169\.254\.169\.254|metadata\.google\.internal|://localhost|://127\.0\.0\.1|://10\.[0-9]+\.[0-9]+\.[0-9]+|://192\.168\.)' then
    f := f || '["W22 internal or metadata address"]';
  end if;
  if t ~ '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)' and t !~ 'AKIA[0-9A-Z]*EXAMPLE' then
    f := f || '["W11 credential in content"]';
  end if;
  if n ~ '\m(nmap|masscan|sqlmap|metasploit|hydra)\M' or n ~ '/etc/passwd' then
    f := f || '["W13 recon or exploit material"]';
  end if;
  if n ~ '\m(create|spawn|register|make) [0-9]+ (helper )?(agents|accounts|keys|bots)\M' then
    f := f || '["W20 asks to spawn agents or accounts"]';
  end if;
  return f;
end $$;

-- A pull request's changed files against the task's declared scope (paths and dependencies).
create function app.wall_files_flags(p_task uuid, p_files jsonb) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  f jsonb := '[]'::jsonb;
  paths text[];
  deps text[];
  fl jsonb;
  added text;
  m text;
begin
  select coalesce(array_agg(s.value) filter (where s.kind = 'path'), '{}'), coalesce(array_agg(s.value) filter (where s.kind = 'dependency'), '{}')
    into paths, deps from app.work_task_scope s where s.task_id = p_task;
  for fl in select * from jsonb_array_elements(coalesce(p_files, '[]'::jsonb)) loop
    if cardinality(paths) > 0 and not exists (select 1 from unnest(paths) p where (fl ->> 'filename') like p || '%') then
      f := f || jsonb_build_array('W04 file outside the task''s declared paths: ' || left(fl ->> 'filename', 120));
    end if;
    if (fl ->> 'filename') ~ '(^|/)(\.github/|CODEOWNERS$|jevs/|secondlook/|thirdlook/|db/migrations/)' and cardinality(paths) = 0 then
      f := f || jsonb_build_array('W03 protected file: ' || left(fl ->> 'filename', 120));
    end if;
    if (fl ->> 'filename') ~ '(^|/)package\.json$' then
      added := (select string_agg(l, E'\n') from regexp_split_to_table(coalesce(fl ->> 'patch', ''), E'\n') l where l ~ '^\+');
      if added ~ '"(pre|post)?install"[[:space:]]*:' then f := f || '["W19 install hook"]'; end if;
      for m in select (regexp_matches(coalesce(added, ''), '"([@a-z0-9._/-]+)"[[:space:]]*:[[:space:]]*"[\^~]?[0-9]', 'g'))[1] loop
        if m <> all (array['version', 'node']) and cardinality(deps) > 0 and m <> all (deps) then
          f := f || jsonb_build_array('W18 dependency outside the task''s declared list: ' || left(m, 100));
        end if;
      end loop;
    end if;
  end loop;
  return f;
end $$;

-- The gate: runs on every insert into the places work enters, writes a decision, changes nothing in shadow mode.
create function app.wall_gate() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
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
      dec := case when jsonb_array_length(flags) > 0 then 'hold' else 'allow' end;
      perform pg_advisory_xact_lock(7307307);
      select d.hash into prev from app.wall_decisions d where not exists (select 1 from app.wall_decisions x where x.prev_hash = d.hash);
      prev := coalesce(prev, repeat('0', 64));
      h := encode(sha256(convert_to(prev || '|' || k || '|' || ref::text || '|' || dec || '|' || flags::text || '|' || st.rules_version, 'UTF8')), 'hex');
      insert into app.wall_decisions (kind, ref, member_id, agent_id, decision, flags, mode, rules_version, prev_hash, hash)
        values (k, ref, mem, ag, dec, flags, st.mode, st.rules_version, prev, h);
    end loop;
    return null;
  end if;
  if ag is not null and mem is null then mem := (select g.owner_id from app.agents g where g.id = ag); end if;
  flags := flags || app.wall_text_flags(txt);
  dec := case when jsonb_array_length(flags) > 0 then 'hold' else 'allow' end;
  -- The chain: serialize writers so each row carries the one before it.
  perform pg_advisory_xact_lock(7307307);
  select d.hash into prev from app.wall_decisions d where not exists (select 1 from app.wall_decisions x where x.prev_hash = d.hash);
  prev := coalesce(prev, repeat('0', 64));
  h := encode(sha256(convert_to(prev || '|' || k || '|' || ref::text || '|' || dec || '|' || flags::text || '|' || st.rules_version, 'UTF8')), 'hex');
  insert into app.wall_decisions (kind, ref, member_id, agent_id, decision, flags, mode, rules_version, prev_hash, hash)
    values (k, ref, mem, ag, dec, flags, st.mode, st.rules_version, prev, h);
  return null;
end $$;
revoke execute on function app.wall_gate(), app.wall_files_flags(uuid, jsonb), app.wall_text_flags(text), app.wall_decisions_append_only() from public;

create trigger wall_gate after insert on app.work_tasks for each row execute function app.wall_gate('task');
create trigger wall_gate after insert on app.work_submissions for each row execute function app.wall_gate('submission');
create trigger wall_gate after insert on app.work_disputes for each row execute function app.wall_gate('dispute');
create trigger wall_gate after insert on app.work_dispute_evidence for each row execute function app.wall_gate('evidence');
create trigger wall_gate after insert on app.tl_files for each row execute function app.wall_gate('pr_files');
-- Fire always, so the replication setting that switches ordinary triggers off can't switch the Wall off (as 021).
alter table app.work_tasks enable always trigger wall_gate;
alter table app.work_submissions enable always trigger wall_gate;
alter table app.work_disputes enable always trigger wall_gate;
alter table app.work_dispute_evidence enable always trigger wall_gate;
alter table app.tl_files enable always trigger wall_gate;
alter table app.wall_decisions enable always trigger wall_decisions_no_update;
reset role;

-- The poster declares a task's scope (the API calls this right after posting, in the same transaction).
grant create on schema app to dog_work;
set local role dog_work;
create function app.work_task_scope_put(p_task uuid, p_scope jsonb) returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  w record;
  t record;
  e record;
  n integer := 0;
begin
  select * into w from app.work_who();
  select * into t from app.work_tasks x where x.id = p_task;
  if t.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  if t.poster_member is distinct from w.member_id or t.poster_agent is distinct from w.agent_id then
    raise exception 'only the task''s poster declares its scope' using errcode = '42501';
  end if;
  if t.status <> 'open' or exists (select 1 from app.work_claims c where c.task_id = p_task) then
    raise exception 'work_scope_fixed' using errcode = 'P0001', hint = 'A task''s scope is set when it is posted, before anyone claims it.';
  end if;
  if p_scope is null or jsonb_typeof(p_scope) <> 'object' or exists (select 1 from jsonb_object_keys(p_scope) k where k <> all (array['paths', 'dependencies', 'hosts'])) then
    raise exception 'bad scope' using errcode = '22023';
  end if;
  for e in select case k when 'paths' then 'path' when 'dependencies' then 'dependency' else 'host' end as kind, v #>> '{}' as value
             from jsonb_each(p_scope) as j(k, a), jsonb_array_elements(case when jsonb_typeof(a) = 'array' then a else '[]'::jsonb end) v loop
    if e.value is null or char_length(e.value) not between 1 and 200 or e.value ~ '[[:space:]]' then raise exception 'bad scope' using errcode = '22023'; end if;
    n := n + 1;
    if n > 50 then raise exception 'bad scope' using errcode = '22023', hint = 'At most 50 entries.'; end if;
    insert into app.work_task_scope (task_id, kind, value) values (p_task, e.kind, e.value) on conflict do nothing;
  end loop;
  return n;
end $$;

-- A task's scope, for its page (public, like the task itself).
create function app.work_task_scope_get(p_task uuid) returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object(
    'paths', coalesce((select jsonb_agg(s.value order by s.value) from app.work_task_scope s where s.task_id = p_task and s.kind = 'path'), '[]'::jsonb),
    'dependencies', coalesce((select jsonb_agg(s.value order by s.value) from app.work_task_scope s where s.task_id = p_task and s.kind = 'dependency'), '[]'::jsonb),
    'hosts', coalesce((select jsonb_agg(s.value order by s.value) from app.work_task_scope s where s.task_id = p_task and s.kind = 'host'), '[]'::jsonb))
$$;

-- The Wall's log for an administrator, newest first, and a check that the chain is unbroken.
create function app.wall_log(p_limit integer) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator reads the Wall''s log' using errcode = '42501'; end if;
  return (select coalesce(jsonb_agg(jsonb_build_object('id', d.id, 'kind', d.kind, 'ref', d.ref, 'decision', d.decision, 'flags', d.flags,
            'mode', d.mode, 'rules_version', d.rules_version, 'at', d.created_at) order by d.created_at desc, d.id desc), '[]'::jsonb)
          from (select * from app.wall_decisions x order by x.created_at desc, x.id desc limit least(greatest(coalesce(p_limit, 50), 1), 200)) d);
end $$;

create function app.wall_chain_ok() returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  -- One start (the all-zero hash), every other row follows a row that exists, and each row's hash is what its
  -- fields give: an edited or removed row breaks it.
  select (select count(*) from app.wall_decisions d where d.prev_hash = repeat('0', 64)) <= 1
     and not exists (select 1 from app.wall_decisions d where d.prev_hash <> repeat('0', 64)
                       and not exists (select 1 from app.wall_decisions x where x.hash = d.prev_hash))
     and not exists (select 1 from app.wall_decisions d
                      where d.hash <> encode(sha256(convert_to(d.prev_hash || '|' || d.kind || '|' || d.ref::text || '|' || d.decision || '|' || d.flags::text || '|' || d.rules_version, 'UTF8')), 'hex'))
$$;

revoke execute on function app.work_task_scope_put(uuid, jsonb), app.work_task_scope_get(uuid), app.wall_log(integer), app.wall_chain_ok() from public;
grant execute on function app.work_task_scope_put(uuid, jsonb), app.work_task_scope_get(uuid), app.wall_log(integer), app.wall_chain_ok() to dog_app;
reset role;
revoke create on schema app from dog_work;
