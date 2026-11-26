-- 095: the link sandbox (Aaron, Nov 24: the oversight diagram's "sandboxed penetration tester", "no cutting corners";
-- Nov 26: "I should only look at high risk cases after several reviews and sandbox testing"). Until now the sandbox
-- (088, W47) ran only pull requests' files: work sent as a link was never opened. Now each link submitted for work and
-- not yet decided is opened once in headless Chrome inside the sandbox of the GitHub facts workflow (wall/links.js):
-- no lasting profile, downloads denied and recorded, every request logged, and no network but HTTPS to the link's own
-- host through a proxy that refuses private, local and cloud-metadata addresses. Its findings come back through
-- dog-github as dog_ghsync, like the pull request sandbox's, and are written here to the Wall's log as a decision
-- about the submission, so the reviewers' settle (094) sees them: any finding is a high-risk case for Aaron.
--   W51   block  the page started a program's download on its own, loads a crypto-miner, or reached for a cloud-metadata
--                address: refused at once (a person can mark it a mistake)
--   W51b  flag   an archive's download, a redirect to another site, a password or payment-card form, hidden code, a
--                private or local address, or a link that could not be opened
-- The hosts and links the page reached or tried are read against the security wiki's threat lists here (W28, W28b).
-- Files sent as work carry only a SHA-256; the Wall's gate already checks it against the wiki's known-bad list (W33,
-- app.wall_intel_flags on the submission's text, which holds the fingerprint since 081), so nothing changes for them.

reset role;
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W51', 'block', 'A link that, opened in the sandbox, started a program''s download on its own, loads a crypto-miner or reached for a cloud-metadata address'),
  ('W51b', 'flag', 'A link that, opened in the sandbox, started an archive''s download, redirected to another site, asks for a password or a payment card, hides code, reached for a private address, or could not be opened');
alter table app.wall_rules enable row level security;

set local role dog_owner;
-- Which links the sandbox has opened: each once. A link whose run never came back is asked for again by the next run.
create table app.wall_link_runs (
  id uuid primary key default app.uuid_v7(),
  submission_id uuid not null unique references app.work_submissions (id) on delete cascade,
  decision_id uuid references app.wall_decisions (id) on delete set null,
  ran_at timestamptz not null default now()
);
alter table app.wall_link_runs enable row level security;
alter table app.wall_link_runs force row level security;
create policy wall_link_runs_owner on app.wall_link_runs for all to dog_owner using (true) with check (true);
create policy wall_link_runs_work on app.wall_link_runs for select to dog_work using (true);
grant select, insert on app.wall_link_runs to dog_owner;
grant select on app.wall_link_runs to dog_work;

-- The links the sandbox should open: link submissions still waiting or in review that it hasn't opened, oldest first,
-- at most 5 a run. Only the GitHub facts function asks (dog_ghsync).
create function app.wall_links_wanted(p_n integer)
returns table (id uuid, url text)
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function reads this (dog_ghsync)' using errcode = '42501';
  end if;
  return query select s.id, s.artifact_url from app.work_submissions s
    -- 094 review: passed work too (a pass between solo agents can come seconds after the link is sent), for 3 days,
    -- after the work still waiting.
    where s.artifact_kind = 'link' and s.artifact_url ~* '^https?://'
      and (s.status in ('waiting', 'review') or (s.status = 'passed' and s.decided_at > now() - interval '3 days'))
      and not exists (select 1 from app.wall_link_runs r where r.submission_id = s.id)
    order by (s.status = 'passed'), s.created_at, s.id limit least(greatest(coalesce(p_n, 1), 1), 5);
end
$$;
revoke execute on function app.wall_links_wanted(integer) from public;
grant execute on function app.wall_links_wanted(integer) to dog_ghsync;

-- The sandbox's findings, from the GitHub facts function (dog_ghsync): [{ id, flags, seen }]. Only W51 and W51b in the
-- sandbox's own words are taken (anything else drops that link's findings); seen, the hosts and links the page
-- reached or tried, is read against the wiki's threat lists. Each becomes one decision in the Wall's chained log
-- (kind 'submission', ref the submission), once per submission; a block in enforce mode fails the work, as the gate
-- does. Returns how many were recorded.
create function app.wall_links_record(p jsonb)
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  x jsonb;
  s record;
  st record;
  flags jsonb;
  dec text;
  prev text;
  h text;
  mem uuid;
  did uuid;
  n integer := 0;
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function records GitHub''s facts (dog_ghsync)' using errcode = '42501';
  end if;
  if p is null or jsonb_typeof(p) <> 'array' or jsonb_array_length(p) > 10 then
    raise exception 'bad link findings' using errcode = '22023';
  end if;
  select * into st from app.wall_settings;
  for x in select * from jsonb_array_elements(p) loop
    if jsonb_typeof(x) <> 'object' or coalesce(x ->> 'id', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       or jsonb_typeof(x -> 'flags') is distinct from 'array' or jsonb_array_length(x -> 'flags') > 10
       or exists (select 1 from jsonb_array_elements(x -> 'flags') g where jsonb_typeof(g) <> 'string' or char_length(g #>> '{}') > 240
                   or not (starts_with(g #>> '{}', 'W51 link sandbox: ') or starts_with(g #>> '{}', 'W51b link sandbox: ')))
       or (x ? 'seen' and (jsonb_typeof(x -> 'seen') <> 'array' or jsonb_array_length(x -> 'seen') > 50
           or exists (select 1 from jsonb_array_elements(x -> 'seen') g where jsonb_typeof(g) <> 'string' or char_length(g #>> '{}') > 500)))
       or exists (select 1 from jsonb_object_keys(x) k where k <> all (array['id', 'flags', 'seen'])) then
      continue;
    end if;
    select * into s from app.work_submissions w where w.id = (x ->> 'id')::uuid and w.artifact_kind = 'link' and w.status in ('waiting', 'review', 'passed') for update;
    if s.id is null or exists (select 1 from app.wall_link_runs r where r.submission_id = s.id) then continue; end if;
    flags := (x -> 'flags') || coalesce(app.wall_intel_flags((select string_agg(g, E'\n') from jsonb_array_elements_text(coalesce(x -> 'seen', '[]'::jsonb)) g), null), '[]'::jsonb);
    flags := coalesce((select jsonb_agg(distinct f) from jsonb_array_elements(flags) f), '[]'::jsonb);
    dec := app.wall_decide(flags);
    mem := coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent));
    perform pg_advisory_xact_lock(7307307);
    select d.hash into prev from app.wall_decisions d where not exists (select 1 from app.wall_decisions y where y.prev_hash = d.hash);
    prev := coalesce(prev, repeat('0', 64));
    h := encode(sha256(convert_to(prev || '|submission|' || s.id::text || '|' || dec || '|' || flags::text || '|' || st.rules_version, 'UTF8')), 'hex');
    insert into app.wall_decisions (kind, ref, member_id, agent_id, decision, flags, mode, rules_version, prev_hash, hash)
      values ('submission', s.id, mem, s.worker_agent, dec, flags, st.mode, st.rules_version, prev, h) returning id into did;
    insert into app.wall_link_runs (submission_id, decision_id) values (s.id, did);
    if dec = 'block' and st.mode = 'enforce' then
      update app.work_submissions w set status = 'failed', decided_by = 'wall', decided_at = now(),
        reason = left('Refused by the Agentic Wall: ' || (select string_agg(y, '; ') from jsonb_array_elements_text(flags) y), 300)
        where w.id = s.id and w.status in ('waiting', 'review');
    end if;
    -- Already passed, and the sandbox found something: Aaron hears of it, as a high-risk case (he decides a reversal).
    if s.status = 'passed' and jsonb_array_length(flags) > 0 then
      perform app.notify(null, 'alert', 'High-risk work waits for you',
        left('A passed link, opened in the sandbox: ' || (select string_agg(y, '; ') from jsonb_array_elements_text(flags) y), 200),
        '/admin/review#work', 'submission', s.id, 'work:highrisk:' || s.id);
    end if;
    n := n + 1;
  end loop;
  return n;
end
$$;
revoke execute on function app.wall_links_record(jsonb) from public;
grant execute on function app.wall_links_record(jsonb) to dog_ghsync;

-- Whether a link submission still waits for the sandbox: not yet opened, and sent less than 6 hours ago (after that a
-- sandbox outage stops holding it up, as 055 does for GitHub's facts). For the reviewers' settle (094) to wait on.
create function app.wall_link_waiting(p_sub uuid) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from app.work_submissions s where s.id = p_sub and s.artifact_kind = 'link' and s.created_at > now() - interval '6 hours'
                   and not exists (select 1 from app.wall_link_runs r where r.submission_id = s.id))
$$;
revoke execute on function app.wall_link_waiting(uuid) from public;
grant execute on function app.wall_link_waiting(uuid) to dog_work;

-- An appeal's recheck (089) reads a submission's text again under today's rules. The sandbox's findings are what the
-- page did when it was opened, not text, so the recheck keeps them (W51, W51b) beside today's text flags: a refused
-- link isn't cleared just by being appealed; it waits in lane A for a person, as any block the recheck still finds.
create or replace function app.wall_recheck_flags(p_decision uuid) returns jsonb
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
    -- The file's fingerprint too (as wall_gate reads it, 089), so an appealed W33 block can't recheck as clear.
    select coalesce(x.note, '') || ' ' || coalesce(x.artifact_url, '') || ' ' || coalesce(x.artifact_sha256, '') into txt from app.work_submissions x where x.id = d.ref;
    f := app.wall_text_flags(txt) || app.wall_intel_flags(txt)
      || coalesce((select jsonb_agg(g) from jsonb_array_elements(d.flags) g where split_part(g #>> '{}', ' ', 1) in ('W51', 'W51b')), '[]'::jsonb);
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

reset role;
