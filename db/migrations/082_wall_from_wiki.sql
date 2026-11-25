-- 082 The Wall patched from the security wiki on every sync (Aaron, Nov 25: "the wall should be patch with latest updates
--   to protect the system from data within the wiki"; "Put everything you can into the agentic wall currently").
--
--   Like a firewall: known-bad IP addresses, domains and URLs from threat feeds; a match anywhere in work blocks (W28).
--   Like an email filter: a file fingerprint on a known-bad list blocks (W33); executable and installer files (W31) and
--   disguised names (W32) block; archives the Wall can't open are flagged (W30); prompt-injection patterns kept in the
--   wiki block (W29).
--
--   Sources: abuse.ch Feodo Tracker (CC0, no account) always. URLhaus, ThreatFox and MalwareBazaar need an abuse.ch
--   account and may need a paid license for commercial use: built, and used only when the site has a key (Aaron's call).
--   Injection patterns: wiki/reference.json, changed only by a pull request Aaron merges.
--
--   Guards on a poisoned feed: shapes and sizes checked per row; never-block domains (the site's own, GitHub, npm and
--   the big platforms) are dropped; a run that changes more than max_indicator_change_pct of the indicators is refused
--   (nothing changes); an administrator rolls back one step (074), and the Wall follows the active version at once; a
--   false positive goes to the reviewers (076/081).

set local role dog_owner;

alter table app.wiki_settings add column max_indicator_change_pct integer not null default 50 check (max_indicator_change_pct between 1 and 100);
alter table app.wiki_versions add column indicators integer not null default 0 check (indicators between 0 and 200000);

create table app.wiki_indicators (
  id uuid primary key default app.uuid_v7(),
  version_id uuid not null references app.wiki_versions (id) on delete cascade,
  kind text not null check (kind = any (array['ip', 'domain', 'url', 'sha256', 'injection', 'injection_flag'])),
  value text not null check (char_length(value) between 6 and 500),
  source text not null check (source = any (array['feodo', 'urlhaus', 'threatfox', 'malwarebazaar', 'reference'])),
  ref text check (char_length(ref) <= 60 and ref ~ '^[A-Za-z0-9 ._:/-]*$'),
  check (case kind
    when 'ip' then value ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'
    when 'domain' then char_length(value) <= 253 and value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    when 'url' then value ~ '^https?://[^[:space:]"''<>]+$'
    when 'sha256' then value ~ '^[0-9a-f]{64}$'
    when 'injection' then char_length(value) <= 120 and value ~ '^[!-~]([ -~]*[!-~])?$' and value !~ '  ' and value = lower(value)
    when 'injection_flag' then char_length(value) <= 120 and value ~ '^[!-~]([ -~]*[!-~])?$' and value !~ '  ' and value = lower(value)
  end),
  unique (version_id, kind, value)
);
create index wiki_indicators_lookup on app.wiki_indicators (version_id, kind, value);
alter table app.wiki_indicators enable row level security;
alter table app.wiki_indicators force row level security;
create policy wiki_indicators_work on app.wiki_indicators for all to dog_work using (true) with check (true);
create policy wiki_indicators_owner on app.wiki_indicators for select to dog_owner using (true);
grant select, insert, update, delete on app.wiki_indicators to dog_work;

-- The rules table takes rows only from a migration (no insert policy), so this one statement runs with RLS off.
reset role;
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W28', 'block', 'A known-bad IP address, domain or URL from the security wiki''s threat feeds'),
  ('W29', 'block', 'A prompt-injection phrase aimed at a checker or a model, from the security wiki'),
  ('W29b', 'flag', 'A broader injection phrase from the security wiki, or any injection phrase inside a test or fixture'),
  ('W07c', 'flag', 'An instruction aimed at a checker, inside a test or fixture file'),
  ('W30', 'flag', 'An archive the Wall can''t open'),
  ('W31', 'block', 'An executable or installer file the task didn''t name'),
  ('W32', 'block', 'A disguised file name (a double extension or a reversed-text character)'),
  ('W33', 'block', 'A file fingerprint on the security wiki''s known-bad list');
alter table app.wall_rules enable row level security;
set local role dog_owner;

-- The domains the feeds may never block: the site itself and the platforms its work runs on. A feed entry for one is
-- dropped when the wiki records it (a URL on one is still kept: it names one path, not the whole site).
create function app.wiki_never_block(p_domain text) returns boolean
language sql immutable set search_path = pg_catalog as $$
  select coalesce(lower(p_domain), '') ~ '(^|\.)(dayonegreat\.(com|ai)|github\.com|githubusercontent\.com|github\.io|npmjs\.(com|org)|vercel\.(app|com)|supabase\.(co|com)|google\.com|googleapis\.com|microsoft\.com|apple\.com|amazon\.com|amazonaws\.com|cloudflare\.com|anthropic\.com|claude\.ai|wikipedia\.org|example\.(com|org|net))$'
$$;
revoke execute on function app.wiki_never_block(text) from public;

-- 082 review: addresses a feed may never block: private, loopback, link-local, shared, multicast and reserved ranges, and
-- the public DNS resolvers; and public suffixes (a domain indicator like com.au would block a whole country's sites).
create function app.wiki_never_block_ip(p_ip text) returns boolean
language sql immutable set search_path = pg_catalog as $$
  select coalesce(p_ip, '') ~ '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|2[3-5][0-9]\.)'
      or coalesce(p_ip, '') = any (array['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '4.2.2.1', '4.2.2.2'])
$$;
create function app.wiki_public_suffix(p_domain text) returns boolean
language sql immutable set search_path = pg_catalog as $$
  select coalesce(lower(p_domain), '') ~ '^((com|net|org|co|gov|edu|ac|or|ne|go|mil|nic|ltd|plc|sch|nhs|gob|gouv|biz|info|blogspot|github|herokuapp|appspot|azurewebsites|cloudfront|pages|netlify|workers|web)\.[a-z]{2,}|[a-z]{2,3})$'
$$;
revoke execute on function app.wiki_never_block_ip(text), app.wiki_public_suffix(text) from public;
grant execute on function app.wiki_never_block_ip(text), app.wiki_public_suffix(text) to dog_work;
grant execute on function app.wiki_never_block(text) to dog_work;

-- A URL compared without case, fragment, query or a trailing slash (a feed's URL and the one in work alike).
create function app.wall_url_norm(p_url text) returns text
language sql immutable set search_path = pg_catalog as $$
  select rtrim(split_part(split_part(lower(coalesce(p_url, '')), '#', 1), '?', 1), '/')
$$;
revoke execute on function app.wall_url_norm(text) from public;
grant execute on function app.wall_url_norm(text) to dog_work;

-- The Wall's lookups against the active wiki version: what a text names that the feeds or the wiki's patterns flag.
-- Each lookup is an equality on the index (version, kind, value): a host is matched by its own suffixes (a.b.evil.test
-- tries a.b.evil.test, b.evil.test, evil.test), never by a scan. p_path: an injection phrase in a test or fixture file
-- is flagged, not blocked (the project's own red-team tests quote them).
create function app.wall_intel_flags(p_text text, p_path text default null) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  t text := left(coalesce(p_text, ''), 2000000);
  n text;
  vid uuid;
  f jsonb := '[]'::jsonb;
  hit record;
  test_path boolean := coalesce(p_path, '') ~* '(^|/)(test|tests|__tests__|spec|fixtures?|redteam|__fixtures__)/|\.(test|spec)\.[a-z]+$';
begin
  select v.id into vid from app.wiki_versions v where v.status = 'active';
  if vid is null or t = '' then return f; end if;
  n := lower(translate(t, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  n := regexp_replace(regexp_replace(n, '[​‌⁠-⁤﻿]', '', 'g'), '[[:space:]]+', ' ', 'g');
  -- Defanged indicators (hxxp, [.]) read as the real thing.
  n := replace(replace(replace(replace(n, 'hxxp', 'http'), '[.]', '.'), '(.)', '.'), '[:]', ':');
  for hit in
    with urls as (select distinct app.wall_url_norm(rtrim(m[1], '.,;:)]''"')) as u from regexp_matches(n, '(https?://[^[:space:]"''<>`]+)', 'g') m),
         hosts as (select distinct h from (select substring(u from '^https?://(?:[^@/]*@)?([^/:?#]+)') as h from urls
                    union select (regexp_matches(n, '\m([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\.[a-z][a-z0-9-]{1,23})\M', 'g'))[1]) x where h is not null),
         suffixes as (select distinct array_to_string(p[k:], '.') as d
                        from (select string_to_array(h, '.') as p from hosts) y, generate_subscripts(y.p, 1) k where cardinality(p) - k >= 1),
         -- Dotted (leading zeros read as decimal) and a bare 32-bit number, both as a.b.c.d.
         ips as (select distinct ip from (
                   select m[1]::int || '.' || m[2]::int || '.' || m[3]::int || '.' || m[4]::int as ip
                     from regexp_matches(n, '\m([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\M', 'g') m
                   union all
                   select (x >> 24) || '.' || ((x >> 16) & 255) || '.' || ((x >> 8) & 255) || '.' || (x & 255)
                     from (select (regexp_matches(n, '(?:^|[^0-9.])([0-9]{8,10})(?:$|[^0-9.])', 'g'))[1]::bigint as x) z where x between 16777216 and 4294967295) w),
         shas as (select distinct (regexp_matches(n, '\m([0-9a-f]{64})\M', 'g'))[1] as s)
    select 'W28' as rule, i.kind, i.value, i.source, i.ref from urls join app.wiki_indicators i on i.version_id = vid and i.kind = 'url' and i.value = urls.u
    union all
    select 'W28', i.kind, i.value, i.source, i.ref from suffixes join app.wiki_indicators i on i.version_id = vid and i.kind = 'domain' and i.value = suffixes.d
    union all
    select 'W28', i.kind, i.value, i.source, i.ref from ips join app.wiki_indicators i on i.version_id = vid and i.kind = 'ip' and i.value = ips.ip
    union all
    select 'W33', i.kind, i.value, i.source, i.ref from shas join app.wiki_indicators i on i.version_id = vid and i.kind = 'sha256' and i.value = shas.s
    union all
    select case when i.kind = 'injection' and not test_path then 'W29' else 'W29b' end, i.kind, i.value, i.source, i.ref
      from app.wiki_indicators i where i.version_id = vid and i.kind in ('injection', 'injection_flag') and strpos(n, i.value) > 0
    limit 20
  loop
    f := f || jsonb_build_array(hit.rule || case hit.rule when 'W33' then ' known-bad file fingerprint' when 'W29' then ' injection pattern' when 'W29b' then ' injection phrase' else ' known-bad ' || hit.kind end
           || ' (security wiki, ' || hit.source || coalesce(' ' || hit.ref, '') || '): ' || left(hit.value, 100));
  end loop;
  return f;
end $$;
revoke execute on function app.wall_intel_flags(text, text) from public;
reset role;

-- The wiki records indicators beside its entries and packages (074's record, with the indicators and their cap).
grant create on schema app to dog_work;
set local role dog_work;
create or replace function app.wiki_record(p_claim text, p jsonb) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  cur record;
  vid uuid;
  ne integer;
  np integer;
  ni integer;
  changed integer;
  why text;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records the wiki' using errcode = '42501';
  end if;
  select * into s from app.wiki_settings x where x.singleton for update;
  if p_claim is null or s.claim_hash is null or s.claim_until < now() or s.claim_hash <> encode(sha256(convert_to(p_claim, 'UTF8')), 'hex') then
    raise exception 'no wiki claim' using errcode = '42501';
  end if;
  update app.wiki_settings x set claim_hash = null, claim_until = null where x.singleton;
  if p is null or jsonb_typeof(p) <> 'object' or jsonb_typeof(p -> 'entries') <> 'array' or jsonb_typeof(p -> 'packages') <> 'array'
     or jsonb_typeof(coalesce(p -> 'indicators', '[]'::jsonb)) <> 'array'
     or jsonb_typeof(coalesce(p -> 'sources', '{}'::jsonb)) <> 'object' or octet_length(p::text) > 16000000 then
    raise exception 'bad wiki run' using errcode = '22023';
  end if;
  ne := jsonb_array_length(p -> 'entries');
  np := jsonb_array_length(p -> 'packages');
  ni := jsonb_array_length(coalesce(p -> 'indicators', '[]'::jsonb));
  if ne > 20000 or np > 20000 or ni > 200000 then raise exception 'bad wiki run' using errcode = '22023'; end if;
  insert into app.wiki_versions (status, entries, packages, indicators, sources) values ('kept', ne, np, 0, coalesce(p -> 'sources', '{}'::jsonb)) returning id into vid;
  -- Each row is checked by the tables' own limits: one bad row refuses the whole run (nothing half-written).
  insert into app.wiki_entries (version_id, source, ident, title, severity, cwe, kev, published)
    select vid, e ->> 'source', e ->> 'ident', left(e ->> 'title', 300), e ->> 'severity', e ->> 'cwe', coalesce((e ->> 'kev')::boolean, false), (e ->> 'published')::date
      from jsonb_array_elements(p -> 'entries') e
    on conflict do nothing;
  insert into app.wiki_packages (version_id, ecosystem, name, version, advisory)
    select vid, k ->> 'ecosystem', lower(k ->> 'name'), k ->> 'version', k ->> 'advisory' from jsonb_array_elements(p -> 'packages') k
    on conflict do nothing;
  insert into app.wiki_indicators (version_id, kind, value, source, ref)
    select vid, i ->> 'kind', case when i ->> 'kind' = 'url' then app.wall_url_norm(i ->> 'value') else lower(i ->> 'value') end, i ->> 'source', left(i ->> 'ref', 60)
      from jsonb_array_elements(coalesce(p -> 'indicators', '[]'::jsonb)) i
     where not (i ->> 'kind' = 'domain' and (app.wiki_never_block(i ->> 'value') or app.wiki_public_suffix(i ->> 'value')))
       and not (i ->> 'kind' = 'ip' and app.wiki_never_block_ip(i ->> 'value'))
       and not (i ->> 'kind' = 'url' and app.wiki_never_block(substring(lower(i ->> 'value') from '^https?://(?:[^@/]*@)?([^/:?#]+)')) and substring(lower(i ->> 'value') from '^https?://[^/]+(/[^?#]*)?') in ('', '/'))
    on conflict do nothing;
  update app.wiki_versions v set indicators = (select count(*) from app.wiki_indicators x where x.version_id = vid) where v.id = vid;
  -- The change caps: rows added plus rows dropped, against the active version (packages, then indicators).
  select * into cur from app.wiki_versions v where v.status = 'active';
  if cur.id is not null and cur.packages >= 20 then
    select (select count(*) from (select ecosystem, name, version, advisory from app.wiki_packages where version_id = vid
                                   except select ecosystem, name, version, advisory from app.wiki_packages where version_id = cur.id) a)
         + (select count(*) from (select ecosystem, name, version, advisory from app.wiki_packages where version_id = cur.id
                                   except select ecosystem, name, version, advisory from app.wiki_packages where version_id = vid) b)
      into changed;
    if changed * 100 > cur.packages * s.max_change_pct then
      why := 'refused: ' || changed || ' of ' || cur.packages || ' exact-match rows would change (cap ' || s.max_change_pct || '%)';
    end if;
  end if;
  if why is null and cur.id is not null and cur.indicators >= 20 then
    select (select count(*) from (select kind, value from app.wiki_indicators where version_id = vid
                                   except select kind, value from app.wiki_indicators where version_id = cur.id) a)
         + (select count(*) from (select kind, value from app.wiki_indicators where version_id = cur.id
                                   except select kind, value from app.wiki_indicators where version_id = vid) b)
      into changed;
    if changed * 100 > cur.indicators * s.max_indicator_change_pct then
      why := 'refused: ' || changed || ' of ' || cur.indicators || ' indicators would change (cap ' || s.max_indicator_change_pct || '%)';
    end if;
  end if;
  if why is not null then
    delete from app.wiki_indicators where version_id = vid;
    delete from app.wiki_packages where version_id = vid;
    delete from app.wiki_entries where version_id = vid;
    update app.wiki_versions v set status = 'refused', reason = why where v.id = vid;
    return 'refused';
  end if;
  update app.wiki_versions v set status = 'kept' where v.status = 'active';
  update app.wiki_versions v set status = 'active' where v.id = vid;
  -- Keep the active version and the two before it; refused runs' records go after 30 days.
  delete from app.wiki_versions v where v.status = 'kept' and v.id not in (select x.id from app.wiki_versions x where x.status = 'kept' order by x.created_at desc, x.id desc limit 2);
  delete from app.wiki_versions v where v.status = 'refused' and v.created_at < now() - interval '30 days';
  return 'active';
end $$;
revoke execute on function app.wiki_record(text, jsonb) from public;
grant execute on function app.wiki_record(text, jsonb) to dog_app;
reset role;
revoke create on schema app from dog_work;

set local role dog_owner;
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
  ext text;
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
    -- 081 review: no task wording exempts a protected file. Inside the poster's declared paths it is flagged (goes ahead,
    -- reviewers see it); anywhere else it is blocked.
    if fname ~* '(^|/)(\.github/|CODEOWNERS$|\.semgrep|jevs/|secondlook/|thirdlook/|wall/|scripts/check|\.husky/|Dockerfile[^/]*$|[^/]*\.dockerfile$|vercel\.json$|db/migrations/|\.npmrc$)' then
      -- Flag, not block, only when the task is about it in both ways: a declared path that itself names the protected place
      -- (.github/workflows/ does; src/ doesn't) and task wording about it. Wording alone, or a broad path alone, blocks.
      if cardinality(paths) > 0 and exists (select 1 from unnest(paths) p where lower(fname) like lower(p) || '%'
           and p ~* '(^|/)(\.github/|CODEOWNERS$|\.semgrep|jevs/|secondlook/|thirdlook/|wall/|scripts/check|\.husky/|Dockerfile[^/]*$|[^/]*\.dockerfile$|vercel\.json$|db/migrations/|\.npmrc$)')
         and lower(coalesce(task, '')) ~ '\m(ci|workflow|nightly|action|pipeline|migration|codeowners|owners|docker|deploy|hook)s?\M' then
        f := f || jsonb_build_array('W03b protected file in the declared paths: ' || left(fname, 120));
      else
        f := f || jsonb_build_array('W03 protected file: ' || left(fname, 120));
      end if;
    end if;
    if not (fl ? 'patch') and coalesce(fl ->> 'status', '') <> 'removed' then
      f := f || jsonb_build_array('W27 changed file the Wall couldn''t read: ' || left(fname, 120));
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
    -- 082 review: inside a test or fixture file, a phrase aimed at a checker is flagged (W07c), not blocked: the
    -- project's red-team tests quote them. Reviewers still see it.
    if fname ~* '(^|/)(test|tests|__tests__|spec|fixtures?|redteam|__fixtures__)/|\.(test|spec)\.[a-z]+$' then
      f := f || coalesce((select jsonb_agg(case when x like 'W07b %' then 'W07c' || substr(x, 5) || ' (in a test or fixture)' else x end)
                            from jsonb_array_elements_text(app.wall_code_flags(fname, added, task)) x), '[]'::jsonb) || app.wall_intel_flags(added, fname);
    else
      f := f || app.wall_code_flags(fname, added, task) || app.wall_intel_flags(added, fname);
    end if;
    -- 082, as an email filter treats attachments: by the file's name (GitHub sends no bytes for a binary file).
    ext := lower(substring(fname from '\.([A-Za-z0-9]{1,8})$'));
    if lower(fname) ~ '\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rtf)\.(exe|scr|pif|com|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|lnk|msi|ps1|jar)$'
       or fname ~ '[\u202e\u202d\u200e\u200f]' then
      f := f || jsonb_build_array('W32 disguised file name: ' || left(fname, 120));
    elsif ext = any (array['exe', 'scr', 'pif', 'com', 'vbe', 'wsf', 'wsh', 'hta', 'lnk', 'msi', 'msp', 'cpl', 'apk', 'dll', 'sys', 'dmg', 'pkg', 'deb', 'rpm', 'iso', 'img'])
       and not (cardinality(paths) > 0 and exists (select 1 from unnest(paths) p where lower(p) = lower(fname))) then
      f := f || jsonb_build_array('W31 executable or installer file: ' || left(fname, 120));
    elsif ext = any (array['zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'jar', 'war', 'cab']) then
      f := f || jsonb_build_array('W30 archive the Wall can''t open: ' || left(fname, 120));
    end if;
  end loop;
  return f;
end $$;
revoke execute on function app.wall_files_flags(uuid, jsonb) from public;
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
  flags := flags || app.wall_text_flags(txt) || app.wall_intel_flags(txt);
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
reset role;

alter table app.wall_settings disable row level security;
update app.wall_settings set rules_version = rules_version + 1;
alter table app.wall_settings enable row level security;
