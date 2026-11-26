-- 084 The Agentic Wall scans file contents (Aaron, Nov 25: "checking a file's real type from its contents",
--   "unpacking archives and scanning inside", built into the Wall). The GitHub facts workflow, which already reads a
--   pull request's changed files for Third Look, now also reads each file's contents and runs the Wall's scanner
--   (wall/files.js) on them; the scan (real type and broken rules) is recorded with the file, and the Wall's gate
--   decides on it like its other rules: W39 disguised type, W40 archive bomb and W41 active document block; W31 an
--   executable inside an archive blocks; W30 an archive the Wall can't open is flagged.

reset role;
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W39', 'block', 'A file whose contents are a program or another kind of file than its name says'),
  ('W40', 'block', 'An archive past the limits: nested more than 3 deep, over 1,000 files, over 50 MB unpacked, or an entry that unpacks past its declared size'),
  ('W40b', 'flag', 'An archive that unpacks to over 100 times its size, within the size limit'),
  ('W41', 'block', 'An Office file with macros, or a PDF with JavaScript or a launch action');
alter table app.wall_rules enable row level security;

grant create on schema app to dog_work;
set local role dog_work;
create or replace function app.tl_files_record(p jsonb)
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  x jsonb;
  added integer := 0;
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function records GitHub''s facts (dog_ghsync)' using errcode = '42501';
  end if;
  if p is null or jsonb_typeof(p) <> 'array' or jsonb_array_length(p) > 10 then
    raise exception 'bad changed files' using errcode = '22023';
  end if;
  delete from app.tl_files f where f.read_at < now() - interval '14 days';
  for x in select * from jsonb_array_elements(p) loop
    if jsonb_typeof(x) <> 'object' or coalesce(x ->> 'number', '') !~ '^[1-9][0-9]{0,6}$' or jsonb_typeof(x -> 'files') is distinct from 'array'
       or jsonb_array_length(x -> 'files') > 100 or octet_length((x -> 'files')::text) > 100000 then
      continue;
    end if;
    if exists (select 1 from jsonb_array_elements(x -> 'files') f
                where jsonb_typeof(f) <> 'object' or jsonb_typeof(f -> 'filename') is distinct from 'string' or char_length(f ->> 'filename') > 300
                   or (f ? 'status' and (jsonb_typeof(f -> 'status') <> 'string' or char_length(f ->> 'status') > 20))
                   or (f ? 'changes' and jsonb_typeof(f -> 'changes') <> 'number')
                   or (f ? 'patch' and jsonb_typeof(f -> 'patch') <> 'string')
                   -- 084: the Wall's scan of the file's contents (wall/files.js): its real type and the rules it breaks.
                   -- Only the scanner's own rules, in its own words, are taken: anything else drops the list.
                   or (f ? 'scan' and (jsonb_typeof(f -> 'scan') <> 'object' or jsonb_typeof(f -> 'scan' -> 'type') is distinct from 'string'
                       or char_length(f -> 'scan' ->> 'type') > 12 or jsonb_typeof(f -> 'scan' -> 'flags') is distinct from 'array'
                       or jsonb_array_length(f -> 'scan' -> 'flags') > 20
                       or exists (select 1 from jsonb_array_elements(f -> 'scan' -> 'flags') g
                                   where jsonb_typeof(g) <> 'string' or char_length(g #>> '{}') > 240
                                      or split_part(g #>> '{}', ' ', 1) <> all (array['W30', 'W31', 'W39', 'W40', 'W40b', 'W41']))))
                   or exists (select 1 from jsonb_object_keys(f) k where k <> all (array['filename', 'status', 'changes', 'patch', 'scan']))) then
      continue;
    end if;
    if not app.tl_wants((x ->> 'number')::integer) then continue; end if;
    insert into app.tl_files (number, files) values ((x ->> 'number')::integer, x -> 'files')
      on conflict (number) do update set files = excluded.files, read_at = now();
    added := added + 1;
  end loop;
  return added;
end
$$;
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
    -- 084: the scan of the file's contents, made by the Wall's scanner in the facts workflow (wall/files.js).
    if jsonb_typeof(fl -> 'scan' -> 'flags') = 'array' then
      f := f || (fl -> 'scan' -> 'flags');
    end if;
    if not (fl ? 'patch') and not (fl ? 'scan') and coalesce(fl ->> 'status', '') <> 'removed' then
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
reset role;

alter table app.wall_settings disable row level security;
update app.wall_settings set rules_version = rules_version + 1;
alter table app.wall_settings enable row level security;
