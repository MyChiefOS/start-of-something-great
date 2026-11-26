-- 085 The Agentic Wall's malware signatures (Aaron, Nov 25: "matching files against malware signatures (YARA rules,
--   the standard pattern language) ... yes implement it"). YARA runs inside the Wall's scanner in the GitHub facts
--   workflow (wall/yara.js, YARA as WebAssembly), on YARA Forge's core rules read fresh each hourly run, kept only from
--   rule sets whose license allows our use, and never a rule that matches an honest test file. A match is W42 and blocks.

reset role;
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W42', 'block', 'A file matching a malware signature (a YARA rule from YARA Forge''s core pack, from a rule set whose license allows our use)'),
  ('W42b', 'flag', 'A malware signature that matched files in 3 or more pull requests, or 10 or more files, in one run (more likely a bad rule: flagged, not blocked)');
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
                                      or split_part(g #>> '{}', ' ', 1) <> all (array['W30', 'W31', 'W39', 'W40', 'W40b', 'W41', 'W42', 'W42b']))))
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

alter table app.wall_settings disable row level security;
update app.wall_settings set rules_version = rules_version + 1;
alter table app.wall_settings enable row level security;
