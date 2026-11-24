-- 074 The security wiki and option (a) (Aaron, Nov 24: "create a security focused wiki ... updates two times a day";
--   "I will make an exception to allow the agentic wall to be updated twice a day"; scoped to option (a), recorded in
--   harness/FACTS.md).
--
--   The site's timer reads public feeds twice a day (wiki/sync.js: NVD's recent CVEs with CISA KEV marked, and the
--   pinned reference lists for MITRE's CWE Top 25, the OWASP API Security Top 10 and OWASP ASVS 5.0) and records them
--   here as a new version. Option (a) only: the Wall uses exact-match data (a package name and version an advisory
--   names), never new rule patterns. New rules still change only by a PR Aaron merges.
--
--   Guards on what a feed can do (a poisoned feed is the risk): structured fields only, each checked for shape and size;
--   a run that would change more than a quarter of the exact-match rows is refused and kept as "refused" (nothing
--   changes); the last three versions are kept and an administrator can roll back one step. The Wall only flags; in
--   shadow mode it changes nothing (073).

set local role dog_owner;

create table app.wiki_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  mode text not null default 'on' check (mode = any (array['off', 'on'])),
  -- Twice a day: a run is due 12 hours after the last one began.
  every_hours integer not null default 12 check (every_hours between 6 and 168),
  last_run_at timestamptz,
  claim_hash text check (char_length(claim_hash) = 64 and claim_hash ~ '^[0-9a-f]+$'),
  claim_until timestamptz,
  -- A run may change at most this share of the exact-match rows before it is refused.
  max_change_pct integer not null default 25 check (max_change_pct between 1 and 100)
);
-- The first run is 12 hours after this migration, so a fresh database (a test's, a preview's) reads no feed on its own.
insert into app.wiki_settings (singleton, last_run_at) values (true, now());

create table app.wiki_versions (
  id uuid primary key default app.uuid_v7(),
  status text not null check (status = any (array['active', 'kept', 'refused'])),
  entries integer not null check (entries between 0 and 20000),
  packages integer not null check (packages between 0 and 20000),
  sources jsonb not null check (jsonb_typeof(sources) = 'object' and octet_length(sources::text) <= 2000),
  reason text check (char_length(reason) <= 300),
  created_at timestamptz not null default now()
);
create unique index wiki_versions_one_active on app.wiki_versions ((true)) where status = 'active';

-- What the wiki knows: one row per advisory, weakness or reference item.
create table app.wiki_entries (
  id uuid primary key default app.uuid_v7(),
  version_id uuid not null references app.wiki_versions (id) on delete cascade,
  source text not null check (source = any (array['nvd', 'cwe', 'owasp_api', 'asvs'])),
  ident text not null check (char_length(ident) <= 24 and ident ~ '^(CVE-[0-9]{4}-[0-9]{4,7}|CWE-[0-9]{1,5}|API[0-9]{1,2}:20[0-9]{2}|V[0-9]{1,2}(\.[0-9]{1,2}){0,2})$'),
  title text not null check (char_length(title) between 1 and 300),
  severity text check (severity = any (array['low', 'medium', 'high', 'critical'])),
  cwe text check (char_length(cwe) <= 9 and cwe ~ '^CWE-[0-9]{1,5}$'),
  kev boolean not null default false,
  published date,
  unique (version_id, source, ident)
);
create index wiki_entries_version on app.wiki_entries (version_id, source);

-- Option (a)'s exact-match data: a package version an advisory names.
create table app.wiki_packages (
  id uuid primary key default app.uuid_v7(),
  version_id uuid not null references app.wiki_versions (id) on delete cascade,
  ecosystem text not null check (ecosystem = any (array['npm'])),
  name text not null check (char_length(name) between 1 and 214 and name ~ '^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$'),
  version text not null check (char_length(version) between 1 and 64 and version ~ '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'),
  advisory text not null check (char_length(advisory) <= 20 and advisory ~ '^CVE-[0-9]{4}-[0-9]{4,7}$'),
  unique (version_id, ecosystem, name, version, advisory)
);
create index wiki_packages_lookup on app.wiki_packages (ecosystem, name, version);

do $rls$
declare t text;
begin
  foreach t in array array['wiki_settings', 'wiki_versions', 'wiki_entries', 'wiki_packages'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('alter table app.%I force row level security', t);
    execute format('create policy %I on app.%I for all to dog_work using (true) with check (true)', t || '_work', t);
    execute format('create policy %I on app.%I for select to dog_owner using (true)', t || '_owner', t);
    execute format('grant select, insert, update, delete on app.%I to dog_work', t);
  end loop;
end
$rls$;

-- The Wall reads it: is this exact package version named by an advisory in the active version? The advisory, or null.
create function app.wiki_bad_package(p_eco text, p_name text, p_version text) returns text
language sql stable security definer set search_path = pg_catalog as $$
  select p.advisory from app.wiki_packages p join app.wiki_versions v on v.id = p.version_id and v.status = 'active'
   where p.ecosystem = p_eco and p.name = lower(p_name) and p.version = p_version
   order by p.advisory limit 1
$$;

-- The Wall's pull-request check (073) gains option (a): an added dependency pinned to a version an advisory names.
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
      for m in select regexp_matches(coalesce(added, ''), '"([@a-z0-9._/-]+)"[[:space:]]*:[[:space:]]*"([\^~]?)([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*)"', 'g') loop
        if m[1] <> all (array['version', 'node']) and cardinality(deps) > 0 and m[1] <> all (deps) then
          f := f || jsonb_build_array('W18 dependency outside the task''s declared list: ' || left(m[1], 100));
        end if;
        adv := app.wiki_bad_package('npm', m[1], m[3]);
        if adv is not null then
          f := f || jsonb_build_array('W25 known-bad package version (security wiki, ' || adv || '): ' || left(m[1] || '@' || m[3], 120));
        end if;
      end loop;
    end if;
  end loop;
  return f;
end $$;
revoke execute on function app.wiki_bad_package(text, text, text), app.wall_files_flags(uuid, jsonb) from public;
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- The timer asks whether a run is due; if so it gets a claim good for 10 minutes, and only that claim can record.
create function app.wiki_claim() returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare s record; c text;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the wiki''s sync' using errcode = '42501';
  end if;
  select * into s from app.wiki_settings x where x.singleton for update;
  if s.mode = 'off' or (s.last_run_at is not null and s.last_run_at > now() - make_interval(hours => s.every_hours)) then return null; end if;
  if s.claim_until is not null and s.claim_until > now() then return null; end if;
  c := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  update app.wiki_settings x set last_run_at = now(), claim_hash = encode(sha256(convert_to(c, 'UTF8')), 'hex'), claim_until = now() + interval '10 minutes' where x.singleton;
  return c;
end $$;

-- Records a run: { entries: [{source, ident, title, severity?, cwe?, kev?, published?}], packages: [{ecosystem, name,
-- version, advisory}], sources: {name: count} }. Returns 'active' or 'refused'.
create function app.wiki_record(p_claim text, p jsonb) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  cur record;
  vid uuid;
  ne integer;
  np integer;
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
     or jsonb_typeof(coalesce(p -> 'sources', '{}'::jsonb)) <> 'object' or octet_length(p::text) > 4000000 then
    raise exception 'bad wiki run' using errcode = '22023';
  end if;
  ne := jsonb_array_length(p -> 'entries');
  np := jsonb_array_length(p -> 'packages');
  if ne > 20000 or np > 20000 then raise exception 'bad wiki run' using errcode = '22023'; end if;
  insert into app.wiki_versions (status, entries, packages, sources) values ('kept', ne, np, coalesce(p -> 'sources', '{}'::jsonb)) returning id into vid;
  -- Each row is checked by the tables' own limits: one bad row refuses the whole run (nothing half-written).
  insert into app.wiki_entries (version_id, source, ident, title, severity, cwe, kev, published)
    select vid, e ->> 'source', e ->> 'ident', left(e ->> 'title', 300), e ->> 'severity', e ->> 'cwe', coalesce((e ->> 'kev')::boolean, false), (e ->> 'published')::date
      from jsonb_array_elements(p -> 'entries') e
    on conflict do nothing;
  insert into app.wiki_packages (version_id, ecosystem, name, version, advisory)
    select vid, k ->> 'ecosystem', lower(k ->> 'name'), k ->> 'version', k ->> 'advisory' from jsonb_array_elements(p -> 'packages') k
    on conflict do nothing;
  -- The change cap: rows added plus rows dropped, against the active version's exact-match rows.
  select * into cur from app.wiki_versions v where v.status = 'active';
  if cur.id is not null and cur.packages >= 20 then
    select (select count(*) from (select ecosystem, name, version, advisory from app.wiki_packages where version_id = vid
                                   except select ecosystem, name, version, advisory from app.wiki_packages where version_id = cur.id) a)
         + (select count(*) from (select ecosystem, name, version, advisory from app.wiki_packages where version_id = cur.id
                                   except select ecosystem, name, version, advisory from app.wiki_packages where version_id = vid) b)
      into changed;
    if changed * 100 > cur.packages * s.max_change_pct then
      why := 'refused: ' || changed || ' of ' || cur.packages || ' exact-match rows would change (cap ' || s.max_change_pct || '%)';
      delete from app.wiki_packages where version_id = vid;
      delete from app.wiki_entries where version_id = vid;
      update app.wiki_versions v set status = 'refused', reason = why where v.id = vid;
      return 'refused';
    end if;
  end if;
  update app.wiki_versions v set status = 'kept' where v.status = 'active';
  update app.wiki_versions v set status = 'active' where v.id = vid;
  -- Keep the active version and the two before it; refused runs' records go after 30 days.
  delete from app.wiki_versions v where v.status = 'kept' and v.id not in (select x.id from app.wiki_versions x where x.status = 'kept' order by x.created_at desc, x.id desc limit 2);
  delete from app.wiki_versions v where v.status = 'refused' and v.created_at < now() - interval '30 days';
  return 'active';
end $$;

-- One step back: the newest kept version becomes active again; the one that was active is set aside as kept.
create function app.wiki_rollback() returns uuid
language plpgsql security definer set search_path = pg_catalog as $$
declare cur uuid; prev uuid;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator rolls the wiki back' using errcode = '42501'; end if;
  select v.id into cur from app.wiki_versions v where v.status = 'active';
  select v.id into prev from app.wiki_versions v where v.status = 'kept' order by v.created_at desc, v.id desc limit 1;
  if prev is null then raise exception 'work_wiki_none' using errcode = 'P0001', hint = 'There is no earlier version to go back to.'; end if;
  update app.wiki_versions v set status = 'kept', created_at = least(v.created_at, (select x.created_at from app.wiki_versions x where x.id = prev) - interval '1 second') where v.id = cur;
  update app.wiki_versions v set status = 'active' where v.id = prev;
  perform app.audit_add('wiki_rollback', 'wiki_version', prev, jsonb_build_object('from', cur));
  return prev;
end $$;

-- The wiki's state, public: versions with their counts, and the active version's entries (counts by source, KEV,
-- and the newest 50 advisories). Public information from public feeds.
create function app.wiki_summary() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object(
    'versions', coalesce((select jsonb_agg(jsonb_build_object('id', v.id, 'status', v.status, 'entries', v.entries, 'packages', v.packages,
                   'sources', v.sources, 'reason', v.reason, 'at', v.created_at) order by v.created_at desc) from app.wiki_versions v), '[]'::jsonb),
    'last_run_at', (select s.last_run_at from app.wiki_settings s where s.singleton),
    'newest', coalesce((select jsonb_agg(jsonb_build_object('ident', e.ident, 'title', e.title, 'severity', e.severity, 'cwe', e.cwe, 'kev', e.kev, 'published', e.published)
                   order by e.published desc nulls last, e.ident) from (select * from app.wiki_entries e join app.wiki_versions v on v.id = e.version_id and v.status = 'active'
                   where e.source = 'nvd' order by e.published desc nulls last, e.ident limit 50) e), '[]'::jsonb))
$$;

revoke execute on function app.wiki_claim(), app.wiki_record(text, jsonb), app.wiki_rollback(), app.wiki_summary() from public;
grant execute on function app.wiki_claim(), app.wiki_record(text, jsonb), app.wiki_rollback(), app.wiki_summary() to dog_app;
reset role;
revoke create on schema app from dog_work;
