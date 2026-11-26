-- 086 The Agentic Wall's threat feeds, round two (Aaron, Nov 26: "Lets implement your recommendations", after Fable's
--   search for free sources needing no account and allowing commercial use). Blocking sources are national CERTs and
--   security vendors; a source anyone can be listed in by mistake only scores (flags):
--     CERT Polska's warning list (phishing domains)       block   "may be used by any user for any purpose"
--     PhishTank verified online URLs (Cisco Talos)        block   commercial use OK (FAQ); read once a day
--     Emerging Threats Open compromised and block IPs     block   BSD (Proofpoint), with credit
--     ESET malware-ioc file fingerprints                  block   BSD-2-Clause, with credit; read once a day
--     CINS Army bad IPs                                   flag    "use in any way you see fit"; addresses get reassigned
--     OSV.dev npm advisories and malicious packages       block a malicious package (W25), flag a vulnerable one (W25b)
--   OSV is asked about the packages a pull request adds (in the facts workflow), so version ranges count, not only
--   exact versions (Claude's own narrowing in 074, undone).

reset role;
set local role dog_owner;
alter table app.wiki_indicators drop constraint wiki_indicators_source_check;
alter table app.wiki_indicators add constraint wiki_indicators_source_check
  check (source = any (array['feodo', 'spamhaus', 'certpl', 'phishtank', 'et', 'cins', 'eset', 'urlhaus', 'threatfox', 'malwarebazaar', 'reference']));
alter table app.wiki_versions drop constraint wiki_versions_indicators_check;
alter table app.wiki_versions add constraint wiki_versions_indicators_check check (indicators between 0 and 400000);
create or replace function app.wall_intel_flags(p_text text, p_path text default null) returns jsonb
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
                     from (select (regexp_matches(n, '(?:^|[^0-9.])([0-9]{8,10})(?:$|[^0-9.])', 'g'))[1]::bigint as x) z where x between 16777216 and 4294967295) w
                  where ip ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'),
         shas as (select distinct (regexp_matches(n, '\m([0-9a-f]{64})\M', 'g'))[1] as s)
    select 'W28' as rule, i.kind, i.value, i.source, i.ref from urls join app.wiki_indicators i on i.version_id = vid and i.kind = 'url' and i.value = urls.u
    union all
    select 'W28', i.kind, i.value, i.source, i.ref from suffixes join app.wiki_indicators i on i.version_id = vid and i.kind = 'domain' and i.value = suffixes.d
    union all
    select 'W28', i.kind, i.value, i.source, i.ref from ips join app.wiki_indicators i on i.version_id = vid and i.kind = 'ip' and i.value = ips.ip
    union all
    -- 083: a range from Spamhaus DROP (about 1,700 ranges; a containment test per address).
    select 'W28', i.kind, i.value, i.source, i.ref from ips join app.wiki_indicators i on i.version_id = vid and i.kind = 'cidr' and ips.ip::inet <<= i.value::inet
    union all
    select 'W33', i.kind, i.value, i.source, i.ref from shas join app.wiki_indicators i on i.version_id = vid and i.kind = 'sha256' and i.value = shas.s
    union all
    select case when i.kind = 'injection' and not test_path then 'W29' else 'W29b' end, i.kind, i.value, i.source, i.ref
      from app.wiki_indicators i where i.version_id = vid and i.kind in ('injection', 'injection_flag') and strpos(n, i.value) > 0
    limit 20
  loop
    -- 086: a score-only source (CINS Army: IP addresses get reassigned and shared) is flagged, never blocked.
    if hit.rule = 'W28' and hit.source = any (array['cins']) then hit.rule := 'W28b'; end if;
    f := f || jsonb_build_array(hit.rule || case hit.rule when 'W33' then ' known-bad file fingerprint' when 'W29' then ' injection pattern' when 'W29b' then ' injection phrase' else ' known-bad ' || hit.kind end
           || ' (security wiki, ' || hit.source || coalesce(' ' || hit.ref, '') || '): ' || left(hit.value, 100));
  end loop;
  return f;
end $$;
revoke execute on function app.wall_intel_flags(text, text) from public;
reset role;

alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W25b', 'flag', 'A dependency at a version with a known vulnerability (OSV.dev; a malicious package is W25 and blocks)'),
  ('W28b', 'flag', 'An address on a score-only threat list (CINS Army): flagged, never blocked, since addresses get reassigned');
update app.wall_rules set what = 'A dependency that is a known malicious package (OSV.dev, OpenSSF), or pinned to a version the security wiki names in an advisory' where rule = 'W25';
update app.wall_rules set what = 'A known-bad IP address, domain or URL from the security wiki''s threat feeds (Spamhaus DROP, Feodo Tracker, CERT Polska, PhishTank, Emerging Threats)' where rule = 'W28';
update app.wall_rules set what = 'A request from an address or range on the security wiki''s blocking threat lists (Spamhaus DROP, Feodo Tracker, Emerging Threats)' where rule = 'W38';
update app.wall_rules set what = 'A file fingerprint on the security wiki''s known-bad list (ESET)' where rule = 'W33';
alter table app.wall_rules enable row level security;

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
     or jsonb_typeof(coalesce(p -> 'indicator_groups', '[]'::jsonb)) <> 'array'
     or jsonb_typeof(coalesce(p -> 'sources', '{}'::jsonb)) <> 'object' or octet_length(p::text) > 40000000 then
    raise exception 'bad wiki run' using errcode = '22023';
  end if;
  ne := jsonb_array_length(p -> 'entries');
  np := jsonb_array_length(p -> 'packages');
  -- 086: indicators also come in groups (one kind and source, many values), which keeps a run of 200,000 small.
  ni := jsonb_array_length(coalesce(p -> 'indicators', '[]'::jsonb))
      + coalesce((select sum(jsonb_array_length(g -> 'values')) from jsonb_array_elements(coalesce(p -> 'indicator_groups', '[]'::jsonb)) g
                   where jsonb_typeof(g -> 'values') = 'array'), 0);
  if ne > 20000 or np > 20000 or ni > 400000 then raise exception 'bad wiki run' using errcode = '22023'; end if;
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
       and not (i ->> 'kind' = 'cidr' and app.wiki_never_block_cidr(i ->> 'value'))
       and not (i ->> 'kind' = 'ip' and app.wiki_never_block_ip(i ->> 'value'))
       and not (i ->> 'kind' = 'url' and app.wiki_never_block(substring(lower(i ->> 'value') from '^https?://(?:[^@/]*@)?([^/:?#]+)')) and substring(lower(i ->> 'value') from '^https?://[^/]+(/[^?#]*)?') in ('', '/'))
    on conflict do nothing;
  -- 083: a source read once a day (Spamhaus asks for no more) is carried over from the active version on the other run.
  if jsonb_typeof(p -> 'carry') = 'array' then
    insert into app.wiki_indicators (version_id, kind, value, source, ref)
      select vid, x.kind, x.value, x.source, x.ref from app.wiki_indicators x join app.wiki_versions v on v.id = x.version_id and v.status = 'active'
       where x.source in (select jsonb_array_elements_text(p -> 'carry')) and x.source = any (array['spamhaus', 'phishtank', 'eset'])
      on conflict do nothing;
  end if;
  insert into app.wiki_indicators (version_id, kind, value, source, ref)
    select vid, g ->> 'kind', case when g ->> 'kind' = 'url' then app.wall_url_norm(x) else lower(x) end, g ->> 'source', left(g ->> 'ref', 60)
      from jsonb_array_elements(coalesce(p -> 'indicator_groups', '[]'::jsonb)) g, jsonb_array_elements_text(g -> 'values') x
     where jsonb_typeof(g -> 'values') = 'array'
       and not (g ->> 'kind' = 'domain' and (app.wiki_never_block(x) or app.wiki_public_suffix(x)))
       and not (g ->> 'kind' = 'cidr' and app.wiki_never_block_cidr(x))
       and not (g ->> 'kind' = 'ip' and app.wiki_never_block_ip(x))
       and not (g ->> 'kind' = 'url' and app.wiki_never_block(substring(lower(x) from '^https?://(?:[^@/]*@)?([^/:?#]+)')) and substring(lower(x) from '^https?://[^/]+(/[^?#]*)?') in ('', '/'))
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
    -- 083 review: a source the active version doesn't have yet (a new feed's first run) isn't counted as change.
    select (select count(*) from (select kind, value from app.wiki_indicators where version_id = vid
                                    and source in (select distinct y.source from app.wiki_indicators y where y.version_id = cur.id)
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
create or replace function app.wall_edge_addresses() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object('version', (select v.id from app.wiki_versions v where v.status = 'active'),
    'firewall_since', (select w.firewall_since from app.wall_settings w where w.singleton),
    'addresses', coalesce((select jsonb_agg(i.value order by i.value) from app.wiki_indicators i join app.wiki_versions v on v.id = i.version_id and v.status = 'active'
                            where i.kind in ('ip', 'cidr') and i.source <> all (array['cins'])), '[]'::jsonb))
$$;
revoke execute on function app.wall_edge_addresses() from public;
grant execute on function app.wall_edge_addresses() to dog_app;
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
                                      or split_part(g #>> '{}', ' ', 1) <> all (array['W25', 'W25b', 'W30', 'W31', 'W39', 'W40', 'W40b', 'W41', 'W42', 'W42b']))))
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
