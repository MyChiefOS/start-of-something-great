-- 083 The Agentic Wall's firewall (Aaron, Nov 25: "It needs to catch things like a firewall would"; "blocking by
--   country ... Yes North Korea"; "I want it built and operating in the software for the agentic wall").
--
--   The firewall itself runs in front of every request (middleware.js, wall/firewall.js): country (W34), web attacks
--   (W35), rate (W36), attack scanners (W37), threat-list addresses (W38). This migration publishes those rules, adds
--   Spamhaus DROP's ranges to the security wiki (free for any use with credit to Spamhaus; read at most once a day, as
--   its terms ask, and carried over on the other run), lets the Wall's content check match an address inside a range,
--   and serves the firewall its list.

set local role dog_owner;
alter table app.wiki_indicators drop constraint wiki_indicators_kind_check;
alter table app.wiki_indicators add constraint wiki_indicators_kind_check
  check (kind = any (array['ip', 'cidr', 'domain', 'url', 'sha256', 'injection', 'injection_flag']));
alter table app.wiki_indicators drop constraint wiki_indicators_source_check;
alter table app.wiki_indicators add constraint wiki_indicators_source_check
  check (source = any (array['feodo', 'spamhaus', 'urlhaus', 'threatfox', 'malwarebazaar', 'reference']));
-- A kind with no branch here would pass any value (a CASE with no match is null), so every kind has one.
alter table app.wiki_indicators drop constraint wiki_indicators_check;
alter table app.wiki_indicators add constraint wiki_indicators_check check (case kind
    when 'ip' then value ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'
    when 'cidr' then value ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])/([89]|[12][0-9]|3[0-2])$'
    when 'domain' then char_length(value) <= 253 and value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    when 'url' then value ~ '^https?://[^[:space:]"''<>]+$'
    when 'sha256' then value ~ '^[0-9a-f]{64}$'
    when 'injection' then char_length(value) <= 120 and value ~ '^[!-~]([ -~]*[!-~])?$' and value !~ '  ' and value = lower(value)
    when 'injection_flag' then char_length(value) <= 120 and value ~ '^[!-~]([ -~]*[!-~])?$' and value !~ '  ' and value = lower(value)
    else false end);

-- A range a feed may never block: one that covers a private, loopback, link-local or shared range, or a public
-- resolver (the same addresses as 082's wiki_never_block_ip), or one wider than a /8.
create function app.wiki_never_block_cidr(p_cidr text) returns boolean
language sql immutable set search_path = pg_catalog as $$
  select case when coalesce(p_cidr, '') !~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])/([89]|[12][0-9]|3[0-2])$' then true
      else exists (select 1 from unnest(array['0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
                  '100.64.0.0/10', '224.0.0.0/3', '1.1.1.1/32', '1.0.0.1/32', '8.8.8.8/32', '8.8.4.4/32', '9.9.9.9/32', '149.112.112.112/32',
                  '208.67.222.222/32', '208.67.220.220/32']::cidr[]) r where r && p_cidr::cidr) end
$$;
revoke execute on function app.wiki_never_block_cidr(text) from public;
grant execute on function app.wiki_never_block_cidr(text) to dog_work;
reset role;

-- The firewall's rules, published beside the Wall's others.
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W34', 'block', 'A request from a blocked country (North Korea)'),
  ('W35', 'block', 'A web attack in a request: SQL injection, cross-site scripting, path traversal, command injection, file inclusion, a lookup string'),
  ('W36', 'block', 'Too many requests a minute from one address (answered 429, try again in a minute; never a lockout)'),
  ('W37', 'block', 'A known attack scanner (a request with no user agent is only flagged)'),
  ('W38', 'block', 'A request from an address or range on the security wiki''s threat lists (Spamhaus DROP, Feodo Tracker)');
alter table app.wall_rules enable row level security;

set local role dog_owner;
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
    select 'W28', i.kind, i.value, i.source, i.ref from ips join app.wiki_indicators i on i.version_id = vid and i.kind = 'cidr' and ips.ip::inet <<= i.value::cidr
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
       and not (i ->> 'kind' = 'cidr' and app.wiki_never_block_cidr(i ->> 'value'))
       and not (i ->> 'kind' = 'ip' and app.wiki_never_block_ip(i ->> 'value'))
       and not (i ->> 'kind' = 'url' and app.wiki_never_block(substring(lower(i ->> 'value') from '^https?://(?:[^@/]*@)?([^/:?#]+)')) and substring(lower(i ->> 'value') from '^https?://[^/]+(/[^?#]*)?') in ('', '/'))
    on conflict do nothing;
  -- 083: a source read once a day (Spamhaus asks for no more) is carried over from the active version on the other run.
  if jsonb_typeof(p -> 'carry') = 'array' then
    insert into app.wiki_indicators (version_id, kind, value, source, ref)
      select vid, x.kind, x.value, x.source, x.ref from app.wiki_indicators x join app.wiki_versions v on v.id = x.version_id and v.status = 'active'
       where x.source in (select jsonb_array_elements_text(p -> 'carry')) and x.source = any (array['spamhaus'])
      on conflict do nothing;
  end if;
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

-- 083: the firewall's threat addresses (single addresses and ranges) from the active wiki version, public: they come
-- from public feeds. The firewall in front of the site (middleware.js) reads them through /api/work/wall_edge.
create function app.wall_edge_addresses() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object('version', (select v.id from app.wiki_versions v where v.status = 'active'),
    'addresses', coalesce((select jsonb_agg(i.value order by i.value) from app.wiki_indicators i join app.wiki_versions v on v.id = i.version_id and v.status = 'active'
                            where i.kind in ('ip', 'cidr')), '[]'::jsonb))
$$;
revoke execute on function app.wall_edge_addresses() from public;
grant execute on function app.wall_edge_addresses() to dog_app;
reset role;
revoke create on schema app from dog_work;

alter table app.wall_settings disable row level security;
update app.wall_settings set rules_version = rules_version + 1;
alter table app.wall_settings enable row level security;
