-- 090 The AI Gateway check (Aaron, Nov 26: "Try the openai model ... to see if a call works"). Since 088 three reviewer
--   models (Claude Haiku 5.5, DeepSeek V3.2, Claude Fable 5.2) get "gateway 403" on every call, while Qwen and Mistral
--   answer, with the same token and request. Only the deployed site holds the identity token the gateway accepts, so the
--   site checks for itself: once a day the timer sends one tiny request to each model the reviewers use, plus OpenAI's
--   GPT-5 mini and GPT-5.5, and the administrators get one alert listing each model's answer (the status and the
--   gateway's own error message, up to 200 characters; never a token). Alerts only; nothing is switched on or off.
--   Also: the wiki's health check (088) read each feed's count from this run's sources, so a feed carried over from the
--   last version (Spamhaus is read only before noon UTC) showed as "empty" though the Wall still holds its entries. It now
--   counts the entries the active version actually holds.

reset role;
alter table app.oversight_settings add column gateway_checked_on date;

grant create on schema app to dog_work;
set local role dog_work;

-- Claim today's check: the models to try, once a UTC day.
create function app.gateway_check_claim() returns text[]
language plpgsql security definer set search_path = pg_catalog as $$
declare
  today date := (now() at time zone 'UTC')::date;
  ms text[];
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer checks the gateway' using errcode = '42501';
  end if;
  update app.oversight_settings s set gateway_checked_on = today
   where s.singleton and (s.gateway_checked_on is null or s.gateway_checked_on < today);
  if not found then return null; end if;
  select array_agg(distinct m order by m) into ms from (
    select r.model as m from app.oversight_roles r
    union select 'openai/gpt-5-mini' union select 'openai/gpt-5.5') x;
  return ms;
end $$;
revoke execute on function app.gateway_check_claim() from public;
grant execute on function app.gateway_check_claim() to dog_app;

-- Record today's answers: [{model, status, message}], one alert to the administrators.
create function app.gateway_check_record(p_results jsonb) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
declare
  body text;
  bad integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer checks the gateway' using errcode = '42501';
  end if;
  if p_results is null or jsonb_typeof(p_results) <> 'array' or jsonb_array_length(p_results) > 20 then return false; end if;
  select string_agg(left(coalesce(e ->> 'model', '?'), 80) || ': ' || left(coalesce(e ->> 'status', '?'), 10)
           || case when coalesce(e ->> 'message', '') <> '' then ' (' || left(e ->> 'message', 200) || ')' else '' end, E'\n'
           order by e ->> 'model'),
         count(*) filter (where coalesce(e ->> 'status', '') <> '200')
    into body, bad from jsonb_array_elements(p_results) e;
  perform app.notify(null, 'alert', left('AI Gateway check: ' || bad || ' of ' || jsonb_array_length(p_results) || ' models refused', 120),
    left('One small test request to each model, from the site''s own identity. ' || E'\n' || coalesce(body, ''), 2000),
    '/admin', null, null, 'gateway-check:' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
  return true;
end $$;
revoke execute on function app.gateway_check_record(jsonb) from public;
grant execute on function app.gateway_check_record(jsonb) to dog_app;

-- The wiki's health check, as 088's, with "empty" read from the entries the active version holds.
CREATE OR REPLACE FUNCTION app.wiki_health_check() returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare
  v record;
  last_good timestamptz;
  probs jsonb := '[]'::jsonb;
  k text;
  day text := to_char(now() at time zone 'UTC', 'YYYY-MM-DD');
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer checks the wiki' using errcode = '42501';
  end if;
  select max(x.created_at) into last_good from app.wiki_versions x where x.status in ('active', 'kept');
  select * into v from app.wiki_versions x where x.status = 'active';
  if last_good is null or last_good < now() - interval '24 hours' then
    probs := probs || jsonb_build_array('stale: no good run since ' || coalesce(to_char(last_good at time zone 'UTC', 'YYYY-MM-DD HH24:MI'), 'ever') || ' UTC');
  end if;
  if v.id is not null then
    -- 090: the threat feeds by what the Wall holds (a feed carried over from the last version is not empty); the CVE
    -- sources by this run's count, as they are read every run.
    foreach k in array array['feodo', 'spamhaus', 'certpl', 'phishtank', 'et', 'cins', 'eset'] loop
      if v.sources ? k and not exists (select 1 from app.wiki_indicators i where i.version_id = v.id and i.source = k) then
        probs := probs || jsonb_build_array('empty: ' || k);
      end if;
    end loop;
    foreach k in array array['nvd', 'kev'] loop
      if v.sources ? k and (v.sources ->> k) ~ '^[0-9]+$' and (v.sources ->> k)::bigint = 0 then
        probs := probs || jsonb_build_array('empty: ' || k);
      end if;
    end loop;
    for k in select e.key from jsonb_each_text(coalesce(v.sources -> 'newest', '{}'::jsonb)) e
             where e.value ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' and left(e.value, 10)::date < (now() at time zone 'UTC')::date - 7 loop
      probs := probs || jsonb_build_array('old: ' || k || ' newest entry ' || left(v.sources -> 'newest' ->> k, 10));
    end loop;
  end if;
  for k in select jsonb_array_elements_text(probs) loop
    perform app.notify(null, 'alert', left('Security wiki: ' || k, 120),
      'The security wiki''s health check found this. The Wall keeps using the last good copy; the next run tries again.',
      '/checks', null, null, 'wiki-health:' || split_part(k, ':', 1) || ':' || md5(k) || ':' || day);
  end loop;
  return jsonb_build_object('problems', probs, 'last_good', last_good);
end $$;

reset role;
revoke create on schema app from dog_work;
