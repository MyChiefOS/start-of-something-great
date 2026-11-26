-- 088 The Wall's operations (Aaron, Nov 26, with passcode 3213: "execute the attached" plan, Phase 0 and Phase 1; "Pay-As-
--   You-Go Billing: Configure all paid services, components, and reviewers on a pay-as-you-go basis for now. Remove or
--   bypass any monthly cap blockers"):
--     the model reviewers on, pay-as-you-go: the monthly cap is gone (null), each role's daily call cap stays as the
--       brake on a runaway loop;
--     the AI classifier (phishing and prompt injection) reads each new post; a concern goes to the review queue (W48);
--     every pull request in review is scanned again after new commits, at most every 20 minutes (scan at submission);
--     ClamAV antivirus (W46) and the sandbox (W47) results are accepted from the facts workflow;
--     the YARA pack is pinned by the wiki (release and SHA-256), served with the firewall's list;
--     the wiki's health: an alert when it has gone 24 hours without a good run, when a feed came back empty, and when
--       a feed's own newest entry is more than 7 days old (Feodo Tracker's has been, since March 4).

reset role;
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W46', 'block', 'A file the ClamAV antivirus engine identifies as malware'),
  ('W46b', 'flag', 'The antivirus check could not run on a file'),
  ('W47', 'block', 'A file that, run in the sandbox (no network, no lasting disk), tried to reach the network, start a shell or plant itself'),
  ('W47b', 'flag', 'A sandbox run that did something unusual, or could not run'),
  ('W48', 'flag', 'The AI classifier read a post as phishing or prompt injection: it goes to the review queue'),
  ('W49', 'flag', 'A link that was clean when posted but is on a threat list when someone clicks it: the click is stopped with a warning');
update app.wall_rules set what = 'A malware signature that matched files in 3 or more pull requests or 10 or more files in one run, or a signature check that could not run' where rule = 'W42b';
alter table app.wall_rules enable row level security;

set local role dog_owner;
-- Pay-as-you-go: no monthly cap. A null cap means no monthly limit; 0 still means no model call at all.
alter table app.oversight_settings alter column monthly_cap_cents drop not null;
comment on column app.oversight_settings.monthly_cap_cents is 'US cents a month for every model role together. Null: pay-as-you-go, no monthly limit (Aaron, Nov 26); each role''s daily_call_cap still applies. 0: no model call at all.';

-- The AI classifier is a model role like the reviewers, reading posts instead of submissions.
alter table app.oversight_roles drop constraint oversight_roles_role_check;
alter table app.oversight_roles add constraint oversight_roles_role_check
  check (role = any (array['exploit_researcher', 'penetration_tester', 'quality_assurance', 'solution_architect', 'fable_report', 'fable_crosscheck', 'classifier']));
alter table app.oversight_calls drop constraint oversight_calls_role_check;
alter table app.oversight_calls add constraint oversight_calls_role_check
  check (role = any (array['exploit_researcher', 'penetration_tester', 'quality_assurance', 'solution_architect', 'fable_report', 'fable_crosscheck', 'classifier']));
alter table app.oversight_calls add column post_id uuid references app.posts (id) on delete cascade;
alter table app.oversight_calls add constraint oversight_calls_one_subject check (num_nonnulls(submission_id, post_id) <= 1);
create index oversight_calls_post on app.oversight_calls (post_id, role) where post_id is not null;

-- The classifier's concern on a post goes to the review queue, as the other classifiers' do.
grant insert (post_id, source, classifier, score) on app.review_flags to dog_work;
grant select (id, post_id, source, classifier, resolved_at) on app.review_flags to dog_work;
create policy review_flags_work_insert on app.review_flags for insert to dog_work
  with check (source = 'classifier' and classifier = 'ai' and reporter_id is null);
create policy review_flags_work_select on app.review_flags for select to dog_work using (source = 'classifier' and classifier = 'ai');
-- The flag's own audit record (004's trigger writes it as the inserting role): only that, as the timer.
create policy audit_insert_classifier on app.audit_log for insert to dog_work
  with check (action = 'review.flag' and actor_kind = (select app.actor_kind()) and actor_id is not distinct from (select app.current_actor_id()));
grant insert (action, subject_kind, subject_id, detail) on app.audit_log to dog_work;
grant select (id, body, status, created_at) on app.posts to dog_work;
do $p$ begin
  if not exists (select 1 from pg_policies where schemaname = 'app' and tablename = 'posts' and policyname = 'posts_work_select') then
    create policy posts_work_select on app.posts for select to dog_work using (true);
  end if;
end $p$;

-- Click-time link checks (Aaron, Nov 25: "check links again when someone clicks them"; plan Phase 1 item 5): the
-- link is read against the security wiki's threat lists at the moment of the click, not when it was posted. Blocking
-- lists stop the click with a warning (W49); score-only lists warn and let the person go on.
create function app.wall_link_check(p_url text) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  u text := left(coalesce(p_url, ''), 2000);
  f jsonb;
begin
  if u !~* '^https?://[^[:space:]/?#]+' then return jsonb_build_object('verdict', 'bad', 'why', 'Only web links (http or https) can be followed.'); end if;
  f := app.wall_intel_flags(u, null);
  if exists (select 1 from jsonb_array_elements_text(f) x where split_part(x, ' ', 1) = 'W28') then
    return jsonb_build_object('verdict', 'blocked', 'why', 'This link is on a threat list the security wiki reads (malware or phishing). It may have been clean when it was posted.');
  elsif exists (select 1 from jsonb_array_elements_text(f) x where split_part(x, ' ', 1) = 'W28b') then
    return jsonb_build_object('verdict', 'warn', 'why', 'This link''s address is on a score-only threat list: often harmless, sometimes not.');
  end if;
  return jsonb_build_object('verdict', 'ok');
end $$;
revoke execute on function app.wall_link_check(text) from public;
grant execute on function app.wall_link_check(text) to dog_app;

reset role;
-- Rows in the oversight tables, as the migration's owner (their row policies admit only dog_work), as 077 did.
alter table app.oversight_roles disable row level security;
alter table app.oversight_settings disable row level security;
update app.oversight_settings set monthly_cap_cents = null where singleton;
insert into app.oversight_roles (role, model, call_price_centi_cents, mode, daily_call_cap)
  values ('classifier', 'anthropic/claude-haiku-5.5', 4, 'on', 500);
update app.oversight_roles set mode = 'on' where role = any (array['exploit_researcher', 'penetration_tester', 'quality_assurance', 'solution_architect']);
alter table app.oversight_roles enable row level security;
alter table app.oversight_settings enable row level security;
grant create on schema app to dog_work;
set local role dog_work;

-- The timer asks for work for one model role. Nothing when the role is off, a cap of $0 is set, the month's cap is
-- reached (when there is one: null is pay-as-you-go), or the day's calls are used. Returns the items and books each.
create or replace function app.oversight_claim(p_role text, p_n integer) returns table (submission_id uuid, model text)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  r record;
  spent bigint;
  today integer;
  k integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the model reviewers' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 3 then raise exception 'bad claim' using errcode = '22023'; end if;
  select * into s from app.oversight_settings x where x.singleton;
  select * into r from app.oversight_roles x where x.role = p_role for update;
  if r.id is null or r.mode = 'off' or s.monthly_cap_cents = 0 or r.role in ('fable_report', 'fable_crosscheck', 'classifier') then return; end if;
  select count(*) into today from app.oversight_calls c where c.role = p_role and c.created_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  k := least(p_n, r.daily_call_cap - today);
  if s.monthly_cap_cents is not null then
    select coalesce(sum(c.centi_cents), 0) into spent from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC';
    k := least(k, ((s.monthly_cap_cents::bigint * 100 - spent) / r.call_price_centi_cents)::integer);
  end if;
  if k < 1 then return; end if;
  return query
    with picked as (
      select x.id from app.work_submissions x
       where x.status in ('waiting', 'review', 'passed') and x.created_at > now() - interval '2 days'
         and not exists (select 1 from app.oversight_calls c where c.submission_id = x.id and c.role = p_role)
       order by x.created_at limit k),
    booked as (insert into app.oversight_calls (role, submission_id, model, centi_cents, error)
               select p_role, picked.id, r.model, r.call_price_centi_cents, 'pending' from picked returning oversight_calls.submission_id)
    select b.submission_id, r.model from booked b;
end $$;

-- The AI classifier (Aaron, Nov 25: "AI classifiers for phishing and injection ... turn it on"): the newest posts not
-- yet read, at most p_n a call, under the same caps as the reviewers. Returns each post's text with its booking.
create function app.oversight_classify_claim(p_n integer) returns table (post_id uuid, model text, body text)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  r record;
  spent bigint;
  today integer;
  k integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the classifier' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 10 then raise exception 'bad claim' using errcode = '22023'; end if;
  select * into s from app.oversight_settings x where x.singleton;
  select * into r from app.oversight_roles x where x.role = 'classifier' for update;
  if r.id is null or r.mode = 'off' or s.monthly_cap_cents = 0 then return; end if;
  select count(*) into today from app.oversight_calls c where c.role = 'classifier' and c.created_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  k := least(p_n, r.daily_call_cap - today);
  if s.monthly_cap_cents is not null then
    select coalesce(sum(c.centi_cents), 0) into spent from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC';
    k := least(k, ((s.monthly_cap_cents::bigint * 100 - spent) / r.call_price_centi_cents)::integer);
  end if;
  if k < 1 then return; end if;
  return query
    with picked as (
      select p.id, p.body from app.posts p
       where p.status <> 'removed' and p.created_at > now() - interval '1 day'
         and not exists (select 1 from app.oversight_calls c where c.post_id = p.id and c.role = 'classifier')
       order by p.created_at limit k),
    booked as (insert into app.oversight_calls (role, post_id, model, centi_cents, error)
               select 'classifier', picked.id, r.model, r.call_price_centi_cents, 'pending' from picked returning oversight_calls.post_id)
    select b.post_id, r.model, (select picked.body from picked where picked.id = b.post_id) from booked b;
end $$;

-- The classifier's answer for one post. A concern is a flag for the review queue (W48); advisory, the post stays as
-- it is until a person decides.
create function app.oversight_classify_record(p_post uuid, p_verdict text, p_reason text, p_error text) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records the classifier' using errcode = '42501';
  end if;
  if p_verdict is not null and p_verdict <> all (array['ok', 'concern']) then raise exception 'bad verdict' using errcode = '22023'; end if;
  update app.oversight_calls c set verdict = case when p_error is null then p_verdict end, reason = left(p_reason, 300), error = left(p_error, 40)
   where c.role = 'classifier' and c.post_id = p_post and c.error = 'pending';
  if not found then return false; end if;
  if p_error is null and p_verdict = 'concern'
     and not exists (select 1 from app.review_flags f where f.post_id = p_post and f.source = 'classifier' and f.classifier = 'ai' and f.resolved_at is null) then
    -- The flag carries no words (only reports do); the classifier's reason stays with its call, for the reviewers.
    insert into app.review_flags (post_id, source, classifier, score) values (p_post, 'classifier', 'ai', 0.9);
  end if;
  return true;
end $$;
revoke execute on function app.oversight_classify_claim(integer), app.oversight_classify_record(uuid, text, text, text) from public;
grant execute on function app.oversight_classify_claim(integer), app.oversight_classify_record(uuid, text, text, text) to dog_app;

-- Scan at submission (Aaron's plan, Phase 1 item 2): every pull request submitted for work is read as soon as a run
-- of the facts workflow sees it (each push to a pull request starts one), not only once merged for Third Look; one not
-- yet decided is read again once its last reading is 20 minutes old, so new commits are scanned too. Up to 5 a run,
-- those never read first.
create or replace function app.tl_files_wanted(p_n integer)
returns table (number integer)
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function reads this (dog_ghsync)' using errcode = '42501';
  end if;
  return query select x.pr_number from app.work_submissions x
    left join app.tl_files f on f.number = x.pr_number
    where x.artifact_kind = 'pr' and x.pr_number is not null and x.status in ('waiting', 'review', 'passed')
      and (f.id is null or (x.status in ('waiting', 'review') and f.read_at < now() - interval '20 minutes'))
      -- Third Look's merged pull requests, as before (tl_wants), and (088) every pull request submitted for work and not
      -- yet decided, so the Wall scans it when it arrives.
      and (app.tl_wants(x.pr_number) or x.status in ('waiting', 'review'))
    group by x.pr_number order by bool_or(f.id is null) desc, min(x.created_at), x.pr_number limit least(greatest(coalesce(p_n, 1), 1), 5);
end
$$;

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
                                      or split_part(g #>> '{}', ' ', 1) <> all (array['W25', 'W25b', 'W30', 'W31', 'W39', 'W40', 'W40b', 'W41', 'W42', 'W42b', 'W46', 'W46b', 'W47', 'W47b']))))
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


-- The firewall's list, with the YARA pack the wiki pinned (088): its release and SHA-256, for the facts workflow.
create or replace function app.wall_edge_addresses() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object('version', (select v.id from app.wiki_versions v where v.status = 'active'),
    'firewall_since', (select w.firewall_since from app.wall_settings w where w.singleton),
    'yara', (select v.sources -> 'yara' from app.wiki_versions v where v.status = 'active'),
    'addresses', coalesce((select jsonb_agg(i.value order by i.value) from app.wiki_indicators i join app.wiki_versions v on v.id = i.version_id and v.status = 'active'
                            where i.kind in ('ip', 'cidr', 'cidr6') and i.source <> all (array['cins', 'et'])), '[]'::jsonb))
$$;

-- The wiki's health, from the site's timer: alerts (in-app, to the administrators, once a day each) when the wiki has
-- had no good run in 24 hours, when a feed came back empty, or when a feed's own newest entry is more than 7 days old.
-- Returns what it found. Alerts only: nothing stops.
create function app.wiki_health_check() returns jsonb
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
    foreach k in array array['feodo', 'spamhaus', 'certpl', 'phishtank', 'et', 'cins', 'eset', 'nvd', 'kev'] loop
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
revoke execute on function app.wiki_health_check() from public;
grant execute on function app.wiki_health_check() to dog_app;

reset role;
revoke create on schema app from dog_work;

