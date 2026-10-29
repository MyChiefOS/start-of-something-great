-- 030 The JEVs behaviour watch, part 2: the web indicators from Aaron's list (Oct 28) that 026 didn't build (Aaron,
--   Oct 29: "Yes, we need the not built but web centric focused use latest research"). Like 026 it alerts Aaron in his
--   inbox and never blocks, refuses or signs anyone out (his rule: checks alert, never lock out). What it adds:
--     1. A session that moves: a signed-in session used from another kind of browser (its name and system, such as
--        "Firefox on Windows"), or from another country, than it was first used from. A copied session cookie is the
--        usual cause (the session-hijacking rule in common web detection: a session's browser or network changing).
--     2. Travel too fast to be possible: two places one account was used from, further apart than travel_min_km and
--        reached faster than travel_kmh. The place is the host's estimate of the network's location, rounded to about
--        100 km, sealed by the site with a key derived from the first fingerprint key (never stored readable; whoever
--        can read that key in the project's Vault could read it), not used after a day and cleared within the hour.
--     3. Activity at an unusual hour: once an account has a long history (hours_min_active active hours, over 21 days),
--        activity in an hour of the day (UTC) when it has never been active, nor in the hours either side.
--     4. Unusually many requests: an account's requests in one hour past requests_floor and requests_multiplier times
--        its usual hour of use over the last 7 days (scraping or a script using the account); once a day.
--     5. Many removals by one account: removals_per_hour posts removed, members banned, levels set, agents revoked or
--        brakes switched off by one account in an hour (mass deletion, or a taken-over administrator account).
--     6. Safety controls changing: a member made administrator, a JEVs setting changed, the brake for everyone switched
--        off, or a behaviour watch or sub-agent limit changed.
--     7. A sign-in after wrong tries: the right key file after wrong_files_before or more wrong ones for the username.
--   Not built here (harness/PLAN.md, FACTS.md Oct 29): Tor and datacenter networks (Vercel's headers carry no network
--   type, so it needs a public list fetched every day: a new moving part, queued for the next watch PR); switching
--   networks within one country (phones change address all the time, so it would alert on most members; far moves show
--   as a country change or travel, and 026 watches new networks for the administrator); requests made with agent keys
--   (not counted: 030 watches signed-in sessions; agents' actions are, by 011's hourly check, not their reads); what happens on a person's own
--   computer (USB, cloud storage, archiving, other software), which a website can't see; and patterns before someone
--   leaves, beyond what the request and removal alerts show (deleting an account removes the alerts about it).
--   What it keeps, all deleted with the account: per session, keyed hashes of its browser kind and first country
--   (deleted when the session ends or runs out); per account, the sealed place of its latest activity (at most a day), a count of the
--   hours of the day it has been active in (halved as it grows, deleted after 90 days without activity), and how many
--   requests and removals it made each hour (8 days). Keyed with the first fingerprint key, as in 026: never a browser
--   string, a country, a place or an address in readable form. Alerts name the session or member, never a hash.
set local role dog_owner;

-- The thresholds, changed only by a reviewed migration (6 alerts when they are).
alter table app.watch_settings
  add column travel_kmh integer not null default 1000 check (travel_kmh between 100 and 100000),
  add column travel_min_km integer not null default 1000 check (travel_min_km between 100 and 20000),
  add column hours_min_active integer not null default 100 check (hours_min_active between 10 and 10000),
  add column requests_floor integer not null default 300 check (requests_floor between 10 and 1000000),
  add column requests_multiplier integer not null default 10 check (requests_multiplier between 2 and 1000),
  add column removals_per_hour integer not null default 10 check (removals_per_hour between 2 and 10000),
  add column wrong_files_before integer not null default 3 check (wrong_files_before between 1 and 9);

-- 1: each session's browser kind and first country, as keyed hashes; when its place was last compared (2).
create table app.watch_sessions (
  id uuid primary key default app.uuid_v7(),
  session_id uuid not null unique references app.sessions (id) on delete cascade,
  ua_hash text check (char_length(ua_hash) = 64 and ua_hash ~ '^[0-9a-f]+$'),
  country_hash text check (char_length(country_hash) = 64 and country_hash ~ '^[0-9a-f]+$'),
  place_checked_at timestamptz,
  created_at timestamptz not null default now()
);

-- 2: each account's latest place (sealed by the site: AES-256-GCM, base64url), and when its active hours were last
-- counted (3).
create table app.watch_activity (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null unique references app.members (id) on delete cascade,
  place text check (char_length(place) between 40 and 200 and place ~ '^[A-Za-z0-9_-]+$'),
  place_at timestamptz,
  counted_hour timestamptz,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  check ((place is null) = (place_at is null))
);
create index watch_activity_last on app.watch_activity (last_seen);
create index watch_activity_place on app.watch_activity (place_at) where place_at is not null;

-- 3: for each account, how many hours it has been active in, by hour of the day (UTC). Goes with its activity row.
create table app.watch_hours (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.watch_activity (member_id) on delete cascade,
  hour smallint not null check (hour between 0 and 23),
  n integer not null default 1 check (n >= 1),
  unique (member_id, hour)
);

-- 4 and 5: per account and hour, how many requests and removals it made.
create table app.watch_counts (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id) on delete cascade,
  kind text not null check (kind = any (array['requests', 'post.remove', 'member.ban', 'member.level_set', 'agent.revoke', 'brake.off'])),
  hour timestamptz not null,
  n integer not null default 1 check (n >= 1),
  unique (member_id, kind, hour)
);
create index watch_counts_hour on app.watch_counts (hour);

-- The audit trigger (6) checks that a brake for everyone really is off before it alerts: the sign-in role may read
-- which brake is which and whether it is off, nothing else.
create policy brakes_signin_select on app.brakes for select to dog_signin using (true);
grant select (id, member_id, lifted_at) on app.brakes to dog_signin;

-- Only the sign-in role touches them, inside the watch's functions. One policy per action, as in 026.
alter table app.watch_sessions enable row level security;
alter table app.watch_sessions force row level security;
alter table app.watch_activity enable row level security;
alter table app.watch_activity force row level security;
alter table app.watch_hours enable row level security;
alter table app.watch_hours force row level security;
alter table app.watch_counts enable row level security;
alter table app.watch_counts force row level security;
create policy watch_sessions_signin_select on app.watch_sessions for select to dog_signin using (true);
create policy watch_sessions_signin_insert on app.watch_sessions for insert to dog_signin with check (true);
create policy watch_sessions_signin_update on app.watch_sessions for update to dog_signin using (true) with check (true);
create policy watch_sessions_signin_delete on app.watch_sessions for delete to dog_signin using (true);
create policy watch_activity_signin_select on app.watch_activity for select to dog_signin using (true);
create policy watch_activity_signin_insert on app.watch_activity for insert to dog_signin with check (true);
create policy watch_activity_signin_update on app.watch_activity for update to dog_signin using (true) with check (true);
create policy watch_activity_signin_delete on app.watch_activity for delete to dog_signin using (true);
create policy watch_hours_signin_select on app.watch_hours for select to dog_signin using (true);
create policy watch_hours_signin_insert on app.watch_hours for insert to dog_signin with check (true);
create policy watch_hours_signin_update on app.watch_hours for update to dog_signin using (true) with check (true);
create policy watch_hours_signin_delete on app.watch_hours for delete to dog_signin using (true);
create policy watch_counts_signin_select on app.watch_counts for select to dog_signin using (true);
create policy watch_counts_signin_insert on app.watch_counts for insert to dog_signin with check (true);
create policy watch_counts_signin_update on app.watch_counts for update to dog_signin using (true) with check (true);
create policy watch_counts_signin_delete on app.watch_counts for delete to dog_signin using (true);
grant select on app.watch_sessions, app.watch_activity, app.watch_hours, app.watch_counts to dog_signin;
grant insert (session_id, ua_hash, country_hash) on app.watch_sessions to dog_signin;
grant update (country_hash, place_checked_at) on app.watch_sessions to dog_signin;
grant delete on app.watch_sessions to dog_signin;
grant insert (member_id) on app.watch_activity to dog_signin;
grant update (place, place_at, counted_hour, last_seen) on app.watch_activity to dog_signin;
grant delete on app.watch_activity to dog_signin;
grant insert (member_id, hour) on app.watch_hours to dog_signin;
grant update (n) on app.watch_hours to dog_signin;
grant delete on app.watch_hours to dog_signin;
grant insert (member_id, kind, hour) on app.watch_counts to dog_signin;
grant update (n) on app.watch_counts to dog_signin;
grant delete on app.watch_counts to dog_signin;

-- 1, 3 and 4: at every signed-in request, as the site resolves its session (signin/session.js). p_ua and p_country are
-- the site's keyed hashes of the request's browser kind and country, or null. Returns the alerts raised and, when the
-- session's place is due a comparison (its first request, then at most once an hour), the account's latest sealed
-- place for the site to compare (2, app.watch_travel). Never waits long for a lock, never refuses.
create function app.watch_session(p_session_hash text, p_ua text, p_country text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  w app.watch_sessions%rowtype;
  a app.watch_activity%rowtype;
  st app.watch_settings%rowtype;
  hr timestamptz := date_trunc('hour', now() at time zone 'UTC') at time zone 'UTC';
  h integer := extract(hour from now() at time zone 'UTC')::integer;
  day text := to_char(now() at time zone 'UTC', 'YYYYMMDD');
  n integer;
  q integer;
  usual numeric;
  total integer;
  near integer;
  due boolean := false;
  alerts integer := 0;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or (p_ua is not null and p_ua !~ '^[0-9a-f]{64}$')
     or (p_country is not null and p_country !~ '^[0-9a-f]{64}$') then
    return jsonb_build_object('alerts', 0);
  end if;
  select x.id, x.member_id into s from app.sessions x where x.token_hash = p_session_hash and x.expires_at > now();
  if not found then
    return jsonb_build_object('alerts', 0);
  end if;
  -- Never wait long for a lock: the request it watches has already been served its session.
  perform set_config('lock_timeout', '300ms', true);
  select * into st from app.watch_settings limit 1;

  -- 1. The session's browser kind and country, kept as first seen; a change alerts once for the session.
  insert into app.watch_sessions (session_id, ua_hash, country_hash) values (s.id, p_ua, p_country)
    on conflict (session_id) do nothing returning * into w;
  if found then
    due := true;
  else
    select * into w from app.watch_sessions x where x.session_id = s.id;
    if p_ua is not null and w.ua_hash is not null and p_ua <> w.ua_hash then
      if app.notify(null, 'alert', 'A session moved to another browser',
           'A signed-in session was used from a different kind of browser than it started on. A copied session cookie is '
           || 'the usual cause. If it is the administrator''s, sign out everywhere, which also cancels the key file.',
           '/controls', 'member', s.member_id, 'watch:moved:browser:' || s.id::text) then
        alerts := alerts + 1;
      end if;
    end if;
    if p_country is not null and w.country_hash is null then
      update app.watch_sessions x set country_hash = p_country where x.session_id = s.id;
    elsif p_country is not null and p_country <> w.country_hash then
      if app.notify(null, 'alert', 'A session was used from another country',
           'A signed-in session was used from a different country than it started in. Travel or a VPN can do this; so can '
           || 'a copied session cookie.', '/controls', 'member', s.member_id, 'watch:moved:country:' || s.id::text) then
        alerts := alerts + 1;
      end if;
    end if;
    due := w.place_checked_at is null or w.place_checked_at < now() - interval '1 hour';
  end if;

  -- 4. This hour's requests, against the account's usual hour of use over the last 7 days, checked when the count
  -- reaches the floor and each doubling of it, so the check is rare; at most one alert a day per account.
  insert into app.watch_counts (member_id, kind, hour) values (s.member_id, 'requests', hr)
    on conflict (member_id, kind, hour) do update set n = app.watch_counts.n + 1 returning app.watch_counts.n into n;
  if n >= st.requests_floor and n % st.requests_floor = 0 then
    q := n / st.requests_floor;
    if q & (q - 1) = 0 then
      -- The usual hour is the average of the hours it was used in, so a busy but regular account isn't flagged daily.
      select coalesce(avg(c.n), 0) into usual from app.watch_counts c
        where c.member_id = s.member_id and c.kind = 'requests' and c.hour < hr and c.hour >= hr - interval '7 days';
      if n > st.requests_multiplier * usual and app.notify(null, 'alert', 'Unusually many requests from one account',
           n || ' requests from one account in this hour; its usual hour of use over the last 7 days is ' || round(usual, 1)
           || '. A script using the account, or a copied session, can cause it.', '/controls', 'member', s.member_id,
           'watch:requests:' || s.member_id::text || ':' || day) then
        alerts := alerts + 1;
      end if;
    end if;
  end if;

  -- 3. The hours of the day the account is active in, counted once an hour. The row is read without a lock; the hour is
  -- claimed by one update, so only the first request of each hour waits for the row, and only that one counts.
  select * into a from app.watch_activity x where x.member_id = s.member_id;
  if not found then
    insert into app.watch_activity (member_id) values (s.member_id) on conflict (member_id) do nothing;
    select * into a from app.watch_activity x where x.member_id = s.member_id;
  end if;
  update app.watch_activity x set counted_hour = hr, last_seen = now()
    where x.member_id = s.member_id and (x.counted_hour is null or x.counted_hour < hr);
  if found then
    select coalesce(sum(x.n), 0), coalesce(sum(x.n) filter (where x.hour in (h, (h + 23) % 24, (h + 1) % 24)), 0)
      into total, near from app.watch_hours x where x.member_id = s.member_id;
    if total >= st.hours_min_active and a.first_seen < now() - interval '21 days' and near = 0 then
      if app.notify(null, 'alert', 'Activity at an unusual hour',
           'An account was used at ' || lpad(h::text, 2, '0') || ':00 UTC, an hour of the day it has not been used in '
           || 'before, nor in the hours either side, over a long history. Travel can do this; so can someone else using it.',
           '/controls', 'member', s.member_id, 'watch:hours:' || s.member_id::text || ':' || day) then
        alerts := alerts + 1;
      end if;
    end if;
    insert into app.watch_hours (member_id, hour) values (s.member_id, h)
      on conflict (member_id, hour) do update set n = app.watch_hours.n + 1;
    -- Halved as it grows, so old habits fade (an hour counted once goes).
    if total + 1 > 4 * st.hours_min_active then
      delete from app.watch_hours x where x.member_id = s.member_id and x.n = 1;
      update app.watch_hours x set n = x.n / 2 where x.member_id = s.member_id;
    end if;
    -- A place more than a day old is no use for travel: cleared here as well as by the hourly sweep.
    if a.place_at <= now() - interval '1 day' then
      update app.watch_activity x set place = null, place_at = null where x.member_id = s.member_id and x.place_at = a.place_at;
    end if;
  end if;

  if due then
    -- A place older than a day is no use for travel and is not kept (the sweep clears it too).
    return jsonb_build_object('alerts', alerts, 'place', jsonb_build_object('sealed',
      case when a.place_at > now() - interval '1 day' then a.place end));
  end if;
  return jsonb_build_object('alerts', alerts);
end
$$;

-- 2: the site's comparison. p_place is the sealed place of this request (or null when the host gave none); p_km the
-- distance the site found from p_prev, the sealed place app.watch_session returned (or null). The account's place
-- becomes this one. The comparison counts only if the account's place is still p_prev (nothing moved it since).
create function app.watch_travel(p_session_hash text, p_place text, p_km integer, p_prev text)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  a app.watch_activity%rowtype;
  st app.watch_settings%rowtype;
  hrs numeric;
  alerted boolean := false;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$'
     or (p_place is not null and (char_length(p_place) not between 40 and 200 or p_place !~ '^[A-Za-z0-9_-]+$'))
     or (p_km is not null and p_km not between 0 and 25000) then
    return false;
  end if;
  select x.id, x.member_id into s from app.sessions x where x.token_hash = p_session_hash and x.expires_at > now();
  if not found then
    return false;
  end if;
  perform set_config('lock_timeout', '300ms', true);
  select * into st from app.watch_settings limit 1;
  update app.watch_sessions x set place_checked_at = now() where x.session_id = s.id;
  select * into a from app.watch_activity x where x.member_id = s.member_id for update;
  if not found then
    return false;
  end if;
  if p_km is not null and p_prev is not null and a.place = p_prev and a.place_at > now() - interval '1 day'
     and p_km >= st.travel_min_km then
    hrs := greatest(extract(epoch from (now() - a.place_at)) / 3600.0, 1.0 / 60);
    if p_km / hrs > st.travel_kmh then
      alerted := app.notify(null, 'alert', 'Travel too fast to be possible',
        'One account was used from two places about ' || p_km || ' km apart within '
        || case when hrs < 1 then greatest(round(hrs * 60), 1) || ' minutes' else round(hrs, 1) || ' hours' end
        || ', faster than ' || st.travel_kmh || ' km/h. A copied session or key file can cause it; so can a VPN.',
        '/controls', 'member', s.member_id, 'watch:travel:' || s.member_id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
    end if;
  end if;
  if p_place is not null then
    update app.watch_activity x set place = p_place, place_at = now() where x.member_id = s.member_id;
  end if;
  return alerted;
end
$$;

-- 5 and 6: from the audit log, which records every one of these actions whoever makes them. Never stops the action.
create function app.watch_audit()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  st app.watch_settings%rowtype;
  hr timestamptz := date_trunc('hour', now() at time zone 'UTC') at time zone 'UTC';
  n integer;
  word text := '^[A-Za-z0-9_.:-]{1,40}$';
begin
  begin
    -- The texts are fixed; only short, plain values from the record go into them (the CSO's review, S1). The site's
    -- roles can't write these two actions at all (the restrictive policy below).
    if new.action = 'admin.set' then
      perform app.notify(null, 'alert', 'A member was made administrator',
        'A member was given administrator powers. If you didn''t do this, the site''s administrator account may not be yours alone.',
        '/controls', 'member', new.subject_id, 'watch:admin:' || new.id::text);
    elsif new.action = 'jevs.setting' then
      perform app.notify(null, 'alert', 'A JEVs setting changed',
        'JEVs''s setting "' || case when new.detail ->> 'key' ~ word then new.detail ->> 'key' else '?' end || '" changed from "'
        || case when new.detail ->> 'from' ~ word then new.detail ->> 'from' else '?' end || '" to "'
        || case when new.detail ->> 'to' ~ word then new.detail ->> 'to' else '?' end || '". Only a reviewed migration changes it.',
        '/controls', null, null, 'watch:setting:' || new.id::text);
    -- Only for a brake for everyone that really is off: the site's role writes brake records too (the CSO's re-check).
    elsif new.action = 'brake.off' and new.detail ->> 'scope' = 'everyone'
          and exists (select 1 from app.brakes b where b.id = new.subject_id and b.member_id is null and b.lifted_at is not null) then
      perform app.notify(null, 'alert', 'The brake for everyone was switched off',
        'The emergency brake on the whole site was switched off. If you didn''t do this, switch it on again from the owner controls.',
        '/controls', 'brake', new.subject_id, 'watch:brake:' || new.id::text);
    end if;
    -- A sub-agent stopped with the agent above it is part of one revocation, not another one.
    if new.action in ('post.remove', 'member.ban', 'member.level_set', 'agent.revoke', 'brake.off')
       and new.actor_kind in ('member', 'admin') and new.actor_id is not null
       and not (new.action = 'agent.revoke' and (new.detail ? 'parent' or new.detail ? 'cascade'))
       -- Never wait: if another transaction is counting the same account, action and hour, this one goes uncounted
       -- rather than hold up the action it watches (the CSO's review, S4). Only this function writes these counts.
       and pg_try_advisory_xact_lock(hashtext('dayonegreat.watch_audit'), hashtext(new.actor_id::text || new.action || to_char(hr at time zone 'UTC', 'YYYYMMDDHH24'))) then
      select * into st from app.watch_settings limit 1;
      insert into app.watch_counts (member_id, kind, hour) values (new.actor_id, new.action, hr)
        on conflict (member_id, kind, hour) do update set n = app.watch_counts.n + 1 returning app.watch_counts.n into n;
      if n = st.removals_per_hour then
        perform app.notify(null, 'alert', 'Many removals by one account',
          n || ' ' || case new.action when 'post.remove' then 'posts removed' when 'member.ban' then 'members banned'
            when 'member.level_set' then 'member levels set' when 'agent.revoke' then 'agents revoked' else 'brakes switched off' end
          || ' by one account within the hour. If it isn''t you, the account may have been taken over.',
          '/controls', 'member', new.actor_id, 'watch:removals:' || new.actor_id::text || ':' || new.action || ':'
          || to_char(hr at time zone 'UTC', 'YYYYMMDDHH24'));
      end if;
    end if;
  exception when others then
    null; -- the watch only alerts: it never stops what it watches
  end;
  return null;
end
$$;
create trigger audit_log_watch after insert on app.audit_log for each row
  when (new.action in ('admin.set', 'jevs.setting', 'post.remove', 'member.ban', 'member.level_set', 'agent.revoke', 'brake.off'))
  execute function app.watch_audit();
-- Only the database owner (setting an administrator) and JEVs's own settings trigger record these two actions; the
-- site's roles never do, so none of them can make the watch raise those alerts (the CSO's review, S1).
create policy audit_insert_not_watched on app.audit_log as restrictive for insert to dog_app, dog_delegate, dog_erase, dog_signin
  with check (action <> all (array['admin.set', 'jevs.setting']));

-- 6: the behaviour watch's own thresholds and the sub-agent limits (JEVs's settings are in the audit log above).
create function app.watch_settings_changed()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  what text;
begin
  begin
    select string_agg(e.key, ', ' order by e.key) into what from jsonb_each(to_jsonb(new)) e
      where e.key <> 'updated_at' and e.value is distinct from (to_jsonb(old) -> e.key);
    if what is not null then
      perform app.notify(null, 'alert', 'A safety setting changed',
        'Changed in ' || case tg_table_name when 'watch_settings' then 'the behaviour watch''s thresholds' else 'the sub-agent limits' end
        || ': ' || what || '. Only a reviewed migration changes these.', '/controls', null, null,
        'watch:settings:' || tg_table_name || ':' || txid_current()::text || ':' || md5(what));
    end if;
  exception when others then
    null;
  end;
  return null;
end
$$;
create trigger watch_settings_changed after update on app.watch_settings for each row execute function app.watch_settings_changed();
create trigger subagent_settings_changed after update on app.subagent_settings for each row execute function app.watch_settings_changed();

-- Keeping no more than promised, at every run of the timers (027): counts after 8 days, places after a day, and
-- active hours after 90 days without activity. Never fails the timers.
create function app.watch_sweep()
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  a integer;
  b integer;
  c integer;
  d integer;
begin
  delete from app.watch_counts x where x.hour < now() - interval '8 days';
  get diagnostics a = row_count;
  -- A session that has run out (sign-out, sign-out everywhere and account deletion take their rows at once).
  delete from app.watch_sessions w using app.sessions x where x.id = w.session_id and x.expires_at <= now();
  get diagnostics d = row_count;
  a := a + d;
  update app.watch_activity x set place = null, place_at = null where x.place_at < now() - interval '1 day';
  get diagnostics b = row_count;
  delete from app.watch_activity x where x.last_seen < now() - interval '90 days';
  get diagnostics c = row_count;
  return jsonb_build_object('watch_swept', a + b + c);
exception when others then
  return jsonb_build_object('watch_swept', -1);
end
$$;

-- Who may call them, set while dog_owner still owns them (a revoke by any other role does nothing). The triggers are
-- made above, while dog_owner may still run their functions; no role calls a trigger function directly.
revoke execute on function app.watch_session(text, text, text), app.watch_travel(text, text, integer, text), app.watch_audit(),
  app.watch_settings_changed(), app.watch_sweep() from public;
grant execute on function app.watch_session(text, text, text), app.watch_travel(text, text, integer, text) to dog_app;
-- The sweep goes to whoever may run the timers (027's app.run_timers: the site's role and dog_timers).
grant execute on function app.watch_sweep() to dog_app, dog_timers;

grant create on schema app to dog_signin;
alter function app.watch_session(text, text, text) owner to dog_signin;
alter function app.watch_travel(text, text, integer, text) owner to dog_signin;
alter function app.watch_audit() owner to dog_signin;
alter function app.watch_settings_changed() owner to dog_signin;
alter function app.watch_sweep() owner to dog_signin;
revoke create on schema app from dog_signin;

-- The timers (027's app.run_timers) with the sweep added at the end.
create or replace function app.run_timers()
returns jsonb
language plpgsql
as $$
declare
  out jsonb;
begin
  perform app.require_system();
  if not pg_try_advisory_xact_lock(hashtext('dayonegreat.timers'), 0) then
    return jsonb_build_object('busy', true);
  end if;
  out := jsonb_build_object('lifted', app.containment_lift_job(), 'expired_drafts', app.drafts_expire_job());
  out := out || app.act_reconfirm_job() || app.watch_job();
  -- JEVs (PR 12): the 24-hour timer on deletion reviews Aaron hasn't decided, and the sweep that keeps marks no
  -- longer than promised.
  out := out || jsonb_build_object('deletion_reviews_disabled', app.deletion_reviews_expire(), 'marks_swept', app.jevs_sweep());
  -- PR 16: sub-agents whose time is up (each takes everything under it with it).
  out := out || jsonb_build_object('subagents_expired', app.subagents_expire());
  -- 027: the key broker's hand-outs and failures (control 3).
  out := out || app.broker_watch_job();
  -- 030: the behaviour watch keeps no more than promised.
  out := out || app.watch_sweep();
  return out;
end
$$;

-- 7: the key file's sign-in (026's app.file_sign_in), with an alert when the right file follows wrong ones. It stays
-- the sign-in role's, so it is replaced as that role, with the right to create in the schema for these lines only.
grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.file_sign_in(p_login_hash text, p_key_hash text, p_display_name text, p_session_hash text,
                                 p_session_days integer, p_region text)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  k app.file_keys%rowtype;
  s record;
begin
  if p_login_hash is null or p_login_hash !~ '^[0-9a-f]{64}$' or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad key file request' using errcode = '22023';
  end if;
  select * into k from app.file_keys f where f.login_hash = p_login_hash and f.key_hash = p_key_hash for update;
  if not found then
    -- A wrong file for a username that has a key file counts; the 10th cancels it and tells the member, who then
    -- starts again with a new code (Aaron, Oct 28).
    update app.file_keys f set failed = f.failed + 1 where f.login_hash = p_login_hash returning * into k;
    -- The behaviour watch (026): Aaron hears at the 5th wrong file for a username, and when a key file is cancelled.
    if found and k.failed = 5 then
      begin
        perform app.notify(null, 'alert', 'Wrong key files for one account',
          '5 wrong key files have been tried for one member''s GitHub username. At 10 their key file is cancelled and they '
          || 'sign in again with a new code.', '/controls', 'member', k.member_id, 'watch:failed:' || k.id::text);
      exception when others then
        null; -- the watch only alerts: it never stops the count or the cancellation
      end;
    end if;
    if found and k.failed >= 10 then
      begin
        perform app.notify(null, 'alert',
          case when exists (select 1 from app.members m where m.id = k.member_id and m.is_admin) then 'Your own key file was cancelled'
               else 'A member''s key file was cancelled' end,
          '10 wrong key files were tried for the GitHub username, so the key file no longer works. The account is safe; '
          || 'the member signs in again with a new code.', '/controls', 'member', k.member_id, 'watch:cancelled:' || k.id::text);
      exception when others then
        null;
      end;
      delete from app.file_keys f where f.id = k.id;
      perform app.notify(k.member_id, 'signin_keyfile', 'Your key file was cancelled',
        'Someone tried 10 wrong key files with your GitHub username, so your key file no longer works. Your account is '
        || 'safe. To sign in, get a new code on the join page, post it, and choose a new key file.', '/join', 'member',
        k.member_id, 'signin:keyfile:cancelled:' || k.id::text);
      return query select 'start_again'::text, null::uuid, null::boolean, null::smallint, null::boolean;
      return;
    end if;
    return query select 'no_match'::text, null::uuid, null::boolean, null::smallint, null::boolean;
    return;
  end if;
  select * into s from app.sign_in_core('github', array[k.fingerprint], 1::smallint, 1::smallint, p_display_name,
                                   p_session_hash, p_session_days, null::timestamptz, null::uuid, p_region);
  -- The behaviour watch (030): the right key file after wrong ones for the username. All of it, the setting's read
  -- too, inside the catch, so it can never stop a sign-in.
  begin
    if k.failed >= coalesce((select w.wrong_files_before from app.watch_settings w limit 1), 3) then
      perform app.notify(null, 'alert', 'A sign-in after wrong key files',
        'The right key file signed in after ' || k.failed || ' wrong ones were tried for the same GitHub username. If the '
        || 'wrong ones weren''t the member''s own mistakes, someone else has been trying their username.', '/controls',
        'member', k.member_id, 'watch:afterfail:' || k.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
    end if;
  exception when others then
    null;
  end;
  update app.file_keys f set used_at = now(), failed = 0 where f.id = k.id;
  perform app.notify(s.member_id, 'signin_keyfile', 'Signed in with your key file',
    'Your key file was used to sign in to Day One Great. If that wasn''t you, sign out everywhere from your account page '
    || 'and sign in again with a new code and a new key file.', '/account', 'member', s.member_id,
    'signin:keyfile:' || p_session_hash);
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_signin;
