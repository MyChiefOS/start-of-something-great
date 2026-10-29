-- 027 Pre-opening safety (Aaron, Oct 29: "Lets finish so we can open the site"; harness/REVIEW-2026-10-26.md, the CSO's
--   route B controls 3 and 6, R-8's leftover and R-9). Nothing here opens or closes the site: it stays closed until
--   Aaron's go-live merge. Every check here alerts; none blocks anyone (Aaron: checks alert, never lock out).
--
--   1. The timer slot (control 6). The timers run with no timer secret on the site. app.timers_run(), which the site's
--      role may call as an anonymous visitor, runs app.run_timers() as the site itself at most once every 50 seconds,
--      a fixed interval no caller can change (the CSO's conditions, harness/FACTS.md, Oct 26: stricter than the 30
--      seconds Aaron approved). The slot and the timers are one transaction: if the timers fail, their work and the
--      slot are both undone, so the slot is given back and the next call (within a minute) tries again; the failure
--      itself is kept and alerts Aaron once a day. Calls that don't say they came from Vercel Cron (its user-agent,
--      read by api/cron.js) are counted, as evidence only, and alert once a day past 30 runs.
--      It runs as dog_timers, a role made here for it alone: it can't sign in, belongs to dog_app only (so the
--      timers run under exactly the site's policies, as before), and may make the site's own stamp (app.actor_stamp,
--      019), which dog_app may not. Nobody can act as dog_timers but the database owner. The stamp is set only around
--      app.run_timers() and the caller's own settings are put back before it returns, so the site never gets the
--      site's own powers for anything else. app.actor_keys.system_hash (019) is no longer needed by the timers and
--      stays empty under route B (RISKS.md RK85).
--   2. The heartbeat (R-9). app.timer_slot.last_ok_at, when the timers last finished, is readable by the site as
--      anyone (no personal data: a time). /api/ready reports how long ago that was, and the uptime monitor (every 15
--      minutes) raises its issue when the site is open and the timers haven't finished for 15 minutes.
--   3. The 90-day check on agents acting alone, on each agent post (R-9, CAI-4). Until now only the timers moved an
--      agent back to drafting at day 90 (R33, 012), so a missed timer left it acting on its own. Now each post an agent
--      makes on its own checks the clock in the database: past 90 days since its owner's last fresh confirmation, the
--      post is refused as "drafts" and becomes a draft for the owner's approval, never "off". The timers still record
--      the change and tell the owner when they run.
--   4. Broker alerts (control 3). The key broker (supabase/functions/dog-keys) adds one to this hour's count of
--      hand-outs, or of failures, in app.broker_uses (counts only). The timers alert Aaron in his inbox when an hour
--      has 100 hand-outs or more (each running copy of the site asks about 6 times an hour) or any failure, once per
--      hour each. Counts older than 30 days are deleted.
-- ---- The timers' role, made by the runner's own login (like dog_web in 022) ----
do $timers_role$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_timers') then
    create role dog_timers nologin noinherit nobypassrls;
  end if;
end
$timers_role$;
-- It has the site's rights (dog_app's grants and policies apply to it), and nothing more of its own but below.
grant dog_app to dog_timers with inherit true, set false;
-- The owner may hand it its one function, for this migration only: the membership is revoked at the end, so no role
-- can act as dog_timers afterwards (and no chain dog_owner -> dog_timers -> dog_app is left behind).
grant dog_timers to dog_owner with inherit false, set true;

set local role dog_owner;

-- ---- The slot: one row ----
create table app.timer_slot (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  last_at timestamptz,                -- when the last run that finished took the slot
  last_ok_at timestamptz,             -- when the timers last finished (the heartbeat)
  failures integer not null default 0 check (failures >= 0),
  last_failure_at timestamptz,
  last_failure_state text check (char_length(last_failure_state) <= 5), -- the SQLSTATE only, never a message
  other_day date,                     -- the UTC day of other_runs
  other_runs integer not null default 0 check (other_runs >= 0)
);
alter table app.timer_slot enable row level security;
alter table app.timer_slot force row level security;
create policy timer_slot_owner on app.timer_slot for all to dog_owner using (true) with check (true);
create policy timer_slot_timers on app.timer_slot for all to dog_timers using (true) with check (true);
-- The heartbeat, for anyone: the site reads when the timers last finished, and nothing else.
create policy timer_slot_heartbeat on app.timer_slot for select to dog_app using (true);
grant select, update on app.timer_slot to dog_timers;
grant select (last_ok_at) on app.timer_slot to dog_app;
insert into app.timer_slot (singleton) values (true);

-- ---- Broker counts: hand-outs and failures per hour ----
create table app.broker_uses (
  id uuid primary key default app.uuid_v7(),
  hour timestamptz not null unique,
  handed integer not null default 0 check (handed >= 0),
  failed integer not null default 0 check (failed >= 0)
);
alter table app.broker_uses enable row level security;
alter table app.broker_uses force row level security;
-- The broker writes as the project's main login, which holds dog_owner's rights (001).
create policy broker_uses_owner on app.broker_uses for all to dog_owner using (true) with check (true);
create policy broker_uses_system on app.broker_uses for select to dog_app using ((select app.actor_kind()) = 'system');
grant select on app.broker_uses to dog_app;

-- One hand-out or one failure, this hour. Called by the broker only; counts, never a value.
create function app.broker_note(p_outcome text) returns void
language plpgsql set search_path = pg_catalog
as $$
begin
  if p_outcome is null or p_outcome not in ('handed', 'failed') then
    raise exception 'broker_note: handed or failed' using errcode = '22023';
  end if;
  insert into app.broker_uses as u (hour, handed, failed)
    values (date_trunc('hour', now() at time zone 'UTC') at time zone 'UTC', (p_outcome = 'handed')::int, (p_outcome = 'failed')::int)
    on conflict (hour) do update set handed = u.handed + excluded.handed, failed = u.failed + excluded.failed;
  delete from app.broker_uses u where u.hour < now() - interval '30 days';
end
$$;

-- The timers' broker check: this hour and the last, each alerted once.
create function app.broker_watch_job() returns jsonb
language plpgsql
as $$
declare
  r record;
  n integer := 0;
  limit_per_hour constant integer := 100;
begin
  perform app.require_system();
  for r in select u.hour, u.handed, u.failed from app.broker_uses u
           where u.hour >= date_trunc('hour', now() at time zone 'UTC') at time zone 'UTC' - interval '1 hour' order by u.hour loop
    if r.handed >= limit_per_hour and app.notify(null, 'alert', 'The key broker handed out the site''s keys unusually often',
         r.handed || ' hand-outs in the hour from ' || to_char(r.hour at time zone 'UTC', 'YYYY-MM-DD HH24:00') || ' UTC; each running copy '
         || 'of the site asks about 6 times an hour. Someone may be using a production identity token of ours (RISKS.md RK88). '
         || 'Nothing was stopped.', '/controls', null, null, 'alert:broker:busy:' || to_char(r.hour at time zone 'UTC', 'YYYYMMDDHH24')) then
      n := n + 1;
    end if;
    if r.failed > 0 and app.notify(null, 'alert', 'The key broker failed',
         r.failed || ' failed answers in the hour from ' || to_char(r.hour at time zone 'UTC', 'YYYY-MM-DD HH24:00') || ' UTC (the login '
         || 'or a key missing from Vault, or a read error). The site keeps its last good keys meanwhile. Nothing was stopped.',
         '/controls', null, null, 'alert:broker:failed:' || to_char(r.hour at time zone 'UTC', 'YYYYMMDDHH24')) then
      n := n + 1;
    end if;
  end loop;
  return jsonb_build_object('broker_alerts', n);
end
$$;

-- ---- The timers, with the broker check (014's version, with the part marked 027) ----
create or replace function app.run_timers() returns jsonb
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
  return out;
end
$$;

-- ---- The slot-gated wrapper the site calls (control 6) ----
create function app.timers_run(p_from_cron boolean) returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  st text;
  ran boolean := false;
  n integer;
  today date := (now() at time zone 'UTC')::date;
  -- The caller's own settings, put back before returning.
  c_actor text := coalesce(current_setting('app.actor', true), '');
  c_member text := coalesce(current_setting('app.member_id', true), '');
  c_agent text := coalesce(current_setting('app.agent_id', true), '');
  c_fresh text := coalesce(current_setting('app.fresh', true), '');
  c_session text := coalesce(current_setting('app.session', true), '');
  c_stamp text := coalesce(current_setting('app.stamp', true), '');
begin
  -- One run at a time; a run under way, or one that finished less than 50 seconds ago, means nothing to do.
  select t.last_at into s from app.timer_slot t where t.singleton for update skip locked;
  if not found then
    return jsonb_build_object('ran', false, 'why', 'busy');
  end if;
  if s.last_at is not null and s.last_at > now() - interval '50 seconds' then
    return jsonb_build_object('ran', false, 'why', 'early');
  end if;
  begin
    update app.timer_slot set last_at = now() where singleton;
    perform set_config('app.actor', 'system', true), set_config('app.member_id', '', true), set_config('app.agent_id', '', true),
            set_config('app.fresh', '', true), set_config('app.session', '', true);
    perform set_config('app.stamp', app.actor_stamp('system', '', '', '', ''), true);
    perform app.run_timers();
    update app.timer_slot set last_ok_at = now(), failures = 0 where singleton;
    ran := true;
  exception when others then
    -- Everything in this block is undone, the slot and the stamp included, so the slot is given back.
    get stacked diagnostics st = returned_sqlstate;
  end;
  if not ran or not coalesce(p_from_cron, false) then
    if not ran then
      update app.timer_slot set failures = failures + 1, last_failure_at = now(), last_failure_state = left(st, 5) where singleton;
    else
      update app.timer_slot set other_runs = case when other_day = today then other_runs + 1 else 1 end, other_day = today
        where singleton returning other_runs into n;
    end if;
    perform set_config('app.actor', 'system', true), set_config('app.member_id', '', true), set_config('app.agent_id', '', true),
            set_config('app.fresh', '', true), set_config('app.session', '', true);
    perform set_config('app.stamp', app.actor_stamp('system', '', '', '', ''), true);
    if not ran then
      perform app.notify(null, 'alert', 'The site''s timers failed',
        'A run of the timers failed (error ' || coalesce(left(st, 5), 'unknown') || ') and was undone; the next call, within a minute, '
        || 'tries again. If this repeats, the uptime monitor''s heartbeat check also opens an issue. Nothing was stopped.',
        '/controls', null, null, 'alert:timers:failed:' || to_char(today, 'YYYYMMDD'));
    elsif n = 30 then
      perform app.notify(null, 'alert', 'The timers are being started by something other than Vercel Cron',
        '30 runs today were started by a caller that didn''t say it was Vercel Cron. The timer address is open by design (at most '
        || 'one run every 50 seconds), so this only costs timer runs; it may be someone calling it. Nothing was stopped.',
        '/controls', null, null, 'alert:timers:other:' || to_char(today, 'YYYYMMDD'));
    end if;
  end if;
  perform set_config('app.actor', c_actor, true), set_config('app.member_id', c_member, true), set_config('app.agent_id', c_agent, true),
          set_config('app.fresh', c_fresh, true), set_config('app.session', c_session, true), set_config('app.stamp', c_stamp, true);
  return jsonb_build_object('ran', ran, 'failed', not ran);
end
$$;

-- ---- The 90-day clock, checked on each agent post (R-9) ----
-- Past 90 days since the owner's last fresh confirmation (012's clock: the newest owner version that restarts it).
-- An agent with no such version (one that never acted on its own) has no clock, as in app.act_reconfirm_job.
create function app.act_clock_expired(p_agent uuid) returns boolean
language sql stable
as $$
  select coalesce((select max(x.created_at) from app.agent_rules x
                   where x.agent_id = p_agent and x.set_by = 'owner' and x.restarts_clock) <= now() - interval '90 days', false)
$$;

-- 008's version, with the part marked 027: an agent whose clock has run out drafts.
create or replace function app.posts_delegation() returns trigger
language plpgsql
as $$
declare
  cur app.agent_rules%rowtype;
begin
  if current_user = 'dog_delegate' then
    return new;
  end if;
  if app.actor_kind() <> 'agent' then
    new.delegation := null;
    new.rules_version := null;
    new.draft_id := null;
    return new;
  end if;
  select * into cur from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  if not found or cur.post_mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  if cur.post_mode <> 'act' then
    raise exception 'agent_drafts' using errcode = 'P0001';
  end if;
  -- 027: the 90-day clock, even if the timers haven't run: the post waits for the owner as a draft.
  if app.act_clock_expired(new.agent_id) then
    raise exception 'agent_drafts' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.agentcap'), hashtext(new.agent_id::text));
  if app.agent_actions_today(new.agent_id) >= cur.daily_cap then
    raise exception 'agent_cap' using errcode = 'P0001', hint = 'This agent has reached its daily limit of ' || cur.daily_cap || '.';
  end if;
  new.delegation := 'rules';
  new.rules_version := cur.version;
  new.draft_id := null;
  return new;
end
$$;

-- 008's version, with the part marked 027: a draft is also allowed when posting is "act" but the clock has run out.
create or replace function app.agent_drafts_fill() returns trigger
language plpgsql
as $$
declare
  cur app.agent_rules%rowtype;
begin
  if app.actor_kind() <> 'agent' then
    raise exception 'only an agent writes drafts' using errcode = '42501';
  end if;
  new.agent_id := app.current_agent();
  new.owner_id := app.current_member();
  new.action := 'post';
  new.body_hash := encode(sha256(convert_to(new.body, 'UTF8')), 'hex');
  new.status := 'pending';
  new.created_at := now();
  new.expires_at := now() + interval '48 hours';
  new.decided_at := null;
  select * into cur from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  if not found or cur.post_mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  if cur.post_mode <> 'draft' and not (cur.post_mode = 'act' and app.act_clock_expired(new.agent_id)) then
    raise exception 'agent_acts' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.agentcap'), hashtext(new.agent_id::text));
  if app.agent_actions_today(new.agent_id) >= cur.daily_cap then
    raise exception 'agent_cap' using errcode = 'P0001', hint = 'This agent has reached its daily limit of ' || cur.daily_cap || '.';
  end if;
  new.rules_version := cur.version;
  return new;
end
$$;

-- ---- Who may call what ----
revoke execute on function app.broker_note(text), app.broker_watch_job(), app.act_clock_expired(uuid), app.timers_run(boolean) from public;
grant execute on function app.broker_watch_job(), app.act_clock_expired(uuid) to dog_app;
-- app.broker_note: the owner's rights only (the broker's login holds them).

-- Hands app.timers_run to dog_timers (as 019 does for dog_signin): Postgres only hands a function to a role that may
-- create objects in its schema, so dog_timers has that right for these lines only.
grant create on schema app to dog_timers;
alter function app.timers_run(boolean) owner to dog_timers;
revoke create on schema app from dog_timers;
set local role dog_timers;
revoke execute on function app.timers_run(boolean) from public;
grant execute on function app.timers_run(boolean) to dog_app;
-- The site's own stamp: dog_timers may make one (inside app.timers_run, its only function); dog_app still may not.
set local role dog_signin;
grant execute on function app.actor_stamp(text, text, text, text, text) to dog_timers;
-- Back to the runner's own login, which granted the membership above, to take it back.
reset role;
revoke dog_timers from dog_owner;
set local role dog_owner;
