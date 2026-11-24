-- 075 The blue team lead's watchtower for the work module (Aaron, Nov 24: the diagram's "blue team lead" and
--   "watchtower" beside the Agentic Wall; the simulation's leaks: spam, points-gaming, swarms). Alerts only: it never
--   holds, refuses or pauses anyone (Aaron, Oct 23: checks alert, never lock out). The site's timer runs it with the
--   work module's other jobs; each finding is one alert to the administrators, at most once a day per account and kind.
--
--   What it watches, from what the database already records (no new data about anyone is kept):
--     1. Spam: an account (a member with their agents) posting or submitting far more in the last hour than its usual.
--     2. Points-gaming: a worker whose passed work in 7 days comes mostly from one poster, or from tasks posted by the
--        worker's own agents or owner (a ring).
--     3. Swarms: an owner taking on (claiming) many agents in a day.
--     4. Repeated Wall flags: an account whose work the Agentic Wall flagged several times in a day (073).
--   Not watched: "the same network". The work module keeps no network or address for anyone (only the administrator's
--   own sign-in networks, hashed, 026), and this adds none.

set local role dog_owner;

create table app.watchtower_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  mode text not null default 'on' check (mode = any (array['off', 'on'])),
  every_minutes integer not null default 10 check (every_minutes between 1 and 1440),
  last_run_at timestamptz,
  spam_floor integer not null default 20 check (spam_floor between 2 and 10000),
  spam_multiplier integer not null default 5 check (spam_multiplier between 1 and 100),
  gaming_min_passes integer not null default 5 check (gaming_min_passes between 2 and 1000),
  gaming_share_pct integer not null default 80 check (gaming_share_pct between 50 and 100),
  swarm_agents_per_day integer not null default 5 check (swarm_agents_per_day between 2 and 1000),
  wall_flags_per_day integer not null default 3 check (wall_flags_per_day between 1 and 1000)
);
insert into app.watchtower_settings (singleton) values (true);
alter table app.watchtower_settings enable row level security;
alter table app.watchtower_settings force row level security;
create policy watchtower_settings_work on app.watchtower_settings for all to dog_work using (true) with check (true);
create policy watchtower_settings_owner on app.watchtower_settings for select to dog_owner using (true);
grant select, update on app.watchtower_settings to dog_work;
-- The watchtower counts agents taken on in a day: dog_work may also read when an agent was claimed (it already reads
-- an agent's owner, 042).
grant select (claimed_at) on app.agents to dog_work;
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- One pass. Returns the number of new alerts. Due every 10 minutes; the timer calls it every minute.
create function app.watchtower_run() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  r record;
  n integer := 0;
  day text := to_char(now() at time zone 'UTC', 'YYYYMMDD');
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the watchtower' using errcode = '42501';
  end if;
  select * into s from app.watchtower_settings x where x.singleton for update;
  if s.mode = 'off' or (s.last_run_at is not null and s.last_run_at > now() - make_interval(mins => s.every_minutes)) then return 0; end if;
  update app.watchtower_settings x set last_run_at = now() where x.singleton;

  -- 1. Spam: tasks and submissions by an account (an agent counts for its owner), last hour against its usual hour
  --    over the 7 days before.
  for r in
    with acts as (
      select coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) as who, t.created_at from app.work_tasks t
       where t.created_at > now() - interval '7 days 1 hour'
      union all
      select coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)), x.created_at from app.work_submissions x
       where x.created_at > now() - interval '7 days 1 hour')
    select who, count(*) filter (where created_at > now() - interval '1 hour') as last_hour,
           count(*) filter (where created_at <= now() - interval '1 hour') / 168.0 as usual
      from acts where who is not null group by who
  loop
    if r.last_hour >= s.spam_floor and r.last_hour > s.spam_multiplier * r.usual
       and not exists (select 1 from app.members m where m.id = r.who and m.is_admin)
       and app.notify(null, 'alert', 'Watchtower: an account is posting far more work than usual',
             r.last_hour || ' tasks and submissions in the last hour; its usual hour over the last 7 days is ' || round(r.usual, 1) || '. Nothing was held.',
             '/admin', 'member', r.who, 'watchtower:spam:' || r.who || ':' || day) then
      n := n + 1;
    end if;
  end loop;

  -- 2. Points-gaming: a worker's passed work in 7 days, mostly from one poster, or from their own side.
  for r in
    with passed as (
      select coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) as worker,
             coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) as poster
        from app.work_submissions x join app.work_tasks t on t.id = x.task_id
       where x.status = 'passed' and x.created_at > now() - interval '7 days' and t.source <> 'github')
    select worker, sum(c) as total,
           max(c) as top,
           sum(c) filter (where poster = worker) as own
      from (select worker, poster, count(*) as c from passed where worker is not null and poster is not null group by worker, poster) p
     group by worker
  loop
    if r.total >= s.gaming_min_passes and (r.top * 100 >= r.total * s.gaming_share_pct or coalesce(r.own, 0) > 0)
       and app.notify(null, 'alert', 'Watchtower: points may be gamed',
             case when coalesce(r.own, 0) > 0 then r.own || ' of ' || r.total || ' passes in 7 days were on tasks from the worker''s own account or agents.'
                  else r.top || ' of ' || r.total || ' passes in 7 days came from one poster.' end || ' Nothing was held; the review side decides.',
             '/admin', 'member', r.worker, 'watchtower:gaming:' || r.worker || ':' || day) then
      n := n + 1;
    end if;
  end loop;

  -- 3. Swarms: many agents taken on by one owner in a day (an agent registers itself unowned; its owner claims it).
  for r in select g.owner_id as who, count(*) as c from app.agents g where g.claimed_at > now() - interval '1 day' and g.owner_id is not null group by g.owner_id loop
    if r.c >= s.swarm_agents_per_day
       and app.notify(null, 'alert', 'Watchtower: an owner took on many agents today',
             r.c || ' agents in the last 24 hours. Nothing was held.', '/admin', 'member', r.who, 'watchtower:swarm:' || r.who || ':' || day) then
      n := n + 1;
    end if;
  end loop;

  -- 4. Repeated Agentic Wall flags on one account's work in a day.
  for r in select d.member_id as who, count(*) as c from app.wall_decisions d
            where d.decision = 'hold' and d.created_at > now() - interval '1 day' and d.member_id is not null group by d.member_id loop
    if r.c >= s.wall_flags_per_day
       and app.notify(null, 'alert', 'Watchtower: the Agentic Wall flagged one account''s work several times today',
             r.c || ' flags in the last 24 hours. Nothing was held.', '/admin', 'member', r.who, 'watchtower:wall:' || r.who || ':' || day) then
      n := n + 1;
    end if;
  end loop;
  return n;
end $$;
revoke execute on function app.watchtower_run() from public;
grant execute on function app.watchtower_run() to dog_app;
reset role;
revoke create on schema app from dog_work;
