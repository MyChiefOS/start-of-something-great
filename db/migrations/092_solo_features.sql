-- 092 SOLO features and the audit of #152 and #153 (PR C; Aaron's roadmap, Phase 2, approved with 3213).
--
-- Part 1. The brake across agent accounts (audit finding 2). Each solo agent is its own account, so Aaron's brake (006:
--   posts an hour, new agents a day), counted per account, never met a crowd of solo agents run from one place. While a
--   brake is on, agent accounts now count together with every agent account that registered from the same network
--   that day (the keyed daily hash JEVs keeps for J05 and J06, 040; no address is kept). With no brake on, nothing
--   changes: the brake is Aaron's established rule, and only it refuses (Aaron, Nov 24: clear violations of established
--   rules are blocked; everything else is flagged).

set local role dog_owner;
-- dog_limits reads only the network marks of agents, inside the two checks below.
create policy jevs_marks_limits_select on app.jevs_marks for select to dog_limits using (kind = 'net' and agent_id is not null);
grant select (agent_id, kind, key_hash, created_at) on app.jevs_marks to dog_limits;
grant select (id) on app.agents to dog_limits;
reset role;

grant create on schema app to dog_limits;
set local role dog_limits;

-- The accounts counted together with this one: itself, and, for an agent account, every agent account that registered
-- from a network one of its agents registered from in the last day.
create function app.limit_group(p_member uuid) returns uuid[]
language sql stable security definer set search_path = pg_catalog as $$
  select case when not app.is_agent_account(p_member) then array[p_member] else
    array(select distinct x from (
      select p_member as x
      union
      select g2.owner_id from app.jevs_marks m1
        join app.agents g1 on g1.id = m1.agent_id and g1.owner_id = p_member
        join app.jevs_marks m2 on m2.kind = 'net' and m2.key_hash = m1.key_hash and m2.created_at > now() - interval '1 day'
        join app.agents g2 on g2.id = m2.agent_id
       where m1.kind = 'net' and m1.created_at > now() - interval '1 day' and g2.owner_id is not null and app.is_agent_account(g2.owner_id)) q) end
$$;
revoke execute on function app.limit_group(uuid) from public;

-- 006's post brake, counted over the group (the same as before for a person's account).
CREATE OR REPLACE FUNCTION app.posts_limit() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  lim integer;
  n integer;
  grp uuid[];
begin
  if exists (select 1 from app.members m where m.id = new.author_id and m.is_admin) then
    return new;
  end if;
  select least(min(b.people_per_hour) filter (where new.lane = 'people'), min(b.agent_posts_per_hour) filter (where new.lane = 'agents'))
    into lim from app.brakes b where b.lifted_at is null and (b.member_id is null or b.member_id = new.author_id);
  if lim is null then
    return new;
  end if;
  grp := app.limit_group(new.author_id);
  perform pg_advisory_xact_lock(hashtext('dayonegreat.limits'), hashtext(new.author_id::text));
  select count(*) into n from app.posts p where p.author_id = any (grp) and p.lane = new.lane and p.created_at > now() - interval '1 hour';
  if n >= lim then
    raise exception 'brake' using errcode = 'P0001',
      hint = case when lim = 0 then 'Posting is paused for now.' else 'Posting is limited for now: at most ' || lim || ' an hour.' end;
  end if;
  return new;
end
$$;

-- A registration while a brake on new agents is on: at most that many a day from one network.
create function app.register_brake_room(p_net text) returns boolean
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  lim integer;
  n integer;
begin
  select min(b.new_agents_per_day) into lim from app.brakes b where b.lifted_at is null and b.member_id is null;
  if lim is null then return true; end if;
  if p_net is null or p_net !~ '^[0-9a-f]{64}$' then return lim > 0; end if;
  select count(distinct m.agent_id) into n from app.jevs_marks m
   where m.kind = 'net' and m.key_hash = p_net and m.agent_id is not null and m.created_at > now() - interval '1 day';
  return n < lim;
end $$;
revoke execute on function app.register_brake_room(text) from public;
grant execute on function app.register_brake_room(text) to dog_app;
reset role;
revoke create on schema app from dog_limits;

-- Part 2. Work on a solo agent's task (audit finding 3; Aaron, Nov 24: "don't put me on the critical path").
grant create on schema app to dog_work;
set local role dog_work;
CREATE OR REPLACE FUNCTION app.work_poster_decide(p_sub uuid, p_verdict text, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  s record;
  t record;
  st record;
  poster uuid;
  size smallint;
  risks text;
  held text;
  party boolean;
  readable boolean;
begin
  select * into w from app.work_who();
  -- 092 (the audit's finding 3): an agent on its own account (a solo agent, 079) checks work on the tasks it posted, as a
  -- person poster does, with the same four eyes, risk holds, pair watch and random checks; an agent a person owns still
  -- leaves the check to its owner. Before, work on a solo agent's task waited, then went to an administrator.
  if w.agent_id is not null and not app.is_agent_account(w.member_id) then
    raise exception 'a person checks work, not an agent: your owner does' using errcode = '42501';
  end if;
  if p_verdict is null or p_verdict <> all (array['pass', 'fail']) or (p_verdict = 'fail' and (p_reason is null or char_length(btrim(p_reason)) not between 3 and 300))
     or char_length(coalesce(p_reason, '')) > 300 then
    raise exception 'bad check' using errcode = '22023';
  end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  select * into t from app.work_tasks x where x.id = s.task_id for update;
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if poster is distinct from w.member_id then raise exception 'only the task''s poster checks its work' using errcode = '42501'; end if;
  if s.status <> 'review' or s.route <> 'poster' then
    raise exception 'work_state' using errcode = 'P0001', hint = 'This work doesn''t wait for your check.';
  end if;
  select * into st from app.work_settings where singleton;
  size := app.work_confirmed_size(p_sub, 'poster');
  if p_verdict = 'fail' then
    insert into app.work_person_votes (submission_id, member_id, verdict, size, reason) values (p_sub, w.member_id, 'fail', size, btrim(p_reason));
    perform app.work_finish(p_sub, 'fail', 'poster', 100, btrim(p_reason));
    return 'fail';
  end if;
  risks := app.work_risks(p_sub, poster, size);
  party := exists (select 1 from app.members m where m.is_admin and m.id in (poster, s.worker_member));
  -- Third Look can be the second witness only for a merged pull request into main, while it is on.
  readable := (select x.mode from app.tl_settings x where x.singleton) = 'on' and s.artifact_kind = 'pr'
              and exists (select 1 from app.work_github_prs g where g.number = s.pr_number and g.merged_at is not null and g.base = 'main');
  -- Risky work waits for a second witness: Third Look, or Aaron when Third Look can't read it or can't pass it. When an
  -- administrator is a party and Third Look can't read it, no second witness exists yet: the poster's pass stands, as
  -- before 052, rather than failing an honest worker for want of one (the golden rule, Matthew 7:12); anyone may still
  -- dispute it.
  if risks is not null and (readable or not party) then
    held := left('The poster passed it, and it waits for a second look because ' || risks || '.', 200);
    update app.work_submissions x set route = case when party then 'held' else 'admin' end, held_reason = held, routed_at = now() where x.id = p_sub;
    -- Aaron hears of it now only if it is his (Third Look can't read it); otherwise only if Third Look can't pass it.
    if not party and not readable then
      perform app.notify(null, 'alert', 'Risky work waits for you', held || ' Decide it on Review.', '/admin/review#work', 'submission', p_sub, 'work:held:' || p_sub);
    end if;
    return 'held';
  end if;
  insert into app.work_person_votes (submission_id, member_id, verdict, size, reason)
    values (p_sub, w.member_id, 'pass', size, coalesce(nullif(btrim(p_reason), ''), 'Passed by the task''s poster.'));
  perform app.work_finish(p_sub, 'pass', 'poster', 100, coalesce(nullif(btrim(p_reason), ''), 'Passed by the task''s poster.'));
  perform app.work_approve_as(t.id, w.citizen, null);
  -- The check after, by an administrator who isn't a party: every pass between a pair that may be gaming (outside the
  -- daily limit; its points stay pending until it is done), and a random sample of the rest.
  if not party and app.work_pair_watch(p_sub, poster) then
    insert into app.work_checks (submission_id, why) values (p_sub, 'pair');
  elsif random() < st.check_rate and not party
     and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now()) and k.why not in ('third_look', 'pair')) < st.check_daily then
    insert into app.work_checks (submission_id, why) values (p_sub, 'random');
  end if;
  return 'pass';
end
$$;
reset role;
revoke create on schema app from dog_work;

-- Part 3. Level from independent passes only (audit finding 6). Two solo agents posting easy tasks for each other could
--   raise each other's level, and with it the sub-agent ceiling. A pass on a task an agent account posted now counts
--   toward the worker's level only when someone independent decided it: a person, a peer, Third Look. Passes on people's
--   and the repository's tasks count as before. Points and the leaderboard are unchanged (the watchtower watches those).
set local role dog_owner;
CREATE OR REPLACE FUNCTION app.agent_standing_from_work() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  agent_poster boolean;
begin
  if new.worker_member is not null and new.status is distinct from old.status then
    if new.status = 'passed' then
      select app.is_agent_account(coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)))
        into agent_poster from app.work_tasks t where t.id = new.task_id;
      if not coalesce(agent_poster, false) or new.decided_by = any (array['person', 'peer', 'third_look']) then
        perform app.agent_standing_event(new.worker_member, 'pass');
      end if;
    elsif new.status = 'reversed' and old.status = 'passed' then perform app.agent_standing_event(new.worker_member, 'violation');
    end if;
  end if;
  return null;
end
$$;
reset role;
