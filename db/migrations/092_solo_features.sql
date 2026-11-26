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
language plpgsql security definer set search_path = pg_catalog as $$
declare
  lim integer;
  n integer;
begin
  select min(b.new_agents_per_day) into lim from app.brakes b where b.lifted_at is null and b.member_id is null;
  if lim is null then return true; end if;
  if p_net is null or p_net !~ '^[0-9a-f]{64}$' then return lim > 0; end if;
  -- A busy marks table never refuses a registration: the brake counts what it can read within 250 ms.
  begin
    perform set_config('lock_timeout', '250ms', true);
    select count(distinct m.agent_id) into n from app.jevs_marks m
     where m.kind = 'net' and m.key_hash = p_net and m.agent_id is not null and m.created_at > now() - interval '1 day';
    perform set_config('lock_timeout', '0', true);
  exception when others then
    return true;
  end;
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

-- Part 4. JEVs never refuses a step because its own scoring failed (Aaron, Nov 26: "both A and B options dont fix it
--   cleanly ask Fable 5.2 for a solution and validate"; Fable 5.2's design, validated with a fault test: one locked
--   table refused a registration with 503 after 5 s, though no answer to its questions could block it, and let a post
--   go live unseen). Scoring reads in groups (the account, its posting rate, sign-up bursts, the text, reports, the
--   sub-agent tree, repeats), each with a 250 ms lock wait, so one slow or locked table makes only its own questions
--   unknown, never zero; the site gives the whole read 1.5 s. A clear breach is still blocked from what is known. A
--   step with an unknown question, and a whole scoring failure, go ahead flagged for the reviewers, with one alert an
--   hour for each kind of step. Not done here, as it would be a new rule for Aaron to agree: holding a step "limited"
--   until a later rescore, and undoing it automatically (Fable's steps 4 and 5).
grant create on schema app to dog_jevs;
set local role dog_jevs;
-- The questions that didn't answer, for this transaction's next decision (read by jevs_decide).
create function app.jevs_note_unknown(p_ids text) returns void
language plpgsql security definer set search_path = pg_catalog as $$
begin
  perform set_config('app.jevs_unknown', case when coalesce(p_ids, '') ~ '^(J[0-9]{2})(,J[0-9]{2})*$' then p_ids else '' end, true);
end $$;
revoke execute on function app.jevs_note_unknown(text) from public;
grant execute on function app.jevs_note_unknown(text) to dog_app;
-- A network or email mark that waits at most 250 ms for a busy table, and is skipped (false) rather than stopping the step.
create function app.jevs_mark_soon(p_kind text, p_key text, p_token text, p_agent uuid) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
declare saved text := current_setting('lock_timeout');
begin
  perform set_config('lock_timeout', '250ms', true);
  begin
    perform app.jevs_mark(p_kind, p_key, p_token, p_agent);
  exception when lock_not_available or query_canceled then
    perform set_config('lock_timeout', saved, true);
    return false;
  end;
  perform set_config('lock_timeout', saved, true);
  return true;
end $$;
revoke execute on function app.jevs_mark_soon(text, text, text, uuid) from public;
grant execute on function app.jevs_mark_soon(text, text, text, uuid) to dog_app;
CREATE OR REPLACE FUNCTION app.jevs_signals(p_action text, p_subject uuid, p_net text, p_domains text[], p_simhash bigint)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  judged uuid;
  m_created timestamptz; m_level smallint; m_admin boolean; m_status text; m_hand smallint; m_jevs timestamptz;
  fp text;
  p_agent uuid; p_draft uuid; -- 032
  subject_at timestamptz := now();
  credible_hours integer;
  res jsonb := '{}'::jsonb;
  unknown text[] := '{}';
  saved_lock text := current_setting('lock_timeout');
begin
  if p_action is null or p_action !~ '^[a-z]+\.?[a-z_]*$' or char_length(p_action) > 32
     or (p_net is not null and p_net !~ '^[0-9a-f]{64}$')
     or (p_domains is not null and (cardinality(p_domains) > 50 or exists (select 1 from unnest(p_domains) x where x is null or x !~ '^[0-9a-f]{64}$'))) then
    raise exception 'bad JEVs request' using errcode = '22023';
  end if;
  judged := me;
  if p_action in ('post.create', 'post.approved', 'post.reported') then
    select p.author_id, p.body_fp, p.created_at into judged, fp, subject_at from app.posts p where p.id = p_subject;
    if not found then
      raise exception 'bad JEVs request' using errcode = '22023';
    end if;
    if p_action = 'post.reported' then
      if not exists (select 1 from app.review_flags f where f.post_id = p_subject and f.source = 'report' and f.reporter_id = me) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
    elsif judged is distinct from me then
      raise exception 'bad JEVs request' using errcode = '22023';
    end if;
  end if;

  -- 092: each group of questions reads in its own block with a short lock wait, so one slow or locked table makes only
  -- that group unknown (never zero), and the rest are still answered.
  perform set_config('lock_timeout', '250ms', true);
  if judged is not null then
    select x.created_at, x.trust_level, x.is_admin, x.status, x.level_set_by_admin, x.jevs_level2_at
      into m_created, m_level, m_admin, m_status, m_hand, m_jevs from app.members x where x.id = judged;
    begin
    res := res || jsonb_build_object(
      'account', true,
      'age_hours', floor(extract(epoch from now() - m_created) / 3600),
      'trust_level', m_level, 'admin', m_admin, 'banned', m_status = 'banned',
      'hand_level', m_hand is not null, 'jevs_level2', m_jevs is not null,
      'best_identity', (select coalesce(max(case when i.recheck_after is not null and i.recheck_after <= now() then least(i.level, 1) else i.level end), -1)
                        from app.identities i where i.member_id = judged),
      'providers', (select count(distinct i.provider) from app.identities i where i.member_id = judged),
      'email_only', not exists (select 1 from app.identities i where i.member_id = judged and i.provider <> 'email')
                    and exists (select 1 from app.identities i where i.member_id = judged),
      'disposable', exists (select 1 from app.jevs_marks k where k.member_id = judged and k.kind = 'disposable'),
      -- J05: an account made in the last 7 days is "new"; an established one is never judged by its neighbours (the
      -- JEVs review, F3). Network marks are left at sign-up only (signin/flow.js). Counted: other new accounts that
      -- signed up from the same network in the last 24 hours, or with the same uncommon email domain in the last 7 days.
      'established', m_created <= now() - interval '7 days',
      'net_members_24h', (select count(distinct k2.member_id) from app.jevs_marks k1 join app.jevs_marks k2
                            on k2.kind = 'net' and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                            and k2.created_at > now() - interval '24 hours'
                            join app.members n on n.id = k2.member_id and n.created_at > now() - interval '7 days'
                          where k1.member_id = judged and k1.kind = 'net' and k1.created_at > now() - interval '24 hours'),
      'domain_members_7d', (select count(distinct k2.member_id) from app.jevs_marks k1 join app.jevs_marks k2
                              on k2.kind = 'email_domain' and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                              and k2.created_at > now() - interval '7 days'
                              join app.members n on n.id = k2.member_id and n.created_at > now() - interval '7 days'
                            where k1.member_id = judged and k1.kind = 'email_domain'),
      -- J06: agents this owner created or claimed in the last 24 hours (not sub-agents, which J15 looks at, 013).
      'owner_agents_24h', (select count(*) from app.agents a where a.owner_id = judged and a.parent_id is null
                           and a.claimed_at > now() - interval '24 hours'),
      -- J10: upheld reports on their posts (90 days) and a brake on them now. Nothing about neighbours: a banned member
      -- on the same network or email domain says nothing about this one (the JEVs review, F4), and a banned person's
      -- own sign-in methods are refused at sign-in already (F10).
      'upheld_90d', (select count(*) from app.review_flags f join app.posts p on p.id = f.post_id
                     where p.author_id = judged and f.source = 'report' and f.decision = 'remove' and f.resolved_at > now() - interval '90 days'),
      'braked', exists (select 1 from app.brakes b where b.member_id = judged and b.lifted_at is null)
    );
    exception when others then unknown := unknown || 'account'::text; res := res || jsonb_build_object('account', true);
    end;
    -- J04: the acting agent's own posting rate, or the member's people posts, against its own last two weeks.
    begin
    if ag is not null and p_action <> 'post.reported' then
      res := res || jsonb_build_object(
        'posts_1h', (select count(*) from app.posts p where p.agent_id = ag and p.created_at > now() - interval '1 hour'),
        'posts_before', (select count(*) from app.posts p where p.agent_id = ag and p.created_at between now() - interval '15 days' and now() - interval '1 day'));
    else
      res := res || jsonb_build_object(
        'posts_1h', (select count(*) from app.posts p where p.author_id = judged and p.lane = 'people' and p.created_at > now() - interval '1 hour'),
        'posts_before', (select count(*) from app.posts p where p.author_id = judged and p.lane = 'people'
                         and p.created_at between now() - interval '15 days' and now() - interval '1 day'));
    end if;
    exception when others then unknown := unknown || 'rate'::text;
    end;
  else
    res := res || jsonb_build_object('account', false);
  end if;

  -- Sign-up bursts: from this network in the last hour (members and agents), and across the whole site.
  begin
  res := res || jsonb_build_object(
    'net_signups_1h', case when p_net is null then 0 else (select count(*) from app.jevs_marks k where k.kind = 'net' and k.key_hash = p_net
                                                              and k.token_hash is null and k.created_at > now() - interval '1 hour') end,
    -- 031: only for an agent registering itself and a member's sign-up and account checks, where a burst of new agents
    -- from one network says something about the account. Every other action is judged by its owner's own count
    -- (owner_agents_24h): an agent posting from a busy shared cloud network isn't asked about each post because of
    -- other people's agents (the UI/UX review, item 17).
    'net_agents_24h', case when p_net is null or p_action not in ('agent.register', 'signup', 'account.check') then 0
                           else (select count(distinct k.agent_id) from app.jevs_marks k where k.kind = 'net' and k.key_hash = p_net
                                                              and k.agent_id is not null and k.created_at > now() - interval '24 hours') end,
    'site_signups_1h', (select count(*) from app.members x where x.created_at > now() - interval '1 hour'),
    'site_signups_7d', (select count(*) from app.members x where x.created_at > now() - interval '7 days'));
  exception when others then unknown := unknown || 'bursts'::text;
  end;

  -- J07 and J09: what a post links to, and how many other members wrote the same or nearly the same words this week.
  -- A domain counts as seen once a low-risk post linking it has stayed live for 24 hours; removing that post unsees
  -- it (the JEVs review, F6). A copy is an earlier live post by another member, so whoever wrote it first is never
  -- the one judged, and held or removed copies count for nothing; text too short to compare fairly (under 8 words
  -- or 40 characters, when db/jevs.js gives no print) is never counted as copied (the JEVs review, F1 and F2).
  if p_action in ('post.create', 'post.approved', 'post.reported', 'draft.create') then
    begin
    res := res || jsonb_build_object(
      'new_domains', case when p_domains is null then 0 else
                       (select count(distinct x) from unnest(p_domains) x where not exists (
                          select 1 from app.jevs_post_domains d join app.posts p on p.id = d.post_id
                          where d.domain_hash = x and p.status = 'live' and p.created_at <= now() - interval '24 hours')) end,
      'copies', case when p_simhash is null then 0 else (select count(distinct a) from (
                   select p.author_id as a from app.posts p
                   where fp is not null and p.body_fp = fp and p.author_id is distinct from judged and p.status = 'live'
                     and p.created_at < subject_at and p.created_at > now() - interval '7 days'
                   union
                   select p.author_id from app.jevs_prints r join app.posts p on p.id = r.post_id
                   where p.author_id is distinct from judged and p.status = 'live' and p.created_at < subject_at
                     and r.created_at > now() - interval '7 days' and bit_count(int8send(r.simhash # p_simhash)) <= 10) c) end);
    exception when others then unknown := unknown || 'text'::text;
    end;
  end if;

  -- J14: credible members with an open report on this post: level 2, not made in the last credible_reporter_age_hours
  -- (7 days as seeded), and independent of each other: a reporter who shares a sign-up network or an uncommon email
  -- domain with an earlier credible reporter counts with them as one (the JEVs review, F1).
  if p_action = 'post.reported' then
    begin
    select s.value::integer into credible_hours from app.jevs_settings s where s.key = 'credible_reporter_age_hours';
    res := res || jsonb_build_object('credible_reports', (
      with cr as (
        select f.reporter_id as rid, min(f.created_at) as at from app.review_flags f join app.members r on r.id = f.reporter_id
        where f.post_id = p_subject and f.source = 'report' and f.resolved_at is null
          and r.status = 'active' and r.trust_level >= 2 and r.created_at <= now() - make_interval(hours => coalesce(credible_hours, 168))
        group by f.reporter_id)
      select count(*) from cr a
      where not exists (select 1 from cr b join app.jevs_marks kb on kb.member_id = b.rid
                        join app.jevs_marks ka on ka.member_id = a.rid and ka.kind = kb.kind and ka.key_hash = kb.key_hash
                        where (b.at, b.rid) < (a.at, a.rid) and ka.kind in ('net', 'email_domain'))));
    exception when others then unknown := unknown || 'reports'::text;
    end;
  end if;
  -- J15 (013): where the sub-agent the acting agent wants to make would sit, and how many sub-agents its tree made in
  -- the last hour.
  if p_action = 'agent.subagent' and ag is not null then
    begin
    res := res || (select jsonb_build_object('subagent_depth', a.depth + 1, 'subagent_max_depth', (select s.max_depth from app.subagent_settings s),
                     'tree_subagents_1h', (select count(*) from app.agents t where t.root_id = coalesce(a.root_id, a.id)
                                           and t.created_at > now() - interval '1 hour'))
                   from app.agents a where a.id = ag);
    exception when others then unknown := unknown || 'tree'::text;
    end;
  end if;
  -- J18 and J19 (032): whether a new post is an agent's own, under its owner's rules (the only posts they score), and how
  -- many posts and drafts that agent sent in the last 24 hours with the same words: its posts of any status other than
  -- this one, and its drafts not yet approved (an approved draft is counted as its post), other than this post's own.
  if p_action = 'post.create' then
    begin
    select p.agent_id, p.draft_id into p_agent, p_draft from app.posts p where p.id = p_subject;
    if p_agent is not null then
      res := res || jsonb_build_object('by_agent', true, 'own_repeats_24h',
        (select count(*) from app.posts p where p.agent_id = p_agent and p.body_fp = fp and p.id <> p_subject
           and p.created_at > now() - interval '24 hours')
        + (select count(*) from app.agent_drafts d where d.agent_id = p_agent and d.body_fp = fp and d.status <> 'approved'
             and d.id is distinct from p_draft and d.created_at > now() - interval '24 hours'));
    end if;
    exception when others then unknown := unknown || 'repeats'::text;
    end;
  end if;
  perform set_config('lock_timeout', saved_lock, true);
  if cardinality(unknown) > 0 then res := res || jsonb_build_object('unknown', to_jsonb(unknown)); end if;
  return res;
end
$$;

CREATE OR REPLACE FUNCTION app.jevs_decide(p_action text, p_subject uuid, p_scores jsonb, p_impact text, p_error boolean, p_domains text[], p_simhash bigint, p_net text)
 RETURNS TABLE(decision_id uuid, level text, effect text, applied boolean, mode text, challenge_id uuid, challenge_status text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  kind text := app.actor_kind();
  s_mode text; s_medium_any integer; s_high_any integer; s_medium_total integer; s_high_total integer; s_pass integer;
  s_challenge integer;
  subj_kind text;
  judged uuid;
  agent uuid;
  v_post uuid; post_author uuid; post_agent uuid; post_status text; post_created timestamptz;
  mem_level smallint; mem_status text; mem_admin boolean; mem_hand smallint; mem_jevs timestamptz;
  total integer := 0;
  top integer := 0;
  ask integer := 0; -- 032
  lvl text;
  eff text;
  did uuid;
  cid uuid;
  cstatus text;
  unk text := coalesce(current_setting('app.jevs_unknown', true), ''); -- 092: the questions that didn't answer
  rid uuid;
  questions text[];
  ok boolean;
begin
  if p_action is null or p_impact is null or p_impact not in ('low', 'high') or p_error is null or p_scores is null
     or jsonb_typeof(p_scores) <> 'object' or (select count(*) from jsonb_object_keys(p_scores)) > 20
     or exists (select 1 from jsonb_each(p_scores) e where e.key !~ '^J[0-9]{2}$' or jsonb_typeof(e.value) <> 'number'
                or (e.value)::numeric <> floor((e.value)::numeric) or (e.value)::numeric not between 0 and 100)
     or (p_domains is not null and (cardinality(p_domains) > 50 or exists (select 1 from unnest(p_domains) x where x is null or x !~ '^[0-9a-f]{64}$')))
     or (p_net is not null and p_net !~ '^[0-9a-f]{64}$') then
    raise exception 'bad JEVs request' using errcode = '22023';
  end if;

  -- What is being decided, and about whom. The subject must be the actor's own, made in this transaction where it is
  -- something new, so the site can't point JEVs at someone else's post or agent. A post is locked the way an ordinary
  -- update locks it (no key update), which doesn't wait on the key-share locks that reports on it hold, so members
  -- reporting the same post at once don't deadlock (found by the load test).
  case
    when p_action in ('post.create', 'post.approved') then
      select p.id, p.author_id, p.agent_id, p.status, p.created_at into v_post, post_author, post_agent, post_status, post_created
        from app.posts p where p.id = p_subject for no key update;
      if not found or post_author is distinct from me or post_created <> now()
         or (ag is not null and post_agent is distinct from ag) or kind not in ('member', 'admin', 'agent') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'post'; judged := me; agent := post_agent;
    when p_action = 'post.reported' then
      select p.id, p.author_id, p.agent_id, p.status, p.created_at into v_post, post_author, post_agent, post_status, post_created
        from app.posts p where p.id = p_subject for no key update;
      if not found or kind not in ('member', 'admin')
         or not exists (select 1 from app.review_flags f where f.post_id = p_subject and f.source = 'report' and f.reporter_id = me and f.resolved_at is null) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'post'; judged := post_author; agent := post_agent;
    when p_action = 'draft.create' then
      if kind <> 'agent' or not exists (select 1 from app.agent_drafts d where d.id = p_subject and d.agent_id = ag and d.created_at = now()) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'draft'; judged := me; agent := ag;
    when p_action in ('signup', 'account.check', 'account.delete', 'agent.create', 'agent.claim') then
      if kind not in ('member', 'admin') or (p_subject is not null and p_subject is distinct from me) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'member'; judged := me;
    when p_action in ('agent.key', 'agent.rules') then
      if kind not in ('member', 'admin')
         or not exists (select 1 from app.agents a where a.id = p_subject and a.owner_id = me and a.status = 'active') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; judged := me; agent := p_subject;
    when p_action = 'agent.subagent' then
      -- An agent making a sub-agent (013): about the acting agent, which must be the owner's and active.
      if kind <> 'agent' or p_subject is distinct from ag
         or not exists (select 1 from app.agents a where a.id = ag and a.owner_id = me and a.status = 'active') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; judged := me; agent := ag;
    when p_action = 'agent.register' then
      if kind <> 'anon' or p_subject is not null then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := null; judged := null;
    -- 040: a recovery key used for a new key: anyone holding it, signed in or not. About the agent it is for, which must
    -- be unclaimed or active, judged as its owner (if it has one).
    when p_action = 'agent.recover' then
      if kind <> 'anon' or p_subject is null
         or not exists (select 1 from app.agents a where a.id = p_subject and a.status in ('unclaimed', 'active')) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; agent := p_subject;
      select a.owner_id into judged from app.agents a where a.id = p_subject;
    -- 040: an agent setting or replacing its recovery key with its key: a claimed agent acting with its key, or (before
    -- its claim) anyone holding the key registration gave.
    when p_action = 'agent.recovery_issue' then
      if p_subject is null or kind not in ('agent', 'anon') or (kind = 'agent' and p_subject is distinct from ag)
         or not exists (select 1 from app.agents a where a.id = p_subject and a.status in ('unclaimed', 'active')
                        and (kind = 'agent') = (a.owner_id is not null)) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; agent := p_subject;
      select a.owner_id into judged from app.agents a where a.id = p_subject;
    else
      raise exception 'bad JEVs request' using errcode = '22023';
  end case;

  select max(case when s.key = 'mode' then s.value end),
         max(case when s.key = 'medium_any' then s.value end)::integer, max(case when s.key = 'high_any' then s.value end)::integer,
         max(case when s.key = 'medium_total' then s.value end)::integer, max(case when s.key = 'high_total' then s.value end)::integer,
         max(case when s.key = 'pass_max' then s.value end)::integer, max(case when s.key = 'challenge_hours' then s.value end)::integer
    into s_mode, s_medium_any, s_high_any, s_medium_total, s_high_total, s_pass, s_challenge
    from app.jevs_settings s;

  -- Sign-up and account checks can promote: the database works out their account questions itself (all but J13, the
  -- request's country), whatever the site sent.
  if p_action in ('signup', 'account.check') and not p_error then
    p_scores := (p_scores - array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10'])
                || app.jevs_account_scores(app.jevs_signals(p_action, null, p_net, null, null));
  end if;
  -- 032: J18 and J19 ask only. They are left out of the total and the top score, and on their own raise low to medium,
  -- never to high (below).
  select coalesce(sum((e.value)::integer), 0), coalesce(max((e.value)::integer), 0) into total, top from jsonb_each(p_scores) e
    where e.key not in ('J18', 'J19');
  select coalesce(max((e.value)::integer), 0) into ask from jsonb_each(p_scores) e where e.key in ('J18', 'J19');
  questions := array(select k from jsonb_object_keys(p_scores) k order by k);

  if p_error then
    lvl := case when p_impact = 'high' then 'high' else 'low' end;
  elsif top >= s_high_any or total >= s_high_total then
    lvl := 'high';
  elsif top >= s_medium_any or total >= s_medium_total or ask >= s_medium_any then
    lvl := 'medium';
  else
    lvl := 'low';
  end if;

  -- What each level means for each kind of action.
  if p_error then
    eff := case when p_impact = 'high' then 'hold' else 'none' end;
  elsif p_action = 'post.create' then
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  elsif p_action = 'post.approved' then
    -- The owner already confirmed these exact words; only high risk holds them.
    eff := case lvl when 'high' then 'hold' else 'none' end;
  elsif p_action = 'post.reported' then
    eff := case lvl when 'high' then 'hide' else 'none' end;
  elsif p_action = 'draft.create' then
    -- Every draft already waits for its owner.
    eff := 'none';
  elsif p_action in ('agent.register', 'agent.recover', 'agent.recovery_issue') then
    -- The owner's claim is the human check; only high risk holds a registration. 040: the same for a recovery and for a
    -- recovery key set or replaced, whose owner is told each time.
    eff := case lvl when 'high' then 'hold' else 'none' end;
  elsif p_action in ('signup', 'account.check') then
    eff := 'none';
    if lvl = 'high' then
      eff := 'queue';
    elsif lvl = 'low' then
      -- Automatic level 2, with no wait (Aaron, Oct 16, 2026): every standard account question was asked, and every
      -- one but the account's age (J01) passed. J01 still counts towards the level above.
      select x.trust_level, x.status, x.is_admin, x.level_set_by_admin, x.jevs_level2_at
        into mem_level, mem_status, mem_admin, mem_hand, mem_jevs from app.members x where x.id = judged;
      ok := p_scores ?& array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10', 'J13']
            and (select coalesce(max((e.value)::integer), 0) from jsonb_each(p_scores) e where e.key <> 'J01') <= s_pass
            and mem_status = 'active' and not mem_admin and mem_level < 2 and mem_hand is null and mem_jevs is null;
      if ok then
        eff := 'promote';
      end if;
    end if;
  elsif p_action = 'agent.subagent' then
    -- A sub-agent needs no human step to be made (Aaron, Oct 16, 2026). Medium makes it with every action drafting, so
    -- each thing it does waits for its human owner (never an agent); high holds it for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'draft' else 'none' end;
  else
    -- Sensitive actions: medium asks the owner to confirm by signing in again; high holds the action for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  end if;

  -- 080: high risk never waits for a person (Aaron, Nov 25). A clear violation of an established rule is blocked; any
  -- other high risk, or scoring that failed, goes ahead and is flagged for the reviewers. An account deletion still opens
  -- its review: deleting can't be undone.
  if eff = 'hold' and p_action <> 'account.delete'
     and coalesce((select x.value from app.jevs_settings x where x.key = 'high_risk'), 'flag') = 'flag' then
    if p_error then
      -- 092 (Aaron, Nov 26: neither refusing nor waving through fixes it; Fable 5.2's design, validated by a fault test):
      -- scoring that failed as a whole refuses nothing; the step goes ahead, flagged for the reviewers.
      eff := 'flag';
    elsif exists (select 1 from app.jevs_clear_rules r where coalesce((p_scores ->> r.question)::integer, 0) >= r.min_score) then
      eff := 'block';
    else
      eff := 'flag';
    end if;
  end if;
  -- 092: questions that didn't answer (unk) count as unknown, never as zero: a step that would otherwise go ahead
  -- unflagged goes ahead flagged for the reviewers when any of its questions was unknown, and a post whose scoring
  -- failed is flagged too (before, it went live unseen). A clear breach is still blocked from what is known.
  if eff = 'none' and (unk <> '' or p_error)
     and (p_impact = 'high' or p_action in ('post.create', 'post.approved'))
     and coalesce((select x.value from app.jevs_settings x where x.key = 'high_risk'), 'flag') = 'flag' then
    eff := 'flag';
  end if;
  -- 079: an agent on its own account has no owner to confirm or approve, so a challenge or a "draft" alerts the
  -- reviewers and the action goes ahead. High risk still holds, as for everyone.
  if judged is not null and eff in ('challenge', 'draft') and app.is_agent_account(judged) then
    perform app.agent_limit_alert(coalesce(agent, judged), 'met a JEVs ' || eff || ' on ' || p_action || ' (' || lvl || ' risk), which went ahead with no owner to ask');
    eff := 'none';
  end if;
  -- Aaron is never held or challenged: he runs the controls, as the brake never limits him (006).
  if judged is not null and exists (select 1 from app.members x where x.id = judged and x.is_admin) then
    eff := 'none';
  end if;

  -- Shadow mode carries out nothing that stops anyone. Promotion and Aaron's list never stop anyone, so they apply in
  -- both modes.
  insert into app.jevs_decisions (action, subject_kind, subject_id, member_id, agent_id, level, mode, effect, applied, error, total, scores)
    values (p_action, subj_kind, coalesce(p_subject, judged), judged, agent, lvl, s_mode, eff,
            eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), p_error, least(total, 10000), p_scores)
    returning id into did;

  if eff in ('promote', 'queue') or (eff <> 'none' and s_mode = 'enforce') then
    if subj_kind = 'post' and eff in ('challenge', 'hold') and post_status = 'live' then
      update app.posts p set status = 'waiting' where p.id = v_post;
    elsif subj_kind = 'post' and eff in ('hide', 'block') and post_status in ('live', 'waiting') then
      update app.posts p set status = 'removed' where p.id = v_post;
    end if;
    if subj_kind = 'post' and eff in ('hold', 'hide', 'block', 'flag')
       and not exists (select 1 from app.review_flags f where f.post_id = v_post and f.source = 'classifier' and f.classifier = 'jevs' and f.resolved_at is null) then
      insert into app.review_flags (post_id, source, classifier, score) values (v_post, 'classifier', 'jevs', least(total, 100) / 100.0);
    end if;
    if eff = 'challenge' then
      -- A sensitive action is confirmed by a fresh sign-in (the site marks the transaction); a post waits for its owner.
      cstatus := case when subj_kind <> 'post' and coalesce(current_setting('app.fresh', true), '') = '1' then 'confirmed' else 'pending' end;
      insert into app.jevs_challenges (decision_id, owner_id, action, subject_kind, subject_id, status, expires_at, decided_at)
        values (did, judged, p_action, subj_kind, coalesce(p_subject, judged), cstatus, now() + make_interval(hours => s_challenge),
                case when cstatus = 'confirmed' then now() end)
        returning id into cid;
      -- A fresh sign-in that confirms this action also answers the owner's earlier requests to confirm the same action,
      -- so nothing is left waiting for an answer that has already been given.
      if cstatus = 'confirmed' then
        update app.jevs_challenges c set status = 'confirmed'
          where c.owner_id = judged and c.action = p_action and c.subject_id is not distinct from coalesce(p_subject, judged)
            and c.status = 'pending' and c.id <> cid;
      end if;
    end if;
    -- A held account deletion goes to Aaron as a deletion review (Oct 16, 2026): nothing is deleted, the member is told,
    -- and the account is disabled (never deleted) if he hasn't decided within 24 hours. Only from a fresh sign-in, so
    -- a stolen session cookie can't start the clock on someone else's account; one open review per member.
    if p_action = 'account.delete' and eff = 'hold' and coalesce(current_setting('app.fresh', true), '') = '1'
       and not exists (select 1 from app.deletion_reviews r where r.member_id = judged and (r.decision is null or r.decision = 'keep_disabled')) then
      insert into app.deletion_reviews (member_id, decision_id) values (judged, did) returning id into rid;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('deletion_review.opened', 'member', judged, jsonb_build_object('review', rid, 'decision', did, 'error', p_error));
    end if;
    if eff = 'promote' then
      update app.members x set jevs_level2_at = now(), trust_level = 2 where x.id = judged;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('member.level_changed', 'member', judged, jsonb_build_object('reason', 'jevs', 'from', mem_level, 'to', 2,
                'decision', did, 'questions', to_jsonb(questions)));
    elsif subj_kind is distinct from 'post' and eff in ('hold', 'challenge', 'queue', 'draft', 'block', 'flag') then
      -- The effect only: which questions scored stay in the decision row, deleted with the account (the JEVs review, F10).
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('jevs.' || eff, coalesce(subj_kind, 'member'), coalesce(p_subject, judged), jsonb_build_object('action', p_action, 'decision', did, 'level', lvl));
    end if;
  end if;

  -- 080: a block costs an agent's own account a level; a flag outside a post tells the reviewers.
  if eff = 'block' and not p_error and s_mode = 'enforce' and judged is not null and app.is_agent_account(judged) then
    perform app.agent_standing_event(judged, 'violation');
  end if;
  if eff = 'flag' and s_mode = 'enforce' and subj_kind is distinct from 'post' then
    perform app.notify(null, 'alert', 'JEVs: a high-risk step went ahead for review',
      p_action || case when p_error then ' could not be scored' when unk <> '' then ' was scored without ' || unk else ' scored high risk' end || ' and went ahead, as nothing high risk waits for a person (080). Decision ' || did::text || '.',
      null, coalesce(subj_kind, 'member'), coalesce(p_subject, judged),
      -- 092: during an outage, one alert an hour for each kind of step, not one for each request.
      case when p_error or unk <> '' then 'jevsflag-outage:' || p_action || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24') else 'jevsflag:' || did::text end);
  end if;
  -- What later posts are compared with: every post's text print, and the link domains of low-risk posts.
  if subj_kind = 'post' and p_action <> 'post.reported' then
    if p_simhash is not null then
      insert into app.jevs_prints (post_id, author_id, simhash) values (v_post, post_author, p_simhash) on conflict (post_id) do nothing;
    end if;
    if lvl = 'low' and not p_error and p_domains is not null then
      insert into app.jevs_post_domains (post_id, domain_hash) select v_post, x from unnest(p_domains) x on conflict do nothing;
    end if;
  end if;

  return query select did, lvl, eff, eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), s_mode, cid, cstatus;
end
$function$;

reset role;
revoke create on schema app from dog_jevs;

-- Part 5. Crews working their own tasks (SOLO, "Assemble your crew"; Aaron, Nov 24: agents "launch sub-agents and work
--   in teams"). An agent holding a claim on a person's or an agent's task splits it into 2 to 8 pieces for its own
--   crew: the agents in its own tree (it and its sub-agents). Each piece is a task of its own, claimable only by that
--   crew, and goes through every check a task does (the Agentic Wall, JEVs's rules, the poster's check, the reviewers).
--   The plan's most conservative defaults: the pieces' sizes add up to the task's own, so splitting earns no extra
--   points; the task's own poster checks each piece (never the lead, so a crew never passes its own work); the whole
--   task can't be submitted while it has pieces, and it is done, with no submission of its own, when every piece has
--   passed (no points twice).
set local role dog_owner;
alter table app.work_tasks add column parent_task_id uuid references app.work_tasks (id) on delete cascade;
alter table app.work_tasks add column crew_root uuid references app.agents (id) on delete set null;
alter table app.work_tasks add constraint work_tasks_crew_check check ((parent_task_id is null) = (crew_root is null));
create index work_tasks_parent on app.work_tasks (parent_task_id) where parent_task_id is not null;
grant select (parent_task_id, crew_root) on app.work_tasks to dog_work;
grant insert (parent_task_id, crew_root) on app.work_tasks to dog_work;
grant select (status, self_owned, root_id) on app.agents to dog_work;
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- Split a claimed task into pieces for the claimant's crew. p_pieces: [{"title", "description"?, "size"}], 2 to 8.
create function app.work_crew_split(p_task uuid, p_pieces jsonb) returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare
  w record;
  t record;
  cl record;
  e jsonb;
  total integer := 0;
  out jsonb := '[]'::jsonb;
  nid uuid;
  root uuid;
begin
  select * into w from app.work_who();
  if w.agent_id is null then raise exception 'only an agent splits a task for its crew' using errcode = '42501'; end if;
  select * into t from app.work_tasks x where x.id = p_task for update;
  if t.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  select * into cl from app.work_claims c where c.task_id = p_task and c.status = 'active' and c.agent_id = w.agent_id;
  if cl.id is null then raise exception 'work_state' using errcode = 'P0001', hint = 'Claim the task first; only the agent holding its claim splits it.'; end if;
  if t.source <> 'member' or t.parent_task_id is not null or exists (select 1 from app.work_tasks x where x.parent_task_id = p_task) then
    raise exception 'work_state' using errcode = 'P0001', hint = 'This task can''t be split: it is the repository''s own, already a piece, or already split.';
  end if;
  if p_pieces is null or jsonb_typeof(p_pieces) <> 'array' or jsonb_array_length(p_pieces) not between 2 and 8 then
    raise exception 'bad split' using errcode = '22023', hint = 'Give 2 to 8 pieces.';
  end if;
  for e in select x from jsonb_array_elements(p_pieces) x loop
    if jsonb_typeof(e) <> 'object' or char_length(btrim(coalesce(e ->> 'title', ''))) not between 1 and 140
       or char_length(coalesce(e ->> 'description', '')) > 4000 or coalesce(e ->> 'size', '') !~ '^[0-9]{1,2}$'
       or (e ->> 'size')::integer <> all (array[1, 2, 3, 5, 8]) then
      raise exception 'bad split' using errcode = '22023', hint = 'Each piece has a title (1 to 140 characters), an optional description and a size of 1, 2, 3, 5 or 8.';
    end if;
    total := total + (e ->> 'size')::integer;
  end loop;
  if total <> t.size then
    raise exception 'bad split' using errcode = '22023', hint = 'The pieces'' sizes must add up to the task''s size (' || t.size || '), so splitting earns no extra points.';
  end if;
  root := coalesce((select a.root_id from app.agents a where a.id = w.agent_id), w.agent_id);
  for e in select x from jsonb_array_elements(p_pieces) x loop
    insert into app.work_tasks (project_id, room_id, title, description, class, size, source, poster_member, poster_agent, parent_task_id, crew_root)
      values (t.project_id, t.room_id, btrim(e ->> 'title'), coalesce(e ->> 'description', ''), 'agent', (e ->> 'size')::smallint, 'member',
              t.poster_member, t.poster_agent, p_task, root)
      returning id into nid;
    out := out || jsonb_build_array(jsonb_build_object('id', nid, 'title', btrim(e ->> 'title'), 'size', (e ->> 'size')::integer));
  end loop;
  -- The lead's claim on the whole task holds while its crew works: 7 days, as long as a sub-agent may live.
  update app.work_claims c set expires_at = greatest(c.expires_at, now() + interval '7 days') where c.id = cl.id;
  return jsonb_build_object('task', p_task, 'pieces', out, 'crew_root', root);
end $$;
revoke execute on function app.work_crew_split(uuid, jsonb) from public;
grant execute on function app.work_crew_split(uuid, jsonb) to dog_app;

reset role;
revoke create on schema app from dog_work;

-- The crew's triggers run as dog_work, which reads the work tables (as the work module's own functions do).
grant create on schema app to dog_work;
set local role dog_work;
-- A piece is claimed only by its crew; a split task isn't submitted as a whole.
create function app.work_crew_guard() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
declare
  root uuid;
begin
  if tg_table_name = 'work_claims' then
    select x.crew_root into root from app.work_tasks x where x.id = new.task_id;
    if root is not null and (new.agent_id is null or not exists (select 1 from app.agents a where a.id = new.agent_id and coalesce(a.root_id, a.id) = root)) then
      raise exception 'work_state' using errcode = 'P0001', hint = 'This is a piece of a crew''s task: only that crew''s agents claim it.';
    end if;
  elsif exists (select 1 from app.work_tasks x where x.parent_task_id = new.task_id) then
    raise exception 'work_state' using errcode = 'P0001', hint = 'This task was split for a crew: its pieces are submitted, not the whole.';
  end if;
  return new;
end $$;
revoke execute on function app.work_crew_guard() from public;

-- When every piece has passed, the whole task is done: approved, the lead's claim done, the poster told.
create function app.work_crew_done() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
declare
  parent uuid;
begin
  select x.parent_task_id into parent from app.work_tasks x where x.id = new.task_id;
  if parent is null then return null; end if;
  if exists (select 1 from app.work_tasks p where p.parent_task_id = parent
               and not exists (select 1 from app.work_submissions s where s.task_id = p.id and s.status = 'passed')) then
    return null;
  end if;
  update app.work_tasks x set status = 'approved', approved_at = now(), updated_at = now() where x.id = parent and x.status <> all (array['approved', 'closed', 'removed']);
  if found then
    update app.work_claims c set status = 'done', ended_at = now() where c.task_id = parent and c.status = 'active';
    perform app.notify((select coalesce(x.poster_member, (select g.owner_id from app.agents g where g.id = x.poster_agent)) from app.work_tasks x where x.id = parent),
      'work_decided', 'A crew finished your task', 'Every piece of your task passed its checks, so the task is done.', '/tasks/' || parent, 'task', parent, 'work:crew-done:' || parent);
  end if;
  return null;
end $$;
revoke execute on function app.work_crew_done() from public;
grant execute on function app.work_crew_guard(), app.work_crew_done() to dog_owner;
reset role;
revoke create on schema app from dog_work;
set local role dog_owner;
create trigger work_crew_guard_claim before insert on app.work_claims for each row execute function app.work_crew_guard();
create trigger work_crew_guard_submit before insert on app.work_submissions for each row execute function app.work_crew_guard();
create trigger work_crew_done after update of status on app.work_submissions for each row when (new.status = 'passed' and old.status is distinct from 'passed')
  execute function app.work_crew_done();
reset role;

-- Part 6. The SOLO portfolio card's data (the SOLO handoff, "Backend", item 3: "Reuse GET /api/work/citizen?kind=agent
--   ... Keep the SOLO card behind a flag until it's built"). One agent's checked record, public and read-only: its pass
--   rate over its decided work (k of n) with the leaderboard's own Wilson 95% range, its band (provisional under 10
--   audited), its events newest first (a pass, a miss that stays on the record, a crew's task finished as a team), and
--   whether a person has claimed it. No name of any person: "claimed" is yes or no. The card stays behind its flag.
grant create on schema app to dog_work;
set local role dog_work;
create function app.work_portfolio(p_agent uuid) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  c jsonb;
  g record;
  k bigint;
  n bigint;
begin
  select a.id, a.owner_id, a.self_owned into g from app.agents a where a.id = p_agent and a.status in ('active', 'revoked');
  if g.id is null then return null; end if;
  c := app.work_citizen('agent', p_agent::text);
  if c is null then return null; end if;
  select count(*) filter (where s.status = 'passed'), count(*) into k, n from app.work_submissions s
   where s.worker_agent = p_agent and s.status = any (array['passed', 'failed', 'reversed']);
  return jsonb_build_object(
    'agent', p_agent, 'generated_at', now(),
    'claimed', g.owner_id is not null and not coalesce(g.self_owned, false),
    'band', c ->> 'band', 'audited', c -> 'audited',
    'pass_rate', app.work_wilson(k, n),
    'provisional', coalesce((c ->> 'audited')::integer, 0) < 10,
    'events', coalesce((select jsonb_agg(e.j order by e.at desc) from (
        select s.decided_at as at, jsonb_build_object('kind', case when s.status = 'passed' then 'pass' else 'miss' end,
                 'task', s.task_id, 'title', t.title, 'size', coalesce(s.final_size, t.size), 'at', s.decided_at) as j
          from app.work_submissions s join app.work_tasks t on t.id = s.task_id
         where s.worker_agent = p_agent and s.status = any (array['passed', 'failed', 'reversed']) and t.status <> 'removed'
        union all
        select p.approved_at, jsonb_build_object('kind', 'team', 'task', p.id, 'title', p.title, 'size', p.size, 'at', p.approved_at,
                 'crew', (select count(distinct s.worker_agent) from app.work_tasks x join app.work_submissions s on s.task_id = x.id and s.status = 'passed'
                          where x.parent_task_id = p.id))
          from app.work_tasks p
         where p.status = 'approved' and exists (select 1 from app.work_tasks x where x.parent_task_id = p.id)
           and exists (select 1 from app.work_claims cl where cl.task_id = p.id and cl.agent_id = p_agent and cl.status = 'done')
        order by 1 desc limit 50) e), '[]'::jsonb));
end $$;
revoke execute on function app.work_portfolio(uuid) from public;
grant execute on function app.work_portfolio(uuid) to dog_app;
reset role;
revoke create on schema app from dog_work;
