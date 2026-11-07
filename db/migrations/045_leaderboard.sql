-- 045 The leaderboard and citizen profiles (CODING_AGENT_SPEC.md 4.1, 4.2, 4.4, 4.5): a weak prior, not a verdict.
--   * No single number. Each citizen (a member, an agent, or a GitHub account credited with this repository's history)
--     has six dimensions, each with its sample size, and every rate with its Wilson 95% interval:
--       1. Impact: final points, each weighted by 0.5 ^ (its age in days / 30) (a 30-day half-life, Agent Points'
--          computeScore), with the all-time total, the season's (a calendar quarter) and the points still pending.
--       2. Calibration (people who checked work): of the passes they gave that have settled (points final, or the pass
--          reversed), the share that held. Fails are never checked again, so they can't be scored.
--       3. Reliability: of the claims that ended, the share that ended in passed work (released, expired or reversed
--          count against).
--       4. Revert rate: of their passes, the share reversed (public).
--       5. Disputes: opened, upheld and dismissed; received, and upheld against them.
--       6. Breadth: the rooms they have passed work in.
--   * Bands, not ranks: Provisional under 10 audited items; past that, by the chosen dimension among the board's
--     established citizens, Top 10%, Strong (the next 25%) or Established. An exact place only in the top 10. Rates sort
--     by their interval's cautious end (the lower end; for the revert rate, the upper end, lowest first), so a few
--     lucky items don't top a board.
--   * From my network (signed in): trust from the viewer along audited collaborations (a task one citizen posted and
--     another did, passed by the JEVs auditor's rules or an administrator, so a third party checked it; never two
--     citizens of one owner), halved at each hop, at most 3 hops, split by each citizen's collaborations. Accounts that
--     only work with each other get nothing from an honest viewer (MeritRank's idea; the spec's acceptance test).
--   * The integrity panel: reciprocal passes between posters (two members passing each other's work within 30 days),
--     checks after and what they found, disputes, reversals and points removed.
-- Everything here reads what the work module already keeps and is public on its pages; nothing new is stored. All of
-- it is this module's (dog_work) and read-only.


-- Owned by dog_owner, as everything in app that isn't a security-definer function: the figures' row type and two
-- plain helpers the module's functions call.
set local role dog_owner;
create type app.work_stat as (kind text, ref text, impact numeric, pending bigint, all_time bigint, season bigint, items bigint, audited bigint,
  cal_k bigint, cal_n bigint, rel_k bigint, rel_n bigint, rev_k bigint, rev_n bigint,
  d_opened bigint, d_upheld bigint, d_dismissed bigint, d_received bigint, d_against bigint, rooms bigint);

-- A rate with its Wilson 95% interval (z = 1.96), or null with no sample.
create function app.work_wilson(k bigint, n bigint)
returns jsonb
language sql immutable set search_path = pg_catalog
as $$
  select case when n is null or n <= 0 then jsonb_build_object('k', coalesce(k, 0), 'n', 0, 'rate', null, 'lo', null, 'hi', null)
  else (select jsonb_build_object('k', k, 'n', n, 'rate', round(p::numeric, 4),
                                  'lo', round(greatest(0, (p + z * z / (2 * n) - z * sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / (1 + z * z / n))::numeric, 4),
                                  'hi', round(least(1, (p + z * z / (2 * n) + z * sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / (1 + z * z / n))::numeric, 4))
        from (select k::float8 / n as p, 1.96::float8 as z) v) end
$$;

-- The value a board sorts by, highest first (the revert rate is negated: lowest first).
create function app.work_sort_value(p_sort text, s app.work_stat)
returns numeric
language sql stable set search_path = pg_catalog
as $$
  select case p_sort
    when 'impact' then coalesce(s.impact, 0)
    when 'season' then coalesce(s.season, 0)
    when 'all_time' then coalesce(s.all_time, 0)
    when 'calibration' then coalesce((app.work_wilson(s.cal_k, s.cal_n) ->> 'lo')::numeric, -1)
    when 'reliability' then coalesce((app.work_wilson(s.rel_k, s.rel_n) ->> 'lo')::numeric, -1)
    when 'revert' then coalesce(-(app.work_wilson(s.rev_k, s.rev_n) ->> 'hi')::numeric, -2)
    when 'breadth' then coalesce(s.rooms, 0)
  end
$$;

revoke execute on function app.work_wilson(bigint, bigint), app.work_sort_value(text, app.work_stat) from public;
grant execute on function app.work_wilson(bigint, bigint), app.work_sort_value(text, app.work_stat) to dog_work;

grant create on schema app to dog_work;
set local role dog_work;

-- Every citizen's figures. p_room limits the impact figures (impact, pending, all-time, season, items) to one room;
-- the other dimensions are always the citizen's whole record. kind is member, agent or github; ref its ID or login.
create function app.work_stats(p_room uuid)
returns setof app.work_stat
language sql stable security definer set search_path = pg_catalog
as $$
  with sub as (
    select s.id, s.status, s.decided_by, s.worker_kind as kind,
           case s.worker_kind when 'member' then s.worker_member::text when 'agent' then s.worker_agent::text else s.worker_github end as ref
      from app.work_submissions s join app.work_tasks t on t.id = s.task_id
     where s.status = any (array['passed', 'failed', 'reversed']) and t.status <> 'removed'),
  pts as (
    select p.citizen_kind as kind,
           case p.citizen_kind when 'member' then p.citizen_member::text when 'agent' then p.citizen_agent::text else p.citizen_github end as ref,
           p.points, p.status, p.created_at, p.room_id
      from app.work_points p join app.work_tasks t on t.id = p.task_id
     where p.status <> 'removed' and t.status <> 'removed'),
  rows as (
    -- Impact (in the room, when one is chosen).
    select x.kind, x.ref,
           sum(case when x.status = 'final' then x.points * power(0.5, greatest(0, extract(epoch from now() - x.created_at) / 86400) / 30) else 0 end)::numeric as impact,
           sum(x.points) filter (where x.status = 'pending') as pending,
           sum(x.points) filter (where x.status = 'final') as all_time,
           sum(x.points) filter (where x.status = 'final' and x.created_at >= date_trunc('quarter', now())) as season,
           count(*) as items, 0::bigint as audited, 0::bigint as cal_k, 0::bigint as cal_n, 0::bigint as rel_k, 0::bigint as rel_n,
           0::bigint as rev_k, 0::bigint as rev_n, 0::bigint as d_opened, 0::bigint as d_upheld, 0::bigint as d_dismissed,
           0::bigint as d_received, 0::bigint as d_against, 0::bigint as rooms
      from pts x where p_room is null or x.room_id = p_room group by x.kind, x.ref
    union all
    -- Breadth: rooms with passed work, anywhere.
    select x.kind, x.ref, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, count(distinct x.room_id) from pts x group by x.kind, x.ref
    union all
    -- Audited items and the revert rate.
    select s.kind, s.ref, 0, 0, 0, 0, 0, count(*), 0, 0, 0, 0,
           count(*) filter (where s.status = 'reversed'), count(*) filter (where s.status in ('passed', 'reversed')), 0, 0, 0, 0, 0, 0
      from sub s group by s.kind, s.ref
    union all
    -- Calibration: a person's passes as the task's poster or an administrator, once settled.
    select 'member', v.member_id::text, 0, 0, 0, 0, 0, 0,
           count(*) filter (where s.status = 'passed'),
           count(*), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      from app.work_person_votes v join sub s on s.id = v.submission_id
     where v.verdict = 'pass' and v.member_id is not null and s.decided_by in ('poster', 'person')
       and (s.status = 'reversed' or exists (select 1 from app.work_points p where p.submission_id = s.id and p.status = 'final'))
     group by v.member_id
    union all
    -- Reliability: claims that ended, on tasks that weren't removed.
    select case when c.agent_id is null then 'member' else 'agent' end, coalesce(c.agent_id, c.member_id)::text, 0, 0, 0, 0, 0, 0, 0, 0,
           count(*) filter (where c.status = 'done'), count(*), 0, 0, 0, 0, 0, 0, 0, 0
      from app.work_claims c join app.work_tasks t on t.id = c.task_id
     where c.status = any (array['done', 'released', 'expired']) and t.status <> 'removed'
     group by 1, 2
    union all
    -- Disputes opened (people only).
    select 'member', d.member_id::text, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           count(*), count(*) filter (where d.status = 'upheld'), count(*) filter (where d.status = 'dismissed'), 0, 0, 0
      from app.work_disputes d group by d.member_id
    union all
    -- Disputes received on their work.
    select s.kind, s.ref, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           count(*), count(*) filter (where d.status = 'upheld'), 0
      from app.work_disputes d join sub s on s.id = d.submission_id group by s.kind, s.ref)
  select r.kind, r.ref, round(sum(r.impact), 2), sum(r.pending)::bigint, sum(r.all_time)::bigint, sum(r.season)::bigint, sum(r.items)::bigint,
         sum(r.audited)::bigint, sum(r.cal_k)::bigint, sum(r.cal_n)::bigint, sum(r.rel_k)::bigint, sum(r.rel_n)::bigint, sum(r.rev_k)::bigint,
         sum(r.rev_n)::bigint, sum(r.d_opened)::bigint, sum(r.d_upheld)::bigint, sum(r.d_dismissed)::bigint, sum(r.d_received)::bigint,
         sum(r.d_against)::bigint, sum(r.rooms)::bigint
    from rows r where r.ref is not null group by r.kind, r.ref
$$;

-- One citizen's figures as the pages show them.
create function app.work_profile(s app.work_stat)
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select app.work_display(case when s.kind = 'member' then s.ref::uuid end, case when s.kind = 'agent' then s.ref::uuid end,
                          case when s.kind = 'github' then s.ref end)
    || jsonb_build_object(
      'impact', jsonb_build_object('score', coalesce(s.impact, 0), 'pending', coalesce(s.pending, 0), 'all_time', coalesce(s.all_time, 0),
                                   'season', coalesce(s.season, 0), 'n', coalesce(s.items, 0)),
      'audited', coalesce(s.audited, 0),
      'calibration', app.work_wilson(s.cal_k, s.cal_n),
      'reliability', app.work_wilson(s.rel_k, s.rel_n),
      'revert', app.work_wilson(s.rev_k, s.rev_n),
      'disputes', jsonb_build_object('opened', coalesce(s.d_opened, 0), 'upheld', coalesce(s.d_upheld, 0), 'dismissed', coalesce(s.d_dismissed, 0),
                                     'received', coalesce(s.d_received, 0), 'against', coalesce(s.d_against, 0)),
      'breadth', coalesce(s.rooms, 0))
$$;

-- The board: p_kind everyone, people (members and GitHub accounts), agents or auditors (people who checked work);
-- p_room a room code or null; p_sort one dimension. At most 200 rows: the established citizens by the dimension,
-- then the provisional ones by impact.
create function app.work_board(p_kind text, p_room text, p_sort text)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  rid uuid;
  out jsonb;
begin
  if p_kind is null then p_kind := 'everyone'; end if;
  if p_sort is null then p_sort := 'impact'; end if;
  if p_kind <> all (array['everyone', 'people', 'agents', 'auditors'])
     or p_sort <> all (array['impact', 'season', 'all_time', 'calibration', 'reliability', 'revert', 'breadth'])
     or (p_room is not null and p_room !~ '^[0-9]{2}-0000$') then
    raise exception 'bad board' using errcode = '22023';
  end if;
  if p_room is not null then
    select r.id into rid from app.work_rooms r where r.code = p_room;
    if rid is null then raise exception 'bad board' using errcode = '22023'; end if;
  end if;
  with s as (
    select x as st, x.kind, x.ref, x.impact, x.audited from app.work_stats(rid) x
     where (p_kind = 'everyone' or (p_kind = 'people' and x.kind in ('member', 'github')) or (p_kind = 'agents' and x.kind = 'agent')
            or (p_kind = 'auditors' and x.kind = 'member' and x.cal_n > 0))
       and (rid is null or x.items > 0)
       and case x.kind when 'member' then exists (select 1 from app.members m where m.id = x.ref::uuid and m.status = 'active')
                       when 'agent' then exists (select 1 from app.agents g where g.id = x.ref::uuid) else true end),
  v as (select s.*, app.work_sort_value(p_sort, s.st) as val, s.audited >= 10 as est from s),
  b as (
    select v.*, case when v.est then cume_dist() over (partition by v.est order by v.val desc) end as cd,
           case when v.est then row_number() over (partition by v.est order by v.val desc, v.impact desc, v.ref) end as place
      from v)
  select jsonb_build_object('generated_at', now(), 'kind', p_kind, 'room', p_room, 'sort', p_sort, 'half_life_days', 30,
      'season', to_char(now(), 'YYYY "Q"Q'),
      'citizens', coalesce((select jsonb_agg(app.work_profile(q.st) || jsonb_build_object(
          'band', case when not q.est then 'provisional' when q.cd <= 0.10 then 'top10' when q.cd <= 0.35 then 'strong' else 'established' end,
          'place', case when q.est and q.place <= 10 then q.place end) order by q.est desc, q.val desc, q.impact desc, q.ref)
        from (select * from b order by b.est desc, b.val desc, b.impact desc, b.ref limit 200) q), '[]'::jsonb),
      'counts', jsonb_build_object(
          'people', (select count(*) from v where v.kind in ('member', 'github')),
          'agents', (select count(*) from v where v.kind = 'agent'),
          'established', (select count(*) from v where v.est),
          'median_impact_people', (select percentile_cont(0.5) within group (order by v.impact) from v where v.kind in ('member', 'github')),
          'median_impact_agents', (select percentile_cont(0.5) within group (order by v.impact) from v where v.kind = 'agent')),
      'integrity', app.work_integrity())
    into out;
  return out;
end
$$;

-- The board's integrity panel (spec 4.4): what the checks found, in counts.
create function app.work_integrity()
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  with pp as (
    select distinct v.member_id as poster, s.worker_member as worker
      from app.work_person_votes v join app.work_submissions s on s.id = v.submission_id
     where v.verdict = 'pass' and s.decided_by = 'poster' and v.member_id is not null and s.worker_member is not null
       and v.created_at > now() - interval '30 days' and v.member_id <> s.worker_member)
  select jsonb_build_object(
    'reciprocal_pairs', (select count(*) from pp a join pp b on a.poster = b.worker and a.worker = b.poster where a.poster < a.worker),
    'checks', (select count(*) from app.work_checks),
    'checks_reversed', (select count(*) from app.work_checks k where k.status = 'reversed'),
    'disputes', (select count(*) from app.work_disputes),
    'disputes_upheld', (select count(*) from app.work_disputes d where d.status = 'upheld'),
    'passes_reversed', (select count(*) from app.work_submissions s where s.status = 'reversed'),
    'points_removed', (select coalesce(sum(p.points), 0) from app.work_points p where p.status = 'removed'))
$$;

-- One citizen's profile: kind member, agent or github and its ID or login. Null if there is no such citizen.
create function app.work_citizen(p_kind text, p_ref text)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  s app.work_stat;
  anchored bigint := app.work_anchored_through();
begin
  if p_kind is null or p_ref is null or p_kind <> all (array['member', 'agent', 'github'])
     or (p_kind in ('member', 'agent') and p_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
     or (p_kind = 'github' and p_ref !~ '^[a-z0-9-]{1,39}$') then
    return null;
  end if;
  if p_kind = 'member' then
    if not exists (select 1 from app.members m where m.id = p_ref::uuid and m.status = 'active') then return null; end if;
  elsif p_kind = 'agent' then
    if not exists (select 1 from app.agents g where g.id = p_ref::uuid) then return null; end if;
  end if;
  select x.* into s from app.work_stats(null) x where x.kind = p_kind and x.ref = p_ref;
  if not found then
    if p_kind = 'github' then return null; end if;
    -- A member or agent with no work yet: a provisional profile, not a zero.
    select p_kind as kind, p_ref as ref, 0::numeric as impact, 0::bigint as pending, 0::bigint as all_time, 0::bigint as season,
           0::bigint as items, 0::bigint as audited, 0::bigint as cal_k, 0::bigint as cal_n, 0::bigint as rel_k, 0::bigint as rel_n,
           0::bigint as rev_k, 0::bigint as rev_n, 0::bigint as d_opened, 0::bigint as d_upheld, 0::bigint as d_dismissed,
           0::bigint as d_received, 0::bigint as d_against, 0::bigint as rooms into s;
  end if;
  return jsonb_build_object('generated_at', now(), 'half_life_days', 30, 'season', to_char(now(), 'YYYY "Q"Q'),
    -- Its band on the everyone board by impact, as work_board computes it.
    'band', case when s.audited < 10 then 'provisional' else (
        select case when q.cd <= 0.10 then 'top10' when q.cd <= 0.35 then 'strong' else 'established' end
          from (select (count(*) filter (where x.impact >= s.impact))::float8 / count(*) as cd from app.work_stats(null) x where x.audited >= 10) q) end)
    || app.work_profile(s)
    || jsonb_build_object(
      -- The receipt chain: each audited item, newest first, with the log entries that record it.
      'receipts', coalesce((select jsonb_agg(r.j order by r.at desc, r.seq desc nulls last) from (
          select x.decided_at as at, x.decided_seq as seq, jsonb_build_object('submission', x.id, 'task', jsonb_build_object('id', t.id, 'title', t.title, 'size', t.size),
                   'room', (select jsonb_build_object('code', rm.code, 'name', rm.name) from app.work_rooms rm where rm.id = t.room_id),
                   'status', x.status, 'decided_by', x.decided_by, 'confidence', x.confidence, 'decided_at', x.decided_at,
                   'seq', x.decided_seq, 'anchored', x.decided_seq < anchored, 'submitted_seq', x.submitted_seq,
                   'approved_seq', t.approved_seq,
                   'points', (select jsonb_build_object('points', p.points, 'status', p.status, 'final_at', p.final_at) from app.work_points p where p.submission_id = x.id)) as j
            from app.work_submissions x join app.work_tasks t on t.id = x.task_id
           where x.status = any (array['passed', 'failed', 'reversed']) and t.status <> 'removed'
             and x.worker_kind = p_kind
             and case p_kind when 'member' then x.worker_member::text when 'agent' then x.worker_agent::text else x.worker_github end = p_ref
           order by x.decided_at desc, x.decided_seq desc nulls last limit 50) r), '[]'::jsonb),
      'rooms', coalesce((select jsonb_agg(jsonb_build_object('code', rm.code, 'name', rm.name, 'points', q.pts) order by q.pts desc, rm.code) from (
          select p.room_id, sum(p.points) as pts from app.work_points p
           where p.status <> 'removed' and p.citizen_kind = p_kind
             and case p_kind when 'member' then p.citizen_member::text when 'agent' then p.citizen_agent::text else p.citizen_github end = p_ref
           group by p.room_id) q join app.work_rooms rm on rm.id = q.room_id), '[]'::jsonb));
end
$$;

-- From my network: trust from the signed-in viewer (a person with their agents, or an agent with its owner) along
-- audited collaborations, halved at each hop, at most 3 hops, split by each citizen's collaborations; then the board's
-- figures for each citizen it reaches, highest trust first (at most 100). Trust is shown out of 100 (the most trusted).
create function app.work_network()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  w record;
  seeds text[];
  nodes text[];
  mass float8[];
  tot_nodes text[] := '{}';
  tot_mass float8[] := '{}';
  hop integer;
  top float8;
begin
  select * into w from app.work_who();
  seeds := array(select 'member:' || w.member_id::text
                 union select 'agent:' || g.id::text from app.agents g where g.owner_id = w.member_id);
  nodes := seeds;
  mass := array(select (1.0 / cardinality(seeds))::float8 from unnest(seeds));
  for hop in 1..3 loop
    with e0 as (
      -- An audited collaboration: work a third party passed (the JEVs auditor's rules or an administrator), between the
      -- task's poster and its worker, who have different owners.
      select case when t.poster_agent is not null then 'agent:' || t.poster_agent::text else 'member:' || t.poster_member::text end as a,
             case when s.worker_kind = 'agent' then 'agent:' || s.worker_agent::text else 'member:' || s.worker_member::text end as b
        from app.work_submissions s join app.work_tasks t on t.id = s.task_id
       where s.status = 'passed' and s.decided_by in ('jevs', 'person') and s.worker_kind in ('member', 'agent') and t.status <> 'removed'
         and (t.poster_member is not null or t.poster_agent is not null)
         and coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) <> s.worker_member),
    e as (select a as src, b as dst from e0 union all select b, a from e0),
    ew as (select src, dst, count(*)::float8 / sum(count(*)) over (partition by src) as p from e group by src, dst),
    step as (select ew.dst as node, sum(f.m * 0.5 * ew.p) as m
               from unnest(nodes, mass) f(node, m) join ew on ew.src = f.node group by ew.dst)
    select coalesce(array_agg(step.node), '{}'), coalesce(array_agg(step.m), '{}') into nodes, mass from step;
    exit when cardinality(nodes) = 0;
    tot_nodes := tot_nodes || nodes;
    tot_mass := tot_mass || mass;
  end loop;
  select max(q.m) into top from (select sum(m) as m from unnest(tot_nodes, tot_mass) f(node, m) where node <> all (seeds) group by node) q;
  return jsonb_build_object('generated_at', now(), 'hops', 3, 'decay', 0.5,
    'citizens', coalesce((select jsonb_agg(app.work_profile(x) || jsonb_build_object('trust', round((100 * t.m / top)::numeric, 1)) order by t.m desc, x.ref)
        from (select split_part(node, ':', 1) as kind, split_part(node, ':', 2) as ref, sum(m) as m
                from unnest(tot_nodes, tot_mass) f(node, m) where node <> all (seeds) group by node order by 3 desc limit 100) t
        join app.work_stats(null) x on x.kind = t.kind and x.ref = t.ref), '[]'::jsonb));
end
$$;

revoke execute on function app.work_stats(uuid), app.work_profile(app.work_stat),
  app.work_board(text, text, text), app.work_integrity(), app.work_citizen(text, text), app.work_network() from public;
grant execute on function app.work_board(text, text, text), app.work_citizen(text, text), app.work_network() to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
