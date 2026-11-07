-- 051 The administrator's console (the design handoff's console.html; Aaron, Nov 7: "Continue building"): the work
-- module seen whole, in six tabs (summary, agents, projects, submissions, ledger, admins), for administrators only, with
-- every read logged.
--   * app.work_console(tab, status, cursor): one tab's figures. Only an administrator reads it, and each read writes an
--     audit row ('console.read', the tab) inside the same call, so no page or route can read without the record.
--   * Every list pages, newest first, by its time and id together (the cursor "time~id"), so no row is skipped at a
--     page's edge and every agent, task, submission, ledger row and administrator action can be reached.
--   * The ledger tab: the public log's size and its latest signed checkpoints, and the points ledger (048) checked row by
--     row: each points row's ledger rows must add up to its points in the bucket its state says, for the same citizen.
--   * The admins tab: the administrators and their recent activity from the audit log. The design's "Revoke access"
--     isn't built: the site has exactly one administrator (028's members_one_admin), and the design's own rules say you
--     can't revoke yourself and the last administrator can never be revoked, so the button could never act.
--   * Read only, apart from the audit row: nothing here changes work, points or people.

set local role dog_owner;

-- The work module's role writes its console reads to the audit log, and reads the rows the admins tab shows: both only
-- while an administrator is acting, as 001's audit_select. As every audit policy: the row says who is acting, and
-- nobody can write it for someone else (S1).
create policy audit_insert_console on app.audit_log for insert to dog_work
  with check ((select app.actor_kind()) = 'admin' and action = 'console.read'
              and actor_kind = (select app.actor_kind()) and actor_id is not distinct from (select app.current_actor_id()));
create policy audit_select_console on app.audit_log for select to dog_work
  using ((select app.actor_kind()) = 'admin'
         and (actor_kind = 'admin' or action = any (array['console.read', 'admin.set'])
              or (action = 'member.signed_in' and subject_kind = 'member' and subject_id in (select m.id from app.members m where m.is_admin))));
grant insert (action, subject_kind, subject_id, detail) on app.audit_log to dog_work;
grant select on app.audit_log to dog_work;
grant execute on function app.current_actor_id() to dog_work;
-- The activity list reads the newest rows first; without this it reads the whole log.
create index audit_log_at on app.audit_log (at desc, id desc);
-- Two more columns for the console: when an agent was made (the agents tab), and a checkpoint's root hash (the ledger
-- tab; every checkpoint is already public at /api/log/checkpoint).
grant select (created_at) on app.agents to dog_work;
grant select (root) on app.log_checkpoints to dog_work;
grant create on schema app to dog_work;

set local role dog_work;

-- The points ledger checked row by row (048): for each points row, its ledger rows' pending and final balances must equal
-- its points in the bucket its state says (pending: pending; final: final; removed: neither), and every ledger row must
-- name the row's own citizen. Totals alone could hide two errors that cancel out; this can't.
create function app.work_console_integrity()
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  with e as (select x.points_id,
                    coalesce(sum(x.amount) filter (where x.bucket = 'pending'), 0) as pending,
                    coalesce(sum(x.amount) filter (where x.bucket = 'final'), 0) as final,
                    count(*) as n
               from app.work_point_entries x group by x.points_id),
       c as (select x.points_id, count(*) as n
               from app.work_point_entries x join app.work_points p on p.id = x.points_id
              where x.citizen_kind is distinct from p.citizen_kind or x.citizen_member is distinct from p.citizen_member
                 or x.citizen_agent is distinct from p.citizen_agent or x.citizen_github is distinct from p.citizen_github
              group by x.points_id),
       r as (select p.id, p.status, p.points, coalesce(e.pending, 0) as pending, coalesce(e.final, 0) as final, coalesce(e.n, 0) as n,
                    coalesce(c.n, 0) as wrong_citizen
               from app.work_points p left join e on e.points_id = p.id left join c on c.points_id = p.id)
  select jsonb_build_object(
    'log_size', (select max(k.size) from app.log_checkpoints k),
    'last_checkpoint_at', (select max(k.created_at) from app.log_checkpoints k),
    'pending_balance', coalesce(sum(r.pending), 0), 'final_balance', coalesce(sum(r.final), 0),
    'pending_points', coalesce(sum(r.points) filter (where r.status = 'pending'), 0),
    'final_points', coalesce(sum(r.points) filter (where r.status = 'final'), 0),
    'points_rows', count(*),
    'rows_without_entries', count(*) filter (where r.points > 0 and r.n = 0),
    'rows_wrong', count(*) filter (where r.pending <> case when r.status = 'pending' then r.points else 0 end
                                      or r.final <> case when r.status = 'final' then r.points else 0 end
                                      or r.wrong_citizen > 0),
    'intact', count(*) filter (where r.pending <> case when r.status = 'pending' then r.points else 0 end
                                  or r.final <> case when r.status = 'final' then r.points else 0 end
                                  or r.wrong_citizen > 0) = 0)
  from r
$$;

create function app.work_console(p_tab text, p_status text, p_cursor text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  c_at timestamptz;
  c_id uuid;
  out jsonb;
begin
  if app.actor_kind() is distinct from 'admin' then raise exception 'only an administrator' using errcode = '42501'; end if;
  if p_tab is null or p_tab <> all (array['summary', 'agents', 'projects', 'submissions', 'ledger', 'admins']) then
    raise exception 'no such tab' using errcode = '22023';
  end if;
  if p_status is not null and p_status <> all (array['open', 'claimed', 'submitted', 'audited', 'approved', 'closed']) then
    raise exception 'no such status' using errcode = '22023';
  end if;
  -- The cursor is the last row shown: its time and id, "time~id". A time that isn't real (Feb 31, 25:00) is refused.
  if p_cursor is not null then
    begin
      c_at := split_part(p_cursor, '~', 1)::timestamptz;
      c_id := split_part(p_cursor, '~', 2)::uuid;
    exception when data_exception then
      raise exception 'that cursor is not a time and an id' using errcode = '22023';
    end;
    if c_at is null or c_id is null or c_at not between '2026-01-01' and now() + interval '1 day' then
      raise exception 'that cursor is not a time and an id' using errcode = '22023';
    end if;
  end if;
  -- Every read is recorded, by the database, in the same transaction as the read.
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('console.read', null, null, jsonb_build_object('tab', p_tab)
      || case when p_status is not null then jsonb_build_object('status', p_status) else '{}'::jsonb end
      || case when p_cursor is not null then jsonb_build_object('page', true) else '{}'::jsonb end);

  if p_tab = 'summary' then
    out := jsonb_build_object(
      'agents', (select count(*) from app.agents g where g.status = 'active'),
      'agents_all', (select count(*) from app.agents g),
      'submissions', (select count(*) from app.work_submissions),
      'points', (select coalesce(sum(p.points), 0) from app.work_points p where p.status <> 'removed'),
      'rooms_open', (select count(distinct t.room_id) from app.work_tasks t where t.status = 'open'),
      'rooms', (select count(*) from app.work_rooms),
      'tasks', (select coalesce(jsonb_object_agg(x.status, x.n), '{}'::jsonb)
                  from (select t.status, count(*) as n from app.work_tasks t where t.status <> 'removed' group by t.status) x),
      'ledger', app.work_console_integrity());
  elsif p_tab = 'agents' then
    out := (select jsonb_build_object(
              'agents', coalesce(jsonb_agg(jsonb_build_object('id', g.id, 'name', g.name, 'status', g.status, 'created_at', g.created_at,
                  'owner', jsonb_build_object('id', m.id, 'name', m.display_name), 'points', coalesce(pt.points, 0))
                order by g.created_at desc, g.id desc), '[]'::jsonb),
              'next', case when count(*) = 100 then (array_agg(to_jsonb(g.created_at) #>> '{}' || '~' || g.id order by g.created_at, g.id))[1] end)
            from (select x.id, x.name, x.status, x.created_at, x.owner_id from app.agents x where c_at is null or (x.created_at, x.id) < (c_at, c_id)
                   order by x.created_at desc, x.id desc limit 100) g
            left join app.members m on m.id = g.owner_id
            left join (select p.citizen_agent, sum(p.points) as points from app.work_points p
                        where p.status <> 'removed' and p.citizen_agent is not null group by p.citizen_agent) pt on pt.citizen_agent = g.id);
  elsif p_tab = 'projects' then
    out := (select jsonb_build_object(
              'tasks', coalesce(jsonb_agg(app.work_card(x.id) || jsonb_build_object(
                  'poster', app.work_display(x.poster_member, x.poster_agent, x.github_author)) order by x.updated_at desc, x.id desc), '[]'::jsonb),
              'next', case when count(*) = 100 then (array_agg(to_jsonb(x.updated_at) #>> '{}' || '~' || x.id order by x.updated_at, x.id))[1] end)
            from (select t.* from app.work_tasks t
                   where t.status <> 'removed' and (p_status is null or t.status = p_status)
                     and (c_at is null or (t.updated_at, t.id) < (c_at, c_id))
                   order by t.updated_at desc, t.id desc limit 100) x)
        || jsonb_build_object('counts', (select coalesce(jsonb_object_agg(x.status, x.n), '{}'::jsonb)
                   from (select t.status, count(*) as n from app.work_tasks t where t.status <> 'removed' group by t.status) x));
  elsif p_tab = 'submissions' then
    out := (select jsonb_build_object(
              'submissions', coalesce(jsonb_agg(jsonb_build_object('id', s.id, 'task', app.work_card(s.task_id),
                  'worker', app.work_display(case when s.worker_kind = 'member' then s.worker_member end, s.worker_agent, s.worker_github),
                  'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'pr', s.pr_number),
                  'status', s.status, 'decided_by', s.decided_by, 'confidence', s.confidence, 'created_at', s.created_at, 'decided_at', s.decided_at,
                  'receipt', s.decided_seq) order by s.created_at desc, s.id desc), '[]'::jsonb),
              'next', case when count(*) = 100 then (array_agg(to_jsonb(s.created_at) #>> '{}' || '~' || s.id order by s.created_at, s.id))[1] end)
            from (select x.* from app.work_submissions x where c_at is null or (x.created_at, x.id) < (c_at, c_id)
                   order by x.created_at desc, x.id desc limit 100) s);
  elsif p_tab = 'ledger' then
    out := jsonb_build_object('integrity', app.work_console_integrity(),
      'checkpoints', coalesce((select jsonb_agg(jsonb_build_object('size', c.size, 'at', c.created_at, 'root', encode(c.root, 'hex')) order by c.size desc)
          from (select x.size, x.root, x.created_at from app.log_checkpoints x order by x.size desc limit 20) c), '[]'::jsonb))
      || (select jsonb_build_object(
            'entries', coalesce(jsonb_agg(jsonb_build_object('at', e.at, 'kind', e.kind, 'bucket', e.bucket, 'amount', e.amount,
                'citizen', app.work_display(e.citizen_member, e.citizen_agent, e.citizen_github), 'task', app.work_card(p.task_id))
              order by e.at desc, e.id desc), '[]'::jsonb),
            'next', case when count(*) = 50 then (array_agg(to_jsonb(e.at) #>> '{}' || '~' || e.id order by e.at, e.id))[1] end)
          from (select x.* from app.work_point_entries x where c_at is null or (x.at, x.id) < (c_at, c_id)
                 order by x.at desc, x.id desc limit 50) e
          join app.work_points p on p.id = e.points_id);
  else
    out := jsonb_build_object(
      'admins', coalesce((select jsonb_agg(jsonb_build_object('id', m.id, 'name', m.display_name, 'joined', m.created_at,
              'since', (select max(l.at) from app.audit_log l where l.action = 'admin.set' and l.subject_kind = 'member' and l.subject_id = m.id))
            order by m.created_at)
          from app.members m where m.is_admin), '[]'::jsonb),
      'one_admin', true)
      || (select jsonb_build_object(
            'activity', coalesce(jsonb_agg(jsonb_build_object('at', l.at, 'actor_kind', l.actor_kind, 'action', l.action,
                'by', (select m.display_name from app.members m where m.id = l.actor_id),
                'detail', case when l.action = 'console.read' then l.detail else '{}'::jsonb end) order by l.at desc, l.id desc), '[]'::jsonb),
            'next', case when count(*) = 50 then (array_agg(to_jsonb(l.at) #>> '{}' || '~' || l.id order by l.at, l.id))[1] end)
          from (select x.* from app.audit_log x
                 where (c_at is null or (x.at, x.id) < (c_at, c_id))
                 order by x.at desc, x.id desc limit 50) l);
  end if;
  return jsonb_build_object('tab', p_tab, 'generated_at', now()) || out;
end
$$;

revoke execute on function app.work_console(text, text, text), app.work_console_integrity() from public;
grant execute on function app.work_console(text, text, text) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
