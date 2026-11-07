-- 046 The disputes pages (CODING_AGENT_SPEC.md 4.5): /disputes and /disputes/<id>, with each dispute's steps (opened,
--   evidence, settlement, outcome), its evidence with who added what, its window, and its outcome with the log entry
--   that records it.
--   * Evidence: the dispute's opener, the worker (or the agent's owner), the task's poster (or the agent's owner) and an
--     administrator who isn't a party may each add notes while it is open: at most 5 each and 20 a dispute, 3 to 1,000
--     characters, with email addresses, phone numbers and keys hidden before they are stored (db/work.js). Public on the
--     dispute's page with the adder's name and role, like the dispute itself. Deleting an account deletes its notes.
--   * Opening a dispute now also tells the worker (or the agent's owner) and the task's poster, so they can answer it.
--   * The outcome's log entry: for an upheld dispute, the reversal's audit.verdict entry; for a dismissed one, the pass's
--     own entry, which stands. Nothing new goes into the log.
--   * Text: an administrator who is a party is told another administrator decides (Third Look decides no disputes or
--     checks), and a task's audit says Third Look's mode (044) instead of "not built".
-- 042's app.work_task, app.work_dispute, app.work_dispute_decide and app.work_check_decide are otherwise word for word.

set local role dog_owner;
create table app.work_dispute_evidence (
  id uuid primary key default app.uuid_v7(),
  dispute_id uuid not null references app.work_disputes (id) on delete cascade,
  member_id uuid not null references app.members (id) on delete cascade,
  role text not null check (role = any (array['opener', 'worker', 'poster', 'admin'])),
  note text not null check (char_length(note) between 3 and 1000),
  created_at timestamptz not null default now()
);
create index work_dispute_evidence_dispute on app.work_dispute_evidence (dispute_id, created_at);
create index work_dispute_evidence_member on app.work_dispute_evidence (member_id);
alter table app.work_dispute_evidence enable row level security;
alter table app.work_dispute_evidence force row level security;
create policy work_dispute_evidence_work on app.work_dispute_evidence for all to dog_work using (true) with check (true);
grant select, insert on app.work_dispute_evidence to dog_work;

grant create on schema app to dog_work;
set local role dog_work;

-- Adds a note of evidence to an open dispute: its opener, the worker, the task's poster, or an administrator who isn't
-- a party. People only. Returns the note's ID.
create function app.work_evidence_add(p_dispute uuid, p_note text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  d record;
  s record;
  t record;
  r text;
  eid uuid;
begin
  select * into w from app.work_who();
  if w.agent_id is not null then raise exception 'a person adds evidence, not an agent' using errcode = '42501'; end if;
  if p_note is null or char_length(btrim(p_note)) not between 3 and 1000 then raise exception 'bad evidence' using errcode = '22023'; end if;
  select * into d from app.work_disputes x where x.id = p_dispute for update;
  if d.id is null then raise exception 'no such dispute' using errcode = 'P0002'; end if;
  if d.status <> 'open' then raise exception 'work_state' using errcode = 'P0001', hint = 'This dispute is decided, so it takes no more evidence.'; end if;
  select * into s from app.work_submissions x where x.id = d.submission_id;
  select * into t from app.work_tasks x where x.id = s.task_id;
  r := case when d.member_id = w.member_id then 'opener'
            when s.worker_member = w.member_id then 'worker'
            when coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) = w.member_id then 'poster'
            when w.is_admin and not app.work_party(d.submission_id, w.member_id) then 'admin' end;
  if r is null then
    raise exception 'work_party' using errcode = 'P0001', hint = 'Only the dispute''s opener, the worker, the task''s poster or an administrator adds evidence.';
  end if;
  if (select count(*) from app.work_dispute_evidence e where e.dispute_id = d.id and e.member_id = w.member_id) >= 5 then
    raise exception 'work_cap' using errcode = 'P0001', hint = 'You have added 5 notes to this dispute, the most for one person.';
  end if;
  if (select count(*) from app.work_dispute_evidence e where e.dispute_id = d.id) >= 20 then
    raise exception 'work_cap' using errcode = 'P0001', hint = 'This dispute has 20 notes, the most it takes.';
  end if;
  insert into app.work_dispute_evidence (dispute_id, member_id, role, note) values (d.id, w.member_id, r, btrim(p_note)) returning id into eid;
  return eid;
end
$$;

-- One dispute, as its page shows it. Null if there is no such dispute (or its task was removed).
create function app.work_dispute_page(p_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  d record;
  s record;
  t record;
  p record;
  outcome bigint;
  anchored bigint := app.work_anchored_through();
begin
  select * into d from app.work_disputes x where x.id = p_id;
  if d.id is null then return null; end if;
  select * into s from app.work_submissions x where x.id = d.submission_id;
  select * into t from app.work_tasks x where x.id = s.task_id and x.status <> 'removed';
  if t.id is null then return null; end if;
  select * into p from app.work_points x where x.submission_id = s.id;
  outcome := case d.status
    when 'upheld' then (select max(e.seq) from app.log_entries e where e.type = 'audit.verdict' and e.subject = 'submission:' || s.id::text
                         and e.created_at >= d.created_at)
    when 'dismissed' then s.decided_seq end;
  return jsonb_build_object('generated_at', now(), 'id', d.id, 'status', d.status, 'reason', d.reason,
    'opener', app.work_display(d.member_id, null, null), 'created_at', d.created_at,
    'decision', d.decision, 'decided_at', d.decided_at,
    'decided_by', case when d.decided_by is null then null else app.work_display(d.decided_by, null, null) end,
    'outcome_seq', outcome, 'outcome_anchored', outcome is not null and outcome < anchored,
    -- Who could decide it now: an administrator who is neither a party nor its opener.
    'decidable', d.status = 'open' and exists (select 1 from app.members m where m.is_admin and m.status = 'active'
                                              and m.id <> d.member_id and not app.work_party(d.submission_id, m.id)),
    'task', app.work_card(t.id),
    'submission', jsonb_build_object('id', s.id, 'status', s.status,
        'worker', app.work_display(case when s.worker_kind = 'member' then s.worker_member end, s.worker_agent, s.worker_github),
        'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256, 'pr', s.pr_number),
        'decided_by', s.decided_by, 'confidence', s.confidence, 'decided_at', s.decided_at, 'seq', s.decided_seq,
        'poster', case when t.source = 'github' then jsonb_build_object('kind', 'github', 'name', 'GitHub: MyChiefOS/start-of-something-great')
                       else app.work_display(t.poster_member, t.poster_agent, null) end),
    -- The dispute window: from the pass to its points' final_at (dispute_hours). An open dispute holds the points.
    'window', case when p.id is null then null else jsonb_build_object('opened_at', p.created_at, 'closes_at', p.final_at, 'points', p.points, 'points_status', p.status) end,
    'evidence', coalesce((select jsonb_agg(jsonb_build_object('id', e.id, 'role', e.role, 'by', app.work_display(e.member_id, null, null),
                                                              'note', e.note, 'at', e.created_at) order by e.created_at, e.id)
                          from app.work_dispute_evidence e where e.dispute_id = d.id), '[]'::jsonb));
end
$$;

-- Disputes, newest first: status open, upheld, dismissed, settled (both) or all; a cursor and a limit (1 to 100).
create function app.work_disputes_list(p_status text, p_before uuid, p_limit integer)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  ids uuid[];
  more boolean;
begin
  if p_limit is null or p_limit not between 1 and 100
     or (p_status is not null and p_status <> all (array['open', 'upheld', 'dismissed', 'settled', 'all'])) then
    raise exception 'bad dispute list' using errcode = '22023';
  end if;
  ids := array(select d.id from app.work_disputes d join app.work_submissions s on s.id = d.submission_id join app.work_tasks t on t.id = s.task_id
                where t.status <> 'removed' and (p_before is null or d.id < p_before)
                  and (coalesce(p_status, 'all') = 'all' or d.status = p_status or (p_status = 'settled' and d.status <> 'open'))
                order by d.id desc limit p_limit + 1);
  more := cardinality(ids) > p_limit;
  if more then ids := ids[1:p_limit]; end if;
  return jsonb_build_object('generated_at', now(),
    'counts', jsonb_build_object('open', (select count(*) from app.work_disputes x where x.status = 'open'),
                                 'upheld', (select count(*) from app.work_disputes x where x.status = 'upheld'),
                                 'dismissed', (select count(*) from app.work_disputes x where x.status = 'dismissed')),
    'disputes', coalesce((select jsonb_agg(jsonb_build_object('id', d.id, 'status', d.status, 'reason', d.reason, 'created_at', d.created_at,
        'decided_at', d.decided_at, 'opener', app.work_display(d.member_id, null, null),
        'task', jsonb_build_object('id', t.id, 'title', t.title),
        'worker', app.work_display(case when s.worker_kind = 'member' then s.worker_member end, s.worker_agent, s.worker_github),
        'closes_at', (select p.final_at from app.work_points p where p.submission_id = s.id),
        'evidence', (select count(*) from app.work_dispute_evidence e where e.dispute_id = d.id)) order by d.id desc)
      from app.work_disputes d join app.work_submissions s on s.id = d.submission_id join app.work_tasks t on t.id = s.task_id
      where d.id = any (ids)), '[]'::jsonb),
    'next', case when more then ids[p_limit] end);
end
$$;

create or replace function app.work_task(p_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  t record;
  anchored bigint := app.work_anchored_through();
begin
  select * into t from app.work_tasks x where x.id = p_id and x.status <> 'removed';
  if t.id is null then return null; end if;
  return app.work_card(p_id) || jsonb_build_object(
    'description', t.description, 'generated_at', now(),
    'poster', case when t.source = 'github' then jsonb_build_object('kind', 'github', 'name', case when t.github_kind = 'pr' then '@' || t.github_author
                                                                                              else 'GitHub: MyChiefOS/start-of-something-great' end)
                   else app.work_display(t.poster_member, t.poster_agent, null) end,
    'approved_at', t.approved_at, 'approved_seq', t.approved_seq, 'anchored_through', anchored,
    'claim', (select jsonb_build_object('by', app.work_display(c.member_id, c.agent_id, null), 'status', c.status, 'claimed_at', c.created_at,
                                        'expires_at', c.expires_at, 'seq', c.log_seq)
              from app.work_claims c where c.task_id = t.id and c.status in ('active', 'submitted') limit 1),
    'submissions', coalesce((select jsonb_agg(jsonb_build_object(
        'id', s.id, 'status', s.status, 'route', s.route, 'held_reason', s.held_reason, 'created_at', s.created_at, 'decided_at', s.decided_at,
        'worker', app.work_display(case when s.worker_kind = 'member' then s.worker_member end, s.worker_agent, s.worker_github),
        'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256, 'pr', s.pr_number),
        'note', s.note,
        'seal', jsonb_build_object('seal', s.seal, 'key', encode(s.seal_key, 'hex'),
                                   'facts', jsonb_build_object('task', s.task_id::text, 'kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256)),
        'jevs', jsonb_build_object('verdict', s.jevs_verdict, 'rules', s.jevs_rules),
        -- Who audits it: the JEVs auditor's rules, then a person for what they can't decide (Aaron, Nov 5).
        'audit', jsonb_build_object('by', coalesce(s.decided_by, case s.route when 'poster' then 'poster' when 'admin' then 'person' when 'held' then 'third_look' else 'jevs' end),
                                    'third_look', (select x.mode from app.tl_settings x where x.singleton)),
        'check', (select jsonb_build_object('status', k.status, 'why', k.why, 'reason', k.reason, 'decided_at', k.decided_at) from app.work_checks k where k.submission_id = s.id),
        'disputes', coalesce((select jsonb_agg(jsonb_build_object('id', d.id, 'status', d.status, 'reason', d.reason, 'decision', d.decision,
                                                                 'created_at', d.created_at, 'decided_at', d.decided_at,
                                                                 'opener', app.work_display(d.member_id, null, null),
                                                                 'evidence', (select count(*) from app.work_dispute_evidence e where e.dispute_id = d.id)) order by d.created_at)
                              from app.work_disputes d where d.submission_id = s.id), '[]'::jsonb),
        'decided_by', s.decided_by, 'confidence', s.confidence, 'size', s.final_size, 'reason', s.reason,
        'points', (select jsonb_build_object('points', x.points, 'size', x.size, 'confidence', x.confidence, 'independence', x.independence,
                                             'status', x.status, 'final_at', x.final_at) from app.work_points x where x.submission_id = s.id),
        'submitted_seq', s.submitted_seq, 'decided_seq', s.decided_seq,
        'anchored', s.decided_seq is not null and s.decided_seq < anchored) order by s.created_at desc)
      from (select * from app.work_submissions y where y.task_id = t.id order by y.created_at desc limit 20) s), '[]'::jsonb));
end
$$;

create or replace function app.work_dispute(p_sub uuid, p_reason text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  s record;
  n integer;
  did uuid;
begin
  select * into w from app.work_who();
  if w.agent_id is not null then raise exception 'a person disputes work, not an agent' using errcode = '42501'; end if;
  if p_reason is null or char_length(btrim(p_reason)) not between 3 and 500 then raise exception 'bad dispute' using errcode = '22023'; end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  if s.worker_member = w.member_id then raise exception 'work_own' using errcode = 'P0001', hint = 'This is your own work: you can''t dispute it.'; end if;
  if s.status <> 'passed' or not exists (select 1 from app.work_points p where p.submission_id = p_sub and p.status = 'pending') then
    raise exception 'work_state' using errcode = 'P0001', hint = 'Only a pass whose points are still pending can be disputed.';
  end if;
  if exists (select 1 from app.work_disputes d where d.submission_id = p_sub and d.status = 'open') then
    raise exception 'work_state' using errcode = 'P0001', hint = 'A dispute on this work is already open.';
  end if;
  select count(*) into n from app.work_disputes d where d.member_id = w.member_id and d.created_at > now() - interval '1 day';
  if n >= (select x.dispute_daily from app.work_settings x where x.singleton) then
    raise exception 'work_cap' using errcode = 'P0001', hint = 'You have opened ' || n || ' disputes today, the most for one day.';
  end if;
  insert into app.work_disputes (submission_id, member_id, reason) values (p_sub, w.member_id, btrim(p_reason)) returning id into did;
  perform app.notify(null, 'alert', 'A pass on work is disputed', 'Someone disputed a pass on a task. Its points wait until you decide it on Review.', '/admin/review#work',
    'submission', p_sub, 'work:dispute:' || did);
  -- The worker (or the agent's owner) and the task's poster hear of it, so they can add evidence (046).
  perform app.notify(x.m, 'work_decided', 'A pass on work is disputed', 'Someone disputed a pass on "' || left(t.title, 80) || '". Its points wait until an administrator decides. You can add evidence on the dispute''s page.',
    '/disputes/' || did, 'submission', p_sub, 'work:dispute:' || did || ':' || x.m)
    from app.work_tasks t, lateral (select s.worker_member as m union select coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent))) x
   where t.id = s.task_id and x.m is not null and x.m <> w.member_id;
  return did;
end
$$;

create or replace function app.work_dispute_decide(p_dispute uuid, p_decision text, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  d record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides disputes' using errcode = '42501'; end if;
  if p_decision is null or p_decision <> all (array['uphold', 'dismiss']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into d from app.work_disputes x where x.id = p_dispute for update;
  if d.id is null or d.status <> 'open' then return 'not_open'; end if;
  if app.work_party(d.submission_id, app.current_member()) or d.member_id = app.current_member() then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You are a party to this work or this dispute, so another administrator decides it. Until one can, it stays open and its points stay pending.';
  end if;
  update app.work_disputes x set status = case when p_decision = 'uphold' then 'upheld' else 'dismissed' end, decided_by = app.current_member(),
    decision = btrim(p_reason), decided_at = now() where x.id = p_dispute;
  if p_decision = 'uphold' then perform app.work_reverse(d.submission_id, 'dispute', btrim(p_reason)); end if;
  perform app.notify(d.member_id, 'work_decided', 'Your dispute was decided', 'Your dispute was ' || case when p_decision = 'uphold' then 'upheld: the pass is reversed.' else 'dismissed.' end
    || ' ' || left(btrim(p_reason), 200), '/tasks/' || (select s.task_id from app.work_submissions s where s.id = d.submission_id), 'submission', d.submission_id, 'work:dispute-decided:' || d.id);
  return p_decision;
end
$$;

create or replace function app.work_check_decide(p_check uuid, p_decision text, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  k record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides checks' using errcode = '42501'; end if;
  if p_decision is null or p_decision <> all (array['confirm', 'reverse']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into k from app.work_checks x where x.id = p_check for update;
  if k.id is null or k.status <> 'open' then return 'not_open'; end if;
  if app.work_party(k.submission_id, app.current_member()) then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You are a party to this work, so another administrator decides its check. Until one can, it stays open.';
  end if;
  update app.work_checks x set status = case when p_decision = 'confirm' then 'confirmed' else 'reversed' end, member_id = app.current_member(),
    reason = btrim(p_reason), decided_at = now() where x.id = p_check;
  if p_decision = 'reverse' then perform app.work_reverse(k.submission_id, 'check', btrim(p_reason)); end if;
  return p_decision;
end
$$;

revoke execute on function app.work_evidence_add(uuid, text), app.work_dispute_page(uuid), app.work_disputes_list(text, uuid, integer) from public;
grant execute on function app.work_evidence_add(uuid, text), app.work_dispute_page(uuid), app.work_disputes_list(text, uuid, integer) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
