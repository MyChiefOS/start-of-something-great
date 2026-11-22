-- 068 Automatic remedies, so the administrator isn't the last step every time (Aaron, Nov 22, 2026: "automatic
--   remedies so the administrator isn't the last step every time ... without needing me to take any action but
--   approving the PR"). Payments stay off.
--
--   1. An overturned fail is put right automatically. Until now an administrator who overturned a fail was told to
--      "put right what the work is owed" by hand. Now the work passes as it should have: its points are recorded
--      (pending for the dispute window, as every pass's are), the worker's claim is done, and the task moves to
--      audited for its poster to approve, unless the task has moved on meanwhile (claimed by someone else, approved,
--      closed), when it keeps its state and only the points are given.
--   2. Peers decide fail checks and disputes first. A level-2 member with no tie to the work (067's peer_block) and who
--      had no part in deciding it takes an open check of a fail (a sample or an appeal) or an open dispute, for 24 hours, and
--      proposes a decision with a reason. It takes effect after the dispute window (72 hours), unless the worker, the
--      poster or the one who disputed appeals it; an appeal leaves it for an administrator, who is now the last
--      appeal. The administrator may still decide any case first, as before, and is told of every peer's proposal.
--      The checks that look for collusion on a pass (random, size, pair, note) stay with the administrator: only the
--      worker and the poster could appeal a peer's answer there, and they are the pair being checked (the fresh review, H1).
--   3. Work held only because an administrator is a party (route 'held') that Third Look can't read (anything but a
--      pull request) goes to the peer review queue too, so it no longer waits forever.

-- ---- The cases peers decide ----
set local role dog_owner;
create table app.peer_cases (
  id uuid primary key default app.uuid_v7(),
  kind text not null check (kind = any (array['check', 'dispute'])),
  check_id uuid references app.work_checks (id) on delete cascade,
  dispute_id uuid references app.work_disputes (id) on delete cascade,
  submission_id uuid not null references app.work_submissions (id) on delete cascade,
  reviewer_member uuid not null references app.members (id) on delete cascade,
  status text not null default 'assigned' check (status = any (array['assigned', 'proposed', 'appealed', 'applied', 'superseded', 'lapsed', 'released'])),
  decision text check (decision = any (array['confirm', 'reverse', 'uphold', 'dismiss'])),
  reason text check (char_length(reason) between 3 and 300),
  assigned_at timestamptz not null default now(),
  expires_at timestamptz not null,
  decided_at timestamptz,
  due_at timestamptz,
  appealed_by uuid references app.members (id) on delete set null,
  appeal_reason text check (char_length(appeal_reason) between 3 and 300),
  check ((kind = 'check') = (check_id is not null)),
  check ((kind = 'dispute') = (dispute_id is not null)),
  check ((kind = 'check' and (decision is null or decision = any (array['confirm', 'reverse'])))
      or (kind = 'dispute' and (decision is null or decision = any (array['uphold', 'dismiss'])))),
  check (status not in ('proposed', 'appealed', 'applied') or (decision is not null and decided_at is not null)),
  check (status <> 'assigned' or decision is null)
);
create unique index peer_cases_one_live_check on app.peer_cases (check_id) where status = any (array['assigned', 'proposed', 'appealed']);
create unique index peer_cases_one_live_dispute on app.peer_cases (dispute_id) where status = any (array['assigned', 'proposed', 'appealed']);
create index peer_cases_due on app.peer_cases (due_at) where status = 'proposed';
alter table app.peer_cases enable row level security;
alter table app.peer_cases force row level security;
grant select, insert, update on app.peer_cases to dog_work;
create policy peer_cases_work on app.peer_cases for all to dog_work using (true) with check (true);
create policy peer_cases_app on app.peer_cases for select to dog_app using (reviewer_member = (select app.current_member()) or (select app.actor_kind()) = 'admin');
grant select on app.peer_cases to dog_app;
-- Who decided a check or a dispute: an administrator, or a peer through a case.
alter table app.work_checks add column decided_kind text not null default 'admin' check (decided_kind = any (array['admin', 'peer']));
alter table app.work_disputes add column decided_kind text not null default 'admin' check (decided_kind = any (array['admin', 'peer']));
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- ---- 1. A check's effect, whoever decides it ----
create function app.work_check_apply(p_check uuid, p_decision text, p_reason text, p_member uuid, p_kind text)
returns text language plpgsql security definer set search_path = pg_catalog as $$
declare k record; s record; t record; before text;
begin
  select * into k from app.work_checks x where x.id = p_check for update;
  if k.id is null or k.status <> 'open' then return 'not_open'; end if;
  update app.work_checks x set status = case when p_decision = 'confirm' then 'confirmed' else 'reversed' end, member_id = p_member,
    reason = btrim(p_reason), decided_at = now(), decided_kind = p_kind where x.id = p_check;
  -- Any case still waiting on this check is now moot.
  update app.peer_cases c set status = case when c.status <> 'assigned' and c.decision = p_decision then 'applied' else 'superseded' end
   where c.check_id = p_check and c.status = any (array['assigned', 'proposed', 'appealed']);
  if p_decision = 'reverse' and k.why = any (array['peer_fail_sample', 'peer_fail_appeal', 'fail_appeal']) then
    -- 1. The overturned fail passes as it should have: points, the claim done, the task to its poster, unless the task
    -- has moved on, when it keeps its state and only the points are given.
    select * into s from app.work_submissions x where x.id = k.submission_id for update;
    select * into t from app.work_tasks x where x.id = s.task_id for update;
    before := t.status;
    if s.status = 'failed' and before = any (array['open', 'claimed']) and not exists (select 1 from app.work_claims c where c.task_id = t.id and c.status = 'active' and c.id <> s.claim_id) then
      -- The task is free: the work passes as an independent decision ('person'), the task goes to its poster.
      update app.work_submissions x set status = 'review', route = null where x.id = s.id;
      perform app.work_finish(s.id, 'pass', 'person', 100, 'A fail overturned on a check: ' || btrim(p_reason));
    elsif s.status = 'failed' then
      -- The task moved on (claimed by someone else, approved, closed): only the points are given; nothing tells the
      -- poster to approve anything.
      perform app.log_work('audit.verdict', 'work-audit', null, 'submission:' || s.id::text, jsonb_build_object(
        'task', s.task_id::text, 'verdict', 'pass', 'by', 'person', 'confidence', 100, 'size', coalesce(s.final_size, t.size), 'independence', 100,
        'points', app.work_points_of(coalesce(s.final_size, t.size), 100, 100, (select st.points_cap from app.work_settings st where st.singleton)), 'votes', '[]'::jsonb));
      update app.work_submissions x set status = 'passed', route = null, decided_by = 'person', reason = left('A fail overturned on a check: ' || btrim(p_reason), 300), decided_at = now() where x.id = s.id;
      insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, citizen_agent, citizen_github, size, confidence, independence, points, final_at)
        values (s.id, t.id, t.room_id, s.worker_kind, s.worker_member, s.worker_agent, s.worker_github, coalesce(s.final_size, t.size), 100, 100,
                app.work_points_of(coalesce(s.final_size, t.size), 100, 100, (select st.points_cap from app.work_settings st where st.singleton)),
                now() + make_interval(hours => (select st.dispute_hours from app.work_settings st where st.singleton)));
    end if;
    -- Calibration (066) reads the fail's decider and the check beside it: the decider is kept on the submission's record.
    if s.status = 'failed' then
      update app.work_submissions x set decided_by = s.decided_by where x.id = s.id;
    end if;
    if coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)) is not null then
      perform app.notify(coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)), 'work_decided',
        'A failed verdict on your work was overturned', 'A check of a fail on your work disagreed with it. Your work now counts as passed and its points are recorded.',
        '/tasks/' || s.task_id, 'submission', s.id, 'work:fail-overturned:' || k.id);
    end if;
    perform app.notify(null, 'alert', 'A fail was overturned and put right', 'A fail was overturned; the work passed and its points were recorded.',
      '/admin/review#work', 'submission', k.submission_id, 'work:fail-overturned-admin:' || k.id);
  elsif p_decision = 'reverse' then
    perform app.work_reverse(k.submission_id, 'check', btrim(p_reason));
  end if;
  return p_decision;
end $$;
revoke execute on function app.work_check_apply(uuid, text, text, uuid, text) from public;

-- The administrator's decision, as before (067), now through the shared effect.
CREATE OR REPLACE FUNCTION app.work_check_decide(p_check uuid, p_decision text, p_reason text)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog'
AS $function$
declare k record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides checks' using errcode = '42501'; end if;
  if p_decision is null or p_decision <> all (array['confirm', 'reverse']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into k from app.work_checks x where x.id = p_check;
  if k.id is null or k.status <> 'open' then return 'not_open'; end if;
  if app.work_party(k.submission_id, app.current_member()) then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You are a party to this work, so a peer decides its check (068).';
  end if;
  return app.work_check_apply(p_check, p_decision, p_reason, app.current_member(), 'admin');
end
$function$;

-- ---- A dispute's effect, whoever decides it ----
create function app.work_dispute_apply(p_dispute uuid, p_decision text, p_reason text, p_member uuid, p_kind text)
returns text language plpgsql security definer set search_path = pg_catalog as $$
declare d record;
begin
  select * into d from app.work_disputes x where x.id = p_dispute for update;
  if d.id is null or d.status <> 'open' then return 'not_open'; end if;
  update app.work_disputes x set status = case when p_decision = 'uphold' then 'upheld' else 'dismissed' end, decided_by = p_member,
    decision = btrim(p_reason), decided_at = now(), decided_kind = p_kind where x.id = p_dispute;
  update app.peer_cases c set status = case when c.status <> 'assigned' and c.decision = p_decision then 'applied' else 'superseded' end
   where c.dispute_id = p_dispute and c.status = any (array['assigned', 'proposed', 'appealed']);
  if p_decision = 'uphold' then perform app.work_reverse(d.submission_id, 'dispute', btrim(p_reason)); end if;
  perform app.notify(d.member_id, 'work_decided', 'Your dispute was decided', 'Your dispute was ' || case when p_decision = 'uphold' then 'upheld: the pass is reversed.' else 'dismissed.' end
    || ' ' || left(btrim(p_reason), 200), '/tasks/' || (select s.task_id from app.work_submissions s where s.id = d.submission_id), 'submission', d.submission_id, 'work:dispute-decided:' || d.id);
  return p_decision;
end $$;
revoke execute on function app.work_dispute_apply(uuid, text, text, uuid, text) from public;

create or replace function app.work_dispute_decide(p_dispute uuid, p_decision text, p_reason text)
returns text language plpgsql security definer set search_path = pg_catalog as $$
declare d record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides disputes' using errcode = '42501'; end if;
  if p_decision is null or p_decision <> all (array['uphold', 'dismiss']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into d from app.work_disputes x where x.id = p_dispute;
  if d.id is null or d.status <> 'open' then return 'not_open'; end if;
  if app.work_may_settle(p_dispute, app.current_member()) is distinct from 'any' and app.work_may_settle(p_dispute, app.current_member()) is distinct from p_decision then
    raise exception 'work_own' using errcode = 'P0001', hint = 'On your own work for someone else''s task you may only uphold the dispute (give up the pass); a dispute you opened you may only dismiss (withdraw). Otherwise a peer decides it (068).';
  end if;
  return app.work_dispute_apply(p_dispute, p_decision, p_reason, app.current_member(), 'admin');
end $$;

-- ---- 2. Peers decide checks and disputes first ----
-- Why this member may not decide this case, or null: 067's blocks, and no part in what is being decided.
create function app.peer_case_block(p_member uuid, p_sub uuid, p_dispute uuid) returns text
language plpgsql stable security definer set search_path = pg_catalog as $$
declare why text;
begin
  why := app.peer_block(p_member, p_sub);
  if why is not null then return why; end if;
  if exists (select 1 from app.work_person_votes v where v.submission_id = p_sub and v.member_id = p_member)
     or exists (select 1 from app.peer_reviews r where r.submission_id = p_sub and r.reviewer_member = p_member and r.status = 'decided') then
    return 'decided_it';
  end if;
  if p_dispute is not null and exists (select 1 from app.work_disputes d where d.id = p_dispute and d.member_id = p_member) then return 'party'; end if;
  -- Rotation, as for reviews (067), counted over cases too: no more than 3 cases on one worker's or one poster's work in 30 days.
  if (select count(*) from app.peer_cases c join app.work_submissions x on x.id = c.submission_id join app.work_submissions s on s.id = p_sub
       where c.reviewer_member = p_member and c.decided_at > now() - interval '30 days'
         and coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) = coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent))) >= 3
     or (select count(*) from app.peer_cases c join app.work_submissions x on x.id = c.submission_id join app.work_tasks y on y.id = x.task_id
           join app.work_submissions s on s.id = p_sub join app.work_tasks t on t.id = s.task_id
          where c.reviewer_member = p_member and c.decided_at > now() - interval '30 days'
            and coalesce(y.poster_member, (select g.owner_id from app.agents g where g.id = y.poster_agent)) = coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent))) >= 3 then
    return 'rotation';
  end if;
  return null;
end $$;

create function app.peer_case_take() returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); x record; cid uuid; why text; tried integer := 0;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site decides a case; an agent can''t.';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.peer'));
  update app.peer_cases c set status = 'lapsed' where c.status = 'assigned' and c.expires_at <= now();
  if exists (select 1 from app.peer_cases c where c.reviewer_member = me and c.status = 'assigned') then
    raise exception 'work_peer_busy' using errcode = 'P0001', hint = 'Finish or give back the case you have first.';
  end if;
  for x in
    select 'check'::text as kind, k.id as cid, null::uuid as did, k.submission_id as sub, k.created_at as at
      from app.work_checks k where k.status = 'open' and k.why = any (array['peer_fail_sample', 'peer_fail_appeal', 'fail_appeal'])
       and not exists (select 1 from app.peer_cases c where c.check_id = k.id and c.status = any (array['assigned', 'proposed', 'appealed']))
    union all
    select 'dispute', null, d.id, d.submission_id, d.created_at
      from app.work_disputes d where d.status = 'open'
       and not exists (select 1 from app.peer_cases c where c.dispute_id = d.id and c.status = any (array['assigned', 'proposed', 'appealed']))
    order by at limit 200 loop
    tried := tried + 1;
    why := app.peer_case_block(me, x.sub, x.did);
    if why is null then
      insert into app.peer_cases (kind, check_id, dispute_id, submission_id, reviewer_member, expires_at)
        values (x.kind, x.cid, x.did, x.sub, me, now() + interval '24 hours') returning id into cid;
      perform app.audit_add('peer.case_taken', 'member', me, jsonb_build_object('case', cid, 'kind', x.kind, 'submission', x.sub), 'success');
      -- What the peer needs to judge (the fresh review, M6): the decision being checked and the reasons given.
      return jsonb_build_object('case', cid, 'kind', x.kind, 'submission', x.sub, 'expires_at', now() + interval '24 hours',
        'task', (select s.task_id from app.work_submissions s where s.id = x.sub),
        'decision', (select jsonb_build_object('status', s.status, 'by', s.decided_by, 'reason', s.reason) from app.work_submissions s where s.id = x.sub),
        'check_why', (select k.why from app.work_checks k where k.id = x.cid),
        'appeal_reason', (select k.appeal_reason from app.work_checks k where k.id = x.cid),
        'dispute_reason', (select d.reason from app.work_disputes d where d.id = x.did));
    end if;
  end loop;
  return jsonb_build_object('case', null, 'reason', case when tried = 0 then 'empty' else coalesce(why, 'empty') end);
end $$;

-- The peer proposes a decision; it takes effect after the dispute window unless appealed.
create function app.peer_case_decide(p_case uuid, p_decision text, p_reason text) returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); c record; why text; hrs integer; open_ boolean;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site decides a case; an agent can''t.';
  end if;
  if p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then raise exception 'bad decision' using errcode = '22023'; end if;
  select * into c from app.peer_cases x where x.id = p_case for update;
  if c.id is null or c.reviewer_member <> me then raise exception 'not your case' using errcode = '42501'; end if;
  if (c.kind = 'check' and (p_decision is null or p_decision <> all (array['confirm', 'reverse'])))
     or (c.kind = 'dispute' and (p_decision is null or p_decision <> all (array['uphold', 'dismiss']))) then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  if c.status <> 'assigned' or c.expires_at <= now() then
    update app.peer_cases x set status = 'lapsed' where x.id = c.id and x.status = 'assigned';
    return jsonb_build_object('result', 'lapsed');
  end if;
  open_ := case when c.kind = 'check' then exists (select 1 from app.work_checks k where k.id = c.check_id and k.status = 'open')
                else exists (select 1 from app.work_disputes d where d.id = c.dispute_id and d.status = 'open') end;
  if not open_ then
    update app.peer_cases x set status = 'released' where x.id = c.id;
    return jsonb_build_object('result', 'not_open');
  end if;
  why := app.peer_case_block(me, c.submission_id, c.dispute_id);
  if why is not null then
    update app.peer_cases x set status = 'released' where x.id = c.id;
    return jsonb_build_object('result', 'blocked', 'reason', why);
  end if;
  select coalesce(st.dispute_hours, 72) into hrs from app.work_settings st where st.singleton;
  update app.peer_cases x set status = 'proposed', decision = p_decision, reason = btrim(p_reason), decided_at = now(),
    due_at = now() + make_interval(hours => hrs) where x.id = c.id;
  -- The parties hear of it, so they can appeal within the window.
  perform app.notify(m, 'work_decided', 'A peer decided a case on your work', 'A peer proposed: ' || p_decision || '. ' || left(btrim(p_reason), 180)
    || ' It takes effect in ' || hrs || ' hours unless you appeal it on the Peer review page.', '/peer?case=' || c.id,
    'submission', c.submission_id, 'work:peer-case:' || c.id || ':' || m)
    from (select coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)) as m from app.work_submissions s where s.id = c.submission_id
          union select coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) from app.work_submissions s join app.work_tasks t on t.id = s.task_id where s.id = c.submission_id
          union select d.member_id from app.work_disputes d where d.id = c.dispute_id) z
   where z.m is not null and z.m <> me;
  perform app.notify(null, 'alert', 'A peer proposed a decision', 'A peer proposed "' || p_decision || '" on a ' || c.kind || '. It takes effect in ' || hrs
    || ' hours unless a party appeals; you may decide it first on Review.', '/admin/review#work', 'submission', c.submission_id, 'work:peer-case-admin:' || c.id);
  perform app.audit_add('peer.case_decided', 'member', me, jsonb_build_object('case', c.id, 'decision', p_decision), 'success');
  return jsonb_build_object('result', 'proposed', 'decision', p_decision, 'due_at', now() + make_interval(hours => hrs));
end $$;

create function app.peer_case_release(p_case uuid) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member();
begin
  update app.peer_cases x set status = 'released' where x.id = p_case and x.reviewer_member = me and x.status = 'assigned';
  return case when found then 'released' else 'not_yours' end;
end $$;

-- A party appeals a peer's proposed decision, within its window: the case waits for an administrator, the last appeal.
create function app.peer_case_appeal(p_case uuid, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); c record; worker uuid; poster uuid; opener uuid;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site appeals; an agent''s owner appeals for it.';
  end if;
  if p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then raise exception 'bad appeal' using errcode = '22023'; end if;
  select * into c from app.peer_cases x where x.id = p_case for update;
  if c.id is null then raise exception 'no such case' using errcode = 'P0002'; end if;
  if c.status <> 'proposed' then raise exception 'work_appeal_not_appealable' using errcode = 'P0001', hint = 'Only a peer''s decision still waiting to take effect can be appealed.'; end if;
  if c.due_at <= now() then raise exception 'work_appeal_late' using errcode = 'P0001', hint = 'The time to appeal this decision has passed.'; end if;
  select coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)),
         coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent))
    into worker, poster from app.work_submissions s join app.work_tasks t on t.id = s.task_id where s.id = c.submission_id;
  select d.member_id into opener from app.work_disputes d where d.id = c.dispute_id;
  if me is distinct from worker and me is distinct from poster and me is distinct from opener then
    raise exception 'only the worker, the poster or the one who disputed appeals a peer''s decision' using errcode = '42501';
  end if;
  update app.peer_cases x set status = 'appealed', appealed_by = me, appeal_reason = btrim(p_reason) where x.id = c.id;
  perform app.notify(null, 'alert', 'A peer''s decision was appealed', 'A party appealed a peer''s decision on a ' || c.kind || '. You are the last appeal: decide it on Review.',
    '/admin/review#work', 'submission', c.submission_id, 'work:peer-case-appeal:' || c.id);
  return 'appealed';
end $$;

-- The timer: a peer's decision nobody appealed takes effect when its window ends.
create function app.peer_cases_due() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare c record; n integer := 0;
begin
  for c in select * from app.peer_cases x where x.status = 'proposed' and x.due_at <= now() order by x.due_at limit 100 for update skip locked loop
    begin
      if c.kind = 'check' then
        perform app.work_check_apply(c.check_id, c.decision, 'Decided by a peer: ' || c.reason, c.reviewer_member, 'peer');
      else
        perform app.work_dispute_apply(c.dispute_id, c.decision, 'Decided by a peer: ' || c.reason, c.reviewer_member, 'peer');
      end if;
      update app.peer_cases x set status = 'applied' where x.id = c.id and x.status = 'proposed';
      n := n + 1;
    exception when others then
      -- One case that can't be applied never stops the rest (the fresh review, M5): it waits for the administrator.
      update app.peer_cases x set status = 'appealed', appeal_reason = 'The timer couldn''t apply it' where x.id = c.id;
      perform app.notify(null, 'alert', 'A peer''s decision couldn''t be applied', 'Decide it on Review.', '/admin/review#work', 'submission', c.submission_id, 'work:peer-case-failed:' || c.id);
    end;
  end loop;
  return n;
end $$;

-- ---- 3. Held work an administrator is a party to, that Third Look can't read, goes to peers too ----
create or replace function app.peer_review_take() returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); x record; rid uuid; why text; tried integer := 0;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site reviews work; an agent can''t.';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.peer'));
  update app.peer_reviews r set status = 'lapsed' where r.status = 'assigned' and r.expires_at <= now();
  if exists (select 1 from app.peer_reviews r where r.reviewer_member = me and r.status = 'assigned') then
    raise exception 'work_peer_busy' using errcode = 'P0001', hint = 'Finish or give back the review you have first.';
  end if;
  for x in select s.id as sub, s.task_id
             from app.work_submissions s join app.work_tasks t on t.id = s.task_id
            where s.status = 'review' and (s.route = 'admin' or (s.route = 'held' and s.artifact_kind <> 'pr'))
              and t.status <> all (array['closed', 'removed'])
              and coalesce(s.held_reason, '') not like 'The task''s poster didn''t check it%'
              and not exists (select 1 from app.peer_reviews r where r.submission_id = s.id and r.status = 'assigned')
              and (select count(*) from app.peer_reviews r where r.task_id = t.id and r.status = 'decided') < 3
            order by coalesce(s.routed_at, s.created_at) limit 200 loop
    tried := tried + 1;
    why := app.peer_block(me, x.sub);
    if why is null then
      insert into app.peer_reviews (submission_id, task_id, reviewer_member, expires_at)
        values (x.sub, x.task_id, me, now() + interval '24 hours') returning id into rid;
      perform app.audit_add('peer.taken', 'member', me, jsonb_build_object('review', rid, 'submission', x.sub), 'success');
      return jsonb_build_object('review', rid, 'submission', x.sub, 'task', x.task_id, 'expires_at', now() + interval '24 hours');
    end if;
  end loop;
  return jsonb_build_object('review', null, 'reason', case when tried = 0 then 'empty' else coalesce(why, 'empty') end);
end $$;

revoke execute on function app.peer_case_block(uuid, uuid, uuid), app.peer_case_take(), app.peer_case_decide(uuid, text, text),
  app.peer_case_release(uuid), app.peer_case_appeal(uuid, text), app.peer_cases_due() from public;
grant execute on function app.peer_case_take(), app.peer_case_decide(uuid, text, text), app.peer_case_release(uuid),
  app.peer_case_appeal(uuid, text), app.peer_cases_due() to dog_app;
reset role;
revoke create on schema app from dog_work;
