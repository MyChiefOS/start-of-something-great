-- 066 Failed peer verdicts can be checked, and count for calibration (Aaron, Nov 12, 2026, RK152: "route a random 15%
--   sample of failed peer-review verdicts (plus any buyer/worker appeal) for re-check, and lower the reviewer's
--   calibration score if a failed verdict is overturned").
--   * A sample: when a paid peer reviewer fails work, 15% of the time (work_settings.fail_sample_rate) it joins the
--     administrator's checks (042's app.work_checks, why 'peer_fail_sample'), on the Review page he already uses.
--   * An appeal: the worker (or the owner of the agent that did it) or the task's poster may appeal a peer fail, once,
--     within the dispute window (dispute_hours, 72 at the start), with a reason (why 'peer_fail_appeal').
--   * The check: confirming keeps the fail; reversing overturns it. An overturned fail is never "reversed" the way a
--     pass is (there are no points to take back): the worker and the administrators are told, and what the work is then
--     owed is put right by an administrator, by hand for now.
--   * Calibration: 045's statistics count a peer reviewer's checked fails beside their passes, held when confirmed.

alter table app.work_checks drop constraint work_checks_why_check;
alter table app.work_checks add constraint work_checks_why_check
  check (why = any (array['random', 'size', 'pair', 'note', 'third_look', 'peer_fail_sample', 'peer_fail_appeal']));
set local role dog_owner;
alter table app.work_checks add column appealed_by uuid references app.members (id) on delete set null;
alter table app.work_checks add column appeal_reason text check (char_length(appeal_reason) between 3 and 300);
create unique index work_checks_one_fail_check on app.work_checks (submission_id) where why = any (array['peer_fail_sample', 'peer_fail_appeal']);
alter table app.work_settings add column fail_sample_rate numeric(4,3) not null default 0.150 check (fail_sample_rate between 0 and 1);
grant update (appealed_by, appeal_reason) on app.work_checks to dog_work;
reset role;

grant create on schema app to dog_work;
set local role dog_work;
CREATE OR REPLACE FUNCTION app.peer_review_decide(p_review uuid, p_verdict text, p_reason text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare me uuid := app.current_member(); r record; s record; why text;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site reviews work for the fee; an agent can''t.';
  end if;
  if p_verdict is null or p_verdict <> all (array['pass', 'fail']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into r from app.peer_reviews x where x.id = p_review for update;
  if r.id is null or r.reviewer_member <> me then raise exception 'not your review' using errcode = '42501'; end if;
  if r.status <> 'assigned' or r.expires_at <= now() then
    update app.peer_reviews x set status = 'lapsed' where x.id = r.id and x.status = 'assigned';
    return 'lapsed';
  end if;
  select * into s from app.work_submissions x where x.id = r.submission_id for update;
  if s.status <> 'review' then
    update app.peer_reviews x set status = 'released' where x.id = r.id;
    return 'not_waiting';
  end if;
  -- The money must still be held for this work (H1): a task closed or refunded meanwhile gives no fee and no decision.
  if not exists (select 1 from app.work_bounties b join app.work_tasks t on t.id = b.task_id
                  where b.id = r.bounty_id and b.status = 'funded' and t.status <> all (array['closed', 'removed'])) then
    update app.peer_reviews x set status = 'released' where x.id = r.id;
    return 'not_waiting';
  end if;
  why := app.peer_block(me, r.submission_id);
  if why is not null then
    update app.peer_reviews x set status = 'released' where x.id = r.id;
    raise exception 'work_peer_blocked' using errcode = 'P0001', hint = 'You can''t review this work any more (' || why || '). It has gone back to the queue.';
  end if;
  insert into app.work_person_votes (submission_id, member_id, verdict, size, reason) values (r.submission_id, me, p_verdict, null, btrim(p_reason));
  perform app.work_finish(r.submission_id, p_verdict, 'peer', 100, btrim(p_reason));
  update app.peer_reviews x set status = 'decided', verdict = p_verdict, reason = btrim(p_reason), decided_at = now() where x.id = r.id;
  update app.peer_reviews x set fee_cents = app.bounty_peer_fee(r.id) where x.id = r.id;
  -- 066 (Aaron, Nov 12): a random share of peer fails (15% to start) is checked again by an administrator.
  if p_verdict = 'fail' and random() < (select st.fail_sample_rate from app.work_settings st where st.singleton) then
    insert into app.work_checks (submission_id, why) values (r.submission_id, 'peer_fail_sample') on conflict do nothing;
  end if;
  perform app.audit_add('peer.decided', 'member', me, jsonb_build_object('review', r.id, 'submission', r.submission_id, 'verdict', p_verdict), 'success');
  return p_verdict;
end $function$;

CREATE OR REPLACE FUNCTION app.work_check_decide(p_check uuid, p_decision text, p_reason text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
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
  -- 066: a check of a peer fail that disagrees overturns the fail (it lowers the reviewer's calibration, above), never
  -- reverses work that didn't pass. The worker and the administrators are told; what the work is owed then (it may have
  -- been claimed again, or the bounty refunded) is the administrator's to put right, by hand for now.
  if p_decision = 'reverse' and k.why = any (array['peer_fail_sample', 'peer_fail_appeal']) then
    -- The fresh review (M5): a GitHub-only worker has no member to tell; app.notify(null, ...) would send this to the
    -- administrators instead, so it is skipped then.
    if (select coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)) from app.work_submissions s where s.id = k.submission_id) is not null then
    perform app.notify((select coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)) from app.work_submissions s where s.id = k.submission_id),
      'work_decided', 'A failed verdict on your work was overturned', 'An administrator checked a peer reviewer''s fail on your work and disagreed. Aaron will put right what the work is owed.',
      '/tasks/' || (select s.task_id from app.work_submissions s where s.id = k.submission_id), 'submission', k.submission_id, 'work:fail-overturned:' || k.id);
    end if;
    perform app.notify(null, 'alert', 'A peer fail was overturned: put right what the work is owed', 'You overturned a peer reviewer''s fail. The work may have been claimed again or its bounty refunded; decide what it is owed.',
      '/admin/review#work', 'submission', k.submission_id, 'work:fail-overturned-admin:' || k.id);
  elsif p_decision = 'reverse' then
    perform app.work_reverse(k.submission_id, 'check', btrim(p_reason));
  end if;
  return p_decision;
end
$function$;

CREATE OR REPLACE FUNCTION app.work_stats(p_room uuid)
 RETURNS SETOF app.work_stat
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
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
    -- Calibration: a person's passes as the task's poster, an administrator or a paid peer reviewer (065), once settled;
    -- and (066) a peer reviewer's fails that were checked again.
    select 'member', v.member_id::text, 0, 0, 0, 0, 0, 0,
           count(*) filter (where s.status = 'passed'),
           count(*), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      from app.work_person_votes v join sub s on s.id = v.submission_id
     where v.verdict = 'pass' and v.member_id is not null and s.decided_by in ('poster', 'person', 'peer')
       and (s.status = 'reversed' or exists (select 1 from app.work_points p where p.submission_id = s.id and p.status = 'final'))
     group by v.member_id
    union all
    -- 066: a peer reviewer's fails that were checked again (a sample, or an appeal): held if the check confirmed them.
    select 'member', v.member_id::text, 0, 0, 0, 0, 0, 0,
           count(*) filter (where k.status = 'confirmed'),
           count(*), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      from app.work_person_votes v join sub s on s.id = v.submission_id
      join app.work_checks k on k.submission_id = s.id and k.why = any (array['peer_fail_sample', 'peer_fail_appeal']) and k.status <> 'open'
     where v.verdict = 'fail' and v.member_id is not null and s.decided_by = 'peer'
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
$function$;

-- An appeal of a peer fail: its worker (or the agent's owner) or its task's poster, once, within the dispute window.
create function app.work_fail_appeal(p_sub uuid, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); s record; t record; worker uuid; poster uuid; hrs integer;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site appeals a fail; an agent''s owner appeals for it.';
  end if;
  if p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then raise exception 'bad appeal' using errcode = '22023'; end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.id is null or s.status <> 'failed' or s.decided_by <> 'peer' then
    raise exception 'work_appeal_not_peer_fail' using errcode = 'P0001', hint = 'Only a fail decided by a paid peer reviewer can be appealed.';
  end if;
  select * into t from app.work_tasks x where x.id = s.task_id;
  worker := coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent));
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if me is distinct from worker and me is distinct from poster then raise exception 'only the worker or the poster appeals a fail' using errcode = '42501'; end if;
  select st.dispute_hours into hrs from app.work_settings st where st.singleton;
  if s.decided_at + make_interval(hours => hrs) <= now() then
    raise exception 'work_appeal_late' using errcode = 'P0001', hint = 'The time to appeal (' || hrs || ' hours after the decision) has passed.';
  end if;
  if exists (select 1 from app.work_checks k where k.submission_id = p_sub and k.why = any (array['peer_fail_sample', 'peer_fail_appeal'])) then
    -- Already being checked (a sample), or appealed: the appeal joins it. Already decided (the fresh review, M3): say so,
    -- rather than answer as if the appeal were recorded.
    if not exists (select 1 from app.work_checks k where k.submission_id = p_sub and k.why = any (array['peer_fail_sample', 'peer_fail_appeal']) and k.status = 'open') then
      raise exception 'work_appeal_checked' using errcode = 'P0001', hint = 'An administrator has already checked this fail.';
    end if;
    update app.work_checks k set appealed_by = coalesce(k.appealed_by, me), appeal_reason = coalesce(k.appeal_reason, btrim(p_reason))
     where k.submission_id = p_sub and k.why = any (array['peer_fail_sample', 'peer_fail_appeal']) and k.status = 'open';
    return 'already';
  end if;
  insert into app.work_checks (submission_id, why, appealed_by, appeal_reason) values (p_sub, 'peer_fail_appeal', me, btrim(p_reason));
  perform app.notify(null, 'alert', 'A peer fail was appealed', 'The worker or the poster appealed a paid peer reviewer''s fail. Check it on Review.',
    '/admin/review#work', 'submission', p_sub, 'work:fail-appeal:' || p_sub);
  return 'appealed';
end $$;
revoke execute on function app.work_fail_appeal(uuid, text) from public;
grant execute on function app.work_fail_appeal(uuid, text) to dog_app;
-- The fresh review (H2): the Review page shows a check's appeal and its reason (only the administrator reads this).
create or replace function app.work_admin()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator' using errcode = '42501'; end if;
  -- Each item says whether the administrator reading it may decide it ('party': he did the work or opened the dispute;
  -- since 052 a dispute of his own task is his). A dispute carries Third Look's review of the work, as Aaron asked
  -- ("Third look can weigh in"); work still to be decided doesn't, so the person deciding it isn't swayed by it (047).
  return jsonb_build_object('generated_at', now(),
    'waiting', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('submission', s.id, 'jevs_rules', s.jevs_rules, 'note', s.note, 'held_reason', s.held_reason,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256), 'party', app.work_party(s.id, me))
                         order by s.created_at)
                        from app.work_submissions s where s.status = 'review' and s.route = 'admin'), '[]'::jsonb),
    'checks', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('check', k.id, 'submission', s.id, 'why', k.why, 'note', s.note,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256),
                           'decided_by', s.decided_by, 'reason', s.reason, 'party', app.work_party(s.id, me),
                           'appealed', k.appealed_by is not null, 'appeal_reason', k.appeal_reason) order by k.created_at)
                       from app.work_checks k join app.work_submissions s on s.id = k.submission_id where k.status = 'open'), '[]'::jsonb),
    'disputes', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('dispute', d.id, 'submission', s.id, 'dispute_reason', d.reason,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256),
                           'decided_by', s.decided_by, 'reason', s.reason, 'party', app.work_may_settle(d.id, me) <> 'any', 'may', app.work_may_settle(d.id, me), 'third_look', (select jsonb_build_object('suggestion', r.suggestion, 'answers', r.answers, 'reason', r.reason, 'at', r.decided_at) from app.tl_reviews r where r.submission_id = s.id and r.decided_at is not null)) order by d.created_at)
                         from app.work_disputes d join app.work_submissions s on s.id = d.submission_id where d.status = 'open'), '[]'::jsonb),
    'held', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'held'));
end
$$;

reset role;
revoke create on schema app from dog_work;
