-- 067 The zero-payment launch (Aaron, Nov 21, 2026: "Provide a plan to launch the system with a Zero Payment trust
--   platform ... then prepare the PR for my approval", after the audit of the same day). Day One Great offers no
--   payments: people and their agents agree to tasks, do them and have them verified, and the result is reputation
--   that has no money value and can never be redeemed. The payment code (061 to 066) stays in place, dormant; this
--   migration locks it in the database itself, so turning money on again takes a migration Aaron merges.
--
--   1. The money lock: no row can be added to, changed in or removed from work_bounties, pay_requests, pay_accounts,
--      pay_ledger or pay_events. Until now the switch lived only in the site's code (db/pay.js, payments.json): the
--      audit's gap G12 (and the fresh review's H1: inserts alone left updates open).
--   2. Draft mode holds at the work steps that commit to something: an agent whose owner's rules are "draft" can't
--      claim a task, submit work or post a task (gap G4). It can still read its work, release, cancel and add
--      evidence (the fresh review's H2: blocking it at sign-in locked it out of its own tasks). "Off" already stopped it.
--   6. Peer review without pay (Aaron, Nov 21: "I want peer reviews performed they will not be paid"): a level-2
--      member reviews held work on any task, funded or not, and no fee is ever queued. The reviewer's verdict counts
--      for calibration, as before; reviewing earns no points, so nobody farms reviews. The top-tenth rule (065) is
--      dropped: it needs 10 established auditors in a room, so no one could ever review on a new platform. The
--      blocks against parties, collaborators and repeat reviewing stay. A peer's pass is checked after: always between
--      a pair that may be gaming, otherwise one in five; 15% of peer fails are checked again (066); canaries test too.
--   3. Every work action records the version of its agent's owner's rules that allowed it (gap G4).
--   4. Any fail can be appealed once within the dispute window by the worker (or the agent's owner) or the poster,
--      whoever decided it, except the administrator's own decision (gap G11). 066 allowed it for peer fails only.
--   5. The points ledger's purpose, restated: points are reputation, never money (gap G7; 048 said they could "back
--      payments later").

-- ---- 1. The money lock ----
set local role dog_owner;
create function app.money_locked() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  raise exception 'money_off' using errcode = 'P0001', hint = 'Day One Great offers no payments: nothing is funded, charged, paid out or refunded.';
end $$;
revoke execute on function app.money_locked() from public;
create trigger money_locked before insert or update or delete on app.work_bounties for each row execute function app.money_locked();
create trigger money_locked before insert or update or delete on app.pay_requests for each row execute function app.money_locked();
create trigger money_locked before insert or update or delete on app.pay_accounts for each row execute function app.money_locked();
create trigger money_locked before insert or update or delete on app.pay_ledger for each row execute function app.money_locked();
create trigger money_locked before insert or update or delete on app.pay_events for each row execute function app.money_locked();
-- The fresh review of 067 (M2): emptying a table is refused too, and the locks fire whatever the session's
-- replication role (as 001 does for the audit log). Only a migration Aaron merges can lift them.
create function app.money_locked_stmt() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  raise exception 'money_off' using errcode = 'P0001', hint = 'Day One Great offers no payments: nothing is funded, charged, paid out or refunded.';
end $$;
revoke execute on function app.money_locked_stmt() from public;
create trigger money_locked_truncate before truncate on app.work_bounties for each statement execute function app.money_locked_stmt();
create trigger money_locked_truncate before truncate on app.pay_requests for each statement execute function app.money_locked_stmt();
create trigger money_locked_truncate before truncate on app.pay_accounts for each statement execute function app.money_locked_stmt();
create trigger money_locked_truncate before truncate on app.pay_ledger for each statement execute function app.money_locked_stmt();
create trigger money_locked_truncate before truncate on app.pay_events for each statement execute function app.money_locked_stmt();
alter table app.work_bounties enable always trigger money_locked, enable always trigger money_locked_truncate;
alter table app.pay_requests enable always trigger money_locked, enable always trigger money_locked_truncate;
alter table app.pay_accounts enable always trigger money_locked, enable always trigger money_locked_truncate;
alter table app.pay_ledger enable always trigger money_locked, enable always trigger money_locked_truncate;
alter table app.pay_events enable always trigger money_locked, enable always trigger money_locked_truncate;
reset role;

-- ---- 3. The owner's rules version on every work action ----
set local role dog_owner;
alter table app.work_actions add column rules_version integer;
create function app.work_action_rules() returns trigger
language plpgsql set search_path = pg_catalog as $$
declare mode text;
begin
  if new.agent_id is not null then
    select r.version, r.post_mode into new.rules_version, mode from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
    -- 2. Draft mode means the owner approves each step; work has no approval step yet, so the steps that commit to
    -- something (claim, submit, post: every kind of work action) wait for the owner to switch the agent to acting.
    if mode = 'draft' then
      raise exception 'work_draft' using errcode = 'P0001', hint = 'Your owner''s rules are in draft mode, where every action waits for them; claiming, submitting and posting work have no such step yet, so ask your owner to switch you to acting.';
    end if;
  end if;
  return new;
end $$;
revoke execute on function app.work_action_rules() from public;
create trigger work_action_rules before insert on app.work_actions for each row execute function app.work_action_rules();
reset role;

-- ---- 4. Appeals for any fail: the kind of check ----
alter table app.work_checks drop constraint work_checks_why_check;
alter table app.work_checks add constraint work_checks_why_check
  check (why = any (array['random', 'size', 'pair', 'note', 'third_look', 'peer_fail_sample', 'peer_fail_appeal', 'fail_appeal']));
set local role dog_owner;
drop index app.work_checks_one_fail_check;
create unique index work_checks_one_fail_check on app.work_checks (submission_id) where why = any (array['peer_fail_sample', 'peer_fail_appeal', 'fail_appeal']);
reset role;

-- ---- 2 and 4. The work module's functions, in its own role ----
grant create on schema app to dog_work;
set local role dog_work;

-- (2. moved: the draft check now lives in app.work_action_rules, above; 042's work_who stands unchanged.)

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
  -- 066, and since 067 any appealed fail: a check of a fail that disagrees overturns the fail (it lowers the reviewer's calibration, above), never
  -- reverses work that didn't pass. The worker and the administrators are told; what the work is owed then (it may have
  -- been claimed again, or the bounty refunded) is the administrator's to put right, by hand for now.
  if p_decision = 'reverse' and k.why = any (array['peer_fail_sample', 'peer_fail_appeal', 'fail_appeal']) then
    -- The fresh review (M5): a GitHub-only worker has no member to tell; app.notify(null, ...) would send this to the
    -- administrators instead, so it is skipped then.
    if (select coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)) from app.work_submissions s where s.id = k.submission_id) is not null then
    perform app.notify((select coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)) from app.work_submissions s where s.id = k.submission_id),
      'work_decided', 'A failed verdict on your work was overturned', 'An administrator checked a fail on your work and disagreed. Aaron will put right what the work is owed.',
      '/tasks/' || (select s.task_id from app.work_submissions s where s.id = k.submission_id), 'submission', k.submission_id, 'work:fail-overturned:' || k.id);
    end if;
    perform app.notify(null, 'alert', 'A fail was overturned: put right what the work is owed', 'You overturned a fail. The work may have been claimed again; decide what it is owed (its points, or reopening the task).',
      '/admin/review#work', 'submission', k.submission_id, 'work:fail-overturned-admin:' || k.id);
  elsif p_decision = 'reverse' then
    perform app.work_reverse(k.submission_id, 'check', btrim(p_reason));
  end if;
  return p_decision;
end
$function$;

create or replace function app.work_fail_appeal(p_sub uuid, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); s record; t record; worker uuid; poster uuid; hrs integer;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site appeals a fail; an agent''s owner appeals for it.';
  end if;
  if p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then raise exception 'bad appeal' using errcode = '22023'; end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  -- 067 (Aaron, Nov 21, the zero-payment launch; the audit's gap G11): any fail can be appealed, whoever decided it,
  -- except the administrator's own decision ('person'), which an appeal would send back to him.
  if s.id is null or s.status <> 'failed' or s.decided_by is null or s.decided_by not in ('peer', 'poster', 'jevs', 'timeout', 'third_look') then
    raise exception 'work_appeal_not_appealable' using errcode = 'P0001', hint = 'Only a fail decided by the rules, the poster, a reviewer or a timeout can be appealed; the administrator''s own decision can''t.';
  end if;
  select * into t from app.work_tasks x where x.id = s.task_id;
  worker := coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent));
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if me is distinct from worker and me is distinct from poster then raise exception 'only the worker or the poster appeals a fail' using errcode = '42501'; end if;
  select st.dispute_hours into hrs from app.work_settings st where st.singleton;
  if s.decided_at + make_interval(hours => hrs) <= now() then
    raise exception 'work_appeal_late' using errcode = 'P0001', hint = 'The time to appeal (' || hrs || ' hours after the decision) has passed.';
  end if;
  if exists (select 1 from app.work_checks k where k.submission_id = p_sub and k.why = any (array['peer_fail_sample', 'peer_fail_appeal', 'fail_appeal'])) then
    -- Already being checked (a sample), or appealed: the appeal joins it. Already decided (the fresh review, M3): say so,
    -- rather than answer as if the appeal were recorded.
    if not exists (select 1 from app.work_checks k where k.submission_id = p_sub and k.why = any (array['peer_fail_sample', 'peer_fail_appeal', 'fail_appeal']) and k.status = 'open') then
      raise exception 'work_appeal_checked' using errcode = 'P0001', hint = 'An administrator has already checked this fail.';
    end if;
    update app.work_checks k set appealed_by = coalesce(k.appealed_by, me), appeal_reason = coalesce(k.appeal_reason, btrim(p_reason))
     where k.submission_id = p_sub and k.why = any (array['peer_fail_sample', 'peer_fail_appeal', 'fail_appeal']) and k.status = 'open';
    return 'already';
  end if;
  insert into app.work_checks (submission_id, why, appealed_by, appeal_reason) values (p_sub, case when s.decided_by = 'peer' then 'peer_fail_appeal' else 'fail_appeal' end, me, btrim(p_reason));
  perform app.notify(null, 'alert', 'A fail was appealed', 'The worker or the poster appealed a fail. Check it on Review.',
    '/admin/review#work', 'submission', p_sub, 'work:fail-appeal:' || p_sub);
  return 'appealed';
end $$;
revoke execute on function app.work_fail_appeal(uuid, text) from public;
grant execute on function app.work_fail_appeal(uuid, text) to dog_app;

-- ---- 6. Peer review without pay ----
-- 065's blocks, without the payouts and top-tenth rules.
create or replace function app.peer_block(p_member uuid, p_sub uuid) returns text
language plpgsql stable security definer set search_path = pg_catalog as $$
declare s record; t record; m record; worker uuid; poster uuid;
begin
  select * into s from app.work_submissions x where x.id = p_sub;
  select * into t from app.work_tasks x where x.id = s.task_id;
  select x.id, x.status, x.trust_level, x.is_admin into m from app.members x where x.id = p_member;
  if m.id is null or m.status <> 'active' then return 'inactive'; end if;
  if m.is_admin then return 'admin'; end if;
  if app.is_buyer(p_member) then return 'buyer'; end if;
  if m.trust_level < 2 then return 'level'; end if;
  if s.worker_kind not in ('member', 'agent') then return 'github_worker'; end if;
  worker := coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent));
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if p_member = worker or p_member = poster then return 'party'; end if;
  if exists (select 1 from app.work_submissions x join app.work_tasks y on y.id = x.task_id
              cross join lateral (select coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) as w,
                                         coalesce(y.poster_member, (select g.owner_id from app.agents g where g.id = y.poster_agent)) as p) z
              where x.created_at > now() - interval '90 days' and x.task_id <> s.task_id
                and ((z.w = p_member and z.p in (worker, poster)) or (z.p = p_member and z.w in (worker, poster)))) then
    return 'collaborated';
  end if;
  if (select count(*) from app.peer_reviews r join app.work_submissions x on x.id = r.submission_id
       where r.reviewer_member = p_member and r.status = 'decided' and r.decided_at > now() - interval '30 days'
         and coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) = worker) >= 3 then
    return 'rotation';
  end if;
  if (select count(*) from app.peer_reviews r join app.work_tasks y on y.id = r.task_id
       where r.reviewer_member = p_member and r.status = 'decided' and r.decided_at > now() - interval '30 days'
         and coalesce(y.poster_member, (select g.owner_id from app.agents g where g.id = y.poster_agent)) = poster) >= 3 then
    return 'rotation';
  end if;
  return null;
end $$;

-- Take the oldest held work on any open task (no bounty needed), for 24 hours, one at a time.
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
            where s.status = 'review' and s.route = 'admin' and t.status <> all (array['closed', 'removed'])
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

-- Decide pass or fail with a reason. No fee: fee_cents stays empty.
create or replace function app.peer_review_decide(p_review uuid, p_verdict text, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); r record; s record; why text;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site reviews work; an agent can''t.';
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
  if s.status <> 'review' or exists (select 1 from app.work_tasks t where t.id = r.task_id and t.status = any (array['closed', 'removed'])) then
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
  -- 066, kept: a random share of peer fails (15% to start) is checked again by an administrator.
  if p_verdict = 'fail' and random() < (select st.fail_sample_rate from app.work_settings st where st.singleton) then
    insert into app.work_checks (submission_id, why) values (r.submission_id, 'peer_fail_sample') on conflict do nothing;
  end if;
  -- The fresh review of 067 (H1): a peer's pass is checked after, as a poster's is (052), and more often, since it
  -- clears work the rules held for its risk: every pass between a pair that may be gaming, and one in five of the rest
  -- (Third Look's own re-check rate, 047's tl_check_rate). Its points stay pending until the check is decided.
  if p_verdict = 'pass' then
    if app.work_pair_watch(r.submission_id, (select coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) from app.work_tasks t where t.id = r.task_id)) then
      insert into app.work_checks (submission_id, why) values (r.submission_id, 'pair');
    elsif random() < (select st.tl_check_rate from app.work_settings st where st.singleton) then
      insert into app.work_checks (submission_id, why) values (r.submission_id, 'random');
    end if;
  end if;
  perform app.audit_add('peer.decided', 'member', me, jsonb_build_object('review', r.id, 'submission', r.submission_id, 'verdict', p_verdict), 'success');
  return p_verdict;
end $$;
reset role;
revoke create on schema app from dog_work;

-- ---- 5. What points are ----
set local role dog_owner;
comment on table app.work_point_entries is 'Reputation, never money (067, Aaron, Nov 21, 2026): points record verified work; they have no money value and can''t be redeemed, exchanged or transferred.';
reset role;
