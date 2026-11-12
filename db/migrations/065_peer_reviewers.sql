-- 065 Paid peer reviewers, a buyer's backup passkey, and the last hardening of the Nov 11 sprint (Aaron, Nov 11 and 12,
--   2026).
--
--   1. The paid peer reviewer queue (Aaron: "Route medium/high-risk JEVs holds to top-decile calibrated, KYC-eligible
--      operators in the matching SOC Room for the 2% audit fee (paid out of our 15% platform fee, never staked
--      collateral), with strict anti-collusion/self-review blocks"). Work the JEVs auditor held for a person (route
--      'admin' or 'held', status 'review') on a task with a funded bounty may be taken by an eligible member, one at a
--      time, for 24 hours, and decided pass or fail with a reason. It finishes as any person's decision does (042's
--      app.work_finish), recorded as decided by 'peer', with the reviewer's vote kept for calibration. The
--      administrator can still decide it first; the assignment then lapses.
--      Only work held for a person by JEVs's risk rules (route 'admin'), not a poster's timeout and not work an
--      administrator is a party to (route 'held', Third Look's). Eligible: a person (never an agent, never a buyer
--      account, 063, never an administrator), active, at JEVs level 2, with payouts set up at
--      Stripe (Connect Express's own identity checks: Aaron's Nov 11 "payout identity"), and in the top decile for
--      calibration among auditors in the task's room (045's leaderboard band 'top10', which needs an established
--      record). Blocked: the worker, the poster, either one's agent owner, anyone who worked with either of them, in
--      either role, in the last 90 days, and a reviewer who has already decided 3 of this worker's submissions, or 3 of
--      this poster's tasks, in 30 days. Each block is checked when the work is taken and again when it is decided.
--      At most 3 paid peer reviews per task; after that the administrator decides, as before.
--   2. The fee (Aaron, Nov 12): 2% of the bounty on every completed review, pass or fail, so no reviewer earns by
--      passing. On a pass the bounty splits 85% to the worker, 13% to ChiefOS, 2% to the reviewer. After a peer-reviewed
--      fail, the 2% stays from the escrow for the reviewer, and a refund returns the bounty less those fees (98% after
--      one review); a task cancelled before any peer review is refunded in full. The payment function sends each fee as
--      a Stripe transfer to the reviewer's connected account (dog-pay, 'reviewer_fee').
--   3. Calibration (Aaron: overturned verdicts drop it): 045's calibration now counts a peer reviewer's passes, held
--      or reversed, as it counts a poster's. A fail has no appeal in the work module today, so only passes can be
--      overturned.
--   4. A buyer's backup passkey (Aaron, Nov 12, RK151): a signed-in buyer, from a fresh session, adds one more buyer
--      key, at most 2. No email is ever kept.

-- ---- The tables ----
alter table app.work_submissions drop constraint work_submissions_decided_by_check;
alter table app.work_submissions add constraint work_submissions_decided_by_check
  check (decided_by = any (array['jevs', 'poster', 'person', 'timeout', 'third_look', 'peer']));

set local role dog_owner;
create table app.peer_reviews (
  id uuid primary key default app.uuid_v7(),
  submission_id uuid not null references app.work_submissions (id) on delete cascade,
  task_id uuid not null references app.work_tasks (id) on delete cascade,
  bounty_id uuid references app.work_bounties (id) on delete set null,
  reviewer_member uuid not null references app.members (id) on delete cascade,
  status text not null default 'assigned' check (status = any (array['assigned', 'decided', 'lapsed', 'released'])),
  verdict text check (verdict = any (array['pass', 'fail'])),
  reason text check (char_length(reason) between 3 and 300),
  fee_cents integer check (fee_cents between 0 and 100000000),
  assigned_at timestamptz not null default now(),
  expires_at timestamptz not null,
  decided_at timestamptz,
  check ((status = 'decided') = (verdict is not null and decided_at is not null))
);
create unique index peer_reviews_one_open on app.peer_reviews (submission_id) where status = 'assigned';
create index peer_reviews_reviewer on app.peer_reviews (reviewer_member, assigned_at desc);
create index peer_reviews_task on app.peer_reviews (task_id) where status = 'decided';
alter table app.peer_reviews enable row level security;
alter table app.peer_reviews force row level security;
create policy peer_reviews_work on app.peer_reviews for all to dog_work using (true) with check (true);
create policy peer_reviews_pay_select on app.peer_reviews for select to dog_pay using (true);
create policy peer_reviews_app on app.peer_reviews for select to dog_app using (reviewer_member = (select app.current_member()) or (select app.actor_kind()) = 'admin');
grant select, insert, update on app.peer_reviews to dog_work;
grant select (id, submission_id, task_id, bounty_id, reviewer_member, status, verdict, fee_cents, decided_at) on app.peer_reviews to dog_pay;
-- The site reads a reviewer's own rows (and the administrator all); row-level security limits the rows.
grant select on app.peer_reviews to dog_app;

-- The fee's request and its ledger line.
alter table app.pay_requests add column peer_review_id uuid references app.peer_reviews (id) on delete set null;
alter table app.pay_requests drop constraint pay_requests_kind_check;
alter table app.pay_requests add constraint pay_requests_kind_check
  check (kind = any (array['connect_onboard', 'fund_task', 'release', 'refund', 'reverse', 'reconcile', 'reviewer_fee']));
-- 061's rule that a bounty's kinds name their bounty, with the fee among them.
alter table app.pay_requests drop constraint pay_requests_check;
alter table app.pay_requests add constraint pay_requests_check
  check ((kind = any (array['fund_task', 'release', 'refund', 'reverse', 'reviewer_fee'])) = (bounty_id is not null) or bounty_id is null);
alter table app.pay_requests add constraint pay_requests_reviewer_fee_check
  check ((kind = 'reviewer_fee') = (peer_review_id is not null) and (kind <> 'reviewer_fee' or bounty_id is not null));
create unique index pay_requests_one_reviewer_fee on app.pay_requests (peer_review_id) where kind = 'reviewer_fee' and status <> 'failed';
alter table app.pay_ledger drop constraint pay_ledger_kind_check;
alter table app.pay_ledger add constraint pay_ledger_kind_check
  check (kind = any (array['charge', 'transfer', 'refund', 'reversal', 'chargeback', 'reviewer_fee']));
grant select (id, member_id, payouts_enabled) on app.pay_accounts to dog_work;
create policy pay_accounts_work_select on app.pay_accounts for select to dog_work using (true);
grant select (id, task_id, status, bounty_cents, reviewer_fee_bps) on app.work_bounties to dog_work;
create policy work_bounties_work_select on app.work_bounties for select to dog_work using (true);
grant update (peer_review_id) on app.pay_requests to dog_pay;
create index pay_requests_review on app.pay_requests (peer_review_id) where peer_review_id is not null;
-- Three paid reviews never take more than the platform's fee (the red-team review of PR #5, L3).
alter table app.work_bounties add constraint work_bounties_review_fees_check check (3 * reviewer_fee_bps <= platform_fee_bps);

-- ---- 4. A buyer's backup key: at most 2 keys a buyer ----
alter table app.buyer_keys drop constraint buyer_keys_member_id_key;
create index buyer_keys_member on app.buyer_keys (member_id);
reset role;

-- A peer reviewer is never a buyer account (063's scope). Rights on a function are its owner's to give.
set local role dog_signin;
grant execute on function app.buyer_scope() to dog_owner;
reset role;
set local role dog_owner;
create trigger a_buyer_scope before insert or update of reviewer_member on app.peer_reviews for each row execute function app.buyer_scope('reviewer_member');
reset role;
set local role dog_signin;
revoke execute on function app.buyer_scope() from dog_owner;
reset role;

-- ---- 2. The payment role's two steps for the fee ----
grant create on schema app to dog_pay;
set local role dog_pay;
-- A decided peer review's fee: 2% of its bounty (the bounty's reviewer_fee_bps), queued as a transfer to the reviewer.
-- Once, whatever happens to the bounty afterwards (the fee is for the review, Aaron's Nov 12 rule).
create function app.bounty_peer_fee(p_review uuid) returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare r record; b record; cents integer;
begin
  select x.id, x.status, x.bounty_id, x.reviewer_member into r from app.peer_reviews x where x.id = p_review;
  if r.id is null or r.status <> 'decided' or r.bounty_id is null then return 0; end if;
  select * into b from app.work_bounties x where x.id = r.bounty_id;
  -- Only while the money is still held for the work (the red-team review of PR #5, H1: never after a refund began).
  if b.id is null or b.status <> all (array['funded', 'releasing', 'transferring', 'awaiting_payee', 'released']) then return 0; end if;
  cents := (b.bounty_cents * b.reviewer_fee_bps) / 10000;
  if cents <= 0 then return 0; end if;
  insert into app.pay_requests (member_id, kind, bounty_id, peer_review_id) values (r.reviewer_member, 'reviewer_fee', b.id, r.id) on conflict do nothing;
  return cents;
end $$;
-- What a refund returns: the bounty less every fee its peer reviews earned (98% after one; 100% before any).
create function app.bounty_refund_cents(p_bounty uuid) returns integer
language sql stable security definer set search_path = pg_catalog as $$
  -- Only fees actually owed: a review whose fee request failed for good, or never queued, takes nothing (L1).
  select greatest(0, b.bounty_cents - ((b.bounty_cents * b.reviewer_fee_bps) / 10000)
                    * (select count(*) from app.peer_reviews r where r.bounty_id = b.id and r.status = 'decided'
                         and exists (select 1 from app.pay_requests q where q.peer_review_id = r.id and q.kind = 'reviewer_fee' and q.status <> 'failed')))::integer
    from app.work_bounties b where b.id = p_bounty
$$;
revoke execute on function app.bounty_peer_fee(uuid), app.bounty_refund_cents(uuid) from public;
grant execute on function app.bounty_peer_fee(uuid) to dog_work;
reset role;
revoke create on schema app from dog_pay;

-- ---- 1. The queue (the work role's) ----
grant create on schema app to dog_work;
set local role dog_work;

-- In the top tenth for calibration among the auditors of this room (045's leaderboard band 'top10'). 045 lists an
-- auditor in a room only if they have done work there, and gives a band only to an established record (10 audited
-- items), so a room needs at least 10 established auditors before anyone in it is in the top tenth.
create function app.peer_top_decile(p_member uuid, p_room text) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce((select c ->> 'band' = 'top10' from jsonb_array_elements(app.work_board('auditors', p_room, 'calibration') -> 'citizens') c
                    where c ->> 'kind' = 'member' and c ->> 'id' = p_member::text limit 1), false)
$$;

-- Why this member may not review this submission, or null when they may. Every block named above; read again at
-- decision time, so a block that arrives meanwhile still holds.
create function app.peer_block(p_member uuid, p_sub uuid) returns text
language plpgsql stable security definer set search_path = pg_catalog as $$
declare s record; t record; m record; worker uuid; poster uuid; code text;
begin
  select * into s from app.work_submissions x where x.id = p_sub;
  select * into t from app.work_tasks x where x.id = s.task_id;
  select x.id, x.status, x.trust_level, x.is_admin into m from app.members x where x.id = p_member;
  if m.id is null or m.status <> 'active' then return 'inactive'; end if;
  -- The administrator decides held work as the administrator, never for the fee (the red-team review of PR #5, L4).
  if m.is_admin then return 'admin'; end if;
  if app.is_buyer(p_member) then return 'buyer'; end if;
  if m.trust_level < 2 then return 'level'; end if;
  if not exists (select 1 from app.pay_accounts a where a.member_id = p_member and a.payouts_enabled) then return 'payouts'; end if;
  if s.worker_kind not in ('member', 'agent') then return 'github_worker'; end if;
  worker := coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent));
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if p_member = worker or p_member = poster then return 'party'; end if;
  -- Collaboration in the last 90 days, either way round (the red-team review of PR #5, M1): any audited or submitted
  -- work between the reviewer and the worker or the poster, whoever posted and whoever did it.
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
  -- And per poster: no more than 3 of one poster's tasks in 30 days (M3).
  if (select count(*) from app.peer_reviews r join app.work_tasks y on y.id = r.task_id
       where r.reviewer_member = p_member and r.status = 'decided' and r.decided_at > now() - interval '30 days'
         and coalesce(y.poster_member, (select g.owner_id from app.agents g where g.id = y.poster_agent)) = poster) >= 3 then
    return 'rotation';
  end if;
  select r.code into code from app.work_rooms r where r.id = t.room_id;
  if not app.peer_top_decile(p_member, code) then return 'not_top_decile'; end if;
  return null;
end $$;

-- An eligible member takes the oldest held work on a funded task they may review, for 24 hours. One at a time.
create function app.peer_review_take() returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); x record; rid uuid; why text; tried integer := 0;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'work_peer_person' using errcode = 'P0001', hint = 'Only a person signed in on the site reviews work for the fee; an agent can''t.';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.peer'));
  update app.peer_reviews r set status = 'lapsed' where r.status = 'assigned' and r.expires_at <= now();
  if exists (select 1 from app.peer_reviews r where r.reviewer_member = me and r.status = 'assigned') then
    raise exception 'work_peer_busy' using errcode = 'P0001', hint = 'Finish or give back the review you have first.';
  end if;
  for x in select s.id as sub, s.task_id, b.id as bounty
             from app.work_submissions s join app.work_tasks t on t.id = s.task_id
             join app.work_bounties b on b.task_id = t.id and b.status = 'funded'
            -- Work JEVs held for a person (route 'admin'); not work sent there only because its poster didn't check it in
            -- time, and not 'held' work, which an administrator is a party to and 052 keeps for Third Look (the red-team
            -- review of PR #5, M2).
            where s.status = 'review' and s.route = 'admin'
              and coalesce(s.held_reason, '') not like 'The task''s poster didn''t check it%'
              and not exists (select 1 from app.peer_reviews r where r.submission_id = s.id and r.status = 'assigned')
              and (select count(*) from app.peer_reviews r where r.task_id = t.id and r.status = 'decided') < 3
            order by coalesce(s.routed_at, s.created_at) limit 200 loop
    tried := tried + 1;
    why := app.peer_block(me, x.sub);
    if why is null then
      insert into app.peer_reviews (submission_id, task_id, bounty_id, reviewer_member, expires_at)
        values (x.sub, x.task_id, x.bounty, me, now() + interval '24 hours') returning id into rid;
      perform app.audit_add('peer.taken', 'member', me, jsonb_build_object('review', rid, 'submission', x.sub), 'success');
      return jsonb_build_object('review', rid, 'submission', x.sub, 'task', x.task_id, 'expires_at', now() + interval '24 hours');
    end if;
  end loop;
  return jsonb_build_object('review', null, 'reason', case when tried = 0 then 'empty' else coalesce(why, 'empty') end);
end $$;

-- The reviewer decides: pass or fail, with a reason. The blocks are read again; the fee is queued either way.
create function app.peer_review_decide(p_review uuid, p_verdict text, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
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
  perform app.audit_add('peer.decided', 'member', me, jsonb_build_object('review', r.id, 'submission', r.submission_id, 'verdict', p_verdict), 'success');
  return p_verdict;
end $$;

-- The reviewer gives the work back to the queue.
create function app.peer_review_release(p_review uuid) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member();
begin
  update app.peer_reviews x set status = 'released' where x.id = p_review and x.reviewer_member = me and x.status = 'assigned';
  return case when found then 'released' else 'not_yours' end;
end $$;

-- 3. 045's statistics, unchanged but that a peer reviewer's passes count for calibration.
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
    -- Calibration: a person's passes as the task's poster, an administrator or a paid peer reviewer (065), once settled.
    select 'member', v.member_id::text, 0, 0, 0, 0, 0, 0,
           count(*) filter (where s.status = 'passed'),
           count(*), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      from app.work_person_votes v join sub s on s.id = v.submission_id
     where v.verdict = 'pass' and v.member_id is not null and s.decided_by in ('poster', 'person', 'peer')
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
$function$;

revoke execute on function app.peer_top_decile(uuid, text), app.peer_block(uuid, uuid), app.peer_review_take(), app.peer_review_decide(uuid, text, text),
  app.peer_review_release(uuid) from public;
grant execute on function app.peer_review_take(), app.peer_review_decide(uuid, text, text), app.peer_review_release(uuid) to dog_app;
reset role;
revoke create on schema app from dog_work;
-- The queue reads 063's is_buyer and 061's fee step.

-- ---- 4. A buyer's backup key (Aaron, Nov 12, RK151) ----
grant create on schema app to dog_signin;
set local role dog_signin;
-- A new key's attested credential, checked exactly as 063's app.buyer_register checks it: the browser's report and the
-- authenticator's data (app.buyer_webauthn, which uses up the challenge), the attested credential flag, this credential
-- ID and, right after it, this public key as an ES256 P-256 COSE key in CTAP2's canonical form. The counter, or null.
create function app.buyer_attested(p_credential_id bytea, p_public_key bytea, p_client_data bytea, p_auth_data bytea) returns bigint
language plpgsql security definer set search_path = pg_catalog as $$
declare n bigint; len integer; rest bytea;
begin
  if p_credential_id is null or octet_length(p_credential_id) not between 16 and 1023 or p_public_key is null or not app.p256_point_ok(p_public_key) then
    return null;
  end if;
  n := app.buyer_webauthn('webauthn.create', p_client_data, p_auth_data);
  if n is null or get_byte(p_auth_data, 32) & 64 = 0 or octet_length(p_auth_data) < 55 + octet_length(p_credential_id) then return null; end if;
  len := (get_byte(p_auth_data, 53) << 8) + get_byte(p_auth_data, 54);
  rest := substring(p_auth_data from 56 + len for 77);
  if len <> octet_length(p_credential_id) or substring(p_auth_data from 56 for len) <> p_credential_id
     or rest <> '\xa5010203262001215820'::bytea || substring(p_public_key from 2 for 32) || '\x225820'::bytea || substring(p_public_key from 34 for 32) then
    return null;
  end if;
  return n;
end $$;

-- A signed-in buyer adds one backup key, from a session begun in the last 10 minutes (by the database's clock, as
-- PR 15's links are), so a stolen or forgotten session can't add its holder's key. At most 2 keys; the member is told.
create function app.buyer_key_backup(p_credential_id bytea, p_public_key bytea, p_client_data bytea, p_auth_data bytea, p_session_hash text)
returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); n bigint;
begin
  if me is null or app.actor_kind() <> 'member' or not app.is_buyer(me) then return 'not_buyer'; end if;
  if p_session_hash is null or not exists (select 1 from app.sessions s where s.token_hash = p_session_hash and s.member_id = me
                                             and s.created_at > now() - interval '10 minutes' and s.expires_at > now()) then
    return 'fresh';
  end if;
  perform 1 from app.members m where m.id = me for update;
  if (select count(*) from app.buyer_keys k where k.member_id = me) >= 2 then return 'full'; end if;
  n := app.buyer_attested(p_credential_id, p_public_key, p_client_data, p_auth_data);
  if n is null then return 'bad_proof'; end if;
  if exists (select 1 from app.buyer_keys k where k.credential_id = p_credential_id or k.public_key = p_public_key) then return 'taken'; end if;
  insert into app.buyer_keys (member_id, credential_id, public_key, sign_count) values (me, p_credential_id, p_public_key, n);
  perform app.audit_add('buyer.key_added', 'member', me, jsonb_build_object('backup', true), 'success');
  perform app.notify(me, 'signin_browser', 'A backup passkey was added',
    'A second passkey was added to your buyer account. If that wasn''t you, tell security@dayonegreat.com at once.',
    '/join/buyer', 'member', me, 'buyer:backup:' || encode(sha256(p_public_key), 'hex'));
  return 'ok';
end $$;
revoke execute on function app.buyer_attested(bytea, bytea, bytea, bytea), app.buyer_key_backup(bytea, bytea, bytea, bytea, text) from public;
grant execute on function app.buyer_key_backup(bytea, bytea, bytea, bytea, text) to dog_app;
reset role;
revoke create on schema app from dog_signin;
