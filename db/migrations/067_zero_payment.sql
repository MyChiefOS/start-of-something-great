-- 067 The zero-payment launch (Aaron, Nov 21, 2026: "Provide a plan to launch the system with a Zero Payment trust
--   platform ... then prepare the PR for my approval", after the audit of the same day). Day One Great offers no
--   payments: people and their agents agree to tasks, do them and have them verified, and the result is reputation
--   that has no money value and can never be redeemed. The payment code (061 to 066) stays in place, dormant; this
--   migration locks it in the database itself, so turning money on again takes a migration Aaron merges.
--
--   1. The money lock: no row can be added to work_bounties, pay_requests, pay_accounts or pay_ledger. Until now the
--      switch lived only in the site's code (db/pay.js, payments.json): the audit's gap G12.
--   2. Draft mode holds in the work module: an agent whose owner's rules are "draft" can't claim, submit, check or
--      dispute work (gap G4). "Off" already stopped it.
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
create trigger money_locked before insert on app.work_bounties for each row execute function app.money_locked();
create trigger money_locked before insert on app.pay_requests for each row execute function app.money_locked();
create trigger money_locked before insert on app.pay_accounts for each row execute function app.money_locked();
create trigger money_locked before insert on app.pay_ledger for each row execute function app.money_locked();
reset role;

-- ---- 3. The owner's rules version on every work action ----
set local role dog_owner;
alter table app.work_actions add column rules_version integer;
create function app.work_action_rules() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  if new.agent_id is not null and new.rules_version is null then
    select r.version into new.rules_version from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
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

create or replace function app.work_who()
returns table (kind text, member_id uuid, agent_id uuid, tree_root uuid, citizen text, level smallint, is_admin boolean)
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  k text := app.actor_kind();
  m record;
  a record;
  mode text;
begin
  if k not in ('member', 'admin', 'agent') then
    raise exception 'sign in to take part in the work' using errcode = '42501';
  end if;
  select x.id, x.trust_level, x.status, x.is_admin into m from app.members x where x.id = app.current_member();
  if m.id is null or m.status <> 'active' then
    raise exception 'this account isn''t active' using errcode = '42501';
  end if;
  if k = 'agent' then
    select g.id, g.status, g.expires_at, coalesce(g.root_id, g.id) as root into a from app.agents g
     where g.id = app.current_agent() and g.owner_id = m.id;
    if a.id is null or a.status <> 'active' or (a.expires_at is not null and a.expires_at <= now()) then
      raise exception 'this agent isn''t active' using errcode = '42501';
    end if;
    select r.post_mode into mode from app.agent_rules r where r.agent_id = a.id order by r.version desc limit 1;
    if coalesce(mode, 'off') = 'off' then
      raise exception 'work_off' using errcode = 'P0001', hint = 'Your owner''s rules have posting off, so you can''t take work.';
    end if;
    -- 067 (Aaron, Nov 21; the audit's gap G4): draft mode means the owner approves each action. Work has no approval
    -- queue yet, so an agent in draft mode can read the work but not take part in it; its owner switches it to acting.
    if mode = 'draft' then
      raise exception 'work_draft' using errcode = 'P0001', hint = 'Your owner''s rules are in draft mode, where every action waits for them; work has no such step yet, so ask your owner to switch you to acting.';
    end if;
    return query select 'agent'::text, m.id, a.id, a.root, 'agent:' || a.id::text, m.trust_level, false;
    return;
  end if;
  return query select 'member'::text, m.id, null::uuid, null::uuid, 'member:' || m.id::text, m.trust_level, m.is_admin;
end
$$;

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
reset role;
revoke create on schema app from dog_work;

-- ---- 5. What points are ----
set local role dog_owner;
comment on table app.work_point_entries is 'Reputation, never money (067, Aaron, Nov 21, 2026): points record verified work; they have no money value and can''t be redeemed, exchanged or transferred.';
reset role;
