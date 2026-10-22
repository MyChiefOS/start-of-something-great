-- 016 Security fixes from the risk register (batch 1, Oct 22, 2026; Aaron: "start working on fixing the identified
-- vulnerabilities"). Two fixes, both from the independent review of the PR 17 merge:
--
-- 1. The passkey step-up is bound to the session by the database itself (finding 3, RK64). Until now every step-up
--    trigger trusted the transaction flag app.step_up that db/index.js sets; nothing in the database checked that the
--    flag belonged to the session the request came from. app.step_up_check() now requires all of it, by the database
--    clock: the flag; the session named by app.session belongs to the acting member and is current; it passed a passkey
--    check in the last 5 minutes with a passkey that still exists; and no recovery is open. A site role that set the
--    flag by itself, or for another session, gets nothing.
--
-- 2. Deleting your own account opens 24 hours after the account's first passkey (finding 7, RK62), the same rule as
--    linking a sign-in method (014). Before it, someone who copied a session cookie in the 10 minutes after sign-in, on
--    an account with no passkey yet, could add the first passkey and delete the account at once. Aaron's "delete" on a
--    deletion review is not affected (it is not his own account).
--
-- Every step-up trigger from 014 is replaced with the same body, the flag test swapped for app.step_up_check(); nothing
-- else changes. Members' everyday actions never call it with a step-up (the triggers still return first for them).
set local role dog_owner;

create function app.step_up_check(p_own_delete boolean) returns text
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  s app.sessions%rowtype;
  first_at timestamptz;
begin
  if app.actor_kind() not in ('member', 'admin') or coalesce(current_setting('app.step_up', true), '') <> '1' then
    return 'step_up';
  end if;
  select * into s from app.sessions x
    where x.token_hash = nullif(current_setting('app.session', true), '') and x.member_id = app.current_member() and x.expires_at > now();
  if not found or s.stepped_up_at is null or s.stepped_up_at <= now() - interval '5 minutes' or s.stepped_up_with is null
     or not exists (select 1 from app.passkeys k where k.id = s.stepped_up_with and k.member_id = s.member_id)
     or exists (select 1 from app.passkey_recoveries r where r.member_id = s.member_id and r.cancelled_at is null and r.completed_at is null) then
    return 'step_up';
  end if;
  if p_own_delete then
    select min(k.created_at) into first_at from app.passkeys k where k.member_id = s.member_id;
    if first_at > now() - interval '24 hours' then
      return 'passkey_new';
    end if;
  end if;
  return 'ok';
end
$$;
-- Every role that writes on a person's behalf may ask; it answers only about the transaction's own session.
revoke execute on function app.step_up_check(boolean) from public;
grant execute on function app.step_up_check(boolean) to dog_app, dog_erase, dog_limits, dog_jevs, dog_delegate;
-- Handing a function to a role needs that role to hold CREATE on the schema for the moment, as 012 and 014 do.
grant create on schema app to dog_signin;
alter function app.step_up_check(boolean) owner to dog_signin;
revoke create on schema app from dog_signin;

create or replace function app.agent_rules_step_up() returns trigger
language plpgsql
as $$
declare
  prev record;
begin
  if app.actor_kind() not in ('member', 'admin') or app.step_up_check(false) = 'ok'
     or new.reason in ('created', 'containment_lifted', 'report_upheld', 'ban', 'disabled', 'act_expired', 'containment') then
    return new;
  end if;
  if new.reason = 'reconfirmed' then
    raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to keep an agent acting on its own.';
  end if;
  -- Only the columns the sign-in role may read too, as agent_rules_fill does.
  select r.post_mode, r.reply_mode, r.report_mode, r.daily_cap into prev
    from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  if found and ((new.post_mode = 'act' and prev.post_mode <> 'act') or (new.reply_mode = 'act' and prev.reply_mode <> 'act')
                or (new.report_mode = 'act' and prev.report_mode <> 'act')
                or (new.daily_cap > prev.daily_cap and 'act' in (new.post_mode, new.reply_mode, new.report_mode))) then
    raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to let an agent do more without your approval.';
  end if;
  return new;
end
$$;

create or replace function app.agent_keys_step_up() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() in ('member', 'admin') and app.step_up_check(false) <> 'ok'
     and exists (select 1 from app.agent_rules r where r.agent_id = new.agent_id
                 and r.version = (select max(x.version) from app.agent_rules x where x.agent_id = new.agent_id)
                 and 'act' in (r.post_mode, r.reply_mode, r.report_mode)) then
    raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to make a new key for an agent that acts on its own.';
  end if;
  return new;
end
$$;

create or replace function app.identities_step_up() returns trigger
language plpgsql
as $$
declare
  first_at timestamptz;
begin
  if app.actor_kind() in ('member', 'admin') then
    if app.step_up_check(false) <> 'ok' then
      raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to link a sign-in method.';
    end if;
    select min(k.created_at) into first_at from app.passkeys k where k.member_id = new.member_id;
    if first_at > now() - interval '24 hours' then
      raise exception 'passkey_new' using errcode = 'P0001',
        hint = 'A new sign-in method can be linked 24 hours after your first passkey was added.';
    end if;
  end if;
  return new;
end
$$;

create or replace function app.admin_step_up() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() = 'admin' and app.step_up_check(false) <> 'ok' then
    raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to use the owner controls.';
  end if;
  return new;
end
$$;

create or replace function app.admin_review_step_up() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() <> 'admin' or app.step_up_check(false) = 'ok' or current_user = 'dog_jevs' then
    return new;
  end if;
  -- A pause whose time is up ends by itself, whoever reads the rules (liftDue); that is no decision.
  -- (Nested: PL/pgSQL would read a containment's field on any table if the two tests were joined with "and".)
  if tg_table_name = 'containments' then
    if new.appeal_decision is not distinct from old.appeal_decision and (new.lifted_at is null or old.ends_at <= now()) then
      return new;
    end if;
  end if;
  raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to decide this.';
end
$$;


create or replace function app.members_step_up() returns trigger
language plpgsql
as $$
declare
  verdict text;
begin
  -- A member's own deletion runs inside app.delete_account (owned by dog_erase), which checks the step-up and the
  -- 24-hour wait up front, while the member's session still exists: the deletion ends every session before it reaches
  -- this row. Only that path is skipped. Aaron's decisions on a deletion review (app.deletion_review_decide, also owned
  -- by dog_erase) are checked here, against his own session, which the deletion leaves alone.
  if current_user = 'dog_erase' and app.actor_kind() = 'member' then
    return case when tg_op = 'DELETE' then old else new end;
  end if;
  if app.actor_kind() in ('member', 'admin')
     and (tg_op = 'DELETE' or (app.actor_kind() = 'admin' and new.status is distinct from old.status)) then
    -- Defence in depth for any other path: a member deleting their own account waits 24 hours after the account's
    -- first passkey (finding 7, RK62).
    verdict := app.step_up_check(tg_op = 'DELETE' and old.id = app.current_member());
    if verdict = 'passkey_new' then
      raise exception 'passkey_new' using errcode = 'P0001',
        hint = 'An account can be deleted 24 hours after its first passkey was added.';
    elsif verdict <> 'ok' then
      raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey first.';
    end if;
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end
$$;

-- identities_passkeys belongs to dog_signin (014), so it is replaced as dog_signin, with CREATE on the schema for the
-- moment, as 014 did.
grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.identities_passkeys() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  ids uuid[];
begin
  -- 016: the step-up is checked against the request's own session. When the whole account is being deleted, every
  -- session of the member is already gone (app.erase_member ends them first), and that deletion was checked up front:
  -- app.delete_account for the member's own, and members_step_up (against Aaron's own session) for his "delete" on a
  -- deletion review.
  if app.actor_kind() in ('member', 'admin') and exists (select 1 from app.passkeys k where k.identity_id = old.id)
     and exists (select 1 from app.sessions s where s.member_id = old.member_id) and app.step_up_check(false) <> 'ok' then
    raise exception 'step_up' using errcode = 'P0001',
      hint = 'Passkeys were added while signed in with this method; confirm with a passkey to remove it.';
  end if;
  with gone as (delete from app.passkeys k where k.identity_id = old.id returning k.id)
  select array_agg(g.id) into ids from gone g;
  if ids is not null and exists (select 1 from app.sessions s where s.member_id = old.member_id) then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      select 'passkey.removed', 'member', old.member_id, jsonb_build_object('passkey', x, 'reason', 'method_unlinked') from unnest(ids) x;
    perform app.notify(old.member_id, 'passkey_removed',
      case when cardinality(ids) = 1 then 'A passkey was removed with a sign-in method' else cardinality(ids) || ' passkeys were removed with a sign-in method' end,
      'A sign-in method was removed from your account, and the passkeys added while signed in with it went with it.',
      '/account', 'identity', old.id, 'passkey:with_method:' || old.id::text);
  end if;
  return old;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_signin;

-- The member's own deletion (010's version, plus the check above), replaced as its owner dog_erase.
grant create on schema app to dog_erase;
set local role dog_erase;
create or replace function app.delete_account()
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
begin
  if app.actor_kind() <> 'member' or me is null then
    raise exception 'not_member' using errcode = '42501';
  end if;
  if coalesce(current_setting('app.fresh', true), '') <> '1' then
    raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to delete your account.';
  end if;
  if exists (select 1 from app.deletion_reviews r where r.member_id = me and (r.decision is null or r.decision = 'keep_disabled')) then
    raise exception 'under_review' using errcode = 'P0001';
  end if;
  perform 1 from app.members m where m.id = me and m.status = 'active' and not m.is_admin;
  if not found then
    raise exception 'not_active' using errcode = '42501';
  end if;
  -- 016: a passkey check bound to this session (RK64), and not within 24 hours of the account's first passkey (RK62).
  case app.step_up_check(true)
    when 'ok' then null;
    when 'passkey_new' then
      raise exception 'passkey_new' using errcode = 'P0001', hint = 'An account can be deleted 24 hours after its first passkey was added.';
    else
      raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey first.';
  end case;
  return query select * from app.erase_member(me);
end
$$;
set local role dog_owner;
revoke create on schema app from dog_erase;
