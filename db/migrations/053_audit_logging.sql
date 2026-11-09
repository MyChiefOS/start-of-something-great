-- 053 Audit logging to NIST SP 800-53 Rev 5 (the AU family, with AC-7) and the DISA Application Security and
-- Development STIG (Aaron, Nov 8: "Go review NIST 800-53 audit logging requirements and go review DISA STIG Application
-- Logging requirements make sure that level of logging in intergarated into the system." and "Put in the requirements
-- based on NIST 800-53 and DISA STIG application logging requirements."). Where the STIG conflicted with his earlier
-- decisions he chose the STIG each time (harness/FACTS.md, Nov 8). The requirements, one by one, are in AUDIT-LOGGING.md
-- and ACCEPTANCE.md (AL1 to AL16). This migration:
--   * Every audit row gets its outcome (success or failure), the component it came from, and the session it was made in
--     (a reference: the first 16 hex of a SHA-256 of the session's own hash, never the session). AU-3, V-222474,
--     V-222476, V-222441.
--   * The request behind each audit row: the connecting IP address, the user agent, the referrer, the method, the path
--     (no query string) and the host, as Vercel gives them (db/index.js). V-222447, V-222448, V-222470. They are kept in
--     app.audit_net, beside the row, for a year, then deleted (V-222621: at least a year); the audit row itself is kept.
--     This replaces, for audit records, the privacy page's "Never the network address itself" (Aaron's choice).
--   * Every failed logon is its own audit row (V-222462, AC-7): a wrong key file, a wrong PIN with a key file or a
--     browser key, a wrong current PIN on the account page, and, with no account to count against, a key file for a
--     username with none, a browser or code proof that fails, and a code that has expired. The first three count: three
--     in 15 minutes lock the account's sign-in, every way in, GitHub's included, for 15 minutes (V-222432; Aaron, Nov 8:
--     "Follow the STIG guidelines", and again on Nov 9: "you need to follow NIST and DISA STIG guidelines"). While it is
--     locked no key file or PIN is tested or counted, and every try gets the same answer, "locked". The member and Aaron
--     are told; an administrator may release it early, with a reason, in the audit log (V-222433). A right sign-in clears
--     the count ("consecutive").
--   * Sessions: created, ended (signed out, ended by a ban or erasure) and expired, each an audit row (V-222441, V-222442,
--     V-222445, V-222464). Session IDs are never renewed here (a session keeps its ID for its life), so V-222443 has
--     nothing to record. Expired sessions are swept, and so recorded, every timer run.
--   * Account and key changes: renames, PINs set or changed, browser keys added or removed, key files set, paused or
--     cancelled (V-222414, V-222467).
--   * The work module's decisions by people and by the timers (checks, disputes, decisions, reversals, removed tasks),
--     Third Look's mode, and changes to the work, watch and sub-agent settings (V-222431, V-222463, V-222472, V-222512).
--   * Aaron's reads of the review queues and controls (V-222465, V-222471): app.audit_admin_read, called by the routes
--     that show the work queue, the post review queue and the owner controls.
--   * Erasure keeps the audit rows (as before) and now Aaron's own security alerts about the member: only the member's
--     inbox is deleted (V-222621; Aaron, Nov 8: "Follow the STIG requirements").
--   * Storage: the database's size against its plan's capacity, every run of the hourly check; at 75% Aaron is warned at
--     once (V-222483, AU-5(1)).
--   * Nothing here can change or delete an audit row: the always-on triggers of 001 stand. Writes happen in the same
--     transaction as what they record, so an action whose record can't be written doesn't happen. The rest of V-222486
--     (halting on a broken record chain) and the alerts on audit failures are the second part (AL11 to AL15).

set local role dog_owner;

-- ---- What every audit row now carries ----
alter table app.audit_log
  add column outcome text not null default 'success' check (outcome = any (array['success', 'failure'])),
  add column component text check (char_length(component) <= 31 and component ~ '^[a-z][a-z0-9_]{0,30}$'),
  add column session_ref text check (char_length(session_ref) = 16 and session_ref ~ '^[0-9a-f]{16}$');

create function app.audit_fill() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  -- Only a name the column takes, so no action is ever refused for its name (the review of 053, L4).
  if new.component is null and split_part(new.action, '.', 1) ~ '^[a-z][a-z0-9_]{0,30}$' then
    new.component := split_part(new.action, '.', 1);
  end if;
  if new.session_ref is null and coalesce(current_setting('app.session', true), '') ~ '^[0-9a-f]{64}$' then
    new.session_ref := left(encode(sha256(convert_to(current_setting('app.session', true), 'UTF8')), 'hex'), 16);
  end if;
  return new;
end $$;
create trigger audit_log_fill before insert on app.audit_log for each row execute function app.audit_fill();

-- ---- The request behind each row, for a year ----
create table app.audit_net (
  id uuid primary key default app.uuid_v7(),
  audit_id uuid not null unique,
  at timestamptz not null default now(),
  -- As written (IPv4, or IPv6 up to 45 characters), checked here.
  ip text check (char_length(ip) <= 45 and ip ~ '^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:.]{2,45})$'),
  user_agent text check (char_length(user_agent) <= 512),
  referer text check (char_length(referer) <= 512),
  method text check (char_length(method) <= 10 and method ~ '^[A-Z]{1,10}$'),
  path text check (char_length(path) <= 300),
  host text check (char_length(host) <= 100)
);
create index audit_net_at on app.audit_net (at);
alter table app.audit_net enable row level security;
alter table app.audit_net force row level security;
create policy audit_net_owner_insert on app.audit_net for insert to dog_owner with check (true);
create policy audit_net_owner_select on app.audit_net for select to dog_owner using (true);
-- Deleted only once a year old (the retention below); never changed.
create policy audit_net_owner_delete on app.audit_net for delete to dog_owner using (at < now() - interval '366 days');
-- Read as the audit log is: by an administrator.
create policy audit_net_select on app.audit_net for select to dog_app using ((select app.actor_kind()) = 'admin');
grant select, insert, delete on app.audit_net to dog_owner;
grant select on app.audit_net to dog_app;
create function app.audit_net_no_change() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  raise exception 'the audit log''s request records can''t be changed' using errcode = '42501';
end $$;
create trigger audit_net_no_change before update on app.audit_net for each row execute function app.audit_net_no_change();
alter table app.audit_net enable always trigger audit_net_no_change;
-- Not emptied, and not deleted before a year, by any role, the owner's and a superuser's included (the second review of
-- 053, 3): as the audit log itself refuses.
create function app.audit_net_keep() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'TRUNCATE' or old.at >= now() - interval '366 days' then
    raise exception 'the audit log''s request records are kept a year' using errcode = '42501';
  end if;
  return old;
end $$;
create trigger audit_net_no_truncate before truncate on app.audit_net for each statement execute function app.audit_net_keep();
create trigger audit_net_keep_year before delete on app.audit_net for each row execute function app.audit_net_keep();
alter table app.audit_net enable always trigger audit_net_no_truncate;
alter table app.audit_net enable always trigger audit_net_keep_year;

create function app.audit_net_add() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
declare ip text := nullif(current_setting('app.req_ip', true), '');
begin
  if coalesce(ip, nullif(current_setting('app.req_ua', true), ''), nullif(current_setting('app.req_method', true), ''),
              nullif(current_setting('app.req_path', true), ''), nullif(current_setting('app.req_host', true), '')) is null then
    return null;
  end if;
  insert into app.audit_net (audit_id, at, ip, user_agent, referer, method, path, host)
  values (new.id, new.at,
    case when ip ~ '^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:.]{2,45})$' then ip end,
    left(nullif(current_setting('app.req_ua', true), ''), 512), left(nullif(current_setting('app.req_referer', true), ''), 512),
    case when current_setting('app.req_method', true) ~ '^[A-Z]{1,10}$' then current_setting('app.req_method', true) end,
    left(nullif(current_setting('app.req_path', true), ''), 300), left(nullif(current_setting('app.req_host', true), ''), 100));
  return null;
end $$;
create trigger audit_log_net after insert on app.audit_log for each row execute function app.audit_net_add();
alter table app.audit_log enable always trigger audit_log_fill;
alter table app.audit_log enable always trigger audit_log_net;

-- A row in the audit log from a trigger: as whoever is acting (the policy pins the actor), with its outcome.
create function app.audit_add(p_action text, p_subject_kind text, p_subject uuid, p_detail jsonb, p_outcome text default 'success')
returns void
language plpgsql security definer set search_path = pg_catalog as $$
begin
  insert into app.audit_log (action, subject_kind, subject_id, detail, outcome)
  values (p_action, p_subject_kind, p_subject, coalesce(p_detail, '{}'::jsonb), coalesce(p_outcome, 'success'));
end $$;
revoke execute on function app.audit_add(text, text, uuid, jsonb, text) from public;
-- The sign-in role records the failures that have no account to count against (below).
grant execute on function app.audit_add(text, text, uuid, jsonb, text) to dog_signin;

-- ---- Failed logons, and the lock after three in 15 minutes (V-222432, AC-7) ----
create table app.signin_failures (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id) on delete cascade,
  at timestamptz not null default now()
);
create index signin_failures_member on app.signin_failures (member_id, at);
create table app.signin_locks (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null unique references app.members (id) on delete cascade,
  locked_at timestamptz not null default now(),
  until timestamptz not null
);
alter table app.signin_failures enable row level security;
alter table app.signin_failures force row level security;
alter table app.signin_locks enable row level security;
alter table app.signin_locks force row level security;
create policy signin_failures_owner on app.signin_failures for all to dog_owner using (true) with check (true);
create policy signin_locks_owner on app.signin_locks for all to dog_owner using (true) with check (true);
grant select, insert, delete on app.signin_failures to dog_owner;
-- app.notify runs with its caller's rights: the owner role's triggers here send two kinds, the member's lock notice and
-- Aaron's alerts.
create policy notices_owner_insert on app.notices for insert to dog_owner
  with check ((member_id is not null and kind = 'signin_pin') or (member_id is null and kind = 'alert'));
grant select, insert, update, delete on app.signin_locks to dog_owner;

-- One failed logon for a member: its audit row, and the lock at the third within 15 minutes since the last good one.
create function app.signin_failed(p_member uuid, p_lane text, p_reason text)
returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare n integer; adm boolean;
begin
  -- One at a time per member, so two failures at once can't both count to 2 and miss the lock (the review of 053, L1).
  perform pg_advisory_xact_lock(hashtextextended('signin_failed:' || p_member::text, 53));
  perform app.audit_add('signin.failed', 'member', p_member, jsonb_build_object('lane', p_lane, 'reason', p_reason), 'failure');
  insert into app.signin_failures (member_id) values (p_member);
  select count(*) into n from app.signin_failures f where f.member_id = p_member and f.at > now() - interval '15 minutes';
  if n >= 3 and not exists (select 1 from app.signin_locks l where l.member_id = p_member and l.until > now()) then
    insert into app.signin_locks (member_id, locked_at, until) values (p_member, now(), now() + interval '15 minutes')
      on conflict (member_id) do update set locked_at = excluded.locked_at, until = excluded.until;
    perform app.audit_add('signin.locked', 'member', p_member, jsonb_build_object('failures', n, 'minutes', 15), 'failure');
    adm := exists (select 1 from app.members m where m.id = p_member and m.is_admin);
    perform app.notify(p_member, 'signin_pin', 'Sign-in locked for 15 minutes',
      '3 sign-in attempts failed for your account within 15 minutes, so signing in to it is locked for 15 minutes, every way '
      || 'in. Browsers already signed in stay signed in. If it wasn''t you, sign out everywhere from your account page once '
      || 'you are back in.', '/account', 'member', p_member, 'signin:locked:' || p_member || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MI'));
    perform app.notify(null, 'alert', case when adm then 'Sign-in locked on your own account' else 'Sign-in locked for one account' end,
      '3 sign-in attempts failed within 15 minutes, so the account''s sign-in is locked for 15 minutes. You can release it '
      || 'early from the Console, with a reason.', '/admin/console', 'member', p_member,
      'watch:locked:' || p_member || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MI'));
  end if;
end $$;
revoke execute on function app.signin_failed(uuid, text, text) from public;

-- Whether a member's sign-in is locked now. The sign-in functions ask before they test anything (the review of 053, H1).
create function app.signin_is_locked(p_member uuid) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from app.signin_locks l where l.member_id = p_member and l.until > now())
$$;
revoke execute on function app.signin_is_locked(uuid) from public;
grant execute on function app.signin_is_locked(uuid) to dog_signin;

-- Wrong key files and wrong PINs, wherever they are counted (023, 030, 037).
create function app.signin_keys_audit() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if tg_table_name = 'file_keys' then
    if tg_op = 'INSERT' then
      perform app.audit_add('signin.key_file_set', 'member', new.member_id, '{}'::jsonb);
    elsif tg_op = 'DELETE' then
      perform app.audit_add('signin.key_file_cancelled', 'member', old.member_id, '{}'::jsonb);
    else
      if new.failed > old.failed then perform app.signin_failed(new.member_id, 'key_file', 'wrong_file'); end if;
      if new.pin_failed > old.pin_failed then perform app.signin_failed(new.member_id, 'key_file', 'wrong_pin'); end if;
      if new.paused_until is not null and new.paused_until is distinct from old.paused_until and new.paused_until > now() then
        perform app.audit_add('signin.paused', 'member', new.member_id, jsonb_build_object('lane', 'key_file', 'minutes', 10), 'failure');
      end if;
    end if;
  elsif tg_table_name = 'browser_keys' then
    if tg_op = 'INSERT' then
      perform app.audit_add('signin.browser_added', 'member', new.member_id, jsonb_build_object('key', new.id));
    elsif tg_op = 'DELETE' then
      perform app.audit_add('signin.browser_removed', 'member', old.member_id, jsonb_build_object('key', old.id));
    elsif new.failed > old.failed then
      perform app.signin_failed(new.member_id, 'browser', 'wrong_pin');
    end if;
  else -- signin_pins
    if tg_op = 'INSERT' then
      perform app.audit_add('signin.pin_set', 'member', new.member_id, '{}'::jsonb);
    elsif tg_op = 'UPDATE' then
      if new.pin_hash is distinct from old.pin_hash then perform app.audit_add('signin.pin_changed', 'member', new.member_id, '{}'::jsonb); end if;
      if new.change_failed > old.change_failed then perform app.signin_failed(new.member_id, 'pin_change', 'wrong_pin'); end if;
    end if;
  end if;
  return null;
end $$;
create trigger file_keys_audit after insert or update or delete on app.file_keys for each row execute function app.signin_keys_audit();
create trigger browser_keys_audit after insert or update or delete on app.browser_keys for each row execute function app.signin_keys_audit();
create trigger signin_pins_audit after insert or update on app.signin_pins for each row execute function app.signin_keys_audit();
alter table app.file_keys enable always trigger file_keys_audit;
alter table app.browser_keys enable always trigger browser_keys_audit;
alter table app.signin_pins enable always trigger signin_pins_audit;

-- ---- Sessions: created (refused while locked), ended, expired ----
create function app.sessions_audit() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
declare ref text;
begin
  if tg_op = 'INSERT' then
    if exists (select 1 from app.signin_locks l where l.member_id = new.member_id and l.until > now()) then
      raise exception 'locked' using errcode = 'P0001';
    end if;
    -- A good sign-in ends the run of failures: the limit counts consecutive ones.
    delete from app.signin_failures f where f.member_id = new.member_id;
    ref := left(encode(sha256(convert_to(new.token_hash, 'UTF8')), 'hex'), 16);
    insert into app.audit_log (action, subject_kind, subject_id, detail, session_ref)
      values ('session.created', 'member', new.member_id, jsonb_build_object('expires', new.expires_at), ref);
    return new;
  end if;
  ref := left(encode(sha256(convert_to(old.token_hash, 'UTF8')), 'hex'), 16);
  insert into app.audit_log (action, subject_kind, subject_id, detail, session_ref)
    values (case when old.expires_at <= now() then 'session.expired' else 'session.ended' end, 'member', old.member_id,
            jsonb_build_object('began', old.created_at, 'last_seen', old.last_seen_at, 'expires', old.expires_at), ref);
  return old;
end $$;
create trigger sessions_audit_insert before insert on app.sessions for each row execute function app.sessions_audit();
create trigger sessions_audit_delete after delete on app.sessions for each row execute function app.sessions_audit();
alter table app.sessions enable always trigger sessions_audit_insert;
alter table app.sessions enable always trigger sessions_audit_delete;

-- The sweep: sessions past their end are deleted, so each expiry is recorded (V-222445). From the timer route.
create policy sessions_owner_sweep on app.sessions for delete to dog_owner using (expires_at <= now());
create policy sessions_owner_sweep_read on app.sessions for select to dog_owner using (expires_at <= now());
grant select, delete on app.sessions to dog_owner;
create function app.session_sweep()
returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare n integer;
begin
  delete from app.sessions s where s.id in (select x.id from app.sessions x where x.expires_at <= now() order by x.expires_at limit 500);
  get diagnostics n = row_count;
  return n;
end $$;
revoke execute on function app.session_sweep() from public;
grant execute on function app.session_sweep() to dog_app;

-- The refusal while locked, as the sign-in functions report a refusal (037's app.signin_refusal, with 'locked').
create or replace function app.signin_refusal(p_state text, p_message text) returns text
language sql immutable set search_path = pg_catalog as $$
  select case when p_state = 'P0001' and p_message in ('banned', 'disabled', 'taken', 'region', 'weak_pin', 'locked') then p_message
              when p_state in ('22023', '23505') then 'bad_key' end
$$;

-- The key-file pause for one member ends now: only for an administrator's release of a lock (below). The sign-in role's,
-- as the key files are.
grant create on schema app to dog_signin;
set local role dog_signin;
create function app.keyfile_unpause(p_member uuid) returns void
language plpgsql security definer set search_path = pg_catalog as $$
begin
  update app.file_keys f set paused_until = null, failed = 0 where f.member_id = p_member and (f.paused_until > now() or f.failed > 0);
end $$;
revoke execute on function app.keyfile_unpause(uuid) from public;
grant execute on function app.keyfile_unpause(uuid) to dog_owner;
set local role dog_owner;
revoke create on schema app from dog_signin;

-- An administrator releases a lock early, with a reason (V-222433). It needs his session, so he can release his own lock
-- only from a browser that was already signed in.
create function app.signin_unlock(p_member uuid, p_reason text)
returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() is distinct from 'admin' then raise exception 'only an administrator' using errcode = '42501'; end if;
  if p_reason is null or char_length(btrim(p_reason)) not between 3 and 200 then raise exception 'a reason, 3 to 200 characters' using errcode = '22023'; end if;
  delete from app.signin_locks l where l.member_id = p_member;
  if not found then return false; end if;
  delete from app.signin_failures f where f.member_id = p_member;
  -- The key-file pause the same failures started ends too, so "released" means every way in (the third review, L1).
  perform app.keyfile_unpause(p_member);
  perform app.audit_add('signin.unlocked', 'member', p_member, jsonb_build_object('reason', btrim(p_reason)));
  return true;
end $$;
revoke execute on function app.signin_unlock(uuid, text) from public;
grant execute on function app.signin_unlock(uuid, text) to dog_app;

-- The locks in force now, for the Console's Admins tab, where each can be released (the second review of 053, 4).
create function app.signin_locks_open() returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() is distinct from 'admin' then return '[]'::jsonb; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('member', l.member_id, 'name', m.display_name, 'locked_at', l.locked_at, 'until', l.until)
      order by l.locked_at desc)
    from app.signin_locks l join app.members m on m.id = l.member_id where l.until > now()), '[]'::jsonb);
end $$;
revoke execute on function app.signin_locks_open() from public;
grant execute on function app.signin_locks_open() to dog_app;

-- ---- Account changes not recorded before: renames ----
create function app.members_rename_audit() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if new.display_name is distinct from old.display_name then
    perform app.audit_add('member.renamed', 'member', new.id, '{}'::jsonb);
  end if;
  return null;
end $$;
create trigger members_rename_audit after update of display_name on app.members for each row execute function app.members_rename_audit();
alter table app.members enable always trigger members_rename_audit;

-- ---- The work module's decisions and settings ----
create function app.work_audit() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
declare o jsonb := to_jsonb(old); n jsonb := to_jsonb(new);
begin
  -- Each table's own columns, read from its row as JSON (PL/pgSQL may read every field named in one condition).
  if tg_table_name = 'work_disputes' then
    if o ->> 'status' = 'open' and n ->> 'status' <> 'open' then
      perform app.audit_add('work.dispute_decided', 'submission', (n ->> 'submission_id')::uuid, jsonb_build_object('dispute', n -> 'id', 'decision', n -> 'status'));
    end if;
  elsif tg_table_name = 'work_checks' then
    if o ->> 'status' = 'open' and n ->> 'status' <> 'open' then
      perform app.audit_add('work.check_decided', 'submission', (n ->> 'submission_id')::uuid, jsonb_build_object('check', n -> 'id', 'decision', n -> 'status'));
    end if;
  elsif tg_table_name = 'work_submissions' then
    if n ->> 'status' is distinct from o ->> 'status' and n ->> 'status' = any (array['passed', 'failed', 'reversed']) then
      perform app.audit_add('work.' || case when n ->> 'status' = 'reversed' then 'reversed' else 'decided' end, 'submission', (n ->> 'id')::uuid,
        jsonb_build_object('verdict', n -> 'status', 'by', n -> 'decided_by'));
      -- The decision itself succeeded whatever its verdict, so its outcome is success; the verdict is in the detail.
    end if;
  elsif tg_table_name = 'work_tasks' then
    if n ->> 'status' is distinct from o ->> 'status' and n ->> 'status' = 'removed' then
      perform app.audit_add('work.task_removed', 'task', (n ->> 'id')::uuid, '{}'::jsonb);
    end if;
  elsif tg_table_name = 'tl_settings' then
    if n ->> 'mode' is distinct from o ->> 'mode' then
      perform app.audit_add('thirdlook.mode', null, null, jsonb_build_object('from', o -> 'mode', 'to', n -> 'mode'));
    end if;
  elsif tg_table_name = any (array['work_settings', 'watch_settings', 'subagent_settings']) then
    -- Only settings, not the timers' own bookkeeping.
    if (to_jsonb(new) - array['last_tick_at', 'last_alert_day', 'ledger_checked_at', 'updated_at'])
       is distinct from (to_jsonb(old) - array['last_tick_at', 'last_alert_day', 'ledger_checked_at', 'updated_at']) then
      perform app.audit_add('settings.changed', null, null, jsonb_build_object('table', tg_table_name, 'changed',
        (select coalesce(jsonb_object_agg(k, to_jsonb(new) -> k), '{}'::jsonb) from jsonb_object_keys(to_jsonb(new)) k
          where k <> all (array['last_tick_at', 'last_alert_day', 'ledger_checked_at', 'updated_at']) and to_jsonb(new) -> k is distinct from to_jsonb(old) -> k)));
    end if;
  end if;
  return null;
end $$;
create trigger work_disputes_audit after update on app.work_disputes for each row execute function app.work_audit();
create trigger work_checks_audit after update on app.work_checks for each row execute function app.work_audit();
create trigger work_submissions_audit after update of status on app.work_submissions for each row execute function app.work_audit();
create trigger work_tasks_audit after update of status on app.work_tasks for each row execute function app.work_audit();
create trigger tl_settings_audit after update on app.tl_settings for each row execute function app.work_audit();
create trigger work_settings_audit after update on app.work_settings for each row execute function app.work_audit();
create trigger watch_settings_audit after update on app.watch_settings for each row execute function app.work_audit();
create trigger subagent_settings_audit after update on app.subagent_settings for each row execute function app.work_audit();
alter table app.work_disputes enable always trigger work_disputes_audit;
alter table app.work_checks enable always trigger work_checks_audit;
alter table app.work_submissions enable always trigger work_submissions_audit;
alter table app.work_tasks enable always trigger work_tasks_audit;
alter table app.tl_settings enable always trigger tl_settings_audit;
alter table app.work_settings enable always trigger work_settings_audit;
alter table app.watch_settings enable always trigger watch_settings_audit;
alter table app.subagent_settings enable always trigger subagent_settings_audit;

-- ---- Aaron's reads of the review queues ----
create function app.audit_admin_read(p_area text)
returns void
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() is distinct from 'admin' then return; end if;
  if p_area is null or p_area !~ '^[a-z][a-z_]{1,30}$' then raise exception 'bad area' using errcode = '22023'; end if;
  perform app.audit_add('admin.read', null, null, jsonb_build_object('area', p_area));
end $$;
revoke execute on function app.audit_admin_read(text) from public;
grant execute on function app.audit_admin_read(text) to dog_app;

-- ---- Erasure keeps Aaron's alerts about the member (only the member's own inbox goes) ----
drop policy notices_erase_delete on app.notices;
create policy notices_erase_delete on app.notices for delete to dog_erase using (member_id is not null);

-- ---- Retention and storage, from the timer route, at most once an hour ----
create table app.audit_upkeep (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  -- The plan's database capacity, in bytes (Supabase Pro: 8 GB included). Changed by migration when the plan changes.
  capacity_bytes bigint not null default 8589934592 check (capacity_bytes > 0),
  warn_percent smallint not null default 75 check (warn_percent between 10 and 99),
  last_run_at timestamptz,
  last_size_bytes bigint
);
alter table app.audit_upkeep enable row level security;
alter table app.audit_upkeep force row level security;
create policy audit_upkeep_owner on app.audit_upkeep for all to dog_owner using (true) with check (true);
grant select, insert, update on app.audit_upkeep to dog_owner;
insert into app.audit_upkeep default values;

create function app.audit_upkeep_run()
returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare u record; size bigint; pct numeric; net integer; fails integer; locks integer;
begin
  select * into u from app.audit_upkeep where singleton for update skip locked;
  if not found or (u.last_run_at is not null and u.last_run_at > now() - interval '1 hour') then return null; end if;
  -- Retention (V-222621): request records a year and a day old go; audit rows stay.
  delete from app.audit_net n where n.at < now() - interval '366 days';
  get diagnostics net = row_count;
  delete from app.signin_failures f where f.at < now() - interval '1 day';
  get diagnostics fails = row_count;
  delete from app.signin_locks l where l.until < now() - interval '1 day';
  get diagnostics locks = row_count;
  -- Storage (V-222483): the database's size against the plan's capacity.
  -- If the size can't be read, the deletions above still stand and Aaron is told (the review of 053, L5).
  begin
    size := pg_database_size(current_database());
  exception when others then
    size := null;
    perform app.notify(null, 'alert', 'The storage check could not run',
      'The hourly check could not read the database''s size, so it can''t warn before storage fills. Old request records '
      || 'were still deleted.', '/admin/console', null, null, 'audit:sizefail:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end;
  pct := case when size is null then null else round(100.0 * size / u.capacity_bytes, 1) end;
  update app.audit_upkeep set last_run_at = now(), last_size_bytes = size where singleton;
  if pct >= u.warn_percent then
    perform app.notify(null, 'alert', 'The database is ' || pct || '% full',
      'The database, audit records included, uses ' || pg_size_pretty(size) || ' of the plan''s ' || pg_size_pretty(u.capacity_bytes)
      || '. Audit records are never deleted; before it fills, move to a larger plan or move old records off.', '/admin/console', null, null,
      'audit:capacity:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end if;
  return jsonb_build_object('size', size, 'percent', pct, 'net_deleted', net, 'failures_deleted', fails, 'locks_deleted', locks);
end $$;
revoke execute on function app.audit_upkeep_run() from public;
grant execute on function app.audit_upkeep_run() to dog_app;

-- The triggers' own functions are called by their triggers only.
revoke execute on function app.audit_fill(), app.audit_net_add(), app.audit_net_no_change(), app.audit_net_keep(), app.signin_keys_audit(), app.sessions_audit(),
  app.members_rename_audit(), app.work_audit() from public;

-- 037's notices about wrong PINs promised that GitHub sign-in always stays open; with the lock (above) it opens again
-- once any lock ends. The same function with those two sentences made true, as its owner.
-- pin_wrong is the sign-in role's (037), so it is replaced as that role, which may create in app only for this step.
grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.pin_wrong(p_member uuid, p_kind text, p_id uuid, p_count integer) returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare what text := case p_kind when 'browser' then 'this browser' when 'file' then 'your key file' else 'your account page' end;
  thing text := case p_kind when 'browser' then 'browser key' when 'file' then 'key file' else 'PIN change form' end;
  adm boolean := exists (select 1 from app.members m where m.id = p_member and m.is_admin);
  day text := to_char(now() at time zone 'UTC', 'YYYYMMDD');
begin
  if p_count = 5 then
    begin
      perform app.notify(null, 'alert', case when adm then 'Wrong PINs on your own account' else 'Wrong PINs for one account' end,
        '5 wrong PINs have been tried with one member''s ' || thing || '. At 10 '
        || case when p_kind = 'change' then 'that session is signed out' else 'it is cancelled' end
        || '; 3 failed sign-ins in 15 minutes also lock the account for 15 minutes, every way in (053).', '/controls', 'member', p_member,
        'watch:pin5:' || p_kind || ':' || p_id::text || ':' || day);
    exception when others then null;
    end;
    perform app.notify(p_member, 'signin_pin', 'Wrong PINs were tried',
      '5 wrong PINs have been tried with ' || what || '. If that wasn''t you, sign out everywhere from your account page. '
      || case when p_kind = 'change' then 'After 10, that session is signed out.'
              else 'After 10, ' || what || ' is cancelled; you can sign in again with GitHub on the join page once any lock (15 minutes after 3 failed sign-ins) ends.' end,
      '/account', 'member', p_member, 'signin:pin5:' || p_kind || ':' || p_id::text || ':' || day);
  elsif p_count >= 10 and p_kind in ('browser', 'file') then
    begin
      perform app.notify(null, 'alert', case when adm then 'Your own ' || thing || ' was cancelled' else 'A member''s ' || thing || ' was cancelled' end,
        '10 wrong PINs were tried, so it no longer signs in. The account is safe; the member signs in again with GitHub, or a '
        || 'new browser with their key file and PIN.', '/controls', 'member', p_member, 'watch:pin10:' || p_kind || ':' || p_id::text);
    exception when others then null;
    end;
    perform app.notify(p_member, 'signin_pin', case when p_kind = 'browser' then 'A browser of yours was cancelled' else 'Your key file was cancelled' end,
      '10 wrong PINs were tried with ' || what || ', so it no longer signs you in. Your account is safe. To sign in, get a '
      || 'new code on the join page' || case when p_kind = 'browser' then ', or use your key file and PIN' else '' end || '.', '/join',
      'member', p_member, 'signin:pin10:' || p_kind || ':' || p_id::text);
  end if;
end $$;

-- The review of 053 (H1): the lock was checked only when a session was made, after the PIN was tested, so a wrong PIN
-- answered "wrong PIN" and the right one "locked", which told a guesser the PIN. 037's sign-in functions, the same but
-- for the lines marked 053: they ask whether the account is locked before testing any key file or PIN, and answer
-- "locked" as a status (so the challenge stays used up), and they record the failures that have no account.
create or replace function app.code_sign_in_pin(p_browser_hash text, p_display_name text, p_session_hash text, p_session_days integer,
  p_region text, p_pin text, p_public bytea, p_label text, p_challenge text, p_origin text, p_signature bytea, p_remove_others boolean)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean, key_id uuid)
language plpgsql security definer set search_path = pg_catalog as $$
declare s record; replaced boolean; kid uuid; why text; gone integer := 0;
begin
  if p_pin is null or p_pin !~ '^[0-9]{6}$' or app.pin_weak(p_pin) then
    return query select 'weak_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid; return;
  end if;
  if not app.signin_proof(p_public, p_challenge, p_origin, p_signature) then
    perform app.audit_add('signin.failed', null, null, jsonb_build_object('lane', 'code', 'reason', 'bad_proof'), 'failure');
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid; return;
  end if;
  begin
    select * into s from app.code_sign_in(p_browser_hash, p_display_name, p_session_hash, p_session_days, p_region) x;
    if s.status <> 'ok' then
      if s.status = 'expired' then
        perform app.audit_add('signin.failed', null, null, jsonb_build_object('lane', 'code', 'reason', 'code_expired'), 'failure');
      end if;
      return query select s.status, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid; return;
    end if;
    replaced := app.pin_store(s.member_id, p_pin);
    kid := app.browser_key_add(s.member_id, p_public, p_label);
  exception when sqlstate 'P0001' or sqlstate '22023' or sqlstate '23505' then
    why := app.signin_refusal(sqlstate, sqlerrm);
    if why is null then raise; end if;
    -- 053: a refusal while locked is recorded, against the member the claimed code names (the second review of 053, 6).
    if why = 'locked' then
      perform app.audit_add('signin.refused', 'member', (select i.member_id from app.code_signins x
          join app.identities i on i.provider = 'github' and i.fingerprint = x.fingerprint
          where x.browser_hash = p_browser_hash and x.status = 'claimed' order by x.claimed_at desc limit 1),
        jsonb_build_object('lane', 'code', 'reason', 'locked'), 'failure');
    end if;
    return query select why, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid; return;
  end;
  if replaced and coalesce(p_remove_others, false) then
    delete from app.browser_keys b where b.member_id = s.member_id and b.id <> kid;
    get diagnostics gone = row_count;
  end if;
  if replaced then
    perform app.notify(s.member_id, 'signin_pin', 'Your PIN was changed',
      'Your PIN was set again when you signed in with a code posted through GitHub'
      || case when gone > 0 then ', and your other browsers (' || gone || ') were removed' else '' end
      || '. If that wasn''t you, sign out everywhere from your account page.', '/account', 'member', s.member_id,
      'signin:pinset:' || p_session_hash);
  end if;
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin, kid;
end $$;

create or replace function app.file_sign_in_pin(p_login_hash text, p_key_hash text, p_display_name text, p_session_hash text,
  p_session_days integer, p_region text, p_pin text, p_public bytea, p_label text, p_challenge text, p_origin text, p_signature bytea,
  p_pin_again text)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean, key_id uuid, tries_left smallint, wait_seconds integer)
language plpgsql security definer set search_path = pg_catalog as $$
declare k app.file_keys%rowtype; s record; kid uuid; first_pin boolean; why text; locked_now boolean;
begin
  if p_login_hash is null or p_login_hash !~ '^[0-9a-f]{64}$' or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad key file request' using errcode = '22023';
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{6}$' then
    return query select 'wrong_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end if;
  if not app.signin_proof(p_public, p_challenge, p_origin, p_signature) then
    perform app.audit_add('signin.failed', null, null, jsonb_build_object('lane', 'key_file', 'reason', 'bad_proof'), 'failure');
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end if;
  select * into k from app.file_keys f where f.login_hash = p_login_hash for update;
  -- 053: while the account is locked, no key file or PIN is tested or counted, and every try gets the same answer.
  if found and app.signin_is_locked(k.member_id) then
    perform app.audit_add('signin.refused', 'member', k.member_id, jsonb_build_object('lane', 'key_file', 'reason', 'locked'), 'failure');
    return query select 'locked'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end if;
  if found and k.paused_until > now() then
    return query select 'paused'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint,
      greatest(1, ceil(extract(epoch from k.paused_until - now()))::integer); return;
  end if;
  if not found or k.key_hash <> p_key_hash then
    if found then
      update app.file_keys f set failed = f.failed + 1 where f.id = k.id returning * into k;
      if k.failed >= 3 then
        update app.file_keys f set failed = 0, paused_until = now() + interval '10 minutes', last_paused_at = now() where f.id = k.id;
        -- 053: the pause counts wrong files since the last right one; the lock, failed sign-ins in the last 15 minutes.
        -- The same 3 may or may not have locked the account (the third review of 053, M1), so the words say which.
        locked_now := app.signin_is_locked(k.member_id);
        begin
          perform app.notify(null, 'alert', case when exists (select 1 from app.members m where m.id = k.member_id and m.is_admin)
              then 'Key-file sign-in paused on your own account' else 'Key-file sign-in paused for one account' end,
            '3 wrong key files were tried for one member''s GitHub username, so signing in with a key file is paused for that '
            || 'username for 10 minutes. ' || case when locked_now
              then 'Failed sign-ins, these included, also locked the account''s sign-in for 15 minutes, every way in; you can release it from the Console.'
              else 'Their browser and their GitHub sign-in still work.' end, '/admin/console', 'member', k.member_id,
            'watch:paused:' || k.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MI'));
        exception when others then null;
        end;
        perform app.notify(k.member_id, 'signin_keyfile', 'Key-file sign-in paused for 10 minutes',
          '3 wrong key files were tried with your GitHub username, so signing in with your key file is paused for 10 minutes; '
          || 'then it works again. Your account is safe. ' || case when locked_now
            then 'Failed sign-ins, these included, also locked signing in to your account for 15 minutes, every way in; browsers already signed in stay '
              || 'signed in. After that, this browser with your PIN or a new code on the join page sign you in.'
            else 'This browser, with your PIN, and a new code on the join page still sign you in.' end
          || ' If it wasn''t you, you don''t need to do anything.', '/account', 'member', k.member_id,
          'signin:keyfile:paused:' || k.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MI'));
        if locked_now then
          return query select 'locked'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
        end if;
        return query select 'paused'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, 600; return;
      end if;
    end if;
    -- 053: when this wrong file made the lock, the answer says so (the fourth review of 053, L-1).
    if found and app.signin_is_locked(k.member_id) then
      return query select 'locked'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
    end if;
    if not found then
      -- 053: no account has a key file for this username; recorded, with nothing to count against (V-222462).
      perform app.audit_add('signin.failed', null, null, jsonb_build_object('lane', 'key_file', 'reason', 'no_account'), 'failure');
    end if;
    return query select 'no_match'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end if;
  -- The right file. Its PIN, or (an account from before 037) the PIN it sets now, typed twice.
  first_pin := not exists (select 1 from app.signin_pins x where x.member_id = k.member_id);
  if first_pin then
    if app.pin_weak(p_pin) then
      return query select 'weak_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
    end if;
    if p_pin_again is distinct from p_pin then
      return query select 'confirm_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
    end if;
  elsif not app.pin_matches(k.member_id, p_pin) then
    update app.file_keys f set pin_failed = least(f.pin_failed + 1, 10) where f.id = k.id returning * into k;
    perform app.pin_wrong(k.member_id, 'file', k.id, k.pin_failed);
    if k.pin_failed >= 10 then
      delete from app.file_keys f where f.id = k.id;
      return query select 'start_again'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, 0::smallint, null::integer; return;
    end if;
    if app.signin_is_locked(k.member_id) then
      return query select 'locked'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
    end if;
    return query select 'wrong_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, (10 - k.pin_failed)::smallint, null::integer; return;
  end if;
  begin
    select * into s from app.sign_in_core('github', array[k.fingerprint], 1::smallint, 1::smallint, p_display_name,
                                     p_session_hash, p_session_days, null::timestamptz, null::uuid, p_region);
    if first_pin then
      perform app.pin_store(s.member_id, p_pin);
    end if;
    kid := app.browser_key_add(s.member_id, p_public, p_label);
  exception when sqlstate 'P0001' or sqlstate '22023' or sqlstate '23505' then
    why := app.signin_refusal(sqlstate, sqlerrm);
    if why is null then raise; end if;
    return query select why, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end;
  -- 030's alert: the right key file after wrong ones for the username (since the review of 037, after a pause in the
  -- last day too). All of it inside the catch.
  begin
    if k.failed >= coalesce((select w.wrong_files_before from app.watch_settings w limit 1), 3) or k.last_paused_at > now() - interval '1 day' then
      perform app.notify(null, 'alert', 'A sign-in after wrong key files',
        'The right key file signed in after wrong ones were tried for the same GitHub username. If the wrong ones weren''t '
        || 'the member''s own mistakes, someone else has been trying their username.', '/controls',
        'member', k.member_id, 'watch:afterfail:' || k.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
    end if;
  exception when others then null;
  end;
  update app.file_keys f set used_at = now(), failed = 0, pin_failed = 0 where f.id = k.id;
  perform app.notify(s.member_id, 'signin_browser', 'New browser added',
    'Your key file and PIN added a new browser (' || p_label || ') and signed it in. If that wasn''t you, remove it on your '
    || 'account page and sign out everywhere.', '/account', 'member', s.member_id, 'signin:browser:' || kid::text);
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin, kid, null::smallint, null::integer;
end $$;

create or replace function app.browser_sign_in(p_key_id uuid, p_display_name text, p_session_hash text, p_session_days integer,
  p_region text, p_pin text, p_challenge text, p_origin text, p_signature bytea)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean, tries_left smallint)
language plpgsql security definer set search_path = pg_catalog as $$
declare b app.browser_keys%rowtype; s record; fp text; why text;
begin
  select * into b from app.browser_keys x where x.id = p_key_id for update;
  if not found then
    return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end if;
  -- The proof first: without this browser's private key, no PIN is ever tested.
  if not app.signin_proof(b.public_key, p_challenge, p_origin, p_signature) then
    perform app.audit_add('signin.failed', 'member', b.member_id, jsonb_build_object('lane', 'browser', 'reason', 'bad_proof'), 'failure');
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end if;
  -- 053: while the account is locked, no PIN is tested or counted, and every try gets the same answer.
  if app.signin_is_locked(b.member_id) then
    perform app.audit_add('signin.refused', 'member', b.member_id, jsonb_build_object('lane', 'browser', 'reason', 'locked'), 'failure');
    return query select 'locked'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end if;
  if not app.pin_matches(b.member_id, p_pin) then
    if not exists (select 1 from app.signin_pins x where x.member_id = b.member_id) then
      return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
    end if;
    update app.browser_keys x set failed = least(x.failed + 1, 10) where x.id = b.id returning * into b;
    perform app.pin_wrong(b.member_id, 'browser', b.id, b.failed);
    if b.failed >= 10 then
      delete from app.browser_keys x where x.id = b.id;
      return query select 'cancelled'::text, null::uuid, null::boolean, null::smallint, null::boolean, 0::smallint; return;
    end if;
    if app.signin_is_locked(b.member_id) then
      return query select 'locked'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
    end if;
    return query select 'wrong_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, (10 - b.failed)::smallint; return;
  end if;
  -- The member's GitHub sign-in method, the one their account began with (never a fingerprint the caller names).
  select i.fingerprint into fp from app.identities i where i.member_id = b.member_id and i.provider = 'github'
    order by (i.linked_by is null) desc, i.created_at limit 1;
  if fp is null then
    return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end if;
  begin
    select * into s from app.sign_in_core('github', array[fp], 1::smallint, 1::smallint, p_display_name,
                                     p_session_hash, p_session_days, null::timestamptz, null::uuid, p_region);
  exception when sqlstate 'P0001' or sqlstate '22023' or sqlstate '23505' then
    why := app.signin_refusal(sqlstate, sqlerrm);
    if why is null then raise; end if;
    return query select why, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end;
  update app.browser_keys x set failed = 0, used_at = now() where x.id = b.id;
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin, null::smallint;
end $$;

create or replace function app.pin_change(p_current text, p_new text) returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); x app.signin_pins%rowtype;
begin
  if me is null then return jsonb_build_object('status', 'signed_out'); end if;
  select * into x from app.signin_pins p where p.member_id = me for update;
  if not found then return jsonb_build_object('status', 'no_pin'); end if;
  -- 053: while the account is locked, no current PIN is tested or counted.
  if app.signin_is_locked(me) then
    perform app.audit_add('signin.refused', 'member', me, jsonb_build_object('lane', 'pin_change', 'reason', 'locked'), 'failure');
    return jsonb_build_object('status', 'locked');
  end if;
  if p_new is null or p_new !~ '^[0-9]{6}$' or app.pin_weak(p_new) then return jsonb_build_object('status', 'weak_pin'); end if;
  if not app.pin_matches(me, p_current) then
    update app.signin_pins p set change_failed = least(p.change_failed + 1, 10) where p.id = x.id returning * into x;
    if x.change_failed = 5 then
      perform app.pin_wrong(me, 'change', x.id, 5);
    end if;
    if x.change_failed >= 10 then
      update app.signin_pins p set change_failed = 0 where p.id = x.id;
      delete from app.sessions s where s.member_id = me and s.token_hash = current_setting('app.session', true);
      begin
        perform app.notify(null, 'alert', 'A session was signed out after wrong PINs',
          '10 wrong current PINs were typed to change one member''s PIN, so that session was signed out.', '/controls', 'member', me,
          'watch:pinchange:' || x.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MI'));
      exception when others then null;
      end;
      return jsonb_build_object('status', 'signed_out');
    end if;
    if app.signin_is_locked(me) then return jsonb_build_object('status', 'locked'); end if;
    return jsonb_build_object('status', 'wrong_pin', 'tries_left', 10 - x.change_failed);
  end if;
  perform app.pin_store(me, p_new);
  perform app.notify(me, 'signin_pin', 'Your PIN was changed', 'Your PIN was changed from your account page. If that '
    || 'wasn''t you, sign out everywhere and sign in again with a code posted through GitHub, which sets a new PIN.', '/account',
    'member', me, 'signin:pinchange:' || x.id::text || ':' || to_char(now(), 'YYYYMMDDHH24MISSUS'));
  return jsonb_build_object('status', 'ok');
end $$;
set local role dog_owner;
revoke create on schema app from dog_signin;
