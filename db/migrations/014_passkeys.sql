-- 014 Passkeys (Release 2, PR 17): step 2 of the agreed authentication plan. Requirement D5: riskier grants need the
-- person to prove it is them again, and GitHub and X can't force a fresh login (GitHub offers only select_account).
-- So a passkey (WebAuthn, checked by our own code with @simplewebauthn/server) is the proof.
--
-- What it adds:
--   * app.passkeys: public keys only (credential ID, public key, sign counter, transports, a label the member chose,
--     when added and last used, and the sign-in method of the session that added it). Never a private key, never
--     anything biometric: the fingerprint or face check happens on the person's own device and never reaches us.
--   * app.passkey_challenges: single-use, 2-minute challenges bound to one session, stored as SHA-256 only. Postgres
--     rather than a sealed cookie: a sealed cookie can be replayed until it expires unless a server-side nonce is kept
--     anyway (PR 15's review, F6); a row that is deleted when used is single use by construction, and ends with its
--     session (on delete cascade).
--   * app.passkey_recoveries: losing every passkey. A fresh sign-in starts a 72-hour cool-off, during which every risky
--     grant stays blocked and a notice says so; any session of the member can cancel it; after it, a new passkey can
--     be added without the old ones.
--   * sessions.stepped_up_at: when this session last passed a passkey check (with user verification). A step-up counts
--     for 5 minutes by the database clock, like the 10-minute fresh sign-in (app.fresh).
--   * The step-up check itself is the transaction setting app.step_up, set only by db/index.js from
--     app.session_step_up (the database's own answer, by its clock), exactly as app.fresh is. It is required, in
--     addition to every existing rule (fresh sign-in, seniority, lock order), for: letting an agent act on its own,
--     raising the daily cap of an agent that acts on its own, a new key for an agent that acts, the 90-day keep, linking or unlinking a sign-in method,
--     deleting an account, and Aaron's controls (a brake, a ban or unban, a deletion review). Drafting, lowering,
--     approving drafts and everything else never needs it.
--
-- How it is enforced without touching anyone else's functions: new triggers, not replaced functions. PR 16's 013
-- replaces app.agent_rules_fill, app.agent_resolve and others; replacing any of them here would undo its work when 014
-- runs after it. So every check below is a trigger of its own, and nothing that 012 or 013 defines is replaced.
--
-- After the PR 15 review (the lead, Oct 16): whatever a linked sign-in method did dies with it. Each passkey records
-- the method of the session that added it (identity_id); removing that method (unlinking it, or anything that deletes
-- it) deletes its passkeys in the same transaction, with an audit row and a notice. And a session may remove only
-- passkeys added by its own method or by a method added after it (the seniority rule of 012's unlink).
--
-- Rebase point: notices_kind_check and the notices_signin_insert policy are restated here with three new kinds. If
-- PR 15's fixes or PR 16 add a kind before this merges, add it to both lists below.

set local role dog_owner;

-- ---- The three new kinds of notice ----
alter table app.notices drop constraint notices_kind_check;
alter table app.notices add constraint notices_kind_check check (kind = any (array['draft_waiting', 'draft_expired', 'report_upheld', 'brake_on',
  'contained', 'containment_lifted', 'appeal_decided', 'act_reconfirm', 'act_expired', 'challenge', 'account_flagged', 'alert',
  'signin_linked', 'signin_unlinked', 'passkey_added', 'passkey_removed', 'passkey_recovery']));

-- ---- When a session last passed a passkey check ----
alter table app.sessions add column stepped_up_at timestamptz;
grant update (stepped_up_at) on app.sessions to dog_signin;

-- ---- Passkeys: public keys only ----
-- Removed with the member (on delete cascade, which Postgres runs outside row-level security, as integrity checks
-- are), and with the sign-in method that added them (app.identities_passkeys, below, which also tells the member).
create table app.passkeys (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id) on delete cascade,
  -- The sign-in method of the session that added it (seniority, and "dies with the method").
  identity_id uuid not null references app.identities (id),
  -- WebAuthn credential IDs are at most 1023 bytes: 1364 characters of base64url.
  credential_id text not null unique check (char_length(credential_id) >= 16 and char_length(credential_id) <= 1366 and credential_id ~ '^[A-Za-z0-9_-]+$'),
  -- The COSE public key, base64url. Public by nature; a private key never leaves the person's device.
  public_key text not null check (char_length(public_key) >= 16 and char_length(public_key) <= 2048 and public_key ~ '^[A-Za-z0-9_-]+$'),
  sign_count bigint not null default 0 check (sign_count >= 0 and sign_count <= 4294967295),
  transports text not null default '' check (char_length(transports) <= 100 and transports ~ '^([a-z-]+(,[a-z-]+)*)?$'),
  label text not null check (char_length(label) >= 1 and char_length(label) <= 60),
  backed_up boolean not null default false,
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);
create index passkeys_member on app.passkeys (member_id);
create index passkeys_identity on app.passkeys (identity_id);
alter table app.passkeys enable row level security;
alter table app.passkeys force row level security;
-- A member (or Aaron, as himself) reads only their own passkeys: the site needs the public key and counter to check a
-- signature. Nobody can read anyone else's, and the site's role can't write any: only the sign-in functions below can.
create policy passkeys_select on app.passkeys for select to dog_app
  using (app.actor_kind() in ('member', 'admin') and member_id = app.current_member());
create policy passkeys_signin_select on app.passkeys for select to dog_signin using (true);
create policy passkeys_signin_insert on app.passkeys for insert to dog_signin with check (true);
create policy passkeys_signin_update on app.passkeys for update to dog_signin using (true) with check (true);
create policy passkeys_signin_delete on app.passkeys for delete to dog_signin using (true);
grant select on app.passkeys to dog_app;
grant select, delete on app.passkeys to dog_signin;
grant insert (member_id, identity_id, credential_id, public_key, sign_count, transports, label, backed_up) on app.passkeys to dog_signin;
grant update (sign_count, last_used_at, backed_up) on app.passkeys to dog_signin;

-- ---- Challenges: single use, 2 minutes, one session ----
create table app.passkey_challenges (
  id uuid primary key default app.uuid_v7(),
  session_id uuid not null references app.sessions (id) on delete cascade,
  purpose text not null check (purpose = any (array['enrol', 'step_up'])),
  challenge_hash text not null unique check (char_length(challenge_hash) = 64 and challenge_hash ~ '^[0-9a-f]+$'),
  expires_at timestamptz not null
);
create index passkey_challenges_session on app.passkey_challenges (session_id);
alter table app.passkey_challenges enable row level security;
alter table app.passkey_challenges force row level security;
create policy passkey_challenges_signin_select on app.passkey_challenges for select to dog_signin using (true);
create policy passkey_challenges_signin_insert on app.passkey_challenges for insert to dog_signin with check (true);
create policy passkey_challenges_signin_delete on app.passkey_challenges for delete to dog_signin using (true);
grant select, delete on app.passkey_challenges to dog_signin;
grant insert (session_id, purpose, challenge_hash, expires_at) on app.passkey_challenges to dog_signin;

-- ---- Recovery: 72 hours, cancellable from any session ----
create table app.passkey_recoveries (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id) on delete cascade,
  started_at timestamptz not null default now(),
  ends_at timestamptz not null,
  cancelled_at timestamptz,
  completed_at timestamptz,
  constraint passkey_recoveries_once check (cancelled_at is null or completed_at is null)
);
-- One open recovery a member at a time.
create unique index passkey_recoveries_open on app.passkey_recoveries (member_id) where cancelled_at is null and completed_at is null;
alter table app.passkey_recoveries enable row level security;
alter table app.passkey_recoveries force row level security;
create policy passkey_recoveries_select on app.passkey_recoveries for select to dog_app
  using (app.actor_kind() in ('member', 'admin') and member_id = app.current_member());
create policy passkey_recoveries_signin_select on app.passkey_recoveries for select to dog_signin using (true);
create policy passkey_recoveries_signin_insert on app.passkey_recoveries for insert to dog_signin with check (true);
create policy passkey_recoveries_signin_update on app.passkey_recoveries for update to dog_signin using (true) with check (true);
grant select on app.passkey_recoveries to dog_app;
grant select on app.passkey_recoveries to dog_signin;
grant insert (member_id, ends_at) on app.passkey_recoveries to dog_signin;
grant update (cancelled_at, completed_at) on app.passkey_recoveries to dog_signin;

-- ---- The sign-in role leaves the passkey notices too (as it leaves the sign-in ones, 012) ----
drop policy notices_signin_insert on app.notices;
create policy notices_signin_insert on app.notices for insert to dog_signin
  with check (member_id is not null and kind in ('signin_linked', 'signin_unlinked', 'passkey_added', 'passkey_removed', 'passkey_recovery'));

-- ---- The step-up checks: triggers of their own (none of 012's or 013's functions is replaced) ----
-- Each fires always, refuses with 'step_up' unless this transaction carries a passkey check from the last 5 minutes
-- (app.step_up, set only by db/index.js from app.session_step_up), and applies only to people (members and Aaron):
-- the site's own timers (system) and agents never carry a passkey and are never asked for one.

-- Letting an agent act on its own, raising the daily cap of an agent that acts on its own, or keeping it acting at the
-- 90-day check. Drafting never needs it: raising the cap of an agent that only drafts lets more drafts wait for the
-- owner's approval, and nothing more (the fresh sign-in for any bigger cap, 008, still applies). A first version
-- (always draft), and the system's own versions (which can only lower, or restore exactly what the owner had), never
-- need it either. Fires after agent_rules_fill (names sort), so a stale session is still told to sign in again first.
create function app.agent_rules_step_up() returns trigger
language plpgsql
as $$
declare
  prev record;
begin
  if app.actor_kind() not in ('member', 'admin') or coalesce(current_setting('app.step_up', true), '') = '1'
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
create trigger agent_rules_step_up before insert on app.agent_rules for each row execute function app.agent_rules_step_up();
alter table app.agent_rules enable always trigger agent_rules_step_up;

-- A new key for an agent that acts on its own (the same test as 008's agent_keys_fresh, which fires first).
create function app.agent_keys_step_up() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() in ('member', 'admin') and coalesce(current_setting('app.step_up', true), '') <> '1'
     and exists (select 1 from app.agent_rules r where r.agent_id = new.agent_id
                 and r.version = (select max(x.version) from app.agent_rules x where x.agent_id = new.agent_id)
                 and 'act' in (r.post_mode, r.reply_mode, r.report_mode)) then
    raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to make a new key for an agent that acts on its own.';
  end if;
  return new;
end
$$;
create trigger agent_keys_step_up before insert on app.agent_keys for each row execute function app.agent_keys_step_up();
alter table app.agent_keys enable always trigger agent_keys_step_up;

-- Linking or unlinking a sign-in method (and deleting one with the account). Signing in (someone not signed in) is
-- untouched, so a first sign-up never needs a passkey.
create function app.identities_step_up() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() in ('member', 'admin') and coalesce(current_setting('app.step_up', true), '') <> '1' then
    raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to change how you sign in.';
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end
$$;
create trigger identities_step_up before insert or delete on app.identities for each row execute function app.identities_step_up();
alter table app.identities enable always trigger identities_step_up;

-- Deleting an account (the member's own, or Aaron's "delete" on a deletion review), and Aaron banning, unbanning,
-- disabling or restoring an account. A member renaming themselves, and the site's own timers, never need it.
create function app.members_step_up() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() in ('member', 'admin') and coalesce(current_setting('app.step_up', true), '') <> '1'
     and (tg_op = 'DELETE' or (app.actor_kind() = 'admin' and new.status is distinct from old.status)) then
    raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey first.';
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end
$$;
create trigger members_step_up before update or delete on app.members for each row execute function app.members_step_up();
alter table app.members enable always trigger members_step_up;

-- Aaron's controls: setting or lifting a brake, and deciding a deletion review.
create function app.admin_step_up() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() = 'admin' and coalesce(current_setting('app.step_up', true), '') <> '1' then
    raise exception 'step_up' using errcode = 'P0001', hint = 'Confirm it''s you with your passkey to use the owner controls.';
  end if;
  return new;
end
$$;
create trigger brakes_step_up before insert or update on app.brakes for each row execute function app.admin_step_up();
alter table app.brakes enable always trigger brakes_step_up;
create trigger deletion_reviews_step_up before update on app.deletion_reviews for each row execute function app.admin_step_up();
alter table app.deletion_reviews enable always trigger deletion_reviews_step_up;

-- ---- The passkey functions, in the sign-in role (which alone writes sessions, identities and passkeys) ----
-- Created as dog_owner, their callers set, then handed to dog_signin (as 012 does), so PUBLIC never keeps a right.

-- Whether this session passed a passkey check in the last 5 minutes (by the database clock), how many passkeys its
-- member has, and when an open recovery's cool-off ends. While a recovery is open nothing counts as a step-up, so
-- every risky grant stays blocked. Asked as someone not signed in, alongside app.session_resolve.
create function app.session_step_up(p_session_hash text)
returns table (stepped_up boolean, passkeys integer, recovery_until timestamptz)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s app.sessions%rowtype;
  n integer;
  rec timestamptz;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  select * into s from app.sessions x where x.token_hash = p_session_hash and x.expires_at > now();
  if not found then
    return;
  end if;
  select count(*)::int into n from app.passkeys k where k.member_id = s.member_id;
  select r.ends_at into rec from app.passkey_recoveries r where r.member_id = s.member_id and r.cancelled_at is null and r.completed_at is null;
  return query select (s.stepped_up_at is not null and s.stepped_up_at > now() - interval '5 minutes' and n > 0 and rec is null), n, rec;
end
$$;

-- A new challenge for this session: 'enrol' (adding a passkey, which needs a fresh sign-in) or 'step_up'. Only its
-- SHA-256 is kept, for 2 minutes. At most 5 waiting a session. Returns when it expires, or null when refused ('fresh'
-- for an enrol from a session older than 10 minutes).
create function app.passkey_challenge(p_session_hash text, p_purpose text, p_challenge_hash text)
returns table (status text, expires_at timestamptz)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  s app.sessions%rowtype;
  n integer;
  exp timestamptz := now() + interval '2 minutes';
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or p_challenge_hash is null or p_challenge_hash !~ '^[0-9a-f]{64}$'
     or p_purpose is null or p_purpose not in ('enrol', 'step_up') or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad passkey request' using errcode = '22023';
  end if;
  select * into s from app.sessions x where x.token_hash = p_session_hash and x.member_id = me and x.expires_at > now();
  if not found then
    return query select 'session'::text, null::timestamptz;
    return;
  end if;
  if p_purpose = 'enrol' and s.created_at <= now() - interval '10 minutes' then
    return query select 'fresh'::text, null::timestamptz;
    return;
  end if;
  if random() < 0.05 then
    delete from app.passkey_challenges c where c.expires_at < now() - interval '1 hour';
  end if;
  delete from app.passkey_challenges c where c.session_id = s.id and c.expires_at <= now();
  select count(*)::int into n from app.passkey_challenges c where c.session_id = s.id;
  if n >= 5 then
    return query select 'too_many'::text, null::timestamptz;
    return;
  end if;
  insert into app.passkey_challenges (session_id, purpose, challenge_hash, expires_at) values (s.id, p_purpose, p_challenge_hash, exp);
  return query select 'ok'::text, exp;
end
$$;

-- Throws a challenge away unused (the site calls this when a signature doesn't check out, so even a failed answer
-- uses it up). Only this member's own session's challenge.
create function app.passkey_challenge_drop(p_session_hash text, p_challenge_hash text)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  n integer;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or p_challenge_hash is null or p_challenge_hash !~ '^[0-9a-f]{64}$'
     or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad passkey request' using errcode = '22023';
  end if;
  delete from app.passkey_challenges c using app.sessions s
    where c.challenge_hash = p_challenge_hash and c.session_id = s.id and s.token_hash = p_session_hash and s.member_id = me;
  get diagnostics n = row_count;
  return n > 0;
end
$$;

-- Adds a passkey the site has just verified (attestation, origin, RP ID, user verification), from this member's own
-- session, begun in the last 10 minutes. The challenge is used up whatever happens next (refusals are statuses, not
-- errors, so the transaction keeps that). Rules:
--   * an open recovery: only once its 72 hours are over, which completes it; before that, 'cool_off'
--   * otherwise, a member who already has a passkey: this session must have passed a passkey check in the last 5
--     minutes ('step_up'), so a stolen fresh cookie can't add its holder's own key
--   * a session from before 012 has no recorded sign-in method and must sign in again ('signin_again')
--   * at most 10 passkeys ('too_many'); a credential already registered anywhere is 'taken'
-- Returns the status, the new passkey's ID and whether it completed a recovery.
create function app.passkey_enrol(p_session_hash text, p_challenge_hash text, p_credential_id text, p_public_key text, p_sign_count bigint,
                                  p_transports text, p_label text, p_backed_up boolean)
returns table (status text, passkey_id uuid, recovery_completed boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  s app.sessions%rowtype;
  rec app.passkey_recoveries%rowtype;
  n integer;
  nid uuid;
  took integer;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or p_challenge_hash is null or p_challenge_hash !~ '^[0-9a-f]{64}$'
     or p_credential_id is null or char_length(p_credential_id) not between 16 and 1366 or p_credential_id !~ '^[A-Za-z0-9_-]+$'
     or p_public_key is null or char_length(p_public_key) not between 16 and 2048 or p_public_key !~ '^[A-Za-z0-9_-]+$'
     or p_sign_count is null or p_sign_count not between 0 and 4294967295
     or p_transports is null or char_length(p_transports) > 100 or p_transports !~ '^([a-z-]+(,[a-z-]+)*)?$'
     or p_label is null or char_length(p_label) not between 1 and 60 or p_backed_up is null
     or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad passkey request' using errcode = '22023';
  end if;
  -- The member's lock first, as linking and unlinking take it (012, review F2).
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  select * into s from app.sessions x where x.token_hash = p_session_hash and x.member_id = me and x.expires_at > now() for update;
  if not found then
    return query select 'session'::text, null::uuid, false;
    return;
  end if;
  delete from app.passkey_challenges c where c.challenge_hash = p_challenge_hash and c.session_id = s.id and c.purpose = 'enrol' and c.expires_at > now();
  get diagnostics took = row_count;
  if took = 0 then
    return query select 'challenge'::text, null::uuid, false;
    return;
  end if;
  perform 1 from app.members m where m.id = me and m.status = 'active' and not app.deletion_overdue(me) for update;
  if not found then
    return query select 'not_active'::text, null::uuid, false;
    return;
  end if;
  if s.created_at <= now() - interval '10 minutes' then
    return query select 'fresh'::text, null::uuid, false;
    return;
  end if;
  if s.identity_id is null then
    return query select 'signin_again'::text, null::uuid, false;
    return;
  end if;
  select * into rec from app.passkey_recoveries r where r.member_id = me and r.cancelled_at is null and r.completed_at is null for update;
  select count(*)::int into n from app.passkeys k where k.member_id = me;
  if rec.id is not null then
    if rec.ends_at > now() then
      return query select 'cool_off'::text, null::uuid, false;
      return;
    end if;
  elsif n > 0 and (s.stepped_up_at is null or s.stepped_up_at <= now() - interval '5 minutes') then
    return query select 'step_up'::text, null::uuid, false;
    return;
  end if;
  if n >= 10 then
    return query select 'too_many'::text, null::uuid, false;
    return;
  end if;
  if exists (select 1 from app.passkeys k where k.credential_id = p_credential_id) then
    return query select 'taken'::text, null::uuid, false;
    return;
  end if;
  insert into app.passkeys (member_id, identity_id, credential_id, public_key, sign_count, transports, label, backed_up)
    values (me, s.identity_id, p_credential_id, p_public_key, p_sign_count, p_transports, p_label, p_backed_up) returning id into nid;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('passkey.enrolled', 'member', me, jsonb_build_object('passkey', nid, 'recovery', rec.id is not null));
  if rec.id is not null then
    update app.passkey_recoveries r set completed_at = now() where r.id = rec.id;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('passkey.recovery_completed', 'member', me, jsonb_build_object('recovery', rec.id, 'passkey', nid));
  end if;
  perform app.notify(me, 'passkey_added', 'A passkey was added to your account',
    'A new passkey can now confirm risky steps on your account, such as letting an agent act on its own. If this wasn''t you, '
    || 'sign in with your oldest sign-in method, remove it on your account page, and sign out everywhere.',
    '/account', 'passkey', nid, 'passkey:added:' || nid::text);
  return query select 'ok'::text, nid, rec.id is not null;
end
$$;

-- A passkey check the site has just verified (signature, origin, RP ID, user verification): uses up this session's
-- challenge, checks the credential is the member's own and that its sign counter moved forward, and marks this session
-- as stepped up for 5 minutes. A counter that didn't move forward (when either side counts) may mean a copied key: the
-- check fails, the audit log records it and the member is told. While a recovery is open nothing counts.
-- Returns the status and until when the step-up lasts.
create function app.passkey_assert(p_session_hash text, p_challenge_hash text, p_credential_id text, p_sign_count bigint, p_backed_up boolean)
returns table (status text, until timestamptz)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  s app.sessions%rowtype;
  k app.passkeys%rowtype;
  took integer;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or p_challenge_hash is null or p_challenge_hash !~ '^[0-9a-f]{64}$'
     or p_credential_id is null or char_length(p_credential_id) not between 16 and 1366 or p_credential_id !~ '^[A-Za-z0-9_-]+$'
     or p_sign_count is null or p_sign_count not between 0 and 4294967295 or p_backed_up is null
     or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad passkey request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  select * into s from app.sessions x where x.token_hash = p_session_hash and x.member_id = me and x.expires_at > now() for update;
  if not found then
    return query select 'session'::text, null::timestamptz;
    return;
  end if;
  delete from app.passkey_challenges c where c.challenge_hash = p_challenge_hash and c.session_id = s.id and c.purpose = 'step_up' and c.expires_at > now();
  get diagnostics took = row_count;
  if took = 0 then
    return query select 'challenge'::text, null::timestamptz;
    return;
  end if;
  select * into k from app.passkeys x where x.credential_id = p_credential_id and x.member_id = me for update;
  if not found then
    return query select 'unknown'::text, null::timestamptz;
    return;
  end if;
  if exists (select 1 from app.passkey_recoveries r where r.member_id = me and r.cancelled_at is null and r.completed_at is null) then
    return query select 'recovery'::text, null::timestamptz;
    return;
  end if;
  if (k.sign_count > 0 or p_sign_count > 0) and p_sign_count <= k.sign_count then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('passkey.counter_regression', 'member', me, jsonb_build_object('passkey', k.id, 'stored', k.sign_count, 'seen', p_sign_count));
    perform app.notify(me, 'passkey_removed', 'A passkey check was refused',
      'One of your passkeys answered with a sign counter that went backwards, which can mean the key was copied. The check was '
      || 'refused. If you didn''t just use it on another device, remove that passkey on your account page and add a new one.',
      '/account', 'passkey', k.id, 'passkey:counter:' || k.id::text || ':' || p_sign_count::text);
    return query select 'counter'::text, null::timestamptz;
    return;
  end if;
  update app.passkeys x set sign_count = p_sign_count, last_used_at = now(), backed_up = p_backed_up where x.id = k.id;
  update app.sessions x set stepped_up_at = now() where x.id = s.id;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('passkey.used', 'member', me, jsonb_build_object('passkey', k.id));
  return query select 'ok'::text, now() + interval '5 minutes';
end
$$;

-- Removing a passkey: never silently. It needs this session's own passkey check in the last 5 minutes, never during a
-- recovery's cool-off, never the last one (protection never quietly drops to none; add a new one first), and (the
-- seniority rule of 012's unlink) only a passkey added by this session's own sign-in method or by one added after it.
-- The member is told, and the audit log records it.
create function app.passkey_remove(p_session_hash text, p_passkey uuid)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  s app.sessions%rowtype;
  k app.passkeys%rowtype;
  own app.identities%rowtype;
  added app.identities%rowtype;
  n integer;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or p_passkey is null
     or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad passkey request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  select * into s from app.sessions x where x.token_hash = p_session_hash and x.member_id = me and x.expires_at > now() for update;
  if not found then
    return 'session';
  end if;
  if s.stepped_up_at is null or s.stepped_up_at <= now() - interval '5 minutes' then
    return 'step_up';
  end if;
  if exists (select 1 from app.passkey_recoveries r where r.member_id = me and r.cancelled_at is null and r.completed_at is null) then
    return 'recovery';
  end if;
  select * into k from app.passkeys x where x.id = p_passkey and x.member_id = me for update;
  if not found then
    return 'not_found';
  end if;
  select count(*)::int into n from app.passkeys x where x.member_id = me;
  if n <= 1 then
    return 'last';
  end if;
  select * into own from app.identities i where i.id = s.identity_id and i.member_id = me;
  select * into added from app.identities i where i.id = k.identity_id and i.member_id = me;
  if own.id is null or added.id is null or (added.created_at, added.id) < (own.created_at, own.id) then
    return 'senior';
  end if;
  delete from app.passkeys x where x.id = k.id;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('passkey.removed', 'member', me, jsonb_build_object('passkey', k.id, 'reason', 'member'));
  perform app.notify(me, 'passkey_removed', 'A passkey was removed from your account',
    'That passkey can no longer confirm risky steps on your account. If this wasn''t you, sign in with your oldest sign-in method '
    || 'and check your passkeys and sign-in methods on your account page.', '/account', 'passkey', k.id, 'passkey:removed:' || k.id::text);
  return 'ok';
end
$$;

-- Starting recovery after losing every passkey: from a session begun in the last 10 minutes. For 72 hours every risky
-- grant stays blocked (no session counts as stepped up, and any step-up already given ends now); then a new passkey
-- can be added without the old ones. The member is told, and any session of theirs can cancel it.
create function app.passkey_recovery_start(p_session_hash text)
returns table (status text, ends_at timestamptz)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  s app.sessions%rowtype;
  rid uuid;
  ends timestamptz := now() + interval '72 hours';
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad passkey request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  select * into s from app.sessions x where x.token_hash = p_session_hash and x.member_id = me and x.expires_at > now() for update;
  if not found then
    return query select 'session'::text, null::timestamptz;
    return;
  end if;
  if s.created_at <= now() - interval '10 minutes' then
    return query select 'fresh'::text, null::timestamptz;
    return;
  end if;
  perform 1 from app.members m where m.id = me and m.status = 'active' for update;
  if not found then
    return query select 'not_active'::text, null::timestamptz;
    return;
  end if;
  if exists (select 1 from app.passkey_recoveries r where r.member_id = me and r.cancelled_at is null and r.completed_at is null) then
    return query select 'open'::text, null::timestamptz;
    return;
  end if;
  insert into app.passkey_recoveries (member_id, ends_at) values (me, ends) returning id into rid;
  update app.sessions x set stepped_up_at = null where x.member_id = me and x.stepped_up_at is not null;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('passkey.recovery_started', 'member', me, jsonb_build_object('recovery', rid));
  perform app.notify(me, 'passkey_recovery', 'Passkey recovery started',
    'Someone signed in to your account started passkey recovery. For 72 hours nothing risky can be done on your account (letting '
    || 'an agent act on its own, new keys for acting agents, sign-in changes, deleting it); after that a new passkey can be added. '
    || 'If this wasn''t you, cancel it on your account page from any session.', '/account', 'passkey_recovery', rid,
    'passkey:recovery:' || rid::text || ':started');
  return query select 'ok'::text, ends;
end
$$;

-- Cancelling a recovery: from any session of the member, with no fresh sign-in or passkey (cancelling only ever takes
-- something away). The member is told, and the audit log records it.
create function app.passkey_recovery_cancel(p_session_hash text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  rid uuid;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad passkey request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  perform 1 from app.sessions x where x.token_hash = p_session_hash and x.member_id = me and x.expires_at > now();
  if not found then
    return 'session';
  end if;
  update app.passkey_recoveries r set cancelled_at = now()
    where r.member_id = me and r.cancelled_at is null and r.completed_at is null returning r.id into rid;
  if rid is null then
    return 'none';
  end if;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('passkey.recovery_cancelled', 'member', me, jsonb_build_object('recovery', rid));
  perform app.notify(me, 'passkey_recovery', 'Passkey recovery cancelled',
    'Passkey recovery on your account was cancelled. Your passkeys work as before.', '/account', 'passkey_recovery', rid,
    'passkey:recovery:' || rid::text || ':cancelled');
  return 'ok';
end
$$;

-- "Whatever a linked method did dies with it": removing a sign-in method removes the passkeys its sessions added, in
-- the same transaction. When it happens while the member is still signed in (an unlink), the audit log records each
-- one and the member is told; when it is part of deleting the whole account (every session is already gone), the
-- account's own deletion record covers it and nothing is left behind.
create function app.identities_passkeys() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  ids uuid[];
begin
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

grant create on schema app to dog_signin;

-- The trigger first: creating it needs the right to run its function, which only its owner keeps afterwards.
create trigger identities_passkeys before delete on app.identities for each row execute function app.identities_passkeys();
alter table app.identities enable always trigger identities_passkeys;

-- Only the site's role may call them; set before handing them to dog_signin, as 012 does.
revoke execute on function app.session_step_up(text), app.passkey_challenge(text, text, text), app.passkey_challenge_drop(text, text),
  app.passkey_enrol(text, text, text, text, bigint, text, text, boolean), app.passkey_assert(text, text, text, bigint, boolean),
  app.passkey_remove(text, uuid), app.passkey_recovery_start(text), app.passkey_recovery_cancel(text), app.identities_passkeys() from public;
grant execute on function app.session_step_up(text), app.passkey_challenge(text, text, text), app.passkey_challenge_drop(text, text),
  app.passkey_enrol(text, text, text, text, bigint, text, text, boolean), app.passkey_assert(text, text, text, bigint, boolean),
  app.passkey_remove(text, uuid), app.passkey_recovery_start(text), app.passkey_recovery_cancel(text), app.identities_passkeys() to dog_app;
alter function app.session_step_up(text) owner to dog_signin;
alter function app.passkey_challenge(text, text, text) owner to dog_signin;
alter function app.passkey_challenge_drop(text, text) owner to dog_signin;
alter function app.passkey_enrol(text, text, text, text, bigint, text, text, boolean) owner to dog_signin;
alter function app.passkey_assert(text, text, text, bigint, boolean) owner to dog_signin;
alter function app.passkey_remove(text, uuid) owner to dog_signin;
alter function app.passkey_recovery_start(text) owner to dog_signin;
alter function app.passkey_recovery_cancel(text) owner to dog_signin;
alter function app.identities_passkeys() owner to dog_signin;
revoke create on schema app from dog_signin;
