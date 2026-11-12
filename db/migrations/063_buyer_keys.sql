-- 063 The buyer door: a person who only wants to post and pay for work signs in with a passkey, no GitHub account
--   (Aaron, Nov 11, 2026: "a buyer may sign in with a passkey and no GitHub account"; scope "posting, funding,
--   reviewing and disputing tasks only: no feed posts, no claims, no agents"; Nov 12: name the table app.buyer_keys,
--   keep dog-migrate's "no passkey" check unchanged, and enforce the scope in the database).
--
--   Why "buyer keys" and not "passkeys": the runner's daily check (supabase/functions/dog-migrate/core.mjs) refuses any
--   app table or function named like "passkey". It guards against the worker passkey and step-up system removed on
--   Oct 23 coming back, and it stays. A buyer key is a WebAuthn passkey too, but a different thing: it opens a buyer
--   account and nothing else. db/README.md says the same.
--
--   What a buyer key is: a WebAuthn credential (ES256, P-256 only) made by the person's own device for this site's
--   address, with user verification (Face ID, a fingerprint or the device PIN). Only its public key is stored. Every
--   check is made here, in the database, not only by the site: the one-time challenge (037's app.signin_challenges,
--   used up by the first try), the browser's report of what it signed (type, challenge, this site's address), the
--   authenticator's data (this site's name, user present and verified) and, at sign-in, the ECDSA signature over both
--   (037's app.p256_verify). So the site's own database login can't sign anyone in as a buyer without that device.
--   A buyer account is a member with one sign-in method, "buyer", whose fingerprint is the SHA-256 of the public key.
--   It can never gain another method, and no other member can gain a buyer key.
--
--   What a buyer can do: create projects and tasks, fund them (061), decide on submitted work and dispute. What they
--   can't: feed posts and replies, reports, claims, submissions, points, agents (and so MCP), browser keys, PINs, key
--   files, payouts, engine orders, or becoming administrator. Each is refused by a trigger before the row exists
--   (app.buyer_scope), whichever role writes it. A buyer stays at level 1: their pass on submitted work waits for Third
--   Look (052), as a level-1 poster's does.
--
--   The funding gate: a buyer's new task starts as "funding". It is hidden from everyone but its poster and the
--   administrator (a restrictive policy on the work role), so nobody can claim it, and it opens when its bounty is
--   funded (app.buyer_task_funded). A buyer's project shows to others only once one of its tasks is open.
--
--   The site's buyer door stays shut while payments are off (payments.json), since its only use is funded work.

-- ---- The method ----
alter table app.identities drop constraint identities_provider_check;
alter table app.identities add constraint identities_provider_check check (provider = any (array['github', 'x', 'email', 'linkedin', 'buyer']));

-- ---- The keys ----
set local role dog_owner;
create table app.buyer_keys (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null unique references app.members (id) on delete cascade,
  -- The device's own name for the credential (WebAuthn's credential ID): random bytes, nothing about the person.
  credential_id bytea not null unique check (octet_length(credential_id) between 16 and 1023),
  -- The raw uncompressed P-256 point (0x04, X, Y), checked to be on the curve when it is added.
  public_key bytea not null unique check (octet_length(public_key) = 65),
  -- The authenticator's signature counter. Many passkeys always send 0; one that goes backwards alerts (a cloned key),
  -- it never refuses (checks alert, never lock out).
  sign_count bigint not null default 0 check (sign_count between 0 and 4294967295),
  created_at timestamptz not null default now(),
  used_at timestamptz
);
alter table app.buyer_keys enable row level security;
alter table app.buyer_keys force row level security;
create policy buyer_keys_signin_select on app.buyer_keys for select to dog_signin using (true);
create policy buyer_keys_signin_insert on app.buyer_keys for insert to dog_signin with check (true);
create policy buyer_keys_signin_update on app.buyer_keys for update to dog_signin using (true) with check (true);
grant select on app.buyer_keys to dog_signin;
grant insert (member_id, credential_id, public_key, sign_count) on app.buyer_keys to dog_signin;
grant update (sign_count, used_at) on app.buyer_keys to dog_signin;

-- A funding task (below).
alter table app.work_tasks drop constraint work_tasks_status_check;
alter table app.work_tasks add constraint work_tasks_status_check
  check (status = any (array['open', 'claimed', 'submitted', 'audited', 'approved', 'closed', 'removed', 'funding']));
reset role;

-- ---- The sign-in role's functions ----
grant create on schema app to dog_signin;
set local role dog_signin;

-- 025's sign-in core, unchanged but for the one more method it accepts.
create or replace function app.sign_in_core(p_provider text, p_fingerprints text[], p_key_version smallint, p_level smallint, p_display_name text, p_session_hash text, p_session_days integer, p_recheck_after timestamp with time zone, p_link_member uuid, p_region text)
 returns table(member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
 language plpgsql
 security definer
 set search_path to 'pg_catalog'
as $function$
declare
  ident app.identities%rowtype;
  mem app.members%rowtype;
  fresh boolean := false;
  used uuid;
begin
  if p_provider is null or not (p_provider = any (array['github', 'x', 'email', 'linkedin', 'buyer']))
     or p_fingerprints is null or cardinality(p_fingerprints) not between 1 and 5
     or exists (select 1 from unnest(p_fingerprints) f where f is null or f !~ '^[0-9a-f]{64}$')
     or p_key_version is null or p_key_version not between 1 and 999
     or p_level is null or p_level not between 0 and 2 or p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$'
     or p_session_days is null or p_session_days not between 1 and 30
     or p_display_name is null or char_length(p_display_name) not between 1 and 80
     or (p_region is not null and p_region !~ '^[A-Z]{2}$') then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  -- Signing in is for someone not signed in, and never links a method (PR 15: app.identity_link does, with no session).
  if p_link_member is not null or app.actor_kind() <> 'anon' then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;

  select * into ident from app.identities i where i.provider = p_provider and i.fingerprint = any (p_fingerprints)
    order by i.created_at limit 1 for update;

  if found then
    select * into mem from app.members m where m.id = ident.member_id for update;
    update app.identities i set fingerprint = p_fingerprints[1], key_version = p_key_version, level = p_level,
                                verified_at = now(), recheck_after = p_recheck_after
      where i.id = ident.id;
    used := ident.id;
  elsif p_region is not null then
    -- Nobody signs up from a declined region, whatever they confirm.
    raise exception 'region' using errcode = 'P0001';
  else
    insert into app.members (display_name, trust_level) values (p_display_name, p_level) returning * into mem;
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (mem.id, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after) returning id into used;
    fresh := true;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.joined', 'member', mem.id, jsonb_build_object('provider', p_provider, 'level', mem.trust_level));
  end if;

  if mem.status = 'banned' then
    raise exception 'banned' using errcode = 'P0001';
  end if;
  if mem.status = 'disabled' or app.deletion_overdue(mem.id) then
    raise exception 'disabled' using errcode = 'P0001';
  end if;

  if app.verified_level(mem.id) is distinct from mem.trust_level then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_changed', 'member', mem.id,
              jsonb_build_object('provider', p_provider, 'from', mem.trust_level, 'to', app.verified_level(mem.id)));
    update app.members m set trust_level = app.verified_level(mem.id) where m.id = mem.id;
    mem.trust_level := app.verified_level(mem.id);
  end if;

  -- The session records the method it signed in with (review F1: seniority).
  insert into app.sessions (member_id, token_hash, expires_at, identity_id)
    values (mem.id, p_session_hash, now() + make_interval(days => p_session_days), used);
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.signed_in', 'member', mem.id, jsonb_build_object('provider', p_provider));
  if p_region is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.region_confirmed', 'member', mem.id, jsonb_build_object('country', p_region));
  end if;

  return query select mem.id, fresh, mem.trust_level, mem.is_admin;
end
$function$;

-- Is this member a buyer (their one sign-in method is a buyer key)?
create function app.is_buyer(p_member uuid) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select p_member is not null and exists (select 1 from app.identities i where i.member_id = p_member and i.provider = 'buyer')
$$;

-- What a WebAuthn browser reports, checked: its report of what it signed (clientDataJSON) has this type, a one-time
-- challenge of ours (used up now, right or wrong) and the address that challenge was made for, and not another site's
-- frame; the authenticator's data names this site (the SHA-256 of its host, WebAuthn's RP ID) with the user present and
-- verified. Returns the signature counter, or null when anything fails.
create function app.buyer_webauthn(p_type text, p_client_data bytea, p_auth_data bytea) returns bigint
language plpgsql security definer set search_path = pg_catalog as $$
declare cd jsonb; ch app.signin_challenges%rowtype; rp text; flags integer;
begin
  if p_type is null or p_client_data is null or p_auth_data is null or octet_length(p_client_data) not between 50 and 2048
     or octet_length(p_auth_data) not between 37 and 4096 then
    return null;
  end if;
  begin
    cd := convert_from(p_client_data, 'UTF8')::jsonb;
  exception when others then
    return null;
  end;
  if jsonb_typeof(cd) <> 'object' or cd ->> 'type' is distinct from p_type or coalesce(cd ->> 'challenge', '') !~ '^[A-Za-z0-9_-]{43}$'
     or coalesce(cd ->> 'crossOrigin', 'false') <> 'false' or cd ? 'topOrigin' then
    return null;
  end if;
  update app.signin_challenges c set used_at = now()
    where c.challenge_hash = encode(sha256(convert_to(cd ->> 'challenge', 'UTF8')), 'hex') and c.used_at is null and c.expires_at > now()
    returning * into ch;
  if not found or ch.origin is distinct from cd ->> 'origin' then
    return null;
  end if;
  rp := substring(ch.origin from '^https://([a-z0-9.-]+)');
  flags := get_byte(p_auth_data, 32);
  -- User present (bit 0) and user verified (bit 2).
  if rp is null or substring(p_auth_data from 1 for 32) <> sha256(convert_to(rp, 'UTF8')) or flags & 1 = 0 or flags & 4 = 0 then
    return null;
  end if;
  return (get_byte(p_auth_data, 33)::bigint << 24) + (get_byte(p_auth_data, 34) << 16) + (get_byte(p_auth_data, 35) << 8) + get_byte(p_auth_data, 36);
end $$;

-- A new buyer: the key the person's device just made. The authenticator's data must carry this credential (the attested
-- credential flag, bit 6, and the credential ID) and this public key as an ES256 P-256 key (COSE kty 2, alg -7, crv 1,
-- and the key's X and Y). No attestation is asked for, so no maker's certificate and nothing that tells devices apart
-- is ever stored. A key that is already here signs nobody in from this door ('taken'). Makes the member and their
-- session in one go, as the other ways in do.
create function app.buyer_register(p_credential_id bytea, p_public_key bytea, p_client_data bytea, p_auth_data bytea,
  p_display_name text, p_session_hash text, p_session_days integer)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog as $$
declare n bigint; len integer; rest bytea; s record; why text;
begin
  if app.actor_kind() <> 'anon' or p_credential_id is null or octet_length(p_credential_id) not between 16 and 1023
     or p_public_key is null or not app.p256_point_ok(p_public_key) then
    return query select 'bad_key'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  n := app.buyer_webauthn('webauthn.create', p_client_data, p_auth_data);
  if n is null or get_byte(p_auth_data, 32) & 64 = 0 or octet_length(p_auth_data) < 55 + octet_length(p_credential_id) then
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  -- Attested credential data from byte 37: the maker's ID (16 bytes, unused), the credential ID's length (2 bytes) and
  -- the ID, then the public key as COSE.
  len := (get_byte(p_auth_data, 53) << 8) + get_byte(p_auth_data, 54);
  rest := substring(p_auth_data from 56 + len);
  if len <> octet_length(p_credential_id) or substring(p_auth_data from 56 for len) <> p_credential_id
     or position('\x0102'::bytea in rest) = 0 or position('\x0326'::bytea in rest) = 0 or position('\x2001'::bytea in rest) = 0
     or position('\x215820'::bytea || substring(p_public_key from 2 for 32) in rest) = 0
     or position('\x225820'::bytea || substring(p_public_key from 34 for 32) in rest) = 0 then
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  if exists (select 1 from app.buyer_keys k where k.credential_id = p_credential_id or k.public_key = p_public_key)
     or exists (select 1 from app.identities i where i.provider = 'buyer' and i.fingerprint = encode(sha256(p_public_key), 'hex')) then
    return query select 'taken'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  begin
    select * into s from app.sign_in_core('buyer', array[encode(sha256(p_public_key), 'hex')], 1::smallint, 1::smallint, p_display_name,
                                     p_session_hash, p_session_days, null::timestamptz, null::uuid, null::text);
  exception when sqlstate 'P0001' or sqlstate '22023' or sqlstate '23505' then
    why := app.signin_refusal(sqlstate, sqlerrm);
    if why is null then raise; end if;
    return query select why, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end;
  if not s.is_new then raise exception 'a new buyer key opened an account that was already here' using errcode = '42501'; end if;
  insert into app.buyer_keys (member_id, credential_id, public_key, sign_count) values (s.member_id, p_credential_id, p_public_key, n);
  perform app.audit_add('buyer.key_added', 'member', s.member_id, '{}'::jsonb, 'success');
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin;
end $$;

-- The public half of a buyer key, by its credential ID, so the site checks the signature itself before the database
-- checks it again (as 037's app.browser_key_public). Null for a key that isn't here. Nothing secret.
create function app.buyer_key_public(p_credential_id bytea) returns bytea
language sql stable security definer set search_path = pg_catalog as $$
  select k.public_key from app.buyer_keys k where k.credential_id = p_credential_id
$$;

-- A buyer signing in: the device's signature over the authenticator's data and the SHA-256 of the browser's report,
-- checked here with the stored public key. While the account is locked (053) nothing is tested and every try gets the
-- same answer.
create function app.buyer_sign_in(p_credential_id bytea, p_client_data bytea, p_auth_data bytea, p_signature bytea,
  p_display_name text, p_session_hash text, p_session_days integer)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog as $$
declare k app.buyer_keys%rowtype; n bigint; fp text; s record; why text;
begin
  if app.actor_kind() <> 'anon' or p_credential_id is null or octet_length(p_credential_id) not between 16 and 1023 then
    return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  select * into k from app.buyer_keys x where x.credential_id = p_credential_id for update;
  if not found then
    return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  n := app.buyer_webauthn('webauthn.get', p_client_data, p_auth_data);
  if n is null or not app.p256_verify(k.public_key, p_auth_data || sha256(p_client_data), p_signature) then
    perform app.audit_add('signin.failed', 'member', k.member_id, jsonb_build_object('lane', 'buyer', 'reason', 'bad_proof'), 'failure');
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  if app.signin_is_locked(k.member_id) then
    perform app.audit_add('signin.refused', 'member', k.member_id, jsonb_build_object('lane', 'buyer', 'reason', 'locked'), 'failure');
    return query select 'locked'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  -- A counter that went backwards may mean a copied key: Aaron is told, and the sign-in goes on.
  if n > 0 and k.sign_count > 0 and n <= k.sign_count then
    perform app.audit_add('buyer.counter_backwards', 'member', k.member_id, jsonb_build_object('stored', k.sign_count, 'sent', n), 'failure');
    perform app.notify(null, 'alert', 'A buyer key''s counter went backwards',
      'A buyer key signed in with a lower signature count than before, which can mean the key was copied. The sign-in went ahead (checks alert, never lock out). Look at the audit log for buyer.counter_backwards.',
      '/admin', 'system', null, 'watch:buyer-counter:' || k.id::text || ':' || n::text);
  end if;
  select i.fingerprint into fp from app.identities i where i.member_id = k.member_id and i.provider = 'buyer';
  if fp is null then
    return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end if;
  begin
    select * into s from app.sign_in_core('buyer', array[fp], 1::smallint, 1::smallint, p_display_name,
                                     p_session_hash, p_session_days, null::timestamptz, null::uuid, null::text);
  exception when sqlstate 'P0001' or sqlstate '22023' or sqlstate '23505' then
    why := app.signin_refusal(sqlstate, sqlerrm);
    if why is null then raise; end if;
    return query select why, null::uuid, null::boolean, null::smallint, null::boolean; return;
  end;
  update app.buyer_keys x set sign_count = greatest(x.sign_count, n), used_at = now() where x.id = k.id;
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin;
end $$;

-- ---- The scope: refused before the row exists, whoever writes it ----
-- One trigger function for every table a buyer can't be in; its argument names the column that holds the member.
create function app.buyer_scope() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
declare who uuid;
begin
  who := (to_jsonb(new) ->> tg_argv[0])::uuid;
  if who is not null and app.is_buyer(who) then
    raise exception 'buyer_scope' using errcode = 'P0001',
      hint = 'An account that signs in with a buyer key posts, funds, reviews and disputes tasks. It can''t do this; sign in with GitHub for the rest of the site.';
  end if;
  return new;
end $$;

-- A buyer key is a member's only method, and never added to anyone else.
create function app.buyer_identity_guard() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if new.provider = 'buyer' and exists (select 1 from app.identities i where i.member_id = new.member_id and i.id <> new.id) then
    raise exception 'buyer_scope' using errcode = 'P0001', hint = 'A buyer key opens its own account only.';
  end if;
  if new.provider <> 'buyer' and app.is_buyer(new.member_id) then
    raise exception 'buyer_scope' using errcode = 'P0001', hint = 'A buyer account signs in with its buyer key only.';
  end if;
  return new;
end $$;

-- A buyer stays at level 1 and is never administrator.
create function app.buyer_member_guard() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.is_buyer(new.id) then
    if new.is_admin then raise exception 'buyer_scope' using errcode = 'P0001', hint = 'A buyer account can''t be administrator.'; end if;
    if new.trust_level > 1 then new.trust_level := 1; end if;
  end if;
  return new;
end $$;

-- A buyer's new task waits for its bounty.
create function app.buyer_task_guard() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if tg_op = 'INSERT' then
    if new.status = 'open' and app.is_buyer(new.poster_member) then new.status := 'funding'; end if;
    return new;
  end if;
  if old.status = 'funding' and new.status is distinct from old.status and new.status <> all (array['open', 'removed', 'closed']) then
    raise exception 'a funding task opens, or is removed or closed' using errcode = '42501';
  end if;
  return new;
end $$;
reset role;
revoke create on schema app from dog_signin;

revoke execute on function app.is_buyer(uuid), app.buyer_webauthn(text, bytea, bytea),
  app.buyer_register(bytea, bytea, bytea, bytea, text, text, integer), app.buyer_key_public(bytea),
  app.buyer_sign_in(bytea, bytea, bytea, bytea, text, text, integer),
  app.buyer_scope(), app.buyer_identity_guard(), app.buyer_member_guard(), app.buyer_task_guard() from public;
grant execute on function app.buyer_register(bytea, bytea, bytea, bytea, text, text, integer), app.buyer_key_public(bytea),
  app.buyer_sign_in(bytea, bytea, bytea, bytea, text, text, integer) to dog_app;
-- The work role's policies below ask it.
grant execute on function app.is_buyer(uuid) to dog_work;

-- ---- The triggers (made as the tables' owner, with execute only while making them, as 056 does) ----
-- Named a_buyer_scope so each fires before a table's other triggers (Postgres runs them in name order) and a buyer is
-- told why in plain words, whatever else the row would have failed.
grant execute on function app.buyer_scope(), app.buyer_identity_guard(), app.buyer_member_guard(), app.buyer_task_guard() to dog_owner;
set local role dog_owner;
create trigger a_buyer_scope before insert or update of author_id on app.posts for each row execute function app.buyer_scope('author_id');
create trigger a_buyer_scope before insert or update of reporter_id on app.review_flags for each row execute function app.buyer_scope('reporter_id');
create trigger a_buyer_scope before insert or update of owner_id on app.agents for each row execute function app.buyer_scope('owner_id');
create trigger a_buyer_scope before insert or update of owner_id on app.agent_drafts for each row execute function app.buyer_scope('owner_id');
create trigger a_buyer_scope before insert or update of member_id on app.browser_keys for each row execute function app.buyer_scope('member_id');
create trigger a_buyer_scope before insert or update of member_id on app.file_keys for each row execute function app.buyer_scope('member_id');
create trigger a_buyer_scope before insert or update of member_id on app.signin_pins for each row execute function app.buyer_scope('member_id');
create trigger a_buyer_scope before insert or update of member_id on app.work_claims for each row execute function app.buyer_scope('member_id');
create trigger a_buyer_scope before insert or update of worker_member on app.work_submissions for each row execute function app.buyer_scope('worker_member');
create trigger a_buyer_scope before insert or update of citizen_member on app.work_points for each row execute function app.buyer_scope('citizen_member');
create trigger a_buyer_scope before insert or update of member_id on app.work_person_votes for each row execute function app.buyer_scope('member_id');
create trigger a_buyer_scope before insert or update of member_id on app.pay_accounts for each row execute function app.buyer_scope('member_id');
create trigger a_buyer_scope before insert or update of payee_member on app.work_bounties for each row execute function app.buyer_scope('payee_member');
create trigger a_buyer_scope before insert or update of created_by on app.engine_orders for each row execute function app.buyer_scope('created_by');
create trigger buyer_identity_guard before insert or update of provider, member_id on app.identities for each row execute function app.buyer_identity_guard();
create trigger buyer_member_guard before update of is_admin, trust_level on app.members for each row execute function app.buyer_member_guard();
create trigger buyer_task_guard before insert or update of status on app.work_tasks for each row execute function app.buyer_task_guard();

-- The funding gate: a task waiting for its bounty is seen only by its poster and the administrator, and a buyer's
-- project by others only once one of its tasks is open. Restrictive, so every work function (all run as dog_work)
-- keeps it, lists, counts and claims included.
create policy work_tasks_funding on app.work_tasks as restrictive for all to dog_work
  using (status <> 'funding' or poster_member = (select app.current_member()) or (select app.actor_kind()) = 'admin');
create policy work_projects_buyer on app.work_projects as restrictive for all to dog_work
  using (poster_member is null or poster_member = (select app.current_member()) or (select app.actor_kind()) = 'admin'
         or not app.is_buyer(poster_member)
         or exists (select 1 from app.work_tasks t where t.project_id = work_projects.id and t.status <> 'funding'));
reset role;
revoke execute on function app.buyer_scope(), app.buyer_identity_guard(), app.buyer_member_guard(), app.buyer_task_guard() from dog_owner;

-- ---- The payment role: a funded bounty opens its funding task; a funding task can be funded ----
grant create on schema app to dog_pay;
set local role dog_pay;
create or replace function app.bounty_fund_request(p_task uuid, p_cents integer)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  t record;
  b record;
  rid uuid;
begin
  if me is null or app.actor_kind() not in ('member', 'admin') then raise exception 'only a person signed in on the site funds a task or sets up payouts' using errcode = '42501'; end if;
  if p_task is null or p_cents is null or p_cents not between 1000 and 1000000 then raise exception 'a bounty is $10 to $10,000, in cents' using errcode = '22023'; end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.bounty'), hashtext(p_task::text));
  select x.id, x.status, x.poster_member into t from app.work_tasks x where x.id = p_task;
  if t.id is null then raise exception 'task' using errcode = 'P0002'; end if;
  if t.poster_member is distinct from me then raise exception 'only the task''s poster funds it' using errcode = '42501'; end if;
  -- 063: a buyer's task waits as "funding" until its bounty is paid.
  if t.status <> all (array['open', 'funding']) then raise exception 'work_pay_not_open' using errcode = 'P0001', hint = 'Only an open task can be funded.'; end if;
  select * into b from app.work_bounties where task_id = p_task;
  if b.id is not null and b.status <> 'failed' then raise exception 'work_pay_funded' using errcode = 'P0001', hint = 'This task is already funded, or its payment is under way.'; end if;
  if b.id is not null then update app.work_bounties set task_id = null where id = b.id; end if;
  insert into app.work_bounties (task_id, payer_member, bounty_cents) values (p_task, me, p_cents) returning id into b;
  insert into app.pay_requests (member_id, kind, bounty_id) values (me, 'fund_task', b.id) returning id into rid;
  return rid;
end
$$;

-- A funding task opens only when its bounty is funded (the money row, which the payment role reads).
create function app.buyer_task_open_guard() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if old.status = 'funding' and new.status = 'open'
     and not exists (select 1 from app.work_bounties b where b.task_id = new.id and b.status = 'funded') then
    raise exception 'a funding task opens only when its bounty is funded' using errcode = '42501';
  end if;
  return new;
end $$;

create function app.buyer_task_funded() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if new.status = 'funded' and old.status is distinct from 'funded' and new.task_id is not null then
    update app.work_tasks t set status = 'open', updated_at = now() where t.id = new.task_id and t.status = 'funding';
  end if;
  return new;
end $$;
reset role;
revoke create on schema app from dog_pay;
revoke execute on function app.buyer_task_funded(), app.buyer_task_open_guard() from public;
set local role dog_owner;
create policy work_tasks_pay_update on app.work_tasks for update to dog_pay using (status = 'funding') with check (status = 'open');
grant update (status, updated_at) on app.work_tasks to dog_pay;
reset role;
grant execute on function app.buyer_task_funded(), app.buyer_task_open_guard() to dog_owner;
set local role dog_owner;
create trigger buyer_task_funded after update of status on app.work_bounties for each row execute function app.buyer_task_funded();
create trigger buyer_task_open_guard before update of status on app.work_tasks for each row execute function app.buyer_task_open_guard();
reset role;
revoke execute on function app.buyer_task_funded(), app.buyer_task_open_guard() from dog_owner;
