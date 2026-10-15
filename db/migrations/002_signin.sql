-- 002 Sign-in and trust levels (Release 2, PR 2): identities, sessions, email links and rate limits.
-- Criteria: S5 no passwords and only hashed secrets, S6 rate limits on sign-up and sign-in, S12 we keep only which
-- provider verified someone, their level, the date and a fingerprint, F10 a banned account can't come back.
--
-- How sign-in reaches the database: the site's everyday role (dog_app) can't create members, read sessions or see
-- anyone's identities. A handful of narrow functions do those jobs. They run as their own role, dog_signin, which
-- has exactly the rights those jobs need and nothing else, and each takes and returns only what its job needs.
-- They are the only functions allowed to run with their owner's rights; the coverage check enforces that.
do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_signin') then
    create role dog_signin nologin noinherit nobypassrls;
  end if;
end
$roles$;
-- dog_owner may hand functions to dog_signin; dog_app may not become it.
grant dog_signin to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_signin;

-- Aaron is the only administrator, and only the database owner can make someone one (db/README.md says how).
alter table app.members add column is_admin boolean not null default false;
create policy members_owner_select on app.members for select to dog_owner using (true);
create policy members_owner_update on app.members for update to dog_owner using (true) with check (true);

-- Who signed in with what. The provider's account ID is never stored: only a keyed fingerprint (HMAC-SHA256 with a
-- server key kept outside the database), with the key's version so keys can be rotated on each person's next sign-in.
create table app.identities (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id),
  provider text not null check (provider = any (array['github', 'x', 'email', 'linkedin'])),
  fingerprint text not null check (char_length(fingerprint) = 64 and fingerprint ~ '^[0-9a-f]+$'),
  key_version smallint not null check (key_version between 1 and 999),
  level smallint not null check (level between 0 and 2),
  verified_at timestamptz not null default now(),
  recheck_after timestamptz,
  created_at timestamptz not null default now(),
  unique (provider, fingerprint)
);
create index identities_member on app.identities (member_id);
alter table app.identities enable row level security;
alter table app.identities force row level security;

-- Signed-in sessions. Only a SHA-256 of the cookie's token is kept, so a copy of this table signs nobody in.
create table app.sessions (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id),
  token_hash text not null unique check (char_length(token_hash) = 64 and token_hash ~ '^[0-9a-f]+$'),
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index sessions_member on app.sessions (member_id);
alter table app.sessions enable row level security;
alter table app.sessions force row level security;

-- Email sign-in links: single use, 15 minutes. The address itself is never stored, only its fingerprint.
create table app.email_tokens (
  id uuid primary key default app.uuid_v7(),
  token_hash text not null unique check (char_length(token_hash) = 64 and token_hash ~ '^[0-9a-f]+$'),
  email_fingerprint text not null check (char_length(email_fingerprint) = 64 and email_fingerprint ~ '^[0-9a-f]+$'),
  key_version smallint not null check (key_version between 1 and 999),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz
);
alter table app.email_tokens enable row level security;
alter table app.email_tokens force row level security;

-- Counters for rate limits (S6). Keys are keyed hashes of an IP range or an email fingerprint, never raw values.
create table app.rate_limits (
  id uuid primary key default app.uuid_v7(),
  bucket text not null check (char_length(bucket) <= 32 and bucket ~ '^[a-z_]+$'),
  key_hash text not null check (char_length(key_hash) = 64 and key_hash ~ '^[0-9a-f]+$'),
  window_start timestamptz not null,
  hits integer not null default 0 check (hits >= 0),
  unique (bucket, key_hash, window_start)
);
alter table app.rate_limits enable row level security;
alter table app.rate_limits force row level security;

-- ---- What dog_signin may do (it acts only inside the functions below) ----
create policy members_signin_select on app.members for select to dog_signin using (true);
create policy members_signin_insert on app.members for insert to dog_signin with check (is_admin = false);
create policy members_signin_update on app.members for update to dog_signin using (true) with check (true);
grant select on app.members to dog_signin;
grant insert (display_name, trust_level) on app.members to dog_signin;
grant update (trust_level) on app.members to dog_signin;

create policy identities_signin_select on app.identities for select to dog_signin using (true);
create policy identities_signin_insert on app.identities for insert to dog_signin with check (true);
create policy identities_signin_update on app.identities for update to dog_signin using (true) with check (true);
grant select on app.identities to dog_signin;
grant insert (member_id, provider, fingerprint, key_version, level, recheck_after) on app.identities to dog_signin;
grant update (fingerprint, key_version, level, verified_at, recheck_after) on app.identities to dog_signin;

create policy sessions_signin_select on app.sessions for select to dog_signin using (true);
create policy sessions_signin_insert on app.sessions for insert to dog_signin with check (true);
create policy sessions_signin_update on app.sessions for update to dog_signin using (true) with check (true);
create policy sessions_signin_delete on app.sessions for delete to dog_signin using (true);
grant select, delete on app.sessions to dog_signin;
grant insert (member_id, token_hash, expires_at) on app.sessions to dog_signin;
grant update (last_seen_at) on app.sessions to dog_signin;

create policy email_tokens_signin_select on app.email_tokens for select to dog_signin using (true);
create policy email_tokens_signin_insert on app.email_tokens for insert to dog_signin with check (true);
create policy email_tokens_signin_update on app.email_tokens for update to dog_signin using (true) with check (true);
create policy email_tokens_signin_delete on app.email_tokens for delete to dog_signin using (true);
grant select, delete on app.email_tokens to dog_signin;
grant insert (token_hash, email_fingerprint, key_version, expires_at) on app.email_tokens to dog_signin;
grant update (used_at) on app.email_tokens to dog_signin;

create policy rate_limits_signin_select on app.rate_limits for select to dog_signin using (true);
create policy rate_limits_signin_insert on app.rate_limits for insert to dog_signin with check (true);
create policy rate_limits_signin_update on app.rate_limits for update to dog_signin using (true) with check (true);
create policy rate_limits_signin_delete on app.rate_limits for delete to dog_signin using (true);
grant select, delete on app.rate_limits to dog_signin;
grant insert (bucket, key_hash, window_start, hits) on app.rate_limits to dog_signin;
grant update (hits) on app.rate_limits to dog_signin;

-- Audit rows written during sign-in name the real actor (usually someone not yet signed in), as for dog_app.
create policy audit_insert_signin on app.audit_log for insert to dog_signin
  with check (actor_kind = app.actor_kind() and actor_id is not distinct from app.current_actor_id());
grant insert (action, subject_kind, subject_id, detail) on app.audit_log to dog_signin;
grant execute on function app.uuid_v7(), app.actor_kind(), app.current_member(), app.current_agent(),
  app.current_actor_id() to dog_signin;

-- ---- What a member may see and do about their own sign-in (as dog_app) ----
create policy identities_select on app.identities for select to dog_app
  using ((app.actor_kind() = 'member' and member_id = app.current_member()) or app.actor_kind() = 'admin');
grant select (id, member_id, provider, level, verified_at, created_at) on app.identities to dog_app;
create policy sessions_select on app.sessions for select to dog_app
  using (app.actor_kind() = 'member' and member_id = app.current_member());
create policy sessions_delete on app.sessions for delete to dog_app
  using (app.actor_kind() = 'member' and member_id = app.current_member());
grant select (id, member_id, created_at, last_seen_at, expires_at), delete on app.sessions to dog_app;

-- The member guard also lets the sign-in role raise a level it has just verified.
create or replace function app.members_guard() returns trigger
language plpgsql
as $$
begin
  if (new.trust_level is distinct from old.trust_level or new.status is distinct from old.status)
     and app.actor_kind() not in ('admin', 'system') and current_user <> 'dog_signin' then
    raise exception 'only an administrator can change trust level or status' using errcode = '42501';
  end if;
  if new.is_admin is distinct from old.is_admin and current_user <> 'dog_owner' then
    raise exception 'only the database owner can change administrator rights' using errcode = '42501';
  end if;
  return new;
end
$$;

-- ---- The sign-in functions ----
-- Each one: runs as dog_signin, fixed search path, inputs checked again here even though the site checks them first.
create function app.rate_limit_hit(p_bucket text, p_key_hash text, p_window_seconds integer, p_max integer)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w timestamptz;
  n integer;
begin
  if p_bucket !~ '^[a-z_]{1,32}$' or p_key_hash !~ '^[0-9a-f]{64}$' or p_window_seconds not between 1 and 86400
     or p_max not between 1 and 100000 then
    raise exception 'bad rate limit request' using errcode = '22023';
  end if;
  w := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
  insert into app.rate_limits (bucket, key_hash, window_start, hits) values (p_bucket, p_key_hash, w, 1)
    on conflict (bucket, key_hash, window_start) do update set hits = app.rate_limits.hits + 1
    returning hits into n;
  -- Old windows are cleared now and then, so an attack can't grow the table without end.
  if random() < 0.01 then
    delete from app.rate_limits where window_start < now() - interval '2 days';
  end if;
  return n <= p_max;
end
$$;

create function app.email_token_issue(p_token_hash text, p_email_fingerprint text, p_key_version smallint)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' or p_email_fingerprint !~ '^[0-9a-f]{64}$' then
    raise exception 'bad email link request' using errcode = '22023';
  end if;
  insert into app.email_tokens (token_hash, email_fingerprint, key_version, expires_at)
    values (p_token_hash, p_email_fingerprint, p_key_version, now() + interval '15 minutes');
  if random() < 0.05 then
    delete from app.email_tokens where expires_at < now() - interval '1 day';
  end if;
end
$$;

-- Uses up a link and says which email fingerprint it was for, or nothing if it's unknown, used or expired.
create function app.email_token_redeem(p_token_hash text)
returns table (email_fingerprint text, key_version smallint)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query
    update app.email_tokens t set used_at = now()
    where t.token_hash = p_token_hash and t.used_at is null and t.expires_at > now()
    returning t.email_fingerprint, t.key_version;
end
$$;

-- Signs someone in with a verified identity and records a new session.
--   p_fingerprints: this account's fingerprint under each key still in use, current key first.
--   p_link_member: set only when a signed-in member is adding another sign-in method; never set from an email match.
-- Returns the member, or raises 'banned' or 'taken' (the identity already belongs to someone else).
create function app.sign_in(p_provider text, p_fingerprints text[], p_key_version smallint, p_level smallint,
                            p_display_name text, p_session_hash text, p_session_days integer,
                            p_recheck_after timestamptz, p_link_member uuid)
returns table (member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  ident app.identities%rowtype;
  mem app.members%rowtype;
  fresh boolean := false;
begin
  if p_provider is null or not (p_provider = any (array['github', 'x', 'email', 'linkedin']))
     or p_fingerprints is null or cardinality(p_fingerprints) not between 1 and 5
     or exists (select 1 from unnest(p_fingerprints) f where f !~ '^[0-9a-f]{64}$')
     or p_level not between 0 and 2 or p_session_hash !~ '^[0-9a-f]{64}$' or p_session_days not between 1 and 30
     or p_display_name is null or char_length(p_display_name) not between 1 and 80 then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;

  select * into ident from app.identities i where i.provider = p_provider and i.fingerprint = any (p_fingerprints)
    order by i.created_at limit 1 for update;

  if found then
    select * into mem from app.members m where m.id = ident.member_id for update;
    if p_link_member is not null and p_link_member <> mem.id then
      raise exception 'taken' using errcode = 'P0001';
    end if;
    -- Moves the fingerprint to the current key the first time someone signs in after a rotation.
    update app.identities i set fingerprint = p_fingerprints[1], key_version = p_key_version, level = p_level,
                                verified_at = now(), recheck_after = p_recheck_after
      where i.id = ident.id;
  elsif p_link_member is not null then
    select * into mem from app.members m where m.id = p_link_member for update;
    if not found then
      raise exception 'bad sign-in request' using errcode = '22023';
    end if;
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (mem.id, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after);
  else
    insert into app.members (display_name, trust_level) values (p_display_name, p_level) returning * into mem;
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (mem.id, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after);
    fresh := true;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.joined', 'member', mem.id, jsonb_build_object('provider', p_provider, 'level', p_level));
  end if;

  if mem.status = 'banned' then
    raise exception 'banned' using errcode = 'P0001';
  end if;

  -- The member's level is the highest any of their sign-in methods has verified. It never drops on its own here;
  -- a lapsed level 2 is handled when it is rechecked.
  if p_level > mem.trust_level then
    update app.members m set trust_level = p_level where m.id = mem.id;
    mem.trust_level := p_level;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_raised', 'member', mem.id, jsonb_build_object('provider', p_provider, 'level', p_level));
  end if;

  insert into app.sessions (member_id, token_hash, expires_at)
    values (mem.id, p_session_hash, now() + make_interval(days => p_session_days));
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values (case when p_link_member is not null then 'member.identity_linked' else 'member.signed_in' end,
            'member', mem.id, jsonb_build_object('provider', p_provider));

  return query select mem.id, fresh, mem.trust_level, mem.is_admin;
end
$$;

-- Who a session cookie belongs to. Returns nothing for an unknown, expired or idle session, or a banned member.
-- Sessions last at most p_absolute days and end after p_idle days unused.
create function app.session_resolve(p_session_hash text, p_idle_days integer)
returns table (member_id uuid, trust_level smallint, is_admin boolean, display_name text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s app.sessions%rowtype;
begin
  if p_session_hash !~ '^[0-9a-f]{64}$' or p_idle_days not between 1 and 30 then
    return;
  end if;
  select * into s from app.sessions x where x.token_hash = p_session_hash;
  if not found or s.expires_at <= now() or s.last_seen_at <= now() - make_interval(days => p_idle_days) then
    return;
  end if;
  -- Written at most once an hour, so reading pages doesn't turn into a write on every request.
  if s.last_seen_at < now() - interval '1 hour' then
    update app.sessions x set last_seen_at = now() where x.id = s.id;
  end if;
  return query select m.id, m.trust_level, m.is_admin, m.display_name
    from app.members m where m.id = s.member_id and m.status = 'active';
end
$$;

create function app.session_end(p_session_hash text)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_session_hash ~ '^[0-9a-f]{64}$' then
    delete from app.sessions where token_hash = p_session_hash;
  end if;
end
$$;

-- Only the site's role may call them; set before handing them over, while dog_owner can still grant.
revoke execute on function app.rate_limit_hit(text, text, integer, integer), app.email_token_issue(text, text, smallint),
  app.email_token_redeem(text), app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid),
  app.session_resolve(text, integer), app.session_end(text) from public;
grant execute on function app.rate_limit_hit(text, text, integer, integer), app.email_token_issue(text, text, smallint),
  app.email_token_redeem(text), app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid),
  app.session_resolve(text, integer), app.session_end(text) to dog_app;

-- Hands the functions to dog_signin, so they run with its narrow rights rather than the owner's. Postgres only
-- hands a function to a role that may create objects in its schema, so dog_signin has that right for these lines only.
grant create on schema app to dog_signin;
alter function app.rate_limit_hit(text, text, integer, integer) owner to dog_signin;
alter function app.email_token_issue(text, text, smallint) owner to dog_signin;
alter function app.email_token_redeem(text) owner to dog_signin;
alter function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid) owner to dog_signin;
alter function app.session_resolve(text, integer) owner to dog_signin;
alter function app.session_end(text) owner to dog_signin;
revoke create on schema app from dog_signin;
