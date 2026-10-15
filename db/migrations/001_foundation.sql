-- 001 Foundation (Release 2, PR 1): roles, the app schema, time-ordered IDs, members and the audit log.
-- Criteria: S1 row-level security forced on every table, S7/G4 append-only audit log, S8 size limits in the
-- database as well as the code, G3 time-ordered unique IDs instead of counters.
-- Runs once, inside one transaction, through scripts/migrate.js. Plain Postgres 15+, so it works on Supabase or Neon.

-- Roles. Neither can sign in; a login role is granted one of them and switches to it.
--   dog_owner owns every object. Only migrations act as it.
--   dog_app is what the site's functions act as for every request. It can't bypass row-level security,
--   doesn't own anything, and can't create objects, so it can't switch off a policy or a trigger.
do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_owner') then
    create role dog_owner nologin noinherit nobypassrls;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'dog_app') then
    create role dog_app nologin noinherit nobypassrls;
  end if;
end
$roles$;
grant dog_owner to current_user;

-- Our own schema, not "public", so a provider's automatic web API (Supabase exposes "public") never sees our tables.
create schema app authorization dog_owner;
revoke all on schema app from public;
grant usage on schema app to dog_app;

set local role dog_owner;

-- Time-ordered unique IDs (UUIDv7, RFC 9562): 48 bits of milliseconds then random bits. They sort by creation
-- time and never collide across databases, so tables can be split later (G3). Postgres 18 has uuidv7() built in;
-- this version runs on 15 to 17.
create function app.uuid_v7() returns uuid
language sql volatile parallel safe
as $$
  select encode(
    set_bit(set_bit(
      overlay(uuid_send(gen_random_uuid())
        placing substring(int8send(floor(extract(epoch from clock_timestamp()) * 1000)::bigint) from 3)
        from 1 for 6),
      52, 1), 53, 1),
    'hex')::uuid
$$;

-- Who is acting. The site's functions set these at the start of every transaction (db/index.js); they end with
-- the transaction, so nothing carries over to the next request on a pooled connection.
--   app.actor: anon (not signed in), member, agent, admin (Aaron), system (the site itself, e.g. during sign-up)
create function app.actor_kind() returns text
language sql stable parallel safe
as $$ select coalesce(nullif(current_setting('app.actor', true), ''), 'anon') $$;

create function app.current_member() returns uuid
language sql stable parallel safe
as $$ select nullif(current_setting('app.member_id', true), '')::uuid $$;

create function app.current_agent() returns uuid
language sql stable parallel safe
as $$ select nullif(current_setting('app.agent_id', true), '')::uuid $$;

-- The ID an audit row must carry for the current actor: the agent for agents, the member for members and Aaron,
-- nothing for the site itself or someone not signed in.
create function app.current_actor_id() returns uuid
language sql stable parallel safe
as $$
  select case app.actor_kind()
    when 'agent' then app.current_agent()
    when 'member' then app.current_member()
    when 'admin' then app.current_member()
    else null
  end
$$;

-- Bookkeeping for scripts/migrate.js. It is a table, so S1 applies to it too.
create table app.schema_migrations (
  version text primary key check (char_length(version) <= 64),
  sha256 text not null check (char_length(sha256) = 64),
  applied_at timestamptz not null default now()
);
alter table app.schema_migrations enable row level security;
alter table app.schema_migrations force row level security;
create policy migrations_owner_only on app.schema_migrations for all to dog_owner using (true) with check (true);

-- Members. Sign-in identities, agents and posts arrive in later pull requests and point here.
create table app.members (
  id uuid primary key default app.uuid_v7(),
  created_at timestamptz not null default now(),
  display_name text not null check (char_length(display_name) between 1 and 80),
  trust_level smallint not null default 0 check (trust_level between 0 and 3),
  status text not null default 'active' check (status = any (array['active', 'banned']))
);
alter table app.members enable row level security;
alter table app.members force row level security;

-- One policy per action, each with its whole rule, so adding a policy later can't quietly widen another.
-- A member sees and edits only their own row; Aaron sees and edits all; only the site itself creates members.
create policy members_select on app.members for select to dog_app
  using (id = app.current_member() or app.actor_kind() in ('admin', 'system'));
create policy members_insert on app.members for insert to dog_app
  with check (app.actor_kind() = 'system');
create policy members_update on app.members for update to dog_app
  using (id = app.current_member() or app.actor_kind() = 'admin')
  with check (id = app.current_member() or app.actor_kind() = 'admin');

grant select, insert on app.members to dog_app;
grant update (display_name, trust_level, status) on app.members to dog_app;
-- No delete yet: deleting an account (F8) arrives with its own rules in PR 7.

-- Members may rename themselves, but only Aaron or the site can change a trust level or ban status.
create function app.members_guard() returns trigger
language plpgsql
as $$
begin
  if (new.trust_level is distinct from old.trust_level or new.status is distinct from old.status)
     and app.actor_kind() not in ('admin', 'system') then
    raise exception 'only an administrator can change trust level or status' using errcode = '42501';
  end if;
  return new;
end
$$;
create trigger members_guard before update on app.members
  for each row execute function app.members_guard();

-- The audit log (S7, G4). Rows can be added and Aaron can read them; nobody can change or remove one.
-- No foreign keys: the record of what happened has to outlive a deleted account.
create table app.audit_log (
  id uuid primary key default app.uuid_v7(),
  at timestamptz not null default now(),
  actor_kind text not null default app.actor_kind()
    check (actor_kind = any (array['anon', 'member', 'agent', 'admin', 'system'])),
  actor_id uuid default app.current_actor_id(),
  action text not null check (char_length(action) <= 64 and action ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$'),
  subject_kind text check (char_length(subject_kind) <= 32 and subject_kind ~ '^[a-z][a-z_]*$'),
  subject_id uuid,
  detail jsonb not null default '{}'::jsonb
    check (jsonb_typeof(detail) = 'object' and octet_length(detail::text) <= 4096)
);
alter table app.audit_log enable row level security;
alter table app.audit_log force row level security;

-- An audit row always names who is really acting: nobody can write one in someone else's name.
create policy audit_insert on app.audit_log for insert to dog_app
  with check (actor_kind = app.actor_kind() and actor_id is not distinct from app.current_actor_id());
create policy audit_select on app.audit_log for select to dog_app
  using (app.actor_kind() = 'admin');

grant select, insert on app.audit_log to dog_app;

-- The second lock: even a role holding update or delete rights, a superuser included, is stopped by these
-- triggers. They run once per statement, so an attempt fails even when it matches no rows. Only the owner could
-- remove them, and the site never acts as the owner.
create function app.audit_log_append_only() returns trigger
language plpgsql
as $$
begin
  raise exception 'the audit log is append-only' using errcode = '42501';
end
$$;
create trigger audit_log_no_change before update or delete on app.audit_log
  for each statement execute function app.audit_log_append_only();
create trigger audit_log_no_truncate before truncate on app.audit_log
  for each statement execute function app.audit_log_append_only();

-- Functions: only the site's role may call them (they are also unreachable without the schema's usage right).
revoke execute on all functions in schema app from public;
grant execute on function app.uuid_v7(), app.actor_kind(), app.current_member(), app.current_agent(),
  app.current_actor_id() to dog_app;
