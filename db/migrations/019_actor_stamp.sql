-- 019 The database decides who is acting (harness/PLAN.md fix 3; Oct 26, 2026).
--   Until now the site said who was acting by setting app.actor, app.member_id, app.agent_id and app.fresh at the start
--   of each transaction (db/index.js), and app.actor_kind() believed them. Postgres lets any login set those settings,
--   so anyone holding the site's database login could act as Aaron. Now the site can only ask, with proof:
--     * a person: their session (by its hash); the database looks the session up itself, and decides from it whether
--       they are Aaron and whether they signed in within the last 10 minutes ("fresh");
--     * an agent: its key (by its hash), looked up the same way;
--     * the site itself ("system", the timers): the site's own secret, checked against its hash (empty until the setup
--       run stores it, fix 8; until then nothing can act as the site itself).
--   app.act_as checks the proof, sets the settings and adds a stamp: a SHA-256 over a key the site's role can never read
--   (only the sign-in and owner roles can), the settings, and the transaction's ID. Everything that asks who is acting checks the stamp, so a
--   setting the site edits, invents or copies from another transaction counts as nobody (an anonymous visitor).
--   The prototype (test/prototypes/actor-stamp.js) ran the same design on Oct 25: 10 of 10 checks.
set local role dog_owner;

-- ---- The keys: the stamp key (made here, never leaves the database) and the hash of the site's own secret ----
-- One row only: "singleton" is unique and must be true. (A check passes when system_hash is empty, until it is set.)
create table app.actor_keys (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  stamp_key bytea not null check (octet_length(stamp_key) = 32),
  system_hash bytea check (octet_length(system_hash) = 32)
);
alter table app.actor_keys enable row level security;
alter table app.actor_keys force row level security;
create policy actor_keys_signin on app.actor_keys for select to dog_signin using (true);
-- The owner makes the row here and, in the setup run (fix 8), stores the hash of the site's own secret.
create policy actor_keys_owner_select on app.actor_keys for select to dog_owner using (true);
create policy actor_keys_owner_insert on app.actor_keys for insert to dog_owner with check (true);
create policy actor_keys_owner_update on app.actor_keys for update to dog_owner using (true) with check (true);
grant select on app.actor_keys to dog_signin;
-- 32 random bytes from two random UUIDs (244 random bits), with Postgres's own generator: no extension needed.
insert into app.actor_keys (stamp_key)
  values (decode(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'hex'));

-- The stamp for these settings in this transaction. Only the sign-in role (and the owner, for set_administrator) may
-- make one; the site's role never can.
create function app.actor_stamp(p_actor text, p_member text, p_agent text, p_fresh text, p_session text) returns text
language sql stable security definer set search_path = pg_catalog as $$
  select encode(sha256(k.stamp_key || convert_to(coalesce(p_actor, '') || '|' || coalesce(p_member, '') || '|' ||
    coalesce(p_agent, '') || '|' || coalesce(p_fresh, '') || '|' || coalesce(p_session, '') || '|' || txid_current()::text, 'UTF8')
    || k.stamp_key), 'hex')
  from app.actor_keys k where k.singleton
$$;

-- Whether the settings carry this transaction's stamp. Asked by every check of who is acting.
create function app.stamp_ok() returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce(current_setting('app.stamp', true), '') <> ''
     and current_setting('app.stamp', true) = app.actor_stamp(current_setting('app.actor', true), current_setting('app.member_id', true),
           current_setting('app.agent_id', true), current_setting('app.fresh', true), current_setting('app.session', true))
$$;

-- The only way to act as someone. Raises 'not_acting' (42501) when the proof doesn't match the claim, so a mistake in
-- the site fails loudly instead of acting as someone else. Returns the actor granted.
--   p_idle_days: how long an unused session lasts (signin/config.js IDLE_DAYS; a test keeps the two the same).
create function app.act_as(p_actor text, p_member uuid, p_agent uuid, p_fresh boolean, p_session text, p_key text, p_system text)
returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  a text := 'anon'; m text := ''; ag text := ''; f text := ''; s text := '';
  sm uuid; sadmin boolean; sfresh boolean; km uuid; ka uuid;
begin
  if p_actor in ('member', 'admin') then
    select r.member_id, r.is_admin, r.fresh into sm, sadmin, sfresh from app.session_resolve(p_session, 7) r;
    if sm is null or sm is distinct from p_member or (p_actor = 'admin' and not sadmin) then
      raise exception 'not_acting' using errcode = '42501';
    end if;
    a := p_actor; m := sm::text; s := p_session; f := case when p_fresh and sfresh then '1' else '' end;
  elsif p_actor = 'agent' then
    select r.agent_id, r.owner_id into ka, km from app.agent_resolve(p_key) r;
    if ka is null or ka is distinct from p_agent or km is distinct from p_member then
      raise exception 'not_acting' using errcode = '42501';
    end if;
    a := 'agent'; m := km::text; ag := ka::text;
  elsif p_actor = 'system' then
    if p_system is null or p_system = '' or not exists (select 1 from app.actor_keys k
         where k.singleton and k.system_hash is not null and k.system_hash = sha256(convert_to(p_system, 'UTF8'))) then
      raise exception 'not_acting' using errcode = '42501';
    end if;
    a := 'system';
  elsif p_actor is distinct from 'anon' then
    raise exception 'not_acting' using errcode = '42501';
  end if;
  perform set_config('app.actor', a, true), set_config('app.member_id', m, true), set_config('app.agent_id', ag, true),
          set_config('app.fresh', f, true), set_config('app.session', s, true);
  perform set_config('app.stamp', case when a = 'anon' then '' else app.actor_stamp(a, m, ag, f, s) end, true);
  return a;
end
$$;

-- ---- Everything that asks who is acting checks the stamp first ----
-- No longer "parallel safe": the stamp is bound to the transaction's ID, which a parallel worker can't take.
create or replace function app.actor_kind() returns text
language sql stable parallel unsafe
as $$ select case when app.stamp_ok() then coalesce(nullif(current_setting('app.actor', true), ''), 'anon') else 'anon' end $$;

create or replace function app.current_member() returns uuid
language sql stable parallel unsafe
as $$ select case when app.stamp_ok() then nullif(current_setting('app.member_id', true), '')::uuid end $$;

create or replace function app.current_agent() returns uuid
language sql stable parallel unsafe
as $$ select case when app.stamp_ok() then nullif(current_setting('app.agent_id', true), '')::uuid end $$;

-- The setup run's administrator step (013) acts as the site itself: it now stamps that, as the database owner.
create or replace function app.set_administrator(p_member uuid)
returns text
language plpgsql set search_path = pg_catalog
as $$
declare
  other uuid;
  n integer;
begin
  if p_member is null then raise exception 'member required' using errcode = '22023'; end if;
  perform set_config('app.actor', 'system', true), set_config('app.member_id', '', true), set_config('app.agent_id', '', true),
          set_config('app.fresh', '', true), set_config('app.session', '', true);
  perform set_config('app.stamp', app.actor_stamp('system', '', '', '', ''), true);
  if exists (select 1 from app.members where id = p_member and is_admin) then return 'already'; end if;
  select id into other from app.members where is_admin limit 1;
  if other is not null then
    raise exception 'another member is already the administrator (%); nothing changed', other using errcode = '23505';
  end if;
  update app.members set is_admin = true where id = p_member and status = 'active';
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'no active member with that ID; nothing changed' using errcode = '02000'; end if;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('admin.set', 'member', p_member, jsonb_build_object('by', 'production setup run'));
  return 'set';
end
$$;

-- ---- Who may call what ----
revoke execute on function app.actor_stamp(text, text, text, text, text), app.stamp_ok(),
  app.act_as(text, uuid, uuid, boolean, text, text, text) from public;
-- Checking a stamp: every role that runs checks of who is acting (dog_owner's grant comes after the handover below).
grant execute on function app.stamp_ok() to dog_app, dog_public, dog_limits, dog_erase, dog_delegate, dog_jevs;
-- Acting as someone, with proof: the site's role only.
grant execute on function app.act_as(text, uuid, uuid, boolean, text, text, text) to dog_app;

-- Hands the three functions to the sign-in role, which alone reads the keys, sessions and agent keys. Postgres only
-- hands a function to a role that may create objects in its schema, so dog_signin has that right for these lines only.
grant create on schema app to dog_signin;
alter function app.actor_stamp(text, text, text, text, text) owner to dog_signin;
alter function app.stamp_ok() owner to dog_signin;
alter function app.act_as(text, uuid, uuid, boolean, text, text, text) owner to dog_signin;
revoke create on schema app from dog_signin;
-- The owner's own grants: made by the new owner, since Postgres folds a grant to the old owner into the new owner's
-- when ownership moves. dog_owner may act as dog_signin (002), and returns to itself straight after.
--   The stamp itself: only the owner, for set_administrator. Checking one: the owner too.
set local role dog_signin;
grant execute on function app.actor_stamp(text, text, text, text, text), app.stamp_ok() to dog_owner;
set local role dog_owner;
