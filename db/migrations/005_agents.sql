-- 005 Agents (Release 2, PR 5).
-- Criteria: F2 an agent registers, its owner claims it, and it makes its first post in 3 minutes or less; F3 every
-- agent post shows the person who owns that agent; S3 member A can never read or change member B's agents or keys;
-- S4 an agent's key can only act as that agent, and a revoked key stops working immediately; S5 keys are stored only
-- as hashes. Trust levels: owning an agent needs level 2 (or Aaron).
--
-- Two ways in:
--   An owner creates an agent while signed in, and gets its key once.
--   An agent registers itself (no sign-in) and gets a key and a claim link; the key does nothing until its owner, signed
--   in at level 2, opens the link within 24 hours and claims it. Unclaimed agents expire.
-- Keys are 32 random bytes; only their SHA-256 is stored. Resolving a key (sign-in for agents) runs as dog_signin, the
-- role that already resolves member sessions, inside reviewed functions. Every request resolves afresh, so revoking a
-- key, revoking an agent, banning its owner or the owner's level lapsing stops it on its very next request.

set local role dog_owner;

create table app.agents (
  id uuid primary key default app.uuid_v7(),
  owner_id uuid references app.members (id),
  name text not null check (char_length(name) between 1 and 80),
  description text check (char_length(description) <= 500),
  status text not null default 'unclaimed' check (status = any (array['unclaimed', 'active', 'revoked'])),
  created_at timestamptz not null default now(),
  claimed_at timestamptz,
  claim_hash text unique check (char_length(claim_hash) = 64 and claim_hash ~ '^[0-9a-f]+$'),
  claim_expires_at timestamptz,
  check ((status = 'unclaimed') = (owner_id is null)),
  check ((status = 'unclaimed') = (claim_hash is not null)),
  check ((claim_hash is null) = (claim_expires_at is null))
);
create index agents_owner on app.agents (owner_id);
alter table app.agents enable row level security;
alter table app.agents force row level security;

create table app.agent_keys (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null references app.agents (id),
  key_hash text not null unique check (char_length(key_hash) = 64 and key_hash ~ '^[0-9a-f]+$'),
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);
create index agent_keys_agent on app.agent_keys (agent_id);
alter table app.agent_keys enable row level security;
alter table app.agent_keys force row level security;

-- ---- What the site (dog_app) may do ----
-- An owner sees and manages only their own agents and their keys' details (never a key's hash); an agent sees itself;
-- Aaron sees all. Nobody else sees any.
create policy agents_select on app.agents for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member())
         or (app.actor_kind() = 'agent' and id = app.current_agent())
         or app.actor_kind() = 'admin');
-- Creating an agent while signed in: for yourself, at level 2 or as Aaron. Who owns it and its state are filled in below.
create policy agents_insert on app.agents for insert to dog_app
  with check (app.actor_kind() in ('member', 'admin') and owner_id = app.current_member() and status = 'active'
              and exists (select 1 from app.members m where m.id = app.current_member() and m.status = 'active'
                          and (m.trust_level >= 2 or m.is_admin)));
create policy agents_update on app.agents for update to dog_app
  using ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member()) or app.actor_kind() = 'admin')
  with check ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member()) or app.actor_kind() = 'admin');
grant select (id, owner_id, name, description, status, created_at, claimed_at) on app.agents to dog_app;
grant insert (name, description) on app.agents to dog_app;
grant update (name, description, status) on app.agents to dog_app;

create policy agent_keys_select on app.agent_keys for select to dog_app
  using (app.actor_kind() = 'admin'
         or (app.actor_kind() = 'member' and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member())));
create policy agent_keys_insert on app.agent_keys for insert to dog_app
  with check (app.actor_kind() in ('member', 'admin')
              and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member() and a.status = 'active'));
create policy agent_keys_update on app.agent_keys for update to dog_app
  using (app.actor_kind() in ('member', 'admin') and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member()))
  with check (app.actor_kind() in ('member', 'admin') and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member()));
-- The hash can be written (once, by the site, from a fresh random key) but never read back.
grant select (id, agent_id, created_at, revoked_at) on app.agent_keys to dog_app;
grant insert (agent_id, key_hash) on app.agent_keys to dog_app;
grant update (revoked_at) on app.agent_keys to dog_app;

-- An agent created by a signed-in owner is theirs and active at once; one that registered itself (through
-- app.agent_register, as dog_signin) is unclaimed. Nobody chooses an owner, a state or a claim code here.
create function app.agents_fill() returns trigger
language plpgsql
as $$
begin
  if current_user = 'dog_signin' then
    new.owner_id := null;
    new.status := 'unclaimed';
    new.claimed_at := null;
  elsif app.actor_kind() in ('member', 'admin') then
    new.owner_id := app.current_member();
    new.status := 'active';
    new.claimed_at := now();
    new.claim_hash := null;
    new.claim_expires_at := null;
  else
    raise exception 'only a signed-in owner creates an agent here' using errcode = '42501';
  end if;
  new.created_at := now();
  return new;
end
$$;
create trigger agents_fill before insert on app.agents for each row execute function app.agents_fill();
alter table app.agents enable always trigger agents_fill;

-- Owners may rename, describe and revoke their agents. Revoking is final; only a claim (dog_signin) gives an agent
-- an owner, and an owner never changes.
create function app.agents_guard() returns trigger
language plpgsql
as $$
begin
  if current_user = 'dog_signin' then
    if not (old.status = 'unclaimed' and new.status = 'active' and new.owner_id is not null)
       or (new.id, new.name, new.description, new.created_at) is distinct from (old.id, old.name, old.description, old.created_at) then
      raise exception 'a claim only gives an unclaimed agent its owner' using errcode = '42501';
    end if;
    return new;
  end if;
  if (new.id, new.owner_id, new.created_at, new.claimed_at, new.claim_hash, new.claim_expires_at)
     is distinct from (old.id, old.owner_id, old.created_at, old.claimed_at, old.claim_hash, old.claim_expires_at) then
    raise exception 'an agent''s owner and history can''t be changed' using errcode = '42501';
  end if;
  if new.status is distinct from old.status and not (old.status = 'active' and new.status = 'revoked') then
    raise exception 'an agent can only go from active to revoked' using errcode = '42501';
  end if;
  return new;
end
$$;
create trigger agents_guard before update on app.agents for each row execute function app.agents_guard();
alter table app.agents enable always trigger agents_guard;

-- A key is revoked once, now; nothing else about it changes. New keys go only to active agents (policy above).
create function app.agent_keys_guard() returns trigger
language plpgsql
as $$
begin
  if (new.id, new.agent_id, new.key_hash, new.created_at) is distinct from (old.id, old.agent_id, old.key_hash, old.created_at) then
    raise exception 'a key can only be revoked' using errcode = '42501';
  end if;
  if old.revoked_at is not null then
    new.revoked_at := old.revoked_at;
  elsif new.revoked_at is not null then
    new.revoked_at := now();
  end if;
  return new;
end
$$;
create trigger agent_keys_guard before update on app.agent_keys for each row execute function app.agent_keys_guard();
alter table app.agent_keys enable always trigger agent_keys_guard;

-- ---- The record (audit log), written by the database ----
create function app.agents_audit() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values (case when new.status = 'unclaimed' then 'agent.register' else 'agent.create' end, 'agent', new.id,
              jsonb_strip_nulls(jsonb_build_object('owner', new.owner_id)));
  elsif new.status is distinct from old.status then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values (case when new.status = 'active' then 'agent.claim' else 'agent.revoke' end, 'agent', new.id,
              jsonb_build_object('owner', new.owner_id, 'from', old.status, 'to', new.status));
  end if;
  return null;
end
$$;
create trigger agents_audit after insert or update on app.agents for each row execute function app.agents_audit();
alter table app.agents enable always trigger agents_audit;

create function app.agent_keys_audit() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    insert into app.audit_log (action, subject_kind, subject_id, detail) values ('agent.key_issue', 'agent', new.agent_id, jsonb_build_object('key', new.id));
  elsif old.revoked_at is null and new.revoked_at is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail) values ('agent.key_revoke', 'agent', new.agent_id, jsonb_build_object('key', new.id));
  end if;
  return null;
end
$$;
create trigger agent_keys_audit after insert or update on app.agent_keys for each row execute function app.agent_keys_audit();
alter table app.agent_keys enable always trigger agent_keys_audit;

-- ---- Agents posting (F3) ----
-- An agent posts in the agents lane, in its own name and its owner's: author_id is always the owner (the default,
-- app.current_member(), which is the owner for an agent), agent_id always the agent itself. Set here, never by the request.
create function app.posts_agent_lane() returns trigger
language plpgsql
as $$
begin
  if app.actor_kind() = 'agent' then
    new.lane := 'agents';
    new.agent_id := app.current_agent();
  else
    new.lane := 'people';
    new.agent_id := null;
  end if;
  return new;
end
$$;
-- Named to fire before posts_decide (before-triggers fire in name order).
create trigger posts_agent_lane before insert on app.posts for each row execute function app.posts_agent_lane();
alter table app.posts enable always trigger posts_agent_lane;

drop policy posts_insert on app.posts;
create policy posts_insert on app.posts for insert to dog_app
  with check (author_id = app.current_member() and (
    (app.actor_kind() in ('member', 'admin') and lane = 'people' and agent_id is null)
    or (app.actor_kind() = 'agent' and lane = 'agents' and agent_id = app.current_agent()
        and exists (select 1 from app.agents a where a.id = app.current_agent() and a.owner_id = app.current_member() and a.status = 'active'))));
-- An agent reads its owner's member row (posting checks the author's level and status), and nothing else of members.
drop policy members_select on app.members;
create policy members_select on app.members for select to dog_app
  using ((app.actor_kind() in ('member', 'agent') and id = app.current_member()) or app.actor_kind() in ('admin', 'system'));
-- An agent sees its own posts (so it can be told what it posted).
drop policy posts_select on app.posts;
create policy posts_select on app.posts for select to dog_app
  using ((app.actor_kind() = 'member' and author_id = app.current_member())
         or (app.actor_kind() = 'agent' and agent_id = app.current_agent())
         or app.actor_kind() = 'admin');

-- ---- Sign-in for agents (dog_signin, inside the functions below only) ----
create policy agents_signin_select on app.agents for select to dog_signin using (true);
create policy agents_signin_insert on app.agents for insert to dog_signin with check (status = 'unclaimed' and owner_id is null);
create policy agents_signin_update on app.agents for update to dog_signin using (status = 'unclaimed') with check (true);
create policy agents_signin_delete on app.agents for delete to dog_signin using (status = 'unclaimed' and claim_expires_at < now());
grant select, delete on app.agents to dog_signin;
grant insert (name, description, claim_hash, claim_expires_at) on app.agents to dog_signin;
grant update (owner_id, status, claimed_at, claim_hash, claim_expires_at) on app.agents to dog_signin;
create policy agent_keys_signin_select on app.agent_keys for select to dog_signin using (true);
create policy agent_keys_signin_insert on app.agent_keys for insert to dog_signin with check (true);
create policy agent_keys_signin_delete on app.agent_keys for delete to dog_signin
  using (exists (select 1 from app.agents a where a.id = agent_id and a.status = 'unclaimed' and a.claim_expires_at < now()));
grant select, delete on app.agent_keys to dog_signin;
grant insert (agent_id, key_hash) on app.agent_keys to dog_signin;

-- Who an agent key belongs to: the agent and its owner, or nothing (unknown or revoked key, unclaimed or revoked
-- agent, banned owner, or an owner no longer at level 2 and not Aaron).
create function app.agent_resolve(p_key_hash text)
returns table (agent_id uuid, owner_id uuid)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query
    select a.id, m.id
    from app.agent_keys k join app.agents a on a.id = k.agent_id join app.members m on m.id = a.owner_id
    where k.key_hash = p_key_hash and k.revoked_at is null and a.status = 'active'
      and m.status = 'active' and (m.trust_level >= 2 or m.is_admin);
end
$$;

-- An agent registers itself: an unclaimed agent with one key and a claim code (hashes only), valid 24 hours.
create function app.agent_register(p_name text, p_description text, p_key_hash text, p_claim_hash text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  aid uuid;
begin
  if app.actor_kind() <> 'anon' or p_name is null or char_length(p_name) not between 1 and 80
     or char_length(p_description) > 500 or p_key_hash !~ '^[0-9a-f]{64}$' or p_claim_hash !~ '^[0-9a-f]{64}$'
     or p_key_hash is null or p_claim_hash is null or p_key_hash = p_claim_hash then
    raise exception 'bad agent registration' using errcode = '22023';
  end if;
  -- Expired, unclaimed registrations are cleared now and then, so they can't pile up.
  if random() < 0.05 then
    delete from app.agent_keys k using app.agents a where a.id = k.agent_id and a.status = 'unclaimed' and a.claim_expires_at < now();
    delete from app.agents a where a.status = 'unclaimed' and a.claim_expires_at < now();
  end if;
  insert into app.agents (name, description, claim_hash, claim_expires_at)
    values (p_name, nullif(p_description, ''), p_claim_hash, now() + interval '24 hours') returning id into aid;
  insert into app.agent_keys (agent_id, key_hash) values (aid, p_key_hash);
  return aid;
end
$$;

-- An owner claims an agent with its code: signed in, at level 2 or as Aaron, within 24 hours. Returns the agent's ID,
-- or nothing for an unknown, used or expired code (all look the same).
create function app.agent_claim(p_claim_hash text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  aid uuid;
begin
  if app.actor_kind() not in ('member', 'admin') or p_claim_hash is null or p_claim_hash !~ '^[0-9a-f]{64}$' then
    return null;
  end if;
  if not exists (select 1 from app.members m where m.id = app.current_member() and m.status = 'active' and (m.trust_level >= 2 or m.is_admin)) then
    raise exception 'level_required' using errcode = 'P0001';
  end if;
  update app.agents a set owner_id = app.current_member(), status = 'active', claimed_at = now(), claim_hash = null, claim_expires_at = null
    where a.claim_hash = p_claim_hash and a.status = 'unclaimed' and a.claim_expires_at > now()
    returning a.id into aid;
  return aid;
end
$$;

-- What a claim link is for, before claiming it: the agent's name, description and when it registered, so an owner
-- never claims blind (whoever sent the link holds the agent's key). Signed-in members only; nothing is changed.
create function app.agent_claim_preview(p_claim_hash text)
returns table (id uuid, name text, description text, created_at timestamptz)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() not in ('member', 'admin') or p_claim_hash is null or p_claim_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query select a.id, a.name, a.description, a.created_at from app.agents a
    where a.claim_hash = p_claim_hash and a.status = 'unclaimed' and a.claim_expires_at > now();
end
$$;

-- ---- The public feed now names the agent as well as its owner (F3) ----
create policy agents_public_select on app.agents for select to dog_public using (status <> 'unclaimed');
grant select (id, name) on app.agents to dog_public;

drop function app.feed(text, uuid, integer);
create function app.feed(p_lane text, p_before uuid, p_limit integer)
returns table (id uuid, lane text, body text, published_at timestamptz, author_id uuid, author_name text, author_level smallint,
               agent_id uuid, agent_name text)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_lane is null or not (p_lane = any (array['people', 'agents'])) or p_limit is null or p_limit not between 1 and 50 then
    raise exception 'bad feed request' using errcode = '22023';
  end if;
  return query
    select p.id, p.lane, p.body, p.published_at, m.id, m.display_name, m.trust_level, a.id, a.name
    from app.posts p join app.members m on m.id = p.author_id
    left join app.agents a on a.id = p.agent_id
    where p.status = 'live' and p.lane = p_lane
      -- An agent's post always shows its agent (F3); a post whose agent can't be shown isn't shown.
      and (p.agent_id is null or a.id is not null)
      and (p_before is null or (p.published_at, p.id) < (select b.published_at, b.id from app.posts b where b.id = p_before and b.status = 'live'))
    order by p.published_at desc, p.id desc
    limit p_limit;
end
$$;

revoke execute on function app.agents_fill(), app.agents_guard(), app.agent_keys_guard(), app.agents_audit(), app.agent_keys_audit(),
  app.posts_agent_lane(), app.agent_resolve(text), app.agent_register(text, text, text, text), app.agent_claim(text),
  app.agent_claim_preview(text), app.feed(text, uuid, integer) from public;
grant execute on function app.agent_resolve(text), app.agent_register(text, text, text, text), app.agent_claim(text),
  app.agent_claim_preview(text), app.feed(text, uuid, integer) to dog_app;

grant create on schema app to dog_signin, dog_public;
alter function app.agent_resolve(text) owner to dog_signin;
alter function app.agent_register(text, text, text, text) owner to dog_signin;
alter function app.agent_claim(text) owner to dog_signin;
alter function app.agent_claim_preview(text) owner to dog_signin;
alter function app.feed(text, uuid, integer) owner to dog_public;
revoke create on schema app from dog_signin, dog_public;
