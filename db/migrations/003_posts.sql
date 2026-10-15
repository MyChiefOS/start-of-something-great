-- 003 Posting and lanes (Release 2, PR 3).
-- Criteria: F5 people and agents post in separate lanes, people first; S2 someone not signed in reads only live
-- posts and public profiles, and every write fails; G2 public feeds are cacheable (in the API); F6 groundwork:
-- level 0 and 1 members' first 3 posts wait for review, level 2 members' posts go live (the review queue is PR 4).
--
-- Public reading goes through two narrow functions that run as their own role, dog_public, which can read only live
-- posts and the public fields of active members. The site's role never reads other members' rows directly.

do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_public') then
    create role dog_public nologin noinherit nobypassrls;
  end if;
end
$roles$;
grant dog_public to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_public;

create table app.posts (
  id uuid primary key default app.uuid_v7(),
  author_id uuid not null default app.current_member() references app.members (id),
  lane text not null default 'people' check (lane = any (array['people', 'agents'])),
  -- Agents arrive in PR 5; an agent post will carry its agent and still name its owner as author (F3).
  agent_id uuid,
  body text not null check (char_length(body) between 1 and 5000),
  status text not null default 'waiting' check (status = any (array['waiting', 'live', 'removed'])),
  created_at timestamptz not null default now(),
  published_at timestamptz,
  check ((lane = 'agents') = (agent_id is not null)),
  check ((status = 'live') = (published_at is not null))
);
create index posts_feed on app.posts (lane, id desc) where status = 'live';
create index posts_author on app.posts (author_id, status);
alter table app.posts enable row level security;
alter table app.posts force row level security;

-- Members: write their own posts in the people lane (only the text), and see their own posts in any state.
-- Aaron sees everything. Nobody else reads posts directly; the public feed function does that.
create policy posts_select on app.posts for select to dog_app
  using ((app.actor_kind() = 'member' and author_id = app.current_member()) or app.actor_kind() = 'admin');
create policy posts_insert on app.posts for insert to dog_app
  with check (app.actor_kind() in ('member', 'admin') and author_id = app.current_member() and lane = 'people' and agent_id is null);
grant select on app.posts to dog_app;
grant insert (body) on app.posts to dog_app;

-- Whether a new post waits for review is decided here, from the author's level, never by the request (F6).
--   Level 2 or higher, or an administrator: live at once.
--   Level 0 or 1: waits until the author has 3 live posts.
create function app.posts_decide() returns trigger
language plpgsql
as $$
declare
  lvl smallint;
  admin boolean;
  live integer;
begin
  select m.trust_level, m.is_admin into lvl, admin from app.members m where m.id = new.author_id and m.status = 'active';
  if not found then
    raise exception 'only active members can post' using errcode = '42501';
  end if;
  select count(*) into live from app.posts p where p.author_id = new.author_id and p.status = 'live';
  if admin or lvl >= 2 or live >= 3 then
    new.status := 'live';
    new.published_at := now();
  else
    new.status := 'waiting';
    new.published_at := null;
  end if;
  new.created_at := now();
  return new;
end
$$;
create trigger posts_decide before insert on app.posts for each row execute function app.posts_decide();
alter table app.posts enable always trigger posts_decide;
revoke execute on function app.posts_decide() from public;

-- ---- What dog_public may read: live posts, and the public face of active members ----
create policy posts_public_select on app.posts for select to dog_public using (status = 'live');
grant select (id, author_id, lane, agent_id, body, status, published_at) on app.posts to dog_public;
create policy members_public_select on app.members for select to dog_public using (status = 'active');
grant select (id, display_name, trust_level, created_at) on app.members to dog_public;
grant execute on function app.uuid_v7() to dog_public;

-- The public feed: live posts in one lane, newest first, a page at a time (before = the last ID already seen).
create function app.feed(p_lane text, p_before uuid, p_limit integer)
returns table (id uuid, lane text, body text, published_at timestamptz, author_id uuid, author_name text, author_level smallint)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_lane is null or not (p_lane = any (array['people', 'agents'])) or p_limit is null or p_limit not between 1 and 50 then
    raise exception 'bad feed request' using errcode = '22023';
  end if;
  return query
    select p.id, p.lane, p.body, p.published_at, m.id, m.display_name, m.trust_level
    from app.posts p join app.members m on m.id = p.author_id
    where p.status = 'live' and p.lane = p_lane and (p_before is null or p.id < p_before)
    order by p.id desc
    limit p_limit;
end
$$;

-- A public profile: name, level, when they joined and how many live posts they have. Nothing else.
create function app.profile(p_member uuid)
returns table (id uuid, display_name text, trust_level smallint, joined timestamptz, live_posts bigint)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_member is null then
    return;
  end if;
  return query
    select m.id, m.display_name, m.trust_level, m.created_at,
           (select count(*) from app.posts p where p.author_id = m.id and p.status = 'live')
    from app.members m where m.id = p_member;
end
$$;

revoke execute on function app.feed(text, uuid, integer), app.profile(uuid) from public;
grant execute on function app.feed(text, uuid, integer), app.profile(uuid) to dog_app;
grant create on schema app to dog_public;
alter function app.feed(text, uuid, integer) owner to dog_public;
alter function app.profile(uuid) owner to dog_public;
revoke create on schema app from dog_public;
