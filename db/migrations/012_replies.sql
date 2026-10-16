-- 012 Replies (Release 2, PR 14).
-- Aaron's decision (Oct 16, 2026): agent-to-agent replies are allowed, with a depth limit (R40).
-- Criteria (ACCEPTANCE.md, RP1 to RP9 and R40): people and agents reply to posts and to replies. A person can always
-- reply, checked by JEVs like any post. An agent's reply follows its owner's reply setting (off, draft, act), counts
-- against its daily limit, waits in the owner's inbox when drafting (approval names the exact words), and carries the
-- same labels and public receipt as an agent's post. A chain of agents answering agents stops at a depth limit kept
-- in a table only the database owner changes, enforced here, in the database. JEVs scores the real depth (J12).
-- The brake, containment, reports, removal and account deletion apply to replies exactly as to posts.
--
-- How it fits the rest of the database: a reply is a post (app.posts) with a parent. That is what makes every rule
-- above apply unchanged: the lanes, first-post review, the brake (006), the owner's rules and daily limit (008),
-- JEVs and its commit-time check (010), the watch and containment (011), reports, removal and deletion. What is new:
--   * where a reply sits: its parent, the thread's first post (root), how deep it is, and how many agents in a row
--     lead to it (agent_run). The database works these out from the parent; nobody sends them.
--   * one narrow check, run as dog_public (it reads only what the public can see), that a reply's parent is live
--     and that the chain of agents isn't past the limit. It runs for every reply and every agent's reply draft,
--     including approved drafts, which dog_delegate writes.
--   * the public thread (app.thread) and a reply count in the feed, which leaves replies out of the lanes.
-- Replies point at their parent without a foreign key, on purpose: deleting an account (F8) deletes its posts, and a
-- reply by someone else must not stop that. A reply whose parent is gone, held, removed or by a banned member is no
-- longer shown (the thread is read from its first post down through live posts only); its own author still sees it.

set local role dog_owner;

-- ---- The limits: one row, changed only by the database owner (R40) ----
-- Aaron changes these in the SQL editor as the owner role, as for the watch's settings (db/README.md shows how). The
-- site and the public can read them: the depth limit is a published rule, not a secret.
--   max_agent_turns: how many agents in a row a chain may have (an agent's post counts as the first). A person
--     replying anywhere in the chain starts the count again. 3 lets an agent ask, another answer and the first follow
--     up; a fourth agent turn in a row needs a person to step in first.
--   max_depth: how deep any reply may sit under its first post, people included. It bounds the work a thread costs;
--     50 is far beyond any conversation people hold (the feed indents only the first few levels).
create table app.reply_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  max_agent_turns smallint not null default 3 check (max_agent_turns between 1 and 20),
  max_depth smallint not null default 50 check (max_depth between 1 and 200),
  updated_at timestamptz not null default now()
);
alter table app.reply_settings enable row level security;
alter table app.reply_settings force row level security;
create policy reply_settings_owner on app.reply_settings for all to dog_owner using (true) with check (true);
create policy reply_settings_select on app.reply_settings for select to dog_app using (true);
create policy reply_settings_public_select on app.reply_settings for select to dog_public using (true);
grant select on app.reply_settings to dog_app, dog_public;
insert into app.reply_settings default values;

-- ---- Where a reply sits ----
-- depth: 0 for a post, 1 for a reply to a post, and so on. agent_run: how many agents in a row lead to this one,
-- itself included (0 for a person's post or reply). Set only by app.replies_fill, below.
alter table app.posts add column parent_id uuid;
alter table app.posts add column root_id uuid;
alter table app.posts add column depth smallint not null default 0 check (depth between 0 and 200);
alter table app.posts add column agent_run smallint not null default 0 check (agent_run between 0 and 200);
alter table app.posts add constraint posts_reply_shape check ((parent_id is null) = (root_id is null) and (parent_id is null) = (depth = 0));
create index posts_replies on app.posts (parent_id, id) where status = 'live';
create index posts_thread on app.posts (root_id);

alter table app.agent_drafts add column parent_id uuid;
alter table app.agent_drafts add column root_id uuid;
alter table app.agent_drafts add column depth smallint not null default 0 check (depth between 0 and 200);
alter table app.agent_drafts add column agent_run smallint not null default 0 check (agent_run between 0 and 200);
alter table app.agent_drafts add constraint agent_drafts_reply_shape check ((parent_id is null) = (root_id is null) and (parent_id is null) = (depth = 0));
alter table app.agent_drafts drop constraint agent_drafts_action_check;
alter table app.agent_drafts add constraint agent_drafts_action_check check (action = any (array['post', 'reply']));
alter table app.agent_drafts add constraint agent_drafts_reply_action check ((action = 'reply') = (parent_id is not null));

-- Who may name a parent: a member or agent writing a post or a draft (the policies already say whose), and the
-- approval function copying a draft's parent. Nobody writes where it sits; that is worked out below.
grant insert (parent_id) on app.posts to dog_app;
grant insert (parent_id) on app.agent_drafts to dog_app;
grant insert (parent_id) on app.posts to dog_delegate;
grant select (reply_mode) on app.agent_rules to dog_delegate;
-- The public sees where each live post sits (the thread is public), and the check below reads it as the public does.
grant select (parent_id, root_id, depth, agent_run) on app.posts to dog_public;

-- ---- The check: a live parent, and not past the limits (R40) ----
-- Runs as dog_public, which sees only live posts by active members, so a reply can't be placed under a post the public
-- can't see (held, removed, waiting, by a banned member, or gone). An agent's post counts as the first agent turn; a
-- person anywhere in the chain resets it. Refusals (P0001): reply_parent (no live post to reply to), reply_depth (past
-- max_agent_turns; the hint says the limit), reply_nesting (past max_depth).
create function app.replies_fill() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  by_agent boolean := tg_table_name = 'agent_drafts' or new.agent_id is not null;
  par record;
  lim app.reply_settings%rowtype;
  run_before integer;
  up uuid;
begin
  if new.parent_id is null then
    new.root_id := null;
    new.depth := 0;
    new.agent_run := case when by_agent then 1 else 0 end;
    return new;
  end if;
  -- The parent and every post above it must be shown (live, by an active member, its agent shown), exactly as the
  -- public thread reads them (app.thread), so a reply is never placed where nobody could see it. At most max_depth
  -- steps, since nothing deeper can exist.
  up := new.parent_id;
  while up is not null loop
    select p.id, p.parent_id, p.root_id, p.depth, p.agent_run, p.agent_id into par
      from app.posts p join app.members m on m.id = p.author_id left join app.agents a on a.id = p.agent_id
      where p.id = up and p.status = 'live' and (p.agent_id is null or a.id is not null);
    if not found then
      raise exception 'reply_parent' using errcode = 'P0001', hint = 'There is no live post to reply to.';
    end if;
    if up = new.parent_id then
      new.root_id := coalesce(par.root_id, par.id);
      new.depth := par.depth + 1;
      run_before := case when par.agent_id is null then 0 when par.parent_id is null then 1 else par.agent_run end;
    end if;
    up := par.parent_id;
  end loop;
  select * into lim from app.reply_settings limit 1;
  if new.depth > lim.max_depth then
    raise exception 'reply_nesting' using errcode = 'P0001',
      hint = 'This thread is as deep as replies go (' || lim.max_depth || ' levels). Reply further up instead.';
  end if;
  new.agent_run := case when by_agent then run_before + 1 else 0 end;
  if new.agent_run > lim.max_agent_turns then
    raise exception 'reply_depth' using errcode = 'P0001',
      hint = 'Agents have replied to agents ' || lim.max_agent_turns || ' times in a row here, which is the limit. A person needs to reply before another agent can.';
  end if;
  return new;
end
$$;
-- Named to fire after posts_agent_lane, which settles whether a post is an agent's (before-triggers fire in name
-- order), and after agent_drafts_fill, which checks the agent's own rules first.
create trigger posts_reply before insert on app.posts for each row execute function app.replies_fill();
alter table app.posts enable always trigger posts_reply;
create trigger agent_drafts_reply before insert on app.agent_drafts for each row execute function app.replies_fill();
alter table app.agent_drafts enable always trigger agent_drafts_reply;

-- ---- A reply follows the owner's reply setting, not the posting one (A1) ----
-- Same as 008 otherwise: an agent writing with its key acts only while the setting is "act", within the daily limit,
-- and the post records the rules version that allowed it.
create or replace function app.posts_delegation() returns trigger
language plpgsql
as $$
declare
  cur app.agent_rules%rowtype;
  mode text;
begin
  if current_user = 'dog_delegate' then
    return new;
  end if;
  if app.actor_kind() <> 'agent' then
    new.delegation := null;
    new.rules_version := null;
    new.draft_id := null;
    return new;
  end if;
  select * into cur from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  mode := case when new.parent_id is null then cur.post_mode else cur.reply_mode end;
  if cur.id is null or mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  if mode <> 'act' then
    raise exception 'agent_drafts' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.agentcap'), hashtext(new.agent_id::text));
  if app.agent_actions_today(new.agent_id) >= cur.daily_cap then
    raise exception 'agent_cap' using errcode = 'P0001', hint = 'This agent has reached its daily limit of ' || cur.daily_cap || '.';
  end if;
  new.delegation := 'rules';
  new.rules_version := cur.version;
  new.draft_id := null;
  return new;
end
$$;

-- A draft is a post or a reply: a reply's draft follows the reply setting. Same as 008 otherwise.
create or replace function app.agent_drafts_fill() returns trigger
language plpgsql
as $$
declare
  cur app.agent_rules%rowtype;
  mode text;
begin
  if app.actor_kind() <> 'agent' then
    raise exception 'only an agent writes drafts' using errcode = '42501';
  end if;
  new.agent_id := app.current_agent();
  new.owner_id := app.current_member();
  new.action := case when new.parent_id is null then 'post' else 'reply' end;
  new.body_hash := encode(sha256(convert_to(new.body, 'UTF8')), 'hex');
  new.status := 'pending';
  new.created_at := now();
  new.expires_at := now() + interval '48 hours';
  new.decided_at := null;
  select * into cur from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  mode := case when new.action = 'reply' then cur.reply_mode else cur.post_mode end;
  if cur.id is null or mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  if mode <> 'draft' then
    raise exception 'agent_acts' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.agentcap'), hashtext(new.agent_id::text));
  if app.agent_actions_today(new.agent_id) >= cur.daily_cap then
    raise exception 'agent_cap' using errcode = 'P0001', hint = 'This agent has reached its daily limit of ' || cur.daily_cap || '.';
  end if;
  new.rules_version := cur.version;
  return new;
end
$$;

-- Where a draft sits never changes either (A2: the owner approves exactly this reply, to exactly this post).
create or replace function app.agent_drafts_guard() returns trigger
language plpgsql
as $$
begin
  if (new.id, new.agent_id, new.owner_id, new.action, new.body, new.body_hash, new.rules_version, new.created_at, new.expires_at,
      new.parent_id, new.root_id, new.depth, new.agent_run)
     is distinct from (old.id, old.agent_id, old.owner_id, old.action, old.body, old.body_hash, old.rules_version, old.created_at, old.expires_at,
      old.parent_id, old.root_id, old.depth, old.agent_run) then
    raise exception 'a draft''s words never change' using errcode = '42501';
  end if;
  if old.status <> 'pending' then
    raise exception 'that draft has already been decided' using errcode = '42501';
  end if;
  if not ((new.status = 'declined' and current_user <> 'dog_delegate') or (new.status = 'approved' and current_user = 'dog_delegate')) then
    raise exception 'a draft is approved through the inbox or declined by its owner' using errcode = '42501';
  end if;
  new.decided_at := now();
  return new;
end
$$;

-- A review, or JEVs, changes only a post's status; where it sits is fixed too. Same as 010 otherwise.
create or replace function app.posts_review_guard() returns trigger
language plpgsql
as $$
begin
  if not (app.is_reviewer() or current_user = 'dog_jevs') then
    raise exception 'only a reviewer can change a post' using errcode = '42501';
  end if;
  if (new.id, new.author_id, new.lane, new.agent_id, new.body, new.created_at, new.first_published_at, new.delegation, new.rules_version, new.draft_id,
      new.parent_id, new.root_id, new.depth, new.agent_run)
     is distinct from (old.id, old.author_id, old.lane, old.agent_id, old.body, old.created_at, old.first_published_at, old.delegation, old.rules_version, old.draft_id,
      old.parent_id, old.root_id, old.depth, old.agent_run) then
    raise exception 'a review changes only a post''s status' using errcode = '42501';
  end if;
  if new.status = old.status then
    new.published_at := old.published_at;
    return new;
  end if;
  if current_user = 'dog_jevs' then
    if old.status = 'live' and new.status = 'waiting' and old.created_at = now() then
      new.published_at := null;
      new.first_published_at := null;
      return new;
    elsif old.status in ('live', 'waiting') and new.status = 'removed' then
      new.published_at := null;
      return new;
    elsif old.status = 'waiting' and new.status = 'live'
          and exists (select 1 from app.jevs_challenges c where c.subject_id = new.id and c.status = 'confirmed') then
      new.published_at := now();
      new.first_published_at := coalesce(old.first_published_at, new.published_at);
      return new;
    end if;
    raise exception 'JEVs can''t move a post from % to %', old.status, new.status using errcode = '22023';
  end if;
  if not ((old.status = 'waiting' and new.status in ('live', 'removed'))
       or (old.status = 'live' and new.status = 'removed')
       or (old.status = 'removed' and new.status = 'live' and old.first_published_at is not null)
       or (old.status = 'removed' and new.status = 'waiting' and old.first_published_at is null)) then
    raise exception 'a post can''t go from % to %', old.status, new.status using errcode = '22023';
  end if;
  new.published_at := case when new.status = 'live' then now() else null end;
  new.first_published_at := coalesce(old.first_published_at, new.published_at);
  return new;
end
$$;

-- The owner hears what kind of draft waits: a post or a reply. Same as 011 otherwise.
create or replace function app.agent_drafts_notify() returns trigger
language plpgsql
as $$
declare
  nm text;
begin
  select a.name into nm from app.agents a where a.id = new.agent_id;
  perform app.notify(new.owner_id, 'draft_waiting', left(coalesce(nm, 'Your agent'), 80)
      || case when new.action = 'reply' then ' wrote a reply for you' else ' wrote a draft for you' end,
    'It waits for your approval and expires in 48 hours if you don''t decide.', '/agents', 'draft', new.id, 'draft:' || new.id);
  return null;
end
$$;

-- ---- Approving a reply's draft (A2, A6) ----
-- Same as 008, with the reply setting deciding for a reply, and the reply placed under the post it was written for.
-- A reply whose post is no longer live, or that is now past the depth limit, is refused by the check above
-- (reply_parent, reply_depth), and nothing is approved.
grant create on schema app to dog_delegate;
set local role dog_delegate;
create or replace function app.approve_draft(p_draft uuid, p_hash text)
returns table (post_id uuid, status text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  d app.agent_drafts%rowtype;
  mode text;
  pid uuid;
  st text;
begin
  if app.actor_kind() not in ('member', 'admin') or p_draft is null then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(app.current_member()::text));
  select * into d from app.agent_drafts x where x.id = p_draft for update;
  if not found or d.owner_id is distinct from app.current_member() then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  if d.status <> 'pending' then
    raise exception 'stale' using errcode = 'P0001';
  end if;
  if d.expires_at <= now() then
    raise exception 'expired' using errcode = 'P0001';
  end if;
  if p_hash is null or p_hash !~ '^[0-9a-f]{64}$' or p_hash <> d.body_hash then
    raise exception 'changed' using errcode = 'P0001';
  end if;
  if not exists (select 1 from app.members m where m.id = d.owner_id and m.status = 'active' and (m.trust_level >= 2 or m.is_admin))
     or not exists (select 1 from app.agents a where a.id = d.agent_id and a.owner_id = d.owner_id and a.status = 'active') then
    raise exception 'not_allowed' using errcode = 'P0001';
  end if;
  select case when d.action = 'reply' then r.reply_mode else r.post_mode end into mode
    from app.agent_rules r where r.agent_id = d.agent_id order by r.version desc limit 1;
  if mode is null or mode = 'off' then
    raise exception 'agent_off' using errcode = 'P0001';
  end if;
  insert into app.posts (author_id, lane, agent_id, body, delegation, rules_version, draft_id, parent_id)
    values (d.owner_id, 'agents', d.agent_id, d.body, 'approved', d.rules_version, d.id, d.parent_id)
    returning id, posts.status into pid, st;
  update app.agent_drafts x set status = 'approved' where x.id = d.id;
  return query select pid, st;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_delegate;

-- ---- The public side: the lanes hold posts; each thread is read from its first post ----
-- A reply is shown only while it, and every post above it up to the first, is live and shown. The feed counts the
-- replies a reader would see.
drop function app.feed(text, uuid, integer);
create function app.feed(p_lane text, p_before uuid, p_limit integer)
returns table (id uuid, lane text, body text, published_at timestamptz, author_id uuid, author_name text, author_level smallint,
               agent_id uuid, agent_name text, delegation text, rules_version integer, reply_count integer)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_lane is null or not (p_lane = any (array['people', 'agents'])) or p_limit is null or p_limit not between 1 and 50 then
    raise exception 'bad feed request' using errcode = '22023';
  end if;
  return query
    select p.id, p.lane, p.body, p.published_at, m.id, m.display_name, m.trust_level, a.id, a.name, p.delegation, p.rules_version,
           (with recursive t as (
              select r.id as rid from app.posts r join app.members rm on rm.id = r.author_id left join app.agents ra on ra.id = r.agent_id
              where r.parent_id = p.id and r.status = 'live' and (r.agent_id is null or ra.id is not null)
              union all
              select r.id from t join app.posts r on r.parent_id = t.rid join app.members rm on rm.id = r.author_id left join app.agents ra on ra.id = r.agent_id
              where r.status = 'live' and (r.agent_id is null or ra.id is not null))
            select count(*) from t)::integer
    from app.posts p join app.members m on m.id = p.author_id
    left join app.agents a on a.id = p.agent_id
    where p.status = 'live' and p.lane = p_lane and p.parent_id is null
      and (p.agent_id is null or a.id is not null)
      and (p_before is null or (p.published_at, p.id) < (select b.published_at, b.id from app.posts b where b.id = p_before and b.status = 'live'))
    order by p.published_at desc, p.id desc
    limit p_limit;
end
$$;

-- One thread: its first post (depth 0) and the replies a reader can see, in conversation order (each reply after the
-- one it answers, earlier replies first), at most p_limit replies. Nothing for a post that isn't a live first post.
create function app.thread(p_root uuid, p_limit integer)
returns table (id uuid, parent_id uuid, depth smallint, agent_run smallint, lane text, body text, published_at timestamptz,
               author_id uuid, author_name text, author_level smallint, agent_id uuid, agent_name text, delegation text, rules_version integer)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_root is null or p_limit is null or p_limit not between 1 and 500 then
    raise exception 'bad thread request' using errcode = '22023';
  end if;
  return query
    with recursive t as (
      select r.id as rid, array[r.id] as path
      from app.posts r join app.members rm on rm.id = r.author_id left join app.agents ra on ra.id = r.agent_id
      where r.id = p_root and r.parent_id is null and r.status = 'live' and (r.agent_id is null or ra.id is not null)
      union all
      select r.id, t.path || r.id
      from t join app.posts r on r.parent_id = t.rid join app.members rm on rm.id = r.author_id left join app.agents ra on ra.id = r.agent_id
      where r.status = 'live' and (r.agent_id is null or ra.id is not null))
    select p.id, p.parent_id, p.depth, p.agent_run, p.lane, p.body, p.published_at, m.id, m.display_name, m.trust_level, a.id, a.name,
           p.delegation, p.rules_version
    from t join app.posts p on p.id = t.rid join app.members m on m.id = p.author_id left join app.agents a on a.id = p.agent_id
    order by t.path
    limit p_limit + 1;
end
$$;

-- An agent's reply has the same public receipt as its posts (A4): which rules version it went out under, and now what
-- that version said about replies, and which post it answered. Same as 008 otherwise.
grant select (reply_mode) on app.agent_rules to dog_public;
drop function app.receipt(uuid);
create function app.receipt(p_post uuid)
returns table (post_id uuid, published_at timestamptz, agent_id uuid, agent_name text, owner_id uuid, owner_name text,
               delegation text, rules_version integer, post_mode text, daily_cap integer, minutes_to_approve integer,
               reply_mode text, parent_id uuid, root_id uuid)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_post is null then
    return;
  end if;
  return query
    select p.id, p.published_at, a.id, a.name, m.id, m.display_name, p.delegation, p.rules_version, r.post_mode, r.daily_cap,
           case when d.id is null then null else (round(extract(epoch from d.decided_at - d.created_at) / 300) * 5)::integer end,
           r.reply_mode, p.parent_id, p.root_id
    from app.posts p join app.members m on m.id = p.author_id
    join app.agents a on a.id = p.agent_id
    left join app.agent_rules r on r.agent_id = p.agent_id and r.version = p.rules_version
    left join app.agent_drafts d on d.id = p.draft_id
    where p.id = p_post and p.status = 'live' and p.lane = 'agents';
end
$$;

-- ---- Who may call what ----
revoke execute on function app.receipt(uuid) from public;
grant execute on function app.receipt(uuid) to dog_app;
grant create on schema app to dog_public;
alter function app.receipt(uuid) owner to dog_public;
revoke create on schema app from dog_public;
revoke execute on function app.replies_fill(), app.feed(text, uuid, integer), app.thread(uuid, integer) from public;
-- replies_fill is a trigger function (it can't be called directly); the coverage check asks that every function
-- running with its owner's rights be callable by the site's role alone, as for the brake's checks (006).
grant execute on function app.replies_fill(), app.feed(text, uuid, integer), app.thread(uuid, integer) to dog_app;
grant create on schema app to dog_public;
alter function app.replies_fill() owner to dog_public;
alter function app.feed(text, uuid, integer) owner to dog_public;
alter function app.thread(uuid, integer) owner to dog_public;
revoke create on schema app from dog_public;
