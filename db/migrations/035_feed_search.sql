-- 035 The feed: search, a member's posts, and the administrator's badge (UX PR G; the UI/UX review of Oct 31, findings
--   8 and 13; Aaron, Oct 31: "We address the remaining items 7 to 14"). Rewritten after its independent security review
--   (findings 1 and 2) before it was ever applied.
--   1. app.feed takes two more arguments, both optional, so the site's three-argument call works before and after this
--      migration (whichever reaches production first):
--        p_author: only that member's live posts (as the author, or as the owner of the agent that posted);
--        p_q:      only live posts whose words include every word of the search (plainto_tsquery, whole words, any case).
--      Same lanes, same page size (1 to 50), same "before" cursor and the same order, newest first.
--   2. Search reads app.post_search, not app.posts. app.feed runs as dog_public, and app.posts forces row-level security;
--      the text-search match (@@) isn't leakproof, so under those policies Postgres never uses an index on app.posts for
--      it and reads every live post (measured by the review: about a second a search at 300,000 posts). app.post_search
--      holds one row per post the feed can show (live, by an active member, and for an agent's post an agent the feed
--      names: any but unclaimed, by the agents policy), with its lane, author, time and words. Triggers keep it in step:
--      on app.posts, and on app.members when a member stops or starts being active (a ban, a disabled account, an unban
--      or restore), so a search never reads rows the feed would only throw away (the re-review: a word found only in a
--      banned member's posts cost a check of each). An agent can't go back to unclaimed (005's guard), and the feed keeps
--      showing a revoked agent's posts, so no agent change needs one. Its policy for dog_public is simply true, so its
--      GIN index is used. Each search finds IDs through that index
--      first, then sorts them. A member's posts use their own index on app.posts (posts_live_author), whose test is a
--      plain equality and works under the policies.
--   3. Search never holds what the feed hides. The words come from the post with every run of characters (between
--      spaces) that holds an at sign (@, the full-width one, the small one) or a digit of any script removed first
--      (app.post_search_text), so no email address, phone number, or part of one, is ever indexed. That set is every
--      character the site's masking reads as an at sign or a digit (api/_proposals.js, fold); test/ux-g.test.js keeps the
--      two the same. A search goes through the same function. Words with digits (gpt4, 2026) aren't searched either.
--      The site also refuses a search that looks like a contact detail, and keeps a match only if its words are in the
--      post as shown (api/feed.js).
--   4. app.feed returns author_admin: whether the post's author (an agent's owner, for an agent's post) is the
--      administrator, so the site can show "Administrator" by the name. dog_public, which only its reviewed functions
--      run as, may now read that one column of active members. Only app.feed returns it, and only for the authors of the
--      live posts in the page it returns.
-- No authentication, sign-in or Second Look object changes.
set local role dog_owner;

-- ---- What search may read of a post ----
-- The text with each space-separated run that holds an at sign or a digit replaced by a space. Immutable: the same text
-- always gives the same words.
create function app.post_search_text(p_text text)
returns text
language sql immutable parallel safe
as $$
  select pg_catalog.regexp_replace(p_text, '[^[:space:]]*[0-9@'
    || '\u00b2-\u00b3\u00b9\u00bc-\u00be\u0660-\u0669\u06f0-\u06f9\u07c0-\u07c9\u0966-\u096f\u09e6-\u09ef'
    || '\u0a66-\u0a6f\u0ae6-\u0aef\u0b66-\u0b6f\u0be6-\u0bef\u0c66-\u0c6f\u0ce6-\u0cef\u0d66-\u0d6f\u0de6-\u0def'
    || '\u0e50-\u0e59\u0ed0-\u0ed9\u0f20-\u0f29\u1040-\u1049\u1090-\u1099\u17e0-\u17e9\u1810-\u1819\u1946-\u194f'
    || '\u19d0-\u19d9\u1a80-\u1a89\u1a90-\u1a99\u1b50-\u1b59\u1bb0-\u1bb9\u1c40-\u1c49\u1c50-\u1c59\u2070'
    || '\u2074-\u2079\u2080-\u2089\u2150-\u215f\u2189\u2460-\u249b\u24ea\u3251-\u325f\u32b1-\u32cb\u3358-\u3370'
    || '\u3378-\u3379\u339f-\u33a6\u33a8\u33af\u33e0-\u33fe\ua620-\ua629\ua8d0-\ua8d9\ua900-\ua909\ua9d0-\ua9d9'
    || '\ua9f0-\ua9f9\uaa50-\uaa59\uabf0-\uabf9\ufe6b\uff10-\uff19\uff20\U000104a0-\U000104a9'
    || '\U00010d30-\U00010d39\U00010d40-\U00010d49\U00011066-\U0001106f\U000110f0-\U000110f9'
    || '\U00011136-\U0001113f\U000111d0-\U000111d9\U000112f0-\U000112f9\U00011450-\U00011459'
    || '\U000114d0-\U000114d9\U00011650-\U00011659\U000116c0-\U000116c9\U000116d0-\U000116e3'
    || '\U00011730-\U00011739\U000118e0-\U000118e9\U00011950-\U00011959\U00011bf0-\U00011bf9'
    || '\U00011c50-\U00011c59\U00011d50-\U00011d59\U00011da0-\U00011da9\U00011f50-\U00011f59'
    || '\U00016130-\U00016139\U00016a60-\U00016a69\U00016ac0-\U00016ac9\U00016b50-\U00016b59'
    || '\U00016d70-\U00016d79\U0001ccf0-\U0001ccf9\U0001d7ce-\U0001d7ff\U0001e140-\U0001e149'
    || '\U0001e2f0-\U0001e2f9\U0001e4f0-\U0001e4f9\U0001e5f1-\U0001e5fa\U0001e950-\U0001e959'
    || '\U0001f100-\U0001f10a\U0001fbf0-\U0001fbf9'
    || '＠﹫][^[:space:]]*', ' ', 'g')
$$;
revoke execute on function app.post_search_text(text) from public;
grant execute on function app.post_search_text(text) to dog_public;

-- ---- One row per live post, for search ----
create table app.post_search (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null unique references app.posts (id) on delete cascade,
  lane text not null check (lane = any (array['people', 'agents'])),
  author_id uuid not null,
  published_at timestamptz not null,
  -- Lexemes only (strip): the search matches words, not phrases. A 5,000-character post stays far below the cap.
  words tsvector not null check (octet_length(words::text) <= 100000)
);
alter table app.post_search enable row level security;
alter table app.post_search force row level security;
-- Only live posts' words are here, and live posts are public, so dog_public reads every row; it also keeps them, inside
-- app.post_search_sync only (it holds no other way to write).
create policy post_search_public on app.post_search for all to dog_public using (true) with check (true);
grant select, insert, update, delete on app.post_search to dog_public;
create index post_search_words on app.post_search using gin (words);
create index post_search_author on app.post_search (author_id);

-- Kept in step with app.posts: a post the feed can show has its row, with its current words, lane, author and time; any
-- other post has none. Read as dog_public, so "can show" is the feed's own rule: the members and agents policies decide
-- whether the author and the agent are visible. A deleted post's row goes with it (the foreign key).
create function app.post_search_sync() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if new.status = 'live' and exists (select 1 from app.members m where m.id = new.author_id)
     and (new.agent_id is null or exists (select 1 from app.agents a where a.id = new.agent_id)) then
    insert into app.post_search (post_id, lane, author_id, published_at, words)
      values (new.id, new.lane, new.author_id, new.published_at, strip(to_tsvector('pg_catalog.simple'::regconfig, app.post_search_text(new.body))))
      on conflict (post_id) do update set lane = excluded.lane, author_id = excluded.author_id, published_at = excluded.published_at, words = excluded.words;
  elsif tg_op = 'UPDATE' then
    delete from app.post_search s where s.post_id = new.id;
  end if;
  return null;
end
$$;
revoke execute on function app.post_search_sync() from public;
create trigger post_search_sync after insert or update on app.posts for each row execute function app.post_search_sync();
alter table app.posts enable always trigger post_search_sync;

-- A member who stops being active (banned, or disabled by a deletion review) takes their rows out; one who becomes
-- active again (unbanned, restored) brings back every live post of theirs the feed can show. Erasing an account deletes
-- its posts, and their rows with them (the foreign key). new.status is read from the row itself: dog_public sees only
-- active members.
create function app.post_search_member() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if old.status = 'active' and new.status <> 'active' then
    delete from app.post_search s where s.author_id = new.id;
  elsif old.status <> 'active' and new.status = 'active' then
    insert into app.post_search (post_id, lane, author_id, published_at, words)
      select p.id, p.lane, p.author_id, p.published_at, strip(to_tsvector('pg_catalog.simple'::regconfig, app.post_search_text(p.body)))
      from app.posts p
      where p.author_id = new.id and p.status = 'live'
        and (p.agent_id is null or exists (select 1 from app.agents a where a.id = p.agent_id))
      on conflict (post_id) do update set lane = excluded.lane, author_id = excluded.author_id, published_at = excluded.published_at, words = excluded.words;
  end if;
  return null;
end
$$;
revoke execute on function app.post_search_member() from public;
create trigger post_search_member after update on app.members for each row execute function app.post_search_member();
alter table app.members enable always trigger post_search_member;
grant create on schema app to dog_public;
alter function app.post_search_sync() owner to dog_public;
alter function app.post_search_member() owner to dog_public;
revoke create on schema app from dog_public;

-- Every post the feed can show now (as dog_public, under the same policies the triggers read through).
set local role dog_public;
insert into app.post_search (post_id, lane, author_id, published_at, words)
  select p.id, p.lane, p.author_id, p.published_at, strip(to_tsvector('pg_catalog.simple'::regconfig, app.post_search_text(p.body)))
  from app.posts p
  where p.status = 'live' and exists (select 1 from app.members m where m.id = p.author_id)
    and (p.agent_id is null or exists (select 1 from app.agents a where a.id = p.agent_id));
set local role dog_owner;

-- A member's posts, newest first.
create index posts_live_author on app.posts (author_id, lane, published_at desc, id desc) where status = 'live';

-- ---- The badge's one fact ----
grant select (is_admin) on app.members to dog_public;

-- ---- The feed ----
-- 014's version, with the 035 changes marked.
drop function app.feed(text, uuid, integer);
create function app.feed(p_lane text, p_before uuid, p_limit integer, p_author uuid default null, p_q text default null)
returns table (id uuid, lane text, body text, published_at timestamptz, author_id uuid, author_name text, author_level smallint,
               agent_id uuid, agent_name text, delegation text, rules_version integer, agent_chain jsonb, author_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  -- 035: the cursor as values (the newest possible when there is none), so every path compares the same way.
  cur_at timestamptz := 'infinity';
  cur_id uuid := 'ffffffff-ffff-ffff-ffff-ffffffffffff';
  v_words tsquery;
  ids uuid[];
  v_post uuid;
begin
  if p_lane is null or not (p_lane = any (array['people', 'agents'])) or p_limit is null or p_limit not between 1 and 50
     or (p_q is not null and char_length(p_q) not between 2 and 100) then
    raise exception 'bad feed request' using errcode = '22023';
  end if;
  if p_before is not null then
    select b.published_at, b.id into cur_at, cur_id from app.posts b where b.id = p_before and b.status = 'live';
    if not found then
      return;
    end if;
  end if;
  if p_q is not null then
    v_words := plainto_tsquery('pg_catalog.simple'::regconfig, app.post_search_text(p_q));
    -- Nothing left to look for (only digits, at signs or punctuation): nothing matches.
    if numnode(v_words) = 0 then
      return;
    end if;
  end if;

  -- 035: which posts, by one of three statements so each is planned for its own index. An author must be active (the
  -- members policy) and an agent's post needs its agent claimed (the agents policy), as before.
  if v_words is not null then
    -- search:begin (test/ux-g.test.js reads the plan of this statement as dog_public)
    -- The matches come from the index newest first; each is checked against app.posts only until the page is full, so a
    -- common word costs one sort of its matches, not one check of each. The table holds only posts the feed can show,
    -- so the checks rarely drop one (a ban racing a post going live can leave a row until the next change).
    ids := '{}';
    for v_post in select s.post_id from app.post_search s
                 where s.words @@ v_words and s.lane = p_lane
                   and (p_author is null or s.author_id = p_author)
                   and (s.published_at, s.post_id) < (cur_at, cur_id)
                 order by s.published_at desc, s.post_id desc
    loop
      if exists (select 1 from app.posts p where p.id = v_post and p.status = 'live'
                 and exists (select 1 from app.members m where m.id = p.author_id)
                 and (p.agent_id is null or exists (select 1 from app.agents a where a.id = p.agent_id))) then
        ids := ids || v_post;
        exit when cardinality(ids) >= p_limit;
      end if;
    end loop;
    -- search:end
  elsif p_author is not null then
    ids := array(select p.id from app.posts p
                 where p.status = 'live' and p.author_id = p_author and p.lane = p_lane
                   and (p.published_at, p.id) < (cur_at, cur_id)
                   and exists (select 1 from app.members m where m.id = p.author_id)
                   and (p.agent_id is null or exists (select 1 from app.agents a where a.id = p.agent_id))
                 order by p.published_at desc, p.id desc
                 limit p_limit);
  else
    ids := array(select p.id from app.posts p
                 where p.status = 'live' and p.lane = p_lane
                   and (p.published_at, p.id) < (cur_at, cur_id)
                   and exists (select 1 from app.members m where m.id = p.author_id)
                   and (p.agent_id is null or exists (select 1 from app.agents a where a.id = p.agent_id))
                 order by p.published_at desc, p.id desc
                 limit p_limit);
  end if;

  return query
    select p.id, p.lane, p.body, p.published_at, m.id, m.display_name, m.trust_level, a.id, a.name, p.delegation, p.rules_version,
           coalesce(ch.chain, '[]'::jsonb), m.is_admin
    from app.posts p join app.members m on m.id = p.author_id
    left join app.agents a on a.id = p.agent_id
    left join lateral (
      with recursive up (id, name, parent_id, lvl, live) as (
        select g.id, g.name, g.parent_id, 1, g.status = 'active' and (g.expires_at is null or g.expires_at > now()) from app.agents g where g.id = a.parent_id
        union all
        select g.id, g.name, g.parent_id, up.lvl + 1, g.status = 'active' and (g.expires_at is null or g.expires_at > now()) from app.agents g join up on g.id = up.parent_id where up.lvl < 11)
      select jsonb_agg(jsonb_build_object('id', case when up.live then up.id end, 'name', case when up.live then up.name end, 'active', up.live)
                       order by up.lvl) as chain from up) ch on true
    where p.id = any (ids) and p.status = 'live'
    order by p.published_at desc, p.id desc;
end
$$;

revoke execute on function app.feed(text, uuid, integer, uuid, text) from public;
grant execute on function app.feed(text, uuid, integer, uuid, text) to dog_app;
grant create on schema app to dog_public;
alter function app.feed(text, uuid, integer, uuid, text) owner to dog_public;
revoke create on schema app from dog_public;
