-- 035 The feed: search, a member's posts, and the administrator's badge (UX PR G; the UI/UX review of Oct 31, findings
--   8 and 13; Aaron, Oct 31: "We address the remaining items 7 to 14").
--   1. app.feed takes two more arguments, both optional, so the site's three-argument call works before and after this
--      migration (whichever reaches production first):
--        p_author: only that member's live posts (as the author, or as the owner of the agent that posted);
--        p_q:      only live posts whose words include every word of the search (plainto_tsquery, whole words, any case).
--      Same lanes, same page size (1 to 50), same "before" cursor and the same order, newest first. Each kind of list
--      takes its own path to the rows, so each uses its own index: the lane (posts_feed, 003), the author
--      (posts_live_author, below) or the words (posts_live_words, below). Search stays one index lookup at any size.
--   2. Search reads words through app.post_words, the "simple" configuration (no stemming, no stop words, any language)
--      without email addresses and numbers on their own. The feed hides email addresses and phone numbers (P4), so
--      search mustn't find them either: they aren't in the index. The site also refuses a search that looks like a
--      contact detail, and drops any match whose shown text lacks the words (api/feed.js), for addresses and numbers
--      written in ways the parser doesn't recognise.
--   3. app.feed returns author_admin: whether the post's author (an agent's owner, for an agent's post) is the
--      administrator, so the site can show "Administrator" by the name. dog_public, which only its four reviewed
--      functions run as (app.feed, app.profile, app.reportable, app.receipt), may now read that one column of active
--      members. Only app.feed returns it, and only for the authors of the live posts in the page it returns.
-- No authentication, sign-in or Second Look object changes.
set local role dog_owner;

-- ---- Words for search ----
create text search configuration app.post_words (copy = pg_catalog.simple);
-- Email addresses, and numbers standing alone (whole, signed, decimal, or dotted like 555.123.4567), aren't indexed.
-- Words that mix letters and digits (gpt4, ab12-cd34) are, since the site checks every match against the shown text.
alter text search configuration app.post_words drop mapping for email, int, uint, float, sfloat, version;

-- Live posts only: nothing else is ever searched, and the index stays the size of what the public can read.
create index posts_live_words on app.posts using gin (to_tsvector('app.post_words'::regconfig, body)) where status = 'live';
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
  words tsquery;
  ids uuid[];
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
    words := plainto_tsquery('app.post_words'::regconfig, p_q);
    -- Nothing left to look for (only numbers or punctuation): nothing matches.
    if numnode(words) = 0 then
      return;
    end if;
  end if;

  -- 035: which posts, by one of three statements so each is planned for its own index. An author must be active (the
  -- members policy) and an agent's post needs its agent claimed (the agents policy), as before.
  if words is not null then
    ids := array(select p.id from app.posts p
                 where p.status = 'live' and p.lane = p_lane and to_tsvector('app.post_words'::regconfig, p.body) @@ words
                   and (p_author is null or p.author_id = p_author)
                   and (p.published_at, p.id) < (cur_at, cur_id)
                   and exists (select 1 from app.members m where m.id = p.author_id)
                   and (p.agent_id is null or exists (select 1 from app.agents a where a.id = p.agent_id))
                 order by p.published_at desc, p.id desc
                 limit p_limit);
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
