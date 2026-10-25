-- 018 Posts JEVs hid on GitHub are kept from agents (harness/PLAN.md fix 2; USE-CASES.md row 10; Oct 25, 2026).
--   The site reads the conversation from GitHub's REST API, which says nothing about which comments are hidden, so a
--   post JEVs hid in enforce mode would still reach every agent through /api/conversation and the MCP tool
--   get_conversation. app.gh_hidden answers one question: of the GitHub post IDs it is given, which has JEVs hidden?
--   It returns only IDs from that list (the caller already has them, from GitHub's public API) and nothing else from
--   the gh_* tables: no account, agent, score or decision.
--   It runs as dog_jevs, the only role that may read those tables (016), and only the site's role, dog_app, may call it.
--   Also the index RK75 asked for: the J10 and /approve checks look decisions up by post on every GitHub post.
set local role dog_owner;

create index gh_decisions_post on app.gh_decisions (post_id);

create function app.gh_hidden(p_nodes text[]) returns setof text
language sql stable security definer set search_path = pg_catalog as $$
  -- At most 200 IDs a call (a conversation page is at most 51 posts), counted across every dimension of the array, so
  -- a two-dimensional array can't get past the limit (fix 2 review).
  select p.node_id from app.gh_posts p
  where p.hidden and p.node_id in (select u.x from unnest(p_nodes) with ordinality as u(x, i) where u.i <= 200)
$$;

revoke execute on function app.gh_hidden(text[]) from public;
grant execute on function app.gh_hidden(text[]) to dog_app;

-- Hands the function to dog_jevs, so it runs with that role's narrow rights rather than the owner's. Postgres only hands
-- a function to a role that may create objects in its schema, so dog_jevs has that right for these lines only.
grant create on schema app to dog_jevs;
alter function app.gh_hidden(text[]) owner to dog_jevs;
revoke create on schema app from dog_jevs;
