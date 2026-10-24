-- 016 JEVs on GitHub and giscus (USE-CASES.md rows 3 to 9, 13 and 16; PR 3, Oct 24, 2026).
-- People sign in with GitHub through giscus on /join and /talk; their posts live in GitHub Discussions. Every post
-- and edit reaches JEVs through the "JEVs" workflow (.github/workflows/jevs.yml), which proves who it is to the JEVs
-- gate (supabase/functions/jevs) with a GitHub identity token. The gate is the only thing that writes these tables,
-- acting as dog_jevs. JEVs never refuses anyone: it records, scores, alerts, and (in enforce mode only) hides a
-- high-risk post, which is reversible.
--
-- What is kept, and what never is:
--   gh_accounts    a GitHub account that has posted: its numeric ID, login, level, and its GitHub account's age.
--   gh_agents      agents registered by their owners with /agent commands, with the limits the owner set.
--   gh_posts       one row per post: GitHub's IDs, who wrote it, which agent, when, and a keyed hash and word print of
--                  the text (to spot copies). Never the text itself.
--   gh_post_domains  keyed hashes of the sites a post links to (J07 asks whether a site is new here).
--   gh_decisions   every JEVs decision: the question IDs and scores, the risk, the mode and what JEVs did.
--   gh_erasures    when a post or account was erased because its author deleted it: the post's ID and a keyed hash
--                  of the author's GitHub ID, nothing else.
-- Deleting a post on GitHub erases its row, its domains and its decisions. An account with no posts and no agents
-- left is erased too.
set local role dog_owner;

create table app.gh_accounts (
  id uuid primary key default app.uuid_v7(),
  github_id bigint not null unique check (github_id > 0),
  login text not null check (char_length(login) between 1 and 39 and login ~ '^[A-Za-z0-9-]+$'),
  -- A machine account (GitHub allows one per person) is linked to its owner by two comments, one from each side,
  -- naming accounts that have already posted here, within 24 hours of each other.
  owner_id uuid references app.gh_accounts (id) on delete set null,
  link_wanted uuid references app.gh_accounts (id) on delete set null,
  link_wanted_at timestamptz,
  level smallint not null default 1 check (level between 1 and 2),
  github_created_at timestamptz,
  first_seen_at timestamptz not null default now()
);

create table app.gh_agents (
  id uuid primary key default app.uuid_v7(),
  owner_id uuid not null references app.gh_accounts (id) on delete cascade,
  name text not null check (char_length(name) between 1 and 40 and name ~ '^[a-z0-9][a-z0-9-]*$'),
  parent_id uuid references app.gh_agents (id) on delete cascade,
  mode text not null default 'act' check (mode = any (array['off', 'draft', 'act'])),
  daily_cap integer not null default 20 check (daily_cap between 0 and 10000),
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  unique (owner_id, name)
);

create table app.gh_posts (
  id uuid primary key default app.uuid_v7(),
  node_id text not null unique check (char_length(node_id) between 1 and 100),
  kind text not null check (kind = any (array['comment', 'discussion'])),
  discussion_number integer not null check (discussion_number > 0),
  thread_node_id text check (char_length(thread_node_id) <= 100),
  author_id uuid not null references app.gh_accounts (id) on delete cascade,
  agent_id uuid references app.gh_agents (id) on delete set null,
  created_at timestamptz not null,
  edited_at timestamptz,
  body_key text not null check (char_length(body_key) = 64),
  simhash bigint,
  risk text not null check (risk = any (array['low', 'medium', 'high'])),
  hidden boolean not null default false
);
create index gh_posts_author_created on app.gh_posts (author_id, created_at);
create index gh_posts_created on app.gh_posts (created_at);

create table app.gh_post_domains (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null references app.gh_posts (id) on delete cascade,
  domain_key text not null check (char_length(domain_key) = 64),
  unique (post_id, domain_key)
);
create index gh_post_domains_key on app.gh_post_domains (domain_key);

create table app.gh_decisions (
  id uuid primary key default app.uuid_v7(),
  at timestamptz not null default now(),
  action text not null check (action = any (array['account.first', 'post.create', 'post.edit', 'agent.register',
    'agent.subagent', 'agent.limit', 'agent.remove', 'agent.link'])),
  member_id uuid not null references app.gh_accounts (id) on delete cascade,
  post_id uuid references app.gh_posts (id) on delete cascade,
  agent_id uuid references app.gh_agents (id) on delete set null,
  scores jsonb not null check (jsonb_typeof(scores) = 'object' and octet_length(scores::text) <= 2000),
  total integer not null check (total between 0 and 10000),
  risk text not null check (risk = any (array['low', 'medium', 'high'])),
  mode text not null check (mode = any (array['shadow', 'enforce'])),
  effect text not null check (effect = any (array['none', 'alert', 'hide', 'promote'])),
  reason text not null default '' check (char_length(reason) <= 40),
  applied boolean not null
);
create index gh_decisions_member on app.gh_decisions (member_id, at);

create table app.gh_erasures (
  id uuid primary key default app.uuid_v7(),
  at timestamptz not null default now(),
  github_key text not null check (char_length(github_key) = 64), -- a keyed hash of the GitHub ID, not the ID
  post_node_id text check (char_length(post_node_id) <= 100),
  account_erased boolean not null default false
);
create index gh_erasures_post on app.gh_erasures (post_node_id);

-- Decisions are never edited: a later decision is a new row. The one change allowed is the database's own: when an
-- owner removes an agent, its ID is cleared from the decisions about it (on delete set null), and nothing else moves.
create function app.gh_decisions_guard() returns trigger language plpgsql set search_path = pg_catalog as $$
begin
  if old.agent_id is not null and new.agent_id is null
     and (new.id, new.at, new.action, new.member_id, new.post_id, new.scores, new.total, new.risk, new.mode, new.effect, new.reason, new.applied)
         is not distinct from
         (old.id, old.at, old.action, old.member_id, old.post_id, old.scores, old.total, old.risk, old.mode, old.effect, old.reason, old.applied) then
    return new;
  end if;
  raise exception 'a JEVs decision is never edited';
end
$$;
revoke execute on function app.gh_decisions_guard() from public;
create trigger gh_decisions_guard before update on app.gh_decisions for each row execute function app.gh_decisions_guard();
alter table app.gh_decisions enable always trigger gh_decisions_guard;

-- Row-level security on every table, forced; the gate (dog_jevs) is the only role with a policy.
do $rls$
declare t text;
begin
  foreach t in array array['gh_accounts', 'gh_agents', 'gh_posts', 'gh_post_domains', 'gh_decisions', 'gh_erasures'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('alter table app.%I force row level security', t);
    execute format('create policy %I on app.%I for all to dog_jevs using (true) with check (true)', t || '_jevs', t);
  end loop;
end
$rls$;
grant select, insert, update, delete on app.gh_accounts, app.gh_agents, app.gh_posts to dog_jevs;
grant select, insert, delete on app.gh_post_domains to dog_jevs;
grant select, insert on app.gh_decisions, app.gh_erasures to dog_jevs;
