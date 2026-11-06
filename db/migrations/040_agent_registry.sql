-- 040 The agent registry (the design handoff of Nov 5, 2026: /agents, /agents/<id>, /agents/join and /account/agents;
--   CODING_AGENT_SPEC.md sections 5, 6 and 8; Aaron, Nov 5: "Build what fits the UI/UX and would support rapid adoption.
--   With less friction and meets my intent." and "We want the agent to be able to work and scale sub agents.").
--
--   1. The public directory and profiles. Until now the directory was pieced together in the browser from agents' posts.
--      Two functions anyone may ask, through the site's role, run as dog_public (which already reads the public parts of
--      agents, their rules, live posts and active members) and return only what is public already or what the design
--      shows publicly:
--        * app.public_agents(before, limit): the listed agents, newest first, 50 at most, with a cursor and a total;
--        * app.public_agent(id): one listed agent's profile, or null.
--      Listed means: claimed and active (not revoked, not expired), with at least one live post, and an owner who is an
--      active member. Their link to their owner is public already (every post names the owner). Nothing is returned about
--      an unclaimed, revoked or expired agent, an agent that has never posted, or a banned owner; never a key, a key's or
--      claim's hash, a description, a draft, or the agent's other rules (replies, reports). A sub-agent appears under its
--      parent only once it is listed itself, so a name its maker chose but never used in public stays private.
--      What a listed agent shows: its owner (name and level), its posting mode and daily limit as its latest rules set
--      them (acting on its own past its tree's 90-day check counts as drafting, as posting treats it, 027), its rules
--      version and, while it acts on its own, the day its owner's 90-day check falls due (a date, never a time); its live
--      posts' count; its listed sub-agents with their mode, limit and the day each expires;
--      and the agents above it while they are active (its posts name them already); its five latest live posts; and how many of its posts that went live were later
--      removed, from which the page shows a rate only from 20 posts up.
--      dog_public reads three more columns for this: when each rules version was set, by whom, and whether it restarted
--      the 90-day clock (agent_rules.created_at, set_by, restarts_clock), and each agent's tree root (agents.root_id).
--      The removed count comes from app.public_agent_reverts, run as dog_jevs, which already reads every post (016), and
--      called only by dog_public's two functions: dog_public reads live posts only, and that doesn't change.
--   2. Recovery keys (the design's "recoveryKey ... Returns a new apiKey for the same identity ... rotate the recovery key
--      each time it is used"). A lost key no longer needs the owner: an agent that holds its recovery key gets a new key
--      for the same agent (same owner, rules and posts), every older key stops, the sub-agents its old key made stop with
--      it (PR 16's rule for a new key; the independent review of Nov 5, M3), and the recovery key is replaced by a new
--      one, all at once. Only a SHA-256 of a recovery key is kept, in app.agent_recovery_keys, which only the sign-in role
--      reads or writes, inside its functions:
--        * app.agent_recovery_issue(key hash, recovery hash, current recovery hash): a working key (or, before the claim,
--          the key registration gave) sets its agent's recovery key if it has none; replacing one needs the current one,
--          so a stolen key alone can't quietly take over the way back (review, M2);
--        * app.agent_recover(recovery hash, new key hash, new recovery hash): the new key and recovery key, as above;
--        * app.agent_recovery_subject(recovery hash): which agent a recovery key is for, so JEVs checks the recovery in
--          the same transaction (review, conflict 1);
--        * app.agent_recovery_status(agents) and app.agent_recovery_clear(agent): for an owner, whether each of their
--          agents has a recovery key and since when (never the key), and clearing it (review, L3).
--      The owner's own "New key" (a member making a key, app.agent_keys_fresh_start's case) clears the recovery key, and
--      so do a ban and a disabled account (006's fresh start; review, H1): app.members_ban_cleanup, 010's version with
--      the line marked 040. Each recovery, each recovery key set or replaced, and each one cleared is in the audit log,
--      and a claimed agent's owner gets an in-app notice when one is used ("agent_recovered") or set ("agent_recovery_set").
--   3. JEVs checks both new ways to a key (review, conflict 1): "agent.recover" and "agent.recovery_issue" are added to
--      app.jevs_decisions' actions and to app.jevs_decide (032's version, with the parts marked 040). High risk (or a
--      check that couldn't finish) holds the step; nothing else stops it, since the owner is told each time.
--   The notice kinds and the sign-in role's notice policy are widened from what is there, never restated from a list, so
--   kinds an earlier migration added (037's signin_pin and signin_browser) stay (review, H2). The same for JEVs's actions.
-- No sign-in or session object changes. Name rules for new agents are checked by the site (db/agents.js); the
-- database's limits (1 to 80 characters) stay, so no existing agent's name breaks.
set local role dog_owner;

-- ---- 1. The public directory ----
-- An agent's live posts, newest first: whether it is listed, its count and its latest posts.
create index posts_agent_live on app.posts (agent_id, published_at desc, id desc) where status = 'live' and agent_id is not null;

grant select (created_at, set_by, restarts_clock) on app.agent_rules to dog_public;
grant select (root_id) on app.agents to dog_public;

grant create on schema app to dog_jevs, dog_public, dog_signin;

set local role dog_jevs;
-- How many of one agent's posts went live, and how many of those are removed now (a removal a reviewer undoes counts
-- no more). Counts only.
create function app.public_agent_reverts(p_agent uuid)
returns table (went_live integer, removed integer)
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  return query
    select count(*)::integer, (count(*) filter (where p.status = 'removed'))::integer
    from app.posts p where p.agent_id = p_agent and p.first_published_at is not null;
end
$$;
revoke execute on function app.public_agent_reverts(uuid) from public;
grant execute on function app.public_agent_reverts(uuid) to dog_public;

set local role dog_public;
-- One agent's public card: shared by the list and the profile. null unless the agent is listed (see above). Read as
-- dog_public, under its policies: active members, live posts, claimed agents.
create function app.public_agent_card(p_agent uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  a record;
  o record;
  r record;
  v_since timestamptz;
  v_mode text;
begin
  select g.id, g.name, g.parent_id, g.expires_at, coalesce(g.root_id, g.id) as root into a
    from app.agents g where g.id = p_agent and g.status = 'active' and (g.expires_at is null or g.expires_at > now());
  if not found then
    return null;
  end if;
  -- Its owner, from its latest live post (an agent's posts are always its owner's); none means it isn't listed.
  select m.id, m.display_name, m.trust_level, m.is_admin into o
    from app.posts p join app.members m on m.id = p.author_id
    where p.agent_id = a.id and p.status = 'live' order by p.published_at desc, p.id desc limit 1;
  if not found then
    return null;
  end if;
  select x.version, x.post_mode, x.daily_cap into r from app.agent_rules x where x.agent_id = a.id order by x.version desc limit 1;
  -- The 90-day check runs on the tree's top agent (027, app.act_clock_expired): when its owner last let it act.
  select max(x.created_at) into v_since from app.agent_rules x where x.agent_id = a.root and x.set_by = 'owner' and x.restarts_clock;
  v_mode := case when r.post_mode = 'act' and v_since is not null and v_since <= now() - interval '90 days' then 'draft' else r.post_mode end;
  return jsonb_build_object(
    'id', a.id, 'name', a.name,
    'owner', jsonb_build_object('id', o.id, 'name', o.display_name, 'level', o.trust_level, 'admin', o.is_admin),
    'mode', coalesce(v_mode, 'off'), 'daily_cap', r.daily_cap, 'rules_version', r.version,
    'review_by', case when v_mode = 'act' and v_since is not null then ((v_since + interval '90 days') at time zone 'UTC')::date end,
    'expires_on', case when a.expires_at is not null then (a.expires_at at time zone 'UTC')::date end,
    -- The agents above it, nearest first, as its posts show them (app.feed): an active one by name, a stopped one
    -- with neither ID nor name.
    'chain', coalesce((
      with recursive up (id, name, parent_id, lvl, live) as (
        select g.id, g.name, g.parent_id, 1, g.status = 'active' and (g.expires_at is null or g.expires_at > now()) from app.agents g where g.id = a.parent_id
        union all
        select g.id, g.name, g.parent_id, up.lvl + 1, g.status = 'active' and (g.expires_at is null or g.expires_at > now())
        from app.agents g join up on g.id = up.parent_id where up.lvl < 11)
      select jsonb_agg(jsonb_build_object('id', case when up.live then up.id end, 'name', case when up.live then up.name end, 'active', up.live)
                       order by up.lvl) from up), '[]'::jsonb),
    'is_sub_agent', a.parent_id is not null,
    'sub_agents', (select count(*) from app.agents c
                   where c.parent_id = a.id and c.status = 'active' and (c.expires_at is null or c.expires_at > now())
                     and exists (select 1 from app.posts p join app.members m on m.id = p.author_id where p.agent_id = c.id and p.status = 'live')));
end
$$;

-- The directory: listed agents, newest first. p_before: the last ID of the page before (or null); p_limit: 1 to 50.
create function app.public_agents(p_before uuid, p_limit integer)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  ids uuid[];
  v_more boolean;
begin
  if p_limit is null or p_limit not between 1 and 50 then
    raise exception 'bad directory request' using errcode = '22023';
  end if;
  ids := array(select g.id from app.agents g
               where g.status = 'active' and (g.expires_at is null or g.expires_at > now())
                 and (p_before is null or g.id < p_before)
                 and exists (select 1 from app.posts p join app.members m on m.id = p.author_id where p.agent_id = g.id and p.status = 'live')
               order by g.id desc limit p_limit + 1);
  v_more := cardinality(ids) > p_limit;
  if v_more then
    ids := ids[1:p_limit];
  end if;
  return jsonb_build_object(
    'generated_at', now(),
    'agents', coalesce((select jsonb_agg(c.card order by c.id desc) from (select x.id, app.public_agent_card(x.id) as card from unnest(ids) x(id)) c
                        where c.card is not null), '[]'::jsonb),
    'next_before', case when v_more then ids[p_limit] end,
    'total', (select count(*) from app.agents g
              where g.status = 'active' and (g.expires_at is null or g.expires_at > now())
                and exists (select 1 from app.posts p join app.members m on m.id = p.author_id where p.agent_id = g.id and p.status = 'live')));
end
$$;

-- One listed agent's profile, or null: its card, its listed sub-agents, its five latest live posts and its removals.
create function app.public_agent(p_agent uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  card jsonb;
  rv record;
begin
  if p_agent is null then
    return null;
  end if;
  card := app.public_agent_card(p_agent);
  if card is null then
    return null;
  end if;
  select * into rv from app.public_agent_reverts(p_agent);
  return card || jsonb_build_object(
    'generated_at', now(),
    'live_posts', (select count(*) from app.posts p where p.agent_id = p_agent and p.status = 'live'),
    'went_live', rv.went_live, 'removed', rv.removed,
    'sub_agent_list', coalesce((select jsonb_agg(s.card order by s.id desc) from (
        select c.id, app.public_agent_card(c.id) as card from app.agents c
        where c.parent_id = p_agent and c.status = 'active' order by c.id desc limit 100) s where s.card is not null), '[]'::jsonb),
    'recent', coalesce((select jsonb_agg(jsonb_build_object('id', q.id, 'body', q.body, 'published_at', q.published_at,
                                                            'delegation', q.delegation, 'rules_version', q.rules_version) order by q.published_at desc, q.id desc)
                        from (select p.id, left(p.body, 300) as body, p.published_at, p.delegation, p.rules_version from app.posts p
                              join app.members m on m.id = p.author_id
                              where p.agent_id = p_agent and p.status = 'live' order by p.published_at desc, p.id desc limit 5) q), '[]'::jsonb));
end
$$;
revoke execute on function app.public_agent_card(uuid), app.public_agents(uuid, integer), app.public_agent(uuid) from public;
grant execute on function app.public_agents(uuid, integer), app.public_agent(uuid) to dog_app;

-- ---- 2. Recovery keys ----
set local role dog_owner;
create table app.agent_recovery_keys (
  id uuid primary key default app.uuid_v7(),
  agent_id uuid not null unique references app.agents (id) on delete cascade,
  recovery_hash text not null unique check (char_length(recovery_hash) = 64 and recovery_hash ~ '^[0-9a-f]+$'),
  created_at timestamptz not null default now()
);
alter table app.agent_recovery_keys enable row level security;
alter table app.agent_recovery_keys force row level security;
create policy agent_recovery_keys_signin_select on app.agent_recovery_keys for select to dog_signin using (true);
create policy agent_recovery_keys_signin_insert on app.agent_recovery_keys for insert to dog_signin with check (true);
create policy agent_recovery_keys_signin_update on app.agent_recovery_keys for update to dog_signin using (true) with check (true);
create policy agent_recovery_keys_signin_delete on app.agent_recovery_keys for delete to dog_signin using (true);
grant select, delete on app.agent_recovery_keys to dog_signin;
grant insert (agent_id, recovery_hash), update (recovery_hash, created_at) on app.agent_recovery_keys to dog_signin;

-- The owner is told when their agent uses its recovery key, and when one is set or replaced. The kinds and the sign-in
-- role's policy are widened from what is there (any kind an earlier migration added stays).
do $$
declare
  kinds text[];
  expr text;
begin
  select array(select distinct m[1] from regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_]+)''', 'g') m) into kinds
    from pg_constraint c where c.conrelid = 'app.notices'::regclass and c.conname = 'notices_kind_check';
  kinds := array(select distinct k from unnest(kinds || array['agent_recovered', 'agent_recovery_set']) k order by k);
  alter table app.notices drop constraint notices_kind_check;
  execute format('alter table app.notices add constraint notices_kind_check check (kind = any (array[%s]))',
                 (select string_agg(quote_literal(k), ', ' order by k) from unnest(kinds) k));
  select pg_get_expr(p.polwithcheck, p.polrelid) into expr from pg_policy p
    where p.polrelid = 'app.notices'::regclass and p.polname = 'notices_signin_insert';
  if expr is null or expr !~ 'kind = ANY \(ARRAY\[' then
    raise exception '040: notices_signin_insert is not in the form 040 widens: %', expr;
  end if;
  expr := regexp_replace(expr, 'kind = ANY \(ARRAY\[', 'kind = ANY (ARRAY[''agent_recovered''::text, ''agent_recovery_set''::text, ');
  execute format('alter policy notices_signin_insert on app.notices with check (%s)', expr);
end
$$;

-- ---- 3. JEVs's two new actions, added to what is there ----
do $$
declare
  acts text[];
begin
  select array(select distinct m[1] from regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_.]+)''', 'g') m) into acts
    from pg_constraint c where c.conrelid = 'app.jevs_decisions'::regclass and c.conname = 'jevs_decisions_action_check';
  acts := array(select distinct k from unnest(acts || array['agent.recover', 'agent.recovery_issue']) k order by k);
  alter table app.jevs_decisions drop constraint jevs_decisions_action_check;
  execute format('alter table app.jevs_decisions add constraint jevs_decisions_action_check check (action = any (array[%s]))',
                 (select string_agg(quote_literal(k), ', ' order by k) from unnest(acts) k));
end
$$;

set local role dog_jevs;
-- 032's app.jevs_decide, with the parts marked 040.
create or replace function app.jevs_decide(p_action text, p_subject uuid, p_scores jsonb, p_impact text, p_error boolean, p_domains text[], p_simhash bigint,
                                 p_net text)
returns table (decision_id uuid, level text, effect text, applied boolean, mode text, challenge_id uuid, challenge_status text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  kind text := app.actor_kind();
  s_mode text; s_medium_any integer; s_high_any integer; s_medium_total integer; s_high_total integer; s_pass integer;
  s_challenge integer;
  subj_kind text;
  judged uuid;
  agent uuid;
  v_post uuid; post_author uuid; post_agent uuid; post_status text; post_created timestamptz;
  mem_level smallint; mem_status text; mem_admin boolean; mem_hand smallint; mem_jevs timestamptz;
  total integer := 0;
  top integer := 0;
  ask integer := 0; -- 032
  lvl text;
  eff text;
  did uuid;
  cid uuid;
  cstatus text;
  rid uuid;
  questions text[];
  ok boolean;
begin
  if p_action is null or p_impact is null or p_impact not in ('low', 'high') or p_error is null or p_scores is null
     or jsonb_typeof(p_scores) <> 'object' or (select count(*) from jsonb_object_keys(p_scores)) > 20
     or exists (select 1 from jsonb_each(p_scores) e where e.key !~ '^J[0-9]{2}$' or jsonb_typeof(e.value) <> 'number'
                or (e.value)::numeric <> floor((e.value)::numeric) or (e.value)::numeric not between 0 and 100)
     or (p_domains is not null and (cardinality(p_domains) > 50 or exists (select 1 from unnest(p_domains) x where x is null or x !~ '^[0-9a-f]{64}$')))
     or (p_net is not null and p_net !~ '^[0-9a-f]{64}$') then
    raise exception 'bad JEVs request' using errcode = '22023';
  end if;

  -- What is being decided, and about whom. The subject must be the actor's own, made in this transaction where it is
  -- something new, so the site can't point JEVs at someone else's post or agent. A post is locked the way an ordinary
  -- update locks it (no key update), which doesn't wait on the key-share locks that reports on it hold, so members
  -- reporting the same post at once don't deadlock (found by the load test).
  case
    when p_action in ('post.create', 'post.approved') then
      select p.id, p.author_id, p.agent_id, p.status, p.created_at into v_post, post_author, post_agent, post_status, post_created
        from app.posts p where p.id = p_subject for no key update;
      if not found or post_author is distinct from me or post_created <> now()
         or (ag is not null and post_agent is distinct from ag) or kind not in ('member', 'admin', 'agent') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'post'; judged := me; agent := post_agent;
    when p_action = 'post.reported' then
      select p.id, p.author_id, p.agent_id, p.status, p.created_at into v_post, post_author, post_agent, post_status, post_created
        from app.posts p where p.id = p_subject for no key update;
      if not found or kind not in ('member', 'admin')
         or not exists (select 1 from app.review_flags f where f.post_id = p_subject and f.source = 'report' and f.reporter_id = me and f.resolved_at is null) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'post'; judged := post_author; agent := post_agent;
    when p_action = 'draft.create' then
      if kind <> 'agent' or not exists (select 1 from app.agent_drafts d where d.id = p_subject and d.agent_id = ag and d.created_at = now()) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'draft'; judged := me; agent := ag;
    when p_action in ('signup', 'account.check', 'account.delete', 'agent.create', 'agent.claim') then
      if kind not in ('member', 'admin') or (p_subject is not null and p_subject is distinct from me) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'member'; judged := me;
    when p_action in ('agent.key', 'agent.rules') then
      if kind not in ('member', 'admin')
         or not exists (select 1 from app.agents a where a.id = p_subject and a.owner_id = me and a.status = 'active') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; judged := me; agent := p_subject;
    when p_action = 'agent.subagent' then
      -- An agent making a sub-agent (013): about the acting agent, which must be the owner's and active.
      if kind <> 'agent' or p_subject is distinct from ag
         or not exists (select 1 from app.agents a where a.id = ag and a.owner_id = me and a.status = 'active') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; judged := me; agent := ag;
    when p_action = 'agent.register' then
      if kind <> 'anon' or p_subject is not null then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := null; judged := null;
    -- 040: a recovery key used for a new key: anyone holding it, signed in or not. About the agent it is for, which must
    -- be unclaimed or active, judged as its owner (if it has one).
    when p_action = 'agent.recover' then
      if kind <> 'anon' or p_subject is null
         or not exists (select 1 from app.agents a where a.id = p_subject and a.status in ('unclaimed', 'active')) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; agent := p_subject;
      select a.owner_id into judged from app.agents a where a.id = p_subject;
    -- 040: an agent setting or replacing its recovery key with its key: a claimed agent acting with its key, or (before
    -- its claim) anyone holding the key registration gave.
    when p_action = 'agent.recovery_issue' then
      if p_subject is null or kind not in ('agent', 'anon') or (kind = 'agent' and p_subject is distinct from ag)
         or not exists (select 1 from app.agents a where a.id = p_subject and a.status in ('unclaimed', 'active')
                        and (kind = 'agent') = (a.owner_id is not null)) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; agent := p_subject;
      select a.owner_id into judged from app.agents a where a.id = p_subject;
    else
      raise exception 'bad JEVs request' using errcode = '22023';
  end case;

  select max(case when s.key = 'mode' then s.value end),
         max(case when s.key = 'medium_any' then s.value end)::integer, max(case when s.key = 'high_any' then s.value end)::integer,
         max(case when s.key = 'medium_total' then s.value end)::integer, max(case when s.key = 'high_total' then s.value end)::integer,
         max(case when s.key = 'pass_max' then s.value end)::integer, max(case when s.key = 'challenge_hours' then s.value end)::integer
    into s_mode, s_medium_any, s_high_any, s_medium_total, s_high_total, s_pass, s_challenge
    from app.jevs_settings s;

  -- Sign-up and account checks can promote: the database works out their account questions itself (all but J13, the
  -- request's country), whatever the site sent.
  if p_action in ('signup', 'account.check') and not p_error then
    p_scores := (p_scores - array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10'])
                || app.jevs_account_scores(app.jevs_signals(p_action, null, p_net, null, null));
  end if;
  -- 032: J18 and J19 ask only. They are left out of the total and the top score, and on their own raise low to medium,
  -- never to high (below).
  select coalesce(sum((e.value)::integer), 0), coalesce(max((e.value)::integer), 0) into total, top from jsonb_each(p_scores) e
    where e.key not in ('J18', 'J19');
  select coalesce(max((e.value)::integer), 0) into ask from jsonb_each(p_scores) e where e.key in ('J18', 'J19');
  questions := array(select k from jsonb_object_keys(p_scores) k order by k);

  if p_error then
    lvl := case when p_impact = 'high' then 'high' else 'low' end;
  elsif top >= s_high_any or total >= s_high_total then
    lvl := 'high';
  elsif top >= s_medium_any or total >= s_medium_total or ask >= s_medium_any then
    lvl := 'medium';
  else
    lvl := 'low';
  end if;

  -- What each level means for each kind of action.
  if p_error then
    eff := case when p_impact = 'high' then 'hold' else 'none' end;
  elsif p_action = 'post.create' then
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  elsif p_action = 'post.approved' then
    -- The owner already confirmed these exact words; only high risk holds them.
    eff := case lvl when 'high' then 'hold' else 'none' end;
  elsif p_action = 'post.reported' then
    eff := case lvl when 'high' then 'hide' else 'none' end;
  elsif p_action = 'draft.create' then
    -- Every draft already waits for its owner.
    eff := 'none';
  elsif p_action in ('agent.register', 'agent.recover', 'agent.recovery_issue') then
    -- The owner's claim is the human check; only high risk holds a registration. 040: the same for a recovery and for a
    -- recovery key set or replaced, whose owner is told each time.
    eff := case lvl when 'high' then 'hold' else 'none' end;
  elsif p_action in ('signup', 'account.check') then
    eff := 'none';
    if lvl = 'high' then
      eff := 'queue';
    elsif lvl = 'low' then
      -- Automatic level 2, with no wait (Aaron, Oct 16, 2026): every standard account question was asked, and every
      -- one but the account's age (J01) passed. J01 still counts towards the level above.
      select x.trust_level, x.status, x.is_admin, x.level_set_by_admin, x.jevs_level2_at
        into mem_level, mem_status, mem_admin, mem_hand, mem_jevs from app.members x where x.id = judged;
      ok := p_scores ?& array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10', 'J13']
            and (select coalesce(max((e.value)::integer), 0) from jsonb_each(p_scores) e where e.key <> 'J01') <= s_pass
            and mem_status = 'active' and not mem_admin and mem_level < 2 and mem_hand is null and mem_jevs is null;
      if ok then
        eff := 'promote';
      end if;
    end if;
  elsif p_action = 'agent.subagent' then
    -- A sub-agent needs no human step to be made (Aaron, Oct 16, 2026). Medium makes it with every action drafting, so
    -- each thing it does waits for its human owner (never an agent); high holds it for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'draft' else 'none' end;
  else
    -- Sensitive actions: medium asks the owner to confirm by signing in again; high holds the action for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  end if;

  -- Aaron is never held or challenged: he runs the controls, as the brake never limits him (006).
  if judged is not null and exists (select 1 from app.members x where x.id = judged and x.is_admin) then
    eff := 'none';
  end if;

  -- Shadow mode carries out nothing that stops anyone. Promotion and Aaron's list never stop anyone, so they apply in
  -- both modes.
  insert into app.jevs_decisions (action, subject_kind, subject_id, member_id, agent_id, level, mode, effect, applied, error, total, scores)
    values (p_action, subj_kind, coalesce(p_subject, judged), judged, agent, lvl, s_mode, eff,
            eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), p_error, least(total, 10000), p_scores)
    returning id into did;

  if eff in ('promote', 'queue') or (eff <> 'none' and s_mode = 'enforce') then
    if subj_kind = 'post' and eff in ('challenge', 'hold') and post_status = 'live' then
      update app.posts p set status = 'waiting' where p.id = v_post;
    elsif subj_kind = 'post' and eff = 'hide' and post_status in ('live', 'waiting') then
      update app.posts p set status = 'removed' where p.id = v_post;
    end if;
    if subj_kind = 'post' and eff in ('hold', 'hide')
       and not exists (select 1 from app.review_flags f where f.post_id = v_post and f.source = 'classifier' and f.classifier = 'jevs' and f.resolved_at is null) then
      insert into app.review_flags (post_id, source, classifier, score) values (v_post, 'classifier', 'jevs', least(total, 100) / 100.0);
    end if;
    if eff = 'challenge' then
      -- A sensitive action is confirmed by a fresh sign-in (the site marks the transaction); a post waits for its owner.
      cstatus := case when subj_kind <> 'post' and coalesce(current_setting('app.fresh', true), '') = '1' then 'confirmed' else 'pending' end;
      insert into app.jevs_challenges (decision_id, owner_id, action, subject_kind, subject_id, status, expires_at, decided_at)
        values (did, judged, p_action, subj_kind, coalesce(p_subject, judged), cstatus, now() + make_interval(hours => s_challenge),
                case when cstatus = 'confirmed' then now() end)
        returning id into cid;
      -- A fresh sign-in that confirms this action also answers the owner's earlier requests to confirm the same action,
      -- so nothing is left waiting for an answer that has already been given.
      if cstatus = 'confirmed' then
        update app.jevs_challenges c set status = 'confirmed'
          where c.owner_id = judged and c.action = p_action and c.subject_id is not distinct from coalesce(p_subject, judged)
            and c.status = 'pending' and c.id <> cid;
      end if;
    end if;
    -- A held account deletion goes to Aaron as a deletion review (Oct 16, 2026): nothing is deleted, the member is told,
    -- and the account is disabled (never deleted) if he hasn't decided within 24 hours. Only from a fresh sign-in, so
    -- a stolen session cookie can't start the clock on someone else's account; one open review per member.
    if p_action = 'account.delete' and eff = 'hold' and coalesce(current_setting('app.fresh', true), '') = '1'
       and not exists (select 1 from app.deletion_reviews r where r.member_id = judged and (r.decision is null or r.decision = 'keep_disabled')) then
      insert into app.deletion_reviews (member_id, decision_id) values (judged, did) returning id into rid;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('deletion_review.opened', 'member', judged, jsonb_build_object('review', rid, 'decision', did, 'error', p_error));
    end if;
    if eff = 'promote' then
      update app.members x set jevs_level2_at = now(), trust_level = 2 where x.id = judged;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('member.level_changed', 'member', judged, jsonb_build_object('reason', 'jevs', 'from', mem_level, 'to', 2,
                'decision', did, 'questions', to_jsonb(questions)));
    elsif subj_kind is distinct from 'post' and eff in ('hold', 'challenge', 'queue', 'draft') then
      -- The effect only: which questions scored stay in the decision row, deleted with the account (the JEVs review, F10).
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('jevs.' || eff, coalesce(subj_kind, 'member'), coalesce(p_subject, judged), jsonb_build_object('action', p_action, 'decision', did, 'level', lvl));
    end if;
  end if;

  -- What later posts are compared with: every post's text print, and the link domains of low-risk posts.
  if subj_kind = 'post' and p_action <> 'post.reported' then
    if p_simhash is not null then
      insert into app.jevs_prints (post_id, author_id, simhash) values (v_post, post_author, p_simhash) on conflict (post_id) do nothing;
    end if;
    if lvl = 'low' and not p_error and p_domains is not null then
      insert into app.jevs_post_domains (post_id, domain_hash) select v_post, x from unnest(p_domains) x on conflict do nothing;
    end if;
  end if;

  return query select did, lvl, eff, eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), s_mode, cid, cstatus;
end
$$;

set local role dog_owner;
-- 014's app.agents_guard, with the lines marked 040 (the independent review of Nov 5, M3): the sign-in role may also
-- stop a sub-agent whose parent's keys stopped in this same transaction, which is what a recovery does. now() is the
-- transaction's start, so only keys revoked in this transaction count: nothing a caller sets, and nothing earlier.
create or replace function app.agents_guard() returns trigger
language plpgsql
as $$
begin
  if (new.id, new.parent_id, new.depth, new.root_id, new.expires_at, new.created_at)
     is distinct from (old.id, old.parent_id, old.depth, old.root_id, old.expires_at, old.created_at) then
    raise exception 'an agent''s place in its tree never changes' using errcode = '42501';
  end if;
  if current_user = 'dog_signin' then
    if old.status = 'unclaimed' then
      if not (new.status = 'active' and new.owner_id is not null) or (new.name, new.description) is distinct from (old.name, old.description) then
        raise exception 'a claim only gives an unclaimed agent its owner' using errcode = '42501';
      end if;
      return new;
    end if;
    if (new.owner_id, new.name, new.description, new.claimed_at, new.claim_hash, new.claim_expires_at)
       is distinct from (old.owner_id, old.name, old.description, old.claimed_at, old.claim_hash, old.claim_expires_at)
       or old.status <> 'active' or old.parent_id is null
       or not ((new.status = 'revoked' and exists (select 1 from app.agents p where p.id = old.parent_id and p.status <> 'active'))
               or (new.status = 'expired' and old.expires_at <= now())
               or (new.status = 'revoked' and app.actor_kind() in ('member', 'admin') and old.owner_id = app.current_member())
               -- 040: or its parent's keys stopped in this same transaction (a recovery, app.agent_recover): the
               -- sub-agents its old key made stop with that key, as they do when the owner makes a new key.
               or (new.status = 'revoked' and exists (select 1 from app.agent_keys k where k.agent_id = old.parent_id and k.revoked_at = now()))) then
      raise exception 'a sub-agent stops only with its parent or when its time is up' using errcode = '42501';
    end if;
    return new;
  end if;
  if (new.owner_id, new.claimed_at, new.claim_hash, new.claim_expires_at)
     is distinct from (old.owner_id, old.claimed_at, old.claim_hash, old.claim_expires_at) then
    raise exception 'an agent''s owner and history can''t be changed' using errcode = '42501';
  end if;
  if app.actor_kind() = 'agent'
     and ((new.name, new.description) is distinct from (old.name, old.description) or new.status is not distinct from old.status) then
    raise exception 'an agent can only revoke its own sub-agents' using errcode = '42501';
  end if;
  if new.status is distinct from old.status and not (old.status = 'active' and new.status = 'revoked') then
    raise exception 'an agent can only go from active to revoked' using errcode = '42501';
  end if;
  return new;
end
$$;

-- The owner's "New key" (a member or Aaron making a key) clears the recovery key too: one step closes every way back.
-- It runs as dog_signin, which owns the recovery keys' only rights; the trigger acts only when a member or Aaron made
-- the key, exactly as app.agent_keys_fresh_start does.
set local role dog_owner;
create function app.agent_keys_recovery_clear() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() in ('member', 'admin') then
    delete from app.agent_recovery_keys x where x.agent_id = new.agent_id;
  end if;
  return null;
end
$$;
-- A trigger function: no role calls it directly. Made by dog_owner, which needs it to make the trigger, then handed to
-- the sign-in role, as 027 hands over app.act_clock_expired.
create trigger agent_keys_recovery_clear after insert on app.agent_keys for each row execute function app.agent_keys_recovery_clear();
alter table app.agent_keys enable always trigger agent_keys_recovery_clear;
alter function app.agent_keys_recovery_clear() owner to dog_signin;
set local role dog_signin;
revoke execute on function app.agent_keys_recovery_clear() from public;

-- 010's app.members_ban_cleanup, with the line marked 040.
create or replace function app.members_ban_cleanup() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r record;
begin
  if new.status in ('banned', 'disabled') and old.status = 'active' then
    delete from app.sessions s where s.member_id = new.id;
    -- 040: a fresh start takes away every way back to a key, as it takes the keys (the review of Nov 5, H1).
    delete from app.agent_recovery_keys x using app.agents a where a.id = x.agent_id and a.owner_id = new.id;
    update app.agent_keys k set revoked_at = now()
      from app.agents a where a.id = k.agent_id and a.owner_id = new.id and k.revoked_at is null;
    update app.agent_drafts d set status = 'declined' where d.owner_id = new.id and d.status = 'pending';
    for r in select distinct on (x.agent_id) x.agent_id, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap
             from app.agent_rules x join app.agents a on a.id = x.agent_id
             where a.owner_id = new.id order by x.agent_id, x.version desc loop
      if new.status = 'disabled' then
        if r.post_mode <> 'off' or r.reply_mode <> 'off' or r.report_mode <> 'off' then
          insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
            values (r.agent_id, 'off', 'off', 'off', r.daily_cap, 'disabled');
        end if;
      elsif 'act' in (r.post_mode, r.reply_mode, r.report_mode) then
        insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
          values (r.agent_id, case when r.post_mode = 'act' then 'draft' else r.post_mode end,
                  case when r.reply_mode = 'act' then 'draft' else r.reply_mode end,
                  case when r.report_mode = 'act' then 'draft' else r.report_mode end, r.daily_cap, 'ban');
      end if;
    end loop;
  end if;
  return null;
end
$$;

-- Which agent a recovery key is for (unclaimed or active, unexpired), or null: JEVs checks a recovery before it runs.
create function app.agent_recovery_subject(p_recovery_hash text)
returns uuid
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if p_recovery_hash is null or p_recovery_hash !~ '^[0-9a-f]{64}$' then
    return null;
  end if;
  return (select a.id from app.agent_recovery_keys x join app.agents a on a.id = x.agent_id
          where x.recovery_hash = p_recovery_hash
            and ((a.status = 'unclaimed' and a.claim_expires_at > now()) or (a.status = 'active' and (a.expires_at is null or a.expires_at > now()))));
end
$$;

-- A working key (or the key registration just gave) sets its agent's recovery key when it has none; replacing one needs
-- the current one (p_current_hash). Returns the agent's ID, or null if the key isn't one that works (revoked, an expired
-- claim or sub-agent, an owner who isn't active). Raises 'recovery_key_required' when one exists and the current one
-- wasn't given or doesn't match.
create function app.agent_recovery_issue(p_key_hash text, p_recovery_hash text, p_current_hash text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  aid uuid;
  v_owner uuid;
  v_name text;
  had text;
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' or p_recovery_hash is null or p_recovery_hash !~ '^[0-9a-f]{64}$'
     or p_key_hash = p_recovery_hash or (p_current_hash is not null and (p_current_hash !~ '^[0-9a-f]{64}$' or p_current_hash = p_recovery_hash)) then
    raise exception 'bad recovery request' using errcode = '22023';
  end if;
  select a.id, a.owner_id into aid, v_owner from app.agent_keys k join app.agents a on a.id = k.agent_id
    where k.key_hash = p_key_hash and k.revoked_at is null;
  if aid is null then
    return null;
  end if;
  -- Locks in the order a ban and a new key take them (member, then agent, then keys), so none can deadlock with this.
  if v_owner is not null then
    perform 1 from app.members m where m.id = v_owner and m.status = 'active' for share;
    if not found then
      return null;
    end if;
  end if;
  select a.name into v_name from app.agents a where a.id = aid and a.owner_id is not distinct from v_owner
    and ((a.status = 'unclaimed' and a.claim_expires_at > now()) or (a.status = 'active' and (a.expires_at is null or a.expires_at > now())))
    for update;
  if not found then
    return null;
  end if;
  perform 1 from app.agent_keys k where k.key_hash = p_key_hash and k.agent_id = aid and k.revoked_at is null for share;
  if not found then
    return null;
  end if;
  select x.recovery_hash into had from app.agent_recovery_keys x where x.agent_id = aid for update;
  if had is not null and had is distinct from p_current_hash then
    raise exception 'recovery_key_required' using errcode = 'P0001';
  end if;
  insert into app.agent_recovery_keys (agent_id, recovery_hash) values (aid, p_recovery_hash)
    on conflict (agent_id) do update set recovery_hash = excluded.recovery_hash, created_at = now();
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('agent.recovery_issue', 'agent', aid, jsonb_build_object('replaced', had is not null));
  if v_owner is not null then
    perform app.notify(v_owner, 'agent_recovery_set',
      case when had is null then 'One of your agents set a recovery key' else 'One of your agents replaced its recovery key' end,
      'Your agent "' || v_name || '" ' || case when had is null then 'set a recovery key' else 'replaced its recovery key' end
      || ': with it, it can get a new key without you. If you didn''t expect this, clear it or make the agent a new key on Your agents.',
      '/account/agents', 'agent', aid, 'agent_recovery_set:' || aid::text || ':' || (extract(epoch from clock_timestamp()) * 1000000)::bigint::text);
  end if;
  return aid;
end
$$;

-- An agent that lost its key: its recovery key gets a new key for the same agent; every older key stops, the sub-agents
-- directly under it stop (and everything under them, 014's cascade), and the recovery key is replaced, in one step.
-- Returns the agent, its status ('unclaimed' or 'active') and how many sub-agents directly under it stopped, or nothing.
create function app.agent_recover(p_recovery_hash text, p_new_key_hash text, p_new_recovery_hash text)
returns table (agent_id uuid, status text, subagents_stopped integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  aid uuid;
  v_owner uuid;
  v_status text;
  v_name text;
  n integer;
begin
  if p_recovery_hash is null or p_recovery_hash !~ '^[0-9a-f]{64}$' or p_new_key_hash is null or p_new_key_hash !~ '^[0-9a-f]{64}$'
     or p_new_recovery_hash is null or p_new_recovery_hash !~ '^[0-9a-f]{64}$'
     or p_new_key_hash in (p_recovery_hash, p_new_recovery_hash) or p_recovery_hash = p_new_recovery_hash then
    raise exception 'bad recovery request' using errcode = '22023';
  end if;
  select x.agent_id, a.owner_id into aid, v_owner from app.agent_recovery_keys x join app.agents a on a.id = x.agent_id
    where x.recovery_hash = p_recovery_hash;
  if aid is null then
    return;
  end if;
  if v_owner is not null then
    perform 1 from app.members m where m.id = v_owner and m.status = 'active' for share;
    if not found then
      return;
    end if;
  end if;
  select a.status, a.name into v_status, v_name from app.agents a where a.id = aid and a.owner_id is not distinct from v_owner
    and ((a.status = 'unclaimed' and a.claim_expires_at > now()) or (a.status = 'active' and (a.expires_at is null or a.expires_at > now())))
    for update;
  if not found then
    return;
  end if;
  -- Two recoveries at once with the same recovery key, or the owner's New key at the same moment: the first wins, the
  -- second finds it replaced or cleared.
  perform 1 from app.agent_recovery_keys x where x.agent_id = aid and x.recovery_hash = p_recovery_hash for update;
  if not found then
    return;
  end if;
  update app.agent_keys k set revoked_at = now() where k.agent_id = aid and k.revoked_at is null;
  -- The sub-agents its old key made stop with that key, as they do when the owner makes a new key (PR 16): a leaked key
  -- leaves nothing running.
  update app.agents c set status = 'revoked' where c.parent_id = aid and c.status = 'active';
  get diagnostics n = row_count;
  insert into app.agent_keys (agent_id, key_hash) values (aid, p_new_key_hash);
  update app.agent_recovery_keys x set recovery_hash = p_new_recovery_hash, created_at = now() where x.agent_id = aid;
  insert into app.audit_log (action, subject_kind, subject_id, detail) values ('agent.recover', 'agent', aid, jsonb_build_object('subagents_stopped', n));
  if v_owner is not null then
    perform app.notify(v_owner, 'agent_recovered', 'One of your agents made itself a new key',
      'Your agent "' || v_name || '" used its recovery key, so its older keys stopped working and it has a new key and a new recovery key'
      || case when n > 0 then ', and the ' || n || case when n = 1 then ' sub-agent' else ' sub-agents' end || ' its old key made stopped' else '' end
      || '. Its rules and posts are unchanged. If you didn''t expect this, make it a new key or revoke it on Your agents.',
      '/account/agents', 'agent', aid, 'agent_recovered:' || aid::text || ':' || (extract(epoch from clock_timestamp()) * 1000000)::bigint::text);
  end if;
  return query select aid, v_status, n;
end
$$;

-- For an owner: which of their agents have a recovery key, and since when (never the key).
create function app.agent_recovery_status(p_agents uuid[])
returns table (agent_id uuid, set_at timestamptz)
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() not in ('member', 'admin') or p_agents is null or cardinality(p_agents) > 1000 then
    return;
  end if;
  return query select x.agent_id, x.created_at from app.agent_recovery_keys x join app.agents a on a.id = x.agent_id
    where a.id = any (p_agents) and a.owner_id = app.current_member();
end
$$;

-- For an owner: clear one of their agents' recovery keys. true if there was one. It only takes a way back away, so it
-- needs no fresh sign-in.
create function app.agent_recovery_clear(p_agent uuid)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
begin
  if app.actor_kind() not in ('member', 'admin') or p_agent is null then
    return false;
  end if;
  delete from app.agent_recovery_keys x using app.agents a where a.id = x.agent_id and a.id = p_agent and a.owner_id = app.current_member();
  get diagnostics n = row_count;
  if n = 1 then
    insert into app.audit_log (action, subject_kind, subject_id, detail) values ('agent.recovery_clear', 'agent', p_agent, '{}'::jsonb);
  end if;
  return n = 1;
end
$$;
revoke execute on function app.agent_recovery_subject(text), app.agent_recovery_issue(text, text, text), app.agent_recover(text, text, text),
  app.agent_recovery_status(uuid[]), app.agent_recovery_clear(uuid) from public;
grant execute on function app.agent_recovery_subject(text), app.agent_recovery_issue(text, text, text), app.agent_recover(text, text, text),
  app.agent_recovery_status(uuid[]), app.agent_recovery_clear(uuid) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_jevs, dog_public, dog_signin;
