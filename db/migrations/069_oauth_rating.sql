-- 069 OAuth for agents, and the poster rating (Aaron, Nov 22, 2026: "an agent card, a poster rating, OAuth ... without
--   needing me to take any action but approving the PR"). Payments stay off.
--
--   1. OAuth 2.1 (authorization code with PKCE, public clients, dynamic client registration). An AI app (Claude,
--      ChatGPT, an open-model client) registers itself, sends its person to /oauth/authorize, and the person, signed
--      in on the site, approves it. Approving makes a new agent of theirs, through the site's own agent creation (JEVs,
--      the level-2 rule, a fresh sign-in to act alone), and its key becomes the app's access token: the same agent key
--      every acting route already checks, so nothing downstream changes, and the owner revokes it on /account/agents
--      like any agent. The key is never stored readable: the authorization code's row holds it sealed (AES-256-GCM)
--      under a key made from the code, which only the app receives, and only the code's hash is kept. No signing key,
--      no secret, no hosted service.
--   2. The poster rating: how fair a poster's checking has been. Every number is from their own record: tasks posted,
--      work they checked, their fails later overturned, disputes they opened that were dismissed, and how long they
--      take to check. Public, like the leaderboard.

set local role dog_owner;
create table app.oauth_clients (
  id uuid primary key default app.uuid_v7(),
  client_id text not null unique check (char_length(client_id) = 26 and client_id ~ '^doc_[A-Za-z0-9_-]{22}$'),
  name text not null check (char_length(name) between 1 and 80),
  created_at timestamptz not null default now()
);
-- Each return address on its own row, with its own limit (S8): 1 to 5 an app.
create table app.oauth_redirects (
  id uuid primary key default app.uuid_v7(),
  client uuid not null references app.oauth_clients (id) on delete cascade,
  uri text not null check (char_length(uri) between 8 and 500),
  unique (client, uri)
);
create table app.oauth_codes (
  id uuid primary key default app.uuid_v7(),
  code_hash text not null unique check (char_length(code_hash) = 64 and code_hash ~ '^[0-9a-f]+$'),
  client uuid not null references app.oauth_clients (id) on delete cascade,
  redirect_uri text not null check (char_length(redirect_uri) between 8 and 500),
  challenge text not null check (char_length(challenge) = 43 and challenge ~ '^[A-Za-z0-9_-]+$'),
  agent_id uuid not null references app.agents (id) on delete cascade,
  owner_id uuid not null references app.members (id) on delete cascade,
  sealed bytea not null check (octet_length(sealed) between 40 and 200),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz
);
create index oauth_codes_expiry on app.oauth_codes (expires_at);
alter table app.oauth_clients enable row level security;
alter table app.oauth_clients force row level security;
alter table app.oauth_codes enable row level security;
alter table app.oauth_codes force row level security;
alter table app.oauth_redirects enable row level security;
alter table app.oauth_redirects force row level security;
-- No role reads or writes these tables directly; the functions below, owned here, are the only way in.
-- The sign-in module's role (it already reads and revokes agents and their keys) owns the functions and uses the tables.
create policy oauth_clients_signin on app.oauth_clients for all to dog_signin using (true) with check (true);
create policy oauth_codes_signin on app.oauth_codes for all to dog_signin using (true) with check (true);
create policy oauth_redirects_signin on app.oauth_redirects for all to dog_signin using (true) with check (true);
grant select, insert, delete on app.oauth_clients, app.oauth_redirects to dog_signin;
grant select, insert, update, delete on app.oauth_codes to dog_signin;
reset role;
grant create on schema app to dog_signin;
set local role dog_signin;

-- Register a client (RFC 7591), public, no secret. Redirect addresses: https, or http on this computer only (RFC 8252).
create function app.oauth_register(p_id text, p_name text, p_redirects text[]) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare u text; cid uuid;
begin
  if p_id is null or p_id !~ '^doc_[A-Za-z0-9_-]{22}$' then raise exception 'bad client' using errcode = '22023'; end if;
  if p_name is null or char_length(btrim(p_name)) not between 1 and 80 or p_name ~ '[[:cntrl:]<>]' then
    raise exception 'invalid_client_metadata' using errcode = '22023', hint = 'client_name is 1 to 80 characters, without < or >.';
  end if;
  if p_redirects is null or cardinality(p_redirects) not between 1 and 5 then
    raise exception 'invalid_redirect_uri' using errcode = '22023', hint = 'Give 1 to 5 redirect_uris.';
  end if;
  foreach u in array p_redirects loop
    if u is null or char_length(u) > 500 or u ~ '[[:space:]#]'
       or not (u ~ '^https://[a-z0-9.-]+(:[0-9]+)?(/[^?]*)?(\?.*)?$' or u ~ '^http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?(/[^?]*)?(\?.*)?$') then
      raise exception 'invalid_redirect_uri' using errcode = '22023', hint = 'Each redirect URI is https, or http on localhost, with no fragment.';
    end if;
  end loop;
  insert into app.oauth_clients (client_id, name) values (p_id, btrim(p_name)) returning id into cid;
  insert into app.oauth_redirects (client, uri) select cid, x from (select distinct unnest(p_redirects) as x) d;
  return p_id;
end $$;

create function app.oauth_client(p_id text) returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object('client_id', c.client_id, 'client_name', c.name,
           'redirect_uris', (select coalesce(jsonb_agg(r.uri order by r.id), '[]'::jsonb) from app.oauth_redirects r where r.client = c.id))
    from app.oauth_clients c where c.client_id = p_id
$$;

-- The signed-in owner approved: keep the code's hash, with the agent's key sealed under the code, for 10 minutes.
create function app.oauth_code_put(p_code_hash text, p_client text, p_redirect text, p_challenge text, p_agent uuid, p_sealed bytea) returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); cid uuid;
begin
  if app.actor_kind() not in ('member', 'admin') or me is null then raise exception 'sign in to approve an app' using errcode = '42501'; end if;
  select c.id into cid from app.oauth_clients c join app.oauth_redirects r on r.client = c.id where c.client_id = p_client and r.uri = p_redirect;
  if cid is null then
    raise exception 'invalid_request' using errcode = '22023', hint = 'That app or its return address isn''t registered.';
  end if;
  if not exists (select 1 from app.agents g where g.id = p_agent and g.owner_id = me and g.status = 'active') then
    raise exception 'not your agent' using errcode = '42501';
  end if;
  insert into app.oauth_codes (code_hash, client, redirect_uri, challenge, agent_id, owner_id, sealed, expires_at)
    values (p_code_hash, cid, p_redirect, p_challenge, p_agent, me, p_sealed, now() + interval '10 minutes');
  delete from app.oauth_codes x where x.expires_at < now() - interval '1 day';
  perform app.audit_add('oauth.approved', 'member', me, jsonb_build_object('client', p_client, 'agent', p_agent), 'success');
end $$;

-- The token endpoint: one use, before it expires, by the same app and return address. Returns the challenge and the
-- sealed key; the site checks the PKCE verifier and opens the seal with the code. Null for anything wrong.
create function app.oauth_code_take(p_code_hash text, p_client text, p_redirect text) returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare x record;
begin
  select * into x from app.oauth_codes c where c.code_hash = p_code_hash for update;
  if x.code_hash is null or x.used_at is not null or x.expires_at <= now()
     or x.client is distinct from (select c.id from app.oauth_clients c where c.client_id = p_client) or x.redirect_uri <> p_redirect then
    -- A code used twice is a sign it leaked (RFC 9700): the key it gave out is revoked (the owner sees it on
    -- /account/agents and can make a new one).
    if x.code_hash is not null and x.used_at is not null then
      update app.agent_keys k set revoked_at = now() where k.agent_id = x.agent_id and k.revoked_at is null;
    end if;
    return null;
  end if;
  update app.oauth_codes c set used_at = now() where c.code_hash = p_code_hash;
  return jsonb_build_object('challenge', x.challenge, 'sealed', encode(x.sealed, 'base64'), 'agent', x.agent_id);
end $$;

revoke execute on function app.oauth_register(text, text, text[]), app.oauth_client(text), app.oauth_code_put(text, text, text, text, uuid, bytea),
  app.oauth_code_take(text, text, text) from public;
grant execute on function app.oauth_register(text, text, text[]), app.oauth_client(text), app.oauth_code_put(text, text, text, text, uuid, bytea),
  app.oauth_code_take(text, text, text) to dog_app;
reset role;
revoke create on schema app from dog_signin;

-- ---- 2. The poster rating ----
grant create on schema app to dog_work;
set local role dog_work;
create function app.work_poster_rating(p_member uuid) returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  with mine as (select t.id from app.work_tasks t where t.poster_member = p_member and t.status <> 'removed'),
  checked as (
    select s.id, s.status, s.created_at, s.decided_at from app.work_submissions s
     where s.task_id in (select id from mine) and s.decided_by = 'poster' and s.decided_at is not null)
  select jsonb_build_object(
    'tasks_posted', (select count(*) from mine),
    'work_checked', (select count(*) from checked),
    'passed', (select count(*) from checked c where c.status in ('passed', 'reversed')),
    'failed', (select count(*) from checked c where c.status = 'failed'
                 or exists (select 1 from app.work_checks k where k.submission_id = c.id and k.why = 'fail_appeal')),
    'fails_overturned', (select count(*) from checked c join app.work_checks k on k.submission_id = c.id
                          where k.why = 'fail_appeal' and k.status = 'reversed'),
    'disputes_opened', (select count(*) from app.work_disputes d where d.member_id = p_member),
    'disputes_dismissed', (select count(*) from app.work_disputes d where d.member_id = p_member and d.status = 'dismissed'),
    'median_hours_to_check', (select round((percentile_cont(0.5) within group (order by extract(epoch from c.decided_at - c.created_at) / 3600))::numeric, 1) from checked c),
    'note', 'From this member''s own record as a poster. A fail later overturned on appeal, or a dispute dismissed, counts against fairness; few checks mean little is known yet.')
$$;
revoke execute on function app.work_poster_rating(uuid) from public;
grant execute on function app.work_poster_rating(uuid) to dog_app;
reset role;
revoke create on schema app from dog_work;
