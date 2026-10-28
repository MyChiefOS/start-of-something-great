-- 023 Signing in to the site by posting a one-time code through giscus (Aaron, Oct 28, 2026: "Okay you can implement
--   this feature"; harness/FACTS.md). No GitHub sign-in app and no secret are needed: the proof of who someone is is
--   GitHub's own record of who posted the code, which reaches the database only through the JEVs gate (it accepts only
--   jevs.yml on main, proved by GitHub's identity token).
--     1. The site makes a code for one browser: app.code_issue keeps a keyed hash of the code and of a random tag in that
--        browser's cookie, for 10 minutes. Never the code or the tag.
--     2. The person posts the code in the giscus box on /join. The JEVs gate hashes it the same way and, with the
--        poster's GitHub fingerprint (the same keyed hash GitHub sign-in uses, signin/crypto.js), claims it:
--        app.code_claim, which only the gate's role may call.
--     3. The browser asks app.code_sign_in, with its tag. The database takes the GitHub account from the claimed code
--        itself and signs that account in through app.sign_in. The site never says who is signing in, so on this path
--        it can't sign in as anyone else (RISKS.md RK82; RK82 closes only when the site's other route to app.sign_in,
--        the switched-off GitHub and X sign-in, is retired or moved behind proof of its own).
--   A code works once, for the browser that asked for it, within 10 minutes. Level 1 at sign-in, as for every sign-in
--   (021); JEVs promotes from the GitHub post itself.
--   Also here: sessions last a flat 30 days with no idle limit (Aaron, Oct 28), at the end of this file.
set local role dog_owner;

create table app.code_signins (
  id uuid primary key default app.uuid_v7(),
  code_hash text not null unique check (char_length(code_hash) = 64 and code_hash ~ '^[0-9a-f]+$'),
  browser_hash text not null check (char_length(browser_hash) = 64 and browser_hash ~ '^[0-9a-f]+$'),
  fingerprint text check (char_length(fingerprint) = 64 and fingerprint ~ '^[0-9a-f]+$'), -- null until claimed
  status text not null default 'waiting' check (status = any (array['waiting', 'claimed', 'used'])),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  claimed_at timestamptz,
  used_at timestamptz,
  check ((status = 'waiting') = (fingerprint is null))
);
create index code_signins_browser on app.code_signins (browser_hash);
create index code_signins_expires on app.code_signins (expires_at);
alter table app.code_signins enable row level security;
alter table app.code_signins force row level security;
-- Only the sign-in role touches it, inside the three functions below. One policy per action.
create policy code_signins_signin_select on app.code_signins for select to dog_signin using (true);
create policy code_signins_signin_insert on app.code_signins for insert to dog_signin with check (true);
create policy code_signins_signin_update on app.code_signins for update to dog_signin using (true) with check (true);
create policy code_signins_signin_delete on app.code_signins for delete to dog_signin using (true);
grant select, delete on app.code_signins to dog_signin;
grant insert (code_hash, browser_hash, expires_at) on app.code_signins to dog_signin;
grant update (fingerprint, status, claimed_at, used_at) on app.code_signins to dog_signin;

-- The three functions are made here, then handed to dog_signin (as in 002), so they run with its narrow rights.

-- 1. A new code for one browser, for 10 minutes. Every call also clears codes that expired more than an hour ago, so
--    nothing about a code (or the account that claimed it) is kept long (the CSO's review, finding 4).
create function app.code_issue(p_code_hash text, p_browser_hash text)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_code_hash is null or p_code_hash !~ '^[0-9a-f]{64}$' or p_browser_hash is null or p_browser_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad code request' using errcode = '22023';
  end if;
  if app.actor_kind() <> 'anon' then
    raise exception 'bad code request' using errcode = '22023';
  end if;
  delete from app.code_signins where expires_at < now() - interval '1 hour';
  insert into app.code_signins (code_hash, browser_hash, expires_at) values (p_code_hash, p_browser_hash, now() + interval '10 minutes');
end
$$;

-- 2. The JEVs gate claims a posted code for the GitHub account that posted it. True for a waiting, unexpired code, and
--    again for the same account's own code if the same post is sent twice (a retried workflow run; the CSO's review,
--    finding 8). A used, expired or unknown code, or one another account claimed, changes nothing and answers false.
create function app.code_claim(p_code_hash text, p_fingerprint text)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_code_hash is null or p_code_hash !~ '^[0-9a-f]{64}$' or p_fingerprint is null or p_fingerprint !~ '^[0-9a-f]{64}$' then
    return false;
  end if;
  update app.code_signins c set fingerprint = p_fingerprint, status = 'claimed', claimed_at = now()
    where c.code_hash = p_code_hash and c.status = 'waiting' and c.expires_at > now();
  if found then
    return true;
  end if;
  return exists (select 1 from app.code_signins c where c.code_hash = p_code_hash and c.fingerprint = p_fingerprint
                   and c.expires_at > now());
end
$$;

-- 3. The browser that asked for a code signs in, once it has been claimed. status: 'waiting' (not posted yet),
--    'expired' (nothing usable for this browser), 'region' (a new person in a declined region: the code and the
--    fingerprint it holds are deleted at once, Oct 16 rule), or 'ok' with who signed in. The GitHub account comes from
--    the claimed code, never from the caller. app.sign_in's other refusals (banned, disabled) are raised as they are.
create function app.code_sign_in(p_browser_hash text, p_display_name text, p_session_hash text, p_session_days integer,
                                 p_region text)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  c app.code_signins%rowtype;
begin
  if p_browser_hash is null or p_browser_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad code request' using errcode = '22023';
  end if;
  select * into c from app.code_signins x
    where x.browser_hash = p_browser_hash and x.status = 'claimed' and x.expires_at > now()
    order by x.claimed_at desc limit 1 for update;
  if not found then
    if exists (select 1 from app.code_signins x where x.browser_hash = p_browser_hash and x.status = 'waiting' and x.expires_at > now()) then
      return query select 'waiting'::text, null::uuid, null::boolean, null::smallint, null::boolean;
    else
      return query select 'expired'::text, null::uuid, null::boolean, null::smallint, null::boolean;
    end if;
    return;
  end if;
  update app.code_signins x set status = 'used', used_at = now() where x.id = c.id;
  -- Key version 1: the gate holds the first fingerprint key (dog_fingerprint_key_1). A rotation must move the gate too.
  begin
    return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin
      from app.sign_in('github', array[c.fingerprint], 1::smallint, 1::smallint, p_display_name, p_session_hash,
                       p_session_days, null::timestamptz, null::uuid, p_region) s;
  exception when sqlstate 'P0001' then
    if sqlerrm <> 'region' then
      raise;
    end if;
    delete from app.code_signins x where x.id = c.id;
    return query select 'region'::text, null::uuid, null::boolean, null::smallint, null::boolean;
  end;
end
$$;

-- Who may call them, set before handing them over, while dog_owner can still grant: the site's role makes and uses
-- codes; only the JEVs gate's role claims one.
revoke execute on function app.code_issue(text, text), app.code_claim(text, text),
  app.code_sign_in(text, text, text, integer, text) from public;
grant execute on function app.code_issue(text, text), app.code_sign_in(text, text, text, integer, text) to dog_app;
grant execute on function app.code_claim(text, text) to dog_jevs;

-- Postgres hands a function only to a role that may create objects in its schema, so dog_signin has that right for
-- these lines only.
grant create on schema app to dog_signin;
alter function app.code_issue(text, text) owner to dog_signin;
alter function app.code_claim(text, text) owner to dog_signin;
alter function app.code_sign_in(text, text, text, integer, text) owner to dog_signin;
revoke create on schema app from dog_signin;

-- ---- Sessions last a flat 30 days (Aaron, Oct 28, 2026: "it will last 30 days") ----
-- app.act_as is 019's, except that an unused session now lasts 30 days, not 7: the same as its absolute limit and as
-- signin/config.js IDLE_DAYS (a test keeps the two the same). It stays the sign-in role's, so it is replaced as that
-- role, which dog_owner may act as (002), with the right to create in the schema for these lines only (as in 021).
grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.act_as(p_actor text, p_member uuid, p_agent uuid, p_fresh boolean, p_session text, p_key text, p_system text)
returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  a text := 'anon'; m text := ''; ag text := ''; f text := ''; s text := '';
  sm uuid; sadmin boolean; sfresh boolean; km uuid; ka uuid;
begin
  if p_actor in ('member', 'admin') then
    select r.member_id, r.is_admin, r.fresh into sm, sadmin, sfresh from app.session_resolve(p_session, 30) r;
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
set local role dog_owner;
revoke create on schema app from dog_signin;
