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
set local role dog_owner;

create table app.code_signins (
  id uuid primary key default app.uuid_v7(),
  code_hash text not null unique check (char_length(code_hash) = 64 and code_hash ~ '^[0-9a-f]+$'),
  browser_hash text not null check (char_length(browser_hash) = 64 and browser_hash ~ '^[0-9a-f]+$'),
  fingerprint text check (fingerprint is null or (char_length(fingerprint) = 64 and fingerprint ~ '^[0-9a-f]+$')),
  status text not null default 'waiting' check (status = any (array['waiting', 'claimed', 'used'])),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  claimed_at timestamptz,
  used_at timestamptz,
  check ((status = 'waiting') = (fingerprint is null))
);
create index code_signins_browser on app.code_signins (browser_hash);
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

grant create on schema app to dog_signin;
set local role dog_signin;

-- 1. A new code for one browser, for 10 minutes. Old rows are cleared now and then (a day after they expire).
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
  insert into app.code_signins (code_hash, browser_hash, expires_at) values (p_code_hash, p_browser_hash, now() + interval '10 minutes');
  if random() < 0.05 then
    delete from app.code_signins where expires_at < now() - interval '1 day';
  end if;
end
$$;

-- 2. The JEVs gate claims a posted code for the GitHub account that posted it. True only for a waiting, unexpired
--    code; a used, expired, unknown or already-claimed one changes nothing.
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
  return found;
end
$$;

-- 3. The browser that asked for a code signs in, once it has been claimed. status: 'waiting' (not posted yet),
--    'expired' (nothing usable for this browser), or 'ok' with who signed in. The GitHub account comes from the
--    claimed code, never from the caller. app.sign_in's refusals (banned, disabled, region) are raised as they are.
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
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin
    from app.sign_in('github', array[c.fingerprint], 1::smallint, 1::smallint, p_display_name, p_session_hash,
                     p_session_days, null::timestamptz, null::uuid, p_region) s;
end
$$;

set local role dog_owner;
revoke create on schema app from dog_signin;

revoke execute on function app.code_issue(text, text), app.code_claim(text, text),
  app.code_sign_in(text, text, text, integer, text) from public;
grant execute on function app.code_issue(text, text), app.code_sign_in(text, text, text, integer, text) to dog_app;
grant execute on function app.code_claim(text, text) to dog_jevs;
