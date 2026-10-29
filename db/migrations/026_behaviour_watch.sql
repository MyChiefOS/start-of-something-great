-- 026 The JEVs behaviour watch (Aaron, Oct 28: "one JEVs watching the user's behaviour"; the list he confirmed, recorded
--   in harness/STATUS.md 5b). It alerts Aaron in his inbox and never blocks or refuses anyone (his rule: checks alert,
--   never lock out). What it watches, on the site's own system once it opens:
--     1. Many sessions at once: a sign-in that leaves one member with more live sessions than watch_settings says.
--     2. A new country: a member signing in from a country none of their sign-ins in the last 90 days came from.
--     3. A new network: the same, for the administrator's account only (the account worth taking over).
--     4. Failed tries: the 5th wrong key file for a username, and a key file cancelled at the 10th (023), with a
--        separate title when it is Aaron's own.
--     5. Reaching for administrator powers: a signed-in member who isn't the administrator asking for the review
--        queue or the owner controls.
--     6. First-time sensitive actions: a member's first agent key or first change to an agent's rules, as recorded by
--        the site's checks (app.jevs_decisions). (Not a deletion request: a deletion that goes ahead takes its alert with
--        the account, and one held for Aaron already alerts him.)
--   What it keeps (app.watch_seen): for each member, keyed hashes of the countries their sign-ins came from (and, for the
--   administrator only, of the networks), with when each was first and last seen. Each hash includes the member's ID,
--   so the same country gives a different hash for each member. Rows unseen for 90 days are deleted at every sign-in
--   (anyone's), and with the account. Alerts name the row, never the hash. Keyed by the site with the first fingerprint
--   key, so the table alone names no country or network; someone holding that key could test the 250 or so country
--   codes against a member's hashes (RISKS.md RK90). Never an address, never a country in readable form.
set local role dog_owner;

alter table app.watch_settings add column max_sessions integer not null default 5 check (max_sessions between 1 and 1000);
-- The sign-in role reads it, inside app.watch_signin only.
create policy watch_settings_signin_select on app.watch_settings for select to dog_signin using (true);
grant select on app.watch_settings to dog_signin;

create table app.watch_seen (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id) on delete cascade,
  kind text not null check (kind = any (array['country', 'net'])),
  key_hash text not null check (char_length(key_hash) = 64 and key_hash ~ '^[0-9a-f]+$'),
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  unique (member_id, kind, key_hash)
);
create index watch_seen_last on app.watch_seen (last_seen);
alter table app.watch_seen enable row level security;
alter table app.watch_seen force row level security;
-- Only the sign-in role touches it, inside app.watch_signin. One policy per action.
create policy watch_seen_signin_select on app.watch_seen for select to dog_signin using (true);
create policy watch_seen_signin_insert on app.watch_seen for insert to dog_signin with check (true);
create policy watch_seen_signin_update on app.watch_seen for update to dog_signin using (true) with check (true);
create policy watch_seen_signin_delete on app.watch_seen for delete to dog_signin using (true);
grant select, delete on app.watch_seen to dog_signin;
grant insert (member_id, kind, key_hash) on app.watch_seen to dog_signin;
grant update (last_seen) on app.watch_seen to dog_signin;

-- The sign-in role may raise the watch's alerts too.
drop policy notices_signin_insert on app.notices;
create policy notices_signin_insert on app.notices for insert to dog_signin
  with check ((member_id is not null and kind in ('signin_linked', 'signin_unlinked', 'signin_keyfile'))
              or (member_id is null and kind = 'alert' and (dedupe_key like 'signin:capped:%' or dedupe_key like 'watch:%')));

-- 1 to 3: after every sign-in, as the member who just signed in (the site calls it with that new session). p_country
-- and p_net are the site's keyed hashes of the request's country and network, or null.
create function app.watch_signin(p_country text, p_net text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  adm boolean;
  day text := to_char(now() at time zone 'UTC', 'YYYYMMDD');
  n integer;
  lim integer;
  alerts integer := 0;
  r record;
  rid uuid;
begin
  if me is null then
    return jsonb_build_object('alerts', 0);
  end if;
  -- Never wait long for a lock: the site runs this in its own transaction after the sign-in, which has already worked.
  perform set_config('lock_timeout', '300ms', true);
  select m.is_admin into adm from app.members m where m.id = me;
  -- Everyone's rows unseen for 90 days, at every sign-in (the index on last_seen keeps it cheap). Rows another sign-in
  -- or a deletion holds are skipped, not waited for: the next sign-in takes them (the re-check, P6).
  delete from app.watch_seen w where w.id in (select x.id from app.watch_seen x where x.last_seen < now() - interval '90 days'
                                              for update skip locked);
  select count(*) into n from app.sessions s where s.member_id = me and s.expires_at > now();
  select s.max_sessions into lim from app.watch_settings s limit 1;
  if n > coalesce(lim, 5) then
    if app.notify(null, 'alert', 'Many sessions at once',
         n || ' sessions are signed in for one member at once, more than ' || coalesce(lim, 5) || '.', '/controls', 'member', me,
         'watch:sessions:' || me::text || ':' || day) then
      alerts := alerts + 1;
    end if;
  end if;
  for r in select * from (values ('country', p_country), ('net', case when adm then p_net end)) v(kind, key_hash)
           where v.key_hash is not null and v.key_hash ~ '^[0-9a-f]{64}$' loop
    rid := null;
    if exists (select 1 from app.watch_seen w where w.member_id = me and w.kind = r.kind)
       and not exists (select 1 from app.watch_seen w where w.member_id = me and w.kind = r.kind and w.key_hash = r.key_hash) then
      -- The new row first, so the alert names the row, never the hash; a country seen again after 90 days has a new row
      -- and alerts again.
      -- Two sign-ins from the same new place at once: the second finds the row made and stays quiet.
      insert into app.watch_seen (member_id, kind, key_hash) values (me, r.kind, r.key_hash)
        on conflict (member_id, kind, key_hash) do nothing returning id into rid;
      if rid is not null and app.notify(null, 'alert',
           case when r.kind = 'country' then 'A sign-in from a new country' else 'Your account signed in from a new network' end,
           case when r.kind = 'country' then 'A member signed in from a country none of their sign-ins in the last 90 days came from.'
                else 'The administrator''s account signed in from a network it hasn''t used in the last 90 days. If that wasn''t you, '
                  || 'sign out everywhere, which also cancels the key file.' end,
           '/controls', 'member', me, 'watch:' || r.kind || ':' || rid::text) then
        alerts := alerts + 1;
      end if;
    end if;
    if rid is null then
      -- Seen before (or just made by a sign-in at the same moment): remember it was seen now.
      insert into app.watch_seen (member_id, kind, key_hash) values (me, r.kind, r.key_hash)
        on conflict (member_id, kind, key_hash) do update set last_seen = now();
    end if;
  end loop;
  return jsonb_build_object('alerts', alerts);
end
$$;

-- 5: a signed-in member who isn't the administrator asking for an administrator's page. Once a day per member and page.
create function app.watch_reach(p_what text)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
begin
  if me is null or p_what is null or p_what not in ('review', 'controls')
     or exists (select 1 from app.members m where m.id = me and m.is_admin) then
    return false;
  end if;
  return app.notify(null, 'alert', 'Someone reached for administrator powers',
    'A signed-in member who isn''t the administrator asked for the ' || case when p_what = 'review' then 'review queue' else 'owner controls' end
    || '. Nothing was shown to them.', '/controls', 'member', me,
    'watch:reach:' || me::text || ':' || p_what || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
end
$$;



-- Who may call them, set before handing them over, while dog_owner can still grant.
revoke execute on function app.watch_signin(text, text), app.watch_reach(text) from public;
grant execute on function app.watch_signin(text, text), app.watch_reach(text) to dog_app;

grant create on schema app to dog_signin;
alter function app.watch_signin(text, text) owner to dog_signin;
alter function app.watch_reach(text) owner to dog_signin;
revoke create on schema app from dog_signin;

-- 6: a member's first sensitive action, as the site's checks recorded it. Run by the site straight after the check, in
-- the same transaction, so the decision just made is the first one if it is the only one.
create function app.watch_first(p_action text)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  n integer;
begin
  if me is null or p_action is null or p_action not in ('agent.key', 'agent.rules') then
    return false;
  end if;
  select count(*) into n from app.jevs_decisions d where d.member_id = me and d.action = p_action;
  if n <> 1 then
    return false;
  end if;
  return app.notify(null, 'alert', 'A first-time sensitive action',
    'A member did this for the first time: ' || case p_action when 'agent.key' then 'made an agent key'
      else 'changed an agent''s rules' end || '.',
    '/controls', 'member', me, 'watch:first:' || me::text || ':' || p_action);
end
$$;
revoke execute on function app.watch_first(text) from public;
grant execute on function app.watch_first(text) to dog_app;
grant create on schema app to dog_jevs;
alter function app.watch_first(text) owner to dog_jevs;
revoke create on schema app from dog_jevs;

-- 4: the key file's failed tries (023's app.file_sign_in, as 025 left it, with the two alerts added). It stays the
-- sign-in role's, so it is replaced as that role, with the right to create in the schema for these lines only (as in 025).
grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.file_sign_in(p_login_hash text, p_key_hash text, p_display_name text, p_session_hash text,
                                 p_session_days integer, p_region text)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  k app.file_keys%rowtype;
  s record;
begin
  if p_login_hash is null or p_login_hash !~ '^[0-9a-f]{64}$' or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad key file request' using errcode = '22023';
  end if;
  select * into k from app.file_keys f where f.login_hash = p_login_hash and f.key_hash = p_key_hash for update;
  if not found then
    -- A wrong file for a username that has a key file counts; the 10th cancels it and tells the member, who then
    -- starts again with a new code (Aaron, Oct 28).
    update app.file_keys f set failed = f.failed + 1 where f.login_hash = p_login_hash returning * into k;
    -- The behaviour watch (026): Aaron hears at the 5th wrong file for a username, and when a key file is cancelled.
    if found and k.failed = 5 then
      begin
        perform app.notify(null, 'alert', 'Wrong key files for one account',
          '5 wrong key files have been tried for one member''s GitHub username. At 10 their key file is cancelled and they '
          || 'sign in again with a new code.', '/controls', 'member', k.member_id, 'watch:failed:' || k.id::text);
      exception when others then
        null; -- the watch only alerts: it never stops the count or the cancellation
      end;
    end if;
    if found and k.failed >= 10 then
      begin
        perform app.notify(null, 'alert',
          case when exists (select 1 from app.members m where m.id = k.member_id and m.is_admin) then 'Your own key file was cancelled'
               else 'A member''s key file was cancelled' end,
          '10 wrong key files were tried for the GitHub username, so the key file no longer works. The account is safe; '
          || 'the member signs in again with a new code.', '/controls', 'member', k.member_id, 'watch:cancelled:' || k.id::text);
      exception when others then
        null;
      end;
      delete from app.file_keys f where f.id = k.id;
      perform app.notify(k.member_id, 'signin_keyfile', 'Your key file was cancelled',
        'Someone tried 10 wrong key files with your GitHub username, so your key file no longer works. Your account is '
        || 'safe. To sign in, get a new code on the join page, post it, and choose a new key file.', '/join', 'member',
        k.member_id, 'signin:keyfile:cancelled:' || k.id::text);
      return query select 'start_again'::text, null::uuid, null::boolean, null::smallint, null::boolean;
      return;
    end if;
    return query select 'no_match'::text, null::uuid, null::boolean, null::smallint, null::boolean;
    return;
  end if;
  select * into s from app.sign_in_core('github', array[k.fingerprint], 1::smallint, 1::smallint, p_display_name,
                                   p_session_hash, p_session_days, null::timestamptz, null::uuid, p_region);
  update app.file_keys f set used_at = now(), failed = 0 where f.id = k.id;
  perform app.notify(s.member_id, 'signin_keyfile', 'Signed in with your key file',
    'Your key file was used to sign in to Day One Great. If that wasn''t you, sign out everywhere from your account page '
    || 'and sign in again with a new code and a new key file.', '/account', 'member', s.member_id,
    'signin:keyfile:' || p_session_hash);
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_signin;
