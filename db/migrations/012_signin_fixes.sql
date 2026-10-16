-- 012 Sign-in fixes (Release 2, PR 15): two go-live-blocking fixes from the sign-in review, and one small one.
--
-- 1 (High). Linking a sign-in method bypassed the fresh-sign-in rule and gave lasting access. Starting a link needed
--   only a current session, and finishing it made a brand-new session, which is fresh for 10 minutes: enough to let
--   agents act on their own, make agent keys and pass the fresh-delete check (RK3). A stolen session cookie could link
--   the thief's own GitHub or X and keep signing in as the victim after "sign out everywhere", since nothing could
--   unlink it. Now:
--     * Linking has its own function, app.identity_link. It runs only for the member the request acts as, from that
--       member's own session (named by its hash), and only if that session began within the last 10 minutes by the
--       database clock: the same rule as deleting an account (009) and letting an agent act (008).
--     * It makes no session at all, so a link can never make anyone fresh. It ends every other session of the member,
--       leaves an in-app notice ("A new sign-in method was linked") and writes an audit row.
--     * app.sign_in no longer links (p_link_member must be null), so no code path can link and get a new session.
--     * app.identity_unlink removes a method: the same fresh-session rule, never the last method, every other session
--       ended, with a notice and an audit row. The member's level follows the methods that remain.
-- 2 (Medium). app.agent_resolve checked the level stored on the member row, which is re-read only at sign-in and at
--   most hourly as pages are read (session_resolve). An X business badge past its 30-day recheck therefore kept its
--   owner's agents working for as long as the owner stayed away. It now checks the live verified level
--   (app.verified_level, the level sign-in and sessions already follow), so the next agent request is refused.
--   Aaron (is_admin) is unaffected.
-- 3 (Small). Keeping an agent acting on its own at the 90-day check (reason 'reconfirmed', 011) needed no fresh
--   sign-in. Keeping it is letting it act without approval for another 90 days, so it needs one now.
--
-- How it fits: the two new functions run as dog_signin (the sign-in role, which alone may write identities and
-- sessions), like app.sign_in. dog_signin gains only what they need: deleting an identity, and leaving the two new
-- kinds of notice through app.notify (as JEVs does, 011). Everything else is as before.

set local role dog_owner;

-- ---- The two new kinds of notice ----
alter table app.notices drop constraint notices_kind_check;
alter table app.notices add constraint notices_kind_check check (kind = any (array['draft_waiting', 'draft_expired', 'report_upheld', 'brake_on',
  'contained', 'containment_lifted', 'appeal_decided', 'act_reconfirm', 'act_expired', 'challenge', 'account_flagged', 'alert',
  'signin_linked', 'signin_unlinked']));

-- ---- What dog_signin may do in addition (inside its functions only) ----
create policy identities_signin_delete on app.identities for delete to dog_signin using (true);
grant delete on app.identities to dog_signin;
create policy notices_signin_insert on app.notices for insert to dog_signin
  with check (member_id is not null and kind in ('signin_linked', 'signin_unlinked'));
grant insert (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key) on app.notices to dog_signin;
grant execute on function app.notify(uuid, text, text, text, text, text, uuid, text) to dog_signin;

grant create on schema app to dog_signin;
set local role dog_signin;

-- ---- Signing in: never links any more (fix 1) ----
-- Same as 010, except that linking is refused here: it is app.identity_link's job, which makes no session. The
-- signature is unchanged (p_link_member must be null), so the callers and the coverage check's list stay the same.
-- Raises 'banned', 'disabled' or 'region'.
create or replace function app.sign_in(p_provider text, p_fingerprints text[], p_key_version smallint, p_level smallint,
                                       p_display_name text, p_session_hash text, p_session_days integer,
                                       p_recheck_after timestamptz, p_link_member uuid, p_region text)
returns table (member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  ident app.identities%rowtype;
  mem app.members%rowtype;
  fresh boolean := false;
begin
  if p_provider is null or not (p_provider = any (array['github', 'x', 'email', 'linkedin']))
     or p_fingerprints is null or cardinality(p_fingerprints) not between 1 and 5
     or exists (select 1 from unnest(p_fingerprints) f where f is null or f !~ '^[0-9a-f]{64}$')
     or p_key_version is null or p_key_version not between 1 and 999
     or p_level is null or p_level not between 0 and 2 or p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$'
     or p_session_days is null or p_session_days not between 1 and 30
     or p_display_name is null or char_length(p_display_name) not between 1 and 80
     or (p_region is not null and p_region !~ '^[A-Z]{2}$') then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  -- Signing in is for someone not signed in, and never links a method (PR 15: app.identity_link does, with no session).
  if p_link_member is not null or app.actor_kind() <> 'anon' then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;

  select * into ident from app.identities i where i.provider = p_provider and i.fingerprint = any (p_fingerprints)
    order by i.created_at limit 1 for update;

  if found then
    select * into mem from app.members m where m.id = ident.member_id for update;
    update app.identities i set fingerprint = p_fingerprints[1], key_version = p_key_version, level = p_level,
                                verified_at = now(), recheck_after = p_recheck_after
      where i.id = ident.id;
  elsif p_region is not null then
    -- Nobody signs up from a declined region, whatever they confirm.
    raise exception 'region' using errcode = 'P0001';
  else
    insert into app.members (display_name, trust_level) values (p_display_name, p_level) returning * into mem;
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (mem.id, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after);
    fresh := true;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.joined', 'member', mem.id, jsonb_build_object('provider', p_provider, 'level', p_level));
  end if;

  if mem.status = 'banned' then
    raise exception 'banned' using errcode = 'P0001';
  end if;
  if mem.status = 'disabled' or app.deletion_overdue(mem.id) then
    raise exception 'disabled' using errcode = 'P0001';
  end if;

  if app.verified_level(mem.id) is distinct from mem.trust_level then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_changed', 'member', mem.id,
              jsonb_build_object('provider', p_provider, 'from', mem.trust_level, 'to', app.verified_level(mem.id)));
    update app.members m set trust_level = app.verified_level(mem.id) where m.id = mem.id;
    mem.trust_level := app.verified_level(mem.id);
  end if;

  insert into app.sessions (member_id, token_hash, expires_at)
    values (mem.id, p_session_hash, now() + make_interval(days => p_session_days));
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.signed_in', 'member', mem.id, jsonb_build_object('provider', p_provider));
  if p_region is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.region_confirmed', 'member', mem.id, jsonb_build_object('country', p_region));
  end if;

  return query select mem.id, fresh, mem.trust_level, mem.is_admin;
end
$$;

-- ---- Sign-in for agents: the owner's live verified level (fix 2) ----
-- Same as 010, with one change: the owner must be at level 2 by app.verified_level (a lapsed X badge counts as level
-- 1 from its recheck date), not by the level last stored on their row. Aaron (is_admin) is unaffected.
create or replace function app.agent_resolve(p_key_hash text)
returns table (agent_id uuid, owner_id uuid)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query
    select a.id, m.id
    from app.agent_keys k join app.agents a on a.id = k.agent_id join app.members m on m.id = a.owner_id
    where k.key_hash = p_key_hash and k.revoked_at is null and a.status = 'active'
      and m.status = 'active' and (app.verified_level(m.id) >= 2 or m.is_admin) and not app.deletion_overdue(m.id);
end
$$;
set local role dog_owner;

-- ---- Linking a sign-in method (fix 1) ----
-- For the signed-in member the transaction acts as, from their own session (p_session_hash), which must have begun
-- within the last 10 minutes by the database clock. It makes no session: the member keeps the one they have, and
-- every other session of theirs ends. The member is told in-app and the audit log records it.
--   p_region: the country a traveller confirmed they are signing in from (010), recorded as at sign-in.
-- Returns the member, whether a method was added (false: it was already theirs, and is verified again) and how many
-- sessions ended. Raises 'fresh_sign_in', 'taken' (the method belongs to someone else), 'banned' or 'disabled'.
create function app.identity_link(p_provider text, p_fingerprints text[], p_key_version smallint, p_level smallint,
                                  p_recheck_after timestamptz, p_session_hash text, p_region text)
returns table (member_id uuid, trust_level smallint, is_admin boolean, linked boolean, sessions_ended integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ident app.identities%rowtype;
  mem app.members%rowtype;
  nid uuid;
  ended integer := 0;
  added boolean := false;
begin
  if p_provider is null or not (p_provider = any (array['github', 'x', 'email', 'linkedin']))
     or p_fingerprints is null or cardinality(p_fingerprints) not between 1 and 5
     or exists (select 1 from unnest(p_fingerprints) f where f is null or f !~ '^[0-9a-f]{64}$')
     or p_key_version is null or p_key_version not between 1 and 999
     or p_level is null or p_level not between 0 and 2 or p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$'
     or (p_region is not null and p_region !~ '^[A-Z]{2}$')
     or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  -- The member's own session, begun in the last 10 minutes (the database's clock, as for app.fresh). Another
  -- member's session, an expired one, or an older one counts for nothing.
  perform 1 from app.sessions s where s.token_hash = p_session_hash and s.member_id = me and s.expires_at > now()
    and s.created_at > now() - interval '10 minutes';
  if not found then
    raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again, then link it within 10 minutes.';
  end if;
  -- The same lock order as deleting an account (009): the member, then sign-in methods, then the member row.
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  select * into ident from app.identities i where i.provider = p_provider and i.fingerprint = any (p_fingerprints)
    order by i.created_at limit 1 for update;
  if found and ident.member_id <> me then
    raise exception 'taken' using errcode = 'P0001';
  end if;
  select * into mem from app.members m where m.id = me for update;
  if not found then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  if mem.status = 'banned' then
    raise exception 'banned' using errcode = 'P0001';
  end if;
  if mem.status = 'disabled' or app.deletion_overdue(mem.id) then
    raise exception 'disabled' using errcode = 'P0001';
  end if;

  if ident.id is not null then
    -- Already theirs: verified again, as a sign-in would, and nothing else changes.
    update app.identities i set fingerprint = p_fingerprints[1], key_version = p_key_version, level = p_level,
                                verified_at = now(), recheck_after = p_recheck_after
      where i.id = ident.id;
  else
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (me, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after) returning id into nid;
    added := true;
    -- Whoever linked it keeps only the session they linked from; every other session of the member ends.
    delete from app.sessions s where s.member_id = me and s.token_hash <> p_session_hash;
    get diagnostics ended = row_count;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.identity_linked', 'member', me, jsonb_build_object('provider', p_provider, 'sessions_ended', ended));
    perform app.notify(me, 'signin_linked', 'A new sign-in method was linked',
      case p_provider when 'github' then 'GitHub' when 'x' then 'X' when 'email' then 'An email address' else 'A sign-in method' end
      || ' can now sign in to your account, and every other session of yours was signed out. If this wasn''t you, sign in again, '
      || 'unlink it on your account page, and sign out everywhere.', '/account', 'identity', nid, 'signin:linked:' || nid::text);
  end if;

  if app.verified_level(mem.id) is distinct from mem.trust_level then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_changed', 'member', mem.id,
              jsonb_build_object('provider', p_provider, 'from', mem.trust_level, 'to', app.verified_level(mem.id)));
    update app.members m set trust_level = app.verified_level(mem.id) where m.id = mem.id;
    mem.trust_level := app.verified_level(mem.id);
  end if;
  if p_region is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.region_confirmed', 'member', mem.id, jsonb_build_object('country', p_region));
  end if;
  return query select mem.id, mem.trust_level, mem.is_admin, added, ended;
end
$$;

-- ---- Unlinking a sign-in method (fix 1) ----
-- The same rules as linking: the member's own session, begun in the last 10 minutes. Never the last method, so
-- nobody locks themselves out. Every other session ends (so a session an intruder made with the method being removed
-- goes too), the member is told in-app, and the audit log records it. The level follows the methods that remain.
-- Raises 'fresh_sign_in', 'not_found' (no such method of theirs) or 'last_method'.
create function app.identity_unlink(p_identity uuid, p_session_hash text)
returns table (provider text, trust_level smallint, sessions_ended integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ident app.identities%rowtype;
  mem app.members%rowtype;
  n integer;
  ended integer := 0;
begin
  if p_identity is null or p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$'
     or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  perform 1 from app.sessions s where s.token_hash = p_session_hash and s.member_id = me and s.expires_at > now()
    and s.created_at > now() - interval '10 minutes';
  if not found then
    raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again, then unlink it within 10 minutes.';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  perform 1 from app.identities i where i.member_id = me for update;
  select * into mem from app.members m where m.id = me and m.status = 'active' for update;
  if not found then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  select * into ident from app.identities i where i.id = p_identity and i.member_id = me;
  if not found then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  select count(*) into n from app.identities i where i.member_id = me;
  if n <= 1 then
    raise exception 'last_method' using errcode = 'P0001', hint = 'This is the only way you sign in; link another first.';
  end if;

  delete from app.identities i where i.id = ident.id;
  delete from app.sessions s where s.member_id = me and s.token_hash <> p_session_hash;
  get diagnostics ended = row_count;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.identity_unlinked', 'member', me, jsonb_build_object('provider', ident.provider, 'sessions_ended', ended));
  perform app.notify(me, 'signin_unlinked', 'A sign-in method was removed',
    case ident.provider when 'github' then 'GitHub' when 'x' then 'X' when 'email' then 'An email address' else 'A sign-in method' end
    || ' can no longer sign in to your account, and every other session of yours was signed out. If this wasn''t you, sign in '
    || 'again and check how you sign in on your account page.', '/account', 'identity', ident.id, 'signin:unlinked:' || ident.id::text);
  if app.verified_level(me) is distinct from mem.trust_level then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_changed', 'member', me,
              jsonb_build_object('provider', ident.provider, 'from', mem.trust_level, 'to', app.verified_level(me)));
    update app.members m set trust_level = app.verified_level(me) where m.id = me;
    mem.trust_level := app.verified_level(me);
  end if;
  return query select ident.provider, mem.trust_level, ended;
end
$$;

-- Only the site's role may call them; set before handing them to dog_signin, as 002 and 010 do.
revoke execute on function app.identity_link(text, text[], smallint, smallint, timestamptz, text, text), app.identity_unlink(uuid, text) from public;
grant execute on function app.identity_link(text, text[], smallint, smallint, timestamptz, text, text), app.identity_unlink(uuid, text) to dog_app;
alter function app.identity_link(text, text[], smallint, smallint, timestamptz, text, text) owner to dog_signin;
alter function app.identity_unlink(uuid, text) owner to dog_signin;
revoke create on schema app from dog_signin;

-- ---- The 90-day check needs a fresh sign-in (fix 3) ----
-- Same as 011, except that a confirmation ('reconfirmed') needs a fresh sign-in (app.fresh), as raising an agent to
-- act does: keeping it acting on its own is letting it act without approval for another 90 days.
create or replace function app.agent_rules_fill() returns trigger
language plpgsql
as $$
declare
  prev app.agent_rules%rowtype;
  before app.agent_rules%rowtype;
  rank_of constant jsonb := '{"off": 0, "draft": 1, "act": 2}';
begin
  perform pg_advisory_xact_lock(hashtext('dayonegreat.rules'), hashtext(new.agent_id::text));
  -- Only the columns the sign-in role may read too (it writes first rules on a claim and lowered ones on a ban).
  select r.id, r.version, r.post_mode, r.reply_mode, r.report_mode, r.daily_cap
    into prev.id, prev.version, prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap
    from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  new.version := coalesce(prev.version, 0) + 1;
  new.created_at := now();
  new.set_by := case when new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment', 'containment_lifted') then 'system' else 'owner' end;
  if new.reason = 'created' then
    if prev.id is not null then
      raise exception 'an agent''s first rules are set once' using errcode = '42501';
    end if;
    new.post_mode := 'draft';
    new.reply_mode := 'draft';
    new.report_mode := 'draft';
    new.daily_cap := coalesce(new.daily_cap, 20);
    return new;
  end if;
  if prev.id is null then
    raise exception 'this agent has no rules yet' using errcode = '42501';
  end if;
  if new.reason = 'reconfirmed' then
    if (new.post_mode, new.reply_mode, new.report_mode, new.daily_cap) is distinct from (prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap)
       or 'act' <> all (array[prev.post_mode, prev.reply_mode, prev.report_mode]) then
      raise exception 'a confirmation keeps rules that act exactly as they are' using errcode = '42501';
    end if;
    -- PR 15: keeping an agent acting on its own for another 90 days needs a fresh sign-in.
    if coalesce(current_setting('app.fresh', true), '') <> '1' then
      raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to keep an agent acting on its own.';
    end if;
    return new;
  end if;
  if new.reason = 'containment_lifted' then
    -- Written only by the site or Aaron (as dog_app), which may read every column.
    select r.reason into prev.reason from app.agent_rules r where r.id = prev.id;
    select * into before from app.agent_rules r where r.agent_id = new.agent_id and r.version = prev.version - 1;
    if prev.reason is distinct from 'containment' or before.id is null
       or (new.post_mode, new.reply_mode, new.report_mode, new.daily_cap) is distinct from (before.post_mode, before.reply_mode, before.report_mode, before.daily_cap)
       or exists (select 1 from app.containments c join app.agents a on a.owner_id = c.member_id
                  where a.id = new.agent_id and c.lifted_at is null) then
      raise exception 'lifting a containment only restores the rules it replaced' using errcode = '42501';
    end if;
    return new;
  end if;
  if (rank_of ->> new.post_mode)::int > (rank_of ->> prev.post_mode)::int
     or (rank_of ->> new.reply_mode)::int > (rank_of ->> prev.reply_mode)::int
     or (rank_of ->> new.report_mode)::int > (rank_of ->> prev.report_mode)::int
     or new.daily_cap > prev.daily_cap then
    if new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment') then
      raise exception 'an upheld report, a ban, a disabled account, an expiry or a containment can only lower an agent''s rules' using errcode = '42501';
    end if;
    -- While a containment is in force (until its time is up), the owner can't raise any agent's rules, existing or
    -- new: everything drafts for their approval until it ends. Lowering stays open (the notifications review,
    -- finding 1).
    if exists (select 1 from app.containments c join app.agents a on a.owner_id = c.member_id
               where a.id = new.agent_id and c.lifted_at is null and c.ends_at > now()) then
      raise exception 'contained' using errcode = 'P0001', hint = 'Your agents draft for your approval until the pause ends.';
    end if;
    if ((new.post_mode = 'act' and prev.post_mode <> 'act') or (new.reply_mode = 'act' and prev.reply_mode <> 'act')
        or (new.report_mode = 'act' and prev.report_mode <> 'act') or new.daily_cap > prev.daily_cap)
       and coalesce(current_setting('app.fresh', true), '') <> '1' then
      raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to let an agent do more without your approval.';
    end if;
  end if;
  return new;
end
$$;
