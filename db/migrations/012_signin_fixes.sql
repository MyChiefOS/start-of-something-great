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
-- After the independent review of PR 15:
--   F1 (High), seniority: each session records the sign-in method it signed in with (sessions.identity_id), and a
--     session may unlink only methods linked after that one. Someone who copies a fresh cookie and links their own
--     method can never remove the owner's older one; the owner, signing in with it, can always remove theirs. No hand
--     work for Aaron, and no email (notices stay in-app only).
--   F2: the member's lock is taken before the session is checked, so a link or unlink can't go ahead from a session
--     that a concurrent one has just ended.
--   F6 (from PR 12): a traveller's sealed confirmation is single use in the database too (app.region_confirm_use).
-- After the second review of PR 15:
--   R1 (Medium), revoke on unlink: whatever a linked method's sessions did dies with it. Agent keys, owner-set rules
--     versions and links record the method of the session that made them (read by the database from the request's
--     own session, app.current_identity). Unlinking method M, in the same transaction: every agent key made from a
--     session of M is revoked, and every key of an agent a session of M created or claimed, whoever made the key; every
--     action a version of M's ever raised to "act" goes back to "draft" (never "off"), however it was kept or restored
--     since, and a daily cap it raised goes back; every method M's sessions linked is unlinked too, and so on down the
--     chain; and the sessions of all of them end. One audit row and one notice say exactly what was undone.
--     (After the re-review, probe E: undoing only the version that last switched an action to "act", or only the keys
--     M's sessions made, could be escaped by a re-save, a containment's end, or a key rotated from another session.)
--   R2 (Medium): the 90-day clock (R33) restarts only on an owner's save made with a fresh sign-in (a fresh
--     re-confirm, a raise, or a first switch to act). A save without one that leaves actions on act is still allowed,
--     but no longer moves the clock (agent_rules.restarts_clock).
--   R4 (the re-review, probe G; the lead's decision, pending Aaron): a link ends the session that made it too, so the
--     member signs in again with whichever method they like. A copied session cookie dies at the moment it is used to
--     take an account over.
--   R3 (Low): link and unlink take their locks in the order deleting an account (009) and a ban (006) use: the
--     member's advisory lock, sign-in methods, the member row, and only then the session row. A link or unlink at the
--     same moment as a ban waits instead of deadlocking; any serialization failure left is a clean "try again".
--     Reading a session (app.session_resolve) takes the member row before the session row too (the re-review, probe H).
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

-- ---- Which sign-in method each session signed in with (review F1: seniority) ----
-- Set by app.sign_in and never changed; a link keeps the session's own method (the one its holder proved). A session
-- made before this migration has none, and can't unlink anything until it signs in again.
alter table app.sessions add column identity_id uuid references app.identities (id) on delete set null;
create index sessions_identity on app.sessions (identity_id);
grant insert (identity_id) on app.sessions to dog_signin;

-- ---- What made each key, rules version and link (the second review, R1: revoke on unlink) ----
-- Each records the sign-in method (identities.id) of the session that made it. The database reads it from the
-- request's own session (app.current_identity, below); the site never sends it. Plain IDs, not references: rules
-- versions are never changed, and the record should outlive the method it names.
--   identities.linked_by:         the method of the session that linked this one (null for the one an account began with)
--   agent_keys.by_identity:       the method of the session that made the key (null for a key an agent made itself)
--   agents.created_by_identity:   the method of the session that created the agent (null for one that registered itself)
--   agents.claimed_by_identity:   the method of the session that claimed the agent (its key was made by the agent)
--   agent_rules.by_identity:      the method of the session that set an owner's rules version
-- And R2: whether an owner's version restarts the 90-day clock (R33): only one saved with a fresh sign-in.
alter table app.identities add column linked_by uuid;
alter table app.agent_keys add column by_identity uuid;
alter table app.agents add column created_by_identity uuid;
alter table app.agents add column claimed_by_identity uuid;
alter table app.agent_rules add column by_identity uuid;
alter table app.agent_rules add column restarts_clock boolean not null default false;
create index identities_linked_by on app.identities (linked_by) where linked_by is not null;
create index agent_keys_by_identity on app.agent_keys (by_identity) where by_identity is not null;
create index agent_rules_by_identity on app.agent_rules (by_identity) where by_identity is not null;
create index agent_rules_clock on app.agent_rules (agent_id, version) where restarts_clock;
grant insert (linked_by) on app.identities to dog_signin;
grant select (by_identity, reason) on app.agent_rules to dog_signin;

-- A version written on unlinking a method only ever lowers (R1), by the system.
alter table app.agent_rules drop constraint agent_rules_reason_check;
alter table app.agent_rules add constraint agent_rules_reason_check
  check (reason = any (array['created', 'owner', 'report_upheld', 'ban', 'disabled', 'reconfirmed', 'act_expired', 'containment',
                             'containment_lifted', 'signin_unlinked']));
alter policy agent_rules_signin_insert on app.agent_rules with check (reason in ('created', 'ban', 'disabled', 'signin_unlinked'));

-- The method of the session this request came from: the session named by app.session (set only by db/index.js, from
-- the request's own cookie), if it is the acting member's and still current. Null for anything else: an agent, the
-- site itself, an anonymous visitor, or a session made before this migration. Runs as dog_signin, which alone reads
-- sessions; the site's role may call it (it does, inside the triggers below).
create function app.current_identity() returns uuid
language sql stable security definer set search_path = pg_catalog
as $$
  select s.identity_id from app.sessions s
  where app.actor_kind() in ('member', 'admin') and s.member_id = app.current_member()
    and s.token_hash = nullif(current_setting('app.session', true), '') and s.expires_at > now()
$$;

-- A key records the method of the session that made it, and that never changes.
create function app.agent_keys_by() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'UPDATE' then
    new.by_identity := old.by_identity;
  else
    new.by_identity := case when app.actor_kind() in ('member', 'admin') then app.current_identity() end;
  end if;
  return new;
end
$$;
create trigger agent_keys_by before insert or update on app.agent_keys for each row execute function app.agent_keys_by();
alter table app.agent_keys enable always trigger agent_keys_by;

-- An agent records the method of the session that created it, or that claimed it (a claim, through app.agent_claim,
-- is the only way an unclaimed agent becomes active), and neither ever changes.
create function app.agents_by() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    new.created_by_identity := case when app.actor_kind() in ('member', 'admin') then app.current_identity() end;
    new.claimed_by_identity := null;
  else
    new.created_by_identity := old.created_by_identity;
    if old.status = 'unclaimed' and new.status = 'active' and app.actor_kind() in ('member', 'admin') then
      new.claimed_by_identity := app.current_identity();
    else
      new.claimed_by_identity := old.claimed_by_identity;
    end if;
  end if;
  return new;
end
$$;
create trigger agents_by before insert or update on app.agents for each row execute function app.agents_by();
alter table app.agents enable always trigger agents_by;
revoke execute on function app.agent_keys_by(), app.agents_by() from public;

-- ---- A traveller's confirmation is used once (review F6) ----
-- Only a SHA-256 of the random nonce in the sealed cookie, for as long as the cookie could live (10 minutes) plus a
-- day before it is tidied away. It names nobody.
create table app.region_confirms (
  id uuid primary key default app.uuid_v7(),
  token_hash text not null unique check (char_length(token_hash) = 64 and token_hash ~ '^[0-9a-f]+$'),
  expires_at timestamptz not null
);
alter table app.region_confirms enable row level security;
alter table app.region_confirms force row level security;
create policy region_confirms_signin_select on app.region_confirms for select to dog_signin using (true);
create policy region_confirms_signin_insert on app.region_confirms for insert to dog_signin with check (true);
create policy region_confirms_signin_delete on app.region_confirms for delete to dog_signin using (true);
grant select, delete on app.region_confirms to dog_signin;
grant insert (token_hash, expires_at) on app.region_confirms to dog_signin;

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
-- Same as 010, except that linking is refused here (it is app.identity_link's job, which makes no session), and the
-- new session records the method it signed in with (review F1). The signature is unchanged (p_link_member must be
-- null), so the callers and the coverage check's list stay the same.
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
  used uuid;
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
    used := ident.id;
  elsif p_region is not null then
    -- Nobody signs up from a declined region, whatever they confirm.
    raise exception 'region' using errcode = 'P0001';
  else
    insert into app.members (display_name, trust_level) values (p_display_name, p_level) returning * into mem;
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (mem.id, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after) returning id into used;
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

  -- The session records the method it signed in with (review F1: seniority).
  insert into app.sessions (member_id, token_hash, expires_at, identity_id)
    values (mem.id, p_session_hash, now() + make_interval(days => p_session_days), used);
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

-- ---- Reading a session: the member row before the session row (the re-review, probe H) ----
-- Same as 010, except for the order of locks in the hourly refresh, the only time it writes. 010 updated the session
-- row and then, if an X badge had lapsed, the member row: the reverse of every other path that writes both (a ban,
-- deleting an account, linking and unlinking all take the member row first), so a page read at the same moment as a
-- link or unlink could deadlock. Now it locks the member row first, then reads the session again (it may have ended
-- meanwhile), then writes both, in one transaction, so the refresh and the lowered level still commit together.
create or replace function app.session_resolve(p_session_hash text, p_idle_days integer)
returns table (member_id uuid, trust_level smallint, is_admin boolean, display_name text, fresh boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s app.sessions%rowtype;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or p_idle_days is null or p_idle_days not between 1 and 30 then
    return;
  end if;
  select * into s from app.sessions x where x.token_hash = p_session_hash;
  if not found or s.expires_at <= now() or s.last_seen_at <= now() - make_interval(days => p_idle_days) then
    return;
  end if;
  if s.last_seen_at < now() - interval '1 hour' then
    -- The member row first, as everywhere else; then the session again, by its own row, in case it ended meanwhile.
    perform 1 from app.members m where m.id = s.member_id for update;
    update app.sessions x set last_seen_at = now() where x.id = s.id and x.expires_at > now();
    if not found then
      return;
    end if;
    if exists (select 1 from app.members m where m.id = s.member_id and m.trust_level > app.verified_level(m.id)) then
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        select 'member.level_changed', 'member', m.id, jsonb_build_object('reason', 'recheck_lapsed', 'from', m.trust_level, 'to', app.verified_level(m.id))
        from app.members m where m.id = s.member_id;
      update app.members m set trust_level = app.verified_level(m.id) where m.id = s.member_id;
    end if;
  end if;
  return query select m.id, m.trust_level, m.is_admin, m.display_name, s.created_at > now() - interval '10 minutes'
    from app.members m where m.id = s.member_id and m.status = 'active' and not app.deletion_overdue(m.id);
end
$$;
set local role dog_owner;

-- ---- Linking a sign-in method (fix 1; the re-review, R4) ----
-- For the signed-in member the transaction acts as, from their own session (p_session_hash), which must have begun
-- within the last 10 minutes by the database clock. It makes no session, and once a method is added every session of
-- the member ends, the one that linked it too (R4): the member signs in again with whichever method they like, so a
-- copied cookie used to link can do nothing more. The member is told in-app and the audit log records it. Verifying
-- again a method that is already theirs changes no session.
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
  sid uuid;
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
  -- The lock order of deleting an account (009): the member's advisory lock, then sign-in methods (the member's own,
  -- and the one being linked, wherever it is), then the member row; then, last, the session row. A ban locks the
  -- member row and then deletes sessions (006), and a sign-in locks its method and then the member row, so a link at
  -- the same moment as either waits for it instead of deadlocking (the second review, R3). The advisory lock comes
  -- before the session is checked (review F2), so a concurrent link or unlink that ends this session is seen below.
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  perform 1 from app.identities i where i.member_id = me or (i.provider = p_provider and i.fingerprint = any (p_fingerprints))
    order by i.id for update;
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
  -- The member's own session, begun in the last 10 minutes (the database's clock, as for app.fresh). Another
  -- member's session, an expired one, an ended one, or an older one counts for nothing. Its method is recorded as
  -- the one that linked the new method (R1).
  select s.identity_id into sid from app.sessions s where s.token_hash = p_session_hash and s.member_id = me and s.expires_at > now()
    and s.created_at > now() - interval '10 minutes' for update;
  if not found then
    raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again, then link it within 10 minutes.';
  end if;
  select * into ident from app.identities i where i.provider = p_provider and i.fingerprint = any (p_fingerprints)
    order by i.created_at limit 1;
  if found and ident.member_id <> me then
    raise exception 'taken' using errcode = 'P0001';
  end if;

  if ident.id is not null then
    -- Already theirs: verified again, as a sign-in would, and nothing else changes.
    update app.identities i set fingerprint = p_fingerprints[1], key_version = p_key_version, level = p_level,
                                verified_at = now(), recheck_after = p_recheck_after
      where i.id = ident.id;
  else
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after, linked_by)
      values (me, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after, sid) returning id into nid;
    added := true;
    -- Every session of the member ends, the one that linked it too (R4): they sign in again with whichever method
    -- they like, so a copied session cookie can't go on after it has been used to link.
    delete from app.sessions s where s.member_id = me;
    get diagnostics ended = row_count;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.identity_linked', 'member', me, jsonb_build_object('provider', p_provider, 'sessions_ended', ended));
    -- What the owner can do about it, and what that undoes (R1); what it can't undo is in RISKS.md (RK62).
    perform app.notify(me, 'signin_linked', 'A new sign-in method was linked',
      case p_provider when 'github' then 'GitHub' when 'x' then 'X' when 'email' then 'An email address' else 'A sign-in method' end
      || ' can now sign in to your account. To keep your account safe, every session of yours was signed out, the one '
      || 'that linked it too, so sign in again with whichever method you like. If this wasn''t you, sign in with the '
      || 'method you have had longest and unlink it on your account page. That signs out everyone who used it, revokes '
      || 'the keys of any agent made with it, puts anything it let act on its own back to drafting for your approval, and '
      || 'unlinks anything it linked. Then check your agents and your posts: anything else it did, such as a post or a '
      || 'deletion, isn''t undone.', '/account', 'identity', nid, 'signin:linked:' || nid::text);
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

-- ---- Unlinking a sign-in method (fix 1; the second review, R1 and R3) ----
-- The same rules as linking: the member's own session, begun in the last 10 minutes. Never the last method, so
-- nobody locks themselves out. Seniority (review F1): only a method linked after the one this session signed in with
-- (by when each was added), so whoever holds the older method always wins.
-- Revoke on unlink (R1): whatever the method's sessions did dies with it, in this same transaction:
--   * the methods its sessions linked are unlinked too, and the ones theirs linked, down the chain (never the method
--     this session signed in with: seniority puts it before all of them);
--   * every agent key made from a session of any of them is revoked, and every key of an agent such a session
--     created or claimed, whoever made or rotated the key;
--   * every action that a rules version from such a session ever raised to "act" goes back to "draft", never "off",
--     however it was kept since (an owner's re-save, a confirmation, a containment's end); a daily cap such a version
--     raised goes back to what it was before; and an agent paused by a containment gets a version too, so the pause's
--     end can't restore what that method set;
--   * every other session of the member ends, theirs included.
-- One audit row and one notice say exactly what was undone. The level follows the methods that remain.
-- Raises 'fresh_sign_in', 'not_found' (no such method of theirs, or the account isn't active), 'last_method' or
-- 'not_senior'.
create function app.identity_unlink(p_identity uuid, p_session_hash text)
returns table (provider text, trust_level smallint, sessions_ended integer, also_unlinked integer, keys_revoked integer,
               agents_lowered integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ident app.identities%rowtype;
  own app.identities%rowtype;
  mem app.members%rowtype;
  sid uuid;
  n integer;
  ended integer := 0;
  gone uuid[];
  others text[];
  keys integer := 0;
  lowered integer := 0;
  a record;
  post text;
  rep text;
  rpt text;
  cap integer;
  cap_before integer;
  body text;
  name_of constant jsonb := '{"github": "GitHub", "x": "X", "email": "an email address", "linkedin": "LinkedIn"}';
  lead_of constant jsonb := '{"github": "GitHub", "x": "X", "email": "An email address", "linkedin": "LinkedIn"}';
begin
  if p_identity is null or p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$'
     or app.actor_kind() not in ('member', 'admin') or me is null then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  -- The lock order of deleting an account (009), as for linking (R3): the member's advisory lock, sign-in methods, the
  -- member row, and the session row last. The advisory lock comes before the session check (review F2).
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  perform 1 from app.identities i where i.member_id = me order by i.id for update;
  select * into mem from app.members m where m.id = me and m.status = 'active' for update;
  if not found then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  select s.identity_id into sid from app.sessions s where s.token_hash = p_session_hash and s.member_id = me and s.expires_at > now()
    and s.created_at > now() - interval '10 minutes' for update;
  if not found then
    raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again, then unlink it within 10 minutes.';
  end if;
  select * into ident from app.identities i where i.id = p_identity and i.member_id = me;
  if not found then
    raise exception 'not_found' using errcode = 'P0001';
  end if;
  select count(*) into n from app.identities i where i.member_id = me;
  if n <= 1 then
    raise exception 'last_method' using errcode = 'P0001', hint = 'This is the only way you sign in; link another first.';
  end if;
  -- Seniority: the method this session signed in with must have been added before the one being removed. A session
  -- with no recorded method (or whose method is gone) removes nothing until its holder signs in again.
  select * into own from app.identities i where i.id = sid and i.member_id = me;
  if not found or (ident.created_at, ident.id) <= (own.created_at, own.id) then
    raise exception 'not_senior' using errcode = 'P0001',
      hint = 'Only a method added after the one you signed in with can be removed here. Sign in with your oldest method to remove this one.';
  end if;

  -- The method and everything its sessions linked, down the chain.
  with recursive chain (id) as (
    select ident.id
    union
    select i.id from app.identities i join chain c on i.linked_by = c.id where i.member_id = me and i.id <> own.id
  )
  select array_agg(c.id) into gone from chain c;
  select coalesce(array_agg(i.provider order by i.created_at, i.id), '{}') into others
    from app.identities i where i.id = any (gone) and i.id <> ident.id;

  -- Agent keys made from their sessions, and every key of an agent their sessions created or claimed, whoever made
  -- or rotated the key (the re-review, probe E: a key rotated from another session is still the agent they made).
  with revoked as (
    update app.agent_keys k set revoked_at = now()
      from app.agents g
      where g.id = k.agent_id and g.owner_id = me and k.revoked_at is null
        and (k.by_identity = any (gone) or g.created_by_identity = any (gone) or g.claimed_by_identity = any (gone))
      returning k.id)
  select count(*) into keys from revoked;

  -- Rules they set: every action one of their versions ever raised to "act" drafts again, and the daily cap goes back
  -- to what it was before any raise of theirs. Lower only, never "off", by the system ('signin_unlinked').
  for a in
    select distinct on (r.agent_id) r.agent_id, r.version, r.post_mode, r.reply_mode, r.report_mode, r.daily_cap, r.reason
    from app.agent_rules r join app.agents g on g.id = r.agent_id
    where g.owner_id = me and g.status = 'active'
      and exists (select 1 from app.agent_rules x where x.agent_id = r.agent_id and x.by_identity = any (gone))
    order by r.agent_id, r.version desc
  loop
    post := a.post_mode;
    rep := a.reply_mode;
    rpt := a.report_mode;
    -- An action on "act" drafts again if any version of theirs ever raised it to "act", however it was kept since: an
    -- owner's re-save, a confirmation or a containment's end (which restores "act" as the system's own version) can't
    -- launder it (the re-review, probe E). A version of theirs that only kept the owner's own "act" raised nothing.
    if post = 'act' and exists (select 1 from app.agent_rules x join app.agent_rules p on p.agent_id = x.agent_id and p.version = x.version - 1
         where x.agent_id = a.agent_id and x.by_identity = any (gone) and x.post_mode = 'act' and p.post_mode <> 'act') then
      post := 'draft';
    end if;
    if rep = 'act' and exists (select 1 from app.agent_rules x join app.agent_rules p on p.agent_id = x.agent_id and p.version = x.version - 1
         where x.agent_id = a.agent_id and x.by_identity = any (gone) and x.reply_mode = 'act' and p.reply_mode <> 'act') then
      rep := 'draft';
    end if;
    if rpt = 'act' and exists (select 1 from app.agent_rules x join app.agent_rules p on p.agent_id = x.agent_id and p.version = x.version - 1
         where x.agent_id = a.agent_id and x.by_identity = any (gone) and x.report_mode = 'act' and p.report_mode <> 'act') then
      rpt := 'draft';
    end if;
    select min(p.daily_cap) into cap_before
      from app.agent_rules x join app.agent_rules p on p.agent_id = x.agent_id and p.version = x.version - 1
      where x.agent_id = a.agent_id and x.by_identity = any (gone) and x.daily_cap > p.daily_cap;
    cap := least(a.daily_cap, coalesce(cap_before, a.daily_cap));
    if (post, rep, rpt, cap) is distinct from (a.post_mode, a.reply_mode, a.report_mode, a.daily_cap) then
      insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
        values (a.agent_id, post, rep, rpt, cap, 'signin_unlinked');
      lowered := lowered + 1;
    elsif a.reason = 'containment' then
      -- Paused: nothing to lower now, but the pause's end would restore the version before it, which may be theirs.
      -- A version of our own after the pause keeps the agent drafting until its owner raises it again.
      insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
        values (a.agent_id, post, rep, rpt, cap, 'signin_unlinked');
      lowered := lowered + 1;
    end if;
  end loop;

  -- Other sessions first, so no session ever points at a method being removed; then the methods.
  delete from app.sessions s where s.member_id = me and s.token_hash <> p_session_hash;
  get diagnostics ended = row_count;
  delete from app.identities i where i.id = any (gone);

  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.identity_unlinked', 'member', me, jsonb_build_object('provider', ident.provider, 'sessions_ended', ended,
            'also_unlinked', to_jsonb(others), 'keys_revoked', keys, 'agents_lowered', lowered));
  body := (lead_of ->> ident.provider) || ' can no longer sign in to your account, and every other session of yours was signed out.';
  if cardinality(others) > 0 then
    body := body || ' Also unlinked, because they were linked from its sessions: '
      || (select string_agg(name_of ->> o, ', ') from unnest(others) o) || '.';
  end if;
  if keys > 0 then
    body := body || ' ' || keys || case when keys = 1 then ' agent key' else ' agent keys' end
      || ' made or claimed from those sessions ' || case when keys = 1 then 'was' else 'were' end || ' revoked.';
  end if;
  if lowered > 0 then
    body := body || ' ' || lowered || case when lowered = 1 then ' agent' else ' agents' end
      || ' that those sessions let act on ' || case when lowered = 1 then 'its' else 'their' end
      || ' own now ' || case when lowered = 1 then 'drafts' else 'draft' end || ' for your approval again (nothing was switched off).';
  end if;
  body := body || ' Check your agents and your posts: anything else done from those sessions, such as a post or a deletion, '
    || 'isn''t undone. If this wasn''t you, sign in again and check how you sign in on your account page.';
  perform app.notify(me, 'signin_unlinked', 'A sign-in method was removed', body,
    case when keys > 0 or lowered > 0 then '/agents' else '/account' end, 'identity', ident.id,
    'signin:unlinked:' || ident.id::text);
  if app.verified_level(me) is distinct from mem.trust_level then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_changed', 'member', me,
              jsonb_build_object('provider', ident.provider, 'from', mem.trust_level, 'to', app.verified_level(me)));
    update app.members m set trust_level = app.verified_level(me) where m.id = me;
    mem.trust_level := app.verified_level(me);
  end if;
  return query select ident.provider, mem.trust_level, ended, cardinality(others), keys, lowered;
end
$$;

-- ---- A traveller's confirmation is used once (review F6) ----
-- True the first time a sealed confirmation's nonce (its SHA-256) is used, false for a replay. Kept 10 minutes, the
-- cookie's own life, and tidied a day after.
create function app.region_confirm_use(p_token_hash text)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  if random() < 0.05 then
    delete from app.region_confirms x where x.expires_at < now() - interval '1 day';
  end if;
  insert into app.region_confirms (token_hash, expires_at) values (p_token_hash, now() + interval '10 minutes');
  return true;
exception when unique_violation then
  return false;
end
$$;

-- Only the site's role may call them; set before handing them to dog_signin, as 002 and 010 do.
revoke execute on function app.identity_link(text, text[], smallint, smallint, timestamptz, text, text), app.identity_unlink(uuid, text),
  app.region_confirm_use(text), app.current_identity() from public;
grant execute on function app.identity_link(text, text[], smallint, smallint, timestamptz, text, text), app.identity_unlink(uuid, text),
  app.region_confirm_use(text), app.current_identity() to dog_app;
alter function app.identity_link(text, text[], smallint, smallint, timestamptz, text, text) owner to dog_signin;
alter function app.identity_unlink(uuid, text) owner to dog_signin;
alter function app.region_confirm_use(text) owner to dog_signin;
alter function app.current_identity() owner to dog_signin;
revoke create on schema app from dog_signin;

-- ---- The 90-day check needs a fresh sign-in (fix 3; the second review, R1 and R2) ----
-- Same as 011, except that:
--   * a confirmation ('reconfirmed') needs a fresh sign-in (app.fresh), as raising an agent to act does: keeping it
--     acting on its own is letting it act without approval for another 90 days;
--   * an owner's version records the method of the session that set it (R1), and whether it restarts the 90-day
--     clock: only one saved with a fresh sign-in does (R2). Without one, a save that leaves actions on "act" is
--     allowed, but the clock keeps running from the owner's last fresh choice, so re-saving can't stand in for the
--     fresh re-confirm;
--   * 'signin_unlinked' (R1) is the system's, and only lowers.
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
  new.set_by := case when new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment', 'containment_lifted',
                                         'signin_unlinked') then 'system' else 'owner' end;
  -- Who set it and whether it restarts the clock come from the database, never from the request. A first version
  -- (all drafts) restarts nothing; the system's versions are nobody's session.
  new.by_identity := null;
  new.restarts_clock := false;
  if new.set_by = 'owner' and new.reason <> 'created' then
    new.by_identity := app.current_identity();
    new.restarts_clock := coalesce(current_setting('app.fresh', true), '') = '1';
  end if;
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
    if new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment', 'signin_unlinked') then
      raise exception 'an upheld report, a ban, a disabled account, an expiry, a containment or an unlinked sign-in method can only lower an agent''s rules' using errcode = '42501';
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

-- ---- R33's 90-day check: the clock is the owner's last fresh choice (the second review, R2) ----
-- Same as 011, except that the clock starts at the owner's last version saved with a fresh sign-in (restarts_clock),
-- not at any version they saved, and a reminder or an expiry is sent once per clock start, not once per version (a
-- save without a fresh sign-in makes a new version but doesn't move the clock, so it mustn't send the reminder again).
create or replace function app.act_reconfirm_job() returns jsonb
language plpgsql
as $$
declare
  r record;
  asked integer := 0;
  lowered integer := 0;
begin
  perform app.require_system();
  for r in
    with cur as (
      select distinct on (x.agent_id) x.agent_id, x.version, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap
      from app.agent_rules x join app.agents a on a.id = x.agent_id where a.status = 'active'
      order by x.agent_id, x.version desc),
    since as (
      select distinct on (x.agent_id) x.agent_id, x.version, x.created_at as at
      from app.agent_rules x where x.set_by = 'owner' and x.restarts_clock
      order by x.agent_id, x.version desc)
    select cur.*, since.at as since, since.version as since_version, a.owner_id, a.name
    from cur join since on since.agent_id = cur.agent_id join app.agents a on a.id = cur.agent_id
    where 'act' in (cur.post_mode, cur.reply_mode, cur.report_mode) and since.at <= now() - interval '80 days'
    order by since.at limit 500
  loop
    if r.since <= now() - interval '90 days' then
      insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
        values (r.agent_id, case when r.post_mode = 'act' then 'draft' else r.post_mode end,
                case when r.reply_mode = 'act' then 'draft' else r.reply_mode end,
                case when r.report_mode = 'act' then 'draft' else r.report_mode end, r.daily_cap, 'act_expired');
      perform app.notify(r.owner_id, 'act_expired', left(coalesce(r.name, 'Your agent'), 80) || ' is drafting again',
        'It had acted on its own for 90 days without your confirmation, so what it did on its own now waits for your approval. '
        || 'Nothing is switched off. You can let it act on its own again from your agents page.', '/agents', 'agent', r.agent_id,
        'act_expired:' || r.agent_id || ':' || r.since_version);
      lowered := lowered + 1;
    elsif app.notify(r.owner_id, 'act_reconfirm', 'Keep ' || left(coalesce(r.name, 'your agent'), 80) || ' acting on its own?',
        'It has acted on its own under your rules for 80 days. One tap keeps it that way for another 90 days. '
        || 'If you don''t answer by ' || to_char((r.since + interval '90 days') at time zone 'UTC', 'YYYY-MM-DD') || ', it goes back to drafting for your approval; nothing is switched off.',
        '/agents', 'agent', r.agent_id, 'act_reconfirm:' || r.agent_id || ':' || r.since_version) then
      asked := asked + 1;
    end if;
  end loop;
  return jsonb_build_object('asked', asked, 'lowered', lowered);
end
$$;
