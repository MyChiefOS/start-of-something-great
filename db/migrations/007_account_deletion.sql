-- 007 Deleting an account (Release 2, PR 8).
-- Criterion: F8 a member can delete their account, and their personal data is removed.
--
-- What goes, in one transaction: the member, every way they sign in, their sessions, their posts (and the reports
-- about those posts), the reports they made, their agents and the agents' keys, any brake set on them,
-- and Aaron's notes about them (admin_notes).
-- What stays: the audit log (S7: nobody can edit or delete it). Its rows carry only IDs, which point at nothing once
-- the member is gone, and what happened (for example "post.remove"), never the member's name, text, accounts or
-- notes about them.
--
-- Deleting reaches rows the site's role can't touch, so it runs as its own narrow role, dog_erase, inside one
-- reviewed function, and only ever for the member the request acts as. Aaron can't delete himself this way, so the
-- site can't lose its administrator by accident. A banned member can't sign in, so can't use this; a deletion
-- request from them comes to Aaron by email (privacy policy, L2).

do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_erase') then
    create role dog_erase nologin noinherit nobypassrls;
  end if;
end
$roles$;
grant dog_erase to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_erase;

-- ---- Aaron's notes about a member live where they can be deleted ----
-- The audit log can't be edited, so it must never hold words about a person. Until now a ban, unban or hand-set
-- level copied Aaron's note into the log, and a brake copied its note too. From here on the note is kept in this
-- table, keyed to the member, and the log carries only the note's ID; deleting the account deletes the notes.
-- (No database has run 006 in production yet, so no note was ever written to a live log.)
create table app.admin_notes (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id),
  action text not null check (action = any (array['member.ban', 'member.unban', 'member.level_set'])),
  note text not null check (char_length(note) between 1 and 200),
  created_at timestamptz not null default now()
);
create index admin_notes_member on app.admin_notes (member_id);
alter table app.admin_notes enable row level security;
alter table app.admin_notes force row level security;
create policy admin_notes_select on app.admin_notes for select to dog_app using (app.actor_kind() = 'admin');
create policy admin_notes_insert on app.admin_notes for insert to dog_app with check (app.actor_kind() = 'admin');
grant select on app.admin_notes to dog_app;
grant insert (member_id, action, note) on app.admin_notes to dog_app;

create or replace function app.members_audit() returns trigger
language plpgsql
as $$
declare
  note text := left(nullif(current_setting('app.note', true), ''), 200);
  act text;
  nid uuid;
begin
  if new.status is distinct from old.status then
    act := case when new.status = 'banned' then 'member.ban' else 'member.unban' end;
  elsif new.trust_level is distinct from old.trust_level and current_user <> 'dog_signin' then
    -- Levels that sign-in sets are recorded by sign-in itself.
    act := 'member.level_set';
  else
    return null;
  end if;
  if note is not null then
    insert into app.admin_notes (member_id, action, note) values (new.id, act, note) returning id into nid;
  end if;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values (act, 'member', new.id, jsonb_strip_nulls(jsonb_build_object('note_id', nid,
            'from', case when act = 'member.level_set' then old.trust_level end, 'to', case when act = 'member.level_set' then new.trust_level end)));
  -- A ban and a level change in one update are two events.
  if act <> 'member.level_set' and new.trust_level is distinct from old.trust_level and current_user <> 'dog_signin' then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_set', 'member', new.id, jsonb_build_object('from', old.trust_level, 'to', new.trust_level));
  end if;
  return null;
end
$$;

-- A brake's note stays on the brake itself (deleted with the member it names); the record says only that it had one.
create or replace function app.brakes_audit() returns trigger
language plpgsql
as $$
begin
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values (case when tg_op = 'INSERT' then 'brake.on' else 'brake.off' end, 'brake', new.id,
            jsonb_strip_nulls(jsonb_build_object('scope', case when new.member_id is null then 'everyone' else 'member' end,
              'member', new.member_id, 'people_per_hour', new.people_per_hour, 'agent_posts_per_hour', new.agent_posts_per_hour,
              'new_agents_per_day', new.new_agents_per_day, 'has_note', case when new.note is not null then true end)));
  return null;
end
$$;

-- What dog_erase may do, inside app.delete_account only: read and delete a member's own rows. Locking the member's
-- row (so nothing new can be added for them while they are being deleted) needs an update right; it is on one
-- column, and the function never updates anything.
create policy members_erase_select on app.members for select to dog_erase using (true);
create policy members_erase_update on app.members for update to dog_erase using (true) with check (true);
create policy members_erase_delete on app.members for delete to dog_erase using (true);
grant select (id, status, is_admin), delete on app.members to dog_erase;
grant update (display_name) on app.members to dog_erase;

create policy identities_erase_select on app.identities for select to dog_erase using (true);
create policy identities_erase_delete on app.identities for delete to dog_erase using (true);
grant select (id, member_id), delete on app.identities to dog_erase;
create policy sessions_erase_select on app.sessions for select to dog_erase using (true);
create policy sessions_erase_delete on app.sessions for delete to dog_erase using (true);
grant select (id, member_id), delete on app.sessions to dog_erase;
create policy posts_erase_select on app.posts for select to dog_erase using (true);
create policy posts_erase_delete on app.posts for delete to dog_erase using (true);
grant select (id, author_id), delete on app.posts to dog_erase;
create policy review_flags_erase_select on app.review_flags for select to dog_erase using (true);
create policy review_flags_erase_delete on app.review_flags for delete to dog_erase using (true);
grant select (id, post_id, reporter_id), delete on app.review_flags to dog_erase;
create policy agents_erase_select on app.agents for select to dog_erase using (true);
create policy agents_erase_delete on app.agents for delete to dog_erase using (true);
grant select (id, owner_id), delete on app.agents to dog_erase;
create policy agent_keys_erase_select on app.agent_keys for select to dog_erase using (true);
create policy agent_keys_erase_delete on app.agent_keys for delete to dog_erase using (true);
grant select (id, agent_id), delete on app.agent_keys to dog_erase;
create policy admin_notes_erase_select on app.admin_notes for select to dog_erase using (true);
create policy admin_notes_erase_delete on app.admin_notes for delete to dog_erase using (true);
grant select (id, member_id), delete on app.admin_notes to dog_erase;
-- Locks only (see delete_account): the member's sign-ins and posts are locked before anything is deleted.
create policy identities_erase_update on app.identities for update to dog_erase using (true) with check (true);
grant update (key_version) on app.identities to dog_erase;
create policy posts_erase_update on app.posts for update to dog_erase using (true) with check (true);
grant update (body) on app.posts to dog_erase;
create policy brakes_erase_select on app.brakes for select to dog_erase using (true);
create policy brakes_erase_delete on app.brakes for delete to dog_erase using (true);
grant select (id, member_id), delete on app.brakes to dog_erase;

-- The record of the deletion names the real actor (the member, by ID), like every other audit row.
create policy audit_insert_erase on app.audit_log for insert to dog_erase
  with check (actor_kind = app.actor_kind() and actor_id is not distinct from app.current_actor_id());
grant insert (action, subject_kind, subject_id, detail) on app.audit_log to dog_erase;
grant execute on function app.uuid_v7(), app.actor_kind(), app.current_member(), app.current_agent(), app.current_actor_id() to dog_erase;

-- Deletes the signed-in member's account. Returns how many rows went from each place, for the record and the reply.
-- Raises 'not_member' for anyone but a signed-in member (Aaron included) and 'not_active' for a missing or banned one.
create function app.delete_account()
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  n_posts integer; n_flags integer; n_my_reports integer; n_agents integer; n_keys integer; n_sessions integer; n_ids integer; n_brakes integer;
begin
  if app.actor_kind() <> 'member' or me is null then
    raise exception 'not_member' using errcode = '42501';
  end if;
  -- Locks first, in the order signing in takes them (sign-ins, then the member), so the two can't deadlock. Then the
  -- member's posts, so a report or review arriving now waits and then finds nothing. Posting, claiming and signing in
  -- all wait for these locks, then find nobody.
  perform 1 from app.identities i where i.member_id = me for update;
  perform 1 from app.members m where m.id = me and m.status = 'active' and not m.is_admin for update;
  if not found then
    raise exception 'not_active' using errcode = '42501';
  end if;
  perform 1 from app.posts p where p.author_id = me for update;
  delete from app.review_flags f where f.post_id in (select p.id from app.posts p where p.author_id = me);
  get diagnostics n_flags = row_count;
  delete from app.review_flags f where f.reporter_id = me;
  get diagnostics n_my_reports = row_count;
  delete from app.posts p where p.author_id = me;
  get diagnostics n_posts = row_count;
  delete from app.agent_keys k where k.agent_id in (select a.id from app.agents a where a.owner_id = me);
  get diagnostics n_keys = row_count;
  delete from app.agents a where a.owner_id = me;
  get diagnostics n_agents = row_count;
  delete from app.brakes b where b.member_id = me;
  get diagnostics n_brakes = row_count;
  delete from app.admin_notes x where x.member_id = me;
  delete from app.sessions s where s.member_id = me;
  get diagnostics n_sessions = row_count;
  delete from app.identities i where i.member_id = me;
  get diagnostics n_ids = row_count;
  delete from app.members m where m.id = me;
  -- Counts only: the record never keeps what was deleted.
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.deleted', 'member', me, jsonb_build_object('posts', n_posts, 'reports_on_posts', n_flags, 'reports_made', n_my_reports,
            'agents', n_agents, 'keys', n_keys, 'brakes', n_brakes, 'sessions', n_sessions, 'identities', n_ids));
  return query select n_posts, n_my_reports, n_agents, n_keys, n_sessions, n_ids;
end
$$;

revoke execute on function app.delete_account(), app.members_audit(), app.brakes_audit() from public;
grant execute on function app.delete_account() to dog_app;
grant create on schema app to dog_erase;
alter function app.delete_account() owner to dog_erase;
revoke create on schema app from dog_erase;
