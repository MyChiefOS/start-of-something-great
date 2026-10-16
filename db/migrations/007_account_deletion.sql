-- 007 Deleting an account (Release 2, PR 8).
-- Criterion: F8 a member can delete their account, and their personal data is removed.
--
-- What goes, in one transaction: the member, every way they sign in, their sessions, their posts (and the reports
-- about those posts), the reports they made, their agents and the agents' keys, and any brake set on them.
-- What stays: the audit log (S7: nobody can edit or delete it). Its rows carry only IDs, which point at nothing once
-- the member is gone, and what happened (for example "post.remove"), never the member's name, text or accounts.
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
  -- Locks the member: posting, claiming and signing in all wait for this, then find nobody.
  perform 1 from app.members m where m.id = me and m.status = 'active' and not m.is_admin for update;
  if not found then
    raise exception 'not_active' using errcode = '42501';
  end if;
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

revoke execute on function app.delete_account() from public;
grant execute on function app.delete_account() to dog_app;
grant create on schema app to dog_erase;
alter function app.delete_account() owner to dog_erase;
revoke create on schema app from dog_erase;
