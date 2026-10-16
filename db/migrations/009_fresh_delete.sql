-- PR 11 (preview readiness), RK3: deleting an account needs a fresh sign-in, as minting a key for an agent that acts
-- on its own already does (008). Same function as 008 otherwise; its owner (dog_erase) and grants are unchanged.

-- Replacing a function needs its owner's role, and that role needs the right to create here for these lines only.
grant create on schema app to dog_erase;
set local role dog_erase;
create or replace function app.delete_account()
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  n_posts integer; n_flags integer; n_my_reports integer; n_agents integer; n_keys integer; n_sessions integer; n_ids integer; n_brakes integer;
  n_drafts integer;
begin
  if app.actor_kind() <> 'member' or me is null then
    raise exception 'not_member' using errcode = '42501';
  end if;
  -- RK3: a stolen session cookie alone can't delete an account. The session must have started in the last few minutes
  -- (app.fresh, set only by db/index.js from the session's own start time, read from the database clock).
  if coalesce(current_setting('app.fresh', true), '') <> '1' then
    raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to delete your account.';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
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
  delete from app.agent_drafts d where d.owner_id = me;
  get diagnostics n_drafts = row_count;
  delete from app.agent_rules r where r.agent_id in (select a.id from app.agents a where a.owner_id = me);
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
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('member.deleted', 'member', me, jsonb_build_object('posts', n_posts, 'reports_on_posts', n_flags, 'reports_made', n_my_reports,
            'agents', n_agents, 'keys', n_keys, 'drafts', n_drafts, 'brakes', n_brakes, 'sessions', n_sessions, 'identities', n_ids));
  return query select n_posts, n_my_reports, n_agents, n_keys, n_sessions, n_ids;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_erase;
