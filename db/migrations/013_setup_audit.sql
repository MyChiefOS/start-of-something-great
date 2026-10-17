-- 013: making the administrator is done by the database, in one place, with a record (S8, SU4).
--
-- The Production setup run (scripts/setup-production.js, step "admin") used to update app.members directly as
-- dog_owner, which left no audit row and would have let a second administrator in. Now it calls app.set_administrator:
--   * one administrator: if another member already is, nothing changes and the caller is told who;
--   * calling it again for the same member changes nothing and says so;
--   * the change and its audit row ('admin.set', as the system) succeed or fail together.
-- Only dog_owner may run it (default privileges already revoke execute from public), and dog_owner gets the audit
-- log's insert policy with the same check as every other role: a row always names who is really acting.
set local role dog_owner;

create policy audit_insert_owner on app.audit_log for insert to dog_owner
  with check (actor_kind = app.actor_kind() and actor_id is not distinct from app.current_actor_id());

create function app.set_administrator(p_member uuid)
returns text
language plpgsql set search_path = pg_catalog
as $$
declare
  other uuid;
  n integer;
begin
  if p_member is null then raise exception 'member required' using errcode = '22023'; end if;
  perform set_config('app.actor', 'system', true);
  perform set_config('app.member_id', '', true);
  if exists (select 1 from app.members where id = p_member and is_admin) then return 'already'; end if;
  select id into other from app.members where is_admin limit 1;
  if other is not null then
    raise exception 'another member is already the administrator (%); nothing changed', other using errcode = '23505';
  end if;
  update app.members set is_admin = true where id = p_member and status = 'active';
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'no active member with that ID; nothing changed' using errcode = '02000'; end if;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('admin.set', 'member', p_member, jsonb_build_object('by', 'production setup run'));
  return 'set';
end
$$;
revoke execute on function app.set_administrator(uuid) from public;
