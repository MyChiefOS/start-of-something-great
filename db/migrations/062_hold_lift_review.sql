-- 062 Lifting a legal hold never erases an account that a deletion review still has open (the fresh review of PR #127;
-- Aaron, Nov 12: "the legal-hold guard so lifting a hold never erases an account with an open deletion review").
-- Before: app.legal_hold_lift (060) erased a held member who had asked to be deleted, at once. If our checks had also
-- opened a deletion review on that account (010), the erasure decided the review before Aaron did. Now the lift keeps
-- the account closed and leaves the decision to the review; it answers 'lifted_review_open'. The member's request to
-- be deleted stays recorded on the hold. Otherwise the function is unchanged.

grant create on schema app to dog_erase;
set local role dog_erase;

create or replace function app.legal_hold_lift(p_hold uuid, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  h app.legal_holds%rowtype;
begin
  if app.actor_kind() <> 'admin' then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  if p_hold is null or p_reason is null or char_length(btrim(p_reason)) not between 10 and 500 then
    raise exception 'bad legal hold request' using errcode = '22023';
  end if;
  select * into h from app.legal_holds x where x.id = p_hold for update;
  if not found then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  if h.lifted_at is not null then
    raise exception 'stale' using errcode = 'P0001';
  end if;
  update app.legal_holds x set lifted_at = now(), lifted_by = app.current_member(), lift_reason = btrim(p_reason) where x.id = h.id;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('legal_hold.lifted', 'member', h.member_id, jsonb_build_object('hold', h.id, 'deletion_requested', h.deletion_requested_at is not null));
  if h.deletion_requested_at is not null then
    -- An open deletion review decides first: the account stays closed until it does.
    if exists (select 1 from app.deletion_reviews r where r.member_id = h.member_id and r.decision is null) then
      return 'lifted_review_open';
    end if;
    perform app.erase_member(h.member_id);
    return 'lifted_deleted';
  end if;
  return 'lifted';
end
$$;

reset role;
set local role dog_owner;
revoke create on schema app from dog_erase;
