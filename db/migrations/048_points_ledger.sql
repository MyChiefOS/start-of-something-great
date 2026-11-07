-- 048 An append-only points ledger, so the points can back payments later (Aaron, Nov 7: "Make that change now";
-- the provider will be Stripe; money earned is public only if the person or the agent's owner chooses).
--   * app.work_point_entries: every change to a citizen's points as a new row, never an edit. Two buckets, pending and
--     final: a pass adds its points to pending (earned); the end of its dispute window moves them from pending to final
--     (two rows, final); a reversal takes them out of the bucket they were in (reversed). A bucket's balance is the sum
--     of its rows, and it may go below zero (a reversal after a payout would be paid back from later earnings).
--   * Rows can't be changed or deleted: a trigger refuses it, for every role. The one exception is deleting an account,
--     which deletes its points (Privacy) and with them their rows, as the cascade from app.work_points.
--   * The work module's functions are unchanged: triggers on app.work_points write the rows, so no path can change
--     points without a row. The rows already owed are written here, from app.work_points as it stands.
--   * Points stay what they are: public signs of audited work, for people and agents alike. Nothing here is money, and
--     nothing here is shown publicly yet.

set local role dog_owner;

create table app.work_point_entries (
  id uuid primary key default app.uuid_v7(),
  points_id uuid not null references app.work_points (id) on delete cascade,
  submission_id uuid not null,
  citizen_kind text not null check (citizen_kind = any (array['member', 'agent', 'github'])),
  citizen_member uuid,
  citizen_agent uuid,
  citizen_github text check (char_length(citizen_github) <= 39),
  room_id uuid not null,
  kind text not null check (kind = any (array['earned', 'final', 'reversed'])),
  bucket text not null check (bucket = any (array['pending', 'final'])),
  amount integer not null check (amount between -1000 and 1000 and amount <> 0),
  at timestamptz not null default now()
);
create index work_point_entries_points on app.work_point_entries (points_id);
create index work_point_entries_member on app.work_point_entries (citizen_member) where citizen_member is not null;
create index work_point_entries_agent on app.work_point_entries (citizen_agent) where citizen_agent is not null;
alter table app.work_point_entries enable row level security;
alter table app.work_point_entries force row level security;
create policy work_point_entries_work on app.work_point_entries for all to dog_work using (true) with check (true);
grant select, insert on app.work_point_entries to dog_work;

-- No change and no delete, by anyone, except the cascade from deleting an account's points.
create function app.work_point_entries_append_only()
returns trigger
language plpgsql set search_path = pg_catalog
as $$
begin
  if tg_op = 'DELETE' and pg_trigger_depth() > 1 then return old; end if;
  raise exception 'the points ledger is append-only' using errcode = '42501';
end
$$;
create trigger work_point_entries_no_change before update or delete on app.work_point_entries for each row execute function app.work_point_entries_append_only();
create trigger work_point_entries_no_truncate before truncate on app.work_point_entries for each statement execute function app.work_point_entries_append_only();
alter table app.work_point_entries enable always trigger work_point_entries_no_change;
alter table app.work_point_entries enable always trigger work_point_entries_no_truncate;

-- The rows for one change to app.work_points: what was earned, made final or reversed.
create function app.work_points_ledger()
returns trigger
language plpgsql set search_path = pg_catalog
as $$
declare
  rows jsonb := '[]';
begin
  if tg_op = 'INSERT' then
    if new.points > 0 then rows := jsonb_build_array(jsonb_build_object('kind', 'earned', 'bucket', 'pending', 'amount', new.points)); end if;
    if new.status = 'final' and new.points > 0 then
      rows := rows || jsonb_build_array(jsonb_build_object('kind', 'final', 'bucket', 'pending', 'amount', -new.points),
                                        jsonb_build_object('kind', 'final', 'bucket', 'final', 'amount', new.points));
    elsif new.status = 'removed' and new.points > 0 then
      rows := rows || jsonb_build_array(jsonb_build_object('kind', 'reversed', 'bucket', 'pending', 'amount', -new.points));
    end if;
  elsif tg_op = 'UPDATE' then
    if new.points <> old.points then raise exception 'points are changed only by a new row' using errcode = '42501'; end if;
    if new.status is distinct from old.status and new.points > 0 then
      rows := case
        when old.status = 'pending' and new.status = 'final' then
          jsonb_build_array(jsonb_build_object('kind', 'final', 'bucket', 'pending', 'amount', -new.points),
                            jsonb_build_object('kind', 'final', 'bucket', 'final', 'amount', new.points))
        when new.status = 'removed' then
          jsonb_build_array(jsonb_build_object('kind', 'reversed', 'bucket', old.status, 'amount', -new.points))
        else null end;
      if rows is null then raise exception 'points can''t go from % to %', old.status, new.status using errcode = '42501'; end if;
    end if;
  end if;
  insert into app.work_point_entries (points_id, submission_id, citizen_kind, citizen_member, citizen_agent, citizen_github, room_id, kind, bucket, amount)
  select new.id, new.submission_id, new.citizen_kind, new.citizen_member, new.citizen_agent, new.citizen_github, new.room_id, r ->> 'kind', r ->> 'bucket', (r ->> 'amount')::integer
    from jsonb_array_elements(rows) r;
  return new;
end
$$;
create trigger work_points_ledger after insert or update on app.work_points for each row execute function app.work_points_ledger();
alter table app.work_points enable always trigger work_points_ledger;

-- The rows owed for the points that exist now: earned, then final or reversed as they stand.
insert into app.work_point_entries (points_id, submission_id, citizen_kind, citizen_member, citizen_agent, citizen_github, room_id, kind, bucket, amount, at)
select p.id, p.submission_id, p.citizen_kind, p.citizen_member, p.citizen_agent, p.citizen_github, p.room_id, x.kind, x.bucket, x.amount, x.at
  from app.work_points p
  cross join lateral (values ('earned', 'pending', p.points, p.created_at),
                             ('final', 'pending', -p.points, p.final_at), ('final', 'final', p.points, p.final_at),
                             ('reversed', 'pending', -p.points, now())) x(kind, bucket, amount, at)
 where p.points > 0
   and (x.kind = 'earned' or (x.kind = 'final' and p.status = 'final') or (x.kind = 'reversed' and p.status = 'removed'));

revoke execute on function app.work_point_entries_append_only(), app.work_points_ledger() from public;
