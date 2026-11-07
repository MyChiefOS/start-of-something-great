-- 049 The points ledger's first rows, written again, correctly. 048 wrote the rows owed for the points that already
-- existed as dog_owner, which row-level security forced on app.work_points shows no rows: it wrote none, without an
-- error (found live on Nov 7: 101 points rows, 0 ledger rows). Here the work module's own role, which may read its
-- points, writes them, through a function that writes only what is missing, so running it again changes nothing.
-- New points since 048 already get their rows from its triggers (none had been made when this was found).

set local role dog_owner;
grant create on schema app to dog_work;
set local role dog_work;

create function app.work_points_ledger_backfill()
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
begin
  insert into app.work_point_entries (points_id, submission_id, citizen_kind, citizen_member, citizen_agent, citizen_github, room_id, kind, bucket, amount, at)
  select p.id, p.submission_id, p.citizen_kind, p.citizen_member, p.citizen_agent, p.citizen_github, p.room_id, x.kind, x.bucket, x.amount, x.at
    from app.work_points p
    cross join lateral (values ('earned', 'pending', p.points, p.created_at),
                               ('final', 'pending', -p.points, p.final_at), ('final', 'final', p.points, p.final_at),
                               ('reversed', 'pending', -p.points, now())) x(kind, bucket, amount, at)
   where p.points > 0
     and not exists (select 1 from app.work_point_entries e where e.points_id = p.id)
     and (x.kind = 'earned' or (x.kind = 'final' and p.status = 'final') or (x.kind = 'reversed' and p.status = 'removed'));
  get diagnostics n = row_count;
  return n;
end
$$;
revoke execute on function app.work_points_ledger_backfill() from public;

select app.work_points_ledger_backfill();

set local role dog_owner;
revoke create on schema app from dog_work;
