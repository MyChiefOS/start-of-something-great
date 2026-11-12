-- 064 Funded work on the public pages, without public prices (Aaron, Nov 12, 2026: "Exact dollar prices stay off
--   unauthenticated public pages"; signed out, the home page and /build show the count of funded tasks, the total
--   funded pool per room and the bounty tiers; signed in, workers and agents see the exact net bounty on open tasks;
--   once a task is claimed, only the poster, the worker and the administrator see the amount).
--
--   1. 061 let anyone reach a listed bounty's amount through the site's role: its policy showed a funded bounty on an
--      open task to every caller, signed in or not. Nothing displayed it, but nothing stopped it. Now the open-task
--      branch is for a signed-in person or agent only; the payer, the payee and the administrator see theirs always.
--   2. app.work_market(): the public figures. The count of funded open tasks, how many in each tier, and each room's
--      count by tier. No dollar sum, overall or per room (Aaron, Nov 12, after the fresh review of PR #4 proved that
--      pools rounded to the $100 gave a task's price to about $100: the overall pool less the rooms shown, or the pool
--      before and after one task). Tiers: 1 $10 to under $100, 2 $100 to under $500, 3 $500 to under $2,500, 4 $2,500
--      and up; a task's tier is public, so counts by tier tell nothing more.
--   3. app.work_bounty_of(task): one task's bounty for whoever asks. Signed out: its tier while it is listed. Signed in:
--      also the exact net (the bounty less the 15% platform fee) while the task is open. Claimed or later: the amounts
--      only for its payer, its payee and the administrator. Never a Stripe ID.

-- ---- 1. The policy ----
set local role dog_owner;
drop policy work_bounties_app on app.work_bounties;
create policy work_bounties_app on app.work_bounties for select to dog_app using (
  payer_member = (select app.current_member()) or payee_member = (select app.current_member()) or (select app.actor_kind()) = 'admin'
  or (listed and status = 'funded' and (select app.actor_kind()) in ('member', 'agent')));
-- What the figures read about rooms.
create policy work_rooms_pay_select on app.work_rooms for select to dog_pay using (true);
grant select (id, code, name, ord) on app.work_rooms to dog_pay;
grant select (id, room_id) on app.work_tasks to dog_pay;
-- A bounty's tier, from its cents. Plain arithmetic, owned like everything not run with its owner's rights.
create function app.work_tier(p_cents integer) returns smallint
language sql immutable set search_path = pg_catalog as $$
  select case when p_cents is null then null when p_cents < 10000 then 1 when p_cents < 50000 then 2 when p_cents < 250000 then 3 else 4 end::smallint
$$;

revoke execute on function app.work_tier(integer) from public;
grant execute on function app.work_tier(integer) to dog_pay;
reset role;

-- ---- 2 and 3. The payment role's two reads ----
grant create on schema app to dog_pay;
set local role dog_pay;

-- Public, by design: counts and tiers only, never a dollar figure (no actor check; redteam/reviewed-functions.json).
create function app.work_market() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  with f as (
    select b.bounty_cents, app.work_tier(b.bounty_cents) as tier, t.room_id
      from app.work_bounties b join app.work_tasks t on t.id = b.task_id
     where b.status = 'funded' and b.listed and t.status = 'open'),
  r as (
    select w.code, w.name, w.ord, count(f.*)::integer as n,
           jsonb_build_object('1', count(*) filter (where f.tier = 1), '2', count(*) filter (where f.tier = 2),
                              '3', count(*) filter (where f.tier = 3), '4', count(*) filter (where f.tier = 4)) as by_tier
      from app.work_rooms w left join f on f.room_id = w.id group by w.code, w.name, w.ord)
  select jsonb_build_object(
    'funded_tasks', (select count(*) from f),
    'tiers', (select jsonb_agg(jsonb_build_object('tier', x.tier, 'label', x.label, 'tasks', (select count(*) from f where f.tier = x.tier)) order by x.tier)
              from (values (1, '$10 to $100'), (2, '$100 to $500'), (3, '$500 to $2,500'), (4, '$2,500 and up')) as x(tier, label)),
    'rooms', coalesce((select jsonb_agg(jsonb_build_object('code', r.code, 'name', r.name, 'funded_tasks', r.n, 'tiers', r.by_tier)
                         order by r.ord) from r where r.n > 0), '[]'::jsonb),
    'fee_bps', 1500)
$$;

create function app.work_bounty_of(p_task uuid) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  b record;
  k text := app.actor_kind();
  me uuid := app.current_member();
  party boolean;
begin
  select x.bounty_cents, x.platform_fee_bps, x.status, x.listed, x.payer_member, x.payee_member, t.status as task_status
    into b from app.work_bounties x join app.work_tasks t on t.id = x.task_id
   where x.task_id = p_task and x.status <> 'failed' order by x.created_at desc limit 1;
  if not found then return null; end if;
  party := k = 'admin' or (me is not null and me in (b.payer_member, b.payee_member));
  if party then
    return jsonb_build_object('tier', app.work_tier(b.bounty_cents), 'status', b.status, 'bounty_cents', b.bounty_cents,
      'net_cents', b.bounty_cents - (b.bounty_cents * b.platform_fee_bps) / 10000);
  end if;
  -- Everyone else: only a funded bounty on an open task, and its exact net only for someone signed in.
  if not (b.status = 'funded' and b.listed and b.task_status = 'open') then return null; end if;
  if k in ('member', 'agent') then
    return jsonb_build_object('tier', app.work_tier(b.bounty_cents), 'status', b.status, 'net_cents', b.bounty_cents - (b.bounty_cents * b.platform_fee_bps) / 10000);
  end if;
  return jsonb_build_object('tier', app.work_tier(b.bounty_cents), 'status', b.status);
end $$;

revoke execute on function app.work_market(), app.work_bounty_of(uuid) from public;
grant execute on function app.work_market(), app.work_bounty_of(uuid) to dog_app;
reset role;
revoke create on schema app from dog_pay;

-- ---- The fresh review of PR #4, low: 061's task trigger kept quiet when it failed ----
-- 064's policy shows an amount to signed-in strangers only while the bounty is listed, and listed is reset by this
-- trigger's touch when a task leaves "open". A failure there now alerts Aaron as well as the log; it still never stops
-- the task's own change (Money never stops points or tasks, PM20).
grant create on schema app to dog_pay;
set local role dog_pay;
create or replace function app.work_tasks_pay()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  b record;
begin
  if new.status is not distinct from old.status then return new; end if;
  begin
    -- The price shows only while the task is open (the guard sets listed on every update).
    update app.work_bounties set updated_at = now() where task_id = new.id and status = 'funded';
    if new.status <> all (array['removed', 'closed']) then return new; end if;
    select * into b from app.work_bounties where task_id = new.id for update;
    if b.id is null or b.status <> 'funded' then return new; end if;
    if exists (select 1 from app.work_points p where p.task_id = new.id and p.status = 'final') then return new; end if;
    update app.work_bounties set status = 'refunding' where id = b.id;
    insert into app.pay_requests (member_id, kind, bounty_id) values (b.payer_member, 'refund', b.id) on conflict do nothing;
  exception when others then
    raise warning 'work_tasks_pay: %', sqlstate;
    begin
      perform app.notify(null, 'alert', 'A funded task''s money step failed',
        'Moving the money behind a task that changed state failed (' || sqlstate || '). Its price may still show to signed-in members, or its refund may not have started. Look at the task and its bounty.',
        '/admin/console', 'system', null, 'pay:task:' || new.id::text || ':' || new.status);
    exception when others then
      raise warning 'work_tasks_pay alert: %', sqlstate;
    end;
  end;
  return new;
end
$$;
reset role;
revoke create on schema app from dog_pay;
