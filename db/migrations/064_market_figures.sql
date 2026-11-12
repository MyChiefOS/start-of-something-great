-- 064 Funded work on the public pages, without public prices (Aaron, Nov 12, 2026: "Exact dollar prices stay off
--   unauthenticated public pages"; signed out, the home page and /build show the count of funded tasks, the total
--   funded pool per room and the bounty tiers; signed in, workers and agents see the exact net bounty on open tasks;
--   once a task is claimed, only the poster, the worker and the administrator see the amount).
--
--   1. 061 let anyone reach a listed bounty's amount through the site's role: its policy showed a funded bounty on an
--      open task to every caller, signed in or not. Nothing displayed it, but nothing stopped it. Now the open-task
--      branch is for a signed-in person or agent only; the payer, the payee and the administrator see theirs always.
--   2. app.work_market(): the public figures. The count of funded open tasks, how many in each tier, and each room's
--      count and pool. A room's pool shows only once it holds at least 3 funded tasks, and then rounded down to the
--      $100: with one task the pool would be that task's price (the leak harness/FACTS.md named, Nov 12). The overall
--      pool follows the same rule. Tiers: 1 $10 to under $100, 2 $100 to under $500, 3 $500 to under $2,500, 4
--      $2,500 and up.
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

-- Public, by design: counts, tiers and rounded pools only (no actor check; redteam/reviewed-functions.json).
create function app.work_market() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  with f as (
    select b.bounty_cents, app.work_tier(b.bounty_cents) as tier, t.room_id
      from app.work_bounties b join app.work_tasks t on t.id = b.task_id
     where b.status = 'funded' and b.listed and t.status = 'open'),
  r as (
    select w.code, w.name, w.ord, count(f.*)::integer as n, coalesce(sum(f.bounty_cents), 0)::bigint as cents
      from app.work_rooms w left join f on f.room_id = w.id group by w.code, w.name, w.ord)
  select jsonb_build_object(
    'funded_tasks', (select count(*) from f),
    -- At least 3 funded tasks, rounded down to the $100, or nothing.
    'pool_dollars', (select case when count(*) >= 3 then (sum(bounty_cents) / 10000) * 100 end from f),
    'pool_rule', 'A pool shows once it holds at least 3 funded tasks, rounded down to the $100, so no single price can be read from it.',
    'tiers', (select jsonb_agg(jsonb_build_object('tier', x.tier, 'label', x.label, 'tasks', (select count(*) from f where f.tier = x.tier)) order by x.tier)
              from (values (1, '$10 to $100'), (2, '$100 to $500'), (3, '$500 to $2,500'), (4, '$2,500 and up')) as x(tier, label)),
    'rooms', coalesce((select jsonb_agg(jsonb_build_object('code', r.code, 'name', r.name, 'funded_tasks', r.n,
                         'pool_dollars', case when r.n >= 3 then (r.cents / 10000) * 100 end) order by r.ord) from r where r.n > 0), '[]'::jsonb),
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
