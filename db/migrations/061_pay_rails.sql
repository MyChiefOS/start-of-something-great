-- 061 Funded bounties: the money rails under Build (Aaron, Nov 11, 2026: "Stick with Separate Charges and Transfers";
-- Stripe only; scale first; payouts through Stripe Connect Express onboarding; no member email stored; the site's
-- identity token goes only to the key broker).
--
-- The money path:
--   1. A poster funds an open task they posted. The database writes a request; the payment function (dog-pay, the only
--      code that talks to Stripe) makes a Stripe Checkout session on the platform's own Stripe account. The worker is
--      not known yet, so the charge can't be made on the worker's account (Stripe: separate charges and transfers).
--   2. Stripe's signed event says the payment succeeded: the bounty is funded. The funds sit in the platform's Stripe
--      balance until the task's points go final (claim, audit and dispute windows: up to 9 days, 042:81-83).
--   3. The points go final (048's final bucket): a trigger writes one release request. dog-pay transfers the bounty less
--      the platform fee to the worker's connected account. An agent's work pays its owner.
--   4. The points are removed before final, or the task is removed while funded: one refund request. Removed after the
--      transfer (a reversal, FACTS.md:301): one reversal request; Stripe reverses a transfer only while the worker's
--      balance covers it, so a failed reversal is a state of its own, never a lie.
-- The residual question for counsel (RISKS.md RK150): does holding funded bounties for up to 9 days make ChiefOS a
-- money transmitter anywhere? Engineering does not wait for the answer (Aaron); go-live does.
--
-- Controls in this file, not in the payment function: every state change of a bounty passes one trigger that allows
-- only the listed transitions, freezes the amount, fees and payer once funding starts, sets the payee only from the
-- final points' citizen, and allows a release only while those points are final. Each request has a unique key per
-- task and kind, and its id is Stripe's Idempotency-Key, so a repeat can never charge or pay twice. Each Stripe event
-- is recorded once. The money ledger is append-only. Amounts are private: a price shows only while its task is open
-- and unclaimed (earnings private by default, Nov 7).

do $pay_role$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_pay') then
    create role dog_pay nologin noinherit nobypassrls;
  end if;
end
$pay_role$;
grant dog_pay to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_pay;
grant execute on function app.uuid_v7(), app.actor_kind(), app.current_member() to dog_pay;
set local role dog_signin;
grant execute on function app.stamp_ok() to dog_pay;
set local role dog_owner;

-- ---- A member's Stripe connected account (Express), for payouts ----
create table app.pay_accounts (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null unique references app.members (id) on delete cascade,
  stripe_account text not null unique check (char_length(stripe_account) <= 64 and stripe_account ~ '^acct_[A-Za-z0-9]{8,59}$'),
  livemode boolean not null,
  payouts_enabled boolean not null default false,
  details_submitted boolean not null default false,
  updated_at timestamptz not null default now()
);

-- ---- The money behind a task ----
create table app.work_bounties (
  id uuid primary key default app.uuid_v7(),
  task_id uuid unique references app.work_tasks (id) on delete set null,
  payer_member uuid references app.members (id) on delete set null,
  payee_member uuid references app.members (id) on delete set null,
  bounty_cents integer not null check (bounty_cents between 1000 and 1000000),
  currency text not null default 'usd' check (currency = any (array['usd'])),
  platform_fee_bps smallint not null default 1500 check (platform_fee_bps between 0 and 3000),
  reviewer_fee_bps smallint not null default 200 check (reviewer_fee_bps between 0 and 500),
  livemode boolean,
  -- Listed: funded and its task still open, so its price shows publicly (kept by the triggers below; the site's role
  -- can't read the task table, so the policy reads this instead).
  listed boolean not null default false,
  status text not null default 'funding' check (status = any (array[
    'funding', 'funded', 'releasing', 'transferring', 'released', 'awaiting_payee', 'refunding', 'sending_refund', 'refunded',
    'reversing', 'reversed', 'reversal_failed', 'chargeback', 'failed'])),
  -- Points removed while a transfer is in flight at Stripe: the payment function reverses it as soon as the transfer is
  -- recorded (the fresh review of PR #2, C1: never refund money that was also paid out).
  undo_requested boolean not null default false,
  stripe_checkout_session_id text check (char_length(stripe_checkout_session_id) <= 255 and stripe_checkout_session_id ~ '^cs_(test|live)_[A-Za-z0-9]+$'),
  stripe_payment_intent_id text check (char_length(stripe_payment_intent_id) <= 255 and stripe_payment_intent_id ~ '^pi_[A-Za-z0-9]+$'),
  stripe_charge_id text check (char_length(stripe_charge_id) <= 255 and stripe_charge_id ~ '^(ch|py)_[A-Za-z0-9]+$'),
  stripe_transfer_id text check (char_length(stripe_transfer_id) <= 255 and stripe_transfer_id ~ '^tr_[A-Za-z0-9]+$'),
  stripe_refund_id text check (char_length(stripe_refund_id) <= 255 and stripe_refund_id ~ '^re_[A-Za-z0-9]+$'),
  charged_cents integer check (charged_cents between 0 and 1000000),
  transferred_cents integer check (transferred_cents between 0 and 1000000),
  funded_at timestamptz,
  released_at timestamptz,
  refunded_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (reviewer_fee_bps <= platform_fee_bps),
  check (not (stripe_transfer_id is not null and stripe_refund_id is not null)),
  check ((status = any (array['funded', 'releasing', 'released', 'awaiting_payee', 'refunding', 'refunded', 'reversing', 'reversed', 'reversal_failed', 'chargeback']))
         <= (stripe_payment_intent_id is not null and charged_cents is not null and livemode is not null)),
  check ((status = any (array['released', 'reversing', 'reversed', 'reversal_failed'])) <= (stripe_transfer_id is not null and transferred_cents is not null)),
  check ((status = 'refunded') <= (stripe_refund_id is not null)),
  check (transferred_cents is null or transferred_cents <= charged_cents - (bounty_cents::bigint * platform_fee_bps / 10000))
);
create index work_bounties_funded on app.work_bounties (status) where status = 'funded';

-- ---- Requests for the payment function: written only by the functions and triggers below ----
create table app.pay_requests (
  id uuid primary key default app.uuid_v7(),                 -- also Stripe's Idempotency-Key
  member_id uuid references app.members (id) on delete set null,
  kind text not null check (kind = any (array['connect_onboard', 'fund_task', 'release', 'refund', 'reverse', 'reconcile'])),
  bounty_id uuid references app.work_bounties (id) on delete set null,
  status text not null default 'queued' check (status = any (array['queued', 'working', 'done', 'failed'])),
  attempts smallint not null default 0 check (attempts between 0 and 30),
  -- When it was last taken up, and when it may next be tried: Stripe replays a saved error for the same key for 24
  -- hours, so retries back off over hours (the fresh review of PR #2, H2).
  claimed_at timestamptz,
  next_at timestamptz not null default now(),
  hosted_url text check (char_length(hosted_url) <= 2048 and hosted_url ~ '^https://(checkout|connect)\.stripe\.com/[A-Za-z0-9/_#?=&%.-]+$'),
  stripe_object_id text check (char_length(stripe_object_id) <= 255 and stripe_object_id ~ '^[a-z]+_[A-Za-z0-9_]+$'),
  error_code text check (char_length(error_code) <= 64 and error_code ~ '^[a-z_]+$'),
  created_at timestamptz not null default now(),
  done_at timestamptz,
  check ((kind = any (array['fund_task', 'release', 'refund', 'reverse'])) = (bounty_id is not null) or bounty_id is null)
);
create index pay_requests_queue on app.pay_requests (next_at) where status = 'queued';
create unique index pay_requests_one_fund on app.pay_requests (bounty_id) where kind = 'fund_task' and status <> 'failed';
-- A release waits for a worker without a payout account (awaiting_payee) as a failed request, and a new one is made
-- when their account is ready; so the one-at-a-time rule counts only requests that haven't failed.
create unique index pay_requests_one_release on app.pay_requests (bounty_id) where kind = 'release' and status <> 'failed';
create unique index pay_requests_one_refund on app.pay_requests (bounty_id) where kind = 'refund' and status <> 'failed';
create unique index pay_requests_one_reverse on app.pay_requests (bounty_id) where kind = 'reverse' and status <> 'failed';

-- ---- Stripe's events, each recorded once ----
create table app.pay_events (
  id uuid primary key default app.uuid_v7(),
  stripe_event_id text not null unique check (char_length(stripe_event_id) <= 255 and stripe_event_id ~ '^evt_[A-Za-z0-9]+$'),
  type text not null check (char_length(type) <= 100 and type ~ '^[a-z_.]+$'),
  livemode boolean not null,
  object_id text check (char_length(object_id) <= 255 and object_id ~ '^[a-z]+_[A-Za-z0-9_]+$'),
  received_at timestamptz not null default now()
);

-- ---- The money ledger: append-only, private; amounts signed by kind ----
create table app.pay_ledger (
  id uuid primary key default app.uuid_v7(),
  bounty_id uuid references app.work_bounties (id) on delete set null,
  member_id uuid references app.members (id) on delete set null,
  kind text not null check (kind = any (array['charge', 'transfer', 'refund', 'reversal', 'chargeback'])),
  amount_cents bigint not null check (amount_cents between -100000000 and 100000000 and amount_cents <> 0),
  stripe_object_id text not null check (char_length(stripe_object_id) <= 255 and stripe_object_id ~ '^[a-z]+_[A-Za-z0-9_]+$'),
  at timestamptz not null default now(),
  unique (kind, stripe_object_id),
  check ((kind = any (array['charge', 'reversal'])) = (amount_cents > 0))
);

create function app.pay_ledger_append_only()
returns trigger
language plpgsql set search_path = pg_catalog
as $$
begin
  raise exception 'the money ledger is append-only' using errcode = '42501';
end
$$;
create trigger pay_ledger_no_change before update or delete on app.pay_ledger for each row execute function app.pay_ledger_append_only();
create trigger pay_ledger_no_truncate before truncate on app.pay_ledger for each statement execute function app.pay_ledger_append_only();
alter table app.pay_ledger enable always trigger pay_ledger_no_change;
alter table app.pay_ledger enable always trigger pay_ledger_no_truncate;

-- ---- A bounty's state machine ----
create function app.work_bounties_guard()
returns trigger
language plpgsql set search_path = pg_catalog
as $$
declare
  ok boolean;
  pts record;
begin
  if tg_op = 'INSERT' then
    if new.status <> 'funding' then raise exception 'a bounty starts as funding' using errcode = '42501'; end if;
    return new;
  end if;
  if new.bounty_cents <> old.bounty_cents or new.currency <> old.currency or new.platform_fee_bps <> old.platform_fee_bps
     or new.reviewer_fee_bps <> old.reviewer_fee_bps or new.payer_member is distinct from old.payer_member and new.payer_member is not null
     or old.livemode is not null and new.livemode is distinct from old.livemode then
    raise exception 'a bounty''s amount, fees, payer and mode are fixed' using errcode = '42501';
  end if;
  if new.task_id is distinct from old.task_id and new.task_id is not null then
    raise exception 'a bounty stays with its task' using errcode = '42501';
  end if;
  if new.status is distinct from old.status then
    ok := (old.status, new.status) in (
      ('funding', 'funded'), ('funding', 'failed'),
      ('funded', 'releasing'), ('funded', 'refunding'), ('funded', 'chargeback'),
      ('releasing', 'transferring'), ('releasing', 'awaiting_payee'), ('releasing', 'refunding'), ('releasing', 'chargeback'),
      ('transferring', 'released'), ('transferring', 'releasing'),
      ('awaiting_payee', 'releasing'), ('awaiting_payee', 'refunding'), ('awaiting_payee', 'chargeback'),
      ('refunding', 'sending_refund'), ('refunding', 'chargeback'),
      ('sending_refund', 'refunded'), ('sending_refund', 'refunding'),
      ('released', 'reversing'), ('released', 'chargeback'),
      ('reversing', 'reversed'), ('reversing', 'reversal_failed'));
    if not ok then raise exception 'a bounty can''t go from % to %', old.status, new.status using errcode = '42501'; end if;
  end if;
  -- A release is only for points that are final, and pays only their citizen (an agent's work pays its owner).
  -- A transfer Stripe made is recorded whatever happened meanwhile (transferring to released); only starting one needs
  -- final points.
  if (new.status = any (array['releasing', 'transferring']) and old.status <> 'transferring' and (old.status is distinct from new.status or new.payee_member is distinct from old.payee_member))
     or (new.payee_member is distinct from old.payee_member and new.payee_member is not null) then
    select p.status, coalesce(p.citizen_member, a.owner_id) as member into pts
      from app.work_points p left join app.agents a on a.id = p.citizen_agent
      where p.task_id = new.task_id and p.status = 'final' order by p.created_at desc limit 1;
    if pts.status is null then raise exception 'a bounty is released only when its points are final' using errcode = '42501'; end if;
    if new.payee_member is distinct from pts.member then raise exception 'a bounty pays the citizen of its final points' using errcode = '42501'; end if;
  end if;
  if new.payee_member is distinct from old.payee_member and old.payee_member is not null then
    raise exception 'a bounty''s payee is fixed once set' using errcode = '42501';
  end if;
  new.listed := new.status = 'funded' and exists (select 1 from app.work_tasks t where t.id = new.task_id and t.status = 'open');
  new.updated_at := now();
  return new;
end
$$;
create trigger work_bounties_guard before insert or update on app.work_bounties for each row execute function app.work_bounties_guard();
alter table app.work_bounties enable always trigger work_bounties_guard;

-- ---- Row-level security ----
alter table app.pay_accounts enable row level security;
alter table app.pay_accounts force row level security;
alter table app.work_bounties enable row level security;
alter table app.work_bounties force row level security;
alter table app.pay_requests enable row level security;
alter table app.pay_requests force row level security;
alter table app.pay_events enable row level security;
alter table app.pay_events force row level security;
alter table app.pay_ledger enable row level security;
alter table app.pay_ledger force row level security;

-- The payment function's role works on every money row; the database's triggers above keep it honest.
create policy pay_accounts_pay on app.pay_accounts for all to dog_pay using (true) with check (true);
create policy work_bounties_pay on app.work_bounties for all to dog_pay using (true) with check (true);
create policy pay_requests_pay on app.pay_requests for all to dog_pay using (true) with check (true);
create policy pay_events_pay on app.pay_events for all to dog_pay using (true) with check (true);
create policy pay_ledger_pay on app.pay_ledger for all to dog_pay using (true) with check (true);
grant select, insert, update on app.pay_accounts, app.pay_requests to dog_pay;
grant select, insert, update on app.work_bounties to dog_pay;
grant select, insert on app.pay_events, app.pay_ledger to dog_pay;

-- The site's role: a member sees their own connected account and requests; a bounty's amount only while its task is
-- open (the funded-bounty list), or to its payer, its payee and the administrator. One policy a table.
create policy pay_accounts_app on app.pay_accounts for select to dog_app using (member_id = (select app.current_member()));
create policy pay_requests_app on app.pay_requests for select to dog_app using (member_id = (select app.current_member()));
create policy work_bounties_app on app.work_bounties for select to dog_app using (
  payer_member = (select app.current_member()) or payee_member = (select app.current_member()) or (select app.actor_kind()) = 'admin'
  or (listed and status = 'funded'));
create policy pay_ledger_app on app.pay_ledger for select to dog_app using (member_id = (select app.current_member()) or (select app.actor_kind()) = 'admin');
grant select (id, member_id, livemode, payouts_enabled, details_submitted, updated_at) on app.pay_accounts to dog_app;
grant select (id, member_id, kind, bounty_id, status, hosted_url, error_code, created_at, done_at) on app.pay_requests to dog_app;
grant select (id, task_id, payer_member, payee_member, bounty_cents, currency, platform_fee_bps, status, listed, funded_at, released_at, refunded_at, created_at) on app.work_bounties to dog_app;
grant select (id, bounty_id, member_id, kind, amount_cents, at) on app.pay_ledger to dog_app;

-- What the payment function reads elsewhere.
create policy work_tasks_pay_select on app.work_tasks for select to dog_pay using (true);
grant select (id, title, status, poster_member) on app.work_tasks to dog_pay;
create policy work_points_pay_select on app.work_points for select to dog_pay using (true);
grant select (id, task_id, status, citizen_kind, citizen_member, citizen_agent, created_at) on app.work_points to dog_pay;
create policy agents_pay_select on app.agents for select to dog_pay using (true);
grant select (id, owner_id) on app.agents to dog_pay;
create policy members_pay_select on app.members for select to dog_pay using (true);
grant select (id, status) on app.members to dog_pay;

-- The payment function alerts the administrators (in-app, as the work module does) when money is stuck: a release or
-- refund that failed for good, a reversal Stripe refused, a funding that arrived for a task no longer open.
grant execute on function app.notify(uuid, text, text, text, text, text, uuid, text) to dog_pay;
create policy notices_pay_insert on app.notices for insert to dog_pay with check (member_id is null and kind = 'alert');
grant insert (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key) on app.notices to dog_pay;

-- ---- The functions, owned by dog_pay ----
grant create on schema app to dog_pay;
set local role dog_pay;

-- (The site rate-limits both requests with app.rate_limit_hit before calling, as every route does: db/pay.js.)
-- A poster funds an open task they posted: $10 to $10,000. Only a person, never an agent. Returns the request's id; the
-- site reads its hosted_url (Stripe Checkout) when the payment function has made it.
create function app.bounty_fund_request(p_task uuid, p_cents integer)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  t record;
  b record;
  rid uuid;
begin
  if me is null or app.actor_kind() not in ('member', 'admin') then raise exception 'only a person signed in on the site funds a task or sets up payouts' using errcode = '42501'; end if;
  if p_task is null or p_cents is null or p_cents not between 1000 and 1000000 then raise exception 'a bounty is $10 to $10,000, in cents' using errcode = '22023'; end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.bounty'), hashtext(p_task::text));
  select x.id, x.status, x.poster_member into t from app.work_tasks x where x.id = p_task;
  if t.id is null then raise exception 'task' using errcode = 'P0002'; end if;
  if t.poster_member is distinct from me then raise exception 'only the task''s poster funds it' using errcode = '42501'; end if;
  if t.status <> 'open' then raise exception 'work_pay_not_open' using errcode = 'P0001', hint = 'Only an open task can be funded.'; end if;
  select * into b from app.work_bounties where task_id = p_task;
  if b.id is not null and b.status <> 'failed' then raise exception 'work_pay_funded' using errcode = 'P0001', hint = 'This task is already funded, or its payment is under way.'; end if;
  if b.id is not null then update app.work_bounties set task_id = null where id = b.id; end if;
  insert into app.work_bounties (task_id, payer_member, bounty_cents) values (p_task, me, p_cents) returning id into b;
  insert into app.pay_requests (member_id, kind, bounty_id) values (me, 'fund_task', b.id) returning id into rid;
  return rid;
end
$$;

-- A member asks for Stripe's onboarding link, to be paid. Only a person.
create function app.connect_onboard_request()
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  rid uuid;
begin
  if me is null or app.actor_kind() not in ('member', 'admin') then raise exception 'only a person signed in on the site funds a task or sets up payouts' using errcode = '42501'; end if;
  insert into app.pay_requests (member_id, kind) values (me, 'connect_onboard') returning id into rid;
  return rid;
end
$$;

-- Points going final or removed move the money: one request each, never two (the unique indexes above).
create function app.work_points_pay()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  b record;
  payee uuid;
begin
  if new.status is not distinct from old.status then return new; end if;
  -- Money never stops points going final (checks alert, never lock out; the fresh review of PR #2, M4): any error here
  -- is caught, the points change stands, and the bounty is left for the payment function's daily check, which alerts.
  begin
  select * into b from app.work_bounties where task_id = new.task_id for update;
  if b.id is null then return new; end if;
  if new.status = 'removed' and b.status = 'transferring' then
    update app.work_bounties set undo_requested = true where id = b.id;
    return new;
  end if;
  if new.status = 'final' and b.status = 'funded' then
    select coalesce(new.citizen_member, (select a.owner_id from app.agents a where a.id = new.citizen_agent)) into payee;
    update app.work_bounties set status = 'releasing', payee_member = payee where id = b.id;
    insert into app.pay_requests (member_id, kind, bounty_id) values (payee, 'release', b.id) on conflict do nothing;
  elsif new.status = 'removed' and b.status = any (array['funded', 'releasing', 'awaiting_payee']) then
    update app.work_bounties set status = 'refunding' where id = b.id;
    insert into app.pay_requests (member_id, kind, bounty_id) values (b.payer_member, 'refund', b.id) on conflict do nothing;
  elsif new.status = 'removed' and b.status = 'released' then
    update app.work_bounties set status = 'reversing' where id = b.id;
    insert into app.pay_requests (member_id, kind, bounty_id) values (b.payee_member, 'reverse', b.id) on conflict do nothing;
  end if;
  exception when others then
    raise warning 'work_points_pay: % (bounty of task %)', sqlstate, new.task_id;
  end;
  return new;
end
$$;

-- A funded task removed or closed with no final points refunds its payer.
create function app.work_tasks_pay()
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
  end;
  return new;
end
$$;

revoke execute on function app.bounty_fund_request(uuid, integer), app.connect_onboard_request(), app.work_points_pay(), app.work_tasks_pay() from public;
grant execute on function app.bounty_fund_request(uuid, integer), app.connect_onboard_request() to dog_app;
-- Only for making the two triggers below, as 056 does; taken back right after.
grant execute on function app.work_points_pay(), app.work_tasks_pay() to dog_owner;

-- A task deleted with its project or its poster's account (erasure) while funded refunds its payer first (the fresh
-- review of PR #2, M3). The bounty keeps its row, detached, for the record.
create function app.work_tasks_pay_delete()
returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  b record;
begin
  begin
    select * into b from app.work_bounties where task_id = old.id for update;
    if b.id is not null and b.status = any (array['funded', 'releasing', 'awaiting_payee']) then
      update app.work_bounties set status = 'refunding' where id = b.id;
      insert into app.pay_requests (member_id, kind, bounty_id) values (b.payer_member, 'refund', b.id) on conflict do nothing;
    end if;
  exception when others then
    raise warning 'work_tasks_pay_delete: %', sqlstate;
  end;
  return old;
end
$$;
revoke execute on function app.work_tasks_pay_delete() from public;
grant execute on function app.work_tasks_pay_delete() to dog_owner;

reset role;
set local role dog_owner;
revoke create on schema app from dog_pay;

create trigger work_points_pay after update of status on app.work_points for each row execute function app.work_points_pay();
create trigger work_tasks_pay after update of status on app.work_tasks for each row execute function app.work_tasks_pay();
create trigger work_tasks_pay_delete before delete on app.work_tasks for each row execute function app.work_tasks_pay_delete();

reset role;
set local role dog_pay;
revoke execute on function app.work_points_pay(), app.work_tasks_pay(), app.work_tasks_pay_delete() from dog_owner;
reset role;
set local role dog_owner;
