-- 034 Second Look v1 (Aaron, Oct 31: "Use this to build the narrow AI" with Kimi 3's plan, "Make sure you change code to
--   be able to run it on superbase and vercel here and the dayonegreat site", and "can you make the second look have
--   the capabilities of the kimi provide plans I shared"). Kimi's plan in this database:
--   * Modes, kept here so switching needs no deploy: off (nothing runs), shadow (it decides and logs, nothing changes)
--     and on (a clear publishes the post). It starts in shadow.
--   * The gate, checked here before the model runs and again when it decides: a post made on the site, held by JEVs
--     only for account age (J01), sign-in strength (J02), activity rate (J04), links (J07) or region (J13), no other
--     JEVs question above 0, JEVs's scoring didn't fail, and no report, appeal or first-post review open.
--   * A log of every decision (sl_decisions): the decision, the model's nine answers, the risk score, the reason, how
--     long it took and whether it failed closed.
--   * On: a clear publishes the post, closes JEVs's hold as decided by Second Look, tells the author, and tells Aaron
--     (his list of what it published). At most 10 a day. "Reject" only records: nothing is removed.
--   * The unlock (Kimi's shadow gate): shadow becomes on by itself only when Aaron's own decisions agreed with its
--     last 80 shadow clears since the mode last changed (he approved all 80 and removed none). A pause, or Aaron
--     switching the mode himself, starts that count again, so his "shadow" stays shadow until 80 fresh agreements (the
--     fresh review of v1, finding 1). Zero wrong in 80 alone doesn't prove 1 in 80 (the 95% upper bound is about 1 in
--     22); the stop below is what holds it to 1 in 80 while it runs. Aaron can also switch it on himself.
--   * Counts that outlive account deletion (the fresh review, finding 4): what it published, what Aaron removed, the
--     day's publications, and Aaron's decisions on its shadow clears (app.sl_outcomes, with no post or person in it),
--     so an author deleting their account can't erase the evidence the stop and the unlock rest on.
--   * The stop (Aaron's limit, "1 in 80"): Aaron removing a post Second Look published counts against it. When those
--     removals go above 1 in 80 of its publications (so the first one, until it has published 80), it pauses itself
--     back to shadow and alerts Aaron. A report on a post it published puts the post back on hold for him and alerts
--     him. Pausing never locks anyone out: the posts stay with Aaron, as they are today.
--   * A weekly report to Aaron: what it decided, his reversals, and the 95% Wilson bound on its error rate.
--   Who may do what: the site's role (dog_app) may only ask for the next eligible posts (app.sl_claim) and record a
--   decision on a post it was given (app.sl_decide); both are JEVs's (dog_jevs) and check everything themselves. An
--   administrator may switch the mode (app.sl_set_mode) and read the log and the report.
set local role dog_owner;

-- ---- Settings ----
create table app.sl_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  mode text not null default 'shadow' check (mode = any (array['off', 'shadow', 'on'])),
  model text not null default 'mistral/ministral-3b' check (model = any (array['mistral/ministral-3b'])),
  daily_clear_cap integer not null default 10 check (daily_clear_cap between 0 and 50),
  daily_call_cap integer not null default 300 check (daily_call_cap between 0 and 2000),
  unlock_n integer not null default 80 check (unlock_n between 80 and 10000),
  paused_reason text check (char_length(paused_reason) <= 300),
  last_claim_at timestamptz,
  last_report_at timestamptz,
  counted_since timestamptz not null default now(),  -- the unlock counts Aaron's decisions on shadow clears after this
  published_total integer not null default 0 check (published_total >= 0),
  reversed_total integer not null default 0 check (reversed_total >= 0),
  reported_total integer not null default 0 check (reported_total >= 0),
  clears_day date,
  clears_today integer not null default 0 check (clears_today >= 0),
  updated_at timestamptz not null default now()
);
insert into app.sl_settings default values;
alter table app.sl_settings enable row level security;
alter table app.sl_settings force row level security;
create policy sl_settings_jevs_select on app.sl_settings for select to dog_jevs using (true);
create policy sl_settings_jevs_update on app.sl_settings for update to dog_jevs using (true) with check (true);
grant select, update (mode, paused_reason, last_claim_at, last_report_at, updated_at, counted_since, published_total, reversed_total,
  reported_total, clears_day, clears_today) on app.sl_settings to dog_jevs;
create policy sl_settings_admin_select on app.sl_settings for select to dog_app using (app.actor_kind() = 'admin');
grant select (mode, model, daily_clear_cap, daily_call_cap, unlock_n, paused_reason, updated_at) on app.sl_settings to dog_app;

-- ---- Posts handed to the model, once each ----
create table app.sl_claims (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null unique references app.posts (id) on delete cascade,
  claimed_at timestamptz not null default now()
);
alter table app.sl_claims enable row level security;
alter table app.sl_claims force row level security;
create policy sl_claims_jevs on app.sl_claims for all to dog_jevs using (true) with check (true);
grant select, insert on app.sl_claims to dog_jevs;

-- ---- Every decision ----
create table app.sl_decisions (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null unique references app.posts (id) on delete cascade,
  version text not null check (version = any (array['v1'])),
  model text check (model = any (array['mistral/ministral-3b'])),
  mode text not null check (mode = any (array['shadow', 'on'])),
  decision text not null check (decision = any (array['clear', 'leave', 'reject'])),
  answers jsonb check (octet_length(answers::text) <= 400) check (jsonb_typeof(answers) = 'object'), -- null when there is no answer
  risk smallint not null check (risk between 0 and 100),
  reason text not null check (char_length(reason) between 1 and 1000),
  fail_closed boolean not null,
  error text check (char_length(error) <= 80),
  latency_ms integer not null check (latency_ms between 0 and 600000),
  published boolean not null default false,
  created_at timestamptz not null default now(),
  check (decision <> 'clear' or (answers is not null and not fail_closed and risk < 15))
);
alter table app.sl_decisions enable row level security;
alter table app.sl_decisions force row level security;
create policy sl_decisions_jevs on app.sl_decisions for all to dog_jevs using (true) with check (true);
grant select, insert, update (published) on app.sl_decisions to dog_jevs;
create policy sl_decisions_admin_select on app.sl_decisions for select to dog_app using (app.actor_kind() = 'admin');
grant select on app.sl_decisions to dog_app;

-- ---- Aaron's decision on each of its shadow clears: whether he approved the post, and when. No post, no person ----
create table app.sl_outcomes (
  id uuid primary key default app.uuid_v7(),
  decided_at timestamptz not null default now(),
  approved boolean not null
);
alter table app.sl_outcomes enable row level security;
alter table app.sl_outcomes force row level security;
create policy sl_outcomes_jevs on app.sl_outcomes for all to dog_jevs using (true) with check (true);
grant select, insert on app.sl_outcomes to dog_jevs;
create policy sl_outcomes_admin_select on app.sl_outcomes for select to dog_app using (app.actor_kind() = 'admin');
grant select on app.sl_outcomes to dog_app;

-- ---- What it published, and what happened to those posts ----
create table app.sl_releases (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null unique references app.posts (id) on delete cascade,
  decision_id uuid not null references app.sl_decisions (id) on delete cascade,
  created_at timestamptz not null default now(),
  reversed_at timestamptz,
  reported_at timestamptz
);
alter table app.sl_releases enable row level security;
alter table app.sl_releases force row level security;
create policy sl_releases_jevs on app.sl_releases for all to dog_jevs using (true) with check (true);
grant select, insert, update (reversed_at, reported_at) on app.sl_releases to dog_jevs;
create policy sl_releases_admin_select on app.sl_releases for select to dog_app using (app.actor_kind() = 'admin');
grant select on app.sl_releases to dog_app;

-- ---- What JEVs's role may now read and change, for Second Look ----
-- The post's words, to hand to the model (only for posts the gate lets through, in app.sl_claim).
grant select (body, published_at, first_published_at) on app.posts to dog_jevs;
-- Closing JEVs's own hold on a post Second Look publishes, and nothing else.
create policy review_flags_jevs_update on app.review_flags for update to dog_jevs
  using (source = 'classifier' and classifier = 'jevs' and resolved_at is null)
  with check (source = 'classifier' and classifier = 'jevs');
grant update (decision) on app.review_flags to dog_jevs;
-- Whether Aaron (a member) decided a flag, for the unlock and the report.
grant select (resolved_by) on app.review_flags to dog_jevs;
-- A flag Second Look closes has no member as its decider: allowed only for JEVs's own hold, approved.
alter table app.review_flags drop constraint review_flags_check5;
alter table app.review_flags add constraint review_flags_check5 check ((resolved_at is null) = (resolved_by is null)
  or (resolved_at is not null and resolved_by is null and source = 'classifier' and classifier = 'jevs' and decision = 'approve'));
-- The author's notice when Second Look publishes their post.
alter table app.notices drop constraint notices_kind_check;
alter table app.notices add constraint notices_kind_check check (kind = any (array['draft_waiting', 'draft_expired', 'report_upheld', 'brake_on',
  'contained', 'containment_lifted', 'appeal_decided', 'act_reconfirm', 'act_expired', 'challenge', 'account_flagged', 'alert',
  'signin_linked', 'signin_unlinked', 'signin_keyfile', 'post_published']));
drop policy notices_jevs_insert on app.notices;
create policy notices_jevs_insert on app.notices for insert to dog_jevs
  with check (kind in ('challenge', 'account_flagged', 'alert', 'post_published'));

-- Flags: Second Look may close JEVs's hold on a post it is publishing in this same transaction; every other close is
-- still a reviewer's, as before (004).
create or replace function app.review_flags_guard() returns trigger
language plpgsql
as $$
begin
  if old.resolved_at is not null then
    raise exception 'this flag is already closed' using errcode = '22023';
  end if;
  if new.decision is null then
    raise exception 'closing a flag needs a decision' using errcode = '22023';
  end if;
  if current_user = 'dog_jevs' and not app.is_reviewer() then
    if not (old.source = 'classifier' and old.classifier = 'jevs' and new.decision = 'approve'
            and exists (select 1 from app.sl_releases r where r.post_id = old.post_id and r.created_at = now())) then
      raise exception 'only a reviewer can close a flag' using errcode = '42501';
    end if;
    new.resolved_at := now();
    new.resolved_by := null;
    return new;
  end if;
  if not app.is_reviewer() then
    raise exception 'only a reviewer can close a flag' using errcode = '42501';
  end if;
  new.resolved_at := now();
  new.resolved_by := app.current_member();
  return new;
end
$$;

-- Posts: Second Look may publish a held post it is releasing in this same transaction, and put a post it published
-- back on hold when someone reports it. Everything else is unchanged from 010.
create or replace function app.posts_review_guard() returns trigger
language plpgsql
as $$
begin
  if not (app.is_reviewer() or current_user = 'dog_jevs') then
    raise exception 'only a reviewer can change a post' using errcode = '42501';
  end if;
  if (new.id, new.author_id, new.lane, new.agent_id, new.body, new.created_at, new.first_published_at, new.delegation, new.rules_version, new.draft_id)
     is distinct from (old.id, old.author_id, old.lane, old.agent_id, old.body, old.created_at, old.first_published_at, old.delegation, old.rules_version, old.draft_id) then
    raise exception 'a review changes only a post''s status' using errcode = '42501';
  end if;
  if new.status = old.status then
    new.published_at := old.published_at;
    return new;
  end if;
  if current_user = 'dog_jevs' then
    if old.status = 'live' and new.status = 'waiting' and old.created_at = now() then
      new.published_at := null;
      new.first_published_at := null;
      return new;
    elsif old.status in ('live', 'waiting') and new.status = 'removed' then
      new.published_at := null;
      return new;
    elsif old.status = 'waiting' and new.status = 'live'
          and exists (select 1 from app.jevs_challenges c where c.subject_id = new.id and c.status = 'confirmed') then
      new.published_at := now();
      new.first_published_at := coalesce(old.first_published_at, new.published_at);
      return new;
    elsif old.status = 'waiting' and new.status = 'live'
          and exists (select 1 from app.sl_releases r where r.post_id = new.id and r.created_at = now() and r.reversed_at is null) then
      new.published_at := now();
      new.first_published_at := coalesce(old.first_published_at, new.published_at);
      return new;
    elsif old.status = 'live' and new.status = 'waiting'
          and exists (select 1 from app.sl_releases r where r.post_id = new.id and r.reported_at = now()) then
      new.published_at := null;
      return new;
    end if;
    raise exception 'JEVs can''t move a post from % to %', old.status, new.status using errcode = '22023';
  end if;
  if not ((old.status = 'waiting' and new.status in ('live', 'removed'))
       or (old.status = 'live' and new.status = 'removed')
       or (old.status = 'removed' and new.status = 'live' and old.first_published_at is not null)
       or (old.status = 'removed' and new.status = 'waiting' and old.first_published_at is null)) then
    raise exception 'a post can''t go from % to %', old.status, new.status using errcode = '22023';
  end if;
  new.published_at := case when new.status = 'live' then now() else null end;
  new.first_published_at := coalesce(old.first_published_at, new.published_at);
  return new;
end
$$;

grant create on schema app to dog_jevs;
set local role dog_jevs;

-- Whether a post passes the gate now. Used before the model runs and again when it decides.
create function app.sl_eligible(p_post uuid)
returns boolean
language sql stable security definer set search_path = pg_catalog
as $$
  select exists (
    select 1 from app.posts p
     where p.id = p_post and p.status = 'waiting'
       and exists (select 1 from app.review_flags f where f.post_id = p.id and f.source = 'classifier' and f.classifier = 'jevs'
                   and f.resolved_at is null)
       and not exists (select 1 from app.review_flags f where f.post_id = p.id and f.resolved_at is null
                       and not (f.source = 'classifier' and f.classifier = 'jevs'))
       and exists (
         select 1 from (select d.scores, d.error from app.jevs_decisions d
                         where d.subject_kind = 'post' and d.subject_id = p.id and d.effect = 'hold' and d.applied
                           and d.action = any (array['post.create', 'post.approved'])
                         order by d.created_at desc, d.id desc limit 1) h
          where not h.error
            and not exists (select 1 from jsonb_each(h.scores) e where e.key <> all (array['J01', 'J02', 'J04', 'J07', 'J13'])
                              and (jsonb_typeof(e.value) <> 'number' or (e.value::text)::numeric > 0))
            and exists (select 1 from jsonb_each(h.scores) e where e.key = any (array['J01', 'J02', 'J04', 'J07', 'J13'])
                          and jsonb_typeof(e.value) = 'number' and (e.value::text)::numeric >= 25)))
$$;

-- The unlock: its last unlock_n shadow clears that Aaron has decided were all approved by him. Returns true if it
-- switched to on.
create function app.sl_try_unlock()
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  n integer;
  bad integer;
begin
  select * into s from app.sl_settings where singleton for update;
  if s.mode <> 'shadow' or s.paused_reason is not null then
    return false;
  end if;
  select count(*), count(*) filter (where not x.approved) into n, bad from (
    select o.approved from app.sl_outcomes o where o.decided_at > s.counted_since
     order by o.decided_at desc, o.id desc limit s.unlock_n) x;
  if n < s.unlock_n or bad > 0 then
    return false;
  end if;
  update app.sl_settings set mode = 'on', counted_since = now(), updated_at = now() where singleton;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('secondlook.mode', null, null, jsonb_build_object('from', 'shadow', 'to', 'on', 'by', 'the unlock', 'agreed', n));
  perform app.notify(null, 'alert', 'Second Look is now publishing easy held posts',
    'You approved all of the last ' || n || ' posts Second Look would have published in shadow mode, so it now publishes '
    || 'easy held posts itself, at most ' || s.daily_clear_cap || ' a day. You get a notice for each one. If your removals of '
    || 'what it publishes go above 1 in 80, it pauses itself back to shadow.', '/review', null, null, 'secondlook:unlock:' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MISS'));
  return true;
end
$$;

-- The next eligible held posts, for the site to put to the model: at most p_n (1 to 3), at most once every 50
-- seconds, never in off mode, within the daily call cap, each post once. Also runs the unlock check and, once a week,
-- Aaron's report.
create function app.sl_claim(p_n integer)
returns table (post_id uuid, body text, held text[], account_days integer, sign_in text, model text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  today_calls integer;
begin
  if p_n is null or p_n < 1 or p_n > 3 then
    raise exception 'bad Second Look claim' using errcode = '22023';
  end if;
  select * into s from app.sl_settings where singleton for update skip locked;
  if not found or s.mode = 'off' or (s.last_claim_at is not null and s.last_claim_at > now() - interval '50 seconds') then
    return;
  end if;
  update app.sl_settings set last_claim_at = now() where singleton;
  if s.last_report_at is null or s.last_report_at < now() - interval '7 days' then
    perform app.sl_weekly_report();
  end if;
  perform app.sl_try_unlock();
  select count(*) into today_calls from app.sl_claims c where c.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  if today_calls >= s.daily_call_cap then
    return;
  end if;
  return query
    with picked as (
      select p.id from app.posts p
       where p.status = 'waiting' and not exists (select 1 from app.sl_claims c where c.post_id = p.id) and app.sl_eligible(p.id)
       order by p.created_at, p.id
       limit least(p_n, s.daily_call_cap - today_calls)
       for update of p skip locked),
    claimed as (insert into app.sl_claims (post_id) select id from picked returning sl_claims.post_id)
    select p.id, p.body,
           (select coalesce(array_agg(e.key order by e.key), '{}') from (select d.scores from app.jevs_decisions d
              where d.subject_kind = 'post' and d.subject_id = p.id and d.effect = 'hold' and d.applied
              order by d.created_at desc, d.id desc limit 1) h, jsonb_each(h.scores) e
             where jsonb_typeof(e.value) = 'number' and (e.value::text)::numeric >= 25),
           greatest(0, extract(day from now() - m.created_at))::integer,
           case when p.agent_id is not null then 'an agent posting for its owner, level ' || m.trust_level
                else 'a member, level ' || m.trust_level end,
           s.model
      from claimed c join app.posts p on p.id = c.post_id join app.members m on m.id = p.author_id;
end
$$;

-- Records Second Look's decision on a post it was given, and, in on mode, acts on a clear. Returns what happened:
-- 'published', 'logged' or 'refused'.
create function app.sl_decide(p_post uuid, p_version text, p_model text, p_decision text, p_answers jsonb, p_risk integer,
                              p_reason text, p_fail_closed boolean, p_error text, p_latency integer)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  did uuid;
  author uuid;
  v_decision text := p_decision;
  v_reason text := p_reason;
  today integer;
begin
  if p_post is null or p_version is distinct from 'v1' or p_decision is null or p_risk is null or p_reason is null
     or p_fail_closed is null or p_latency is null then
    raise exception 'bad Second Look decision' using errcode = '22023';
  end if;
  -- Only a post it was given in the last 2 minutes, and only once.
  if not exists (select 1 from app.sl_claims c where c.post_id = p_post and c.claimed_at > now() - interval '2 minutes')
     or exists (select 1 from app.sl_decisions d where d.post_id = p_post) then
    return 'refused';
  end if;
  -- A clear must be what the nine answers say: Q1 to Q8 "no" and Q9 "yes" (the table checks the rest).
  if v_decision = 'clear' and not coalesce(p_answers ?& array['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9']
      and (select bool_and(p_answers ->> k = 'no') from unnest(array['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8']) k)
      and p_answers ->> 'q9' = 'yes', false) then
    raise exception 'a clear that its answers don''t support' using errcode = '22023';
  end if;
  select * into s from app.sl_settings where singleton for update;
  -- The gate again: anything that changed since it was given the post (a report, an appeal, Aaron's own decision) means
  -- it leaves the post.
  if v_decision = 'clear' and not app.sl_eligible(p_post) then
    v_decision := 'leave';
    v_reason := left('the post changed while it was checked; ' || v_reason, 1000);
  end if;
  insert into app.sl_decisions (post_id, version, model, mode, decision, answers, risk, reason, fail_closed, error, latency_ms)
    values (p_post, p_version, p_model, case when s.mode = 'on' then 'on' else 'shadow' end, v_decision, p_answers, p_risk,
            v_reason, p_fail_closed, left(p_error, 80), least(p_latency, 600000))
    returning id into did;
  if v_decision <> 'clear' or s.mode <> 'on' or s.paused_reason is not null then
    return 'logged';
  end if;
  today := case when s.clears_day = (now() at time zone 'UTC')::date then s.clears_today else 0 end;
  if today >= s.daily_clear_cap then
    return 'logged';
  end if;
  update app.sl_settings set clears_day = (now() at time zone 'UTC')::date, clears_today = today + 1,
    published_total = published_total + 1 where singleton;
  -- Publish: the release row first (the post and flag guards look for it), then the post, then JEVs's hold.
  insert into app.sl_releases (post_id, decision_id) values (p_post, did);
  update app.posts set status = 'live' where id = p_post and status = 'waiting' returning author_id into author;
  if author is null then
    raise exception 'the post was no longer waiting' using errcode = '40001';
  end if;
  update app.review_flags set decision = 'approve'
   where post_id = p_post and source = 'classifier' and classifier = 'jevs' and resolved_at is null;
  update app.sl_decisions set published = true where id = did;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('secondlook.release', 'post', p_post, jsonb_build_object('decision', did, 'model', p_model, 'risk', p_risk));
  perform app.notify(author, 'post_published', 'Your post was reviewed and published',
    'Your post was held for a check. Second Look, the site''s automated reviewer, checked it and published it.',
    '/talk', 'post', p_post, 'secondlook:published:' || p_post);
  perform app.notify(null, 'alert', 'Second Look published a held post',
    'Reason: ' || left(v_reason, 300) || '. You can remove it from the review page; if you do, Second Look pauses itself.',
    '/review', 'post', p_post, 'secondlook:release:' || p_post);
  return 'published';
end
$$;

-- Aaron's weekly report: counts only, with the 95% Wilson bound on its error rate (his removals of what it published,
-- or, before it publishes anything, his removals of what it would have published in shadow).
create function app.sl_report_core()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  r jsonb;
  n integer;
  k integer;
  z numeric := 1.96;
  upper numeric;
begin
  select count(*), count(*) filter (where not o.approved) into n, k from app.sl_outcomes o;
  upper := case when n = 0 then 1 else
    ((k::numeric / n + z * z / (2 * n)) + z * sqrt((k::numeric / n) * (1 - k::numeric / n) / n + z * z / (4 * n * n))) / (1 + z * z / n) end;
  select jsonb_build_object(
    'mode', (select mode from app.sl_settings), 'paused', (select paused_reason is not null from app.sl_settings),
    'decisions_7d', (select count(*) from app.sl_decisions where created_at > now() - interval '7 days'),
    'clears_7d', (select count(*) from app.sl_decisions where decision = 'clear' and created_at > now() - interval '7 days'),
    'rejects_7d', (select count(*) from app.sl_decisions where decision = 'reject' and created_at > now() - interval '7 days'),
    'failed_closed_7d', (select count(*) from app.sl_decisions where fail_closed and created_at > now() - interval '7 days'),
    'published_total', (select published_total from app.sl_settings),
    'reversed_total', (select reversed_total from app.sl_settings),
    'reported_total', (select reported_total from app.sl_settings),
    'shadow_clears_decided', n, 'shadow_clears_removed', k, 'shadow_error_upper_95', round(upper, 4),
    'clears_by_new_accounts_7d', (select count(*) from app.sl_decisions d join app.posts p on p.id = d.post_id join app.members m on m.id = p.author_id
                                   where d.decision = 'clear' and d.created_at > now() - interval '7 days' and m.created_at > now() - interval '30 days'),
    'clears_by_agents_7d', (select count(*) from app.sl_decisions d join app.posts p on p.id = d.post_id
                             where d.decision = 'clear' and d.created_at > now() - interval '7 days' and p.agent_id is not null)) into r;
  return r;
end
$$;

-- The report for an administrator.
create function app.sl_report()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() <> 'admin' then
    raise exception 'only an administrator can read Second Look''s report' using errcode = '42501';
  end if;
  return app.sl_report_core();
end
$$;

create function app.sl_weekly_report()
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r jsonb := app.sl_report_core();
begin
  update app.sl_settings set last_report_at = now() where singleton;
  perform app.notify(null, 'alert', 'Second Look this week',
    'Mode: ' || (r ->> 'mode') || case when (r ->> 'paused')::boolean then ' (paused)' else '' end
    || '. Last 7 days: ' || (r ->> 'decisions_7d') || ' decisions, ' || (r ->> 'clears_7d') || ' clears, ' || (r ->> 'rejects_7d')
    || ' rejects, ' || (r ->> 'failed_closed_7d') || ' left because the model gave no usable answer. Published so far: '
    || (r ->> 'published_total') || ', of which you removed ' || (r ->> 'reversed_total') || ' and members reported '
    || (r ->> 'reported_total') || '. Shadow clears you decided: ' || (r ->> 'shadow_clears_decided') || ', removed '
    || (r ->> 'shadow_clears_removed') || ' (95% upper bound on its error rate: ' || (r ->> 'shadow_error_upper_95') || ').',
    '/review', null, null, 'secondlook:week:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
end
$$;

-- The stop. Aaron removing a post Second Look published (still live, or back on hold after a report): counted; above 1 in 80 of what it published, it pauses to
-- shadow and alerts him. A report on a post it published: back on hold for him, and an alert.
create function app.sl_after_post_change() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  pub integer;
  rev integer;
begin
  if old.status in ('live', 'waiting') and new.status = 'removed'
     and exists (select 1 from app.sl_releases r where r.post_id = new.id and r.reversed_at is null) then
    update app.sl_releases set reversed_at = now() where post_id = new.id;
    update app.sl_settings set reversed_total = reversed_total + 1 where singleton returning published_total, reversed_total into pub, rev;
    if rev * 80 > pub then
      update app.sl_settings set mode = 'shadow', counted_since = now(), paused_reason = left('Paused: ' || rev || ' of the ' || pub
        || ' posts it published were removed, above 1 in 80', 300), updated_at = now() where singleton and mode = 'on';
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('secondlook.mode', 'post', new.id, jsonb_build_object('to', 'shadow', 'by', 'the stop', 'published', pub, 'removed', rev));
      perform app.notify(null, 'alert', 'Second Look paused itself',
        'You removed ' || rev || ' of the ' || pub || ' posts Second Look published, which is above 1 in 80, so it is back in shadow '
        || 'mode: it logs what it would do and publishes nothing. Held posts come to you as before.',
        '/review', 'post', new.id, 'secondlook:pause:' || new.id);
    end if;
  end if;
  return null;
end
$$;

create function app.sl_after_report() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if new.source = 'report' and exists (select 1 from app.sl_releases r where r.post_id = new.post_id and r.reported_at is null
                                       and r.reversed_at is null) then
    update app.sl_releases set reported_at = now() where post_id = new.post_id;
    update app.sl_settings set reported_total = reported_total + 1 where singleton;
    update app.posts set status = 'waiting' where id = new.post_id and status = 'live';
    perform app.notify(null, 'alert', 'A post Second Look published was reported',
      'A member reported a post Second Look published, so it is back on hold for you to decide.',
      '/review', 'post', new.post_id, 'secondlook:reported:' || new.post_id);
  end if;
  return null;
end
$$;

-- Aaron decides a post Second Look would have cleared in shadow: his decision is kept as an outcome (approved or
-- not), with no post or person, so the unlock and the report survive the post's deletion.
create function app.sl_after_flag_close() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if new.resolved_by is not null and new.source = 'classifier' and new.classifier = 'jevs' and new.decision in ('approve', 'remove')
     and exists (select 1 from app.sl_decisions d where d.post_id = new.post_id and d.mode = 'shadow' and d.decision = 'clear') then
    insert into app.sl_outcomes (approved) values (new.decision = 'approve');
  end if;
  return null;
end
$$;

-- An administrator switches the mode. Turning it on by hand is allowed (it is Aaron's call) and clears a pause.
create function app.sl_set_mode(p_mode text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  was text;
begin
  if app.actor_kind() <> 'admin' then
    raise exception 'only an administrator can switch Second Look' using errcode = '42501';
  end if;
  if p_mode is null or p_mode <> all (array['off', 'shadow', 'on']) then
    raise exception 'bad Second Look mode' using errcode = '22023';
  end if;
  select mode into was from app.sl_settings where singleton for update;
  -- Aaron's choice stands: the unlock counts only his decisions after this switch.
  update app.sl_settings set mode = p_mode, paused_reason = null, counted_since = now(), updated_at = now() where singleton;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('secondlook.mode', null, null, jsonb_build_object('from', was, 'to', p_mode, 'by', 'an administrator'));
  return p_mode;
end
$$;

-- The two triggers, made by the tables' owner while it can still call the functions (making a trigger needs that
-- right; running one doesn't), before the rights below take it away from everyone else.
set local role dog_owner;
create trigger sl_after_post_change after update of status on app.posts for each row
  when (old.status in ('live', 'waiting') and new.status = 'removed') execute function app.sl_after_post_change();
alter table app.posts enable always trigger sl_after_post_change;
create trigger sl_after_report after insert on app.review_flags for each row
  when (new.source = 'report') execute function app.sl_after_report();
alter table app.review_flags enable always trigger sl_after_report;
create trigger sl_after_flag_close after update of decision on app.review_flags for each row
  when (new.resolved_by is not null and old.resolved_at is null) execute function app.sl_after_flag_close();
alter table app.review_flags enable always trigger sl_after_flag_close;
set local role dog_jevs;

-- Rights, granted by their owner (JEVs's role).
revoke execute on function app.sl_eligible(uuid), app.sl_try_unlock(), app.sl_report_core(), app.sl_claim(integer),
  app.sl_decide(uuid, text, text, text, jsonb, integer, text, boolean, text, integer), app.sl_report(), app.sl_weekly_report(),
  app.sl_after_post_change(), app.sl_after_report(), app.sl_after_flag_close(), app.sl_set_mode(text) from public;
grant execute on function app.sl_claim(integer), app.sl_decide(uuid, text, text, text, jsonb, integer, text, boolean, text, integer),
  app.sl_report(), app.sl_set_mode(text) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_jevs;
