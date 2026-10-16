-- 010 JEVs core (Release 2, PR 12): the automated checking layer.
-- Aaron's decisions (Oct 16, 2026): every account and every action is scored against a standard set of risk questions
-- written in code; low risk passes, medium risk is challenged (confirmation goes to the human owner, never the agent),
-- high risk is held or hidden and goes to Aaron. Members are trusted by default. No trust level is promoted by hand:
-- JEVs promotes to level 2 automatically when every standard question passes. Sign-up from the EU, EEA, UK and
-- Switzerland is declined before any personal data is collected; only daily counts by country are kept.
-- Criteria: F6 (every post is checked by JEVs; first-post review only until JEVs leaves shadow mode), trust levels
-- (level 2 automatic), S1/S7/S8/G3 as for every table.
--
-- How the work is split:
--   The questions and how each one scores (0 to 100) are public code (db/jevs.js). The site computes the scores from
--   signals the database gathers (app.jevs_signals: counts only, never another member's rows).
--   The thresholds that turn scores into low, medium or high are NOT in the code. They live in app.jevs_settings,
--   which only the database owner can change, and only the narrow role dog_jevs reads them. This migration seeds
--   conservative defaults, which the public repository shows; Aaron tunes the real values (db/README.md says how).
--   app.jevs_decide applies the thresholds, records the decision (append-only) and carries out its effect in the same
--   transaction as the action, so a held post is never seen by anyone before it is held.
-- Mode: 'shadow' (the default) scores and records everything and blocks nothing; first-post review (F6) keeps running.
-- 'enforce' carries out the effects, and the same switch turns first-post review off.

do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_jevs') then
    create role dog_jevs nologin noinherit nobypassrls;
  end if;
end
$roles$;
grant dog_jevs to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_jevs;

-- ---- Settings: the thresholds (Aaron's, private) and the mode ----
create table app.jevs_settings (
  id uuid primary key default app.uuid_v7(),
  key text not null unique check (key = any (array['mode', 'medium_any', 'high_any', 'medium_total', 'high_total', 'pass_max',
    'promote_min_age_hours', 'challenge_hours', 'credible_reporter_age_hours'])),
  value text not null check (char_length(value) between 1 and 16),
  updated_at timestamptz not null default now()
);
alter table app.jevs_settings enable row level security;
alter table app.jevs_settings force row level security;

-- Everyone may read the mode (posting needs it, and whether JEVs enforces is public); Aaron may read every setting
-- on the site. Only the database owner changes them (in the SQL editor, as db/README.md shows); the site can't.
create policy jevs_settings_select on app.jevs_settings for select to dog_app, dog_delegate
  using (key = 'mode' or app.actor_kind() = 'admin');
grant select (key, value, updated_at) on app.jevs_settings to dog_app, dog_delegate;
create policy jevs_settings_jevs_select on app.jevs_settings for select to dog_jevs using (true);
grant select on app.jevs_settings to dog_jevs;
create policy jevs_settings_owner_select on app.jevs_settings for select to dog_owner using (true);
create policy jevs_settings_owner_insert on app.jevs_settings for insert to dog_owner with check (true);
create policy jevs_settings_owner_update on app.jevs_settings for update to dog_owner using (true) with check (true);

-- A setting keeps its name; the mode is shadow or enforce; every other value is a whole number from 0 to 9999.
create function app.jevs_settings_check() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'UPDATE' and new.key is distinct from old.key then
    raise exception 'a JEVs setting keeps its name' using errcode = '42501';
  end if;
  if new.key = 'mode' then
    if new.value not in ('shadow', 'enforce') then
      raise exception 'the JEVs mode is shadow or enforce' using errcode = '22023';
    end if;
  elsif new.value !~ '^[0-9]{1,4}$' then
    raise exception 'a JEVs threshold is a whole number from 0 to 9999' using errcode = '22023';
  end if;
  new.updated_at := now();
  return new;
end
$$;
create trigger jevs_settings_check before insert or update on app.jevs_settings for each row execute function app.jevs_settings_check();
alter table app.jevs_settings enable always trigger jevs_settings_check;

-- The seeds: conservative, public, and meant to be tuned. Scores per question run 0 to 100 (db/jevs.js).
--   medium_any / high_any: one question scoring this much makes the action medium / high.
--   medium_total / high_total: the questions' scores added up reaching this makes it medium / high.
--   pass_max: a question "passes" for automatic level 2 at this score or lower.
--   promote_min_age_hours: no automatic level 2 before an account is this old (14 days).
--   challenge_hours: how long an owner has to confirm a challenged action.
--   credible_reporter_age_hours: a report counts as credible (for hiding at once) only from an account this old.
insert into app.jevs_settings (key, value) values
  ('mode', 'shadow'), ('medium_any', '40'), ('high_any', '80'), ('medium_total', '70'), ('high_total', '140'),
  ('pass_max', '10'), ('promote_min_age_hours', '336'), ('challenge_hours', '48'), ('credible_reporter_age_hours', '168');

-- Whether JEVs enforces (one switch). Read as the caller.
create function app.jevs_enforcing() returns boolean
language sql stable
as $$ select exists (select 1 from app.jevs_settings s where s.key = 'mode' and s.value = 'enforce') $$;

-- ---- Decisions: one row per scored action, append-only ----
-- Holds IDs, the question IDs and their scores, and what JEVs did. No words, no names, no addresses: the same kind of
-- record the audit log keeps. It is deleted only with the account it is about (F8).
create table app.jevs_decisions (
  id uuid primary key default app.uuid_v7(),
  created_at timestamptz not null default now(),
  action text not null check (action = any (array['signup', 'account.check', 'post.create', 'post.approved', 'post.reported', 'draft.create',
    'agent.register', 'agent.create', 'agent.claim', 'agent.key', 'agent.rules', 'account.delete'])),
  subject_kind text check (subject_kind = any (array['member', 'post', 'agent', 'draft'])),
  subject_id uuid,
  member_id uuid,
  agent_id uuid,
  level text not null check (level = any (array['low', 'medium', 'high'])),
  mode text not null check (mode = any (array['shadow', 'enforce'])),
  effect text not null check (effect = any (array['none', 'challenge', 'hold', 'hide', 'promote', 'queue'])),
  applied boolean not null,
  error boolean not null,
  total integer not null check (total between 0 and 10000),
  scores jsonb not null check (jsonb_typeof(scores) = 'object' and octet_length(scores::text) <= 1024)
);
create index jevs_decisions_member on app.jevs_decisions (member_id, created_at);
create index jevs_decisions_subject on app.jevs_decisions (subject_id);
create index jevs_decisions_recent on app.jevs_decisions (created_at, level);
alter table app.jevs_decisions enable row level security;
alter table app.jevs_decisions force row level security;

-- Aaron reads them; only app.jevs_decide writes them.
create policy jevs_decisions_select on app.jevs_decisions for select to dog_app using (app.actor_kind() = 'admin');
grant select on app.jevs_decisions to dog_app;
create policy jevs_decisions_jevs_select on app.jevs_decisions for select to dog_jevs using (true);
create policy jevs_decisions_jevs_insert on app.jevs_decisions for insert to dog_jevs with check (true);
grant select, insert on app.jevs_decisions to dog_jevs;

create function app.jevs_decisions_guard() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'DELETE' and current_user = 'dog_erase' then
    return old;
  end if;
  raise exception 'JEVs decisions are only ever added' using errcode = '42501';
end
$$;
create trigger jevs_decisions_guard before update or delete on app.jevs_decisions for each row execute function app.jevs_decisions_guard();
alter table app.jevs_decisions enable always trigger jevs_decisions_guard;

-- ---- Challenges: a medium-risk action waits for its human owner ----
-- Tied to the one action. The Notifications PR delivers them (delivered_at is for it); until then the owner sees and
-- answers them through the API. A sensitive action is confirmed by signing in again (a fresh session), the way a
-- card issuer asks you to confirm a purchase.
create table app.jevs_challenges (
  id uuid primary key default app.uuid_v7(),
  decision_id uuid not null references app.jevs_decisions (id),
  owner_id uuid not null references app.members (id),
  action text not null check (action = any (array['post.create', 'agent.create', 'agent.claim', 'agent.key', 'agent.rules', 'account.delete'])),
  subject_kind text check (subject_kind = any (array['member', 'post', 'agent'])),
  subject_id uuid,
  status text not null default 'pending' check (status = any (array['pending', 'confirmed', 'declined'])),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  decided_at timestamptz,
  delivered_at timestamptz,
  check ((status = 'pending') = (decided_at is null))
);
create index jevs_challenges_owner on app.jevs_challenges (owner_id, status, created_at);
create index jevs_challenges_subject on app.jevs_challenges (subject_id);
alter table app.jevs_challenges enable row level security;
alter table app.jevs_challenges force row level security;

create policy jevs_challenges_select on app.jevs_challenges for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member()) or app.actor_kind() = 'admin');
grant select (id, owner_id, action, subject_kind, subject_id, status, created_at, expires_at, decided_at, delivered_at) on app.jevs_challenges to dog_app;
create policy jevs_challenges_jevs_select on app.jevs_challenges for select to dog_jevs using (true);
create policy jevs_challenges_jevs_insert on app.jevs_challenges for insert to dog_jevs with check (true);
create policy jevs_challenges_jevs_update on app.jevs_challenges for update to dog_jevs using (true) with check (true);
grant select, insert on app.jevs_challenges to dog_jevs;
grant update (status) on app.jevs_challenges to dog_jevs;

-- Answered once, by JEVs (for the owner), from pending; nothing else changes. Deleted only with the account.
create function app.jevs_challenges_guard() returns trigger
language plpgsql
as $$
begin
  if tg_op = 'DELETE' then
    if current_user = 'dog_erase' then
      return old;
    end if;
    raise exception 'a challenge is never deleted on its own' using errcode = '42501';
  end if;
  if current_user <> 'dog_jevs' then
    raise exception 'only the owner''s answer, through JEVs, closes a challenge' using errcode = '42501';
  end if;
  if (new.id, new.decision_id, new.owner_id, new.action, new.subject_kind, new.subject_id, new.created_at, new.expires_at, new.delivered_at)
     is distinct from (old.id, old.decision_id, old.owner_id, old.action, old.subject_kind, old.subject_id, old.created_at, old.expires_at, old.delivered_at) then
    raise exception 'a challenge''s action never changes' using errcode = '42501';
  end if;
  if old.status <> 'pending' or new.status = 'pending' then
    raise exception 'a challenge is answered once' using errcode = '42501';
  end if;
  new.decided_at := now();
  return new;
end
$$;
create trigger jevs_challenges_guard before update or delete on app.jevs_challenges for each row execute function app.jevs_challenges_guard();
alter table app.jevs_challenges enable always trigger jevs_challenges_guard;

-- ---- Marks: what the cluster questions compare, kept 30 days ----
-- Keyed hashes only, made by the site with the key it already uses for rate limits (IP_HASH_KEY): the network a member
-- or agent signed up from (the same daily-changing hash the rate limits use), the domain of a sign-up email address
-- (only for uncommon domains; never gmail.com and the like), and whether that domain is a disposable-email service.
-- A mark belongs to a member, an agent, or (for a few minutes) an email sign-in link that hasn't been used yet.
-- No foreign keys: unclaimed agents are cleared on their own schedule, and marks are cleared with the account.
create table app.jevs_marks (
  id uuid primary key default app.uuid_v7(),
  member_id uuid,
  agent_id uuid,
  token_hash text check (char_length(token_hash) = 64 and token_hash ~ '^[0-9a-f]+$'),
  kind text not null check (kind = any (array['net', 'email_domain', 'disposable'])),
  key_hash text not null check (char_length(key_hash) = 64 and key_hash ~ '^[0-9a-f]+$'),
  created_at timestamptz not null default now(),
  check (num_nonnulls(member_id, agent_id, token_hash) = 1)
);
create index jevs_marks_key on app.jevs_marks (kind, key_hash, created_at);
create index jevs_marks_member on app.jevs_marks (member_id);
create index jevs_marks_agent on app.jevs_marks (agent_id);
create index jevs_marks_token on app.jevs_marks (token_hash);
alter table app.jevs_marks enable row level security;
alter table app.jevs_marks force row level security;
create policy jevs_marks_jevs_select on app.jevs_marks for select to dog_jevs using (true);
create policy jevs_marks_jevs_insert on app.jevs_marks for insert to dog_jevs with check (true);
create policy jevs_marks_jevs_update on app.jevs_marks for update to dog_jevs using (true) with check (true);
create policy jevs_marks_jevs_delete on app.jevs_marks for delete to dog_jevs using (true);
grant select, insert, delete on app.jevs_marks to dog_jevs;
grant update (member_id, token_hash) on app.jevs_marks to dog_jevs;

-- ---- Text prints: for "near-copies of other members' text" ----
-- A 64-bit simhash of each post's words (db/jevs.js), so reworded copies are caught as well as exact ones
-- (exact ones already match on app.posts.body_fp). Not reversible to the words.
create table app.jevs_prints (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null unique references app.posts (id),
  author_id uuid not null,
  simhash bigint not null,
  created_at timestamptz not null default now()
);
create index jevs_prints_recent on app.jevs_prints (created_at);
alter table app.jevs_prints enable row level security;
alter table app.jevs_prints force row level security;
create policy jevs_prints_jevs_select on app.jevs_prints for select to dog_jevs using (true);
create policy jevs_prints_jevs_insert on app.jevs_prints for insert to dog_jevs with check (true);
grant select, insert on app.jevs_prints to dog_jevs;

-- ---- Link domains seen in low-risk posts (a SHA-256 of the domain; domains in public posts are public) ----
create table app.jevs_domains (
  id uuid primary key default app.uuid_v7(),
  domain_hash text not null unique check (char_length(domain_hash) = 64 and domain_hash ~ '^[0-9a-f]+$'),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  posts integer not null default 1 check (posts >= 0)
);
alter table app.jevs_domains enable row level security;
alter table app.jevs_domains force row level security;
create policy jevs_domains_jevs_select on app.jevs_domains for select to dog_jevs using (true);
create policy jevs_domains_jevs_insert on app.jevs_domains for insert to dog_jevs with check (true);
create policy jevs_domains_jevs_update on app.jevs_domains for update to dog_jevs using (true) with check (true);
grant select, insert on app.jevs_domains to dog_jevs;
grant update (last_seen_at, posts) on app.jevs_domains to dog_jevs;

-- ---- The regional gate's only record: how many visitors we declined, per country, per day ----
create table app.region_declines (
  id uuid primary key default app.uuid_v7(),
  day date not null default current_date,
  country text not null check (char_length(country) = 2 and country ~ '^[A-Z]+$'),
  declines integer not null default 0 check (declines >= 0),
  unique (day, country)
);
alter table app.region_declines enable row level security;
alter table app.region_declines force row level security;
create policy region_declines_select on app.region_declines for select to dog_app using (app.actor_kind() = 'admin');
grant select on app.region_declines to dog_app;
create policy region_declines_jevs_select on app.region_declines for select to dog_jevs using (true);
create policy region_declines_jevs_insert on app.region_declines for insert to dog_jevs with check (true);
create policy region_declines_jevs_update on app.region_declines for update to dog_jevs using (true) with check (true);
grant select, insert on app.region_declines to dog_jevs;
grant update (declines) on app.region_declines to dog_jevs;

-- ---- Automatic level 2 ----
-- When JEVs promotes a member it records the moment here; their level is then 2 for as long as it isn't set lower by
-- hand. Only JEVs (or the database owner) writes it.
alter table app.members add column jevs_level2_at timestamptz;

-- A member's level: a level Aaron set lower by hand wins; otherwise the highest that a sign-in method verifies or
-- that JEVs granted. (Same as 002 otherwise.)
create or replace function app.verified_level(p_member uuid)
returns smallint
language sql stable
as $$
  select coalesce((select m.level_set_by_admin from app.members m where m.id = p_member),
    greatest(
      (select coalesce(max(case when i.recheck_after is not null and i.recheck_after <= now() then least(i.level, 1) else i.level end), 0)
       from app.identities i where i.member_id = p_member),
      (select case when m.jevs_level2_at is not null then 2 else 0 end from app.members m where m.id = p_member)))::smallint
$$;

-- No trust level is promoted by hand (Oct 16, 2026). A level goes up only through a verified sign-in (dog_signin) or
-- JEVs (dog_jevs). Aaron can still set a level lower, to slow someone down, and that holds until the owner clears it.
create or replace function app.members_guard() returns trigger
language plpgsql
as $$
begin
  if (new.trust_level is distinct from old.trust_level or new.status is distinct from old.status)
     and app.actor_kind() not in ('admin', 'system') and current_user not in ('dog_signin', 'dog_jevs') then
    raise exception 'only an administrator can change trust level or status' using errcode = '42501';
  end if;
  if new.trust_level > old.trust_level and current_user not in ('dog_signin', 'dog_jevs') then
    raise exception 'levels go up only through a verified sign-in or JEVs, never by hand' using errcode = '42501';
  end if;
  if current_user = 'dog_jevs' and (new.status is distinct from old.status
     or (new.trust_level is distinct from old.trust_level and new.trust_level <> 2)) then
    raise exception 'JEVs only promotes to level 2' using errcode = '42501';
  end if;
  if new.status = 'banned' and old.status <> 'banned' and old.is_admin then
    raise exception 'an administrator can''t be banned' using errcode = '42501';
  end if;
  if new.trust_level is distinct from old.trust_level and current_user not in ('dog_signin', 'dog_jevs') then
    new.level_set_by_admin := new.trust_level;
  elsif new.level_set_by_admin is distinct from old.level_set_by_admin and current_user <> 'dog_owner' then
    raise exception 'the hand-set level changes only through the trust level' using errcode = '42501';
  end if;
  if new.jevs_level2_at is distinct from old.jevs_level2_at and current_user not in ('dog_jevs', 'dog_owner') then
    raise exception 'only JEVs records its own promotion' using errcode = '42501';
  end if;
  if new.is_admin is distinct from old.is_admin and current_user <> 'dog_owner' then
    raise exception 'only the database owner can change administrator rights' using errcode = '42501';
  end if;
  return new;
end
$$;

-- Levels that sign-in or JEVs sets are recorded by them, with their reasons (JEVs names the questions).
create or replace function app.members_audit() returns trigger
language plpgsql
as $$
declare
  note text := left(nullif(current_setting('app.note', true), ''), 200);
  act text;
  nid uuid;
begin
  if new.status is distinct from old.status then
    act := case when new.status = 'banned' then 'member.ban' else 'member.unban' end;
  elsif new.trust_level is distinct from old.trust_level and current_user not in ('dog_signin', 'dog_jevs') then
    act := 'member.level_set';
  else
    return null;
  end if;
  if note is not null then
    insert into app.admin_notes (member_id, action, note) values (new.id, act, note) returning id into nid;
  end if;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values (act, 'member', new.id, jsonb_strip_nulls(jsonb_build_object('note_id', nid,
            'from', case when act = 'member.level_set' then old.trust_level end, 'to', case when act = 'member.level_set' then new.trust_level end)));
  if act <> 'member.level_set' and new.trust_level is distinct from old.trust_level and current_user not in ('dog_signin', 'dog_jevs') then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_set', 'member', new.id, jsonb_build_object('from', old.trust_level, 'to', new.trust_level));
  end if;
  return null;
end
$$;

-- ---- F6: first-post review stays on only until JEVs enforces (the same single switch) ----
-- Same as 003 otherwise: level 2 members and Aaron post live; level 0 and 1 members' first 3 posts wait for review
-- while JEVs runs in shadow mode. In enforce mode every post goes live unless JEVs holds it.
create or replace function app.posts_decide() returns trigger
language plpgsql
as $$
declare
  lvl smallint;
  admin boolean;
  live integer;
  reviewed boolean;
begin
  select m.trust_level, m.is_admin into lvl, admin from app.members m where m.id = new.author_id and m.status = 'active';
  if not found then
    raise exception 'only active members can post' using errcode = '42501';
  end if;
  select count(*) into live from app.posts p where p.author_id = new.author_id and p.status = 'live';
  reviewed := not (admin or lvl >= 2 or live >= 3);
  if reviewed then
    reviewed := not app.jevs_enforcing();
  end if;
  if reviewed then
    perform pg_advisory_xact_lock(hashtext('dayonegreat.posts'), hashtext(new.author_id::text));
    if (select count(*) from app.posts p where p.author_id = new.author_id and p.status = 'waiting') >= 3 then
      raise exception 'waiting_limit' using errcode = 'P0001',
        hint = 'Your first 3 posts are waiting for review; you can post again once they have been reviewed.';
    end if;
    new.status := 'waiting';
    new.published_at := null;
  else
    new.status := 'live';
    new.published_at := now();
  end if;
  new.created_at := now();
  return new;
end
$$;

-- ---- What JEVs may do to a post ----
-- Hold a post written in this same transaction (so nobody saw it), hide a post (live or held), or put a held post live
-- once its owner confirmed the challenge. Reviewers' moves are unchanged (008).
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

-- JEVs's own moves are recorded as JEVs's and close no flags: whatever is open stays in Aaron's queue, and a held post
-- isn't put in the first-posts queue. A reviewer's moves are recorded as before (004).
create or replace function app.posts_after_review() returns trigger
language plpgsql
as $$
declare
  d text;
begin
  if new.status is distinct from old.status then
    if current_user = 'dog_jevs' then
      d := case when new.status = 'waiting' then 'hold' when new.status = 'removed' then 'hide' else 'release' end;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('jevs.' || d, 'post', new.id, jsonb_build_object('from', old.status, 'to', new.status, 'author', new.author_id));
      return null;
    end if;
    d := case when old.status = 'waiting' and new.status = 'live' then 'approve'
              when new.status = 'removed' then 'remove'
              else 'restore' end;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('post.' || d, 'post', new.id, jsonb_build_object('from', old.status, 'to', new.status, 'author', new.author_id));
    update app.review_flags set decision = d where post_id = new.id and resolved_at is null;
    if new.status = 'waiting' then
      insert into app.review_flags (post_id, source) values (new.id, 'first_posts');
    end if;
  end if;
  return null;
end
$$;

-- ---- Flags: JEVs flags for Aaron, and appeals by the author ----
-- The report re-check (004) asks app.reportable only for reports. Written as one condition, Postgres checks the right to
-- call that function even for other flags, and JEVs (rightly) may not call it; nested, it is asked only when needed.
create or replace function app.review_flags_recheck() returns trigger
language plpgsql
as $$
begin
  if new.source = 'report' then
    if not app.reportable(new.post_id, new.reporter_id) then
      raise exception 'not_reportable' using errcode = 'P0001';
    end if;
  end if;
  return null;
end
$$;

alter table app.review_flags drop constraint review_flags_source_check;
alter table app.review_flags add constraint review_flags_source_check check (source = any (array['first_posts', 'report', 'classifier', 'appeal']));
create unique index review_flags_appeal on app.review_flags (post_id) where source = 'appeal' and resolved_at is null;
create unique index review_flags_jevs on app.review_flags (post_id) where source = 'classifier' and classifier = 'jevs' and resolved_at is null;

-- The author of a post that JEVs held or hid (high risk) may appeal it, which puts their appeal beside JEVs's flag in
-- Aaron's queue. Runs as dog_jevs, which can see JEVs's decisions; it answers only yes or no.
create function app.jevs_appealable(p_post uuid)
returns boolean
language plpgsql volatile security definer set search_path = pg_catalog
as $$
begin
  return app.actor_kind() in ('member', 'admin') and exists (
    select 1 from app.posts p
    where p.id = p_post and p.author_id = app.current_member() and p.status in ('waiting', 'removed')
      and exists (select 1 from app.jevs_decisions d where d.subject_id = p.id and d.applied and d.effect in ('hold', 'hide')));
end
$$;

drop policy review_flags_insert on app.review_flags;
create policy review_flags_insert on app.review_flags for insert to dog_app
  with check (
    (source = 'first_posts' and reporter_id is null and app.actor_kind() in ('member', 'admin')
      and exists (select 1 from app.posts p where p.id = post_id and p.status = 'waiting'
                  and (p.author_id = app.current_member() or app.is_reviewer())))
    or (source = 'report' and app.actor_kind() in ('member', 'admin') and reporter_id = app.current_member()
      and app.reportable(post_id, app.current_member()))
    or (source = 'classifier' and reporter_id is null and app.actor_kind() = 'system')
    or (source = 'appeal' and reporter_id is null and reason is null and app.jevs_appealable(post_id))
  );

-- ---- What dog_jevs may read and do (inside its functions below only) ----
create policy members_jevs_select on app.members for select to dog_jevs using (true);
create policy members_jevs_update on app.members for update to dog_jevs using (true) with check (true);
grant select (id, created_at, trust_level, status, is_admin, level_set_by_admin, jevs_level2_at) on app.members to dog_jevs;
grant update (trust_level, jevs_level2_at) on app.members to dog_jevs;
create policy identities_jevs_select on app.identities for select to dog_jevs using (true);
grant select (member_id, provider, level, recheck_after) on app.identities to dog_jevs;
create policy posts_jevs_select on app.posts for select to dog_jevs using (true);
create policy posts_jevs_update on app.posts for update to dog_jevs using (true) with check (true);
grant select (id, author_id, agent_id, lane, status, body_fp, created_at) on app.posts to dog_jevs;
grant update (status) on app.posts to dog_jevs;
create policy agents_jevs_select on app.agents for select to dog_jevs using (true);
grant select (id, owner_id, status, created_at, claimed_at) on app.agents to dog_jevs;
create policy agent_drafts_jevs_select on app.agent_drafts for select to dog_jevs using (true);
grant select (id, agent_id, owner_id, created_at) on app.agent_drafts to dog_jevs;
create policy review_flags_jevs_select on app.review_flags for select to dog_jevs using (true);
create policy review_flags_jevs_insert on app.review_flags for insert to dog_jevs
  with check (source = 'classifier' and classifier = 'jevs' and reporter_id is null);
grant select (id, post_id, source, reason, reporter_id, classifier, created_at, resolved_at, decision) on app.review_flags to dog_jevs;
grant insert (post_id, source, classifier, score) on app.review_flags to dog_jevs;
create policy brakes_jevs_select on app.brakes for select to dog_jevs using (true);
grant select (member_id, lifted_at) on app.brakes to dog_jevs;
create policy audit_insert_jevs on app.audit_log for insert to dog_jevs
  with check (actor_kind = app.actor_kind() and actor_id is not distinct from app.current_actor_id());
grant insert (action, subject_kind, subject_id, detail) on app.audit_log to dog_jevs;
grant execute on function app.uuid_v7(), app.actor_kind(), app.current_member(), app.current_agent(), app.current_actor_id(),
  app.is_reviewer(), app.jevs_enforcing() to dog_jevs;
grant execute on function app.jevs_enforcing() to dog_app, dog_delegate;

-- ---- The signals: counts the questions need, never another member's rows ----
-- p_action: what is being checked; p_subject: its post, draft or agent (or null); p_net: the keyed daily hash of the
-- network the request came from (or null); p_domains: SHA-256s of the post's link domains; p_simhash: the post's
-- text print. Returns a JSON object of numbers and yes/no answers about the account being judged: the author for
-- posts, otherwise whoever is acting.
create function app.jevs_signals(p_action text, p_subject uuid, p_net text, p_domains text[], p_simhash bigint)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  judged uuid;
  m_created timestamptz; m_level smallint; m_admin boolean; m_status text; m_hand smallint; m_jevs timestamptz;
  fp text;
  credible_hours integer;
  res jsonb := '{}'::jsonb;
begin
  if p_action is null or p_action !~ '^[a-z]+\.?[a-z_]*$' or char_length(p_action) > 32
     or (p_net is not null and p_net !~ '^[0-9a-f]{64}$')
     or (p_domains is not null and (cardinality(p_domains) > 50 or exists (select 1 from unnest(p_domains) x where x is null or x !~ '^[0-9a-f]{64}$'))) then
    raise exception 'bad JEVs request' using errcode = '22023';
  end if;
  judged := me;
  if p_action in ('post.create', 'post.approved', 'post.reported') then
    select p.author_id, p.body_fp into judged, fp from app.posts p where p.id = p_subject;
    if not found then
      raise exception 'bad JEVs request' using errcode = '22023';
    end if;
    if p_action = 'post.reported' then
      if not exists (select 1 from app.review_flags f where f.post_id = p_subject and f.source = 'report' and f.reporter_id = me) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
    elsif judged is distinct from me then
      raise exception 'bad JEVs request' using errcode = '22023';
    end if;
  end if;

  if judged is not null then
    select x.created_at, x.trust_level, x.is_admin, x.status, x.level_set_by_admin, x.jevs_level2_at
      into m_created, m_level, m_admin, m_status, m_hand, m_jevs from app.members x where x.id = judged;
    res := res || jsonb_build_object(
      'account', true,
      'age_hours', floor(extract(epoch from now() - m_created) / 3600),
      'trust_level', m_level, 'admin', m_admin, 'banned', m_status = 'banned',
      'hand_level', m_hand is not null, 'jevs_level2', m_jevs is not null,
      'best_identity', (select coalesce(max(case when i.recheck_after is not null and i.recheck_after <= now() then least(i.level, 1) else i.level end), -1)
                        from app.identities i where i.member_id = judged),
      'providers', (select count(distinct i.provider) from app.identities i where i.member_id = judged),
      'email_only', not exists (select 1 from app.identities i where i.member_id = judged and i.provider <> 'email')
                    and exists (select 1 from app.identities i where i.member_id = judged),
      'disposable', exists (select 1 from app.jevs_marks k where k.member_id = judged and k.kind = 'disposable'),
      -- J05: other accounts that signed up from the same network in the last 24 hours, or with the same uncommon email
      -- domain in the last 7 days.
      'net_members_24h', (select count(distinct k2.member_id) from app.jevs_marks k1 join app.jevs_marks k2
                            on k2.kind = 'net' and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                            and k2.created_at > now() - interval '24 hours'
                          where k1.member_id = judged and k1.kind = 'net' and k1.created_at > now() - interval '24 hours'),
      'domain_members_7d', (select count(distinct k2.member_id) from app.jevs_marks k1 join app.jevs_marks k2
                              on k2.kind = 'email_domain' and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                              and k2.created_at > now() - interval '7 days'
                            where k1.member_id = judged and k1.kind = 'email_domain'),
      -- J06: agents this owner created or claimed in the last 24 hours.
      'owner_agents_24h', (select count(*) from app.agents a where a.owner_id = judged and a.claimed_at > now() - interval '24 hours'),
      -- J10: upheld reports on their posts (90 days), a brake on them now, and banned members who share a network or
      -- email-domain mark with them (30 days).
      'upheld_90d', (select count(*) from app.review_flags f join app.posts p on p.id = f.post_id
                     where p.author_id = judged and f.source = 'report' and f.decision = 'remove' and f.resolved_at > now() - interval '90 days'),
      'braked', exists (select 1 from app.brakes b where b.member_id = judged and b.lifted_at is null),
      'banned_links', (select count(distinct k2.member_id) from app.jevs_marks k1
                         join app.jevs_marks k2 on k2.kind = k1.kind and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                         join app.members b on b.id = k2.member_id and b.status = 'banned'
                       where k1.member_id = judged and k1.kind in ('net', 'email_domain') and k1.created_at > now() - interval '30 days')
    );
    -- J04: the acting agent's own posting rate, or the member's people posts, against its own last two weeks.
    if ag is not null and p_action <> 'post.reported' then
      res := res || jsonb_build_object(
        'posts_1h', (select count(*) from app.posts p where p.agent_id = ag and p.created_at > now() - interval '1 hour'),
        'posts_before', (select count(*) from app.posts p where p.agent_id = ag and p.created_at between now() - interval '15 days' and now() - interval '1 day'));
    else
      res := res || jsonb_build_object(
        'posts_1h', (select count(*) from app.posts p where p.author_id = judged and p.lane = 'people' and p.created_at > now() - interval '1 hour'),
        'posts_before', (select count(*) from app.posts p where p.author_id = judged and p.lane = 'people'
                         and p.created_at between now() - interval '15 days' and now() - interval '1 day'));
    end if;
  else
    res := res || jsonb_build_object('account', false);
  end if;

  -- Sign-up bursts: from this network in the last hour (members and agents), and across the whole site.
  res := res || jsonb_build_object(
    'net_signups_1h', case when p_net is null then 0 else (select count(*) from app.jevs_marks k where k.kind = 'net' and k.key_hash = p_net
                                                              and k.token_hash is null and k.created_at > now() - interval '1 hour') end,
    'net_agents_24h', case when p_net is null then 0 else (select count(distinct k.agent_id) from app.jevs_marks k where k.kind = 'net' and k.key_hash = p_net
                                                              and k.agent_id is not null and k.created_at > now() - interval '24 hours') end,
    'site_signups_1h', (select count(*) from app.members x where x.created_at > now() - interval '1 hour'),
    'site_signups_7d', (select count(*) from app.members x where x.created_at > now() - interval '7 days'));

  -- J07 and J09: what a post links to, and how many other members wrote the same or nearly the same words this week.
  if p_action in ('post.create', 'post.approved', 'post.reported', 'draft.create') then
    res := res || jsonb_build_object(
      'new_domains', case when p_domains is null then 0 else
                       (select count(distinct x) from unnest(p_domains) x where not exists (select 1 from app.jevs_domains d where d.domain_hash = x)) end,
      'copies', (select count(distinct a) from (
                   select p.author_id as a from app.posts p
                   where fp is not null and p.body_fp = fp and p.author_id is distinct from judged and p.created_at > now() - interval '7 days'
                   union
                   select r.author_id from app.jevs_prints r
                   where p_simhash is not null and r.author_id is distinct from judged and r.created_at > now() - interval '7 days'
                     and bit_count(int8send(r.simhash # p_simhash)) <= 10) c));
  end if;

  -- J14: credible members with an open report on this post (accounts at level 1 or more, old enough).
  if p_action = 'post.reported' then
    select s.value::integer into credible_hours from app.jevs_settings s where s.key = 'credible_reporter_age_hours';
    res := res || jsonb_build_object('credible_reports', (
      select count(distinct f.reporter_id) from app.review_flags f join app.members r on r.id = f.reporter_id
      where f.post_id = p_subject and f.source = 'report' and f.resolved_at is null
        and r.status = 'active' and r.trust_level >= 1 and r.created_at <= now() - make_interval(hours => coalesce(credible_hours, 168))));
  end if;
  return res;
end
$$;

-- ---- The decision ----
-- p_scores: question ID -> score (0 to 100), computed by the site from the signals and the public questions.
-- p_impact: 'high' for sensitive actions (held if scoring failed), 'low' for the rest (they go ahead if it failed).
-- p_error: scoring failed (p_scores is then empty). Returns what JEVs decided and whether it was carried out.
create function app.jevs_decide(p_action text, p_subject uuid, p_scores jsonb, p_impact text, p_error boolean, p_domains text[], p_simhash bigint)
returns table (decision_id uuid, level text, effect text, applied boolean, mode text, challenge_id uuid, challenge_status text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  kind text := app.actor_kind();
  s_mode text; s_medium_any integer; s_high_any integer; s_medium_total integer; s_high_total integer; s_pass integer;
  s_age integer; s_challenge integer;
  subj_kind text;
  judged uuid;
  agent uuid;
  v_post uuid; post_author uuid; post_agent uuid; post_status text; post_created timestamptz;
  mem_level smallint; mem_status text; mem_admin boolean; mem_hand smallint; mem_jevs timestamptz; mem_created timestamptz;
  total integer := 0;
  top integer := 0;
  lvl text;
  eff text;
  did uuid;
  cid uuid;
  cstatus text;
  questions text[];
  ok boolean;
begin
  if p_action is null or p_impact is null or p_impact not in ('low', 'high') or p_error is null or p_scores is null
     or jsonb_typeof(p_scores) <> 'object' or (select count(*) from jsonb_object_keys(p_scores)) > 20
     or exists (select 1 from jsonb_each(p_scores) e where e.key !~ '^J[0-9]{2}$' or jsonb_typeof(e.value) <> 'number'
                or (e.value)::numeric <> floor((e.value)::numeric) or (e.value)::numeric not between 0 and 100)
     or (p_domains is not null and (cardinality(p_domains) > 50 or exists (select 1 from unnest(p_domains) x where x is null or x !~ '^[0-9a-f]{64}$'))) then
    raise exception 'bad JEVs request' using errcode = '22023';
  end if;

  -- What is being decided, and about whom. The subject must be the actor's own, made in this transaction where it is
  -- something new, so the site can't point JEVs at someone else's post or agent. A post is locked the way an ordinary
  -- update locks it (no key update), which doesn't wait on the key-share locks that reports on it hold, so members
  -- reporting the same post at once don't deadlock (found by the load test).
  case
    when p_action in ('post.create', 'post.approved') then
      select p.id, p.author_id, p.agent_id, p.status, p.created_at into v_post, post_author, post_agent, post_status, post_created
        from app.posts p where p.id = p_subject for no key update;
      if not found or post_author is distinct from me or post_created <> now()
         or (ag is not null and post_agent is distinct from ag) or kind not in ('member', 'admin', 'agent') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'post'; judged := me; agent := post_agent;
    when p_action = 'post.reported' then
      select p.id, p.author_id, p.agent_id, p.status, p.created_at into v_post, post_author, post_agent, post_status, post_created
        from app.posts p where p.id = p_subject for no key update;
      if not found or kind not in ('member', 'admin')
         or not exists (select 1 from app.review_flags f where f.post_id = p_subject and f.source = 'report' and f.reporter_id = me and f.resolved_at is null) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'post'; judged := post_author; agent := post_agent;
    when p_action = 'draft.create' then
      if kind <> 'agent' or not exists (select 1 from app.agent_drafts d where d.id = p_subject and d.agent_id = ag and d.created_at = now()) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'draft'; judged := me; agent := ag;
    when p_action in ('signup', 'account.check', 'account.delete', 'agent.create', 'agent.claim') then
      if kind not in ('member', 'admin') or (p_subject is not null and p_subject is distinct from me) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'member'; judged := me;
    when p_action in ('agent.key', 'agent.rules') then
      if kind not in ('member', 'admin')
         or not exists (select 1 from app.agents a where a.id = p_subject and a.owner_id = me and a.status = 'active') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; judged := me; agent := p_subject;
    when p_action = 'agent.register' then
      if kind <> 'anon' or p_subject is not null then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := null; judged := null;
    else
      raise exception 'bad JEVs request' using errcode = '22023';
  end case;

  select max(case when s.key = 'mode' then s.value end),
         max(case when s.key = 'medium_any' then s.value end)::integer, max(case when s.key = 'high_any' then s.value end)::integer,
         max(case when s.key = 'medium_total' then s.value end)::integer, max(case when s.key = 'high_total' then s.value end)::integer,
         max(case when s.key = 'pass_max' then s.value end)::integer, max(case when s.key = 'promote_min_age_hours' then s.value end)::integer,
         max(case when s.key = 'challenge_hours' then s.value end)::integer
    into s_mode, s_medium_any, s_high_any, s_medium_total, s_high_total, s_pass, s_age, s_challenge
    from app.jevs_settings s;

  select coalesce(sum((e.value)::integer), 0), coalesce(max((e.value)::integer), 0) into total, top from jsonb_each(p_scores) e;
  questions := array(select k from jsonb_object_keys(p_scores) k order by k);

  if p_error then
    lvl := case when p_impact = 'high' then 'high' else 'low' end;
  elsif top >= s_high_any or total >= s_high_total then
    lvl := 'high';
  elsif top >= s_medium_any or total >= s_medium_total then
    lvl := 'medium';
  else
    lvl := 'low';
  end if;

  -- What each level means for each kind of action.
  if p_error then
    eff := case when p_impact = 'high' then 'hold' else 'none' end;
  elsif p_action = 'post.create' then
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  elsif p_action = 'post.approved' then
    -- The owner already confirmed these exact words; only high risk holds them.
    eff := case lvl when 'high' then 'hold' else 'none' end;
  elsif p_action = 'post.reported' then
    eff := case lvl when 'high' then 'hide' else 'none' end;
  elsif p_action = 'draft.create' then
    -- Every draft already waits for its owner.
    eff := 'none';
  elsif p_action = 'agent.register' then
    -- The owner's claim is the human check; only high risk holds a registration.
    eff := case lvl when 'high' then 'hold' else 'none' end;
  elsif p_action in ('signup', 'account.check') then
    eff := 'none';
    if lvl = 'high' then
      eff := 'queue';
    elsif lvl = 'low' then
      -- Automatic level 2: every standard account question was asked and passed, and the account is old enough.
      select x.trust_level, x.status, x.is_admin, x.level_set_by_admin, x.jevs_level2_at, x.created_at
        into mem_level, mem_status, mem_admin, mem_hand, mem_jevs, mem_created from app.members x where x.id = judged;
      ok := p_scores ?& array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10', 'J13'] and top <= s_pass
            and mem_status = 'active' and not mem_admin and mem_level < 2 and mem_hand is null
            and mem_jevs is null and mem_created <= now() - make_interval(hours => s_age);
      if ok then
        eff := 'promote';
      end if;
    end if;
  else
    -- Sensitive actions: medium asks the owner to confirm by signing in again; high holds the action for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  end if;

  -- Aaron is never held or challenged: he runs the controls, as the brake never limits him (006).
  if judged is not null and exists (select 1 from app.members x where x.id = judged and x.is_admin) then
    eff := 'none';
  end if;

  -- Shadow mode carries out nothing that stops anyone. Promotion and Aaron's list never stop anyone, so they apply in
  -- both modes.
  insert into app.jevs_decisions (action, subject_kind, subject_id, member_id, agent_id, level, mode, effect, applied, error, total, scores)
    values (p_action, subj_kind, coalesce(p_subject, judged), judged, agent, lvl, s_mode, eff,
            eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), p_error, least(total, 10000), p_scores)
    returning id into did;

  if eff in ('promote', 'queue') or (eff <> 'none' and s_mode = 'enforce') then
    if subj_kind = 'post' and eff in ('challenge', 'hold') and post_status = 'live' then
      update app.posts p set status = 'waiting' where p.id = v_post;
    elsif subj_kind = 'post' and eff = 'hide' and post_status in ('live', 'waiting') then
      update app.posts p set status = 'removed' where p.id = v_post;
    end if;
    if subj_kind = 'post' and eff in ('hold', 'hide')
       and not exists (select 1 from app.review_flags f where f.post_id = v_post and f.source = 'classifier' and f.classifier = 'jevs' and f.resolved_at is null) then
      insert into app.review_flags (post_id, source, classifier, score) values (v_post, 'classifier', 'jevs', least(total, 100) / 100.0);
    end if;
    if eff = 'challenge' then
      -- A sensitive action is confirmed by a fresh sign-in (the site marks the transaction); a post waits for its owner.
      cstatus := case when subj_kind <> 'post' and coalesce(current_setting('app.fresh', true), '') = '1' then 'confirmed' else 'pending' end;
      insert into app.jevs_challenges (decision_id, owner_id, action, subject_kind, subject_id, status, expires_at, decided_at)
        values (did, judged, p_action, subj_kind, coalesce(p_subject, judged), cstatus, now() + make_interval(hours => s_challenge),
                case when cstatus = 'confirmed' then now() end)
        returning id into cid;
    end if;
    if eff = 'promote' then
      update app.members x set jevs_level2_at = now(), trust_level = 2 where x.id = judged;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('member.level_changed', 'member', judged, jsonb_build_object('reason', 'jevs', 'from', mem_level, 'to', 2,
                'decision', did, 'questions', to_jsonb(questions)));
    elsif subj_kind is distinct from 'post' and eff in ('hold', 'challenge', 'queue') then
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('jevs.' || eff, coalesce(subj_kind, 'member'), coalesce(p_subject, judged), jsonb_build_object('action', p_action, 'decision', did, 'level', lvl,
                'questions', to_jsonb(array(select k from jsonb_each(p_scores) e(k, v) where (v)::integer > 0 order by k))));
    end if;
  end if;

  -- What later posts are compared with: every post's text print, and the link domains of low-risk posts.
  if subj_kind = 'post' and p_action <> 'post.reported' then
    if p_simhash is not null then
      insert into app.jevs_prints (post_id, author_id, simhash) values (v_post, post_author, p_simhash) on conflict (post_id) do nothing;
    end if;
    if lvl = 'low' and not p_error and p_domains is not null then
      insert into app.jevs_domains (domain_hash) select distinct x from unnest(p_domains) x
        on conflict (domain_hash) do update set last_seen_at = now(), posts = app.jevs_domains.posts + 1;
    end if;
  end if;

  -- Marks are kept 30 days; links not used within a day are dropped.
  if random() < 0.01 then
    delete from app.jevs_marks k where k.created_at < now() - interval '30 days' or (k.token_hash is not null and k.created_at < now() - interval '1 day');
  end if;

  return query select did, lvl, eff, eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), s_mode, cid, cstatus;
end
$$;

-- ---- The owner answers a challenge (never an agent) ----
-- Returns 'confirmed' or 'declined'. Refusals: not_found (P0002: unknown, or not yours), stale (already answered),
-- expired. Confirming a held post puts it live; declining removes it.
create function app.jevs_answer(p_challenge uuid, p_answer text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  c app.jevs_challenges%rowtype;
  st text;
  ps text;
begin
  if app.actor_kind() not in ('member', 'admin') or p_challenge is null or p_answer is null or p_answer not in ('confirm', 'decline') then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  select * into c from app.jevs_challenges x where x.id = p_challenge for update;
  if not found or c.owner_id is distinct from app.current_member() then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  if c.status <> 'pending' then
    raise exception 'stale' using errcode = 'P0001';
  end if;
  if c.expires_at <= now() then
    raise exception 'expired' using errcode = 'P0001';
  end if;
  st := case when p_answer = 'confirm' then 'confirmed' else 'declined' end;
  update app.jevs_challenges x set status = st where x.id = c.id;
  if c.subject_kind = 'post' then
    select p.status into ps from app.posts p where p.id = c.subject_id for no key update;
    if ps = 'waiting' then
      update app.posts p set status = case when st = 'confirmed' then 'live' else 'removed' end where p.id = c.subject_id;
    end if;
  end if;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('jevs.answer', coalesce(c.subject_kind, 'member'), c.subject_id, jsonb_build_object('challenge', c.id, 'answer', st));
  return st;
end
$$;

-- ---- Marks ----
-- p_agent: an agent that registered in the last 10 minutes (signed out). p_token: an email sign-in link that hasn't
-- been used yet (signed out). Otherwise the signed-in member. Repeats are ignored.
create function app.jevs_mark(p_kind text, p_key_hash text, p_token text, p_agent uuid)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  kind text := app.actor_kind();
begin
  if p_kind is null or p_kind not in ('net', 'email_domain', 'disposable') or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$'
     or (p_token is not null and p_token !~ '^[0-9a-f]{64}$') or (p_token is not null and p_agent is not null) then
    raise exception 'bad JEVs mark' using errcode = '22023';
  end if;
  if p_agent is not null then
    if kind <> 'anon' or not exists (select 1 from app.agents a where a.id = p_agent and a.status = 'unclaimed' and a.created_at > now() - interval '10 minutes') then
      raise exception 'bad JEVs mark' using errcode = '22023';
    end if;
    insert into app.jevs_marks (agent_id, kind, key_hash)
      select p_agent, p_kind, p_key_hash where not exists (select 1 from app.jevs_marks k where k.agent_id = p_agent and k.kind = p_kind);
  elsif p_token is not null then
    if kind <> 'anon' or (select count(*) from app.jevs_marks k where k.token_hash = p_token) >= 3 then
      raise exception 'bad JEVs mark' using errcode = '22023';
    end if;
    insert into app.jevs_marks (token_hash, kind, key_hash) values (p_token, p_kind, p_key_hash);
  else
    if kind not in ('member', 'admin') then
      raise exception 'bad JEVs mark' using errcode = '22023';
    end if;
    insert into app.jevs_marks (member_id, kind, key_hash)
      select app.current_member(), p_kind, p_key_hash
      where not exists (select 1 from app.jevs_marks k where k.member_id = app.current_member() and k.kind = p_kind and k.key_hash = p_key_hash);
  end if;
end
$$;

-- The marks an email link carried become the signed-in member's (right after signing in with that link).
create function app.jevs_mark_claim(p_token text)
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
begin
  if app.actor_kind() not in ('member', 'admin') or p_token is null or p_token !~ '^[0-9a-f]{64}$' then
    raise exception 'bad JEVs mark' using errcode = '22023';
  end if;
  update app.jevs_marks k set member_id = app.current_member(), token_hash = null
    where k.token_hash = p_token and k.created_at > now() - interval '1 day';
  get diagnostics n = row_count;
  return n;
end
$$;

-- ---- The regional gate's count ----
create function app.region_decline(p_country text)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_country is null or p_country !~ '^[A-Z]{2}$' then
    raise exception 'bad country' using errcode = '22023';
  end if;
  insert into app.region_declines (day, country, declines) values (current_date, p_country, 1)
    on conflict (day, country) do update set declines = app.region_declines.declines + 1;
end
$$;

-- ---- A change to a setting is recorded (who: the owner's session, which the log shows as signed out) ----
create function app.jevs_settings_audit() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if new.value is distinct from old.value then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('jevs.setting', null, null, jsonb_build_object('key', new.key, 'from', old.value, 'to', new.value));
  end if;
  return null;
end
$$;
create trigger jevs_settings_audit after update on app.jevs_settings for each row execute function app.jevs_settings_audit();
alter table app.jevs_settings enable always trigger jevs_settings_audit;

-- ---- Deleting an account (F8) also clears what JEVs kept about it ----
create policy jevs_decisions_erase_select on app.jevs_decisions for select to dog_erase using (true);
create policy jevs_decisions_erase_delete on app.jevs_decisions for delete to dog_erase using (true);
grant select (id, member_id, agent_id), delete on app.jevs_decisions to dog_erase;
create policy jevs_challenges_erase_select on app.jevs_challenges for select to dog_erase using (true);
create policy jevs_challenges_erase_delete on app.jevs_challenges for delete to dog_erase using (true);
grant select (id, owner_id), delete on app.jevs_challenges to dog_erase;
create policy jevs_marks_erase_select on app.jevs_marks for select to dog_erase using (true);
create policy jevs_marks_erase_delete on app.jevs_marks for delete to dog_erase using (true);
grant select (id, member_id, agent_id), delete on app.jevs_marks to dog_erase;
create policy jevs_prints_erase_select on app.jevs_prints for select to dog_erase using (true);
create policy jevs_prints_erase_delete on app.jevs_prints for delete to dog_erase using (true);
grant select (id, author_id, post_id), delete on app.jevs_prints to dog_erase;

grant create on schema app to dog_erase;
set local role dog_erase;
create or replace function app.delete_account()
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  n_posts integer; n_flags integer; n_my_reports integer; n_agents integer; n_keys integer; n_sessions integer; n_ids integer; n_brakes integer;
  n_drafts integer; n_jevs integer;
begin
  if app.actor_kind() <> 'member' or me is null then
    raise exception 'not_member' using errcode = '42501';
  end if;
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
  -- What JEVs kept about them (010): decisions, challenges, marks and text prints.
  delete from app.jevs_challenges c where c.owner_id = me;
  delete from app.jevs_decisions d where d.member_id = me or d.agent_id in (select a.id from app.agents a where a.owner_id = me);
  get diagnostics n_jevs = row_count;
  delete from app.jevs_marks k where k.member_id = me or k.agent_id in (select a.id from app.agents a where a.owner_id = me);
  delete from app.jevs_prints r where r.author_id = me;
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
            'agents', n_agents, 'keys', n_keys, 'drafts', n_drafts, 'brakes', n_brakes, 'sessions', n_sessions, 'identities', n_ids, 'jevs_decisions', n_jevs));
  return query select n_posts, n_my_reports, n_agents, n_keys, n_sessions, n_ids;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_erase;

-- ---- Who may call what ----
revoke execute on function app.jevs_settings_check(), app.jevs_enforcing(), app.jevs_decisions_guard(), app.jevs_challenges_guard(),
  app.jevs_appealable(uuid), app.jevs_signals(text, uuid, text, text[], bigint), app.jevs_decide(text, uuid, jsonb, text, boolean, text[], bigint),
  app.jevs_answer(uuid, text), app.jevs_mark(text, text, text, uuid), app.jevs_mark_claim(text), app.region_decline(text),
  app.jevs_settings_audit() from public;
grant execute on function app.jevs_appealable(uuid), app.jevs_signals(text, uuid, text, text[], bigint),
  app.jevs_decide(text, uuid, jsonb, text, boolean, text[], bigint), app.jevs_answer(uuid, text), app.jevs_mark(text, text, text, uuid),
  app.jevs_mark_claim(text), app.region_decline(text), app.jevs_settings_audit() to dog_app;

grant create on schema app to dog_jevs;
alter function app.jevs_appealable(uuid) owner to dog_jevs;
alter function app.jevs_signals(text, uuid, text, text[], bigint) owner to dog_jevs;
alter function app.jevs_decide(text, uuid, jsonb, text, boolean, text[], bigint) owner to dog_jevs;
alter function app.jevs_answer(uuid, text) owner to dog_jevs;
alter function app.jevs_mark(text, text, text, uuid) owner to dog_jevs;
alter function app.jevs_mark_claim(text) owner to dog_jevs;
alter function app.region_decline(text) owner to dog_jevs;
alter function app.jevs_settings_audit() owner to dog_jevs;
revoke create on schema app from dog_jevs;
