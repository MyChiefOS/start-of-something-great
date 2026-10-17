-- 010 JEVs core (Release 2, PR 12): the automated checking layer.
-- Aaron's decisions (Oct 16, 2026): every account and every action is scored against a standard set of risk questions
-- written in code; low risk passes, medium risk is challenged (confirmation goes to the human owner, never the agent),
-- high risk is held or hidden and goes to Aaron. Members are trusted by default. No trust level is promoted by hand:
-- JEVs promotes to level 2 automatically when every standard question passes, with no wait. Sign-up from the EU, EEA,
-- UK and Switzerland is declined before anything is stored; only daily counts by country are kept. Members who live
-- elsewhere can sign in while travelling there after confirming it (Oct 16, 2026). A high-risk account deletion goes
-- to Aaron for review, and an account he hasn't decided on within 24 hours is disabled, never deleted (Oct 16, 2026).
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
    'challenge_hours', 'credible_reporter_age_hours'])),
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
--   pass_max: a question "passes" for automatic level 2 at this score or lower. There is no minimum age (Aaron,
--   Oct 16, 2026: "No wait at all"): J01, the account's age, is asked and counts towards the risk level, but it
--   doesn't have to pass for level 2.
--   challenge_hours: how long an owner has to confirm a challenged action.
--   credible_reporter_age_hours: a report counts as credible (for hiding at once) only from an account this old.
insert into app.jevs_settings (key, value) values
  ('mode', 'shadow'), ('medium_any', '40'), ('high_any', '80'), ('medium_total', '70'), ('high_total', '140'),
  ('pass_max', '10'), ('challenge_hours', '48'), ('credible_reporter_age_hours', '168');

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

-- ---- Link domains in low-risk posts (a SHA-256 of the domain; domains in public posts are public) ----
-- One row per post and domain. A domain counts as "seen" (J07) only through a post that has stayed live for 24 hours,
-- so a post Aaron removes stops vouching for its links, and a spammer can't launder a domain with one quick harmless
-- post (the JEVs review, F6). Deleted with the post's author.
create table app.jevs_post_domains (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null references app.posts (id),
  domain_hash text not null check (char_length(domain_hash) = 64 and domain_hash ~ '^[0-9a-f]+$'),
  created_at timestamptz not null default now(),
  unique (post_id, domain_hash)
);
create index jevs_post_domains_domain on app.jevs_post_domains (domain_hash);
alter table app.jevs_post_domains enable row level security;
alter table app.jevs_post_domains force row level security;
create policy jevs_post_domains_jevs_select on app.jevs_post_domains for select to dog_jevs using (true);
create policy jevs_post_domains_jevs_insert on app.jevs_post_domains for insert to dog_jevs with check (true);
grant select, insert on app.jevs_post_domains to dog_jevs;

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
  -- Disabling an account and restoring it belong to a deletion review alone (dog_erase, below), and only between
  -- active and disabled. Aaron is never disabled.
  if new.status is distinct from old.status and (current_user = 'dog_erase' or 'disabled' in (new.status, old.status)) then
    if current_user <> 'dog_erase' or not ((old.status = 'active' and new.status = 'disabled') or (old.status = 'disabled' and new.status = 'active')) then
      raise exception 'only a deletion review disables or restores an account' using errcode = '42501';
    end if;
    if old.is_admin then
      raise exception 'an administrator can''t be disabled' using errcode = '42501';
    end if;
  end if;
  if new.trust_level is distinct from old.trust_level and current_user not in ('dog_signin', 'dog_jevs') then
    new.level_set_by_admin := new.trust_level;
  elsif new.level_set_by_admin is distinct from old.level_set_by_admin and current_user <> 'dog_owner' then
    raise exception 'the hand-set level changes only through the trust level' using errcode = '42501';
  end if;
  if new.jevs_level2_at is distinct from old.jevs_level2_at and current_user <> 'dog_jevs' then
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
    act := case when new.status = 'banned' then 'member.ban' when new.status = 'disabled' then 'member.disable'
                when old.status = 'disabled' then 'member.restore' else 'member.unban' end;
  elsif new.trust_level is distinct from old.trust_level and current_user not in ('dog_signin', 'dog_jevs') then
    act := 'member.level_set';
  else
    return null;
  end if;
  -- Aaron's notes go with bans and levels; a deletion review records its own reasons.
  if note is not null and act in ('member.ban', 'member.unban', 'member.level_set') then
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

-- ---- Deletion reviews (Aaron, Oct 16, 2026) ----
-- "JEVs scores and provide deletion as high risk. The member should be informed their account was flagged as high
-- risk. A review will be provided to me and I will make a decision on account status. If I have not responded to a
-- high risk account in 24 hours the account should be disabled but not deleted until I make a decision based on the
-- data provided."
-- A review points at the JEVs decision that held the deletion (its question IDs and scores, append-only: the data
-- Aaron decides on). It is open until Aaron decides: delete (the account and the review go), keep disabled, or
-- restore. An open review older than 24 hours disables the account: every session ends, sign-in is refused with a
-- plain message, the owner's agents are switched off and their keys revoked, and nothing is deleted.
alter table app.members drop constraint members_status_check;
alter table app.members add constraint members_status_check check (status = any (array['active', 'banned', 'disabled']));

create table app.deletion_reviews (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id),
  decision_id uuid not null references app.jevs_decisions (id),
  created_at timestamptz not null default now(),
  disabled_at timestamptz,
  decided_at timestamptz,
  decision text check (decision = any (array['keep_disabled', 'restore'])),
  check ((decision is null) = (decided_at is null))
);
-- One review a member at a time: open, or kept disabled (Aaron can still delete or restore later).
create unique index deletion_reviews_one on app.deletion_reviews (member_id) where decision is null or decision = 'keep_disabled';
create index deletion_reviews_due on app.deletion_reviews (created_at) where decision is null and disabled_at is null;
alter table app.deletion_reviews enable row level security;
alter table app.deletion_reviews force row level security;
-- Aaron sees every review; a member sees their own (when it started, whether it disabled them, what was decided).
create policy deletion_reviews_select on app.deletion_reviews for select to dog_app
  using (app.actor_kind() = 'admin' or (app.actor_kind() = 'member' and member_id = app.current_member()));
grant select on app.deletion_reviews to dog_app;
-- JEVs opens them (app.jevs_decide); the review functions (dog_erase) decide, disable and delete them; sign-in
-- (dog_signin) reads whether one is overdue.
create policy deletion_reviews_jevs_select on app.deletion_reviews for select to dog_jevs using (true);
create policy deletion_reviews_jevs_insert on app.deletion_reviews for insert to dog_jevs with check (true);
grant select (id, member_id, decision), insert (member_id, decision_id) on app.deletion_reviews to dog_jevs;
create policy deletion_reviews_signin_select on app.deletion_reviews for select to dog_signin using (true);
grant select (member_id, created_at, disabled_at, decision) on app.deletion_reviews to dog_signin;
create policy deletion_reviews_erase_select on app.deletion_reviews for select to dog_erase using (true);
create policy deletion_reviews_erase_update on app.deletion_reviews for update to dog_erase using (true) with check (true);
create policy deletion_reviews_erase_delete on app.deletion_reviews for delete to dog_erase using (true);
grant select, delete on app.deletion_reviews to dog_erase;
grant update (disabled_at, decided_at, decision) on app.deletion_reviews to dog_erase;

-- What a review is about never changes; it is disabled once and decided (only from open or kept disabled), by the
-- review functions alone; it is deleted only with the account.
create function app.deletion_reviews_guard() returns trigger
language plpgsql
as $$
begin
  if current_user <> 'dog_erase' then
    raise exception 'only Aaron''s decision or the 24-hour timer changes a deletion review' using errcode = '42501';
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  if (new.id, new.member_id, new.decision_id, new.created_at) is distinct from (old.id, old.member_id, old.decision_id, old.created_at)
     or (old.disabled_at is not null and new.disabled_at is distinct from old.disabled_at)
     or old.decision = 'restore' or (old.decision is not null and new.decision is null) then
    raise exception 'a deletion review''s record never changes' using errcode = '42501';
  end if;
  return new;
end
$$;
create trigger deletion_reviews_guard before update or delete on app.deletion_reviews for each row execute function app.deletion_reviews_guard();
alter table app.deletion_reviews enable always trigger deletion_reviews_guard;

-- Whether a member's open review is past its 24 hours without a decision. Sign-in, sessions and agent keys treat
-- such an account as disabled straight away, whenever the timer (app.deletion_reviews_expire) next runs.
create function app.deletion_overdue(p_member uuid)
returns boolean
language sql stable
as $$
  select exists (select 1 from app.deletion_reviews r where r.member_id = p_member and r.decision is null and r.disabled_at is null
                 and r.created_at <= now() - interval '24 hours')
$$;

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
  subject_at timestamptz := now();
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
    select p.author_id, p.body_fp, p.created_at into judged, fp, subject_at from app.posts p where p.id = p_subject;
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
      -- J05: an account made in the last 7 days is "new"; an established one is never judged by its neighbours (the
      -- JEVs review, F3). Network marks are left at sign-up only (signin/flow.js). Counted: other new accounts that
      -- signed up from the same network in the last 24 hours, or with the same uncommon email domain in the last 7 days.
      'established', m_created <= now() - interval '7 days',
      'net_members_24h', (select count(distinct k2.member_id) from app.jevs_marks k1 join app.jevs_marks k2
                            on k2.kind = 'net' and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                            and k2.created_at > now() - interval '24 hours'
                            join app.members n on n.id = k2.member_id and n.created_at > now() - interval '7 days'
                          where k1.member_id = judged and k1.kind = 'net' and k1.created_at > now() - interval '24 hours'),
      'domain_members_7d', (select count(distinct k2.member_id) from app.jevs_marks k1 join app.jevs_marks k2
                              on k2.kind = 'email_domain' and k2.key_hash = k1.key_hash and k2.member_id is not null and k2.member_id <> judged
                              and k2.created_at > now() - interval '7 days'
                              join app.members n on n.id = k2.member_id and n.created_at > now() - interval '7 days'
                            where k1.member_id = judged and k1.kind = 'email_domain'),
      -- J06: agents this owner created or claimed in the last 24 hours.
      'owner_agents_24h', (select count(*) from app.agents a where a.owner_id = judged and a.claimed_at > now() - interval '24 hours'),
      -- J10: upheld reports on their posts (90 days) and a brake on them now. Nothing about neighbours: a banned member
      -- on the same network or email domain says nothing about this one (the JEVs review, F4), and a banned person's
      -- own sign-in methods are refused at sign-in already (F10).
      'upheld_90d', (select count(*) from app.review_flags f join app.posts p on p.id = f.post_id
                     where p.author_id = judged and f.source = 'report' and f.decision = 'remove' and f.resolved_at > now() - interval '90 days'),
      'braked', exists (select 1 from app.brakes b where b.member_id = judged and b.lifted_at is null)
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
  -- A domain counts as seen once a low-risk post linking it has stayed live for 24 hours; removing that post unsees
  -- it (the JEVs review, F6). A copy is an earlier live post by another member, so whoever wrote it first is never
  -- the one judged, and held or removed copies count for nothing; text too short to compare fairly (under 8 words
  -- or 40 characters, when db/jevs.js gives no print) is never counted as copied (the JEVs review, F1 and F2).
  if p_action in ('post.create', 'post.approved', 'post.reported', 'draft.create') then
    res := res || jsonb_build_object(
      'new_domains', case when p_domains is null then 0 else
                       (select count(distinct x) from unnest(p_domains) x where not exists (
                          select 1 from app.jevs_post_domains d join app.posts p on p.id = d.post_id
                          where d.domain_hash = x and p.status = 'live' and p.created_at <= now() - interval '24 hours')) end,
      'copies', case when p_simhash is null then 0 else (select count(distinct a) from (
                   select p.author_id as a from app.posts p
                   where fp is not null and p.body_fp = fp and p.author_id is distinct from judged and p.status = 'live'
                     and p.created_at < subject_at and p.created_at > now() - interval '7 days'
                   union
                   select p.author_id from app.jevs_prints r join app.posts p on p.id = r.post_id
                   where p.author_id is distinct from judged and p.status = 'live' and p.created_at < subject_at
                     and r.created_at > now() - interval '7 days' and bit_count(int8send(r.simhash # p_simhash)) <= 10) c) end);
  end if;

  -- J14: credible members with an open report on this post: level 2, not made in the last credible_reporter_age_hours
  -- (7 days as seeded), and independent of each other: a reporter who shares a sign-up network or an uncommon email
  -- domain with an earlier credible reporter counts with them as one (the JEVs review, F1).
  if p_action = 'post.reported' then
    select s.value::integer into credible_hours from app.jevs_settings s where s.key = 'credible_reporter_age_hours';
    res := res || jsonb_build_object('credible_reports', (
      with cr as (
        select f.reporter_id as rid, min(f.created_at) as at from app.review_flags f join app.members r on r.id = f.reporter_id
        where f.post_id = p_subject and f.source = 'report' and f.resolved_at is null
          and r.status = 'active' and r.trust_level >= 2 and r.created_at <= now() - make_interval(hours => coalesce(credible_hours, 168))
        group by f.reporter_id)
      select count(*) from cr a
      where not exists (select 1 from cr b join app.jevs_marks kb on kb.member_id = b.rid
                        join app.jevs_marks ka on ka.member_id = a.rid and ka.kind = kb.kind and ka.key_hash = kb.key_hash
                        where (b.at, b.rid) < (a.at, a.rid) and ka.kind in ('net', 'email_domain'))));
  end if;
  return res;
end
$$;

-- ---- The account questions, worked out by the database itself (the JEVs review, F5) ----
-- The same scores db/jevs.js gives J01 to J06 and J10, from app.jevs_signals' counts (a test keeps the two the same
-- over thousands of cases). For sign-up and account checks, which can promote an account, the database uses these and
-- not the site's numbers; only J13 (the request's country) comes from the site, as the actor does.
create function app.jevs_account_scores(s jsonb)
returns jsonb
language plpgsql immutable
as $$
declare
  n numeric;
  usual numeric;
  r numeric;
  best integer := coalesce((s ->> 'best_identity')::integer, -1);
  j04 integer;
  j05 integer;
begin
  n := coalesce((s ->> 'posts_1h')::numeric, 0);
  if n >= 60 then
    j04 := 85;
  else
    usual := greatest(3, 3 * (coalesce((s ->> 'posts_before')::numeric, 0) / (14 * 24)));
    r := n / usual;
    j04 := case when r <= 1 then 0 when r <= 2 then 20 when r <= 4 then 45 else 70 end;
  end if;
  if coalesce((s ->> 'established')::boolean, false) then
    j05 := 0;
  else
    j05 := greatest(
      case when (s ->> 'net_members_24h')::numeric >= 10 then 80 when (s ->> 'net_members_24h')::numeric >= 5 then 50
           when (s ->> 'net_members_24h')::numeric >= 2 then 25 else 0 end,
      case when (s ->> 'domain_members_7d')::numeric >= 10 then 60 when (s ->> 'domain_members_7d')::numeric >= 3 then 30 else 0 end,
      case when (s ->> 'net_signups_1h')::numeric >= 20 then 50 when (s ->> 'net_signups_1h')::numeric >= 5 then 25 else 0 end,
      case when coalesce((s ->> 'site_signups_1h')::numeric, 0) > greatest(50, 10 * (coalesce((s ->> 'site_signups_7d')::numeric, 0) / 168)) then 20 else 0 end);
  end if;
  return jsonb_build_object(
    'J01', case when coalesce((s ->> 'age_hours')::numeric, 0) < 1 then 25 when (s ->> 'age_hours')::numeric < 24 then 15
                when (s ->> 'age_hours')::numeric < 168 then 10 else 0 end,
    'J02', case when coalesce((s ->> 'admin')::boolean, false) then 0 when best >= 2 then 0
                when best = 1 then case when coalesce((s ->> 'providers')::integer, 0) >= 2 then 0 else 10 end
                when best = 0 then 30 else 40 end,
    'J03', case when coalesce((s ->> 'disposable')::boolean, false) then 60 else 0 end,
    'J04', j04,
    'J05', j05,
    'J06', greatest(
      case when (s ->> 'owner_agents_24h')::numeric >= 25 then 70 when (s ->> 'owner_agents_24h')::numeric >= 10 then 50
           when (s ->> 'owner_agents_24h')::numeric >= 4 then 25 else 0 end,
      case when (s ->> 'net_agents_24h')::numeric >= 25 then 70 when (s ->> 'net_agents_24h')::numeric >= 10 then 50
           when (s ->> 'net_agents_24h')::numeric >= 4 then 25 else 0 end),
    'J10', greatest(
      case when (s ->> 'upheld_90d')::numeric >= 3 then 90 when (s ->> 'upheld_90d')::numeric >= 2 then 60
           when (s ->> 'upheld_90d')::numeric >= 1 then 30 else 0 end,
      case when coalesce((s ->> 'braked')::boolean, false) then 40 else 0 end));
end
$$;
revoke execute on function app.jevs_account_scores(jsonb) from public;
grant execute on function app.jevs_account_scores(jsonb) to dog_jevs;

-- ---- The decision ----
-- p_scores: question ID -> score (0 to 100), computed by the site from the signals and the public questions.
-- p_impact: 'high' for sensitive actions (held if scoring failed), 'low' for the rest (they go ahead if it failed).
-- p_error: scoring failed (p_scores is then empty). p_net: the request's network hash, as for app.jevs_signals.
-- Returns what JEVs decided and whether it was carried out.
create function app.jevs_decide(p_action text, p_subject uuid, p_scores jsonb, p_impact text, p_error boolean, p_domains text[], p_simhash bigint,
                                 p_net text)
returns table (decision_id uuid, level text, effect text, applied boolean, mode text, challenge_id uuid, challenge_status text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  kind text := app.actor_kind();
  s_mode text; s_medium_any integer; s_high_any integer; s_medium_total integer; s_high_total integer; s_pass integer;
  s_challenge integer;
  subj_kind text;
  judged uuid;
  agent uuid;
  v_post uuid; post_author uuid; post_agent uuid; post_status text; post_created timestamptz;
  mem_level smallint; mem_status text; mem_admin boolean; mem_hand smallint; mem_jevs timestamptz;
  total integer := 0;
  top integer := 0;
  lvl text;
  eff text;
  did uuid;
  cid uuid;
  cstatus text;
  rid uuid;
  questions text[];
  ok boolean;
begin
  if p_action is null or p_impact is null or p_impact not in ('low', 'high') or p_error is null or p_scores is null
     or jsonb_typeof(p_scores) <> 'object' or (select count(*) from jsonb_object_keys(p_scores)) > 20
     or exists (select 1 from jsonb_each(p_scores) e where e.key !~ '^J[0-9]{2}$' or jsonb_typeof(e.value) <> 'number'
                or (e.value)::numeric <> floor((e.value)::numeric) or (e.value)::numeric not between 0 and 100)
     or (p_domains is not null and (cardinality(p_domains) > 50 or exists (select 1 from unnest(p_domains) x where x is null or x !~ '^[0-9a-f]{64}$')))
     or (p_net is not null and p_net !~ '^[0-9a-f]{64}$') then
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
         max(case when s.key = 'pass_max' then s.value end)::integer, max(case when s.key = 'challenge_hours' then s.value end)::integer
    into s_mode, s_medium_any, s_high_any, s_medium_total, s_high_total, s_pass, s_challenge
    from app.jevs_settings s;

  -- Sign-up and account checks can promote: the database works out their account questions itself (all but J13, the
  -- request's country), whatever the site sent.
  if p_action in ('signup', 'account.check') and not p_error then
    p_scores := (p_scores - array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10'])
                || app.jevs_account_scores(app.jevs_signals(p_action, null, p_net, null, null));
  end if;
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
      -- Automatic level 2, with no wait (Aaron, Oct 16, 2026): every standard account question was asked, and every
      -- one but the account's age (J01) passed. J01 still counts towards the level above.
      select x.trust_level, x.status, x.is_admin, x.level_set_by_admin, x.jevs_level2_at
        into mem_level, mem_status, mem_admin, mem_hand, mem_jevs from app.members x where x.id = judged;
      ok := p_scores ?& array['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10', 'J13']
            and (select coalesce(max((e.value)::integer), 0) from jsonb_each(p_scores) e where e.key <> 'J01') <= s_pass
            and mem_status = 'active' and not mem_admin and mem_level < 2 and mem_hand is null and mem_jevs is null;
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
      -- A fresh sign-in that confirms this action also answers the owner's earlier requests to confirm the same action,
      -- so nothing is left waiting for an answer that has already been given.
      if cstatus = 'confirmed' then
        update app.jevs_challenges c set status = 'confirmed'
          where c.owner_id = judged and c.action = p_action and c.subject_id is not distinct from coalesce(p_subject, judged)
            and c.status = 'pending' and c.id <> cid;
      end if;
    end if;
    -- A held account deletion goes to Aaron as a deletion review (Oct 16, 2026): nothing is deleted, the member is told,
    -- and the account is disabled (never deleted) if he hasn't decided within 24 hours. Only from a fresh sign-in, so
    -- a stolen session cookie can't start the clock on someone else's account; one open review per member.
    if p_action = 'account.delete' and eff = 'hold' and coalesce(current_setting('app.fresh', true), '') = '1'
       and not exists (select 1 from app.deletion_reviews r where r.member_id = judged and (r.decision is null or r.decision = 'keep_disabled')) then
      insert into app.deletion_reviews (member_id, decision_id) values (judged, did) returning id into rid;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('deletion_review.opened', 'member', judged, jsonb_build_object('review', rid, 'decision', did, 'error', p_error));
    end if;
    if eff = 'promote' then
      update app.members x set jevs_level2_at = now(), trust_level = 2 where x.id = judged;
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('member.level_changed', 'member', judged, jsonb_build_object('reason', 'jevs', 'from', mem_level, 'to', 2,
                'decision', did, 'questions', to_jsonb(questions)));
    elsif subj_kind is distinct from 'post' and eff in ('hold', 'challenge', 'queue') then
      -- The effect only: which questions scored stay in the decision row, deleted with the account (the JEVs review, F10).
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('jevs.' || eff, coalesce(subj_kind, 'member'), coalesce(p_subject, judged), jsonb_build_object('action', p_action, 'decision', did, 'level', lvl));
    end if;
  end if;

  -- What later posts are compared with: every post's text print, and the link domains of low-risk posts.
  if subj_kind = 'post' and p_action <> 'post.reported' then
    if p_simhash is not null then
      insert into app.jevs_prints (post_id, author_id, simhash) values (v_post, post_author, p_simhash) on conflict (post_id) do nothing;
    end if;
    if lvl = 'low' and not p_error and p_domains is not null then
      insert into app.jevs_post_domains (post_id, domain_hash) select v_post, x from unnest(p_domains) x on conflict do nothing;
    end if;
  end if;

  return query select did, lvl, eff, eff <> 'none' and (eff in ('promote', 'queue') or s_mode = 'enforce'), s_mode, cid, cstatus;
end
$$;

-- ---- In enforce mode, no post goes live unscored (the JEVs review, F5) ----
-- Enforce mode turns first-post review off, so JEVs must have decided about every new post in the same transaction:
-- checked at commit, a post with no JEVs decision is refused. A path that forgot jevs.check can't publish around it.
create function app.posts_scored() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if app.jevs_enforcing() and not exists (select 1 from app.jevs_decisions d where d.subject_id = new.id and d.subject_kind = 'post') then
    raise exception 'unscored' using errcode = 'P0001', hint = 'Every post is checked by JEVs before it can be published.';
  end if;
  return null;
end
$$;
create constraint trigger posts_scored after insert on app.posts deferrable initially deferred
  for each row execute function app.posts_scored();
alter table app.posts enable always trigger posts_scored;

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
  -- A sensitive action is confirmed only by signing in again: a session cookie alone, which could be stolen, can
  -- decline but never confirm one. With a fresh sign-in, repeating the action goes ahead (app.jevs_decide).
  if p_answer = 'confirm' and c.subject_kind is distinct from 'post' and coalesce(current_setting('app.fresh', true), '') <> '1' then
    raise exception 'fresh' using errcode = 'P0001';
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

-- ---- Keeping marks no longer than promised ----
-- Marks are kept 30 days, and an email link's marks a day if the link isn't used. The site's scheduled job (the
-- system actor) runs this, so the promise holds however quiet the site is. Returns how many marks went.
create function app.jevs_sweep()
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
begin
  if app.actor_kind() not in ('system', 'admin') then
    raise exception 'not_system' using errcode = '42501';
  end if;
  delete from app.jevs_marks k where k.created_at < now() - interval '30 days' or (k.token_hash is not null and k.created_at < now() - interval '1 day');
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

-- ---- A disabled account: refused at sign-in, its sessions and keys stop, its agents are switched off ----
-- The ban clean-up (006, 008) now runs for a disabled account too. A ban lowers agents that act alone to draft; a
-- disabled account's agents are switched off altogether (every action "off"), with the reason recorded.
alter table app.agent_rules drop constraint agent_rules_reason_check;
alter table app.agent_rules add constraint agent_rules_reason_check check (reason = any (array['created', 'owner', 'report_upheld', 'ban', 'disabled']));
alter policy agent_rules_signin_insert on app.agent_rules with check (reason in ('created', 'ban', 'disabled'));

-- Same as 008, with 'disabled' among the reasons that can only lower an agent.
create or replace function app.agent_rules_fill() returns trigger
language plpgsql
as $$
declare
  prev app.agent_rules%rowtype;
  rank_of constant jsonb := '{"off": 0, "draft": 1, "act": 2}';
begin
  perform pg_advisory_xact_lock(hashtext('dayonegreat.rules'), hashtext(new.agent_id::text));
  select r.id, r.version, r.post_mode, r.reply_mode, r.report_mode, r.daily_cap
    into prev.id, prev.version, prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap
    from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  new.version := coalesce(prev.version, 0) + 1;
  new.created_at := now();
  new.set_by := case when new.reason in ('report_upheld', 'ban', 'disabled') then 'system' else 'owner' end;
  if new.reason = 'created' then
    if prev.id is not null then
      raise exception 'an agent''s first rules are set once' using errcode = '42501';
    end if;
    new.post_mode := 'draft';
    new.reply_mode := 'draft';
    new.report_mode := 'draft';
    new.daily_cap := coalesce(new.daily_cap, 20);
    return new;
  end if;
  if prev.id is null then
    raise exception 'this agent has no rules yet' using errcode = '42501';
  end if;
  if (rank_of ->> new.post_mode)::int > (rank_of ->> prev.post_mode)::int
     or (rank_of ->> new.reply_mode)::int > (rank_of ->> prev.reply_mode)::int
     or (rank_of ->> new.report_mode)::int > (rank_of ->> prev.report_mode)::int
     or new.daily_cap > prev.daily_cap then
    if new.reason in ('report_upheld', 'ban', 'disabled') then
      raise exception 'an upheld report, a ban or a disabled account can only lower an agent''s rules' using errcode = '42501';
    end if;
    if ((new.post_mode = 'act' and prev.post_mode <> 'act') or (new.reply_mode = 'act' and prev.reply_mode <> 'act')
        or (new.report_mode = 'act' and prev.report_mode <> 'act') or new.daily_cap > prev.daily_cap)
       and coalesce(current_setting('app.fresh', true), '') <> '1' then
      raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to let an agent do more without your approval.';
    end if;
  end if;
  return new;
end
$$;

revoke execute on function app.deletion_overdue(uuid) from public;
grant execute on function app.deletion_overdue(uuid) to dog_signin;

grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.members_ban_cleanup() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r record;
begin
  if new.status in ('banned', 'disabled') and old.status = 'active' then
    delete from app.sessions s where s.member_id = new.id;
    update app.agent_keys k set revoked_at = now()
      from app.agents a where a.id = k.agent_id and a.owner_id = new.id and k.revoked_at is null;
    update app.agent_drafts d set status = 'declined' where d.owner_id = new.id and d.status = 'pending';
    for r in select distinct on (x.agent_id) x.agent_id, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap
             from app.agent_rules x join app.agents a on a.id = x.agent_id
             where a.owner_id = new.id order by x.agent_id, x.version desc loop
      if new.status = 'disabled' then
        if r.post_mode <> 'off' or r.reply_mode <> 'off' or r.report_mode <> 'off' then
          insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
            values (r.agent_id, 'off', 'off', 'off', r.daily_cap, 'disabled');
        end if;
      elsif 'act' in (r.post_mode, r.reply_mode, r.report_mode) then
        insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
          values (r.agent_id, case when r.post_mode = 'act' then 'draft' else r.post_mode end,
                  case when r.reply_mode = 'act' then 'draft' else r.reply_mode end,
                  case when r.report_mode = 'act' then 'draft' else r.report_mode end, r.daily_cap, 'ban');
      end if;
    end loop;
  end if;
  return null;
end
$$;

-- Sessions (008) and agent keys (005) stop for a disabled account, and for one whose deletion review is overdue,
-- from the 24th hour, whenever the timer runs. Same as before otherwise.
create or replace function app.session_resolve(p_session_hash text, p_idle_days integer)
returns table (member_id uuid, trust_level smallint, is_admin boolean, display_name text, fresh boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s app.sessions%rowtype;
begin
  if p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$' or p_idle_days is null or p_idle_days not between 1 and 30 then
    return;
  end if;
  select * into s from app.sessions x where x.token_hash = p_session_hash;
  if not found or s.expires_at <= now() or s.last_seen_at <= now() - make_interval(days => p_idle_days) then
    return;
  end if;
  if s.last_seen_at < now() - interval '1 hour' then
    update app.sessions x set last_seen_at = now() where x.id = s.id;
    if exists (select 1 from app.members m where m.id = s.member_id and m.trust_level > app.verified_level(m.id)) then
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        select 'member.level_changed', 'member', m.id, jsonb_build_object('reason', 'recheck_lapsed', 'from', m.trust_level, 'to', app.verified_level(m.id))
        from app.members m where m.id = s.member_id;
      update app.members m set trust_level = app.verified_level(m.id) where m.id = s.member_id;
    end if;
  end if;
  return query select m.id, m.trust_level, m.is_admin, m.display_name, s.created_at > now() - interval '10 minutes'
    from app.members m where m.id = s.member_id and m.status = 'active' and not app.deletion_overdue(m.id);
end
$$;

create or replace function app.agent_resolve(p_key_hash text)
returns table (agent_id uuid, owner_id uuid)
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query
    select a.id, m.id
    from app.agent_keys k join app.agents a on a.id = k.agent_id join app.members m on m.id = a.owner_id
    where k.key_hash = p_key_hash and k.revoked_at is null and a.status = 'active'
      and m.status = 'active' and (m.trust_level >= 2 or m.is_admin) and not app.deletion_overdue(m.id);
end
$$;
set local role dog_owner;
revoke create on schema app from dog_signin;

-- ---- Signing in: refused for a disabled account; the regional gate's confirmation (Oct 16, 2026) ----
-- Sign-up from the EU, EEA, UK and Switzerland stays declined before anything is stored. A member who lives
-- elsewhere and signs in from there confirms on a page that they live outside those regions; only then does
-- sign-in finish, and the record is only that they confirmed: when (the log's time), the country, and the member.
--   p_region: the country they confirmed from, or null. With it, sign-in never makes a new account ('region').
-- Same as 002 otherwise. Raises 'banned', 'disabled', 'taken' or 'region'.
drop function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid);
create function app.sign_in(p_provider text, p_fingerprints text[], p_key_version smallint, p_level smallint,
                            p_display_name text, p_session_hash text, p_session_days integer,
                            p_recheck_after timestamptz, p_link_member uuid, p_region text)
returns table (member_id uuid, is_new boolean, trust_level smallint, is_admin boolean)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  ident app.identities%rowtype;
  mem app.members%rowtype;
  fresh boolean := false;
begin
  if p_provider is null or not (p_provider = any (array['github', 'x', 'email', 'linkedin']))
     or p_fingerprints is null or cardinality(p_fingerprints) not between 1 and 5
     or exists (select 1 from unnest(p_fingerprints) f where f is null or f !~ '^[0-9a-f]{64}$')
     or p_key_version is null or p_key_version not between 1 and 999
     or p_level is null or p_level not between 0 and 2 or p_session_hash is null or p_session_hash !~ '^[0-9a-f]{64}$'
     or p_session_days is null or p_session_days not between 1 and 30
     or p_display_name is null or char_length(p_display_name) not between 1 and 80
     or (p_region is not null and p_region !~ '^[A-Z]{2}$') then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  if (p_link_member is null and app.actor_kind() <> 'anon')
     or (p_link_member is not null and (app.actor_kind() not in ('member', 'admin') or p_link_member is distinct from app.current_member())) then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;

  select * into ident from app.identities i where i.provider = p_provider and i.fingerprint = any (p_fingerprints)
    order by i.created_at limit 1 for update;

  if found then
    select * into mem from app.members m where m.id = ident.member_id for update;
    if p_link_member is not null and p_link_member <> mem.id then
      raise exception 'taken' using errcode = 'P0001';
    end if;
    update app.identities i set fingerprint = p_fingerprints[1], key_version = p_key_version, level = p_level,
                                verified_at = now(), recheck_after = p_recheck_after
      where i.id = ident.id;
  elsif p_link_member is not null then
    select * into mem from app.members m where m.id = p_link_member for update;
    if not found then
      raise exception 'bad sign-in request' using errcode = '22023';
    end if;
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (mem.id, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after);
  elsif p_region is not null then
    -- Nobody signs up from a declined region, whatever they confirm.
    raise exception 'region' using errcode = 'P0001';
  else
    insert into app.members (display_name, trust_level) values (p_display_name, p_level) returning * into mem;
    insert into app.identities (member_id, provider, fingerprint, key_version, level, recheck_after)
      values (mem.id, p_provider, p_fingerprints[1], p_key_version, p_level, p_recheck_after);
    fresh := true;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.joined', 'member', mem.id, jsonb_build_object('provider', p_provider, 'level', p_level));
  end if;

  if mem.status = 'banned' then
    raise exception 'banned' using errcode = 'P0001';
  end if;
  if mem.status = 'disabled' or app.deletion_overdue(mem.id) then
    raise exception 'disabled' using errcode = 'P0001';
  end if;

  if app.verified_level(mem.id) is distinct from mem.trust_level then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.level_changed', 'member', mem.id,
              jsonb_build_object('provider', p_provider, 'from', mem.trust_level, 'to', app.verified_level(mem.id)));
    update app.members m set trust_level = app.verified_level(mem.id) where m.id = mem.id;
    mem.trust_level := app.verified_level(mem.id);
  end if;

  insert into app.sessions (member_id, token_hash, expires_at)
    values (mem.id, p_session_hash, now() + make_interval(days => p_session_days));
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values (case when p_link_member is not null then 'member.identity_linked' else 'member.signed_in' end,
            'member', mem.id, jsonb_build_object('provider', p_provider));
  if p_region is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('member.region_confirmed', 'member', mem.id, jsonb_build_object('country', p_region));
  end if;

  return query select mem.id, fresh, mem.trust_level, mem.is_admin;
end
$$;

-- Whether a sign-in method already belongs to an account: asked only after the provider (or the emailed link) has
-- confirmed who the person is, so it tells nobody but the account holder whether the account exists. It decides
-- whether a sign-in from a declined region gets the confirmation page (a member) or the polite refusal (sign-up).
create function app.sign_in_known(p_provider text, p_fingerprints text[])
returns boolean
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() <> 'anon' or p_provider is null or not (p_provider = any (array['github', 'x', 'email', 'linkedin']))
     or p_fingerprints is null or cardinality(p_fingerprints) not between 1 and 5
     or exists (select 1 from unnest(p_fingerprints) f where f is null or f !~ '^[0-9a-f]{64}$') then
    raise exception 'bad sign-in request' using errcode = '22023';
  end if;
  return exists (select 1 from app.identities i where i.provider = p_provider and i.fingerprint = any (p_fingerprints));
end
$$;
revoke execute on function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid, text), app.sign_in_known(text, text[]) from public;
grant execute on function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid, text), app.sign_in_known(text, text[]) to dog_app;
grant create on schema app to dog_signin;
alter function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid, text) owner to dog_signin;
alter function app.sign_in_known(text, text[]) owner to dog_signin;
revoke create on schema app from dog_signin;

-- ---- Deleting an account (F8) also clears what JEVs kept about it ----
grant update (status) on app.members to dog_erase;
create policy jevs_decisions_erase_select on app.jevs_decisions for select to dog_erase using (true);
create policy jevs_decisions_erase_delete on app.jevs_decisions for delete to dog_erase using (true);
grant select (id, member_id, agent_id), delete on app.jevs_decisions to dog_erase;
create policy jevs_challenges_erase_select on app.jevs_challenges for select to dog_erase using (true);
create policy jevs_challenges_erase_delete on app.jevs_challenges for delete to dog_erase using (true);
grant select (id, owner_id), delete on app.jevs_challenges to dog_erase;
create policy jevs_marks_erase_select on app.jevs_marks for select to dog_erase using (true);
create policy jevs_marks_erase_delete on app.jevs_marks for delete to dog_erase using (true);
grant select (id, member_id, agent_id), delete on app.jevs_marks to dog_erase;
create policy jevs_post_domains_erase_select on app.jevs_post_domains for select to dog_erase using (true);
create policy jevs_post_domains_erase_delete on app.jevs_post_domains for delete to dog_erase using (true);
grant select (id, post_id), delete on app.jevs_post_domains to dog_erase;
create policy jevs_prints_erase_select on app.jevs_prints for select to dog_erase using (true);
create policy jevs_prints_erase_delete on app.jevs_prints for delete to dog_erase using (true);
grant select (id, author_id, post_id), delete on app.jevs_prints to dog_erase;

-- The deletion itself, for one member: everything about them, in one transaction (F8). It runs with its caller's
-- rights, and only dog_erase may call it: from app.delete_account (the member, signed in again just now) and from
-- app.deletion_review_decide (Aaron allowing a reviewed deletion). Aaron's own account is never deleted.
create function app.erase_member(p_member uuid)
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql
as $$
declare
  me uuid := p_member;
  n_posts integer; n_flags integer; n_my_reports integer; n_agents integer; n_keys integer; n_sessions integer; n_ids integer; n_brakes integer;
  n_drafts integer; n_jevs integer; n_reviews integer;
begin
  if me is null then
    raise exception 'not_active' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.member'), hashtext(me::text));
  perform 1 from app.identities i where i.member_id = me for update;
  perform 1 from app.members m where m.id = me and not m.is_admin for update;
  if not found then
    raise exception 'not_active' using errcode = '42501';
  end if;
  perform 1 from app.posts p where p.author_id = me for update;
  -- Its deletion review, then what JEVs kept about them (010): decisions, challenges, marks and text prints.
  delete from app.deletion_reviews r where r.member_id = me;
  get diagnostics n_reviews = row_count;
  delete from app.jevs_challenges c where c.owner_id = me;
  delete from app.jevs_decisions d where d.member_id = me or d.agent_id in (select a.id from app.agents a where a.owner_id = me);
  get diagnostics n_jevs = row_count;
  delete from app.jevs_marks k where k.member_id = me or k.agent_id in (select a.id from app.agents a where a.owner_id = me);
  delete from app.jevs_prints r where r.author_id = me;
  delete from app.jevs_post_domains d where d.post_id in (select p.id from app.posts p where p.author_id = me);
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
            'agents', n_agents, 'keys', n_keys, 'drafts', n_drafts, 'brakes', n_brakes, 'sessions', n_sessions, 'identities', n_ids,
            'jevs_decisions', n_jevs, 'deletion_reviews', n_reviews));
  return query select n_posts, n_my_reports, n_agents, n_keys, n_sessions, n_ids;
end
$$;
revoke execute on function app.erase_member(uuid) from public;
grant execute on function app.erase_member(uuid) to dog_erase;

grant create on schema app to dog_erase;
set local role dog_erase;
-- A member deletes their own account: signed in within the last few minutes (RK3), active, not Aaron, and not while
-- a deletion review is open or keeping the account disabled (that is Aaron's to decide).
create or replace function app.delete_account()
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
begin
  if app.actor_kind() <> 'member' or me is null then
    raise exception 'not_member' using errcode = '42501';
  end if;
  if coalesce(current_setting('app.fresh', true), '') <> '1' then
    raise exception 'fresh_sign_in' using errcode = 'P0001', hint = 'Sign in again to delete your account.';
  end if;
  if exists (select 1 from app.deletion_reviews r where r.member_id = me and (r.decision is null or r.decision = 'keep_disabled')) then
    raise exception 'under_review' using errcode = 'P0001';
  end if;
  perform 1 from app.members m where m.id = me and m.status = 'active' and not m.is_admin;
  if not found then
    raise exception 'not_active' using errcode = '42501';
  end if;
  return query select * from app.erase_member(me);
end
$$;

-- Aaron decides a deletion review: 'delete' (the account and everything about it go now), 'keep_disabled' (it stays,
-- disabled, with all its data; he can still delete or restore it later) or 'restore' (it is active again; a
-- restored account's sessions and keys stay ended, so its owner signs in and makes new keys, as after an unban).
-- Returns 'deleted', 'disabled' or 'restored'. Refusals: not_admin, not_found (P0002), stale (already so).
create function app.deletion_review_decide(p_review uuid, p_decision text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r app.deletion_reviews%rowtype;
  st text;
begin
  if app.actor_kind() <> 'admin' then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  if p_review is null or p_decision is null or p_decision not in ('delete', 'keep_disabled', 'restore') then
    raise exception 'bad deletion review request' using errcode = '22023';
  end if;
  select * into r from app.deletion_reviews x where x.id = p_review for update;
  if not found then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  if r.decision = 'restore' or r.decision = p_decision then
    raise exception 'stale' using errcode = 'P0001';
  end if;
  select m.status into st from app.members m where m.id = r.member_id for update;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('deletion_review.decided', 'member', r.member_id, jsonb_build_object('review', r.id, 'decision', p_decision,
            'was_disabled', r.disabled_at is not null));
  if p_decision = 'delete' then
    perform app.erase_member(r.member_id);
    return 'deleted';
  elsif p_decision = 'keep_disabled' then
    if st = 'active' then
      update app.members m set status = 'disabled' where m.id = r.member_id;
    end if;
    update app.deletion_reviews x set decision = 'keep_disabled', decided_at = now(), disabled_at = coalesce(x.disabled_at, now()) where x.id = r.id;
    return 'disabled';
  end if;
  if st = 'disabled' then
    update app.members m set status = 'active' where m.id = r.member_id;
  end if;
  update app.deletion_reviews x set decision = 'restore', decided_at = now() where x.id = r.id;
  return 'restored';
end
$$;

-- The 24-hour timer: every open review Aaron hasn't decided within 24 hours disables its account (sessions end,
-- sign-in is refused, agents are switched off and their keys revoked; nothing is deleted), recorded. Run by the
-- site's scheduled job (the system actor) or by Aaron. Returns how many accounts it disabled.
create function app.deletion_reviews_expire()
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  r record;
  n integer := 0;
begin
  if app.actor_kind() not in ('system', 'admin') then
    raise exception 'not_system' using errcode = '42501';
  end if;
  for r in select x.id, x.member_id from app.deletion_reviews x
           where x.decision is null and x.disabled_at is null and x.created_at <= now() - interval '24 hours'
           order by x.created_at for update skip locked loop
    update app.members m set status = 'disabled' where m.id = r.member_id and m.status = 'active' and not m.is_admin;
    update app.deletion_reviews x set disabled_at = now() where x.id = r.id;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('deletion_review.disabled', 'member', r.member_id, jsonb_build_object('review', r.id, 'after_hours', 24));
    n := n + 1;
  end loop;
  return n;
end
$$;
revoke execute on function app.deletion_review_decide(uuid, text), app.deletion_reviews_expire() from public;
grant execute on function app.deletion_review_decide(uuid, text), app.deletion_reviews_expire() to dog_app;
set local role dog_owner;
revoke create on schema app from dog_erase;

-- ---- Who may call what ----
revoke execute on function app.deletion_reviews_guard() from public;
revoke execute on function app.posts_scored() from public;
grant execute on function app.posts_scored() to dog_app;
revoke execute on function app.jevs_settings_check(), app.jevs_enforcing(), app.jevs_decisions_guard(), app.jevs_challenges_guard(),
  app.jevs_appealable(uuid), app.jevs_signals(text, uuid, text, text[], bigint), app.jevs_decide(text, uuid, jsonb, text, boolean, text[], bigint, text),
  app.jevs_answer(uuid, text), app.jevs_mark(text, text, text, uuid), app.jevs_mark_claim(text), app.region_decline(text),
  app.jevs_settings_audit(), app.jevs_sweep() from public;
grant execute on function app.jevs_appealable(uuid), app.jevs_signals(text, uuid, text, text[], bigint),
  app.jevs_decide(text, uuid, jsonb, text, boolean, text[], bigint, text), app.jevs_answer(uuid, text), app.jevs_mark(text, text, text, uuid),
  app.jevs_mark_claim(text), app.region_decline(text), app.jevs_settings_audit(), app.jevs_sweep() to dog_app;

grant create on schema app to dog_jevs;
alter function app.jevs_appealable(uuid) owner to dog_jevs;
alter function app.jevs_signals(text, uuid, text, text[], bigint) owner to dog_jevs;
alter function app.jevs_decide(text, uuid, jsonb, text, boolean, text[], bigint, text) owner to dog_jevs;
alter function app.jevs_answer(uuid, text) owner to dog_jevs;
alter function app.jevs_mark(text, text, text, uuid) owner to dog_jevs;
alter function app.jevs_mark_claim(text) owner to dog_jevs;
alter function app.region_decline(text) owner to dog_jevs;
alter function app.jevs_settings_audit() owner to dog_jevs;
alter function app.jevs_sweep() owner to dog_jevs;
alter function app.posts_scored() owner to dog_jevs;
revoke create on schema app from dog_jevs;
