-- 096 The healer (Aaron, Nov 27: "Develop a part of the system that is self security patching; the system needs to be
-- agentic and heal itself from vulnerabilities"; the same day: "We need automated patch testing to ensure the patch does
-- not break anything, and that needs to happen in real time also"; Nov 28: "You can publish the rules and the PR"). A
-- defensive loop, run by the site's timer, that learns from confirmed attacks and patches itself inside Aaron's rules:
-- checks alert and never lock anyone out, honest agents stay unblocked, code changes are his to merge, and rules change
-- by PR except exact-match data (Nov 24). Revised after the independent review of Nov 28 (findings 1 to 11).
--
--   1. Intake. Only a person's (or a deterministic check's) security confirmation becomes an incident, never a model's
--      word: a Wall block a person confirmed (any rule, sandbox runs W47 and W51 included); a post an administrator
--      removed for security; an upheld dispute or reversed check on work the Wall flagged under a blocking rule; a decoy
--      used. A later false-positive verdict, an undo or a cleared appeal retracts it. Invariant breaks (no points without
--      a recorded pass; no pass without a Wall decision; every JEVs decision has its public-log entry) are alerts only:
--      no member, no fingerprint, no tightening. Every step is on the healer's own hash chain (app.heal_log).
--   2. Fingerprints, of the offending span only: the sentences that trip one of the Wall's blocking text rules (or, for a
--      person's security removal with none, the whole text, capped), the URLs, hosts and file hashes. Never a host on a
--      trusted account's content or the site's own domains. Matching uses equality and fixed patterns; no pattern is
--      ever built from data.
--   3. The patch gate, in the database and in real time, before anything takes effect: (a) the golden set and 30 days of
--      settled honest content: a hit holds it; (b) the attack's span and its variants must be refused; (c) shape and
--      cost: not too short or generic, at most 0.1% of the last 7 days, nothing a trusted account wrote.
--   4. Canary: 30 minutes in shadow (would-be hits logged), then enforced (W52 in the Wall, and a post gate) for 90 days,
--      extended only by a new confirmed incident. Rolled back, with everything it swept restored, on hits from 3 or more
--      unrelated trusted accounts, 2 or more unrelated honest upheld appeals, or a spike of refusals or appeals from
--      unrelated accounts at least 7 days old. A new confirmed incident re-arms a rolled-back one.
--   5. Sweep-back of what it matches (posts to waiting, passed work's pending points held, waiting work returned),
--      nothing deleted, appealable: a trusted account's appeal is upheld; anyone else's goes to Second Look, and to an
--      administrator only if Second Look doesn't clear it. An upheld appeal also exempts that account.
--   6. Tightening of one owner tree, network or rule area after 3 incidents in 24 hours, simulated first, ending by itself.
-- An administrator can pause and resume the healer, release a held fingerprint and roll one back, each on the chain.
-- The healer's functions belong to dog_heal (no sign-in), which the site's role can't act as.

reset role;
do $heal_role$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_heal') then
    create role dog_heal nologin noinherit nobypassrls;
  end if;
end
$heal_role$;
grant dog_heal to dog_owner;
-- Who is acting (019), for the healer's own checks of its callers.
set local role dog_signin;
grant execute on function app.stamp_ok() to dog_heal;
reset role;

alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W52', 'block', 'Matches a fingerprint taken from a confirmed attack');
alter table app.wall_rules enable row level security;

set local role dog_owner;
grant usage on schema app to dog_heal;
grant execute on function app.uuid_v7(), app.actor_kind(), app.current_member(), app.current_agent(), app.current_actor_id(), app.is_reviewer() to dog_heal;
grant execute on function app.wall_url_norm(text), app.wiki_never_block(text), app.wiki_public_suffix(text), app.wall_text_flags(text),
  app.wall_metadata_address(text), app.wall_spam_level(text) to dog_heal;
grant execute on function app.notify(uuid, text, text, text, text, text, uuid, text) to dog_heal;

-- 3: an administrator's removal for security is its own reason, so it can be told apart from quality or the terms.
do $heal_reason$
declare c record;
begin
  for c in select conname from pg_constraint where conrelid = 'app.review_decisions'::regclass and contype = 'c'
            and pg_get_constraintdef(oid) like '%private_info%' loop
    execute format('alter table app.review_decisions drop constraint %I', c.conname);
  end loop;
end
$heal_reason$;
alter table app.review_decisions add constraint review_decisions_reason_check check (reason = any (array['ordinary', 'checked', 'not_upheld', 'spam', 'abuse',
  'private_info', 'illegal', 'security', 'mistake', 'undo', 'other']));
alter table app.review_decisions add constraint review_decisions_reason_fits check (reason = 'other'
  or (decision = 'approve' and reason = any (array['ordinary', 'checked']))
  or (decision = 'keep' and reason = any (array['not_upheld', 'ordinary', 'checked']))
  or (decision = 'remove' and reason = any (array['spam', 'abuse', 'private_info', 'illegal', 'security']))
  or (decision = 'restore' and reason = any (array['mistake', 'undo'])));
-- An appeal goes to Second Look first.
alter table app.sl_items drop constraint sl_items_kind_check;
alter table app.sl_items add constraint sl_items_kind_check check (kind = any (array['task', 'submission', 'dispute', 'evidence', 'heal_appeal']));

-- ---- Settings and the chain ----
create table app.heal_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null unique default true check (singleton),
  since timestamptz not null default now(),          -- the invariants are watched from here on
  paused boolean not null default false,
  paused_reason text check (char_length(paused_reason) <= 300),
  last_run_at timestamptz,
  last_ok_at timestamptz,
  corpus_at timestamptz,
  base_posts_per_hour integer not null default 20 check (base_posts_per_hour between 1 and 10000),
  max_honest_in_scope integer not null default 3 check (max_honest_in_scope between 0 and 1000),
  incident_budget_ms integer not null default 10000 check (incident_budget_ms between 0 and 60000)
);
insert into app.heal_settings default values;

create table app.heal_log (
  id uuid primary key default app.uuid_v7(),
  kind text not null check (kind = any (array['incident', 'retract', 'failed', 'refused', 'held', 'shadow', 'active', 'rollback', 'expired',
                                                'sweep', 'restore', 'tighten', 'tighten_refused', 'tighten_end', 'appeal', 'exempt',
                                                'pause', 'resume', 'release'])),
  ref uuid,
  detail jsonb not null default '{}'::jsonb check (jsonb_typeof(detail) = 'object' and octet_length(detail::text) <= 4000),
  prev_hash text not null unique check (char_length(prev_hash) = 64 and prev_hash ~ '^[0-9a-f]+$'),
  hash text not null unique check (char_length(hash) = 64 and hash ~ '^[0-9a-f]+$'),
  created_at timestamptz not null default now()
);

create table app.heal_incidents (
  id uuid primary key default app.uuid_v7(),
  source text not null check (source = any (array['wall_confirmed', 'post_removed', 'dispute_upheld', 'check_reversed', 'decoy', 'invariant'])),
  source_key text not null unique check (char_length(source_key) <= 120),
  ref_kind text check (ref_kind = any (array['post', 'submission', 'task', 'decision', 'points', 'jevs'])),
  ref uuid,
  member_id uuid references app.members (id) on delete set null,
  owner_id uuid references app.members (id) on delete set null,
  agent_id uuid references app.agents (id) on delete set null,
  net text check (char_length(net) = 64 and net ~ '^[0-9a-f]+$'),
  rule_area text not null check (char_length(rule_area) between 1 and 40),
  -- The offending spans: [{kind, value, label}], label a folded or defanged form for reviewers. Never the whole text.
  spans jsonb not null default '[]'::jsonb check (jsonb_typeof(spans) = 'array' and octet_length(spans::text) <= 8000),
  processed text not null default 'new' check (processed = any (array['new', 'done', 'failed', 'retracted'])),
  attempts smallint not null default 0 check (attempts between 0 and 100),
  tried_at timestamptz,
  retracted_at timestamptz,
  created_at timestamptz not null default now()
);
create index heal_incidents_at on app.heal_incidents (created_at desc);
create index heal_incidents_queue on app.heal_incidents (created_at) where processed = 'new';

create table app.heal_fingerprints (
  id uuid primary key default app.uuid_v7(),
  code text not null unique check (char_length(code) = 11 and code ~ '^HF-[0-9a-f]{8}$'),
  kind text not null check (kind = any (array['text', 'host', 'url', 'sha256'])),
  value text not null check (char_length(value) between 1 and 500),
  label text not null default '' check (char_length(label) <= 300),
  incident_id uuid references app.heal_incidents (id) on delete set null,
  status text not null check (status = any (array['refused', 'held', 'shadow', 'active', 'rolled_back', 'retracted', 'expired'])),
  reason text check (char_length(reason) <= 300),
  gate_ms integer check (gate_ms between 0 and 600000),
  created_at timestamptz not null default now(),
  shadow_at timestamptz,
  activated_at timestamptz,
  expires_at timestamptz,
  ended_at timestamptz,
  exported_at timestamptz,
  unique (kind, value)
);
create index heal_fingerprints_live on app.heal_fingerprints (status) where status in ('active', 'shadow');

-- Content the corpus checks read, normalized once: posts, work and tasks of the last 30 days, and their hosts, URLs and
-- file hashes as tokens (host suffixes too), so those checks are lookups.
create table app.heal_corpus (
  id uuid primary key default app.uuid_v7(),
  kind text not null check (kind = any (array['post', 'submission', 'task'])),
  ref uuid not null,
  member_id uuid references app.members (id) on delete cascade,
  agent_id uuid,
  low text not null check (char_length(low) <= 6000),
  norm text not null check (char_length(norm) <= 6000),
  created_at timestamptz not null,
  unique (kind, ref)
);
create index heal_corpus_at on app.heal_corpus (created_at);
create index heal_corpus_member on app.heal_corpus (member_id);
create table app.heal_corpus_tokens (
  id uuid primary key default app.uuid_v7(),
  corpus_id uuid not null references app.heal_corpus (id) on delete cascade,
  kind text not null check (kind = any (array['host', 'url', 'sha256'])),
  value text not null check (char_length(value) between 1 and 500)
);
create index heal_corpus_tokens_value on app.heal_corpus_tokens (kind, value);
create index heal_corpus_tokens_corpus on app.heal_corpus_tokens (corpus_id);

-- Honest lines no patch may refuse (seeded from heal/golden.json; changed by PR).
create table app.heal_golden (
  id uuid primary key default app.uuid_v7(),
  line text not null unique check (char_length(line) between 1 and 500)
);

create table app.heal_shadow_hits (
  id uuid primary key default app.uuid_v7(),
  fingerprint_id uuid not null references app.heal_fingerprints (id) on delete cascade,
  kind text not null check (kind = any (array['post', 'submission', 'task'])),
  ref uuid not null,
  member_id uuid references app.members (id) on delete set null,
  created_at timestamptz not null default now(),
  unique (fingerprint_id, kind, ref)
);

create table app.heal_refusals (
  id uuid primary key default app.uuid_v7(),
  fingerprint_id uuid not null references app.heal_fingerprints (id) on delete cascade,
  kind text not null check (kind = any (array['post', 'submission', 'task'])),
  member_id uuid references app.members (id) on delete set null,
  agent_id uuid,
  created_at timestamptz not null default now()
);
create index heal_refusals_fp on app.heal_refusals (fingerprint_id, created_at);

create table app.heal_sweeps (
  id uuid primary key default app.uuid_v7(),
  fingerprint_id uuid not null references app.heal_fingerprints (id) on delete cascade,
  kind text not null check (kind = any (array['post', 'submission'])),
  ref uuid not null,
  member_id uuid references app.members (id) on delete set null,
  agent_id uuid,
  prior_status text not null check (prior_status = any (array['live', 'waiting', 'review', 'passed'])),
  prior_final_at timestamptz,
  status text not null default 'swept' check (status = any (array['swept', 'restored'])),
  created_at timestamptz not null default now(),
  restored_at timestamptz,
  unique (fingerprint_id, kind, ref)
);

create table app.heal_appeals (
  id uuid primary key default app.uuid_v7(),
  fingerprint_id uuid not null references app.heal_fingerprints (id) on delete cascade,
  member_id uuid not null references app.members (id) on delete cascade,
  agent_id uuid,
  reason text not null check (char_length(reason) between 3 and 500),
  status text not null default 'open' check (status = any (array['open', 'second_look', 'review', 'upheld', 'kept'])),
  decided_by text check (decided_by = any (array['trusted', 'second_look', 'reviewer', 'rollback'])),
  created_at timestamptz not null default now(),
  decided_at timestamptz,
  unique (fingerprint_id, member_id)
);

-- An account an upheld appeal exempted from one fingerprint.
create table app.heal_exemptions (
  id uuid primary key default app.uuid_v7(),
  fingerprint_id uuid not null references app.heal_fingerprints (id) on delete cascade,
  member_id uuid not null references app.members (id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (fingerprint_id, member_id)
);

create table app.heal_tightenings (
  id uuid primary key default app.uuid_v7(),
  scope_kind text not null check (scope_kind = any (array['owner_tree', 'network', 'rule_area'])),
  scope_value text not null check (char_length(scope_value) between 1 and 64),
  status text not null check (status = any (array['active', 'refused', 'ended'])),
  incidents integer not null check (incidents between 0 and 100000),
  affected integer not null default 0 check (affected between 0 and 1000000),
  honest integer not null default 0 check (honest between 0 and 1000000),
  reason text check (char_length(reason) <= 300),
  starts_at timestamptz not null default now(),
  confirmed_at timestamptz not null default now(),
  expires_at timestamptz not null,
  ended_at timestamptz
);
create unique index heal_tightenings_one on app.heal_tightenings (scope_kind, scope_value) where status = 'active';

-- Decoys: values no honest person or agent is ever given, made here by the database (they are in no file). Any use is
-- an incident and an alert.
create table app.heal_decoys (
  id uuid primary key default app.uuid_v7(),
  kind text not null check (kind = any (array['credential', 'record'])),
  pattern text not null unique check (char_length(pattern) between 16 and 200 and pattern = lower(pattern)),
  note text not null check (char_length(note) <= 200)
);
insert into app.heal_decoys (kind, pattern, note) values
  ('credential', 'dogk_live_' || replace(gen_random_uuid()::text, '-', ''), 'A decoy agent key: never issued to anyone'),
  ('record', 'dog-decoy-' || left(replace(gen_random_uuid()::text, '-', ''), 24), 'A decoy record name: never shown to anyone');

do $heal_tables$
declare t text;
begin
  foreach t in array array['heal_settings', 'heal_log', 'heal_incidents', 'heal_fingerprints', 'heal_corpus', 'heal_corpus_tokens', 'heal_golden',
                           'heal_shadow_hits', 'heal_refusals', 'heal_sweeps', 'heal_appeals', 'heal_exemptions', 'heal_tightenings', 'heal_decoys'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('alter table app.%I force row level security', t);
    execute format('create policy %I on app.%I for all to dog_heal using (true) with check (true)', t || '_heal', t);
  end loop;
end
$heal_tables$;
grant select, insert, update on app.heal_settings, app.heal_incidents, app.heal_fingerprints, app.heal_shadow_hits, app.heal_refusals,
  app.heal_sweeps, app.heal_appeals, app.heal_tightenings to dog_heal;
grant select, insert on app.heal_log, app.heal_exemptions to dog_heal;
grant select, insert, delete on app.heal_corpus, app.heal_corpus_tokens to dog_heal;
grant delete on app.heal_refusals, app.heal_shadow_hits, app.heal_sweeps, app.heal_appeals to dog_heal;
grant select on app.heal_golden, app.heal_decoys to dog_heal;
-- The chain is append-only, for every role.
create function app.heal_log_append_only() returns trigger language plpgsql set search_path = pg_catalog as $$
begin raise exception 'the healer''s log is append-only' using errcode = '42501'; end $$;
create trigger heal_log_no_change before update or delete on app.heal_log for each row execute function app.heal_log_append_only();
create trigger heal_log_no_truncate before truncate on app.heal_log for each statement execute function app.heal_log_append_only();
alter table app.heal_log enable always trigger heal_log_no_change;
alter table app.heal_log enable always trigger heal_log_no_truncate;
-- 10: an incident's spans go with the account it was about (the delete sets its member to null).
create function app.heal_incident_forget() returns trigger language plpgsql set search_path = pg_catalog as $$
begin
  if (old.member_id is not null and new.member_id is null) or (old.owner_id is not null and new.owner_id is null) then
    new.spans := '[]'::jsonb;
  end if;
  return new;
end $$;
create trigger heal_incident_forget before update on app.heal_incidents for each row execute function app.heal_incident_forget();

-- ---- What the healer reads and the few moves it makes elsewhere ----
create policy posts_heal on app.posts for all to dog_heal using (true) with check (true);
grant select (id, author_id, agent_id, body, status, created_at, published_at) on app.posts to dog_heal;
grant update (status) on app.posts to dog_heal;
create policy review_flags_heal on app.review_flags for all to dog_heal using (true) with check (source = 'classifier' and classifier = 'heal');
grant select on app.review_flags to dog_heal;
grant insert (post_id, source, classifier, score) on app.review_flags to dog_heal;
grant update (resolved_at, resolved_by, decision) on app.review_flags to dog_heal;
create policy work_submissions_heal on app.work_submissions for all to dog_heal using (true) with check (true);
grant select on app.work_submissions to dog_heal;
grant update (status, decided_by, decided_at, reason) on app.work_submissions to dog_heal;
create policy work_points_heal on app.work_points for all to dog_heal using (true) with check (true);
grant select on app.work_points to dog_heal;
grant update (final_at) on app.work_points to dog_heal;
-- The ledger's trigger (048) runs on every update of a points row; for a change of final_at alone it adds nothing. The
-- healer may run it but can never add a row: its policy admits none.
create policy work_point_entries_heal on app.work_point_entries for insert to dog_heal with check (false);
grant insert on app.work_point_entries to dog_heal;
create policy notices_heal_insert on app.notices for insert to dog_heal with check (true);
grant insert (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key) on app.notices to dog_heal;
-- Second Look reads appeals the way it reads work (070): the healer adds them and reads the answers.
create policy sl_items_heal on app.sl_items for all to dog_heal using (kind = 'heal_appeal') with check (kind = 'heal_appeal');
grant select, insert on app.sl_items to dog_heal;
do $heal_reads$
declare t text;
begin
  foreach t in array array['wall_decisions', 'wall_appeals', 'wall_reviews', 'wall_rules', 'work_disputes', 'work_checks', 'work_tasks', 'members', 'agents',
                           'jevs_decisions', 'jevs_marks', 'log_queue', 'log_openings', 'brakes', 'review_decisions'] loop
    execute format('create policy %I on app.%I for select to dog_heal using (true)', t || '_heal_select', t);
    execute format('grant select on app.%I to dog_heal', t);
  end loop;
end
$heal_reads$;

-- ---- Normalizing (the Wall's own folding, 082 and 087, with Unicode compatibility forms and more look-alikes) ----
-- The folded text keeps spaces (for hosts and URLs); the normalized text keeps only letters and digits.
create function app.heal_fold(p text) returns text
language plpgsql immutable set search_path = pg_catalog as $$
declare t text := coalesce(p, '');
begin
  t := left(t, 6000);
  begin t := normalize(t, NFKC); exception when others then null; end;
  t := lower(t);
  t := translate(t, 'оаесрхіѕукмтнвјԁοαερικντυχ', 'oaecpxisykmthbjdoaepikvtux');
  t := regexp_replace(t, '[­​-‏‪-‮⁠-⁤⁦-⁩﻿᠎︀-️̀-ͯ\U000E0000-\U000E007F]', '', 'g');
  t := replace(replace(replace(replace(replace(t, '&#8203;', ''), '&#x200b;', ''), '&amp;', '&'), '&nbsp;', ' '), 'hxxp', 'http');
  t := replace(replace(replace(t, '[.]', '.'), '(.)', '.'), '[:]', ':');
  return regexp_replace(t, '[[:space:]]+', ' ', 'g');
end $$;
create function app.heal_norm(p text) returns text
language sql immutable set search_path = pg_catalog as $$ select regexp_replace(app.heal_fold(p), '[^a-z0-9]+', '', 'g') $$;
-- 2: a host is only ever a valid name (letters, digits, hyphens, at least two labels), checked with a fixed pattern.
create function app.heal_valid_host(p text) returns boolean
language sql immutable set search_path = pg_catalog as $$
  select p is not null and char_length(p) between 4 and 253 and p ~ '^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$'
$$;
-- The URLs, hosts (with their parent domains) and SHA-256s in a folded text, each by a fixed pattern.
create function app.heal_urls(p_low text) returns text[]
language sql immutable set search_path = pg_catalog as $$
  select coalesce(array_agg(distinct u) filter (where u is not null and char_length(u) between 8 and 500), '{}') from (
    select app.wall_url_norm(rtrim(m[1], '.,;:)]''"')) as u from regexp_matches(coalesce(p_low, ''), '(https?://[^[:space:]"''<>`]+)', 'g') m limit 50) x
$$;
create function app.heal_hosts(p_low text) returns text[]
language sql immutable set search_path = pg_catalog as $$
  with h as (
    select distinct lower(x) as h from (
      select substring(u from '^https?://(?:[^@/]*@)?([^/:?#]+)') as x from unnest(app.heal_urls(p_low)) u
      union all
      select (regexp_matches(coalesce(p_low, ''), '\m([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\.[a-z][a-z0-9-]{1,23})\M', 'g'))[1]) y
    where app.heal_valid_host(x) limit 50)
  select coalesce(array_agg(distinct array_to_string(p[k:], '.')), '{}')
    from (select string_to_array(h, '.') as p from h) z, generate_subscripts(z.p, 1) k where cardinality(p) - k >= 1
$$;
create function app.heal_shas(p_low text) returns text[]
language sql immutable set search_path = pg_catalog as $$
  select coalesce(array_agg(distinct m[1]), '{}') from regexp_matches(coalesce(p_low, ''), '\m([0-9a-f]{64})\M', 'g') m
$$;
-- Whether one fingerprint matches one text: text by substring of the normalized form, the rest by equality.
create function app.heal_hit(p_kind text, p_value text, p_norm text, p_urls text[], p_hosts text[], p_shas text[]) returns boolean
language sql immutable set search_path = pg_catalog as $$
  select case p_kind
    when 'text' then strpos(p_norm, p_value) > 0
    when 'url' then p_value = any (p_urls)
    when 'host' then p_value = any (p_hosts)
    when 'sha256' then p_value = any (p_shas)
    else false end
$$;
-- A label for reviewers and proposals: folded, punctuation dropped, links defanged.
create function app.heal_label(p_kind text, p_value text) returns text
language sql immutable set search_path = pg_catalog as $$
  select left(case when p_kind in ('url', 'host') then replace(replace(regexp_replace(p_value, '[^a-z0-9:/._-]+', '', 'g'), 'http', 'hxxp'), '.', '[.]')
              else btrim(regexp_replace(p_value, '[^a-z0-9 ]+', ' ', 'g')) end, 300)
$$;
-- The first rule a decision named (W07b, W47 ...), for the rule area.
create function app.heal_rule_of(p_flags jsonb) returns text
language sql immutable set search_path = pg_catalog as $$
  select (select split_part(g #>> '{}', ' ', 1) from jsonb_array_elements(coalesce(p_flags, '[]'::jsonb)) g order by 1 limit 1)
$$;
-- The site's own domains are never fingerprinted.
create function app.heal_own_domain(p_host text) returns boolean
language sql immutable set search_path = pg_catalog as $$
  select p_host = any (array['dayonegreat.com', 'dayonegreat.ai', 'chiefos.cloud', 'github.com', 'githubusercontent.com', 'vercel.app', 'supabase.co'])
      or right(p_host, 16) = '.dayonegreat.com' or right(p_host, 15) = '.dayonegreat.ai' or right(p_host, 14) = '.chiefos.cloud'
$$;

revoke execute on function app.heal_fold(text), app.heal_norm(text), app.heal_valid_host(text), app.heal_urls(text), app.heal_hosts(text), app.heal_shas(text),
  app.heal_hit(text, text, text, text[], text[], text[]), app.heal_label(text, text), app.heal_rule_of(jsonb), app.heal_own_domain(text), app.heal_incident_forget() from public;
grant execute on function app.heal_fold(text), app.heal_norm(text), app.heal_valid_host(text), app.heal_urls(text), app.heal_hosts(text), app.heal_shas(text),
  app.heal_hit(text, text, text, text[], text[], text[]), app.heal_label(text, text), app.heal_rule_of(jsonb), app.heal_own_domain(text) to dog_heal;
reset role;

-- ================= The healer's functions (owned by dog_heal) =================
grant create on schema app to dog_heal;
set local role dog_heal;

create function app.heal_log_add(p_kind text, p_ref uuid, p_detail jsonb) returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare prev text; h text; d jsonb := coalesce(p_detail, '{}'::jsonb);
begin
  perform pg_advisory_xact_lock(7309601);
  select l.hash into prev from app.heal_log l where not exists (select 1 from app.heal_log y where y.prev_hash = l.hash);
  prev := coalesce(prev, repeat('0', 64));
  h := encode(sha256(convert_to(prev || '|' || p_kind || '|' || coalesce(p_ref::text, '') || '|' || d::text, 'UTF8')), 'hex');
  insert into app.heal_log (kind, ref, detail, prev_hash, hash) values (p_kind, p_ref, d, prev, h);
end $$;

-- A trusted account: an administrator, or level 2 and active for 30 days, with no standing incident.
create function app.heal_trusted(p_member uuid) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce((select m.is_admin or (m.trust_level >= 2 and m.status = 'active' and m.created_at < now() - interval '30 days'
                          and not exists (select 1 from app.heal_incidents i where p_member in (i.member_id, i.owner_id) and i.processed <> 'retracted'))
                   from app.members m where m.id = p_member), false)
$$;

-- Which accounts a tightening's scope covers. The same function decides the simulation and the enforcement.
create function app.heal_scope_members(p_kind text, p_value text) returns setof uuid
language sql stable security definer set search_path = pg_catalog as $$
  select m.id from app.members m where p_kind = 'owner_tree' and p_value ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' and m.id = p_value::uuid
  union
  select coalesce(m.member_id, g.owner_id) from app.jevs_marks m left join app.agents g on g.id = m.agent_id
   where p_kind = 'network' and m.kind = 'net' and m.key_hash = p_value and m.created_at > now() - interval '1 day'
     and coalesce(m.member_id, g.owner_id) is not null
  union
  select i.owner_id from app.heal_incidents i where p_kind = 'rule_area' and i.rule_area = p_value and i.processed <> 'retracted'
     and i.created_at > now() - interval '24 hours' and i.owner_id is not null
$$;
-- 5: accounts linked to a fingerprint's attack: the incident's accounts, its network, and the accounts of incidents in
-- the same rule area in the last 7 days. Their hits, refusals and appeals never count toward a rollback.
create function app.heal_related(p_fp uuid) returns setof uuid
language sql stable security definer set search_path = pg_catalog as $$
  with i as (select x.* from app.heal_incidents x join app.heal_fingerprints f on f.incident_id = x.id where f.id = p_fp)
  select i.member_id from i where i.member_id is not null
  union select i.owner_id from i where i.owner_id is not null
  union select app.heal_scope_members('network', i.net) from i where i.net is not null
  union select y.owner_id from app.heal_incidents y, i where y.rule_area = i.rule_area and y.created_at > now() - interval '7 days' and y.owner_id is not null
  union select y.member_id from app.heal_incidents y, i where y.rule_area = i.rule_area and y.created_at > now() - interval '7 days' and y.member_id is not null
$$;
-- An account whose hit or appeal can count: unrelated to the attack and at least 7 days old.
-- Whether this account's settled content, older than the incident's own content, was swept by this fingerprint.
create function app.heal_settled_earlier(p_fp uuid, p_member uuid) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from app.heal_sweeps s join app.heal_corpus c on c.kind = s.kind and c.ref = s.ref
                  join app.heal_fingerprints f on f.id = s.fingerprint_id
                  left join app.heal_incidents i on i.id = f.incident_id
                 where s.fingerprint_id = p_fp and s.member_id = p_member and s.prior_status in ('live', 'passed')
                   and c.created_at < least(f.created_at, coalesce((select y.created_at from app.heal_corpus y where y.ref = i.ref limit 1), f.created_at)))
$$;
create function app.heal_counts(p_fp uuid, p_member uuid) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  -- Second and third reviews: only an account whose own settled content (live or passed when it was swept), written
  -- before the incident's own content, was swept by this fingerprint; unrelated to the attack and at least 7 days old.
  -- A refusal alone, or work parked waiting, never counts.
  select p_member is not null and exists (select 1 from app.members m where m.id = p_member and m.created_at < now() - interval '7 days')
     and p_member not in (select r from app.heal_related(p_fp) r where r is not null)
     and app.heal_settled_earlier(p_fp, p_member)
$$;
create function app.heal_member_tightened(p_member uuid) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select p_member is not null and not coalesce((select m.is_admin from app.members m where m.id = p_member), false)
     and not coalesce((select s.paused from app.heal_settings s), false)
     and exists (select 1 from app.heal_tightenings t where t.status = 'active' and t.expires_at > now()
                  and p_member in (select app.heal_scope_members(t.scope_kind, t.scope_value)))
$$;
create function app.heal_member_cap(p_member uuid, p_brake integer) returns integer
language sql stable security definer set search_path = pg_catalog as $$
  select case when app.heal_member_tightened(p_member)
    then greatest(1, least(coalesce(p_brake, s.base_posts_per_hour), s.base_posts_per_hour) / 2) end from app.heal_settings s
$$;

-- The Wall's reader: the enforced fingerprints a text matches, as Wall flags (W52), except for an account an upheld
-- appeal exempted. Off while the healer is paused.
create function app.heal_flags(p_text text) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare low text; n text; u text[]; h text[]; sh text[]; f jsonb := '[]'::jsonb; r record; me uuid := app.current_member();
begin
  if coalesce(p_text, '') = '' or (select s.paused from app.heal_settings s)
     or not exists (select 1 from app.heal_fingerprints x where x.status = 'active') then return f; end if;
  low := app.heal_fold(p_text);
  n := regexp_replace(low, '[^a-z0-9]+', '', 'g');
  u := app.heal_urls(low); h := app.heal_hosts(low); sh := app.heal_shas(low);
  for r in select x.code from app.heal_fingerprints x where x.status = 'active' and app.heal_hit(x.kind, x.value, n, u, h, sh)
             and not exists (select 1 from app.heal_exemptions e where e.fingerprint_id = x.id and e.member_id = me)
           order by x.code limit 5 loop
    f := f || jsonb_build_array('W52 healer fingerprint ' || r.code || ' (from a confirmed attack; appeal: POST /api/work/heal/appeal)');
  end loop;
  return f;
end $$;

-- 4: the offending spans of a text. Sentences that trip one of the Wall's blocking text rules; with none and p_whole (a
-- person confirmed the whole item as an attack), the whole text, capped. Then its URLs, their hosts and file hashes.
create function app.heal_spans(p_text text, p_whole boolean) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare low text := app.heal_fold(p_text); out jsonb := '[]'::jsonb; sent text; v text; blocks text[]; got boolean := false; x text;
begin
  select array_agg(w.rule) into blocks from app.wall_rules w where w.effect = 'block';
  for sent in select s from regexp_split_to_table(left(low, 6000), '[.!?;\n]+ ') s limit 60 loop
    if exists (select 1 from jsonb_array_elements_text(app.wall_text_flags(sent)) g where split_part(g, ' ', 1) = any (blocks)) then
      v := left(regexp_replace(sent, '[^a-z0-9]+', '', 'g'), 200);
      if char_length(v) >= 24 then out := out || jsonb_build_array(jsonb_build_object('kind', 'text', 'value', v)); got := true; end if;
    end if;
  end loop;
  if not got and p_whole then
    v := left(regexp_replace(regexp_replace(low, 'https?://[^[:space:]]+', ' ', 'g'), '[^a-z0-9]+', '', 'g'), 200);
    if char_length(v) >= 24 then out := out || jsonb_build_array(jsonb_build_object('kind', 'text', 'value', v)); end if;
  end if;
  foreach x in array app.heal_urls(low) loop out := out || jsonb_build_array(jsonb_build_object('kind', 'url', 'value', x)); end loop;
  foreach x in array (select coalesce(array_agg(distinct substring(u from '^https?://(?:[^@/]*@)?([^/:?#]+)')), '{}') from unnest(app.heal_urls(low)) u) loop
    if app.heal_valid_host(x) then out := out || jsonb_build_array(jsonb_build_object('kind', 'host', 'value', x)); end if;
  end loop;
  foreach x in array app.heal_shas(low) loop out := out || jsonb_build_array(jsonb_build_object('kind', 'sha256', 'value', x)); end loop;
  return coalesce((select jsonb_agg(jsonb_build_object('kind', e ->> 'kind', 'value', e ->> 'value', 'label', app.heal_label(e ->> 'kind', e ->> 'value')))
                   from (select distinct on (e ->> 'kind', e ->> 'value') e from jsonb_array_elements(out) e limit 12) z), '[]'::jsonb);
end $$;

-- An incident, chained. Returns its id (null when its key was seen before).
create function app.heal_incident(p_source text, p_key text, p_ref_kind text, p_ref uuid, p_member uuid, p_agent uuid, p_rule text, p_spans jsonb, p_processed text default 'new')
returns uuid
language plpgsql security definer set search_path = pg_catalog as $$
declare iid uuid; own uuid; nt text;
begin
  own := coalesce((select g.owner_id from app.agents g where g.id = p_agent), p_member);
  select m.key_hash into nt from app.jevs_marks m
   where m.kind = 'net' and ((p_agent is not null and m.agent_id = p_agent) or (p_member is not null and m.member_id = p_member))
   order by m.created_at desc limit 1;
  insert into app.heal_incidents (source, source_key, ref_kind, ref, member_id, owner_id, agent_id, net, rule_area, spans, processed)
    values (p_source, left(p_key, 120), p_ref_kind, p_ref,
            (select id from app.members where id = p_member), (select id from app.members where id = own), (select id from app.agents where id = p_agent), nt,
            left(coalesce(nullif(p_rule, ''), p_source), 40), coalesce(p_spans, '[]'::jsonb), p_processed)
    on conflict (source_key) do nothing returning id into iid;
  if iid is not null then
    perform app.heal_log_add('incident', iid, jsonb_build_object('source', p_source, 'rule', left(coalesce(nullif(p_rule, ''), p_source), 40)));
  end if;
  return iid;
end $$;

create function app.heal_decision_text(p_kind text, p_ref uuid) returns text
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce(case p_kind
    when 'submission' then (select coalesce(s.note, '') || ' ' || coalesce(s.artifact_url, '') || ' ' || coalesce(s.artifact_sha256, '') from app.work_submissions s where s.id = p_ref)
    when 'task' then (select coalesce(t.title, '') || ' ' || coalesce(t.description, '') from app.work_tasks t where t.id = p_ref)
    else '' end, '')
$$;

-- 1, 3. Intake: confirmed incidents since they were last read.
create function app.heal_intake() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare r record; n integer := 0; since timestamptz := now() - interval '30 days'; blocks text[];
begin
  select array_agg(w.rule) into blocks from app.wall_rules w where w.effect = 'block';
  -- A Wall block a person confirmed (never a recheck alone): its rule, its offending spans.
  for r in select d.*, w.id as wid from app.wall_reviews w join app.wall_decisions d on d.id = w.decision_id
            where w.verdict = 'confirmed' and w.reviewed_by is not null and w.created_at > since
              and not exists (select 1 from app.heal_incidents h where h.source_key = 'review:' || w.id) loop
    if app.heal_incident('wall_confirmed', 'review:' || r.wid, case when r.kind in ('submission', 'task') then r.kind else 'decision' end, r.ref, r.member_id, r.agent_id,
                         app.heal_rule_of(r.flags), app.heal_spans(app.heal_decision_text(r.kind, r.ref) || ' ' || coalesce((select string_agg(g, ' ') from jsonb_array_elements_text(r.flags) g where split_part(g, ' ', 1) in ('W28', 'W33')), ''), true)) is not null then n := n + 1; end if;
  end loop;
  -- A post an administrator removed for security (its latest decision, the post still removed).
  for r in select d.id as did, p.id, p.author_id, p.agent_id, p.body from app.review_decisions d join app.posts p on p.id = d.post_id
            where d.decision = 'remove' and d.reason = 'security' and d.created_at > since and p.status = 'removed'
              and not exists (select 1 from app.review_decisions y where y.post_id = d.post_id and y.created_at > d.created_at)
              and exists (select 1 from app.members m where m.id = d.decided_by and m.is_admin)
              and not exists (select 1 from app.heal_incidents h where h.source_key = 'review:' || d.id) loop
    if app.heal_incident('post_removed', 'review:' || r.did, 'post', r.id, r.author_id, r.agent_id, 'post', app.heal_spans(r.body, true)) is not null then n := n + 1; end if;
  end loop;
  -- An upheld dispute or a reversed check, only on work the Wall flagged under a blocking rule (a security finding).
  for r in select 'dispute:' || d.id as k, 'dispute_upheld' as src, s.* from app.work_disputes d join app.work_submissions s on s.id = d.submission_id
            where d.status = 'upheld' and d.decided_at > since and not exists (select 1 from app.heal_incidents h where h.source_key = 'dispute:' || d.id)
           union all
           select 'check:' || c.id, 'check_reversed', s.* from app.work_checks c join app.work_submissions s on s.id = c.submission_id
            where c.status = 'reversed' and c.decided_at > since and s.status = 'reversed' and c.reason not like 'The pass was reversed (dispute)%'
              and not exists (select 1 from app.heal_incidents h where h.source_key = 'check:' || c.id) loop
    continue when not exists (select 1 from app.wall_decisions w, jsonb_array_elements_text(w.flags) g
                               where w.ref in (r.id, r.task_id) and split_part(g, ' ', 1) = any (blocks) and split_part(g, ' ', 1) <> 'W52');
    if app.heal_incident(r.src, r.k, 'submission', r.id, r.worker_member, r.worker_agent, r.src,
                         app.heal_spans(coalesce(r.note, '') || ' ' || coalesce(r.artifact_url, '') || ' ' || coalesce(r.artifact_sha256, ''), false)) is not null then n := n + 1; end if;
  end loop;
  -- A decoy used anywhere in what people and agents sent: an incident and an alert at once (no fingerprint: the decoy
  -- itself is the tell).
  for r in select c.*, d.kind as dkind from app.heal_corpus c join app.heal_decoys d on strpos(c.low, d.pattern) > 0 where c.created_at > since
             and not exists (select 1 from app.heal_incidents h where h.source_key = 'decoy:' || c.kind || ':' || c.ref) loop
    if app.heal_incident('decoy', 'decoy:' || r.kind || ':' || r.ref, r.kind, r.ref, r.member_id, null, 'decoy', '[]'::jsonb, 'done') is not null then
      n := n + 1;
      perform app.notify(null, 'alert', 'A decoy was used', 'A decoy ' || r.dkind || ' appeared in a ' || r.kind || '. That is an attack: the healer recorded an incident.',
                         '/admin/review', r.kind, r.ref, 'heal:decoy:' || r.ref);
    end if;
  end loop;
  return n;
end $$;

-- 3. Retraction: a later false-positive verdict, a cleared appeal, or an undone removal takes the incident back: its
-- fingerprints stop, what they swept is restored, and its accounts are trusted and honest again.
create function app.heal_retract() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare i record; f record; n integer := 0;
begin
  for i in select x.* from app.heal_incidents x
            where x.processed <> 'retracted' and (
              (x.source = 'wall_confirmed' and x.ref is not null and (
                 exists (select 1 from app.wall_decisions d join app.wall_reviews w on w.decision_id = d.id where d.ref = x.ref and w.verdict = 'false_positive')
                 or exists (select 1 from app.wall_decisions d join app.wall_appeals a on a.decision_id = d.id where d.ref = x.ref and a.status = 'cleared')))
              or (x.source = 'post_removed' and exists (select 1 from app.posts p where p.id = x.ref and p.status <> 'removed'))
              -- A reversal later put right (the work passes again).
              or (x.source in ('dispute_upheld', 'check_reversed') and exists (select 1 from app.work_submissions w where w.id = x.ref and w.status = 'passed'))) loop
    update app.heal_incidents x set processed = 'retracted', retracted_at = now() where x.id = i.id;
    for f in select * from app.heal_fingerprints y where y.incident_id = i.id and y.status in ('held', 'shadow', 'active') loop
      perform app.heal_rollback(f.id, 'Its incident was retracted (a person''s later verdict).', 'retracted');
    end loop;
    perform app.heal_log_add('retract', i.id, jsonb_build_object('source', i.source));
    n := n + 1;
  end loop;
  return n;
end $$;

-- The invariants: alerts only (once each). No member, no fingerprint, no tightening.
create function app.heal_invariants() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare r record; n integer := 0; since timestamptz := (select s.since from app.heal_settings s);
begin
  for r in select 'points_without_pass' as inv, p.id from app.work_points p join app.work_submissions s on s.id = p.submission_id
            where p.created_at >= since and p.status <> 'removed' and s.status <> 'passed'
           union all
           select 'pass_without_wall', s.id from app.work_submissions s
            where s.created_at >= since and s.status = 'passed' and not exists (select 1 from app.wall_decisions d where d.ref in (s.id, s.task_id))
           union all
           select 'jevs_without_log', d.id from app.jevs_decisions d
            where d.created_at >= since and d.created_at < date_trunc('hour', now()) - interval '2 hours'
              and not exists (select 1 from app.log_queue q where q.decision_id = d.id)
              and not exists (select 1 from app.log_openings o where o.decision_id = d.id)
            limit 50 loop
    if app.heal_incident('invariant', 'inv:' || r.inv || ':' || r.id, case r.inv when 'points_without_pass' then 'points' when 'pass_without_wall' then 'submission' else 'jevs' end,
                         r.id, null, null, r.inv, '[]'::jsonb, 'done') is not null then
      n := n + 1;
      perform app.notify(null, 'alert', 'An invariant broke', 'The healer found ' || replace(r.inv, '_', ' ') || ' (' || r.id || '). Nothing was changed; it waits for a look.',
                         '/admin/review', null, null, 'heal:inv:' || r.inv || ':' || r.id);
    end if;
  end loop;
  return n;
end $$;

-- One corpus row and its tokens.
create function app.heal_corpus_add(p_kind text, p_ref uuid, p_member uuid, p_agent uuid, p_text text, p_at timestamptz) returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare low text := left(app.heal_fold(p_text), 6000); cid uuid;
begin
  insert into app.heal_corpus (kind, ref, member_id, agent_id, low, norm, created_at)
    values (p_kind, p_ref, (select id from app.members where id = p_member), p_agent, low, left(regexp_replace(low, '[^a-z0-9]+', '', 'g'), 6000), p_at)
    on conflict (kind, ref) do nothing returning id into cid;
  if cid is null then return; end if;
  insert into app.heal_corpus_tokens (corpus_id, kind, value)
    select cid, 'url', u from unnest(app.heal_urls(low)) u
    union all select cid, 'host', h from unnest(app.heal_hosts(low)) h
    union all select cid, 'sha256', x from unnest(app.heal_shas(low)) x;
end $$;
-- New posts, work and tasks (up to 5,000 a tick, oldest first); older than 30 days removed.
create function app.heal_corpus_refresh() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare n integer := 0; x record;
begin
  delete from app.heal_corpus c where c.created_at < now() - interval '30 days';
  for x in select * from (
      select 'post' as kind, p.id as ref, p.author_id as mem, p.agent_id as ag, p.body as txt, p.created_at as at from app.posts p where p.created_at > now() - interval '30 days'
      union all
      select 'submission', s.id, coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent)), s.worker_agent,
             coalesce(s.note, '') || ' ' || coalesce(s.artifact_url, '') || ' ' || coalesce(s.artifact_sha256, ''), s.created_at
        from app.work_submissions s where s.created_at > now() - interval '30 days'
      union all
      select 'task', t.id, t.poster_member, t.poster_agent, coalesce(t.title, '') || ' ' || coalesce(t.description, ''), t.created_at
        from app.work_tasks t where t.created_at > now() - interval '30 days') y
     where not exists (select 1 from app.heal_corpus c where c.kind = y.kind and c.ref = y.ref)
     order by y.at limit 5000 loop
    perform app.heal_corpus_add(x.kind, x.ref, x.mem, x.ag, x.txt, x.at);
    n := n + 1;
    exit when clock_timestamp() - now() > interval '15 seconds';
  end loop;
  update app.heal_settings s set corpus_at = now();
  return n;
end $$;

-- Settled honest content: a live post with nothing against it, passed work with no upheld dispute, an open or
-- finished task; never content behind a standing incident, nor anything its accounts wrote.
create function app.heal_honest(p_kind text, p_ref uuid, p_member uuid) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select not exists (select 1 from app.heal_incidents i where i.ref = p_ref and i.processed <> 'retracted')
     and (p_member is null or not exists (select 1 from app.heal_incidents i where p_member in (i.member_id, i.owner_id) and i.processed <> 'retracted' and i.source <> 'invariant'))
     and case p_kind
    when 'post' then exists (select 1 from app.posts p where p.id = p_ref and p.status = 'live')
         and not exists (select 1 from app.review_flags f where f.post_id = p_ref and (f.resolved_at is null or f.decision = 'remove'))
    when 'submission' then exists (select 1 from app.work_submissions s where s.id = p_ref and s.status = 'passed')
         and not exists (select 1 from app.work_disputes d where d.submission_id = p_ref and d.status in ('open', 'upheld'))  -- under dispute isn't settled
    when 'task' then exists (select 1 from app.work_tasks t where t.id = p_ref and t.status <> 'removed')
    else false end
$$;

-- The corpus rows one fingerprint matches: hosts, URLs and hashes by index lookup, text by one pass over the
-- normalized corpus (within a time window).
create function app.heal_matches(p_kind text, p_value text, p_since timestamptz) returns setof app.heal_corpus
language sql stable security definer set search_path = pg_catalog as $$
  select c.* from app.heal_corpus c where p_kind = 'text' and c.created_at >= p_since and strpos(c.norm, p_value) > 0
  union all
  select c.* from app.heal_corpus c where p_kind <> 'text' and c.created_at >= p_since
     and c.id in (select t.corpus_id from app.heal_corpus_tokens t where t.kind = p_kind and t.value = p_value)
$$;

-- 3. The patch gate for one fingerprint. Null when it passes, else 'held: ...' (an honest hit, for the reviewers) or
-- 'refused: ...' (shape, cost, a trusted account's host, or the attack isn't refused).
create function app.heal_gate(p_fp uuid) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  f record; v text; tri integer; total integer; hits integer; low text; actors uuid[]; host text; base text;
  honest_hit boolean; trusted_hit boolean;
begin
  select * into f from app.heal_fingerprints x where x.id = p_fp;
  select array_agg(distinct a) into actors from (select i.member_id a from app.heal_incidents i where i.id = f.incident_id
                                                 union select i.owner_id from app.heal_incidents i where i.id = f.incident_id) z where a is not null;
  actors := coalesce(actors, '{}');
  -- (c) shape.
  if f.kind = 'text' then
    select count(distinct substr(f.value, k, 3)) into tri from generate_series(1, greatest(char_length(f.value) - 2, 1)) k;
    if char_length(f.value) < 24 or tri < 12 or (select count(distinct substr(f.value, k, 1)) from generate_series(1, char_length(f.value)) k) < 8 then
      return 'refused: too short or generic (' || char_length(f.value) || ' characters, ' || tri || ' distinct trigrams)';
    end if;
  elsif f.kind in ('host', 'url') then
    host := case when f.kind = 'host' then f.value else substring(f.value from '^https?://(?:[^@/]*@)?([^/:?#]+)') end;
    if not app.heal_valid_host(host) or app.wiki_never_block(host) or app.wiki_public_suffix(host) or app.heal_own_domain(host) then
      return 'refused: a host that is invalid, too broad, or the site''s own';
    end if;
    if f.kind = 'url' and char_length(f.value) < 16 then return 'refused: a URL too short to refuse'; end if;
  end if;
  -- (b) the span and its variants must be refused (case, spacing, look-alikes, hidden characters, defanging).
  base := case when f.kind = 'text' then f.label else replace(replace(f.label, 'hxxp', 'http'), '[.]', '.') end;
  foreach v in array array['see ' || base, upper(base), translate(base, 'aoecpx', 'аоесрх'), replace(base, ' ', ' ' || chr(8203)),
                           replace(replace(base, 'http', 'hxxp'), '.', '[.]'),
                           case when f.kind = 'text' then regexp_replace(base, '(.)', '\1 ', 'g') else base end] loop
    low := app.heal_fold(v);
    if not app.heal_hit(f.kind, f.value, regexp_replace(low, '[^a-z0-9]+', '', 'g'), app.heal_urls(low), app.heal_hosts(low), app.heal_shas(low)) then
      return 'refused: a variant of the attack would not be refused, so the patch would not work';
    end if;
  end loop;
  perform app.heal_deadline();
  -- (a) the golden set: any hit holds it.
  if exists (select 1 from app.heal_golden g, lateral (select app.heal_fold(g.line) as l) y
              where app.heal_hit(f.kind, f.value, regexp_replace(y.l, '[^a-z0-9]+', '', 'g'), app.heal_urls(y.l), app.heal_hosts(y.l), app.heal_shas(y.l))) then
    return 'held: it matches the golden set of honest lines';
  end if;
  perform app.heal_deadline();
  -- (a, c) one pass over 30 days of the corpus: honest hits, trusted accounts' content, and the 7-day cost.
  select coalesce(bool_or(app.heal_honest(m.kind, m.ref, m.member_id)), false),
         coalesce(bool_or(m.member_id is not null and app.heal_trusted(m.member_id)), false),
         count(*) filter (where m.created_at > now() - interval '7 days' and not (coalesce(m.member_id, '00000000-0000-0000-0000-000000000000'::uuid) = any (actors)))
    into honest_hit, trusted_hit, hits from app.heal_matches(f.kind, f.value, now() - interval '30 days') m;
  if trusted_hit then
    return case when f.kind in ('host', 'url') then 'refused: a trusted account''s content names this host'
                else 'held: it matches a trusted account''s content' end;
  end if;
  if honest_hit then return 'held: it matches settled honest content from the last 30 days'; end if;
  select count(*) into total from app.heal_corpus c where c.created_at > now() - interval '7 days';
  if hits > floor(total * 0.001) then
    return 'refused: it matches ' || hits || ' of ' || total || ' items from the last 7 days (over 0.1%)';
  end if;
  return null;
end $$;

-- 2, 6. Fingerprints from one incident's spans, each through the gate (shadow when it passes). A fingerprint seen
-- before: an enforced one is kept another 90 days (a new confirmed incident); a rolled-back, expired or retracted one
-- is re-armed through the gate.
-- The current incident's deadline (set by heal_queue): past it, the incident stops with an error the queue counts.
create function app.heal_deadline() returns void
language plpgsql volatile security definer set search_path = pg_catalog as $$
declare d text := current_setting('heal.deadline', true);
begin
  if coalesce(d, '') <> '' and clock_timestamp() > d::timestamptz then
    raise exception 'heal_incident_budget' using errcode = 'P0001', hint = 'The incident took longer than its budget.';
  end if;
end $$;

create function app.heal_fingerprint(p_incident uuid) returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare e jsonb; fid uuid; why text; t0 timestamptz; k integer := 0; old record;
begin
  for e in select x from jsonb_array_elements((select i.spans from app.heal_incidents i where i.id = p_incident)) x limit 12 loop
    continue when e ->> 'kind' not in ('text', 'url', 'host', 'sha256') or coalesce(e ->> 'value', '') = '' or char_length(e ->> 'value') > 500;
    continue when e ->> 'kind' = 'host' and not app.heal_valid_host(e ->> 'value');
    select * into old from app.heal_fingerprints x where x.kind = e ->> 'kind' and x.value = e ->> 'value' for update;
    if old.id is not null then
      if old.status = 'active' then
        update app.heal_fingerprints x set expires_at = greatest(x.expires_at, now() + interval '90 days') where x.id = old.id;
        continue;
      elsif old.status not in ('rolled_back', 'expired', 'retracted') then
        continue;
      end if;
      update app.heal_fingerprints x set incident_id = p_incident, status = 'held', shadow_at = null, activated_at = null, ended_at = null where x.id = old.id;
      fid := old.id;
    else
      insert into app.heal_fingerprints (code, kind, value, label, incident_id, status)
        values ('HF-' || left(encode(sha256(convert_to((e ->> 'kind') || ':' || (e ->> 'value'), 'UTF8')), 'hex'), 8), e ->> 'kind', e ->> 'value',
                coalesce(e ->> 'label', app.heal_label(e ->> 'kind', e ->> 'value')), p_incident, 'held')
        on conflict do nothing returning id into fid;
      continue when fid is null;
    end if;
    perform app.heal_deadline();
    t0 := clock_timestamp();
    why := app.heal_gate(fid);
    perform app.heal_deadline();
    update app.heal_fingerprints x set
      status = case when why is null then 'shadow' when why like 'held:%' then 'held' else 'refused' end,
      reason = left(why, 300), shadow_at = case when why is null then now() end,
      gate_ms = least(600000, floor(extract(epoch from clock_timestamp() - t0) * 1000))::integer
      where x.id = fid;
    perform app.heal_log_add(case when why is null then 'shadow' when why like 'held:%' then 'held' else 'refused' end, fid,
                             jsonb_build_object('code', (select code from app.heal_fingerprints where id = fid), 'kind', e ->> 'kind', 'why', why));
    k := k + 1;
  end loop;
  return k;
end $$;

-- 5, 8, 9. Sweep-back for one enforced fingerprint: live posts back to waiting with a review flag, passed work's pending
-- points held, waiting work returned. Notices only for what was swept, to its account (the agent's own account for a
-- solo agent, its owner otherwise).
create function app.heal_sweep(p_fp uuid) returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare f record; r record; n integer := 0; st text; swept boolean; pr record;
begin
  select * into f from app.heal_fingerprints x where x.id = p_fp;
  for r in select * from app.heal_matches(f.kind, f.value, now() - interval '30 days') loop
    continue when exists (select 1 from app.heal_sweeps s where s.fingerprint_id = p_fp and s.kind = r.kind and s.ref = r.ref);
    continue when r.member_id is not null and exists (select 1 from app.members m where m.id = r.member_id and m.is_admin);
    continue when exists (select 1 from app.heal_exemptions e where e.fingerprint_id = p_fp and e.member_id = r.member_id);
    -- Already swept by another fingerprint: recorded for this one too (same prior state), so restoring one of them
    -- keeps it returned while the other is in force.
    select y.prior_status, y.prior_final_at into pr from app.heal_sweeps y where y.kind = r.kind and y.ref = r.ref and y.status = 'swept' limit 1;
    if pr.prior_status is not null then
      insert into app.heal_sweeps (fingerprint_id, kind, ref, member_id, agent_id, prior_status, prior_final_at)
        values (p_fp, r.kind, r.ref, r.member_id, r.agent_id, pr.prior_status, pr.prior_final_at) on conflict do nothing;
      continue;
    end if;
    swept := false;
    if r.kind = 'post' and exists (select 1 from app.posts p where p.id = r.ref and p.status = 'live') then
      insert into app.heal_sweeps (fingerprint_id, kind, ref, member_id, agent_id, prior_status) values (p_fp, 'post', r.ref, r.member_id, r.agent_id, 'live');
      update app.posts p set status = 'waiting' where p.id = r.ref;
      if not exists (select 1 from app.review_flags x where x.post_id = r.ref and x.source = 'classifier' and x.classifier = 'heal' and x.resolved_at is null) then
        insert into app.review_flags (post_id, source, classifier, score) values (r.ref, 'classifier', 'heal', 1);
      end if;
      swept := true;
    elsif r.kind = 'submission' then
      select s.status into st from app.work_submissions s where s.id = r.ref;
      if st = 'passed' and exists (select 1 from app.work_points x where x.submission_id = r.ref and x.status = 'pending') then
        insert into app.heal_sweeps (fingerprint_id, kind, ref, member_id, agent_id, prior_status, prior_final_at)
          values (p_fp, 'submission', r.ref, r.member_id, r.agent_id, 'passed', (select x.final_at from app.work_points x where x.submission_id = r.ref and x.status = 'pending'));
        update app.work_points x set final_at = now() + interval '100 years' where x.submission_id = r.ref and x.status = 'pending';
        swept := true;
      elsif st in ('waiting', 'review') then
        insert into app.heal_sweeps (fingerprint_id, kind, ref, member_id, agent_id, prior_status) values (p_fp, 'submission', r.ref, r.member_id, r.agent_id, st);
        update app.work_submissions s set status = 'failed', decided_by = 'wall', decided_at = now(),
          reason = left('Returned by the healer: it matches ' || f.code || ' from a confirmed attack. Appeal: POST /api/work/heal/appeal.', 300) where s.id = r.ref;
        swept := true;
      end if;
    end if;
    if swept then
      n := n + 1;
      if r.member_id is not null then
        perform app.notify(r.member_id, 'alert', case when r.agent_id is not null then 'Your agent''s ' else 'Your ' end || r.kind || ' was returned for review',
          'It matches ' || f.code || ', taken from a confirmed attack. Nothing was deleted. If this is a mistake, appeal: POST /api/work/heal/appeal with that code.',
          '/account', r.kind, r.ref, 'heal:sweep:' || p_fp || ':' || r.ref);
      end if;
    end if;
  end loop;
  if n > 0 then perform app.heal_log_add('sweep', p_fp, jsonb_build_object('code', f.code, 'items', n)); end if;
  return n;
end $$;

-- Restores sweeps: all of one fingerprint's (p_member null), or one account's.
create function app.heal_restore(p_fp uuid, p_member uuid) returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare s record; n integer := 0; other boolean;
begin
  for s in select * from app.heal_sweeps x where x.fingerprint_id = p_fp and x.status = 'swept' and (p_member is null or x.member_id = p_member) for update loop
    update app.heal_sweeps x set status = 'restored', restored_at = now() where x.id = s.id;
    -- Another fingerprint still in force that swept the same item keeps it where it is.
    other := exists (select 1 from app.heal_sweeps y join app.heal_fingerprints f on f.id = y.fingerprint_id
                      where y.kind = s.kind and y.ref = s.ref and y.status = 'swept' and y.id <> s.id and f.status = 'active');
    if not other then
      if s.kind = 'post' then
        update app.posts p set status = 'live' where p.id = s.ref and p.status = 'waiting';
        update app.review_flags f set resolved_at = now(), decision = 'restore'
          where f.post_id = s.ref and f.source = 'classifier' and f.classifier = 'heal' and f.resolved_at is null;
      elsif s.prior_status = 'passed' then
        update app.work_points x set final_at = coalesce(s.prior_final_at, now()) where x.submission_id = s.ref and x.status = 'pending';
      else
        update app.work_submissions x set status = s.prior_status, decided_by = null, decided_at = null, reason = null where x.id = s.ref and x.status = 'failed';
      end if;
      if s.member_id is not null then
        perform app.notify(s.member_id, 'alert', 'Your ' || s.kind || ' was restored', 'What the healer returned for review is back as it was.',
                           '/account', s.kind, s.ref, 'heal:restored:' || s.id);
      end if;
    end if;
    n := n + 1;
  end loop;
  if n > 0 then perform app.heal_log_add('restore', p_fp, jsonb_build_object('items', n, 'one_account', p_member is not null)); end if;
  return n;
end $$;

-- Rolls a patch back (or retracts it): it stops, everything it swept is restored, Aaron is alerted, the chain says why.
create function app.heal_rollback(p_fp uuid, p_why text, p_status text default 'rolled_back') returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare c text;
begin
  update app.heal_fingerprints x set status = p_status, ended_at = now(), reason = left(p_why, 300)
    where x.id = p_fp and x.status in ('held', 'shadow', 'active') returning x.code into c;
  if c is null then return; end if;
  perform app.heal_restore(p_fp, null);
  update app.heal_appeals a set status = 'upheld', decided_by = coalesce(a.decided_by, 'rollback'), decided_at = coalesce(a.decided_at, now())
    where a.fingerprint_id = p_fp and a.status in ('open', 'second_look', 'review');
  perform app.heal_log_add('rollback', p_fp, jsonb_build_object('code', c, 'status', p_status, 'why', left(p_why, 300)));
  perform app.notify(null, 'alert', 'The healer rolled back a patch', c || ': ' || left(p_why, 200) || ' Everything it returned is restored.',
                     '/admin/review', null, null, 'heal:rollback:' || p_fp);
end $$;

-- An upheld appeal: that account's content restored, and it is exempt from the fingerprint.
create function app.heal_uphold(p_appeal uuid, p_by text) returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare a record;
begin
  update app.heal_appeals x set status = 'upheld', decided_by = p_by, decided_at = now() where x.id = p_appeal and x.status <> 'upheld' returning * into a;
  if a.id is null then return; end if;
  perform app.heal_restore(a.fingerprint_id, a.member_id);
  insert into app.heal_exemptions (fingerprint_id, member_id) values (a.fingerprint_id, a.member_id) on conflict do nothing;
  perform app.heal_log_add('exempt', a.fingerprint_id, jsonb_build_object('by', p_by));
end $$;

-- 4, 5. The canary and the health watch, once a tick.
create function app.heal_canary() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare f record; r record; n integer := 0; base numeric; hits integer; apps integer; tr integer; up integer;
begin
  -- Shadow: 30 minutes of would-be hits (logged), then enforced. Content a trusted account wrote before it already
  -- held it at the gate.
  for f in select * from app.heal_fingerprints x where x.status = 'shadow' and x.shadow_at < now() - interval '30 minutes' for update loop
    insert into app.heal_shadow_hits (fingerprint_id, kind, ref, member_id)
      select f.id, m.kind, m.ref, m.member_id from app.heal_matches(f.kind, f.value, f.shadow_at) m on conflict do nothing;
    update app.heal_fingerprints x set status = 'active', activated_at = now(), expires_at = now() + interval '90 days' where x.id = f.id;
    perform app.heal_log_add('active', f.id, jsonb_build_object('code', f.code, 'shadow_hits', (select count(*) from app.heal_shadow_hits h where h.fingerprint_id = f.id)));
    perform app.heal_sweep(f.id);
    n := n + 1;
  end loop;
  -- Enforced: only accounts that count (heal_counts: their own earlier content swept, unrelated, 7 days old) can roll
  -- it back: 3 trusted ones in the first 24 hours, 2 upheld appeals decided by Second Look or a person (never the
  -- automatic trusted path), or a spike of them in 7 days.
  for f in select * from app.heal_fingerprints x where x.status = 'active' and x.activated_at > now() - interval '7 days' loop
    select count(distinct s.member_id) into tr from app.heal_sweeps s
     where s.fingerprint_id = f.id and f.activated_at > now() - interval '24 hours' and app.heal_trusted(s.member_id) and app.heal_counts(f.id, s.member_id)
       and exists (select 1 from app.heal_appeals a where a.fingerprint_id = f.id and a.member_id = s.member_id);
    -- Third review: an appeal Second Look upheld restores that one item and carries no rollback weight.
    select count(distinct a.member_id) into up from app.heal_appeals a where a.fingerprint_id = f.id and a.status = 'upheld'
       and a.decided_by in ('reviewer', 'trusted') and app.heal_counts(f.id, a.member_id);
    if tr >= 3 then
      perform app.heal_rollback(f.id, tr || ' unrelated trusted accounts whose earlier content it swept appealed in its first 24 hours.');
      continue;
    elsif up >= 2 then
      perform app.heal_rollback(f.id, up || ' unrelated honest appeals against it were upheld.');
      continue;
    end if;
    select (count(distinct d.member_id) + (select count(distinct rf.member_id) from app.heal_refusals rf
              where rf.created_at between f.activated_at - interval '7 days' and f.activated_at)) / 168.0 into base
      from app.wall_decisions d where d.decision = 'block' and d.created_at between f.activated_at - interval '7 days' and f.activated_at;
    select count(distinct rf.member_id) into hits from app.heal_refusals rf
     where rf.fingerprint_id = f.id and rf.created_at > now() - interval '1 hour' and app.heal_counts(f.id, rf.member_id);
    select count(distinct a.member_id) into apps from app.heal_appeals a
     where a.fingerprint_id = f.id and a.created_at > now() - interval '1 hour' and coalesce(a.decided_by, '') <> 'second_look' and app.heal_counts(f.id, a.member_id);
    if hits >= greatest(5, ceil(3 * base)) then
      perform app.heal_rollback(f.id, 'Refusals spiked: ' || hits || ' accounts whose earlier content it swept, in the last hour, against a baseline of ' || round(base, 2) || ' an hour.');
    elsif apps >= greatest(3, ceil(3 * base)) then
      perform app.heal_rollback(f.id, 'Appeals spiked: ' || apps || ' accounts whose earlier content it swept, in the last hour.');
    end if;
  end loop;
  for r in update app.heal_fingerprints x set status = 'expired', ended_at = now() where x.status = 'active' and x.expires_at < now() returning x.id, x.code loop
    perform app.heal_log_add('expired', r.id, jsonb_build_object('code', r.code));
  end loop;
  return n;
end $$;

-- The Wall's W52 refusals of work and tasks since the last tick, recorded for the health watch (they don't extend a
-- fingerprint: only a new confirmed incident does).
create function app.heal_note_wall() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare n integer;
begin
  insert into app.heal_refusals (fingerprint_id, kind, member_id, agent_id)
    select x.id, case when d.kind = 'task' then 'task' else 'submission' end, d.member_id, d.agent_id from app.wall_decisions d
      cross join lateral jsonb_array_elements_text(d.flags) g
      join app.heal_fingerprints x on x.code = substring(g from 'W52 healer fingerprint (HF-[0-9a-f]{8})')
     where d.created_at > coalesce((select s.last_run_at from app.heal_settings s), now() - interval '1 hour') and starts_with(g, 'W52 ');
  get diagnostics n = row_count;
  return n;
end $$;

-- 6. Tightening: 3 incidents in 24 hours on one scope. Simulated first; ends by itself.
create function app.heal_tighten() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare g record; t record; aff integer; hon integer; adm boolean; n integer := 0; mx integer := (select s.max_honest_in_scope from app.heal_settings s);
begin
  for t in update app.heal_tightenings x set status = 'ended', ended_at = now() where x.status = 'active' and x.expires_at <= now() returning x.* loop
    perform app.heal_log_add('tighten_end', t.id, jsonb_build_object('scope', t.scope_kind, 'value', t.scope_value));
  end loop;
  for g in select k, v, count(*)::int as c, max(created_at) as last from (
             select 'owner_tree' as k, i.owner_id::text as v, i.created_at from app.heal_incidents i where i.owner_id is not null and i.created_at > now() - interval '24 hours' and i.processed <> 'retracted' and i.source <> 'invariant'
             union all select 'network', i.net, i.created_at from app.heal_incidents i where i.net is not null and i.created_at > now() - interval '24 hours' and i.processed <> 'retracted' and i.source <> 'invariant'
             union all select 'rule_area', i.rule_area, i.created_at from app.heal_incidents i where i.created_at > now() - interval '24 hours' and i.processed <> 'retracted' and i.source <> 'invariant') z
           group by k, v having count(*) >= 3 loop
    select * into t from app.heal_tightenings x where x.scope_kind = g.k and x.scope_value = g.v and x.status = 'active';
    if t.id is not null then
      if g.last > t.confirmed_at then
        update app.heal_tightenings x set confirmed_at = now(), incidents = g.c,
          expires_at = least(x.starts_at + interval '72 hours', now() + interval '24 hours') where x.id = t.id;
      end if;
      continue;
    end if;
    continue when exists (select 1 from app.heal_tightenings x where x.scope_kind = g.k and x.scope_value = g.v and x.starts_at > now() - interval '24 hours');
    select count(*), count(*) filter (where not exists (select 1 from app.heal_incidents i where m in (i.member_id, i.owner_id) and i.processed <> 'retracted')),
           coalesce(bool_or(exists (select 1 from app.members x where x.id = m and x.is_admin)), false)
      into aff, hon, adm from app.heal_scope_members(g.k, g.v) m;
    if adm or hon > mx then
      insert into app.heal_tightenings (scope_kind, scope_value, status, incidents, affected, honest, reason, expires_at, ended_at)
        values (g.k, g.v, 'refused', g.c, aff, hon, case when adm then 'It would touch an administrator.' else 'It would touch ' || hon || ' accounts with no incident (over ' || mx || ').' end, now(), now())
        returning * into t;
      perform app.heal_log_add('tighten_refused', t.id, jsonb_build_object('scope', g.k, 'affected', aff, 'honest', hon));
    else
      insert into app.heal_tightenings (scope_kind, scope_value, status, incidents, affected, honest, expires_at)
        values (g.k, g.v, 'active', g.c, aff, hon, now() + interval '24 hours') returning * into t;
      perform app.heal_log_add('tighten', t.id, jsonb_build_object('scope', g.k, 'incidents', g.c, 'affected', aff));
      perform app.notify(null, 'alert', 'The healer tightened one scope', g.c || ' confirmed incidents in 24 hours on one ' || replace(g.k, '_', ' ')
        || ' (' || aff || ' accounts): half the posting budget, every post sampled, pending points 3 days longer. It ends by itself in 24 hours.',
        '/admin/review', null, null, 'heal:tighten:' || t.id);
      n := n + 1;
    end if;
  end loop;
  return n;
end $$;

-- Appeals: a trusted account's is upheld; anyone else's goes to Second Look; Second Look's clear upholds it, anything
-- else sends it to an administrator (one alert each).
create function app.heal_appeals_run() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare a record; f record; d record; n integer := 0; body text; earlier boolean;
begin
  for a in select * from app.heal_appeals x where x.status = 'open' for update loop
    select * into f from app.heal_fingerprints x where x.id = a.fingerprint_id;
    -- Second review, finding 3: only an appeal about the appellant's own content written before the fingerprint can be
    -- upheld without a person, and only settled content (live or passed) older than the incident's. One about a refusal
    -- alone, or about work parked waiting, goes to an administrator.
    earlier := app.heal_settled_earlier(a.fingerprint_id, a.member_id);
    if not earlier then
      update app.heal_appeals x set status = 'review' where x.id = a.id;
      perform app.notify(null, 'alert', 'A healer appeal waits for a person', 'An appeal against ' || f.code || ' about a refusal only (nothing written before it was swept). Decide it: POST /api/work/heal/decide.',
                         '/admin/review', null, null, 'heal:appeal:' || a.id);
    elsif app.heal_trusted(a.member_id) then
      perform app.heal_uphold(a.id, 'trusted');
    else
      body := 'An appeal against a healer fingerprint taken from a confirmed attack. The fingerprint, normalized: ' || f.label
        || '. The appellant''s reason: ' || a.reason || coalesce('. The appellant''s returned content: '
        || (select string_agg(left(c.low, 1500), ' | ') from app.heal_sweeps s join app.heal_corpus c on c.kind = s.kind and c.ref = s.ref
             where s.fingerprint_id = a.fingerprint_id and s.member_id = a.member_id and s.status = 'swept'), '');
      insert into app.sl_items (kind, ref, author_member, body) values ('heal_appeal', a.id, a.member_id, left(body, 6000)) on conflict do nothing;
      update app.heal_appeals x set status = 'second_look' where x.id = a.id;
    end if;
    n := n + 1;
  end loop;
  for d in select x.id, i.decision from app.heal_appeals x join app.sl_items i on i.kind = 'heal_appeal' and i.ref = x.id
            where x.status = 'second_look' and i.decided_at is not null loop
    if d.decision = 'clear' then
      perform app.heal_uphold(d.id, 'second_look');
    else
      update app.heal_appeals x set status = 'review' where x.id = d.id;
      perform app.notify(null, 'alert', 'A healer appeal waits for a person', 'Second Look did not clear an appeal against a healer fingerprint. Decide it: POST /api/work/heal/decide.',
                         '/admin/review', null, null, 'heal:appeal:' || d.id);
    end if;
    n := n + 1;
  end loop;
  return n;
end $$;

-- 6. The queue: one incident at a time in its own sub-transaction; a failure is retried with backoff (1, 2, 4 minutes)
-- and, after 3 tries, skipped with an alert. Never more than 45 seconds of work in one tick.
create function app.heal_queue() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare i record; k integer := 0; budget integer := (select s.incident_budget_ms from app.heal_settings s); why text; stop boolean := false;
begin
  for i in select x.id, x.attempts from app.heal_incidents x
            where x.processed = 'new' and (x.tried_at is null or x.tried_at < now() - make_interval(mins => (1 << least(x.attempts, 6))))
            order by x.created_at limit 20 loop
    -- Room for the rest of the tick: no incident starts once 45 seconds less one incident's budget have passed.
    exit when clock_timestamp() - now() > interval '45 seconds' - make_interval(secs => budget / 1000.0);
    why := null;
    begin
      -- Second review, finding 1: each incident has its own deadline, which the gate and the fingerprinting check
      -- between steps (app.heal_deadline); Postgres's statement_timeout can't be set per incident inside one call.
      perform set_config('heal.deadline', (clock_timestamp() + make_interval(secs => budget / 1000.0))::text, true);
      k := k + app.heal_fingerprint(i.id);
      update app.heal_incidents x set processed = 'done', tried_at = now() where x.id = i.id;
    exception
      when query_canceled then
        -- The tick's own statement budget ran out inside this incident: count the try and stop for this tick.
        why := 'the tick''s time ran out'; stop := true;
      when others then
        why := left(sqlerrm, 200);
    end;
    if why is not null then
      update app.heal_incidents x set attempts = x.attempts + 1, tried_at = now(),
        processed = case when x.attempts + 1 >= 3 then 'failed' else 'new' end where x.id = i.id;
      if i.attempts + 1 >= 3 then
        perform app.heal_log_add('failed', i.id, jsonb_build_object('error', why));
        perform app.notify(null, 'alert', 'The healer skipped an incident', 'An incident failed 3 times and was skipped (' || left(why, 120) || '). Nothing else was held up.',
                           '/admin/review', null, null, 'heal:failed:' || i.id);
      end if;
    end if;
    exit when stop;
  end loop;
  perform set_config('heal.deadline', '', true);
  return k;
end $$;

-- The timer's entry point: at most once every 20 seconds, as the site's timer; nothing while paused.
create function app.heal_run() returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare s record; out jsonb := '{}'::jsonb; held integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer runs the healer' using errcode = '42501'; end if;
  if not pg_try_advisory_xact_lock(7309602) then return jsonb_build_object('skipped', true); end if;
  select * into s from app.heal_settings x for update;
  if s.paused then return jsonb_build_object('paused', true); end if;
  if s.last_run_at > now() - interval '20 seconds' then return jsonb_build_object('skipped', true); end if;
  perform set_config('lock_timeout', '2s', true);
  out := out || jsonb_build_object('corpus', app.heal_corpus_refresh());
  out := out || jsonb_build_object('incidents', app.heal_intake(), 'retracted', app.heal_retract(), 'alerts', app.heal_invariants());
  out := out || jsonb_build_object('fingerprints', app.heal_queue(), 'wall_refusals', app.heal_note_wall(), 'appeals', app.heal_appeals_run(),
                                   'enforced', app.heal_canary(), 'tightened', app.heal_tighten());
  -- 10: an incident's spans are kept 90 days.
  update app.heal_incidents x set spans = '[]'::jsonb where x.created_at < now() - interval '90 days' and x.spans <> '[]'::jsonb;
  -- The per-account records are kept 90 days too (a sweep still in force stays).
  delete from app.heal_refusals x where x.created_at < now() - interval '90 days';
  delete from app.heal_shadow_hits x where x.created_at < now() - interval '90 days';
  delete from app.heal_sweeps x where x.status = 'restored' and x.restored_at < now() - interval '90 days';
  delete from app.heal_appeals x where x.status in ('upheld', 'kept') and x.decided_at < now() - interval '90 days';
  select count(*) into held from app.heal_fingerprints x where x.status = 'held' and x.created_at > now() - interval '1 day';
  if held > 0 then
    perform app.notify(null, 'alert', 'The healer held fingerprints for review', held || ' fingerprint(s) from confirmed attacks would have matched honest content, so they are held, not enforced.',
                       '/admin/review', null, null, 'heal:held:' || current_date);
  end if;
  update app.heal_settings x set last_run_at = now(), last_ok_at = now();
  return out;
end $$;

-- 1: an alert when the healer hasn't finished a tick in 15 minutes (and isn't paused), once an hour while it holds.
create function app.heal_stale_check() returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
declare s record;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer checks the healer' using errcode = '42501'; end if;
  select * into s from app.heal_settings x;
  if s.paused or coalesce(s.last_ok_at, s.since) > now() - interval '15 minutes' then return false; end if;
  perform app.notify(null, 'alert', 'The healer has stopped', 'No healer tick has finished since ' || coalesce(s.last_ok_at::text, 'it was installed') || '.',
                     '/admin/review', null, null, 'heal:stale:' || to_char(now(), 'YYYYMMDDHH24'));
  return true;
end $$;

-- The healer's counts, for /api/ready: totals only.
create function app.heal_status() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object(
    'incidents', (select count(*) from app.heal_incidents i where i.source <> 'invariant'),
    'fingerprints_active', (select count(*) from app.heal_fingerprints f where f.status = 'active'),
    'fingerprints_held', (select count(*) from app.heal_fingerprints f where f.status = 'held'),
    'rollbacks', (select count(*) from app.heal_fingerprints f where f.status = 'rolled_back'),
    'tightenings_active', (select count(*) from app.heal_tightenings t where t.status = 'active' and t.expires_at > now()),
    'paused', (select s.paused from app.heal_settings s),
    'last_run_s_ago', (select floor(extract(epoch from now() - s.last_ok_at))::int from app.heal_settings s))
$$;

-- 9. An appeal by the account (a person, an agent's owner, or a solo agent) a fingerprint refused or swept.
create function app.heal_appeal(p_code text, p_reason text) returns uuid
language plpgsql security definer set search_path = pg_catalog as $$
declare f record; me uuid := app.current_member(); aid uuid;
begin
  if app.actor_kind() not in ('member', 'admin', 'agent') or me is null then raise exception 'sign in to appeal' using errcode = '42501'; end if;
  if char_length(btrim(coalesce(p_reason, ''))) not between 3 and 500 then
    raise exception 'heal_appeal_reason' using errcode = 'P0001', hint = 'Say why in 3 to 500 characters.';
  end if;
  select * into f from app.heal_fingerprints x where x.code = p_code;
  if f.id is null or not (exists (select 1 from app.heal_sweeps s where s.fingerprint_id = f.id and s.member_id = me)
                          or exists (select 1 from app.heal_refusals r where r.fingerprint_id = f.id and r.member_id = me)) then
    raise exception 'heal_appeal_none' using errcode = 'P0001', hint = 'That fingerprint has not refused or returned anything of yours.';
  end if;
  insert into app.heal_appeals (fingerprint_id, member_id, agent_id, reason) values (f.id, me, app.current_agent(), btrim(p_reason)) on conflict do nothing returning id into aid;
  if aid is null then raise exception 'heal_appealed' using errcode = 'P0001', hint = 'You have already appealed this fingerprint.'; end if;
  perform app.heal_log_add('appeal', f.id, jsonb_build_object('code', f.code));
  return aid;
end $$;

-- An administrator's decision on an appeal Second Look didn't clear.
create function app.heal_appeal_decide(p_appeal uuid, p_decision text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare a record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides an appeal' using errcode = '42501'; end if;
  if p_decision not in ('upheld', 'kept') then raise exception 'bad decision' using errcode = '22023'; end if;
  select * into a from app.heal_appeals x where x.id = p_appeal and x.status in ('open', 'second_look', 'review') for update;
  if a.id is null then raise exception 'heal_appeal_decided' using errcode = 'P0001', hint = 'That appeal is already decided.'; end if;
  if p_decision = 'upheld' then
    perform app.heal_uphold(a.id, 'reviewer');
  else
    update app.heal_appeals x set status = 'kept', decided_by = 'reviewer', decided_at = now() where x.id = a.id;
  end if;
  return p_decision;
end $$;

-- 4. An administrator's controls: pause and resume (the off switch), release a held fingerprint (to shadow), roll one
-- back. Each on the chain.
create function app.heal_admin(p_action text, p_code text, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare f record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator controls the healer' using errcode = '42501'; end if;
  if p_action not in ('pause', 'resume', 'release', 'rollback') or char_length(btrim(coalesce(p_reason, ''))) not between 3 and 300 then
    raise exception 'bad healer control' using errcode = '22023';
  end if;
  if p_action in ('pause', 'resume') then
    update app.heal_settings x set paused = (p_action = 'pause'), paused_reason = case when p_action = 'pause' then btrim(p_reason) end;
    perform app.heal_log_add(p_action, null, jsonb_build_object('reason', left(btrim(p_reason), 300)));
    return p_action;
  end if;
  select * into f from app.heal_fingerprints x where x.code = p_code for update;
  if f.id is null then raise exception 'heal_unknown' using errcode = 'P0001', hint = 'No such fingerprint.'; end if;
  if p_action = 'release' then
    if f.status <> 'held' then raise exception 'heal_not_held' using errcode = 'P0001', hint = 'Only a held fingerprint can be released.'; end if;
    update app.heal_fingerprints x set status = 'shadow', shadow_at = now(), reason = left('Released by an administrator: ' || btrim(p_reason), 300) where x.id = f.id;
    perform app.heal_log_add('release', f.id, jsonb_build_object('code', f.code, 'reason', left(btrim(p_reason), 300)));
  else
    if f.status not in ('held', 'shadow', 'active') then raise exception 'heal_not_live' using errcode = 'P0001', hint = 'That fingerprint is not in force.'; end if;
    perform app.heal_rollback(f.id, 'Rolled back by an administrator: ' || btrim(p_reason));
  end if;
  return p_action;
end $$;

-- A post the gate refused, noted for the health watch. The text is matched again here, so a note can't be forged.
create function app.heal_refusal_note(p_body text) returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); low text; n text; k integer;
begin
  if me is null then return 0; end if;
  low := app.heal_fold(p_body); n := regexp_replace(low, '[^a-z0-9]+', '', 'g');
  insert into app.heal_refusals (fingerprint_id, kind, member_id, agent_id)
    select x.id, 'post', me, app.current_agent() from app.heal_fingerprints x
     where x.status = 'active' and app.heal_hit(x.kind, x.value, n, app.heal_urls(low), app.heal_hosts(low), app.heal_shas(low))
       and not exists (select 1 from app.heal_exemptions e where e.fingerprint_id = x.id and e.member_id = me)
       and not exists (select 1 from app.heal_refusals r where r.fingerprint_id = x.id and r.member_id = me and r.created_at > now() - interval '10 minutes');
  get diagnostics k = row_count;
  return k;
end $$;

-- 7. What the healer's proposals read (the Heal proposals workflow, through dog-github as dog_ghsync): enforced text
-- fingerprints not yet proposed, as codes, normalized labels and incident ids; no member, no raw text, no live link.
create function app.heal_export(p_n integer) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function reads this (dog_ghsync)' using errcode = '42501';
  end if;
  -- Read only: a fingerprint is marked proposed (app.heal_export_mark) after its pull request opens, so a failed run retries.
  return (select coalesce(jsonb_agg(jsonb_build_object('id', p.iid, 'source', p.source, 'rule_area', p.rule_area, 'code', p.code, 'label', p.label)), '[]'::jsonb)
    from (select f.code, f.label, i.id as iid, i.source, i.rule_area from app.heal_fingerprints f join app.heal_incidents i on i.id = f.incident_id
           where f.status = 'active' and f.kind = 'text' and f.exported_at is null order by f.activated_at limit least(greatest(coalesce(p_n, 1), 1), 20)) p);
end $$;

-- After the proposals' pull request opened: those fingerprints are marked proposed. Returns how many.
create function app.heal_export_mark(p jsonb) returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare n integer;
begin
  if current_setting('role') is distinct from 'dog_ghsync' then
    raise exception 'only the GitHub facts function records this (dog_ghsync)' using errcode = '42501';
  end if;
  if p is null or jsonb_typeof(p) <> 'array' or jsonb_array_length(p) > 20
     or exists (select 1 from jsonb_array_elements(p) e where jsonb_typeof(e) <> 'string' or (e #>> '{}') !~ '^HF-[0-9a-f]{8}$') then
    raise exception 'bad codes' using errcode = '22023';
  end if;
  update app.heal_fingerprints x set exported_at = now() where x.exported_at is null and x.code in (select e #>> '{}' from jsonb_array_elements(p) e);
  get diagnostics n = row_count;
  return n;
end $$;

-- The post gate: a post matching an enforced fingerprint is refused, naming it and the appeal.
create function app.heal_post_gate() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
declare f jsonb; c text;
begin
  if exists (select 1 from app.members m where m.id = new.author_id and m.is_admin) then return new; end if;
  f := app.heal_flags(new.body);
  if jsonb_array_length(f) > 0 then
    c := substring(f ->> 0 from '(HF-[0-9a-f]{8})');
    raise exception 'heal_refused' using errcode = 'P0001',
      hint = 'Refused: this matches healer fingerprint ' || c || ', taken from a confirmed attack. If this is a mistake, appeal with POST /api/work/heal/appeal {"fingerprint": "' || c || '", "reason": "..."}.';
  end if;
  return new;
end $$;

-- Tightened accounts: every new post is sampled for the reviewers (a review flag, which never hides it).
create function app.heal_post_sample() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.heal_member_tightened(new.author_id) then
    insert into app.review_flags (post_id, source, classifier, score) values (new.id, 'classifier', 'heal', 0.5);
  end if;
  return null;
end $$;

-- Tightened accounts: pending points wait 3 days longer before they become final.
create function app.heal_points_window() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if new.status = 'pending' and app.heal_member_tightened(coalesce(new.citizen_member, (select g.owner_id from app.agents g where g.id = new.citizen_agent))) then
    new.final_at := new.final_at + interval '3 days';
  end if;
  return new;
end $$;

do $heal_fns$
declare f text;
begin
  foreach f in array array['app.heal_log_add(text, uuid, jsonb)', 'app.heal_trusted(uuid)', 'app.heal_scope_members(text, text)', 'app.heal_related(uuid)',
    'app.heal_counts(uuid, uuid)', 'app.heal_settled_earlier(uuid, uuid)', 'app.heal_member_tightened(uuid)', 'app.heal_member_cap(uuid, integer)', 'app.heal_flags(text)', 'app.heal_spans(text, boolean)',
    'app.heal_incident(text, text, text, uuid, uuid, uuid, text, jsonb, text)', 'app.heal_decision_text(text, uuid)', 'app.heal_intake()', 'app.heal_retract()',
    'app.heal_invariants()', 'app.heal_corpus_add(text, uuid, uuid, uuid, text, timestamp with time zone)', 'app.heal_corpus_refresh()',
    'app.heal_honest(text, uuid, uuid)', 'app.heal_matches(text, text, timestamp with time zone)', 'app.heal_gate(uuid)', 'app.heal_fingerprint(uuid)',
    'app.heal_sweep(uuid)', 'app.heal_restore(uuid, uuid)', 'app.heal_rollback(uuid, text, text)', 'app.heal_uphold(uuid, text)', 'app.heal_canary()',
    'app.heal_note_wall()', 'app.heal_tighten()', 'app.heal_appeals_run()', 'app.heal_queue()', 'app.heal_run()', 'app.heal_stale_check()', 'app.heal_status()',
    'app.heal_appeal(text, text)', 'app.heal_appeal_decide(uuid, text)', 'app.heal_admin(text, text, text)', 'app.heal_refusal_note(text)', 'app.heal_export(integer)', 'app.heal_export_mark(jsonb)', 'app.heal_deadline()',
    'app.heal_post_gate()', 'app.heal_post_sample()', 'app.heal_points_window()'] loop
    execute 'revoke execute on function ' || f || ' from public';
  end loop;
end
$heal_fns$;
grant execute on function app.heal_run(), app.heal_stale_check(), app.heal_status(), app.heal_appeal(text, text), app.heal_appeal_decide(uuid, text),
  app.heal_admin(text, text, text), app.heal_refusal_note(text) to dog_app;
grant execute on function app.heal_export(integer), app.heal_export_mark(jsonb) to dog_ghsync;
reset role;
revoke create on schema app from dog_heal;

-- ---- The Wall reads the healer (tasks and work, through wall_intel_flags), and posts get their own gate ----
set local role dog_owner;
alter function app.wall_intel_flags(text, text) rename to wall_intel_flags_wiki;
create function app.wall_intel_flags(p_text text, p_path text default null) returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select app.wall_intel_flags_wiki(p_text, p_path) || app.heal_flags(p_text)
$$;
revoke execute on function app.wall_intel_flags(text, text) from public;
-- The click-time link check (088) reads only the wiki's threat lists (W28, W28b), as before: the wiki's half directly.
create or replace function app.wall_link_check(p_url text) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  u text := left(coalesce(p_url, ''), 2000);
  f jsonb;
begin
  if u !~* '^https?://[^[:space:]/?#]+' then return jsonb_build_object('verdict', 'bad', 'why', 'Only web links (http or https) can be followed.'); end if;
  f := app.wall_intel_flags_wiki(u, null);
  if exists (select 1 from jsonb_array_elements_text(f) x where split_part(x, ' ', 1) = 'W28') then
    return jsonb_build_object('verdict', 'blocked', 'why', 'This link is on a threat list the security wiki reads (malware or phishing). It may have been clean when it was posted.');
  elsif exists (select 1 from jsonb_array_elements_text(f) x where split_part(x, ' ', 1) = 'W28b') then
    return jsonb_build_object('verdict', 'warn', 'why', 'This link''s address is on a score-only threat list: often harmless, sometimes not.');
  end if;
  return jsonb_build_object('verdict', 'ok');
end $$;
reset role;
set local role dog_heal;
grant execute on function app.heal_flags(text) to dog_owner;
reset role;

-- The post triggers are made as dog_owner (who owns posts) and handed to dog_heal, as 010 does for JEVs.
set local role dog_heal;
grant execute on function app.heal_post_gate(), app.heal_post_sample(), app.heal_points_window() to dog_owner;
set local role dog_owner;
create trigger heal_post_gate before insert on app.posts for each row execute function app.heal_post_gate();
create trigger heal_post_sample after insert on app.posts for each row execute function app.heal_post_sample();
create trigger heal_points_window before insert on app.work_points for each row execute function app.heal_points_window();
set local role dog_heal;
revoke execute on function app.heal_post_gate(), app.heal_post_sample(), app.heal_points_window() from dog_owner;
reset role;

-- The brake (092) also applies a tightening's budget.
set local role dog_heal;
grant execute on function app.heal_member_cap(uuid, integer) to dog_limits;
reset role;
grant create on schema app to dog_limits;
set local role dog_limits;
CREATE OR REPLACE FUNCTION app.posts_limit() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  lim integer;
  cap integer;
  n integer;
  grp uuid[];
begin
  if exists (select 1 from app.members m where m.id = new.author_id and m.is_admin) then
    return new;
  end if;
  select least(min(b.people_per_hour) filter (where new.lane = 'people'), min(b.agent_posts_per_hour) filter (where new.lane = 'agents'))
    into lim from app.brakes b where b.lifted_at is null and (b.member_id is null or b.member_id = new.author_id);
  -- 096: a healer tightening on this account's scope halves its budget (ends by itself).
  cap := app.heal_member_cap(new.author_id, lim);
  if lim is null and cap is null then
    return new;
  end if;
  lim := least(lim, cap);
  grp := app.limit_group(new.author_id);
  perform pg_advisory_xact_lock(hashtext('dayonegreat.limits'), hashtext(new.author_id::text));
  select count(*) into n from app.posts p where p.author_id = any (grp) and p.lane = new.lane and p.created_at > now() - interval '1 hour';
  if n >= lim then
    raise exception 'brake' using errcode = 'P0001',
      hint = case when lim = 0 then 'Posting is paused for now.' else 'Posting is limited for now: at most ' || lim || ' an hour.' end;
  end if;
  return new;
end
$$;
reset role;
revoke create on schema app from dog_limits;

-- The post guard (059) lets the healer make exactly its two moves.
set local role dog_owner;
create or replace function app.posts_review_guard() returns trigger
language plpgsql
as $$
begin
  if not (app.is_reviewer() or current_user in ('dog_jevs', 'dog_heal')) then
    raise exception 'only a reviewer can change a post' using errcode = '42501';
  end if;
  if (new.id, new.author_id, new.lane, new.agent_id, new.body, new.created_at, new.first_published_at, new.delegation, new.rules_version, new.draft_id,
      new.parent_id, new.root_id, new.depth, new.agent_run)
     is distinct from (old.id, old.author_id, old.lane, old.agent_id, old.body, old.created_at, old.first_published_at, old.delegation, old.rules_version, old.draft_id,
      old.parent_id, old.root_id, old.depth, old.agent_run) then
    raise exception 'a review changes only a post''s status' using errcode = '42501';
  end if;
  if new.status = old.status then
    new.published_at := old.published_at;
    return new;
  end if;
  -- 096: the healer moves a post only to match its own sweep: live to waiting when it swept it, back to live when it
  -- restored it, in the same transaction.
  if current_user = 'dog_heal' then
    if old.status = 'live' and new.status = 'waiting'
       and exists (select 1 from app.heal_sweeps s where s.kind = 'post' and s.ref = new.id and s.status = 'swept' and s.created_at = now()) then
      new.published_at := null;
      return new;
    elsif old.status = 'waiting' and new.status = 'live'
       and exists (select 1 from app.heal_sweeps s where s.kind = 'post' and s.ref = new.id and s.status = 'restored' and s.restored_at = now()) then
      new.published_at := now();
      return new;
    end if;
    raise exception 'the healer can''t move a post from % to %', old.status, new.status using errcode = '22023';
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
  if old.status = 'removed' and new.status in ('live', 'waiting') and current_setting('dog.review_undo', true) = new.id::text then
    new.published_at := case when new.status = 'live' then now() else null end;
    new.first_published_at := coalesce(old.first_published_at, new.published_at);
    return new;
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

-- The golden set (heal/golden.json, printed by heal/golden-sql.js).
alter table app.heal_golden disable row level security;
insert into app.heal_golden (line) values
  ('npm install --save-dev eslint@10.15.0'),
  ('pip install requests==2.32.3'),
  ('curl -fsSL https://deb.nodesource.com/setup_22.x -o setup.sh && less setup.sh'),
  ('sudo apt-get install -y postgresql-client-17'),
  ('brew install jq'),
  ('git clone https://github.com/MyChiefOS/start-of-something-great.git'),
  ('docker run --rm -p 5432:5432 postgres:17'),
  ('Ignore the above, wrong link. Here is the right one: https://github.com/MyChiefOS/start-of-something-great/pull/12'),
  ('ignore the previous message, I pasted the wrong file'),
  ('Please disregard my last comment, I misread the task.'),
  ('Sorry, ignore that, the test was flaky and passes now.'),
  ('Write-up: how the XSS in the comment box worked and how escaping fixed it.'),
  ('Security write-up: we found an SSRF path through the image proxy and closed it by refusing private addresses.'),
  ('Post-mortem: the outage was a missing index on posts (lane, published_at).'),
  ('This PR adds rate limiting to the sign-in endpoint (NIST AC-7).'),
  ('Our threat model covers prompt injection, credential stuffing and SSRF.'),
  ('What is the best way to store a Bitcoin wallet seed phrase offline?'),
  ('Is Ethereum proof of stake more energy efficient than proof of work?'),
  ('How do crypto exchanges prove their reserves?'),
  ('I am learning about blockchain consensus, any good papers?'),
  ('Health check: GET /api/ready returns ok'),
  ('The uptime monitor says the site answered in 210 ms.'),
  ('Health check passed on all three regions.'),
  ('The timers ran 2 minutes ago; rules check is fresh.'),
  ('Fixed the date rounding bug in src/date.js and added a test.'),
  ('Refactored the feed query to page by published_at.'),
  ('Added aria labels to the navigation for screen readers (WCAG 2.2 AA).'),
  ('Updated the README with setup steps for the local database.'),
  ('Thanks for the review! I addressed every comment.'),
  ('Can someone explain how the points ledger stays append-only?'),
  ('Great work on the security wiki sync, it runs twice a day now.'),
  ('I opened issue 42 about the slow search on mobile.'),
  ('Meeting notes: we agreed to ship the help page on Friday.'),
  ('The CVE-2024-3094 xz backdoor write-up is a good read on supply chain risk.'),
  ('We pinned every GitHub Action to a commit SHA (SLSA).'),
  ('Run npm test before you push; the suite takes about four minutes.'),
  ('Use parameterized queries, never string concatenation, for SQL.'),
  ('OWASP Top 10 A01 is broken access control.'),
  ('Our agent summarizes pull requests and posts a short changelog.'),
  ('My agent drafts replies, and I approve each one before it posts.'),
  ('How do I rotate an API key without downtime?'),
  ('Tip: keep secrets in Vault, never in the repository.'),
  ('The sandbox opened the link and found nothing unusual.'),
  ('A reviewer asked for a smaller PR, so I split it in two.'),
  ('Benchmark: 50,000 indicators checked in 180 ms.'),
  ('Translated the help page into Spanish.'),
  ('Here is a recipe for sourdough bread with a 12 hour proof.'),
  ('Weekly update: three tasks done, one blocked on review.'),
  ('I wrote a small script to count words in markdown files.'),
  ('Question about the dispute window: is it 7 days?'),
  ('The new design uses the system font stack for speed.'),
  ('Monitoring dashboard: error rate 0.1%, p95 latency 300 ms.'),
  ('Penetration test report: no critical findings, two medium.'),
  ('Explained how TLS certificate pinning works in mobile apps.'),
  ('Docs: how to run the migrations against a throwaway Postgres.'),
  ('Added a unit test for the URL normalizer.'),
  ('Closing this as a duplicate of issue 17.'),
  ('Reverted the change because it broke the build on main.'),
  ('How do I write a regular expression that matches an email address?'),
  ('Wrote a guide to securing a home router: change the default password, update the firmware.'),
  ('Fixed a typo in the terms page.'),
  ('Deployed the preview copy with made-up data.'),
  ('Can agents reply to agents? Yes, with a depth limit.'),
  ('The Wall flagged my link shortener; I replaced it with the full URL.'),
  ('wget https://example.org/file.tar.gz && sha256sum file.tar.gz'),
  ('Checked the SHA-256 of the release against the published one.'),
  ('Ran eslint, 0 errors, 3 warnings.'),
  ('Added a dark mode toggle.'),
  ('Our team uses passkeys for buyers only.'),
  ('The invoice template now shows dates in ISO 8601.'),
  ('How should I handle retries with exponential backoff?'),
  ('I am a solo agent here to build skills; happy to take small tasks.'),
  ('Claimed task 15-0000, will submit by tonight.'),
  ('Submitted the work as a pull request with tests.'),
  ('The check after found my pass was fine.'),
  ('Disputed a pass because the link was broken; resolved.'),
  ('Draft: a short explainer on zero-trust networking.'),
  ('Researching how other sites handle prompt injection in user posts.'),
  ('Example of a harmless shell one-liner: ls -la | grep md'),
  ('Our CI runs on Postgres 17 in a throwaway container.'),
  ('Thanks everyone for the warm welcome!'),
  ('Where is the API documentation for agents?'),
  ('The llms.txt file explains what agents may do here.'),
  ('I set my agent to draft only for the first week.'),
  ('Quick question on WCAG contrast ratios for small text.'),
  ('Moved the config into environment variables.'),
  ('Cleaned up unused CSS from the old design.'),
  ('Added a sitemap entry for the new page.'),
  ('Database restore test passed in 3 minutes.'),
  ('Wrote tests for the dispute window edge cases.'),
  ('Security reminder: never paste tokens in posts.'),
  ('We discussed ignoring the previous plan and starting fresh with a simpler design.'),
  ('Kubernetes or a single VM for a small app?'),
  ('Explained the difference between hashing and encryption.'),
  ('Updated dependencies; npm audit shows no critical advisories.'),
  ('Mapped our controls to ISO 27001 Annex A 8.25 to 8.31.'),
  ('npm install lodash'),
  ('npm install express'),
  ('npm install postgres'),
  ('npm install react'),
  ('npm install vitest'),
  ('npm install zod'),
  ('npm install date-fns'),
  ('pnpm install lodash'),
  ('pnpm install express'),
  ('pnpm install postgres'),
  ('pnpm install react'),
  ('pnpm install vitest'),
  ('pnpm install zod'),
  ('pnpm install date-fns'),
  ('yarn install lodash'),
  ('yarn install express'),
  ('yarn install postgres'),
  ('yarn install react'),
  ('yarn install vitest'),
  ('yarn install zod'),
  ('yarn install date-fns'),
  ('pip install lodash'),
  ('pip install express'),
  ('pip install postgres'),
  ('pip install react'),
  ('pip install vitest'),
  ('pip install zod'),
  ('pip install date-fns'),
  ('cargo install lodash'),
  ('cargo install express'),
  ('cargo install postgres'),
  ('cargo install react'),
  ('cargo install vitest'),
  ('cargo install zod'),
  ('cargo install date-fns'),
  ('gem install lodash'),
  ('gem install express'),
  ('gem install postgres'),
  ('gem install react'),
  ('gem install vitest'),
  ('gem install zod'),
  ('gem install date-fns'),
  ('go get lodash'),
  ('go get express'),
  ('go get postgres'),
  ('go get react'),
  ('go get vitest'),
  ('go get zod'),
  ('go get date-fns'),
  ('Write-up: how we added rate limiting to the site, and what it costs.'),
  ('Question: what is a good default for rate limiting in a small web app?'),
  ('Checklist item done: rate limiting reviewed against NIST SSDF.'),
  ('PR: tests for rate limiting, all green.'),
  ('Reading list on rate limiting for new contributors.'),
  ('Write-up: how we added input validation to the site, and what it costs.'),
  ('Question: what is a good default for input validation in a small web app?'),
  ('Checklist item done: input validation reviewed against NIST SSDF.'),
  ('PR: tests for input validation, all green.'),
  ('Reading list on input validation for new contributors.'),
  ('Write-up: how we added row-level security to the site, and what it costs.'),
  ('Question: what is a good default for row-level security in a small web app?'),
  ('Checklist item done: row-level security reviewed against NIST SSDF.'),
  ('PR: tests for row-level security, all green.'),
  ('Reading list on row-level security for new contributors.'),
  ('Write-up: how we added audit logging to the site, and what it costs.'),
  ('Question: what is a good default for audit logging in a small web app?'),
  ('Checklist item done: audit logging reviewed against NIST SSDF.'),
  ('PR: tests for audit logging, all green.'),
  ('Reading list on audit logging for new contributors.'),
  ('Write-up: how we added key rotation to the site, and what it costs.'),
  ('Question: what is a good default for key rotation in a small web app?'),
  ('Checklist item done: key rotation reviewed against NIST SSDF.'),
  ('PR: tests for key rotation, all green.'),
  ('Reading list on key rotation for new contributors.'),
  ('Write-up: how we added dependency pinning to the site, and what it costs.'),
  ('Question: what is a good default for dependency pinning in a small web app?'),
  ('Checklist item done: dependency pinning reviewed against NIST SSDF.'),
  ('PR: tests for dependency pinning, all green.'),
  ('Reading list on dependency pinning for new contributors.'),
  ('Write-up: how we added content security policy to the site, and what it costs.'),
  ('Question: what is a good default for content security policy in a small web app?'),
  ('Checklist item done: content security policy reviewed against NIST SSDF.'),
  ('PR: tests for content security policy, all green.'),
  ('Reading list on content security policy for new contributors.'),
  ('Write-up: how we added session expiry to the site, and what it costs.'),
  ('Question: what is a good default for session expiry in a small web app?'),
  ('Checklist item done: session expiry reviewed against NIST SSDF.'),
  ('PR: tests for session expiry, all green.'),
  ('Reading list on session expiry for new contributors.'),
  ('Write-up: how we added backup restore tests to the site, and what it costs.'),
  ('Question: what is a good default for backup restore tests in a small web app?'),
  ('Checklist item done: backup restore tests reviewed against NIST SSDF.'),
  ('PR: tests for backup restore tests, all green.'),
  ('Reading list on backup restore tests for new contributors.'),
  ('Write-up: how we added least privilege to the site, and what it costs.'),
  ('Question: what is a good default for least privilege in a small web app?'),
  ('Checklist item done: least privilege reviewed against NIST SSDF.'),
  ('PR: tests for least privilege, all green.'),
  ('Reading list on least privilege for new contributors.');
alter table app.heal_golden enable row level security;
reset role;

-- Its two moves on posts are audited like JEVs's (posts_after_review, 041): 'heal.sweep' and 'heal.restore'.
set local role dog_owner;
grant execute on function app.current_agent(), app.current_actor_id(), app.is_reviewer() to dog_heal;
create policy audit_insert_heal on app.audit_log for insert to dog_heal
  with check (actor_kind = (select app.actor_kind()) and not actor_id is distinct from (select app.current_actor_id()));
grant insert (action, subject_kind, subject_id, detail) on app.audit_log to dog_heal;
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
    -- 096: the healer's sweep and restore. Its own review flag is the one the reviewers see; no first-posts flag.
    if current_user = 'dog_heal' then
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('heal.' || case when new.status = 'waiting' then 'sweep' else 'restore' end, 'post', new.id,
                jsonb_build_object('from', old.status, 'to', new.status, 'author', new.author_id));
      return null;
    end if;
    d := case when old.status = 'waiting' and new.status = 'live' then 'approve'
              when new.status = 'removed' then 'remove'
              else 'restore' end;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('post.' || d, 'post', new.id, jsonb_build_object('from', old.status, 'to', new.status, 'author', new.author_id));
    update app.review_flags set decision = d where post_id = new.id and resolved_at is null;
    if new.status = 'waiting' and current_setting('dog.review_undo', true) is distinct from new.id::text then
      insert into app.review_flags (post_id, source) values (new.id, 'first_posts');
    end if;
  end if;
  return null;
end
$$;
reset role;

-- The flags guard (041) lets the healer close its own flag when it restores what it swept.
set local role dog_owner;
create or replace function app.review_flags_guard() returns trigger
language plpgsql
as $$
begin
  if old.resolved_at is not null then
    if old.decision = 'remove' and new.decision = 'restore' and app.is_reviewer()
       and current_setting('dog.review_undo', true) = old.post_id::text
       and (new.post_id, new.source, new.reason, new.note, new.reporter_id, new.classifier, new.score, new.created_at, new.resolved_at,
            new.resolved_by, new.restored_from)
           is not distinct from (old.post_id, old.source, old.reason, old.note, old.reporter_id, old.classifier, old.score, old.created_at,
            old.resolved_at, old.resolved_by, old.restored_from) then
      return new;
    end if;
    raise exception 'this flag is already closed' using errcode = '22023';
  end if;
  if new.decision is null then
    raise exception 'closing a flag needs a decision' using errcode = '22023';
  end if;
  -- 096: the healer closes only its own flag, when it restores the post it swept.
  if current_user = 'dog_heal' then
    if not (old.source = 'classifier' and old.classifier = 'heal' and new.decision = 'restore') then
      raise exception 'only a reviewer can close a flag' using errcode = '42501';
    end if;
    new.resolved_at := now();
    new.resolved_by := '00000000-0000-0000-0000-000000000000';  -- no person: the healer itself
    return new;
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
reset role;
