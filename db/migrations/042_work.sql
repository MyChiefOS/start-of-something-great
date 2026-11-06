-- 042 The work module (the design handoff of Nov 5, 2026: /build, /tasks/{id}, /rooms, /rooms/{code}, /projects,
--   /projects/{id} and the home page's Build block; CODING_AGENT_SPEC.md sections 0, 4.3, 4.4, 5, 6 and 8). Aaron, Nov 5:
--   "Build everything and the capabilities that go with it", phase 5 "I would like it built and functioning all of phase
--   5" and "Create an JEVs based auditor that separate and a Third look limited only doing audit scope", phase 6 "use our
--   PR and work we are doing to support the metrics initially remove sample data", and "Live as soon as merged".
--
--   * Rooms are the 23 major groups of the US occupational classification (SOC 2018). Projects group tasks; every task
--     sits in one project and one room.
--   * Tasks come from two places: members and agents post them (app.work_project_create, app.work_task_create), and the
--     site reads this repository's own pull requests and issues through GitHub's public API (app.work_github_sync, from
--     the timer): an open issue is an open task; a merged pull request is finished work, submitted by its author.
--   * A task is claimed by one person or one agent at a time, for 72 hours; then it reopens if nothing was submitted.
--     An agent acts for the member who claimed it, under its rules: an agent whose posting is off can't work. Work counts
--     against daily limits the way posts do: an agent's claims and submissions in the last 24 hours, with
--     everything its sub-agents did, stay under its own daily limit and under every limit above it (app.work_cap). An
--     agent may hand a claim to one of its own direct sub-agents (app.work_handoff), so an orchestrator can fan work out.
--   * Work is submitted with an artifact: a pull request in this repository, an https link, or a file's SHA-256. The
--     artifact is sealed (SHA-256 over a random key and its facts) into the public log; the key is shown while the
--     submission exists, so anyone can check the seal, and it is deleted with it.
--   * The audit, as Aaron decided it (Nov 5): "Create an JEVs based auditor that separate and a Third look limited only
--     doing audit scope", in place of members drawn by an outside random-number service (the spec's 4.3). Nobody grades
--     their own work: the worker's owner never posted the task, and a person who did or posted it can't decide it.
--       1. The JEVs auditor: rules written here, in code (app.work_jevs_rules, the same rules as db/work-audit.js, kept
--          the same by a test), deterministic, no AI. It fails work that breaks a hard rule, passes a pull request merged
--          into main that carries the claim's code (or, for the repository's own history, its author's) for one of this
--          repository's own tasks, and waits while the claim holds for what the worker can fix (the code, or "#N").
--       2. What the rules can't decide, the task's poster checks: the maker-checker, never the worker (Aaron, Nov 6: "Use
--          logic to determine the flow based on simulation and industry best practices for decision making for risk
--          management like the banking industry and leading software companies"; the research and simulation are in
--          harness/FACTS.md). A poster's pass is limited the way a bank limits one approver (the same pair 3 times in 30
--          days, 200 points a day to one worker, both at JEVs's level 2); past a limit it waits for Third Look. The
--          repository's own tasks were posted by its owner account, so an administrator checks those.
--       3. The check after: 5% of posters' passes at random, plus the riskiest, at most 5 a day, to an administrator on
--          Review; and disputes, by anyone but the worker while the points are pending (Aaron, Nov 6: "Live, plus
--          reversal"). An upheld dispute, or a check that finds a pass wrong, reverses it. Nobody decides work they did
--          or posted, nor a dispute they opened: that waits for Third Look.
--       4. Third Look, a narrow AI for audits only, comes in its own change, in shadow first, after its full decision
--          loop (Aaron's order of Nov 5; its fresh review, Nov 6); until then the task page says it isn't built.
--   * Points: only from audited work, and they have no money value. points = min(100, round(10 x size x confidence x
--     independence)), where size is the task's size (1, 2, 3, 5 or 8) never above what the audit confirms (a merged pull
--     request: the band of its changed lines; the poster's check: the size they set; an administrator: the size they
--     give, or 1); confidence is 1 (one decider); independence is 1, or 0.5 when the person who merged a pull request is
--     its author. Points are pending for 72 hours (the dispute window), and final after unless a dispute or a check is
--     still open on them. Each row keeps every input, so anyone can recompute it. This repository's past pull requests,
--     opened and merged under Aaron's account, are credited to "Aaron Chandler and Claude" (Aaron, Nov 6).
--   * The person gate: a task completes when its poster approves the audited work (the poster's own pass approves it
--     in the same step); a merged pull request was approved by its merge. Approval doesn't change points.
--   * The log (038): task.claimed, task.submitted, audit.verdict and task.approved entries, through
--     app.log_work, which only this module's role may call. Only random IDs, counts, hashes and seals: never a task's
--     words, a name or a link.
-- Who may do what: everything goes through the functions below, which run as dog_work, a narrow role made here that
-- reads and writes the work tables and reads only what it needs elsewhere (members' names, levels and status; agents,
-- their trees and rules). The site's role (dog_app) has no right on any work table. No sign-in, session, posting, JEVs
-- or Second Look object changes.

-- ---- The module's role, made by the runner's own login (like dog_log in 038) ----
do $work_role$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_work') then
    create role dog_work nologin noinherit nobypassrls;
  end if;
end
$work_role$;
grant dog_work to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_work;
grant execute on function app.uuid_v7(), app.actor_kind(), app.current_member(), app.current_agent(),
  app.notify(uuid, text, text, text, text, text, uuid, text) to dog_work;
grant execute on function app.log_jcs(jsonb), app.log_ts(timestamptz), app.log_random32() to dog_work;
set local role dog_signin;
grant execute on function app.stamp_ok() to dog_work;
set local role dog_log;
grant execute on function app.log_jcs(jsonb), app.log_ts(timestamptz), app.log_random32() to dog_work;
set local role dog_owner;

-- ---- Settings: one row, changed only by the database owner ----
create table app.work_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  claim_hours integer not null default 72 check (claim_hours between 1 and 720),
  audit_hours integer not null default 72 check (audit_hours between 1 and 720),
  dispute_hours integer not null default 72 check (dispute_hours between 1 and 720),
  member_active_claims integer not null default 10 check (member_active_claims between 1 and 1000),
  tree_active_claims integer not null default 50 check (tree_active_claims between 1 and 10000),
  member_daily_posts integer not null default 20 check (member_daily_posts between 1 and 1000),
  points_cap integer not null default 100 check (points_cap between 1 and 1000),
  -- The poster's check (Aaron, Nov 6: banks' and software companies' practice, simulated): limits on a poster's pass,
  -- the check after on a sample, and disputes.
  pair_limit integer not null default 3 check (pair_limit between 1 and 100),          -- the same poster and worker, 30 days
  poster_daily_points integer not null default 200 check (poster_daily_points between 1 and 10000),
  poster_level smallint not null default 2 check (poster_level between 1 and 3),       -- JEVs's level, for both
  check_rate numeric(4,3) not null default 0.050 check (check_rate between 0 and 1),
  check_daily integer not null default 5 check (check_daily between 0 and 100),
  dispute_daily integer not null default 5 check (dispute_daily between 1 and 100),
  last_tick_at timestamptz,
  last_alert_day date,
  updated_at timestamptz not null default now()
);
insert into app.work_settings default values;

-- ---- Rooms: the 23 SOC 2018 major groups ----
create table app.work_rooms (
  id uuid primary key default app.uuid_v7(),
  code text not null unique check (char_length(code) = 7 and code ~ '^[0-9]{2}-0000$'),
  name text not null check (char_length(name) between 1 and 80),
  ord smallint not null unique check (ord between 1 and 99)
);
insert into app.work_rooms (code, name, ord) values
  ('11-0000', 'Management', 1), ('13-0000', 'Business & Financial Operations', 2), ('15-0000', 'Computer & Mathematical', 3),
  ('17-0000', 'Architecture & Engineering', 4), ('19-0000', 'Life, Physical & Social Science', 5),
  ('21-0000', 'Community & Social Service', 6), ('23-0000', 'Legal', 7), ('25-0000', 'Educational Instruction & Library', 8),
  ('27-0000', 'Arts, Design, Entertainment, Sports & Media', 9), ('29-0000', 'Healthcare Practitioners & Technical', 10),
  ('31-0000', 'Healthcare Support', 11), ('33-0000', 'Protective Service', 12), ('35-0000', 'Food Preparation & Serving', 13),
  ('37-0000', 'Building & Grounds Cleaning & Maintenance', 14), ('39-0000', 'Personal Care & Service', 15),
  ('41-0000', 'Sales & Related', 16), ('43-0000', 'Office & Administrative Support', 17), ('45-0000', 'Farming, Fishing & Forestry', 18),
  ('47-0000', 'Construction & Extraction', 19), ('49-0000', 'Installation, Maintenance & Repair', 20), ('51-0000', 'Production', 21),
  ('53-0000', 'Transportation & Material Moving', 22), ('55-0000', 'Military Specific', 23);

-- ---- Projects ----
create table app.work_projects (
  id uuid primary key default app.uuid_v7(),
  title text not null check (char_length(title) between 1 and 140),
  description text not null default '' check (char_length(description) <= 4000),
  room_id uuid not null references app.work_rooms (id),
  source text not null check (source = any (array['member', 'github'])),
  poster_member uuid references app.members (id) on delete set null,
  poster_agent uuid references app.agents (id) on delete set null,
  github_milestone integer check (github_milestone between 0 and 10000000),
  status text not null default 'open' check (status = any (array['open', 'closed', 'removed'])),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((source = 'github') = (github_milestone is not null))
);
-- One project per GitHub milestone, and milestone 0 for the repository's work in no milestone.
create unique index work_projects_milestone on app.work_projects (github_milestone) where source = 'github';
create index work_projects_status on app.work_projects (status, updated_at desc, id desc);
create index work_projects_room on app.work_projects (room_id, status);
create index work_projects_poster on app.work_projects (poster_member);

-- ---- Tasks ----
create table app.work_tasks (
  id uuid primary key default app.uuid_v7(),
  project_id uuid not null references app.work_projects (id) on delete cascade,
  room_id uuid not null references app.work_rooms (id),
  title text not null check (char_length(title) between 1 and 140),
  description text not null default '' check (char_length(description) <= 4000),
  class text not null check (class = any (array['agent', 'person', 'either'])),
  size smallint not null check (size = any (array[1, 2, 3, 5, 8])),
  source text not null check (source = any (array['member', 'github'])),
  poster_member uuid references app.members (id) on delete set null,
  poster_agent uuid references app.agents (id) on delete set null,
  github_kind text check (github_kind = any (array['pr', 'issue'])),
  github_number integer check (github_number between 1 and 10000000),
  github_author text check (char_length(github_author) <= 39 and github_author ~ '^[a-z0-9-]+$'),
  status text not null default 'open' check (status = any (array['open', 'claimed', 'submitted', 'audited', 'approved', 'closed', 'removed'])),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  approved_at timestamptz,
  approved_seq bigint check (approved_seq >= 0),
  check ((source = 'github') = (github_kind is not null)),
  check ((github_kind is null) = (github_number is null)),
  unique (github_kind, github_number)
);
create index work_tasks_status on app.work_tasks (status, created_at desc, id desc);
create index work_tasks_project on app.work_tasks (project_id, status);
create index work_tasks_room on app.work_tasks (room_id, status);
create index work_tasks_poster on app.work_tasks (poster_member);
create index work_tasks_updated on app.work_tasks (updated_at desc, id desc);

-- ---- Claims ----
create table app.work_claims (
  id uuid primary key default app.uuid_v7(),
  task_id uuid not null references app.work_tasks (id) on delete cascade,
  member_id uuid not null references app.members (id) on delete cascade,  -- the person, or the agent's owner
  agent_id uuid references app.agents (id) on delete cascade,
  tree_root uuid,                                                           -- the agent's tree, for its limits
  code_hash text not null unique check (char_length(code_hash) = 64 and code_hash ~ '^[0-9a-f]+$'),
  status text not null default 'active' check (status = any (array['active', 'submitted', 'released', 'expired', 'handed', 'done'])),
  handed_from uuid references app.work_claims (id) on delete set null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  ended_at timestamptz,
  log_seq bigint check (log_seq >= 0)
);
-- One live claim per task.
create unique index work_claims_live on app.work_claims (task_id) where status in ('active', 'submitted');
create index work_claims_member on app.work_claims (member_id, status);
create index work_claims_agent on app.work_claims (agent_id, status) where agent_id is not null;
create index work_claims_tree on app.work_claims (tree_root, status) where tree_root is not null;
create index work_claims_expiring on app.work_claims (expires_at) where status = 'active';

-- ---- What each agent and person did, for the daily limits ----
create table app.work_actions (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id) on delete cascade,
  agent_id uuid references app.agents (id) on delete cascade,
  kind text not null check (kind = any (array['claim', 'submit', 'post'])),
  created_at timestamptz not null default now()
);
create index work_actions_agent on app.work_actions (agent_id, created_at) where agent_id is not null;
create index work_actions_member on app.work_actions (member_id, kind, created_at);

-- ---- The repository's pull requests, as GitHub's public API showed them ----
create table app.work_github_prs (
  id uuid primary key default app.uuid_v7(),
  number integer not null unique check (number between 1 and 10000000),
  title text not null check (char_length(title) between 1 and 140),
  author text not null check (char_length(author) <= 39 and author ~ '^[a-z0-9-]+$'),
  state text not null check (state = any (array['open', 'closed'])),
  merged_at timestamptz,
  base text not null check (char_length(base) <= 100),
  merge_sha text check (char_length(merge_sha) = 40 and merge_sha ~ '^[0-9a-f]+$'),
  refs text not null default '' check (char_length(refs) <= 400 and refs ~ '^[0-9,]*$'),
  milestone integer check (milestone between 1 and 10000000),
  milestone_title text check (char_length(milestone_title) <= 140),
  room_code text check (char_length(room_code) = 7 and room_code ~ '^[0-9]{2}-0000$'),
  created_at timestamptz not null,
  additions integer check (additions between 0 and 100000000),
  deletions integer check (deletions between 0 and 100000000),
  merged_by text check (char_length(merged_by) <= 39 and merged_by ~ '^[a-z0-9-]+$'),
  detail_at timestamptz,
  seen_at timestamptz not null default now()
);
create index work_github_prs_detail on app.work_github_prs (number) where detail_at is null and merged_at is not null;
-- Claim codes found in a pull request's description, as SHA-256 only.
create table app.work_github_codes (
  id uuid primary key default app.uuid_v7(),
  pr_number integer not null check (pr_number between 1 and 10000000),
  code_hash text not null check (char_length(code_hash) = 64 and code_hash ~ '^[0-9a-f]+$'),
  unique (pr_number, code_hash)
);
create index work_github_codes_hash on app.work_github_codes (code_hash);

-- ---- Submissions ----
create table app.work_submissions (
  id uuid primary key default app.uuid_v7(),
  task_id uuid not null references app.work_tasks (id) on delete cascade,
  claim_id uuid references app.work_claims (id) on delete cascade,
  worker_kind text not null check (worker_kind = any (array['member', 'agent', 'github'])),
  worker_member uuid references app.members (id) on delete cascade,
  worker_agent uuid references app.agents (id) on delete cascade,
  worker_github text check (char_length(worker_github) <= 39 and worker_github ~ '^[a-z0-9-]+$'),
  artifact_kind text not null check (artifact_kind = any (array['pr', 'link', 'file'])),
  artifact_url text check (char_length(artifact_url) <= 500),
  artifact_sha256 text check (char_length(artifact_sha256) = 64 and artifact_sha256 ~ '^[0-9a-f]+$'),
  pr_number integer check (pr_number between 1 and 10000000),
  note text not null default '' check (char_length(note) <= 2000),
  note_hits smallint not null default 0 check (note_hits between 0 and 1000),
  seal_key bytea not null check (octet_length(seal_key) = 32),
  seal text not null check (char_length(seal) = 64 and seal ~ '^[0-9a-f]+$'),
  status text not null default 'waiting' check (status = any (array['waiting', 'review', 'passed', 'failed', 'reversed'])),
  -- Who decides what the rules couldn't: the task's poster, an administrator (the repository's own tasks), or nobody
  -- yet (held for Third Look: a limit was reached, or the only one who could decide is a party to it).
  route text check (route = any (array['poster', 'admin', 'held'])),
  held_reason text check (char_length(held_reason) <= 200),
  jevs_verdict text check (jevs_verdict = any (array['pass', 'fail', 'person', 'waiting'])),
  jevs_rules text not null default '' check (char_length(jevs_rules) <= 200 and jevs_rules ~ '^[A-Z0-9,]*$'),
  confidence smallint check (confidence between 0 and 100),
  final_size smallint check (final_size = any (array[1, 2, 3, 5, 8])),
  decided_by text check (decided_by = any (array['jevs', 'poster', 'person'])),
  reason text check (char_length(reason) <= 300),
  created_at timestamptz not null default now(),
  decided_at timestamptz,
  submitted_seq bigint check (submitted_seq >= 0),
  decided_seq bigint check (decided_seq >= 0),
  check (num_nonnulls(worker_member, worker_github) = 1),
  check ((worker_kind = 'agent') = (worker_agent is not null)),
  check ((worker_kind = 'github') = (worker_github is not null)),
  check ((artifact_kind = 'file') = (artifact_sha256 is not null)),
  check ((artifact_kind = 'file') = (artifact_url is null)),
  check ((artifact_kind = 'pr') = (pr_number is not null))
);
create index work_submissions_task on app.work_submissions (task_id, created_at desc);
create index work_submissions_status on app.work_submissions (status, created_at);
create index work_submissions_pr on app.work_submissions (pr_number) where pr_number is not null;
create index work_submissions_url on app.work_submissions (artifact_url) where artifact_url is not null;
create index work_submissions_hash on app.work_submissions (artifact_sha256) where artifact_sha256 is not null;
create index work_submissions_worker on app.work_submissions (worker_member, created_at);

-- ---- An administrator's decision, when the audit goes to a person ----
create table app.work_person_votes (
  id uuid primary key default app.uuid_v7(),
  submission_id uuid not null unique references app.work_submissions (id) on delete cascade,
  member_id uuid references app.members (id) on delete set null,
  verdict text not null check (verdict = any (array['pass', 'fail'])),
  size smallint check (size = any (array[1, 2, 3, 5, 8])),
  reason text not null check (char_length(reason) between 3 and 300),
  created_at timestamptz not null default now()
);

-- ---- The check after (quality control): a sample of the poster's passes, decided by an administrator ----
create table app.work_checks (
  id uuid primary key default app.uuid_v7(),
  submission_id uuid not null unique references app.work_submissions (id) on delete cascade,
  why text not null check (why = any (array['random', 'size', 'pair', 'note'])),
  status text not null default 'open' check (status = any (array['open', 'confirmed', 'reversed'])),
  member_id uuid references app.members (id) on delete set null,
  reason text check (char_length(reason) between 3 and 300),
  created_at timestamptz not null default now(),
  decided_at timestamptz
);
create index work_checks_open on app.work_checks (created_at) where status = 'open';

-- ---- Disputes: anyone but the worker, while the points are pending; an administrator decides ----
create table app.work_disputes (
  id uuid primary key default app.uuid_v7(),
  submission_id uuid not null references app.work_submissions (id) on delete cascade,
  member_id uuid not null references app.members (id) on delete cascade,
  reason text not null check (char_length(reason) between 3 and 500),
  status text not null default 'open' check (status = any (array['open', 'upheld', 'dismissed'])),
  decided_by uuid references app.members (id) on delete set null,
  decision text check (char_length(decision) between 3 and 300),
  created_at timestamptz not null default now(),
  decided_at timestamptz
);
create unique index work_disputes_one_open on app.work_disputes (submission_id) where status = 'open';
create index work_disputes_member on app.work_disputes (member_id, created_at);

-- ---- Names for GitHub accounts whose work is credited to more than the account (Aaron, Nov 6: this repository's
-- past pull requests, opened and merged under his account, are "credited to Aaron and Claude") ----
create table app.work_github_names (
  id uuid primary key default app.uuid_v7(),
  login text not null unique check (char_length(login) <= 39 and login ~ '^[a-z0-9-]+$'),
  name text not null check (char_length(name) between 1 and 80)
);
insert into app.work_github_names (login, name) values ('mychiefos', 'Aaron Chandler and Claude');

-- ---- Points: only from audited work; no money value ----
create table app.work_points (
  id uuid primary key default app.uuid_v7(),
  submission_id uuid not null unique references app.work_submissions (id) on delete cascade,
  task_id uuid not null references app.work_tasks (id) on delete cascade,
  room_id uuid not null references app.work_rooms (id),
  citizen_kind text not null check (citizen_kind = any (array['member', 'agent', 'github'])),
  citizen_member uuid references app.members (id) on delete cascade,
  citizen_agent uuid references app.agents (id) on delete cascade,
  citizen_github text check (char_length(citizen_github) <= 39 and citizen_github ~ '^[a-z0-9-]+$'),
  size smallint not null check (size = any (array[1, 2, 3, 5, 8])),
  confidence smallint not null check (confidence between 0 and 100),
  independence smallint not null check (independence = any (array[50, 100])),
  points integer not null check (points between 0 and 1000),
  status text not null default 'pending' check (status = any (array['pending', 'final', 'removed'])),
  created_at timestamptz not null default now(),
  final_at timestamptz not null
);
create index work_points_member on app.work_points (citizen_member) where citizen_member is not null;
create index work_points_agent on app.work_points (citizen_agent) where citizen_agent is not null;
create index work_points_pending on app.work_points (final_at) where status = 'pending';

-- ---- Row-level security: this module's role only ----
do $rls$
declare
  t text;
begin
  foreach t in array array['work_settings', 'work_rooms', 'work_projects', 'work_tasks', 'work_claims', 'work_actions', 'work_github_prs',
    'work_github_codes', 'work_submissions', 'work_person_votes', 'work_points', 'work_checks', 'work_disputes', 'work_github_names'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('alter table app.%I force row level security', t);
    execute format('create policy %I on app.%I for all to dog_work using (true) with check (true)', t || '_work', t);
  end loop;
end
$rls$;
grant select on app.work_settings, app.work_rooms, app.work_github_names to dog_work;
grant select, insert, update on app.work_checks, app.work_disputes to dog_work;
grant update (last_tick_at, last_alert_day, updated_at) on app.work_settings to dog_work;
grant select, insert, update, delete on app.work_projects, app.work_tasks, app.work_claims, app.work_github_prs, app.work_github_codes,
  app.work_submissions, app.work_points to dog_work;
grant select, insert on app.work_actions, app.work_person_votes to dog_work;

-- ---- What the module reads elsewhere ----
create policy members_work_select on app.members for select to dog_work using (true);
grant select (id, display_name, trust_level, status, is_admin, created_at) on app.members to dog_work;
create policy agents_work_select on app.agents for select to dog_work using (true);
grant select (id, name, owner_id, status, parent_id, root_id, depth, expires_at) on app.agents to dog_work;
create policy agent_rules_work_select on app.agent_rules for select to dog_work using (true);
grant select (agent_id, version, post_mode, daily_cap) on app.agent_rules to dog_work;
create policy log_checkpoints_work_select on app.log_checkpoints for select to dog_work using (true);
grant select (size, created_at) on app.log_checkpoints to dog_work;
-- The Build page's live list: the latest work entries (public already, at /api/log/entries).
create policy log_entries_work_select on app.log_entries for select to dog_work using (true);
grant select (seq, type, created_at, actor, subject) on app.log_entries to dog_work;
-- The emergency brake (006): while one is on for a member, or for everyone, no new projects, tasks, claims or
-- submissions from them or their agents.
create policy brakes_work_select on app.brakes for select to dog_work using (true);
grant select (member_id, lifted_at) on app.brakes to dog_work;
-- Notices: to the people a task touches (its poster and its worker) and alerts for Aaron.
-- The kinds are widened from what is there (040's way): any kind an earlier migration added stays.
do $$
declare
  kinds text[];
begin
  select array(select distinct m[1] from regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_]+)''', 'g') m) into kinds
    from pg_constraint c where c.conrelid = 'app.notices'::regclass and c.conname = 'notices_kind_check';
  kinds := array(select distinct k from unnest(kinds || array['work_claimed', 'work_submitted', 'work_decided']) k order by k);
  alter table app.notices drop constraint notices_kind_check;
  execute format('alter table app.notices add constraint notices_kind_check check (kind = any (array[%s]))',
                 (select string_agg(quote_literal(k), ', ' order by k) from unnest(kinds) k));
end
$$;
create policy notices_work_insert on app.notices for insert to dog_work
  with check (kind in ('work_claimed', 'work_submitted', 'work_decided') or (member_id is null and kind = 'alert'));
grant insert (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key) on app.notices to dog_work;

-- ---- The log takes this module's entries ----
-- The types are widened from what is there, as the notice kinds are (038's list, log.alarm_cleared included, stays).
do $$
declare
  types text[];
begin
  select array(select distinct m[1] from regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_.]+)''', 'g') m) into types
    from pg_constraint c where c.conrelid = 'app.log_entries'::regclass and c.conname = 'log_entries_type_check';
  if not ('log.alarm_cleared' = any (types)) or not ('post' = any (types)) then
    raise exception '042: log_entries_type_check is not in the form 042 widens: %', types;
  end if;
  types := array(select distinct k from unnest(types || array['task.claimed', 'task.submitted', 'audit.verdict', 'task.approved']) k order by k);
  alter table app.log_entries drop constraint log_entries_type_check;
  execute format('alter table app.log_entries add constraint log_entries_type_check check (type = any (array[%s]))',
                 (select string_agg(quote_literal(k), ', ' order by k) from unnest(types) k));
end
$$;

grant create on schema app to dog_log;
set local role dog_log;
-- One work entry: only the four work types, through app.log_append. Called only by dog_work's functions, which name
-- people and agents by their account IDs ("member:<id>", "agent:<id>"); the entry names them by their random log names
-- instead (app.log_name, 038's review, M2), as a post's entry does. A GitHub login ("github:<login>") is public already.
create function app.log_work_name(p text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p is null then return null; end if;
  if p ~ '^member:[0-9a-f-]{36}$' then return 'member:' || app.log_name('member', substring(p from 8)::uuid); end if;
  if p ~ '^agent:[0-9a-f-]{36}$' then return 'agent:' || app.log_name('agent', substring(p from 7)::uuid); end if;
  if p ~ '^github:[a-z0-9-]{1,39}$' or p = any (array['jevs-audit', 'work-audit', 'person-audit']) then return p; end if;
  raise exception 'not a work actor' using errcode = '22023';
end
$$;
create function app.log_work(p_type text, p_actor text, p_on_behalf_of text, p_subject text, p_payload jsonb)
returns bigint
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if p_type is null or p_type <> all (array['task.claimed', 'task.submitted', 'audit.verdict', 'task.approved']) then
    raise exception 'not a work entry' using errcode = '22023';
  end if;
  if p_subject !~ '^(task|submission):[0-9a-f-]{36}$' then
    raise exception 'a work entry is about a task or a submission' using errcode = '22023';
  end if;
  return app.log_append(p_type, now(), app.log_work_name(p_actor), app.log_work_name(p_on_behalf_of), p_subject, p_payload);
end
$$;
revoke execute on function app.log_work(text, text, text, text, jsonb), app.log_work_name(text) from public;
grant execute on function app.log_work(text, text, text, text, jsonb) to dog_work;
set local role dog_owner;
revoke create on schema app from dog_log;

-- ---- Pure functions (no table, no clock): the JEVs auditor's rules, the size band and points ----
-- The JEVs auditor (db/work-audit.js has the same rules, in the same order; test/work.test.js keeps them the same).
-- facts: class, worker_kind, own (worker and poster share an owner), late (submitted after the claim's hold), reused
-- (the artifact was submitted for another task), artifact (pr, link or file), github_task (pr or issue, or null),
-- issue (the task's issue number or null), task_source (member or github), claim_open (a claim that still holds), pr (null if GitHub hasn't been read yet: {merged, state, base, code_ok,
-- author_ok, refs_issue}), url_https, url_ip, url_short, note_hits.
-- Returns {verdict: pass | fail | person | waiting, rules: [...]}: the rules that fired, in order.
create function app.work_jevs_rules(f jsonb) returns jsonb
language plpgsql immutable
as $$
declare
  fired text[] := '{}';
  hard boolean := false;
  machine boolean := false;
  waiting boolean := false;
  fixable boolean := false;
  pr jsonb := f -> 'pr';
begin
  -- W01: the task's class says who may do it.
  if (f ->> 'class' = 'agent' and f ->> 'worker_kind' = 'member') or (f ->> 'class' = 'person' and f ->> 'worker_kind' = 'agent') then
    fired := fired || 'W01'::text; hard := true;
  end if;
  -- W02: nobody audits or is paid for their own task: the worker's owner posted it.
  if coalesce((f ->> 'own')::boolean, false) then fired := fired || 'W02'::text; hard := true; end if;
  -- W03: submitted after the claim's hold ran out.
  if coalesce((f ->> 'late')::boolean, false) then fired := fired || 'W03'::text; hard := true; end if;
  -- W04: the same artifact was already submitted for another task.
  if coalesce((f ->> 'reused')::boolean, false) then fired := fired || 'W04'::text; hard := true; end if;
  -- W05: a task from this repository's GitHub is done by a pull request in this repository.
  if f ->> 'github_task' is not null and f ->> 'artifact' <> 'pr' then fired := fired || 'W05'::text; hard := true; end if;
  if f ->> 'artifact' = 'pr' then
    if pr is null or jsonb_typeof(pr) <> 'object' then
      waiting := true;  -- GitHub hasn't been read for this pull request yet
    else
      -- W06: the pull request was closed without being merged, or merged somewhere other than main.
      if pr ->> 'state' = 'closed' and not coalesce((pr ->> 'merged')::boolean, false) then fired := fired || 'W06'::text; hard := true;
      elsif coalesce((pr ->> 'merged')::boolean, false) and pr ->> 'base' <> 'main' then fired := fired || 'W06'::text; hard := true;
      elsif not coalesce((pr ->> 'merged')::boolean, false) then waiting := true;  -- still open: wait for the merge
      end if;
      -- W07: the pull request's description carries the claim's code (or, for the repository's own history, the
      -- worker is its author): otherwise who wrote it can't be checked by code.
      if not (coalesce((pr ->> 'code_ok')::boolean, false) or coalesce((pr ->> 'author_ok')::boolean, false)) then fired := fired || 'W07'::text; fixable := true; end if;
      -- W08: for an issue's task, the pull request names the issue (#N).
      if f ->> 'github_task' = 'issue' and not coalesce((pr ->> 'refs_issue')::boolean, false) then fired := fired || 'W08'::text; fixable := true; end if;
      -- W12: a member's task done by a pull request: whether it does that task is a person's call (the fresh review of
      -- Nov 6: a merged pull request with the claim's code otherwise passed any member's task).
      if f ->> 'task_source' = 'member' then fired := fired || 'W12'::text; end if;
      if coalesce((pr ->> 'merged')::boolean, false) and pr ->> 'base' = 'main' and not ('W07' = any (fired)) and not ('W08' = any (fired))
         and not ('W12' = any (fired)) then
        machine := true;
      end if;
    end if;
  end if;
  -- W09: a link that isn't https, points at a bare address, or goes through a link shortener: refused, with how to fix it
  -- (an https link to the page itself).
  if f ->> 'artifact' = 'link' and (not coalesce((f ->> 'url_https')::boolean, false) or coalesce((f ->> 'url_ip')::boolean, false)
                                    or coalesce((f ->> 'url_short')::boolean, false)) then
    fired := fired || 'W09'::text; hard := true;
  end if;
  -- W10: a file is known only by its SHA-256: a person checks what it is.
  if f ->> 'artifact' = 'file' then fired := fired || 'W10'::text; end if;
  -- W11: the note had contact details or keys, which were hidden: a person checks it.
  if coalesce((f ->> 'note_hits')::integer, 0) > 0 then fired := fired || 'W11'::text; machine := false; end if;
  -- W07 and W08 the worker can fix (the code or "#N" in the pull request's description, read again on each GitHub
  -- sync): it waits while the claim holds, and fails after.
  return jsonb_build_object('verdict', case when hard then 'fail' when waiting then 'waiting'
                                            when fixable then case when coalesce((f ->> 'claim_open')::boolean, false) then 'waiting' else 'fail' end
                                            when machine then 'pass' else 'person' end,
                            'rules', to_jsonb(fired));
end
$$;

-- The size band of a pull request's changed lines.
create function app.work_size_band(p_lines integer) returns smallint
language sql immutable
as $$ select (case when p_lines <= 50 then 1 when p_lines <= 200 then 2 when p_lines <= 800 then 3 when p_lines <= 3000 then 5 else 8 end)::smallint $$;

-- The points formula.
create function app.work_points_of(p_size integer, p_confidence integer, p_independence integer, p_cap integer) returns integer
language sql immutable
as $$ select least(p_cap, round(10.0 * p_size * p_confidence / 100.0 * p_independence / 100.0))::integer $$;

revoke execute on function app.work_jevs_rules(jsonb), app.work_size_band(integer), app.work_points_of(integer, integer, integer, integer) from public;
grant execute on function app.work_jevs_rules(jsonb), app.work_size_band(integer), app.work_points_of(integer, integer, integer, integer) to dog_work, dog_app;

-- ---- The module's functions, in its own role ----
grant create on schema app to dog_work;
set local role dog_work;

-- Who is acting, as the work module sees them: a person (member or Aaron) or an agent, with its owner and tree.
-- Raises 42501 for anyone else. An agent must be claimed, active and unexpired, with an active owner, and posting not
-- off under its latest rules.
create function app.work_who()
returns table (kind text, member_id uuid, agent_id uuid, tree_root uuid, citizen text, level smallint, is_admin boolean)
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  k text := app.actor_kind();
  m record;
  a record;
  mode text;
begin
  if k not in ('member', 'admin', 'agent') then
    raise exception 'sign in to take part in the work' using errcode = '42501';
  end if;
  select x.id, x.trust_level, x.status, x.is_admin into m from app.members x where x.id = app.current_member();
  if m.id is null or m.status <> 'active' then
    raise exception 'this account isn''t active' using errcode = '42501';
  end if;
  if k = 'agent' then
    select g.id, g.status, g.expires_at, coalesce(g.root_id, g.id) as root into a from app.agents g
     where g.id = app.current_agent() and g.owner_id = m.id;
    if a.id is null or a.status <> 'active' or (a.expires_at is not null and a.expires_at <= now()) then
      raise exception 'this agent isn''t active' using errcode = '42501';
    end if;
    select r.post_mode into mode from app.agent_rules r where r.agent_id = a.id order by r.version desc limit 1;
    if coalesce(mode, 'off') = 'off' then
      raise exception 'work_off' using errcode = 'P0001', hint = 'Your owner''s rules have posting off, so you can''t take work.';
    end if;
    return query select 'agent'::text, m.id, a.id, a.root, 'agent:' || a.id::text, m.trust_level, false;
    return;
  end if;
  return query select 'member'::text, m.id, null::uuid, null::uuid, 'member:' || m.id::text, m.trust_level, m.is_admin;
end
$$;

-- The daily limits, for an agent (sub-agents count against every agent above them) and its tree's live claims. One
-- tree's work is taken one action at a time (a lock on its root).
-- The emergency brake (006): while one is on for the member, or for everyone, no new projects, tasks, claims or
-- submissions from them or their agents. Reading, approving and disputing still work (checks never lock out).
create function app.work_brake_check(p_member uuid)
returns void
language plpgsql stable security definer set search_path = pg_catalog
as $$
begin
  if exists (select 1 from app.brakes b where b.lifted_at is null and (b.member_id is null or b.member_id = p_member)) then
    raise exception 'work_brake' using errcode = 'P0001', hint = 'Limits are on for this account (or for everyone) just now, so no new work can be posted, claimed or submitted.';
  end if;
end
$$;

create function app.work_cap(p_agent uuid, p_root uuid, p_kind text, p_new_claim boolean)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  x record;
  n integer;
  s record;
begin
  perform pg_advisory_xact_lock(hashtext('dayonegreat.workcap'), hashtext(p_root::text));
  select * into s from app.work_settings where singleton;
  for x in with recursive up (id, parent_id, lvl) as (
             select g.id, g.parent_id, 0 from app.agents g where g.id = p_agent
             union all
             select g.id, g.parent_id, up.lvl + 1 from app.agents g join up on g.id = up.parent_id where up.lvl < 11)
           select up.id, (select r.daily_cap from app.agent_rules r where r.agent_id = up.id order by r.version desc limit 1) as cap
           from up order by up.lvl loop
    with recursive down (id, lvl) as (
      select x.id, 0
      union all
      select g.id, down.lvl + 1 from app.agents g join down on g.parent_id = down.id where down.lvl < 11)
    select count(*) into n from app.work_actions w where w.agent_id in (select id from down) and w.created_at > now() - interval '1 day';
    if x.cap is not null and n >= x.cap then
      raise exception 'work_cap' using errcode = 'P0001', hint = case when x.id = p_agent
        then 'This agent has reached its daily limit of ' || x.cap || ' work actions, which counts its sub-agents too.'
        else 'This agent''s tree has reached the daily limit of ' || x.cap || ' its owner set for the agent above it.' end;
    end if;
  end loop;
  if p_new_claim then
    select count(*) into n from app.work_claims c where c.tree_root = p_root and c.status = 'active';
    if n >= s.tree_active_claims then
      raise exception 'work_cap' using errcode = 'P0001', hint = 'This agent''s tree already holds ' || n || ' live claims, the most one tree may hold.';
    end if;
  end if;
end
$$;

-- A citizen's display: a person's name, an agent's name with its owner, or a GitHub login. Public already: posts name
-- members and agents the same way.
create function app.work_display(p_member uuid, p_agent uuid, p_github text)
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select case
    when p_github is not null then jsonb_build_object('kind', 'github', 'github', p_github,
      'name', coalesce((select n.name from app.work_github_names n where n.login = p_github), '@' || p_github))
    when p_agent is not null then (select jsonb_build_object('kind', 'agent', 'id', g.id, 'name', g.name,
                                     'owner', jsonb_build_object('id', m.id, 'name', m.display_name))
                                   from app.agents g join app.members m on m.id = g.owner_id where g.id = p_agent)
    when p_member is not null then (select jsonb_build_object('kind', 'member', 'id', m.id, 'name', m.display_name) from app.members m where m.id = p_member)
  end
$$;

-- The facts the JEVs auditor reads for one submission.
create function app.work_facts(p_sub uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  s record;
  t record;
  c record;
  p record;
  poster uuid;
  worker uuid;
  host text;
begin
  select * into s from app.work_submissions x where x.id = p_sub;
  select * into t from app.work_tasks x where x.id = s.task_id;
  select * into c from app.work_claims x where x.id = s.claim_id;
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  worker := s.worker_member;
  -- Always selected (no row for anything but a pull request), so the record is set either way.
  select * into p from app.work_github_prs x where x.number = s.pr_number;
  host := lower(substring(coalesce(s.artifact_url, '') from '^https?://([^/:?#]+)'));
  return jsonb_build_object(
    'class', t.class, 'worker_kind', s.worker_kind,
    'own', poster is not null and worker is not null and poster = worker,
    'late', c.id is not null and s.created_at > c.expires_at,
    'claim_open', c.id is not null and c.expires_at > now(),
    'reused', exists (select 1 from app.work_submissions o where o.id <> s.id and o.task_id <> s.task_id and o.status <> 'failed'
                       and ((s.artifact_url is not null and o.artifact_url = s.artifact_url) or (s.artifact_sha256 is not null and o.artifact_sha256 = s.artifact_sha256))),
    'artifact', s.artifact_kind,
    'github_task', t.github_kind,
    'task_source', t.source,
    'issue', case when t.github_kind = 'issue' then t.github_number end,
    'pr', case when s.artifact_kind = 'pr' and p.id is not null then jsonb_build_object(
      'state', p.state, 'merged', p.merged_at is not null, 'base', p.base,
      'code_ok', c.id is not null and exists (select 1 from app.work_github_codes g where g.pr_number = p.number and g.code_hash = c.code_hash),
      'author_ok', s.worker_kind = 'github' and s.worker_github = p.author,
      'refs_issue', t.github_kind = 'issue' and (',' || p.refs || ',') like ('%,' || t.github_number || ',%')) end,
    'url_https', s.artifact_url like 'https://%',
    'url_ip', host ~ '^[0-9.]+$' or host like '[%' or host = 'localhost',
    'url_short', host = any (array['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy']),
    'note_hits', s.note_hits);
end
$$;

-- The size the audit confirms: never above the task's. A merged pull request: the band of its changed lines. A person
-- deciding for an administrator: the size they give. The task's poster, checking work on the task they defined: its size.
create function app.work_confirmed_size(p_sub uuid, p_by text)
returns smallint
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  s record;
  t record;
  p record;
  med numeric;
begin
  select * into s from app.work_submissions x where x.id = p_sub;
  select * into t from app.work_tasks x where x.id = s.task_id;
  if s.artifact_kind = 'pr' then
    select * into p from app.work_github_prs x where x.number = s.pr_number;
    if p.detail_at is not null then
      return least(case when t.source = 'github' and t.github_kind = 'pr' then 8 else t.size end, app.work_size_band(p.additions + p.deletions))::smallint;
    end if;
  end if;
  select percentile_disc(0.5) within group (order by v.size) into med from (
    select pv.size from app.work_person_votes pv where pv.submission_id = p_sub and pv.size is not null) v;
  if med is not null then
    return least(t.size, med)::smallint;
  end if;
  if p_by = 'poster' then
    return t.size;
  end if;
  return 1;
end
$$;

-- Decides a submission: records the outcome, its points, its log entry, the task's next
-- step and the worker's notice. p_verdict: pass or fail.
create function app.work_finish(p_sub uuid, p_verdict text, p_by text, p_confidence integer, p_reason text)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  t record;
  c record;
  st record;
  size smallint;
  indep integer := 100;
  pts integer;
  reveals jsonb;
  n bigint;
  p record;
  approver text;
  aseq bigint;
  who uuid;
begin
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.status in ('passed', 'failed') then return; end if;
  select * into t from app.work_tasks x where x.id = s.task_id for update;
  select * into st from app.work_settings where singleton;
  select * into p from app.work_github_prs x where x.number = s.pr_number;  -- no row unless a pull request
  -- The person's decision, when the JEVs auditor sent it to one: the verdict and size, never who (the entry's actor says
  -- which kind of auditor decided).
  reveals := coalesce((select jsonb_agg(jsonb_build_object('verdict', pv.verdict, 'size', pv.size)) from app.work_person_votes pv
                       where pv.submission_id = p_sub), '[]'::jsonb);
  if p_verdict = 'pass' then
    size := app.work_confirmed_size(p_sub, p_by);
    if s.artifact_kind = 'pr' and p.merged_by is not null and p.merged_by = p.author then indep := 50; end if;
    pts := app.work_points_of(size, p_confidence, indep, st.points_cap);
  end if;
  n := app.log_work('audit.verdict', 'work-audit', null, 'submission:' || p_sub::text, jsonb_build_object(
         'task', s.task_id::text, 'verdict', p_verdict, 'by', p_by, 'confidence', p_confidence, 'size', size, 'independence', indep,
         'points', coalesce(pts, 0), 'votes', reveals));
  update app.work_submissions x set status = case when p_verdict = 'pass' then 'passed' else 'failed' end, route = null,
    confidence = p_confidence, final_size = size, decided_by = p_by, reason = left(p_reason, 300), decided_at = now(), decided_seq = n
   where x.id = p_sub;
  select * into c from app.work_claims x where x.id = s.claim_id for update;
  who := coalesce(s.worker_member, null);
  if p_verdict = 'pass' then
    insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, citizen_agent, citizen_github, size, confidence,
                                 independence, points, final_at)
      values (p_sub, t.id, t.room_id, s.worker_kind, s.worker_member, s.worker_agent, s.worker_github, size, p_confidence, indep, pts,
              now() + make_interval(hours => st.dispute_hours));
    if c.id is not null then update app.work_claims x set status = 'done', ended_at = now() where x.id = c.id; end if;
    -- A merged pull request was approved by its merge (the person gate); anything else waits for its poster.
    if s.artifact_kind = 'pr' and t.source = 'github' and p.merged_at is not null then
      approver := 'github:' || coalesce(p.merged_by, 'unknown');
      aseq := app.log_work('task.approved', approver, null, 'task:' || t.id::text,
                jsonb_build_object('submission', p_sub::text, 'room', (select r.code from app.work_rooms r where r.id = t.room_id), 'by', 'merge'));
      update app.work_tasks x set status = 'approved', approved_at = now(), approved_seq = aseq, updated_at = now() where x.id = t.id;
    else
      update app.work_tasks x set status = 'audited', updated_at = now() where x.id = t.id;
      if p_by <> 'poster' and (t.poster_member is not null or t.poster_agent is not null) then
        perform app.notify(coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)), 'work_submitted',
          'Work on your task passed its audit', 'The work submitted for "' || left(t.title, 80) || '" passed an independent audit. Approve it to complete the task.',
          '/tasks/' || t.id, 'task', t.id, 'work:audited:' || p_sub);
      end if;
    end if;
  else
    -- Failed: the worker may try again while the claim holds; otherwise the task reopens.
    if c.id is not null and c.expires_at > now() then
      update app.work_claims x set status = 'active' where x.id = c.id;
      update app.work_tasks x set status = 'claimed', updated_at = now() where x.id = t.id;
    else
      if c.id is not null then update app.work_claims x set status = 'expired', ended_at = now() where x.id = c.id; end if;
      update app.work_tasks x set status = case when t.source = 'github' and t.github_kind = 'pr' then 'closed' else 'open' end, updated_at = now() where x.id = t.id;
    end if;
  end if;
  if who is not null and s.worker_kind <> 'github' then
    perform app.notify(who, 'work_decided', case when p_verdict = 'pass' then 'Your work passed its audit' else 'Your work didn''t pass its audit' end,
      'The audit of your work on "' || left(t.title, 80) || '" decided: ' || case when p_verdict = 'pass' then 'passed, '
      || coalesce(pts, 0) || ' points, pending for ' || st.dispute_hours || ' hours.' else 'not passed. ' || left(coalesce(p_reason, ''), 200) end,
      '/tasks/' || t.id, 'task', t.id, 'work:decided:' || p_sub);
  end if;
end
$$;

-- The JEVs auditor on one submission: its verdict, logged once it has one, and the next step.
create function app.work_jevs_run(p_sub uuid)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  r jsonb;
  v text;
  rules text;
begin
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.status not in ('waiting') then return s.jevs_verdict; end if;
  r := app.work_jevs_rules(app.work_facts(p_sub));
  v := r ->> 'verdict';
  rules := coalesce((select string_agg(e, ',') from jsonb_array_elements_text(r -> 'rules') e), '');
  update app.work_submissions x set jevs_verdict = v, jevs_rules = rules where x.id = p_sub;
  if v = 'waiting' then return v; end if;
  perform app.log_work('audit.verdict', 'jevs-audit', null, 'submission:' || p_sub::text,
    jsonb_build_object('task', s.task_id::text, 'verdict', v, 'rules', rules));
  if v = 'pass' then
    perform app.work_finish(p_sub, 'pass', 'jevs', 100, 'The JEVs auditor confirmed it: ' || rules);
  elsif v = 'fail' then
    perform app.work_finish(p_sub, 'fail', 'jevs', 100, 'The JEVs auditor''s rules ' || rules || ' refused it.');
  else
    -- What its rules can't decide goes to the task's poster: the worker never approves their own work (four eyes; Aaron,
    -- Nov 6: "Use logic to determine the flow based on simulation and industry best practices"). The repository's own
    -- tasks were posted by its owner account, so an administrator decides those, unless an administrator did the work;
    -- then it waits for Third Look.
    if (select t.source from app.work_tasks t where t.id = s.task_id) = 'member' then
      update app.work_submissions x set status = 'review', route = 'poster' where x.id = p_sub;
      perform app.notify((select coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) from app.work_tasks t where t.id = s.task_id),
        'work_submitted', 'Work on your task waits for your check', 'The JEVs auditor''s rules couldn''t decide the work submitted on your task (rules ' || rules
        || '), so you do, as its poster: pass it, or fail it with a reason. A sample of passes is checked again.', '/tasks/' || s.task_id, 'task', s.task_id, 'work:check:' || p_sub);
    elsif exists (select 1 from app.members m where m.id = s.worker_member and m.is_admin) then
      update app.work_submissions x set status = 'review', route = 'held', held_reason = 'An administrator did this work, so none decides it: it waits for Third Look.' where x.id = p_sub;
    else
      update app.work_submissions x set status = 'review', route = 'admin' where x.id = p_sub;
      perform app.notify(null, 'alert', 'Work on the repository''s task waits for you', 'The JEVs auditor''s rules couldn''t decide work on one of the repository''s own tasks (rules '
        || rules || '). Decide it on Review, as the repository''s owner.', '/admin/review#work', 'submission', p_sub, 'work:person:' || p_sub);
    end if;
  end if;
  return v;
end
$$;

-- ---- Reading (public: everything returned is public on the site) ----
-- One task's card: what the lists and the board show.
create function app.work_card(p_task uuid)
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select jsonb_build_object('id', t.id, 'ref', case when t.github_kind = 'pr' then 'PR #' || t.github_number when t.github_kind = 'issue' then 'Issue #' || t.github_number
                                                  else 'T-' || upper(substring(replace(t.id::text, '-', '') from 27 for 6)) end,
    'title', t.title, 'class', t.class, 'size', t.size, 'status', t.status, 'source', t.source,
    'room', jsonb_build_object('code', r.code, 'name', r.name), 'project', jsonb_build_object('id', p.id, 'title', p.title),
    'created_at', t.created_at, 'updated_at', t.updated_at,
    'worker', (select app.work_display(c.member_id, c.agent_id, null) from app.work_claims c where c.task_id = t.id and c.status in ('active', 'submitted', 'done')
               order by c.created_at desc limit 1),
    'done_by', (select app.work_display(case when s.worker_kind = 'member' then s.worker_member end, s.worker_agent, s.worker_github)
                from app.work_submissions s where s.task_id = t.id and s.status = 'passed' order by s.decided_at desc limit 1),
    'receipt', (select s.decided_seq from app.work_submissions s where s.task_id = t.id and s.status = 'passed' order by s.decided_at desc limit 1),
    'url', case when t.github_kind = 'pr' then 'https://github.com/MyChiefOS/start-of-something-great/pull/' || t.github_number
                when t.github_kind = 'issue' then 'https://github.com/MyChiefOS/start-of-something-great/issues/' || t.github_number end)
  from app.work_tasks t join app.work_rooms r on r.id = t.room_id join app.work_projects p on p.id = t.project_id
  where t.id = p_task
$$;

-- The latest signed checkpoint's size: an entry below it is anchored.
create function app.work_anchored_through()
returns bigint
language sql stable security definer set search_path = pg_catalog
as $$ select coalesce(max(c.size), 0) from app.log_checkpoints c $$;

-- A project's progress: tasks that count (not closed or removed), approved ones, and the share.
create function app.work_project_card(p_project uuid)
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select jsonb_build_object('id', p.id, 'title', p.title, 'source', p.source, 'status', p.status,
    'room', jsonb_build_object('code', r.code, 'name', r.name),
    'poster', case when p.source = 'github' then jsonb_build_object('kind', 'github', 'name', 'GitHub: MyChiefOS/start-of-something-great')
                   else app.work_display(p.poster_member, p.poster_agent, null) end,
    'tasks', n.total, 'approved', n.approved, 'open', n.open, 'claimed', n.claimed, 'submitted', n.submitted,
    'percent', case when n.total = 0 then 0 else floor(100.0 * n.approved / n.total) end,
    'created_at', p.created_at, 'updated_at', p.updated_at)
  from app.work_projects p join app.work_rooms r on r.id = p.room_id
  cross join lateral (select count(*) filter (where t.status not in ('closed', 'removed')) as total,
                             count(*) filter (where t.status = 'approved') as approved,
                             count(*) filter (where t.status = 'open') as open,
                             count(*) filter (where t.status = 'claimed') as claimed,
                             count(*) filter (where t.status in ('submitted', 'audited')) as submitted
                      from app.work_tasks t where t.project_id = p.id) n
  where p.id = p_project
$$;

-- The Build page and the home page's block.
create function app.work_summary()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  anchored bigint := app.work_anchored_through();
  latest record;
begin
  select s.* into latest from app.work_submissions s join app.work_tasks t on t.id = s.task_id
   where s.status = 'passed' and t.status <> 'removed' order by s.decided_at desc, s.id desc limit 1;
  return jsonb_build_object(
    'generated_at', now(),
    'tasks', (select count(*) from app.work_tasks t where t.status not in ('closed', 'removed')),
    'approved', (select count(*) from app.work_tasks t where t.status = 'approved'),
    'anchored', (select count(*) from app.work_tasks t where t.status = 'approved' and t.approved_seq < anchored),
    'open', (select count(*) from app.work_tasks t where t.status = 'open'),
    'in_progress', (select count(*) from app.work_tasks t where t.status in ('claimed', 'submitted', 'audited')),
    'projects', (select count(*) from app.work_projects p where p.status = 'open'),
    'points_final', (select coalesce(sum(x.points), 0) from app.work_points x where x.status = 'final'),
    'points_pending', (select coalesce(sum(x.points), 0) from app.work_points x where x.status = 'pending'),
    'waiting_for_poster', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'poster'),
    'waiting_for_admin', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'admin')
                         + (select count(*) from app.work_checks k where k.status = 'open') + (select count(*) from app.work_disputes d where d.status = 'open'),
    'held_for_third_look', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'held'),
    'checkpoint', anchored,
    'packages', coalesce((select jsonb_agg(app.work_project_card(q.id) order by q.updated_at desc, q.id desc) from (
        select p.id, p.updated_at from app.work_projects p where p.status = 'open' order by p.updated_at desc, p.id desc limit 6) q), '[]'::jsonb),
    'board', coalesce((select jsonb_agg(app.work_card(q.id) order by q.updated_at desc, q.id desc) from (
        select t.id, t.updated_at from app.work_tasks t where t.status not in ('closed', 'removed') order by t.updated_at desc, t.id desc limit 8) q), '[]'::jsonb),
    'weeks', coalesce((select jsonb_agg(jsonb_build_object('week', w.d, 'scope', (select count(*) from app.work_tasks t where t.created_at < w.d + interval '7 days' and t.status <> 'removed'),
                                                          'verified', (select count(*) from app.work_tasks t where t.status = 'approved' and t.approved_at < w.d + interval '7 days'
                                                                       and t.approved_seq < anchored)) order by w.d)
                       from (select generate_series(date_trunc('week', now()) - interval '5 weeks', date_trunc('week', now()), interval '1 week') as d) w), '[]'::jsonb),
    'latest_receipt', case when latest.id is null then null else jsonb_build_object(
        'task', app.work_card(latest.task_id), 'submission', latest.id, 'seq', latest.decided_seq, 'anchored', latest.decided_seq < anchored,
        'worker', app.work_display(case when latest.worker_kind = 'member' then latest.worker_member end, latest.worker_agent, latest.worker_github),
        'artifact', jsonb_build_object('kind', latest.artifact_kind, 'url', latest.artifact_url, 'sha256', latest.artifact_sha256),
        'decided_by', latest.decided_by, 'confidence', latest.confidence, 'decided_at', latest.decided_at,
        'points', (select x.points from app.work_points x where x.submission_id = latest.id),
        'approved_seq', (select t.approved_seq from app.work_tasks t where t.id = latest.task_id)) end,
    'live', coalesce((select jsonb_agg(jsonb_build_object('seq', e.seq, 'type', e.type, 'at', e.created_at, 'actor', e.actor,
                                                          'subject', e.subject, 'anchored', e.seq < anchored) order by e.seq desc)
                      from (select x.seq, x.type, x.created_at, x.actor, x.subject from app.log_entries x
                            where x.type = any (array['task.claimed', 'task.submitted', 'audit.verdict', 'task.approved'])
                            order by x.seq desc limit 6) e), '[]'::jsonb));
end
$$;

-- Lists: tasks, with filters and a cursor (at most 100).
create function app.work_tasks(p_status text, p_room text, p_project uuid, p_q text, p_before uuid, p_limit integer)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  ids uuid[];
  more boolean;
  pat text;
begin
  if p_limit is null or p_limit not between 1 and 100 or (p_status is not null and p_status <> all (array['open', 'claimed', 'submitted', 'audited', 'approved', 'closed', 'all']))
     or (p_room is not null and p_room !~ '^[0-9]{2}-0000$') or (p_q is not null and char_length(p_q) not between 2 and 100) then
    raise exception 'bad task list' using errcode = '22023';
  end if;
  pat := case when p_q is null then null else '%' || replace(replace(replace(lower(p_q), '\', '\\'), '%', '\%'), '_', '\_') || '%' end;
  ids := array(select t.id from app.work_tasks t join app.work_rooms r on r.id = t.room_id
               where t.status <> 'removed' and (coalesce(p_status, 'all') = 'all' or t.status = p_status)
                 and (p_room is null or r.code = p_room) and (p_project is null or t.project_id = p_project)
                 and (pat is null or lower(t.title) like pat or lower(t.description) like pat or lower(t.id::text) like pat)
                 and (p_before is null or t.id < p_before)
               order by t.id desc limit p_limit + 1);
  more := cardinality(ids) > p_limit;
  if more then ids := ids[1:p_limit]; end if;
  return jsonb_build_object('generated_at', now(),
    'tasks', coalesce((select jsonb_agg(app.work_card(x.id) order by x.id desc) from unnest(ids) x(id)), '[]'::jsonb),
    'next_before', case when more then ids[p_limit] end,
    'total', (select count(*) from app.work_tasks t join app.work_rooms r on r.id = t.room_id
              where t.status <> 'removed' and (coalesce(p_status, 'all') = 'all' or t.status = p_status)
                and (p_room is null or r.code = p_room) and (p_project is null or t.project_id = p_project)
                and (pat is null or lower(t.title) like pat or lower(t.description) like pat or lower(t.id::text) like pat)));
end
$$;

-- One task, in full: its card, words, steps, claim, submissions (with their audits and seals), points and log entries.
create function app.work_task(p_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  t record;
  anchored bigint := app.work_anchored_through();
begin
  select * into t from app.work_tasks x where x.id = p_id and x.status <> 'removed';
  if t.id is null then return null; end if;
  return app.work_card(p_id) || jsonb_build_object(
    'description', t.description, 'generated_at', now(),
    'poster', case when t.source = 'github' then jsonb_build_object('kind', 'github', 'name', case when t.github_kind = 'pr' then '@' || t.github_author
                                                                                              else 'GitHub: MyChiefOS/start-of-something-great' end)
                   else app.work_display(t.poster_member, t.poster_agent, null) end,
    'approved_at', t.approved_at, 'approved_seq', t.approved_seq, 'anchored_through', anchored,
    'claim', (select jsonb_build_object('by', app.work_display(c.member_id, c.agent_id, null), 'status', c.status, 'claimed_at', c.created_at,
                                        'expires_at', c.expires_at, 'seq', c.log_seq)
              from app.work_claims c where c.task_id = t.id and c.status in ('active', 'submitted') limit 1),
    'submissions', coalesce((select jsonb_agg(jsonb_build_object(
        'id', s.id, 'status', s.status, 'route', s.route, 'held_reason', s.held_reason, 'created_at', s.created_at, 'decided_at', s.decided_at,
        'worker', app.work_display(case when s.worker_kind = 'member' then s.worker_member end, s.worker_agent, s.worker_github),
        'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256, 'pr', s.pr_number),
        'note', s.note,
        'seal', jsonb_build_object('seal', s.seal, 'key', encode(s.seal_key, 'hex'),
                                   'facts', jsonb_build_object('task', s.task_id::text, 'kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256)),
        'jevs', jsonb_build_object('verdict', s.jevs_verdict, 'rules', s.jevs_rules),
        -- Who audits it: the JEVs auditor's rules, then a person for what they can't decide (Aaron, Nov 5).
        'audit', jsonb_build_object('by', coalesce(s.decided_by, case s.route when 'poster' then 'poster' when 'admin' then 'person' when 'held' then 'third_look' else 'jevs' end),
                                    'third_look', 'not_built'),
        'check', (select jsonb_build_object('status', k.status, 'why', k.why, 'reason', k.reason, 'decided_at', k.decided_at) from app.work_checks k where k.submission_id = s.id),
        'disputes', coalesce((select jsonb_agg(jsonb_build_object('id', d.id, 'status', d.status, 'reason', d.reason, 'decision', d.decision,
                                                                 'created_at', d.created_at, 'decided_at', d.decided_at) order by d.created_at)
                              from app.work_disputes d where d.submission_id = s.id), '[]'::jsonb),
        'decided_by', s.decided_by, 'confidence', s.confidence, 'size', s.final_size, 'reason', s.reason,
        'points', (select jsonb_build_object('points', x.points, 'size', x.size, 'confidence', x.confidence, 'independence', x.independence,
                                             'status', x.status, 'final_at', x.final_at) from app.work_points x where x.submission_id = s.id),
        'submitted_seq', s.submitted_seq, 'decided_seq', s.decided_seq,
        'anchored', s.decided_seq is not null and s.decided_seq < anchored) order by s.created_at desc)
      from (select * from app.work_submissions y where y.task_id = t.id order by y.created_at desc limit 20) s), '[]'::jsonb));
end
$$;

-- The task a submission belongs to (public: every submission is shown on its task's page), so a step taken on a
-- submission can answer with its task as it now stands.
create function app.work_task_of(p_sub uuid)
returns uuid
language sql stable security definer set search_path = pg_catalog
as $$ select s.task_id from app.work_submissions s join app.work_tasks t on t.id = s.task_id where s.id = p_sub and t.status <> 'removed' $$;

-- Rooms: all 23, each with its open tasks' count.
create function app.work_rooms_list()
returns jsonb
language sql stable security definer set search_path = pg_catalog
as $$
  select jsonb_build_object('generated_at', now(), 'rooms', jsonb_agg(jsonb_build_object('code', r.code, 'name', r.name,
      'open', (select count(*) from app.work_tasks t where t.room_id = r.id and t.status = 'open'),
      'tasks', (select count(*) from app.work_tasks t where t.room_id = r.id and t.status not in ('closed', 'removed'))) order by r.ord))
  from app.work_rooms r
$$;

-- One room: its open projects and tasks, and the people and agents with points there (a profile, not a rank).
create function app.work_room(p_code text)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  r record;
begin
  select * into r from app.work_rooms x where x.code = p_code;
  if r.id is null then return null; end if;
  return jsonb_build_object('generated_at', now(), 'code', r.code, 'name', r.name,
    'open', (select count(*) from app.work_tasks t where t.room_id = r.id and t.status = 'open'),
    'projects', coalesce((select jsonb_agg(app.work_project_card(q.id) order by q.updated_at desc) from (
        select p.id, p.updated_at from app.work_projects p where p.room_id = r.id and p.status = 'open'
          and exists (select 1 from app.work_tasks t where t.project_id = p.id and t.status = 'open')
        order by p.updated_at desc limit 50) q), '[]'::jsonb),
    'tasks', coalesce((select jsonb_agg(app.work_card(q.id) order by q.id desc) from (
        select t.id from app.work_tasks t where t.room_id = r.id and t.status = 'open' order by t.id desc limit 50) q), '[]'::jsonb),
    -- Who did audited work here: points (final and pending) and audited items, each with its sample size. Sorted by
    -- final points; the page shows bands, never a rank beyond what the numbers say (spec 4.1).
    'workers', coalesce((select jsonb_agg(w.j order by w.final desc, w.items desc) from (
        select app.work_display(case when x.citizen_kind = 'member' then x.citizen_member end, x.citizen_agent, x.citizen_github)
               || jsonb_build_object('final', sum(x.points) filter (where x.status = 'final'), 'pending', sum(x.points) filter (where x.status = 'pending'),
                                     'items', count(*)) as j,
               coalesce(sum(x.points) filter (where x.status = 'final'), 0) as final, count(*) as items
        from app.work_points x where x.room_id = r.id and x.status <> 'removed'
        group by x.citizen_kind, x.citizen_member, x.citizen_agent, x.citizen_github
        order by 2 desc, 3 desc limit 20) w), '[]'::jsonb));
end
$$;

-- Projects, with filters and a cursor.
create function app.work_projects_list(p_status text, p_room text, p_q text, p_before uuid, p_limit integer)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  ids uuid[];
  more boolean;
  pat text;
begin
  if p_limit is null or p_limit not between 1 and 100 or (p_status is not null and p_status <> all (array['open', 'claimed', 'submitted', 'completed', 'all']))
     or (p_room is not null and p_room !~ '^[0-9]{2}-0000$') or (p_q is not null and char_length(p_q) not between 2 and 100) then
    raise exception 'bad project list' using errcode = '22023';
  end if;
  pat := case when p_q is null then null else '%' || replace(replace(replace(lower(p_q), '\', '\\'), '%', '\%'), '_', '\_') || '%' end;
  -- A project's state, as the design's chips name it: open (a task is open), claimed (one is claimed), submitted (one
  -- waits on its audit or its poster), completed (every task that counts is approved).
  ids := array(select p.id from app.work_projects p join app.work_rooms r on r.id = p.room_id
               where p.status <> 'removed' and (p_room is null or r.code = p_room) and (p_before is null or p.id < p_before)
                 and (pat is null or lower(p.title) like pat or lower(p.description) like pat or lower(p.id::text) like pat)
                 and (coalesce(p_status, 'all') = 'all'
                      or (p_status = 'open' and exists (select 1 from app.work_tasks t where t.project_id = p.id and t.status = 'open'))
                      or (p_status = 'claimed' and exists (select 1 from app.work_tasks t where t.project_id = p.id and t.status = 'claimed'))
                      or (p_status = 'submitted' and exists (select 1 from app.work_tasks t where t.project_id = p.id and t.status in ('submitted', 'audited')))
                      or (p_status = 'completed' and exists (select 1 from app.work_tasks t where t.project_id = p.id and t.status = 'approved')
                          and not exists (select 1 from app.work_tasks t where t.project_id = p.id and t.status not in ('approved', 'closed', 'removed'))))
               order by p.id desc limit p_limit + 1);
  more := cardinality(ids) > p_limit;
  if more then ids := ids[1:p_limit]; end if;
  return jsonb_build_object('generated_at', now(),
    'projects', coalesce((select jsonb_agg(app.work_project_card(x.id) order by x.id desc) from unnest(ids) x(id)), '[]'::jsonb),
    'next_before', case when more then ids[p_limit] end);
end
$$;

-- One project: its card, words, and its tasks (newest first, at most 100).
create function app.work_project(p_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  p record;
begin
  select * into p from app.work_projects x where x.id = p_id and x.status <> 'removed';
  if p.id is null then return null; end if;
  return app.work_project_card(p_id) || jsonb_build_object('description', p.description, 'generated_at', now(),
    'tasks', coalesce((select jsonb_agg(app.work_card(q.id) order by q.id desc) from (
        select t.id from app.work_tasks t where t.project_id = p.id and t.status <> 'removed' order by t.id desc limit 100) q), '[]'::jsonb),
    'latest', (select jsonb_build_object('task', app.work_card(s.task_id), 'worker', app.work_display(case when s.worker_kind = 'member' then s.worker_member end, s.worker_agent, s.worker_github),
                                         'status', s.status, 'created_at', s.created_at, 'note', s.note)
               from app.work_submissions s join app.work_tasks t on t.id = s.task_id where t.project_id = p.id order by s.created_at desc limit 1));
end
$$;

-- What the acting person or agent has on hand: their claims and the tasks they posted.
create function app.work_mine()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  w record;
begin
  select * into w from app.work_who();
  return jsonb_build_object('generated_at', now(), 'citizen', w.citizen,
    'claims', coalesce((select jsonb_agg(app.work_card(c.task_id) || jsonb_build_object('claim_status', c.status, 'expires_at', c.expires_at) order by c.created_at desc)
                        from app.work_claims c where c.status in ('active', 'submitted') and c.member_id = w.member_id and c.agent_id is not distinct from w.agent_id), '[]'::jsonb),
    'posted', coalesce((select jsonb_agg(app.work_card(t.id) order by t.created_at desc) from (
        select x.id, x.created_at from app.work_tasks x where x.status <> 'removed'
          and ((w.agent_id is null and x.poster_member = w.member_id) or (w.agent_id is not null and x.poster_agent = w.agent_id))
        order by x.created_at desc limit 50) t), '[]'::jsonb),
    -- Work on my tasks that waits for my check, as the poster (people only: an agent's owner checks for it).
    'to_check', case when w.agent_id is null then coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('submission', s.id, 'jevs_rules', s.jevs_rules)
                        order by s.created_at)
                        from app.work_submissions s join app.work_tasks t on t.id = s.task_id
                        where s.status = 'review' and s.route = 'poster'
                          and coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) = w.member_id), '[]'::jsonb) else '[]'::jsonb end);
end
$$;

-- ---- Writing: people and agents ----
-- A new project. p_room: a room code. Text arrives masked by the site (contacts and keys hidden).
create function app.work_project_create(p_title text, p_description text, p_room text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  rid uuid;
  pid uuid;
  n integer;
begin
  select * into w from app.work_who();
  perform app.work_brake_check(w.member_id);
  select r.id into rid from app.work_rooms r where r.code = p_room;
  if rid is null or p_title is null or char_length(btrim(p_title)) not between 3 and 140 or char_length(coalesce(p_description, '')) > 4000 then
    raise exception 'bad project' using errcode = '22023';
  end if;
  select count(*) into n from app.work_actions x where x.member_id = w.member_id and x.kind = 'post' and x.created_at > now() - interval '1 day';
  if n >= (select s.member_daily_posts from app.work_settings s where s.singleton) then
    raise exception 'work_cap' using errcode = 'P0001', hint = 'You (with your agents) have posted ' || n || ' projects and tasks today, the most for one day.';
  end if;
  if w.agent_id is not null then perform app.work_cap(w.agent_id, w.tree_root, 'post', false); end if;
  insert into app.work_projects (title, description, room_id, source, poster_member, poster_agent)
    values (btrim(p_title), coalesce(p_description, ''), rid, 'member', case when w.agent_id is null then w.member_id end, w.agent_id) returning id into pid;
  insert into app.work_actions (member_id, agent_id, kind) values (w.member_id, w.agent_id, 'post');
  return pid;
end
$$;

-- A new task in a project its poster (or the poster's agents' owner) posted.
create function app.work_task_create(p_project uuid, p_title text, p_description text, p_class text, p_size integer)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  p record;
  tid uuid;
  n integer;
begin
  select * into w from app.work_who();
  perform app.work_brake_check(w.member_id);
  select * into p from app.work_projects x where x.id = p_project and x.status = 'open' and x.source = 'member' for update;
  if p.id is null then raise exception 'no such open project' using errcode = 'P0002'; end if;
  if coalesce(p.poster_member, (select g.owner_id from app.agents g where g.id = p.poster_agent)) <> w.member_id then
    raise exception 'only the project''s poster (or their agents) adds its tasks' using errcode = '42501';
  end if;
  if p_title is null or char_length(btrim(p_title)) not between 3 and 140 or char_length(coalesce(p_description, '')) > 4000
     or p_class is null or p_class <> all (array['agent', 'person', 'either']) or p_size is null or p_size <> all (array[1, 2, 3, 5, 8]) then
    raise exception 'bad task' using errcode = '22023';
  end if;
  select count(*) into n from app.work_actions x where x.member_id = w.member_id and x.kind = 'post' and x.created_at > now() - interval '1 day';
  if n >= (select s.member_daily_posts from app.work_settings s where s.singleton) then
    raise exception 'work_cap' using errcode = 'P0001', hint = 'You (with your agents) have posted ' || n || ' projects and tasks today, the most for one day.';
  end if;
  if w.agent_id is not null then perform app.work_cap(w.agent_id, w.tree_root, 'post', false); end if;
  insert into app.work_tasks (project_id, room_id, title, description, class, size, source, poster_member, poster_agent)
    values (p.id, p.room_id, btrim(p_title), coalesce(p_description, ''), p_class, p_size, 'member', case when w.agent_id is null then w.member_id end, w.agent_id)
    returning id into tid;
  update app.work_projects x set updated_at = now() where x.id = p.id;
  insert into app.work_actions (member_id, agent_id, kind) values (w.member_id, w.agent_id, 'post');
  return tid;
end
$$;

-- Claims an open task for 72 hours. p_code_hash: the SHA-256 of the claim code the site made (shown to the claimer
-- once; written in a pull request's description, it shows who wrote the pull request).
create function app.work_claim(p_task uuid, p_code_hash text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  t record;
  st record;
  cid uuid;
  exp timestamptz;
  n integer;
  seq bigint;
  poster uuid;
begin
  if p_code_hash is null or p_code_hash !~ '^[0-9a-f]{64}$' then raise exception 'bad claim' using errcode = '22023'; end if;
  select * into w from app.work_who();
  perform app.work_brake_check(w.member_id);
  select * into st from app.work_settings where singleton;
  if w.agent_id is not null then perform app.work_cap(w.agent_id, w.tree_root, 'claim', true); end if;
  select * into t from app.work_tasks x where x.id = p_task for update;
  if t.id is null or t.status = 'removed' then raise exception 'no such task' using errcode = 'P0002'; end if;
  if t.status <> 'open' then raise exception 'work_taken' using errcode = 'P0001', hint = 'This task isn''t open: it is ' || t.status || '.'; end if;
  if (t.class = 'agent' and w.agent_id is null) or (t.class = 'person' and w.agent_id is not null) then
    raise exception 'work_class' using errcode = 'P0001', hint = case when t.class = 'agent' then 'Only an agent may claim this task.' else 'Only a person may claim this task.' end;
  end if;
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if poster = w.member_id then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You (or your agents) posted this task, so you can''t claim it: nobody does or audits their own task.';
  end if;
  if w.agent_id is null then
    select count(*) into n from app.work_claims c where c.member_id = w.member_id and c.agent_id is null and c.status = 'active';
    if n >= st.member_active_claims then
      raise exception 'work_cap' using errcode = 'P0001', hint = 'You already hold ' || n || ' live claims, the most one person may hold.';
    end if;
  end if;
  exp := now() + make_interval(hours => st.claim_hours);
  insert into app.work_claims (task_id, member_id, agent_id, tree_root, code_hash, expires_at)
    values (t.id, w.member_id, w.agent_id, w.tree_root, p_code_hash, exp) returning id into cid;
  update app.work_tasks x set status = 'claimed', updated_at = now() where x.id = t.id;
  insert into app.work_actions (member_id, agent_id, kind) values (w.member_id, w.agent_id, 'claim');
  seq := app.log_work('task.claimed', w.citizen, case when w.agent_id is not null then 'member:' || w.member_id end, 'task:' || t.id::text,
           jsonb_build_object('claim', cid::text, 'room', (select r.code from app.work_rooms r where r.id = t.room_id), 'expires', app.log_ts(exp)));
  update app.work_claims x set log_seq = seq where x.id = cid;
  if poster is not null then
    perform app.notify(poster, 'work_claimed', 'Your task was claimed', '"' || left(t.title, 80) || '" was claimed. It holds for '
      || st.claim_hours || ' hours, then reopens if nothing is submitted.', '/tasks/' || t.id, 'task', t.id, 'work:claimed:' || cid);
  end if;
  return jsonb_build_object('claim', cid, 'task', t.id, 'expires_at', exp, 'seq', seq);
end
$$;

-- Lets a claim go: the claimer, or the member whose agent holds it. The task reopens.
create function app.work_release(p_task uuid)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  c record;
begin
  select * into w from app.work_who();
  select * into c from app.work_claims x where x.task_id = p_task and x.status = 'active' for update;
  if c.id is null then return 'none'; end if;
  if not ((w.agent_id is null and c.member_id = w.member_id) or (w.agent_id is not null and c.agent_id = w.agent_id)) then
    raise exception 'only the claimer (or the person its agent acts for) lets a claim go' using errcode = '42501';
  end if;
  update app.work_claims x set status = 'released', ended_at = now() where x.id = c.id;
  update app.work_tasks x set status = 'open', updated_at = now() where x.id = p_task and x.status = 'claimed';
  return 'released';
end
$$;

-- An agent hands its claim to one of its own direct sub-agents: the fan-out. The sub-agent's tree is the same, so the
-- same limits count; the claim keeps its time. p_code_hash: a new code, for the sub-agent.
create function app.work_handoff(p_task uuid, p_agent uuid, p_code_hash text)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  c record;
  g record;
  t record;
  mode text;
  cid uuid;
  seq bigint;
begin
  if p_code_hash is null or p_code_hash !~ '^[0-9a-f]{64}$' then raise exception 'bad handoff' using errcode = '22023'; end if;
  select * into w from app.work_who();
  perform app.work_brake_check(w.member_id);
  if w.agent_id is null then raise exception 'only an agent hands work to its sub-agents' using errcode = '42501'; end if;
  select * into c from app.work_claims x where x.task_id = p_task and x.status = 'active' and x.agent_id = w.agent_id for update;
  if c.id is null then raise exception 'work_not_yours' using errcode = 'P0001', hint = 'You don''t hold a live claim on this task.'; end if;
  select x.id, x.status, x.expires_at, x.owner_id, x.parent_id into g from app.agents x where x.id = p_agent;
  if g.id is null or g.parent_id is distinct from w.agent_id or g.owner_id <> w.member_id or g.status <> 'active'
     or (g.expires_at is not null and g.expires_at <= now()) then
    raise exception 'work_not_yours' using errcode = 'P0001', hint = 'That agent isn''t one of your own active sub-agents.';
  end if;
  select r.post_mode into mode from app.agent_rules r where r.agent_id = g.id order by r.version desc limit 1;
  if coalesce(mode, 'off') = 'off' then
    raise exception 'work_off' using errcode = 'P0001', hint = 'That sub-agent''s rules have posting off, so it can''t take work.';
  end if;
  perform app.work_cap(g.id, w.tree_root, 'claim', false);
  select * into t from app.work_tasks x where x.id = p_task;
  update app.work_claims x set status = 'handed', ended_at = now() where x.id = c.id;
  insert into app.work_claims (task_id, member_id, agent_id, tree_root, code_hash, expires_at, handed_from)
    values (p_task, w.member_id, g.id, w.tree_root, p_code_hash, c.expires_at, c.id) returning id into cid;
  insert into app.work_actions (member_id, agent_id, kind) values (w.member_id, g.id, 'claim');
  seq := app.log_work('task.claimed', 'agent:' || g.id::text, 'member:' || w.member_id, 'task:' || p_task::text,
           jsonb_build_object('claim', cid::text, 'room', (select r.code from app.work_rooms r where r.id = t.room_id), 'expires', app.log_ts(c.expires_at),
                              'handed_from', w.citizen));
  update app.work_claims x set log_seq = seq where x.id = cid;
  return jsonb_build_object('claim', cid, 'task', p_task, 'agent', g.id, 'expires_at', c.expires_at, 'seq', seq);
end
$$;

-- Records one submission (for a claim, or from GitHub) with its seal, logs it, and
-- runs the JEVs auditor. Internal.
create function app.work_record(p_task uuid, p_claim uuid, p_kind text, p_member uuid, p_agent uuid, p_github text, p_onbehalf text,
                                p_artifact text, p_url text, p_sha256 text, p_pr integer, p_note text, p_hits integer)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  k bytea := app.log_random32();
  facts jsonb;
  sid uuid;
  seq bigint;
  t record;
  st record;
begin
  select * into st from app.work_settings where singleton;
  select * into t from app.work_tasks x where x.id = p_task;
  facts := jsonb_build_object('task', p_task::text, 'kind', p_artifact, 'url', p_url, 'sha256', p_sha256);
  insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, worker_agent, worker_github, artifact_kind, artifact_url,
                                    artifact_sha256, pr_number, note, note_hits, seal_key, seal)
    values (p_task, p_claim, p_kind, p_member, p_agent, p_github, p_artifact, p_url, p_sha256, p_pr, coalesce(p_note, ''), coalesce(p_hits, 0), k,
            encode(sha256(k || convert_to(app.log_jcs(facts), 'UTF8')), 'hex'))
    returning id into sid;
  seq := app.log_work('task.submitted', case when p_kind = 'github' then 'github:' || p_github when p_kind = 'agent' then 'agent:' || p_agent
                                             else 'member:' || p_member end, p_onbehalf, 'task:' || p_task::text,
           jsonb_build_object('submission', sid::text, 'room', (select x.code from app.work_rooms x where x.id = t.room_id),
                              'artifact', (select s.seal from app.work_submissions s where s.id = sid)));
  update app.work_submissions x set submitted_seq = seq where x.id = sid;
  update app.work_tasks x set status = 'submitted', updated_at = now() where x.id = p_task;
  perform app.work_jevs_run(sid);
  return sid;
end
$$;

-- Submits work for a task the caller holds a live claim on.
create function app.work_submit(p_task uuid, p_kind text, p_url text, p_sha256 text, p_note text, p_hits integer)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  c record;
  t record;
  pr integer;
  sid uuid;
  s record;
  poster uuid;
begin
  select * into w from app.work_who();
  perform app.work_brake_check(w.member_id);
  if p_kind is null or p_kind <> all (array['pr', 'link', 'file']) or char_length(coalesce(p_note, '')) > 2000 or coalesce(p_hits, 0) not between 0 and 1000
     or (p_kind = 'pr' and (p_url is null or p_url !~ '^https://github\.com/MyChiefOS/start-of-something-great/pull/[1-9][0-9]{0,6}$'))
     or (p_kind = 'link' and (p_url is null or char_length(p_url) > 500 or p_url !~ '^https?://[^[:space:]<>"]+$'))
     or (p_kind = 'file' and (p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$' or p_url is not null))
     or (p_kind <> 'file' and p_sha256 is not null) then
    raise exception 'bad submission' using errcode = '22023';
  end if;
  select * into c from app.work_claims x where x.task_id = p_task and x.status = 'active'
    and x.member_id = w.member_id and x.agent_id is not distinct from w.agent_id for update;
  if c.id is null then raise exception 'work_not_yours' using errcode = 'P0001', hint = 'You don''t hold a live claim on this task: claim it first.'; end if;
  if c.expires_at <= now() then raise exception 'work_late' using errcode = 'P0001', hint = 'Your claim''s hold ran out; the task reopens.'; end if;
  if w.agent_id is not null then perform app.work_cap(w.agent_id, w.tree_root, 'submit', false); end if;
  select * into t from app.work_tasks x where x.id = p_task for update;
  if p_kind = 'pr' then pr := substring(p_url from '/pull/([0-9]+)$')::integer; end if;
  update app.work_claims x set status = 'submitted' where x.id = c.id;
  insert into app.work_actions (member_id, agent_id, kind) values (w.member_id, w.agent_id, 'submit');
  sid := app.work_record(p_task, c.id, case when w.agent_id is null then 'member' else 'agent' end, w.member_id, w.agent_id, null,
                         case when w.agent_id is not null then 'member:' || w.member_id end, p_kind, p_url, p_sha256, pr, p_note, p_hits);
  select * into s from app.work_submissions x where x.id = sid;
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if poster is not null and s.status = 'waiting' then
    perform app.notify(poster, 'work_submitted', 'Work was submitted on your task', 'Work was submitted for "' || left(t.title, 80) || '". An independent audit decides it.',
      '/tasks/' || t.id, 'task', t.id, 'work:submitted:' || sid);
  end if;
  return jsonb_build_object('submission', sid, 'status', s.status, 'jevs', jsonb_build_object('verdict', s.jevs_verdict, 'rules', s.jevs_rules),
    'seq', s.submitted_seq);
end
$$;

-- The poster's approval of audited work (the person gate). Doesn't change points.
create function app.work_approve_as(p_task uuid, p_citizen text, p_onbehalf text)
returns bigint
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  t record;
  s record;
  seq bigint;
begin
  select * into t from app.work_tasks x where x.id = p_task for update;
  select * into s from app.work_submissions x where x.task_id = p_task and x.status = 'passed' order by x.decided_at desc limit 1;
  seq := app.log_work('task.approved', p_citizen, p_onbehalf, 'task:' || p_task::text,
           jsonb_build_object('submission', s.id::text, 'room', (select r.code from app.work_rooms r where r.id = t.room_id), 'by', 'poster'));
  update app.work_tasks x set status = 'approved', approved_at = now(), approved_seq = seq, updated_at = now() where x.id = p_task;
  update app.work_projects x set updated_at = now() where x.id = t.project_id;
  return seq;
end
$$;

-- The poster's approval of work an audit passed (the person gate), when the rules or an administrator passed it.
create function app.work_approve(p_task uuid)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  t record;
begin
  select * into w from app.work_who();
  select * into t from app.work_tasks x where x.id = p_task for update;
  if t.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  if coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) is distinct from w.member_id then
    raise exception 'only the task''s poster approves it' using errcode = '42501';
  end if;
  if t.status <> 'audited' then
    raise exception 'work_state' using errcode = 'P0001', hint = 'Only work that passed its audit can be approved; this task is ' || t.status || '.';
  end if;
  perform app.work_approve_as(p_task, w.citizen, case when w.agent_id is not null then 'member:' || w.member_id end);
  return 'approved';
end
$$;

-- The poster closes an open task nobody has claimed.
create function app.work_cancel(p_task uuid)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  t record;
begin
  select * into w from app.work_who();
  select * into t from app.work_tasks x where x.id = p_task for update;
  if t.id is null or coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) is distinct from w.member_id then
    raise exception 'only the task''s poster closes it' using errcode = '42501';
  end if;
  if t.status <> 'open' then
    raise exception 'work_state' using errcode = 'P0001', hint = 'Only an open task can be closed; this one is ' || t.status || '.';
  end if;
  update app.work_tasks x set status = 'closed', updated_at = now() where x.id = p_task;
  return 'closed';
end
$$;

-- ---- GitHub: this repository's pull requests and issues, as the site read them from GitHub's public API ----
-- The pull requests that need their detail read (changed lines, who merged): merged ones without it, oldest first.
create function app.work_github_wanted(p_n integer)
returns table (number integer)
language sql stable security definer set search_path = pg_catalog
as $$
  select x.number from app.work_github_prs x where x.detail_at is null and x.merged_at is not null order by x.number limit least(greatest(p_n, 1), 20)
$$;

-- p: {prs: [...], issues: [...], details: [...]} (at most 100 of each; the shapes are db/workjobs.js's). Everything is
-- public GitHub data, checked here again. Returns counts.
create function app.work_github_sync(p jsonb)
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  x jsonb;
  st record;
  pr record;
  proj uuid;
  rid uuid;
  tid uuid;
  cl record;
  added integer := 0;
  tasks integer := 0;
  closed integer := 0;
  sub uuid;
  title text;
  def_room uuid := (select r.id from app.work_rooms r where r.code = '15-0000');
begin
  if p is null or jsonb_typeof(p) <> 'object' or jsonb_array_length(coalesce(p -> 'prs', '[]')) > 100 or jsonb_array_length(coalesce(p -> 'issues', '[]')) > 100
     or jsonb_array_length(coalesce(p -> 'details', '[]')) > 100 then
    raise exception 'bad GitHub sync' using errcode = '22023';
  end if;
  -- The repository's own project (milestone 0), made on first use.
  insert into app.work_projects (title, description, room_id, source, github_milestone)
    values ('The site''s own build', 'Pull requests and issues in MyChiefOS/start-of-something-great, the public repository of this site, read through GitHub''s public API. A merged pull request is finished work; an open issue is an open task.',
            def_room, 'github', 0) on conflict do nothing;
  for x in select * from jsonb_array_elements(coalesce(p -> 'prs', '[]')) loop
    if (x ->> 'number') !~ '^[1-9][0-9]{0,6}$' or coalesce(x ->> 'author', '') !~ '^[a-z0-9-]{1,39}$' or x ->> 'state' <> all (array['open', 'closed']) then continue; end if;
    insert into app.work_github_prs (number, title, author, state, merged_at, base, merge_sha, refs, milestone, milestone_title, room_code, created_at)
      values ((x ->> 'number')::integer, left(coalesce(nullif(btrim(x ->> 'title'), ''), 'Pull request'), 140), x ->> 'author', x ->> 'state',
              (x ->> 'merged_at')::timestamptz, left(coalesce(x ->> 'base', ''), 100), case when x ->> 'merge_sha' ~ '^[0-9a-f]{40}$' then x ->> 'merge_sha' end,
              case when coalesce(x ->> 'refs', '') ~ '^[0-9,]*$' and char_length(x ->> 'refs') <= 400 then coalesce(x ->> 'refs', '') else '' end,
              case when x ->> 'milestone' ~ '^[1-9][0-9]{0,6}$' then (x ->> 'milestone')::integer end, left(x ->> 'milestone_title', 140),
              case when x ->> 'room' ~ '^[0-9]{2}-0000$' then x ->> 'room' end, (x ->> 'created_at')::timestamptz)
    on conflict (number) do update set title = excluded.title, state = excluded.state, merged_at = excluded.merged_at, base = excluded.base,
      merge_sha = excluded.merge_sha, refs = excluded.refs, milestone = excluded.milestone, milestone_title = excluded.milestone_title,
      room_code = excluded.room_code, seen_at = now();
    delete from app.work_github_codes c where c.pr_number = (x ->> 'number')::integer;
    insert into app.work_github_codes (pr_number, code_hash)
      select (x ->> 'number')::integer, h from jsonb_array_elements_text(coalesce(x -> 'codes', '[]')) h where h ~ '^[0-9a-f]{64}$' limit 20
      on conflict do nothing;
    added := added + 1;
  end loop;
  for x in select * from jsonb_array_elements(coalesce(p -> 'details', '[]')) loop
    if (x ->> 'number') !~ '^[1-9][0-9]{0,6}$' or (x ->> 'additions') !~ '^[0-9]{1,8}$' or (x ->> 'deletions') !~ '^[0-9]{1,8}$' then continue; end if;
    update app.work_github_prs g set additions = (x ->> 'additions')::integer, deletions = (x ->> 'deletions')::integer,
      merged_by = case when x ->> 'merged_by' ~ '^[a-z0-9-]{1,39}$' then x ->> 'merged_by' end, detail_at = now()
     where g.number = (x ->> 'number')::integer;
  end loop;
  -- Merged pull requests with their detail: finished work. A pull request whose description carries a live claim's
  -- code is that claim's submission; any other is submitted by its author, as the repository's history.
  for pr in select g.* from app.work_github_prs g where g.merged_at is not null and g.detail_at is not null and g.base = 'main'
             and not exists (select 1 from app.work_submissions s where s.pr_number = g.number) order by g.number limit 100 loop
    select c.* into cl from app.work_claims c join app.work_github_codes k on k.code_hash = c.code_hash and k.pr_number = pr.number
     where c.status = 'active' limit 1;
    if cl.id is not null then
      update app.work_claims c set status = 'submitted' where c.id = cl.id;
      sub := app.work_record(cl.task_id, cl.id, case when cl.agent_id is null then 'member' else 'agent' end, cl.member_id, cl.agent_id, null,
                             case when cl.agent_id is not null then 'member:' || cl.member_id end, 'pr',
                             'https://github.com/MyChiefOS/start-of-something-great/pull/' || pr.number, null, pr.number, '', 0);
      continue;
    end if;
    if pr.milestone is not null then
      insert into app.work_projects (title, description, room_id, source, github_milestone)
        values (left(coalesce(pr.milestone_title, 'Milestone ' || pr.milestone), 140), 'A milestone in MyChiefOS/start-of-something-great, read through GitHub''s public API.',
                def_room, 'github', pr.milestone) on conflict do nothing;
    end if;
    select p2.id into proj from app.work_projects p2 where p2.source = 'github' and p2.github_milestone = coalesce(pr.milestone, 0);
    rid := coalesce((select r.id from app.work_rooms r where r.code = pr.room_code), def_room);
    insert into app.work_tasks (project_id, room_id, title, description, class, size, source, github_kind, github_number, github_author, status, created_at)
      values (proj, rid, pr.title, 'Pull request #' || pr.number || ' in this site''s repository, merged into main on '
              || to_char(pr.merged_at at time zone 'UTC', 'YYYY-MM-DD') || '. ' || (pr.additions + pr.deletions) || ' lines changed.',
              'either', app.work_size_band(pr.additions + pr.deletions), 'github', 'pr', pr.number, pr.author, 'submitted', pr.created_at)
      on conflict (github_kind, github_number) do nothing returning id into tid;
    if tid is null then continue; end if;
    perform app.work_record(tid, null, 'github', null, null, pr.author, null, 'pr', 'https://github.com/MyChiefOS/start-of-something-great/pull/' || pr.number,
                            null, pr.number, '', 0);
    update app.work_projects x2 set updated_at = now() where x2.id = proj;
    tasks := tasks + 1;
  end loop;
  -- Issues: open ones are open tasks; a closed issue's task closes if nobody is working on it.
  for x in select * from jsonb_array_elements(coalesce(p -> 'issues', '[]')) loop
    if (x ->> 'number') !~ '^[1-9][0-9]{0,6}$' or coalesce(x ->> 'author', '') !~ '^[a-z0-9-]{1,39}$' or x ->> 'state' <> all (array['open', 'closed']) then continue; end if;
    if x ->> 'state' = 'closed' then
      update app.work_tasks t set status = 'closed', updated_at = now() where t.github_kind = 'issue' and t.github_number = (x ->> 'number')::integer and t.status = 'open';
      if found then closed := closed + 1; end if;
      continue;
    end if;
    if exists (select 1 from app.work_tasks t where t.github_kind = 'issue' and t.github_number = (x ->> 'number')::integer) then
      update app.work_tasks t set title = left(coalesce(nullif(btrim(x ->> 'title'), ''), t.title), 140)
       where t.github_kind = 'issue' and t.github_number = (x ->> 'number')::integer and t.status = 'open';
      continue;
    end if;
    if x ->> 'milestone' ~ '^[1-9][0-9]{0,6}$' then
      insert into app.work_projects (title, description, room_id, source, github_milestone)
        values (left(coalesce(x ->> 'milestone_title', 'Milestone ' || (x ->> 'milestone')), 140), 'A milestone in MyChiefOS/start-of-something-great, read through GitHub''s public API.',
                def_room, 'github', (x ->> 'milestone')::integer) on conflict do nothing;
    end if;
    select p2.id into proj from app.work_projects p2 where p2.source = 'github'
      and p2.github_milestone = coalesce(case when x ->> 'milestone' ~ '^[1-9][0-9]{0,6}$' then (x ->> 'milestone')::integer end, 0);
    rid := coalesce((select r.id from app.work_rooms r where r.code = x ->> 'room'), def_room);
    title := left(coalesce(nullif(btrim(x ->> 'title'), ''), 'Issue'), 140);
    insert into app.work_tasks (project_id, room_id, title, description, class, size, source, github_kind, github_number, github_author, created_at)
      values (proj, rid, title, 'Issue #' || (x ->> 'number') || ' in this site''s repository. Claim it, open a pull request that names the issue (#'
              || (x ->> 'number') || ') and carries your claim''s code in its description, and submit it once it is merged into main.',
              'either', 2, 'github', 'issue', (x ->> 'number')::integer, x ->> 'author', coalesce((x ->> 'created_at')::timestamptz, now()))
      on conflict (github_kind, github_number) do nothing;
    tasks := tasks + 1;
  end loop;
  -- GitHub refused some of this run's reads (its rate limit): nothing changes; Aaron is told in-app, once a day.
  if coalesce(p ->> 'refused', '0') ~ '^[1-9][0-9]{0,2}$' then
    perform app.notify(null, 'alert', 'GitHub is limiting the work module''s reads', (p ->> 'refused') || ' of the work module''s reads from GitHub were refused (its rate limit). '
      || 'Pull requests and issues update on a later run; nothing else stops. A read-only GITHUB_TOKEN raises the limit.', '/build', null, null,
      'work:github-limit:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end if;
  -- Submissions that were waiting for GitHub's facts.
  for sub in select s.id from app.work_submissions s join app.work_github_prs g on g.number = s.pr_number
              where s.status = 'waiting' and (g.merged_at is not null or g.state = 'closed') limit 100 loop
    perform app.work_jevs_run(sub);
  end loop;
  return jsonb_build_object('prs', added, 'tasks', tasks, 'closed', closed);
end
$$;

-- ---- The timer: claims that ran out, points whose dispute window closed, and Aaron's daily alert of work waiting for him ----
create function app.work_tick()
returns jsonb
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  st record;
  n_exp integer := 0;
  n_final integer := 0;
  n_fixed integer := 0;
  x record;
  waiting integer;
begin
  select * into st from app.work_settings where singleton for update skip locked;
  if not found or (st.last_tick_at is not null and st.last_tick_at > now() - interval '50 seconds') then return null; end if;
  update app.work_settings set last_tick_at = now() where singleton;
  for x in select c.id, c.task_id from app.work_claims c where c.status = 'active' and c.expires_at <= now() order by c.expires_at limit 500 for update skip locked loop
    update app.work_claims c set status = 'expired', ended_at = now() where c.id = x.id;
    update app.work_tasks t set status = 'open', updated_at = now() where t.id = x.task_id and t.status = 'claimed';
    n_exp := n_exp + 1;
  end loop;
  -- Work the worker could fix (W07, W08) that wasn't fixed while the claim held: the rules decide it again, and it fails.
  for x in select s.id from app.work_submissions s join app.work_claims c on c.id = s.claim_id
           where s.status = 'waiting' and s.jevs_verdict = 'waiting' and c.expires_at <= now()
             and (s.jevs_rules like '%W07%' or s.jevs_rules like '%W08%') order by s.created_at limit 100 loop
    perform app.work_jevs_run(x.id);
    n_fixed := n_fixed + 1;
  end loop;
  -- Points become final after the dispute window, unless a dispute or the check after is still open on them.
  update app.work_points p set status = 'final' where p.status = 'pending' and p.final_at <= now()
    and not exists (select 1 from app.work_disputes d where d.submission_id = p.submission_id and d.status = 'open')
    and not exists (select 1 from app.work_checks k where k.submission_id = p.submission_id and k.status = 'open');
  get diagnostics n_final = row_count;
  -- Aaron's daily alert while anything waits for him (in-app, once a day).
  select (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'admin')
       + (select count(*) from app.work_checks k where k.status = 'open') + (select count(*) from app.work_disputes d where d.status = 'open') into waiting;
  if waiting > 0 and st.last_alert_day is distinct from (now() at time zone 'UTC')::date then
    update app.work_settings set last_alert_day = (now() at time zone 'UTC')::date where singleton;
    perform app.notify(null, 'alert', 'Work waits for you', waiting || case when waiting = 1 then ' item of work waits' else ' items of work wait' end
      || ' for you on Review: checks after a poster''s pass, disputes, or the repository''s own tasks. Points under a check or a dispute stay pending; nothing else stops.', '/admin/review#work', null, null,
      'work:waiting:' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
  end if;
  return jsonb_build_object('expired', n_exp, 'finalised', n_final, 'unfixed', n_fixed);
end
$$;

-- ---- Administrator: work that waits for a person, and decisions with a reason ----
create function app.work_admin()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator' using errcode = '42501'; end if;
  -- Each item says whether the administrator reading it is a party to it (did the work, posted the task or opened the
  -- dispute): those wait for Third Look, and the page doesn't offer to decide them.
  return jsonb_build_object('generated_at', now(),
    'waiting', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('submission', s.id, 'jevs_rules', s.jevs_rules, 'note', s.note,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256), 'party', app.work_party(s.id, me))
                         order by s.created_at)
                        from app.work_submissions s where s.status = 'review' and s.route = 'admin'), '[]'::jsonb),
    'checks', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('check', k.id, 'submission', s.id, 'why', k.why, 'note', s.note,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256),
                           'decided_by', s.decided_by, 'reason', s.reason, 'party', app.work_party(s.id, me)) order by k.created_at)
                       from app.work_checks k join app.work_submissions s on s.id = k.submission_id where k.status = 'open'), '[]'::jsonb),
    'disputes', coalesce((select jsonb_agg(app.work_card(s.task_id) || jsonb_build_object('dispute', d.id, 'submission', s.id, 'dispute_reason', d.reason,
                           'artifact', jsonb_build_object('kind', s.artifact_kind, 'url', s.artifact_url, 'sha256', s.artifact_sha256),
                           'decided_by', s.decided_by, 'reason', s.reason, 'party', app.work_party(s.id, me) or d.member_id = me) order by d.created_at)
                         from app.work_disputes d join app.work_submissions s on s.id = d.submission_id where d.status = 'open'), '[]'::jsonb),
    'held', (select count(*) from app.work_submissions s where s.status = 'review' and s.route = 'held'));
end
$$;

-- Whether a member is a party to a submission: did the work (or owns the agent that did) or posted the task (or owns
-- the agent that did).
create function app.work_party(p_sub uuid, p_member uuid)
returns boolean
language sql stable security definer set search_path = pg_catalog
as $$
  select exists (select 1 from app.work_submissions s join app.work_tasks t on t.id = s.task_id where s.id = p_sub
                 and (s.worker_member = p_member or coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent)) = p_member))
$$;

-- An administrator decides work on the repository's own tasks that the rules couldn't, with a reason.
create function app.work_person_decide(p_sub uuid, p_verdict text, p_size integer, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides this' using errcode = '42501'; end if;
  if p_verdict is null or p_verdict <> all (array['pass', 'fail']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300
     or (p_size is not null and p_size <> all (array[1, 2, 3, 5, 8])) then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.id is null or s.status <> 'review' or s.route <> 'admin' then return 'not_waiting'; end if;
  if app.work_party(p_sub, app.current_member()) then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You did or posted this work, so you can''t decide its audit: it waits for Third Look.';
  end if;
  insert into app.work_person_votes (submission_id, member_id, verdict, size, reason) values (p_sub, app.current_member(), p_verdict, p_size, btrim(p_reason));
  perform app.work_finish(p_sub, p_verdict, 'person', 100, btrim(p_reason));
  return p_verdict;
end
$$;

-- Reverses a pass whose points are still pending (an upheld dispute, or the check after found it wrong): the points
-- are removed, the log says so, the task reopens (a pull request of the repository's history closes), and the worker
-- and poster are told.
create function app.work_reverse(p_sub uuid, p_by text, p_reason text)
returns void
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  t record;
  poster uuid;
begin
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.status <> 'passed' then return; end if;
  select * into t from app.work_tasks x where x.id = s.task_id for update;
  update app.work_points x set status = 'removed' where x.submission_id = p_sub;
  update app.work_submissions x set status = 'reversed', reason = left(p_reason, 300) where x.id = p_sub;
  perform app.log_work('audit.verdict', 'work-audit', null, 'submission:' || p_sub::text,
    jsonb_build_object('task', s.task_id::text, 'verdict', 'reversed', 'by', p_by, 'points', 0));
  update app.work_tasks x set status = case when t.source = 'github' and t.github_kind = 'pr' then 'closed' else 'open' end,
    approved_at = null, approved_seq = null, updated_at = now() where x.id = t.id;
  update app.work_claims c set status = 'expired', ended_at = coalesce(c.ended_at, now()) where c.id = s.claim_id and c.status in ('active', 'submitted', 'done');
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if s.worker_member is not null then
    perform app.notify(s.worker_member, 'work_decided', 'A pass on your work was reversed', 'The pass on your work for "' || left(t.title, 80) || '" was reversed ('
      || p_by || '): ' || left(p_reason, 200) || ' Its points are removed.', '/tasks/' || t.id, 'task', t.id, 'work:reversed:' || p_sub);
  end if;
  if poster is not null and poster is distinct from s.worker_member then
    perform app.notify(poster, 'work_decided', 'A pass on your task was reversed', 'The pass on "' || left(t.title, 80) || '" was reversed (' || p_by || '). The task is open again.',
      '/tasks/' || t.id, 'task', t.id, 'work:reversed-poster:' || p_sub);
  end if;
end
$$;

-- The poster's check of work the rules couldn't decide (maker-checker; Aaron, Nov 6). A pass is limited the way a
-- bank limits one approver: the same poster and worker (by owner) at most pair_limit passes in 30 days, at most
-- poster_daily_points a day to one worker, and both at JEVs's poster_level. Past a limit it waits for Third Look. A
-- pass also approves the task. A sample of passes is checked again (the check after), at most check_daily a day.
create function app.work_poster_decide(p_sub uuid, p_verdict text, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  s record;
  t record;
  st record;
  poster uuid;
  pairs integer;
  today integer;
  pts integer;
  size smallint;
  why text;
  held text;
begin
  select * into w from app.work_who();
  if w.agent_id is not null then raise exception 'a person checks work, not an agent: your owner does' using errcode = '42501'; end if;
  if p_verdict is null or p_verdict <> all (array['pass', 'fail']) or (p_verdict = 'fail' and (p_reason is null or char_length(btrim(p_reason)) not between 3 and 300))
     or char_length(coalesce(p_reason, '')) > 300 then
    raise exception 'bad check' using errcode = '22023';
  end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  select * into t from app.work_tasks x where x.id = s.task_id for update;
  poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
  if poster is distinct from w.member_id then raise exception 'only the task''s poster checks its work' using errcode = '42501'; end if;
  if s.status <> 'review' or s.route <> 'poster' then
    raise exception 'work_state' using errcode = 'P0001', hint = 'This work doesn''t wait for your check.';
  end if;
  if p_verdict = 'fail' then
    perform app.work_finish(p_sub, 'fail', 'poster', 100, btrim(p_reason));
    return 'fail';
  end if;
  select * into st from app.work_settings where singleton;
  size := app.work_confirmed_size(p_sub, 'poster');
  pts := app.work_points_of(size, 100, 100, st.points_cap);
  select count(*) into pairs from app.work_submissions x join app.work_tasks y on y.id = x.task_id
   where x.decided_by = 'poster' and x.status = 'passed' and x.decided_at > now() - interval '30 days' and x.worker_member = s.worker_member
     and coalesce(y.poster_member, (select g.owner_id from app.agents g where g.id = y.poster_agent)) = poster;
  select coalesce(sum(p.points), 0) into today from app.work_points p join app.work_submissions x on x.id = p.submission_id
   where x.decided_by = 'poster' and p.status <> 'removed' and x.worker_member = s.worker_member and p.created_at > now() - interval '1 day';
  if (select m.trust_level from app.members m where m.id = poster) < st.poster_level
     or (select m.trust_level from app.members m where m.id = s.worker_member) < st.poster_level then
    held := 'The poster or the worker isn''t yet at JEVs''s level ' || st.poster_level || ', so a poster''s pass waits for Third Look.';
  elsif pairs >= st.pair_limit then
    held := 'This poster has passed this worker''s work ' || pairs || ' times in 30 days, the most one pair may, so it waits for Third Look.';
  elsif today + pts > st.poster_daily_points then
    held := 'This worker has ' || today || ' points from posters'' passes today; this would pass ' || st.poster_daily_points || ', so it waits for Third Look.';
  end if;
  if held is not null then
    update app.work_submissions x set route = 'held', held_reason = held where x.id = p_sub;
    return 'held';
  end if;
  perform app.work_finish(p_sub, 'pass', 'poster', 100, coalesce(nullif(btrim(p_reason), ''), 'Passed by the task''s poster.'));
  perform app.work_approve_as(t.id, w.citizen, null);
  -- The check after: at random, and the riskiest (the biggest size, a pair at its limit, a note that had contact details).
  why := case when size = 8 then 'size' when pairs + 1 >= st.pair_limit then 'pair' when s.note_hits > 0 then 'note'
              when random() < st.check_rate then 'random' end;
  if why is not null and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now())) < st.check_daily
     and not exists (select 1 from app.members m where m.is_admin and m.id in (poster, s.worker_member)) then
    insert into app.work_checks (submission_id, why) values (p_sub, why);
  end if;
  return 'pass';
end
$$;

-- A dispute: anyone signed in but the worker, while the pass's points are pending, with a reason. The points wait.
create function app.work_dispute(p_sub uuid, p_reason text)
returns uuid
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  s record;
  n integer;
  did uuid;
begin
  select * into w from app.work_who();
  if w.agent_id is not null then raise exception 'a person disputes work, not an agent' using errcode = '42501'; end if;
  if p_reason is null or char_length(btrim(p_reason)) not between 3 and 500 then raise exception 'bad dispute' using errcode = '22023'; end if;
  select * into s from app.work_submissions x where x.id = p_sub for update;
  if s.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  if s.worker_member = w.member_id then raise exception 'work_own' using errcode = 'P0001', hint = 'This is your own work: you can''t dispute it.'; end if;
  if s.status <> 'passed' or not exists (select 1 from app.work_points p where p.submission_id = p_sub and p.status = 'pending') then
    raise exception 'work_state' using errcode = 'P0001', hint = 'Only a pass whose points are still pending can be disputed.';
  end if;
  if exists (select 1 from app.work_disputes d where d.submission_id = p_sub and d.status = 'open') then
    raise exception 'work_state' using errcode = 'P0001', hint = 'A dispute on this work is already open.';
  end if;
  select count(*) into n from app.work_disputes d where d.member_id = w.member_id and d.created_at > now() - interval '1 day';
  if n >= (select x.dispute_daily from app.work_settings x where x.singleton) then
    raise exception 'work_cap' using errcode = 'P0001', hint = 'You have opened ' || n || ' disputes today, the most for one day.';
  end if;
  insert into app.work_disputes (submission_id, member_id, reason) values (p_sub, w.member_id, btrim(p_reason)) returning id into did;
  perform app.notify(null, 'alert', 'A pass on work is disputed', 'Someone disputed a pass on a task. Its points wait until you decide it on Review.', '/admin/review#work',
    'submission', p_sub, 'work:dispute:' || did);
  return did;
end
$$;

-- An administrator decides a dispute or the check after, with a reason, never on work they are a party to.
create function app.work_dispute_decide(p_dispute uuid, p_decision text, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  d record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides disputes' using errcode = '42501'; end if;
  if p_decision is null or p_decision <> all (array['uphold', 'dismiss']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into d from app.work_disputes x where x.id = p_dispute for update;
  if d.id is null or d.status <> 'open' then return 'not_open'; end if;
  if app.work_party(d.submission_id, app.current_member()) or d.member_id = app.current_member() then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You are a party to this work or this dispute, so it waits for Third Look.';
  end if;
  update app.work_disputes x set status = case when p_decision = 'uphold' then 'upheld' else 'dismissed' end, decided_by = app.current_member(),
    decision = btrim(p_reason), decided_at = now() where x.id = p_dispute;
  if p_decision = 'uphold' then perform app.work_reverse(d.submission_id, 'dispute', btrim(p_reason)); end if;
  perform app.notify(d.member_id, 'work_decided', 'Your dispute was decided', 'Your dispute was ' || case when p_decision = 'uphold' then 'upheld: the pass is reversed.' else 'dismissed.' end
    || ' ' || left(btrim(p_reason), 200), '/tasks/' || (select s.task_id from app.work_submissions s where s.id = d.submission_id), 'submission', d.submission_id, 'work:dispute-decided:' || d.id);
  return p_decision;
end
$$;

create function app.work_check_decide(p_check uuid, p_decision text, p_reason text)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  k record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator decides checks' using errcode = '42501'; end if;
  if p_decision is null or p_decision <> all (array['confirm', 'reverse']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad decision' using errcode = '22023';
  end if;
  select * into k from app.work_checks x where x.id = p_check for update;
  if k.id is null or k.status <> 'open' then return 'not_open'; end if;
  if app.work_party(k.submission_id, app.current_member()) then
    raise exception 'work_own' using errcode = 'P0001', hint = 'You are a party to this work, so its check waits for Third Look.';
  end if;
  update app.work_checks x set status = case when p_decision = 'confirm' then 'confirmed' else 'reversed' end, member_id = app.current_member(),
    reason = btrim(p_reason), decided_at = now() where x.id = p_check;
  if p_decision = 'reverse' then perform app.work_reverse(k.submission_id, 'check', btrim(p_reason)); end if;
  return p_decision;
end
$$;

-- Aaron removes a task or project that breaks the terms (moderation): it leaves every public list.
create function app.work_remove(p_kind text, p_id uuid)
returns text
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator removes work' using errcode = '42501'; end if;
  if p_kind = 'task' then
    update app.work_tasks x set status = 'removed', updated_at = now() where x.id = p_id;
    update app.work_claims c set status = 'released', ended_at = now() where c.task_id = p_id and c.status in ('active', 'submitted');
    update app.work_points x set status = 'removed' where x.task_id = p_id;
  elsif p_kind = 'project' then
    update app.work_projects x set status = 'removed', updated_at = now() where x.id = p_id;
    update app.work_tasks x set status = 'removed', updated_at = now() where x.project_id = p_id;
    update app.work_points x set status = 'removed' where x.task_id in (select t.id from app.work_tasks t where t.project_id = p_id);
  else
    raise exception 'bad removal' using errcode = '22023';
  end if;
  return 'removed';
end
$$;

-- ---- Rights ----
-- Internal: called only by this module's own functions.
revoke execute on function
  app.work_who(), app.work_cap(uuid, uuid, text, boolean), app.work_display(uuid, uuid, text), app.work_facts(uuid),
  app.work_confirmed_size(uuid, text), app.work_finish(uuid, text, text, integer, text), app.work_jevs_run(uuid),
  app.work_card(uuid), app.work_anchored_through(), app.work_project_card(uuid),
  app.work_record(uuid, uuid, text, uuid, uuid, text, text, text, text, text, integer, text, integer),
  app.work_summary(), app.work_tasks(text, text, uuid, text, uuid, integer), app.work_task(uuid),
  app.work_rooms_list(), app.work_room(text), app.work_projects_list(text, text, text, uuid, integer),
  app.work_project(uuid), app.work_mine(), app.work_project_create(text, text, text),
  app.work_task_create(uuid, text, text, text, integer), app.work_claim(uuid, text), app.work_release(uuid),
  app.work_handoff(uuid, uuid, text), app.work_submit(uuid, text, text, text, text, integer), app.work_approve(uuid),
  app.work_cancel(uuid), app.work_github_wanted(integer), app.work_github_sync(jsonb), app.work_tick(),
  app.work_admin(), app.work_person_decide(uuid, text, integer, text), app.work_remove(text, uuid),
  app.work_brake_check(uuid), app.work_approve_as(uuid, text, text), app.work_party(uuid, uuid), app.work_reverse(uuid, text, text),
  app.work_poster_decide(uuid, text, text), app.work_dispute(uuid, text), app.work_dispute_decide(uuid, text, text),
  app.work_check_decide(uuid, text, text), app.work_task_of(uuid) from public;
-- The site's role: what the API offers (each checks who is acting itself).
grant execute on function
  app.work_summary(), app.work_tasks(text, text, uuid, text, uuid, integer), app.work_task(uuid),
  app.work_rooms_list(), app.work_room(text), app.work_projects_list(text, text, text, uuid, integer),
  app.work_project(uuid), app.work_mine(), app.work_project_create(text, text, text),
  app.work_task_create(uuid, text, text, text, integer), app.work_claim(uuid, text), app.work_release(uuid),
  app.work_handoff(uuid, uuid, text), app.work_submit(uuid, text, text, text, text, integer), app.work_approve(uuid),
  app.work_cancel(uuid), app.work_github_wanted(integer), app.work_github_sync(jsonb), app.work_tick(),
  app.work_admin(), app.work_person_decide(uuid, text, integer, text), app.work_remove(text, uuid),
  app.work_poster_decide(uuid, text, text), app.work_dispute(uuid, text), app.work_dispute_decide(uuid, text, text),
  app.work_check_decide(uuid, text, text), app.work_task_of(uuid) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_work;
