-- 038 The public log (the design handoff of Nov 5, 2026, CODING_AGENT_SPEC.md section 1, phase 2; Aaron, Nov 5: "Phase 2
--   we can use GItHUB for now" and "2.5 seem like it has a fix on its own"). One append-only Merkle tree (RFC 9162) of
--   what the site and its checks did, signed by a key made here, so anyone can check a receipt without trusting us.
--
--   * Entries. Each is a JSON object written in canonical form (RFC 8785, JCS): v, type, ts, actor, on_behalf_of,
--     subject, payload, prev (the hash of the same actor's previous entry, or null) and sig (null: in phase 2 no
--     actor has a signing key of its own; people's come with phase 3). Entries hold only random IDs and keyed hashes,
--     never a post's text, a name or an email (Aaron, Nov 5). A keyed hash is SHA-256 over a random 32-byte key and
--     the canonical facts; the key is kept in app.log_openings and is deleted with the post or decision it belongs to,
--     so deleting an account still removes the person's data: what stays in the log no longer opens to anything.
--   * What goes in first: every agent post as it goes live (a "post" entry: the agent and the member it acts for, each
--     by a random name kept only for the log and deleted with the account (app.log_names), and its sealed facts; its
--     key is shown in the receipt while the post is live); JEVs's decisions, on the site and on GitHub, queued as they
--     are made (app.log_queue) and added once their hour has ended, a few hundred at a time, stamped with the hour and
--     shuffled within it, each under a fresh random ID with its record sealed, so the public log tells no more than
--     /api/decisions does about who was decided or how, nor when within the hour (036's review; the review of 038, H3,
--     H4 and M2); and Aaron's decisions on proposals, as the site sees them on GitHub (app.log_proposal). Later modules
--     (tasks, audits, disputes) append to the same tree through app.log_append.
--   * The tree. Leaf hash = SHA-256(0x00 || entry bytes), node hash = SHA-256(0x01 || left || right). Every complete
--     subtree's hash is kept (app.log_nodes), so any proof needs at most two lookups per level. Appends take the one
--     head row's lock, so they are serialised and seq has no gaps.
--   * Checkpoints. app.log_checkpoint(), from the timer route every minute, signs a new checkpoint when the tree grew
--     and the last one is 60 seconds old or 100 entries behind, in the c2sp signed-note format, with Ed25519. Before
--     it signs, it checks the tree still reaches the last signed root; if not, it signs nothing, marks the log
--     unverified and alerts Aaron. The site keeps running either way (checks alert, never lock out).
--   * The key. Made here from Postgres's own random generator, inside the database. Only dog_log, a narrow role made
--     here, may read its seed: not the site, not the owner role's policies, not any API. (Like every row, it is
--     readable by the database's superuser, which on Supabase is the migration runner's login.) Ed25519 is written in
--     PL/pgSQL below, since plain Postgres has no Ed25519 (pgcrypto has none; pgsodium is being retired by Supabase);
--     it is checked against RFC 8032's test vectors and Node's own Ed25519 (test/public-log.test.js). It is not
--     constant-time (RISKS.md RK109).
--   * The witness. A GitHub Actions job in this repository (.github/workflows/log-witness.yml) keeps each checkpoint
--     on the branch log-witness and checks it against the last. The site reads that copy (app.log_witness_report):
--     when the witness raises an alarm or its copy doesn't match this tree, the log is marked unverified with the
--     reason and Aaron gets an alert in his inbox. Nothing stops. Only a reviewed migration clears it
--     (app.log_clear_alarm, which records the clearing in the log itself): not the site's login (the review of 038, M3).
-- Nothing here changes sign-in, sessions, posting rules, JEVs's decisions or what anyone may see of posts.

-- ---- The log's role, made by the runner's own login (like dog_jevs in 010) ----
do $log_role$
begin
  if not exists (select 1 from pg_roles where rolname = 'dog_log') then
    create role dog_log nologin noinherit nobypassrls;
  end if;
end
$log_role$;
grant dog_log to dog_owner;

set local role dog_owner;
grant usage on schema app to dog_log;
grant execute on function app.uuid_v7() to dog_log;

-- ---- Tables ----
-- The head: how many entries the tree has. One row; its lock orders appends.
create table app.log_head (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  size bigint not null default 0 check (size >= 0)
);
alter table app.log_head enable row level security;
alter table app.log_head force row level security;
create policy log_head_read on app.log_head for select to dog_app using (true);
create policy log_head_log on app.log_head for all to dog_log using (true) with check (true);
grant select (size) on app.log_head to dog_app;
grant select, insert, update on app.log_head to dog_log;

-- The key. Its seed is readable by dog_log only; its public half by anyone.
create table app.log_keys (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  name text not null check (char_length(name) <= 64 and name = 'dayonegreat.com/log'),
  seed bytea not null check (octet_length(seed) = 32),
  public_key bytea not null check (octet_length(public_key) = 32),
  key_id bytea not null check (octet_length(key_id) = 4),
  created_at timestamptz not null default now()
);
alter table app.log_keys enable row level security;
alter table app.log_keys force row level security;
create policy log_keys_public on app.log_keys for select to dog_app using (true);
create policy log_keys_log on app.log_keys for all to dog_log using (true) with check (true);
grant select (name, public_key, key_id, created_at) on app.log_keys to dog_app;
grant select, insert on app.log_keys to dog_log;

create table app.log_entries (
  id uuid primary key default app.uuid_v7(),
  seq bigint not null unique check (seq >= 0 and seq < 1000000000000000),
  leaf_hash bytea not null unique check (octet_length(leaf_hash) = 32),
  entry jsonb not null check (jsonb_typeof(entry) = 'object' and octet_length(entry::text) <= 4096),
  entry_jcs text not null check (char_length(entry_jcs) <= 4096),
  type text not null check (type = any (array['key.registered', 'post', 'jevs.decision', 'proposal.decided', 'log.alarm_cleared'])),
  actor text not null check (char_length(actor) <= 80),
  subject text not null check (char_length(subject) <= 80),
  created_at timestamptz not null default now(),
  constraint log_entries_leaf check (leaf_hash = sha256('\x00'::bytea || convert_to(entry_jcs, 'UTF8'))),
  constraint log_entries_same check (entry_jcs::jsonb = entry)
);
create index log_entries_actor on app.log_entries (actor, seq desc);
create index log_entries_subject on app.log_entries (subject);
alter table app.log_entries enable row level security;
alter table app.log_entries force row level security;
create policy log_entries_read on app.log_entries for select to dog_app using (true);
create policy log_entries_log_select on app.log_entries for select to dog_log using (true);
create policy log_entries_log_insert on app.log_entries for insert to dog_log with check (true);
grant select on app.log_entries to dog_app;
grant select, insert on app.log_entries to dog_log;

-- Every complete subtree: level 0 holds the leaves, level k the hash of 2^k leaves starting at idx * 2^k.
create table app.log_nodes (
  id uuid primary key default app.uuid_v7(),
  level smallint not null check (level between 0 and 62),
  idx bigint not null check (idx >= 0),
  hash bytea not null check (octet_length(hash) = 32),
  unique (level, idx)
);
alter table app.log_nodes enable row level security;
alter table app.log_nodes force row level security;
create policy log_nodes_read on app.log_nodes for select to dog_app using (true);
create policy log_nodes_log_select on app.log_nodes for select to dog_log using (true);
create policy log_nodes_log_insert on app.log_nodes for insert to dog_log with check (true);
grant select on app.log_nodes to dog_app;
grant select, insert on app.log_nodes to dog_log;

create table app.log_checkpoints (
  id uuid primary key default app.uuid_v7(),
  size bigint not null unique check (size > 0),
  root bytea not null check (octet_length(root) = 32),
  note text not null check (char_length(note) <= 400),
  signature bytea not null check (octet_length(signature) = 64),
  created_at timestamptz not null default now()
);
alter table app.log_checkpoints enable row level security;
alter table app.log_checkpoints force row level security;
create policy log_checkpoints_read on app.log_checkpoints for select to dog_app using (true);
create policy log_checkpoints_log_select on app.log_checkpoints for select to dog_log using (true);
create policy log_checkpoints_log_insert on app.log_checkpoints for insert to dog_log with check (true);
grant select on app.log_checkpoints to dog_app;
grant select, insert on app.log_checkpoints to dog_log;

-- The keys of the keyed hashes, with the facts they seal. Deleted with what they belong to; readable by dog_log only.
create table app.log_openings (
  id uuid primary key default app.uuid_v7(),
  seq bigint not null unique check (seq >= 0),
  key bytea not null check (octet_length(key) = 32),
  facts jsonb not null check (jsonb_typeof(facts) = 'object' and octet_length(facts::text) <= 2048),
  post_id uuid references app.posts (id) on delete cascade,
  decision_id uuid references app.jevs_decisions (id) on delete cascade,
  gh_decision_id uuid references app.gh_decisions (id) on delete cascade,
  check (num_nonnulls(post_id, decision_id, gh_decision_id) = 1)
);
create index log_openings_post on app.log_openings (post_id);
create index log_openings_decision on app.log_openings (decision_id);
create index log_openings_gh on app.log_openings (gh_decision_id);
alter table app.log_openings enable row level security;
alter table app.log_openings force row level security;
create policy log_openings_log_select on app.log_openings for select to dog_log using (true);
create policy log_openings_log_insert on app.log_openings for insert to dog_log with check (true);
grant select, insert on app.log_openings to dog_log;

-- The proposal decisions already logged: one row per proposal, its last logged decision.
create table app.log_proposals_seen (
  id uuid primary key default app.uuid_v7(),
  number integer not null unique check (number between 1 and 10000000),
  decision text not null check (decision = any (array['approved', 'declined', 'shipped'])),
  seq bigint not null check (seq >= 0)
);
alter table app.log_proposals_seen enable row level security;
alter table app.log_proposals_seen force row level security;
create policy log_proposals_seen_log on app.log_proposals_seen for all to dog_log using (true) with check (true);
grant select, insert, update on app.log_proposals_seen to dog_log;

-- The random names the log uses for members and agents (the review of 038, M2): an entry names "agent:<name>" and
-- "member:<name>", never the account's own ID, which the site shows next to the person's name and which, as a
-- UUIDv7, carries their sign-up time. Deleted with the account or agent, so an entry no longer links to anyone.
create table app.log_names (
  id uuid primary key default app.uuid_v7(),
  name uuid not null unique default gen_random_uuid(),
  member_id uuid unique references app.members (id) on delete cascade,
  agent_id uuid unique references app.agents (id) on delete cascade,
  check (num_nonnulls(member_id, agent_id) = 1)
);
alter table app.log_names enable row level security;
alter table app.log_names force row level security;
create policy log_names_log on app.log_names for all to dog_log using (true) with check (true);
grant select, insert on app.log_names to dog_log;

-- JEVs's decisions waiting for their hour to end (the review of 038, H4 and L1): a trigger adds each one in the
-- decision's own transaction, so a decision is queued exactly when it commits, however long that takes, and none is
-- skipped. app.log_jevs_hours() takes a few hundred at a time and deletes what it logged.
create table app.log_queue (
  id uuid primary key default app.uuid_v7(),
  place text not null check (place = any (array['site', 'github'])),
  decision_id uuid not null,
  hour timestamptz not null,
  unique (place, decision_id)
);
create index log_queue_hour on app.log_queue (hour);
alter table app.log_queue enable row level security;
alter table app.log_queue force row level security;
create policy log_queue_log on app.log_queue for all to dog_log using (true) with check (true);
grant select, insert, delete on app.log_queue to dog_log;

-- What the site last read from the witness, and whether the log is verified. One row, readable by anyone.
create table app.log_witness (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  status text not null default 'unknown' check (status = any (array['unknown', 'ok', 'stale', 'unverified'])),
  reason text not null default '' check (char_length(reason) <= 300),
  witness_size bigint check (witness_size >= 0),
  witness_root bytea check (octet_length(witness_root) = 32),
  witnessed_at timestamptz,
  checked_at timestamptz,
  self_ok boolean not null default true,
  -- Set by any mismatch or alarm; only app.log_clear_alarm (a reviewed migration) clears it (the review of 038, M3).
  alarm boolean not null default false
);
alter table app.log_witness enable row level security;
alter table app.log_witness force row level security;
create policy log_witness_read on app.log_witness for select to dog_app using (true);
create policy log_witness_log on app.log_witness for all to dog_log using (true) with check (true);
grant select (status, reason, witness_size, witness_root, witnessed_at, checked_at, self_ok, alarm) on app.log_witness to dog_app;
grant select, insert, update on app.log_witness to dog_log;

-- ---- Append-only: no row of the tree, a checkpoint or the key is ever changed or deleted, by anyone ----
create function app.log_append_only() returns trigger
language plpgsql
as $$
begin
  raise exception 'the public log is append-only' using errcode = '42501';
end
$$;
create trigger log_entries_no_change before update or delete on app.log_entries for each row execute function app.log_append_only();
create trigger log_entries_no_truncate before truncate on app.log_entries for each statement execute function app.log_append_only();
create trigger log_nodes_no_change before update or delete on app.log_nodes for each row execute function app.log_append_only();
create trigger log_nodes_no_truncate before truncate on app.log_nodes for each statement execute function app.log_append_only();
create trigger log_checkpoints_no_change before update or delete on app.log_checkpoints for each row execute function app.log_append_only();
create trigger log_checkpoints_no_truncate before truncate on app.log_checkpoints for each statement execute function app.log_append_only();
create trigger log_keys_no_change before update or delete on app.log_keys for each row execute function app.log_append_only();
create trigger log_keys_no_truncate before truncate on app.log_keys for each statement execute function app.log_append_only();
alter table app.log_entries enable always trigger log_entries_no_change;
alter table app.log_entries enable always trigger log_entries_no_truncate;
alter table app.log_nodes enable always trigger log_nodes_no_change;
alter table app.log_nodes enable always trigger log_nodes_no_truncate;
alter table app.log_checkpoints enable always trigger log_checkpoints_no_change;
alter table app.log_checkpoints enable always trigger log_checkpoints_no_truncate;
alter table app.log_keys enable always trigger log_keys_no_change;
alter table app.log_keys enable always trigger log_keys_no_truncate;
-- The head only grows.
create function app.log_head_guard() returns trigger
language plpgsql
as $$
begin
  if new.size < old.size or new.singleton is distinct from old.singleton or new.id <> old.id then
    raise exception 'the public log only grows' using errcode = '42501';
  end if;
  return new;
end
$$;
create trigger log_head_guard before update on app.log_head for each row execute function app.log_head_guard();
create trigger log_head_no_delete before delete on app.log_head for each row execute function app.log_append_only();
alter table app.log_head enable always trigger log_head_guard;
alter table app.log_head enable always trigger log_head_no_delete;

-- ---- Canonical JSON (RFC 8785) for the entries this log writes: objects with lower-case ASCII keys (letters, digits, _), strings, whole
-- numbers, true, false, null and arrays. Strings are written by Postgres's to_json, which escapes exactly as
-- JSON.stringify does (", \, and characters below U+0020); test/public-log.test.js compares the two. ----
create function app.log_jcs(j jsonb) returns text
language plpgsql immutable
as $$
declare
  t text := jsonb_typeof(j);
  o text;
begin
  if t = 'object' then
    if exists (select 1 from jsonb_object_keys(j) k where k !~ '^[a-z][a-z0-9_]{0,31}$') then
      raise exception 'log entry keys are lower-case ASCII letters, digits and _' using errcode = '22023';
    end if;
    select '{' || coalesce(string_agg(to_json(e.key)::text || ':' || app.log_jcs(e.value), ',' order by e.key collate "C"), '') || '}'
      into o from jsonb_each(j) e;
    return o;
  elsif t = 'array' then
    select '[' || coalesce(string_agg(app.log_jcs(e.value), ',' order by e.n), '') || ']' into o
      from jsonb_array_elements(j) with ordinality e(value, n);
    return o;
  elsif t = 'string' then
    return to_json(j #>> '{}')::text;
  elsif t = 'number' then
    if j::text !~ '^-?(0|[1-9][0-9]{0,14})$' then raise exception 'log entries hold whole numbers only' using errcode = '22023'; end if;
    return j::text;
  end if;
  return j::text; -- true, false, null
end
$$;

-- RFC 3339, UTC, to the millisecond.
create function app.log_ts(p timestamptz) returns text
language sql immutable
as $$ select to_char(p at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') $$;

-- 32 bytes from four of Postgres's random UUIDs (488 random bits), hashed. No extension needed.
create function app.log_random32() returns bytea
language sql volatile
as $$ select sha256(decode(replace(gen_random_uuid()::text || gen_random_uuid()::text || gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'hex')) $$;

-- ---- Ed25519 (RFC 8032), signing only. Field arithmetic modulo p = 2^255 - 19 on numeric; points in extended
-- coordinates (a = -1 twisted Edwards: add-2008-hwcd-3 and dbl-2008-hwcd). ----
create function app.log_le_num(b bytea) returns numeric
language plpgsql immutable
as $$
declare
  n numeric := 0;
  i integer;
begin
  for i in reverse octet_length(b) - 1 .. 0 loop n := n * 256 + get_byte(b, i); end loop;
  return n;
end
$$;

create function app.log_num_le32(n numeric) returns bytea
language plpgsql immutable
as $$
declare
  b bytea := '\x0000000000000000000000000000000000000000000000000000000000000000';
  x numeric := n;
  i integer;
begin
  for i in 0 .. 31 loop b := set_byte(b, i, mod(x, 256)::integer); x := div(x, 256); end loop;
  return b;
end
$$;

-- s * B, for a 32-byte little-endian scalar s; returns the point's 32-byte encoding.
create function app.log_ed_base_mul(s bytea) returns bytea
language plpgsql immutable
as $$
declare
  p constant numeric := 57896044618658097711785492504343953926634992332820282019728792003956564819949;
  d2 constant numeric := 16295367250680780974490674513165176452449235426866156013048779062215315747161; -- 2d mod p
  gx constant numeric := 15112221349535400772501151409588531511454012693041857206046113283949847762202;
  gy constant numeric := 46316835694926478169428394003475163141307993866256225615783033603165251855960;
  gt numeric;
  x1 numeric := 0; y1 numeric := 1; z1 numeric := 1; t1 numeric := 0;
  a numeric; b numeric; c numeric; dd numeric; e numeric; f numeric; g numeric; h numeric;
  i integer; zi numeric; ex numeric; e2 numeric; xa numeric; ya numeric; o bytea;
begin
  gt := mod(gx * gy, p);
  for i in reverse 255 .. 0 loop
    a := mod(x1 * x1, p); b := mod(y1 * y1, p); c := mod(2 * z1 * z1, p);
    h := a + b; e := mod(h - mod((x1 + y1) * (x1 + y1), p) + p, p); g := mod(a - b + p, p); f := mod(c + g, p);
    x1 := mod(e * f, p); y1 := mod(g * h, p); t1 := mod(e * h, p); z1 := mod(f * g, p);
    if get_bit(s, i) = 1 then
      a := mod((y1 - x1 + p) * (gy - gx + p), p); b := mod((y1 + x1) * (gy + gx), p);
      c := mod(mod(t1 * d2, p) * gt, p); dd := mod(2 * z1, p);
      e := mod(b - a + p, p); f := mod(dd - c + p, p); g := mod(dd + c, p); h := mod(b + a, p);
      x1 := mod(e * f, p); y1 := mod(g * h, p); t1 := mod(e * h, p); z1 := mod(f * g, p);
    end if;
  end loop;
  zi := 1; ex := p - 2; e2 := z1;
  while ex > 0 loop
    if mod(ex, 2) = 1 then zi := mod(zi * e2, p); end if;
    e2 := mod(e2 * e2, p); ex := div(ex, 2);
  end loop;
  xa := mod(x1 * zi, p); ya := mod(y1 * zi, p);
  o := app.log_num_le32(ya);
  if mod(xa, 2) = 1 then o := set_byte(o, 31, get_byte(o, 31) | 128); end if;
  return o;
end
$$;

create function app.log_ed_scalar(seed bytea) returns bytea
language plpgsql immutable
as $$
declare
  h bytea := substring(sha512(seed) from 1 for 32);
begin
  h := set_byte(h, 0, get_byte(h, 0) & 248);
  h := set_byte(h, 31, (get_byte(h, 31) & 127) | 64);
  return h;
end
$$;

create function app.log_ed25519_public(seed bytea) returns bytea
language sql immutable
as $$ select app.log_ed_base_mul(app.log_ed_scalar(seed)) $$;

create function app.log_ed25519_sign(seed bytea, msg bytea) returns bytea
language plpgsql immutable
as $$
declare
  l constant numeric := 7237005577332262213973186563042994240857116359379907606001950938285454250989;
  hs bytea := sha512(seed);
  a bytea := app.log_ed_scalar(seed);
  pub bytea;
  r numeric;
  rr bytea;
  k numeric;
begin
  if octet_length(seed) <> 32 then raise exception 'an Ed25519 seed is 32 bytes' using errcode = '22023'; end if;
  pub := app.log_ed_base_mul(a);
  r := mod(app.log_le_num(sha512(substring(hs from 33 for 32) || msg)), l);
  rr := app.log_ed_base_mul(app.log_num_le32(r));
  k := mod(app.log_le_num(sha512(rr || pub || msg)), l);
  return rr || app.log_num_le32(mod(r + k * app.log_le_num(a), l));
end
$$;

-- The root of the first p_size leaves, from the complete subtrees (RFC 9162 section 2.1.1).
create function app.log_root(p_size bigint) returns bytea
language plpgsql stable
as $$
declare
  lvl integer;
  start bigint := 0;
  parts bytea[] := '{}';
  h bytea;
  k integer;
  r bytea;
begin
  if p_size is null or p_size < 0 then raise exception 'a tree size is 0 or more' using errcode = '22023'; end if;
  if p_size = 0 then return sha256(''::bytea); end if;
  for lvl in reverse 62 .. 0 loop
    if (p_size >> lvl) & 1 = 1 then
      select n.hash into h from app.log_nodes n where n.level = lvl and n.idx = start >> lvl;
      if h is null then raise exception 'the log has no subtree % at level %', start >> lvl, lvl using errcode = 'P0002'; end if;
      parts := parts || h;
      start := start + (1::bigint << lvl);
    end if;
  end loop;
  r := parts[array_length(parts, 1)];
  for k in reverse array_length(parts, 1) - 1 .. 1 loop r := sha256('\x01'::bytea || parts[k] || r); end loop;
  return r;
end
$$;

revoke execute on function app.log_append_only(), app.log_head_guard(), app.log_jcs(jsonb), app.log_ts(timestamptz), app.log_random32(),
  app.log_le_num(bytea), app.log_num_le32(numeric), app.log_ed_base_mul(bytea), app.log_ed_scalar(bytea), app.log_ed25519_public(bytea),
  app.log_ed25519_sign(bytea, bytea), app.log_root(bigint) from public;
grant execute on function app.log_jcs(jsonb), app.log_ts(timestamptz), app.log_random32(), app.log_le_num(bytea), app.log_num_le32(numeric),
  app.log_ed_base_mul(bytea), app.log_ed_scalar(bytea), app.log_ed25519_public(bytea), app.log_ed25519_sign(bytea, bytea), app.log_root(bigint) to dog_log;
-- The site computes no roots itself (it reads node hashes), but may ask for one, and may canonicalise for its tests of the format.
grant execute on function app.log_root(bigint), app.log_jcs(jsonb) to dog_app;

-- ---- What the log may read elsewhere: the facts of agent posts, JEVs's decisions, and Aaron's inbox for alerts ----
create policy posts_log_select on app.posts for select to dog_log using (lane = 'agents');
grant select (id, author_id, agent_id, lane, body, status, published_at, delegation, rules_version) on app.posts to dog_log;
create policy jevs_decisions_log_select on app.jevs_decisions for select to dog_log using (true);
grant select (id, created_at, action, subject_kind, subject_id, level, mode, effect, applied, error, total) on app.jevs_decisions to dog_log;
create policy gh_decisions_log_select on app.gh_decisions for select to dog_log using (true);
grant select (id, at, action, post_id, agent_id, member_id, risk, mode, effect, applied, total) on app.gh_decisions to dog_log;
create policy notices_log_insert on app.notices for insert to dog_log with check (member_id is null and kind = 'alert');
grant insert (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key) on app.notices to dog_log;
grant execute on function app.notify(uuid, text, text, text, text, text, uuid, text) to dog_log;

-- ---- The functions that write the log, in dog_log ----
grant create on schema app to dog_log;
set local role dog_log;

-- The one way anything is added: one entry, its leaf and every subtree it completes. Returns the entry's seq.
-- Called only by the functions below (and by later modules' own, made the same way).
create function app.log_append(p_type text, p_ts timestamptz, p_actor text, p_on_behalf_of text, p_subject text, p_payload jsonb)
returns bigint
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n bigint;
  prev bytea;
  e jsonb;
  j text;
  h bytea;
  lvl integer := 0;
  i bigint;
  sib bytea;
begin
  if p_actor !~ '^[a-z][a-z0-9_.:-]{0,79}$' or p_subject !~ '^[a-z][a-z0-9_.:-]{0,79}$'
     or (p_on_behalf_of is not null and p_on_behalf_of !~ '^[a-z][a-z0-9_.:-]{0,79}$') then
    raise exception 'log actors and subjects are typed IDs' using errcode = '22023';
  end if;
  update app.log_head x set size = x.size + 1 where x.singleton returning x.size - 1 into n;
  select x.leaf_hash into prev from app.log_entries x where x.actor = p_actor order by x.seq desc limit 1;
  e := jsonb_build_object('v', 1, 'type', p_type, 'ts', app.log_ts(p_ts), 'actor', p_actor, 'on_behalf_of', p_on_behalf_of,
         'subject', p_subject, 'payload', coalesce(p_payload, '{}'::jsonb), 'prev', encode(prev, 'hex'), 'sig', null);
  j := app.log_jcs(e);
  h := sha256('\x00'::bytea || convert_to(j, 'UTF8'));
  insert into app.log_entries (seq, leaf_hash, entry, entry_jcs, type, actor, subject) values (n, h, e, j, p_type, p_actor, p_subject);
  insert into app.log_nodes (level, idx, hash) values (0, n, h);
  i := n;
  while i % 2 = 1 loop
    select x.hash into sib from app.log_nodes x where x.level = lvl and x.idx = i - 1;
    h := sha256('\x01'::bytea || sib || h);
    lvl := lvl + 1;
    i := i / 2;
    insert into app.log_nodes (level, idx, hash) values (lvl, i, h);
  end loop;
  return n;
end
$$;

-- A keyed hash: SHA-256 over the key and the facts' canonical JSON, in hex.
create function app.log_seal(p_key bytea, p_facts jsonb) returns text
language sql stable security definer set search_path = pg_catalog
as $$ select encode(sha256(p_key || convert_to(app.log_jcs(p_facts), 'UTF8')), 'hex') $$;

-- The log's random name for a member or an agent, made the first time it is needed (the review of 038, M2).
create function app.log_name(p_kind text, p_id uuid) returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n uuid;
begin
  if p_kind = 'member' then
    insert into app.log_names (member_id) values (p_id) on conflict (member_id) do nothing;
    select x.name into n from app.log_names x where x.member_id = p_id;
  elsif p_kind = 'agent' then
    insert into app.log_names (agent_id) values (p_id) on conflict (agent_id) do nothing;
    select x.name into n from app.log_names x where x.agent_id = p_id;
  else
    raise exception 'a member or an agent' using errcode = '22023';
  end if;
  return n::text;
end
$$;

-- One agent post, once, when it first goes live: the agent acted for the member who owns it. The entry names both by
-- the log's random names; the sealed facts, opened while the post is live, hold their real IDs.
create function app.log_post(p_id uuid, p_agent uuid, p_owner uuid, p_delegation text, p_rules_version integer, p_body text,
                             p_published_at timestamptz)
returns bigint
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  k bytea := app.log_random32();
  facts jsonb;
  n bigint;
begin
  if exists (select 1 from app.log_entries x where x.subject = 'post:' || p_id::text) then return null; end if;
  -- The entry names the agent and the owner by their log names (random, the review of 038, M2); the sealed facts
  -- carry the same names beside the account IDs, so an opened receipt shows which accounts the names stand for.
  facts := jsonb_build_object('post', p_id::text, 'agent', p_agent::text, 'owner', p_owner::text,
             'actor', 'agent:' || app.log_name('agent', p_agent), 'on_behalf_of', 'member:' || app.log_name('member', p_owner),
             'delegation', p_delegation, 'rules_version', p_rules_version, 'body_sha256', encode(sha256(convert_to(p_body, 'UTF8')), 'hex'));
  n := app.log_append('post', p_published_at, facts->>'actor', facts->>'on_behalf_of', 'post:' || p_id::text,
         jsonb_build_object('facts', app.log_seal(k, facts)));
  insert into app.log_openings (seq, key, facts, post_id) values (n, k, facts, p_id);
  return n;
end
$$;

-- The trigger: an agent post that goes live (inserted live, approved, or published by Second Look), after the row is
-- written, in the post's own transaction. Appends wait on the head row's lock from then until that transaction commits
-- (agents and their sub-agents posting at once take turns for that long; RISKS.md RK113 has the measured rate).
create function app.log_post_live() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if new.lane = 'agents' and new.status = 'live' and (tg_op = 'INSERT' or old.status is distinct from 'live') then
    perform app.log_post(new.id, new.agent_id, new.author_id, new.delegation, new.rules_version, new.body, new.published_at);
  end if;
  return null;
end
$$;

-- Queues a JEVs decision for the log, in the decision's own transaction (the review of 038, H4 and L1).
create function app.log_queue_decision() returns trigger
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  if tg_table_name = 'jevs_decisions' then
    insert into app.log_queue (place, decision_id, hour) values ('site', new.id, date_trunc('hour', new.created_at)) on conflict do nothing;
  else
    insert into app.log_queue (place, decision_id, hour) values ('github', new.id, date_trunc('hour', new.at)) on conflict do nothing;
  end if;
  return null;
end
$$;

-- JEVs's decisions whose hour has ended, at most 250 a call (about a quarter of a second of the head row's lock, so
-- agent posts never wait long; the timer calls it again while it is full), each stamped with its hour, shuffled
-- within it, under a fresh random ID (gen_random_uuid, not the decision's own UUIDv7, which carries its exact time:
-- the review of 038, H3), with its record sealed. A decision deleted before its turn is dropped from the queue.
-- Returns how many it logged.
create function app.log_jevs_hours() returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  q record;
  facts jsonb;
  k bytea;
  n bigint;
  c integer := 0;
begin
  if not pg_try_advisory_xact_lock(4038000002) then return 0; end if;
  for q in
    select x.id, x.place, x.decision_id, x.hour from app.log_queue x
    where x.hour < date_trunc('hour', now())
    order by x.hour, sha256(convert_to(x.place || x.decision_id::text, 'UTF8'))
    limit 250
  loop
    delete from app.log_queue x where x.id = q.id;
    if q.place = 'site' then
      select jsonb_build_object('decision', d.id::text, 'place', 'site', 'action', d.action, 'subject_kind', d.subject_kind,
               'subject', d.subject_id::text, 'level', d.level, 'mode', d.mode, 'effect', d.effect, 'applied', d.applied,
               'error', d.error, 'total', d.total) into facts
      from app.jevs_decisions d where d.id = q.decision_id;
    else
      select jsonb_build_object('decision', g.id::text, 'place', 'github', 'action', g.action, 'post', g.post_id::text,
               'agent', g.agent_id::text, 'member', g.member_id::text, 'level', g.risk, 'mode', g.mode, 'effect', g.effect,
               'applied', g.applied, 'total', g.total) into facts
      from app.gh_decisions g where g.id = q.decision_id;
    end if;
    if facts is null then continue; end if;
    k := app.log_random32();
    n := app.log_append('jevs.decision', q.hour, 'jevs', null, 'decision:' || gen_random_uuid()::text, jsonb_build_object('record', app.log_seal(k, facts)));
    if q.place = 'site' then
      insert into app.log_openings (seq, key, facts, decision_id) values (n, k, facts, q.decision_id);
    else
      insert into app.log_openings (seq, key, facts, gh_decision_id) values (n, k, facts, q.decision_id);
    end if;
    c := c + 1;
  end loop;
  return c;
end
$$;

-- Aaron's decision on a proposal, as the site read it from GitHub's labels: logged when it differs from the last one
-- logged for that proposal. Public facts only (the proposal's number and the decision), never who filed it.
create function app.log_proposal(p_number integer, p_decision text) returns bigint
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  last text;
  n bigint;
begin
  if p_number is null or p_number < 1 or p_number > 10000000 or p_decision is null or p_decision <> all (array['approved', 'declined', 'shipped']) then
    raise exception 'a proposal number and approved, declined or shipped' using errcode = '22023';
  end if;
  select s.decision into last from app.log_proposals_seen s where s.number = p_number for update;
  if last is not distinct from p_decision then return null; end if;
  n := app.log_append('proposal.decided', now(), 'github:mychiefos', null, 'proposal:' || p_number::text,
         jsonb_build_object('proposal', p_number, 'decision', p_decision));
  insert into app.log_proposals_seen (number, decision, seq) values (p_number, p_decision, n)
    on conflict (number) do update set decision = excluded.decision, seq = excluded.seq;
  return n;
end
$$;

-- Marks the log unverified with a reason, and tells Aaron once per kind of reason (numbers in it, such as a growing
-- tree size, don't make a new alert: the review of 038, L2).
create function app.log_unverified(p_reason text) returns void
language plpgsql security definer set search_path = pg_catalog
as $$
begin
  update app.log_witness w set status = 'unverified', reason = left(p_reason, 300), checked_at = now() where w.singleton;
  perform app.notify(null, 'alert', 'The public log is unverified', left(p_reason, 300) || ' The site keeps running; receipts show the log as unverified until this is resolved.',
                     '/security#log', null, null, 'log.unverified.' || md5(regexp_replace(p_reason, '[0-9]+', '#', 'g')));
end
$$;

-- A new signed checkpoint when the tree grew and the last is 60 seconds old or 100 entries behind. Returns the newest
-- checkpoint's size (0 if there is none). Before signing, the tree must still reach the last signed root.
create function app.log_checkpoint() returns bigint
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n bigint;
  last_size bigint;
  last_root bytea;
  last_at timestamptz;
  root bytea;
  body text;
  sig bytea;
  k record;
begin
  if not pg_try_advisory_xact_lock(4038000001) then return null; end if;
  select x.size into n from app.log_head x where x.singleton;
  select c.size, c.root, c.created_at into last_size, last_root, last_at from app.log_checkpoints c order by c.size desc limit 1;
  if n = 0 or n = last_size or (last_size is not null and n - last_size < 100 and now() - last_at < interval '60 seconds') then
    return coalesce(last_size, 0);
  end if;
  if last_size is not null and app.log_root(last_size) <> last_root then
    update app.log_witness w set self_ok = false where w.singleton;
    perform app.log_unverified('The tree no longer reaches the root of signed checkpoint ' || last_size || ', so no new checkpoint was signed.');
    return last_size;
  end if;
  root := app.log_root(n);
  select * into k from app.log_keys x where x.singleton;
  body := k.name || chr(10) || n::text || chr(10) || encode(root, 'base64') || chr(10);
  sig := app.log_ed25519_sign(k.seed, convert_to(body, 'UTF8'));
  insert into app.log_checkpoints (size, root, note, signature)
    values (n, root, body || chr(10) || chr(8212) || ' ' || k.name || ' ' || replace(encode(k.key_id || sig, 'base64'), chr(10), '') || chr(10), sig);
  return n;
end
$$;

-- What the site read from the witness's branch: its last good checkpoint (size and root), when it last ran, and its
-- alarm if it raised one. The log compares the copy with its own tree; a mismatch or an alarm marks it unverified and
-- alerts Aaron. Returns the status.
create function app.log_witness_report(p_size bigint, p_root bytea, p_witnessed_at timestamptz, p_alarm text) returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n bigint;
  w record;
  why text;
begin
  select x.size into n from app.log_head x where x.singleton;
  select * into w from app.log_witness x where x.singleton for update;
  -- An alarm or a mismatch stays until a reviewed migration clears it (app.log_clear_alarm): nothing the site's login
  -- reports clears it, so a copy of the right root sent by the site itself can't mark the log verified (M3).
  if w.alarm then
    update app.log_witness x set witnessed_at = coalesce(p_witnessed_at, x.witnessed_at), checked_at = now() where x.singleton;
    return 'unverified';
  end if;
  if p_alarm is not null and p_alarm <> '' then
    why := 'The witness on GitHub raised an alarm: ' || left(regexp_replace(p_alarm, '[^ -~]', '', 'g'), 200);
  elsif p_size is null or p_root is null then
    update app.log_witness x set status = case when x.status = 'unverified' then x.status else 'unknown' end, checked_at = now() where x.singleton;
    return (select x.status from app.log_witness x where x.singleton);
  elsif octet_length(p_root) <> 32 or p_size < 1 then
    why := 'The witness''s copy on GitHub isn''t a checkpoint of this log.';
  elsif p_size > n then
    why := 'The witness on GitHub has a checkpoint of ' || p_size || ' entries, but the log has only ' || n || '.';
  elsif app.log_root(p_size) <> p_root then
    why := 'The witness''s copy of checkpoint ' || p_size || ' on GitHub doesn''t match this log''s tree.';
  end if;
  if why is not null then
    update app.log_witness x set witness_size = case when octet_length(p_root) = 32 then p_size else x.witness_size end,
      witnessed_at = p_witnessed_at, alarm = true where x.singleton;
    perform app.log_unverified(why);
    return 'unverified';
  end if;
  -- Once unverified, the log stays so until the reason is gone: a witness copy that matches again, and the tree
  -- reaching its own checkpoints. A witness that hasn't run for 2 hours is "stale": an alert, once a day.
  update app.log_witness x set status = case when not x.self_ok then 'unverified'
                                             when p_witnessed_at < now() - interval '2 hours' then 'stale' else 'ok' end,
    reason = case when not x.self_ok then x.reason when p_witnessed_at < now() - interval '2 hours'
                  then 'The witness on GitHub last ran ' || to_char(p_witnessed_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC.' else '' end,
    witness_size = p_size, witness_root = p_root, witnessed_at = p_witnessed_at, checked_at = now()
  where x.singleton;
  if p_witnessed_at < now() - interval '2 hours' then
    perform app.notify(null, 'alert', 'The public log''s witness has stopped', 'The witness job on GitHub last ran '
      || to_char(p_witnessed_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC, so new receipts show as not yet witnessed. The site keeps running.',
      '/security#log', null, null, 'log.stale.' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
  end if;
  return (select x.status from app.log_witness x where x.singleton);
end
$$;

-- Clears an alarm, in a reviewed migration only (dog_owner; never the site's login), once the reason is understood and
-- the witness's own record is clear. The clearing is itself an entry in the log, with the note, so it is public.
create function app.log_clear_alarm(p_note text) returns bigint
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  w record;
  n bigint;
begin
  if p_note is null or char_length(p_note) < 10 or char_length(p_note) > 300 then
    raise exception 'a note of 10 to 300 characters saying why the alarm is cleared' using errcode = '22023';
  end if;
  select * into w from app.log_witness x where x.singleton for update;
  if not w.alarm then return null; end if;
  n := app.log_append('log.alarm_cleared', now(), 'log', null, 'log:witness', jsonb_build_object('reason', w.reason, 'note', p_note));
  update app.log_witness x set alarm = false, status = 'unknown', reason = '', checked_at = now() where x.singleton;
  return n;
end
$$;

-- A post receipt's opening: its key and sealed facts, while the post is live (so the receipt can show its facts match
-- the entry). Nothing for a decision, a removed post or a deleted one.
create function app.log_opening(p_seq bigint) returns table (key bytea, facts jsonb)
language sql stable security definer set search_path = pg_catalog
as $$
  select o.key, o.facts from app.log_openings o join app.posts p on p.id = o.post_id
  where o.seq = p_seq and p.status = 'live' and p.lane = 'agents'
$$;

revoke execute on function app.log_append(text, timestamptz, text, text, text, jsonb), app.log_seal(bytea, jsonb),
  app.log_post(uuid, uuid, uuid, text, integer, text, timestamptz), app.log_post_live(), app.log_jevs_hours(), app.log_proposal(integer, text),
  app.log_unverified(text), app.log_checkpoint(), app.log_witness_report(bigint, bytea, timestamp with time zone, text), app.log_opening(bigint),
  app.log_name(text, uuid), app.log_queue_decision(), app.log_clear_alarm(text) from public;
grant execute on function app.log_jevs_hours(), app.log_proposal(integer, text), app.log_checkpoint(),
  app.log_witness_report(bigint, bytea, timestamp with time zone, text), app.log_opening(bigint) to dog_app;
-- The owner makes the post trigger (it owns app.posts), with this one right for these lines only.
grant execute on function app.log_post_live(), app.log_queue_decision() to dog_owner;
-- Only a migration (the owner) clears an alarm.
grant execute on function app.log_clear_alarm(text) to dog_owner;
set local role dog_owner;
revoke create on schema app from dog_log;
create trigger posts_log after insert or update of status on app.posts for each row execute function app.log_post_live();
alter table app.posts enable always trigger posts_log;
create trigger jevs_decisions_log after insert on app.jevs_decisions for each row execute function app.log_queue_decision();
alter table app.jevs_decisions enable always trigger jevs_decisions_log;
create trigger gh_decisions_log after insert on app.gh_decisions for each row execute function app.log_queue_decision();
alter table app.gh_decisions enable always trigger gh_decisions_log;

-- ---- The key, the first entry, and what already exists ----
set local role dog_log;
revoke execute on function app.log_post_live(), app.log_queue_decision() from dog_owner;
insert into app.log_head (singleton) values (true);
insert into app.log_witness (singleton) values (true);
with s as (select app.log_random32() as seed)
insert into app.log_keys (name, seed, public_key, key_id)
  select 'dayonegreat.com/log', s.seed, app.log_ed25519_public(s.seed),
         substring(sha256(convert_to('dayonegreat.com/log', 'UTF8') || '\x0a01'::bytea || app.log_ed25519_public(s.seed)) from 1 for 4)
  from s;
-- Entry 0 states the log's own public key, so the tree itself records which key signs it.
select app.log_append('key.registered', k.created_at, 'log', null, 'key:' || encode(k.key_id, 'hex'),
                      jsonb_build_object('name', k.name, 'algorithm', 'ed25519', 'public_key', encode(k.public_key, 'base64')))
from app.log_keys k where k.singleton;
-- Every agent post already live, in the order it went live.
select app.log_post(p.id, p.agent_id, p.author_id, p.delegation, p.rules_version, p.body, p.published_at)
from app.posts p where p.lane = 'agents' and p.status = 'live' order by p.published_at, p.id;
-- JEVs's decisions so far: queued, then logged up to the last whole hour, 250 at a time.
insert into app.log_queue (place, decision_id, hour) select 'site', d.id, date_trunc('hour', d.created_at) from app.jevs_decisions d;
insert into app.log_queue (place, decision_id, hour) select 'github', g.id, date_trunc('hour', g.at) from app.gh_decisions g;
do $$ begin loop exit when app.log_jevs_hours() < 250; end loop; end $$;
set local role dog_owner;
