-- 015 The change log (USE-CASES.md row 15; PR 2, Oct 24, 2026).
-- The database changes only from code merged to main: the "Database migrations" workflow (database.yml) proves who
-- it is with a GitHub identity token, and the runner (supabase/functions/dog-migrate) applies the files of that
-- merged commit. Every run that changes anything leaves one row here, written by the runner itself, so the record
-- is made by the machine, not by a person or by Claude.
--   change_log     what ran: the commit, the workflow run, who merged, each file with its SHA-256, the result.
--   runner_tokens  the ID of every identity token the runner has accepted, so a token can't be used twice.
-- Both are owned by dog_owner with row-level security forced; no other role can read or write them.
set local role dog_owner;

create table app.change_log (
  id uuid primary key default app.uuid_v7(),
  at timestamptz not null default now(),
  commit_sha text not null check (char_length(commit_sha) = 40 and commit_sha ~ '^[0-9a-f]+$'),
  run_id text not null check (char_length(run_id) <= 40),
  actor text not null check (char_length(actor) <= 100),
  event text not null check (event = any (array['push', 'workflow_dispatch'])),
  reset boolean not null default false,
  applied jsonb not null default '[]'::jsonb check (jsonb_typeof(applied) = 'array' and octet_length(applied::text) <= 65536),
  result text not null check (result = any (array['ok', 'checks_failed']))
);
alter table app.change_log enable row level security;
alter table app.change_log force row level security;
create policy change_log_owner_only on app.change_log for all to dog_owner using (true) with check (true);

create table app.runner_tokens (
  jti text primary key check (char_length(jti) between 1 and 100),
  seen_at timestamptz not null default now()
);
alter table app.runner_tokens enable row level security;
alter table app.runner_tokens force row level security;
create policy runner_tokens_owner_only on app.runner_tokens for all to dog_owner using (true) with check (true);

-- Append-only, like the audit log: a change record can't be edited or removed.
create function app.change_log_no_change() returns trigger language plpgsql set search_path = pg_catalog as $$
begin
  raise exception 'the change log is append-only';
end
$$;
revoke execute on function app.change_log_no_change() from public;
create trigger change_log_no_change before update or delete on app.change_log
  for each row execute function app.change_log_no_change();
create trigger change_log_no_truncate before truncate on app.change_log
  for each statement execute function app.change_log_no_change();
