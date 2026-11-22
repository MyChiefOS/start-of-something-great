-- 070 Full Second Look and full Third Look (Aaron, Nov 21, 2026: "I want the full capabilities of second look
--   implemented." "I want the full capabilities of third look implemented."; Nov 22: "Start now").
--
--   1. Second Look reads more than posts: every task's title and description, every submission's note, every dispute's
--      reason and every note of evidence. Each is queued when written (app.sl_items), and the timer puts it to Second
--      Look's checks and model, as it does held posts. It flags, never blocks (checks alert, never lock out): a
--      "reject" alerts the administrator with the reasons, and the decision is kept beside the item for anyone who
--      reads the record. Off when Second Look is off.
--   2. Third Look reads more than merged pull requests: work submitted as a link (https) is read too. Its suggestion on a
--      link is advice beside the person's decision: 057's rule that only a pull request merged by Aaron's account can be
--      cleared stands, because a page can change, or show a person something else, after it was read. The timer fetches
--      the page itself (public addresses only, at most 500 KB, 8 seconds, text only), puts it to Third Look's model
--      with the task, and records the SHA-256 of exactly what it read beside its suggestion, so anyone can see whether
--      the page changed after. A file known only by its hash can't be read, so it stays with a person.

-- ---- 1. Second Look's items ----
set local role dog_owner;
create table app.sl_items (
  id uuid primary key default app.uuid_v7(),
  kind text not null check (kind = any (array['task', 'submission', 'dispute', 'evidence'])),
  ref uuid not null,
  -- Who wrote it: the copy goes when their account does (the fresh review, H1), and no one fills the queue alone.
  author_member uuid references app.members (id) on delete cascade,
  body text not null check (char_length(body) between 1 and 6000),
  created_at timestamptz not null default now(),
  claimed_at timestamptz,
  decided_at timestamptz,
  decision text check (decision = any (array['clear', 'reject', 'leave'])),
  model text check (char_length(model) <= 60),
  reason text check (char_length(reason) <= 1000),
  unique (kind, ref)
);
create index sl_items_waiting on app.sl_items (created_at) where decided_at is null;
alter table app.sl_items enable row level security;
alter table app.sl_items force row level security;
create policy sl_items_work on app.sl_items for all to dog_work using (true) with check (true);
-- The queue's trigger runs as the tables' owner, whoever writes the row (the work role, the GitHub facts role), so no
-- writer needs a right of its own on this table; it only adds rows.
create policy sl_items_owner_insert on app.sl_items for insert to dog_owner with check (true);
grant select, insert, update, delete on app.sl_items to dog_work;
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- The timer takes up to 3 waiting items, oldest first, while Second Look isn't off, within 200 a day. A claim nobody
-- answered in 3 minutes is free again.
create function app.sl_item_claim(p_n integer) returns table (id uuid, kind text, body text, model text)
language plpgsql security definer set search_path = pg_catalog as $$
declare s record; today integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer hands items to Second Look' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 3 then raise exception 'bad Second Look claim' using errcode = '22023'; end if;
  select x.mode, x.model into s from app.sl_settings x where x.singleton;
  if not found or s.mode = 'off' then return; end if;
  -- Copies are kept 30 days after Second Look answers, then only the decision's existence remains in the alerts.
  delete from app.sl_items i where i.decided_at < now() - interval '30 days';
  select count(*) into today from app.sl_items i where i.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  if today >= 200 then return; end if;
  return query
    with picked as (
      select i.id from app.sl_items i
       where i.decided_at is null and (i.claimed_at is null or i.claimed_at < now() - interval '3 minutes')
         -- No one author takes more than 20 of the day's 200 (the fresh review, M3): theirs wait for tomorrow.
         and (i.author_member is null or (select count(*) from app.sl_items j where j.author_member = i.author_member
               and j.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC') < 20)
       order by i.created_at, i.id limit least(p_n, 200 - today) for update skip locked),
    claimed as (update app.sl_items i set claimed_at = now() from picked where i.id = picked.id returning i.id, i.kind, i.body)
    select c.id, c.kind, c.body, s.model from claimed c;
end $$;

create function app.sl_item_decide(p_id uuid, p_model text, p_decision text, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare i record;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records Second Look''s answers' using errcode = '42501';
  end if;
  if p_decision is null or p_decision <> all (array['clear', 'reject', 'leave']) then raise exception 'bad decision' using errcode = '22023'; end if;
  update app.sl_items x set decided_at = now(), decision = p_decision, model = left(p_model, 60), reason = left(p_reason, 1000)
   where x.id = p_id and x.decided_at is null returning * into i;
  if i.id is null then return 'not_waiting'; end if;
  -- A reject flags for the administrator; nothing is hidden or held.
  if p_decision = 'reject' then
    perform app.notify(null, 'alert', 'Second Look flagged a ' || i.kind, left(coalesce(p_reason, 'Something looked wrong.'), 300),
      case i.kind when 'task' then '/tasks/' || i.ref when 'submission' then '/admin/review#work' else '/admin/review#work' end,
      case i.kind when 'task' then 'task' else 'submission' end,
      case i.kind when 'task' then i.ref
                  when 'submission' then i.ref
                  when 'dispute' then (select d.submission_id from app.work_disputes d where d.id = i.ref)
                  else (select d.submission_id from app.work_dispute_evidence e join app.work_disputes d on d.id = e.dispute_id where e.id = i.ref) end,
      'sl:item:' || i.id);
  end if;
  return p_decision;
end $$;

-- What Second Look said about an item, for anyone reading the record (the reason names checks, never personal data).
create function app.sl_item_status(p_kind text, p_ref uuid) returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object('decision', coalesce(i.decision, 'waiting'), 'decided_at', i.decided_at)
    from app.sl_items i where i.kind = p_kind and i.ref = p_ref
$$;

revoke execute on function app.sl_item_claim(integer), app.sl_item_decide(uuid, text, text, text), app.sl_item_status(text, uuid) from public;
grant execute on function app.sl_item_claim(integer), app.sl_item_decide(uuid, text, text, text), app.sl_item_status(text, uuid) to dog_app;

-- ---- 2. Third Look reads links ----
reset role;
set local role dog_owner;
-- The queue's trigger, owned with the tables, as 067's work_action_rules is.
-- Queue what was written. Text only, as written; nothing is changed or held.
create function app.sl_item_queue() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
declare k text := tg_argv[0]; b text; r jsonb := to_jsonb(new); who uuid;
begin
  b := case k when 'task' then coalesce(r ->> 'title', '') || E'\n' || coalesce(r ->> 'description', '')
              when 'submission' then r ->> 'note'
              when 'dispute' then r ->> 'reason'
              when 'evidence' then r ->> 'note' end;
  who := case k when 'task' then coalesce((r ->> 'poster_member')::uuid, (select g.owner_id from app.agents g where g.id = (r ->> 'poster_agent')::uuid))
                when 'submission' then coalesce((r ->> 'worker_member')::uuid, (select g.owner_id from app.agents g where g.id = (r ->> 'worker_agent')::uuid))
                else (r ->> 'member_id')::uuid end;
  if b is not null and char_length(btrim(b)) > 0 then
    insert into app.sl_items (kind, ref, author_member, body) values (k, new.id, who, left(b, 6000)) on conflict do nothing;
  end if;
  return null;
end $$;
revoke execute on function app.sl_item_queue() from public;

create trigger sl_item_queue after insert on app.work_tasks for each row execute function app.sl_item_queue('task');
create trigger sl_item_queue after insert on app.work_submissions for each row execute function app.sl_item_queue('submission');
create trigger sl_item_queue after insert on app.work_disputes for each row execute function app.sl_item_queue('dispute');
create trigger sl_item_queue after insert on app.work_dispute_evidence for each row execute function app.sl_item_queue('evidence');
reset role;
grant select (singleton, mode, model) on app.sl_settings to dog_work;
create policy sl_settings_work_select on app.sl_settings for select to dog_work using (true);
set local role dog_owner;
alter table app.tl_reviews add column read_sha256 text check (char_length(read_sha256) = 64 and read_sha256 ~ '^[0-9a-f]+$');
alter table app.tl_reviews add column read_url text check (char_length(read_url) <= 500);
reset role;
set local role dog_work;

drop function app.tl_claim(integer);
create function app.tl_claim(p_n integer)
returns table (submission_id uuid, task_title text, task_description text, note text, pr_number integer, pr_title text, jevs_rules text, model text,
               files jsonb, artifact_kind text, artifact_url text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  today integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer hands work to Third Look' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 3 then raise exception 'bad Third Look claim' using errcode = '22023'; end if;
  select * into s from app.tl_settings where singleton for update skip locked;
  if not found or s.mode = 'off' or (s.last_claim_at is not null and s.last_claim_at > now() - interval '50 seconds') then return; end if;
  update app.tl_settings set last_claim_at = now() where singleton;
  with gone as (delete from app.tl_reviews r where r.decided_at is null and r.claimed_at < now() - interval '3 minutes' returning r.submission_id)
  insert into app.tl_releases (submission_id, why) select g.submission_id, 'timed out' from gone g;
  delete from app.tl_releases r where r.released_at < now() - interval '2 days';
  select (select count(*) from app.tl_reviews r where r.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC')
       + (select count(*) from app.tl_releases r where r.released_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC')
    into today;
  if today >= s.daily_call_cap then return; end if;
  return query
    with picked as (
      select x.id from app.work_submissions x left join app.work_github_prs g on g.number = x.pr_number
       where ((x.status = 'review' and x.route in ('admin', 'held'))
              or (x.status = 'passed' and exists (select 1 from app.work_disputes d where d.submission_id = x.id and d.status = 'open')
                  and (select count(*) from app.tl_reviews r join app.work_submissions y on y.id = r.submission_id
                        where r.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC' and y.decided_at < r.claimed_at) < 10))
         and (
           -- 057's pull requests, as before.
           (x.artifact_kind = 'pr' and g.merged_at is not null and g.base = 'main'
            and g.merge_read_at is not null and g.merged_by_id = (select w.merger_github_id from app.work_settings w where w.singleton)
            and exists (select 1 from app.tl_files f where f.number = x.pr_number))
           -- 070: a link to a page, read by the timer itself.
           -- At most 20 links a day, so links can't use up the reviews of pull requests (the fresh review, M3).
           or (x.artifact_kind = 'link' and x.artifact_url like 'https://%'
               and (select count(*) from app.tl_reviews r join app.work_submissions y on y.id = r.submission_id
                     where y.artifact_kind = 'link' and r.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC') < 20))
         and not exists (select 1 from app.tl_reviews r where r.submission_id = x.id)
         and not exists (select 1 from app.tl_releases r where r.submission_id = x.id and r.released_at > now() - interval '10 minutes')
       order by (x.status = 'passed'), x.created_at, x.id
       limit least(p_n, s.daily_call_cap - today)
       for update of x skip locked),
    claimed as (insert into app.tl_reviews (submission_id) select id from picked returning tl_reviews.submission_id)
    select x.id, t.title, t.description, x.note, x.pr_number, g.title, x.jevs_rules, s.model, f.files, x.artifact_kind, x.artifact_url
      from claimed c join app.work_submissions x on x.id = c.submission_id join app.work_tasks t on t.id = x.task_id
      left join app.work_github_prs g on g.number = x.pr_number left join app.tl_files f on f.number = x.pr_number;
end
$$;
revoke execute on function app.tl_claim(integer) from public;
grant execute on function app.tl_claim(integer) to dog_app;

-- What Third Look read, recorded before its suggestion (the hash of the page's text as the model was given it).
create function app.tl_read(p_sub uuid, p_url text, p_sha256 text) returns void
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records what Third Look read' using errcode = '42501';
  end if;
  if p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$' then raise exception 'bad read' using errcode = '22023'; end if;
  update app.tl_reviews r set read_sha256 = p_sha256, read_url = left(p_url, 500) where r.submission_id = p_sub and r.decided_at is null;
end $$;
revoke execute on function app.tl_read(uuid, text, text) from public;
grant execute on function app.tl_read(uuid, text, text) to dog_app;
reset role;
revoke create on schema app from dog_work;
