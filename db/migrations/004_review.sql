-- 004 Review queue and reports (Release 2, PR 4).
-- Criteria: F6 level 0 and 1 members' first 3 posts wait for review; F7 a reported post reaches the queue within
-- 1 minute and a removed post disappears everywhere within 1 minute; G5 moderation is a pipeline that can add
-- automatic classifiers and more reviewers without being rebuilt; O3 every approval and removal is in the audit
-- log, with who did it and when; S6 reporting is rate limited (in the site, db/review.js).
--
-- The pipeline (G5): anything that wants a post looked at adds a *flag*: the first-posts rule, a member's report,
-- or later an automatic classifier. The queue is every post with an open flag, oldest flag first. A reviewer
-- makes one decision per post (approve, keep, remove or restore), which closes all of its open flags.
--   More reviewers later: change app.is_reviewer() (every rule below asks it) and signin/session.js canReview /
--   actorFor (which decide who acts as a reviewer); nothing else changes.
--   Classifiers later: they add flags with source 'classifier', their name and a score; nothing else changes. They
--   flag posts that are waiting or already live; holding a level 2 post back before it goes live would be a
--   change to posts_decide (003), recorded here so it isn't mistaken for something the pipeline already does.
-- The database writes the audit record itself, in triggers, so no code path can make a decision unrecorded (O3).

set local role dog_owner;

-- Who may review. Today only Aaron (the administrator).
create function app.is_reviewer() returns boolean
language sql stable parallel safe
as $$ select app.actor_kind() = 'admin' $$;

-- When a post first went live, so undoing a removal knows whether the post had been approved (it goes back live) or
-- was a first post that was never approved (it goes back to waiting for review). Set only by the database.
alter table app.posts add column first_published_at timestamptz;
create function app.posts_first_published() returns trigger
language plpgsql
as $$
begin
  new.first_published_at := new.published_at;
  return new;
end
$$;
-- Named to fire after posts_decide (before-triggers fire in name order), which decides published_at.
create trigger posts_first_published before insert on app.posts for each row execute function app.posts_first_published();
alter table app.posts enable always trigger posts_first_published;

-- Whether a member may report a post: it is live, its author is an active member, and it isn't the reporter's own.
-- Runs as dog_public, which sees exactly that public view, so reporting reveals nothing the public feed doesn't
-- (a banned member's posts look the same as posts that don't exist). Volatile, so a fresh read is taken each time.
create function app.reportable(p_post uuid, p_reporter uuid)
returns boolean
language plpgsql volatile security definer set search_path = pg_catalog
as $$
begin
  return exists (select 1 from app.posts p join app.members m on m.id = p.author_id
                 where p.id = p_post and p.status = 'live' and p.author_id is distinct from p_reporter);
end
$$;
revoke execute on function app.reportable(uuid, uuid) from public;
grant execute on function app.reportable(uuid, uuid) to dog_app;
grant create on schema app to dog_public;
alter function app.reportable(uuid, uuid) owner to dog_public;
revoke create on schema app from dog_public;

-- ---- Decisions on posts ----
-- Only a reviewer may change a post, and only its status; when it went live is set here, never by the request.
create policy posts_update on app.posts for update to dog_app
  using (app.is_reviewer()) with check (app.is_reviewer());
grant update (status) on app.posts to dog_app;

-- The allowed moves: waiting to live (approve) or removed; live to removed; removed back to live (undo a mistake).
create function app.posts_review_guard() returns trigger
language plpgsql
as $$
begin
  if not app.is_reviewer() then
    raise exception 'only a reviewer can change a post' using errcode = '42501';
  end if;
  if (new.id, new.author_id, new.lane, new.agent_id, new.body, new.created_at, new.first_published_at)
     is distinct from (old.id, old.author_id, old.lane, old.agent_id, old.body, old.created_at, old.first_published_at) then
    raise exception 'a review changes only a post''s status' using errcode = '42501';
  end if;
  if new.status = old.status then
    new.published_at := old.published_at;
    return new;
  end if;
  -- Undoing a removal returns a post to where it was: live if it had been approved, waiting if it never was.
  if not ((old.status = 'waiting' and new.status in ('live', 'removed'))
       or (old.status = 'live' and new.status = 'removed')
       or (old.status = 'removed' and new.status = 'live' and old.first_published_at is not null)
       or (old.status = 'removed' and new.status = 'waiting' and old.first_published_at is null)) then
    raise exception 'a post can''t go from % to %', old.status, new.status using errcode = '22023';
  end if;
  -- Going live puts the post at the top of the feed, which is paged by when posts went live.
  new.published_at := case when new.status = 'live' then now() else null end;
  new.first_published_at := coalesce(old.first_published_at, new.published_at);
  return new;
end
$$;
create trigger posts_review_guard before update on app.posts for each row execute function app.posts_review_guard();
alter table app.posts enable always trigger posts_review_guard;

-- ---- Flags: everything that asks for a review ----
create table app.review_flags (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null references app.posts (id),
  source text not null check (source = any (array['first_posts', 'report', 'classifier'])),
  -- Reports: why, in the reporter's words (optional), and who.
  reason text check (reason = any (array['spam', 'abuse', 'private_info', 'illegal', 'other'])),
  note text check (char_length(note) <= 500),
  reporter_id uuid references app.members (id),
  -- Classifiers (later): which one, and how sure it is (0 to 1).
  classifier text check (char_length(classifier) <= 64 and classifier ~ '^[a-z][a-z0-9_]*$'),
  score real check (score between 0 and 1),
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  resolved_by uuid,
  decision text check (decision = any (array['approve', 'keep', 'remove', 'restore'])),
  check ((source = 'report') = (reporter_id is not null and reason is not null)),
  check (source = 'report' or note is null),
  check ((source = 'classifier') = (classifier is not null)),
  check (source = 'classifier' or score is null),
  check ((resolved_at is null) = (decision is null)),
  check ((resolved_at is null) = (resolved_by is null))
);
-- One open first-posts flag per post, and one open report per member per post (reporting again while it is open
-- changes nothing; once decided, a new report opens a new flag).
create unique index review_flags_first on app.review_flags (post_id) where source = 'first_posts' and resolved_at is null;
create unique index review_flags_report on app.review_flags (post_id, reporter_id) where source = 'report' and resolved_at is null;
create index review_flags_open on app.review_flags (created_at, post_id) where resolved_at is null;
alter table app.review_flags enable row level security;
alter table app.review_flags force row level security;

-- Members see their own reports; the reviewer sees everything.
create policy review_flags_select on app.review_flags for select to dog_app
  using ((app.actor_kind() = 'member' and reporter_id = app.current_member()) or app.is_reviewer());
-- Who may add which flag:
--   first_posts: added when a post is waiting (by the trigger below, acting as its author, or as the reviewer
--   when an undo puts a never-approved post back in the queue);
--   report: a signed-in member, in their own name, on someone else's live post by an active member;
--   classifier: the site itself (actor "system"), never a member.
create policy review_flags_insert on app.review_flags for insert to dog_app
  with check (
    (source = 'first_posts' and reporter_id is null and app.actor_kind() in ('member', 'admin')
      and exists (select 1 from app.posts p where p.id = post_id and p.status = 'waiting'
                  and (p.author_id = app.current_member() or app.is_reviewer())))
    or (source = 'report' and app.actor_kind() in ('member', 'admin') and reporter_id = app.current_member()
      and app.reportable(post_id, app.current_member()))
    or (source = 'classifier' and reporter_id is null and app.actor_kind() = 'system')
  );
-- Only a reviewer closes flags.
create policy review_flags_update on app.review_flags for update to dog_app
  using (app.is_reviewer()) with check (app.is_reviewer());
grant select on app.review_flags to dog_app;
grant insert (post_id, source, reason, note, reporter_id, classifier, score) on app.review_flags to dog_app;
-- Only the decision: when and by whom are filled in by the guard below.
grant update (decision) on app.review_flags to dog_app;

-- Flags are closed once, by a reviewer, in their own name, now; nothing else about a flag changes.
create function app.review_flags_guard() returns trigger
language plpgsql
as $$
begin
  if not app.is_reviewer() then
    raise exception 'only a reviewer can close a flag' using errcode = '42501';
  end if;
  if old.resolved_at is not null then
    raise exception 'this flag is already closed' using errcode = '22023';
  end if;
  if new.decision is null then
    raise exception 'closing a flag needs a decision' using errcode = '22023';
  end if;
  new.resolved_at := now();
  new.resolved_by := app.current_member();
  return new;
end
$$;
create trigger review_flags_guard before update on app.review_flags for each row execute function app.review_flags_guard();
alter table app.review_flags enable always trigger review_flags_guard;

-- A report checks the post again once its row is in: the foreign-key check before this waits for any decision that
-- is locking the post, and this fresh read then sees it. Without it, a report racing a removal could leave an open
-- flag on a removed post. (After-triggers fire in name order; the foreign-key trigger's name sorts first.)
create function app.review_flags_recheck() returns trigger
language plpgsql
as $$
begin
  if new.source = 'report' and not app.reportable(new.post_id, new.reporter_id) then
    raise exception 'not_reportable' using errcode = 'P0001';
  end if;
  return null;
end
$$;
create trigger review_flags_recheck after insert on app.review_flags for each row execute function app.review_flags_recheck();
alter table app.review_flags enable always trigger review_flags_recheck;

-- ---- The audit record (O3), written by the database ----
-- A new flag: who reported it (or which rule or classifier), and why.
create function app.review_flags_audit_new() returns trigger
language plpgsql
as $$
begin
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('review.flag', 'post', new.post_id,
            jsonb_strip_nulls(jsonb_build_object('flag', new.id, 'source', new.source, 'reason', new.reason, 'classifier', new.classifier)));
  return null;
end
$$;
create trigger review_flags_audit_new after insert on app.review_flags for each row execute function app.review_flags_audit_new();
alter table app.review_flags enable always trigger review_flags_audit_new;

-- A closed flag: the decision on it.
create function app.review_flags_audit_close() returns trigger
language plpgsql
as $$
begin
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('review.close', 'post', new.post_id, jsonb_build_object('flag', new.id, 'source', new.source, 'decision', new.decision));
  return null;
end
$$;
create trigger review_flags_audit_close after update on app.review_flags for each row execute function app.review_flags_audit_close();
alter table app.review_flags enable always trigger review_flags_audit_close;

-- A post's status change: approved, removed or restored, by whom (the audit row's actor) and when. The post's open
-- flags close with it, so a change made any way at all leaves the queue and the record consistent.
create function app.posts_after_review() returns trigger
language plpgsql
as $$
declare
  d text;
begin
  if new.status is distinct from old.status then
    d := case when old.status = 'waiting' and new.status = 'live' then 'approve'
              when new.status = 'removed' then 'remove'
              else 'restore' end;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('post.' || d, 'post', new.id, jsonb_build_object('from', old.status, 'to', new.status, 'author', new.author_id));
    update app.review_flags set decision = d where post_id = new.id and resolved_at is null;
    -- A never-approved first post that is put back goes back in the queue.
    if new.status = 'waiting' then
      insert into app.review_flags (post_id, source) values (new.id, 'first_posts');
    end if;
  end if;
  return null;
end
$$;
create trigger posts_after_review after update on app.posts for each row execute function app.posts_after_review();
alter table app.posts enable always trigger posts_after_review;

-- A post that waits for review is put in the queue as it is written (F6).
create function app.posts_flag_waiting() returns trigger
language plpgsql
as $$
begin
  if new.status = 'waiting' then
    insert into app.review_flags (post_id, source) values (new.id, 'first_posts');
  end if;
  return null;
end
$$;
create trigger posts_flag_waiting after insert on app.posts for each row execute function app.posts_flag_waiting();
alter table app.posts enable always trigger posts_flag_waiting;

-- ---- One decision on a post, closing all of its open flags ----
-- Runs with the caller's own rights, so every rule above still applies. Returns the post's new status.
--   approve: a waiting post goes live          keep: a live post stays (the reports were not upheld)
--   remove: a waiting or live post is removed (on an already removed post it closes any flags left open)
--   restore: undo a removal: back to live if the post had been approved, back to waiting if it never was
create function app.review_decide(p_post uuid, p_decision text)
returns text
language plpgsql
as $$
declare
  cur text;
  to_status text;
  was_live boolean;
begin
  if not app.is_reviewer() then
    raise exception 'only a reviewer can decide' using errcode = '42501';
  end if;
  select p.status, p.first_published_at is not null into cur, was_live from app.posts p where p.id = p_post for update;
  if not found then
    raise exception 'no such post' using errcode = 'P0002';
  end if;
  to_status := case
    when p_decision = 'approve' and cur = 'waiting' then 'live'
    when p_decision = 'keep' and cur = 'live' then 'live'
    when p_decision = 'remove' and cur in ('waiting', 'live') then 'removed'
    when p_decision = 'restore' and cur = 'removed' then case when was_live then 'live' else 'waiting' end
    when p_decision = 'remove' and cur = 'removed'
      and exists (select 1 from app.review_flags f where f.post_id = p_post and f.resolved_at is null) then 'removed'
  end;
  if to_status is null then
    raise exception 'cannot % a post that is %', coalesce(p_decision, 'decide'), cur using errcode = 'P0001', hint = 'stale';
  end if;
  if to_status <> cur then
    -- Closes the post's flags and writes the record (posts_after_review).
    update app.posts set status = to_status where id = p_post;
  else
    update app.review_flags set decision = p_decision where post_id = p_post and resolved_at is null;
  end if;
  return to_status;
end
$$;

revoke execute on function app.is_reviewer(), app.posts_review_guard(), app.review_flags_guard(), app.review_flags_audit_new(),
  app.review_flags_audit_close(), app.posts_after_review(), app.posts_flag_waiting(), app.review_decide(uuid, text),
  app.posts_first_published(), app.review_flags_recheck() from public;
grant execute on function app.is_reviewer(), app.review_decide(uuid, text) to dog_app;
