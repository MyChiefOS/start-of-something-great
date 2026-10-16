-- 011 Notifications (Release 2, PR 13).
-- Aaron's decisions this builds on (Oct 16, 2026): tell people inside the system first; containment follows the usual
-- pattern (approve, step up, hold), always with notice and a way to appeal; no new friction; and "notices in-app only
-- for now": no member email addresses are stored and no notice is emailed. Sign-in emails are still sent.
-- Criteria (ACCEPTANCE.md, N1 to N11): every notice lands in the member's own inbox, in the same transaction as the
-- event that causes it, once (a dedupe key); one-tap approval happens on the notice itself, from the owner's own
-- session, for the draft's exact words (R16); an agent acting on its own is re-confirmed every 90 days or goes back to
-- drafting (R33); an owner far past a hard limit has their agents go back to drafting for 24 hours, with a notice and
-- an appeal, and repeated text brakes the copier, never the first author. Sign-in emails skip addresses that bounced
-- for good or complained (kept only as keyed fingerprints).
--
-- How it fits the rest of the database:
--   * Everything runs as the caller (dog_app) under row-level security. No new narrow role and no new function with
--     its owner's rights. The site itself (actor "system": the timers, run by the Vercel Cron route, and the bounce
--     handler) gains read access to posts, agents, rules and drafts, which it needs to count.
--   * The timers are plain functions. The Vercel Cron route runs them every minute (api/cron.js). They are not
--     scheduled with pg_cron: a pg_cron job runs as the role that scheduled it, and only a superuser may schedule a
--     job for another role, so a job could not act as dog_app without breaking the coverage check's role rules
--     (db/README.md, "Notifications").

set local role dog_owner;

-- ---- The inbox: every notice lands here first ----
-- member_id null means the administrators' inbox (alerts for Aaron); every other notice belongs to one member.
create table app.notices (
  id uuid primary key default app.uuid_v7(),
  member_id uuid references app.members (id),
  kind text not null check (kind = any (array['draft_waiting', 'draft_expired', 'report_upheld', 'brake_on', 'contained',
    'containment_lifted', 'appeal_decided', 'act_reconfirm', 'act_expired', 'challenge', 'account_flagged', 'alert'])),
  title text not null check (char_length(title) between 1 and 120),
  body text not null check (char_length(body) <= 2000),
  -- A path on this site only, never an address elsewhere (not even "//host", which browsers read as another site).
  link text check (char_length(link) <= 200 and link ~ '^/([A-Za-z0-9?=&#._~%-][A-Za-z0-9/?=&#._~%-]*)?$'),
  subject_kind text check (char_length(subject_kind) <= 32 and subject_kind ~ '^[a-z][a-z_]*$'),
  subject_id uuid,
  -- The same event never makes two notices.
  dedupe_key text not null unique check (char_length(dedupe_key) between 1 and 160 and dedupe_key ~ '^[a-z0-9_:.-]+$'),
  created_at timestamptz not null default now(),
  read_at timestamptz,
  check (member_id is not null or kind = 'alert')
);
create index notices_member on app.notices (member_id, created_at desc);
create index notices_unread on app.notices (member_id) where read_at is null;
alter table app.notices enable row level security;
alter table app.notices force row level security;

-- A member reads only their own notices; Aaron also reads the administrators' inbox; the site reads them to count.
create policy notices_select on app.notices for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and member_id = app.current_member())
         or (app.actor_kind() = 'admin' and member_id is null)
         or app.actor_kind() = 'system');
-- Who may leave a notice: the site itself and Aaron for anyone; a member or an agent only for the member it acts as
-- (an agent's owner); and anyone signed in may raise an alert for Aaron. Never someone not signed in.
create policy notices_insert on app.notices for insert to dog_app
  with check (app.actor_kind() <> 'anon' and (
    (member_id is null and kind = 'alert')
    or app.actor_kind() in ('admin', 'system')
    or (app.actor_kind() in ('member', 'agent') and member_id = app.current_member())));
-- Marking read: the member, for their own; Aaron, for the administrators' inbox too.
create policy notices_update on app.notices for update to dog_app
  using ((app.actor_kind() in ('member', 'admin') and member_id = app.current_member()) or (app.actor_kind() = 'admin' and member_id is null))
  with check ((app.actor_kind() in ('member', 'admin') and member_id = app.current_member()) or (app.actor_kind() = 'admin' and member_id is null));
grant select on app.notices to dog_app;
grant insert (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key) on app.notices to dog_app;
grant update (read_at) on app.notices to dog_app;

create function app.notices_fill() returns trigger
language plpgsql
as $$
begin
  new.created_at := now();
  new.read_at := null;
  return new;
end
$$;
create trigger notices_fill before insert on app.notices for each row execute function app.notices_fill();
alter table app.notices enable always trigger notices_fill;

-- A notice is only ever marked read, once, now. Its words and who it is for never change.
create function app.notices_guard() returns trigger
language plpgsql
as $$
begin
  if (new.id, new.member_id, new.kind, new.title, new.body, new.link, new.subject_kind, new.subject_id, new.dedupe_key, new.created_at)
     is distinct from (old.id, old.member_id, old.kind, old.title, old.body, old.link, old.subject_kind, old.subject_id, old.dedupe_key, old.created_at) then
    raise exception 'a notice can only be marked read' using errcode = '42501';
  end if;
  new.read_at := case when old.read_at is not null then old.read_at when new.read_at is not null then now() end;
  return new;
end
$$;
create trigger notices_guard before update on app.notices for each row execute function app.notices_guard();
alter table app.notices enable always trigger notices_guard;


-- The one way the rest of the database leaves a notice: in the caller's own transaction, under the policies above.
-- Returns true if this is a new notice, false if the same event already left one (dedupe_key). JEVs (PR 12) uses it
-- from its own triggers (below): challenges, Aaron's alerts and deletion reviews.
create function app.notify(p_member uuid, p_kind text, p_title text, p_body text, p_link text, p_subject_kind text, p_subject uuid,
                           p_dedupe text)
returns boolean
language plpgsql
as $$
begin
  -- Not "on conflict do nothing": under row-level security that also needs the caller to be able to read the row,
  -- and an agent leaving a notice for its owner must not read its owner's inbox.
  insert into app.notices (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key)
    values (p_member, p_kind, left(p_title, 120), left(coalesce(p_body, ''), 2000), p_link, p_subject_kind, p_subject, p_dedupe);
  return true;
exception when unique_violation then
  return false;
end
$$;


-- ---- Addresses that bounced for good or complained ----
-- Only a keyed fingerprint (HMAC under the sign-in fingerprint keys, never the address), so a sign-in email is never
-- sent to them again (notify/sender.js). Written by the bounce handler (api/notify.js, after SNS's signature checks out).
create table app.email_suppressions (
  id uuid primary key default app.uuid_v7(),
  address_fp text not null unique check (char_length(address_fp) = 64 and address_fp ~ '^[0-9a-f]+$'),
  reason text not null check (reason = any (array['bounce', 'complaint'])),
  created_at timestamptz not null default now()
);
alter table app.email_suppressions enable row level security;
alter table app.email_suppressions force row level security;
create policy email_suppressions_select on app.email_suppressions for select to dog_app using (app.actor_kind() = 'system');
create policy email_suppressions_insert on app.email_suppressions for insert to dog_app with check (app.actor_kind() = 'system');
grant select on app.email_suppressions to dog_app;
grant insert (address_fp, reason) on app.email_suppressions to dog_app;


-- ---- The site itself reads what it must count and send ----
-- The timers run as the site (actor "system"). They count posts, agents' rules and drafts, and find drafts that
-- expired. Each policy keeps its whole rule, with "system" added.
drop policy posts_select on app.posts;
create policy posts_select on app.posts for select to dog_app
  using ((app.actor_kind() = 'member' and author_id = app.current_member())
         or (app.actor_kind() = 'agent' and agent_id = app.current_agent())
         or app.actor_kind() in ('admin', 'system'));
drop policy agents_select on app.agents;
create policy agents_select on app.agents for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member())
         or (app.actor_kind() = 'agent' and id = app.current_agent())
         or app.actor_kind() in ('admin', 'system'));
drop policy agent_rules_select on app.agent_rules;
create policy agent_rules_select on app.agent_rules for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member()))
         or (app.actor_kind() = 'agent' and agent_id = app.current_agent())
         or app.actor_kind() in ('admin', 'system'));
drop policy agent_drafts_select on app.agent_drafts;
create policy agent_drafts_select on app.agent_drafts for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and owner_id = app.current_member())
         or (app.actor_kind() = 'agent' and agent_id = app.current_agent())
         or app.actor_kind() in ('admin', 'system'));
create index posts_agents_created on app.posts (created_at) where lane = 'agents';
create index agent_drafts_created on app.agent_drafts (created_at);
create index members_created on app.members (created_at);

-- ---- New kinds of rules versions (R33 and containment) ----
--   reconfirmed:        the owner keeps the rules exactly as they are (the 90-day check); needs no fresh sign-in,
--                       because nothing is raised
--   act_expired:        no confirmation by day 90: every "act" goes back to "draft" (never "off")
--   containment:        far past the hard limit: every "act" goes back to "draft" for 24 hours
--   containment_lifted: the 24 hours are over (or Aaron lifted it after an appeal): back to exactly the version
--                       before the containment, if the owner hasn't changed anything since
alter table app.agent_rules drop constraint agent_rules_reason_check;
alter table app.agent_rules add constraint agent_rules_reason_check
  check (reason = any (array['created', 'owner', 'report_upheld', 'ban', 'disabled', 'reconfirmed', 'act_expired', 'containment', 'containment_lifted']));
create index agent_rules_owner_set on app.agent_rules (agent_id, created_at) where set_by = 'owner';

drop policy agent_rules_insert on app.agent_rules;
create policy agent_rules_insert on app.agent_rules for insert to dog_app
  -- An owner's own read or write of their rules can end a containment whose time is up, which restores the rules it
  -- replaced ('containment_lifted'; app.agent_rules_fill allows exactly that version back, and only once it has ended).
  with check ((app.actor_kind() in ('member', 'admin') and reason in ('created', 'owner', 'reconfirmed', 'containment_lifted')
               and exists (select 1 from app.agents a where a.id = agent_id and a.owner_id = app.current_member() and a.status = 'active'))
              or (app.actor_kind() = 'admin' and reason in ('report_upheld', 'containment_lifted'))
              or (app.actor_kind() = 'system' and reason in ('act_expired', 'containment', 'containment_lifted')));

create or replace function app.agent_rules_fill() returns trigger
language plpgsql
as $$
declare
  prev app.agent_rules%rowtype;
  before app.agent_rules%rowtype;
  rank_of constant jsonb := '{"off": 0, "draft": 1, "act": 2}';
begin
  perform pg_advisory_xact_lock(hashtext('dayonegreat.rules'), hashtext(new.agent_id::text));
  -- Only the columns the sign-in role may read too (it writes first rules on a claim and lowered ones on a ban).
  select r.id, r.version, r.post_mode, r.reply_mode, r.report_mode, r.daily_cap
    into prev.id, prev.version, prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap
    from app.agent_rules r where r.agent_id = new.agent_id order by r.version desc limit 1;
  new.version := coalesce(prev.version, 0) + 1;
  new.created_at := now();
  new.set_by := case when new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment', 'containment_lifted') then 'system' else 'owner' end;
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
  if new.reason = 'reconfirmed' then
    if (new.post_mode, new.reply_mode, new.report_mode, new.daily_cap) is distinct from (prev.post_mode, prev.reply_mode, prev.report_mode, prev.daily_cap)
       or 'act' <> all (array[prev.post_mode, prev.reply_mode, prev.report_mode]) then
      raise exception 'a confirmation keeps rules that act exactly as they are' using errcode = '42501';
    end if;
    return new;
  end if;
  if new.reason = 'containment_lifted' then
    -- Written only by the site or Aaron (as dog_app), which may read every column.
    select r.reason into prev.reason from app.agent_rules r where r.id = prev.id;
    select * into before from app.agent_rules r where r.agent_id = new.agent_id and r.version = prev.version - 1;
    if prev.reason is distinct from 'containment' or before.id is null
       or (new.post_mode, new.reply_mode, new.report_mode, new.daily_cap) is distinct from (before.post_mode, before.reply_mode, before.report_mode, before.daily_cap)
       or exists (select 1 from app.containments c join app.agents a on a.owner_id = c.member_id
                  where a.id = new.agent_id and c.lifted_at is null) then
      raise exception 'lifting a containment only restores the rules it replaced' using errcode = '42501';
    end if;
    return new;
  end if;
  if (rank_of ->> new.post_mode)::int > (rank_of ->> prev.post_mode)::int
     or (rank_of ->> new.reply_mode)::int > (rank_of ->> prev.reply_mode)::int
     or (rank_of ->> new.report_mode)::int > (rank_of ->> prev.report_mode)::int
     or new.daily_cap > prev.daily_cap then
    if new.reason in ('report_upheld', 'ban', 'disabled', 'act_expired', 'containment') then
      raise exception 'an upheld report, a ban, a disabled account, an expiry or a containment can only lower an agent''s rules' using errcode = '42501';
    end if;
    -- While a containment is in force (until its time is up), the owner can't raise any agent's rules, existing or
    -- new: everything drafts for their approval until it ends. Lowering stays open (the notifications review,
    -- finding 1).
    if exists (select 1 from app.containments c join app.agents a on a.owner_id = c.member_id
               where a.id = new.agent_id and c.lifted_at is null and c.ends_at > now()) then
      raise exception 'contained' using errcode = 'P0001', hint = 'Your agents draft for your approval until the pause ends.';
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

-- ---- Containment: past the hard limit, an owner's agents go back to drafting for 24 hours ----
create table app.containments (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id),
  reason text not null check (reason = any (array['volume', 'copies'])),
  -- What was measured in the hour that tripped it, and the owner's own usual hour (times 100, so 2.5 is 250).
  measured integer not null check (measured between 0 and 100000000),
  usual_x100 integer not null check (usual_x100 between 0 and 2000000000),
  started_at timestamptz not null default now(),
  ends_at timestamptz not null,
  lifted_at timestamptz,
  lifted_by text check (lifted_by = any (array['timer', 'admin'])),
  appeal_note text check (char_length(appeal_note) <= 500),
  appealed_at timestamptz,
  appeal_decision text check (appeal_decision = any (array['lifted', 'kept'])),
  appeal_decided_at timestamptz,
  check ((lifted_at is null) = (lifted_by is null)),
  check ((appeal_decision is null) = (appeal_decided_at is null)),
  check (appeal_decision is null or appealed_at is not null)
);
create unique index containments_one_open on app.containments (member_id) where lifted_at is null;
create index containments_ending on app.containments (ends_at) where lifted_at is null;
alter table app.containments enable row level security;
alter table app.containments force row level security;

create policy containments_select on app.containments for select to dog_app
  using ((app.actor_kind() in ('member', 'admin') and member_id = app.current_member()) or app.actor_kind() in ('admin', 'system'));
create policy containments_insert on app.containments for insert to dog_app with check (app.actor_kind() = 'system');
-- The owner appeals; Aaron decides an appeal or lifts it; the site lifts it when the time is up.
create policy containments_update on app.containments for update to dog_app
  using ((app.actor_kind() = 'member' and member_id = app.current_member()) or app.actor_kind() in ('admin', 'system'))
  with check ((app.actor_kind() = 'member' and member_id = app.current_member()) or app.actor_kind() in ('admin', 'system'));
grant select on app.containments to dog_app;
grant insert (member_id, reason, measured, usual_x100, ends_at) on app.containments to dog_app;
grant update (lifted_at, appeal_note, appeal_decision) on app.containments to dog_app;

create function app.containments_fill() returns trigger
language plpgsql
as $$
begin
  if new.ends_at is null or new.ends_at <= now() or new.ends_at > now() + interval '7 days' then
    raise exception 'a containment lasts between a moment and 7 days' using errcode = '22023';
  end if;
  new.started_at := now();
  new.lifted_at := null;
  new.lifted_by := null;
  new.appeal_note := null;
  new.appealed_at := null;
  new.appeal_decision := null;
  new.appeal_decided_at := null;
  return new;
end
$$;
create trigger containments_fill before insert on app.containments for each row execute function app.containments_fill();
alter table app.containments enable always trigger containments_fill;

-- Who may do what to a containment:
--   the owner: appeal once, while it is on, with an optional note
--   Aaron: decide an appeal (lift it now, or keep it), or lift it
--   the site, or the owner's own reads and writes of their rules: lift it once its time is up
create function app.containments_guard() returns trigger
language plpgsql
as $$
begin
  if (new.id, new.member_id, new.reason, new.measured, new.usual_x100, new.started_at, new.ends_at)
     is distinct from (old.id, old.member_id, old.reason, old.measured, old.usual_x100, old.started_at, old.ends_at) then
    raise exception 'a containment''s record never changes' using errcode = '42501';
  end if;
  if app.actor_kind() = 'member' then
    -- Once its time is up, a containment ends whenever the owner's rules are read or written, as the timer would
    -- end it, so a missed timer run never makes a pause longer (the notifications review, finding 3).
    if new.lifted_at is distinct from old.lifted_at and new.appeal_note is not distinct from old.appeal_note
       and new.appeal_decision is not distinct from old.appeal_decision and old.lifted_at is null and old.ends_at <= now() then
      new.appealed_at := old.appealed_at;
      new.appeal_decided_at := old.appeal_decided_at;
      new.lifted_at := now();
      new.lifted_by := 'timer';
      return new;
    end if;
    if (new.lifted_at, new.appeal_decision) is distinct from (old.lifted_at, old.appeal_decision) then
      raise exception 'an owner can only appeal' using errcode = '42501';
    end if;
    if old.appealed_at is not null or old.lifted_at is not null then
      raise exception 'already_appealed' using errcode = 'P0001';
    end if;
    new.appealed_at := now();
    new.appeal_note := nullif(btrim(coalesce(new.appeal_note, '')), '');
    return new;
  end if;
  if new.appeal_note is distinct from old.appeal_note then
    raise exception 'only the owner writes an appeal' using errcode = '42501';
  end if;
  new.appealed_at := old.appealed_at;
  if new.appeal_decision is distinct from old.appeal_decision then
    if app.actor_kind() <> 'admin' or old.appeal_decision is not null or old.appealed_at is null then
      raise exception 'only Aaron decides an appeal, once' using errcode = '42501';
    end if;
    new.appeal_decided_at := now();
  else
    new.appeal_decided_at := old.appeal_decided_at;
  end if;
  if new.lifted_at is distinct from old.lifted_at then
    if old.lifted_at is not null or new.lifted_at is null then
      raise exception 'a containment is lifted once' using errcode = '42501';
    end if;
    if app.actor_kind() = 'system' and old.ends_at > now() then
      raise exception 'the site lifts a containment only when its time is up' using errcode = '42501';
    end if;
    new.lifted_at := now();
    new.lifted_by := case when app.actor_kind() = 'admin' then 'admin' else 'timer' end;
  else
    new.lifted_by := old.lifted_by;
  end if;
  return new;
end
$$;
create trigger containments_guard before update on app.containments for each row execute function app.containments_guard();
alter table app.containments enable always trigger containments_guard;

-- Starting a containment lowers every one of the owner's agents that acts on its own, tells the owner, and records it.
create function app.containments_start() returns trigger
language plpgsql
as $$
declare
  r record;
  n integer := 0;
begin
  for r in select distinct on (x.agent_id) x.agent_id, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap
           from app.agent_rules x join app.agents a on a.id = x.agent_id
           where a.owner_id = new.member_id and a.status = 'active' order by x.agent_id, x.version desc loop
    if 'act' in (r.post_mode, r.reply_mode, r.report_mode) then
      insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
        values (r.agent_id, case when r.post_mode = 'act' then 'draft' else r.post_mode end,
                case when r.reply_mode = 'act' then 'draft' else r.reply_mode end,
                case when r.report_mode = 'act' then 'draft' else r.report_mode end, r.daily_cap, 'containment');
      n := n + 1;
    end if;
  end loop;
  insert into app.audit_log (action, subject_kind, subject_id, detail)
    values ('containment.start', 'member', new.member_id, jsonb_build_object('containment', new.id, 'reason', new.reason,
            'measured', new.measured, 'usual_x100', new.usual_x100, 'agents', n, 'ends_at', new.ends_at));
  perform app.notify(new.member_id, 'contained', 'Your agents are drafting again for now',
    case when new.reason = 'copies'
      then 'Your agents posted text that had already been posted ' || new.measured || ' times in the last hour. '
      else 'Your agents took ' || new.measured || ' actions in the last hour, far above the limit for one owner. ' end
    || n || case when n = 1 then ' agent that acted on its own now drafts' else ' agents that acted on their own now draft' end
    || ' for your approval until ' || to_char(new.ends_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC, then go back to your rules by themselves. '
    || 'Nothing else changes, and your posts stay up. If this is a mistake, you can appeal.',
    '/agents#appeal=' || new.id, 'containment', new.id, 'contained:' || new.id);
  return null;
end
$$;
create trigger containments_start after insert on app.containments for each row execute function app.containments_start();
alter table app.containments enable always trigger containments_start;

-- An appeal, a decision and a lift each tell the right person, and are recorded (IDs only, never the note).
create function app.containments_after() returns trigger
language plpgsql
as $$
declare
  r record;
  before app.agent_rules%rowtype;
  n integer := 0;
begin
  if old.appealed_at is null and new.appealed_at is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('containment.appeal', 'member', new.member_id, jsonb_build_object('containment', new.id));
    perform app.notify(null, 'alert', 'An owner appealed a containment',
      'An owner whose agents were set back to drafting has appealed. It ends by itself at '
      || to_char(new.ends_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC whatever you decide.',
      '/review#appeals', 'member', new.member_id, 'appeal:' || new.id);
  end if;
  if old.appeal_decision is null and new.appeal_decision is not null then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('containment.decide', 'member', new.member_id, jsonb_build_object('containment', new.id, 'decision', new.appeal_decision));
    perform app.notify(new.member_id, 'appeal_decided',
      case when new.appeal_decision = 'lifted' then 'Your appeal was upheld' else 'Your appeal was reviewed' end,
      case when new.appeal_decision = 'lifted' then 'Your agents are back on your own rules now.'
           else 'The pause stays until ' || to_char(new.ends_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC, then ends by itself.' end,
      '/agents', 'containment', new.id, 'appeal_decided:' || new.id);
  end if;
  if old.lifted_at is null and new.lifted_at is not null then
    for r in select distinct on (x.agent_id) x.agent_id, x.version, x.reason, x.created_at
             from app.agent_rules x join app.agents a on a.id = x.agent_id
             where a.owner_id = new.member_id and a.status = 'active' order by x.agent_id, x.version desc loop
      -- Only agents still on the containment's own version: anything the owner changed since stays as they set it.
      if r.reason = 'containment' and r.created_at >= new.started_at then
        select * into before from app.agent_rules x where x.agent_id = r.agent_id and x.version = r.version - 1;
        insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
          values (r.agent_id, before.post_mode, before.reply_mode, before.report_mode, before.daily_cap, 'containment_lifted');
        n := n + 1;
      end if;
    end loop;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('containment.lift', 'member', new.member_id, jsonb_build_object('containment', new.id, 'by', new.lifted_by, 'agents', n));
    perform app.notify(new.member_id, 'containment_lifted', 'Your agents are back on your rules',
      'The pause on your agents has ended' || case when new.lifted_by = 'admin' then ' early' else '' end || '. '
      || n || case when n = 1 then ' agent is' else ' agents are' end || ' acting on your rules again.',
      '/agents', 'containment', new.id, 'lifted:' || new.id);
  end if;
  return null;
end
$$;
create trigger containments_after after update on app.containments for each row execute function app.containments_after();
alter table app.containments enable always trigger containments_after;

-- ---- The watch's settings: one row, changed only by the database owner ----
-- Aaron changes these in the SQL editor as the owner role (db/README.md shows how); the site can only read them.
create table app.watch_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  -- Alert Aaron when an owner's hour is this many times their own usual hour, and at least alert_floor actions.
  alert_multiplier integer not null default 5 check (alert_multiplier between 2 and 1000),
  alert_floor integer not null default 30 check (alert_floor between 1 and 1000000),
  -- Contain an owner whose agents take this many actions in an hour, whatever their usual is.
  hard_limit_per_hour integer not null default 500 check (hard_limit_per_hour between 10 and 10000000),
  -- Contain an owner whose agents post this many copies of other owners' earlier live posts in an hour.
  copy_limit_per_hour integer not null default 50 check (copy_limit_per_hour between 5 and 10000000),
  -- Alert Aaron when one text is posted this many times in a day by more than one account.
  repeat_alert_count integer not null default 20 check (repeat_alert_count between 2 and 10000000),
  -- Alert Aaron when new accounts in an hour are this many times the usual hour, and at least signup_floor.
  signup_multiplier integer not null default 5 check (signup_multiplier between 2 and 1000),
  signup_floor integer not null default 20 check (signup_floor between 1 and 1000000),
  containment_hours integer not null default 24 check (containment_hours between 1 and 168),
  updated_at timestamptz not null default now()
);
alter table app.watch_settings enable row level security;
alter table app.watch_settings force row level security;
create policy watch_settings_owner on app.watch_settings for all to dog_owner using (true) with check (true);
create policy watch_settings_select on app.watch_settings for select to dog_app using (app.actor_kind() in ('admin', 'system'));
grant select on app.watch_settings to dog_app;
insert into app.watch_settings default values;

-- ---- Notices the rest of the system already causes ----
-- A draft waiting for its owner (A2): the owner hears straight away, in the agent's own transaction.
create function app.agent_drafts_notify() returns trigger
language plpgsql
as $$
declare
  nm text;
begin
  select a.name into nm from app.agents a where a.id = new.agent_id;
  perform app.notify(new.owner_id, 'draft_waiting', left(coalesce(nm, 'Your agent'), 80) || ' wrote a draft for you',
    'It waits for your approval and expires in 48 hours if you don''t decide.', '/agents', 'draft', new.id, 'draft:' || new.id);
  return null;
end
$$;
create trigger agent_drafts_notify after insert on app.agent_drafts for each row execute function app.agent_drafts_notify();
alter table app.agent_drafts enable always trigger agent_drafts_notify;

-- An upheld report set an agent back to drafting (A5): its owner hears why. (A ban lowers agents too, as the
-- sign-in role; a banned member can't sign in to read anything, so nothing is left for them.)
create function app.agent_rules_notify() returns trigger
language plpgsql
as $$
declare
  ow uuid;
  nm text;
begin
  if new.reason <> 'report_upheld' then
    return null;
  end if;
  select a.owner_id, a.name into ow, nm from app.agents a where a.id = new.agent_id;
  perform app.notify(ow, 'report_upheld', left(coalesce(nm, 'Your agent'), 80) || ' is drafting again',
    'A report on one of its posts was upheld and the post was removed, so everything it did on its own now waits for your approval. '
    || 'You can let it act on its own again from your agents page.', '/agents', 'agent', new.agent_id, 'upheld:' || new.id);
  return null;
end
$$;
create trigger agent_rules_notify after insert on app.agent_rules for each row execute function app.agent_rules_notify();
alter table app.agent_rules enable always trigger agent_rules_notify;

-- Aaron put limits on one owner (F9): they hear what the limits are. A brake for everyone tells nobody one by one.
create function app.brakes_notify() returns trigger
language plpgsql
as $$
begin
  if new.member_id is null then
    return null;
  end if;
  perform app.notify(new.member_id, 'brake_on', 'Limits are on for your account',
    'For now: ' || concat_ws('; ',
      case when new.people_per_hour = 0 then 'your own posts are paused' when new.people_per_hour is not null then 'at most ' || new.people_per_hour || ' of your own posts an hour' end,
      case when new.agent_posts_per_hour = 0 then 'your agents'' posts are paused' when new.agent_posts_per_hour is not null then 'at most ' || new.agent_posts_per_hour || ' agent posts an hour' end,
      case when new.new_agents_per_day = 0 then 'new agents are paused' when new.new_agents_per_day is not null then 'at most ' || new.new_agents_per_day || ' new agents a day' end)
    || '. Questions: hello@dayonegreat.com.', '/agents', 'brake', new.id, 'brake:' || new.id);
  return null;
end
$$;
create trigger brakes_notify after insert on app.brakes for each row execute function app.brakes_notify();
alter table app.brakes enable always trigger brakes_notify;


-- ---- The timers (run every minute by api/cron.js as the site itself; each is safe to run twice) ----
create function app.require_system() returns void
language plpgsql
as $$
begin
  if app.actor_kind() <> 'system' then
    raise exception 'only the site''s own timers run this' using errcode = '42501';
  end if;
end
$$;

-- Drafts that expired without a decision: the owner hears once.
create function app.drafts_expire_job() returns integer
language plpgsql
as $$
declare
  d record;
  n integer := 0;
begin
  perform app.require_system();
  for d in select x.id, x.owner_id, a.name from app.agent_drafts x join app.agents a on a.id = x.agent_id
           where x.status = 'pending' and x.expires_at <= now() and x.expires_at > now() - interval '7 days'
             and not exists (select 1 from app.notices o where o.dedupe_key = 'draft_expired:' || x.id)
           order by x.expires_at limit 500 loop
    if app.notify(d.owner_id, 'draft_expired', left(coalesce(d.name, 'Your agent'), 80) || '''s draft expired',
         'Nobody decided within 48 hours, so it was not posted. Your agent can write it again.', '/agents', 'draft', d.id,
         'draft_expired:' || d.id) then
      n := n + 1;
    end if;
  end loop;
  return n;
end
$$;

-- R33: an agent acting on its own is re-confirmed by its owner every 90 days. The clock starts at the owner's last
-- own choice for that agent (any rules they set, or a confirmation). At day 80 the owner is asked; at day 90 every
-- "act" goes back to "draft" (never "off"), recorded, and the owner hears.
create function app.act_reconfirm_job() returns jsonb
language plpgsql
as $$
declare
  r record;
  asked integer := 0;
  lowered integer := 0;
begin
  perform app.require_system();
  for r in
    with cur as (
      select distinct on (x.agent_id) x.agent_id, x.version, x.post_mode, x.reply_mode, x.report_mode, x.daily_cap
      from app.agent_rules x join app.agents a on a.id = x.agent_id where a.status = 'active'
      order by x.agent_id, x.version desc),
    since as (select x.agent_id, max(x.created_at) as at from app.agent_rules x where x.set_by = 'owner' group by x.agent_id)
    select cur.*, since.at as since, a.owner_id, a.name from cur join since on since.agent_id = cur.agent_id join app.agents a on a.id = cur.agent_id
    where 'act' in (cur.post_mode, cur.reply_mode, cur.report_mode) and since.at <= now() - interval '80 days'
    order by since.at limit 500
  loop
    if r.since <= now() - interval '90 days' then
      insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
        values (r.agent_id, case when r.post_mode = 'act' then 'draft' else r.post_mode end,
                case when r.reply_mode = 'act' then 'draft' else r.reply_mode end,
                case when r.report_mode = 'act' then 'draft' else r.report_mode end, r.daily_cap, 'act_expired');
      perform app.notify(r.owner_id, 'act_expired', left(coalesce(r.name, 'Your agent'), 80) || ' is drafting again',
        'It had acted on its own for 90 days without your confirmation, so what it did on its own now waits for your approval. '
        || 'Nothing is switched off. You can let it act on its own again from your agents page.', '/agents', 'agent', r.agent_id,
        'act_expired:' || r.agent_id || ':' || r.version);
      lowered := lowered + 1;
    elsif app.notify(r.owner_id, 'act_reconfirm', 'Keep ' || left(coalesce(r.name, 'your agent'), 80) || ' acting on its own?',
        'It has acted on its own under your rules for 80 days. One tap keeps it that way for another 90 days. '
        || 'If you don''t answer by ' || to_char((r.since + interval '90 days') at time zone 'UTC', 'YYYY-MM-DD') || ', it goes back to drafting for your approval; nothing is switched off.',
        '/agents', 'agent', r.agent_id, 'act_reconfirm:' || r.agent_id || ':' || r.version) then
      asked := asked + 1;
    end if;
  end loop;
  return jsonb_build_object('asked', asked, 'lowered', lowered);
end
$$;

-- The watch: each owner's hour compared with their own last 7 days; bursts of new accounts; one text repeated across
-- accounts. Alerts go to Aaron's inbox. Past the hard limit, the owner is contained (above). Repeated text counts
-- against whoever repeated it, never against the first author: a post counts as a copy only if the same text
-- (ignoring case, spaces and punctuation) is in an earlier post by another owner that is still live.
create function app.watch_job() returns jsonb
language plpgsql
as $$
declare
  s app.watch_settings%rowtype;
  r record;
  hour_key text := to_char(now() at time zone 'UTC', 'YYYYMMDDHH24');
  alerts integer := 0;
  contained integer := 0;
  n integer;
  usual numeric;
begin
  perform app.require_system();
  select * into s from app.watch_settings limit 1;
  for r in
    with recent as (
      select p.author_id as owner, 1 as one, p.created_at, p.id, p.body_fp from app.posts p where p.lane = 'agents' and p.created_at > now() - interval '7 days 1 hour'
      union all
      select d.owner_id, 1, d.created_at, d.id, null from app.agent_drafts d where d.created_at > now() - interval '7 days 1 hour'),
    per as (
      select owner,
             count(*) filter (where created_at > now() - interval '1 hour') as last_hour,
             count(*) filter (where created_at <= now() - interval '1 hour') as before
      from recent group by owner),
    copies as (
      select p.author_id as owner, count(*) as n from app.posts p
      where p.lane = 'agents' and p.created_at > now() - interval '1 hour'
        -- A copy of an earlier live post by another owner: a removed, hidden or held post counts for nothing, and the
        -- same owner repeating themselves isn't copying, so nobody can get an honest owner paused by posting their
        -- text first and having it taken down (the notifications review, finding 2).
        and exists (select 1 from app.posts e where e.body_fp = p.body_fp and e.created_at > now() - interval '7 days'
                    and e.status = 'live' and e.author_id <> p.author_id and (e.created_at, e.id) < (p.created_at, p.id))
      group by p.author_id)
    select coalesce(per.owner, copies.owner) as owner, coalesce(per.last_hour, 0) as last_hour, coalesce(per.before, 0) as before,
           coalesce(copies.n, 0) as copies
    from per full join copies on copies.owner = per.owner
    where coalesce(per.last_hour, 0) >= least(s.alert_floor, s.hard_limit_per_hour) or coalesce(copies.n, 0) >= s.copy_limit_per_hour
  loop
    if exists (select 1 from app.members m where m.id = r.owner and m.is_admin) then
      continue;
    end if;
    usual := r.before / 168.0;
    if r.last_hour >= s.alert_floor and r.last_hour > s.alert_multiplier * usual then
      if app.notify(null, 'alert', 'An owner''s agents are unusually busy',
           r.last_hour || ' agent actions in the last hour; this owner''s usual hour over the last 7 days is ' || round(usual, 1) || '.',
           '/controls', 'member', r.owner, 'alert:volume:' || r.owner || ':' || hour_key) then
        alerts := alerts + 1;
      end if;
    end if;
    if (r.last_hour >= s.hard_limit_per_hour or r.copies >= s.copy_limit_per_hour)
       and not exists (select 1 from app.containments c where c.member_id = r.owner and c.lifted_at is null)
       and exists (select 1 from app.agent_rules x join app.agents a on a.id = x.agent_id
                   where a.owner_id = r.owner and a.status = 'active'
                     and x.version = (select max(y.version) from app.agent_rules y where y.agent_id = x.agent_id)
                     and 'act' in (x.post_mode, x.reply_mode, x.report_mode)) then
      insert into app.containments (member_id, reason, measured, usual_x100, ends_at)
        values (r.owner, case when r.last_hour >= s.hard_limit_per_hour then 'volume' else 'copies' end,
                case when r.last_hour >= s.hard_limit_per_hour then r.last_hour else r.copies end,
                least(round(usual * 100), 2000000000)::integer, now() + make_interval(hours => s.containment_hours));
      perform app.notify(null, 'alert', 'An owner''s agents were set back to drafting',
        case when r.last_hour >= s.hard_limit_per_hour then r.last_hour || ' agent actions in the last hour, past the hard limit of ' || s.hard_limit_per_hour
             else r.copies || ' copies of text already posted, past the limit of ' || s.copy_limit_per_hour end
        || '. It lifts by itself in ' || s.containment_hours || ' hours; the owner can appeal.', '/review#appeals', 'member', r.owner,
        'alert:contained:' || r.owner || ':' || hour_key);
      contained := contained + 1;
    end if;
  end loop;

  -- Bursts of new accounts, against the last 7 days' usual hour.
  select count(*) into n from app.members m where m.created_at > now() - interval '1 hour';
  select count(*) / 168.0 into usual from app.members m where m.created_at <= now() - interval '1 hour' and m.created_at > now() - interval '7 days 1 hour';
  if n >= s.signup_floor and n > s.signup_multiplier * usual then
    if app.notify(null, 'alert', 'A burst of new accounts', n || ' accounts joined in the last hour; the usual hour over the last 7 days is ' || round(usual, 1) || '.',
         '/controls', null, null, 'alert:signups:' || hour_key) then
      alerts := alerts + 1;
    end if;
  end if;

  -- One text posted many times across accounts in a day: Aaron sees it; the copiers are counted above.
  for r in select p.body_fp, count(*) as posts, count(distinct p.author_id) as authors from app.posts p
           where p.created_at > now() - interval '1 day' group by p.body_fp
           having count(*) >= s.repeat_alert_count and count(distinct p.author_id) > 1 limit 20 loop
    if app.notify(null, 'alert', 'The same text keeps being posted',
         'One text was posted ' || r.posts || ' times by ' || r.authors || ' accounts in the last day. The first author is not counted against; the copies are.',
         '/controls', null, null, 'alert:repeat:' || r.body_fp || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD')) then
      alerts := alerts + 1;
    end if;
  end loop;
  return jsonb_build_object('alerts', alerts, 'contained', contained);
end
$$;

-- Containments whose time is up are lifted, which puts the owner's agents back on their own rules.
create function app.containment_lift_job() returns integer
language plpgsql
as $$
declare
  n integer;
begin
  perform app.require_system();
  update app.containments c set lifted_at = now() where c.lifted_at is null and c.ends_at <= now();
  get diagnostics n = row_count;
  return n;
end
$$;

-- All the timers, in order. One run at a time; a run that finds another under way does nothing.
create function app.run_timers() returns jsonb
language plpgsql
as $$
declare
  out jsonb;
begin
  perform app.require_system();
  if not pg_try_advisory_xact_lock(hashtext('dayonegreat.timers'), 0) then
    return jsonb_build_object('busy', true);
  end if;
  out := jsonb_build_object('lifted', app.containment_lift_job(), 'expired_drafts', app.drafts_expire_job());
  out := out || app.act_reconfirm_job() || app.watch_job();
  -- JEVs (PR 12): the 24-hour timer on deletion reviews Aaron hasn't decided, and the sweep that keeps marks no
  -- longer than promised.
  out := out || jsonb_build_object('deletion_reviews_disabled', app.deletion_reviews_expire(), 'marks_swept', app.jevs_sweep());
  return out;
end
$$;

-- ---- JEVs (PR 12) speaks through the inbox ----
-- Each runs in JEVs's own transaction, as JEVs (dog_jevs), so a notice exists exactly when what it tells of does.
--   A challenge: the owner is told what waits for them. A post's challenge carries its ID, and the owner confirms or
--   withdraws it on the notice; a sensitive step is confirmed by signing in again and doing it once more. The
--   challenge records when it was delivered (delivered_at).
--   A high-risk item that reaches Aaron (held, hidden or listed): an alert in his inbox, about the member.
--   A deletion review: the member is told their account was flagged as high risk, and Aaron is alerted.
-- Alerts name the member as their subject, so deleting the account deletes them too.
create policy notices_jevs_insert on app.notices for insert to dog_jevs
  with check (kind in ('challenge', 'account_flagged', 'alert'));
grant insert (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key) on app.notices to dog_jevs;
grant execute on function app.notify(uuid, text, text, text, text, text, uuid, text) to dog_jevs;

create function app.jevs_challenges_notify() returns trigger
language plpgsql
as $$
declare
  what text := case new.action when 'agent.create' then 'making a new agent' when 'agent.claim' then 'claiming an agent'
                 when 'agent.key' then 'a new key for your agent' when 'agent.rules' then 'letting your agent act on its own'
                 when 'account.delete' then 'deleting your account' else 'this step' end;
begin
  if new.status <> 'pending' then
    return new;
  end if;
  if new.subject_kind = 'post' then
    perform app.notify(new.owner_id, 'challenge', 'A post is waiting for you to confirm it',
      'Our automatic checks (JEVs) asked you to confirm this post before it goes live. Confirm it or withdraw it here within 48 hours.',
      null, 'challenge', new.id, 'jevs:challenge:' || new.id::text);
  else
    perform app.notify(new.owner_id, 'challenge', 'Please confirm ' || what,
      'Our automatic checks (JEVs) ask you to confirm ' || what || ' by signing in again. Sign in, then do it once more: it goes ahead straight away.',
      '/join?return_to=' || case when new.action = 'account.delete' then '%2Faccount' else '%2Fagents' end,
      'challenge', new.id, 'jevs:challenge:' || new.id::text);
  end if;
  new.delivered_at := now();
  return new;
end
$$;
create trigger jevs_challenges_notify before insert on app.jevs_challenges for each row execute function app.jevs_challenges_notify();
alter table app.jevs_challenges enable always trigger jevs_challenges_notify;

create function app.jevs_decisions_alert() returns trigger
language plpgsql
as $$
begin
  if new.applied and new.effect in ('hold', 'hide', 'queue') then
    perform app.notify(null, 'alert',
      case when new.effect = 'hide' then 'JEVs hid a reported post'
           when new.effect = 'queue' then 'JEVs listed a high-risk account'
           when new.subject_kind = 'post' then 'JEVs held a post for you'
           else 'JEVs held a step for you' end,
      'Action: ' || new.action || '. Level: ' || new.level || case when new.error then ' (scoring failed)' else '' end
        || '. The scores are on ' || case when new.subject_kind = 'post' then 'the review queue.' else 'the owner controls.' end,
      case when new.subject_kind = 'post' then '/review' else '/controls' end,
      case when new.member_id is not null then 'member' else new.subject_kind end, coalesce(new.member_id, new.subject_id),
      'jevs:alert:' || new.id::text);
  end if;
  return null;
end
$$;
create trigger jevs_decisions_alert after insert on app.jevs_decisions for each row execute function app.jevs_decisions_alert();
alter table app.jevs_decisions enable always trigger jevs_decisions_alert;

create function app.deletion_reviews_notify() returns trigger
language plpgsql
as $$
begin
  perform app.notify(new.member_id, 'account_flagged', 'Your account was flagged as high risk',
    'Our automatic checks (JEVs) flagged your request to delete your account as high risk, so it hasn''t been deleted. Aaron will '
    || 'review it and decide. If he hasn''t decided within 24 hours, your account will be disabled: you''ll be signed out everywhere, you '
    || 'won''t be able to sign in, and your agents will be switched off. Nothing is deleted until he decides.',
    '/account', 'member', new.member_id, 'jevs:flagged:' || new.id::text);
  perform app.notify(null, 'alert', 'A deletion needs your decision',
    'JEVs scored a request to delete an account as high risk. Decide it under Deletion reviews: allow the deletion, keep the account '
    || 'disabled, or restore it. If you haven''t decided within 24 hours, the account is disabled, not deleted.',
    '/controls', 'member', new.member_id, 'jevs:review:' || new.id::text);
  return null;
end
$$;
create trigger deletion_reviews_notify after insert on app.deletion_reviews for each row execute function app.deletion_reviews_notify();
alter table app.deletion_reviews enable always trigger deletion_reviews_notify;
revoke execute on function app.jevs_challenges_notify(), app.jevs_decisions_alert(), app.deletion_reviews_notify() from public;

-- ---- Deleting an account (F8) also clears notices and containments ----
create policy notices_erase_select on app.notices for select to dog_erase using (true);
create policy notices_erase_delete on app.notices for delete to dog_erase using (true);
grant select (id, member_id, subject_kind, subject_id), delete on app.notices to dog_erase;
create policy containments_erase_select on app.containments for select to dog_erase using (true);
create policy containments_erase_delete on app.containments for delete to dog_erase using (true);
grant select (id, member_id), delete on app.containments to dog_erase;

-- Deleting an account (F8) also clears the member's notices (and Aaron's alerts about them) and containments. The deletion itself is app.erase_member (010), which a member's own deletion and Aaron's
-- decision on a deletion review both use; it runs with dog_erase's rights. Same as 010 otherwise.
create or replace function app.erase_member(p_member uuid)
returns table (posts integer, reports integer, agents integer, keys integer, sessions integer, identities integer)
language plpgsql
as $$
declare
  me uuid := p_member;
  n_posts integer; n_flags integer; n_my_reports integer; n_agents integer; n_keys integer; n_sessions integer; n_ids integer; n_brakes integer;
  n_drafts integer; n_jevs integer; n_reviews integer; n_notices integer;
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
  -- PR 13: the member's notices (and the alerts to Aaron about them) and containments.
  delete from app.notices x where x.member_id = me or (x.member_id is null and x.subject_kind = 'member' and x.subject_id = me);
  get diagnostics n_notices = row_count;
  delete from app.containments c where c.member_id = me;
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
            'jevs_decisions', n_jevs, 'deletion_reviews', n_reviews, 'notices', n_notices));
  return query select n_posts, n_my_reports, n_agents, n_keys, n_sessions, n_ids;
end
$$;

-- ---- Who may call what ----
revoke execute on function app.notices_fill(), app.notices_guard(), app.notify(uuid, text, text, text, text, text, uuid, text),
  app.containments_fill(), app.containments_guard(), app.containments_start(), app.containments_after(), app.agent_drafts_notify(),
  app.agent_rules_notify(), app.brakes_notify(), app.require_system(), app.drafts_expire_job(), app.act_reconfirm_job(),
  app.watch_job(), app.containment_lift_job(), app.run_timers() from public;
grant execute on function app.notify(uuid, text, text, text, text, text, uuid, text), app.require_system(), app.drafts_expire_job(),
  app.act_reconfirm_job(), app.watch_job(), app.containment_lift_job(), app.run_timers() to dog_app;
