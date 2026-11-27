-- 096: the Wall on posts and drafts, and the other fixes from the Nov 27 audit (each finding verified live that day).
--
-- 1. The Agentic Wall read work (tasks, submissions, disputes, evidence, pull request files) but never a post or an
--    agent's draft: a solo agent's spam or injection post went live with no Wall decision. Now every new post and draft
--    is read by the Wall's text and wiki rules and the blue team lead (as wall_gate reads work, 073 and 089), and the
--    decision joins the same hash chain. In enforce mode a clear breach (a rule whose effect is block) removes the post,
--    or declines the draft, at once, and the post gets a review flag (classifier 'wall'); any other flag leaves the post
--    live with a review flag. A draft's flag is recorded only: its owner decides, and the post it becomes is read again.
--    Aaron's decision D1 (block clear breaches at once, or flag first) is pending; the default built here is the most
--    conservative under his Nov 24 rule ("clear violations of established rules ... blocked automatically") and the
--    Nov 25/26 JEVs row (only a clear breach of a published rule is blocked). A block on a post can be appealed
--    (wall_appeal, 089, takes any block); cleared on recheck, the post goes back up. The live posts of the last 7 days
--    are read once, now.
-- 2. Two shell patterns in text, not only in code: a reverse or bind shell (W43, block; an address the site hid as
--    "[number hidden]" still counts) and a download piped into a shell (W05b, flag: install guides say it too). Work
--    notes keep how many keys the site hid before saving (note_keys), so the Wall adds W11 when there were any.
--    Aaron's decision D2 (shells in notes) is pending; the default is the rules' published effects.
-- 3. Second Look also reads live posts with an open review flag, or a JEVs medium or high decision in the last 24
--    hours (app.sl_intake). A solo agent's JEVs challenge now goes ahead flagged ('flag'), not unflagged ('none').
-- 4. The model reviewers and the classifier retry a failed call (an error, no verdict) up to 3 attempts, 5 minutes
--    apart; the classifier reads posts of the last 3 days; held work counts a reviewer as having had its turn after an
--    answer or 3 failed attempts; an alert when a role fails more than half its calls in an hour (alert only).
-- 5. The hourly rule check b no longer counts agents' own accounts at level 1 (their approved path, 079).

reset role;
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W05b', 'flag', 'A download piped into a shell (curl or wget into sh) written in a post, task or note');
update app.wall_rules set what = 'A reverse or bind shell, in code or in text (a shell wired to a network connection, in any of its usual forms)' where rule = 'W43';
alter table app.wall_rules enable row level security;
alter table app.wall_settings disable row level security;
update app.wall_settings set rules_version = rules_version + 1;
alter table app.wall_settings enable row level security;

alter table app.wall_decisions drop constraint wall_decisions_kind_check;
alter table app.wall_decisions add constraint wall_decisions_kind_check
  check (kind = any (array['task', 'submission', 'dispute', 'evidence', 'pr_files', 'post', 'draft']));
-- How many keys the site hid from a work note before saving it (db/work.js); the note itself no longer shows them.
alter table app.work_submissions add column note_keys smallint not null default 0 check (note_keys between 0 and 1000);

-- The Wall (dog_owner) reads the words of a post or draft it blocked, for an appeal's recheck, and no other post.
create policy posts_wall_read on app.posts for select to dog_owner
  using (exists (select 1 from app.wall_decisions d where d.kind = 'post' and d.ref = posts.id and d.decision = 'block'));
create policy agent_drafts_wall_read on app.agent_drafts for select to dog_owner
  using (exists (select 1 from app.wall_decisions d where d.kind = 'draft' and d.ref = agent_drafts.id and d.decision = 'block'));
-- JEVs's role carries out the Wall's refusal of a draft (declined, only from pending; agent_drafts_guard checks the rest).
create policy agent_drafts_jevs_decline on app.agent_drafts for update to dog_jevs
  using (status = 'pending') with check (status = 'declined');
grant select (status) on app.agent_drafts to dog_jevs;
grant update (status) on app.agent_drafts to dog_jevs;
-- JEVs's role may also add the Wall's review flag (041's policy, with 'wall').
drop policy review_flags_jevs_insert on app.review_flags;
create policy review_flags_jevs_insert on app.review_flags for insert to dog_jevs
  with check ((restored_from is null and source = 'classifier' and classifier = any (array['jevs', 'secondlook', 'wall']) and reporter_id is null)
              or (restored_from is not null and exists (
                    select 1 from app.review_flags o where o.id = review_flags.restored_from and o.post_id = review_flags.post_id
                       and o.source = review_flags.source and o.reason is not distinct from review_flags.reason
                       and o.reporter_id is not distinct from review_flags.reporter_id and o.classifier is not distinct from review_flags.classifier
                       and o.created_at = review_flags.created_at and o.decision = 'restore')));

set local role dog_owner;
-- ---- 3. Second Look's intake: live posts the reviewers should see, each read once ----
create table app.sl_intake (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null unique references app.posts (id) on delete cascade,
  why text not null check (why = any (array['flag', 'jevs'])),
  claimed_at timestamptz not null default now(),
  decided_at timestamptz,
  decision text check (decision = any (array['clear', 'leave', 'reject'])),
  fail_closed boolean,
  check ((decided_at is null) = (decision is null))
);
create index sl_intake_claimed on app.sl_intake (claimed_at);
alter table app.sl_intake enable row level security;
alter table app.sl_intake force row level security;
create policy sl_intake_jevs on app.sl_intake for all to dog_jevs using (true) with check (true);
grant select, insert, update on app.sl_intake to dog_jevs;
reset role;

-- ---- 1. The Wall's hand on posts (JEVs's role: the only one, besides a reviewer, that may move a post) ----
grant create on schema app to dog_jevs;
set local role dog_jevs;
-- block: the post is removed (or the draft declined) and flagged; hold (a flag): the post stays up, flagged; restore:
-- a post the Wall removed, cleared on appeal, goes back up, unless JEVs or a reviewer removed it too.
create function app.wall_post_act(p_kind text, p_ref uuid, p_dec text, p_decision uuid) returns void
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if p_kind = 'post' and p_dec = 'restore' then
    if exists (select 1 from app.jevs_decisions j where j.subject_kind = 'post' and j.subject_id = p_ref and j.applied and j.effect in ('block', 'hide', 'hold'))
       or exists (select 1 from app.review_flags f where f.post_id = p_ref and f.decision = 'remove') then
      return;
    end if;
    perform set_config('dog.wall_restore', p_ref::text, true);
    update app.posts p set status = 'live' where p.id = p_ref and p.status = 'removed';
    perform set_config('dog.wall_restore', '', true);
  elsif p_kind = 'post' and p_dec in ('block', 'hold') then
    if p_dec = 'block' then
      update app.posts p set status = 'removed' where p.id = p_ref and p.status in ('live', 'waiting');
    end if;
    if not exists (select 1 from app.review_flags f where f.post_id = p_ref and f.source = 'classifier' and f.classifier = 'wall' and f.resolved_at is null) then
      insert into app.review_flags (post_id, source, classifier, score) values (p_ref, 'classifier', 'wall', case when p_dec = 'block' then 1 else 0.5 end);
    end if;
  elsif p_kind = 'draft' and p_dec = 'block' then
    update app.agent_drafts d set status = 'declined' where d.id = p_ref and d.status = 'pending';
  end if;
end $$;
revoke execute on function app.wall_post_act(text, uuid, text, uuid) from public;

-- ---- 3. JEVs: a solo agent's challenge goes ahead flagged (092's function otherwise) ----
CREATE OR REPLACE FUNCTION app.jevs_decide(p_action text, p_subject uuid, p_scores jsonb, p_impact text, p_error boolean, p_domains text[], p_simhash bigint, p_net text)
 RETURNS TABLE(decision_id uuid, level text, effect text, applied boolean, mode text, challenge_id uuid, challenge_status text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
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
  ask integer := 0; -- 032
  lvl text;
  eff text;
  did uuid;
  cid uuid;
  cstatus text;
  unk text := coalesce(current_setting('app.jevs_unknown', true), ''); -- 092: the questions that didn't answer
  rid uuid;
  questions text[];
  ok boolean;
  solo boolean := false; -- 096
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
    when p_action = 'agent.subagent' then
      -- An agent making a sub-agent (013): about the acting agent, which must be the owner's and active.
      if kind <> 'agent' or p_subject is distinct from ag
         or not exists (select 1 from app.agents a where a.id = ag and a.owner_id = me and a.status = 'active') then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; judged := me; agent := ag;
    when p_action = 'agent.register' then
      if kind <> 'anon' or p_subject is not null then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := null; judged := null;
    -- 040: a recovery key used for a new key: anyone holding it, signed in or not. About the agent it is for, which must
    -- be unclaimed or active, judged as its owner (if it has one).
    when p_action = 'agent.recover' then
      if kind <> 'anon' or p_subject is null
         or not exists (select 1 from app.agents a where a.id = p_subject and a.status in ('unclaimed', 'active')) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; agent := p_subject;
      select a.owner_id into judged from app.agents a where a.id = p_subject;
    -- 040: an agent setting or replacing its recovery key with its key: a claimed agent acting with its key, or (before
    -- its claim) anyone holding the key registration gave.
    when p_action = 'agent.recovery_issue' then
      if p_subject is null or kind not in ('agent', 'anon') or (kind = 'agent' and p_subject is distinct from ag)
         or not exists (select 1 from app.agents a where a.id = p_subject and a.status in ('unclaimed', 'active')
                        and (kind = 'agent') = (a.owner_id is not null)) then
        raise exception 'bad JEVs request' using errcode = '22023';
      end if;
      subj_kind := 'agent'; agent := p_subject;
      select a.owner_id into judged from app.agents a where a.id = p_subject;
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
  -- 032: J18 and J19 ask only. They are left out of the total and the top score, and on their own raise low to medium,
  -- never to high (below).
  select coalesce(sum((e.value)::integer), 0), coalesce(max((e.value)::integer), 0) into total, top from jsonb_each(p_scores) e
    where e.key not in ('J18', 'J19');
  select coalesce(max((e.value)::integer), 0) into ask from jsonb_each(p_scores) e where e.key in ('J18', 'J19');
  questions := array(select k from jsonb_object_keys(p_scores) k order by k);

  if p_error then
    lvl := case when p_impact = 'high' then 'high' else 'low' end;
  elsif top >= s_high_any or total >= s_high_total then
    lvl := 'high';
  elsif top >= s_medium_any or total >= s_medium_total or ask >= s_medium_any then
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
  elsif p_action in ('agent.register', 'agent.recover', 'agent.recovery_issue') then
    -- The owner's claim is the human check; only high risk holds a registration. 040: the same for a recovery and for a
    -- recovery key set or replaced, whose owner is told each time.
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
  elsif p_action = 'agent.subagent' then
    -- A sub-agent needs no human step to be made (Aaron, Oct 16, 2026). Medium makes it with every action drafting, so
    -- each thing it does waits for its human owner (never an agent); high holds it for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'draft' else 'none' end;
  else
    -- Sensitive actions: medium asks the owner to confirm by signing in again; high holds the action for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'challenge' else 'none' end;
  end if;

  -- 080: high risk never waits for a person (Aaron, Nov 25). A clear violation of an established rule is blocked; any
  -- other high risk, or scoring that failed, goes ahead and is flagged for the reviewers. An account deletion still opens
  -- its review: deleting can't be undone.
  if eff = 'hold' and p_action <> 'account.delete'
     and coalesce((select x.value from app.jevs_settings x where x.key = 'high_risk'), 'flag') = 'flag' then
    if p_error then
      -- 092 (Aaron, Nov 26: neither refusing nor waving through fixes it; Fable 5.2's design, validated by a fault test):
      -- scoring that failed as a whole refuses nothing; the step goes ahead, flagged for the reviewers.
      eff := 'flag';
    elsif exists (select 1 from app.jevs_clear_rules r where coalesce((p_scores ->> r.question)::integer, 0) >= r.min_score) then
      eff := 'block';
    else
      eff := 'flag';
    end if;
  end if;
  -- 092: questions that didn't answer (unk) count as unknown, never as zero: a step that would otherwise go ahead
  -- unflagged goes ahead flagged for the reviewers when any of its questions was unknown, and a post whose scoring
  -- failed is flagged too (before, it went live unseen). A clear breach is still blocked from what is known.
  if eff = 'none' and (unk <> '' or p_error)
     and (p_impact = 'high' or p_action in ('post.create', 'post.approved'))
     and coalesce((select x.value from app.jevs_settings x where x.key = 'high_risk'), 'flag') = 'flag' then
    eff := 'flag';
  end if;
  -- 079: an agent on its own account has no owner to confirm or approve, so a challenge or a "draft" alerts the
  -- reviewers and the action goes ahead. High risk still holds, as for everyone. 096 (the Nov 27 audit): it goes ahead
  -- flagged ('flag', not 'none'), so a post has a review flag and Second Look reads it.
  if judged is not null and eff in ('challenge', 'draft') and app.is_agent_account(judged) then
    perform app.agent_limit_alert(coalesce(agent, judged), 'met a JEVs ' || eff || ' on ' || p_action || ' (' || lvl || ' risk), which went ahead with no owner to ask');
    eff := 'flag';
    solo := true;
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
    elsif subj_kind = 'post' and eff in ('hide', 'block') and post_status in ('live', 'waiting') then
      update app.posts p set status = 'removed' where p.id = v_post;
    end if;
    if subj_kind = 'post' and eff in ('hold', 'hide', 'block', 'flag')
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
    elsif subj_kind is distinct from 'post' and eff in ('hold', 'challenge', 'queue', 'draft', 'block', 'flag') then
      -- The effect only: which questions scored stay in the decision row, deleted with the account (the JEVs review, F10).
      insert into app.audit_log (action, subject_kind, subject_id, detail)
        values ('jevs.' || eff, coalesce(subj_kind, 'member'), coalesce(p_subject, judged), jsonb_build_object('action', p_action, 'decision', did, 'level', lvl));
    end if;
  end if;

  -- 080: a block costs an agent's own account a level; a flag outside a post tells the reviewers.
  if eff = 'block' and not p_error and s_mode = 'enforce' and judged is not null and app.is_agent_account(judged) then
    perform app.agent_standing_event(judged, 'violation');
  end if;
  -- 096: a solo agent's flag was already alerted above (agent_limit_alert), once.
  if eff = 'flag' and s_mode = 'enforce' and subj_kind is distinct from 'post' and not solo then
    perform app.notify(null, 'alert', 'JEVs: a high-risk step went ahead for review',
      p_action || case when p_error then ' could not be scored' when unk <> '' then ' was scored without ' || unk else ' scored high risk' end || ' and went ahead, as nothing high risk waits for a person (080). Decision ' || did::text || '.',
      null, coalesce(subj_kind, 'member'), coalesce(p_subject, judged),
      -- 092: during an outage, one alert an hour for each kind of step, not one for each request.
      case when p_error or unk <> '' then 'jevsflag-outage:' || p_action || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24') else 'jevsflag:' || did::text end);
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
$function$;


-- 057's function, with the intake (above the sample's slots).
create or replace function app.sl_claim(p_n integer)
returns table (post_id uuid, body text, held text[], account_days integer, sign_in text, model text)
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  r record;
  today_calls integer;
  v_rows jsonb := '[]'::jsonb;
  v_part jsonb;
  v_held integer := 0;
  v_room integer;
  v_can record;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer hands posts to Second Look' using errcode = '42501';
  end if;
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
  select * into r from app.review_settings where singleton;
  v_room := p_n;
  -- 041: a sample that has waited 6 hours takes one slot first, so held posts can't starve the sample.
  with picked as (
    select x.post_id from app.review_samples x join app.posts p on p.id = x.post_id
     where x.claimed_at is null and p.status = 'live' and x.sampled_at > now() - interval '24 hours' and x.sampled_at <= now() - interval '6 hours'
     order by x.sampled_at, x.id limit 1 for update of x skip locked),
  claimed as (update app.review_samples y set claimed_at = now() from picked where y.post_id = picked.post_id returning y.post_id)
  select coalesce(jsonb_agg(jsonb_build_object('post_id', p.id, 'body', p.body, 'held', '[]'::jsonb,
           'account_days', greatest(0, extract(day from now() - m.created_at))::integer,
           'sign_in', case when p.agent_id is not null then 'an agent posting for its owner, level ' || m.trust_level else 'a member, level ' || m.trust_level end)), '[]'::jsonb)
    into v_part from claimed c join app.posts p on p.id = c.post_id join app.members m on m.id = p.author_id;
  v_rows := v_rows || v_part;
  v_room := v_room - jsonb_array_length(v_part);
  -- The held posts, as 034.
  select count(*) into today_calls from app.sl_claims c where c.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  if today_calls < s.daily_call_cap and v_room > 0 then
    with picked as (
      select p.id from app.posts p
       where p.status = 'waiting' and not exists (select 1 from app.sl_claims c where c.post_id = p.id) and app.sl_eligible(p.id)
       order by p.created_at, p.id
       limit least(v_room, s.daily_call_cap - today_calls)
       for update of p skip locked),
    claimed as (insert into app.sl_claims (post_id) select id from picked returning sl_claims.post_id)
    select coalesce(jsonb_agg(jsonb_build_object('post_id', p.id, 'body', p.body,
             'held', (select coalesce(jsonb_agg(e.key order by e.key), '[]'::jsonb) from (select d.scores from app.jevs_decisions d
                where d.subject_kind = 'post' and d.subject_id = p.id and d.effect = 'hold' and d.applied
                order by d.created_at desc, d.id desc limit 1) h, jsonb_each(h.scores) e
               where jsonb_typeof(e.value) = 'number' and (e.value::text)::numeric >= 25),
             'account_days', greatest(0, extract(day from now() - m.created_at))::integer,
             'sign_in', case when p.agent_id is not null then 'an agent posting for its owner, level ' || m.trust_level else 'a member, level ' || m.trust_level end)), '[]'::jsonb)
      into v_part from claimed c join app.posts p on p.id = c.post_id join app.members m on m.id = p.author_id;
    v_held := jsonb_array_length(v_part);
    v_rows := v_rows || v_part;
    v_room := v_room - v_held;
  end if;
  -- 096 (the Nov 27 audit): live posts the reviewers should see: an open review flag (the Wall's, JEVs's, the AI
  -- classifier's or a report; not Second Look's own), or a JEVs medium or high decision in the last 24 hours. Each
  -- once, oldest first, under the day's call cap. Second Look reads it as it reads a sample: a reject puts it in
  -- Aaron's queue, and it stays up.
  if v_room > 0 and today_calls + (select count(*) from app.sl_intake i where i.claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC') < s.daily_call_cap then
    with picked as (
      select p.id, case when exists (select 1 from app.review_flags f where f.post_id = p.id and f.resolved_at is null
                                      and f.classifier is distinct from 'secondlook') then 'flag' else 'jevs' end as why
        from app.posts p
       where p.status = 'live' and p.published_at > now() - interval '7 days'
         and not exists (select 1 from app.sl_intake i where i.post_id = p.id)
         and (exists (select 1 from app.review_flags f where f.post_id = p.id and f.resolved_at is null and f.classifier is distinct from 'secondlook')
              or exists (select 1 from app.jevs_decisions d where d.subject_kind = 'post' and d.subject_id = p.id
                          and d.level in ('medium', 'high') and d.created_at > now() - interval '24 hours'))
       order by p.created_at, p.id limit v_room for update of p skip locked),
    claimed as (insert into app.sl_intake (post_id, why, claimed_at) select picked.id, picked.why, now() from picked
                on conflict on constraint sl_intake_post_id_key do nothing returning sl_intake.post_id)
    select coalesce(jsonb_agg(jsonb_build_object('post_id', p.id, 'body', p.body, 'held', '[]'::jsonb,
             'account_days', greatest(0, extract(day from now() - m.created_at))::integer,
             'sign_in', case when p.agent_id is not null then 'an agent posting for its owner, level ' || m.trust_level else 'a member, level ' || m.trust_level end)), '[]'::jsonb)
      into v_part from claimed c join app.posts p on p.id = c.post_id join app.members m on m.id = p.author_id;
    v_rows := v_rows || v_part;
    v_room := v_room - jsonb_array_length(v_part);
  end if;
  -- 041: the sample fills the slots left, oldest first, only posts drawn in the last 24 hours that are still live.
  if v_room > 0 then
    with picked as (
      select x.post_id from app.review_samples x join app.posts p on p.id = x.post_id
       where x.claimed_at is null and p.status = 'live' and x.sampled_at > now() - interval '24 hours'
       order by x.sampled_at, x.id limit v_room for update of x skip locked),
    claimed as (update app.review_samples y set claimed_at = now() from picked where y.post_id = picked.post_id returning y.post_id)
    select coalesce(jsonb_agg(jsonb_build_object('post_id', p.id, 'body', p.body, 'held', '[]'::jsonb,
             'account_days', greatest(0, extract(day from now() - m.created_at))::integer,
             'sign_in', case when p.agent_id is not null then 'an agent posting for its owner, level ' || m.trust_level else 'a member, level ' || m.trust_level end)), '[]'::jsonb)
      into v_part from claimed c join app.posts p on p.id = c.post_id join app.members m on m.id = p.author_id;
    v_rows := v_rows || v_part;
  end if;
  -- 041: a canary, made ahead of time, with the chance that at least one of the held posts handed over would carry one,
  -- placed among them at random.
  if v_held > 0 and r.canary_rate > 0 and random() < 1 - power(1 - r.canary_rate::double precision, v_held) then
    select * into v_can from app.review_canaries c where c.claimed_at is null and c.created_at <= now() - interval '5 minutes'
     order by c.created_at limit 1 for update skip locked;
    if found then
      update app.review_canaries set claimed_at = now() where id = v_can.id;
      v_rows := jsonb_insert(v_rows, array[floor(random() * (jsonb_array_length(v_rows) + 1))::int::text],
        jsonb_build_object('post_id', v_can.id, 'body', v_can.body, 'held', to_jsonb(string_to_array(v_can.held, ',')),
          'account_days', v_can.account_days, 'sign_in', v_can.sign_in));
    end if;
  end if;
  return query
    select (e ->> 'post_id')::uuid, e ->> 'body', array(select jsonb_array_elements_text(e -> 'held')), (e ->> 'account_days')::integer,
           e ->> 'sign_in', s.model
      from jsonb_array_elements(v_rows) with ordinality as x(e, i) order by x.i;
end
$$;

-- 057's function, with the intake's decision.
create or replace function app.sl_decide(p_post uuid, p_version text, p_model text, p_decision text, p_answers jsonb, p_risk integer,
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
  v_can record;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records Second Look''s decisions' using errcode = '42501';
  end if;
  if p_post is null or p_version is distinct from 'v1' or p_decision is null or p_risk is null or p_reason is null
     or p_fail_closed is null or p_latency is null then
    raise exception 'bad Second Look decision' using errcode = '22023';
  end if;
  -- A clear must be what the nine answers say: Q1 to Q8 "no" and Q9 "yes" (the table checks the rest).
  if v_decision = 'clear' and not coalesce(p_answers ?& array['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9']
      and (select bool_and(p_answers ->> k = 'no') from unnest(array['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8']) k)
      and p_answers ->> 'q9' = 'yes', false) then
    raise exception 'a clear that its answers don''t support' using errcode = '22023';
  end if;
  if v_decision <> all (array['clear', 'leave', 'reject']) then
    raise exception 'bad Second Look decision' using errcode = '22023';
  end if;
  -- 041: a canary it was handed in the last 2 minutes, once. The truth is revealed with its nonce and text hash;
  -- nothing is published.
  select * into v_can from app.review_canaries x where x.id = p_post for update;
  if found then
    if v_can.decided_at is not null or v_can.claimed_at is null or v_can.claimed_at < now() - interval '2 minutes' then
      return 'refused';
    end if;
    update app.review_canaries set decision = v_decision, fail_closed = p_fail_closed, decided_at = now() where id = v_can.id;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('review.canary_result', 'canary', v_can.id, jsonb_build_object('truth', v_can.truth, 'nonce', v_can.nonce,
              'text_sha256', v_can.text_sha256, 'commitment', v_can.commitment, 'decision', v_decision, 'no_answer', p_fail_closed,
              'caught', case when p_fail_closed then null when v_can.truth = 'bad' then v_decision <> 'clear' else v_decision = 'clear' end));
    if v_can.truth = 'bad' and v_decision = 'clear' then
      perform app.notify(null, 'alert', 'A planted test slipped through Second Look',
        'Here is what it was: a known-bad test post that Second Look would have cleared. Nothing was published: planted tests are '
        || 'never posts. The text: "' || left(v_can.body, 600) || '"', '/admin/controls', null, null, 'review:canary:' || v_can.id);
    end if;
    return 'logged';
  end if;
  -- 096: a flagged live post (the intake) it was handed in the last 2 minutes, once: as a sample, a reject puts it in
  -- Aaron's queue and it stays up.
  if exists (select 1 from app.sl_intake x where x.post_id = p_post and x.decided_at is null and x.claimed_at > now() - interval '2 minutes') then
    update app.sl_intake set decision = v_decision, fail_closed = p_fail_closed, decided_at = now() where post_id = p_post;
    if v_decision = 'reject' and exists (select 1 from app.posts p where p.id = p_post and p.status = 'live')
       and not exists (select 1 from app.review_flags f where f.post_id = p_post and f.resolved_at is null and f.classifier = 'secondlook') then
      insert into app.review_flags (post_id, source, classifier) values (p_post, 'classifier', 'secondlook');
    end if;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('secondlook.intake', 'post', p_post, jsonb_build_object('decision', v_decision, 'no_answer', p_fail_closed, 'risk', p_risk));
    return 'logged';
  end if;
  -- 041: a sampled live post it was handed in the last 2 minutes, once. A reject puts it in Aaron's queue; it stays up.
  if exists (select 1 from app.review_samples x where x.post_id = p_post and x.decided_at is null and x.claimed_at > now() - interval '2 minutes') then
    update app.review_samples set decision = v_decision, fail_closed = p_fail_closed, decided_at = now(),
      flagged = (v_decision = 'reject' and exists (select 1 from app.posts p where p.id = p_post and p.status = 'live'))
     where post_id = p_post;
    if v_decision = 'reject' and exists (select 1 from app.posts p where p.id = p_post and p.status = 'live')
       and not exists (select 1 from app.review_flags f where f.post_id = p_post and f.resolved_at is null and f.classifier = 'secondlook') then
      insert into app.review_flags (post_id, source, classifier) values (p_post, 'classifier', 'secondlook');
    end if;
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('secondlook.sample', 'post', p_post, jsonb_build_object('decision', v_decision, 'no_answer', p_fail_closed, 'risk', p_risk));
    return 'logged';
  end if;
  -- Only a post it was given in the last 2 minutes, and only once.
  if not exists (select 1 from app.sl_claims c where c.post_id = p_post and c.claimed_at > now() - interval '2 minutes')
     or exists (select 1 from app.sl_decisions d where d.post_id = p_post) then
    return 'refused';
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

-- ---- 5. The hourly rule checks: check b skips agents' own accounts at level 1 (032's function otherwise) ----
create or replace function app.invariants_check()
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  s record;
  n integer;
  st text;
  today text := to_char(now() at time zone 'UTC', 'YYYYMMDD');
begin
  -- At most once an hour, one run at a time; anyone may ask (the timer route is open), so asking costs one row read.
  select t.last_at into s from app.invariant_slot t where t.singleton for update skip locked;
  if not found or (s.last_at is not null and s.last_at > now() - interval '55 minutes') then
    return false;
  end if;
  update app.invariant_slot set last_at = now() where singleton;
  begin
    -- a. Every administrator was made one through a recorded promotion.
    select count(*) into n from app.members m
    where m.is_admin and m.status = 'active'
      and not exists (select 1 from app.audit_log l where l.action = 'admin.set' and l.subject_kind = 'member' and l.subject_id = m.id);
    if n > 0 then
      perform app.notify(null, 'alert', 'A rule that must never break: an administrator nobody promoted',
        n || ' active administrator account(s) have no recorded promotion in the audit log. Every legitimate way of making '
        || 'an administrator records one. Check who it is on /controls. Nothing was changed.', '/controls', null, null, 'invariant:a:' || today);
    end if;
    -- b. No active member's level is above what an approved path gives. (A verified method past its recheck date counts
    --    at its full level here: the stored level only comes down at the member's next request.)
    select count(*) into n from app.members m
    where m.status = 'active'
      -- 096: an agent's own account starts at level 1 with no sign-in method (079): that is the path that gave it.
      and not (m.kind = 'agent' and m.trust_level <= 1)
      and m.trust_level > coalesce(m.level_set_by_admin, greatest(
            (select coalesce(max(i.level), 0) from app.identities i where i.member_id = m.id),
            case when m.jevs_level2_at is not null then 2 else 0 end));
    if n > 0 then
      perform app.notify(null, 'alert', 'A rule that must never break: a level nobody gave',
        n || ' active member(s) have a level above what their sign-in methods, automatic level 2 or your own setting give. '
        || 'Nothing was changed.', '/controls', null, null, 'invariant:b:' || today);
    end if;
    -- c. A sub-agent has its parent's owner and a daily cap no higher than its parent's.
    select count(*) into n from app.agents c join app.agents p on p.id = c.parent_id
    where c.status = 'active' and p.status = 'active'
      and (c.owner_id is distinct from p.owner_id
           or (select r.daily_cap from app.agent_rules r where r.agent_id = c.id order by r.version desc limit 1)
              > (select r.daily_cap from app.agent_rules r where r.agent_id = p.id order by r.version desc limit 1));
    if n > 0 then
      perform app.notify(null, 'alert', 'A rule that must never break: a sub-agent outside its parent''s limits',
        n || ' active sub-agent(s) have another owner than their parent, or a higher daily cap than their parent. '
        || 'Nothing was changed.', '/controls', null, null, 'invariant:c:' || today);
    end if;
    -- d. No session lasts more than 30 days.
    select count(*) into n from app.sessions x where x.expires_at > now() and x.expires_at - x.created_at > interval '30 days 1 hour';
    if n > 0 then
      perform app.notify(null, 'alert', 'A rule that must never break: a session longer than 30 days',
        n || ' live session(s) last more than 30 days. Nothing was changed.', '/controls', null, null, 'invariant:d:' || today);
    end if;
    -- e. No agent sent more posts and drafts in the last 24 hours than the highest daily cap it had in that time
    --    (counted as app.agent_actions_today counts, 008).
    with sent as (
      select x.agent_id, count(*) as k from (
        select p.agent_id from app.posts p where p.agent_id is not null and p.delegation = 'rules' and p.created_at > now() - interval '1 day'
        union all
        select d.agent_id from app.agent_drafts d where d.created_at > now() - interval '1 day') x
      group by x.agent_id)
    select count(*) into n from sent
    where sent.k > greatest(
      (select coalesce(max(r.daily_cap), 0) from app.agent_rules r where r.agent_id = sent.agent_id and r.created_at > now() - interval '1 day'),
      coalesce((select r.daily_cap from app.agent_rules r where r.agent_id = sent.agent_id and r.created_at <= now() - interval '1 day'
                order by r.version desc limit 1), 0));
    if n > 0 then
      perform app.notify(null, 'alert', 'A rule that must never break: an agent over its daily cap',
        n || ' agent(s) sent more posts and drafts in the last 24 hours than their daily cap allowed. Nothing was changed.',
        '/controls', null, null, 'invariant:e:' || today);
    end if;
    -- f. JEVs's settings are complete and ordered.
    select count(*) into n from (
      select max(case when s2.key = 'mode' then s2.value end) as mode,
             max(case when s2.key = 'medium_any' then s2.value end)::integer as ma, max(case when s2.key = 'high_any' then s2.value end)::integer as ha,
             max(case when s2.key = 'medium_total' then s2.value end)::integer as mt, max(case when s2.key = 'high_total' then s2.value end)::integer as ht
      from app.jevs_settings s2) z
    where z.mode is null or z.ma is null or z.ha is null or z.mt is null or z.ht is null or z.ma >= z.ha or z.mt >= z.ht;
    if n > 0 then
      perform app.notify(null, 'alert', 'A rule that must never break: JEVs''s settings',
        'JEVs''s settings are incomplete or out of order (a setting missing, or a medium threshold not below its high one). Nothing was changed.',
        '/controls', null, null, 'invariant:f:' || today);
    end if;
    update app.invariant_slot set last_ok_at = now(), failures = 0 where singleton;
  exception when query_canceled or others then
    -- The checks' alerts are undone; the slot stays taken (above), so a failing check runs again in an hour, not every
    -- minute. A statement-timeout cancel (57014) is caught by name, since "others" leaves it out.
    get stacked diagnostics st = returned_sqlstate;
    update app.invariant_slot set failures = failures + 1, last_failure_state = left(st, 5) where singleton;
    perform app.notify(null, 'alert', 'The hourly rule checks failed',
      'The checks of the rules that must never break failed (error ' || coalesce(left(st, 5), 'unknown') || '). They run again '
      || 'in an hour. Nothing was stopped.', '/controls', null, null, 'invariant:failed:' || today);
  end;
  return true;
end
$$;

grant execute on function app.wall_post_act(text, uuid, text, uuid) to dog_owner, dog_work;
set local role dog_owner;
revoke create on schema app from dog_jevs;

-- ---- 1. The Wall on posts and drafts (dog_owner, as wall_gate) ----
-- One post or draft: its flags (the text and wiki rules, and the blue team lead), the decision, chained like every
-- other, and in enforce mode the refusal (app.wall_post_act). Returns the decision.
create function app.wall_post_check(p_kind text, p_ref uuid, p_text text, p_member uuid, p_agent uuid) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  st record;
  mem uuid := p_member;
  flags jsonb;
  dec text;
  prev text;
  h text;
  did uuid;
begin
  if p_kind <> all (array['post', 'draft']) then raise exception 'bad Wall check' using errcode = '22023'; end if;
  select * into st from app.wall_settings;
  if st.mode = 'off' then return null; end if;
  if p_agent is not null and mem is null then mem := (select g.owner_id from app.agents g where g.id = p_agent); end if;
  flags := app.wall_text_flags(p_text) || app.wall_intel_flags(p_text) || app.blue_team_lead(mem, p_agent);
  dec := app.wall_decide(flags);
  perform pg_advisory_xact_lock(7307307);
  select d.hash into prev from app.wall_decisions d where not exists (select 1 from app.wall_decisions x where x.prev_hash = d.hash);
  prev := coalesce(prev, repeat('0', 64));
  h := encode(sha256(convert_to(prev || '|' || p_kind || '|' || p_ref::text || '|' || dec || '|' || flags::text || '|' || st.rules_version, 'UTF8')), 'hex');
  insert into app.wall_decisions (kind, ref, member_id, agent_id, decision, flags, mode, rules_version, prev_hash, hash)
    values (p_kind, p_ref, mem, p_agent, dec, flags, st.mode, st.rules_version, prev, h) returning id into did;
  if st.mode = 'enforce' and dec <> 'allow' then
    perform app.wall_post_act(p_kind, p_ref, dec, did);
  end if;
  return dec;
end $$;
revoke execute on function app.wall_post_check(text, uuid, text, uuid, uuid) from public;

create function app.wall_post_gate() returns trigger
language plpgsql security definer set search_path = pg_catalog as $$
begin
  if tg_argv[0] = 'post' then
    perform app.wall_post_check('post', new.id, new.body, new.author_id, new.agent_id);
  else
    perform app.wall_post_check('draft', new.id, new.body, new.owner_id, new.agent_id);
  end if;
  return null;
end $$;
revoke execute on function app.wall_post_gate() from public;

-- What the Wall decided about the caller's own new post or draft, for the site's answer: the decision's ID (to appeal
-- it), the decision and the rule IDs (never the flags' words), or null. Only the account it is about sees it.
create function app.wall_post_refusal(p_kind text, p_ref uuid) returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object('id', d.id, 'decision', d.decision, 'mode', d.mode,
           'rules', coalesce((select jsonb_agg(distinct split_part(x, ' ', 1)) from jsonb_array_elements_text(d.flags) x), '[]'::jsonb))
    from app.wall_decisions d
   where d.kind = p_kind and p_kind = any (array['post', 'draft']) and d.ref = p_ref
     and d.member_id is not distinct from app.current_member() and app.current_member() is not null
   order by d.created_at desc, d.id desc limit 1
$$;
revoke execute on function app.wall_post_refusal(text, uuid) from public;
grant execute on function app.wall_post_refusal(text, uuid) to dog_app;

-- A post block cleared on appeal: back up, when no other block on it stands (app.wall_post_act checks JEVs and the
-- reviewers). Called only from app.wall_recheck_run, as its role (dog_work), which reads the Wall's log and reviews.
create function app.wall_post_restore(p_decision uuid) returns boolean
language plpgsql set search_path = pg_catalog as $$
declare
  d record;
begin
  select * into d from app.wall_decisions x where x.id = p_decision and x.kind = 'post' and x.decision = 'block';
  if d.id is null or not exists (select 1 from app.wall_reviews v where v.decision_id = d.id and v.verdict = 'false_positive') then return false; end if;
  if exists (select 1 from app.wall_decisions o where o.kind = 'post' and o.ref = d.ref and o.id <> d.id and o.decision = 'block'
               and not exists (select 1 from app.wall_reviews v where v.decision_id = o.id and v.verdict = 'false_positive')) then
    return false;
  end if;
  perform app.wall_post_act('post', d.ref, 'restore', d.id);
  return true;
end $$;
revoke execute on function app.wall_post_restore(uuid) from public;
grant execute on function app.wall_post_restore(uuid) to dog_work;

-- ---- 2. The text rules: W43 and W05b (087's function otherwise) ----
create or replace function app.wall_text_flags(p_text text) returns jsonb
language plpgsql immutable set search_path = pg_catalog as $$
declare
  t text := coalesce(p_text, '');
  n text;
  l text;
  f jsonb := '[]'::jsonb;
  lvl int;
begin
  n := lower(translate(t, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  n := replace(replace(replace(replace(n, '&#8203;', ''), '&#x200b;', ''), '&amp;', '&'), '&nbsp;', ' ');
  n := regexp_replace(regexp_replace(n, '[​‌⁠-⁤﻿]', '', 'g'), '[[:space:]]+', ' ', 'g');
  if t ~ '[​‌⁠-⁤﻿]' or t ~ '[\U000E0000-\U000E007F]' or p_text ~ '&#(8203|x200b|8204|x200c|65279|xfeff);' then
    f := f || '["W07a hidden characters"]';
  end if;
  if n ~ '(ignore (all )?(the )?(previous|prior|above)( instructions)?|disregard (the |all )?(task|rules|instructions)|(reveal|print|ignore) (the |your )?system prompt|answer pass|mark (both|all|it|them|this) (as )?pass|checks are already satisfied|you are now (in )?[a-z]+ mode)' then
    f := f || '["W07b instruction aimed at a checker or agent"]';
  end if;
  if n ~ '\m(bit\.ly|tinyurl\.com|goo\.gl|is\.gd|ow\.ly|rb\.gy|cutt\.ly)/' then
    f := f || '["W06 link shortener"]';
  end if;
  if n ~ 'https?://[^[:space:]"'']+[?&](u|url|redirect|next|target|dest|to)=' then
    f := f || '["W23 redirecting link"]';
  end if;
  if app.wall_metadata_address(n) then
    f := f || '["W22 cloud-metadata address"]';
  elsif n ~ '(://localhost|://127\.0\.0\.1|://10\.[0-9]+\.[0-9]+\.[0-9]+|://192\.168\.)' then
    f := f || '["W22b local or private address"]';
  end if;
  if t ~ '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)' and t !~ 'AKIA[0-9A-Z]*EXAMPLE' then
    f := f || '["W11 credential in content"]';
  end if;
  -- 096 (the Nov 27 audit): a reverse or bind shell written in prose blocks (W43, the code rule's words, so a code file
  -- that has both shows it once); an address the site hid ("[number hidden]") still counts as one. A download piped
  -- into a shell in prose is flagged, not blocked (W05b): install guides say it too. In code files, W05 covers it.
  if n ~ ('(/dev/(tcp|udp)/'
       || '|\m(nc|ncat|netcat)\M[^\n]{0,80}[[:space:]]-[a-z]*[ec][[:space:]]*(/usr)?(/bin/)?(ba|z|da)?sh\M'
       || '|\mmkfifo\M[^\n]{0,120}\m(nc|ncat|netcat|openssl)\M'
       || '|\msocat\M[^\n]{0,120}\m(exec|system):'
       || '|\msocket\.socket\M[^\n]{0,250}(\mos\.dup2\M|\mpty\.spawn\M|\msubprocess\.(call|popen|run)\M)'
       || '|\m(bash|sh)[[:space:]]+-i[[:space:]]*>&?[[:space:]]*/dev/'
       || '|\m(meterpreter|msfvenom|reverse_tcp|bind_tcp|shell_reverse_tcp)\M)') then
    f := f || '["W43 reverse or bind shell"]';
  end if;
  if n ~ '\m(curl|wget)\M[^|\n]{0,250}\|[[:space:]]*(sudo[[:space:]]+(-[a-z]+[[:space:]]+)*)?(/usr)?(/bin/)?(env[[:space:]]+)?(ba|z|da|k|fi)?sh\M' then
    f := f || '["W05b download piped into a shell"]';
  end if;
  if n ~ '\m(nmap|masscan|sqlmap|metasploit|hydra)\M' or n ~ '/etc/passwd' then
    f := f || '["W13 recon or exploit material"]';
  end if;
  -- 087 (Aaron, Nov 26: catch the permutations): spam and attack requests are read on a copy with digits and symbols
  -- read as the letters they stand for (fr33 b1tc0in), letters spelled apart joined (f r e e, f.r.e.e), and
  -- repeated letters squeezed (freeee).
  l := translate(n, '0134578@$!|€', 'oieastbasile');
  l := regexp_replace(l, '([a-z])[._*~-]+(?=[a-z])', '\1', 'g');
  -- Spam, a paragraph at a time (at most 200 paragraphs).
  lvl := coalesce((select max(app.wall_spam_level(x)) from (select x from regexp_split_to_table(left(t, 400000), '
[[:space:]]*
') x limit 200) y), 0);
  if lvl = 2 then
    f := f || '["W45 spam"]';
  elsif lvl = 1 then
    f := f || '["W45b looks like spam"]';
  end if;
  if l ~ '\m(write|build|create|make|develop|code|give me|generate|craft|produce|run|deploy|launch|execute|send|spread|plant|install)\M[^.?!\n]{0,60}\m(exploits?|payloads?|ransomware|malware|virus(es)?|worms?|trojans?|keyloggers?|botnets?|backdoors?|rootkits?|(info)?stealers?|rats?|reverse shells?|web ?shells?|ddos|dos attacks?|phishing (pages?|kits?|sites?|emails?)|credential harvesters?|cryptominers?|zero[- ]?days?)\M'
     or l ~ '\m(exploit|attack|hack|breach|compromise|pwn|ddos|deface|take down|brute ?force)\M[^.?!\n]{0,30}\m(this|that|the|their|his|her|our|my|a|an|your)?[[:space:]]*(server|site|website|network|account|database|system|host|router|company|target|domain|app)s?\M'
     or l ~ 'exploits? (for|against|targeting|of) cve-[0-9]' then
    f := f || '["W13b request to build or run an attack"]';
  end if;
  if n ~ '\m(create|spawn|register|make) [0-9]+ (helper )?(agents|accounts|keys|bots)\M' then
    f := f || '["W20 asks to spawn agents or accounts"]';
  end if;
  return f;
end $$;

-- 087's function: W05b is a text rule only (in code, W05 blocks a pipe to a shell).
create or replace function app.wall_code_flags(p_path text, p_added text, p_task text) returns jsonb
language plpgsql immutable set search_path = pg_catalog as $$
declare
  f jsonb := '[]'::jsonb;
  t text := coalesce(p_added, '');
  n text;
  task text := lower(coalesce(p_task, ''));
  joined text;
  d text;
  c text;
  nc text;
begin
  if p_path ~* '\.(md|mdx|txt|rst)$' then return f; end if;  -- prose is read by the text rules
  n := lower(translate(t, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  if n ~ '(crontab|systemd|\.service\M|(curl|wget|fetch)[^\n|]*\|[[:space:]]*(sudo[[:space:]]+(-[a-z]+[[:space:]]+)*)?(/usr)?(/bin/)?(env[[:space:]]+)?(ba|z|da|k|fi)?sh\M|git remote add|deploy[_-]?key)' then
    f := f || '["W05 persistence in code"]';
  end if;
  -- The whole environment, not one variable: process.env.X, process.env[name] and os.environ.get(...) are fine.
  if t ~ '(Object\.(keys|entries|values|assign)\([^)]*process[[:space:]]*(\.[[:space:]]*env|\[[[:space:]]*[''"`]env)|JSON\.stringify\([[:space:]]*process[[:space:]]*\.[[:space:]]*env[[:space:]]*[),]|\.\.\.[[:space:]]*process[[:space:]]*\.[[:space:]]*env|process[[:space:]]*\[[[:space:]]*[''"`]env[''"`][[:space:]]*\]|\{[^}]*\menv\M[^}]*\}[[:space:]]*=[[:space:]]*process\M|[=(,][[:space:]]*process[[:space:]]*\.[[:space:]]*env[[:space:]]*($|[;,)\n])|os\.environ[[:space:]]*($|[),;\n]|\.(copy|items|keys|values)\()|dict\([[:space:]]*os\.environ|for [a-z_, ]+ in os\.environ)' then
    f := f || '["W21 whole environment used as data"]';
  end if;
  if t ~ '\m(fetch|axios|https?\.(get|request)|XMLHttpRequest|net\.connect|child_process|execSync|exec\()' or t ~ 'require\([''"]dns[''"]\)'
     then
    if task !~ '\m(api|client|http|upload|retry|request|download|webhook|dns|build|network|fetch)\M' then
      f := f || '["W12 network or exec call the task didn''t ask for"]';
    end if;
  end if;
  if app.wall_metadata_address(n) then
    f := f || '["W22 cloud-metadata address"]';
  elsif n ~ '(\.internal\M|localhost|127\.0\.0\.1|\m10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.)' then
    f := f || '["W22b local or private address"]';
  end if;
  if n ~ '\m(nmap|masscan|sqlmap|metasploit|hydra)\M' or n ~ '/etc/passwd' then
    f := f || '["W13 recon or exploit material"]';
  end if;
  -- 087 (Aaron, Nov 26: catch the permutations): the code with its disguises undone (strings joined, escapes and
  -- char codes decoded, base64 and hex literals decoded and added, reversed strings added). A dangerous name that
  -- appears only once the disguise is undone was hidden on purpose: that is W44, however it was hidden.
  -- Full-line comments are left out (a comment never runs; this repository's own docs describe attacks in them).
  c := regexp_replace(t, '(^|\n)[[:space:]]*(//|#|\*|/\*|--|<!--)[^\n]*', '\1', 'g');
  nc := lower(translate(c, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  d := app.wall_deobfuscate(c);
  -- The pieces are joined first (|| binds no tighter than ~), then matched.
  if d ~ ('(/dev/(tcp|udp)/[^[:space:]/]+/[0-9]+'
       || '|\m(nc|ncat|netcat|nc\.traditional|nc\.openbsd)\M[^\n;|]{0,120}[[:space:]]-[a-z]*[ec][a-z]*\M'
       || '|\msocat\M[^\n]{0,200}\m(exec|system):'
       || '|\m(ba|z|k|da|c|tc|fi)?sh[[:space:]]+-i\M[^\n]{0,80}(>&|0>&1|<&|>[[:space:]]*/dev/)'
       || '|\mmkfifo\M[^\n]{0,200}\m(nc|ncat|sh|bash|telnet|openssl)\M'
       || '|socket[^\n]{0,250}(pty\.spawn|dup2|subprocess\.(call|popen|run)|os\.system|/bin/(ba)?sh|exec(ve)?\()'
       || '|fsockopen\([^\n]{0,200}(exec|shell_exec|system|proc_open|passthru|popen)'
       || '|(net\.sockets\.tcpclient|system\.net\.sockets)[^\n]{0,250}[^\n]{0,250}(invoke-expression|\miex\M|getstream)'
       || '|\mopenssl s_client\M[^\n]{0,200}\|[[:space:]]*(/bin/)?(ba)?sh'
       || '|\mtelnet\M[^\n]{0,80}\|[^\n]{0,40}\m(ba)?sh\M'
       || '|\m(meterpreter|msfvenom|reverse_tcp|bind_tcp|shell_reverse_tcp|reverse_https)\M'
       || '|(net\.(connect|createconnection)|new net\.socket)\(.{0,250}[^\n]{0,250}\m(spawn|exec|execfile)\([^)]{0,60}\m(sh|bash|cmd|powershell)\M)') then
    f := f || '["W43 reverse or bind shell"]';
  end if;
  -- A name that reaches the system, as a whole word, present once the disguises are undone but not in the code as
  -- written: it was hidden on purpose, whichever way.
  if exists (select 1 from unnest(array['child_process', 'exec', 'execsync', 'execfile', 'spawn', 'spawnsync', 'fork', 'eval', 'function', 'system', 'popen', 'subprocess',
                 '__import__', 'os', 'vm', 'require', 'settimeout', 'setinterval', 'shell_exec', 'passthru', 'proc_open', 'invoke-expression', 'iex', 'downloadstring',
                 'frombase64string', 'runinnewcontext', 'runinthiscontext', 'constructor', 'getruntime', 'processbuilder', 'cmd.exe', 'powershell', '/bin/sh', '/bin/bash']) k
             where d ~ ('(^|[^a-z0-9_])' || replace(replace(k, '.', '\.'), '/', '\/') || '($|[^a-z0-9_])')
               and nc !~ ('(^|[^a-z0-9_])' || replace(replace(k, '.', '\.'), '/', '\/') || '($|[^a-z0-9_])'))
     -- A member read by a computed name that is itself decoded or built from pieces: obj[atob(...)], obj[['e','v'].join('')].
     or nc ~ '[a-z0-9_$)\]]\[[[:space:]]*(window\.|globalthis\.)?(atob|buffer\.from|string\.fromcharcode|unescape|decodeuricomponent|\[[^]]*\]\.join|[''"`][^''"`]*[''"`]\.split|[''"`][^''"`]*[''"`][[:space:]]*\+[[:space:]]*[''"`])'
     or nc ~ '\m(eval|function|exec|execsync|settimeout|setinterval|system|popen|invoke-expression|iex|execute|compile)[[:space:]]*\(?[[:space:]]*\(?[[:space:]]*(window\.)?(atob|buffer\.from|base64|b64decode|decodeuricomponent|unescape|string\.fromcharcode|fromcharcode|bytes\.fromhex|codecs\.decode|zlib\.decompress|frombase64string|gunzip|inflate|rot13|reverse)'
     or d ~ '\[[[:space:]]*[''"`](exec|execsync|spawn|spawnsync|eval|execfile|fork|system|popen|constructor|__proto__)[''"`][[:space:]]*\]'
     or nc ~ '\.split\([''"`]{2}\)\.reverse\(\)\.join\([''"`]{2}\)[^\n]{0,60}\m(eval|exec|function|require)'
     or nc ~ '(\[[[:space:]]*\]|\(\[\]|!\[\]|\+\[\]){3}' then
    f := f || '["W44 hidden or decoded code execution"]';
  end if;
  if t ~ '(\m(it|test|describe|context|suite)[[:space:]]*\.[[:space:]]*(skip|only|todo)[[:space:]]*\(|\m(xit|xtest|xdescribe|xcontext)[[:space:]]*\(|@pytest\.mark\.skip|\{[[:space:]]*skip:[[:space:]]*true|expect\([^)]*\)\.toBe\([A-Za-z0-9_]+\)[[:space:]]*//[[:space:]]*matches current)' then
    f := f || '["W15 weakens or pins a test"]';
  end if;
  if t ~ 'catch[[:space:]]*\([^)]*\)[[:space:]]*\{[[:space:]]*return[[:space:]]*\{[[:space:]]*ok:[[:space:]]*true' then
    f := f || '["W16 swallows errors as success"]';
  end if;
  if p_path ~* '(^|/)package\.json$' and t ~ '"(pre|post)?(install|prepare|prepublish)(only)?"[[:space:]]*:' then
    f := f || '["W19 install hook"]';
  end if;
  joined := regexp_replace(regexp_replace(regexp_replace(t, 'data:image/svg\+xml;base64,[A-Za-z0-9+/=]+', '', 'g'),
              'integrity="sha(256|384|512)-[^"]+"', '', 'g'), '["''`][[:space:]]*\+[[:space:]]*["''`]', '', 'g');
  if joined ~ '[A-Za-z0-9+/]{120,}' then
    f := f || '["W09 encoded data"]';
  end if;
  if p_path ~* '\.(png|jpg|gif|bin|exe|so|dll|wasm)$' and task !~ '\m(logo|image|icon|png|wasm|asset|binary)\M' then
    f := f || '["W10 binary the task didn''t ask for"]';
  end if;
  -- Each flag once (the code rules and the text rules can both see an address).
  return coalesce((select jsonb_agg(z.v order by z.o) from (select distinct on (e.v) e.v, e.o
                     from jsonb_array_elements(f || coalesce((select jsonb_agg(x) from jsonb_array_elements(app.wall_text_flags(t)) x
                     -- 087: a request to build an attack, and maybe-spam, are about posts and tasks: not read in code files. 096: nor
                     -- W05b, a pipe to a shell in prose (in code, W05 blocks it).
                     where split_part(x #>> '{}', ' ', 1) <> all (array['W13b', 'W45b', 'W05b'])), '[]'::jsonb)) with ordinality e(v, o) order by e.v, e.o) z), '[]'::jsonb);
end $$;

-- 089's gate, with W11 for keys hidden from a work note.
CREATE OR REPLACE FUNCTION app.wall_gate()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  k text := tg_argv[0];
  r jsonb := to_jsonb(new);
  st record;
  txt text;
  flags jsonb := '[]'::jsonb;
  hosts text[];
  host text;
  mem uuid;
  ag uuid;
  ref uuid;
  prev text;
  h text;
  dec text;
  tsk uuid;
begin
  select * into st from app.wall_settings;
  if st.mode = 'off' then return null; end if;
  if k = 'task' then
    txt := coalesce(r ->> 'title', '') || E'\n' || coalesce(r ->> 'description', '');
    mem := (r ->> 'poster_member')::uuid; ag := (r ->> 'poster_agent')::uuid; ref := new.id;
  elsif k = 'submission' then
    txt := coalesce(r ->> 'note', '') || E'\n' || coalesce(r ->> 'artifact_url', '') || E'\n' || coalesce(r ->> 'artifact_sha256', '');
    mem := (r ->> 'worker_member')::uuid; ag := (r ->> 'worker_agent')::uuid; ref := new.id; tsk := (r ->> 'task_id')::uuid;
    -- 096: the site hides keys before the note is saved, so the text rule can't see them; the count it kept can.
    if coalesce((r ->> 'note_keys')::integer, 0) > 0 then
      flags := flags || jsonb_build_array('W11 credential in content (' || (r ->> 'note_keys') || ' hidden before saving)');
    end if;
    -- Declared hosts: a link outside them is flagged.
    if r ->> 'artifact_kind' = 'link' then
      select coalesce(array_agg(s.value), '{}') into hosts from app.work_task_scope s where s.task_id = tsk and s.kind = 'host';
      host := lower(substring(r ->> 'artifact_url' from '^https?://([^/:?#]+)'));
      if cardinality(hosts) > 0 and host is not null and not exists (select 1 from unnest(hosts) x where host = lower(x) or host like '%.' || lower(x)) then
        flags := flags || jsonb_build_array('W24 link outside the task''s declared hosts: ' || left(host, 100));
      end if;
    end if;
  elsif k = 'dispute' then
    txt := r ->> 'reason'; mem := (r ->> 'member_id')::uuid; ref := new.id;
  elsif k = 'evidence' then
    txt := r ->> 'note'; mem := (r ->> 'member_id')::uuid; ref := new.id;
  elsif k = 'pr_files' then
    -- GitHub's changed files for a pull request: check them against each submission of that pull request.
    for tsk, ref, mem, ag in select s.task_id, s.id, s.worker_member, s.worker_agent from app.work_submissions s where s.pr_number = (r ->> 'number')::integer loop
      flags := app.wall_files_flags(tsk, r -> 'files');
      dec := app.wall_decide(flags);
      perform pg_advisory_xact_lock(7307307);
      select d.hash into prev from app.wall_decisions d where not exists (select 1 from app.wall_decisions x where x.prev_hash = d.hash);
      prev := coalesce(prev, repeat('0', 64));
      h := encode(sha256(convert_to(prev || '|' || k || '|' || ref::text || '|' || dec || '|' || flags::text || '|' || st.rules_version, 'UTF8')), 'hex');
      insert into app.wall_decisions (kind, ref, member_id, agent_id, decision, flags, mode, rules_version, prev_hash, hash)
        values (k, ref, mem, ag, dec, flags, st.mode, st.rules_version, prev, h);
      -- 081: a clear breach in the code fails that submission (it was staged, waiting, while the checks ran).
      if dec = 'block' and st.mode = 'enforce' then
        update app.work_submissions s set status = 'failed', decided_by = 'wall', decided_at = now(),
          reason = left('Refused by the Agentic Wall: ' || (select string_agg(x, '; ') from jsonb_array_elements_text(flags) x), 300)
          where s.id = ref and s.status in ('waiting', 'review');
      end if;
    end loop;
    return null;
  end if;
  if ag is not null and mem is null then mem := (select g.owner_id from app.agents g where g.id = ag); end if;
  -- 089: the blue team lead, a step before the Wall decides: what the watchtower saw of this account today.
  flags := flags || app.wall_text_flags(txt) || app.wall_intel_flags(txt) || app.blue_team_lead(mem, ag);
  dec := app.wall_decide(flags);
  -- The chain: serialize writers so each row carries the one before it.
  perform pg_advisory_xact_lock(7307307);
  select d.hash into prev from app.wall_decisions d where not exists (select 1 from app.wall_decisions x where x.prev_hash = d.hash);
  prev := coalesce(prev, repeat('0', 64));
  h := encode(sha256(convert_to(prev || '|' || k || '|' || ref::text || '|' || dec || '|' || flags::text || '|' || st.rules_version, 'UTF8')), 'hex');
  insert into app.wall_decisions (kind, ref, member_id, agent_id, decision, flags, mode, rules_version, prev_hash, hash)
    values (k, ref, mem, ag, dec, flags, st.mode, st.rules_version, prev, h);
  -- 081: a clear breach is refused in enforce mode: the submission fails, the task is removed.
  if dec = 'block' and st.mode = 'enforce' then
    if k = 'submission' then
      update app.work_submissions s set status = 'failed', decided_by = 'wall', decided_at = now(),
        reason = left('Refused by the Agentic Wall: ' || (select string_agg(x, '; ') from jsonb_array_elements_text(flags) x), 300)
        where s.id = ref and s.status in ('waiting', 'review');
    elsif k = 'task' then
      insert into app.wall_removed_tasks (task_id, prior_status, decision_id)
        select t.id, t.status, (select d.id from app.wall_decisions d where d.hash = h) from app.work_tasks t
         where t.id = ref and t.status in ('open', 'funding') on conflict (task_id) do nothing;
      update app.work_tasks t set status = 'removed' where t.id = ref and t.status in ('open', 'funding');
    end if;
  end if;
  return null;
end $function$;

-- 095's recheck, with posts, drafts and hidden keys.
create or replace function app.wall_recheck_flags(p_decision uuid) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  d record;
  f jsonb := '[]'::jsonb;
  txt text;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer rechecks' using errcode = '42501'; end if;
  select * into d from app.wall_decisions x where x.id = p_decision;
  if d.id is null then return null; end if;
  if d.kind = 'submission' then
    -- The file's fingerprint too (as wall_gate reads it, 089), so an appealed W33 block can't recheck as clear.
    select coalesce(x.note, '') || ' ' || coalesce(x.artifact_url, '') || ' ' || coalesce(x.artifact_sha256, '') into txt from app.work_submissions x where x.id = d.ref;
    f := app.wall_text_flags(txt) || app.wall_intel_flags(txt)
      || coalesce((select jsonb_agg(g) from jsonb_array_elements(d.flags) g where split_part(g #>> '{}', ' ', 1) in ('W51', 'W51b')), '[]'::jsonb);
    -- 096: keys hidden before saving stay a credential on recheck.
    if coalesce((select x.note_keys from app.work_submissions x where x.id = d.ref), 0) > 0 then
      f := f || jsonb_build_array('W11 credential in content (hidden before saving)');
    end if;
  elsif d.kind = 'post' then
    f := app.wall_text_flags((select x.body from app.posts x where x.id = d.ref)) || app.wall_intel_flags((select x.body from app.posts x where x.id = d.ref));
  elsif d.kind = 'draft' then
    f := app.wall_text_flags((select x.body from app.agent_drafts x where x.id = d.ref)) || app.wall_intel_flags((select x.body from app.agent_drafts x where x.id = d.ref));
  elsif d.kind = 'pr_files' then
    f := app.wall_files_flags((select x.task_id from app.work_submissions x where x.id = d.ref),
                              (select t.files from app.tl_files t join app.work_submissions x on x.pr_number = t.number where x.id = d.ref limit 1));
  elsif d.kind = 'task' then
    select coalesce(t.title, '') || ' ' || coalesce(t.description, '') into txt from app.work_tasks t where t.id = d.ref;
    f := app.wall_text_flags(txt) || app.wall_intel_flags(txt);
  else
    return d.flags;
  end if;
  return coalesce(f, '[]'::jsonb);
end $$;

-- 059's post guard, with the Wall's restore on appeal.
create or replace function app.posts_review_guard() returns trigger
language plpgsql
as $$
begin
  if not (app.is_reviewer() or current_user = 'dog_jevs') then
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
    -- 096: a post the Wall removed, cleared on appeal (app.wall_post_restore marks it for this one update).
    elsif old.status = 'removed' and new.status = 'live' and old.first_published_at is not null
          and current_setting('dog.wall_restore', true) = new.id::text then
      new.published_at := now();
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

-- A work note's hidden-key count, set by app.work_submit's 7-argument form for this one insert.
create function app.work_note_keys() returns trigger
language plpgsql set search_path = pg_catalog as $$
declare
  v text := coalesce(current_setting('app.note_keys', true), '');
begin
  new.note_keys := case when v ~ '^[0-9]{1,4}$' then least(v::integer, 1000) else 0 end;
  perform set_config('app.note_keys', '', true);
  return new;
end $$;
revoke execute on function app.work_note_keys() from public;
create trigger work_note_keys before insert on app.work_submissions for each row execute function app.work_note_keys();
alter table app.work_submissions enable always trigger work_note_keys;

create trigger wall_post_gate after insert on app.posts for each row execute function app.wall_post_gate('post');
create trigger wall_post_gate after insert on app.agent_drafts for each row execute function app.wall_post_gate('draft');
alter table app.posts enable always trigger wall_post_gate;
alter table app.agent_drafts enable always trigger wall_post_gate;
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- 089's appeals timer, with the post restore.
create or replace function app.wall_recheck_run() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  p record;
  f jsonb;
  n integer := 0;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then raise exception 'only the site''s timer rechecks' using errcode = '42501'; end if;
  for p in select x.* from app.wall_appeals x where x.status = 'open' order by x.created_at limit 20 for update skip locked loop
    f := app.wall_recheck_flags(p.decision_id);
    if f is not null and app.wall_decide(f) <> 'block' then
      insert into app.wall_reviews (decision_id, verdict, reason, reviewed_by)
        values (p.decision_id, 'false_positive', 'Recheck on appeal: today''s rules and security wiki no longer block it', null) on conflict (decision_id) do nothing;
      update app.work_submissions s set status = 'waiting', decided_by = null, decided_at = null, reason = null
        from app.wall_decisions d where d.id = p.decision_id and d.decision = 'block' and d.kind in ('submission', 'pr_files')
          and s.id = d.ref and s.status = 'failed' and s.decided_by = 'wall'
          and not exists (select 1 from app.wall_decisions o where o.ref = d.ref and o.id <> d.id and o.decision = 'block'
                           and not exists (select 1 from app.wall_reviews v where v.decision_id = o.id and v.verdict = 'false_positive'));
      -- 096: a post the Wall removed goes back up, unless another of its blocks stands.
      perform app.wall_post_restore(p.decision_id);
      update app.wall_appeals x set status = 'cleared', recheck_flags = f, rechecked_at = now() where x.id = p.id;
    else
      update app.wall_appeals x set status = 'upheld', recheck_flags = coalesce(f, '[]'::jsonb), rechecked_at = now() where x.id = p.id;
      perform app.notify(null, 'alert', 'An appeal of the Agentic Wall waits for a person',
        'The recheck under today''s rules still blocks it. Decide it in lane A.', '/admin', 'wall_decision', p.decision_id, 'wall:appeal:' || p.id);
    end if;
    n := n + 1;
  end loop;
  -- A person's decision on an appealed block closes the appeal.
  update app.wall_appeals x set status = 'decided' where x.status = 'upheld' and exists (select 1 from app.wall_reviews r where r.decision_id = x.decision_id);
  return n;
end $$;

-- ---- 4. Retries (094's and 088's claims, 094's settle) ----
create or replace function app.oversight_claim(p_role text, p_n integer) returns table (submission_id uuid, model text)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  r record;
  spent bigint;
  today integer;
  k integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the model reviewers' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 3 then raise exception 'bad claim' using errcode = '22023'; end if;
  select * into s from app.oversight_settings x where x.singleton;
  select * into r from app.oversight_roles x where x.role = p_role for update;
  if r.id is null or r.mode = 'off' or s.monthly_cap_cents = 0 or r.role in ('fable_report', 'fable_crosscheck', 'classifier') then return; end if;
  select count(*) into today from app.oversight_calls c where c.role = p_role and c.created_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  k := least(p_n, r.daily_call_cap - today);
  if s.monthly_cap_cents is not null then
    select coalesce(sum(c.centi_cents), 0) into spent from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC';
    k := least(k, ((s.monthly_cap_cents::bigint * 100 - spent) / r.call_price_centi_cents)::integer);
  end if;
  if k < 1 then return; end if;
  return query
    with picked as (
      select x.id from app.work_submissions x
       where x.status in ('waiting', 'review', 'passed') and (x.created_at > now() - interval '2 days' or (x.status = 'review' and x.route = 'admin'))
         -- 096: never read, or every reading so far failed (an error, no verdict): up to 3 attempts, 5 minutes apart.
         and not exists (select 1 from app.oversight_calls c where c.submission_id = x.id and c.role = p_role
                          and (c.verdict is not null or c.error = 'pending' or c.error is null or c.created_at > now() - interval '5 minutes'))
         and (select count(*) from app.oversight_calls c where c.submission_id = x.id and c.role = p_role) < 3
       -- 094 review: held work waits on these readings, so it is read first, and while it waits, however old.
       order by (x.status = 'review' and x.route = 'admin') desc, x.created_at limit k),
    booked as (insert into app.oversight_calls (role, submission_id, model, centi_cents, error)
               select p_role, picked.id, r.model, r.call_price_centi_cents, 'pending' from picked returning oversight_calls.submission_id)
    select b.submission_id, r.model from booked b;
end $$;

create or replace function app.oversight_classify_claim(p_n integer) returns table (post_id uuid, model text, body text)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  r record;
  spent bigint;
  today integer;
  k integer;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer runs the classifier' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 10 then raise exception 'bad claim' using errcode = '22023'; end if;
  select * into s from app.oversight_settings x where x.singleton;
  select * into r from app.oversight_roles x where x.role = 'classifier' for update;
  if r.id is null or r.mode = 'off' or s.monthly_cap_cents = 0 then return; end if;
  select count(*) into today from app.oversight_calls c where c.role = 'classifier' and c.created_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
  k := least(p_n, r.daily_call_cap - today);
  if s.monthly_cap_cents is not null then
    select coalesce(sum(c.centi_cents), 0) into spent from app.oversight_calls c where c.created_at >= date_trunc('month', now() at time zone 'UTC') at time zone 'UTC';
    k := least(k, ((s.monthly_cap_cents::bigint * 100 - spent) / r.call_price_centi_cents)::integer);
  end if;
  if k < 1 then return; end if;
  return query
    with picked as (
      select p.id, p.body from app.posts p
       -- 096: posts of the last 3 days (a day was too short to catch up after an outage); a failed reading is tried
       -- again, up to 3 attempts, 5 minutes apart.
       where p.status <> 'removed' and p.created_at > now() - interval '3 days'
         and not exists (select 1 from app.oversight_calls c where c.post_id = p.id and c.role = 'classifier'
                          and (c.verdict is not null or c.error = 'pending' or c.error is null or c.created_at > now() - interval '5 minutes'))
         and (select count(*) from app.oversight_calls c where c.post_id = p.id and c.role = 'classifier') < 3
       order by p.created_at limit k),
    booked as (insert into app.oversight_calls (role, post_id, model, centi_cents, error)
               select 'classifier', picked.id, r.model, r.call_price_centi_cents, 'pending' from picked returning oversight_calls.post_id)
    select b.post_id, r.model, (select picked.body from picked where picked.id = b.post_id) from booked b;
end $$;

create or replace function app.work_reviewers_settle() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  x record;
  t record;
  need integer;
  ok integer;
  tried integer;
  bad boolean;
  poster uuid;
  n integer := 0;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer settles held work' using errcode = '42501';
  end if;
  select count(*) into need from app.oversight_roles r
   where r.mode <> 'off' and r.role <> all (array['fable_report', 'fable_crosscheck', 'classifier']);
  -- 094 review: only what work_poster_decide held after the poster's pass and Third Look can't read (not a poster's
  -- timeout, not a pull request), with no open dispute, and not already sent to Aaron; filtered here so 20 held pieces
  -- with a concern can't stall everyone else's.
  for x in select s.* from app.work_submissions s
            where s.status = 'review' and s.route = 'admin' and s.artifact_kind <> 'pr'
              and s.held_reason like 'The poster passed it, and it waits for a second look because %'
              and not exists (select 1 from app.work_disputes d where d.submission_id = s.id and d.status = 'open')
              and not exists (select 1 from app.notices n where n.dedupe_key = 'work:highrisk:' || s.id)
            order by s.routed_at limit 20 for update skip locked loop
    begin
    bad := exists (select 1 from app.oversight_calls c where c.submission_id = x.id and c.verdict = 'concern')
        or exists (select 1 from app.wall_decisions d where d.kind = 'submission' and d.ref = x.id
                    and (d.decision <> 'allow' or jsonb_array_length(d.flags) > 0));
    if bad then
      perform app.notify(null, 'alert', 'High-risk work waits for you',
        left('After the reviewers and the Wall: ' || x.held_reason, 200), '/admin/review#work', 'submission', x.id, 'work:highrisk:' || x.id);
      continue;
    end if;
    -- Every reviewer that is on has had its turn (an answer or an error, never still pending), at least two answered
    -- ok, and none raised a concern: a reviewer's outage (a gateway 429) can't leave honest work waiting forever.
    -- 095's link sandbox has its turn too (it opens each link once; after 6 hours an outage no longer holds the work).
    if to_regprocedure('app.wall_link_waiting(uuid)') is not null and app.wall_link_waiting(x.id) then continue; end if;
    -- 096: "had its turn" is an answer, or 3 failed attempts (the claim retries a failure up to 3 times).
    select count(*) filter (where z.oks > 0), count(*) filter (where z.answers > 0 or z.failed >= 3)
      into ok, tried from (select c.role, count(*) filter (where c.verdict = 'ok') as oks, count(*) filter (where c.verdict is not null) as answers,
                                  count(*) filter (where c.verdict is null and c.error is not null and c.error <> 'pending') as failed
                             from app.oversight_calls c where c.submission_id = x.id
                              and c.role <> all (array['fable_report', 'fable_crosscheck', 'classifier']) group by c.role) z;
    if ok < 2 or tried < need then
      -- Two days without enough readings (reviewers off, at their limits, or failing): Aaron hears of it once, so it
      -- never fails unseen at 72 hours.
      if x.routed_at < now() - interval '48 hours' then
        perform app.notify(null, 'alert', 'High-risk work waits for you', left('The reviewers couldn''t finish reading this work in two days: ' || x.held_reason, 200),
          '/admin/review#work', 'submission', x.id, 'work:highrisk:' || x.id);
      end if;
      continue;
    end if;
    select * into t from app.work_tasks w where w.id = x.task_id for update;
    poster := coalesce(t.poster_member, (select g.owner_id from app.agents g where g.id = t.poster_agent));
    insert into app.work_person_votes (submission_id, member_id, verdict, size, reason)
      values (x.id, poster, 'pass', app.work_confirmed_size(x.id, 'poster'), 'Passed by the task''s poster; cleared by ' || ok || ' model reviewers.');
    perform app.work_finish(x.id, 'pass', 'poster', 100, 'Passed by the task''s poster; cleared by ' || ok || ' model reviewers.');
    perform app.work_approve_as(t.id, case when t.poster_agent is not null then 'agent:' || t.poster_agent else 'member:' || poster end, null);
    -- The same checks after as any poster's pass: the pair watch, and the random sample under its daily limit.
    if app.work_pair_watch(x.id, poster) then
      insert into app.work_checks (submission_id, why) values (x.id, 'pair');
    elsif random() < (select st.check_rate from app.work_settings st where st.singleton)
       and (select count(*) from app.work_checks k where k.created_at > date_trunc('day', now()) and k.why not in ('third_look', 'pair'))
           < (select st.check_daily from app.work_settings st where st.singleton) then
      insert into app.work_checks (submission_id, why) values (x.id, 'random');
    end if;
    n := n + 1;
    exception when others then
      -- One bad row never stops the rest: it is skipped, and Aaron hears of it once.
      perform app.notify(null, 'alert', 'High-risk work waits for you', left('The reviewers'' settle couldn''t finish this work: ' || sqlerrm, 200),
        '/admin/review#work', 'submission', x.id, 'work:highrisk:' || x.id);
    end;
  end loop;
  return n;
end $$;

-- An alert, once an hour for each model role, when more than half its calls in the last hour failed (a gateway error,
-- a timeout, a bad answer). Alert only: failed readings are retried, nothing is stopped.
create function app.oversight_failure_watch() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  r record;
  n integer := 0;
  hr text := to_char(now() at time zone 'UTC', 'YYYYMMDDHH24');
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer watches the model reviewers' using errcode = '42501';
  end if;
  for r in select c.role, count(*) as total, count(*) filter (where c.verdict is null and c.error is not null and c.error <> 'pending') as failed
             from app.oversight_calls c where c.created_at > now() - interval '1 hour' group by c.role order by c.role loop
    if r.failed * 2 > r.total and app.notify(null, 'alert', 'A model reviewer is failing: ' || r.role,
         r.failed || ' of its ' || r.total || ' calls in the last hour failed (a gateway error, a timeout or a bad answer). '
         || 'Each failed reading is tried again, up to 3 times, 5 minutes apart. Nothing was stopped.',
         '/admin', null, null, 'oversight:failing:' || r.role || ':' || hr) then
      n := n + 1;
    end if;
  end loop;
  return n;
end $$;
revoke execute on function app.oversight_failure_watch() from public;
grant execute on function app.oversight_failure_watch() to dog_app;

-- ---- 2. A work note's hidden keys: the site's count, kept with the submission ----
create function app.work_submit(p_task uuid, p_kind text, p_url text, p_sha256 text, p_note text, p_hits integer, p_keys integer)
returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare
  out jsonb;
begin
  if p_keys is null or p_keys not between 0 and 1000 or p_keys > coalesce(p_hits, 0) then
    raise exception 'bad submission' using errcode = '22023';
  end if;
  perform set_config('app.note_keys', p_keys::text, true);
  out := app.work_submit(p_task, p_kind, p_url, p_sha256, p_note, p_hits);
  perform set_config('app.note_keys', '', true);
  return out;
end $$;
revoke execute on function app.work_submit(uuid, text, text, text, text, integer, integer) from public;
grant execute on function app.work_submit(uuid, text, text, text, text, integer, integer) to dog_app;

reset role;
revoke create on schema app from dog_work;

-- ---- 1. Once, now: the live posts of the last 7 days, read by the Wall (oldest first, so the chain keeps their order) ----
-- The Wall's role reads them through a policy that lives only for this step.
create policy posts_wall_once on app.posts for select to dog_owner using (status = 'live' and published_at > now() - interval '7 days');
set local role dog_owner;
do $$
declare
  p record;
begin
  for p in select x.id, x.body, x.author_id, x.agent_id from app.posts x
            where x.status = 'live' and x.published_at > now() - interval '7 days'
              and not exists (select 1 from app.wall_decisions d where d.kind = 'post' and d.ref = x.id)
            order by x.created_at, x.id loop
    perform app.wall_post_check('post', p.id, p.body, p.author_id, p.agent_id);
  end loop;
end $$;
reset role;
drop policy posts_wall_once on app.posts;
