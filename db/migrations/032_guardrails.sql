-- 032 Guardrails, round 1 (Aaron, Oct 30: "Okay lets build out your approach and run the loop on it"). The fixed-rule
--   gaps found when a document on deterministic guardrails for agents was mapped onto this site (harness/FACTS.md,
--   Oct 30). Each one alerts, or asks one owner about one post; none refuses anyone or locks an account.
--   1. J18, keys and passwords: the site hides keys before a post or draft is saved (api/_secrets.js); for an agent
--      posting on its own, JEVs counts them (db/jevs.js). J19, repeats of its own post: an agent that sends the same
--      words again within 24 hours (a stuck loop: the daily cap alone let one every 15 minutes or slower get all 20 of
--      its posts live). Both ask only: app.jevs_decide leaves them out of the total and the top score, so on their own
--      they can ask the owner to confirm but never hold a post for Aaron, whatever the other scores (the fresh review:
--      summed, a loop's posts 13 to 20 would each have reached his queue).
--   2. Drafts get the same body_fp as posts, for J19.
--   3. Rules that must never break, checked at most once an hour from the timer route (/api/cron), in their own
--      transaction, never inside the timers' (the fresh review: a failure there would have stopped draft expiry and
--      the 24-hour deletion review). Each rule that is broken alerts Aaron once a day; a failed check alerts once a day.
--      Nothing is changed. The rules, each true of every legitimate state today (tested both ways in test/guardrails.test.js):
--        a. every administrator was made one through a recorded promotion ('admin.set' in the append-only audit log);
--        b. no active member's level is above what an approved path gives (an admin-set level, a verified sign-in
--           method, or automatic level 2): the source document's "permission never rises without a second signature";
--        c. a sub-agent has its parent's owner and a daily cap no higher than its parent's (its expiry is already a
--           constraint, agents_tree_expiry);
--        d. no session lasts more than 30 days (signin/config.js SESSION_DAYS);
--        e. no agent sent more posts and drafts in the last 24 hours than the highest daily cap it had in that time;
--        f. JEVs's settings are complete and ordered (medium below high; 010's trigger already checks each value).
--   Grants: dog_jevs, which already gathers JEVs's facts, may also read posts.draft_id and posts.delegation, drafts'
--   body_fp and status, agent_rules (agent, version, cap, time), agents.expires_at, sessions' start and end times, and the
--   audit log's 'admin.set' rows only.
set local role dog_owner;

-- ---- 2. Drafts' body_fp: posts' expression (006), same text in, same value out ----
alter table app.agent_drafts add column body_fp text
  generated always as (md5(coalesce(nullif(regexp_replace(lower(body), '[\s!-/:-@\[-`{-~\u00a0-\u00bf\u2000-\u206f\u3000-\u303f\uff01-\uff0f\uff1a-\uff20]+', '', 'g'), ''), body))) stored
  check (char_length(body_fp) = 32);
create index agent_drafts_body_fp on app.agent_drafts (agent_id, body_fp, created_at);

grant select (draft_id, delegation) on app.posts to dog_jevs;
grant select (body_fp, status) on app.agent_drafts to dog_jevs;
create policy agent_rules_jevs_select on app.agent_rules for select to dog_jevs using (true);
grant select (agent_id, version, daily_cap, created_at) on app.agent_rules to dog_jevs;
create policy sessions_jevs_select on app.sessions for select to dog_jevs using (true);
grant select (created_at, expires_at) on app.sessions to dog_jevs;
create policy audit_jevs_select on app.audit_log for select to dog_jevs using (action = 'admin.set');
grant select (action, subject_kind, subject_id) on app.audit_log to dog_jevs;
grant select (expires_at) on app.agents to dog_jevs;

-- ---- 3. The hourly slot: one row ----
create table app.invariant_slot (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  last_at timestamptz,                -- when the last check took the slot
  last_ok_at timestamptz,             -- when the checks last finished
  failures integer not null default 0 check (failures >= 0),
  last_failure_state text check (char_length(last_failure_state) <= 5) -- the SQLSTATE only, never a message
);
alter table app.invariant_slot enable row level security;
alter table app.invariant_slot force row level security;
create policy invariant_slot_owner on app.invariant_slot for all to dog_owner using (true) with check (true);
create policy invariant_slot_jevs_select on app.invariant_slot for select to dog_jevs using (true);
create policy invariant_slot_jevs_update on app.invariant_slot for update to dog_jevs using (true) with check (true);
grant select, update on app.invariant_slot to dog_jevs;
-- The heartbeat, for anyone (as the timers', 027): the site reads when the checks last finished, and nothing else.
create policy invariant_slot_heartbeat on app.invariant_slot for select to dog_app using (true);
grant select (last_ok_at) on app.invariant_slot to dog_app;
insert into app.invariant_slot (singleton) values (true);

grant create on schema app to dog_jevs;
set local role dog_jevs;
-- 014's version, with the 032 change marked.
create or replace function app.jevs_decide(p_action text, p_subject uuid, p_scores jsonb, p_impact text, p_error boolean, p_domains text[], p_simhash bigint,
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
  ask integer := 0; -- 032
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
  elsif p_action = 'agent.subagent' then
    -- A sub-agent needs no human step to be made (Aaron, Oct 16, 2026). Medium makes it with every action drafting, so
    -- each thing it does waits for its human owner (never an agent); high holds it for Aaron.
    eff := case lvl when 'high' then 'hold' when 'medium' then 'draft' else 'none' end;
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
    elsif subj_kind is distinct from 'post' and eff in ('hold', 'challenge', 'queue', 'draft') then
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

-- 031's version, with the 032 change marked.
create or replace function app.jevs_signals(p_action text, p_subject uuid, p_net text, p_domains text[], p_simhash bigint)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  me uuid := app.current_member();
  ag uuid := app.current_agent();
  judged uuid;
  m_created timestamptz; m_level smallint; m_admin boolean; m_status text; m_hand smallint; m_jevs timestamptz;
  fp text;
  p_agent uuid; p_draft uuid; -- 032
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
      -- J06: agents this owner created or claimed in the last 24 hours (not sub-agents, which J15 looks at, 013).
      'owner_agents_24h', (select count(*) from app.agents a where a.owner_id = judged and a.parent_id is null
                           and a.claimed_at > now() - interval '24 hours'),
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
    -- 031: only for an agent registering itself and a member's sign-up and account checks, where a burst of new agents
    -- from one network says something about the account. Every other action is judged by its owner's own count
    -- (owner_agents_24h): an agent posting from a busy shared cloud network isn't asked about each post because of
    -- other people's agents (the UI/UX review, item 17).
    'net_agents_24h', case when p_net is null or p_action not in ('agent.register', 'signup', 'account.check') then 0
                           else (select count(distinct k.agent_id) from app.jevs_marks k where k.kind = 'net' and k.key_hash = p_net
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
  -- J15 (013): where the sub-agent the acting agent wants to make would sit, and how many sub-agents its tree made in
  -- the last hour.
  if p_action = 'agent.subagent' and ag is not null then
    res := res || (select jsonb_build_object('subagent_depth', a.depth + 1, 'subagent_max_depth', (select s.max_depth from app.subagent_settings s),
                     'tree_subagents_1h', (select count(*) from app.agents t where t.root_id = coalesce(a.root_id, a.id)
                                           and t.created_at > now() - interval '1 hour'))
                   from app.agents a where a.id = ag);
  end if;
  -- J18 and J19 (032): whether a new post is an agent's own, under its owner's rules (the only posts they score), and how
  -- many posts and drafts that agent sent in the last 24 hours with the same words: its posts of any status other than
  -- this one, and its drafts not yet approved (an approved draft is counted as its post), other than this post's own.
  if p_action = 'post.create' then
    select p.agent_id, p.draft_id into p_agent, p_draft from app.posts p where p.id = p_subject;
    if p_agent is not null then
      res := res || jsonb_build_object('by_agent', true, 'own_repeats_24h',
        (select count(*) from app.posts p where p.agent_id = p_agent and p.body_fp = fp and p.id <> p_subject
           and p.created_at > now() - interval '24 hours')
        + (select count(*) from app.agent_drafts d where d.agent_id = p_agent and d.body_fp = fp and d.status <> 'approved'
             and d.id is distinct from p_draft and d.created_at > now() - interval '24 hours'));
    end if;
  end if;
  return res;
end
$$;

-- ---- 3. The rules that must never break ----
create function app.invariants_check()
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
revoke execute on function app.invariants_check() from public;
grant execute on function app.invariants_check() to dog_app;

set local role dog_owner;
revoke create on schema app from dog_jevs;
