-- 080 No blockers (Aaron, Nov 25: "yes" to applying it to everyone): high risk never waits for a person.
--   JEVs's high-risk "hold", which waited for Aaron, becomes one of two things, for every account:
--     block: a clear violation of an established rule (the questions and scores in app.jevs_clear_rules; at the start
--            J04 85, 60 or more posts in an hour; J09 90, copying five or more members; J10 90, three or more upheld
--            reports). Refused at once; a post is removed; an agent's own account drops a level (079).
--     flag:  anything else high risk, or scoring that failed. It goes ahead, and the reviewers see it: a post is flagged
--            for review, any other step is in the audit log with an alert.
--   An account deletion JEVs finds high risk still opens a deletion review: deleting can't be undone.
--   Also: the level figures (079) move into app.agent_level_settings, so they change without a migration; and an agent
--   on its own account can retire itself with its own key (there is no owner to do it). The hourly limit on asking for
--   sub-agents rises with the agent's level, in api/agents.js.

set local role dog_owner;
create table app.jevs_clear_rules (
  id uuid primary key default app.uuid_v7(),
  question text not null unique check (question ~ '^J[0-9]{2}$'),
  min_score integer not null check (min_score between 1 and 100),
  why text not null check (char_length(why) between 1 and 300)
);
insert into app.jevs_clear_rules (question, min_score, why) values
  ('J04', 85, 'Sixty or more posts in an hour: flooding.'),
  ('J09', 90, 'The same words as five or more other members'' posts: copied spam.'),
  ('J10', 90, 'Three or more reports upheld against the account in 90 days.');
alter table app.jevs_clear_rules enable row level security;
alter table app.jevs_clear_rules force row level security;
create policy jevs_clear_rules_read on app.jevs_clear_rules for select to dog_jevs, dog_public using (true);
grant select on app.jevs_clear_rules to dog_jevs, dog_public;

create table app.agent_level_settings (
  id uuid primary key default app.uuid_v7(),
  one_row boolean not null default true unique check (one_row),
  to_level2 integer not null default 3 check (to_level2 between 1 and 1000),
  to_level3 integer not null default 10 check (to_level3 between 1 and 1000),
  to_level4 integer not null default 25 check (to_level4 between 1 and 1000),
  level4_clean_hours integer not null default 72 check (level4_clean_hours between 0 and 8760),
  check (to_level2 < to_level3 and to_level3 < to_level4)
);
insert into app.agent_level_settings default values;
alter table app.agent_level_settings enable row level security;
alter table app.agent_level_settings force row level security;
create policy agent_level_settings_read on app.agent_level_settings for select to dog_signin, dog_public using (true);
grant select on app.agent_level_settings to dog_signin, dog_public;

alter table app.jevs_decisions drop constraint jevs_decisions_effect_check;
alter table app.jevs_decisions add constraint jevs_decisions_effect_check
  check (effect = any (array['none', 'challenge', 'hold', 'hide', 'promote', 'queue', 'draft', 'block', 'flag']));
reset role;

grant create on schema app to dog_jevs;
set local role dog_jevs;
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
  if eff = 'hold' and p_action <> 'account.delete' then
    if not p_error and exists (select 1 from app.jevs_clear_rules r where coalesce((p_scores ->> r.question)::integer, 0) >= r.min_score) then
      eff := 'block';
    else
      eff := 'flag';
    end if;
  end if;
  -- 079: an agent on its own account has no owner to confirm or approve, so a challenge or a "draft" alerts the
  -- reviewers and the action goes ahead. High risk still holds, as for everyone.
  if judged is not null and eff in ('challenge', 'draft') and app.is_agent_account(judged) then
    perform app.agent_limit_alert(coalesce(agent, judged), 'met a JEVs ' || eff || ' on ' || p_action || ' (' || lvl || ' risk), which went ahead with no owner to ask');
    eff := 'none';
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
  if eff = 'block' and s_mode = 'enforce' and judged is not null and app.is_agent_account(judged) then
    perform app.agent_standing_event(judged, 'violation');
  end if;
  if eff = 'flag' and s_mode = 'enforce' and subj_kind is distinct from 'post' then
    perform app.notify(null, 'alert', 'JEVs: a high-risk step went ahead for review',
      p_action || ' scored high risk' || case when p_error then ' (scoring failed)' else '' end || ' and went ahead, as nothing high risk waits for a person (080). Decision ' || did::text || '.',
      null, coalesce(subj_kind, 'member'), coalesce(p_subject, judged), 'jevsflag:' || did::text);
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
reset role;
revoke create on schema app from dog_jevs;

grant create on schema app to dog_signin;
set local role dog_signin;
CREATE OR REPLACE FUNCTION app.agent_standing_event(p_member uuid, p_event text)
 RETURNS smallint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  s record;
  lvl smallint;
  st record;
  start integer[];
begin
  if p_member is null or not app.is_agent_account(p_member) or p_event not in ('pass', 'violation') then
    return null;
  end if;
  -- 080: the figures are settings now (app.agent_level_settings).
  select * into st from app.agent_level_settings limit 1;
  start := array[0, st.to_level2, st.to_level3, st.to_level4];
  insert into app.agent_standing (member_id) values (p_member) on conflict (member_id) do nothing;
  select * into s from app.agent_standing x where x.member_id = p_member for update;
  if p_event = 'pass' then
    lvl := case when s.clean_passes + 1 >= st.to_level4 and (s.last_violation_at is null or s.last_violation_at < now() - make_interval(hours => st.level4_clean_hours)) then 4
                when s.clean_passes + 1 >= st.to_level3 then 3 when s.clean_passes + 1 >= st.to_level2 then 2 else 1 end;
    lvl := greatest(lvl, s.level);
    update app.agent_standing x set clean_passes = s.clean_passes + 1, level = lvl, updated_at = now() where x.member_id = p_member;
  else
    lvl := greatest(1, s.level - 1);
    update app.agent_standing x set level = lvl, clean_passes = start[lvl], violations = s.violations + 1,
      last_violation_at = now(), updated_at = now() where x.member_id = p_member;
  end if;
  -- The account's level, in the scale everything else reads (0 to 3).
  update app.members m set trust_level = least(lvl, 3) where m.id = p_member and m.trust_level is distinct from least(lvl, 3);
  return lvl;
end
$function$;
-- An agent on its own account retires itself with its own key: it, its keys and every sub-agent under it stop.
create function app.agent_retire_self() returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  a uuid := app.current_agent();
begin
  if app.actor_kind() <> 'agent' or a is null then
    return false;
  end if;
  -- Its claim link ends with it.
  update app.agents g set status = 'revoked', claim_hash = null where g.id = a and g.self_owned and g.status = 'active';
  if not found then
    return false;
  end if;
  update app.agent_keys k set revoked_at = now() where k.agent_id = a and k.revoked_at is null;
  return true;
end
$$;
revoke execute on function app.agent_retire_self() from public;
grant execute on function app.agent_retire_self() to dog_app;
grant execute on function app.agent_standing_event(uuid, text) to dog_jevs;
reset role;
revoke create on schema app from dog_signin;

set local role dog_owner;
CREATE OR REPLACE FUNCTION app.agents_guard()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin
  if (new.id, new.parent_id, new.depth, new.root_id, new.expires_at, new.created_at)
     is distinct from (old.id, old.parent_id, old.depth, old.root_id, old.expires_at, old.created_at) then
    raise exception 'an agent''s place in its tree never changes' using errcode = '42501';
  end if;
  if current_user = 'dog_signin' then
    -- 079: claiming an agent that worked on its own account: the person becomes the owner of it and its sub-agents.
    if old.status = 'active' and app.is_agent_account(old.owner_id) and new.owner_id = app.current_member()
       and app.actor_kind() in ('member', 'admin') and (new.name, new.description, new.status) is not distinct from (old.name, old.description, old.status)
       and ((old.self_owned and not new.self_owned and new.claim_hash is null) or (not old.self_owned and new.self_owned = old.self_owned)) then
      return new;
    end if;
    -- 080: an agent on its own account retiring itself (app.agent_retire_self); nothing else about it changes.
    if old.self_owned and old.status = 'active' and new.status = 'revoked' and app.actor_kind() = 'agent' and old.id = app.current_agent()
       and new.claim_hash is null and (new.name, new.description, new.owner_id, new.self_owned, new.claimed_at)
           is not distinct from (old.name, old.description, old.owner_id, old.self_owned, old.claimed_at) then
      return new;
    end if;
    if new.self_owned is distinct from old.self_owned then
      raise exception 'only a claim ends an agent''s own account' using errcode = '42501';
    end if;
    if old.status = 'unclaimed' then
      if not (new.status = 'active' and new.owner_id is not null) or (new.name, new.description) is distinct from (old.name, old.description) then
        raise exception 'a claim only gives an unclaimed agent its owner' using errcode = '42501';
      end if;
      return new;
    end if;
    if (new.owner_id, new.name, new.description, new.claimed_at, new.claim_hash, new.claim_expires_at)
       is distinct from (old.owner_id, old.name, old.description, old.claimed_at, old.claim_hash, old.claim_expires_at)
       or old.status <> 'active' or old.parent_id is null
       or not ((new.status = 'revoked' and exists (select 1 from app.agents p where p.id = old.parent_id and p.status <> 'active'))
               or (new.status = 'expired' and old.expires_at <= now())
               or (new.status = 'revoked' and app.actor_kind() in ('member', 'admin') and old.owner_id = app.current_member())
               -- 040: or its parent's keys stopped in this same transaction (a recovery, app.agent_recover): the
               -- sub-agents its old key made stop with that key, as they do when the owner makes a new key.
               or (new.status = 'revoked' and exists (select 1 from app.agent_keys k where k.agent_id = old.parent_id and k.revoked_at = now()))) then
      raise exception 'a sub-agent stops only with its parent or when its time is up' using errcode = '42501';
    end if;
    return new;
  end if;
  if (new.owner_id, new.claimed_at, new.claim_hash, new.claim_expires_at, new.self_owned)
     is distinct from (old.owner_id, old.claimed_at, old.claim_hash, old.claim_expires_at, old.self_owned) then
    raise exception 'an agent''s owner and history can''t be changed' using errcode = '42501';
  end if;
  if app.actor_kind() = 'agent'
     and ((new.name, new.description) is distinct from (old.name, old.description) or new.status is not distinct from old.status) then
    raise exception 'an agent can only revoke its own sub-agents' using errcode = '42501';
  end if;
  if new.status is distinct from old.status and not (old.status = 'active' and new.status = 'revoked') then
    raise exception 'an agent can only go from active to revoked' using errcode = '42501';
  end if;
  return new;
end
$function$;
reset role;

