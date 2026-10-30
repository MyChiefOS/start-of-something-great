-- 031 Fair checks (the UI/UX review, items 17 and 9; Aaron, Oct 30: "I would like you to implement the changes",
--   "Yes, all 15 in that order").
--   1. J06 counts the agents registered from one network only where that says something about the account itself: an
--      agent registering itself (agent.register), and a member's sign-up and account checks (signup, account.check: the
--      checks that decide automatic level 2, unchanged). Until now every action on that network counted them too, so an
--      agent posting from a busy shared cloud network (10 or more agents registered there that day, whoever owns them)
--      had each post asked about, however established its owner (harness/FACTS.md, Oct 29). Posts, drafts, approvals,
--      claims, rules, keys and deletions are judged by the owner's own count. Only the signal changes: the questions,
--      their scores and the thresholds don't (db/jevs.js; app.jevs_settings). The fresh review of this PR found the
--      first version also changed the level-2 check; this one doesn't (RISKS.md RK96).
--   2. app.jevs_post_reasons: the author of their own post that JEVs is still holding, still asking them about, or
--      hid and Aaron hasn't yet decided, is told which questions asked about it, by ID in a fixed order (the site shows
--      each one's public title), never a score, a total or a threshold, nor which scored higher. Once the author
--      answers, the challenge expires or Aaron decides, it says nothing (the fresh review: an out-of-date "held" and an
--      appeal button after his decision would put work back on him). Read as the author, through dog_jevs, which
--      already reads these decisions, challenges and review flags; no new grant on any table.
set local role dog_owner;

grant create on schema app to dog_jevs;
set local role dog_jevs;
-- 014's version, with the 031 change marked.
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
  return res;
end
$$;


create function app.jevs_post_reasons(p_post uuid)
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  d record;
begin
  if app.actor_kind() not in ('member', 'admin') or p_post is null then
    return null;
  end if;
  select x.effect, x.scores into d
  from app.jevs_decisions x
  join app.posts p on p.id = x.subject_id
  where x.subject_id = p_post and x.subject_kind = 'post' and x.applied and x.effect in ('challenge', 'hold', 'hide')
    and p.author_id = app.current_member() and p.status in ('waiting', 'removed')
  order by x.created_at desc, x.id desc
  limit 1;
  if not found then
    return null;
  end if;
  -- Still current: a challenge the author hasn't answered and that hasn't expired, on a post still waiting; or a hold
  -- (waiting) or a hide (removed) whose JEVs flag in Aaron's queue is still open.
  if d.effect = 'challenge' then
    if not exists (select 1 from app.posts p where p.id = p_post and p.status = 'waiting')
       or not exists (select 1 from app.jevs_challenges c where c.subject_kind = 'post' and c.subject_id = p_post
                      and c.status = 'pending' and c.expires_at > now()) then
      return null;
    end if;
  elsif not exists (select 1 from app.posts p where p.id = p_post and p.status = case when d.effect = 'hold' then 'waiting' else 'removed' end)
        or not exists (select 1 from app.review_flags f where f.post_id = p_post and f.source = 'classifier' and f.classifier = 'jevs'
                       and f.resolved_at is null) then
    return null;
  end if;
  return jsonb_build_object(
    'effect', d.effect,
    'questions', coalesce((select jsonb_agg(q.k order by q.k)
                           from (select e.key as k, (e.value)::numeric as v from jsonb_each(d.scores) e
                                 where e.key ~ '^J[0-9]{2}$' and jsonb_typeof(e.value) = 'number' and (e.value)::numeric >= 25) q), '[]'::jsonb));
end
$$;
revoke execute on function app.jevs_post_reasons(uuid) from public;
grant execute on function app.jevs_post_reasons(uuid) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_jevs;
