-- 036 The public JEVs decisions page, /decisions (the design handoff of Nov 5, 2026; Aaron: "Please implement the design
--   and details I provided"; CODING_AGENT_SPEC.md section 6, "decisions", and 2.4 and 2.5, "Human oversight").
--   Until now these numbers were the administrator's only, on Controls (app.jevs_decisions and Second Look's tables are
--   readable by an administrator alone). This adds one function that anyone may ask, through the site's role, for the
--   counts the design shows, and nothing else:
--     * the last 24 hours: low risk (went ahead), medium waiting for the owner, high risk held or hidden, open appeals;
--     * high-risk decisions in the last 7 days, grouped by day (UTC), place and outcome: a count and the question IDs
--       that scored 25 or more, for groups of 5 or more only, never a score, a total, a member, an agent, a post or a
--       time of day. Sign-ups declined by region come from 012's daily counts, without the country;
--     * Second Look: its mode, whether it paused itself, how many of Aaron's most recent decisions on its shadow clears
--       agreed in a row (the unlock's own count, 034), and its limits;
--     * human oversight: the decisions people made on the review queue in the last 7 and 30 days (approved or kept,
--       removed, a removal undone), the median minutes from the first flag to the decision, and the queue now (open
--       items, median and oldest age in hours). Counts only; the page shows a rate only from 20 decisions up.
--   After its independent review (Nov 5), every count is private by size and by time:
--     * k = 5: a count from 1 to 4 is returned as null ("fewer than 5"), a 7-day group under 5 isn't returned at all,
--       and a median or age needs 5 decisions or 5 open items, so no number on the page describes one person or post;
--     * whole hours: the last 24 hours end at the start of this hour, so polling can't time a decision to the minute,
--       and queue ages are whole hours;
--     * account deletions are left out: a flagged deletion is between the member and Aaron (Oct 16).
--   It runs as dog_jevs, which already reads every table it counts (010, 016, 034), and returns one jsonb value. It
--   changes nothing, and it reads no post text, name or score into its answer.
--   Two indexes keep it cheap as the tables grow: GitHub decisions by time, and people's decisions on the queue by time.
-- No authentication, sign-in, row-level security or Second Look object changes.
set local role dog_owner;

create index gh_decisions_at on app.gh_decisions (at);
create index review_flags_decided on app.review_flags (resolved_at) where resolved_by is not null;

grant create on schema app to dog_jevs;
set local role dog_jevs;

create function app.public_decisions()
returns jsonb
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  v_mode text;
  v_sl_mode text;
  v_paused boolean;
  v_unlock integer;
  v_cap integer;
  v_since timestamptz;
  v_agreed integer;
  v_last_bad timestamptz;
  v_sl boolean;
  v_to timestamptz := date_trunc('hour', now());  -- whole hours only (the review, finding 2)
  k constant integer := 5;                        -- the smallest count shown (the review, finding 1)
begin
  select value into v_mode from app.jevs_settings where key = 'mode';
  select x.mode, x.paused_reason is not null, x.unlock_n, x.daily_clear_cap, x.counted_since
    into v_sl_mode, v_paused, v_unlock, v_cap, v_since
    from app.sl_settings x where x.singleton;
  v_sl := found;
  -- Second Look's unlock counts Aaron's decisions on its shadow clears after counted_since; any removal among the last
  -- unlock_n holds it in shadow (034, app.sl_try_unlock). So the progress is the approvals since the latest removal.
  if v_sl then
    select max(o.decided_at) into v_last_bad from app.sl_outcomes o where not o.approved and o.decided_at > v_since;
    select least(count(*), v_unlock) into v_agreed from app.sl_outcomes o
      where o.approved and o.decided_at > v_since and o.decided_at > coalesce(v_last_bad, '-infinity'::timestamptz);
  end if;

  return jsonb_build_object(
    'generated_at', v_to, 'min_count', k,
    'jevs_mode', coalesce(v_mode, 'shadow'),
    'last_24h', (
      select jsonb_build_object(
        'decisions', case when a.n + g.n between 1 and k - 1 then null else a.n + g.n end,
        'low', case when a.low + g.low between 1 and k - 1 then null else a.low + g.low end,
        'medium_waiting', case when a.medium_waiting between 1 and k - 1 then null else a.medium_waiting end,
        'high', case when a.high + g.high between 1 and k - 1 then null else a.high + g.high end,
        'high_held', case when a.high_held + g.high_held between 1 and k - 1 then null else a.high_held + g.high_held end,
        'appeals_open', (select case when c between 1 and k - 1 then null else c end
                         from (select count(distinct f.post_id) as c from app.review_flags f where f.source = 'appeal' and f.resolved_at is null) z))
      from (select count(*) as n,
                   count(*) filter (where d.level = 'low') as low,
                   count(*) filter (where d.level = 'medium' and d.effect = 'challenge' and d.applied) as medium_waiting,
                   count(*) filter (where d.level = 'high') as high,
                   count(*) filter (where d.level = 'high' and d.effect in ('hold', 'hide') and d.applied) as high_held
            from app.jevs_decisions d where d.created_at >= v_to - interval '24 hours' and d.created_at < v_to and d.action <> 'account.delete') a,
           (select count(*) as n,
                   count(*) filter (where x.risk = 'low') as low,
                   count(*) filter (where x.risk = 'high') as high,
                   count(*) filter (where x.risk = 'high' and x.effect = 'hide' and x.applied) as high_held
            from app.gh_decisions x where x.at >= v_to - interval '24 hours' and x.at < v_to) g),
    'high_7d', (
      with hi as (
        select h.*
        from (
          select (d.created_at at time zone 'UTC')::date as day,
                 case when d.action in ('post.create', 'post.approved', 'post.reported') and d.agent_id is not null then 'agent_post'
                      when d.action in ('post.create', 'post.approved', 'post.reported') then 'site_post'
                      when d.action = 'draft.create' then 'agent_draft'
                      when d.action in ('signup', 'account.check') then 'account'
                      else 'agent' end as place,
                 case when d.error then 'scoring_error'
                      when not d.applied then 'recorded_only'
                      when d.effect = 'hold' then 'held'
                      when d.effect = 'hide' then 'hidden'
                      when d.effect = 'queue' then 'queued'
                      when d.effect = 'challenge' then 'challenged'
                      else 'went_ahead' end as outcome,
                 d.scores
          from app.jevs_decisions d
          where d.level = 'high' and d.created_at >= v_to - interval '7 days' and d.created_at < v_to and d.action <> 'account.delete'
          union all
          select (x.at at time zone 'UTC')::date,
                 case when x.action in ('post.create', 'post.edit', 'post.approve', 'post.appeal') then 'github_post'
                      when x.action = 'account.first' then 'github_account'
                      else 'github_agent' end,
                 case when not x.applied then 'recorded_only'
                      when x.effect = 'hide' then 'hidden'
                      when x.effect = 'alert' then 'alerted'
                      else 'went_ahead' end,
                 x.scores
          from app.gh_decisions x
          where x.risk = 'high' and x.at >= v_to - interval '7 days' and x.at < v_to) h),
      grouped as (
        select hi.day, hi.place, hi.outcome, count(*) as n,
               coalesce((select jsonb_agg(q.id order by q.id)
                         from (select distinct e.key as id
                               from hi h2 cross join lateral jsonb_each(h2.scores) e
                               where h2.day = hi.day and h2.place = hi.place and h2.outcome = hi.outcome
                                 and e.key ~ '^J[0-9]{2}$' and jsonb_typeof(e.value) = 'number' and (e.value)::numeric >= 25) q),
                        '[]'::jsonb) as questions
        from hi group by hi.day, hi.place, hi.outcome
        union all
        select r.day, 'signup', 'declined', sum(r.declines)::bigint, '["region"]'::jsonb
        from app.region_declines r where r.day > (now() at time zone 'UTC')::date - 7
        group by r.day)
      select coalesce(jsonb_agg(jsonb_build_object('day', g.day, 'place', g.place, 'outcome', g.outcome, 'decisions', g.n,
                                                   'questions', g.questions) order by g.day desc, g.n desc, g.place, g.outcome), '[]'::jsonb)
      from (select * from grouped where n >= k order by day desc, n desc, place, outcome limit 30) g),
    'second_look', case when not v_sl then null else jsonb_build_object(
      'mode', v_sl_mode, 'paused', v_paused, 'agreed_in_a_row', coalesce(v_agreed, 0), 'needed', v_unlock,
      'daily_clear_cap', v_cap, 'shadow_clears_decided', (select count(*) from app.sl_outcomes),
      'shadow_clears_removed', (select count(*) from app.sl_outcomes o where not o.approved)) end,
    'oversight', jsonb_build_object(
      'people', (
        with decided as (
          -- One decision closes every open flag on its post at once (004, app.review_decide): one row per decision.
          select f.post_id, f.resolved_at, min(f.decision) as decision, min(f.created_at) as first_flag
          from app.review_flags f
          where f.resolved_by is not null and f.resolved_at >= v_to - interval '30 days' and f.resolved_at < v_to
          group by f.post_id, f.resolved_at)
        select jsonb_build_object(
          'd7', (select case when count(*) < k then jsonb_build_object('decided', case when count(*) = 0 then 0 end, 'approved', case when count(*) = 0 then 0 end,
                     'removed', case when count(*) = 0 then 0 end, 'undone', case when count(*) = 0 then 0 end, 'median_minutes', null)
                   else jsonb_build_object('decided', count(*),
                   'approved', case when count(*) filter (where x.decision in ('approve', 'keep')) between 1 and k - 1 then null else count(*) filter (where x.decision in ('approve', 'keep')) end,
                   'removed', case when count(*) filter (where x.decision = 'remove') between 1 and k - 1 then null else count(*) filter (where x.decision = 'remove') end,
                   'undone', case when count(*) filter (where x.decision = 'restore') between 1 and k - 1 then null else count(*) filter (where x.decision = 'restore') end,
                   'median_minutes', round((percentile_cont(0.5) within group (order by extract(epoch from x.resolved_at - x.first_flag)) / 60)::numeric, 0)) end
                 from decided x where x.resolved_at >= v_to - interval '7 days'),
          'd30', (select case when count(*) < k then jsonb_build_object('decided', case when count(*) = 0 then 0 end, 'approved', case when count(*) = 0 then 0 end,
                     'removed', case when count(*) = 0 then 0 end, 'undone', case when count(*) = 0 then 0 end, 'median_minutes', null)
                   else jsonb_build_object('decided', count(*),
                   'approved', case when count(*) filter (where x.decision in ('approve', 'keep')) between 1 and k - 1 then null else count(*) filter (where x.decision in ('approve', 'keep')) end,
                   'removed', case when count(*) filter (where x.decision = 'remove') between 1 and k - 1 then null else count(*) filter (where x.decision = 'remove') end,
                   'undone', case when count(*) filter (where x.decision = 'restore') between 1 and k - 1 then null else count(*) filter (where x.decision = 'restore') end,
                   'median_minutes', round((percentile_cont(0.5) within group (order by extract(epoch from x.resolved_at - x.first_flag)) / 60)::numeric, 0)) end
                 from decided x))),
      'queue', (
        select case when count(*) < k then jsonb_build_object('open', case when count(*) = 0 then 0 end, 'median_hours', null, 'oldest_hours', null)
               else jsonb_build_object('open', count(*),
                 'median_hours', round((percentile_cont(0.5) within group (order by extract(epoch from v_to - q.first_flag)) / 3600)::numeric, 0),
                 'oldest_hours', round((max(extract(epoch from v_to - q.first_flag)) / 3600)::numeric, 0)) end
        from (select f.post_id, min(f.created_at) as first_flag from app.review_flags f where f.resolved_at is null group by f.post_id) q))
  );
end
$$;
revoke execute on function app.public_decisions() from public;
grant execute on function app.public_decisions() to dog_app;

set local role dog_owner;
revoke create on schema app from dog_jevs;
