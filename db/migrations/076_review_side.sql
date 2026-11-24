-- 076 The review side of the check design (Aaron, Nov 24: the diagram's JEVs final score, CSO lanes A and B, the daily
--   digest, person decides, and quality assurance re-routing verified false positives).
--
--   1. The final score (Aaron: "change the JEVs Final Score to 70%"): for each submission, from facts only, 100 less
--      what the checks found (Second Look rejected its note: 40; Third Look left it to a person: 20; an open dispute: 20;
--      a watchtower alert on its worker today: 20), and capped at 69 while the Agentic Wall's flag on it is unreviewed.
--      70 or more is the pass line. The score advises: it changes no verdict and no points.
--   2. Lane A: the Wall's flags no one has reviewed. Lane B: work of the last 7 days scoring under 70. Administrators see
--      both on the work queue (GET /api/work/admin, "lanes").
--   3. The daily digest: one notice a day to the administrators, grouped (lane A by rule, lane B by reason), not one
--      notice per item. Incidents alert at once: a flag for a credential in content (W11), an internal or metadata
--      address (W22) or recon material (W13).
--   4. Quality assurance: an administrator marks a Wall flag a verified false positive or confirmed, with a reason
--      (POST /api/work/wall/review). A false positive leaves lane A and lifts the cap; nothing else changes, because in
--      shadow mode nothing was held. Each review is kept, so the rules' false positives can be counted.
--   Not built here: holding work (the Wall's enforce mode). The verdict function records points in the same step that
--   passes work (042), so a hold has to be built into that step, carefully, in its own pull request.

set local role dog_owner;

create table app.wall_reviews (
  id uuid primary key default app.uuid_v7(),
  decision_id uuid not null unique references app.wall_decisions (id) on delete cascade,
  verdict text not null check (verdict = any (array['false_positive', 'confirmed'])),
  reason text not null check (char_length(reason) between 3 and 300),
  reviewed_by uuid references app.members (id) on delete set null,
  created_at timestamptz not null default now()
);
alter table app.wall_reviews enable row level security;
alter table app.wall_reviews force row level security;
create policy wall_reviews_work on app.wall_reviews for all to dog_work using (true) with check (true);
create policy wall_reviews_owner on app.wall_reviews for select to dog_owner using (true);
grant select, insert on app.wall_reviews to dog_work;

create table app.lanes_settings (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  pass_line integer not null default 70 check (pass_line between 1 and 100),
  digest_last_day date,
  -- The digest goes out at or after this hour, UTC (13:00 UTC is morning in the US), so a day's work is in it.
  digest_hour integer not null default 13 check (digest_hour between 0 and 23),
  incidents_checked_at timestamptz not null default now()
);
insert into app.lanes_settings (singleton) values (true);
alter table app.lanes_settings enable row level security;
alter table app.lanes_settings force row level security;
create policy lanes_settings_work on app.lanes_settings for all to dog_work using (true) with check (true);
create policy lanes_settings_owner on app.lanes_settings for select to dog_owner using (true);
grant select, update on app.lanes_settings to dog_work;
reset role;

grant create on schema app to dog_work;
set local role dog_work;

-- The final score of one submission, with its reasons. Facts only; no model.
create function app.work_final_score(p_sub uuid) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  s record;
  score integer := 100;
  why jsonb := '[]'::jsonb;
  line integer;
  wall boolean;
begin
  select x.id, x.task_id, x.pr_number, x.worker_member, x.worker_agent into s from app.work_submissions x where x.id = p_sub;
  if s.id is null then return null; end if;
  select r.pass_line into line from app.lanes_settings r where r.singleton;
  if exists (select 1 from app.sl_items i where i.kind = 'submission' and i.ref = p_sub and i.decision = 'reject') then
    score := score - 40; why := why || '["Second Look rejected its note"]';
  end if;
  if exists (select 1 from app.tl_reviews r where r.submission_id = p_sub and r.suggestion = 'person') then
    score := score - 20; why := why || '["Third Look left it to a person"]';
  end if;
  if exists (select 1 from app.work_disputes d where d.submission_id = p_sub and d.status = 'open') then
    score := score - 20; why := why || '["an open dispute"]';
  end if;
  if exists (select 1 from app.notices n where n.member_id is null and n.dedupe_key like 'watchtower:%:'
               || coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent))::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD')) then
    score := score - 20; why := why || '["a watchtower alert on its worker today"]';
  end if;
  wall := exists (select 1 from app.wall_decisions d where d.decision = 'hold' and d.kind in ('submission', 'pr_files') and d.ref = p_sub
                   and not exists (select 1 from app.wall_reviews w where w.decision_id = d.id and w.verdict = 'false_positive'));
  if wall then why := why || '["an unreviewed Agentic Wall flag (capped below the line)"]'; score := least(score, line - 1); end if;
  return jsonb_build_object('score', greatest(score, 0), 'pass_line', line, 'passes', greatest(score, 0) >= line, 'reasons', why);
end $$;

-- Lanes A and B, for an administrator.
create function app.review_lanes() returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator reads the lanes' using errcode = '42501'; end if;
  return jsonb_build_object(
    'a', coalesce((select jsonb_agg(jsonb_build_object('decision', d.id, 'kind', d.kind, 'ref', d.ref, 'flags', d.flags, 'mode', d.mode, 'at', d.created_at)
                    order by d.created_at desc) from (select * from app.wall_decisions x where x.decision = 'hold'
                    and not exists (select 1 from app.wall_reviews w where w.decision_id = x.id) order by x.created_at desc limit 100) d), '[]'::jsonb),
    'b', coalesce((select jsonb_agg(jsonb_build_object('submission', z.id, 'task', z.task_id, 'status', z.status) || app.work_final_score(z.id) order by z.created_at desc)
                    from (select x.id, x.task_id, x.status, x.created_at from app.work_submissions x where x.created_at > now() - interval '7 days'
                          order by x.created_at desc limit 500) z
                   where (app.work_final_score(z.id) ->> 'passes')::boolean is false), '[]'::jsonb));
end $$;

-- Quality assurance on one flag.
create function app.wall_review(p_decision uuid, p_verdict text, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare w record;
begin
  if app.actor_kind() <> 'admin' then raise exception 'only an administrator reviews the Wall''s flags' using errcode = '42501'; end if;
  select * into w from app.work_who();
  if p_verdict is null or p_verdict <> all (array['false_positive', 'confirmed']) or p_reason is null or char_length(btrim(p_reason)) not between 3 and 300 then
    raise exception 'bad review' using errcode = '22023';
  end if;
  if not exists (select 1 from app.wall_decisions d where d.id = p_decision and d.decision = 'hold') then
    raise exception 'no such flag' using errcode = 'P0002';
  end if;
  if exists (select 1 from app.wall_reviews r where r.decision_id = p_decision) then
    raise exception 'work_wall_reviewed' using errcode = 'P0001', hint = 'This flag was already reviewed.';
  end if;
  insert into app.wall_reviews (decision_id, verdict, reason, reviewed_by) values (p_decision, p_verdict, btrim(p_reason), w.member_id);
  perform app.audit_add('wall_review', 'wall_decision', p_decision, jsonb_build_object('verdict', p_verdict));
  return p_verdict;
end $$;

-- The timer: incidents at once, and the digest once a day.
create function app.review_digest_run() returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  d record;
  n integer := 0;
  a_total integer;
  a_groups text;
  b_total integer;
  b_groups text;
  today date := (now() at time zone 'UTC')::date;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer sends the review digest' using errcode = '42501';
  end if;
  select * into s from app.lanes_settings x where x.singleton for update;
  for d in select x.id, x.kind, x.flags from app.wall_decisions x
            where x.decision = 'hold' and x.created_at > s.incidents_checked_at
              and exists (select 1 from jsonb_array_elements_text(x.flags) f where split_part(f, ' ', 1) = any (array['W11', 'W22', 'W13']))
            order by x.created_at limit 20 loop
    if app.notify(null, 'alert', 'Incident: the Agentic Wall flagged a ' || d.kind, left(d.flags::text, 300) || ' Review it in lane A.', '/admin',
                  'wall_decision', d.id, 'wall:incident:' || d.id) then
      n := n + 1;
    end if;
  end loop;
  update app.lanes_settings x set incidents_checked_at = now() where x.singleton;
  if (s.digest_last_day is not null and s.digest_last_day >= today) or extract(hour from now() at time zone 'UTC') < s.digest_hour then return n; end if;
  update app.lanes_settings x set digest_last_day = today where x.singleton;
  select count(*), string_agg(g.code || ' ' || g.c, ', ' order by g.c desc, g.code) into a_total, a_groups
    from (select split_part(f, ' ', 1) as code, count(*) as c from app.wall_decisions x, jsonb_array_elements_text(x.flags) f
           where x.decision = 'hold' and x.created_at > now() - interval '1 day'
             and not exists (select 1 from app.wall_reviews w where w.decision_id = x.id) group by 1) g;
  select coalesce(sum(g.c), 0), string_agg(g.r || ' ' || g.c, ', ' order by g.c desc, g.r) into b_total, b_groups
    from (select r as r, count(*) as c from (select x.id, app.work_final_score(x.id) as sc from app.work_submissions x where x.created_at > now() - interval '1 day') z,
           jsonb_array_elements_text(z.sc -> 'reasons') r where (z.sc ->> 'passes')::boolean is false group by 1) g;
  a_total := (select count(*) from app.wall_decisions x where x.decision = 'hold' and x.created_at > now() - interval '1 day'
                and not exists (select 1 from app.wall_reviews w where w.decision_id = x.id));
  b_total := (select count(*) from app.work_submissions x where x.created_at > now() - interval '1 day' and (app.work_final_score(x.id) ->> 'passes')::boolean is false);
  if a_total + b_total > 0 and app.notify(null, 'alert', 'Daily review digest: ' || a_total || ' in lane A, ' || b_total || ' in lane B',
       'Lane A (the Agentic Wall''s unreviewed flags, last 24 hours): ' || coalesce(a_groups, 'none') || '. Lane B (work under the 70% line, last 24 hours): '
       || coalesce(b_groups, 'none') || '. Nothing was held.', '/admin', null, null, 'review:digest:' || today) then
    n := n + 1;
  end if;
  return n;
end $$;

revoke execute on function app.work_final_score(uuid), app.review_lanes(), app.wall_review(uuid, text, text), app.review_digest_run() from public;
grant execute on function app.work_final_score(uuid), app.review_lanes(), app.wall_review(uuid, text, text), app.review_digest_run() to dog_app;
reset role;
revoke create on schema app from dog_work;
