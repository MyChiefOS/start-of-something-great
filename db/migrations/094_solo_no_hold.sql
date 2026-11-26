-- 094: solo work isn't held for being new (Aaron, Nov 24, 2026: "I don't want blockers for the agent and subagent";
-- Nov 26: "SOLO would have its own path without blockers. As long as the code or what the Agent is not malware").
-- The live proof on Nov 26 found every pass between two solo agents waited for an administrator, because agent
-- accounts are below level 2 by birth. Only that reason changes; contact details, the largest size and a burst still
-- hold, and nothing about people's work changes.
grant create on schema app to dog_work;
set local role dog_work;

create or replace function app.work_risks(p_sub uuid, p_poster uuid, p_size smallint)
returns text
language plpgsql stable security definer set search_path = pg_catalog
as $$
declare
  s record;
  st record;
  wm uuid;
  why text[] := '{}';
begin
  select * into s from app.work_submissions x where x.id = p_sub;
  -- The worker as a person: the member, or the owner of the agent that did it.
  wm := coalesce(s.worker_member, (select g.owner_id from app.agents g where g.id = s.worker_agent));
  select * into st from app.work_settings where singleton;
  -- Unknown to the site (a deleted account, or a GitHub account with no member) counts as below the level.
  -- 094 (Aaron, Nov 24: solo agents and sub-agents work without blockers): when both sides are agent accounts (the
  -- solo track, 079), being new is not a reason to hold. Their levels don't rise from each other's passes (092 part 3),
  -- the pair watch and random checks still look after, and the Wall and JEVs still refuse malware before this point.
  if not (app.is_agent_account(p_poster) and app.is_agent_account(wm))
     and (coalesce((select m.trust_level from app.members m where m.id = p_poster), 0) < st.poster_level
     or coalesce((select m.trust_level from app.members m where m.id = wm), 0) < st.poster_level) then
    why := why || ('the poster or the worker isn''t yet at JEVs''s level ' || st.poster_level);
  end if;
  if s.note_hits > 0 then why := why || 'the note had contact details, hidden'::text; end if;
  if p_size = 8 then why := why || 'it is the largest size'::text; end if;
  -- Spam: a burst of work from one worker, in the hour before this piece was sent (waiting to check doesn't hide it).
  if (select count(*) from app.work_submissions x where x.created_at > s.created_at - interval '1 hour' and x.created_at <= s.created_at
        and coalesce(x.worker_member, (select g.owner_id from app.agents g where g.id = x.worker_agent)) = wm) > st.burst_hourly then
    why := why || ('this worker sent more than ' || st.burst_hourly || ' pieces of work in an hour');
  end if;
  return case when cardinality(why) = 0 then null else array_to_string(why, '; ') end;
end
$$;

reset role;
revoke create on schema app from dog_work;
