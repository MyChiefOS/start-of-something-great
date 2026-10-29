-- 024 Each agent post on GitHub records its tree's top agent (gate hardening, R-4; the CSO's review of the gate-hardening
--   PR, B1). A tree of sub-agents is counted against the top agent's daily limit (supabase/functions/jevs/gate.mjs).
--   Counting only the agents that still exist let a linked machine account remove a sub-agent and make it again, or let
--   one expire, and so start the count again. The top agent's ID is kept on the post itself, with no foreign key, so a
--   removed sub-agent's posts still count for the day. When the top agent itself is removed, its posts keep the ID,
--   which then names nothing; making a new top agent needs the owner's own account (gate.mjs).
--   Posts are erased with their records when deleted on GitHub, as before. Nothing else changes.
set local role dog_owner;

alter table app.gh_posts add column top_agent_id uuid;
create index gh_posts_top_agent on app.gh_posts (top_agent_id, created_at) where top_agent_id is not null;
