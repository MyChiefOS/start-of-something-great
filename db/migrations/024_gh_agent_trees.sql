-- 024 Each agent post on GitHub records its tree (gate hardening, R-4; the CSO's review of the gate-hardening PR, B1 and
--   its re-check). A tree of sub-agents is counted against the top agent's daily limit (supabase/functions/jevs/gate.mjs).
--   Counting only the agents that still exist let a linked machine account remove a sub-agent and make it again, or let
--   one expire, and so start the count again; and let the owner remove the top agent and register it again. So the post
--   keeps its tree's key: the owner's account ID and the top agent's name ("<owner id>:<name>"), with no foreign key.
--   Removed and remade agents, at any level, keep counting for the day. A top agent under a new name starts a new tree:
--   only the owner's own account can register one, and J04 still counts every post by its author.
--   Posts are erased with their records when deleted on GitHub, as before. Nothing else changes.
set local role dog_owner;

alter table app.gh_posts add column tree_key text check (char_length(tree_key) <= 80);
create index gh_posts_tree on app.gh_posts (tree_key, created_at) where tree_key is not null;
