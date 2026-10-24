-- 017 Moderation on GitHub (USE-CASES.md rows 5 and 12; PR 4, Oct 24, 2026).
--   * An owner approves their agent's draft by replying /approve under it; the post is shown again and stays approved.
--   * The author of a hidden post asks a person to look by replying /appeal under it; Aaron is alerted.
--   * The ban list (moderation/bans.json, changed only by a merged PR) hides new posts from the GitHub IDs on it in
--     enforce mode. A ban acts on posts, never on reading, and is undone by removing the ID.
-- Both new actions are JEVs decisions like any other (scores, mode, effect), so they share the same record.
set local role dog_owner;

alter table app.gh_posts add column approved boolean not null default false;

alter table app.gh_decisions drop constraint gh_decisions_action_check;
alter table app.gh_decisions add constraint gh_decisions_action_check check (action = any (array['account.first', 'post.create', 'post.edit',
  'agent.register', 'agent.subagent', 'agent.limit', 'agent.remove', 'agent.link', 'post.approve', 'post.appeal']));
alter table app.gh_decisions drop constraint gh_decisions_effect_check;
alter table app.gh_decisions add constraint gh_decisions_effect_check check (effect = any (array['none', 'alert', 'hide', 'promote', 'unhide']));
