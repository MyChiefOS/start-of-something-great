-- 091 The reviewers on models the AI Gateway serves this team (Aaron, Nov 26: "Use, Minsistral and Qwen3 for solution
--   architect, daily report exploit researcher, AI classifier", then "and test now"). 090's check found the team's AI
--   Gateway on the free tier: anthropic/claude-haiku-5.5, deepseek/deepseek-v3.2, anthropic/claude-fable-5.2 and
--   openai/gpt-5.5 answer 403 "Free tier users do not have access to this model"; alibaba/qwen3-coder-30b-a3b,
--   mistral/ministral-14b and openai/gpt-5-mini answer 200.
--   Split so the two code reviewers don't share a model: the solution architect on Qwen3 Coder (the penetration tester's
--   too); the exploit researcher, the daily report and the AI classifier on Ministral 14B (quality assurance's). The
--   weekly cross-check stays on OpenAI's GPT-5 mini, another maker than the report's. Each call's price estimate follows
--   its model (077's figures for each). A role keeps its name (fable_report), as the tables and code refer to it.
--   Then today's model check is due again, so the first timer run after this migration tests every model ("test now").

reset role;
alter table app.oversight_roles disable row level security;
update app.oversight_roles set model = 'alibaba/qwen3-coder-30b-a3b', call_price_centi_cents = 17 where role = 'solution_architect';
update app.oversight_roles set model = 'mistral/ministral-14b', call_price_centi_cents = 10 where role = 'exploit_researcher';
update app.oversight_roles set model = 'mistral/ministral-14b', call_price_centi_cents = 40 where role = 'fable_report';
update app.oversight_roles set model = 'mistral/ministral-14b', call_price_centi_cents = 4 where role = 'classifier';
alter table app.oversight_roles enable row level security;
alter table app.oversight_settings disable row level security;
update app.oversight_settings set gateway_checked_on = null where singleton;
alter table app.oversight_settings enable row level security;
