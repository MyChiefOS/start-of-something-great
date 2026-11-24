-- 078 An agent declares its own task's scope (found by the end-to-end test of Nov 24: sign up, claim, work over MCP).
--   073 compared the task's poster with the acting member, but a task an agent posts names only the agent (042), so an
--   agent's scope was refused ("only the task's poster declares its scope") and, through the API, its task with it.
--   The same function, comparing the poster as 042 records it.

grant create on schema app to dog_work;
set local role dog_work;
create or replace function app.work_task_scope_put(p_task uuid, p_scope jsonb) returns integer
language plpgsql security definer set search_path = pg_catalog as $$
declare
  w record;
  t record;
  e record;
  n integer := 0;
begin
  select * into w from app.work_who();
  select * into t from app.work_tasks x where x.id = p_task;
  if t.id is null then raise exception 'no such task' using errcode = 'P0002'; end if;
  -- A task an agent posted names the agent and no member (042, work_task_create); one a person posted, the person.
  if t.poster_member is distinct from (case when w.agent_id is null then w.member_id end) or t.poster_agent is distinct from w.agent_id then
    raise exception 'only the task''s poster declares its scope' using errcode = '42501';
  end if;
  if t.status <> 'open' or exists (select 1 from app.work_claims c where c.task_id = p_task) then
    raise exception 'work_scope_fixed' using errcode = 'P0001', hint = 'A task''s scope is set when it is posted, before anyone claims it.';
  end if;
  if p_scope is null or jsonb_typeof(p_scope) <> 'object' or exists (select 1 from jsonb_object_keys(p_scope) k where k <> all (array['paths', 'dependencies', 'hosts'])) then
    raise exception 'bad scope' using errcode = '22023';
  end if;
  for e in select case k when 'paths' then 'path' when 'dependencies' then 'dependency' else 'host' end as kind, v #>> '{}' as value
             from jsonb_each(p_scope) as j(k, a), jsonb_array_elements(case when jsonb_typeof(a) = 'array' then a else '[]'::jsonb end) v loop
    if e.value is null or char_length(e.value) not between 1 and 200 or e.value ~ '[[:space:]]' then raise exception 'bad scope' using errcode = '22023'; end if;
    n := n + 1;
    if n > 50 then raise exception 'bad scope' using errcode = '22023', hint = 'At most 50 entries.'; end if;
    insert into app.work_task_scope (task_id, kind, value) values (p_task, e.kind, e.value) on conflict do nothing;
  end loop;
  return n;
end $$;
reset role;
revoke create on schema app from dog_work;
