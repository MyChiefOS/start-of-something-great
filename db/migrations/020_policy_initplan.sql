-- 020 Every policy asks who is acting once per query, not once per row (fix 3's review, finding 2; Oct 26, 2026).
--   Since 019 the check of who is acting tests a stamp (a SHA-256 and a key read). A policy that calls
--   app.actor_kind() asks again for every row it looks at: an administrator counting 10,000 posts took 1.5 s instead of
--   4 ms (measured by the review, Postgres 16). Who is acting can't change within a transaction, so each call is
--   written as a sub-select, "(select app.actor_kind())", which Postgres runs once per query and reuses (an InitPlan).
--   The policies mean exactly what they meant; only when the answer is worked out changes. The five functions are the
--   ones the policies call with no arguments, each fixed for the whole transaction: app.actor_kind, app.current_member,
--   app.current_agent, app.current_actor_id and app.is_reviewer.
set local role dog_owner;
-- Postgres prints a function without its schema when that schema is on the search path, which would leave nothing for
-- the rewrite below to find (PR #49 review). Pinned, every call prints as app.actor_kind() and so on.
set local search_path = pg_catalog;

do $$
declare
  p record;
  fns constant text := '(\mapp\.(actor_kind|current_member|current_agent|current_actor_id|is_reviewer)\(\))';
  q text;
  c text;
begin
  for p in
    select pol.polname, cls.relname, pg_get_expr(pol.polqual, pol.polrelid) as qual, pg_get_expr(pol.polwithcheck, pol.polrelid) as chk
    from pg_policy pol join pg_class cls on cls.oid = pol.polrelid join pg_namespace n on n.oid = cls.relnamespace
    where n.nspname = 'app'
  loop
    -- Wrap each call that isn't already a sub-select.
    q := regexp_replace(p.qual, '(?<!SELECT )' || fns, '(SELECT \1)', 'g');
    c := regexp_replace(p.chk, '(?<!SELECT )' || fns, '(SELECT \1)', 'g');
    if q is distinct from p.qual then
      execute format('alter policy %I on app.%I using (%s)', p.polname, p.relname, q);
    end if;
    if c is distinct from p.chk then
      execute format('alter policy %I on app.%I with check (%s)', p.polname, p.relname, c);
    end if;
  end loop;
end
$$;

-- Nothing is left asking per row (a policy that still did would fail this migration, and nothing would change).
do $$
declare n integer;
begin
  select count(*) into n
  from pg_policy pol join pg_class cls on cls.oid = pol.polrelid join pg_namespace s on s.oid = cls.relnamespace
  where s.nspname = 'app'
    and (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') ~ '(?<!SELECT )\mapp\.(actor_kind|current_member|current_agent|current_actor_id|is_reviewer)\(\)'
      or coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') ~ '(?<!SELECT )\mapp\.(actor_kind|current_member|current_agent|current_actor_id|is_reviewer)\(\)');
  if n > 0 then
    raise exception '% policies still ask who is acting once per row', n;
  end if;
end
$$;
