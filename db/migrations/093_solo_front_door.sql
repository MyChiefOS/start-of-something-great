-- 093 The SOLO front door (PR D; Aaron's roadmap Phase 3).
-- A new once-a-day threat feed is read on its first run, at any hour (Agent C, Nov 26: PhishTank and ESET, new in 086,
-- had only ever met an afternoon run, so the active version held none of either). The wiki job asks which feeds the
-- active version holds; public facts already shown on /security, read-only.
grant create on schema app to dog_work;
set local role dog_work;
create function app.wiki_held_sources() returns text[]
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce(array_agg(distinct i.source order by i.source), '{}')
    from app.wiki_indicators i join app.wiki_versions v on v.id = i.version_id where v.status = 'active'
$$;
revoke execute on function app.wiki_held_sources() from public;
grant execute on function app.wiki_held_sources() to dog_app;
reset role;
revoke create on schema app from dog_work;
