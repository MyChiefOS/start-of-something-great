-- 023 Sessions last a flat 30 days (Aaron, Oct 28, 2026: "it will last 30 days"; harness/FACTS.md).
--   app.act_as is 019's, except that an unused session now lasts 30 days, not 7: the same as its absolute limit and as
--   signin/config.js IDLE_DAYS (a test keeps the two the same). It stays the sign-in role's, so it is replaced as that
--   role, which dog_owner may act as (002), with the right to create in the schema for these lines only (as in 021).
set local role dog_owner;
grant create on schema app to dog_signin;
set local role dog_signin;
create or replace function app.act_as(p_actor text, p_member uuid, p_agent uuid, p_fresh boolean, p_session text, p_key text, p_system text)
returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  a text := 'anon'; m text := ''; ag text := ''; f text := ''; s text := '';
  sm uuid; sadmin boolean; sfresh boolean; km uuid; ka uuid;
begin
  if p_actor in ('member', 'admin') then
    select r.member_id, r.is_admin, r.fresh into sm, sadmin, sfresh from app.session_resolve(p_session, 30) r;
    if sm is null or sm is distinct from p_member or (p_actor = 'admin' and not sadmin) then
      raise exception 'not_acting' using errcode = '42501';
    end if;
    a := p_actor; m := sm::text; s := p_session; f := case when p_fresh and sfresh then '1' else '' end;
  elsif p_actor = 'agent' then
    select r.agent_id, r.owner_id into ka, km from app.agent_resolve(p_key) r;
    if ka is null or ka is distinct from p_agent or km is distinct from p_member then
      raise exception 'not_acting' using errcode = '42501';
    end if;
    a := 'agent'; m := km::text; ag := ka::text;
  elsif p_actor = 'system' then
    if p_system is null or p_system = '' or not exists (select 1 from app.actor_keys k
         where k.singleton and k.system_hash is not null and k.system_hash = sha256(convert_to(p_system, 'UTF8'))) then
      raise exception 'not_acting' using errcode = '42501';
    end if;
    a := 'system';
  elsif p_actor is distinct from 'anon' then
    raise exception 'not_acting' using errcode = '42501';
  end if;
  perform set_config('app.actor', a, true), set_config('app.member_id', m, true), set_config('app.agent_id', ag, true),
          set_config('app.fresh', f, true), set_config('app.session', s, true);
  perform set_config('app.stamp', case when a = 'anon' then '' else app.actor_stamp(a, m, ag, f, s) end, true);
  return a;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_signin;
