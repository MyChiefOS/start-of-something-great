-- 021 New members start at level 1 at most; only JEVs makes a member level 2 (RISKS.md RK82; Oct 26, 2026).
--   Before this, app.sign_in and app.identity_link took the starting level from their caller (0 to 2,
--   012_signin_fixes.sql), so whoever held the site's database login could make a member at level 2, who may own
--   agents, by just asking. Now a trigger applies the cap (phase 1: 1) to every level written to
--   app.identities and to every new member, whichever function or role writes it. A higher level is lowered, never
--   refused, so the person still signs in (checks alert, never lock out), and the audit log records
--   'signup.level_capped' for Aaron to see. Level 2 then comes only from JEVs's own promotion (jevs_level2_at, 010).
--   The cap changes only by a migration.
--   NOT done here, on purpose:
--     * GitHub-only (Aaron, Oct 23) stays in the site's code. In the database it would add nothing: the database can't
--       tell a real GitHub sign-in from a made-up one, so a forged caller would simply say "github".
--     * The regional decline stays in the site's code (signin/region.js): the database can't know where a request
--       came from. Both are recorded in RK82.
set local role dog_owner;

-- The cap is the constant 1 in both triggers below. A migration changes it by replacing them; nothing else can, and
-- there is no table for the site to read.
-- Runs as whoever writes the row (not a definer): in production that is dog_signin, inside app.sign_in or
-- app.identity_link.
create function app.identities_level_cap() returns trigger
language plpgsql set search_path = pg_catalog as $$
declare
  cap constant smallint := 1; -- phase 1's cap
begin
  if new.level > cap then
    insert into app.audit_log (action, subject_kind, subject_id, detail)
      values ('signup.level_capped', 'member', new.member_id,
              jsonb_build_object('provider', new.provider, 'asked', new.level, 'given', cap));
    new.level := cap;
  end if;
  return new;
end
$$;

create function app.members_level_cap() returns trigger
language plpgsql set search_path = pg_catalog as $$
declare
  cap constant smallint := 1; -- phase 1's cap, as above
begin
  if new.trust_level > cap then
    new.trust_level := cap;
  end if;
  return new;
end
$$;

revoke execute on function app.identities_level_cap(), app.members_level_cap() from public;

create trigger identities_level_cap before insert or update of level on app.identities
  for each row execute function app.identities_level_cap();
-- Only a new member's starting level: later raises come from app.verified_level (capped identities, or JEVs).
create trigger members_level_cap before insert on app.members
  for each row execute function app.members_level_cap();
