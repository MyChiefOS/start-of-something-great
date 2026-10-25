// Prototype for fix 3 (harness/PLAN.md): the database rejects a "who is acting" setting it didn't stamp itself.
// Throwaway database only: it creates one on a local Postgres, runs the real migrations, makes a real member and
// session with the real sign-in function, tries the attacks, and drops the database. Never point it at production.
// Run: pg_ctlcluster 16 main start; npm ci --ignore-scripts; node test/prototypes/actor-stamp.js
// Result on Oct 25, 2026 (Postgres 16): 10 of 10 checks pass; 41 microseconds per check, forced once per row.
'use strict';
const REPO = process.argv[2] || require('path').join(__dirname, '..', '..');
const postgres = require(REPO + '/node_modules/postgres');
const { migrate } = require(REPO + '/scripts/migrate');
const signin = require(REPO + '/db/signin');
const crypto = require('crypto');
const ADMIN = 'postgres://postgres@localhost/postgres';
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };

(async () => {
  const admin = postgres(ADMIN, { max: 1, onnotice: () => {} });
  const name = 'proto_stamp_' + crypto.randomBytes(3).toString('hex');
  await admin.unsafe('create database ' + name);
  const url = ADMIN.replace(/\/postgres$/, '/' + name);
  const sql = postgres(url, { max: 1, prepare: false, onnotice: () => {} });
  try {
    await migrate(sql);
    // The site's login, as the setup script made it: no rights of its own, may become dog_app.
    await sql.unsafe("do $$ begin if not exists (select 1 from pg_roles where rolname='dog_web') then create role dog_web login noinherit password 'proto-only'; end if; end $$");
    await sql.unsafe('grant dog_app to dog_web');
    await sql.unsafe('grant connect on database ' + name + ' to dog_web');

    await sql.unsafe("create extension if not exists pgcrypto with schema public");
    // ---- The prototype: a stamp key only the database's own functions can read (stands in for Vault) ----
    await sql.unsafe(`
      create table app.actor_stamp_key (k bytea not null);
      alter table app.actor_stamp_key enable row level security; alter table app.actor_stamp_key force row level security;
      alter table app.actor_stamp_key owner to dog_owner;
      create policy actor_stamp_key_owner on app.actor_stamp_key for select to dog_owner using (true);
      insert into app.actor_stamp_key values (public.gen_random_bytes(32));
      create function app.actor_stamp(p_actor text, p_member text, p_agent text, p_fresh text) returns text
        language sql stable security definer set search_path = pg_catalog as $f$
          select encode(public.hmac(convert_to(p_actor||'|'||p_member||'|'||p_agent||'|'||p_fresh||'|'||txid_current()::text, 'UTF8'),
                                    (select k from app.actor_stamp_key), 'sha256'), 'hex') $f$;
      alter function app.actor_stamp(text, text, text, text) owner to dog_owner;
      revoke execute on function app.actor_stamp(text, text, text, text) from public;
      -- The only way in: from a session hash the database looks up itself.
      create function app.act_as_session(p_session_hash text) returns text
        language plpgsql security definer set search_path = pg_catalog as $f$
        declare r record; a text; f text;
        begin
          select * into r from app.session_resolve(p_session_hash, 7);
          if r.member_id is null then a := 'anon'; perform set_config('app.member_id', '', true); f := '';
          else a := case when r.is_admin then 'admin' else 'member' end; perform set_config('app.member_id', r.member_id::text, true);
               f := case when r.fresh then '1' else '' end; end if;
          perform set_config('app.actor', a, true); perform set_config('app.agent_id', '', true); perform set_config('app.fresh', f, true);
          perform set_config('app.stamp', app.actor_stamp(a, current_setting('app.member_id', true), '', f), true);
          return a;
        end $f$;
      alter function app.act_as_session(text) owner to dog_owner;
      grant execute on function app.session_resolve(text, integer) to dog_owner;
      grant execute on function app.act_as_session(text) to dog_app;
      -- The checks every policy uses: a setting without a matching stamp counts as nobody.
      create function app.stamp_ok() returns boolean language sql stable security definer set search_path = pg_catalog as $f$
        select coalesce(current_setting('app.stamp', true), '') <> '' and current_setting('app.stamp', true) =
          app.actor_stamp(coalesce(current_setting('app.actor', true), ''), coalesce(current_setting('app.member_id', true), ''),
                          coalesce(current_setting('app.agent_id', true), ''), coalesce(current_setting('app.fresh', true), '')) $f$;
      alter function app.stamp_ok() owner to dog_owner;
      grant execute on function app.stamp_ok() to dog_app;
      create function app.actor_kind_each(g int) returns text language plpgsql volatile as $f$ begin return app.actor_kind(); end $f$;
      grant execute on function app.actor_kind_each(int) to dog_app;
      create or replace function app.actor_kind() returns text language sql stable parallel safe as $f$
        select case when app.stamp_ok() then coalesce(nullif(current_setting('app.actor', true), ''), 'anon') else 'anon' end $f$;
    `);

    // A real member and session, made by the real sign-in function (as the site would, through dog_app).
    const tokenHash = crypto.randomBytes(32).toString('hex');
    await sql.begin(async (t) => {
      await t`set local role dog_app`;
      await t`select set_config('app.actor', 'anon', true)`;
      await signin.signIn(t, { provider: 'github', fingerprints: [crypto.randomBytes(32).toString('hex')], keyVersion: 1, level: 1,
        displayName: 'Proto', sessionHash: tokenHash, sessionDays: 30 });
    }).catch(async (e) => { console.log('note: sign-in through dog_app needs the site path:', e.message.slice(0, 120)); throw e; });
    const [m] = await sql`select member_id from app.sessions where token_hash = ${tokenHash}`;
    ok(Boolean(m), 'a real member and session exist, made by app.sign_in');
    await sql`update app.members set is_admin = false where id = ${m.member_id}`;

    // Connect as the site's login, the way the site would.
    const web = postgres(url.replace('postgres@', 'dog_web:proto-only@'), { max: 1, prepare: false, onnotice: () => {} });
    const asWeb = (fn) => web.begin(async (t) => { await t`set local role dog_app`; return fn(t); });

    // 1. The attack: the site's login declares itself the administrator, as db/index.js can today.
    const forged = await asWeb(async (t) => {
      await t`select set_config('app.actor', 'admin', true), set_config('app.member_id', ${m.member_id}, true)`;
      return (await t`select app.actor_kind() as k`)[0].k;
    });
    ok(forged === 'anon', 'forged "admin" setting is treated as nobody (got: ' + forged + ')');

    // 2. Forging the stamp too: copying a stamp field without the key.
    const forged2 = await asWeb(async (t) => {
      await t`select set_config('app.actor', 'admin', true), set_config('app.stamp', ${'0'.repeat(64)}, true)`;
      return (await t`select app.actor_kind() as k`)[0].k;
    });
    ok(forged2 === 'anon', 'a made-up stamp is rejected (got: ' + forged2 + ')');

    // 3. The key can't be read by the site's role.
    const read = await asWeb((t) => t`select count(*)::int as n from app.actor_stamp_key`).catch((e) => 'refused: ' + e.code);
    ok(String(read).startsWith('refused') || (read[0] && read[0].n === 0), 'the stamp key is unreadable to the site (' + JSON.stringify(read) + ')');

    // 4. The honest path: a real session gives the real member, decided by the database.
    const honest = await asWeb(async (t) => {
      const a = (await t`select app.act_as_session(${tokenHash}) as a`)[0].a;
      const [r] = await t`select app.actor_kind() as k, app.current_member() as m`;
      return { a, k: r.k, m: r.m };
    });
    ok(honest.k === 'member' && honest.m === m.member_id, 'a real session acts as its member (' + JSON.stringify(honest) + ')');

    // 5. Upgrading a stamped member to admin by editing the setting breaks the stamp.
    const upgrade = await asWeb(async (t) => {
      await t`select app.act_as_session(${tokenHash})`;
      await t`select set_config('app.actor', 'admin', true)`;
      return (await t`select app.actor_kind() as k`)[0].k;
    });
    ok(upgrade === 'anon', 'editing a stamped actor to admin is rejected (got: ' + upgrade + ')');

    // 6. Replay: a stamp from one transaction doesn't work in the next.
    const stamp = await asWeb(async (t) => { await t`select app.act_as_session(${tokenHash})`; return (await t`select current_setting('app.stamp') as s`)[0].s; });
    const replay = await asWeb(async (t) => {
      await t`select set_config('app.actor', 'member', true), set_config('app.member_id', ${m.member_id}, true), set_config('app.agent_id', '', true), set_config('app.fresh', '', true), set_config('app.stamp', ${stamp}, true)`;
      return (await t`select app.actor_kind() as k`)[0].k;
    });
    ok(replay === 'anon', 'a stamp copied from an earlier transaction is rejected (got: ' + replay + ')');

    // 7. A forged "fresh sign-in" can't raise an agent's rules either: fresh is part of the stamp.
    // Age the session past the 10-minute window first, so the database itself says "not fresh".
    await sql`update app.sessions set created_at = now() - interval '1 hour' where token_hash = ${tokenHash}`;
    const realFresh = await asWeb(async (t) => { await t`select app.act_as_session(${tokenHash})`; return (await t`select current_setting('app.fresh', true) as f`)[0].f; });
    ok(realFresh === '', 'an hour-old session is not fresh, by the database\'s own lookup (got: ' + JSON.stringify(realFresh) + ')');
    const fresh = await asWeb(async (t) => {
      await t`select app.act_as_session(${tokenHash})`;
      await t`select set_config('app.fresh', '1', true)`;
      return (await t`select app.actor_kind() as k`)[0].k;
    });
    ok(fresh === 'anon', 'adding a fake "fresh sign-in" breaks the stamp (got: ' + fresh + ')');

    // 8. Cost: 10,000 checks in one transaction, as row rules would make them.
    const ms = await asWeb(async (t) => {
      await t`select app.act_as_session(${tokenHash})`;
      // A volatile wrapper forces one full check per row, as a worst case for row rules.
      const t0 = Date.now();
      await t`select count(*) from generate_series(1, 10000) g where app.actor_kind_each(g) = 'member'`;
      return Date.now() - t0;
    });
    console.log('INFO 10,000 forced per-row actor checks took ' + ms + ' ms (' + (ms * 1000 / 10000).toFixed(1) + ' microseconds each)');
    ok(ms < 2000, 'cost is acceptable for row rules');
    await web.end({ timeout: 5 });
  } finally {
    await sql.end({ timeout: 5 });
    await admin.unsafe('drop database if exists ' + name + ' with (force)');
    await admin.end({ timeout: 5 });
  }
})().catch((e) => { console.error('ERROR', e.message); process.exitCode = 1; });
