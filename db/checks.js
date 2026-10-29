// The database coverage check. It reads Postgres's own catalog, so it judges the database as it really is, not
// as the migration files describe it. Every build runs it against a fresh database built from the migrations
// (test/db.test.js), and the migration workflow runs it against production afterwards (scripts/db-check.js).
//   S1  every table has row-level security on and forced, with at most one permissive policy per action; nothing
//       in "public"; no view, function or right that lets a request around the policies; no temporary tables
//   S7  the site's role owns nothing, belongs to no other role, and holds exactly the audit-log rights it needs;
//       the audit log's policies and triggers are exactly the reviewed ones and fire always
//   S8  every variable-length column (numbers aside) has an upper size limit (or a fixed list of values) in the database
//   S12 no column for ID documents, ID numbers, face images or passwords
//   G3  no counters: primary keys are UUIDv7 from app.uuid_v7(), and keys that point at them are uuid
// Returns a list of problems in plain words; an empty list means it passes. Queries are tagged templates like
// every other query (S8), so the "our schemas" condition is written out in each one.
'use strict';

const FORBIDDEN_COLUMN = /(passport|ssn|social_security|national_id|id_number|id_document|drivers?_licen[cs]e|licen[cs]e_number|tax_id|face|selfie|biometric|password|passwd)/;
const MAX_LIMIT = 100000; // a "limit" above this many characters or bytes isn't a limit
// The roles that requests act as. dog_signin acts only inside the reviewed sign-in functions below.
const ACTING = ['dog_app', 'dog_signin', 'dog_public', 'dog_limits', 'dog_erase', 'dog_delegate', 'dog_jevs'];
// Narrow roles that only act inside their own reviewed functions (below). dog_limits (PR 6) only counts, inside the
// two emergency-brake checks; dog_erase (PR 8) only deletes, inside the one account-deletion function.
// dog_delegate (PR 7) only turns an approved draft into a post, inside app.approve_draft. dog_jevs (PR 12) only gathers
// JEVs's signals and records and carries out its decisions, inside the JEVs functions.
const NARROW = ['dog_signin', 'dog_public', 'dog_limits', 'dog_erase', 'dog_delegate', 'dog_jevs'];
// The only functions allowed to run with their owner's rights (security definer). Each must be owned by the narrow
// role named for it, fix its search path, and be callable only by dog_app. Adding one is a reviewed change to this list.
// Matched by name and argument types, so an extra version of one of them with other arguments isn't covered.
// Each is pinned to the one narrow role it must run as.
const DEFINERS = {
  'app.rate_limit_hit(text, text, integer, integer)': 'dog_signin',
  'app.email_token_issue(text, text, text, smallint)': 'dog_signin',
  'app.email_token_redeem(text, text, boolean)': 'dog_signin',
  // PR 12 added the region a traveller confirmed (p_region) to sign-in, and the check for whether a sign-in method
  // already belongs to an account, asked only after the provider has confirmed who the person is.
  'app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamp with time zone, uuid, text)': 'dog_signin',
  'app.sign_in_known(text, text[])': 'dog_signin',
  'app.session_resolve(text, integer)': 'dog_signin',
  'app.session_end(text)': 'dog_signin',
  // PR 15: linking and unlinking a sign-in method, from the member's own fresh session, making no session.
  'app.identity_link(text, text[], smallint, smallint, timestamp with time zone, text, text)': 'dog_signin',
  'app.identity_unlink(uuid, text)': 'dog_signin',
  // PR 15's review (F6): a traveller's sealed confirmation is used once.
  'app.region_confirm_use(text)': 'dog_signin',
  // PR 15's second review (R1): the sign-in method of the request's own session, read from the sessions table (which
  // only the sign-in role reads), so what a session makes records it and unlinking that method can undo it.
  'app.current_identity()': 'dog_signin',
  'app.feed(text, uuid, integer)': 'dog_public',
  'app.profile(uuid)': 'dog_public',
  'app.reportable(uuid, uuid)': 'dog_public',
  // PR 5: sign-in for agents (resolve a key, self-register, claim), in the sign-in role.
  'app.agent_resolve(text)': 'dog_signin',
  'app.agent_register(text, text, text, text)': 'dog_signin',
  'app.agent_claim(text)': 'dog_signin',
  'app.agent_claim_preview(text)': 'dog_signin',
  // PR 6: the emergency brake's checks (trigger functions; they count what the acting member or agent can't see).
  'app.posts_limit()': 'dog_limits',
  'app.agents_limit()': 'dog_limits',
  // PR 6: a ban ends the member's sessions and revokes their agents' keys, in the role that manages sessions and keys.
  'app.members_ban_cleanup()': 'dog_signin',
  // PR 8: a member deletes their own account (F8).
  'app.delete_account()': 'dog_erase',
  // Fix 2 (018, Oct 25, 2026): which of the GitHub posts the site already has JEVs hid; only those IDs, nothing more.
  'app.gh_hidden(text[])': 'dog_jevs',
  // Fix 3 (019, Oct 26, 2026): the database decides who is acting. The stamp is made only by the sign-in role and the
  // owner; any role that runs checks of who is acting may test one; only the site's role may ask to act as someone.
  'app.actor_stamp(text, text, text, text, text)': { owner: 'dog_signin', callers: 'dog_owner' },
  'app.stamp_ok()': { owner: 'dog_signin', callers: 'dog_app,dog_delegate,dog_erase,dog_jevs,dog_limits,dog_owner,dog_public' },
  'app.act_as(text, uuid, uuid, boolean, text, text, text)': 'dog_signin',
  // PR 7: approving a draft, a session's start (for the fresh sign-in), and the public receipt.
  'app.approve_draft(uuid, text)': 'dog_delegate',
  'app.receipt(uuid)': 'dog_public',
  // PR 12: JEVs. Its signals (counts only), its decision, the owner's answer to a challenge, sign-up marks, whether a
  // post can be appealed, the regional gate's daily count, and the record of a settings change.
  'app.jevs_signals(text, uuid, text, text[], bigint)': 'dog_jevs',
  'app.jevs_decide(text, uuid, jsonb, text, boolean, text[], bigint, text)': 'dog_jevs',
  'app.jevs_answer(uuid, text)': 'dog_jevs',
  'app.jevs_mark(text, text, text, uuid)': 'dog_jevs',
  'app.jevs_mark_claim(text)': 'dog_jevs',
  'app.jevs_appealable(uuid)': 'dog_jevs',
  'app.region_decline(text)': 'dog_jevs',
  'app.jevs_settings_audit()': 'dog_jevs',
  // PR 12, after its review: the scheduled sweep that keeps marks no longer than promised, and the commit-time check
  // that in enforce mode no post goes live without a JEVs decision.
  'app.jevs_sweep()': 'dog_jevs',
  'app.posts_scored()': 'dog_jevs',
  // PR 12 (Aaron, Oct 16, 2026): a high-risk deletion is reviewed by Aaron. His decision (delete, keep disabled or
  // restore) and the 24-hour timer that disables an account he hasn't decided on, in the role that deletes.
  'app.deletion_review_decide(uuid, text)': 'dog_erase',
  'app.deletion_reviews_expire()': 'dog_erase',
  // PR 16 (Aaron, Oct 16, 2026): agents make sub-agents. Making one, stopping a tree when an agent above stops or its
  // time is up, and lowering sub-agents with their parent, in the role that registers, claims and resolves agents; and
  // a parent's daily cap counting its whole subtree, in the role that counts for the brake.
  'app.subagent_create(text, text, text, text, text, text, integer, integer, boolean, text)': 'dog_signin',
  'app.agents_cascade()': 'dog_signin',
  'app.agent_rules_cascade()': 'dog_signin',
  'app.subagents_expire()': 'dog_signin',
  'app.agent_tree_cap()': 'dog_limits',
  // 023 (Aaron, Oct 28, 2026): signing in by posting a one-time code through giscus. The site makes a code and signs in
  // with a claimed one; only the JEVs gate's role may claim a code, for the GitHub account that posted it.
  'app.code_issue(text, text, text, text)': 'dog_signin',
  'app.code_claim(text, text, text)': { owner: 'dog_signin', callers: 'dog_jevs' },
  'app.code_sign_in(text, text, text, integer, text)': 'dog_signin',
  // The key file (Aaron, Oct 28): signing in again with the username and file, never as an administrator.
  'app.file_sign_in(text, text, text, text, integer, text)': 'dog_signin',
  // "Sign out everywhere" cancels the member's own key file.
  'app.file_key_revoke()': 'dog_signin'
};
const NO_UUID_PK = ['app.schema_migrations', 'app.runner_tokens']; // bookkeeping keyed by file name or token ID, not a record

// The audit log's reviewed policies, compared with spaces and brackets removed so Postgres versions that print
// them slightly differently still match. Since 020 each call of who is acting is a sub-select, "(SELECT app.actor_kind()
// AS actor_kind)", run once per query; test/policy-initplan.test.js proves 020 changed nothing else.
const AUDIT_POLICIES = {
  audit_insert: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_select: { cmd: 'r', using: "SELECTapp.actor_kind()ASactor_kind='admin'::text", check: '' },
  audit_insert_signin: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_insert_erase: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_insert_delegate: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_insert_jevs: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_insert_owner: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" }
};
const squash = (s) => (s || '').replace(/[\s()]/g, '');

async function problems(sql, { snapshot } = {}) {
  const out = [];
  const add = (s) => out.push(s);

  // ---- Everything security-relevant matches the reviewed snapshot (db/snapshot.txt) ----
  if (snapshot) {
    const now = await fingerprint(sql);
    const want = new Set(snapshot), have = new Set(now);
    for (const line of now) if (!want.has(line)) add('not in the reviewed snapshot: ' + line + ' (S1, S7)');
    for (const line of snapshot) if (!have.has(line)) add('missing compared with the reviewed snapshot: ' + line + ' (S1, S7)');
  }

  // ---- Tables, views and policies (S1) ----
  const rels = await sql`
    select n.nspname as schema, c.relname as name, c.relkind as kind, c.relrowsecurity as rls,
           c.relforcerowsecurity as forced, c.reloptions as options, pg_get_userbyid(c.relowner) as owner
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner')
      and c.relkind in ('r', 'p', 'v', 'm', 'f')`;
  for (const t of rels) {
    const name = t.schema + '.' + t.name;
    if (t.schema === 'public') add(name + ' is in the public schema; our tables belong in app (S1)');
    if (t.owner !== 'dog_owner') add(name + ' is owned by ' + t.owner + '; everything in app belongs to dog_owner (S1)');
    if (t.kind === 'r' || t.kind === 'p') {
      if (!t.rls) add(name + ' does not have row-level security on (S1)');
      if (!t.forced) add(name + ' does not have row-level security forced (S1)');
    }
    if (t.kind === 'v' && !(t.options || []).includes('security_invoker=true')) add(name + ' is a view without security_invoker, so it would skip row-level security (S1)');
    if (t.kind === 'm') add(name + ' is a materialized view, which row-level security cannot cover (S1)');
    if (t.kind === 'f') add(name + ' is a foreign table, which row-level security cannot cover (S1)');
  }

  // One permissive policy per action (a policy "for all" counts for every action): a second one would widen the
  // first without anyone editing it.
  const pol = await sql`
    select n.nspname || '.' || c.relname as tbl, p.polname as name, p.polcmd as cmd, p.polpermissive as permissive,
           coalesce((select array_agg(case when r = 0 then 'PUBLIC' else pg_get_userbyid(r) end) from unnest(p.polroles) r), '{}') as roles,
           pg_get_expr(p.polqual, p.polrelid) as using, pg_get_expr(p.polwithcheck, p.polrelid) as check
    from pg_policy p join pg_class c on c.oid = p.polrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner'`;
  const perms = {};
  for (const p of pol.filter((x) => x.permissive)) {
    for (const role of p.roles) for (const cmd of p.cmd === '*' ? ['r', 'a', 'w', 'd'] : [p.cmd]) {
      const k = p.tbl + ' ' + cmd + ' ' + role;
      (perms[k] = perms[k] || []).push(p.name);
    }
  }
  for (const p of pol) if (p.roles.includes('PUBLIC')) add(p.tbl + ' policy ' + p.name + ' applies to every role; name the role (S1)');
  for (const [k, names] of Object.entries(perms)) if (names.length > 1) add(k.split(' ')[0] + ' has ' + names.length + ' permissive policies for one action and role (' + names.join(', ') + '); combine them into one (S1)');

  const audit = pol.filter((p) => p.tbl === 'app.audit_log');
  const auditNames = audit.map((p) => p.name).sort();
  if (auditNames.join() !== Object.keys(AUDIT_POLICIES).sort().join()) add('the audit log has policies ' + (auditNames.join(', ') || 'none') + '; it must have exactly ' + Object.keys(AUDIT_POLICIES).sort().join(', ') + ' (S7)');
  for (const p of audit) {
    const want = AUDIT_POLICIES[p.name];
    if (want && (p.cmd !== want.cmd || !p.permissive || squash(p.using) !== squash(want.using) || squash(p.check) !== squash(want.check))) {
      add('the audit log policy ' + p.name + ' differs from the reviewed one (S7)');
    }
  }

  // ---- Rights (S1, S7) ----
  const grants = await sql`
    select n.nspname || '.' || c.relname as name, coalesce(r.rolname, 'PUBLIC') as grantee, a.privilege_type as privilege
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
    left join pg_roles r on r.oid = a.grantee
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner')
      and c.relkind in ('r', 'p', 'v')
      and coalesce(r.rolname, 'PUBLIC') not in ('dog_owner', 'dog_app', 'dog_signin', 'dog_public', 'dog_limits', 'dog_erase', 'dog_delegate', 'dog_jevs')`;
  for (const g of grants) add(g.name + ' grants ' + g.privilege + ' to ' + g.grantee + '; only dog_owner, dog_app and the narrow roles may hold rights (S1)');
  // dog_signin's rights are pinned exactly by the reviewed snapshot; it holds none on the tables of later features.

  // Anywhere outside app: the acting roles may not write, and nothing may be granted to them by name.
  for (const role of ACTING) {
    const outside = await sql`
      select n.nspname || '.' || c.relname as name
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname not in ('app', 'pg_catalog', 'information_schema') and n.nspname !~ '^pg_toast'
        and c.relkind in ('r', 'p', 'v', 'm', 'f')
        and exists (select 1 from pg_roles where rolname = ${role})
        and (has_table_privilege(${role}, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')
             or has_any_column_privilege(${role}, c.oid, 'INSERT, UPDATE')
             or exists (select 1 from aclexplode(c.relacl) a where a.grantee = (select oid from pg_roles where rolname = ${role}))
             -- Reading through PUBLIC counts too, where the role can use the schema; providers' own schemas that
             -- every role may read (Supabase's "extensions") are left out.
             or (has_schema_privilege(${role}, n.oid, 'USAGE') and n.nspname not in ('extensions')
                 and has_any_column_privilege(${role}, c.oid, 'SELECT')))`;
    for (const o of outside) add(role + ' can reach ' + o.name + ' outside the app schema, where no policy protects it (S1)');
    const schemas = await sql`
      select n.nspname as name from pg_namespace n
      where exists (select 1 from pg_roles where rolname = ${role}) and has_schema_privilege(${role}, n.oid, 'CREATE')`;
    for (const x of schemas) add(role + ' can create objects in schema ' + x.name + '; it must not (S1, S7)');
    const [temp] = await sql`select exists (select 1 from pg_roles where rolname = ${role}) and has_database_privilege(${role}, current_database(), 'TEMP') as yes`;
    if (temp.yes) add(role + ' can make temporary tables, which outlive a transaction on a pooled connection (S1)');
  }
  const appSchema = await sql`
    select coalesce(r.rolname, 'PUBLIC') as grantee, a.privilege_type as privilege
    from pg_namespace n cross join lateral aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
    left join pg_roles r on r.oid = a.grantee
    where n.nspname = 'app' and coalesce(r.rolname, '') <> 'dog_owner'
      and not (coalesce(r.rolname, '') in ('dog_app', 'dog_signin', 'dog_public', 'dog_limits', 'dog_erase', 'dog_delegate', 'dog_jevs') and a.privilege_type = 'USAGE')`;
  for (const g of appSchema) add('schema app grants ' + g.privilege + ' to ' + g.grantee + '; the acting roles may only use it (S1)');

  // The audit log: read the table, write only the four content columns.
  const [ar] = await sql`
    select has_table_privilege('dog_app', 'app.audit_log', 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER') as table_write,
           has_any_column_privilege('dog_app', 'app.audit_log', 'UPDATE') as column_update,
           (select array_agg(a.attname::text order by a.attname) from pg_attribute a
            where a.attrelid = 'app.audit_log'::regclass and a.attnum > 0 and not a.attisdropped
              and has_column_privilege('dog_app', 'app.audit_log', a.attnum, 'INSERT')) as insertable`;
  if (ar.table_write || ar.column_update) add('dog_app holds more rights on the audit log than reading and adding rows (S7)');
  if ((ar.insertable || []).join() !== 'action,detail,subject_id,subject_kind') add('dog_app can set audit log columns ' + (ar.insertable || []).join(', ') + '; only action, subject_kind, subject_id and detail (S7)');

  // ---- Roles (S1, S7) ----
  // Memberships that pass on rights. From Postgres 16, whoever creates a role is given an admin-only membership in
  // it that passes on nothing (no SET, no INHERIT), so those are left out; Postgres 15 has no such memberships.
  const [{ v }] = await sql`select current_setting('server_version_num')::int as v`;
  const roles = v >= 160000 ? await sql`
    with m as (select roleid, member from pg_auth_members where set_option or inherit_option)
    select r.rolname as name, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolreplication,
           coalesce((select array_agg(distinct g.rolname::text) from m join pg_roles g on g.oid = m.roleid where m.member = r.oid), '{}') as member_of,
           r.oid in (select m.member from m where m.roleid = (select oid from pg_roles where rolname = 'dog_app')) as uses_app
    from pg_roles r` : await sql`
    with m as (select roleid, member from pg_auth_members)
    select r.rolname as name, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolreplication,
           coalesce((select array_agg(distinct g.rolname::text) from m join pg_roles g on g.oid = m.roleid where m.member = r.oid), '{}') as member_of,
           r.oid in (select m.member from m where m.roleid = (select oid from pg_roles where rolname = 'dog_app')) as uses_app
    from pg_roles r`;
  const app = roles.find((r) => r.name === 'dog_app');
  const owner = roles.find((r) => r.name === 'dog_owner');
  if (!app || !owner || NARROW.some((n) => !roles.find((r) => r.name === n))) add('the dog_app, dog_owner, ' + NARROW.join(', ') + ' roles must all exist (S1)');
  const powers = [['rolsuper', 'superuser'], ['rolbypassrls', 'bypass row-level security'], ['rolcreaterole', 'create roles'],
    ['rolcreatedb', 'create databases'], ['rolreplication', 'replication']];
  if (app) {
    for (const [k, label] of powers.concat([['rolcanlogin', 'sign in directly']])) if (app[k]) add('dog_app can ' + label + '; it must not (S1, S7)');
    if (app.member_of.length) add('dog_app belongs to ' + app.member_of.join(', ') + '; it must belong to no role, or it gains that role\'s rights (S1, S7)');
  }
  for (const name of NARROW) {
    const r = roles.find((x) => x.name === name);
    if (!r) continue;
    for (const [k, label] of powers.concat([['rolcanlogin', 'sign in directly']])) if (r[k]) add(name + ' can ' + label + '; it must not (S1)');
    if (r.member_of.length) add(name + ' belongs to ' + r.member_of.join(', ') + '; it must belong to no role (S1)');
    const holders = roles.filter((x) => x.member_of.includes(name) && x.name !== 'dog_owner').map((x) => x.name);
    if (holders.length) add(holders.join(', ') + ' can act as ' + name + '; only dog_owner may, to hand it its functions (S1)');
  }
  if (owner) for (const [k, label] of [['rolsuper', 'superuser'], ['rolbypassrls', 'bypass row-level security'], ['rolcanlogin', 'sign in directly']]) {
    if (owner[k]) add('dog_owner can ' + label + '; it must not (S1)');
  }
  // The login the site uses: switching to dog_app is the only thing it can do.
  for (const r of roles.filter((x) => x.uses_app)) {
    for (const [k, label] of powers) if (r[k]) add(r.name + ' (which the site signs in as) can ' + label + '; it must not (S1)');
    const other = r.member_of.filter((g) => g !== 'dog_app');
    if (other.length) add(r.name + ' (which the site signs in as) also belongs to ' + other.join(', ') + '; it may belong only to dog_app (S1, S7)');
  }
  for (const role of ACTING) {
    const owned = await sql`select count(*)::int as n from pg_class where relowner = (select oid from pg_roles where rolname = ${role})`;
    if (owned[0].n) add(role + ' owns ' + owned[0].n + ' tables or other objects; an owner can switch off policies and triggers (S7)');
  }

  // ---- Functions (S1) ----
  const fns = await sql`
    select n.nspname || '.' || p.proname as name, n.nspname || '.' || p.proname || '(' || oidvectortypes(p.proargtypes) || ')' as signature,
           p.prosecdef as definer, pg_get_userbyid(p.proowner) as owner,
           coalesce(array_to_string(p.proconfig, ';'), '') as config,
           coalesce((select array_agg(case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end order by 1)
                     from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                     where a.privilege_type = 'EXECUTE' and a.grantee <> p.proowner), '{}') as callers
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner'`;
  for (const f of fns) {
    if (f.callers.includes('PUBLIC')) add(f.name + ' can be called by every role; grant it to dog_app only (S1)');
    if (f.definer) {
      if (!Object.hasOwn(DEFINERS, f.signature)) add(f.signature + ' runs with its owner\'s rights (security definer); not allowed without a reviewed exception (S1)');
      else {
        const want = typeof DEFINERS[f.signature] === 'string' ? { owner: DEFINERS[f.signature], callers: 'dog_app' } : DEFINERS[f.signature];
        if (f.owner !== want.owner) add(f.name + ' must be owned by ' + want.owner + ', not ' + f.owner + ' (S1)');
        if (f.config !== 'search_path=pg_catalog') add(f.name + ' must fix its search path to pg_catalog (S1)');
        if ([...f.callers].sort().join() !== want.callers) add(f.name + ' may be called only by ' + want.callers + ', not ' + (f.callers.join(', ') || 'nobody') + ' (S1)');
      }
    } else if (f.owner !== 'dog_owner') add(f.name + ' is owned by ' + f.owner + '; everything in app belongs to dog_owner (S1)');
  }

  // ---- The guard triggers (S3, S7, G4) ----
  // tgtype bits: 1 = once per row, 2 = before, 8 = delete, 16 = update, 32 = truncate. "A" = fires always, even in
  // replication mode. No WHEN condition, arguments or column list, which could hide an off-switch.
  const trig = await sql`
    select c.relname as tbl, t.tgname as name, t.tgtype as type, t.tgenabled as enabled, p.proname as fn, p.prosrc as src,
           t.tgqual is null and t.tgnargs = 0 and coalesce(array_length(t.tgattr::int2[], 1), 0) = 0 as plain
    from pg_trigger t join pg_proc p on p.oid = t.tgfoid join pg_class c on c.oid = t.tgrelid
    where c.relnamespace = 'app'::regnamespace and not t.tgisinternal`;
  for (const [tbl, name, type, fn, what] of [
    ['audit_log', 'audit_log_no_change', 26, 'audit_log_append_only', 'every update and delete statement'],
    ['audit_log', 'audit_log_no_truncate', 34, 'audit_log_append_only', 'every truncate statement'],
    ['members', 'members_guard', 19, 'members_guard', 'every updated member row'],
    // PR 4: only a reviewer changes a post's status, along the allowed moves; flags close once, in the reviewer's name.
    ['posts', 'posts_review_guard', 19, 'posts_review_guard', 'every updated post row'],
    ['review_flags', 'review_flags_guard', 19, 'review_flags_guard', 'every updated flag row'],
    // PR 5: an agent's owner never changes and revoking is final; keys only get revoked.
    ['agents', 'agents_guard', 19, 'agents_guard', 'every updated agent row'],
    ['agent_keys', 'agent_keys_guard', 19, 'agent_keys_guard', 'every updated key row'],
    // PR 6: a brake is only ever switched off, once; the brake checks run before every new post and new agent.
    ['brakes', 'brakes_guard', 19, 'brakes_guard', 'every updated brake row'],
    ['posts', 'posts_limit', 7, 'posts_limit', 'every new post'],
    ['agents', 'agents_limit', 23, 'agents_limit', 'every new or updated agent row'],
    // PR 7: rules versions are only added; a draft's words never change and it is decided once; agent posts follow the rules.
    ['agent_rules', 'agent_rules_guard', 27, 'agent_rules_guard', 'every updated or deleted rules row'],
    ['agent_rules', 'agent_rules_fill', 7, 'agent_rules_fill', 'every new rules version'],
    ['agent_drafts', 'agent_drafts_guard', 19, 'agent_drafts_guard', 'every updated draft'],
    ['agent_drafts', 'agent_drafts_fill', 7, 'agent_drafts_fill', 'every new draft'],
    ['posts', 'posts_delegation', 7, 'posts_delegation', 'every new post'],
    // PR 12: JEVs decisions are only added; a challenge is answered once, by JEVs; settings keep their names and ranges.
    ['jevs_decisions', 'jevs_decisions_guard', 27, 'jevs_decisions_guard', 'every updated or deleted decision'],
    ['jevs_challenges', 'jevs_challenges_guard', 27, 'jevs_challenges_guard', 'every updated or deleted challenge'],
    ['jevs_settings', 'jevs_settings_check', 23, 'jevs_settings_check', 'every new or changed setting'],
    // A deletion review's subject never changes; only Aaron's decision or the 24-hour timer moves it.
    ['deletion_reviews', 'deletion_reviews_guard', 27, 'deletion_reviews_guard', 'every updated or deleted deletion review'],
    // PR 16: a parent's daily cap counts its whole subtree, before every new post and draft.
    ['posts', 'posts_tree_cap', 7, 'agent_tree_cap', 'every new post'],
    ['agent_drafts', 'agent_drafts_tree_cap', 7, 'agent_tree_cap', 'every new draft']
  ]) {
    const t = trig.find((x) => x.tbl === tbl && x.name === name);
    const label = 'the app.' + tbl + ' trigger ' + name;
    if (!t) { add('app.' + tbl + ' is missing its ' + name + ' trigger (S3, S7)'); continue; }
    if (t.enabled !== 'A') add(label + ' is not set to fire always (S3, S7)');
    if (t.type !== type || !t.plain) add(label + ' no longer runs before ' + what + ' without conditions (S3, S7)');
    if (t.fn !== fn || !/raise\s+exception/i.test(t.src) || (fn === 'audit_log_append_only' && /\breturn\b/i.test(t.src))) add(label + ' no longer refuses the change (S3, S7)');
  }
  // RK82 (021): the sign-in level cap. These lower a level instead of refusing, so they are checked by their own rule:
  // present, firing always, before every new (or, for methods, re-levelled) row, and still capping at 1.
  for (const [tbl, name, type] of [['identities', 'identities_level_cap', 23], ['members', 'members_level_cap', 7]]) {
    const t = trig.find((x) => x.tbl === tbl && x.name === name);
    const label = 'the app.' + tbl + ' trigger ' + name;
    if (!t) { add('app.' + tbl + ' is missing its ' + name + ' trigger (RK82)'); continue; }
    if (t.enabled !== 'A') add(label + ' is not set to fire always (RK82)');
    if (t.type !== type || t.fn !== name || !/cap constant smallint := 1;/.test(t.src)) add(label + ' no longer caps sign-in levels at 1 (RK82)');
  }

  // ---- Columns and keys (S8, S12, G3) ----
  const seqs = await sql`
    select n.nspname || '.' || c.relname as name from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and c.relkind = 'S'`;
  for (const s of seqs) add(s.name + ' is a counter; IDs must be UUIDv7 (G3)');

  const cols = await sql`
    select n.nspname || '.' || c.relname as tbl, a.attname as col, format_type(a.atttypid, a.atttypmod) as type,
           t.typlen as len, t.typcategory as category, a.atttypmod as typmod, a.attidentity as identity,
           pg_get_expr(d.adbin, d.adrelid) as def,
           exists (select 1 from pg_constraint k where k.conrelid = c.oid and k.contype = 'p' and a.attnum = any (k.conkey)) as pk,
           exists (select 1 from pg_constraint k where k.conrelid = c.oid and k.contype = 'f' and a.attnum = any (k.conkey)) as fk,
           coalesce((select array_agg(pg_get_constraintdef(k.oid)) from pg_constraint k
                     where k.conrelid = c.oid and k.contype = 'c' and a.attnum = any (k.conkey)), '{}') as checks
    from pg_attribute a join pg_class c on c.oid = a.attrelid join pg_namespace n on n.oid = c.relnamespace
    join pg_type t on t.oid = a.atttypid
    left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner')
      and c.relkind in ('r', 'p') and a.attnum > 0 and not a.attisdropped`;
  for (const c of cols) {
    const name = c.tbl + '.' + c.col;
    if (c.category === 'A') add(name + ' is an array; use a table so each item has its own size limit (S8)');
    else if (c.len === -1 && c.category !== 'N' && !limited(c)) add(name + ' has no size limit (S8)');
    if (c.identity) add(name + ' is an identity counter; IDs must be UUIDv7 (G3)');
    if (c.def && /nextval\(/.test(c.def)) add(name + ' takes its value from a counter; IDs must be UUIDv7 (G3)');
    if ((c.pk && !NO_UUID_PK.includes(c.tbl)) || c.col === 'id') {
      if (c.type !== 'uuid' || c.def !== 'app.uuid_v7()') add(name + ' is a key and must be a uuid with default app.uuid_v7() (G3)');
    }
    if (c.fk && c.type !== 'uuid') add(name + ' points at another record and must be a uuid (G3)');
    if (FORBIDDEN_COLUMN.test(c.col)) add(name + ' looks like it stores an ID document, ID number, face image or password (S5, S12)');
  }

  return out;
}

// A column is limited by varchar(n), or by a check constraint built only from AND, one of whose parts is exactly
// a cap of MAX_LIMIT or less on the column's length, or a fixed list of values. OR, NOT, CASE, IS and the like
// are refused, because they can make a cap that never binds.
const ESCAPES = /\b(OR|NOT|CASE|IS|COALESCE|NULLIF|GREATEST|LEAST)\b|<>|!=|=\s*(true|false)\b/i;
function limited(c) {
  const m = c.type.match(/^character varying\((\d+)\)$/);
  if (m && Number(m[1]) <= MAX_LIMIT) return true;
  const col = c.col.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const cap = new RegExp('^\\(*(char_length|octet_length)\\(+' + col + '\\)*(::text\\)*)?\\s*(<|<=|=)\\s*(\\d+)\\)*$');
  const list = new RegExp('^\\(*' + col + '\\s*=\\s*ANY\\s*\\(+ARRAY\\[[^\\]]*\\]\\)*$');
  return c.checks.some((def) => {
    const body = def.replace(/^CHECK\s*/i, '');
    if (ESCAPES.test(body)) return false;
    return body.split(/\s+AND\s+/i).map((part) => part.trim()).some((part) => {
      if (list.test(part)) return true;
      const x = part.match(cap);
      return x !== null && Number(x[4]) <= MAX_LIMIT;
    });
  });
}

// A plain-text record of every security-relevant setting in our schemas: policies, rights (table and column),
// column defaults, check constraints, triggers (with their on/off state) and functions (their attributes and a
// hash of their body). db/snapshot.txt holds the reviewed version, rebuilt from the migrations with
// `npm run db:snapshot`; a pull request that changes it shows exactly what changed, line by line.
async function fingerprint(sql) {
  const rows = await sql`
    with ours as (
      select c.oid, n.nspname || '.' || c.relname as tbl from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and c.relkind in ('r', 'p', 'v', 'm', 'f')
    )
    select 'policy ' || o.tbl || ' ' || p.polname || ' cmd=' || p.polcmd::text || ' permissive=' || p.polpermissive::text
           || ' to=' || coalesce((select string_agg(case when r = 0 then 'PUBLIC' else pg_get_userbyid(r) end, ',' order by 1) from unnest(p.polroles) r), '')
           || ' using=' || coalesce(pg_get_expr(p.polqual, p.polrelid), '') || ' check=' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') as line
    from pg_policy p join ours o on o.oid = p.polrelid
    union all
    select 'grant ' || o.tbl || ' ' || case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end || ' ' || a.privilege_type
    from ours o join pg_class c on c.oid = o.oid cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
    -- The owner's own rights are left out: an owner always holds all of them, and the list differs by version.
    where a.grantee <> c.relowner
    union all
    select 'grant ' || o.tbl || '.' || at.attname || ' ' || case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end || ' ' || a.privilege_type
    from ours o join pg_attribute at on at.attrelid = o.oid cross join lateral aclexplode(at.attacl) a
    where at.attnum > 0 and not at.attisdropped and at.attacl is not null
    union all
    select 'default ' || o.tbl || '.' || at.attname || ' = ' || pg_get_expr(d.adbin, d.adrelid)
    from ours o join pg_attribute at on at.attrelid = o.oid join pg_attrdef d on d.adrelid = at.attrelid and d.adnum = at.attnum
    union all
    select 'constraint ' || o.tbl || ' ' || k.conname || ' ' || pg_get_constraintdef(k.oid)
    from ours o join pg_constraint k on k.conrelid = o.oid
    union all
    select 'trigger ' || o.tbl || ' enabled=' || t.tgenabled::text || ' ' || pg_get_triggerdef(t.oid)
    from ours o join pg_trigger t on t.tgrelid = o.oid where not t.tgisinternal
    union all
    select 'function ' || n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') owner='
           || pg_get_userbyid(p.proowner) || ' execute=' || coalesce((select string_agg(case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end, ',' order by 1)
             from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a where a.privilege_type = 'EXECUTE'), '')
           || ' language=' || l.lanname || ' volatile=' || p.provolatile::text || ' definer=' || p.prosecdef::text
           || ' config=' || coalesce(array_to_string(p.proconfig, ';'), '') || ' returns=' || pg_get_function_result(p.oid)
           || ' body_md5=' || md5(p.prosrc)
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_language l on l.oid = p.prolang
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and p.prokind in ('f', 'p')`;
  // One space between words, so the same definition reads the same on every Postgres version.
  return [...new Set(rows.map((r) => r.line.replace(/\s+/g, ' ').trim()))].sort();
}

module.exports = { problems, fingerprint, limited, MAX_LIMIT };
