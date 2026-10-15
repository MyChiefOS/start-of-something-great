// The database coverage check. It reads Postgres's own catalog, so it judges the database as it really is, not
// as the migration files describe it. Every build runs it against a fresh database built from the migrations
// (test/db.test.js); it can also be run against production to catch drift.
//   S1  every table has row-level security on and forced; nothing sits in "public"; views can't skip policies
//   S7  the site's role owns nothing and can't bypass security, so it can't remove the audit log's locks
//   S8  every text and JSON column has an upper size limit (or a fixed list of values) in the database
//   S12 no column for ID documents, ID numbers, face images or passwords
//   G3  no counters: IDs are UUIDv7 from app.uuid_v7()
// Returns a list of problems in plain words; an empty list means it passes.
'use strict';

// Schemas we check: our own (app), "public", and any other schema our owner role owns. The queries are tagged
// templates like every other query (S8), so this condition is written out in each one.
const FORBIDDEN_COLUMN = /(passport|ssn|social_security|national_id|id_number|id_document|drivers?_licen[cs]e|licen[cs]e_number|tax_id|face|selfie|biometric|password|passwd)/;

async function problems(sql) {
  const out = [];

  const tables = await sql`
    select n.nspname as schema, c.relname as name, c.relkind as kind, c.relrowsecurity as rls,
           c.relforcerowsecurity as forced, c.reloptions as options
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and c.relkind in ('r', 'p', 'v', 'm', 'f')`;
  for (const t of tables) {
    const name = t.schema + '.' + t.name;
    if (t.schema === 'public') out.push(name + ' is in the public schema; our tables belong in app (S1)');
    if (t.kind === 'r' || t.kind === 'p') {
      if (!t.rls) out.push(name + ' does not have row-level security on (S1)');
      if (!t.forced) out.push(name + ' does not have row-level security forced (S1)');
    }
    if (t.kind === 'v' && !(t.options || []).includes('security_invoker=true')) out.push(name + ' is a view without security_invoker, so it would skip row-level security (S1)');
    if (t.kind === 'm') out.push(name + ' is a materialized view, which row-level security cannot cover (S1)');
    if (t.kind === 'f') out.push(name + ' is a foreign table, which row-level security cannot cover (S1)');
  }

  // Only our two roles may hold rights on our tables, and nobody may hold rights through PUBLIC.
  const grants = await sql`
    select n.nspname || '.' || c.relname as name, coalesce(r.rolname, 'PUBLIC') as grantee, a.privilege_type as privilege
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
    left join pg_roles r on r.oid = a.grantee
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and c.relkind in ('r', 'p', 'v')
      and coalesce(r.rolname, 'PUBLIC') not in ('dog_owner', 'dog_app')`;
  for (const g of grants) out.push(g.name + ' grants ' + g.privilege + ' to ' + g.grantee + '; only dog_owner and dog_app may hold rights (S1)');

  const schemaRights = await sql`
    select coalesce(r.rolname, 'PUBLIC') as grantee, a.privilege_type as privilege
    from pg_namespace n cross join lateral aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
    left join pg_roles r on r.oid = a.grantee
    where n.nspname = 'app' and not (coalesce(r.rolname, '') = 'dog_owner')
      and not (coalesce(r.rolname, '') = 'dog_app' and a.privilege_type = 'USAGE')`;
  for (const g of schemaRights) out.push('schema app grants ' + g.privilege + ' to ' + g.grantee + '; dog_app may only use it (S1)');

  const [app] = await sql`select rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication from pg_roles where rolname = 'dog_app'`;
  if (!app) out.push('the dog_app role does not exist');
  else {
    for (const [k, label] of [['rolsuper', 'superuser'], ['rolbypassrls', 'bypass row-level security'], ['rolcreaterole', 'create roles'],
      ['rolcreatedb', 'create databases'], ['rolcanlogin', 'sign in directly'], ['rolreplication', 'replication']]) {
      if (app[k]) out.push('dog_app can ' + label + '; it must not (S1, S7)');
    }
  }
  const owned = await sql`select count(*)::int as n from pg_class where relowner = (select oid from pg_roles where rolname = 'dog_app')`;
  if (owned[0].n) out.push('dog_app owns ' + owned[0].n + ' objects; an owner can switch off policies and triggers (S7)');

  const definers = await sql`
    select n.nspname || '.' || p.proname as name from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and p.prosecdef`;
  for (const f of definers) out.push(f.name + ' runs with its owner\'s rights (security definer); not allowed without a reviewed exception (S1)');

  const auditTriggers = await sql`
    select t.tgname from pg_trigger t where t.tgrelid = to_regclass('app.audit_log') and t.tgenabled = 'O'`;
  const names = auditTriggers.map((t) => t.tgname);
  for (const need of ['audit_log_no_change', 'audit_log_no_truncate']) {
    if (!names.includes(need)) out.push('the audit log is missing its ' + need + ' trigger, or it is switched off (S7)');
  }

  const sequences = await sql`
    select n.nspname || '.' || c.relname as name from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and c.relkind = 'S'`;
  for (const s of sequences) out.push(s.name + ' is a counter; IDs must be UUIDv7 (G3)');

  const columns = await sql`
    select n.nspname || '.' || c.relname as tbl, a.attname as col, format_type(a.atttypid, a.atttypmod) as type,
           pg_get_expr(d.adbin, d.adrelid) as def, a.attidentity as identity,
           exists (select 1 from pg_constraint k where k.conrelid = c.oid and k.contype = 'c'
                   and a.attnum = any (k.conkey)
                   and pg_get_constraintdef(k.oid) ~ ('(char_length|octet_length)\\(+' || quote_ident(a.attname) || '\\)*(::text\\)*)? (<|<=|=) [0-9]|'
                                                   || quote_ident(a.attname) || ' = ANY')) as limited
    from pg_attribute a join pg_class c on c.oid = a.attrelid join pg_namespace n on n.oid = c.relnamespace
    left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and c.relkind in ('r', 'p') and a.attnum > 0 and not a.attisdropped`;
  for (const c of columns) {
    const name = c.tbl + '.' + c.col;
    if (/^(text|character varying|jsonb|json|bytea)$/.test(c.type) && !c.limited) out.push(name + ' has no size limit (S8)');
    if (c.identity) out.push(name + ' is an identity counter; IDs must be UUIDv7 (G3)');
    if (c.col === 'id' && (c.type !== 'uuid' || c.def !== 'app.uuid_v7()')) out.push(name + ' must be a uuid with default app.uuid_v7() (G3)');
    if (FORBIDDEN_COLUMN.test(c.col)) out.push(name + ' looks like it stores an ID document, ID number, face image or password (S5, S12)');
  }

  return out;
}

module.exports = { problems };
