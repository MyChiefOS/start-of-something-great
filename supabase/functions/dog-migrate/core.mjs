// The database runner's work (USE-CASES.md row 15), shared by the Supabase function (index.ts) and the tests, so
// the code CI rehearses is the code production runs. It does what scripts/migrate.js does, from a merged commit:
//   1. reads db/manifest.json at that commit, fetches every file it names and checks each SHA-256;
//      nothing touches the database until every file matches;
//   2. runs the one-time reset (db/reset/) only if the manifest names it and the live ledger holds the exact
//      migration its "when" names;
//   3. applies every pending migration, recording each in app.schema_migrations, all in ONE transaction with the
//      reset, under an advisory lock (a migration already applied must still match; one missing from the manifest stops);
//   4. checks the result: every app table has row-level security forced, the ledger equals the manifest, no
//      passkey table or step-up trigger exists, no dog_* role can sign in but the site login, and that one is no
//      wider than dog_app (fix 4);
//   5. writes one app.change_log row if anything changed; the token's ID is recorded as soon as it is checked.
// It returns versions, counts and check names only: no data, settings or secrets.

const VERSION = /^(\d{3})_[a-z0-9_]+$/;
const HEX64 = /^[0-9a-f]{64}$/;
const RESET_FILE = /^db\/reset\/[a-z0-9_-]+\.sql$/;

export async function sha256(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function checkManifest(m) {
  if (!m || !Array.isArray(m.migrations) || !m.migrations.length) throw new Error('manifest has no migrations');
  m.migrations.forEach((x, i) => {
    const v = VERSION.exec(x && x.version);
    if (!v || Number(v[1]) !== i + 1) throw new Error('manifest migrations must be numbered 001, 002, ... with no gaps');
    if (!HEX64.test(x.sha256)) throw new Error('manifest fingerprint malformed: ' + x.version);
  });
  if (m.reset != null) {
    const r = m.reset;
    if (!RESET_FILE.test(r.file) || !HEX64.test(r.sha256) || !r.when || !VERSION.test(r.when.version) || !HEX64.test(r.when.sha256)) {
      throw new Error('manifest reset entry malformed');
    }
  }
  return m;
}

// fetchText(path) returns a file of the merged commit, e.g. 'db/migrations/001_foundation.sql'.
export async function load(fetchText) {
  const manifest = checkManifest(JSON.parse(await fetchText('db/manifest.json')));
  const files = [];
  for (const m of manifest.migrations) {
    const sql = await fetchText('db/migrations/' + m.version + '.sql');
    if (await sha256(sql) !== m.sha256) throw new Error(m.version + ': file does not match its fingerprint');
    files.push({ version: m.version, sha256: m.sha256, sql });
  }
  let reset = null;
  if (manifest.reset) {
    const sql = await fetchText(manifest.reset.file);
    if (await sha256(sql) !== manifest.reset.sha256) throw new Error('reset file does not match its fingerprint');
    reset = { ...manifest.reset, sql };
  }
  return { files, reset };
}

async function ledger(t) {
  const [{ exists }] = await t`select to_regclass('app.schema_migrations') is not null as exists`;
  if (!exists) return new Map();
  await t`set local role dog_owner`;
  const rows = await t`select version, sha256 from app.schema_migrations`;
  await t`reset role`;
  return new Map(rows.map((r) => [r.version, r.sha256]));
}

const LOCK = 'dayonegreat.migrate';
// The roles the migrations use. None may sign in.
const ROLES = ['dog_owner', 'dog_app', 'dog_public', 'dog_signin', 'dog_jevs', 'dog_limits', 'dog_delegate', 'dog_erase'];
// The site's own database login (harness/PLAN.md fix 5). It is the one role of ours that may sign in, and only this
// narrow (fix 4): no rights of its own (noinherit), not a superuser, can't skip row-level security, make roles or
// databases or replicate, and belonging to dog_app alone, which it switches to for every request (db/index.js).
const SITE_LOGIN = 'dog_web';

// Records a token ID the moment the token passes every other check, so the same token can never be used twice,
// even if the run then fails. Returns true if it was already used. Before 015 exists there is nothing to record.
export async function tokenUsed(sql, jti) {
  return sql.begin(async (t) => {
    const [{ exists }] = await t`select to_regclass('app.runner_tokens') is not null as exists`;
    if (!exists) return false;
    await t`set local role dog_owner`;
    const r = await t`insert into app.runner_tokens (jti) values (${jti}) on conflict do nothing returning jti`;
    return r.length === 0;
  });
}

export async function status(sql) {
  const have = await sql.begin(ledger);
  return [...have].sort().map(([version, sha]) => ({ version, sha256: sha }));
}

// Each file starts as if in a fresh transaction: no role or setting left over from the file before it.
async function clean(t) {
  await t`reset all`;
  await t`reset role`;
}

// claims: the checked identity token (sha, run_id, actor, event_name, jti). Returns the run's result.
// The whole run is ONE transaction: the reset (if due) and every pending migration commit together or not at all,
// so a failure anywhere leaves the database exactly as it was.
export async function run(sql, { files, reset }, claims) {
  const { didReset, applied } = await sql.begin(async (t) => {
    await t`select pg_advisory_xact_lock(hashtext(${LOCK}))`;
    let have = await ledger(t);
    const didReset = Boolean(reset) && have.get(reset.when.version) === reset.when.sha256;
    if (didReset) {
      await t.unsafe(reset.sql);
      await clean(t);
      have = await ledger(t);
    }
    const known = new Set(files.map((f) => f.version));
    const missing = [...have.keys()].filter((v) => !known.has(v));
    if (missing.length) throw new Error('applied migrations missing from the merged commit: ' + missing.sort().join(', '));
    const applied = [];
    for (const f of files) {
      if (have.has(f.version)) {
        if (have.get(f.version) !== f.sha256) throw new Error(f.version + ' changed after it was applied; put the change in a new migration');
        continue;
      }
      await t.unsafe(f.sql);
      await clean(t);
      await t`set local role dog_owner`;
      await t`insert into app.schema_migrations (version, sha256) values (${f.version}, ${f.sha256})`;
      await clean(t);
      applied.push(f.version);
    }
    return { didReset, applied };
  });

  const failed = await checks(sql, files);
  const warnings = await leftovers(sql);
  await sql.begin(async (t) => {
    const [{ exists }] = await t`select to_regclass('app.change_log') is not null and to_regclass('app.runner_tokens') is not null as exists`;
    if (!exists) return;
    await t`set local role dog_owner`;
    await t`insert into app.runner_tokens (jti) values (${claims.jti}) on conflict do nothing`;
    if (!didReset && !applied.length) return;
    const list = files.filter((f) => applied.includes(f.version)).map((f) => ({ version: f.version, sha256: f.sha256 }));
    await t`insert into app.change_log (commit_sha, run_id, actor, event, reset, applied, result)
      values (${claims.sha}, ${String(claims.run_id || '')}, ${String(claims.actor || '')}, ${claims.event_name},
              ${didReset}, ${t.json(list)}, ${failed.length ? 'checks_failed' : 'ok'})`;
  });
  return { ok: failed.length === 0, commit: claims.sha, reset: didReset, applied, total: files.length, failed, warnings };
}

// Things the fresh build tries to remove but treats as notes, not failures, if Supabase doesn't allow it.
export async function leftovers(sql) {
  const [r] = await sql`select
      to_regprocedure('public.rls_auto_enable()') is not null as rls_fn,
      to_regclass('vault.secrets') is not null as vault`;
  const out = [];
  if (r.rls_fn) out.push('public.rls_auto_enable() still exists');
  if (r.vault) {
    const [{ n }] = await sql`select count(*)::int as n from vault.secrets where name = 'dog_web_password'`.catch(() => [{ n: -1 }]);
    if (n !== 0) out.push(n < 0 ? 'Vault could not be read to confirm dog_web_password is gone' : 'dog_web_password is still in Vault');
  }
  return out;
}

// Names of the checks that failed; empty when all pass.
// siteLogin: the site login's name (tests use their own, since roles are shared by every database on a server).
export async function checks(sql, files, { siteLogin = SITE_LOGIN } = {}) {
  const failed = [];
  const have = await sql.begin(ledger);
  const same = have.size === files.length && files.every((f) => have.get(f.version) === f.sha256);
  if (!same) failed.push('ledger equals the merged migrations');
  const [r] = await sql`
    select
      (select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'app' and c.relkind in ('r', 'p') and not (c.relrowsecurity and c.relforcerowsecurity))::int as open_tables,
      (select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'app' and c.relname ilike '%passkey%')::int as passkey_objects,
      (select count(*) from pg_trigger g join pg_class c on c.oid = g.tgrelid join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'app' and g.tgname ilike '%step_up%')::int as step_up_triggers,
      (select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'app' and (p.proname ilike '%passkey%' or p.proname ilike '%step_up%'))::int as passkey_functions,
      (select count(*) from pg_roles where rolcanlogin and rolname = any (${ROLES}))::int as login_roles,
      (select count(*) from pg_roles w where w.rolname = ${siteLogin} and (w.rolsuper or w.rolinherit or w.rolbypassrls or w.rolcreaterole
        or w.rolcreatedb or w.rolreplication
        or exists (select 1 from pg_auth_members a join pg_roles g on g.oid = a.roleid where a.member = w.oid and g.rolname <> 'dog_app')
        -- Its one membership is plain: it may switch to dog_app, never grant it on or inherit it (fix 3's review, finding 3).
        or exists (select 1 from pg_auth_members a join pg_roles g on g.oid = a.roleid where a.member = w.oid and (a.admin_option or a.inherit_option))
        -- No rights or objects of its own in this database: nothing granted to it directly, nothing it owns, no policy naming it.
        or exists (select 1 from pg_shdepend d where d.refclassid = 'pg_authid'::regclass and d.refobjid = w.oid
                     and d.dbid = (select oid from pg_database where datname = current_database()))
        -- No settings of its own (PR #49 review): only a superuser could give it one, such as session_replication_role.
        or exists (select 1 from pg_db_role_setting s where s.setrole = w.oid)
        -- And dog_app itself belongs to no role, so it can't carry another role's rights to the login.
        or exists (select 1 from pg_auth_members a join pg_roles g on g.oid = a.member where g.rolname = 'dog_app')
        or (w.rolcanlogin and not exists (select 1 from pg_auth_members a join pg_roles g on g.oid = a.roleid where a.member = w.oid and g.rolname = 'dog_app'))))::int as wide_site_login`;
  if (r.open_tables) failed.push('row-level security forced on every app table');
  if (r.passkey_objects || r.step_up_triggers || r.passkey_functions) failed.push('no passkey tables, functions or step-up triggers');
  if (r.login_roles) failed.push('no database role of ours can sign in');
  if (r.wide_site_login) failed.push('the site login (dog_web) is no wider than dog_app');
  return failed;
}
