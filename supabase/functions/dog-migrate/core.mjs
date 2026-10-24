// The database runner's work (USE-CASES.md row 15), shared by the Supabase function (index.ts) and the tests, so
// the code CI rehearses is the code production runs. It does what scripts/migrate.js does, from a merged commit:
//   1. reads db/manifest.json at that commit, fetches every file it names and checks each SHA-256;
//      nothing touches the database until every file matches;
//   2. runs the one-time reset (db/reset/) only if the manifest names it and the live ledger holds the exact
//      migration its "when" names;
//   3. applies each pending migration in its own transaction, under one advisory lock, recording it in
//      app.schema_migrations (a migration already applied must still match; one missing from the manifest stops);
//   4. checks the result: every app table has row-level security forced, the ledger equals the manifest, no
//      passkey table or step-up trigger exists, and no dog_* role can sign in;
//   5. writes one app.change_log row if anything changed, and records the identity token's ID so it can't be reused.
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
// The roles the migrations use, and dog_web, the login 017 made. None may sign in.
const ROLES = ['dog_owner', 'dog_app', 'dog_public', 'dog_signin', 'dog_jevs', 'dog_limits', 'dog_delegate', 'dog_erase', 'dog_web'];

export async function tokenSeen(sql, jti) {
  return sql.begin(async (t) => {
    const [{ exists }] = await t`select to_regclass('app.runner_tokens') is not null as exists`;
    if (!exists) return false;
    await t`set local role dog_owner`;
    const r = await t`select 1 from app.runner_tokens where jti = ${jti}`;
    return r.length > 0;
  });
}

export async function status(sql) {
  const have = await sql.begin(ledger);
  return [...have].sort().map(([version, sha]) => ({ version, sha256: sha }));
}

// claims: the checked identity token (sha, run_id, actor, event_name, jti). Returns the run's result.
export async function run(sql, { files, reset }, claims) {
  let didReset = false;
  if (reset) {
    didReset = await sql.begin(async (t) => {
      await t`select pg_advisory_xact_lock(hashtext(${LOCK}))`;
      const have = await ledger(t);
      if (have.get(reset.when.version) !== reset.when.sha256) return false;
      await t.unsafe(reset.sql);
      return true;
    });
  }

  const known = new Set(files.map((f) => f.version));
  const missing = [...(await sql.begin(ledger)).keys()].filter((v) => !known.has(v));
  if (missing.length) throw new Error('applied migrations missing from the merged commit: ' + missing.sort().join(', '));

  const applied = [];
  for (const f of files) {
    const ran = await sql.begin(async (t) => {
      await t`select pg_advisory_xact_lock(hashtext(${LOCK}))`;
      const have = await ledger(t);
      if (have.has(f.version)) {
        if (have.get(f.version) !== f.sha256) throw new Error(f.version + ' changed after it was applied; put the change in a new migration');
        return false;
      }
      await t.unsafe(f.sql);
      await t`set local role dog_owner`;
      await t`insert into app.schema_migrations (version, sha256) values (${f.version}, ${f.sha256})`;
      return true;
    });
    if (ran) applied.push(f.version);
  }

  const failed = await checks(sql, files);
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
  return { ok: failed.length === 0, commit: claims.sha, reset: didReset, applied, total: files.length, failed };
}

// Names of the checks that failed; empty when all pass.
export async function checks(sql, files) {
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
      (select count(*) from pg_roles where rolcanlogin and rolname = any (${ROLES}))::int as login_roles`;
  if (r.open_tables) failed.push('row-level security forced on every app table');
  if (r.passkey_objects || r.step_up_triggers || r.passkey_functions) failed.push('no passkey tables, functions or step-up triggers');
  if (r.login_roles) failed.push('no database role of ours can sign in');
  return failed;
}
