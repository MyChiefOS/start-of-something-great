#!/usr/bin/env node
// Backup restore test (O2, RISKS.md RK12): proves the live data can be rebuilt, not just that a backup exists.
// Run only by the "Restore test" workflow (.github/workflows/restore-test.yml), on main, in the protected
// "production" environment after Aaron approves the run.
//
// 1. Builds an empty database from the migrations, inside the run's own throwaway Postgres.
// 2. Copies every row of the live app schema into it (pg_dump, data only; the live address's user bypasses
//    row-level security, so nothing is filtered out).
// 3. Compares the row count of every table, live against restored, and runs the coverage check on the copy.
// The copy and the dump file never leave the runner, are never uploaded, and are deleted at the end.
//
// Settings: SOURCE_DATABASE_URL (the live migration address), SOURCE_DATABASE_CA, TARGET_DATABASE_URL (the
// throwaway database, a superuser so the copy can load with triggers off).
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const db = require('../db');
const { migrate } = require('./migrate');

const exec = (cmd, args, env) => new Promise((resolve, reject) => {
  execFile(cmd, args, { env: { ...process.env, ...env }, maxBuffer: 16 * 1024 * 1024 }, (e, stdout, stderr) => {
    // Postgres tools can echo a connection string in some errors; never pass their output on.
    if (e) return reject(new Error(cmd + ' failed (exit ' + (e.code ?? '?') + ')'));
    resolve(stdout);
  });
});

// libpq's environment variables for an address, so no password ever appears on a command line.
function pgEnv(url) {
  const u = new URL(url);
  return { PGHOST: u.hostname, PGPORT: u.port || '5432', PGUSER: decodeURIComponent(u.username), PGPASSWORD: decodeURIComponent(u.password), PGDATABASE: decodeURIComponent(u.pathname.slice(1)) || 'postgres' };
}

// Puts each trigger back in the mode it had.
async function setModes(t, modes) {
  for (const m of modes) {
    const tbl = t('app.' + m.tbl); const tg = t(m.name);
    if (m.mode === 'A') await t`alter table ${tbl} enable always trigger ${tg}`;
    else if (m.mode === 'R') await t`alter table ${tbl} enable replica trigger ${tg}`;
    else if (m.mode === 'O') await t`alter table ${tbl} enable trigger ${tg}`;
    else await t`alter table ${tbl} disable trigger ${tg}`;
  }
}

// Every table in the app schema and its row count, as this connection sees it.
async function counts(sql) {
  const tables = await sql`select tablename from pg_tables where schemaname = 'app' order by tablename`;
  const out = {};
  for (const { tablename } of tables) {
    const [{ n }] = await sql`select count(*)::bigint as n from ${sql('app')}.${sql(tablename)}`;
    out[tablename] = Number(n);
  }
  return out;
}

// Which tables differ, as readable lines; empty when the copy matches.
function differences(live, copy) {
  const names = [...new Set([...Object.keys(live), ...Object.keys(copy)])].sort();
  return names.filter((t) => live[t] !== copy[t]).map((t) => t + ': live ' + (live[t] ?? 'missing') + ', restored ' + (copy[t] ?? 'missing'));
}

async function restoreTest({ sourceUrl, sourceCa, targetUrl, log = console.log, check, afterRestore = null }) {
  if (!sourceUrl) throw new Error('SOURCE_DATABASE_URL is not set');
  if (!targetUrl) throw new Error('TARGET_DATABASE_URL is not set');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'restore-'));
  const dump = path.join(dir, 'app.dump');
  const caFile = path.join(dir, 'ca.pem');
  const source = db.connect(sourceUrl, { max: 1, ssl: sourceCa ? db.tls(sourceCa) : false });
  const target = db.connect(targetUrl, { max: 1, ssl: false });
  try {
    const built = await migrate(target, { log: () => {} });
    // The migrations seed some rows (settings, for one); the copy brings the live ones, so the throwaway database is
    // emptied first. Only ever the throwaway one: the live database is only read.
    const own = (await target`select tablename from pg_tables where schemaname = 'app' and tablename <> 'schema_migrations'`).map((t) => 'app.' + t.tablename);
    // Each trigger's exact mode (A always, O origin, R replica, D disabled), recorded now and put back after the
    // emptying below and after pg_restore, whose --disable-triggers switches them back on as plain "origin". The
    // coverage check at the end would catch any trigger left weaker than the migrations made it.
    const modes = await target`select c.relname as tbl, g.tgname as name, g.tgenabled as mode from pg_trigger g
      join pg_class c on c.oid = g.tgrelid join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'app' and not g.tgisinternal`;
    const putBack = (t) => setModes(t, modes);
    if (own.length) {
      // The triggers (the append-only audit log among them) are off just for the emptying.
      await target.begin(async (t) => {
        for (const name of own) await t`alter table ${t(name)} disable trigger all`;
        await t`truncate table ${t(own)}`;
        await putBack(t);
      });
    }
    log('throwaway database built from ' + built.length + ' migrations');
    const tlsEnv = sourceCa ? (fs.writeFileSync(caFile, sourceCa, { mode: 0o600 }), { PGSSLMODE: 'verify-full', PGSSLROOTCERT: caFile }) : {};
    // Connection details go in as environment variables, never on the command line, where the process list would
    // show the password. schema_migrations is already filled in by the migrations above.
    await exec('pg_dump', ['--data-only', '--schema=app', '--exclude-table=app.schema_migrations', '--format=custom', '--no-owner', '--no-privileges', '--file=' + dump], { ...pgEnv(sourceUrl), ...tlsEnv });
    log('live data copied out (' + Math.round(fs.statSync(dump).size / 1024) + ' KB)');
    await exec('pg_restore', ['--data-only', '--disable-triggers', '--single-transaction', '--exit-on-error', '--dbname=' + pgEnv(targetUrl).PGDATABASE, dump], { ...pgEnv(targetUrl), PGSSLMODE: 'disable' });
    await target.begin(putBack);
    log('copied into the throwaway database');
    if (afterRestore) await afterRestore(target);
    const live = await counts(source);
    const copy = await counts(target);
    const diff = differences(live, copy);
    if (diff.length) throw new Error('the restored copy differs:\n- ' + diff.join('\n- '));
    const total = Object.values(live).reduce((a, b) => a + b, 0);
    log('row counts match in all ' + Object.keys(live).length + ' tables (' + total + ' rows)');
    const p = await check(target);
    if (p.length) throw new Error('coverage check failed on the restored copy:\n- ' + p.join('\n- '));
    log('coverage check passed on the restored copy');
    return { tables: Object.keys(live).length, rows: total };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    await source.end({ timeout: 5 });
    await target.end({ timeout: 5 });
  }
}

function defaultCheck(sql) {
  const { problems } = require('../db/checks');
  const snapshot = fs.readFileSync(path.join(__dirname, '..', 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  return problems(sql, { snapshot });
}

if (require.main === module) {
  restoreTest({ sourceUrl: process.env.SOURCE_DATABASE_URL, sourceCa: process.env.SOURCE_DATABASE_CA, targetUrl: process.env.TARGET_DATABASE_URL, check: defaultCheck })
    .then((r) => console.log('restore test passed: ' + r.tables + ' tables, ' + r.rows + ' rows'))
    .catch((e) => { console.error('restore test FAILED: ' + e.message); process.exit(1); });
}

module.exports = { restoreTest, counts, differences, defaultCheck, pgEnv };
