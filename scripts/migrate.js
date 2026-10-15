#!/usr/bin/env node
// Applies db/migrations/*.sql in order, each in its own transaction, and records each one with its SHA-256.
// A migration that was applied and later edited stops the run: changes go in a new file, never into an old one.
// Usage: MIGRATION_DATABASE_URL=postgres://... node scripts/migrate.js
// The address is a direct (or session-mode) connection with rights to create roles and schemas; the site itself
// never uses it. This is the only place raw SQL runs, and only from files in this repository.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('../db');

const DIR = path.join(__dirname, '..', 'db', 'migrations');
const NAME = /^(\d{3})_[a-z0-9_]+\.sql$/;

function migrations(dir = DIR) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  return files.map((f, i) => {
    const m = f.match(NAME);
    if (!m) throw new Error('migration file names look like 001_name.sql: ' + f);
    if (Number(m[1]) !== i + 1) throw new Error('migrations must be numbered 001, 002, ... with no gaps: ' + f);
    const sql = fs.readFileSync(path.join(dir, f), 'utf8');
    return { version: f.replace(/\.sql$/, ''), sql, sha256: crypto.createHash('sha256').update(sql).digest('hex') };
  });
}

async function applied(t) {
  const [{ exists }] = await t`select to_regclass('app.schema_migrations') is not null as exists`;
  if (!exists) return new Map();
  await t`set local role dog_owner`;
  const rows = await t`select version, sha256 from app.schema_migrations`;
  await t`reset role`;
  return new Map(rows.map((r) => [r.version, r.sha256]));
}

// Returns the versions it applied. Safe to run again: applied migrations are checked and skipped.
async function migrate(sql, { dir = DIR, log = () => {} } = {}) {
  const done = [];
  const files = migrations(dir);
  // A migration that ran but whose file is gone means the repository no longer describes the database.
  const known = new Set(files.map((m) => m.version));
  const missing = [...(await sql.begin(applied)).keys()].filter((ver) => !known.has(ver));
  if (missing.length) throw new Error('applied migrations missing from the repository: ' + missing.join(', '));
  for (const m of files) {
    const ran = await sql.begin(async (t) => {
      // One runner at a time, even if two deploys start together.
      await t`select pg_advisory_xact_lock(hashtext('dayonegreat.migrate'))`;
      const have = await applied(t);
      if (have.has(m.version)) {
        if (have.get(m.version) !== m.sha256) throw new Error(m.version + ' changed after it was applied; put the change in a new migration');
        return false;
      }
      await t.unsafe(m.sql);
      await t`set local role dog_owner`;
      await t`insert into app.schema_migrations (version, sha256) values (${m.version}, ${m.sha256})`;
      return true;
    });
    if (ran) { done.push(m.version); log('applied ' + m.version); }
  }
  return done;
}

if (require.main === module) {
  const url = process.env.MIGRATION_DATABASE_URL;
  if (!url) { console.error('MIGRATION_DATABASE_URL is not set'); process.exit(1); }
  const ssl = process.env.MIGRATION_SSL === 'off' ? false : db.tls(process.env.MIGRATION_DATABASE_CA);
  const sql = db.connect(url, { max: 1, ssl });
  migrate(sql, { log: console.log })
    .then((done) => { console.log(done.length ? 'done' : 'already up to date'); return sql.end(); })
    .catch((e) => { console.error('migration failed: ' + e.message); return sql.end().then(() => process.exit(1)); });
}

module.exports = { migrate, migrations };
