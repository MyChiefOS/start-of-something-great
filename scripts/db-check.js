#!/usr/bin/env node
// Runs the database coverage check (db/checks.js: S1, S7, S8, S12, G3) against a real database, such as
// production right after a migration, to catch anything changed by hand outside the migrations.
// Usage: MIGRATION_DATABASE_URL=postgres://... node scripts/db-check.js   (exits 1 and lists problems on failure)
'use strict';

const db = require('../db');
const { problems } = require('../db/checks');

const url = process.env.MIGRATION_DATABASE_URL;
if (!url) { console.error('MIGRATION_DATABASE_URL is not set'); process.exit(1); }
const sql = db.connect(url, { max: 1, ssl: process.env.MIGRATION_SSL === 'off' ? false : 'require' });
problems(sql)
  .then(async (p) => {
    await sql.end();
    if (!p.length) { console.log('database coverage check passed'); return; }
    console.error('database coverage check failed:\n- ' + p.join('\n- '));
    process.exit(1);
  })
  .catch(async (e) => { console.error('database coverage check could not run: ' + e.message); await sql.end(); process.exit(1); });
