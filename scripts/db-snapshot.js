#!/usr/bin/env node
// Rebuilds db/snapshot.txt, the reviewed record of every policy, right, default, constraint, trigger and function
// (db/checks.js, fingerprint). It makes a throwaway database on TEST_DATABASE_URL's server, applies the
// migrations, records the result and drops the database. Run it after adding a migration, and review the diff.
// Usage: TEST_DATABASE_URL=postgres://... npm run db:snapshot
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('../db');
const { migrate } = require('./migrate');
const { fingerprint } = require('../db/checks');

const OUT = path.join(__dirname, '..', 'db', 'snapshot.txt');

async function main() {
  const base = process.env.TEST_DATABASE_URL;
  if (!base) throw new Error('TEST_DATABASE_URL is not set');
  const name = 'dog_snapshot_' + crypto.randomBytes(4).toString('hex');
  const server = db.connect(base, { max: 1, ssl: false });
  const u = new URL(base); u.pathname = '/' + name;
  await server`create database ${server(name)}`;
  const target = db.connect(u.toString(), { max: 1, ssl: false });
  try {
    await migrate(target);
    const lines = await fingerprint(target);
    fs.writeFileSync(OUT, '# Reviewed database snapshot. Rebuild with: npm run db:snapshot\n' + lines.join('\n') + '\n');
    console.log('wrote ' + lines.length + ' lines to db/snapshot.txt');
  } finally {
    await target.end({ timeout: 5 });
    await server`drop database if exists ${server(name)} with (force)`;
    await server.end({ timeout: 5 });
  }
}

main().catch((e) => { console.error('snapshot failed: ' + e.message); process.exit(1); });
