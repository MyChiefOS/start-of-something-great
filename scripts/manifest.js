#!/usr/bin/env node
// Writes db/manifest.json: every migration with its SHA-256. The runner (supabase/functions/dog-migrate) applies only
// what this file lists, at the merged commit; test/runner.test.js fails if it is out of date.
// The runner also accepts a one-time reset entry ({ file, sha256, when }), but none is named now: the Oct 24 fresh
// build's entry (db/reset/fresh-build.sql, when 014_passkeys) was removed in R-14 (harness/REVIEW-2026-10-26.md)
// because it could never run again (the live ledger holds 014_subagents). test/runner.test.js still rehearses that
// reset, naming it itself, and the file stays as the way back to the Oct 23 build (OPERATIONS.md, PR 2 row).
// Usage: node scripts/manifest.js          (rewrite)
//        node scripts/manifest.js --check  (exit 1 if out of date)
'use strict';

const fs = require('fs');
const path = require('path');
const { migrations } = require('./migrate');

const root = path.join(__dirname, '..');
const FILE = path.join(root, 'db', 'manifest.json');

function build() {
  const m = { migrations: migrations().map(({ version, sha256 }) => ({ version, sha256 })) };
  return JSON.stringify(m, null, 2) + '\n';
}

if (require.main === module) {
  const want = build();
  if (process.argv.includes('--check')) {
    const have = fs.existsSync(FILE) ? fs.readFileSync(FILE, 'utf8') : '';
    if (have !== want) { console.error('db/manifest.json is out of date: run node scripts/manifest.js'); process.exit(1); }
  } else {
    fs.writeFileSync(FILE, want);
    console.log('wrote db/manifest.json');
  }
}

module.exports = { build, FILE };
