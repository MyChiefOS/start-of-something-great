#!/usr/bin/env node
// Writes db/manifest.json: every migration with its SHA-256, plus the one-time reset (if any) and the
// exact live migration that must be present for it to run. The runner (supabase/functions/dog-migrate) applies only
// what this file lists, at the merged commit; test/runner.test.js fails if it is out of date.
// Usage: node scripts/manifest.js          (rewrite)
//        node scripts/manifest.js --check  (exit 1 if out of date)
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { migrations } = require('./migrate');

const root = path.join(__dirname, '..');
const FILE = path.join(root, 'db', 'manifest.json');
const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');

// The one-time fresh build of Oct 24, 2026 (PR 2): runs only against the Oct 23 build, which holds 014_passkeys.
// Remove this entry in a later PR once the run is recorded; the runner skips it anyway once 014_passkeys is gone.
const RESET = {
  file: 'db/reset/fresh-build.sql',
  when: { version: '014_passkeys', sha256: '56e45811f334653cbd3cd40f10dd840f525c60e8758e852dc89fa99803c14854' }
};

function build() {
  const m = { migrations: migrations().map(({ version, sha256 }) => ({ version, sha256 })) };
  if (RESET) m.reset = { file: RESET.file, sha256: hash(fs.readFileSync(path.join(root, RESET.file), 'utf8')), when: RESET.when };
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
