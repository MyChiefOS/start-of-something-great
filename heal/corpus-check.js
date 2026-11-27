#!/usr/bin/env node
// The honest-corpus check for healer proposals (096): every draft rule's normalized phrases against the golden set of
// honest lines (heal/golden.json), normalized the same way. A phrase found in an honest line fails the check, as the
// database's patch gate holds a fingerprint that would. Exit 1 on any hit.
'use strict';
const fs = require('fs');
const path = require('path');
const fp = require('./fingerprint');
const golden = require('./golden-sql').lines().map((l) => [l, fp.norm(l)]);

const dir = process.argv[2] || path.join(__dirname, 'drafts');
const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')) : [];
let bad = 0;
for (const f of files) {
  const d = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  for (const ph of d.normalized_phrases || []) {
    if (typeof ph !== 'string' || ph.length < 24) { console.log(f + ': phrase too short or generic: ' + JSON.stringify(ph)); bad++; continue; }
    const hit = golden.find(([, n]) => n.includes(ph));
    if (hit) { console.log(f + ': phrase matches an honest line: ' + JSON.stringify(hit[0])); bad++; }
  }
}
console.log(files.length + ' draft rule(s) checked against ' + golden.length + ' honest lines: ' + (bad ? bad + ' problem(s)' : 'clean'));
process.exit(bad ? 1 : 0);
