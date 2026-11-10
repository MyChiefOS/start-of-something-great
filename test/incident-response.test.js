// STANDARDS.md gap 11: the written incident response plan. It keeps its parts, it rests on the close-the-site runbook,
// every file it points to exists (so it can't quietly go stale), and it never claims HIPAA coverage.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const plan = fs.readFileSync(path.join(root, 'INCIDENT-RESPONSE.md'), 'utf8');

test('gap 11: the plan has every part: who decides, levels, the first hour, the tools, evidence, telling people, the yearly test', () => {
  for (const h of ['## 1. Who decides, and what Claude may do alone', '## 2. How serious it is', '## 3. The first hour', '### 4.1 Close the site',
    '### 4.2 Rotate the site\'s keys (route B: Claude never sees a secret)', '### 4.3 Revoke agents', '### 4.4 Pause Second Look and Third Look',
    '## 5. Evidence kept', '## 6. Telling people', '## 8. The yearly test: a tabletop walkthrough', '## 9. Not built yet, and open questions']) {
    assert.ok(plan.includes(h + '\n'), 'missing: ' + h);
  }
  assert.match(plan, /\*\*Aaron decides\.\*\*/);
  assert.match(plan, /OPERATIONS\.md, "Runbook: close the site now"/);
  assert.ok(fs.readFileSync(path.join(root, 'OPERATIONS.md'), 'utf8').includes('## Runbook: close the site now'), 'the runbook it builds on is still there');
  assert.match(plan, /\*\*Not yet tested:\*\*/, 'it says plainly that it has not been tested');
});

test('gap 11: every file the plan points to exists', () => {
  const refs = new Set();
  // A file is a path in the repository (has a slash, doesn't start with one, unlike /api/status) or a file name with an
  // extension (launch.json). Database names such as app.audit_log are neither.
  for (const m of plan.matchAll(/`([^`\s]+)`/g)) {
    const r = m[1];
    if ((r.includes('/') && !r.startsWith('/')) || /\.(md|js|mjs|json|sql)$/.test(r)) refs.add(r);
  }
  for (const m of plan.matchAll(/\]\(([^)#:]+)\)/g)) refs.add(m[1]);
  assert.ok(refs.size >= 8, 'found ' + refs.size + ' file references');
  for (const r of refs) assert.ok(fs.existsSync(path.join(root, r)), 'INCIDENT-RESPONSE.md points to a file that does not exist: ' + r);
});

test('gap 11: HIPAA is for its practice only; the plan never claims coverage or compliance', () => {
  assert.match(plan, /not HIPAA-covered/);
  assert.doesNotMatch(plan, /HIPAA[- ]compliant|is HIPAA covered|FedRAMP[- ]authorized/i);
});
