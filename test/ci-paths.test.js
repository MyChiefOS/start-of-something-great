// Every path the security scan is told to check must exist; a deleted file left in the list stops the scan in CI (found Oct 16, 2026: act.js).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

test('every path in the Semgrep step of checks.yml exists', () => {
  const root = path.join(__dirname, '..');
  const yml = fs.readFileSync(path.join(root, '.github/workflows/checks.yml'), 'utf8');
  const lines = yml.split('\n').filter((l) => /semgrep scan/.test(l));
  assert.ok(lines.length > 0, 'no Semgrep step found');
  for (const l of lines) {
    const paths = l.split('--error')[1].trim().split(/\s+/);
    for (const p of paths) assert.ok(fs.existsSync(path.join(root, p)), 'checks.yml scans a path that does not exist: ' + p);
  }
});
