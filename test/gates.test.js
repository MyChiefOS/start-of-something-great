// S10, S11, SF6 and the risk register: the release gates that live outside the test suite are in place and pinned.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { gate, CRITICAL } = require('../scripts/sarif-gate');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('S10: CodeQL runs on every pull request and on main, pinned to a commit, with its settings saved in the repo', () => {
  const wf = read('.github/workflows/codeql.yml');
  assert.match(wf, /pull_request:/);
  for (const step of ['init', 'analyze']) assert.match(wf, new RegExp('github/codeql-action/' + step + '@[0-9a-f]{40}'), step + ' is pinned to a commit');
  assert.match(wf, /config-file: \.\/\.github\/codeql\/codeql-config\.yml/);
  assert.match(wf, /node scripts\/sarif-gate\.js sarif-results/);
  assert.match(read('.github/codeql/codeql-config.yml'), /security-extended/);
});

test('S10: the CodeQL gate fails on a critical finding and lets lower ones through for the risk register', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sarif-'));
  try {
    const sarif = (sev) => ({ runs: [{ tool: { driver: { rules: [{ id: 'js/x', properties: { 'security-severity': String(sev) } }] } },
      results: [{ ruleId: 'js/x', message: { text: 'example' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'api/x.js' }, region: { startLine: 3 } } }] }] }] });
    fs.writeFileSync(path.join(dir, 'a.sarif'), JSON.stringify(sarif(6.1)));
    assert.deepStrictEqual([gate(dir).all.length, gate(dir).critical.length], [1, 0]);
    fs.writeFileSync(path.join(dir, 'b.sarif'), JSON.stringify(sarif(CRITICAL)));
    assert.strictEqual(gate(dir).critical.length, 1);
    assert.strictEqual(gate(dir).critical[0].file, 'api/x.js');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('S11: every build checks the locked dependencies for critical advisories', () => {
  assert.match(read('.github/workflows/checks.yml'), /npm audit --package-lock-only --audit-level=critical/);
  assert.ok(fs.existsSync(path.join(root, 'package-lock.json')));
});

test('S10: Semgrep scans every script the site serves', () => {
  const wf = read('.github/workflows/checks.yml');
  const scanned = /semgrep scan[^\n]*/.exec(wf)[0];
  for (const f of fs.readdirSync(root).filter((x) => x.endsWith('.js'))) assert.ok(scanned.includes(' ' + f), f + ' is scanned');
});

test('the risk register: every row has a severity, a control, an owner, a due date and a place for Aaron\'s sign-off', () => {
  const rows = read('RISKS.md').split('\n').filter((l) => /^\| RK\d+ \|/.test(l));
  assert.ok(rows.length >= 10);
  for (const r of rows) {
    const cells = r.split('|').slice(1, -1).map((x) => x.trim());
    assert.strictEqual(cells.length, 7, r);
    assert.match(cells[2], /^\d+\.\d (Low|Medium|High)$/, 'severity: ' + r);
    for (const i of [3, 4, 5]) assert.ok(cells[i].length > 0, r);
  }
});

test('SF6: one release checklist covers decisions, accounts, legal and the go-live decision', () => {
  const c = read('RELEASE-CHECKLIST.md');
  for (const h of ['## Decisions', '## Accounts and settings', '## Legal', '## Go live']) assert.ok(c.includes(h), h);
  assert.match(c, /go-live decision/);
  for (const f of ['SIGNIN-SETUP.md', 'db/README.md', 'RISKS.md']) assert.ok(c.includes(f), f);
});
