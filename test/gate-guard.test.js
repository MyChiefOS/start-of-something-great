// RK146: the required `checks` status runs from the pull request's own copy of checks.yml and scripts/pr-guards.js, so
// a pull request could weaken its own gate. gate-guard.yml runs the same PR guards from main's copy, on
// pull_request_target, and never checks out or runs the pull request's code. These tests hold it to GitHub's guidance
// for that event (docs.github.com, "Securely using pull_request_target"): no checkout of the PR head, no PR text in a
// shell, minimal permissions. And CodeQL's scope covers the privileged code it used to skip.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const GG = '.github/workflows/gate-guard.yml';

test('RK146: gate-guard runs on pull_request_target only, for pull requests to main, including description edits', () => {
  const y = read(GG);
  assert.match(y, /^on:\n  pull_request_target:\n    branches: \[main\]\n    types: \[opened, synchronize, reopened, edited\]\n\n/m);
  // No other trigger: a push or pull_request trigger would run a copy the pull request controls.
  const on = y.split(/^on:\n/m)[1].split(/^\S/m)[0];
  assert.deepStrictEqual(on.match(/^  [a-z_]+:/gm), ['  pull_request_target:']);
});

test('RK146: gate-guard holds no write permission and no secret', () => {
  const y = read(GG);
  assert.match(y, /^permissions: \{\}$/m, 'nothing at the workflow level');
  const perms = [...y.matchAll(/^ {4}permissions:\n((?: {6}[a-z-]+: \w+\n)+)/gm)].map((m) => m[1].trim().split('\n').map((l) => l.trim()).sort());
  assert.deepStrictEqual(perms, [['contents: read', 'pull-requests: read']]);
  assert.doesNotMatch(y, /: write|secrets\.|id-token/);
});

test('RK146: gate-guard never checks out or runs the pull request\'s code, and no PR text reaches a shell', () => {
  const y = read(GG);
  // The checkout takes no ref, so on pull_request_target it is main's latest commit (GITHUB_SHA), and only the guard.
  const checkout = y.split('uses: actions/checkout@')[1].split('\n      - ')[0];
  assert.doesNotMatch(checkout, /\bref:|repository:/);
  assert.match(checkout, /persist-credentials: false/);
  assert.match(checkout, /sparse-checkout: scripts\/pr-guards\.js\n\s+sparse-checkout-cone-mode: false/);
  assert.doesNotMatch(y, /github\.event\.pull_request\.(head|title|body|user)|github\.head_ref|refs\/pull|merge_commit_sha|allow-unsafe/);
  assert.doesNotMatch(y, /npm (ci|install|run|test)|npx |git (fetch|checkout)|gh pr checkout|download-artifact/);
  // The only event value used is the PR number, through env:, never inside run:.
  for (const m of y.matchAll(/\$\{\{([^}]*)\}\}/g)) assert.match(m[1].trim(), /^(github\.token|github\.event\.pull_request\.number)$/, m[0]);
  for (const run of y.matchAll(/run: ([^\n]*)/g)) assert.doesNotMatch(run[1], /\$\{\{/);
  assert.match(y, /run: node scripts\/pr-guards\.js$/m);
});

test('RK146: gate-guard\'s actions are pinned by commit, like every other workflow', () => {
  for (const f of fs.readdirSync(path.join(root, '.github/workflows'))) {
    for (const m of read('.github/workflows/' + f).matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, f + ': ' + m[1]);
  }
});

test('RK146: CodeQL scans the privileged folders it skipped, and still leaves out tests and node_modules', () => {
  const c = read('.github/codeql/codeql-config.yml');
  const list = (key) => c.split(new RegExp('^' + key + ':\\n', 'm'))[1].split(/^\S/m)[0].split('\n').map((l) => l.replace(/^\s*-\s*/, '').replace(/'/g, '').trim()).filter(Boolean);
  const paths = list('paths');
  for (const p of ['api', 'db', 'signin', 'scripts', '*.js', 'supabase', 'secondlook', 'thirdlook', 'notify', 'verifier', 'tools']) assert.ok(paths.includes(p), 'CodeQL scans ' + p);
  for (const p of paths.filter((x) => !x.includes('*'))) assert.ok(fs.existsSync(path.join(root, p)), 'CodeQL scans a folder that does not exist: ' + p);
  const ignored = list('paths-ignore');
  for (const p of ['node_modules', 'test', '**/node_modules', '**/test']) assert.ok(ignored.includes(p), 'CodeQL ignores ' + p);
});
