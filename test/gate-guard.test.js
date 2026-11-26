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

// RK163: since GitHub's Dec 2, 2026 block on pull_request_target, gate-guard runs when the PR relay completes
// (workflow_run), which GitHub also runs from main's copy, on main.
test('RK146, RK163: gate-guard runs only after the PR relay (workflow_run), and the relay can do nothing', () => {
  const y = read(GG);
  assert.match(y, /^on:\n  workflow_run:\n    workflows: \[PR relay\]\n    types: \[completed\]\n\n/m);
  const on = y.split(/^on:\n/m)[1].split(/^\S/m)[0];
  assert.deepStrictEqual(on.match(/^  [a-z_]+:/gm), ['  workflow_run:'], 'no trigger that runs a copy the pull request controls');
  assert.match(y, /if: github\.event\.workflow_run\.event == 'pull_request'/);
  const r = read('.github/workflows/pr-relay.yml');
  assert.match(r, /^name: PR relay$/m);
  assert.match(r, /^on:\n  pull_request:\n    branches: \[main\]\n    types: \[opened, synchronize, reopened, edited, ready_for_review, closed\]\n/m);
  assert.match(r, /^permissions: \{\}$/m);
  assert.doesNotMatch(r, /uses:|\$\{\{|secrets\.|permissions:\n\s+[a-z]/);
  assert.deepStrictEqual([...r.matchAll(/run: (.*)/g)].map((m) => m[1]), ['echo "relayed"']);
});

test('RK146: gate-guard reads, writes only its own commit status, and holds no secret', () => {
  const y = read(GG);
  assert.match(y, /^permissions: \{\}$/m, 'nothing at the workflow level');
  const perms = [...y.matchAll(/^ {4}permissions:\n((?: {6}[a-z-]+: \w+\n)+)/gm)].map((m) => m[1].trim().split('\n').map((l) => l.trim()).sort());
  assert.deepStrictEqual(perms, [['contents: read', 'pull-requests: read', 'statuses: write']]);
  assert.doesNotMatch(y, /secrets\.|id-token|contents: write|pull-requests: write/);
  assert.match(y, /gh api -X POST "repos\/\$GITHUB_REPOSITORY\/statuses\/\$HEAD_SHA" -f state="\$state" -f context=gate-guard/);
});

test('RK146: gate-guard never checks out or runs the pull request\'s code, and no PR text reaches a shell', () => {
  const y = read(GG);
  const checkout = y.split('uses: actions/checkout@')[1].split('\n      - ')[0];
  assert.doesNotMatch(checkout, /\bref:|repository:/);
  assert.match(checkout, /persist-credentials: false/);
  assert.match(checkout, /sparse-checkout: scripts\/pr-guards\.js\n\s+sparse-checkout-cone-mode: false/);
  assert.doesNotMatch(y, /github\.event\.pull_request|github\.head_ref|refs\/pull|merge_commit_sha|allow-unsafe|head_branch|display_title/);
  assert.doesNotMatch(y, /npm (ci|install|run|test)|npx |git (fetch|checkout)|gh pr checkout|download-artifact/);
  // Event values only through env:, never inside run:; the head commit is checked as a SHA, the number as digits.
  for (const m of y.matchAll(/\$\{\{([^}]*)\}\}/g)) assert.match(m[1].trim(), /^(github\.token|github\.event\.workflow_run\.(head_sha|event)|github\.(server_url|repository|run_id)|github\.event\.workflow_run\.event == 'pull_request')$/, m[0]);
  for (const run of y.matchAll(/^\s+run: (.*)$/gm)) assert.doesNotMatch(run[1], /\$\{\{/);
  assert.match(y, /\[\[ "\$HEAD_SHA" =~ \^\[0-9a-f\]\{40\}\$ \]\]/);
  assert.match(y, /\[\[ "\$n" =~ \^\[0-9\]\+\$ \]\]/);
  assert.match(y, /PR_NUMBER="\$n" node scripts\/pr-guards\.js/);
});

test('RK146: gate-guard\'s actions are pinned by commit, like every other workflow', () => {
  for (const f of fs.readdirSync(path.join(root, '.github/workflows'))) {
    for (const m of read('.github/workflows/' + f).matchAll(/^\s*(?:- )?uses: ([^\s]+)/gm)) assert.match(m[1], /@[0-9a-f]{40}$/, f + ': ' + m[1]);
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
