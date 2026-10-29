// Runner and workflow alerts (harness/REVIEW-2026-10-26.md, R-2, R-3, R-7). Every check here alerts and never
// blocks the site, the JEVs gate or the runner (Aaron: checks alert, never lock out).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const digests = require('../scripts/function-digests');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

// ---- R-3: each Edge Function reports which source version it was deployed from.

test('R-3: every function has a source digest file, and each is up to date (run node scripts/function-digests.js)', () => {
  const want = digests.build();
  assert.deepStrictEqual(Object.keys(want).sort(), ['dog-keys', 'dog-migrate', 'jevs'].map((n) => 'supabase/functions/' + n + '/source-digest.mjs'));
  for (const [f, text] of Object.entries(want)) assert.strictEqual(read(f), text, f + ' is stale: run node scripts/function-digests.js');
});

test('R-3: the digest covers exactly the files each function is deployed with (OPERATIONS.md lists the same)', () => {
  assert.deepStrictEqual(digests.sources('jevs'), ['_shared/github-oidc.mjs', 'dog-migrate/core.mjs', 'jevs/core.mjs', 'jevs/gate.mjs', 'jevs/index.ts']);
  assert.deepStrictEqual(digests.sources('dog-migrate'), ['_shared/github-oidc.mjs', 'dog-migrate/core.mjs', 'dog-migrate/index.ts']);
  assert.deepStrictEqual(digests.sources('dog-keys'), ['_shared/vercel-oidc.mjs', 'dog-keys/core.mjs', 'dog-keys/index.ts']);
  // Every relative import of every source file is itself a source (nothing deployed is left out of the digest).
  for (const fn of digests.functions()) {
    const files = new Set(digests.sources(fn));
    for (const f of files) {
      for (const spec of digests.relativeImports(read('supabase/functions/' + f))) {
        const dep = path.posix.normalize(path.posix.join(path.posix.dirname(f), spec));
        if (path.posix.basename(dep) !== 'source-digest.mjs') assert.ok(files.has(dep), fn + ': ' + f + ' imports ' + dep + ', not in the digest');
      }
    }
  }
});

test('R-3: the digest is what sha256sum gives, so anyone can check it by hand', () => {
  for (const fn of digests.functions()) {
    const text = read('supabase/functions/' + fn + '/source-digest.mjs');
    const lines = digests.sources(fn).map((f) => sha(fs.readFileSync(path.join(digests.ROOT, f))) + '  ' + f + '\n').join('');
    assert.ok(text.includes('export const SOURCE_DIGEST = "' + sha(lines) + '";'), fn);
  }
});

test('R-3: changing any source file changes the digest, so a stale digest file fails this suite', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-digest-'));
  try {
    fs.cpSync(digests.ROOT, tmp, { recursive: true });
    const before = digests.digestOf('jevs', tmp).digest;
    assert.strictEqual(before, digests.digestOf('jevs').digest);
    fs.appendFileSync(path.join(tmp, '_shared', 'github-oidc.mjs'), '\n// changed');
    assert.notStrictEqual(digests.digestOf('jevs', tmp).digest, before, 'a shared file is part of the digest');
    assert.notStrictEqual(digests.digestOf('dog-migrate', tmp).digest, digests.digestOf('dog-migrate').digest);
    assert.strictEqual(digests.digestOf('dog-keys', tmp).digest, digests.digestOf('dog-keys').digest, 'dog-keys does not use it');
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('R-3: every answer from every function carries x-source-digest, its own SOURCE_DIGEST (the GET 405 included)', () => {
  for (const fn of digests.functions()) {
    const src = read('supabase/functions/' + fn + '/index.ts');
    assert.match(src, /^import \{ SOURCE_DIGEST \} from "\.\/source-digest\.mjs";$/m, fn + ' imports its own digest');
    assert.match(src, /const reply = \([^)]*\) =>\s*Response\.json\(body, \{ status, headers: \{[^}]*"x-source-digest": SOURCE_DIGEST \}/, fn + ': reply() sets the header');
    assert.strictEqual((src.match(/Response\.json\(|new Response\(/g) || []).length, 1, fn + ': every answer goes through reply()');
    assert.match(src, /return reply\(405|status: 405|handle\(/, fn + ': a GET is refused through reply()');
  }
});

test('R-3: the daily watch GETs each function (no token, no secret), compares digests, and reports dog-probe', () => {
  const y = read('.github/workflows/watch.yml');
  assert.match(y, /^on:\n  schedule:\n    - cron: '\d+ \d+ \* \* \*'\n  workflow_dispatch:$/m, 'daily, or by hand');
  assert.match(y, /^permissions:\n  contents: read\n  issues: write/m);
  assert.doesNotMatch(y, /id-token|secrets\.|pull-requests:|contents: write|-X POST|--data/, 'reads only: no token, no secret, no PR, no POST to a function');
  assert.match(y, /-X GET "\$FUNCTIONS_URL\/\$fn"/);
  assert.match(y, /x-source-digest/);
  assert.match(y, /SOURCE_DIGEST = /, 'main\'s digest is read from the digest files');
  assert.match(y, /function-digests\.js --check/);
  assert.match(y, /dog-probe/);
  assert.match(y, /labels=jevs-alert/, 'it alerts on the JEVs alerts issue');
  for (const m of y.matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, 'pinned to a commit: ' + m[1]);
  assert.match(y, /persist-credentials: false/);
  assert.match(y, /if: github\.repository_id == 1418125608/);
});

// ---- R-2: the runner applies, then checks and reports; a failed check is now seen.

test('R-2: a failed check on a migration run, or on the daily drift check, comments on the alert issue', () => {
  const y = read('.github/workflows/database.yml');
  const migrate = y.split(/^  drift:$/m)[0];
  const drift = y.split(/^  drift:$/m)[1];
  assert.match(migrate, /- name: Alert when the runner's checks failed, or the run did \(R-2\)\n\s+#[^\n]*\n\s+#[^\n]*\n\s+if: always\(\) && steps\.run\.outcome != 'skipped'/);
  assert.match(migrate, /\.ok == true and \(\(\.failed \/\/ \[\]\) \| length == 0\)/, 'a pass posts nothing');
  assert.match(migrate, /issues\/\$issue\/comments/);
  assert.match(drift, /\(\.failed \/\/ \[\]\)\[\]/, 'the drift check reads the runner\'s catalog checks');
  assert.match(drift, /steps\.drift\.outputs\.checks == 'failed'/);
  // The status answer that the scheduled drift check gets runs the catalog checks, and still only reads.
  const ix = read('supabase/functions/dog-migrate/index.ts');
  assert.match(ix, /if \(mode === "status"\) \{\n\s+return reply\(200, \{ ok: true, ledger: await status\(sql\), failed: await catalogChecks\(sql\), warnings: await leftovers\(sql\) \}\);/);
  assert.ok(ix.indexOf('mode === "status"') < ix.indexOf('claims.event_name === "schedule"'), 'status is answered before the schedule refusal, and does nothing else');
  // The checks never stop anything: no exit, no failing the job, in either alert step.
  for (const part of [migrate.split("Alert when the runner's checks failed")[1], drift.split('Alert on drift')[1]]) assert.doesNotMatch(part, /exit 1/);
});

test('R-2: no record says the runner "refuses" migrations on a failed check', () => {
  const rk71 = read('RISKS.md').split('\n').find((l) => l.startsWith('| RK71 '));
  assert.match(rk71, /applies the migrations in one transaction, then checks and reports/);
  const st = read('harness/STATUS.md');
  assert.doesNotMatch(st, /runner allows exactly one narrow site login/);
  assert.match(read('supabase/functions/dog-migrate/core.mjs'), /a failed check does not undo or\n\/\/\s+refuse the migrations/);
});

// ---- R-7: the scanners cover the functions and the workflows; a workflow lint and a scheduled audit, report only.

test('R-7: Semgrep scans supabase/ and the workflows, with a rule written for the workflows', () => {
  const y = read('.github/workflows/checks.yml');
  const line = y.split('\n').find((l) => /semgrep scan/.test(l));
  for (const p of ['supabase/', '.github/workflows/']) assert.ok(line.split(/\s+/).includes(p), 'Semgrep scans ' + p);
  const rules = read('.semgrep/workflows.yml');
  assert.match(rules, /languages: \[yaml\]/);
  assert.match(rules, /github\\\.event\\\.\|/);
});

test('R-7: actionlint is pinned by version and checksum, and can never fail the job', () => {
  const y = read('.github/workflows/checks.yml');
  const step = y.split('- name: Workflow lint')[1].split('\n      - ')[0];
  assert.match(step, /continue-on-error: true/);
  assert.match(step, /releases\/download\/v1\.7\.7\/actionlint_1\.7\.7_linux_amd64\.tar\.gz/);
  assert.match(step, /echo "[0-9a-f]{64}  al\.tgz" \| sha256sum -c -/);
  assert.match(step, /\.\/actionlint [^\n]*\|\| true/);
});

test('R-7: the dependency audit is scheduled, covers the functions\' npm imports, and alerts by comment, never by PR', () => {
  const y = read('.github/workflows/watch.yml');
  assert.match(y, /npm audit --package-lock-only --json/);
  assert.match(y, /"npm:\[\^"\]\+"/, 'the functions\' npm: imports are audited too');
  assert.match(y, /--ignore-scripts/);
  assert.doesNotMatch(y, /dependabot|pull-requests|gh pr /i);
  assert.match(y, /daily-watch:\$key/, 'an unchanged finding is repeated at most once a week');
  // Every npm: import in the functions is an exact version, so the audit checks what is deployed.
  for (const fn of digests.functions()) {
    for (const f of digests.sources(fn)) {
      for (const m of read('supabase/functions/' + f).matchAll(/"npm:([^"]+)"/g)) assert.match(m[1], /^(@[a-z0-9-]+\/)?[a-z0-9.-]+@\d+\.\d+\.\d+$/, f + ': ' + m[1]);
    }
  }
});
