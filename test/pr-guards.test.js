// USE-CASES.md row 14: the required check refuses a pull request that targets a side branch, has a commit GitHub can't
// verify, has a Claude commit under Aaron's identity, or doesn't list its commits.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { problems, AARON_EMAIL } = require('../scripts/pr-guards');

const ok = { sha: 'abcdef1234567890', verified: true, reason: 'valid', authorEmail: 'noreply@anthropic.com', committerEmail: 'noreply@anthropic.com' };

test('a pull request to main with verified Claude commits, all listed, passes', () => {
  assert.deepStrictEqual(problems({ base: 'main', body: 'Commits:\n- abcdef1 the change' }, [ok]), []);
});

test('a pull request to a side branch fails (the Oct 19 and 22 stranded merges)', () => {
  assert.match(problems({ base: 'launch-gate', body: 'abcdef1' }, [ok]).join(), /targets "launch-gate", not main/);
});

test('an unverified commit fails (the 15 Oct 17 commits)', () => {
  const c = { ...ok, verified: false, reason: 'unknown_key', authorEmail: AARON_EMAIL, committerEmail: AARON_EMAIL };
  const p = problems({ base: 'main', body: 'abcdef1' }, [c]).join('\n');
  assert.match(p, /not verified by GitHub \(unknown_key\)/);
  assert.match(p, /carries Aaron's email but was not made by him/);
});

test('Aaron\'s own commit made on GitHub passes', () => {
  const c = { ...ok, authorEmail: AARON_EMAIL, committerEmail: 'noreply@github.com' };
  assert.deepStrictEqual(problems({ base: 'main', body: 'abcdef1' }, [c]), []);
});

test('a description that does not list every commit fails (PR #36 listed 38 of 56)', () => {
  const second = { ...ok, sha: '1234567abcdef' };
  assert.match(problems({ base: 'main', body: 'abcdef1' }, [ok, second]).join(), /does not list commit 1234567/);
});

// ---- Dependabot's pull requests (RK147: Dependabot security updates are on). Its descriptions never list commits, so a
// PR opened by dependabot[bot], whose every commit is Dependabot's and verified, and which changes only dependency
// manifests, is let off listing its commits. Nothing else is loosened.

const DEP = require('../scripts/pr-guards').DEPENDABOT;
const depPr = (over) => ({ base: 'main', body: 'Bumps postgres from 3.4.9 to 3.4.10.', author: { login: 'dependabot[bot]', id: 49699333, type: 'Bot' }, headRepo: 'MyChiefOS/start-of-something-great', baseRepo: 'MyChiefOS/start-of-something-great', ...over });
const depCommit = (over) => ({ sha: 'dddddddeadbeef00', verified: true, reason: 'valid', authorEmail: '49699333+dependabot[bot]@users.noreply.github.com', authorLogin: 'dependabot[bot]', committerEmail: 'noreply@github.com', committerLogin: 'web-flow', ...over });
const lock = [{ filename: 'package.json', status: 'modified' }, { filename: 'package-lock.json', status: 'modified' }];

test('Dependabot: the identity the guard trusts is dependabot[bot], id 49699333, committed through GitHub', () => {
  assert.deepStrictEqual(DEP, { login: 'dependabot[bot]', id: 49699333, email: '49699333+dependabot[bot]@users.noreply.github.com', committerEmail: 'noreply@github.com' });
});

test('Dependabot: its PR that changes only package.json and package-lock.json passes without listing its commits', () => {
  assert.deepStrictEqual(problems(depPr(), [depCommit()], lock), []);
});

test('Dependabot: a PR that also changes any other file fails as today, and says why the exemption did not apply', () => {
  const p = problems(depPr(), [depCommit()], [...lock, { filename: 'api/feed.js', status: 'modified' }]).join('\n');
  assert.match(p, /does not list commit ddddddd/);
  assert.match(p, /Dependabot's exemption .*"api\/feed\.js"/);
  // A manifest it adds or deletes, rather than changes, is not a security update either.
  assert.match(problems(depPr(), [depCommit()], [{ filename: 'tools/package.json', status: 'added' }]).join(), /does not list commit/);
  // So is a workflow file, which only a person may change, with its "Workflow change:" line.
  assert.match(problems(depPr(), [depCommit()], [{ filename: '.github/workflows/checks.yml', status: 'modified' }]).join(), /does not list commit/);
});

test('Dependabot: one commit that is not Dependabot\'s (pushed onto its branch by anyone else) fails as today', () => {
  const mine = { ...ok, sha: '7777777aaaa' };
  assert.match(problems(depPr(), [depCommit(), mine], lock).join(), /does not list commit 7777777/);
  // An author that only claims Dependabot's email, without GitHub linking it to the dependabot[bot] account, is not it.
  assert.match(problems(depPr(), [depCommit({ authorLogin: null })], lock).join(), /does not list commit ddddddd/);
  // A commit Dependabot's email signs, but not committed through GitHub, is not it.
  assert.match(problems(depPr(), [depCommit({ committerEmail: 'someone@example.com' })], lock).join(), /does not list commit ddddddd/);
});

test('Dependabot: an unverified commit still fails, even from Dependabot', () => {
  assert.match(problems(depPr(), [depCommit({ verified: false, reason: 'unsigned' })], lock).join(), /not verified by GitHub \(unsigned\)/);
});

test('Dependabot: the exemption needs the PR opened by the dependabot[bot] app, from this repository, to main', () => {
  for (const over of [{ author: { login: 'MyChiefOS', id: 1, type: 'User' } }, { author: { login: 'dependabot[bot]', id: 1, type: 'Bot' } }, { headRepo: 'someone/fork' }]) {
    assert.match(problems(depPr(over), [depCommit()], lock).join(), /does not list commit ddddddd/, JSON.stringify(over));
  }
  assert.match(problems(depPr({ base: 'side' }), [depCommit()], lock).join(), /targets "side", not main/);
});

test('Dependabot: no commits, or no files, is not a Dependabot update', () => {
  assert.match(problems(depPr(), [depCommit()], []).join(), /does not list commit ddddddd/);
});

// ---- RK146: a PR that changes anything under .github/ (the workflows that are its own gates) must say so in its
// description, one "Workflow change:" line naming each changed file.

const wf = (filename, extra) => ({ filename, status: 'modified', ...extra });

test('RK146: a PR that changes a workflow without a "Workflow change:" line fails, with a plain message', () => {
  const p = problems({ base: 'main', body: 'abcdef1' }, [ok], [wf('.github/workflows/checks.yml')]);
  assert.strictEqual(p.length, 1);
  assert.match(p[0], /changes "\.github\/workflows\/checks\.yml" but the description has no "Workflow change: \.github\/workflows\/checks\.yml" line/);
});

test('RK146: a "Workflow change:" line naming the file passes, in the usual Markdown forms', () => {
  for (const line of ['Workflow change: .github/workflows/checks.yml adds the SBOM job',
    '- Workflow change: `.github/workflows/checks.yml`: adds the SBOM job.',
    '* **Workflow change:** .github/workflows/checks.yml, the SBOM job',
    'workflow change: .github/workflows/checks.yml.']) {
    assert.deepStrictEqual(problems({ base: 'main', body: 'abcdef1\n' + line }, [ok], [wf('.github/workflows/checks.yml'), wf('api/x.js')]), [], line);
  }
});

test('RK146: every changed file under .github/ is named, not just one, and only on a "Workflow change:" line', () => {
  const files = [wf('.github/workflows/checks.yml'), wf('.github/codeql/codeql-config.yml', { status: 'added' }), wf('.github/workflows/old.yml', { status: 'removed' })];
  const p = problems({ base: 'main', body: 'abcdef1\nWorkflow change: .github/workflows/checks.yml\nAlso touches .github/codeql/codeql-config.yml' }, [ok], files).join('\n');
  assert.doesNotMatch(p, /checks\.yml/);
  assert.match(p, /codeql-config\.yml/, 'named elsewhere in the description does not count');
  assert.match(p, /old\.yml/, 'a deleted workflow counts too');
  // A longer path that merely starts with the changed one does not name it.
  assert.match(problems({ base: 'main', body: 'abcdef1\nWorkflow change: .github/workflows/checks.yml.bak' }, [ok], [wf('.github/workflows/checks.yml')]).join(), /no "Workflow change: \.github\/workflows\/checks\.yml" line/);
});

test('RK146: a file renamed out of .github/ is named by its old path', () => {
  const moved = { filename: 'docs/checks.yml', previousFilename: '.github/workflows/checks.yml', status: 'renamed' };
  assert.match(problems({ base: 'main', body: 'abcdef1' }, [ok], [moved]).join(), /"\.github\/workflows\/checks\.yml"/);
  assert.deepStrictEqual(problems({ base: 'main', body: 'abcdef1\nWorkflow change: .github/workflows/checks.yml moved out' }, [ok], [moved]), []);
});

test('RK146: files outside .github/ need no line, and a PR with no file list is judged as before', () => {
  assert.deepStrictEqual(problems({ base: 'main', body: 'abcdef1' }, [ok], [wf('api/feed.js'), wf('github/x.yml'), wf('x/.github/y.yml')]), []);
  assert.deepStrictEqual(problems({ base: 'main', body: 'abcdef1' }, [ok]), []);
});

test('RK146: a file name is quoted, so a name with a line break can\'t start a line of its own in the log', () => {
  const p = problems({ base: 'main', body: 'abcdef1' }, [ok], [wf('.github/x\n::error::forged.yml')]).join('\n');
  assert.ok(!p.split('\n').some((l) => l.startsWith('::')), p);
  assert.match(p, /\\n::error::forged\.yml/);
});

test('RK146: the guard fails when GitHub listed fewer files than the PR changes (never a pass on a partial list)', () => {
  assert.match(problems({ base: 'main', body: 'abcdef1', changedFiles: 3 }, [ok], [wf('api/a.js')]).join(), /GitHub listed 1 of the 3 changed files/);
  assert.deepStrictEqual(problems({ base: 'main', body: 'abcdef1', changedFiles: 1 }, [ok], [wf('api/a.js')]), []);
});
