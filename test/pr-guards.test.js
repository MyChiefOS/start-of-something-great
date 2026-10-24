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
