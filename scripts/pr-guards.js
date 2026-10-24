#!/usr/bin/env node
// Pull-request guards, run by the required `checks` job on every pull request (USE-CASES.md row 14). They catch what
// the audits of Oct 23-24 found by hand: work landing on a side branch, a PR description that doesn't list what is
// being merged, and commits GitHub can't verify (including Claude commits made under Aaron's identity).
'use strict';

const AARON_EMAIL = 'aibizprojectx@gmail.com';
const GITHUB_WEB = 'noreply@github.com';

// Pure, so it is tested: pr = { base, body }, commits = [{ sha, verified, reason, authorEmail, committerEmail }].
function problems(pr, commits) {
  const out = [];
  if (pr.base !== 'main') out.push('the pull request targets "' + pr.base + '", not main (harness rule 1)');
  const body = String(pr.body || '');
  for (const c of commits) {
    const short = c.sha.slice(0, 7);
    if (!c.verified) out.push('commit ' + short + ' is not verified by GitHub (' + (c.reason || 'unknown') + ')');
    // Aaron's own commits are made in GitHub's web editor, which GitHub signs as noreply@github.com. A commit under his
    // email with any other committer was made by someone else in his name.
    if (c.authorEmail === AARON_EMAIL && c.committerEmail !== GITHUB_WEB) out.push('commit ' + short + ' carries Aaron\'s email but was not made by him on GitHub');
    if (!body.includes(short)) out.push('the description does not list commit ' + short + ' (list every commit, from git log main..HEAD)');
  }
  return out;
}

async function main() {
  const repo = process.env.GITHUB_REPOSITORY; const n = process.env.PR_NUMBER; const token = process.env.GITHUB_TOKEN;
  const get = async (path) => {
    const r = await fetch('https://api.github.com/repos/' + repo + path, { headers: { authorization: 'Bearer ' + token, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' } });
    if (!r.ok) throw new Error('GitHub ' + path + ' answered ' + r.status);
    return r.json();
  };
  const pr = await get('/pulls/' + n);
  const commits = [];
  for (let page = 1; ; page++) {
    const batch = await get('/pulls/' + n + '/commits?per_page=100&page=' + page);
    commits.push(...batch.map((c) => ({ sha: c.sha, verified: c.commit.verification.verified, reason: c.commit.verification.reason, authorEmail: c.commit.author.email, committerEmail: c.commit.committer.email })));
    if (batch.length < 100) break;
  }
  const p = problems({ base: pr.base.ref, body: pr.body }, commits);
  if (p.length) { console.error('PR guards failed:\n- ' + p.join('\n- ')); process.exit(1); }
  console.log('PR guards passed: base main, ' + commits.length + ' commit(s) verified and listed in the description');
}

if (require.main === module) main().catch((e) => { console.error('PR guards could not run: ' + e.message); process.exit(1); });
module.exports = { problems, AARON_EMAIL };
