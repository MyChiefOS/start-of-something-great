#!/usr/bin/env node
// Pull-request guards, run by the required `checks` job on every pull request (USE-CASES.md row 14), and again from
// main's copy by gate-guard.yml (RK146), which the pull request can't edit. They catch what the audits of Oct 23-24
// found by hand: work landing on a side branch, a PR description that doesn't list what is being merged, and commits
// GitHub can't verify (including Claude commits made under Aaron's identity). Since Nov 10 they also make a PR that
// changes its own gates (anything under .github/) say so, and let Dependabot's security updates through without a
// commit list, which Dependabot never writes.
'use strict';

const AARON_EMAIL = 'aibizprojectx@gmail.com';
const GITHUB_WEB = 'noreply@github.com';

// Dependabot as GitHub records it. The login and the numeric ID are the dependabot[bot] app's account (GitHub's
// noreply address is "<id>+<login>@users.noreply.github.com"; verified in Dependabot's own commit trailers). Its
// commits are made through GitHub's API with no committer of their own, so GitHub commits and signs them
// (noreply@github.com, the web-flow key); verified in dependabot-core's create_commit, inferred for the hosted
// service until a Dependabot PR reaches this repository. If that inference is wrong, the exemption doesn't apply
// and the PR fails as it did before, printing what GitHub recorded.
const DEPENDABOT = { login: 'dependabot[bot]', id: 49699333, email: '49699333+dependabot[bot]@users.noreply.github.com', committerEmail: GITHUB_WEB };
// The only files a Dependabot pull request may change (npm is the one ecosystem here; supabase/functions pin their
// npm: imports in code, which Dependabot doesn't update).
const DEPENDENCY_MANIFESTS = new Set(['package.json', 'package-lock.json', 'npm-shrinkwrap.json']);

// Untrusted text (file names, emails) is quoted, so a line break in it can't start a line of its own in the log,
// where a line starting "::" is a workflow command.
const q = (s) => JSON.stringify(String(s));

// Why a PR does NOT get Dependabot's exemption from listing its commits, or '' when it does.
function notDependabot(pr, commits, files) {
  const a = pr.author || {};
  if (a.login !== DEPENDABOT.login || a.id !== DEPENDABOT.id || a.type !== 'Bot') return 'not opened by ' + DEPENDABOT.login;
  if (!pr.headRepo || pr.headRepo !== pr.baseRepo) return 'its branch is not in this repository';
  if (!commits.length) return 'it has no commits';
  for (const c of commits) {
    if (c.authorEmail !== DEPENDABOT.email || c.authorLogin !== DEPENDABOT.login || c.committerEmail !== DEPENDABOT.committerEmail) {
      return 'commit ' + c.sha.slice(0, 7) + ' was not made by Dependabot through GitHub (author ' + q(c.authorEmail) + ' linked to ' + q(c.authorLogin) + ', committer ' + q(c.committerEmail) + ')';
    }
  }
  if (!files || !files.length) return 'GitHub listed no changed files';
  for (const f of files) {
    const base = f.filename.split('/').pop();
    if (!DEPENDENCY_MANIFESTS.has(base) || f.status !== 'modified' || f.filename.startsWith('.github/')) return 'it changes ' + q(f.filename) + ' (' + f.status + '), and only changes to package.json or package-lock.json are exempt';
  }
  return '';
}

// The paths named on the description's "Workflow change:" lines.
function namedWorkflowChanges(body) {
  const named = new Set();
  for (const m of body.matchAll(/^[ \t>*_-]*workflow change:[*_]*[ \t]*(.*)$/gim)) {
    for (const tok of m[1].split(/[\s,;`'"()<>[\]]+/)) {
      const t = tok.replace(/[.:]+$/, '');
      if (t) named.add(t);
    }
  }
  return named;
}

// Pure, so it is tested: pr = { base, body, changedFiles?, author?: { login, id, type }, headRepo?, baseRepo? },
// commits = [{ sha, verified, reason, authorEmail, committerEmail, authorLogin? }],
// files = [{ filename, status, previousFilename? }] (omitted: the file checks are skipped, as before Nov 10).
function problems(pr, commits, files) {
  const out = [];
  if (pr.base !== 'main') out.push('the pull request targets "' + pr.base + '", not main (harness rule 1)');
  const body = String(pr.body || '');
  const dependabotWhyNot = notDependabot(pr, commits, files);
  const unlisted = [];
  for (const c of commits) {
    const short = c.sha.slice(0, 7);
    if (!c.verified) out.push('commit ' + short + ' is not verified by GitHub (' + (c.reason || 'unknown') + ')');
    // Aaron's own commits are made in GitHub's web editor, which GitHub signs as noreply@github.com. A commit under his
    // email with any other committer was made by someone else in his name.
    if (c.authorEmail === AARON_EMAIL && c.committerEmail !== GITHUB_WEB) out.push('commit ' + short + ' carries Aaron\'s email but was not made by him on GitHub');
    if (!body.includes(short) && dependabotWhyNot) unlisted.push('the description does not list commit ' + short + ' (list every commit, from git log main..HEAD)');
  }
  out.push(...unlisted);
  if (unlisted.length && pr.author && pr.author.login === DEPENDABOT.login) out.push('Dependabot\'s exemption from listing commits does not apply: ' + dependabotWhyNot);
  if (files) {
    // Never a pass on a partial list: GitHub lists at most 3,000 files.
    if (typeof pr.changedFiles === 'number' && pr.changedFiles !== files.length) out.push('GitHub listed ' + files.length + ' of the ' + pr.changedFiles + ' changed files, so the workflow-change check could not see them all');
    // RK146: the required gate runs from the PR's own copy of the workflows, so a PR that changes .github/ says so.
    const named = namedWorkflowChanges(body);
    const gates = new Set();
    for (const f of files) for (const p of [f.filename, f.previousFilename]) if (p && p.startsWith('.github/')) gates.add(p);
    for (const p of gates) {
      if (!named.has(p)) out.push('the pull request changes ' + q(p) + ' but the description has no "Workflow change: ' + JSON.stringify(p).slice(1, -1) + '" line (RK146: a pull request that edits its own gates says so, one line per file)');
    }
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
  const pages = async (path, map) => {
    const all = [];
    for (let page = 1; ; page++) {
      const batch = await get(path + (path.includes('?') ? '&' : '?') + 'per_page=100&page=' + page);
      all.push(...batch.map(map));
      if (batch.length < 100) return all;
    }
  };
  const pr = await get('/pulls/' + n);
  const commits = await pages('/pulls/' + n + '/commits', (c) => ({ sha: c.sha, verified: c.commit.verification.verified, reason: c.commit.verification.reason,
    authorEmail: c.commit.author.email, committerEmail: c.commit.committer.email, authorLogin: c.author ? c.author.login : null }));
  const files = await pages('/pulls/' + n + '/files', (f) => ({ filename: f.filename, status: f.status, previousFilename: f.previous_filename }));
  const p = problems({ base: pr.base.ref, body: pr.body, changedFiles: pr.changed_files, author: pr.user && { login: pr.user.login, id: pr.user.id, type: pr.user.type },
    headRepo: pr.head.repo && pr.head.repo.full_name, baseRepo: pr.base.repo.full_name }, commits, files);
  if (p.length) { console.error('PR guards failed:\n- ' + p.join('\n- ')); process.exit(1); }
  const dep = !notDependabot({ author: pr.user && { login: pr.user.login, id: pr.user.id, type: pr.user.type }, headRepo: pr.head.repo && pr.head.repo.full_name, baseRepo: pr.base.repo.full_name }, commits, files);
  console.log('PR guards passed: base main, ' + commits.length + ' commit(s) verified and ' + (dep ? 'made by Dependabot, changing only dependency manifests' : 'listed in the description') +
    ', ' + files.length + ' file(s), every change under .github/ named on a "Workflow change:" line');
}

if (require.main === module) main().catch((e) => { console.error('PR guards could not run: ' + e.message); process.exit(1); });
module.exports = { problems, AARON_EMAIL, DEPENDABOT, DEPENDENCY_MANIFESTS };
