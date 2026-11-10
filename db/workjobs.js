// The work module's jobs (042). The timer route (api/cron.js) runs one of them every minute, in its own transaction,
// as an anonymous visitor:
//   * the work timer (app.work_tick: claims whose hold ran out reopen, points whose 72 hours passed become final, and
//     Aaron's daily alert while work waits for him); the database runs it at most once every 50 seconds.
// Since 055 (RISKS.md RK140) the site no longer reads this repository's pull requests and issues for the work module,
// and its role can't record them: GitHub's facts come only from GitHub. The "GitHub facts" workflow
// (.github/workflows/github-facts.yml) runs gather() below inside GitHub, on GitHub's own events and hourly, with the
// workflow's own GitHub token, and sends what it read to the dog-github function (supabase/functions/dog-github), which
// accepts only that workflow on main, proved by GitHub's identity token, and records it as dog_ghsync. Each run reads two
// pages of pull requests, one of issues, and GitHub's read of up to 20 merged pull requests the database asks for
// (app.work_github_wanted: their changed lines, their merge and who merged it, by login and GitHub ID): at most 23 calls
// a run, well inside the 1,000 an hour GitHub gives a workflow's token in one repository (inferred from GitHub's
// published limits). A refused read changes nothing; the database alerts Aaron in-app once a day.
// Only public GitHub data reaches the database, and only these fields: a pull request's number, title (hidden markup,
// contact details and keys removed), author, state, merge, base, merge commit, the issue numbers it names (#N), its
// milestone, its room label and the SHA-256 of any claim codes in its description; never the description itself. From
// GitHub's read of one pull request: its changed lines, state, merge, base, merge commit and who merged it.
// An issue becomes an open task only when it has the "task" label: the repository's other issues (uptime alarms,
// JEVs's alerts, proposals) are the site's own business, not work for the public.
// Since 057 (RK135, RK112) each run also reads, for the database: the changed files of up to 5 merged pull requests
// Third Look is waiting to read (app.tl_files_wanted; each file's name, status, size of change and patch, within
// 80,000 bytes a pull request: a file whose patch doesn't fit is sent without it, so Third Look sees the change wasn't
// read whole and leaves it to a person), and Aaron's decisions on proposals, from the labels of the issues labelled
// "proposal" (api/_proposals.js reads them, as /proposals does). Both are public GitHub data. At most 29 calls a run.
// A failure in one step never stops the other or the timers: it changes nothing, and a later run tries again.
'use strict';

const { stripHidden, maskContacts } = require('../api/_proposals');
const { maskSecrets } = require('../api/_secrets');
const work = require('./work');

const fs = require('fs');
const path = require('path');

// The detail (GitHub's read of one pull request) of at most this many a run: app.work_github_wanted gives at most 20.
const DETAILS = 20;
// The changed files of at most this many pull requests a run (app.tl_files_wanted gives at most 5), each within this
// many bytes of JSON (the database takes at most 100,000).
const FILES = 5;
const FILES_BYTES = 80_000;
const DECIDED = new Set(['approved', 'declined', 'shipped']);
const REPO_API = 'https://api.github.com/repos/MyChiefOS/start-of-something-great';

const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const ROOM_LABEL = /^room:\s?([0-9]{2}-0000)$/i;
const TASK_LABEL = 'task';

async function step(name, out, fn) {
  try { out[name] = await fn(); } catch (e) { out[name] = { failed: String((e && (e.code || e.name)) || 'error').replace(/[^A-Za-z0-9_]/g, '').slice(0, 32) }; }
}

const login = (u) => (u && typeof u.login === 'string' && LOGIN.test(u.login) ? u.login.toLowerCase() : null);
const title = (s) => maskContacts(maskSecrets(stripHidden(String(s || '')).text.replace(/\s+/g, ' ').trim()).text).slice(0, 140);
const labelsOf = (x) => (Array.isArray(x.labels) ? x.labels : []).map((l) => String(typeof l === 'string' ? l : (l && l.name) || ''));
const roomOf = (x) => { for (const l of labelsOf(x)) { const m = ROOM_LABEL.exec(l.trim()); if (m) return m[1]; } return null; };
const at = (s) => (typeof s === 'string' && !Number.isNaN(Date.parse(s)) ? new Date(s).toISOString() : null);
const milestone = (m) => (m && Number.isSafeInteger(m.number) && m.number > 0 ? { milestone: m.number, milestone_title: title(m.title) } : { milestone: null, milestone_title: null });
// The issue numbers a pull request names ("#12"), in its title and description: at most 40, written "12,40".
function refsOf(...texts) {
  const out = new Set();
  for (const t of texts) {
    const s = String(t || '');
    for (let i = s.indexOf('#'); i !== -1 && out.size < 40; i = s.indexOf('#', i + 1)) {
      const digit = (ch) => ch >= '0' && ch <= '9';
      let j = i + 1;
      while (j < s.length && digit(s[j])) j++;
      const prev = i > 0 ? s[i - 1] : ' ';
      const wordBefore = digit(prev) || (prev >= 'A' && prev <= 'Z') || (prev >= 'a' && prev <= 'z') || prev === '&';
      // 1 to 7 digits, not starting with 0, not part of a word ("abc#12") or an HTML entity ("&#12;").
      if (j - i - 1 >= 1 && j - i - 1 <= 7 && s[i + 1] !== '0' && !wordBefore) out.add(Number(s.slice(i + 1, j)));
    }
  }
  return [...out].sort((a, b) => a - b).join(',').slice(0, 400);
}

function shapePr(p) {
  const author = login(p.user);
  if (!p || !Number.isSafeInteger(p.number) || p.number < 1 || !author || !['open', 'closed'].includes(p.state)) return null;
  return { number: p.number, title: title(p.title) || 'Pull request', author, state: p.state, merged_at: at(p.merged_at),
    base: String((p.base && p.base.ref) || '').slice(0, 100),
    merge_sha: p.merged_at && typeof p.merge_commit_sha === 'string' && /^[0-9a-f]{40}$/.test(p.merge_commit_sha) ? p.merge_commit_sha : null,
    refs: refsOf(p.title, p.body), ...milestone(p.milestone), room: roomOf(p), created_at: at(p.created_at) || new Date().toISOString(),
    codes: work.codesIn(p.body) };
}
function shapeIssue(x) {
  const author = login(x.user);
  if (!x || x.pull_request || !Number.isSafeInteger(x.number) || x.number < 1 || !author || !['open', 'closed'].includes(x.state)) return null;
  if (!labelsOf(x).some((l) => l.trim().toLowerCase() === TASK_LABEL)) return null;
  return { number: x.number, title: title(x.title) || 'Issue', author, state: x.state, ...milestone(x.milestone), room: roomOf(x),
    created_at: at(x.created_at) };
}
// GitHub's read of one pull request: its changed lines, its merge and who merged it, by login and by GitHub ID (055: a
// pass by rule needs Aaron's account by ID, which a rename doesn't change).
const userId = (u) => (u && Number.isSafeInteger(u.id) && u.id > 0 && u.id < 1e11 ? u.id : null);
function shapeDetail(p) {
  if (!p || !Number.isSafeInteger(p.number) || p.number < 1 || !Number.isSafeInteger(p.additions) || !Number.isSafeInteger(p.deletions)
      || !['open', 'closed'].includes(p.state)) return null;
  const merged = at(p.merged_at);
  return { number: p.number, additions: Math.min(Math.max(p.additions, 0), 99999999), deletions: Math.min(Math.max(p.deletions, 0), 99999999),
    state: p.state, merged_at: merged, base: String((p.base && p.base.ref) || '').slice(0, 100),
    merge_sha: merged && typeof p.merge_commit_sha === 'string' && /^[0-9a-f]{40}$/.test(p.merge_commit_sha) ? p.merge_commit_sha : null,
    merged_by: merged ? login(p.merged_by) : null, merged_by_id: merged ? userId(p.merged_by) : null };
}

// GitHub's list of one pull request's changed files, shaped for Third Look: name, status, size of change and patch.
// Patches are kept in order while they fit in FILES_BYTES; a file whose patch doesn't fit is sent without one.
function shapeFiles(list) {
  if (!Array.isArray(list)) return null;
  let bytes = 2;
  const out = [];
  for (const f of list.slice(0, 100)) {
    if (!f || typeof f.filename !== 'string') continue;
    const x = { filename: f.filename.slice(0, 300), status: String(f.status || 'changed').slice(0, 20),
      changes: Number.isSafeInteger(f.changes) && f.changes >= 0 ? f.changes : 0 };
    const base = Buffer.byteLength(JSON.stringify(x)) + 2;
    const patch = typeof f.patch === 'string' ? Buffer.byteLength(JSON.stringify(f.patch)) + 12 : 0;
    if (patch && bytes + base + patch <= FILES_BYTES) { x.patch = f.patch; bytes += patch; }
    bytes += base;
    out.push(x);
  }
  return out;
}

// Aaron's decisions on proposals, from GitHub's labels (api/_proposals.js, as /proposals reads them): number and status.
function shapeProposals(issues) {
  if (!Array.isArray(issues)) return [];
  const { shapeList } = require('../api/_proposals');
  return shapeList(issues).proposals.filter((p) => DECIDED.has(p.status) && Number.isSafeInteger(p.number) && p.number > 0)
    .map((p) => ({ number: p.number, status: p.status })).slice(0, 100);
}

// The work timer, every minute from the timer route. Since 055 it reads nothing from GitHub.
async function run(runDb) {
  const out = {};
  await step('tick', out, () => runDb({ actor: 'anon' }, (t) => t`select app.work_tick() as r`).then((r) => r[0].r));
  return out;
}

// What the GitHub facts workflow reads, inside GitHub. get(path) returns the JSON of GitHub's API for this repository,
// or throws with githubStatus; wanted: the pull request numbers dog-github asked for. Returns the facts, shaped.
async function gather({ get, wanted = [], files: filesWanted = [] }) {
  let refused = 0;
  const read = (p) => get(p).catch((e) => { if (e && (e.githubStatus === 403 || e.githubStatus === 429)) refused++; return null; });
  const pages = await Promise.all([1, 2].map((n) => read('/pulls?state=all&per_page=100&sort=updated&direction=desc&page=' + n)));
  const prs = pages.map((x) => (Array.isArray(x) ? x : [])).flat().map(shapePr).filter(Boolean).slice(0, 200);
  const iss = await read('/issues?state=all&labels=' + TASK_LABEL + '&per_page=100&sort=updated&direction=desc');
  const issues = (Array.isArray(iss) ? iss : []).map(shapeIssue).filter(Boolean).slice(0, 100);
  const details = [];
  for (const n of (Array.isArray(wanted) ? wanted : []).filter((x) => Number.isSafeInteger(x) && x > 0 && x < 1e7).slice(0, DETAILS)) {
    const d = shapeDetail(await read('/pulls/' + n)); // null when refused: the next run asks again
    if (d) details.push(d);
  }
  const files = [];
  for (const n of (Array.isArray(filesWanted) ? filesWanted : []).filter((x) => Number.isSafeInteger(x) && x > 0 && x < 1e7).slice(0, FILES)) {
    const list = shapeFiles(await read('/pulls/' + n + '/files?per_page=100')); // null when refused: the next run asks again
    if (list) files.push({ number: n, files: list });
  }
  const proposals = shapeProposals(await read('/issues?labels=proposal&state=all&per_page=100&sort=created&direction=desc'));
  return { prs, issues, details, refused, files, proposals };
}

// The facts as dog-github's sync requests: at most 100 pull requests each (the database's limit); the issues, details,
// refused count, changed files and proposal decisions go with the first.
function requests(facts) {
  const out = [];
  for (let i = 0; i < Math.max(facts.prs.length, 1); i += 100) {
    out.push({ mode: 'sync', facts: { prs: facts.prs.slice(i, i + 100), issues: i === 0 ? facts.issues : [], details: i === 0 ? facts.details : [],
      refused: i === 0 ? facts.refused : 0, files: i === 0 ? facts.files || [] : [], proposals: i === 0 ? facts.proposals || [] : [] } });
  }
  return out;
}

// GitHub's API for this repository, with the workflow's own token (read-only here).
function githubGet(token, { fetchImpl = globalThis.fetch, timeoutMs = 20_000 } = {}) {
  return async (p) => {
    const r = await fetchImpl(REPO_API + p, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs), headers: { Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'dayonegreat-github-facts', ...(token ? { Authorization: 'Bearer ' + token } : {}) } });
    if (!r.ok) throw Object.assign(new Error('GitHub returned ' + r.status), { githubStatus: r.status });
    return r.json();
  };
}

// The workflow's step: node db/workjobs.js gather <dog-github's wanted answer> <folder>. Writes 1.json, 2.json, ...:
// the requests to send, in order. Prints counts only.
async function main(argv, env = process.env) {
  if (argv[0] !== 'gather' || argv.length !== 3) throw new Error('usage: node db/workjobs.js gather <wanted.json> <folder>');
  const answer = JSON.parse(fs.readFileSync(argv[1], 'utf8'));
  if (!answer || answer.ok !== true || !Array.isArray(answer.wanted)) throw new Error('dog-github\'s wanted answer is not usable');
  const facts = await gather({ get: githubGet(env.GH_TOKEN || ''), wanted: answer.wanted, files: Array.isArray(answer.files) ? answer.files : [] });
  const dir = path.resolve(argv[2]);
  fs.mkdirSync(dir, { recursive: true });
  const reqs = requests(facts);
  reqs.forEach((r, i) => fs.writeFileSync(path.join(dir, String(i + 1) + '.json'), JSON.stringify(r)));
  console.log('read ' + facts.prs.length + ' pull requests, ' + facts.issues.length + ' task issues, ' + facts.details.length + ' details, '
    + facts.files.length + ' changed-file lists, ' + facts.proposals.length + ' proposal decisions (' + facts.refused + ' refused); ' + reqs.length + ' request(s)');
}

if (require.main === module) main(process.argv.slice(2)).catch((e) => { console.error(String((e && e.message) || e)); process.exit(1); });

module.exports = { run, gather, requests, githubGet, main, shapePr, shapeIssue, shapeDetail, shapeFiles, shapeProposals, refsOf, DETAILS, FILES, FILES_BYTES };
