// The work module's jobs (042), run by the timer route every minute (api/cron.js), each in its own transaction, as an
// anonymous visitor:
//   * the work timer (app.work_tick: claims whose hold ran out reopen, points whose 72 hours passed become final, and
//     Aaron's daily alert while work waits for him); the database runs it at most once every 50 seconds;
//   * this repository's pull requests and issues from GitHub's public API, at most every 15 minutes per running copy:
//     two pages of pull requests, one of issues, and the detail (changed lines, who merged) of up to 6 merged pull
//     requests that lack it: at most 9 calls a run, so about 36 an hour for one running copy (verified: the count in
//     this file). The site's other GitHub reads share the same allowance. GitHub allows about 60 an hour without a
//     token and about 5,000 with one (api/_lib.js uses GITHUB_TOKEN when it is set; unknown: whether production sets
//     it), and counts the 60 per network address, which Vercel's functions share with other sites (inferred), so a
//     run can be refused. A refused read changes nothing; the database alerts Aaron in-app once a day (042).
// Only public GitHub data reaches the database, and only these fields: a pull request's number, title (hidden markup,
// contact details and keys removed), author, state, merge, base, merge commit, the issue numbers it names (#N), its
// milestone, its room label and the SHA-256 of any claim codes in its description; never the description itself.
// An issue becomes an open task only when it has the "task" label: the repository's other issues (uptime alarms,
// JEVs's alerts, proposals) are the site's own business, not work for the public.
// A failure in one step never stops the other or the timers: it changes nothing, and a later minute tries again.
'use strict';

const { stripHidden, maskContacts } = require('../api/_proposals');
const { maskSecrets } = require('../api/_secrets');
const work = require('./work');

const SYNC_MS = 15 * 60 * 1000;
const DETAILS = 6;
let lastSync = 0;

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
function shapeDetail(p) {
  if (!p || !Number.isSafeInteger(p.number) || !Number.isSafeInteger(p.additions) || !Number.isSafeInteger(p.deletions)) return null;
  return { number: p.number, additions: Math.min(p.additions, 99999999), deletions: Math.min(p.deletions, 99999999), merged_by: login(p.merged_by) };
}

// gh(path): GitHub's public API for this repository (api/_lib.js's reader, cached and rate-aware).
async function run(runDb, { gh = null, now = Date.now } = {}) {
  const out = {};
  const as = (fn) => runDb({ actor: 'anon' }, fn);
  await step('tick', out, () => as((t) => t`select app.work_tick() as r`).then((r) => r[0].r));
  if (gh && now() - lastSync >= SYNC_MS) {
    lastSync = now();
    await step('github', out, async () => {
      let refused = 0;
      const read = (path) => gh(path).catch((e) => { if (e && (e.githubStatus === 403 || e.githubStatus === 429)) refused++; return null; });
      const pages = await Promise.all([1, 2].map((n) => read('/pulls?state=all&per_page=100&sort=updated&direction=desc&page=' + n)));
      const prs = pages.map((x) => (Array.isArray(x) ? x : [])).flat().map(shapePr).filter(Boolean).slice(0, 200);
      const iss = await read('/issues?state=all&labels=' + TASK_LABEL + '&per_page=100&sort=updated&direction=desc');
      const issues = (Array.isArray(iss) ? iss : []).map(shapeIssue).filter(Boolean).slice(0, 100);
      const wanted = await as((t) => t`select number from app.work_github_wanted(${DETAILS}::integer)`);
      const details = [];
      for (const w of wanted) {
        const d = shapeDetail(await read('/pulls/' + Number(w.number))); // null when refused: the next run asks again
        if (d) details.push(d);
      }
      // At most 100 of each a call (the database's limit).
      let totals = { prs: 0, tasks: 0, closed: 0 };
      for (let i = 0; i < Math.max(prs.length, 1); i += 100) {
        const payload = { prs: prs.slice(i, i + 100), issues: i === 0 ? issues : [], details: i === 0 ? details : [], refused: i === 0 ? refused : 0 };
        const [r] = await as((t) => t`select app.work_github_sync(${t.json(payload)}::jsonb) as r`);
        totals = { prs: totals.prs + (r.r.prs || 0), tasks: totals.tasks + (r.r.tasks || 0), closed: totals.closed + (r.r.closed || 0) };
      }
      return totals;
    });
  }
  return out;
}

module.exports = { run, shapePr, shapeIssue, shapeDetail, refsOf, SYNC_MS, _reset: () => { lastSync = 0; } };
