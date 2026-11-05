#!/usr/bin/env node
// The data Build, the Leaderboard, a task and a citizen show (the design handoff of Nov 5, 2026; Aaron, phase 6:
// "the first data is the project's own pull requests and work"; phase 7: pages generated from the repository's files
// before each commit). Nothing here is invented: every figure is counted from three sources in this repository.
//
//   1. git: every "Merge pull request #N" commit up to the as-of merge, and the commits inside each pull request.
//      A commit is Claude's when its author is noreply@anthropic.com or its message carries Claude's session or
//      co-author line (every code commit does; RISKS.md RK71 says why authors alone don't tell). The merge commit's
//      author is the person who merged it.
//   2. harness/PLAN.md, its "The design handoff" section: the proposal Aaron approved on Nov 5, its eight phases (the
//      work packages) and the tasks each phase names. A merged pull request titled "Design handoff phase N" is a task
//      of phase N.
//   3. ROADMAP.md: the milestones, their target and actual dates (the Milestones chart) and the Release 2 target.
//   And, when it is in the repository, design/handoff-2026-11-05/NOTES.md: Aaron's decision on each phase.
//
//   node scripts/build-data.js           regenerate from the newest merged pull request in this checkout
//   node scripts/build-data.js --check   change nothing; regenerate from the as-of merge work.json records and exit 1,
//                                        naming each file that differs. A newer merge is reported, not failed: the
//                                        pages are regenerated in the next pull request (checks alert, never lock out).
//
// It writes work.json (the "As JSON" link), work-data.js (the slim copy task.js and citizen.js read, so those pages
// make no request) and the marked blocks in build.html and leaderboard.html (<!-- work:NAME --> ... <!-- /work:NAME -->).
// No network: git and files only, so the result is the same on every machine with the full history.
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const REPO = 'https://github.com/MyChiefOS/start-of-something-great';
const PAGES = ['build.html', 'leaderboard.html'];

// ---------------------------------------------------------------------------------------------------------------
// Reading git

function git(args, root) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

const isClaude = (email, body) => email === 'noreply@anthropic.com' || /^Claude-Session:/m.test(body) || /^Co-Authored-By: Claude\b/mi.test(body);

// The newest "Merge pull request" commit reachable from HEAD.
function newestMerge(root) {
  const out = git(['log', '--merges', '--format=%H%x00%s', 'HEAD'], root).split('\n').filter(Boolean);
  for (const line of out) {
    const [sha, subject] = line.split('\0');
    if (/^Merge pull request #\d+ from /.test(subject)) return sha;
  }
  throw new Error('No merged pull request in this history. A shallow clone? The generator needs the full history (fetch-depth 0).');
}

function readGit(root, asOf) {
  const commits = new Map();
  for (const rec of git(['log', '--no-merges', '--format=%H%x00%an%x00%ae%x00%aI%x00%s%x00%B%x1e', asOf], root).split('\x1e')) {
    const t = rec.replace(/^\n/, '');
    if (!t) continue;
    const [sha, name, email, date, subject, body] = t.split('\0');
    commits.set(sha, { sha, name, email, date, subject, claude: isClaude(email, body || ''), reverts: ((body || '').match(/This reverts commit ([0-9a-f]{7,40})/) || [])[1] || null });
  }
  const prs = [];
  for (const rec of git(['log', '--merges', '--format=%H%x00%P%x00%an%x00%aI%x00%s%x00%b%x1e', asOf], root).split('\x1e')) {
    const t = rec.replace(/^\n/, '');
    if (!t) continue;
    const [sha, parents, merger, date, subject, body] = t.split('\0');
    const m = subject.match(/^Merge pull request #(\d+) from ([^/\s]+)\/(\S+)$/);
    if (!m) continue;
    const [p1, p2] = parents.split(' ');
    const inside = git(['rev-list', '--no-merges', p1 + '..' + p2], root).split('\n').filter(Boolean);
    const stat = git(['diff', '--shortstat', p1, sha], root);
    const num = (re) => Number((stat.match(re) || [])[1] || 0);
    const claude = inside.filter((c) => commits.get(c) && commits.get(c).claude);
    prs.push({
      number: Number(m[1]), branch: m[3], title: (body || '').split('\n').map((s) => s.trim()).find(Boolean) || m[3],
      merged_at: date, merged_by: merger, sha, commits: inside.length, claude_commits: claude.length,
      additions: num(/(\d+) insertions?/), deletions: num(/(\d+) deletions?/), files: num(/(\d+) files? changed/),
      url: REPO + '/pull/' + m[1], inside
    });
  }
  prs.sort((a, b) => a.number - b.number);
  return { commits, prs };
}

// ---------------------------------------------------------------------------------------------------------------
// Reading harness/PLAN.md: the design handoff, its phases and their tasks

function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
// Split a list on commas (or semicolons) that are not inside brackets.
function splitList(s, sep) {
  const out = [];
  let depth = 0, cur = '';
  for (const ch of s) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === sep && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim().replace(/\s*\([^)]*\)\s*$/, '').replace(/\.$/, '').trim()).filter(Boolean);
}

function readPlan(text) {
  const start = text.indexOf('### The design handoff');
  if (start < 0) throw new Error('harness/PLAN.md has no "### The design handoff" section');
  const end = text.slice(start + 4).search(/\n#{2,3} /);
  const sec = end < 0 ? text.slice(start) : text.slice(start, start + 4 + end);
  const quote = (sec.match(/Aaron, Nov 5: "([^"]+)"/) || [])[1];
  const listAt = sec.search(/\n1\. /);
  if (!quote || listAt < 0) throw new Error('harness/PLAN.md: the design handoff section no longer has Aaron’s quote or its numbered list');
  const list = sec.slice(listAt + 1).replace(/\n/g, ' ');
  // "1. ... 2. ... 3. ..." in order; the numbers may share a line ("4. **Reviewer tiers** (spec 2). 5. **...").
  const chunks = [];
  let at = 0;
  for (let n = 1; ; n++) {
    const re = new RegExp('(?:^|\\s)' + n + '\\.\\s+(?=\\*\\*|[A-Z])', 'g');
    re.lastIndex = at;
    const m = re.exec(list);
    if (!m) break;
    if (chunks.length) chunks[chunks.length - 1].text = list.slice(chunks[chunks.length - 1].from, m.index).trim();
    chunks.push({ n, from: m.index + m[0].length });
    at = m.index + m[0].length;
  }
  if (chunks.length) chunks[chunks.length - 1].text = list.slice(chunks[chunks.length - 1].from).trim();
  if (chunks.length !== 8) throw new Error('harness/PLAN.md: expected the handoff’s 8 phases, found ' + chunks.length);
  return {
    quote,
    phases: chunks.map(({ n, text: t }) => {
      const bold = t.match(/^\*\*([^*]+)\*\*/);
      const name = bold ? bold[1] : t.replace(/\.\s.*$/, '').replace(/\.$/, '');
      const rest = bold ? t.slice(bold[0].length).trim() : t.slice(name.length).replace(/^\.\s*/, '');
      let tasks;
      const listed = rest.match(/^\([^)]*\):\s*([^.]+)\./);
      const notYet = rest.match(/Not yet:\s*(.+?)\.(?:\s|$)/);
      if (listed) tasks = splitList(listed[1], ',');
      else if (notYet) tasks = splitList(notYet[1], ',');
      else tasks = splitList(name, name.includes(';') ? ';' : ',');
      // What else the plan says about the phase: the sentences after its task list, without the build detail.
      let note = listed ? rest.slice(listed[0].length).trim() : notYet ? '' : rest.replace(/^\([^)]*\)[.,]?\s*/, '');
      note = note.replace(/^behind flags\.?$/, 'Behind flags.');
      return { n, title: cap(name), tasks: tasks.map(cap), note: note.trim() };
    })
  };
}

// Aaron's decisions on the handoff, when NOTES.md is in the repository: one row per phase.
function readNotes(text) {
  const out = {};
  if (!text) return out;
  for (const m of text.matchAll(/^\| Phase (\d)[^|]*\|\s*([^|]+?)\s*\|$/gm)) out[m[1]] = m[2].trim();
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Reading ROADMAP.md

const MONTHS = { Oct: 10, Nov: 11, Dec: 12 };
function firstDate(cell) {
  const m = (cell || '').match(/\b(Oct|Nov|Dec) (\d{1,2})\b/);
  return m ? '2026-' + String(MONTHS[m[1]]).padStart(2, '0') + '-' + m[2].padStart(2, '0') : null;
}
function readRoadmap(text) {
  const rows = [];
  let inTable = false;
  for (const line of text.split('\n')) {
    if (/^\| Milestone \| Target \| Actual \| Result/.test(line)) { inTable = true; continue; }
    if (!inTable) continue;
    if (!line.startsWith('|')) { if (rows.length) break; continue; }
    if (/^\|---/.test(line)) continue;
    const c = line.split('|').slice(1, -1).map((s) => s.trim());
    const done = c[3].includes('✅');
    const dropped = /^Dropped|^Replaced/.test(c[3]);
    const missed = c[3].includes('❌');
    rows.push({ name: c[0], target: c[1], actual: c[2], result: c[3], target_date: /^Not set/i.test(c[1]) ? null : firstDate(c[1]), done_date: done ? firstDate(c[2]) : null,
      state: done ? 'Done' : dropped ? (/^Replaced/.test(c[3]) ? 'Replaced' : 'Dropped') : missed ? 'Missed' : /in progress/i.test(c[3]) ? 'In progress' : /merged|built/i.test(c[3]) ? 'Built, not proven' : 'Not done' });
  }
  if (rows.length < 5) throw new Error('ROADMAP.md: the milestone table was not found');
  return rows;
}

// ---------------------------------------------------------------------------------------------------------------
// Counting

// Wilson 95% interval for k of n (spec 4.1: "Use Wilson 95% intervals for rates").
function wilson(k, n) {
  if (!n) return null;
  const z = 1.959964, p = k / n, d = 1 + z * z / n;
  const c = (p + z * z / (2 * n)) / d, h = (z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d;
  return { k, n, rate: p, lo: Math.max(0, c - h), hi: Math.min(1, c + h) };
}
const day = (iso) => new Date(iso).toISOString().slice(0, 10);
function streak(dates, asOfIso) {
  const days = new Set(dates.map(day));
  let n = 0;
  for (let d = new Date(day(asOfIso) + 'T00:00:00Z'); days.has(d.toISOString().slice(0, 10)); d.setUTCDate(d.getUTCDate() - 1)) n++;
  return n;
}

function collect(root, asOf) {
  const { commits, prs } = readGit(root, asOf);
  const asOfPr = prs.find((p) => p.sha === asOf);
  if (!asOfPr) throw new Error('The as-of commit ' + asOf + ' is not a "Merge pull request" commit');
  const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
  const plan = readPlan(read('harness/PLAN.md'));
  const notesFile = path.join(root, 'design/handoff-2026-11-05/NOTES.md');
  const notes = readNotes(fs.existsSync(notesFile) ? fs.readFileSync(notesFile, 'utf8') : '');
  const roadmap = readRoadmap(read('ROADMAP.md'));

  // Reverted pull requests: a revert commit names a commit inside a merged pull request.
  const reverted = new Set();
  for (const c of commits.values()) {
    if (!c.reverts) continue;
    const pr = prs.find((p) => p.inside.some((s) => s.startsWith(c.reverts)));
    if (pr) reverted.add(pr.number);
  }

  // The proposal: the handoff's phases, its tasks, and the merged pull requests titled for a phase.
  const tasks = {};
  const packages = plan.phases.map((ph) => {
    const decision = notes[ph.n] || null;
    const held = decision && /^Not decided/i.test(decision) ? 'Not decided' : decision && /^On hold/i.test(decision) ? 'On hold' : null;
    const ids = [];
    let k = 0;
    for (const pr of prs.filter((p) => new RegExp('^Design handoff phase ' + ph.n + '\\b', 'i').test(p.title))) {
      const id = ph.n + '-' + (++k);
      tasks[id] = { id, label: ph.n + '.' + k, package: String(ph.n), title: cap(pr.title.replace(/^Design handoff phase \d+:\s*/i, '')), status: 'Merged', pr: pr.number };
      ids.push(id);
    }
    for (const t of ph.tasks) {
      const id = ph.n + '-' + (++k);
      tasks[id] = { id, label: ph.n + '.' + k, package: String(ph.n), title: t, status: held || 'Open', pr: null };
      ids.push(id);
    }
    const done = ids.filter((i) => tasks[i].status === 'Merged').length;
    const status = held || (done === ids.length ? 'Merged' : done ? 'In progress' : 'Not started');
    return { id: String(ph.n), title: ph.title, note: ph.note, decision, status, done, total: ids.length, percent: Math.round((100 * done) / ids.length), tasks: ids };
  });
  const totalTasks = Object.keys(tasks).length;
  const doneTasks = Object.values(tasks).filter((t) => t.status === 'Merged').length;

  // The two participants. Claude: the pull requests whose commits carry its marks. Aaron: the merges.
  const claudePrs = prs.filter((p) => p.claude_commits > 0);
  const claudeCommits = new Set(claudePrs.flatMap((p) => p.inside.filter((s) => commits.get(s) && commits.get(s).claude)));
  const otherCommits = new Set(prs.flatMap((p) => p.inside.filter((s) => commits.get(s) && !commits.get(s).claude)));
  const aaronMerges = prs.filter((p) => p.merged_by === 'Aaron Chandler');
  const otherMergers = [...new Set(prs.map((p) => p.merged_by))].filter((n) => n !== 'Aaron Chandler');
  const recent = (list) => list.slice(-5).reverse().map((p) => p.number);
  const sum = (list, k) => list.reduce((a, p) => a + p[k], 0);
  const citizens = {
    claude: {
      handle: 'claude', name: 'Claude', type: 'Agent', band: 'Provisional',
      role: 'AI co-founder. It writes the code and the records in every pull request; Aaron Chandler merges them.',
      merged: claudePrs.length, commits: claudeCommits.size, additions: sum(claudePrs, 'additions'), deletions: sum(claudePrs, 'deletions'),
      sign_offs: 0, audits: 0, receipts: 0, reverted: claudePrs.filter((p) => reverted.has(p.number)).length,
      revert: wilson(claudePrs.filter((p) => reverted.has(p.number)).length, claudePrs.length),
      streak: streak(claudePrs.map((p) => p.merged_at), asOfPr.merged_at),
      first: claudePrs.length ? claudePrs[0].number : null, last: claudePrs.length ? claudePrs[claudePrs.length - 1].number : null,
      recent: recent(claudePrs), sample: claudePrs.length
    },
    aaron: {
      handle: 'aaron', name: 'Aaron Chandler', type: 'Person', band: 'Provisional',
      role: 'Human co-founder. He decides, and approves and merges every pull request.',
      merged: 0, commits: 0, additions: 0, deletions: 0,
      sign_offs: aaronMerges.length, audits: 0, receipts: 0, reverted: 0, revert: null,
      streak: streak(aaronMerges.map((p) => p.merged_at), asOfPr.merged_at),
      first: aaronMerges.length ? aaronMerges[0].number : null, last: aaronMerges.length ? aaronMerges[aaronMerges.length - 1].number : null,
      recent: recent(aaronMerges), sample: aaronMerges.length
    }
  };

  // The latest events: each recent merge and the last commit inside it, newest first.
  const events = [];
  for (const p of prs.slice(-3)) {
    events.push({ at: p.merged_at, kind: 'Person', who: p.merged_by, text: 'merged pull request #' + p.number, pr: p.number, state: 'Merged #' + p.number });
    const last = p.inside.map((s) => commits.get(s)).filter(Boolean).sort((a, b) => (a.date < b.date ? 1 : -1))[0];
    if (last) events.push({ at: last.date, kind: last.claude ? 'Agent' : 'Person', who: last.claude ? 'Claude' : last.name, text: 'committed “' + last.subject + '”', pr: p.number, state: 'In #' + p.number });
  }
  events.sort((a, b) => (new Date(a.at) < new Date(b.at) ? 1 : -1));

  const release2 = roadmap.find((r) => /^Release 2 public/.test(r.name));
  return {
    generated_by: 'scripts/build-data.js',
    as_of: { commit: asOf, pr: asOfPr.number, date: asOfPr.merged_at },
    sources: ['git history: merged pull requests up to #' + asOfPr.number, 'harness/PLAN.md: The design handoff', 'ROADMAP.md: milestones'].concat(fs.existsSync(notesFile) ? ['design/handoff-2026-11-05/NOTES.md: Aaron’s decisions'] : []),
    proposal: { name: 'The design handoff of Nov 5, 2026', quote: plan.quote, approved: '2026-11-05', source: 'harness/PLAN.md' },
    totals: { packages: packages.length, tasks: totalTasks, merged: doneTasks, percent: Math.round((100 * doneTasks) / totalTasks), prs: prs.length, reverted: reverted.size,
      commits_claude: claudeCommits.size, commits_other: otherCommits.size, other_mergers: otherMergers },
    release2: release2 ? { name: release2.name, target: release2.target, target_date: release2.target_date, state: release2.state } : null,
    packages, tasks,
    milestones: roadmap.map(({ name, target_date, done_date, state }) => ({ name, target_date, done_date, state })),
    citizens, events: events.slice(0, 4),
    prs: prs.map(({ inside, ...p }) => p)
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Rendering (text escaped; no inline styles: widths are classes in modules.css)

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function dateText(iso) { const d = new Date(iso.length === 10 ? iso + 'T12:00:00Z' : iso); return MON[d.getUTCMonth()] + ' ' + d.getUTCDate() + ', ' + d.getUTCFullYear(); }
function timeText(iso) { const d = new Date(iso); return String(d.getUTCHours()).padStart(2, '0') + ':' + String(d.getUTCMinutes()).padStart(2, '0') + ' UTC'; }
const n = (x) => x.toLocaleString('en-US');
const pct = (x) => (Math.round(x * 1000) / 10).toString().replace(/\.0$/, '') + '%';
const prLink = (num) => '<a href="' + REPO + '/pull/' + num + '">#' + num + '</a>';
const PILL = { Merged: 'pill f', 'In progress': 'pill a', Open: 'pill', 'Not started': 'pill', 'Not decided': 'pill m', 'On hold': 'pill m' };

function renderBlocks(d) {
  const pr = (num) => d.prs.find((p) => p.number === num);
  const latest = pr(d.as_of.pr);
  const B = {};

  B.kicker = 'Build · main at #' + d.as_of.pr + ' · merged ' + dateText(d.as_of.date);

  B.progress = [
    '<div class="bigbar"><span class="num">' + d.totals.percent + '%</span><div><div class="trk tall" aria-hidden="true"><i class="w' + d.totals.percent + '"></i></div>',
    '<p class="fine">' + d.totals.packages + ' work packages · ' + d.totals.tasks + ' tasks · ' + d.totals.merged + ' merged' +
      (d.release2 ? ' · expected with ' + esc(d.release2.name.replace(/:.*$/, '')) + ', target ' + esc(d.release2.target) + ' (ROADMAP.md)' : '') + '</p>',
    '<p class="fine">Counted as merged pull requests: no receipt is anchored yet, so the bar would stand at 0% by its own rule until the log (phase 2) is built.</p></div></div>'
  ].join('\n');

  B.packages = d.packages.map((p) => {
    const who = p.done ? 'Claude, merged by Aaron Chandler · ' + p.done + ' of ' + p.total + ' tasks merged' : p.status === 'Not decided' || p.status === 'On hold' ? 'Aaron: ' + p.decision : 'Not claimed: claiming opens with phase 5 · ' + p.total + (p.total === 1 ? ' task' : ' tasks');
    return '<div class="li wp"><span class="num tn">' + esc(p.id) + '</span><div><b>' + esc(p.title) + '</b><small>' + esc(who) + '</small></div>' +
      '<div class="trk" aria-hidden="true"><i class="w' + p.percent + '"></i></div><span class="tn">' + p.percent + '%</span><span class="' + PILL[p.status] + '">' + esc(p.status) + '</span></div>';
  }).join('\n');

  // Milestones: planned (by target date) and done (by actual date), week by week from Mon, Oct 12, 2026.
  const weeks = [];
  for (let w = 0; w < 6; w++) { const s = new Date(Date.UTC(2026, 9, 12 + 7 * w)); weeks.push({ label: 'W' + (w + 1), end: new Date(s.getTime() + 7 * 864e5 - 1).toISOString().slice(0, 10) }); }
  const nowWeek = Math.min(5, Math.floor((new Date(d.as_of.date) - Date.UTC(2026, 9, 12)) / (7 * 864e5)));
  // Dropped and replaced milestones left the plan, so they leave the planned line too.
  const inScope = d.milestones.filter((m) => m.state !== 'Dropped' && m.state !== 'Replaced');
  const planned = weeks.map((w) => inScope.filter((m) => m.target_date && m.target_date <= w.end).length);
  const doneBy = weeks.map((w) => d.milestones.filter((m) => m.done_date && m.done_date <= w.end).length);
  const unset = inScope.filter((m) => !m.target_date).length;
  const left = d.milestones.length - inScope.length;
  const top = Math.max(5, Math.ceil(Math.max(...planned, ...doneBy) / 5) * 5);
  const X = (i) => 40 + i * 92, Y = (v) => 230 - (v / top) * 210;
  const grid = [0, 1, 2, 3, 4].map((g) => { const v = (top / 4) * g; return '<line class="fig-grid" x1="40" y1="' + Y(v) + '" x2="510" y2="' + Y(v) + '"/><text class="fig-quiet" x="4" y="' + (Y(v) + 4) + '">' + n(v) + '</text>'; }).join('');
  const labels = weeks.map((w, i) => '<text class="' + (i === nowWeek ? 'fig-now' : 'fig-quiet') + '" x="' + (X(i) - 8) + '" y="250">' + (i === nowWeek ? 'now' : w.label) + '</text>').join('');
  const line = (vals, cls, upto) => '<polyline class="' + cls + '" points="' + vals.slice(0, upto + 1).map((v, i) => X(i) + ',' + Y(v)).join(' ') + '"/>';
  B.chart = [
    '<figure class="chart"><svg class="fig" viewBox="0 0 520 260" role="img" aria-labelledby="chart-t chart-d"><title id="chart-t">Milestones planned and done, by week</title>',
    '<desc id="chart-d">Weeks from Monday, Oct 12, 2026. Planned by the end of each week: ' + planned.join(', ') + '. Done by the end of each week up to now: ' + doneBy.slice(0, nowWeek + 1).join(', ') + '.' + (unset ? ' ' + unset + ' milestones have no target date and are not plotted.' : '') + '</desc>',
    grid, '<line class="fig-zero" x1="40" y1="230" x2="510" y2="230"/>', labels,
    line(planned, 'fig-ref', 5), line(doneBy, 'fig-accent-line', nowWeek),
    '<circle class="fig-dot" cx="' + X(nowWeek) + '" cy="' + Y(doneBy[nowWeek]) + '" r="5"/></svg></figure>'
  ].join('');
  const releases = d.milestones.filter((m) => /^Release \d/.test(m.name));
  B.releases = releases.map((m) => '<span class="' + (m.state === 'Done' ? 'pill m' : m.state === 'In progress' ? 'pill a' : 'pill') + '">' + esc(m.name.replace(/:.*$/, '').replace(/ built on a private preview.*/, ' preview')) + ' · ' + esc(m.state.toLowerCase()) + '</span>').join('');
  B.chartnote = 'Dashed line: milestones planned by the end of each week, from ROADMAP.md’s target dates (' + inScope.length + ' of its ' + d.milestones.length + ' rows' +
    (left ? '; ' + left + ' dropped or replaced' : '') + (unset ? '; ' + unset + ' with no target date yet' : '') + '). Amber line: milestones done by then, from its actual dates. No receipt is anchored yet, so done is the roadmap’s own mark.';

  B.receipt = [
    '<div class="card receipt"><span class="pill f">Merged</span><h3>#' + latest.number + '</h3><p class="fine">The proof behind the latest finished work: a pull request, public on GitHub. Not yet a receipt in the log, so it opens no dispute window.</p>',
    '<dl class="def"><dt>Task</dt><dd>' + esc(latest.title) + '</dd>',
    '<dt>Worker</dt><dd>' + (latest.claude_commits === latest.commits ? 'Claude, ' + latest.commits + (latest.commits === 1 ? ' commit' : ' commits') : esc(latest.claude_commits + ' of ' + latest.commits + ' commits by Claude')) + '</dd>',
    '<dt>Changes</dt><dd class="tn">+' + n(latest.additions) + ' −' + n(latest.deletions) + ' · ' + latest.files + ' files · <code>' + latest.sha.slice(0, 7) + '</code></dd>',
    '<dt>Proof</dt><dd>The pull request’s checks, on GitHub (not copied here)</dd>',
    '<dt>Audit</dt><dd>No separate auditor yet (phase 5)</dd>',
    '<dt>Approved</dt><dd>' + esc(latest.merged_by) + ', by merging it, ' + dateText(latest.merged_at) + '</dd>',
    '<dt>Anchored</dt><dd>Not anchored: the log is phase 2</dd></dl>',
    '<a class="btn s" href="' + latest.url + '">Open the pull request</a></div>'
  ].join('\n');

  B.board = d.packages.flatMap((p) => p.tasks).map((id) => {
    const t = d.tasks[id];
    const p = t.pr ? pr(t.pr) : null;
    const by = p ? 'Claude <span class="pill m">Agent</span>' : '<span class="fine"><i>Unclaimed</i></span>';
    const receipt = p ? prLink(p.number) : t.status === 'Open' ? '<a class="btn s" href="/tasks/' + id + '" aria-label="Claim task ' + t.label + ': not open yet, see why">Claim</a>' : '<span class="fine">none</span>';
    return '<tr><td class="tid">' + t.label + '</td><td><a href="/tasks/' + id + '">' + esc(t.title) + '</a></td><td>' + by + '</td><td><span class="' + PILL[t.status] + '">' + esc(t.status) + '</span></td><td>' + receipt + '</td></tr>';
  }).join('\n');

  B.recent = d.events.map((e) => '<div class="li ev"><span class="fine tn">' + dateText(e.at).replace(/, \d{4}$/, '') + ', ' + timeText(e.at) + '</span><span class="pill m">' + e.kind + '</span><span>' + esc(e.who) + ' ' + esc(e.text) + '</span><span class="pill' + (e.kind === 'Person' ? ' a' : '') + '">' + esc(e.state) + '</span></div>').join('\n');

  // The leaderboard.
  const c = d.citizens;
  const rate = (r, what) => (r ? r.k + ' of ' + r.n + ' ' + what + ' (' + pct(r.rate) + '; 95% interval ' + pct(r.lo) + ' to ' + pct(r.hi) + ')' : 'none to count');
  const notEnough = '<span class="fine">Not enough history yet (0)</span>';
  const row = (x) => '<tr data-type="' + x.type + '" data-merged="' + x.merged + '" data-sign_offs="' + x.sign_offs + '" data-streak="' + x.streak + '"><td><span class="pill">' + x.band + '</span></td>' +
    '<td><a class="who" href="/citizens/' + x.handle + '">' + esc(x.name) + '</a></td><td><span class="' + (x.type === 'Agent' ? 'pill a' : 'pill m') + '">' + x.type + '</span></td>' +
    '<td><span class="fine">Not measured: no audits yet</span></td><td class="tn">' + n(x.merged) + '</td><td class="tn">' + n(x.sign_offs) + '</td><td class="tn">' + x.audits + '</td>' +
    '<td>' + notEnough + '</td><td class="tn">' + x.streak + ' d</td><td class="tn">' + x.receipts + '</td><td class="tn">' + n(x.sample) + ' pull requests</td></tr>';
  B.board_rows = [c.claude, c.aaron].map(row).join('\n');
  B.active = '<div><span class="num big">1</span> <span class="fine">person active · median impact not measured</span></div><div><span class="num big">1</span> <span class="fine">agent active · median impact not measured</span></div>';
  B.profile = [
    '<div class="card"><p class="kicker">Citizen profile</p><h3>' + esc(c.claude.name) + '</h3>',
    '<dl class="def"><dt>Passport</dt><dd>Not issued yet: passports come with the log (phase 2)</dd>',
    '<dt>Reverted</dt><dd class="tn">' + esc(rate(c.claude.revert, 'merged pull requests')) + ', public</dd>',
    '<dt>Strongest</dt><dd>Not measured: needs audits (phase 5)</dd><dt>Weakest</dt><dd>Not measured: needs audits (phase 5)</dd></dl>',
    '<p class="chain"><a class="pill m tn" href="' + REPO + '/pull/' + c.claude.first + '">#' + c.claude.first + '</a> <span aria-hidden="true">→</span> <span class="pill m">…</span> <span aria-hidden="true">→</span> <a class="pill a tn" href="' + REPO + '/pull/' + c.claude.last + '">#' + c.claude.last + '</a></p>',
    '<p class="fine">Every pull request opens to its raw diff on GitHub. None is audited yet.</p><a class="btn s" href="/citizens/claude">Open the profile</a></div>'
  ].join('\n');
  B.asof = 'Counted from git at pull request #' + d.as_of.pr + ', merged ' + dateText(d.as_of.date) + ', by scripts/build-data.js before each commit.';
  return B;
}

// ---------------------------------------------------------------------------------------------------------------
// Writing

// What task.js and citizen.js need, and nothing more.
function slim(d) {
  const keep = new Set(Object.values(d.tasks).map((t) => t.pr).filter(Boolean).concat(...Object.values(d.citizens).map((c) => c.recent), ...Object.values(d.citizens).map((c) => [c.first, c.last])));
  return {
    as_of: d.as_of, proposal: { name: d.proposal.name }, packages: d.packages.map(({ id, title, status, decision, tasks }) => ({ id, title, status, decision, tasks })),
    tasks: d.tasks, citizens: d.citizens, prs: d.prs.filter((p) => keep.has(p.number)).map(({ number, title, merged_at, merged_by, commits, claude_commits, additions, deletions, files, url }) => ({ number, title, merged_at, merged_by, commits, claude_commits, additions, deletions, files, url }))
  };
}

function outputs(root, d) {
  const files = {
    'work.json': JSON.stringify(d, null, 2) + '\n',
    'work-data.js': '// Written by scripts/build-data.js from git, harness/PLAN.md and ROADMAP.md. Do not edit by hand: run node scripts/build-data.js.\n' +
      'window.DOG_WORK = Object.freeze(' + JSON.stringify(slim(d)) + ');\n'
  };
  const blocks = renderBlocks(d);
  for (const page of PAGES) {
    const file = path.join(root, page);
    if (!fs.existsSync(file)) continue;
    let html = fs.readFileSync(file, 'utf8');
    html = html.replace(/<!-- work:([a-z_]+) -->[\s\S]*?<!-- \/work:\1 -->/g, (m, name) => {
      if (!(name in blocks)) throw new Error(page + ': no block named ' + name);
      return '<!-- work:' + name + ' -->' + blocks[name] + '<!-- /work:' + name + ' -->';
    });
    files[page] = html;
  }
  return files;
}

function asOfFromFile(root) {
  try { return JSON.parse(fs.readFileSync(path.join(root, 'work.json'), 'utf8')).as_of.commit; } catch { return null; }
}

function run(root, check) {
  const recorded = asOfFromFile(root);
  const newest = newestMerge(root);
  if (check && !recorded) return { ok: false, message: 'work.json is missing or unreadable. Run: node scripts/build-data.js' };
  const asOf = check ? recorded : newest;
  try { git(['merge-base', '--is-ancestor', asOf, 'HEAD'], root); } catch { return { ok: false, message: 'work.json was made from ' + asOf + ', which is not in this history. Run: node scripts/build-data.js' }; }
  const files = outputs(root, collect(root, asOf));
  const differ = Object.keys(files).filter((f) => !fs.existsSync(path.join(root, f)) || fs.readFileSync(path.join(root, f), 'utf8') !== files[f]);
  if (!check) for (const f of differ) fs.writeFileSync(path.join(root, f), files[f]);
  const stale = check && newest !== recorded ? ' Newer merged pull requests exist since the as-of merge; they appear when the pages are regenerated (node scripts/build-data.js).' : '';
  if (check && differ.length) return { ok: false, message: 'These files differ from what scripts/build-data.js makes: ' + differ.join(', ') + '. Run: node scripts/build-data.js' + stale };
  return { ok: true, message: (check ? 'The work data and pages match the generator.' : differ.length ? 'Wrote ' + differ.join(', ') : 'Everything is already up to date.') + stale };
}

if (require.main === module) {
  const r = run(ROOT, process.argv.includes('--check'));
  console.log(r.message);
  if (!r.ok) process.exitCode = 1;
}

module.exports = { collect, readPlan, readRoadmap, readNotes, wilson, streak, isClaude, outputs, renderBlocks, run, newestMerge, splitList };
