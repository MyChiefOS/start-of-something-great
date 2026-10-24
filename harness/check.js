#!/usr/bin/env node
// The session check (harness/RULES.md): run `npm run harness` at the start of every session. It grounds the session in
// what is true right now, instead of what a summary remembers: open pull requests and where they point, how long work
// has waited off main, whether the live site is closed or open, what is left on the launch path, and which facts in
// harness/FACTS.md are only assumed. Read-only: it changes nothing anywhere.
//
// It needs the GitHub CLI (gh) and curl, as this sandbox has. Anything it can't reach is reported as "not checked",
// never guessed (rule 3).
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const REPO = process.env.GITHUB_REPOSITORY || 'MyChiefOS/start-of-something-great';
const SITE = process.env.SITE_URL || 'https://dayonegreat.com';
const DAY = 86400000;

// ---- Reading the ledger -------------------------------------------------------------------------------------------
// The rows of the table under a "## <title>" heading, as arrays of trimmed cells (header and divider left out).
function table(md, title) {
  const part = md.split('\n## ').find((s) => s.startsWith(title));
  if (!part) return [];
  return part.split('\n').filter((l) => l.startsWith('|') && !/^\|\s*-/.test(l))
    .slice(1).map((l) => l.split('|').slice(1, -1).map((c) => c.trim()));
}

// ---- What to warn about (pure, so it is tested) -------------------------------------------------------------------
// state: { now, prs: [{number, base, head, created_at}], mainLastChange, offMainOldest, signIn, setupRuns, factsMd }
// Each finding: { level: 'stop' | 'warn' | 'info', rule, text }.
function evaluate(state) {
  const out = [];
  const now = state.now || Date.now();
  for (const pr of state.prs || []) {
    if (pr.base !== 'main') out.push({ level: 'stop', rule: 1, text: `PR #${pr.number} (${pr.head}) targets "${pr.base}", not main. Tell Aaron before he merges it: he retargets it (Edit next to the title), or Claude does with his yes.` });
  }
  const prs = state.prs || [];
  if (state.prs) out.push({ level: 'info', rule: 1, text: prs.length ? 'Open PRs: ' + prs.map((p) => `#${p.number} ${p.head} -> ${p.base}`).join('; ') : 'No pull requests are open.' });
  if (prs.length > 1) out.push({ level: 'warn', rule: 1, text: `${prs.length} PRs are open. Keep one, and add work to its branch.` });
  const opened = prs.map((p) => p.created_at).filter(Boolean).sort()[0];
  if (opened) {
    const days = Math.floor((now - Date.parse(opened)) / DAY);
    if (days >= 2) out.push({ level: 'warn', rule: 1, text: `The oldest open PR has waited ${days} days for a merge.` });
  }
  if (state.offMainOldest) {
    const days = Math.floor((now - Date.parse(state.offMainOldest)) / DAY);
    if (days >= 2) out.push({ level: 'warn', rule: 1, text: `The oldest change not yet on main was made ${days} days ago. Shipping it beats adding to it.` });
  }
  if (state.mainLastChange) {
    const days = Math.floor((now - Date.parse(state.mainLastChange)) / DAY);
    if (days >= 2) out.push({ level: 'warn', rule: 1, text: `Nothing has reached main for ${days} days (last change ${state.mainLastChange.slice(0, 10)}).` });
  }
  if (state.signIn === 'off') out.push({ level: 'info', rule: 0, text: 'Sign-in is off on the live site (503): either no database is connected yet or the stage is closed. The goal is a fully functional production site.' });
  if (state.signIn === 'on') out.push({ level: 'info', rule: 0, text: 'The live site has sign-in on.' });
  if (state.setupRuns === 0) out.push({ level: 'info', rule: 0, text: 'Production setup has never run.' });
  if (state.setupRuns > 0) out.push({ level: 'info', rule: 0, text: `Production setup has run ${state.setupRuns} time(s); read the latest run before assuming its result.` });
  const md = state.factsMd || '';
  const facts = table(md, 'Systems').concat(table(md, 'Goal'));
  const assumed = facts.filter((r) => /^assumed$/i.test(r[1] || ''));
  if (assumed.length) out.push({ level: 'warn', rule: 3, text: `${assumed.length} fact(s) are only assumed; check them or say "not checked": ` + assumed.map((r) => r[0]).join('; ') });
  const stale = facts.filter((r) => /^checked$/i.test(r[1] || '') && Date.parse(r[3]) && now - Date.parse(r[3]) > 7 * DAY);
  if (stale.length) out.push({ level: 'warn', rule: 3, text: `${stale.length} checked fact(s) are over a week old; re-check before relying on them.` });
  const open = table(md, 'Open for Aaron').filter((r) => !(r[2] || '').trim());
  if (open.length > 3) out.push({ level: 'warn', rule: 5, text: `${open.length} questions are waiting on Aaron. Ask fewer, sharper ones; don't add more.` });
  const left = table(md, 'Launch path').filter((r) => !/^done$/i.test(r[2] || ''));
  if (left.length) out.push({ level: 'info', rule: 0, text: 'Launch path, left in order: ' + left.map((r, i) => `${i + 1}. ${r[0]} (${r[1]})`).join(' ') });
  const instructions = table(md, "Aaron's instructions");
  const notDone = instructions.filter((r) => !/^(done|in force)\b/i.test(r[2] || ''));
  if (notDone.length) out.push({ level: 'warn', rule: 0, text: `${notDone.length} of Aaron's instructions are not done yet: ` + notDone.map((r) => `${r[0]} [${r[2] || 'no status'}]`).join('; ') });
  if (!md) out.push({ level: 'stop', rule: 4, text: 'harness/FACTS.md is missing. Every fact must live there.' });
  return out;
}

// ---- Gathering the live state (each part reports "not checked" if it can't reach its source) ----------------------
function gh(args) { return JSON.parse(execFileSync('gh', ['api', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 30000 })); }
function curlStatus(url) {
  return execFileSync('curl', ['-sS', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '15', url], { encoding: 'utf8', timeout: 20000 }).trim();
}

function gather() {
  const state = { now: Date.now(), notChecked: [] };
  try { state.factsMd = fs.readFileSync(path.join(ROOT, 'harness', 'FACTS.md'), 'utf8'); } catch { state.factsMd = ''; }
  try {
    state.prs = gh([`repos/${REPO}/pulls?state=open&per_page=50`]).map((p) => ({ number: p.number, base: p.base.ref, head: p.head.ref, created_at: p.created_at }));
  } catch { state.notChecked.push('open pull requests (GitHub)'); }
  try { state.mainLastChange = gh([`repos/${REPO}/commits?sha=main&per_page=1`])[0].commit.committer.date; } catch { state.notChecked.push('last change on main'); }
  try {
    let oldest = null;
    for (const pr of state.prs || []) {
      const c = gh([`repos/${REPO}/compare/main...${encodeURIComponent(pr.head)}`]);
      for (const k of c.commits || []) { const d = k.commit.committer.date; if (!oldest || d < oldest) oldest = d; }
    }
    state.offMainOldest = oldest;
  } catch { state.notChecked.push('work waiting off main'); }
  try { state.setupRuns = gh([`repos/${REPO}/actions/workflows/setup.yml/runs?per_page=1`]).total_count; } catch { state.notChecked.push('Production setup runs'); }
  try {
    const code = curlStatus(SITE + '/auth/github/start');
    state.signIn = code === '503' ? 'off' : /^30[2-3]$/.test(code) ? 'on' : 'unknown (' + code + ')';
  } catch { state.notChecked.push('live sign-in'); }
  return state;
}

function report(state, findings) {
  const icon = { stop: 'STOP', warn: 'WARN', info: 'INFO' };
  const lines = ['Day One Great session check, ' + new Date(state.now).toISOString().slice(0, 16) + 'Z',
    'Read: CHARTER.md (first, as it says), then harness/NORTH-STAR.md, harness/RULES.md and harness/FACTS.md.', ''];
  for (const f of findings) lines.push(`${icon[f.level]}${f.rule ? ' (rule ' + f.rule + ')' : ''}: ${f.text}`);
  if (state.notChecked && state.notChecked.length) lines.push('', 'Not checked: ' + state.notChecked.join(', ') + '.');
  return lines.join('\n');
}

if (require.main === module) {
  const state = gather();
  console.log(report(state, evaluate(state)));
}

module.exports = { evaluate, table, report };
