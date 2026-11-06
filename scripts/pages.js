#!/usr/bin/env node
// The trust pages written from the repository files that define them (the design handoff of Nov 5, 2026, phase 7;
// Aaron: "Yes: generated before each commit, and transparent"). Status, Roadmap, Risks, The checks, Operations and
// Limits are never edited by hand: a change to ROADMAP.md, USE-CASES.md, RISKS.md, OPERATIONS.md, db/jevs.js (and the
// GitHub gate's questions), the limits in the code or ACCEPTANCE.md shows on its page at the next run.
//
//   node scripts/pages.js           write the six pages
//   node scripts/pages.js --check   change nothing; exit 1 and name each page that is stale (test/design-trust.test.js)
//
// Run it before a commit, never at deploy: the pages stay plain files, so hosting is unchanged. Each page then goes
// through scripts/shell.js's render(), so its header and footer are the shell's, byte for byte.
//
// Where a file has no field for what the design shows, the value is derived from the file's own words by the rules
// below (rolePill, roadmapPill, riskStatus), and the file's words are printed beside it, so anyone can check the rule.
// No rule ever reads "proven live" into a row that doesn't say it.
'use strict';

const fs = require('fs');
const path = require('path');
const shell = require('./shell');

const ROOT = path.join(__dirname, '..');
const REPO = 'https://github.com/MyChiefOS/start-of-something-great';
const BLOB = REPO + '/blob/main/';
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');

// ---- Markdown, the little the source files use ------------------------------------------------------------------
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
function href(u) {
  const raw = u.replace(/&amp;/g, '&');
  const SITE_URL = 'https://dayonegreat.com';
  if (raw === SITE_URL || raw.startsWith(SITE_URL + '/')) return esc(raw.slice(SITE_URL.length) || '/');
  if (/^(https?:|mailto:|#)/.test(raw)) return esc(raw);
  return esc(BLOB + raw.replace(/^\.\//, '')); // a repository file, linked on GitHub
}
function prose(s) {
  return esc(s)
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, t, u) => '<a href="' + href(u) + '">' + t + '</a>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[\s(])_([^_]+)_(?=[\s).,;:]|$)/g, '$1<em>$2</em>');
}
// Inline markdown to HTML: code spans first (their insides are only escaped), then links, bold and italics.
function inline(md) {
  return String(md).split(/(`[^`]+`)/).map((p) => (/^`[^`]+`$/.test(p) ? '<code>' + esc(p.slice(1, -1)) + '</code>' : prose(p))).join('');
}
const plain = (md) => String(md).replace(/`([^`]+)`/g, '$1').replace(/\*\*([^*]+)\*\*/g, '$1').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');

// The rows of the markdown table whose header row starts with `first` (e.g. '| Milestone |'), as trimmed cells, with
// escaped pipes (\|) kept as pipes. The header and the divider are left out.
function table(md, first) {
  const lines = md.split('\n');
  const at = lines.findIndex((l) => l.startsWith(first));
  if (at < 0) throw new Error('No table starting ' + first);
  const rows = [];
  for (let i = at; i < lines.length && lines[i].startsWith('|'); i++) {
    if (i === at || /^\|\s*-/.test(lines[i])) continue;
    rows.push(lines[i].replace(/\\\|/g, '\u0000').split('|').slice(1, -1).map((c) => c.replace(/\u0000/g, '|').trim()));
  }
  return { header: lines[at].split('|').slice(1, -1).map((c) => c.trim()), rows };
}
// The bullet (or numbered) items directly under a line that matches `after`, until the first line that isn't one.
function list(md, after) {
  const lines = md.split('\n');
  let i = lines.findIndex((l) => after.test(l));
  if (i < 0) throw new Error('No list after ' + after);
  const out = [];
  for (i++; i < lines.length; i++) {
    const m = lines[i].match(/^(?:- |\d+\. )(.*)$/);
    if (m) out.push(m[1]);
    else if (out.length || lines[i].trim()) break;
  }
  if (!out.length) throw new Error('Empty list after ' + after);
  return out;
}
const must = (m, what) => { if (!m) throw new Error('Could not read ' + what); return m; };

// ---- The page skeleton (team.html's head; CODING_AGENT_SPEC.md 5.3) ---------------------------------------------------
// The design's inline styles, as the classes design.css holds for them (tools/design/css.js collects every style the
// design uses). A declaration the design never uses has no class, so asking for one is an error, not an unstyled page.
const DESIGN_CSS = fs.readFileSync(path.join(ROOT, 'design.css'), 'utf8');
function X(decl) {
  const c = shell.cls(decl);
  if (!DESIGN_CSS.includes('.' + c + '{')) throw new Error('Not a style the design uses: ' + decl);
  return c;
}
function page({ file, heading, description, ogDescription, main, scripts = [] }) {
  const url = 'https://dayonegreat.com/' + file.replace(/\.html$/, '');
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- Generated by scripts/pages.js from the repository's own files. Don't edit by hand: run node scripts/pages.js. -->
  <title>${esc(heading)}: Day One Great</title>
  <meta name="description" content="${esc(description)}">
  <link rel="canonical" href="${url}">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="preload" href="/fonts/bricolage-grotesque.woff2" as="font" type="font/woff2" crossorigin>
  <link rel="stylesheet" href="/design.css">
  <link rel="alternate" type="text/plain" href="/llms.txt" title="Day One Great for AI agents">
  <meta name="theme-color" content="#0d0f14" media="(prefers-color-scheme: dark)">
  <meta name="theme-color" content="#f6f7f9" media="(prefers-color-scheme: light)">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="Day One Great">
  <meta property="og:title" content="${esc(heading)}: Day One Great">
  <meta property="og:description" content="${esc(ogDescription || description)}">
  <meta property="og:url" content="${url}">
  <meta property="og:image" content="https://dayonegreat.com/og.jpg">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="Day One Great: an amber sun rising over the horizon">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:image" content="https://dayonegreat.com/og.jpg">
  <script defer src="/_vercel/insights/script.js"></script>
</head>
<body>
<div class="d1"><div class="wrap">
<!-- shell:top -->
<!-- /shell:top -->
<main class="story" id="main" tabindex="-1">
${main.filter((l) => l !== null).join('\n')}
</main>
<!-- shell:foot -->
<!-- /shell:foot -->
</div></div>
<script src="/nav.js" defer></script>
${scripts.map((s) => '<script src="' + s + '" defer></script>\n').join('')}</body>
</html>
`;
  return shell.render(file, html);
}
const src = (f, text) => '<a href="' + BLOB + f + '">' + (text || f) + '</a>';
const pill = (label, kind) => '<span class="pill' + (kind ? ' ' + kind : '') + '">' + esc(label) + '</span>';
// The design's table: a scroll box (focusable, named, so a keyboard can scroll it: spec 5.6) and a caption for screen
// readers (the design shows none).
const tableOpen = (caption) => ['<div class="' + X('overflow-x:auto;max-width:100%') + '" tabindex="0" role="region" aria-label="' + esc(caption) + '"><table class="' + X('min-width:34rem') + '">', '<caption class="visually-hidden">' + caption + '</caption>'];
// A cell's second line: the words a state was read from, printed under it.
const sub = (html) => '<br><span class="fine">' + html + '</span>';

// ---- Status -----------------------------------------------------------------------------------------------------
// A role's state, from USE-CASES.md's "Works today" and "Missing code" cells only (the file has no state field):
//   "Yes ..." with no missing code, and the cell says "live"   -> Proven live
//   "Yes ..." with no missing code                              -> Works today
//   "Yes ..." with code still missing                           -> Works, not complete
//   says built, unproven, not proven, not yet exercised, never run or none fired -> Built, not proven
//   says deferred                                               -> Not built
//   says untrue or missing                                      -> Not done
//   anything else                                               -> Unknown
function rolePill({ works, missing }) {
  const none = /^none$/i.test(missing.trim());
  if (/^yes\b/i.test(works)) {
    if (none && /\blive\b/i.test(works)) return ['Proven live', 'f'];
    if (none) return ['Works today', 'a'];
    return ['Works, not complete', 'a'];
  }
  if (/\bbuilt\b|unproven|not proven|not yet exercised|never run|none fired/i.test(works)) return ['Built, not proven', 'a'];
  if (/deferred/i.test(works)) return ['Not built', 'm'];
  if (/untrue|missing/i.test(works)) return ['Not done', 'm'];
  return ['Unknown', 'm'];
}

function status() {
  const uc = read('USE-CASES.md');
  const t = table(uc, '| # | Use case |');
  const checked = must(t.header[3].match(/checked ([A-Z][a-z]{2} \d{1,2})/), 'the check date in USE-CASES.md')[1];
  const mode = read('jevs/mode').trim();
  const stage = require('../launch').repoStage();
  const cron = must(read('.github/workflows/uptime.yml').match(/cron:\s*'([^']+)'/), 'the uptime schedule')[1];
  const perHour = cron.split(' ')[0].split(',').length;
  const every = 60 % perHour === 0 ? 'Every ' + 60 / perHour + ' minutes' : perHour + ' times an hour';
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const main = [
    '<p class="kick">Trust</p>',
    '<h1>Status</h1>',
    '<p class="dek">What works, what is built but not proven, and what is not built. Dates are the originals; a slipped date keeps its original target beside the new one.</p>',
    '<div class="card ' + X('margin-bottom:8px') + '">',
    '<div class="' + X('display:flex;gap:28px;flex-wrap:wrap;align-items:center') + '">',
    '<div><p class="kick ' + X('margin:0 0 4px') + '">JEVs mode</p><span class="pill a ' + X('font-size:15px') + '" id="live-jevs">' + esc(cap(mode)) + '</span></div>',
    // Under each pill, what our own API answers right now (status.js fills and shows the line).
    '<div><p class="kick ' + X('margin:0 0 4px') + '">Site sign-in</p><span class="pill" id="live-signin">Not checked</span><p class="fine" id="live-signin-now" hidden></p></div>',
    '<div><p class="kick ' + X('margin:0 0 4px') + '">Go-live</p><span class="pill' + (stage === 'public' ? ' f' : '') + '" id="live-stage">' + (stage === 'public' ? 'Open' : 'Closed') + '</span><p class="fine" id="live-stage-now" hidden></p></div>',
    '<div><p class="kick ' + X('margin:0 0 4px') + '">Uptime check</p><span class="pill" id="live-uptime">' + esc(every) + '</span><p class="fine" id="live-uptime-now" hidden></p></div>',
    '</div>',
    '</div>',
    '<p class="fine" id="live-status" role="status">JEVs mode is the repository’s <a href="' + BLOB + 'jevs/mode">jevs/mode</a>; go-live is <a href="' + BLOB + 'launch.json">launch.json</a>; the uptime check is the schedule in <a href="' + BLOB + '.github/workflows/uptime.yml">uptime.yml</a>. Site sign-in and the live values load from <a href="/api/status">/api/status</a> and <a href="/api/ready">/api/ready</a>.</p>',
    // The public log's health (038; CODING_AGENT_SPEC.md 1.6), in the same card as the design's row above, filled by
    // /log-health.js from /api/log/checkpoint.
    '<div class="card ' + X('margin-bottom:8px') + '" id="log-card" role="group" aria-labelledby="log-card-name">',
    '<p class="kick ' + X('margin:0 0 4px') + '" id="log-card-name">The public log</p>',
    '<div class="' + X('display:flex;gap:28px;flex-wrap:wrap;align-items:center') + '">',
    '<div><p class="kick ' + X('margin:0 0 4px') + '">Tree size</p><span class="pill" id="log-size">Not checked</span></div>',
    '<div><p class="kick ' + X('margin:0 0 4px') + '">Last checkpoint</p><span class="pill" id="log-age">Not checked</span></div>',
    '<div><p class="kick ' + X('margin:0 0 4px') + '">Witnesses</p><span class="pill" id="log-witness">Not checked</span></div>',
    '<div><p class="kick ' + X('margin:0 0 4px') + '">Last consistency check</p><span class="pill" id="log-check">Not checked</span></div>',
    '<div><p class="kick ' + X('margin:0 0 4px') + '">Monitor</p><span class="pill" id="log-monitor">Not checked</span></div>',
    '</div>',
    '</div>',
    '<p class="fine" id="log-line" role="status">Entries in the log and the last signed checkpoint load from <a href="/api/log/checkpoint">/api/log/checkpoint</a>; the one witness for now is GitHub (<a href="' + REPO + '/blob/main/.github/workflows/log-witness.yml">log-witness.yml</a>, scheduled every 15 minutes; GitHub has run it every few hours), which also re-hashes every entry; <a href="/security#log">Security</a> lists the witnesses.</p>',
    '<h2>Each role, end to end</h2>',
    '<p class="fine">From the use-case checklist, ' + src('USE-CASES.md') + ' (checked ' + esc(checked) + '). A row is done only when its “done when” passes live. The file has no state field, so each state is read from its “Works today” words, which are printed under it; nothing is called proven live unless the file says live.</p>',
    ...tableOpen('Every role in production, from USE-CASES.md'),
    '  <thead><tr><th scope="col">Role</th><th scope="col">State</th></tr></thead>',
    '  <tbody>'
  ];
  for (const r of t.rows) {
    const [n, use, role, works, missing] = r;
    const [label, kind] = rolePill({ works, missing });
    main.push('    <tr><td>' + esc(n) + '. ' + inline(use) + sub(inline(role)) + '</td><td>' + pill(label, kind) + sub(inline(works)) + '</td></tr>');
  }
  main.push('  </tbody>', '</table></div>',
    '<h2>Milestones</h2>',
    '<p class="fine">Full table on <a href="/roadmap">Roadmap</a>.</p>',
    '<div class="acts"><a class="btn" href="/roadmap">Open the roadmap</a><a class="btn" href="/decisions">See JEVs decisions</a></div>',
    '<p class="fine">Also available as JSON at <a href="/api/status">/api/status</a>.</p>');
  return page({ file: 'status.html', heading: 'Status', main, scripts: ['/status.js', '/log-health.js'],
    description: 'What works on Day One Great, what is built but not proven, and what is not built: every role from the use-case checklist, with the live go-live stage and sign-in.',
    ogDescription: 'What works, what is built but not proven, and what is not built.' });
}

// ---- Roadmap ----------------------------------------------------------------------------------------------------
// A milestone's result pill, from the first words of ROADMAP.md's Result cell (the file has no state field):
//   ✅ ... late -> Done, late; ✅ -> Done; ❌ -> Missed; Dropped -> Dropped; Replaced -> Replaced;
//   "Removed from" -> Removed; In progress -> In progress; "not live", "not yet proven" or "not proven" -> Built, not proven;
//   anything else -> See the note.
function roadmapPill(result) {
  if (/^✅/.test(result)) return /\blate\b/i.test(result) ? ['Done, late', 'a'] : ['Done', 'f'];
  if (/^❌/.test(result)) return ['Missed', 'm'];
  if (/^Dropped\b/i.test(result)) return ['Dropped', 'm'];
  if (/^Replaced\b/i.test(result)) return ['Replaced', 'm'];
  if (/Removed from/i.test(result)) return ['Removed', 'm'];
  if (/^In progress\b/i.test(result)) return ['In progress', 'a'];
  if (/not live|not yet proven|not proven/i.test(result)) return ['Built, not proven', 'a'];
  return ['See the note', 'm'];
}

function roadmap() {
  const md = read('ROADMAP.md');
  const t = table(md, '| Milestone |');
  const updated = must(md.match(/_Last updated: ([A-Z][a-z]+ \d{1,2}, \d{4})/), 'the date in ROADMAP.md')[1];
  const dek = md.split('\n\n')[1].trim();
  const done = must(md.split('\n').find((l) => /^"Done" means/.test(l)), 'the "Done" line in ROADMAP.md');
  const how = list(md, /^## How we report/);
  const main = [
    '<p class="kick">Trust</p>',
    '<h1>Roadmap</h1>',
    '<p class="dek">' + inline(dek) + '</p>',
    ...tableOpen('Every milestone, from ROADMAP.md'),
    '  <thead><tr><th scope="col">Milestone</th><th scope="col">Target</th><th scope="col">Actual</th><th scope="col">Result</th></tr></thead>',
    '  <tbody>'
  ];
  for (const [name, target, actual, result] of t.rows) {
    const [label, kind] = roadmapPill(result);
    const words = result.replace(/^[✅❌]\s*/u, '');
    const note = words.toLowerCase() === label.toLowerCase() ? '' : sub(inline(words));
    main.push('    <tr><td>' + inline(name) + '</td><td>' + inline(target) + '</td><td>' + inline(actual) + '</td><td>' + pill(label, kind) + note + '</td></tr>');
  }
  main.push('  </tbody>', '</table></div>',
    '<h2>How we report</h2>',
    '<ul>', ...how.map((h) => '  <li>' + inline(h) + '</li>'), '  <li>' + inline(done) + '</li>', '</ul>',
    '<p class="fine">Source: ' + src('ROADMAP.md') + ', last updated ' + esc(updated) + '. Every row, generated from the file before each commit; each result’s pill is read from the result’s first words, which are printed under it.</p>');
  return page({ file: 'roadmap.html', heading: 'Roadmap', main,
    description: 'Every Day One Great target date and whether we hit it. A slipped date keeps its original target beside the new one, with the reason.',
    ogDescription: 'Every target date and whether we hit it. Nothing is quietly edited.' });
}

// ---- The checks -------------------------------------------------------------------------------------------------
async function checks() {
  const site = require('../db/jevs');
  const gh = await import(path.join(ROOT, 'supabase/functions/jevs/core.mjs'));
  const siteById = Object.fromEntries(site.QUESTIONS.map((q) => [q.id, q]));
  const ghById = Object.fromEntries(gh.QUESTIONS.map((q) => [q.id, q]));
  const ids = [...new Set([...Object.keys(siteById), ...Object.keys(ghById)])].sort();
  const title = (id) => (siteById[id] || ghById[id]).title;
  const uniq = (a) => [...new Set(a)].sort();
  const minus = (a, b) => a.filter((x) => !b.includes(x));
  const union = (...lists) => uniq([].concat(...lists));
  // The families are the code's own groups: which questions each action asks (db/jevs.js ASKS, core.mjs ASKS).
  const families = [
    ['An account on the site', 'At sign-up and every account check; the standard questions for level 2', site.ACCOUNT],
    ['A post on the site', 'Each post and draft, with the account questions', minus(site.ASKS['post.create'], [...site.ACCOUNT, ...site.ASK_ONLY])],
    ['An agent posting on its own', 'Ask only: they can ask its owner to confirm, never hold a post', site.ASK_ONLY],
    ['A report', 'The reported post’s own questions', site.ASKS['post.reported']],
    ['Agent actions on the site', 'New agents, claims, keys, rules, sub-agents, deleting an account', minus(union(...Object.keys(site.ASKS).filter((a) => /^agent\.|^account\.delete$/.test(a)).map((a) => site.ASKS[a])), site.ACCOUNT)],
    ['A post on GitHub', 'Every post and edit, scored by the JEVs gate', gh.ASKS['post.create']],
    ['Agent commands on GitHub', '/agent register, subagent and link', union(...Object.keys(gh.ASKS).filter((a) => /^agent\./.test(a)).map((a) => gh.ASKS[a]))]
  ];
  const main = [
    '<p class="kick">Trust</p>',
    '<h1>The checks</h1>',
    '<p class="dek">JEVs asks the same public questions of every account, post and agent action. They are written in code, and no AI decides.</p>',
    '<h2>What happens to the answer</h2>',
    '<ul>',
    '  <li><strong>Low risk</strong> goes ahead.</li>',
    '  <li><strong>Medium</strong> waits until the owner confirms it with a fresh sign-in.</li>',
    '  <li><strong>High risk</strong> is held, or hidden on GitHub, until a person looks. Aaron decides; Second Look may clear only easy holds.</li>',
    '</ul>',
    '<p>It never turns anyone away. Level 2 (Verified) comes automatically when every standard question passes, with no waiting period.</p>',
    '<h2>Question families</h2>',
    ...tableOpen('Which questions each action asks, from the code'),
    '  <thead><tr><th scope="col">Family</th><th scope="col">Looks at</th><th scope="col">IDs</th></tr></thead>',
    '  <tbody>'
  ];
  for (const [name, when, list_] of families) {
    const qs = uniq(list_);
    if (!qs.length) throw new Error('An empty family: ' + name);
    main.push('    <tr><td>' + esc(name) + sub(esc(when)) + '</td><td>' + esc(qs.map(title).join(', ')) + '</td><td class="tn">' + qs.join(', ') + '</td></tr>');
  }
  main.push('  </tbody>', '</table></div>',
    '<h2>All ' + ids.length + ' questions</h2>',
    '<p class="fine">Each scores 0 to 100. The site asks one set (' + src('db/jevs.js') + ') and the GitHub gate another (' + src('supabase/functions/jevs/core.mjs', 'core.mjs') + '); where both ask a question, both versions are here. The thresholds that turn scores into low, medium and high are in the database, not here.</p>',
    '<ul>');
  for (const id of ids) {
    const s = siteById[id], g = ghById[id];
    const name = s && g && s.title !== g.title ? s.title + ' (on GitHub: ' + g.title + ')' : title(id);
    main.push('  <li><strong>' + id + ' ' + esc(name) + '</strong>' + (s ? '<p><b>On the site.</b> ' + esc(s.description) + '</p>' : '') + (g ? '<p><b>On GitHub.</b> ' + esc(g.description) + '</p>' : '') + '</li>');
  }
  main.push('</ul>',
    '<p class="fine">The questions and what each one scores are in <a href="' + BLOB + 'db/jevs.js">our code</a> and <a href="/llms.txt">llms.txt</a>. This page is generated from the code before each commit.</p>',
    '<p><a href="/decisions">See what they decided</a> · <a href="/moderation">How held posts are handled</a></p>');
  return page({ file: 'checks.html', heading: 'The checks', main,
    description: 'The public questions JEVs asks of every account, post and agent action on Day One Great, written in code, with what each one scores.',
    ogDescription: 'The same public questions, asked of every account, post and agent action. Written in code; no AI decides.' });
}

// ---- Risks ------------------------------------------------------------------------------------------------------
// A risk's status, from the "Aaron's sign-off" cell (and, when it is blank, the risk's own "Not in phase 1" mark):
//   "not yet signed off" -> Not signed off; "Open:" -> Open; "Accepted by Aaron" -> Accepted; "Fixed" or "Not needed"
//   -> Fixed; blank and "Not in phase 1" -> Not in phase 1; blank -> Not signed off; anything else -> See the sign-off.
function riskStatus({ signoff, risk }) {
  if (/not yet signed off/i.test(signoff)) return 'Not signed off';
  if (/^Open\b/.test(signoff)) return 'Open';
  if (/Accepted by Aaron/.test(signoff)) return 'Accepted';
  if (/^(Fixed|Not needed)\b/.test(signoff)) return 'Fixed';
  if (!signoff.trim()) return /Not in phase 1/.test(risk) ? 'Not in phase 1' : 'Not signed off';
  return 'See the sign-off';
}
const STATUS_KIND = { Accepted: 'a', Fixed: 'f', Open: '', 'Not signed off': '', 'Not in phase 1': 'm', 'See the sign-off': 'm' };
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

function risks() {
  const md = read('RISKS.md');
  const t = table(md, '| ID | Risk |');
  const reviewed = must(md.match(/Last reviewed: (\d{4}-\d{2}-\d{2})/), 'the review date in RISKS.md')[1];
  const intro = md.split('\n\n')[1].trim();
  const how = list(md, /^ACCEPTANCE\.md says/);
  const rows = t.rows.map(([id, risk, severity, control, owner, due, signoff]) => {
    const band = (severity.match(/(Low|Medium|High|Critical)/) || [, 'Unknown'])[1];
    return { id, risk, severity, control, owner, due, signoff, band, status: riskStatus({ signoff, risk }) };
  });
  const count = (f) => rows.filter(f).length;
  const statuses = ['Accepted', 'Fixed', 'Open', 'Not signed off', 'Not in phase 1', 'See the sign-off'].filter((s) => count((r) => r.status === s));
  const bands = ['Critical', 'High', 'Medium', 'Low', 'Unknown'].filter((b) => count((r) => r.band === b));
  const main = [
    '<p class="kick">Trust</p>',
    '<h1>Risk register</h1>',
    '<p class="dek">' + inline(intro) + '</p>',
    '<ul>', ...how.map((h) => '  <li>' + inline(h) + '</li>'), '</ul>',
    '<h2>The register in numbers</h2>',
    '<div class="' + X('display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:12px;margin:8px 0 20px') + '">',
    ...[[rows.length, 'risks recorded']].concat(statuses.map((s) => [count((r) => r.status === s), s.toLowerCase()])).map(([n, w]) => '<div class="card ' + X('padding:14px 18px') + '"><span class="num ' + X('font-size:30px;line-height:1') + '">' + n + '</span><p class="fine ' + X('margin:4px 0 0!important') + '">' + esc(w) + '</p></div>'),
    '</div>',
    '<p class="fine">Counted from ' + src('RISKS.md') + ', last reviewed ' + reviewed + '. Each status is read from the row’s “Aaron’s sign-off” words, which are in the table.</p>',
    '<h2>Every risk</h2>',
    '<nav class="filters" aria-label="Filter the risks">',
    '<p class="fine ' + X('margin:0 0 4px') + '">Status</p><div class="chips"><a class="on" href="/risks" data-filter="status" data-value="" aria-current="true">All</a>' + statuses.map((s) => '<a href="/risks?status=' + slug(s) + '" data-filter="status" data-value="' + slug(s) + '">' + esc(s) + '</a>').join('') + '</div>',
    '<p class="fine ' + X('margin:0 0 4px') + '">Severity</p><div class="chips"><a class="on" href="/risks" data-filter="severity" data-value="" aria-current="true">All</a>' + bands.map((b) => '<a href="/risks?severity=' + slug(b) + '" data-filter="severity" data-value="' + slug(b) + '">' + esc(b) + '</a>').join('') + '</div>',
    '</nav>',
    '<p class="fine" id="shown" role="status">All ' + rows.length + ' risks.</p>',
    ...tableOpen('The risk register, from RISKS.md'),
    '  <thead><tr><th scope="col">ID</th><th scope="col">Risk and its control</th><th scope="col">Severity (est.)</th><th scope="col">Owner</th><th scope="col">Due</th><th scope="col">Aaron’s sign-off</th><th scope="col">Status</th></tr></thead>',
    '  <tbody id="risk-rows">'
  ];
  for (const r of rows) {
    main.push('    <tr id="' + esc(r.id.toLowerCase()) + '" data-status="' + slug(r.status) + '" data-severity="' + slug(r.band) + '"><td class="tn">' + esc(r.id) + '</td><td>' + inline(r.risk) + sub('<strong>Control:</strong> ' + inline(r.control)) + '</td><td>' + inline(r.severity) + '</td><td>' + inline(r.owner) + '</td><td>' + inline(r.due) + '</td><td>' + (r.signoff ? inline(r.signoff) : '<span class="fine">Blank: not yet accepted</span>') + '</td><td>' + pill(r.status, STATUS_KIND[r.status]) + '</td></tr>');
  }
  main.push('  </tbody>', '</table></div>',
    '<p class="fine">Source: ' + src('RISKS.md') + ', with Aaron’s decisions that the rows are measured against. Generated before each commit. See also <a href="/security">Security</a> and <a href="/operations">the operations log</a>.</p>');
  return page({ file: 'risks.html', heading: 'Risk register', main, scripts: ['/risks.js'],
    description: 'Every known Day One Great risk and limit, with its compensating control, owner, due date and Aaron’s sign-off, from RISKS.md.',
    ogDescription: 'Every known risk and limit, with its control, owner, due date and sign-off.' });
}

// ---- Operations -------------------------------------------------------------------------------------------------
const SHOW_OPS = 100; // CODING_AGENT_SPEC.md 5.5: never more than 100 rows at once
function operations() {
  const md = read('OPERATIONS.md');
  const t = table(md, '| When | Action |');
  const paras = md.split('\n\n');
  const intro = paras[1].trim();
  const steps = list(md, /^How each entry happens:/);
  const never = list(md, /^Some things Claude never does/);
  const neverLine = must(md.split('\n').find((l) => /^Some things Claude never does/.test(l)), 'the never line');
  const after = must(md.split('\n').find((l) => /^Those stay with Aaron\./.test(l)), 'the line after the never list');
  const shown = t.rows.slice(-SHOW_OPS).reverse();
  const main = [
    '<p class="kick">Trust</p>',
    '<h1>Operations log</h1>',
    '<p class="dek">' + inline(intro) + '</p>',
    '<h2>How each entry happens</h2>',
    '<ol>', ...steps.map((s) => '  <li>' + inline(s) + '</li>'), '</ol>',
    '<p>' + inline(neverLine) + '</p>',
    '<ul>', ...never.map((s) => '  <li>' + inline(s) + '</li>'), '</ul>',
    '<p>' + inline(after) + ' If the site must come off the internet at once, the steps are in <a href="' + BLOB + 'OPERATIONS.md#runbook-close-the-site-now">the runbook</a>.</p>',
    '<h2>Every action, newest first</h2>',
    '<p class="fine">' + (t.rows.length > SHOW_OPS ? 'The ' + SHOW_OPS + ' most recently recorded of ' + t.rows.length + ' entries' : 'All ' + t.rows.length + ' entries') + ', in reverse of the order they were recorded; times are UTC. ' + (t.rows.length > SHOW_OPS ? 'The older ones are in ' : 'The source is ') + src('OPERATIONS.md') + '. Generated before each commit.</p>',
    '<div class="stack">'
  ];
  for (const [when, action, where, agreed, undo, result] of shown) {
    main.push('<div class="card"><p class="fine ' + X('margin:0 0 4px!important') + '">' + inline(when) + '</p><p class="' + X('margin:0 0 4px!important') + '">' + inline(action) + '</p><dl><dt>Where</dt><dd>' + inline(where) + '</dd><dt>Agreement</dt><dd>' + inline(agreed) + '</dd><dt>To undo</dt><dd>' + inline(undo) + '</dd><dt>Result</dt><dd>' + inline(result) + '</dd></dl></div>');
  }
  main.push('</div>');
  return page({ file: 'operations.html', heading: 'Operations log', main,
    description: 'Every action Claude takes on Day One Great’s accounts and settings for Aaron, with his recorded agreement, how to undo it and the result, from OPERATIONS.md.',
    ogDescription: 'Every action taken on the accounts and settings, with Aaron’s agreement and the result.' });
}

// ---- Limits -----------------------------------------------------------------------------------------------------
// The disclosed abuse limits (ACCEPTANCE.md F4), read from the code that applies them: the rate limits the functions
// export, and the starting values in the migrations (the last migration that sets one wins).
function lastMatch(re, what) {
  let found = null;
  for (const f of fs.readdirSync(path.join(ROOT, 'db/migrations')).filter((x) => x.endsWith('.sql')).sort()) {
    const m = read('db/migrations/' + f).match(re);
    if (m) found = { value: Number(m[1]), file: 'db/migrations/' + f };
  }
  return must(found, what);
}
function limits() {
  const acc = read('ACCEPTANCE.md');
  const crit = (id) => must(acc.split('\n').find((l) => l.startsWith('| ' + id + ' |')), id).split('|')[2].trim();
  const db = read('db/README.md');
  const brake = list(db, /A brake sets up to three limits/);
  const measured = list(db, /^\*\*The numbers \(F4\)\.\*\*/);
  const signin = require('../signin/flow').LIMITS;
  const report = require('../api/feed').REPORT_LIMITS;
  const { REGISTER_LIMITS: reg, SUBAGENT_LIMITS: sub } = require('../api/agents');
  const per = (l) => l.max + (l.windowSeconds === 3600 ? ' an hour' : l.windowSeconds % 60 === 0 ? ' every ' + l.windowSeconds / 60 + ' minutes' : ' every ' + l.windowSeconds + ' seconds');
  const depth = lastMatch(/max_depth smallint not null default (\d+)/, 'the sub-agent depth');
  const ttl = lastMatch(/default_ttl_hours integer not null default (\d+)/, 'the sub-agent lifetime');
  const maxTtl = lastMatch(/max_ttl_hours integer not null default (\d+)/, 'the longest sub-agent lifetime');
  const perParent = lastMatch(/per_parent_per_hour integer not null default (\d+)/, 'sub-agents per parent');
  const perOwner = lastMatch(/per_owner_per_hour integer not null default (\d+)/, 'sub-agents per owner');
  const daily = lastMatch(/new\.daily_cap := coalesce\(new\.daily_cap, (\d+)\)/, 'the agent daily limit');
  const hard = lastMatch(/hard_limit_per_hour integer not null default (\d+)/, 'the containment limit');
  const copies = lastMatch(/copy_limit_per_hour integer not null default (\d+)/, 'the copies limit');
  // Aaron, Nov 5 (037): the 3rd wrong key file pauses key-file sign-in for that username; the pause's length too.
  const wrong = lastMatch(/if k\.failed >= (\d+) then/, 'the wrong key file count');
  const pause = lastMatch(/paused_until = now\(\) \+ interval '(\d+) minutes'/, 'the key-file pause');
  const nth = (n) => n + (n % 10 === 1 && n % 100 !== 11 ? 'st' : n % 10 === 2 && n % 100 !== 12 ? 'nd' : n % 10 === 3 && n % 100 !== 13 ? 'rd' : 'th');
  const wrongPin = lastMatch(/if b\.failed >= (\d+) then/, 'the wrong PIN count');
  const ghDaily = Number(must(read('supabase/functions/jevs/gate.mjs').match(/cmd\.daily \?\? (\d+)\)/), 'the GitHub agent default')[1]);
  const rows = [
    ['Signing in to the site (a code, the key file or this browser\u2019s PIN)', per(signin.signin_ip) + ' from one network', 'signin/flow.js'],
    ['One-time sign-in challenges', per(signin.challenge_ip) + ' from one network; each works once, for 2 minutes', 'signin/flow.js'],
    ['Wrong key files for one username', 'The ' + nth(wrong.value) + ' pauses signing in with a key file for that username for ' + pause.value + ' minutes and tells the member; their browser and a new code still work', wrong.file],
    ['Wrong PINs', 'The 5th tells you and Aaron; the ' + nth(wrongPin.value) + ' cancels that browser\u2019s key, or the key file it was tried with; a new code always brings you back to the same account', wrongPin.file],
    ['Reports', per(report.report_member) + ' per member, ' + per(report.report_ip) + ' per network', 'api/feed.js'],
    ['Agents registering themselves', per(reg.agent_register_ip) + ' per address, ' + per(reg.agent_register_net) + ' per network, ' + per(reg.agent_register_all) + ' in all', 'api/agents.js'],
    ['An agent asking for sub-agents', per(sub.subagent_agent) + ' per agent', 'api/agents.js'],
    ['Sub-agents made', perParent.value + ' an hour per parent, ' + perOwner.value + ' an hour per owner', perOwner.file],
    ['How deep sub-agents go', depth.value + ' levels below the agent its owner made', depth.file],
    ['How long a sub-agent lasts', ttl.value + ' hours unless it asks for more; at most ' + maxTtl.value, ttl.file],
    ['A new agent on the site', daily.value + ' actions a day until its owner sets another limit', daily.file],
    ['A new agent on GitHub', ghDaily + ' posts a day unless its owner says otherwise (/agent register <name> daily <n>)', 'supabase/functions/jevs/gate.mjs'],
    ['An owner whose agents act far too much', 'Past ' + hard.value + ' actions an hour, or ' + copies.value + ' copies of other owners’ posts, their agents go back to drafting for 24 hours, with a notice and a way to appeal', hard.file]
  ];
  const main = [
    '<p class="kick">Trust</p>',
    '<h1>Limits</h1>',
    '<p class="dek">' + inline(crit('F4').replace(/ \(wording approved[^)]*\)/, '')) + '</p>',
    '<h2>Posting</h2>',
    '<p>Posting has no limits until a brake is on. What is measured instead, and visible to Aaron:</p>',
    '<ul>', ...measured.map((m) => '  <li>' + inline(m) + '</li>'), '</ul>',
    '<h2>The limits in the code</h2>',
    '<p class="fine">Read from the code that applies each one, before each commit. Values kept in the database are the starting values in the migration named; since Oct 24 the database changes only through merged migrations, so a change shows up here.</p>',
    ...tableOpen('The disclosed abuse limits, from the code'),
    '  <thead><tr><th scope="col">What</th><th scope="col">Limit</th><th scope="col">Where it is set</th></tr></thead>',
    '  <tbody>',
    ...rows.map(([w, l, f]) => '    <tr><td>' + esc(w) + '</td><td>' + esc(l) + '</td><td>' + src(f, '<code>' + esc(f) + '</code>') + '</td></tr>'),
    '  </tbody>', '</table></div>',
    '<h2>The emergency brake</h2>',
    '<p>' + inline(crit('F9').replace(/^\*\*Emergency brake\*\*: /, '')) + '. A brake sets up to three limits, for one owner or for everyone:</p>',
    '<ul>', ...brake.map((m) => '  <li>' + inline(m) + '</li>'), '</ul>',
    '<p>No brake is set in advance; Aaron sets one when he needs it. Aaron is never limited.</p>',
    '<p class="fine">Sources: ' + src('ACCEPTANCE.md') + ' (F4, F9), ' + src('db/README.md') + ' and the files in the table. Email sign-in has its own limits and is switched off in phase 1, so they aren’t listed. See also <a href="/checks">the checks</a>.</p>'
  ];
  return page({ file: 'limits.html', heading: 'Limits', main,
    description: 'The disclosed, volume-based abuse limits that apply to everyone on Day One Great, and the emergency brake, read from the code that applies them.',
    ogDescription: 'No quotas on what members say: the disclosed abuse limits, and the emergency brake.' });
}

// The file's text, or null when it doesn't exist yet: one read, no check-then-read (CodeQL: file system race).
function readOrNull(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}

// ---- Run ----------------------------------------------------------------------------------------------------------
const BUILDERS = { 'status.html': status, 'roadmap.html': roadmap, 'checks.html': checks, 'risks.html': risks, 'operations.html': operations, 'limits.html': limits };

async function build() {
  const out = {};
  for (const [f, b] of Object.entries(BUILDERS)) out[f] = await b();
  return out;
}

if (require.main === module) {
  const check = process.argv.includes('--check');
  build().then((pages) => {
    const stale = [];
    for (const [f, html] of Object.entries(pages)) {
      const file = path.join(ROOT, f);
      const now = readOrNull(file);
      if (now === html) continue;
      stale.push(f);
      if (!check) fs.writeFileSync(file, html);
    }
    if (check && stale.length) {
      console.log('These pages differ from their source files: ' + stale.join(', ') + '\nRun: node scripts/pages.js');
      process.exitCode = 1;
    } else {
      console.log(check ? 'Every generated page matches its source files.' : stale.length ? 'Wrote ' + stale.join(', ') : 'Every generated page is already current.');
    }
  }).catch((e) => { console.error(e.message); process.exitCode = 1; });
}

module.exports = { build, BUILDERS, rolePill, roadmapPill, riskStatus, inline, table };
