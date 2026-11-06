#!/usr/bin/env node
// /admin/go-live: the single release checklist (ACCEPTANCE.md SF6; the design handoff of Nov 5, 2026,
// CODING_AGENT_SPEC.md section 6, "/admin/go-live (single release checklist, SF6)"), written from the repository's own
// files so its words can't drift from them (spec 5.7; Aaron's phase 7 decision: pages generated from repository files
// before each commit). Sources: RELEASE-CHECKLIST.md (every heading, paragraph and box, as written), ACCEPTANCE.md
// (the SF6 row) and launch.json (the stage). The page shows each box as the file has it; nothing here ticks one.
// Every source is public on GitHub, so the page shows nothing that isn't already public.
//
//   node scripts/go-live.js           write admin/go-live.html (with the shell from scripts/shell.js)
//   node scripts/go-live.js --check   change nothing; exit 1 if admin/go-live.html differs from what this writes
'use strict';

const fs = require('fs');
const path = require('path');
const shell = require('./shell');

const ROOT = path.join(__dirname, '..');
const OUT = 'admin/go-live.html';
const BLOB = 'https://github.com/MyChiefOS/start-of-something-great/blob/main/';
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// Inline Markdown, the little these files use: `code`, **bold**, and [text](link) (a repository file becomes its
// GitHub page; only https links and repository files are linked, anything else stays text).
// Code spans are set aside first (as numbered placeholders), so bold can wrap them ("**`LAUNCH_STAGE` in Vercel**").
function inline(s) {
  const codes = [];
  let h = esc(s.replace(/\u0000/g, '')).replace(/`([^`]+)`/g, (m, c) => { codes.push('<code>' + c + '</code>'); return '\u0000' + (codes.length - 1) + '\u0000'; });
  h = h.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  h = h.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, text, href) => {
    if (/^https:\/\//.test(href)) return '<a href="' + href + '">' + text + '</a>';
    if (/^[A-Za-z0-9_./-]+\.md(#[\w-]+)?$/.test(href)) return '<a href="' + BLOB + href + '">' + text + '</a>';
    return text;
  });
  return h.replace(/\u0000(\d+)\u0000/g, (m, i) => codes[Number(i)]);
}

// RELEASE-CHECKLIST.md as blocks: its title, then sections of paragraphs and lists of boxes.
function parse(md) {
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  const doc = { title: null, intro: [], sections: [] };
  let section = null;
  let para = [];
  let list = null;
  const target = () => (section ? section.blocks : doc.intro);
  const flush = () => {
    if (para.length) target().push({ kind: 'p', text: para.join(' ') });
    para = [];
  };
  for (const raw of lines) {
    const line = raw.trimEnd();
    let m;
    if ((m = /^# (.+)$/.exec(line))) { flush(); list = null; doc.title = m[1]; continue; }
    if ((m = /^## (.+)$/.exec(line))) { flush(); list = null; section = { title: m[1], blocks: [] }; doc.sections.push(section); continue; }
    if ((m = /^- (?:\[( |x|X)\] )?(.+)$/.exec(line))) {
      flush();
      if (!list) { list = { kind: 'list', items: [] }; target().push(list); }
      list.items.push({ box: m[1] === undefined ? null : m[1] !== ' ', text: m[2] });
      continue;
    }
    if (/^\s+\S/.test(line) && list) { list.items[list.items.length - 1].text += ' ' + line.trim(); continue; }
    if (line === '') { flush(); list = null; continue; }
    list = null;
    para.push(line);
  }
  flush();
  if (!doc.title) throw new Error('RELEASE-CHECKLIST.md has no title');
  return doc;
}

// The SF6 row of ACCEPTANCE.md: | SF6 | criterion | how it's checked |
function sf6() {
  const row = read('ACCEPTANCE.md').split('\n').find((l) => /^\|\s*SF6\s*\|/.test(l));
  if (!row) throw new Error('ACCEPTANCE.md has no SF6 row');
  const cells = row.split('|').slice(1, -1).map((c) => c.trim());
  return { criterion: cells[1], checked: cells[2] };
}

function blocks(list, indent) {
  const out = [];
  for (const b of list) {
    if (b.kind === 'p') { out.push(indent + '<p>' + inline(b.text) + '</p>'); continue; }
    out.push(indent + '<ul class="check">');
    for (const it of b.items) {
      const pill = it.box === null ? '<span class="pill m">Note</span>' : it.box ? '<span class="pill f">Ticked</span>' : '<span class="pill">Open</span>';
      out.push(indent + '  <li>' + pill + '<span>' + inline(it.text) + '</span></li>');
    }
    out.push(indent + '</ul>');
  }
  return out;
}

function page() {
  const doc = parse(read('RELEASE-CHECKLIST.md'));
  const crit = sf6();
  const stage = JSON.parse(read('launch.json')).stage;
  const boxes = doc.sections.flatMap((s) => s.blocks).concat(doc.intro).filter((b) => b.kind === 'list').flatMap((b) => b.items).filter((i) => i.box !== null);
  const ticked = boxes.filter((i) => i.box).length;
  const title = doc.title;
  const lines = [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '  <meta charset="utf-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1">',
    '  <title>' + esc(title) + ': Day One Great</title>',
    '  <meta name="description" content="The single release checklist for Day One Great (SF6), generated from RELEASE-CHECKLIST.md in the public repository.">',
    '  <meta name="robots" content="noindex">',
    '  <link rel="canonical" href="https://dayonegreat.com/admin/go-live">',
    '  <link rel="icon" href="/favicon.svg" type="image/svg+xml">',
    '  <link rel="preload" href="/fonts/bricolage-grotesque.woff2" as="font" type="font/woff2" crossorigin>',
    '  <link rel="stylesheet" href="/styles.css">',
    '  <link rel="stylesheet" href="/design.css">',
    '  <link rel="stylesheet" href="/modules-b.css">',
    '  <link rel="alternate" type="text/plain" href="/llms.txt" title="Day One Great for AI agents">',
    '  <meta name="theme-color" content="#0d0f14" media="(prefers-color-scheme: dark)">',
    '  <meta name="theme-color" content="#f6f7f9" media="(prefers-color-scheme: light)">',
    '  <meta property="og:type" content="website">',
    '  <meta property="og:site_name" content="Day One Great">',
    '  <meta property="og:title" content="' + esc(title) + '">',
    '  <meta property="og:description" content="The single release checklist for Day One Great, generated from the repository.">',
    '  <meta property="og:url" content="https://dayonegreat.com/admin/go-live">',
    '  <meta property="og:image" content="https://dayonegreat.com/og.jpg">',
    '  <meta property="og:image:width" content="1200">',
    '  <meta property="og:image:height" content="630">',
    '  <meta property="og:image:alt" content="Day One Great: an amber sun rising over the horizon">',
    '  <meta name="twitter:card" content="summary_large_image">',
    '  <meta name="twitter:image" content="https://dayonegreat.com/og.jpg">',
    '  <script defer src="/_vercel/insights/script.js"></script>',
    '</head>',
    '<body>',
    '  <a class="skip-link" href="#main">Skip to content</a>',
    '  <div class="wrap">',
    '    <header class="site-header"></header>',
    '',
    '    <!-- Generated by scripts/go-live.js from RELEASE-CHECKLIST.md, ACCEPTANCE.md and launch.json. Do not edit by hand. -->',
    '    <main id="main" class="story mod" tabindex="-1">',
    '      <div class="notice"><b>Generated.</b> Written from <a href="' + BLOB + 'RELEASE-CHECKLIST.md">RELEASE-CHECKLIST.md</a>, the SF6 row of <a href="' + BLOB + 'ACCEPTANCE.md">ACCEPTANCE.md</a> and <a href="' + BLOB + 'launch.json">launch.json</a> before each commit, so it says what they say. Each box shows as the file has it, and only a pull request that changes the file ticks one: this is the checklist as written, not a live status.</div>',
    '      <p class="kicker">Go live</p>',
    '      <h1>' + inline(title) + '</h1>',
    '      <p class="dek">' + inline(crit.criterion) + '.</p>',
    '      <dl class="def">',
    '        <dt>Criterion</dt><dd>SF6 in ACCEPTANCE.md, checked by: ' + inline(crit.checked) + '</dd>',
    '        <dt>Boxes</dt><dd class="tn">' + ticked + ' of ' + boxes.length + ' ticked in the file</dd>',
    '        <dt>Stage</dt><dd>launch.json says <strong>' + esc(String(stage)) + '</strong></dd>',
    '      </dl>',
    ...blocks(doc.intro, '      ')
  ];
  for (const s of doc.sections) {
    lines.push('', '      <h2>' + inline(s.title) + '</h2>', ...blocks(s.blocks, '      '));
  }
  lines.push(
    '    </main>',
    '',
    '    <footer class="site-footer"></footer>',
    '  </div>',
    '  <script src="/nav.js" defer></script>',
    '</body>',
    '</html>',
    ''
  );
  return shell.render(OUT, lines.join('\n'));
}

if (require.main === module) {
  const out = page();
  const file = path.join(ROOT, OUT);
  // One read, no check-then-read (CodeQL: file system race).
  let now = null;
  try { now = fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (process.argv.includes('--check')) {
    if (now !== out) { console.log(OUT + ' differs from RELEASE-CHECKLIST.md, ACCEPTANCE.md or launch.json. Run: node scripts/go-live.js'); process.exitCode = 1; }
    else console.log(OUT + ' matches its sources.');
  } else {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, out);
    console.log(now === out ? OUT + ' was already current.' : 'Wrote ' + OUT + '.');
  }
}

module.exports = { page, parse, inline, sf6, OUT };
