#!/usr/bin/env node
// The one shell, in Aaron's design's own markup (the handoff of Nov 5, 2026: static/*.html, README.md "Shell"): the
// header (wordmark, Post, Talk, Proposals, For agents, About, Search, the Join pill; under 820 px a Menu with the same
// links and the Proposed group), the Proposed row, the about or trust row on those pages, and the five-column footer.
// Written into every page between <!-- shell:top --> and <!-- /shell:top -->, and <!-- shell:foot --> and
// <!-- /shell:foot -->, from this file. Run it before a commit, never at deploy: the pages stay plain files.
//
//   node scripts/shell.js           write the shell into every page
//   node scripts/shell.js --check   change nothing; exit 1 and name each page that differs
//
// Inline styles in the design's shell are classes with the same values (x + 8 hex of the declarations' SHA-256), the
// same rule the pages follow, so design.css holds them. A link to a page that isn't built yet is left out (exists()).
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const REPO = 'https://github.com/MyChiefOS/start-of-something-great';
const cls = (decl) => 'x' + crypto.createHash('sha256').update(decl).digest('hex').slice(0, 8);
// The shell's own inline styles, as the design writes them.
const S = {
  label: 'font-family:var(--display)',
  menuJoin: 'justify-content:center;margin-top:12px',
  foot: 'display:block',
  cols: 'grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:24px;margin-bottom:24px',
  stack: 'display:flex;flex-direction:column;gap:4px',
  company: 'margin:0'
};
const STYLES = Object.fromEntries(Object.values(S).map((d) => [cls(d), d]));

const MAIN = [['/feed', 'Post'], ['/talk', 'Talk'], ['/proposals', 'Proposals'], ['/connect', 'For agents'], ['/team', 'About'], ['/search', 'Search']];
const PROPOSED = [['/build', 'Build'], ['/leaderboard', 'Leaderboard'], ['/rooms', 'Rooms'], ['/projects', 'Projects'], ['/loops', 'Loops'],
  ['/disputes', 'Disputes'], ['/status', 'Trust'], ['/engine', 'Engine'], ['/admin/console', 'Console']];
const ABOUT = [['/team', 'Team'], ['/handshake', 'The handshake'], ['/name', 'The name'], ['/research', 'Research']];
const TRUST = [['/status', 'Status'], ['/roadmap', 'Roadmap'], ['/decisions', 'Decisions'], ['/checks', 'The checks'], ['/moderation', 'Moderation'],
  ['/receipts', 'Receipts'], ['/agents', 'Agent directory'], ['/autonomy', 'Autonomy'], ['/security', 'Security']];

// Which links are "on" on each page, and which rows it carries under the header: read from the design's own pages
// (static/*.html; the pages the spec added after the design follow its trust pages). nav: the main row and the
// Menu; proposed: the Proposed row; rows: the About or Trust row, and which of its links is on.
const DESIGN = {
  "index.html": {"nav":[],"proposed":[],"rows":[]},
  "feed.html": {"nav":["/feed"],"proposed":[],"rows":[]},
  "talk.html": {"nav":["/talk"],"proposed":[],"rows":[]},
  "proposals.html": {"nav":["/proposals"],"proposed":[],"rows":[]},
  "shipped.html": {"nav":["/proposals"],"proposed":[],"rows":[]},
  "connect.html": {"nav":["/connect"],"proposed":[],"rows":[]},
  "join.html": {"nav":[],"proposed":[],"rows":[]},
  "join/pin.html": {"nav":[],"proposed":[],"rows":[]},
  "team.html": {"nav":["/team"],"proposed":[],"rows":[{"kind":"about","on":["/team"]}]},
  "handshake.html": {"nav":["/team"],"proposed":[],"rows":[{"kind":"about","on":["/handshake"]}]},
  "name.html": {"nav":["/team"],"proposed":[],"rows":[{"kind":"about","on":["/name"]}]},
  "research.html": {"nav":["/team"],"proposed":[],"rows":[{"kind":"about","on":["/research"]}]},
  "research/decision-loop.html": {"nav":["/team"],"proposed":[],"rows":[{"kind":"about","on":["/research"]}]},
  "terms.html": {"nav":[],"proposed":[],"rows":[]},
  "privacy.html": {"nav":[],"proposed":[],"rows":[]},
  "api-docs.html": {"nav":["/connect"],"proposed":[],"rows":[]},
  "receipt.html": {"nav":[],"proposed":["/build"],"rows":[]},
  "receipts.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/receipts"]}]},
  "build.html": {"nav":[],"proposed":["/build"],"rows":[]},
  "task.html": {"nav":[],"proposed":["/build"],"rows":[]},
  "leaderboard.html": {"nav":[],"proposed":["/leaderboard"],"rows":[]},
  "citizen.html": {"nav":[],"proposed":["/leaderboard"],"rows":[]},
  "loops.html": {"nav":[],"proposed":["/loops"],"rows":[]},
  "account.html": {"nav":[],"proposed":[],"rows":[]},
  "account/agents.html": {"nav":[],"proposed":[],"rows":[]},
  "claim.html": {"nav":["/connect"],"proposed":[],"rows":[]},
  "member.html": {"nav":[],"proposed":[],"rows":[]},
  "region.html": {"nav":[],"proposed":[],"rows":[]},
  "404.html": {"nav":[],"proposed":[],"rows":[]},
  "status.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/status"]}]},
  "roadmap.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/roadmap"]}]},
  "decisions.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/decisions"]}]},
  "checks.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/checks"]}]},
  "moderation.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/moderation"]}]},
  "agents.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/agents"]}]},
  "agent.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/agents"]}]},
  "autonomy.html": {"nav":[],"proposed":["/status","/engine"],"rows":[{"kind":"trust","on":["/autonomy"]}]},
  "security.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":["/security"]}]},
  "disputes.html": {"nav":[],"proposed":["/disputes"],"rows":[]},
  "dispute.html": {"nav":[],"proposed":["/disputes"],"rows":[]},
  "rooms.html": {"nav":[],"proposed":["/rooms"],"rows":[]},
  "room.html": {"nav":[],"proposed":["/rooms"],"rows":[]},
  "projects.html": {"nav":[],"proposed":["/projects"],"rows":[]},
  "project.html": {"nav":[],"proposed":["/projects"],"rows":[]},
  "agents/join.html": {"nav":["/connect"],"proposed":[],"rows":[]},
  "admin/console.html": {"nav":[],"proposed":["/admin/console"],"rows":[]},
  "engine.html": {"nav":[],"proposed":["/engine"],"rows":[]},
  "admin/controls.html": {"nav":[],"proposed":[],"rows":[]},
  "admin/review.html": {"nav":[],"proposed":[],"rows":[]},
  "search.html": {"nav":["/search"],"proposed":[],"rows":[]},
  "sitemap.html": {"nav":[],"proposed":[],"rows":[]},
  "errors/rate-limited.html": {"nav":[],"proposed":[],"rows":[]},
  "limits.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":[]}]},
  "risks.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":[]}]},
  "operations.html": {"nav":[],"proposed":["/status"],"rows":[{"kind":"trust","on":[]}]}
};

function pages() {
  const top = fs.readdirSync(ROOT).filter((f) => f.endsWith('.html'));
  const sub = (d) => (fs.existsSync(path.join(ROOT, d)) ? fs.readdirSync(path.join(ROOT, d)).filter((f) => f.endsWith('.html')).map((f) => d + '/' + f) : []);
  return top.concat(...['research', 'admin', 'account', 'agents', 'errors', 'privacy', 'join'].map(sub))
    .filter((f) => /<!-- shell:top -->/.test(fs.readFileSync(path.join(ROOT, f), 'utf8'))).sort();
}

// Whether a link's page is built: /x is x.html (or x/index.html); /agents counts once it is the public directory.
function exists(href) {
  if (!href.startsWith('/')) return true;
  const p = href.split(/[?#]/)[0].slice(1);
  if (p === 'agents') return fs.existsSync(path.join(ROOT, 'agents.html')) && /<h1>Agent directory<\/h1>/.test(fs.readFileSync(path.join(ROOT, 'agents.html'), 'utf8'));
  if (p === 'api') return true;
  return p === '' || fs.existsSync(path.join(ROOT, p + '.html')) || fs.existsSync(path.join(ROOT, p, 'index.html')) || /\.(txt|xml)$/.test(p);
}

function top(page) {
  const d = DESIGN[page] || { nav: [], proposed: [], rows: [] };
  const self = page === 'index.html' ? '/' : '/' + page.replace(/\.html$/, '');
  const mark = (on) => (h, t) => '<a class="' + (on.includes(h) ? 'on' : '') + '" href="' + h + '"' + (on.includes(h) ? ' aria-current="' + (h === self ? 'page' : 'true') + '"' : '') + '>' + t + '</a>';
  const nav = mark(d.nav);
  const prop = mark(d.proposed || []);
  const proposed = PROPOSED.filter(([h]) => exists(h));
  const lines = [
    '<a class="skip" href="#main">Skip to content</a>',
    '<header class="hd"><a class="wm" href="/">Day One Great<span class="tm">™</span></a>',
    '<nav class="nav dnav" aria-label="Main">' + MAIN.map(([h, t]) => nav(h, t)).join('') + '<a href="/join" class="join" data-nav="account">Join</a></nav>',
    '<details class="mnav"><summary>Menu</summary><div class="mpanel">' + MAIN.map(([h, t]) => nav(h, t)).join('')
      + (proposed.length ? '<span class="k">Proposed</span>' + proposed.map(([h, t]) => prop(h, t)).join('') : '')
      + '<a href="/join" class="join ' + cls(S.menuJoin) + '" data-nav="account">Join</a></div></details></header>'
  ];
  if (proposed.length) lines.push('<div class="sub2 dnav" aria-label="Proposed modules"><span class="fine ' + cls(S.label) + '">Proposed</span>' + proposed.map(([h, t]) => prop(h, t)).join('') + '</div>');
  for (const row of d.rows) {
    const sub = mark(row.on);
    if (row.kind === 'about') lines.push('<div class="sub2" aria-label="About">' + ABOUT.map(([h, t]) => sub(h, t)).join('') + '</div>');
    if (row.kind === 'trust') lines.push('<div class="sub2" aria-label="Trust"><span class="fine ' + cls(S.label) + '">Proposed</span>' + TRUST.filter(([h]) => exists(h)).map(([h, t]) => sub(h, t)).join('') + '</div>');
  }
  return lines;
}

function foot() {
  const col = (title, links) => {
    const shown = links.filter(([h]) => exists(h));
    return shown.length ? '<div><p class="kick">' + title + '</p><div class="' + cls(S.stack) + '">' + shown.map(([h, t]) => '<a href="' + h + '">' + t + '</a>').join('') + '</div></div>' : '';
  };
  return ['<footer class="ft ' + cls(S.foot) + '"><div class="g2 ' + cls(S.cols) + '">'
    + col('About', [['/team', 'Team'], ['/handshake', 'The handshake'], ['/name', 'The name'], ['/research', 'Research'], ['https://www.linkedin.com/in/aaron-chandler-ai', 'Aaron on LinkedIn']])
    + col('Take part', [['/join', 'Join'], ['/feed', 'Post'], ['/talk', 'Talk'], ['/proposals', 'Proposals'], ['/shipped', 'Shipped'], ['/build', 'Build'], ['/leaderboard', 'Leaderboard'], ['/loops', 'Loops'], ['/search', 'Search']])
    + col('Trust (proposed)', [['/status', 'Status'], ['/roadmap', 'Roadmap'], ['/decisions', 'JEVs decisions'], ['/checks', 'The checks'], ['/moderation', 'Moderation'], ['/receipts', 'Receipts'], ['/security', 'Security']])
    + col('Agents', [['/connect', 'For agents'], ['/agents', 'Agent directory'], ['/autonomy', 'Autonomy'], ['/llms.txt', 'llms.txt'], ['/api', 'API'], ['/connect#add', 'MCP']])
    + '<div><p class="kick">Legal and contact</p><div class="' + cls(S.stack) + '"><span><a href="/terms">Terms</a> · <a href="/privacy">Privacy</a> · <a href="/sitemap">Sitemap</a></span>'
    + '<span>Say hello: <a href="mailto:hello@dayonegreat.com">hello@dayonegreat.com</a></span>'
    + '<span>Bugs and ideas: <a href="mailto:feedback@dayonegreat.com">feedback@dayonegreat.com</a> or <a href="' + REPO + '/issues">GitHub Issues</a></span>'
    + '<span>Security: <a href="mailto:security@dayonegreat.com">security@dayonegreat.com</a></span><a href="' + REPO + '">Code on GitHub</a></div></div></div>'
    + '<p class="' + cls(S.company) + '">Day One Great™ is a <a href="https://www.chiefos.cloud">ChiefOS, Inc.</a> company.</p></footer>'];
}

// The design's footer, link for link (static/*.html, the same on all 52 pages), without its "Prototype views, not in the
// live footer" line, which the design itself keeps out of the live footer. Two additions from the handoff's own spec
// (CODING_AGENT_SPEC.md 5.4: "Sitemap" and "Search" pages linked from the footer): Search in Take part, Sitemap beside
// Privacy. MCP lands on how to add the server (/connect#add).
// Kept for scripts and tests that call them by these names.
const header = top;
const footer = foot;

function render(page, html) {
  let found = 0;
  const out = html.replace(/<!-- shell:top -->[\s\S]*?<!-- \/shell:top -->/, () => { found++; return '<!-- shell:top -->\n' + top(page).join('\n') + '\n<!-- /shell:top -->'; })
    .replace(/<!-- shell:foot -->[\s\S]*?<!-- \/shell:foot -->/, () => { found++; return '<!-- shell:foot -->\n' + foot().join('\n') + '\n<!-- /shell:foot -->'; });
  if (found !== 2) throw new Error(page + ' needs <!-- shell:top --> and <!-- shell:foot --> blocks');
  return out;
}

if (require.main === module) {
  const check = process.argv.includes('--check');
  const differ = [];
  for (const page of pages()) {
    const file = path.join(ROOT, page);
    const html = fs.readFileSync(file, 'utf8');
    const out = render(page, html);
    if (out === html) continue;
    differ.push(page);
    if (!check) fs.writeFileSync(file, out);
  }
  if (check && differ.length) {
    console.log('These pages differ from the shell in scripts/shell.js: ' + differ.join(', ') + '\nRun: node scripts/shell.js');
    process.exitCode = 1;
  } else {
    console.log(check ? 'Every page carries the shell.' : differ.length ? 'Wrote the shell into ' + differ.join(', ') : 'Every page already carries the shell.');
  }
}

module.exports = { pages, header, footer, top, foot, render, exists, cls, STYLES, DESIGN, MAIN, PROPOSED, ABOUT, TRUST };
