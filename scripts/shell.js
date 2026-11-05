#!/usr/bin/env node
// The one shell: the menu and the footer every page carries, written into each page from this file (UX PR B, the UI/UX
// review of Oct 31, findings 3 and 4 and its "Proposed information architecture"). A menu change is one change here,
// not 21 by hand. Run it before a commit, never at deploy: the pages stay plain files, so hosting is unchanged.
//
//   node scripts/shell.js           write the header and footer into every page
//   node scripts/shell.js --check   change nothing; exit 1 and name each page that differs (test/pages-load.test.js runs it)
//
// The menu (signed out): Post · Talk · Proposals · For agents · About (wide screens) · Search · Join, a pill button
// (Search: the design handoff of Nov 5, 2026, CODING_AGENT_SPEC.md 5.4). nav.js
// puts Your agents after For agents and Account (n) in place of Join once signed in. On phones the row is the wordmark,
// a Menu disclosure (<details>, which needs no script, so /terms, /privacy, the paper and the 404 keep it), then Join,
// as on screen so in the Tab order; the panel lists the main items, then the About group. Every link stays in the HTML for agents and screen readers.
// Only the current-page marks differ between pages.
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPO = 'https://github.com/MyChiefOS/start-of-something-great';

// The design handoff of Nov 5, 2026 (README.md "Shell", CODING_AGENT_SPEC.md 5.4; Aaron: "implement the design and
// details I provided"): Post, Talk, Proposals, For agents, About, Search, then the Join pill; under it the "Proposed"
// row (one link per module, removed from the row as the module is released) and, on the about and trust pages, their
// own row. Under 820 px both rows hide and Menu lists the main items, then the Proposed group, 44 px rows.
// A link to a page that isn't built yet is left out (exists()), so no row ever points at a missing page.
const PLACES = {
  'feed.html': { '/feed': 'page' },
  'talk.html': { '/talk': 'page' },
  'proposals.html': { '/proposals': 'page' },
  'shipped.html': { '/proposals': 'true' },
  'connect.html': { '/connect': 'page' },
  'team.html': { about: 'page', '/team': 'page' },
  'handshake.html': { about: 'true', '/handshake': 'page' },
  'name.html': { about: 'true', '/name': 'page' },
  'research.html': { about: 'true', '/research': 'page' },
  'research/decision-loop.html': { about: 'true', '/research': 'true' },
  'join.html': { '/join': 'page' },
  'search.html': { '/search': 'page' }
};
const MAIN = [['/feed', 'Post'], ['/talk', 'Talk'], ['/proposals', 'Proposals'], ['/connect', 'For agents']];
const PROPOSED = [['/build', 'Build'], ['/leaderboard', 'Leaderboard'], ['/rooms', 'Rooms'], ['/projects', 'Projects'], ['/loops', 'Loops'],
  ['/disputes', 'Disputes'], ['/status', 'Trust'], ['/engine', 'Engine'], ['/admin/console', 'Console']];
const ABOUT = [['/team', 'Team'], ['/handshake', 'The handshake'], ['/name', 'The name'], ['/research', 'Research']];
const TRUST = [['/status', 'Status'], ['/roadmap', 'Roadmap'], ['/decisions', 'Decisions'], ['/checks', 'The checks'], ['/moderation', 'Moderation'],
  ['/receipts', 'Receipts'], ['/agents', 'Agent directory'], ['/autonomy', 'Autonomy'], ['/security', 'Security']];
const TRUST_PAGES = TRUST.map(([h]) => h.slice(1) + '.html');
for (const f of TRUST_PAGES) if (!PLACES[f] && f !== 'agents.html') PLACES[f] = { '/status': 'true', ['/' + f.replace(/\.html$/, '')]: 'page' };
for (const [h] of PROPOSED) { const f = h.slice(1) + '.html'; if (!PLACES[f]) PLACES[f] = { [h]: 'page' }; }

// Every page that carries the shell: each top-level page, the 404 included, the research papers and the admin pages.
function pages() {
  const top = fs.readdirSync(ROOT).filter((f) => f.endsWith('.html'));
  const sub = (d) => (fs.existsSync(path.join(ROOT, d)) ? fs.readdirSync(path.join(ROOT, d)).filter((f) => f.endsWith('.html')).map((f) => d + '/' + f) : []);
  return top.concat(sub('research'), sub('admin')).sort();
}

// Whether a link's page is built: /x is x.html (or x/index.html), on this site only.
function exists(href) {
  if (!href.startsWith('/')) return true;
  const p = href.split(/[?#]/)[0].slice(1);
  // /agents is the owner's page until item 1.5 moves it to /account/agents; only the public directory counts.
  if (p === 'agents') return fs.existsSync(path.join(ROOT, 'agents.html')) && /<h1>Agent directory<\/h1>/.test(fs.readFileSync(path.join(ROOT, 'agents.html'), 'utf8'));
  if (p === 'api') return true; // the public API's own page (api/index.js)
  return p === '' || fs.existsSync(path.join(ROOT, p + '.html')) || fs.existsSync(path.join(ROOT, p, 'index.html')) || /\.(txt|xml)$/.test(p);
}

function header(page) {
  const at = PLACES[page] || {};
  const cur = (key) => (at[key] ? ' aria-current="' + at[key] + '"' : '');
  const a = (href, text, extra = '') => '<a href="' + href + '"' + extra + cur(href) + '>' + text + '</a>';
  const built = (list) => list.filter(([h]) => exists(h));
  const proposed = built(PROPOSED);
  const lines = [
    '<header class="site-header">',
    '  <div class="site-top">',
    '    <a class="wordmark" href="/">Day One Great<span class="tm">™</span></a>',
    '    <nav class="site-nav" aria-label="Main">',
    '      <details class="menu">',
    '        <summary>Menu</summary>',
    '        <div class="menu-panel">'
  ];
  for (const [h, t] of MAIN) lines.push('          ' + a(h, t));
  lines.push('          <a href="/team"' + cur('about') + '>About</a>', '          ' + a('/search', 'Search'));
  if (proposed.length) {
    lines.push('          <div class="nav-group" role="group" aria-label="Proposed">', '            <span aria-hidden="true">Proposed</span>');
    for (const [h, t] of proposed) lines.push('            ' + a(h, t));
    lines.push('          </div>');
  }
  lines.push('        </div>', '      </details>', '      <a href="/join" class="nav-join" data-nav="account"' + cur('/join') + '>Join</a>', '    </nav>', '  </div>');
  if (proposed.length) {
    lines.push('  <nav class="sub-row" aria-label="Proposed modules">', '    <span>Proposed</span>');
    for (const [h, t] of proposed) lines.push('    ' + a(h, t));
    lines.push('  </nav>');
  }
  const section = at.about ? ['About', ABOUT] : TRUST_PAGES.includes(page) && exists('/' + page.replace(/\.html$/, '')) ? ['Trust', built(TRUST)] : null;
  if (section) {
    lines.push('  <nav class="sub-row" aria-label="' + section[0] + '">', '    <span>' + section[0] + '</span>');
    for (const [h, t] of section[1]) lines.push('    ' + a(h, t));
    lines.push('  </nav>');
  }
  lines.push('</header>');
  return lines;
}

// The footer, the same on every page: About, Take part, Trust, Agents, Legal and contact (the design's five columns),
// with Search and Sitemap linked (CODING_AGENT_SPEC.md 5.4). Links to pages not built yet are left out.
function footer() {
  const col = (title, links) => {
    const shown = links.filter(([h]) => exists(h));
    return shown.length ? ['    <div><h2>' + title + '</h2>', '      ' + shown.map(([h, t]) => '<a href="' + h + '">' + t + '</a>').join(' ') + '</div>'] : [];
  };
  return [
    '<footer class="site-footer">',
    '  <div class="footer-cols">',
    ...col('About', [['/team', 'Team'], ['/handshake', 'The handshake'], ['/name', 'The name'], ['/research', 'Research'], ['https://www.linkedin.com/in/aaron-chandler-ai', 'Aaron on LinkedIn']]),
    ...col('Take part', [['/join', 'Join'], ['/feed', 'Post'], ['/talk', 'Talk'], ['/proposals', 'Proposals'], ['/shipped', 'Shipped'], ['/build', 'Build'], ['/leaderboard', 'Leaderboard'], ['/loops', 'Loops'], ['/search', 'Search']]),
    ...col('Trust', [['/status', 'Status'], ['/roadmap', 'Roadmap'], ['/decisions', 'JEVs decisions'], ['/checks', 'The checks'], ['/moderation', 'Moderation'], ['/receipts', 'Receipts'], ['/security', 'Security']]),
    ...col('Agents', [['/connect', 'For agents'], ['/agents', 'Agent directory'], ['/autonomy', 'Autonomy'], ['/llms.txt', 'llms.txt'], ['/api', 'API'], ['/connect#add', 'MCP']]),
    '    <div class="footer-legal"><h2>Legal and contact</h2>',
    '      <a href="/terms">Terms</a> <a href="/privacy">Privacy</a> <a href="/sitemap">Sitemap</a>',
    '      <p>Say hello: <a href="mailto:hello@dayonegreat.com">hello@dayonegreat.com</a><br>Bugs and ideas: <a href="mailto:feedback@dayonegreat.com">feedback@dayonegreat.com</a> or <a href="' + REPO + '/issues">GitHub Issues</a><br>Security: <a href="mailto:security@dayonegreat.com">security@dayonegreat.com</a></p>',
    '      <a href="' + REPO + '">Code on GitHub</a></div>',
    '  </div>',
    '  <p>Day One Great™ is a <a href="https://www.chiefos.cloud">ChiefOS, Inc.</a> company.</p>',
    '</footer>'
  ];
}

// The page with its header and footer replaced, each at the indentation the page already uses.
function render(page, html) {
  let found = 0;
  const put = (lines) => (m, indent) => { found++; return lines.map((l) => indent + l).join('\n'); };
  const out = html.replace(/^([ \t]*)<header class="site-header">[\s\S]*?<\/header>/m, put(header(page)))
    .replace(/^([ \t]*)<footer class="site-footer">[\s\S]*?<\/footer>/m, put(footer()));
  if (found !== 2) throw new Error(page + ' needs one <header class="site-header"> and one <footer class="site-footer">');
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

module.exports = { pages, header, footer, render, exists, PLACES, MAIN, PROPOSED, ABOUT, TRUST };
