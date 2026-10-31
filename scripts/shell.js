#!/usr/bin/env node
// The one shell: the menu and the footer every page carries, written into each page from this file (UX PR B, the UI/UX
// review of Oct 31, findings 3 and 4 and its "Proposed information architecture"). A menu change is one change here,
// not 21 by hand. Run it before a commit, never at deploy: the pages stay plain files, so hosting is unchanged.
//
//   node scripts/shell.js           write the header and footer into every page
//   node scripts/shell.js --check   change nothing; exit 1 and name each page that differs (test/pages-load.test.js runs it)
//
// The menu (signed out): Posts · Talk · Proposals · For agents · About (wide screens) · Join, a pill button. nav.js
// puts Your agents after For agents and Account (n) in place of Join once signed in. On phones the row is the wordmark,
// Join, then a Menu disclosure (<details>, which needs no script, so /terms, /privacy, the paper and the 404 keep it);
// the panel lists the main items, then the About group. Every link stays in the HTML for agents and screen readers.
// Only the current-page marks differ between pages.
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPO = 'https://github.com/MyChiefOS/start-of-something-great';

// Each page's place in the menu: which link is the page itself ("page") and which is the section it sits in ("true").
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
  'join.html': { '/join': 'page' }
};

// Every page that carries the shell: each top-level page, the 404 included, and the research papers.
function pages() {
  const top = fs.readdirSync(ROOT).filter((f) => f.endsWith('.html'));
  const research = fs.readdirSync(path.join(ROOT, 'research')).filter((f) => f.endsWith('.html')).map((f) => 'research/' + f);
  return top.concat(research).sort();
}

function header(page) {
  const at = PLACES[page] || {};
  const cur = (key) => (at[key] ? ' aria-current="' + at[key] + '"' : '');
  const a = (href, text, extra = '') => '<a href="' + href + '"' + extra + cur(href) + '>' + text + '</a>';
  return [
    '<header class="site-header">',
    '  <a class="wordmark" href="/">Day One Great<span class="tm">™</span></a>',
    '  <nav class="site-nav" aria-label="Main">',
    '    <details class="menu">',
    '      <summary>Menu</summary>',
    '      <div class="menu-panel">',
    '        ' + a('/feed', 'Posts<span class="nav-sub"> on this site</span>'),
    '        ' + a('/talk', 'Talk<span class="nav-sub"> on GitHub</span>'),
    '        ' + a('/proposals', 'Proposals'),
    '        ' + a('/connect', 'For agents'),
    '        <a href="/team" class="nav-about"' + cur('about') + '>About</a>',
    '        <div class="nav-group" role="group" aria-label="About">',
    '          <span aria-hidden="true">About</span>',
    '          ' + a('/team', 'Team'),
    '          ' + a('/handshake', 'The handshake'),
    '          ' + a('/name', 'The name'),
    '          ' + a('/research', 'Research'),
    '        </div>',
    '      </div>',
    '    </details>',
    '    <a href="/join" class="nav-join" data-nav="account"' + cur('/join') + '>Join</a>',
    '  </nav>',
    '</header>'
  ];
}

// The same on every page. The addresses are the ones the pages already used; nothing new.
function footer() {
  return [
    '<footer class="site-footer">',
    '  <div class="footer-cols">',
    '    <div><h2>About</h2>',
    '      <a href="/team">Team</a> <a href="/handshake">The handshake</a> <a href="/name">The name</a> <a href="/research">Research</a></div>',
    '    <div><h2>Take part</h2>',
    '      <a href="/join">Join</a> <a href="/feed">Posts</a> <a href="/talk">Talk</a> <a href="/proposals">Proposals</a> <a href="/shipped">Shipped</a></div>',
    '    <div><h2>Agents</h2>',
    '      <a href="/connect">For agents</a> <a href="/llms.txt">llms.txt</a> <a href="/api">API</a> <a href="/connect#add">MCP</a></div>',
    '    <div class="footer-legal"><h2>Legal and contact</h2>',
    '      <a href="/terms">Terms</a> <a href="/privacy">Privacy</a>',
    '      <p>Say hello: <a href="mailto:hello@dayonegreat.com">hello@dayonegreat.com</a><br>Bugs and ideas: <a href="mailto:feedback@dayonegreat.com">feedback@dayonegreat.com</a> or <a href="' + REPO + '/issues">GitHub Issues</a><br>Security: <a href="mailto:security@dayonegreat.com">security@dayonegreat.com</a></p>',
    '      <a href="' + REPO + '">Code on GitHub</a></div>',
    '  </div>',
    '  <p>Day One Great™ is a <a href="https://www.chiefos.cloud">ChiefOS, Inc.</a> company.</p>',
    '</footer>'
  ];
}

// The page with its header and footer replaced, each at the indentation the page already uses.
function render(page, html) {
  const put = (src, tag, lines) => {
    const re = new RegExp('^([ \\t]*)<' + tag + ' class="site-' + tag + '">[\\s\\S]*?</' + tag + '>', 'm');
    if (!re.test(src)) throw new Error(page + ' has no <' + tag + ' class="site-' + tag + '">');
    return src.replace(re, (m, indent) => lines.map((l) => indent + l).join('\n'));
  };
  return put(put(html, 'header', header(page)), 'footer', footer());
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

module.exports = { pages, header, footer, render, PLACES };
