'use strict';
// The story pages restyled to Aaron's design (the design handoff of Nov 5, 2026: static/<page>.html and
// CODING_AGENT_SPEC.md 5 and 6). Per page: it is at its path, carries the one shell (scripts/shell.js), has the design's
// h1 and section headings in the design's order, runs no inline style or script (the site's security policy), and shows
// none of the design's sample entries: lists are drawn by the page's script from the live API.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const shell = require('../scripts/shell');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const mainOf = (html) => html.match(/<main[\s\S]*?<\/main>/)[0];
const text = (s) => s.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&rsquo;/g, '’').trim();

// [file, path, h1, the section headings (h2) in order, the stylesheets after /styles.css in order]
const PAGES = [
  ['connect.html', '/connect', 'Connect an agent', ['1. Add the server', '2. What your agent can do', '3. Propose a change through your agent',
    '4. Post for the person you act for', '5. Agents on GitHub', 'The rules for agents', 'Prefer plain HTTP?'], ['/design.css']],
  ['team.html', '/team', 'The team', ['Aaron Chandler', 'Claude', 'JEVs', 'Second Look', 'Account levels', 'How we decide'], ['/design.css', '/team.css']],
  ['handshake.html', '/handshake', 'The start of something great', ['From Claude', 'From Aaron', 'The agreement'], []],
  // The design sets the welcome post's title as an h3 under the h1; it is an h2 here, so no heading level is skipped.
  ['talk.html', '/talk', 'Talk on GitHub', ['Welcome to Day One Great: say hello', 'Replies'], ['/design.css', '/talk.css']],
  ['proposals.html', '/proposals', 'Proposals', ['How a proposal is decided', 'All proposals'], ['/design.css', '/proposals.css']],
  ['shipped.html', '/shipped', 'Shipped', ['Shipped from proposals'], ['/design.css', '/proposals.css']],
  // Search's group headings are drawn by search.js once there is a search.
  ['search.html', '/search', 'Search', [], ['/app.css', '/design.css', '/search.css']],
  ['region.html', '/region', 'Not open where you are yet', ['Live somewhere else?'], []],
  ['name.html', '/name', 'How we landed on Day One Great', ['The name that almost was', 'Going shorter', 'The call'], []],
  ['research.html', '/research', 'Research', ['Working papers', 'What every paper here includes'], []],
  ['research/decision-loop.html', '/research/decision-loop', 'The Day One Great Decision Loop', null, []]
];

// The design's sample entries (static/proposals.html, shipped.html, search.html): never on a live page or in its script.
const SAMPLES = ['Sample entries for review', 'Sample figures for review', 'Receipt verification and execution tracking',
  'Weekly summary of what shipped', 'Topic threads for the conversation', '@mira', '@jordan_k', 'Proposals page, decided in public',
  'MCP server for AI agents', 'Automatic checks (JEVs) on every post', 'Proposed by Claude, for Aaron', 'Decided with a reason',
  'value="receipt"', 'Follow the build'];

test('each restyled page is at its path and carries the one shell', () => {
  const all = shell.pages();
  for (const [f, href] of PAGES) {
    assert.ok(all.includes(f), f + ' is a page the shell writes into');
    assert.strictEqual(href, '/' + f.replace(/\.html$/, ''), f + ' serves ' + href);
    const html = read(f);
    assert.strictEqual(shell.render(f, html), html, f + ' carries the shell as scripts/shell.js writes it');
    assert.match(html, new RegExp('<link rel="canonical" href="https://dayonegreat\\.com' + href.replace(/\//g, '\\/') + '">'), f + ': canonical');
    assert.match(html, /<main id="main" class="story[^"]*" tabindex="-1">/, f + ': the main area takes focus from the skip link');
  }
});

test('each page has the design\'s h1 and section headings, in the design\'s order', () => {
  for (const [f, , h1, h2s] of PAGES) {
    const main = mainOf(read(f));
    const heads = [...main.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1>/g)].map((m) => text(m[1]));
    assert.deepStrictEqual(heads, [h1], f + ': one h1');
    if (h2s) assert.deepStrictEqual([...main.matchAll(/<h2\b[^>]*>([\s\S]*?)<\/h2>/g)].map((m) => text(m[1])), h2s, f + ': the section headings');
  }
});

test('each page loads its stylesheets in order, and none runs an inline style, script or event handler', () => {
  for (const [f, , , , css] of PAGES) {
    const html = read(f);
    const sheets = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)">/g)].map((m) => m[1]);
    assert.deepStrictEqual(sheets, ['/styles.css'].concat(css), f + ': stylesheets');
    for (const s of css) assert.ok(fs.existsSync(path.join(root, s.slice(1))), s + ' exists');
    assert.doesNotMatch(html, /\sstyle="/, f + ': no inline style');
    assert.doesNotMatch(html, /<style\b/, f + ': no style element');
    assert.doesNotMatch(html, /\son[a-z]+="/i, f + ': no event handler attributes');
    // Every script is a file, except the data-only JSON-LD block some pages carry (never run).
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      if (/type="application\/ld\+json"/.test(m[1])) continue;
      assert.match(m[1], /\ssrc="/, f + ': every script has a src');
      assert.strictEqual(m[2].trim(), '', f + ': and nothing inside it');
    }
  }
});

test('no page or list script shows a sample entry from the design', () => {
  for (const f of PAGES.map((p) => p[0]).concat(['proposals.js', 'shipped.js', 'search.js'])) {
    const t = read(f);
    for (const s of SAMPLES) assert.ok(!t.includes(s), f + ' shows the design sample "' + s + '"');
  }
});

test('/proposals and /shipped draw each live entry as the design\'s card, and say so when there are none', () => {
  for (const [js, list] of [['proposals.js', 'proposals'], ['shipped.js', 'shipped']]) {
    const t = read(js);
    assert.match(read(list + '.html'), new RegExp('<div id="' + list + '" class="stack list"></div>'));
    assert.match(t, /el\('article', 'card'\)/, js + ': a card');
    assert.match(t, /el\('span', 'pill/, js + ': a status pill with words');
    assert.match(t, /el\('div', 'empty-state'\)/, js + ': the empty state');
    assert.doesNotMatch(t.replace(/\/\/.*$/gm, ''), /innerHTML|outerHTML|insertAdjacentHTML|document\.write/, js + ': text only');
    assert.match(t, /fetch\('\/api\/(proposals|shipped)'/, js + ': the live API only');
  }
});

test('/talk keeps giscus exactly as it was, inside the design\'s replies card', () => {
  const main = mainOf(read('talk.html'));
  const giscus = '<script src="https://giscus.app/client.js"\n          data-repo="MyChiefOS/start-of-something-great"\n          data-repo-id="R_kgDOVIbhKA"\n'
    + '          data-mapping="number"\n          data-term="1"\n          data-strict="0"\n          data-reactions-enabled="1"\n          data-emit-metadata="0"\n'
    + '          data-input-position="top"\n          data-theme="preferred_color_scheme"\n          data-lang="en"\n          data-loading="lazy"\n'
    + '          crossorigin="anonymous"\n          async></script>';
  assert.ok(main.includes(giscus), 'the giscus embed, attribute for attribute');
  assert.ok(main.indexOf('<div class="card talk-replies">') < main.indexOf(giscus), 'in the replies card');
  assert.match(main, /<a class="btn s" href="https:\/\/github\.com\/MyChiefOS\/start-of-something-great\/discussions\/1">Read and reply on GitHub<\/a>/);
});

test('/research/decision-loop: the design\'s header layout, the paper\'s published text unchanged', () => {
  const main = mainOf(read('research/decision-loop.html'));
  assert.match(main, /<p class="kicker"><a href="\/research">Day One Great Research<\/a> · Working Paper No\. 1<\/p>\s*<h1 class="paper-title">The Day One Great Decision Loop<\/h1>\s*<p class="dek">An evidence-informed simulation of research, simulation, independent review and intent checks in human–AI decisions<\/p>\s*<p class="fine">Claude \(AI researcher\) with Aaron Chandler · Published October 15, 2026 · Version 3, after three reviews<\/p>\s*<p class="fine">Reviewed by independent AI agents in three rounds; not externally peer reviewed\./);
  // The design's "placeholder summary for review" is not this page: this is the full paper.
  assert.ok(!main.includes('placeholder summary'), 'no placeholder words');
  assert.match(main, /<h2 id="references">References<\/h2>/);
});
