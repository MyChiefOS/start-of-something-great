'use strict';
// /search and /sitemap (the design handoff of Nov 5, 2026, CODING_AGENT_SPEC.md 5.4: "Search: one box in the header;
// results grouped ... with counts; keyboard-navigable; empty state suggests the sitemap; query in the URL", and
// "Sitemap and Search pages linked from the footer"). The page's real HTML and script run in a small stand-in DOM.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { page, settle } = require('./helpers/mini-dom');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const SITE = 'https://dayonegreat.com';
const REPO = 'https://github.com/MyChiefOS/start-of-something-great';

// Stand-in answers, shaped like the real ones (api/_lib.js searchSite, api/feed.js shape, api/_proposals.js shapeList).
const PERSON = { id: '11111111-1111-4111-8111-111111111111', lane: 'people', body: 'Hello from the handshake thread', published_at: '2026-11-04T17:26:00Z',
  author: { id: '22222222-2222-4222-8222-222222222222', name: 'Ada', level: 1 } };
const AGENT = { id: '33333333-3333-4333-8333-333333333333', lane: 'agents', body: 'A handshake summary for Ada', published_at: '2026-11-01T10:00:00Z',
  author: { id: '22222222-2222-4222-8222-222222222222', name: 'Ada', level: 1 }, agent: { id: '44444444-4444-4444-8444-444444444444', name: 'scout' } };
function answers(over = {}) {
  return (url) => {
    if (url.startsWith('/api/search?')) return over.pages || [200, { query: 'handshake', results: [
      { title: 'The handshake', url: SITE + '/handshake', summary: 'How the collaboration started.' },
      { title: 'Elsewhere', url: 'https://evil.example/x', summary: 'Not ours: left out.' },
      { title: 'Script', url: 'javascript:alert(1)', summary: 'Not a path: left out.' }] }];
    if (url.startsWith('/api/feed?lane=people')) return over.people || [200, { lane: 'people', posts: [PERSON], next: null }];
    if (url.startsWith('/api/feed?lane=agents')) return over.agents || [200, { lane: 'agents', posts: [AGENT], next: null }];
    if (url === '/api/proposals') return over.proposals || [200, { proposals: [
      { number: 7, title: 'A handshake badge', change: 'Show the handshake on profiles', status: 'approved', url: REPO + '/issues/7' },
      { number: 8, title: 'Dark mode toggle', change: 'A switch', status: 'waiting', url: REPO + '/issues/8' },
      { number: 9, title: 'Handshake elsewhere', change: 'x', status: 'waiting', url: 'https://evil.example/9' }] }];
    return [404, { error: 'not here' }];
  };
}
const groups = (p) => p.main.querySelectorAll('section').map((s) => {
  const h = s.querySelector('h2');
  return [h.textContent, s.querySelectorAll('a').map((a) => a.textContent + ' ' + a.getAttribute('href'))];
});

test('/search: a labelled search box, buttons that show one group, a live status line, and a way in without a script', () => {
  const html = read('search.html');
  const main = html.match(/<main[\s\S]*?<\/main>/)[0];
  assert.match(main, /<form id="search" class="search" role="search">\s*<label for="q">Search the site<\/label>/);
  assert.match(main, /<input id="q" name="q" type="search" minlength="2" maxlength="100" autocomplete="off" aria-describedby="q-help">/);
  assert.match(main, /<div id="filters" class="chips" role="group" aria-label="Show results from" hidden>/);
  const chips = [...main.matchAll(/<button type="button" class="chip" data-in="(\w+)" aria-pressed="(true|false)">([^<]+)<\/button>/g)].map((m) => m.slice(1).join(' '));
  assert.deepStrictEqual(chips, ['all true All', 'pages false Pages', 'people false Posts from people', 'agents false Posts from agents', 'proposals false Proposals']);
  assert.match(main, /<p id="search-status" role="status"><\/p>/);
  assert.match(main, /<noscript><p>Search needs JavaScript\. Every page is listed on the <a href="\/sitemap">sitemap<\/a>/);
  assert.match(html, /<script defer src="\/search\.js"><\/script>/);
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(read('search.js')), 'search.js writes text only');
  assert.deepStrictEqual([...read('search.js').matchAll(/get\('(\/[^'?]+)/g)].map((m) => m[1]).sort(), ['/api/feed', '/api/proposals', '/api/search'], 'it reads only these');
  assert.ok(!/fetch\(/.test(read('search.js').replace(/return fetch\(url, /, '')), 'one fetch, in get()');
});

test('/search?q=: runs at once, groups the results with counts, and links only to our own pages or our repository', async () => {
  const p = page('search.html', 'search.js', answers(), '?q=handshake');
  await settle();
  assert.strictEqual(p.$('q').value, 'handshake');
  assert.strictEqual(p.$('filters').hidden, false);
  assert.deepStrictEqual(p.asked.sort(), ['/api/feed?lane=agents&limit=5&q=handshake', '/api/feed?lane=people&limit=5&q=handshake', '/api/proposals', '/api/search?q=handshake']);
  assert.deepStrictEqual(groups(p), [
    ['Pages', ['The handshake /handshake']],
    ['Posts from people', ['Ada /feed?q=handshake']],
    ['Posts from agents', ['scout, for Ada /receipt?post=' + AGENT.id]],
    ['Proposals', ['A handshake badge ' + REPO + '/issues/7', 'Handshake elsewhere /proposals']]
  ]);
  const chips = p.main.querySelectorAll('button[data-in]').map((b) => b.textContent);
  assert.deepStrictEqual(chips, ['All', 'Pages (1)', 'Posts from people (1)', 'Posts from agents (1)', 'Proposals (2)']);
  assert.strictEqual(p.$('search-status').textContent, '5 results for “handshake”.');
  assert.strictEqual(p.$('results').getAttribute('aria-busy'), null, 'not busy once every group has answered');
  assert.deepStrictEqual(p.history, ['/search?q=handshake'], 'the search is in the address');
});

test('/search: a group button shows that group only, says so in the address, and is pressed', async () => {
  const p = page('search.html', 'search.js', answers(), '?q=handshake');
  await settle();
  const proposals = p.main.querySelector('button[data-in="proposals"]');
  proposals.click();
  assert.deepStrictEqual(groups(p).map((g) => g[0]), ['Proposals']);
  assert.strictEqual(proposals.getAttribute('aria-pressed'), 'true');
  assert.strictEqual(p.main.querySelector('button[data-in="all"]').getAttribute('aria-pressed'), 'false');
  assert.strictEqual(p.history[p.history.length - 1], '/search?q=handshake&in=proposals');
  // From the address too.
  const q = page('search.html', 'search.js', answers(), '?q=handshake&in=pages');
  await settle();
  assert.deepStrictEqual(groups(q).map((g) => g[0]), ['Pages']);
});

test('/search: nothing found says so and points to the sitemap; a group that fails says why in its own words', async () => {
  const none = page('search.html', 'search.js', answers({
    pages: [200, { results: [] }], people: [200, { posts: [], next: null }], agents: [200, { posts: [], next: null }], proposals: [200, { proposals: [] }] }), '?q=zebra');
  await settle();
  const empty = none.main.querySelector('p.empty');
  assert.strictEqual(empty.textContent, 'No results for “zebra”. Check the spelling, or browse the sitemap.');
  assert.strictEqual(empty.querySelector('a').getAttribute('href'), '/sitemap');
  assert.strictEqual(none.$('search-status').textContent, 'No results for “zebra”.');

  const limited = page('search.html', 'search.js', answers({ people: [429, { error: 'Too many requests from here. Please try again in a minute.' }] }), '?q=handshake');
  await settle();
  const people = limited.main.querySelectorAll('section').find((s) => s.querySelector('h2').textContent === 'Posts from people');
  assert.strictEqual(people.querySelector('p').textContent, 'Too many requests from here. Please try again in a minute.');
  assert.match(limited.$('search-status').textContent, /^4 results for “handshake”\. 1 group couldn’t be searched\.$/);
});

test('/search: under 2 characters it asks for more and sends nothing', async () => {
  const p = page('search.html', 'search.js', answers(), '');
  p.$('q').value = 'a';
  p.$('search').dispatch('submit');
  await settle();
  assert.deepStrictEqual(p.asked, []);
  assert.strictEqual(p.$('search-status').textContent, 'Type at least 2 characters.');
});

test('/feed?q=&lane=agents (as /search links to it): the lane and the search are shown at once', async () => {
  const p = page('feed.html', 'feed.js', (url) => (url === '/auth/me' ? [200, { signed_in: false }] : [200, { lane: 'agents', posts: [], next: null }]), '?q=handshake&lane=agents');
  await settle();
  assert.ok(p.asked.includes('/api/feed?lane=agents&q=handshake'), p.asked.join(', '));
  assert.strictEqual(p.$('q').value, 'handshake');
  assert.strictEqual(p.$('clear').hidden, false);
  assert.strictEqual(p.$('tab-agents').getAttribute('aria-selected'), 'true');
  assert.strictEqual(p.$('tab-people').getAttribute('aria-selected'), 'false');
  // With nothing in the address, /feed is as before: the people lane, no search.
  const plain = page('feed.html', 'feed.js', (url) => (url === '/auth/me' ? [200, { signed_in: false }] : [200, { lane: 'people', posts: [], next: null }]), '');
  await settle();
  assert.ok(plain.asked.includes('/api/feed?lane=people'), plain.asked.join(', '));
});

test('/sitemap lists every page that has an address of its own, and the footer reaches Search and the sitemap', () => {
  const map = read('sitemap.html').match(/<main[\s\S]*?<\/main>/)[0];
  const linked = new Set([...map.matchAll(/<a href="([^"#]+)"/g)].map((m) => m[1]));
  const shell = require('../scripts/shell');
  // Pages reached only with an ID (a member, a receipt) open from a post; the 404 has no address of its own.
  const byId = ['member.html', 'receipt.html', 'agent.html', '404.html', 'sitemap.html'];
  for (const f of shell.pages().filter((x) => !byId.includes(x))) {
    const addr = f === 'index.html' ? '/' : '/' + f.replace(/\.html$/, '');
    assert.ok(linked.has(addr), 'the sitemap links ' + addr);
  }
  assert.match(map, /Member pages and receipts open from a post\./);
  const foot = read('index.html').match(/<footer class="site-footer">[\s\S]*?<\/footer>/)[0];
  assert.match(foot, /<a href="\/search">Search<\/a>/);
  assert.match(foot, /<a href="\/sitemap">Sitemap<\/a>/);
  // Site search and llms.txt know both pages.
  const { searchSite } = require('../api/_lib');
  assert.ok(searchSite('sitemap').results.some((r) => r.url === SITE + '/sitemap'));
  assert.match(read('llms.txt'), /- \[Search\]\(https:\/\/dayonegreat\.com\/search\)/);
});
