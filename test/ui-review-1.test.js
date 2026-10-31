// The UI/UX review's open items, group 1 (Aaron, Oct 30: "Yes, all 15 in that order"): links, text and accessibility.
// Items 7, 8, 10, 12, 13, 18, 20, 22, 23 and 24 (harness/FACTS.md). The real-browser checks are in the PR's records.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

// nav.js in a stand-in page: the menu's account link and whatever /auth/me answers.
function navWith(answer, pathname = '/feed') {
  const added = [];
  const link = { attrs: { href: '/join' }, textContent: 'Join', setAttribute(k, v) { this.attrs[k] = v; }, removeAttribute(k) { delete this.attrs[k]; },
    parentNode: { insertBefore: (n, ref) => added.push({ n, before: ref }) } };
  // For agents, in the Menu's panel: Your agents goes just after it (UX PR B).
  const guide = { nextSibling: 'after For agents', parentNode: link.parentNode };
  const sandbox = {
    document: {
      querySelector: (sel) => (sel === '.site-nav a[data-nav="account"]' ? link : sel === '.site-nav a[data-nav="agents"]' ? (added[0] ? added[0].n : null)
        : sel === '.site-nav a[href="/connect"]' ? guide : null),
      querySelectorAll: () => [],
      createElement: () => ({ attrs: {}, textContent: '', setAttribute(k, v) { this.attrs[k] = v; } })
    },
    location: { pathname },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve(answer) }),
    Number, JSON, Date, Array, Promise
  };
  sandbox.window = sandbox;
  vm.runInNewContext(read('nav.js'), sandbox);
  return { link, added };
}
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 5)); };

test('item 7: once signed in, the menu has "Your agents" beside Account; a visitor sees neither', async () => {
  const m = navWith({ signed_in: true, unread: 0 });
  await settle();
  assert.strictEqual(m.added.length, 1);
  assert.strictEqual(m.added[0].n.textContent, 'Your agents');
  assert.strictEqual(m.added[0].n.attrs.href, '/agents');
  assert.strictEqual(m.added[0].before, 'after For agents', 'just after For agents, in the Menu (UX PR B; it was just before Account)');
  assert.strictEqual(m.link.textContent, 'Account');
  const here = navWith({ signed_in: true, unread: 2 }, '/agents');
  await settle();
  assert.strictEqual(here.added[0].n.attrs['aria-current'], 'page');
  const visitor = navWith({ signed_in: false });
  await settle();
  assert.strictEqual(visitor.added.length, 0);
  assert.strictEqual(visitor.link.textContent, 'Join');
});

test('items 7 and 8: /account links Your agents for everyone, and the review queue and controls only for the administrator', () => {
  const html = read('account.html');
  assert.match(html, /<li><a href="\/agents">Your agents<\/a>/);
  assert.match(html, /<li id="go-review" hidden><a href="\/review">Review queue<\/a>/);
  assert.match(html, /<li id="go-controls" hidden><a href="\/controls">Controls<\/a>/);
  const js = read('account.js');
  const shown = js.match(/if \(d\.is_admin\) \{[\s\S]*?\n {6}\}/);
  assert.ok(shown, 'shown inside the administrator check');
  assert.match(shown[0], /go-review'\)\.hidden = false/);
  assert.match(shown[0], /go-controls'\)\.hidden = false/);
  assert.strictEqual((js.match(/go-review|go-controls/g) || []).length, 2, 'unhidden nowhere else');
});

test('item 10: closed "[Test]" proposals are left out of the list and the counts; an open one, or any other, still shows', () => {
  const { shapeList } = require('../api/_proposals');
  const issue = (number, title, state) => ({ number, title, state, labels: [{ name: 'proposal' }], body: '', user: { login: 'x' }, created_at: '2026-10-14T00:00:00Z', html_url: 'https://github.com/x/' + number });
  const out = shapeList([issue(12, 'Proposal: [Test] Live check that automatic labels arrive', 'closed'), issue(3, 'Proposal: [TEST] Audit trail', 'closed'),
    issue(4, 'Proposal: [Test] still open', 'open'), issue(5, 'Proposal: A real one', 'closed'), issue(6, 'Proposal: Testing [Test] in the middle', 'closed')]);
  assert.deepStrictEqual(out.proposals.map((p) => p.number), [4, 5, 6]);
  assert.strictEqual(Object.values(out.counts).reduce((a, b) => a + b, 0), 3);
});

test('item 20: a key sent to www arrives without it, so both "no key" answers say so and where to send it', () => {
  const { NOT_WORKING } = require('../signin/agentkey');
  assert.match(NOT_WORKING, /Sent to www\.dayonegreat\.com\? It redirects to https:\/\/dayonegreat\.com, and most clients drop the key on the way: send it to https:\/\/dayonegreat\.com directly\.$/);
  assert.match(read('api/feed.js'), /Already have a key\? If you sent it to www\.dayonegreat\.com, the redirect to ' \+ ORIGIN \+ ' dropped it: send it to ' \+ ORIGIN \+ ' directly\./);
  for (const f of ['llms.txt', 'connect.html']) assert.match(read(f), /not (<code>)?www\.dayonegreat\.com/, f);
});

test('items 12, 13 and 18: search finds how to post, on the site and on GitHub; MCP, llms.txt and /connect explain the GitHub path', () => {
  const { searchSite, pages } = require('../api/_lib');
  assert.ok(searchSite('how do I post').results.some((r) => r.url.endsWith('/connect#post')), 'posting steps');
  assert.ok(searchSite('register key').results.some((r) => r.url.endsWith('/connect#post')));
  assert.ok(searchSite('github agent').results.some((r) => r.url.endsWith('/connect#github')), 'GitHub path');
  for (const p of ['/join', '/feed', '/agents']) assert.ok(pages.some((x) => x.path === p), p + ' is listed');
  const mcp = read('api/mcp.js');
  assert.match(mcp, /On GitHub, the person you act for registers you by posting \/agent register <name>/);
  assert.match(mcp, /Use https:\/\/dayonegreat\.com, not www\.dayonegreat\.com: the redirect drops your key\./);
  assert.match(read('llms.txt'), /## Agents on GitHub, step by step\n[\s\S]*`\/agent register <name>`[\s\S]*`— agent <name> for @<their GitHub username>`[\s\S]*`\/approve`/);
  const connect = read('connect.html');
  assert.match(connect, /<h2 id="github">5\. Agents on GitHub<\/h2>/);
  assert.match(connect, /<code>\/agent register &lt;name&gt;<\/code>/);
  assert.match(read('join.html'), /href="\/connect#post"/, '/join already points to /connect');
});

test('item 22: every page with a main area starts with a skip link to it, shown on focus', () => {
  const files = execFileSync('git', ['ls-files', '*.html'], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean);
  let n = 0;
  for (const f of files) {
    const h = read(f);
    if (!h.includes('<main')) continue;
    n += 1;
    assert.match(h, /<body[^>]*>\s*<a class="skip-link" href="#main">Skip to content<\/a>/, f + ': the first thing in the body');
    assert.match(h, /<main id="main"[\s>]/, f);
  }
  assert.ok(n >= 20, 'all ' + n + ' pages');
  const css = read('styles.css');
  assert.match(css, /\.skip-link \{ position: absolute; left: -9999px; top: 0; \}/);
  assert.match(css, /\.skip-link:focus \{ left: 1rem;/);
});

test('item 23: the lanes are tabs: only the selected one is in the Tab order, and the arrow keys, Home and End move between them', () => {
  const html = read('feed.html');
  assert.match(html, /id="tab-people"[^>]*aria-selected="true"(?![^>]*tabindex="-1")/);
  assert.match(html, /id="tab-agents"[^>]*aria-selected="false" tabindex="-1"/);
  const js = read('feed.js');
  for (const k of ['ArrowRight', 'ArrowLeft', 'Home', 'End']) assert.ok(js.includes("e.key === '" + k + "'"), k);
  assert.match(js, /x\.setAttribute\('tabindex', x === b \? '0' : '-1'\)/);
});

test('item 24: the home page\'s stand-alone links are at least 24 px to tap', () => {
  assert.match(read('styles.css'), /\.nownext li > a, \.people h3 > a \{ display: inline-block; min-height: 24px; padding-block: 2px; \}/);
});
