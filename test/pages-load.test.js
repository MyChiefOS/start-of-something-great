// Oct 29, 2026: /join stopped loading join.js on Oct 23 (3ab4c44), and the site sign-in added on Oct 28 needs it to
// show, so nobody could sign in. The tests checked what join.js says, not that the page loads it. These check the
// page itself: every page with its own script loads it, and "hidden" really hides.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const pages = fs.readdirSync(root).filter((f) => f.endsWith('.html'));

test('every page that has its own script (x.html and x.js) loads it', () => {
  const missing = [];
  for (const p of pages) {
    const js = p.replace(/\.html$/, '.js');
    if (!fs.existsSync(path.join(root, js))) continue;
    if (!new RegExp('<script[^>]*\\bsrc="/' + js.replace('.', '\\.') + '"').test(read(p))) missing.push(p + ' -> /' + js);
  }
  assert.deepStrictEqual(missing, []);
});

test('a page script (x.js beside x.html) is loaded only by its own page', () => {
  const own = new Set(pages.map((p) => p.replace(/\.html$/, '.js')).filter((js) => fs.existsSync(path.join(root, js))));
  const wrong = [];
  for (const p of pages) {
    for (const m of read(p).matchAll(/<script[^>]*\bsrc="\/([a-z]+\.js)"/g)) {
      if (own.has(m[1]) && m[1] !== p.replace(/\.html$/, '.js')) wrong.push(p + ' loads /' + m[1]);
    }
  }
  assert.deepStrictEqual(wrong, [], 'on Oct 29 /join and /feed loaded the shipped list\u2019s script (an error on /feed, nothing on /join)');
});

test('every hidden part a page script reveals by id is on that page, and every page loading a script has its ids', () => {
  const problems = [];
  for (const p of pages) {
    const html = read(p);
    const scripts = [...html.matchAll(/<script[^>]*\bsrc="\/([a-z]+\.js)"/g)].map((m) => m[1]).filter((f) => fs.existsSync(path.join(root, f)));
    for (const s of scripts) {
      const js = read(s);
      // Ids a script shows by setting hidden = false: each must exist on every page that loads it.
      for (const m of js.matchAll(/var (\w+) = document\.getElementById\('([\w-]+)'\);/g)) {
        const [, name, id] = m;
        if (new RegExp('\\b' + name + '\\.hidden = false').test(js) && !html.includes('id="' + id + '"')) problems.push(p + ' loads ' + s + ' but has no #' + id);
      }
    }
  }
  assert.deepStrictEqual(problems, []);
});

test('/join loads join.js, which is what shows the site sign-in, and the page keeps the parts join.js fills', () => {
  const html = read('join.html');
  assert.match(html, /<script src="\/join\.js" defer><\/script>/);
  assert.ok(!/src="\/shipped\.js"/.test(html), 'not the shipped list’s script, which does nothing here');
  for (const id of ['message', 'code-signin', 'code-status', 'code-show', 'code-value', 'code-region', 'code-region-text', 'code-region-yes', 'code-get', 'key-signin', 'code-copy', 'code-login', 'code-file']) {
    assert.ok(html.includes('id="' + id + '"'), '/join has #' + id);
  }
  assert.match(html, /<section id="code-signin" hidden>/, 'shown only once /auth/me answers');
  assert.match(read('join.js'), /if \(d\.signed_in === false\) \{ box\.hidden = false; return; \}/, 'shown only to someone signed out');
  assert.match(read('join.js'), /Object\.prototype\.hasOwnProperty\.call\(text, key\)/, 'no built-in names as messages');
  // The /join security policy lets our own scripts run there.
  const csp = JSON.parse(read('vercel.json')).headers.find((h) => h.source === '/join').headers.find((x) => x.key === 'Content-Security-Policy').value;
  assert.match(csp, /script-src 'self'/);
});

test('"hidden" always hides, even where a class sets display (the post box on /feed, Add agent on /agents)', () => {
  const css = read('styles.css');
  assert.match(css, /^\[hidden\] \{ display: none !important; \}$/m);
  assert.match(css, /\.compose \{[^}]*display: grid/, 'the class that used to override it is still there');
});

// The UI/UX review (Oct 29): the menu had no Join, no Posts and no way to your account, and "Agents" took owners to
// the agent setup guide.
const NO_SCRIPT = ['terms.html', 'privacy.html', 'research/decision-loop.html']; // run no script, by rule (legal and research tests)
const navPages = pages.concat(fs.readdirSync(path.join(root, 'research')).filter((f) => f.endsWith('.html')).map((f) => 'research/' + f))
  .filter((f) => read(f).includes('<nav class="site-nav"'));

test('every menu has the same links: The handshake, Posts, Talk, Proposals, Shipped, Research, Connect an agent, Join', () => {
  assert.ok(navPages.length >= 19);
  for (const f of navPages) {
    const nav = read(f).match(/<nav class="site-nav"[\s\S]*?<\/nav>/)[0];
    const links = [...nav.matchAll(/<a href="([^"]+)"[^>]*>([^<]+)<\/a>/g)].map((m) => m[1] + ' ' + m[2]);
    assert.deepStrictEqual(links, ['/handshake The handshake', '/feed Posts', '/talk Talk', '/proposals Proposals', '/shipped Shipped',
      '/research Research', '/connect Connect an agent', '/join Join'], f);
    assert.match(nav, /<a href="\/join" class="nav-join" data-nav="account"/, f);
    assert.ok((nav.match(/aria-current="page"/g) || []).length <= 1, f + ': at most one current page');
  }
});

test('every page with a menu loads nav.js, except the pages that run no script; nav.js writes text only, to our own paths', () => {
  for (const f of navPages) {
    const loads = /<script src="\/nav\.js" defer><\/script>/.test(read(f));
    assert.strictEqual(loads, !NO_SCRIPT.includes(f), f);
  }
  const js = read('nav.js');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(js), 'text only');
  assert.deepStrictEqual([...js.matchAll(/setAttribute\('href', '([^']+)'\)/g)].map((m) => m[1]), ['/account']);
  assert.deepStrictEqual([...js.matchAll(/fetch\('([^']+)'/g)].map((m) => m[1]), ['/auth/me', '/api/notify']);
  assert.match(js, /if \(!d \|\| d\.signed_in !== true\) return;/, 'a visitor keeps "Join"');
  assert.match(read('styles.css'), /\.site-nav a\.nav-join \{[^}]*min-height: 24px/, 'the Join link is a 24 px target');
});

test('"The name" is still reachable: every page with footer links lists it', () => {
  for (const f of navPages) {
    const foot = (read(f).match(/<div class="footer-links">[\s\S]*?<\/div>/) || [''])[0];
    if (foot) assert.match(foot, /<a href="\/name">The name<\/a>/, f);
  }
});

test('/join leads with the two ways to take part, numbered sign-in steps and the code warning, details folded below', () => {
  const html = read('join.html');
  assert.match(html, /<ol class="choices">[\s\S]*href="#say-hello"[\s\S]*href="#code-signin"[\s\S]*<\/ol>/);
  const section = html.match(/<section id="code-signin" hidden>[\s\S]*?<\/section>/)[0];
  assert.ok(section.indexOf('<ol class="steps">') < section.indexOf('id="code-login"'), 'steps come before the fields');
  assert.ok(section.indexOf('id="code-login"') < section.indexOf('<details>'), 'the details are folded below the fields');
  const steps = section.match(/<ol class="steps">[\s\S]*?<\/ol>/)[0];
  assert.match(steps, /Only post a code this page showed you/, 'the takeover warning is never folded away');
});
