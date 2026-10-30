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
  assert.match(read('join.js'), /if \(d\.signed_in === false\) \{ box\.hidden = false;/, 'shown only to someone signed out');
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
  assert.deepStrictEqual([...js.matchAll(/setAttribute\('href', '([^']+)'\)/g)].map((m) => m[1]), ['/agents', '/account'], 'our own paths only: Your agents (the UI/UX review, item 7) and Account');
  assert.deepStrictEqual([...js.matchAll(/fetch\('([^']+)'/g)].map((m) => m[1]), ['/auth/me'], 'one request: /auth/me carries the count');
  assert.match(js, /if \(!state \|\| state\.signed_in !== true\) return;/, 'a visitor keeps "Join"');
  assert.match(read('styles.css'), /\.site-nav a\.nav-join \{[^}]*min-height: 24px/, 'the Join link is a 24 px target');
});

test('"The name" and GitHub are still reachable: every page with a menu has footer links to both', () => {
  for (const f of navPages) {
    const foot = (read(f).match(/<div class="footer-links">[\s\S]*?<\/div>/) || [''])[0];
    assert.match(foot, /<a href="\/name">The name<\/a>/, f + ' has footer links with The name');
    assert.match(foot, /<a href="https:\/\/github\.com\/MyChiefOS\/start-of-something-great">Code on GitHub<\/a>/, f + ' links the code');
  }
});

test('/join leads with the two ways to take part, numbered sign-in steps and the code warning, details folded below', () => {
  const html = read('join.html');
  assert.match(html, /<ol class="choices">[\s\S]*href="#code-signin"[\s\S]*href="#say-hello"[\s\S]*<\/ol>/, 'in the order the page shows them');
  const section = html.match(/<section id="code-signin" hidden>[\s\S]*?<\/section>/)[0];
  assert.ok(section.indexOf('<ol class="steps">') < section.indexOf('id="code-login"'), 'steps come before the fields');
  assert.ok(section.indexOf('id="code-login"') < section.indexOf('<details>'), 'the details are folded below the fields');
  const steps = section.match(/<ol class="steps">[\s\S]*?<\/ol>/)[0];
  assert.match(steps, /Only post a code this page showed you/, 'the takeover warning is never folded away');
});

// nav.js run for real, in a stand-in page: what a visitor and a member see, and that it asks once a minute at most.
const vm = require('vm');
function runNav({ path: where = '/feed', me, stored = null, now = 1e12 }) {
  const link = { text: 'Join', attrs: { href: '/join' }, set textContent(v) { this.text = v; }, get textContent() { return this.text; },
    setAttribute(k, v) { this.attrs[k] = String(v); }, removeAttribute(k) { delete this.attrs[k]; } };
  const store = new Map(stored ? [['dog-nav', JSON.stringify(stored)]] : []);
  const calls = [];
  const forms = [{ handlers: [], addEventListener(ev, fn) { this.handlers.push([ev, fn]); } }];
  // "Your agents" is added before Account once signed in (the UI/UX review, item 7).
  const added = [];
  link.parentNode = { insertBefore: (n) => added.push(n) };
  const ctx = {
    document: { querySelector: (q) => (q === '.site-nav a[data-nav="account"]' ? link : q === '.site-nav a[data-nav="agents"]' ? (added[0] || null) : null), querySelectorAll: () => forms,
      createElement: () => ({ attrs: {}, textContent: '', setAttribute(k, v) { this.attrs[k] = String(v); } }) },
    location: { pathname: where },
    sessionStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) },
    fetch: (u) => { calls.push(u); return Promise.resolve({ ok: true, json: () => Promise.resolve(me) }); },
    JSON, Number, Date: { now: () => now }
  };
  ctx.window = ctx;
  vm.runInNewContext(read('nav.js'), ctx);
  return new Promise((r) => setImmediate(() => setImmediate(() => r({ link, calls, store, forms, added }))));
}

test('nav.js, run: a visitor keeps Join; a member sees Account with the unread count; one request, then reused for a minute', async () => {
  const visitor = await runNav({ me: { signed_in: false } });
  assert.strictEqual(visitor.link.textContent, 'Join');
  assert.strictEqual(visitor.link.attrs.href, '/join');
  assert.deepStrictEqual(visitor.calls, ['/auth/me'], 'one request a page, not two');
  const member = await runNav({ me: { signed_in: true, member_id: 'x', display_name: 'Ada', unread: 3 } });
  assert.strictEqual(member.link.textContent, 'Account (3)');
  assert.strictEqual(member.link.attrs.href, '/account');
  assert.strictEqual(member.link.attrs['aria-label'], 'Account, 3 unread notices');
  assert.deepStrictEqual(member.added.map((a) => [a.textContent, a.attrs.href]), [['Your agents', '/agents']], 'and Your agents beside it');
  assert.deepStrictEqual(visitor.added, [], 'a visitor gets no Your agents');
  const kept = JSON.parse(member.store.get('dog-nav'));
  assert.deepStrictEqual(Object.keys(kept).sort(), ['at', 'signed_in', 'unread'], 'only the yes/no and the count are kept, never an ID or a name');
  assert.strictEqual((await runNav({ me: { signed_in: true, unread: 250 } })).link.textContent, 'Account (99+)');
  const reused = await runNav({ me: { signed_in: false }, stored: { at: 1e12 - 30000, signed_in: true, unread: 1 } });
  assert.deepStrictEqual(reused.calls, [], 'a minute-old answer is reused');
  assert.strictEqual(reused.link.textContent, 'Account (1)');
  assert.deepStrictEqual((await runNav({ me: { signed_in: false }, stored: { at: 1e12 - 61000, signed_in: true, unread: 1 } })).calls, ['/auth/me'], 'older is asked again');
  for (const p of ['/join', '/account']) {
    assert.deepStrictEqual((await runNav({ path: p, me: { signed_in: false }, stored: { at: 1e12 - 1000, signed_in: true, unread: 1 } })).calls, ['/auth/me'], p + ' always asks afresh');
  }
  // Only a signed-in answer is reused: a visitor who has just signed in sees Account at once (the browser check, Oct 29).
  const visitorThenMember = await runNav({ me: { signed_in: true, unread: 0 }, stored: { at: 1e12 - 1000, signed_in: false, unread: null } });
  assert.deepStrictEqual(visitorThenMember.calls, ['/auth/me']);
  assert.strictEqual(visitorThenMember.link.textContent, 'Account');
  assert.strictEqual((await runNav({ me: { signed_in: false } })).store.has('dog-nav'), false, 'a visitor\u2019s answer is not kept');
  // Signing out on /account forgets the kept answer.
  const out = await runNav({ path: '/account', me: { signed_in: true, unread: 0 } });
  assert.ok(out.store.has('dog-nav'));
  out.forms[0].handlers.find(([ev]) => ev === 'submit')[1]();
  assert.strictEqual(out.store.has('dog-nav'), false);
  const here = await runNav({ path: '/account', me: { signed_in: true, unread: 0 } });
  assert.strictEqual(here.link.textContent, 'Account');
  assert.strictEqual(here.link.attrs['aria-current'], 'page');
});

test('/auth/me tells a member how many notices are unread, as a count only', () => {
  const flow = read('signin/flow.js');
  assert.match(flow, /try \{ unread = await run\(session\.actorFor\(who\), \(t\) => notices\.unread\(t\)\); \} catch \{ unread = null; \}/);
  assert.match(flow, /trust_level: who\.trustLevel, unread \}/);
});

test('/join shows "Sign in to the site" as a choice only when the sign-in itself shows', () => {
  assert.match(read('join.html'), /<li id="choice-signin" hidden>/);
  // resume(): a code this tab was waiting for before the comment box's GitHub round trip (test/join-page.test.js).
  assert.match(read('join.js'), /if \(d\.signed_in === false\) \{ box\.hidden = false; if \(choice\) choice\.hidden = false; resume\(\); return; \}/);
});
