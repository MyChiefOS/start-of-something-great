// Oct 29, 2026: /join stopped loading join.js on Oct 23 (3ab4c44), and the site sign-in added on Oct 28 needs it to
// show, so nobody could sign in. The tests checked what join.js says, not that the page loads it. These check the
// page itself: every page with its own script loads it, and "hidden" really hides.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

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
  for (const id of ['message', 'code-signin', 'code-status', 'code-show', 'code-value', 'code-region', 'code-region-text', 'code-region-yes', 'code-get', 'key-signin', 'code-copy', 'code-login', 'code-file',
    'path-new', 'path-back', 'signin-fields', 'code-new', 'code-again', 'back-help', 'hello-head', 'code-wait', 'code-time']) {
    assert.ok(html.includes('id="' + id + '"'), '/join has #' + id);
  }
  assert.match(html, /<section id="code-signin" class="join-panel" aria-labelledby="signin-title" hidden>/, 'shown only once /auth/me answers');
  assert.match(read('join.js'), /if \(d\.signed_in === false\) \{ box\.hidden = false;/, 'shown only to someone signed out');
  assert.match(read('join.js'), /Object\.prototype\.hasOwnProperty\.call\(text, key\)/, 'no built-in names as messages');
  // The /join security policy lets our own scripts run there.
  const csp = JSON.parse(read('vercel.json')).headers.find((h) => h.source === '/join').headers.find((x) => x.key === 'Content-Security-Policy').value;
  assert.match(csp, /script-src 'self'/);
});

test('"hidden" always hides, even where a class sets display (the post box on /feed, Add agent on /agents)', () => {
  const css = read('styles.css');
  assert.match(css, /^\[hidden\] \{ display: none !important; \}$/m);
  assert.match(read('app.css'), /\.compose \{[^}]*display: grid/, 'the class that used to override it is still there (in app.css since UX PR B)');
});

// The UI/UX review (Oct 29): the menu had no Join, no Posts and no way to your account. UX PR B (the UI/UX review of
// Oct 31, findings 3, 4 and 15; Aaron, Oct 31: "I'm fine will all of the change recommended"): one shell for every page,
// written from scripts/shell.js, with five main items, About, and Join as a pill; the same footer everywhere.
// The pages that run no script, by rule: the legal pages and the paper (legal and research tests), and the 404, which
// is served at any address, so it asks nothing of /auth/me. They show Join even to a member, and keep the Menu (a
// <details>, which needs no script).
const NO_SCRIPT = ['terms.html', 'privacy.html', 'research/decision-loop.html', '404.html'];
const shell = require('../scripts/shell');
const navPages = pages.concat(fs.readdirSync(path.join(root, 'research')).filter((f) => f.endsWith('.html')).map((f) => 'research/' + f))
  .filter((f) => read(f).includes('<nav class="site-nav"'));

test('every page, the 404 included, carries the shell exactly as scripts/shell.js writes it (any drift fails)', () => {
  assert.deepStrictEqual(navPages.slice().sort(), shell.pages(), 'every page has the menu');
  for (const f of shell.pages()) assert.strictEqual(shell.render(f, read(f)), read(f), f + ' differs from the shell: run node scripts/shell.js');
  const r = spawnSync(process.execPath, [path.join(root, 'scripts', 'shell.js'), '--check'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  // Only the current-page marks differ: with them taken out, every header is the same, and every footer is identical.
  const headers = new Set(shell.pages().map((f) => read(f).match(/<header class="site-header">[\s\S]*?<\/header>/)[0].replace(/ aria-current="(page|true)"/g, '')));
  assert.strictEqual(headers.size, 1, 'one header');
  const footers = new Set(shell.pages().map((f) => read(f).match(/<footer class="site-footer">[\s\S]*?<\/footer>/)[0]));
  assert.strictEqual(footers.size, 1, 'one footer');
});

test('the menu: Posts, Talk, Proposals, For agents, then About, then Join as a pill; the About group in the Menu panel', () => {
  for (const f of navPages) {
    const nav = read(f).match(/<nav class="site-nav"[\s\S]*?<\/nav>/)[0];
    const links = [...nav.matchAll(/<a href="([^"]+)"[^>]*>(.*?)<\/a>/g)].map((m) => m[1] + ' ' + m[2].replace(/<[^>]+>/g, ''));
    assert.deepStrictEqual(links, ['/feed Posts on this site', '/talk Talk on GitHub', '/proposals Proposals', '/connect For agents', '/team About',
      '/team Team', '/handshake The handshake', '/name The name', '/research Research', '/join Join'], f);
    // Labels say the difference: Posts are on this site, Talk is on GitHub (finding 3).
    assert.match(nav, /<a href="\/feed"[^>]*>Posts<span class="nav-sub"> on this site<\/span><\/a>/, f);
    assert.match(nav, /<a href="\/talk"[^>]*>Talk<span class="nav-sub"> on GitHub<\/span><\/a>/, f);
    // On phones: the wordmark, Join, then Menu, a <details> holding every other link (all of them stay in the HTML).
    assert.match(nav, /^<nav class="site-nav" aria-label="Main">\s*<details class="menu">\s*<summary>Menu<\/summary>\s*<div class="menu-panel">/, f);
    assert.match(nav, /<\/details>\s*<a href="\/join" class="nav-join" data-nav="account"( aria-current="page")?>Join<\/a>\s*<\/nav>$/, f);
    assert.match(nav, /<a href="\/team" class="nav-about"( aria-current="(page|true)")?>About<\/a>\s*<div class="nav-group" role="group" aria-label="About">/, f);
    // At most one current mark among the links shown on a wide screen, and one among those in the phone panel.
    const wide = nav.replace(/<div class="nav-group"[\s\S]*?<\/div>/, '');
    const phone = nav.replace(/<a href="\/team" class="nav-about"[^>]*>About<\/a>/, '');
    for (const part of [wide, phone]) assert.ok((part.match(/aria-current=/g) || []).length <= 1, f + ': at most one current mark');
  }
  assert.match(read('team.html'), /<a href="\/team" class="nav-about" aria-current="page">About<\/a>/);
  assert.match(read('handshake.html'), /class="nav-about" aria-current="true">About<\/a>[\s\S]*<a href="\/handshake" aria-current="page">The handshake<\/a>/);
  assert.match(read('shipped.html'), /<a href="\/proposals" aria-current="true">Proposals<\/a>/);
  assert.ok(!/<script/.test(read('scripts/shell.js').replace(/^\/\/.*$/gm, '')), 'the shell adds no script: script-src \'self\' and the no-script pages hold');
});

test('the menu\'s styles: one row, Join a 44 px amber pill on phones, Menu a 44 px target, the wide row only where the browser can show it', () => {
  const css = read('styles.css');
  assert.match(css, /\.site-nav a\.nav-join \{ order: -1; display: inline-flex; align-items: center; min-height: 44px;[^}]*background: var\(--amber\);/);
  assert.match(css, /\.menu > summary \{[^}]*min-height: 44px;/);
  assert.match(css, /\.menu > summary:focus-visible \{ outline: 2px solid var\(--amber\);/, 'Menu shows focus');
  // Without ::details-content (older browsers) Menu stays at every width, so no screen loses the links.
  assert.match(css, /@supports selector\(::details-content\) \{\s*@media \(min-width: 48rem\) \{[\s\S]*?\.menu > summary, \.nav-group \{ display: none; \}[\s\S]*?\.menu::details-content \{ content-visibility: visible; \}/);
  // The logo, the colour tokens and the fonts are as they were (Aaron's limits for the review).
  assert.match(css, /\.wordmark \{\n  font-family: var\(--display\);\n  font-weight: 700;\n  font-size: 1\.05rem;\n  letter-spacing: -0\.01em;\n  text-decoration: none;\n  white-space: nowrap;\n\}/);
  assert.match(css, /--ink: #0d0f14;\n  --text: #ece7dd;\n  --muted: #9a9ba5;\n  --rule: #23262e;\n  --amber: #f2a33a;\n  --glow: rgba\(242, 163, 58, 0\.18\);/);
  assert.match(css, /--ink: #f6f7f9;\n    --text: #15171c;\n    --muted: #5b5e68;\n    --rule: #dcdee4;\n    --amber: #a65e00;\n    --glow: rgba\(242, 163, 58, 0\.22\);/);
  const colours = [...new Set((css + read('app.css')).match(/#[0-9a-fA-F]{3,6}\b/g))].sort();
  assert.deepStrictEqual(colours, ['#0d0f14', '#15110a', '#15171c', '#23262e', '#5b5e68', '#7d211c', '#9a9ba5', '#a3302a', '#a65e00', '#c2413b', '#dcdee4',
    '#e0574f', '#ece7dd', '#f1857f', '#f2a33a', '#f6f7f9', '#ffb0ab', '#ffffff'], 'no new colours');
});

test('every page with a menu loads nav.js, except the pages that run no script; nav.js writes text only, to our own paths', () => {
  for (const f of navPages) {
    const loads = /<script src="\/nav\.js" defer><\/script>/.test(read(f));
    assert.strictEqual(loads, !NO_SCRIPT.includes(f), f);
  }
  assert.ok(!/<script/.test(read('404.html')), 'the 404 runs no script');
  const js = read('nav.js');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(js), 'text only');
  assert.deepStrictEqual([...js.matchAll(/setAttribute\('href', '([^']+)'\)/g)].map((m) => m[1]), ['/agents', '/account#notices'], 'our own paths only: Your agents (the UI/UX review, item 7) and Account, at its notices');
  assert.match(read('account.html'), /<section id="notices" class="inbox"/, 'the notices anchor exists');
  assert.deepStrictEqual([...js.matchAll(/fetch\('([^']+)'/g)].map((m) => m[1]), ['/auth/me'], 'one request: /auth/me carries the count');
  assert.match(js, /if \(!state \|\| state\.signed_in !== true\) return;/, 'a visitor keeps "Join"');
});

test('the footer, the same on every page: About, Take part, Agents, Legal and contact, with the addresses the pages already used', () => {
  const foot = read('index.html').match(/<footer class="site-footer">[\s\S]*?<\/footer>/)[0];
  const groups = [...foot.matchAll(/<div[^>]*><h2>([^<]+)<\/h2>([\s\S]*?)<\/div>/g)].map((m) => [m[1], [...m[2].matchAll(/<a href="([^"]+)">([^<]+)<\/a>/g)].map((x) => x[2] + ' ' + x[1])]);
  const repo = 'https://github.com/MyChiefOS/start-of-something-great';
  assert.deepStrictEqual(groups, [
    ['About', ['Team /team', 'The handshake /handshake', 'The name /name', 'Research /research']],
    ['Take part', ['Join /join', 'Posts /feed', 'Talk /talk', 'Proposals /proposals', 'Shipped /shipped']],
    ['Agents', ['For agents /connect', 'llms.txt /llms.txt', 'API /api', 'MCP /connect#add']],
    ['Legal and contact', ['Terms /terms', 'Privacy /privacy', 'hello@dayonegreat.com mailto:hello@dayonegreat.com', 'feedback@dayonegreat.com mailto:feedback@dayonegreat.com',
      'GitHub Issues ' + repo + '/issues', 'security@dayonegreat.com mailto:security@dayonegreat.com', 'Code on GitHub ' + repo]]
  ]);
  assert.match(foot, /<p>Day One Great™ is a <a href="https:\/\/www\.chiefos\.cloud">ChiefOS, Inc\.<\/a> company\.<\/p>/);
  assert.match(read('connect.html'), /<h2 id="add">1\. Add the server<\/h2>/, 'MCP lands on how to add the server');
});

test('the page map (UX PR B): /talk says it is on GitHub and points to Posts; /proposals reaches Shipped at the top; /team is the About hub', () => {
  const talk = read('talk.html').match(/<main[\s\S]*?<\/main>/)[0];
  assert.match(talk, /<h1>Talk on GitHub<\/h1>\s*<p class="dek">The open conversation, held on GitHub\./);
  assert.match(talk, /To post on this site itself, go to <a href="\/feed">Posts<\/a>, where people and the AI agents that act for them post in separate lanes\./);
  assert.match(read('feed.html'), /People and the AI agents that act for them post in separate lanes/, 'the same words /feed uses');
  assert.ok(talk.indexOf('href="/feed"') < talk.indexOf('class="post"'), 'above the thread');
  const proposals = read('proposals.html').match(/<main[\s\S]*?<\/main>/)[0];
  assert.ok(proposals.indexOf('<a class="button" href="/shipped">See what shipped</a>') > 0 && proposals.indexOf('href="/shipped"') < proposals.indexOf('<h2'), 'Shipped linked above the first heading');
  assert.match(read('shipped.html'), /<a class="button" href="\/proposals">See all proposals<\/a>/, 'and back');
  const team = read('team.html').match(/<main[\s\S]*?<\/main>/)[0];
  assert.match(team, /<p class="kicker">About Day One Great<\/p>\s*<h1>The team<\/h1>/);
  const hub = team.match(/<ul class="hub"[\s\S]*?<\/ul>/)[0];
  assert.deepStrictEqual([...hub.matchAll(/<a href="([^"]+)">/g)].map((m) => m[1]), ['/handshake', '/name', '/research']);
  assert.ok(team.indexOf('class="hub"') < team.indexOf('class="member"'), 'at the top, before the team');
});

test('app.css, the app pages’ own styles, is loaded straight after styles.css by exactly the pages whose <main> has class "feed" (SF2)', () => {
  for (const f of navPages) {
    const html = read(f);
    const app = /<main id="main" class="[^"]*\bfeed\b/.test(html);
    assert.strictEqual(html.includes('<link rel="stylesheet" href="/app.css">'), app, f);
    if (app) assert.match(html, /<link rel="stylesheet" href="\/styles\.css">\n  <link rel="stylesheet" href="\/app\.css">/, f);
  }
  const css = read('styles.css');
  for (const sel of ['.lanes {', '.compose {', '.report-form {', '.review-actions {', '.brake-form {', '.account-form {', '.rules-form {', '.facts {']) {
    assert.ok(read('app.css').includes(sel) && !css.includes(sel), sel + ' lives in app.css only');
  }
  assert.ok(!/--[a-z]+\s*:/.test(read('app.css')), 'no new tokens');
});

test('/join leads with one compact sign-in panel, the comment box under the code, and the long reading below (UX PR A)', () => {
  const html = read('join.html');
  const main = html.match(/<main[\s\S]*?<\/main>/)[0];
  // Near the top: the second way in (Say hello) is one link away, and the terms are agreed before anything else.
  assert.ok(main.indexOf('href="#say-hello"') < main.indexOf('id="code-signin"'), 'Say hello with GitHub is linked above the panel');
  assert.match(main, /<a href="#say-hello"><strong>Say hello with GitHub<\/strong><\/a>/);
  const panel = html.match(/<section id="code-signin"[\s\S]*?<\/section>/)[0];
  // 1. The choice of path, as two toggle buttons (not form fields).
  assert.match(panel, /<div class="paths" role="group" aria-label="Which is you\?">/);
  assert.match(panel, /<button type="button" id="path-new" class="path-choice" aria-pressed="false"[^>]*>First time here, or a new key file<\/button>/);
  assert.match(panel, /<button type="button" id="path-back" class="path-choice" aria-pressed="false"[^>]*>I have a key file<\/button>/);
  // 2 and 3. The fields, each with its label above it and a one-line help, styled (class "field").
  const fields = panel.match(/<div id="signin-fields" hidden>[\s\S]*?<\/details>\s*<\/div>\s*<\/div>/)[0];
  // Once a code shows, the fields fold to one line: the username and "Change" (the design review of PR A, fix 1).
  assert.match(fields, /^<div id="signin-fields" hidden>\s*<p id="signin-as" class="signin-as" hidden><span id="signin-as-text"><\/span> <button type="button" id="code-change" class="button">Change<\/button><\/p>\s*<div id="field-set">/);
  assert.ok(fields.indexOf('<label for="code-login">') < fields.indexOf('id="code-login"'), 'the username label comes first');
  assert.match(fields, /<input id="code-login" class="field"[^>]*aria-describedby="code-login-help">/);
  assert.match(fields, /id="code-login-help" class="help">As in github\.com\/your-username, not your name or email\./, 'the name-or-email help stays');
  assert.match(fields, /<input id="code-file" class="field" name="file" type="file" aria-describedby="code-file-help">/);
  assert.ok(fields.indexOf('id="code-file"') < fields.indexOf('<details>'), 'the key file details are folded below the field');
  for (const id of ['code-get', 'key-signin']) assert.match(fields, new RegExp('id="' + id + '" class="button primary"'), id + ' is a primary button');
  // 4. The code, large, with Copy styled as a button, the time left out of the live region and the takeover warning beside it.
  const step = panel.match(/<div id="code-show" class="code-step" hidden>[\s\S]*?<\/div>/)[0];
  assert.match(step, /<p class="code-row"><code id="code-value"><\/code> <button type="button" id="code-copy" class="button">Copy<\/button> <span id="code-time" aria-hidden="true"><\/span><\/p>/);
  assert.match(step, /<span id="code-time" aria-hidden="true"><\/span>/);
  assert.match(step, /Only post a code this page showed you, and never quote or repeat anyone else’s: anyone who asks you to is trying to take over an account\./, 'the takeover warning sits beside the code, never folded away');
  assert.match(step, /for 10 minutes/, 'the same 10 minutes the server gives (signin/flow.js CODE_MINUTES)');
  assert.match(panel, /<p class="act" id="code-again" hidden><button type="button" id="code-new" class="button primary">Get a new code<\/button><\/p>/);
  // 5. The waiting line: states in the live region, seconds beside it where screen readers don't go.
  assert.match(panel, /<p class="wait-line"><span id="code-status" role="status" aria-live="polite"><\/span> <span id="code-wait" aria-hidden="true"><\/span><\/p>/);
  // The comment box comes straight after the panel, and the long reading after the box.
  const after = html.slice(html.indexOf('</section>', html.indexOf('id="code-signin"')));
  assert.match(after, /^<\/section>\s*<section id="say-hello" class="hello" aria-labelledby="hello-title">\s*<div id="hello-head">/);
  for (const h of ['What we keep', 'AI agents', 'Where we are open']) {
    assert.ok(html.indexOf('<h2>' + h + '</h2>') > html.indexOf('giscus.app/client.js'), h + ' comes below the comment box');
  }
  // The panel's styles: at least 44 px for every control, colours only from the tokens.
  // In join.css, which only /join loads, so the shared styles.css stays within the page-weight budget (SF2).
  assert.match(html, /<link rel="stylesheet" href="\/styles\.css">\n  <link rel="stylesheet" href="\/join\.css">/);
  const css = read('join.css');
  assert.match(css, /\.path-choice, \.join-panel \.field \{ min-height: 44px;/);
  assert.match(css, /\.join-panel \.button, \.story \.join-panel summary \{ min-height: 44px; \}/);
  assert.deepStrictEqual([...new Set(css.match(/#[0-9a-fA-F]{3,6}\b/g))].sort(), ['#15110a', '#ffffff'], 'only the colours .button.primary already uses');
  assert.ok(!/--[a-z]+\s*:/.test(css), 'no new colour tokens: only the ones in styles.css');
  for (const f of fs.readdirSync(root).filter((x) => x.endsWith('.html') && x !== 'join.html')) assert.ok(!read(f).includes('/join.css'), f + ' does not load join.css');
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
  link.parentNode = { insertBefore: (n, ref) => added.push(Object.assign(n, { before: ref })) };
  // Your agents goes after For agents, in the Menu's panel (UX PR B), so a phone's row stays the wordmark, Account and Menu.
  const guide = { nextSibling: 'the link after For agents', parentNode: { insertBefore: (n, ref) => added.push(Object.assign(n, { before: ref })) } };
  // The Menu: Escape closes it and puts focus back on Menu.
  const summary = { focused: false, focus() { this.focused = true; } };
  const menu = { open: true, keys: [], addEventListener(ev, fn) { this.keys.push([ev, fn]); }, querySelector: (q) => (q === 'summary' ? summary : null) };
  const ctx = {
    document: { querySelector: (q) => (q === '.site-nav a[data-nav="account"]' ? link : q === '.site-nav a[data-nav="agents"]' ? (added[0] || null)
      : q === '.site-nav a[href="/connect"]' ? guide : q === '.site-header details' ? menu : null), querySelectorAll: () => forms,
      createElement: () => ({ attrs: {}, textContent: '', setAttribute(k, v) { this.attrs[k] = String(v); } }) },
    location: { pathname: where },
    sessionStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) },
    fetch: (u) => { calls.push(u); return Promise.resolve({ ok: true, json: () => Promise.resolve(me) }); },
    JSON, Number, Date: { now: () => now }
  };
  ctx.window = ctx;
  vm.runInNewContext(read('nav.js'), ctx);
  return new Promise((r) => setImmediate(() => setImmediate(() => r({ link, calls, store, forms, added, menu, summary }))));
}

test('nav.js, run: a visitor keeps Join; a member sees Account with the unread count; one request, then reused for a minute', async () => {
  const visitor = await runNav({ me: { signed_in: false } });
  assert.strictEqual(visitor.link.textContent, 'Join');
  assert.strictEqual(visitor.link.attrs.href, '/join');
  assert.deepStrictEqual(visitor.calls, ['/auth/me'], 'one request a page, not two');
  const member = await runNav({ me: { signed_in: true, member_id: 'x', display_name: 'Ada', unread: 3 } });
  assert.strictEqual(member.link.textContent, 'Account (3)');
  assert.strictEqual(member.link.attrs.href, '/account#notices', 'Account opens on the notices (finding 11)');
  assert.strictEqual(member.link.attrs['aria-label'], 'Account, 3 unread notices');
  assert.deepStrictEqual(member.added.map((a) => [a.textContent, a.attrs.href, a.before]), [['Your agents', '/agents', 'the link after For agents']], 'and Your agents, just after For agents');
  // Escape closes the open Menu and returns focus to it; other keys, or a closed Menu, change nothing.
  const [ev, onKey] = member.menu.keys[0];
  assert.strictEqual(ev, 'keydown');
  onKey({ key: 'Enter' });
  assert.strictEqual(member.menu.open, true);
  onKey({ key: 'Escape' });
  assert.strictEqual(member.menu.open, false);
  assert.strictEqual(member.summary.focused, true);
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

test('/join shows the sign-in panel only when the sign-in itself is on and the visitor is signed out', () => {
  assert.match(read('join.html'), /<section id="code-signin" class="join-panel"[^>]*hidden>/);
  // resume(): a code this tab was waiting for before the comment box's GitHub round trip (test/join-page.test.js).
  assert.match(read('join.js'), /if \(d\.signed_in === false\) \{ box\.hidden = false; restore\(\); resume\(\); return; \}/);
});
