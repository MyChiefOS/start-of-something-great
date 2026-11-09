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
  for (const id of ['message', 'code-signin', 'code-status', 'code-show', 'code-value', 'code-region', 'code-region-text', 'code-region-yes', 'code-get', 'code-copy', 'code-login', 'code-file',
    'path-new', 'path-back', 'signin-fields', 'code-new', 'code-again', 'hello-head', 'code-wait', 'code-time']) {
    assert.ok(html.includes('id="' + id + '"'), '/join has #' + id);
  }
  // 037: lane 3's PIN, lane 2 and lane 1's "Set your PIN" step are on /join/pin, which loads pin.js (the review's M1).
  const pin = read('join/pin.html');
  assert.match(pin, /<script src="\/pin\.js" defer><\/script>/);
  for (const id of ['pin-signin-card', 'pin-lane', 'pin-now', 'pin-signin', 'pin-other', 'paths', 'file-lane', 'code-login', 'code-file', 'key-pin', 'key-pin-again', 'key-signin',
    'pin-set', 'pin-new', 'pin-again', 'pin-remove-others', 'pin-save', 'code-region', 'code-status']) {
    assert.ok(pin.includes('id="' + id + '"'), '/join/pin has #' + id);
  }
  // The design's card (static/join.html "Sign in to the site"), shown only once /auth/me answers.
  assert.match(html, /<div class="card [^"]*" id="code-signin" role="region" aria-labelledby="signin-title" hidden><h2 class="h3" id="signin-title">Sign in to the site<\/h2>/);
  assert.match(read('join.js'), /if \(d\.signed_in === false\) \{[\s\S]*?box\.hidden = false;/, 'shown only to someone signed out');
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
// The pages in folders that scripts/shell.js covers (shell.pages()): the research papers and, since the design handoff
// of Nov 5, 2026, the admin, account, agents, errors and privacy pages.
const inDir = (d) => (fs.existsSync(path.join(root, d)) ? fs.readdirSync(path.join(root, d)).filter((f) => f.endsWith('.html')).map((f) => d + '/' + f) : []);
const navPages = pages.concat(...['research', 'admin', 'account', 'agents', 'errors', 'privacy', 'join'].map(inDir))
  .filter((f) => read(f).includes('<!-- shell:top -->'));
// The shell as scripts/shell.js writes it: between its markers.
const topOf = (f) => read(f).match(/<!-- shell:top -->([\s\S]*?)<!-- \/shell:top -->/)[1];
const footOf = (f) => read(f).match(/<!-- shell:foot -->([\s\S]*?)<!-- \/shell:foot -->/)[1];

test('every page, the 404 included, carries the shell exactly as scripts/shell.js writes it (any drift fails)', () => {
  assert.deepStrictEqual(navPages.slice().sort(), shell.pages(), 'every page has the menu');
  for (const f of shell.pages()) assert.strictEqual(shell.render(f, read(f)), read(f), f + ' differs from the shell: run node scripts/shell.js');
  const r = spawnSync(process.execPath, [path.join(root, 'scripts', 'shell.js'), '--check'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  // Only the current-page marks differ: with them taken out, every header is the same, and every footer is identical.
  // The design handoff (Nov 5): the about and trust pages add their own row under the header; the rest is one header.
  const headers = new Set(shell.pages().map((f) => topOf(f).replace(/ aria-current="(page|true)"/g, '').replace(/class="on"/g, 'class=""')
    .replace(/\n<div class="sub2" aria-label="(About|Trust)">[\s\S]*?<\/div>/, '')));
  assert.strictEqual(headers.size, 1, 'one header');
  const footers = new Set(shell.pages().map((f) => footOf(f)));
  assert.strictEqual(footers.size, 1, 'one footer');
});

test('the menu (the design handoff of Nov 5, 2026, README "Shell"): Post, Talk, Proposals, For agents, About, Search, then Join as a pill', () => {
  const linksOf = (h) => [...h.matchAll(/<a [^>]*href="([^"]+)"[^>]*>(.*?)<\/a>/g)].map((m) => m[1] + ' ' + m[2].replace(/<[^>]+>/g, ''));
  const main = shell.MAIN.map(([h, t]) => h + ' ' + t);
  // The built modules in the design's order, the live ones first (042: a live page is never called proposed).
  const built = shell.PROPOSED.filter(([h]) => shell.exists(h));
  const proposed = built.filter(([h]) => shell.LIVE.includes(h)).concat(built.filter(([h]) => !shell.LIVE.includes(h))).map(([h, t]) => h + ' ' + t);
  for (const f of navPages) {
    const top = topOf(f);
    // The wide row: the six links, then Join as the pill (the design's .join).
    const wide = top.match(/<nav class="nav dnav" aria-label="Main">[\s\S]*?<\/nav>/)[0];
    assert.deepStrictEqual(linksOf(wide), [...main, '/join Join'], f);
    assert.match(wide, /<a href="\/join" class="join" data-nav="account">Join<\/a><\/nav>$/, f);
    // On phones: Menu, a <details> holding every link (all of them stay in the HTML), the Proposed group, then Join.
    const menu = top.match(/<details class="mnav"><summary>Menu<\/summary><div class="mpanel">[\s\S]*?<\/div><\/details>/);
    assert.ok(menu, f + ': the Menu');
    assert.deepStrictEqual(linksOf(menu[0]), [...main, ...proposed, '/join Join'], f);
    // Under the header, from 820 px: the modules row, with only the modules that are built: the live ones first, then
    // "Proposed" and the designs not live yet (042; the CLJO's review of Nov 6: a live page is never called proposed).
    const row = top.match(/<div class="sub2 dnav" aria-label="Modules">[\s\S]*?<\/div>/)[0];
    assert.deepStrictEqual(linksOf(row), proposed, f);
    const label = row.indexOf('>Proposed</span>');
    for (const h of ['/build', '/rooms', '/projects']) if (row.includes('href="' + h + '"')) assert.ok(label < 0 || row.indexOf('href="' + h + '"') < label, f + ': ' + h + ' before "Proposed"');
    assert.ok((top.match(/<nav class="nav dnav"[\s\S]*?<\/nav>/)[0].match(/aria-current=/g) || []).length <= 1, f + ': at most one current mark in the row');
  }
  assert.match(topOf('team.html'), /<a class="on" href="\/team" aria-current="page">About<\/a>/);
  // The about pages carry the About row: Team, The handshake, The name, Research.
  for (const f of ['team.html', 'handshake.html', 'name.html', 'research.html', 'research/decision-loop.html']) {
    const row = topOf(f).match(/<div class="sub2" aria-label="About">[\s\S]*?<\/div>/);
    assert.ok(row, f + ' has the About row');
    assert.deepStrictEqual([...row[0].matchAll(/href="([^"]+)"/g)].map((m) => m[1]), ['/team', '/handshake', '/name', '/research'], f);
  }
  assert.match(topOf('handshake.html'), /<a class="on" href="\/team" aria-current="true">About<\/a>[\s\S]*<a class="on" href="\/handshake" aria-current="page">The handshake<\/a>/);
  assert.match(topOf('shipped.html'), /<a class="on" href="\/proposals" aria-current="true">Proposals<\/a>/);
  // No link in the shell points at a page that isn't built.
  for (const f of shell.pages()) for (const m of (topOf(f) + footOf(f)).matchAll(/href="(\/[^"#?]*)/g)) assert.ok(shell.exists(m[1]), f + ' links ' + m[1]);
  assert.ok(!/<script/.test(read('scripts/shell.js').replace(/^\/\/.*$/gm, '')), 'the shell adds no script: script-src \'self\' and the no-script pages hold');
});

test('the menu\'s styles: one row, Join a 44 px amber pill on phones, Menu a 44 px target, the wide row only where the browser can show it', () => {
  const css = read('styles.css');
  assert.match(css, /\.site-nav a\.nav-join \{ display: inline-flex; align-items: center; min-height: 44px;[^}]*background: var\(--amber\);/);
  // The screen order is the HTML order, so the Tab order matches what a sighted keyboard user sees.
  const header = css.slice(css.indexOf('.site-header {'), css.indexOf('/* Hero'));
  assert.ok(!/\border\s*:/.test(header), 'no order: in the header\'s rules');
  // Light scheme: hover darkens the pill (amber mixed with the site's own dark text colour; 6.2:1 with white), where a
  // brighter pill fell to 4.4:1 (the design review). The dark scheme brightens (10.3:1 with its dark text).
  assert.match(css, /@media \(prefers-color-scheme: light\) \{ \.site-nav a\.nav-join, \.site-nav a\.nav-join:hover \{ color: #ffffff; \} \.site-nav a\.nav-join:hover \{ filter: none; background: color-mix\(in srgb, var\(--amber\) 85%, #15110a\); \} \}/);
  // Narrow phones, signed in: a tighter row, so Account (n) fits beside Menu at 320 and 360 px (scripts/check-shell.js
  // measures it). Signed out, Join keeps its pill shape and spacing: there is room.
  assert.match(css, /@media \(max-width: 24rem\) \{ \.site-top, \.site-nav:has\(\[href\^="\/account"\]\) \{ column-gap: 0\.25rem; \} \.site-nav a\.nav-join\[href\^="\/account"\] \{ padding: 0 0\.5rem; font-size: 0\.875rem; \} \.site-nav:has\(\[href\^="\/account"\]\) \.menu > summary \{ gap: 0\.25rem; padding: 0; \} \}/);
  assert.ok(css.indexOf('@media (max-width: 24rem) { .site-top') > css.indexOf('.menu > summary {'), 'after the rules it narrows');
  // From 820 px (the design): the links sit in the row, and the Proposed and section rows show under it.
  const wide = css.slice(css.indexOf('@supports selector(::details-content)'), css.indexOf('/* Hero'));
  assert.match(wide, /@media \(min-width: 51\.25rem\) \{\s*\.sub-row \{ display: flex; \}/);
  assert.ok(!/clip-path/.test(wide), 'not hidden from sight');
  assert.match(css, /\.menu > summary \{[^}]*min-height: 44px;/);
  assert.match(css, /\.menu > summary:focus-visible \{ outline: 2px solid var\(--amber\);/, 'Menu shows focus');
  // Without ::details-content (older browsers) Menu stays at every width, so no screen loses the links.
  assert.match(css, /@supports selector\(::details-content\) \{\s*@media \(min-width: 51\.25rem\) \{[\s\S]*?\.menu > summary, \.nav-group \{ display: none; \}[\s\S]*?\.menu::details-content \{ content-visibility: visible; \}/);
  // The logo, the colour tokens and the fonts are as they were (Aaron's limits for the review).
  assert.match(css, /\.wordmark \{\n  font-family: var\(--display\);\n  font-weight: 700;\n  font-size: 1\.05rem;\n  letter-spacing: -0\.01em;\n  text-decoration: none;\n  white-space: nowrap;\n\}/);
  // The one addition since: --rule-strong, a grey for form field borders at 3:1 (the design handoff of Nov 5,
  // CODING_AGENT_SPEC.md 5.1; test/design-standard.test.js). The brand colours themselves are unchanged.
  assert.match(css, /--ink: #0d0f14;\n  --text: #ece7dd;\n  --muted: #9a9ba5;\n  --rule: #23262e;\n(?:  \/\*[\s\S]*?\*\/\n)?  --rule-strong: #626160;\n  --amber: #f2a33a;\n  --glow: rgba\(242, 163, 58, 0\.18\);/);
  assert.match(css, /--ink: #f6f7f9;\n    --text: #15171c;\n    --muted: #5b5e68;\n    --rule: #dcdee4;\n    --rule-strong: #8c8e91;\n    --amber: #a65e00;\n    --glow: rgba\(242, 163, 58, 0\.22\);/);
  const colours = [...new Set((css + read('app.css')).match(/#[0-9a-fA-F]{3,6}\b/g))].sort();
  assert.deepStrictEqual(colours, ['#0d0f14', '#15110a', '#15171c', '#23262e', '#5b5e68', '#7d211c', '#9a9ba5', '#a3302a', '#a65e00', '#c2413b', '#dcdee4',
    '#e0574f', '#ece7dd', '#f1857f', '#f2a33a', '#f6f7f9', '#ffb0ab', '#ffffff', '#626160', '#8c8e91'].sort(), 'no new colours but --rule-strong\'s two');
});

test('every page with a menu loads nav.js, except the pages that run no script; nav.js writes text only, to our own paths', () => {
  for (const f of navPages) {
    const loads = /<script src="\/nav\.js" defer><\/script>/.test(read(f));
    assert.strictEqual(loads, !NO_SCRIPT.includes(f), f);
  }
  assert.ok(!/<script/.test(read('404.html')), 'the 404 runs no script');
  const js = read('nav.js');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(js), 'text only');
  assert.deepStrictEqual([...js.matchAll(/setAttribute\('href', '([^']+)'\)/g)].map((m) => m[1]), ['/account/agents', '/account#notices'], 'our own paths only: Your agents (the UI/UX review, item 7) and Account, at its notices');
  assert.match(read('account.html'), /<section id="notices" class="inbox"/, 'the notices anchor exists');
  assert.deepStrictEqual([...js.matchAll(/fetch\('([^']+)'/g)].map((m) => m[1]), ['/auth/me'], 'one request: /auth/me carries the count');
  assert.match(js, /if \(!state \|\| state\.signed_in !== true\) return;/, 'a visitor keeps "Join"');
});

test('the footer, the same on every page (the design\'s columns, each link only once its page is built): About, Take part, Trust, Agents, Legal and contact', () => {
  const foot = footOf('index.html');
  const groups = [...foot.matchAll(/<div><p class="kick">([^<]+)<\/p>\s*<div class="x[0-9a-f]{8}">([\s\S]*?)<\/div><\/div>/g)].map((m) => [m[1], [...m[2].matchAll(/<a href="([^"]+)">([^<]+)<\/a>/g)].map((x) => x[2] + ' ' + x[1])]);
  const repo = 'https://github.com/MyChiefOS/start-of-something-great';
  // The design's five columns, as drawn (README "Shell"), with the pages that aren't built left out.
  assert.deepStrictEqual(groups, [
    ['About', ['Team /team', 'The handshake /handshake', 'The name /name', 'Research /research', 'Aaron on LinkedIn https://www.linkedin.com/in/aaron-chandler-ai']],
    // Search and Sitemap: the handoff's spec (CODING_AGENT_SPEC.md 5.4: "Sitemap" and "Search" pages linked from the footer).
    // Build: the design's column has it; it is built (042).
    ['Take part', ['Join /join', 'Post /feed', 'Talk /talk', 'Proposals /proposals', 'Shipped /shipped', 'Build /build', 'Leaderboard /leaderboard', 'Loops /loops', 'Search /search']],
    ['Trust (proposed)', ['Status /status', 'Roadmap /roadmap', 'JEVs decisions /decisions', 'The checks /checks', 'Moderation /moderation', 'Receipts /receipts', 'Security /security']],
    ['Agents', ['For agents /connect', 'Agent directory /agents', 'Autonomy /autonomy', 'llms.txt /llms.txt', 'API /api', 'MCP /connect#add']],
    ['Legal and contact', ['Terms /terms', 'Privacy /privacy', 'Sitemap /sitemap', 'hello@dayonegreat.com mailto:hello@dayonegreat.com', 'feedback@dayonegreat.com mailto:feedback@dayonegreat.com',
      'GitHub Issues ' + repo + '/issues', 'security@dayonegreat.com mailto:security@dayonegreat.com', 'Code on GitHub ' + repo]]
  ]);
  assert.match(foot, /<p class="x[0-9a-f]{8}">Day One Great™ is a <a href="https:\/\/www\.chiefos\.cloud">ChiefOS, Inc\.<\/a> company\.<\/p><\/footer>/);
  assert.match(read('connect.html'), /<h2 id="add">1\. Add the server<\/h2>/, 'MCP lands on how to add the server');
});

test('the page map (UX PR B): /talk says it is on GitHub and points to Posts; /proposals reaches Shipped at the top; /team is the About hub', () => {
  const talk = read('talk.html').match(/<main[\s\S]*?<\/main>/)[0];
  assert.match(talk, /<h1>Talk on GitHub<\/h1>\s*<p class="dek">The open conversation, held on GitHub\./);
  assert.match(talk, /To post on this site itself, go to <a href="\/feed">Posts<\/a>, where people and the AI agents that act for them post in separate lanes\./);
  assert.match(read('feed.html'), /People and the AI agents that act for them post in separate lanes/, 'the same words /feed uses');
  assert.ok(talk.indexOf('href="/feed"') < talk.indexOf('giscus.app/client.js'), 'above the thread');
  // The design handoff of Nov 5, 2026 draws these as its pill buttons (design.css .btn).
  const proposals = read('proposals.html').match(/<main[\s\S]*?<\/main>/)[0];
  assert.ok(proposals.indexOf('<a class="btn" href="/shipped">See what shipped</a>') > 0 && proposals.indexOf('href="/shipped"') < proposals.indexOf('<h2'), 'Shipped linked above the first heading');
  assert.match(read('shipped.html'), /<a class="btn" href="\/proposals">See all proposals<\/a>/, 'and back');
  const team = read('team.html').match(/<main[\s\S]*?<\/main>/)[0];
  assert.match(team, /<p class="kick">About Day One Great<\/p><h1>The team<\/h1>/);
  const hub = team.match(/<ul class="rule3 x[0-9a-f]{8}">[\s\S]*?<\/ul>/)[0];
  assert.deepStrictEqual([...hub.matchAll(/<a href="([^"]+)">/g)].map((m) => m[1]), ['/handshake', '/name', '/research']);
  assert.ok(team.indexOf(hub) < team.indexOf('class="mem"'), 'at the top, before the team');
});

test('every comment in the style sheets is closed before the next one opens (app.css\'s first one ran on; the design review)', () => {
  for (const f of ['styles.css', 'app.css', 'team.css', 'home.css', 'talk.css', 'proposals.css', 'search.css']) {
    const css = read(f);
    let at = 0;
    for (;;) {
      const open = css.indexOf('/*', at);
      if (open < 0) break;
      const close = css.indexOf('*/', open + 2);
      assert.ok(close > 0, f + ': a comment at ' + open + ' never closes');
      const next = css.indexOf('/*', open + 2);
      assert.ok(next < 0 || close < next, f + ': the comment at ' + open + ' runs into the next one');
      at = close + 2;
    }
  }
});

test('app.css, the app pages’ own styles, is loaded straight after design.css by exactly the signed-in app pages (SF2)', () => {
  // The design handoff of Nov 5: the forms and lists these pages' scripts draw keep their app.css styles; every other
  // page is the design's markup and design.css alone.
  // The administrator's pages (041) are the design's markup, with the shared approval screen's sheet and their own.
  const APP = ['account.html', 'account/agents.html'];
  for (const f of navPages) {
    const html = read(f);
    assert.strictEqual(html.includes('<link rel="stylesheet" href="/app.css">'), APP.includes(f), f);
    if (APP.includes(f)) assert.match(html, /<link rel="stylesheet" href="\/design\.css">\n  <link rel="stylesheet" href="\/app\.css">/, f);
  }
  const css = read('styles.css');
  for (const sel of ['.lanes {', '.compose {', '.report-form {', '.review-actions {', '.brake-form {', '.account-form {', '.rules-form {', '.facts {']) {
    assert.ok(read('app.css').includes(sel) && !css.includes(sel), sel + ' lives in app.css only');
  }
  assert.ok(!/--[a-z]+\s*:/.test(read('app.css')), 'no new tokens');
});

test('/join leads with one compact sign-in panel, the comment box under the code, and the long reading below (UX PR A; since 037 in the design\'s own markup)', () => {
  const html = read('join.html');
  const main = html.match(/<main[\s\S]*?<\/main>/)[0];
  // Near the top: the second way in (Say hello) is one link away, and the terms are agreed before anything else.
  assert.ok(main.indexOf('href="#say-hello"') < main.indexOf('id="code-signin"'), 'Say hello with GitHub is linked above the panel');
  assert.match(main, /<a href="#say-hello"><strong>Say hello with GitHub<\/strong><\/a>/);
  const start = main.indexOf('id="code-signin"'), hello = main.indexOf('id="say-hello"');
  const panel = main.slice(start, hello);
  // 1. The choice of lane, as the design's two tabs (buttons, not form fields); "I have a key file" opens /join/pin.
  assert.match(panel, /<div class="tabs [^"]*" id="paths" role="group" aria-label="Which is you\?"><button class="" type="button" id="path-new" aria-pressed="false"[^>]*>First time here, or a new key file<\/button><button class="" type="button" id="path-back" aria-pressed="false">I have a key file<\/button><\/div>/);
  // 2 and 3. The fields, each with its label above it and a one-line help.
  const fields = panel.slice(panel.indexOf('<div id="signin-fields" hidden>'), panel.indexOf('id="code-region"'));
  // Once a code shows, the fields fold to one line: the username and "Change" (the design review of PR A, fix 1).
  assert.match(fields, /^<div id="signin-fields" hidden><p id="signin-as" class="fine" hidden><span id="signin-as-text"><\/span> <button class="btn s" type="button" id="code-change">Change<\/button><\/p>\s*<div id="field-set">/);
  assert.ok(fields.indexOf('<label for="code-login">') < fields.indexOf('id="code-login"'), 'the username label comes first');
  assert.match(fields, /<input id="code-login" name="login" type="text"[^>]*aria-describedby="code-login-help">/);
  assert.match(fields, /id="code-login-help" class="fine[^"]*">As in github\.com\/your-username, not your name or email\./, 'the name-or-email help stays');
  assert.match(fields, /<input id="code-file" name="file" type="file" aria-describedby="code-file-help">/);
  assert.doesNotMatch(fields, /accept=/, 'any type of file');
  assert.match(fields, /<button class="btn p" type="button" id="code-get" hidden>Get a sign-in code<\/button>/, 'one primary button');
  // 4. The code, large, with Copy, the time left out of the live region and the takeover warning beside it.
  const step = panel.slice(panel.indexOf('<div id="code-show" hidden>'), panel.indexOf('<details id="signin-about">'));
  assert.match(step, /<code id="code-value" class="x[0-9a-f]{8}"><\/code><button class="btn s" type="button" id="code-copy">Copy<\/button><span class="fine">Works once, for 10 minutes<\/span> <span id="code-time" class="fine" aria-hidden="true"><\/span>/);
  assert.match(step, /Only post a code this page showed you, and never quote or repeat anyone else’s: anyone who asks you to is trying to take over an account\./, 'the takeover warning sits beside the code, never folded away');
  assert.match(panel, /<div class="acts [^"]*" id="code-again" hidden><button class="btn p" type="button" id="code-new">Get a new code<\/button><\/div>/);
  // 4b. Once claimed: "Set your PIN", on /join/pin (pin.js).
  assert.match(read('join/pin.html'), /<h3 id="pin-set-title" tabindex="-1"[^>]*>Set your PIN<\/h3>/);
  // 5. The waiting line: states in the live region, seconds beside it where screen readers don't go.
  assert.match(panel, /<p class="fine"><span id="code-status" role="status" aria-live="polite"><\/span> <span id="code-wait" aria-hidden="true"><\/span><\/p>/);
  // The comment box comes straight after the panel, and the long reading after the box.
  assert.match(main.slice(hello - 40), /<div class="card [^"]*" id="say-hello" role="region" aria-labelledby="hello-title"[^>]*><div id="hello-head">/);
  for (const h of ['What we keep', 'AI agents', 'Where we are open']) {
    assert.ok(html.indexOf('<h2>' + h + '</h2>') > html.indexOf('giscus.app/client.js'), h + ' comes below the comment box');
  }
  // The design's styles only (design.css), at least 44 px for every control under 820 px; no page-only stylesheet.
  assert.match(html, /<link rel="stylesheet" href="\/design\.css">/);
  assert.ok(!/href="\/(styles|join)\.css"/.test(html), '/join loads only the design\'s stylesheet');
  assert.ok(!fs.existsSync(path.join(root, 'join.css')), 'join.css is gone with the page it styled');
  assert.match(read('design.css'), /@media\(max-width:820px\)\{\.d1 \.dnav\{[^\n]*\.d1 \.btn,\.d1 button\{min-height:44px\}/);
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
  const inside = { inMenu: true };
  const menu = { open: true, keys: [], addEventListener(ev, fn) { this.keys.push([ev, fn]); }, querySelector: (q) => (q === 'summary' ? summary : null),
    contains: (el) => el === inside };
  const docEvents = [];
  const ctx = {
    // The design's header (scripts/shell.js): the pill in the wide row and in the Menu, For agents in both.
    document: { querySelector: (q) => (q === '.hd a[data-nav="agents"]' ? (added[0] || null) : q === '.hd details.mnav' ? menu : null),
      querySelectorAll: (q) => (q === '.hd a[data-nav="account"]' ? [link] : q === '.hd .dnav a[href="/connect"], .hd .mpanel a[href="/connect"]' ? [guide, guide]
        : q === 'form[action^="/auth/logout"]' ? forms : []),
      addEventListener: (ev, fn) => docEvents.push([ev, fn]),
      createElement: () => ({ attrs: {}, textContent: '', setAttribute(k, v) { this.attrs[k] = String(v); } }) },
    location: { pathname: where },
    sessionStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) },
    fetch: (u) => { calls.push(u); return Promise.resolve({ ok: true, json: () => Promise.resolve(me) }); },
    JSON, Number, Date: { now: () => now }
  };
  ctx.window = ctx;
  vm.runInNewContext(read('nav.js'), ctx);
  return new Promise((r) => setImmediate(() => setImmediate(() => r({ link, calls, store, forms, added, menu, summary, docEvents, inside }))));
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
  assert.deepStrictEqual(member.added.map((a) => [a.textContent, a.attrs.href, a.before]), [['Your agents', '/account/agents', 'the link after For agents'], ['Your agents', '/account/agents', 'the link after For agents']],
    'and Your agents, just after For agents, in the wide row and in the Menu');
  // Escape closes the open Menu and returns focus to it; other keys, or a closed Menu, change nothing.
  const [ev, onKey] = member.menu.keys[0];
  assert.strictEqual(ev, 'keydown');
  onKey({ key: 'Enter' });
  assert.strictEqual(member.menu.open, true);
  onKey({ key: 'Escape' });
  assert.strictEqual(member.menu.open, false);
  assert.strictEqual(member.summary.focused, true);
  // A tap or click outside the open Menu closes it; one inside it (a link, the About heading) leaves it open.
  const clicks = visitor.docEvents.filter(([ev]) => ev === 'click');
  assert.strictEqual(clicks.length, 1, 'one click listener, on the document');
  visitor.menu.open = true;
  clicks[0][1]({ target: visitor.inside });
  assert.strictEqual(visitor.menu.open, true, 'a tap inside keeps it open');
  clicks[0][1]({ target: { elsewhere: true } });
  assert.strictEqual(visitor.menu.open, false, 'a tap outside closes it');
  clicks[0][1]({ target: { elsewhere: true } });
  assert.strictEqual(visitor.menu.open, false, 'and a closed Menu stays closed');
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
  assert.match(read('join.html'), /<div class="card [^"]*" id="code-signin"[^>]*hidden>/);
  // resume(): a code this tab was waiting for before the comment box's GitHub round trip (test/join-page.test.js); then
  // (037) whether this browser keeps its sign-in key, for lane 3.
  assert.match(read('join.js'), /if \(d\.signed_in === false\) \{[\s\S]*?box\.hidden = false; restore\(\); resume\(\);/);
  // A browser that keeps its sign-in key goes to /join/pin first (lane 3), unless it chose another way.
  assert.match(read('join.js'), /location\.replace\('\/join\/pin' \+ location\.search\)/);
});
