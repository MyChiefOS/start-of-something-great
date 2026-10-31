// UX PR E (the UI/UX review of Oct 31, findings 7, 8, 9, 10, 11 and the page part of 14). Front-end only. Each line the
// pages now say about levels is pinned to the code that makes it true (INTEGRITY.md; DS-UXD-004). The behaviour in a
// browser is checked by scripts/check-ux-e.js (not part of this suite, which runs without a browser).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('finding 7: /feed announces a short line when posts load and the count only near the limit, never the whole list', () => {
  const html = read('feed.html');
  assert.match(html, /<span id="count" class="fine">0 \/ 5,000<\/span><span id="count-say" class="visually-hidden" role="status"><\/span>/);
  assert.match(html, /<p id="posts-say" class="visually-hidden" role="status"><\/p>\n\s*<div id="posts" role="tabpanel" aria-labelledby="tab-people">/);
  assert.ok(!/id="posts"[^>]*aria-live/.test(html) && !/id="count"[^>]*aria-live/.test(html), 'neither the list nor the count is a live region');
  const js = read('feed.js');
  assert.match(js, /var now = n >= 5000 \? 'limit' : n >= 4500 \? 'near' : '';/);
  assert.match(js, /if \(now !== near\) countSay\.textContent =/, 'said once when it changes, not on every key');
  assert.match(js, /' loaded' \+ \(next \? '; older posts below' : ''\)/);
  assert.match(read('app.css'), /\.visually-hidden \{ position: absolute; width: 1px; height: 1px;/);
});

test('finding 8: names show "GitHub member" or "Verified", never "GitHub or X" (X sign-in is off), with what the levels mean', () => {
  const js = read('feed.js');
  assert.match(js, /var LEVEL = \['Email only', 'GitHub member', 'Verified'\];/);
  for (const f of ['feed.js', 'feed.html', 'receipt.js', 'agents.js', 'agents.html', 'team.html', 'account.js']) assert.ok(!/GitHub or X/.test(read(f)), f);
  assert.match(read('feed.html'), /<a href="\/team#levels">What the levels mean<\/a>/);
  // Phase 1 signs in with GitHub only: code sign-in makes a GitHub identity at level 1 (023's code_sign_in).
  assert.match(read('db/migrations/023_code_signin.sql'), /app\.sign_in\('github', array\[c\.fingerprint\], 1::smallint, 1::smallint/);
});

test('finding 9 and /team#levels: the way to level 2, in words the code backs', () => {
  const team = read('team.html');
  assert.match(team, /<h2 id="levels">Account levels<\/h2>/);
  assert.match(team, /<strong>Verified<\/strong> \(level 2\): given by our automatic checks \(JEVs\) on their own; nobody promotes an account by hand, and there is no waiting period\./);
  const rule = read('db/migrations/032_guardrails.sql');
  // "when you sign up, each time you sign in and each time you post, until your account is verified"
  assert.match(team, /The checks ask their account questions when you sign up, each time you sign in and each time you post, until your account is verified\./);
  assert.match(rule, /elsif p_action in \('signup', 'account\.check'\) then/);
  assert.match(read('signin/flow.js'), /await jevs\.check\(t, \{ action: out\.isNew \? 'signup' : 'account\.check', \.\.\.f \}\);/);
  assert.ok((read('signin/flow.js').match(/await afterSignIn\(req, /g) || []).length >= 4, 'every sign-in path runs the check');
  assert.match(read('api/feed.js'), /if \(who\.trustLevel < 2 && who\.isAdmin !== true\) await jevs\.check\(t, \{ action: 'account\.check', \.\.\.f \}\);/);
  // "nobody promotes an account by hand"; "no waiting period": promoted in the same check.
  assert.match(read('db/migrations/010_jevs.sql'), /No trust level is promoted by hand/);
  assert.match(rule, /update app\.members x set jevs_level2_at = now\(\), trust_level = 2 where x\.id = judged;/);
  // "a new account's age counts, but alone it never stops it": J01 is left out of the pass test, and its highest score
  // (25) is under the medium line for one question (40) and, with the others at their pass mark, the total line (70).
  assert.match(team, /a new account's age counts, but alone it never stops it\./);
  assert.match(rule, /where e\.key <> 'J01'\) <= s_pass/);
  assert.match(read('db/jevs.js'), /return h < 1 \? 25 : h < 24 \? 15 : h < 168 \? 10 : 0;/);
  assert.match(read('db/migrations/010_jevs.sql'), /\('medium_any', '40'\), \('high_any', '80'\), \('medium_total', '70'\)/);
  // "A verified member can also own AI agents."
  assert.match(read('api/agents.js'), /can_own: who\.trustLevel >= 2 \|\| who\.isAdmin === true/);
  // /agents: the claim's way forward, and the link's 24 hours from registering (005).
  const agents = read('agents.js');
  assert.match(agents, /Our checks give it on their own, with no wait: they look again each time you sign in or post, so sign in again or write a post, then come back to this link\. It works for 24 hours from when your agent registered\./);
  assert.match(agents, /why\.href = '\/team#levels';/);
  assert.match(read('db/migrations/005_agents.sql'), /p_claim_hash, now\(\) \+ interval '24 hours'\) returning id into aid;/);
  // No notice is promised: a promotion sends none (032 writes the audit log only).
  assert.ok(!/notice/i.test(agents.split("if (!x.d.can_own) {")[1].split('}')[0]), 'no notice promised');
});

test('finding 10: one welcome on /feed after a sign-in with a code that lands there; only a yes is kept, and it is cleared once shown', () => {
  const join = read('join.js');
  assert.match(join, /if \(d\.go === '\/feed'\) welcome\(\);/);
  assert.match(join, /function welcome\(\) \{ try \{ sessionStorage\.setItem\('dog-welcome', '1'\); \}/);
  assert.strictEqual((join.match(/welcome\(\)/g) || []).length, 2, 'set in one place (the code path), defined once');
  const feed = read('feed.js');
  assert.match(feed, /flag = sessionStorage\.getItem\('dog-welcome'\); sessionStorage\.removeItem\('dog-welcome'\);/);
  const html = read('feed.html');
  assert.match(html, /<section id="welcome" class="inbox" aria-labelledby="welcome-heading" hidden>/);
  assert.deepStrictEqual([...html.split('id="welcome"')[1].split('</section>')[0].matchAll(/href="([^"]+)"/g)].map((m) => m[1]), ['/account#name', '#body', '/connect', '/team#levels']);
  assert.match(read('signin/flow.js'), /const NEW_NAME = 'New member';/, '"Everyone starts as New member"');
  assert.match(read('account.html'), /id="name" type="text"/);
});

test('finding 11: /account puts Notices first, and #notices and #name are brought into view once the page shows', () => {
  const html = read('account.html');
  const details = html.split('<section id="details" hidden>')[1].split('</main>')[0];
  assert.deepStrictEqual([...details.matchAll(/<h2[^>]*>([^<]+)<\/h2>/g)].map((m) => m[1]),
    ['Notices', 'Shortcuts', 'Your name', 'How you sign in', 'Signing out', 'Delete your account']);
  const js = read('account.js');
  assert.match(js, /document\.getElementById\('details'\)\.hidden = false;\n\s*goToHash\(\);/);
  assert.match(js, /if \(!\/\^\[a-z-\]\+\$\/\.test\(id\)\) return;/, 'only plain ids are looked up');
  assert.match(js, /target\.closest\('#details'\) === null/);
  assert.match(read('nav.js'), /link\.setAttribute\('href', '\/account#notices'\);/);
});

test('finding 14 (page part): /feed names its JSON for agents, and says where the posts are without JavaScript', () => {
  const html = read('feed.html');
  assert.match(html, /<link rel="alternate" type="application\/json" href="\/api\/feed\?lane=people" title="People's posts \(JSON\)">/);
  assert.match(html, /<link rel="alternate" type="application\/json" href="\/api\/feed\?lane=agents" title="Agents' posts \(JSON\)">/);
  assert.match(html, /<noscript><p class="fine">This page needs JavaScript to show posts\. The same posts are at <a href="\/api\/feed\?lane=people">/);
  assert.match(read('api/feed.js'), /lane/);
});
