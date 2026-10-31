// UX PR F (the UI/UX review of Oct 31, finding 13): /member?id=, a member's public page, built only on public answers
// (the profile, and their live posts by author, 035). The browser check is scripts/check-ux-e.js (/member).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('/member: a public page made of public answers only, shown as text, never indexed by search engines', () => {
  const html = read('member.html');
  assert.match(html, /<meta name="robots" content="noindex">/);
  assert.match(html, /<script defer src="\/member\.js"><\/script>/);
  assert.match(html, /<p id="summary" class="dek" role="status">/);
  const js = read('member.js');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(js), 'text only');
  // Only the three public reads: the profile, and each lane by author.
  assert.deepStrictEqual([...js.matchAll(/'(\/api\/[^']+)'/g)].map((m) => m[1]), ['/api/feed?lane=', '/api/feed?profile=']);
  assert.match(js, /'\/api\/feed\?lane=' \+ name \+ '&author=' \+ id \+ '&limit=10'/);
  assert.match(js, /if \(!\/\^\[0-9a-f\]\{8\}-\[0-9a-f\]\{4\}-\[0-9a-f\]\{4\}-\[0-9a-f\]\{4\}-\[0-9a-f\]\{12\}\$\/\.test\(id\)\)/, 'a malformed id asks nothing');
  // What it shows is what the profile answer already gives anyone (api/feed.js).
  assert.match(read('api/feed.js'), /profile: \{ id: p\.id, name: maskContacts\(p\.name\), level: p\.level, joined: p\.joined, live_posts: p\.livePosts \}/);
  assert.match(js, /var LEVEL = \['Email only', 'GitHub member', 'Verified'\];/);
  // "Members' pages show only what is already public ... with email addresses and phone numbers hidden."
  assert.match(html, /Members' pages show only what is already public: the name they chose, their level, when they joined and their live posts, with email addresses and phone numbers hidden\./);
  assert.match(read('api/feed.js'), /name: maskContacts\(p\.author\.name\)/);
});

test('/member: names on /feed and the person on a receipt open their page', () => {
  assert.match(read('feed.js'), /whoLink\.href = '\/member\?id=' \+ encodeURIComponent\(p\.author\.id\);/);
  assert.match(read('receipt.js'), /owner\.href = '\/member\?id=' \+ encodeURIComponent\(r\.owner\.id\);/);
  assert.match(read('api/feed.js'), /owner: \{ id: r\.owner\.id, name: maskContacts\(r\.owner\.name\)/);
  // Clean addresses and the default security policy cover /member (vercel.json).
  const v = JSON.parse(read('vercel.json'));
  assert.strictEqual(v.cleanUrls, true);
});
