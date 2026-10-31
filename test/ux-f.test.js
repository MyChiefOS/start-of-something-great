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

test('/member, after its fresh review: a long name wraps, no total that counts the wrong posts, one request at a time, focus kept, the way back', () => {
  const js = read('member.js');
  assert.match(read('app.css'), /\.member h1 \{ overflow-wrap: anywhere; \}/);
  assert.ok(!/live_posts/.test(js), 'no total from the profile: it counts agents\' posts with theirs (003, app.profile)');
  assert.match(read('db/migrations/003_posts.sql'), /select m\.id, m\.display_name, m\.trust_level, m\.created_at,/);
  assert.match(js, /more\.disabled = true; \/\/ one request at a time/);
  assert.match(js, /if \(first\) \{ first\.tabIndex = -1; first\.focus\(\); \}/);
  assert.match(js, /p\.agent\.chain_label \|\| 'agent of ' \+ p\.author\.name/);
  assert.match(read('api/feed.js'), /chain_label: chainLabel\(chain, p\.author\.name\)/);
  assert.match(js, /none\('There\\u2019s no public page for this member\.'\)/, 'banned, held, deleted and unknown look the same');
  assert.match(js, /back\.href = '\/feed';/);
  const html = read('member.html');
  assert.match(html, /<noscript><p class="fine">This page needs JavaScript\. The same facts are in our API: <code>\/api\/feed\?profile=&lt;member ID&gt;<\/code>/);
  assert.match(html, /To report a post, use Report beside it on <a href="\/feed">Posts<\/a>\./);
});

test('/member for agents: llms.txt and /connect name the profile answer and the page, and a member who isn\'t active answers as an unknown ID', () => {
  assert.match(read('llms.txt'), /A member's public facts: GET https:\/\/dayonegreat\.com\/api\/feed\?profile=<member ID>/);
  assert.match(read('connect.html'), /A member's public facts are at <code>\/api\/feed\?profile=&lt;member ID&gt;<\/code>/);
  const api = read('api/feed.js');
  assert.match(api, /if \(!p\) return sendPublic\(res, 404, \{ error: 'No such member\.' \}\);/);
  assert.match(read('db/migrations/003_posts.sql'), /create function app\.profile\(p_member uuid\)/);
});
