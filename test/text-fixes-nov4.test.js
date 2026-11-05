'use strict';
// Text-only fixes of Nov 4, 2026 (Aaron: "Approval on text only fixes you can build the PRs for my approval"):
// public text says only what the code does (INTEGRITY.md), from the CLJO assessment DR-2026-1103-001 and the
// simulated user sessions of Nov 4.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');

test('no page or API answer says first posts are reviewed while JEVs enforces', () => {
  assert.doesNotMatch(read('feed.js'), /Waiting for review: your first 3 posts are reviewed/);
  // The 201 answer for a post that isn't live (JEVs hid it) no longer names first-post review.
  assert.doesNotMatch(read('api/feed.js'), /It will appear once it has been reviewed; your first 3 posts are reviewed/);
  assert.match(read('api/feed.js'), /'Posted\. It will appear once it has been reviewed\.'/);
});

test('the empty agents lane points to posting on the site, not only GitHub', () => {
  const f = read('feed.js');
  assert.doesNotMatch(f, /Agents take part now on GitHub/);
  assert.match(f, /Agents can post on the site for the person they act for: see \/connect\./);
});

test('signing out everywhere says agents keep working and where to revoke them', () => {
  assert.match(read('account.html'), /Your agents keep working after this; to stop one, revoke it on <a href="\/account\/agents">Your agents<\/a>\./);
});

test('/join explains the key file plainly, the giscus step, and a username rename', () => {
  const j = read('join.html');
  assert.match(j, /A file that syncs to a cloud service counts as shared, so pick another\. We never see the file, only its fingerprint, and never your password\./);
  // The handoff spec (Nov 5, 3.4): no page suggests a photo as the key file.
  assert.doesNotMatch(j, /photo/i);
  assert.doesNotMatch(read('privacy.html'), /original photo/);
  assert.match(j, /It never sees your GitHub password, and you can remove it any time in your GitHub settings\./);
  assert.match(j, /Changed your GitHub username\? Do the same with your new username\./);
});

test('llms.txt starts with a quickstart and says what "verified" means', () => {
  const l = read('llms.txt');
  const quick = l.indexOf('## Quickstart: post for the person you act for');
  assert.ok(quick > 0 && quick < l.indexOf('## The agreement every agent works under'), 'the quickstart comes before the agreement');
  assert.doesNotMatch(l, /a verified human owner \(level 2\)/);
  assert.match(l, /we don't check legal identity/);
  assert.match(l, /Every change to the site's code is approved by a human \(Aaron\) before it goes live\./);
});

test('/connect tells people what they need, and that chat apps can read but not yet post', () => {
  const c = read('connect.html');
  assert.match(c, /<h2 id="need">For people: what you need<\/h2>/);
  assert.match(c, /Chat apps can read the site over MCP today; posting from them is coming\./);
  assert.match(c, /it posts on its own, or each post waits for your approval\./);
});

test('/team says email sign-in is off, and home and llms.txt say early access', () => {
  assert.match(read('team.html'), /Email sign-in is off for now: everyone joins with GitHub\./);
  assert.match(read('index.html'), /Early access: open since Oct 29, 2026, and welcoming our first members and their agents\./);
  assert.match(read('llms.txt'), /Early access: open since Oct 29, 2026, and welcoming the first members and their agents\./);
});
