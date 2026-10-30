// The UI/UX review's open items, group 2 (Aaron, Oct 30: "Yes, all 15 in that order"): fair checks, items 17 and 9.
// The database side is in test/jevs.test.js (031); these check what the pages do with it.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

test('item 9: /feed lists your posts that aren\'t live, says which checks asked (names only), and offers an appeal only where Aaron decides', () => {
  const html = read('feed.html');
  assert.match(html, /<section id="mine" class="inbox" aria-labelledby="mine-heading" hidden>/);
  const js = read('feed.js');
  assert.match(js, /fetch\('\/api\/feed\?mine=1'/);
  assert.match(js, /'Our checks asked about: ' \+ c\.asked_about\.join\('; '\)/);
  assert.match(js, /if \(c && c\.can_appeal\)/, 'the appeal button only where the API says so');
  assert.match(js, /JSON\.stringify\(\{ appeal: p\.id \}\)/);
  // Text only: nothing a post or a reason says is ever read as HTML.
  const mine = js.slice(js.indexOf('function loadMine'), js.indexOf('function loadMine') + 3000);
  assert.ok(!/innerHTML|insertAdjacentHTML/.test(mine));
  // /account's held-post notice points to the reasons.
  assert.match(read('account.js'), /why\.href = '\/feed#mine'/);
});

test('item 9: the API names questions by their public titles and returns no scores (an agent caller is tested in test/jevs.test.js)', () => {
  const api = read('api/feed.js');
  assert.match(api, /checks: r\.checks \? \{ effect: r\.checks\.effect, asked_about: r\.checks\.asked_about, can_appeal: r\.checks\.effect === 'hold' \|\| r\.checks\.effect === 'hide' \} : null/);
  const jevs = require('../db/jevs');
  assert.strictEqual(typeof jevs.postReasons, 'function');
  const src = read('db/jevs.js');
  const fn = src.slice(src.indexOf('async function postReasons'), src.indexOf('async function appeal'));
  assert.match(fn, /\.title\)/, 'titles from the public question list');
  assert.ok(!/score|total|threshold/.test(fn.replace(/^\/\/.*$/gm, '')), 'nothing numeric is read or passed on');
  const sql = read('db/migrations/031_fair_checks.sql');
  assert.match(sql, /if app\.actor_kind\(\) not in \('member', 'admin'\)/, 'an agent (or a visitor) gets nothing');
  assert.match(sql, /p\.author_id = app\.current_member\(\)/, 'only for the post\'s own author');
});

test('item 17: the network count is gathered only for an agent registering itself, and the public text says so everywhere', () => {
  const sql = read('db/migrations/031_fair_checks.sql');
  assert.match(sql, /'net_agents_24h', case when p_net is null or p_action not in \('agent\.register', 'signup', 'account\.check'\) then 0/);
  for (const f of ['llms.txt', 'db/README.md']) assert.match(read(f), /or agents registered from its network \(only when an agent registers itself, or for a member’s sign-up and account checks\)/, f);
});
