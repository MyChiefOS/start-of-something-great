// L1 and L2 (RELEASE-CHECKLIST.md): the terms of service and privacy policy are published, linked from where people
// sign up, and say what Release 2 actually does.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('L1: /terms and /privacy exist, are listed in the sitemap and linked from the join page and the home page', () => {
  for (const p of ['terms', 'privacy']) {
    const html = read(p + '.html');
    assert.match(html, new RegExp('<link rel="canonical" href="https://dayonegreat.com/' + p + '">'));
    assert.match(html, /Effective [A-Z][a-z]+ \d{1,2}, 20\d\d/, p + ' carries its effective date');
    assert.ok(!/<script(?![^>]*src="\/_vercel\/insights\/script\.js")/.test(html), p + ' runs no script of its own');
    assert.match(read('sitemap.xml'), new RegExp('https://dayonegreat.com/' + p + '<'));
    assert.match(read('join.html'), new RegExp('href="/' + p + '"'));
    assert.match(read('index.html'), new RegExp('href="/' + p + '"'));
  }
  assert.match(read('join.html'), /By continuing you agree to our <a href="\/terms">terms<\/a>/);
  assert.ok(!/these buttons don't work yet/.test(read('join.html')), 'the join page no longer says sign-in is off');
});

test('L2: the policies state the standing decisions as built', () => {
  const t = read('terms.html'); const p = read('privacy.html');
  assert.match(t, /at least 18/);
  assert.match(t, /European Economic Area, the United Kingdom or Switzerland are declined at sign-up/);
  assert.match(t, /The owner is responsible for everything their agents and sub-agents do/);
  assert.match(t, /The MCP server is read-only; agents post through the API/);
  assert.match(t, /Decisions that significantly affect your account are made or reviewed by a person/);
  assert.match(p, /no member email addresses/);
  assert.match(p, /deletion opens 24 hours after you add your first passkey/);
  assert.match(p, /__Host-dog_session/);
  assert.match(p, /Supabase/);
  const main = (h) => h.slice(h.indexOf('<main'), h.indexOf('</main>'));
  assert.ok(!/LinkedIn/.test(main(t) + main(p)), 'LinkedIn sign-in was dropped on Oct 16 (the footer link to Aaron\'s profile is not sign-in)');
});
