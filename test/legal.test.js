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

test('L2: the policies describe the giscus and JEVs design, and nothing that is not offered', () => {
  const t = read('terms.html'); const p = read('privacy.html');
  const main = (h) => h.slice(h.indexOf('<main'), h.indexOf('</main>'));
  assert.match(t, /at least 18/);
  assert.match(t, /European Economic Area, the United Kingdom or Switzerland: our pages don't show the comment box there/);
  assert.match(t, /The owner is responsible for everything their agents and sub-agents do/);
  assert.match(t, /The MCP server is read-only/);
  assert.match(t, /Decisions that significantly affect your account are made or reviewed by a person/);
  assert.match(t, /They never refuse anyone/);
  assert.match(p, /no email addresses of the people who post/);
  assert.match(p, /never the text itself/i);
  assert.match(p, /revoke it at any time in your GitHub settings/);
  assert.match(p, /Supabase/);
  assert.match(p, /GitHub Actions/);
  // Oct 24 (USE-CASES.md row 19): nothing the giscus design doesn't do. Since Oct 28 the site's own sign-in (023) is
  // built and described as applying from launch, so its session cookie and the account page are named again.
  for (const gone of [/passkey/i, /declined at sign-up/, /their own key/, /LinkedIn/, /X and email/]) {
    assert.ok(!gone.test(main(t) + main(p)), 'no longer promised: ' + gone);
  }
  assert.ok(!/Nothing of our own/.test(read('join.html')), '/join says what the checks keep');
});

test('L3: the policies describe the site\'s own sign-in (Aaron, Oct 28) as it is built, and as applying from launch', () => {
  const t = read('terms.html'); const p = read('privacy.html');
  assert.match(p, /Signing in to the site itself \(from launch\)/);
  assert.match(p, /the file never leaves your device/);
  assert.match(p, /never the file, and never its fingerprint as your browser sends it/);
  assert.match(p, /after 10 wrong key files for your username, or when you sign out everywhere/);
  assert.match(p, /__Host-dog_session<\/code> keeps you signed in/);
  assert.match(p, /It ends after 30 days/);
  assert.match(p, /for the 10 minutes the code works/);
  assert.match(t, /Signing in to the site itself \(from launch\)/);
  assert.match(t, /Anyone with your key file and your username can sign in as you/);
  assert.match(t, /you are back in the same account/);
  // The numbers in the policies are the code's.
  assert.strictEqual(require('../signin/config').SESSION_DAYS, 30);
  assert.match(read('signin/flow.js'), /const CODE_MINUTES = 10;/);
  assert.match(read('db/migrations/023_code_signin.sql'), /if found and k\.failed >= 10 then/);
});
