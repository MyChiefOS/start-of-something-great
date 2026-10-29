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
  // In enforce mode (028, go-live) the checks hold high risk and challenge medium risk, so the policies say so.
  for (const h of [t, p]) {
    assert.match(h, /Low risk goes ahead\. A medium-risk action waits until its owner confirms it with a fresh sign-in\. A high-risk post or action is held, or hidden on GitHub/);
    assert.doesNotMatch(h, /They never refuse anyone|at first they only alert a person/i);
  }
  assert.match(p, /no email addresses of the people who post/);
  assert.match(p, /never the text itself/i);
  assert.match(p, /revoke it at any time in your GitHub settings/);
  assert.match(p, /Supabase/);
  assert.match(p, /GitHub Actions/);
  // Oct 24 (USE-CASES.md row 19): nothing the giscus design doesn't do. Since Oct 28 the site's own sign-in (023) is
  // built and, since the go-live release, open, so its session cookie and the account page are named again.
  for (const gone of [/passkey/i, /declined at sign-up/, /their own key/, /LinkedIn/, /X and email/]) {
    assert.ok(!gone.test(main(t) + main(p)), 'no longer promised: ' + gone);
  }
  assert.ok(!/Nothing of our own/.test(read('join.html')), '/join says what the checks keep');
});

test('L3: the policies describe the site\'s own sign-in (Aaron, Oct 28) as it is built, and as open (the go-live release)', () => {
  const t = read('terms.html'); const p = read('privacy.html');
  assert.match(p, /<h2>Signing in to the site itself<\/h2>/);
  assert.doesNotMatch(p + t, /from launch|From launch|when we launch|until the site's own posting opens/);
  assert.match(p, /the file never leaves your device/);
  assert.match(p, /never the file, and never its fingerprint as your browser sends it/);
  assert.match(p, /after 10 wrong key files for your username, or when you sign out everywhere/);
  assert.match(p, /__Host-dog_session<\/code> keeps you signed in/);
  assert.match(p, /It stops working after 30 days/);
  assert.match(p, /__Host-dog_resident<\/code>, marks that session for its 30 days/);
  assert.match(p, /in our audit log, which is kept after you delete your account/);
  assert.match(p, /doesn't erase what our checks keep about your GitHub posts/);
  // 026: the behaviour watch's keyed hashes, and that it never refuses.
  assert.match(p, /<strong>Behaviour watch<\/strong>: to spot an account being taken over/);
  assert.match(p, /once it has gone 90 days unseen, and all of them with your account/);
  assert.match(p, /nothing is refused or blocked/);
  // 030: what the web indicators keep, and for how long, as the migration keeps it.
  assert.match(p, /rounded to about 100 km and encrypted, so it is never stored in readable form \(the key is kept in our database host's secret store, so whoever can read that store, our site and the project's owner, could read it\), not used after a day and deleted within about an hour after that/);
  assert.doesNotMatch(p, /our database can't read/);
  assert.match(p, /halved as it grows and deleted after 90 days without activity/);
  assert.match(p, /brakes it switched off, kept 8 days/);
  assert.match(p, /never the full browser details\) and of the country it was first used from, deleted when the session ends or runs out/);
  assert.match(p, /In normal running only our sign-in system reads these records; the project's owner has database access\. The administrator sees alerts naming your account/);
  assert.doesNotMatch(p, /never a place, a hash or these counts/);
  const w = read('db/migrations/030_behaviour_watch_web.sql');
  assert.match(w, /delete from app\.watch_counts x where x\.hour < now\(\) - interval '8 days'/);
  assert.match(w, /update app\.watch_activity x set place = null, place_at = null where x\.place_at < now\(\) - interval '1 day'/);
  assert.match(w, /delete from app\.watch_activity x where x\.last_seen < now\(\) - interval '90 days'/);
  assert.match(w, /session_id uuid not null unique references app\.sessions \(id\) on delete cascade/);
  assert.match(w, /delete from app\.watch_sessions w using app\.sessions x where x\.id = w\.session_id and x\.expires_at <= now\(\)/);
  assert.match(read('signin/watch.js'), /return \{ la: Math\.round\(la\), lo: Math\.round\(lo\) \};/);
  assert.match(read('db/migrations/026_behaviour_watch.sql'), /-- Everyone's rows unseen for 90 days, at every sign-in[\s\S]*?delete from app\.watch_seen w where w\.id in \(select x\.id from app\.watch_seen x where x\.last_seen < now\(\) - interval '90 days'/);
  assert.match(read('db/jevs.js'), /const RESIDENT = '__Host-dog_resident';/);
  assert.match(read('db/migrations/021_signup_level_cap.sql'), /'member\.region_confirmed'/);
  assert.match(read('join.js'), /By continuing, you confirm that you live outside these regions and are using your account lawfully/);
  assert.match(p, /A code works for 10 minutes; its record is deleted the next time anyone asks for a code/);
  assert.match(t, /<strong>Signing in to the site itself\.<\/strong>/);
  assert.match(t, /Anyone with your key file and your username can sign in as you/);
  assert.match(t, /you are back in the same account/);
  // The numbers in the policies are the code's.
  assert.strictEqual(require('../signin/config').SESSION_DAYS, 30);
  assert.match(read('signin/flow.js'), /const CODE_MINUTES = 10;/);
  assert.match(read('db/migrations/023_code_signin.sql'), /if found and k\.failed >= 10 then/);
});
