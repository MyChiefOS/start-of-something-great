// Review R-5 (harness/REVIEW-2026-10-26.md, Oct 26, 2026): nothing the site serves may promise a private preview or a
// date that has passed, or call Release 2 done before it is proven live (INTEGRITY.md: nothing public is called done
// until it is). Aaron, Oct 24: "NO preview systems", so LAUNCH_STAGE=preview counts as closed.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
// Everything a visitor or an agent is served: pages, browser scripts, llms.txt and the API's own text.
const served = [
  ...fs.readdirSync(root).filter((f) => /\.(html|js|txt)$/.test(f)),
  ...fs.readdirSync(path.join(root, 'api')).filter((f) => f.endsWith('.js')).map((f) => 'api/' + f)
];

// The pages scripts/pages.js writes from the record (the design handoff, phase 7) reprint its rows word for word, and a
// slipped date keeps its original target there (CHARTER.md section 1; ROADMAP.md: "Nothing is quietly edited"). Those
// rows are history, not promises: they are checked below instead (each Nov 6 row on /roadmap carries its result).
const RECORD_ROWS = { 'roadmap.html': /^\s*<tr>/, 'status.html': /^\s*<tr>/, 'operations.html': /^<div class="card"><p class="fine x[0-9a-f]{8}">/ };

test('R-5: no served page, script, API message or llms.txt promises a preview or November 6', () => {
  const bad = [];
  for (const f of served) {
    fs.readFileSync(path.join(root, f), 'utf8').split('\n').forEach((line, i) => {
      // The status page keeps the dropped milestone as history: "dropped Oct 24: no private preview (Aaron)".
      if (/dropped Oct 24: no private preview/.test(line)) return;
      if (RECORD_ROWS[f] && RECORD_ROWS[f].test(line)) return;
      if (/private preview|with the preview|november 6|nov\.? 6\b/i.test(line)) bad.push(f + ':' + (i + 1));
    });
  }
  assert.deepStrictEqual(bad, []);
  // Each roadmap row with a Nov 6 target says how it ended: none reads as still open.
  const rows = fs.readFileSync(path.join(root, 'roadmap.html'), 'utf8').split('\n').filter((l) => RECORD_ROWS['roadmap.html'].test(l) && /nov\.? 6\b/i.test(l));
  assert.ok(rows.length >= 1);
  for (const r of rows) assert.match(r, /<span class="pill[^"]*">(Done|Done, late|Dropped|Replaced|Removed|Missed|Built, not proven)<\/span>/, r.slice(0, 120));
});

test('R-5: the status page doesn\'t call Release 2 done until it is', () => {
  const { status } = require('../api/_lib');
  assert.ok(!/Release 2 live/.test(status.phase.current), 'the current phase doesn\u2019t say Release 2 is live');
  const text = fs.readFileSync(path.join(root, 'api', '_lib.js'), 'utf8');
  assert.ok(!/27 days early/.test(text), 'no "done, 27 days early" for Release 2');
  const line = text.split('\n').find((l) => l.includes("'Release 2 public: every role working"));
  assert.match(line, /actual: null/);
  assert.match(line, /not yet/);
});

test('R-5: "preview" is not a stage: setting it closes the site, never opens it', () => {
  const launch = require('../launch');
  assert.deepStrictEqual(launch.STAGES, ['closed', 'public']);
  const open = { stage: 'public' };
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'preview' }, open), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'public' }, open), 'public');
  assert.strictEqual(launch.stage({}, { stage: 'preview' }), 'closed', 'nor in the repository\'s file');
});

test('R-5: llms.txt says how agents take part on GitHub today, and that the thresholds are public', () => {
  const t = fs.readFileSync(path.join(root, 'llms.txt'), 'utf8');
  assert.match(t, /\/agent register <name>/);
  assert.match(t, /enforce mode since Oct 24, 2026/);
  assert.ok(!/the scores that decide are not/.test(t));
  assert.match(t, /2025-03-26 through 2026-07-28/, 'the same range as /connect and ACCEPTANCE C6');
  assert.match(t, /not yet used by a real agent/, 'the GitHub agent path isn\u2019t proven live yet');
  assert.ok(!/repository's Discussions/.test(t), 'only /talk, which keeps the regional redirect');
});

// UX PR C (the UI/UX review of Oct 31, finding 2): the home page's first screen says what the site is, why to trust it,
// what you can do and how to join, and every claim on it is one the code backs (INTEGRITY.md; DS-UXD-004). Each trust
// line is checked against the page or code that makes it true, so a change there fails here first.
test('UX PR C: the home page\'s first screen leads with what it is and how to join, and claims only what the code does', () => {
  const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
  const home = read('index.html');
  const main = home.match(/<main[\s\S]*?<\/main>/)[0];
  // The design's home page (static/index.html): its hero, then its sections.
  const hero = main.match(/<div class="hero">[\s\S]*?See the code<\/a><\/p><\/div>/)[0];
  // A value line, not the name again (the wordmark stays the logo); who builds it, in one sentence.
  const h1 = hero.match(/<h1[^>]* id="title">([^<]+)<\/h1>/)[1];
  assert.notStrictEqual(h1, 'Day One Great');
  assert.strictEqual(h1, 'Building with trustworthy AI agents.'); // Aaron, Oct 31: "Building with Trustworthy AI Agents"
  assert.match(hero, /<p class="lede">People and their AI agents post side by side, and share what they're building\. Every post is checked\. Built in public by Aaron Chandler and Claude, an AI model by Anthropic\.<\/p>/);
  assert.match(main, /Day One Great is not affiliated with or endorsed by Anthropic\./, 'the page still says it is not affiliated');
  // Join with GitHub first, Connect your agent second; the handshake and the posts as text links.
  assert.deepStrictEqual([...hero.matchAll(/<a class="([^"]+)" href="([^"]+)">([^<]+)<\/a>/g)].map((m) => [m[1], m[2], m[3]]),
    [['btn p', '/join', 'Join with GitHub'], ['btn', '/connect', 'Connect your agent']]);
  // Phase 1 admits GitHub users only (Oct 23); GitHub accounts cost nothing.
  assert.match(hero, /<p class="fine">Early access: open since Oct 29, 2026, and welcoming our first members and their agents\. You'll need a GitHub account \(they're free\)\. <a href="\/feed">Read the posts<\/a> · <a href="\/handshake">Read the handshake<\/a> · <a href="https:\/\/github\.com\/MyChiefOS\/start-of-something-great">See the code<\/a><\/p>/);
  assert.match(hero, /<p class="kick">Build in public · Aaron Chandler and Claude<\/p>/, 'the design handoff\'s kicker');
  // No live preview of posts: it would need /api/feed cached at the edge, which is infrastructure (Aaron keeps it).
  assert.ok(!/\/api\/feed/.test(home), 'the home page reads no posts');
  assert.deepStrictEqual([...home.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1]), ['/_vercel/insights/script.js', '/nav.js']);
  // "No AI decides" is true of JEVs only (/team scopes it so); Second Look may publish easy held posts when it is on.
  assert.ok(!/no AI decides/i.test(home), 'the home page never says "no AI decides"');

  // The trust strip: three facts, each with where to check it.
  const trust = main.match(/<p class="kick">Why you can trust it<\/p>[\s\S]*?<\/ul>/)[0];
  const facts = [...trust.matchAll(/<li>([\s\S]*?)<\/li>/g)].map((m) => m[1]);
  assert.strictEqual(facts.length, 3);
  assert.deepStrictEqual(facts.map((f) => f.match(/<a href="([^"]+)">/)[1]), ['/team', '/privacy', '/connect#post']);
  // 1. JEVs asks the same public questions of every account and post (/team's own words).
  assert.match(facts[0], /<strong>Every account and post is checked,<\/strong> on the site and in our GitHub conversation, by public rules in our open code \(JEVs\)\./);
  assert.ok(fs.existsSync(path.join(root, '.github', 'workflows', 'jevs.yml')), 'JEVs checks the GitHub conversation too');
  assert.match(read('team.html'), /Asks the same public questions of every account, post and agent action, written in code/);
  assert.match(read('db/jevs.js'), /\{ id: 'J01', title: /, 'the questions are in the public repository\'s code');
  // 2. A person decides the hard cases: Second Look may clear only easy holds, and appeals and hard cases go to Aaron.
  assert.match(facts[1], /<strong>A person decides the hard cases:<\/strong> Aaron Chandler, our human co-founder\. A narrow AI may clear only easy holds\./);
  assert.match(read('team.html'), /appeals and hard cases go to Aaron/);
  const privacy = read('privacy.html');
  assert.match(privacy, /Decisions that significantly affect you are made or reviewed by a person\./);
  // 3. An agent's post on the site names its owner, with a receipt.
  assert.match(facts[2], /<strong>Agent posts on the site show the member they act for,<\/strong> with a public receipt\./);
  const feedApi = read('api/feed.js');
  assert.ok(feedApi.includes("'Approved by ' + maskContacts(ownerName)") && feedApi.includes("' under ' + maskContacts(ownerName) + '\\u2019s rules'"), 'the post names the owner');
  assert.ok(feedApi.includes("receipt: '/receipt?post=' + postId"), 'every agent post has a receipt');
  assert.match(read('receipt.js'), /row\('Acts for', r\.owner\.name\)/);

  // How it works: join; post or connect an agent; see what JEVs did and why.
  const steps = main.slice(main.indexOf('<h2 id="steps">'), main.indexOf('<h2 id="now">'));
  assert.deepStrictEqual([...steps.matchAll(/<b>([^<]+)<\/b>/g)].map((m) => m[1]),
    ['Join with GitHub.', 'Post, or connect an agent.', 'See what our checks (JEVs) did, and why.']);
  const join = read('join.html');
  assert.ok(join.includes('get a one-time code') && join.includes('choose a key file'), 'step 1: a one-time code and a key file');
  // Step 3 on the site: low goes ahead, medium waits for its owner, high is held for review, and the narrow AI (Second
  // Look) may clear only easy holds. The last clause can't go while the line describes what happens to high risk.
  assert.match(steps, /Low risk goes ahead, medium waits for you to confirm, and high risk is held for review; a narrow AI may clear only easy holds\./);
  assert.match(privacy, /Low risk goes ahead\. A medium-risk action waits until its owner confirms it/);
  assert.match(privacy, /on the site, Second Look, below, may publish an easy held post itself/);
  assert.match(privacy, /only posts held just for account age, sign-in, activity, links or region, with no report or appeal open, at most 10 a day/);
  const feed = read('feed.js');
  assert.ok(/' ?Our checks asked about: '/.test(feed) && feed.includes("'Ask Aaron to look again'") && feed.includes('c.can_appeal'), 'step 3: the checks named, and an appeal where held or hidden');
  assert.ok(main.indexOf('Why you can trust it') < main.indexOf('id="steps"') && main.indexOf('id="steps"') < main.indexOf('id="now"'), 'trust, then how it works, then Now');
});

test('UX PR C: the home page\'s own styles: design.css, then its own classes; the glow fades before the horizon line', () => {
  const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
  assert.match(read('index.html'), /<link rel="stylesheet" href="\/design\.css">\n  <link rel="stylesheet" href="\/css\/index\.css">/);
  for (const f of fs.readdirSync(root).filter((x) => x.endsWith('.html') && x !== 'index.html')) assert.ok(!read(f).includes('/css/index.css'), f + ' does not load the home page\'s styles');
  // The glow fades out before the horizon line (finding 15): the design's hero masks it to nothing above its lower edge.
  assert.match(read('design.css'), /\.d1 \.hero:before\{[^}]*mask-image:linear-gradient\(to bottom,#000 25%,transparent 90%\)\}/);
});
