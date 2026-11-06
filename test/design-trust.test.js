'use strict';
// The trust pages of the design handoff (Nov 5, 2026: static/status, roadmap, checks, moderation, autonomy, security)
// and the spec's extra pages (CODING_AGENT_SPEC.md section 6: /limits, /risks, /operations, /privacy/keys), built into
// the production site. Six are generated from the repository files that define them (scripts/pages.js; Aaron, phase 7:
// "Yes: generated before each commit, and transparent"), and a stale one fails here.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const shell = require('../scripts/shell');
const pages = require('../scripts/pages');

// Each page: its file (x.html serves /x), its h1, and its section headings in the design's order.
const PAGES = {
  'status.html': ['Status', ['Each role, end to end', 'Milestones']],
  'roadmap.html': ['Roadmap', ['How we report']],
  'checks.html': ['The checks', ['What happens to the answer', 'Question families', /^All \d+ questions$/]],
  'moderation.html': ['Moderation and appeals', ['If your post is held or hidden', 'What Second Look may and may not do', 'What the founder can do', 'Reports']],
  'autonomy.html': ['How agents earn more freedom', ['Autonomy licenses', 'Forecasts', 'Precedents', 'Upgrade certificates', 'House model', 'Work orders', 'Immune system', 'Dual signatures']],
  'security.html': ['Security', ['How changes reach the site', 'Known limits', 'The public log']],
  'limits.html': ['Limits', ['Posting', 'The limits in the code', 'The emergency brake']],
  'risks.html': ['Risk register', ['The register in numbers', 'Every risk']],
  'operations.html': ['Operations log', ['How each entry happens', 'Every action, newest first']],
  'privacy/keys.html': ['Key files', ['What a key file is', 'The rule today', 'What we keep', 'Its limits', 'What may change']]
};
const GENERATED = ['status.html', 'roadmap.html', 'checks.html', 'risks.html', 'operations.html', 'limits.html'];
const mainOf = (html) => html.match(/<main[\s\S]*?<\/main>/)[0];
const text = (s) => s.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').trim();

test('each page exists at its path and carries the shell exactly as scripts/shell.js writes it', () => {
  for (const f of Object.keys(PAGES)) {
    assert.ok(fs.existsSync(path.join(root, f)), f + ' exists');
    const html = read(f);
    assert.strictEqual(shell.render(f, html), html, f + ' carries the shell: run node scripts/shell.js');
    const slug = f.replace(/\.html$/, '');
    assert.ok(html.includes('<link rel="canonical" href="https://dayonegreat.com/' + slug + '">'), f + ': canonical /' + slug);
    assert.match(html, /<body>\s*(<!--[^>]*-->\s*)?<div class="d1"><div class="wrap">\s*<!-- shell:top -->\s*<a class="skip" href="#main">Skip to content<\/a>/, f + ': the skip link first');
    assert.ok(html.includes('<main class="story" id="main" tabindex="-1">'), f + ': the design\'s story main');
    // design.css, then the page's own inline styles as classes where it has any (tools/design/build.js).
    const sheets = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)">/g)].map((m) => m[1]);
    assert.deepStrictEqual(sheets, fs.existsSync(path.join(root, 'css', slug.replace(/\//g, '-') + '.css')) ? ['/design.css', '/css/' + slug.replace(/\//g, '-') + '.css'] : ['/design.css'], f + ': the stylesheets in order');
    assert.ok(html.includes('<script src="/nav.js" defer></script>'), f + ': nav.js');
  }
  // The trust pages carry the Trust row, with their own mark.
  for (const f of ['status.html', 'roadmap.html', 'checks.html', 'moderation.html', 'autonomy.html', 'security.html']) {
    const row = read(f).match(/<div class="sub2" aria-label="Trust">[\s\S]*?<\/div>/);
    assert.ok(row, f + ' has the Trust row');
    assert.ok(row[0].includes('<a class="on" href="/' + f.replace(/\.html$/, '') + '" aria-current="page">'), f + ' is marked current');
  }
});

test('each page has the design\'s one h1 and its section headings in order, with no level skipped', () => {
  for (const [f, [h1, h2s]] of Object.entries(PAGES)) {
    const main = mainOf(read(f).replace(/<template[\s\S]*?<\/template>/g, ''));
    const h1s = [...main.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/g)].map((m) => text(m[1]));
    assert.deepStrictEqual(h1s, [h1], f + ': the h1');
    const got = [...main.matchAll(/<h2[^>]*>([\s\S]*?)<\/h2>/g)].map((m) => text(m[1]));
    assert.strictEqual(got.length, h2s.length, f + ': ' + JSON.stringify(got));
    h2s.forEach((want, i) => (want instanceof RegExp ? assert.match(got[i], want, f) : assert.strictEqual(got[i], want, f)));
    let prev = 1;
    for (const m of main.matchAll(/<h([1-6])\b/g)) { assert.ok(Number(m[1]) <= prev + 1, f + ': h' + prev + ' then h' + m[1]); prev = Number(m[1]); }
  }
});

test('no inline style, no inline script, no on* handler; scripts are our own files, text only, our own /api only', () => {
  for (const f of Object.keys(PAGES)) {
    const html = read(f);
    assert.ok(!/\sstyle\s*=/i.test(html), f + ': no style attribute');
    assert.ok(!/<style\b/i.test(html), f + ': no style element');
    assert.ok(!/\son[a-z]+\s*=/i.test(html), f + ': no on* handler');
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      assert.match(m[1], /\bsrc="\/[^"]+"/, f + ': a script with a src on this site');
      assert.strictEqual(m[2].trim(), '', f + ': no inline script');
    }
  }
  for (const js of ['status.js', 'risks.js']) {
    const code = read(js);
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(code), js + ': text only');
    // Every fetch goes through get(path), and get() is called with our own /api paths only (below).
    for (const m of code.matchAll(/fetch\(([^,)]+)/g)) assert.strictEqual(m[1].trim(), 'path', js + ': fetch(' + m[1] + ')');
  }
  // 041: and the public review alerts (Second Look's planted tests and sample), from /api/decisions.
  assert.deepStrictEqual([...read('status.js').matchAll(/get\('([^']+)'\)/g)].map((m) => m[1]), ['/api/status', '/api/ready', '/api/decisions']);
  assert.ok(read('status.html').includes('id="live-review"'), '#live-review');
  assert.ok(!/fetch\(/.test(read('risks.js')), 'risks.js fetches nothing');
  // The live lines status.js reveals are on the page.
  for (const id of ['live-status', 'live-stage', 'live-signin', 'live-stage-now', 'live-signin-now', 'live-uptime-now']) assert.ok(read('status.html').includes('id="' + id + '"'), '#' + id);
  for (const id of ['risk-rows', 'shown']) assert.ok(read('risks.html').includes('id="' + id + '"'), '#' + id);
});

// The design's sample figures and prototype notes (rule 1 of the build guide): none may reach a production page.
const SAMPLES = {
  'status.html': ['>Shadow<', 'Built, off until launch', 'Not yet. Aaron decides.', '>Running<', 'the page is not on the live site'],
  'roadmap.html': ['Abridged here', 'The live site only links the file on GitHub'],
  'checks.html': ['Only the IDs I could confirm', 'Example IDs', 'Scored on sign-up, sign-in and each post', 'The live site points to'],
  'moderation.html': ['authors are not yet told', 'by ID, never a score'],
  'security.html': ['The live site has only the contact line', 'not documented', 'X-Oauth-Client-Id'],
  'autonomy.html': [],
  'privacy/keys.html': ['64 KiB', '65,536', 'public key', 'Argon2', 'photo']
};
test('no figure or note from the design\'s sample set is on any page', () => {
  for (const [f, list] of Object.entries(SAMPLES)) for (const s of list) assert.ok(!read(f).includes(s), f + ' still shows ' + JSON.stringify(s));
  for (const f of Object.keys(PAGES)) {
    assert.ok(!/Sample figures|Prototype views|static\/|\.html"/.test(mainOf(read(f))), f + ': no prototype links or sample pill');
  }
});

test('the generated pages match their source files (node scripts/pages.js --check)', async () => {
  const built = await pages.build();
  assert.deepStrictEqual(Object.keys(built).sort(), GENERATED.slice().sort());
  for (const [f, html] of Object.entries(built)) assert.strictEqual(html, read(f), f + ' is stale: run node scripts/pages.js');
  const r = spawnSync(process.execPath, [path.join(root, 'scripts', 'pages.js'), '--check'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  for (const f of GENERATED) assert.ok(read(f).includes('Generated by scripts/pages.js'), f + ' says it is generated');
});

test('a changed source file makes its page stale, and --check says so', () => {
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'pages-'));
  for (const d of ['scripts', 'db', 'api', 'signin', 'supabase', 'jevs', '.github', 'notify', 'moderation', 'css', 'tools']) fs.cpSync(path.join(root, d), path.join(tmp, d), { recursive: true });
  for (const f of fs.readdirSync(root)) if (/\.(html|md|json|js|txt|css)$/.test(f)) fs.copyFileSync(path.join(root, f), path.join(tmp, f));
  // Every folder of pages too: the shell links a page only once it exists, so the copy needs them all.
  for (const d of ['privacy', 'research', 'admin', 'account', 'agents', 'errors']) if (fs.existsSync(path.join(root, d))) fs.cpSync(path.join(root, d), path.join(tmp, d), { recursive: true });
  try { fs.symlinkSync(path.join(root, 'node_modules'), path.join(tmp, 'node_modules')); } catch { /* already there */ }
  const ok = spawnSync(process.execPath, [path.join(tmp, 'scripts', 'pages.js'), '--check'], { encoding: 'utf8' });
  assert.strictEqual(ok.status, 0, ok.stdout + ok.stderr);
  fs.writeFileSync(path.join(tmp, 'ROADMAP.md'), read('ROADMAP.md').replace('| Site, stories, domains and email |', '| Site, stories, domains, email |'));
  const stale = spawnSync(process.execPath, [path.join(tmp, 'scripts', 'pages.js'), '--check'], { encoding: 'utf8' });
  assert.strictEqual(stale.status, 1, 'a roadmap change makes /roadmap stale');
  assert.match(stale.stdout, /roadmap\.html/);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('derived states never upgrade what a file says: nothing is "Proven live" unless the row says live and nothing is missing', () => {
  assert.deepStrictEqual(pages.rolePill({ works: 'Yes (live)', missing: 'None' }), ['Proven live', 'f']);
  assert.notStrictEqual(pages.rolePill({ works: 'Yes', missing: 'None' })[0], 'Proven live', 'works today, but the row records no live proof');
  assert.notStrictEqual(pages.rolePill({ works: 'Yes (seen Oct 29), live', missing: 'Feed and MCP strip hidden markup' })[0], 'Proven live', 'code still missing');
  assert.strictEqual(pages.rolePill({ works: 'Built, unproven live', missing: 'Tag parser' })[0], 'Built, not proven');
  assert.strictEqual(pages.rolePill({ works: 'GitHub posts scored live (one post); enforce mode not yet exercised', missing: 'x' })[0], 'Built, not proven');
  assert.strictEqual(pages.rolePill({ works: 'Something new', missing: 'x' })[0], 'Unknown', 'an unknown wording says unknown, never a guess');
  // Every role on /status: Proven live only where USE-CASES.md itself says live with no missing code.
  const uc = pages.table(read('USE-CASES.md'), '| # | Use case |');
  const html = read('status.html');
  for (const [n, , , works, missing] of uc.rows) {
    if (pages.rolePill({ works: works, missing: missing })[0] === 'Proven live') assert.ok(/\blive\b/i.test(works) && /^none$/i.test(missing), 'row ' + n);
  }
  assert.strictEqual((html.match(/>Proven live</g) || []).length, uc.rows.filter((r) => /^yes\b/i.test(r[3]) && /\blive\b/i.test(r[3]) && /^none$/i.test(r[4])).length);
  assert.match(html, /\(checked [A-Z][a-z]{2} \d{1,2}\)/, 'the file\'s own check date');
  // The roadmap: a ✅ is Done, a merged but not live row is Built, not proven, never Done.
  assert.deepStrictEqual(pages.roadmapPill('✅ Done, 1 day late'), ['Done, late', 'a']);
  assert.strictEqual(pages.roadmapPill('Merged Oct 17 (#31); not live (our own sign-in is off)')[0], 'Built, not proven');
  assert.strictEqual(pages.roadmapPill('Built and merged, switched off until launch; not yet proven live')[0], 'Built, not proven');
  // Risks: a blank sign-off is never "Accepted".
  assert.strictEqual(pages.riskStatus({ signoff: '', risk: 'x' }), 'Not signed off');
  assert.strictEqual(pages.riskStatus({ signoff: '', risk: '**Not in phase 1** (email)' }), 'Not in phase 1');
  assert.strictEqual(pages.riskStatus({ signoff: 'Checked Oct 31. Recorded for Aaron; not yet signed off', risk: 'x' }), 'Not signed off');
  assert.strictEqual(pages.riskStatus({ signoff: 'Open: Aaron\'s merge of the web-indicators PR accepts it', risk: 'x' }), 'Open');
});

test('the pages hold every row of their source files (no row dropped), and Operations shows at most 100', () => {
  const rows = (f, first) => pages.table(read(f), first).rows.length;
  assert.strictEqual((mainOf(read('roadmap.html')).match(/<tr>/g) || []).length - 1, rows('ROADMAP.md', '| Milestone |'));
  assert.strictEqual((mainOf(read('status.html')).match(/<tr>/g) || []).length - 1, rows('USE-CASES.md', '| # | Use case |'));
  assert.strictEqual((mainOf(read('risks.html')).match(/<tr id="rk/g) || []).length, rows('RISKS.md', '| ID | Risk |'));
  const ops = rows('OPERATIONS.md', '| When | Action |');
  // Each entry is the design's card, its time on the first, fine line.
  const list = mainOf(read('operations.html')).split('<h2>Every action, newest first</h2>')[1];
  assert.strictEqual((list.match(/<div class="card"><p class="fine x[0-9a-f]{8}">/g) || []).length, Math.min(100, ops));
  // Every question in the code is on /checks, both versions where both ask it.
  const site = require('../db/jevs').QUESTIONS;
  for (const q of site) assert.ok(read('checks.html').includes('<strong>' + q.id + ' '), q.id);
  for (const id of ['J16', 'J17']) assert.ok(read('checks.html').includes('<strong>' + id + ' '), id + ' (the GitHub gate)');
});

test('/limits shows the limits the code applies, read from the code', () => {
  const html = read('limits.html');
  const rep = require('../api/feed').REPORT_LIMITS;
  const reg = require('../api/agents').REGISTER_LIMITS;
  assert.ok(html.includes(rep.report_member.max + ' an hour per member, ' + rep.report_ip.max + ' an hour per network'));
  assert.ok(html.includes(reg.agent_register_ip.max + ' an hour per address'));
  assert.ok(html.includes(require('../signin/flow').LIMITS.signin_ip.max + ' every 10 minutes from one network'));
  assert.match(html, /No platform quotas on what members say/, 'F4, in its own words');
});

test('/privacy/keys says today\'s rule only (phase 3 is not decided), and /status takes its live values from our own answers', () => {
  const keys = mainOf(read('privacy/keys.html'));
  assert.match(keys, /There is no minimum size; the page refuses files over 100 MB\./);
  assert.match(read('join.js'), /f\.size > 100 \* 1024 \* 1024/, 'the 100 MB rule is the one join.js applies');
  assert.match(keys, /Nothing about it is decided or live/);
  assert.match(keys, /<nav class="crumbs" aria-label="Breadcrumb"><a href="\/privacy">Privacy policy<\/a> \/ <span aria-current="page">Key files<\/span><\/nav>/);
  const status = read('status.html');
  assert.ok(status.includes('<script src="/status.js" defer></script>'));
  assert.ok(status.includes('>' + read('jevs/mode').trim().replace(/^./, (c) => c.toUpperCase()) + '</span>'), 'JEVs mode is the repository\'s jevs/mode');
  assert.match(read('status.js'), /Couldn(’|\\u2019)t load /, 'an honest "couldn\'t load" state');
});
