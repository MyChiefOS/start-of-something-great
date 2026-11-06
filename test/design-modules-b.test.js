'use strict';
// The design handoff of Nov 5, 2026, module pages group B: /rooms, /rooms/{code}, /projects, /projects/{id},
// /disputes, /disputes/{id}, /agents/join, /admin/console and the generated /admin/go-live. Built as drawn
// (static/<page>.html in the handoff), with every sample figure replaced by real data or the design's empty state,
// and the Proposed notices rewritten so they are true today (CODING_AGENT_SPEC.md 0.2, 5.5, 5.7; Aaron's decisions on
// the handoff, design/handoff-2026-11-05/NOTES.md).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const main = (f) => read(f).match(/<main[\s\S]*?<\/main>/)[0];
const shell = require('../scripts/shell');

// Each page: its file, the address it serves, the h1 and the section headings (h2) in the design's order. Where the
// design's h1 was a sample (a made-up project, room or dispute), the static h1 is the real one or a plain one the
// script fills from the address.
const PAGES = [
  { file: 'agents/join.html', path: '/agents/join', h1: 'Join as an agent', kicker: 'For agents',
    h2: ['1. Join', '2. Store your key, pass on the claim link', '3. Post for the person you act for', 'If you lose your key'] },
  { file: 'admin/go-live.html', path: '/admin/go-live', h1: 'Release checklist (SF6)', kicker: 'Go live',
    h2: ['Decisions', 'Accounts and settings', 'Legal', 'Go live'] }
];
const FILES = PAGES.map((p) => p.file);
const SCRIPTS = [];

// The design's sample set: invented people, agents, projects, receipts, hashes, counts and times
// (static/rooms.html, room.html, projects.html, project.html, disputes.html, dispute.html, agentjoin.html, console.html).
const SAMPLES = ['@jordan_k', '@mira', '@aaron', 'jordan_k', 'claude-sonnet-4.6', 'gpt-5.2-auditor', 'claude_helper', 'build_scribe', 'jordan-agent',
  'R-99231', 'R-99190', 'R-99120', 'proj_3f9a', 'proj_1c20', 'ap_9c1e', 'ap_4b7d', 'ap_77a2', 'reviewer-2',
  'Summarise vendor contracts', 'Port the parser to Rust', 'Write a schema migration', 'Review a lease amendment', 'Reconcile Q3 invoices',
  'Draft a press note', 'Three contracts reviewed', 'Reconciled 214 of 216', '44 of 44', 'Run log from a clean checkout',
  '1,420', '1,388', '1,102', '48,310', '1,204', '1,203', '1,152', '>212<', '>612<', '>208<', '>97<', '12 open', '5 open', '4 open', '3 open', '2 open', '1 open',
  '6 of 23', '58 h', '58 of 72', '41 seconds', '41s ago', 'sha256:9f3a', 'sha256:77be', 'Oct 14</td>', 'Oct 30</td>',
  'Sample figures', 'Sample dispute', 'tax law', 'Intact', 'checks out', 'POST /rpc', 'recoverKey', 'recoveryKey', 'apiKey', '10 joins a minute',
  '1 to 32 characters', 'login_failed', 'admin_read'];

test('every page exists at its path, carries the shell exactly as scripts/shell.js writes it, and loads nav.js', () => {
  for (const p of PAGES) {
    assert.ok(fs.existsSync(path.join(root, p.file)), p.file + ' serves ' + p.path);
    const html = read(p.file);
    assert.strictEqual(shell.render(p.file, html), html, p.file + ' carries the shell (run node scripts/shell.js)');
    assert.match(html, /<script src="\/nav\.js" defer><\/script>/, p.file);
    // The design's own stylesheet, which carries the site's tokens (tools/design/mkcss.js), and no other.
    assert.deepStrictEqual([...html.matchAll(/<link rel="stylesheet" href="([^"]+)">/g)].map((m) => m[1]), ['/design.css'], p.file + ': design.css only');
    const title = html.match(/<title>([^<]+)<\/title>/)[1];
    assert.ok(title.endsWith(': Day One Great'), p.file + ': ' + title);
    assert.match(html, new RegExp('<link rel="canonical" href="https://dayonegreat\\.com/'), p.file);
  }
  const titles = FILES.map((f) => read(f).match(/<title>([^<]+)<\/title>/)[1]);
  assert.strictEqual(new Set(titles).size, titles.length, 'every title is its own');
});

test('the design’s h1, kicker and section headings, in order; one h1 and no skipped heading level', () => {
  for (const p of PAGES) {
    const m = main(p.file);
    assert.strictEqual((m.match(/<h1\b/g) || []).length, 1, p.file + ': one h1');
    assert.strictEqual(m.match(/<h1[^>]*>([^<]*)<\/h1>/)[1], p.h1, p.file + ': h1');
    if (p.kicker) assert.ok(m.indexOf('<p class="kick">' + p.kicker + '</p>') >= 0 && m.indexOf('class="kick"') < m.indexOf('<h1'), p.file + ': kicker above the h1');
    if (p.h2) {
      const h2 = [...m.matchAll(/<h2[^>]*>([^<]*)<\/h2>/g)].map((x) => x[1]).filter((t) => p.h2.includes(t));
      assert.deepStrictEqual(h2, p.h2, p.file + ': section headings in order');
    }
    let prev = 1;
    for (const h of m.matchAll(/<h([1-6])\b/g)) { const n = Number(h[1]); assert.ok(n <= prev + 1, p.file + ': h' + prev + ' then h' + n); prev = n; }
    for (const tag of ['<header class="hd">', '<nav class="nav dnav" aria-label="Main">', ' id="main" tabindex="-1">', '<footer class="ft ']) assert.ok(read(p.file).includes(tag), p.file + ' has ' + tag);
    assert.match(read(p.file), /<body>\s*<div class="d1"><div class="wrap">\s*<!-- shell:top -->\s*<a class="skip" href="#main">Skip to content<\/a>/, p.file);
  }
});

test('no inline style, no inline script, no on* handler; scripts are files, write text only and fetch only our own API', () => {
  for (const f of FILES) {
    const html = read(f);
    assert.ok(!/\sstyle=/i.test(html), f + ': no style attribute');
    assert.ok(!/<style\b/i.test(html), f + ': no style element');
    for (const s of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      assert.match(s[1], /\bsrc="\//, f + ': every script is a file of ours');
      assert.strictEqual(s[2].trim(), '', f + ': nothing inside a script tag');
    }
    assert.ok(!/\son[a-z]+\s*=/i.test(html.replace(/<meta[^>]*>/g, '')), f + ': no on* handler');
  }
  for (const f of SCRIPTS) {
    const js = read(f);
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(js), f + ': text only');
    for (const u of js.matchAll(/fetch\('([^']+)'/g)) assert.match(u[1], /^\/(api\/|auth\/me$)/, f + ' fetches ' + u[1]);
    assert.ok(!/\.style\b|setAttribute\('style'/.test(js), f + ': no inline styles from script either');
  }
});

test('no figure from the design’s sample set: no made-up person, agent, project, receipt, score, hash or time', () => {
  for (const f of FILES) {
    const m = main(f);
    for (const s of SAMPLES) assert.ok(!m.includes(s), f + ' shows the sample "' + s + '"');
  }
  for (const f of SCRIPTS) for (const s of SAMPLES.filter((x) => !x.startsWith('>'))) assert.ok(!read(f).includes(s), f + ' carries the sample "' + s + '"');
});

test('/agents/join, which is real, carries no Proposed notice', () => {
  assert.ok(!/<b>Proposed\.<\/b>/.test(main('agents/join.html')), '/agents/join describes the live registration');
  for (const f of FILES) assert.ok(!/drand|public randomness|random-number/.test(main(f)), f + ': no randomly chosen auditors');
});

test('/agents/join describes the registration that exists today: the call, its limits and answers match the API', () => {
  const m = main('agents/join.html');
  const api = read('api/agents.js');
  assert.match(m, /POST https:\/\/dayonegreat\.com\/api\/agents\/register/);
  assert.match(api, /async 'POST register'\(/, 'the route exists');
  assert.match(api, /agent_register_ip: \{ windowSeconds: 3600, max: 10 \}, agent_register_net: \{ windowSeconds: 3600, max: 20 \},\n  agent_register_all: \{ windowSeconds: 3600, max: 500 \}/);
  assert.match(m, /10 registrations an hour from one address, 20 from one network, and 500 an hour for everyone/);
  assert.match(read('db/agents.js'), /v\.text\('name', s, \{ max: 80 \}\)/);
  assert.match(m, /A name is up to 80 characters/);
  assert.match(read('db/agents.js'), /v\.text\('description', s, \{ max: 500, multiline: true \}\)/);
  assert.match(m, /A description is up to 500 characters/);
  assert.match(api, /claim_url: ORIGIN \+ '\/account\/agents#claim=' \+ code, claim_expires_in_hours: 24/);
  assert.match(m, /within 24 hours/);
  assert.match(api, /return reply\(res, 451, \{ error: region\.MESSAGE \}\)/);
  assert.match(m, /Registration from the EU, the EEA, the UK and Switzerland is declined/);
  for (const href of ['/llms.txt', '/connect#post', '/account/agents']) assert.ok(m.includes('href="' + href + '"'), 'links ' + href);
  assert.match(read('connect.html'), /<h2 id="post">/, 'the /connect anchor exists');
});

test('/admin/go-live is generated from RELEASE-CHECKLIST.md, ACCEPTANCE.md and launch.json, and matches its generator', () => {
  const gen = require('../scripts/go-live');
  assert.strictEqual(gen.page(), read('admin/go-live.html'), 'run node scripts/go-live.js');
  const r = spawnSync(process.execPath, [path.join(root, 'scripts', 'go-live.js'), '--check'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  const m = main('admin/go-live.html');
  // Every box in the file is on the page, with its state in words.
  const md = read('RELEASE-CHECKLIST.md');
  const open = (md.match(/^- \[ \] /gm) || []).length;
  const done = (md.match(/^- \[x\] /gim) || []).length;
  assert.strictEqual((m.match(/<span class="pill">Open<\/span>/g) || []).length, open);
  assert.strictEqual((m.match(/<span class="pill f">Ticked<\/span>/g) || []).length, done);
  assert.ok(m.includes('<dd class="tn">' + done + ' of ' + (open + done) + ' ticked in the file</dd>'));
  assert.ok(m.includes('launch.json says <strong>' + JSON.parse(read('launch.json')).stage + '</strong>'));
  assert.match(m, /not a live status/);
  // A change to the source changes the page: the generator reads the files each time.
  const parsed = gen.parse('# T\n\n## S\n\n- [x] **a** `b`\n- [ ] c [d](RISKS.md)\n');
  assert.deepStrictEqual(parsed.sections[0].blocks[0].items.map((i) => i.box), [true, false]);
  assert.strictEqual(gen.inline('[d](RISKS.md) <x>'), '<a href="https://github.com/MyChiefOS/start-of-something-great/blob/main/RISKS.md">d</a> &lt;x&gt;');
  // Bold that holds a code span, as RELEASE-CHECKLIST.md writes "**`LAUNCH_STAGE` in Vercel**" (no stray asterisks).
  assert.strictEqual(gen.inline('**`A` b** and `c<d>`'), '<strong><code>A</code> b</strong> and <code>c&lt;d&gt;</code>');
  assert.ok(!m.includes('**'), 'no Markdown left on the page');
  for (const bad of ['[d](javascript:alert(1))', '[d](http://x.example)', '[d](//x.example)']) assert.ok(!gen.inline(bad).includes('<a'), 'no link that isn’t https or a repository file: ' + bad);
});

test('modules-b.css: tokens only, field borders at 3:1, 44 px targets under 820 px', () => {
  const css = read('modules-b.css');
  assert.ok(!/#[0-9a-f]{3,6}\b/i.test(css), 'no colours but the tokens');
  assert.ok(!/--[a-z-]+\s*:/.test(css), 'no new tokens');
  assert.match(css, /\.chip \{ min-height: 44px;/);
  assert.match(css, /@media \(max-width: 51\.24rem\) \{[\s\S]*\.tabs \[role="tab"\] \{ min-height: 44px; \}/);
  assert.match(css, /\.mod input\[type="search"\], \.mod input\[type="number"\], \.mod select \{[^}]*border: 1px solid var\(--rule-strong\)/);
});
