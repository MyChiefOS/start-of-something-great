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
  { file: 'rooms.html', path: '/rooms', h1: 'Rooms', h2: null, kicker: 'Agent Points' },
  { file: 'room.html', path: '/rooms/{code}', h1: 'Room', h2: ['Specialist leaderboard', 'Open projects'] },
  { file: 'projects.html', path: '/projects', h1: 'Projects', h2: ['When nothing matches'], kicker: 'Agent Points' },
  { file: 'project.html', path: '/projects/{id}', h1: 'Build Day One Great', h2: ['Complete this project'] },
  { file: 'disputes.html', path: '/disputes', h1: 'Disputes', h2: ['How a dispute works'], kicker: 'Proposed module' },
  { file: 'dispute.html', path: '/disputes/{id}', h1: 'No dispute here', h2: ['Evidence'] },
  { file: 'agents/join.html', path: '/agents/join', h1: 'Join as an agent', kicker: 'For agents',
    h2: ['1. Join', '2. Store your key, pass on the claim link', '3. Post for the person you act for', 'If you lose your key'] },
  { file: 'admin/console.html', path: '/admin/console', h1: 'Admin console', kicker: 'Agent Points',
    h2: ['Projects by status', 'Ledger integrity', 'Checkpoints', 'Activity log'] },
  { file: 'admin/go-live.html', path: '/admin/go-live', h1: 'Release checklist (SF6)', kicker: 'Go live',
    h2: ['Decisions', 'Accounts and settings', 'Legal', 'Go live'] }
];
const FILES = PAGES.map((p) => p.file);
const SCRIPTS = ['soc-rooms.js', 'rooms.js', 'room.js', 'projects.js', 'project.js', 'dispute.js', 'admin/console.js'];

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
    assert.match(html, /<link rel="stylesheet" href="\/styles\.css">\n(  <link rel="stylesheet" href="\/app\.css">\n)?  <link rel="stylesheet" href="\/design\.css">\n  <link rel="stylesheet" href="\/modules-b\.css">/, p.file + ': the site’s tokens, then design.css, then this group’s styles');
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
    if (p.kicker) assert.ok(m.indexOf('<p class="kicker">' + p.kicker + '</p>') >= 0 && m.indexOf('class="kicker"') < m.indexOf('<h1'), p.file + ': kicker above the h1');
    if (p.h2) {
      const h2 = [...m.matchAll(/<h2[^>]*>([^<]*)<\/h2>/g)].map((x) => x[1]).filter((t) => p.h2.includes(t));
      assert.deepStrictEqual(h2, p.h2, p.file + ': section headings in order');
    }
    let prev = 1;
    for (const h of m.matchAll(/<h([1-6])\b/g)) { const n = Number(h[1]); assert.ok(n <= prev + 1, p.file + ': h' + prev + ' then h' + n); prev = n; }
    for (const tag of ['<header class="site-header">', '<nav class="site-nav" aria-label="Main">', '<main id="main"', '<footer class="site-footer">']) assert.ok(read(p.file).includes(tag), p.file + ' has ' + tag);
    assert.match(read(p.file), /<body>\s*<a class="skip-link" href="#main">Skip to content<\/a>/, p.file);
  }
  // Detail pages say where they sit, one step back, above the heading (5.4).
  for (const [f, back] of [['room.html', '/rooms'], ['project.html', '/projects'], ['dispute.html', '/disputes']]) {
    const m = main(f);
    assert.match(m, new RegExp('<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="' + back + '">'), f);
    assert.ok(m.indexOf('class="crumbs"') < m.indexOf('<h1'), f + ': breadcrumbs above the heading');
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
  // Every page script beside its page is loaded by that page; the shared room list by the pages that read it.
  for (const [page, js] of [['rooms.html', 'rooms.js'], ['room.html', 'room.js'], ['projects.html', 'projects.js'], ['project.html', 'project.js'], ['dispute.html', 'dispute.js'], ['admin/console.html', 'admin/console.js']]) {
    assert.match(read(page), new RegExp('<script src="/' + js.replace('.', '\\.') + '" defer></script>'), page + ' loads ' + js);
  }
  assert.match(read('room.html'), /<script src="\/soc-rooms\.js" defer><\/script>\n  <script src="\/room\.js" defer><\/script>/, 'the room list loads before room.js');
});

test('no figure from the design’s sample set: no made-up person, agent, project, receipt, score, hash or time', () => {
  for (const f of FILES) {
    const m = main(f);
    for (const s of SAMPLES) assert.ok(!m.includes(s), f + ' shows the sample "' + s + '"');
  }
  for (const f of SCRIPTS) for (const s of SAMPLES.filter((x) => !x.startsWith('>'))) assert.ok(!read(f).includes(s), f + ' carries the sample "' + s + '"');
});

test('the Proposed notice stays where the module is not built, rewritten true; /agents/join, which is real, drops it', () => {
  for (const f of ['rooms.html', 'room.html', 'projects.html', 'project.html', 'disputes.html', 'dispute.html', 'admin/console.html']) {
    const m = main(f);
    assert.match(m, /^<main[^>]*>\s*<div class="notice"><b>Proposed\.<\/b> /, f + ': the notice comes first');
    assert.ok(!/It is not part of the live Day One Great site|There is no dispute page on the live site yet/.test(m), f + ': the design’s wording, which is no longer true, is gone');
    assert.match(m.match(/<div class="notice">[\s\S]*?<\/div>/)[0], /phase 5|phase 2/, f + ': says which phase it waits for');
  }
  assert.ok(!/<b>Proposed\.<\/b>/.test(main('agents/join.html')), '/agents/join describes the live registration');
  // Aaron's phase 5 decision (NOTES.md): audits by a JEVs-based auditor and Third Look, not members picked at random.
  for (const f of ['disputes.html', 'dispute.html', 'project.html']) assert.match(main(f), /JEVs-based auditor and (by )?Third Look/, f);
  for (const f of FILES) assert.ok(!/drand|public randomness|random-number/.test(main(f)), f + ': no randomly chosen auditors');
});

test('the 23 rooms are the SOC 2018 major groups, the same in soc-rooms.js, /rooms (cards and list) and the /projects filter', () => {
  const ctx = { window: {} };
  vm.runInNewContext(read('soc-rooms.js'), ctx);
  const rooms = JSON.parse(JSON.stringify(ctx.window.DOG_ROOMS)); // out of the script's own context, for deepStrictEqual
  assert.strictEqual(rooms.length, 23);
  assert.deepStrictEqual(rooms.map((r) => r[0]), ['11', '13', '15', '17', '19', '21', '23', '25', '27', '29', '31', '33', '35', '37', '39', '41', '43', '45', '47', '49', '51', '53', '55'].map((c) => c + '-0000'));
  const amp = (s) => s.replace(/&/g, '&amp;');
  const html = read('rooms.html');
  const cards = [...html.matchAll(/<a href="\/rooms\/([0-9-]+)"><div class="card"><span class="room-code">([0-9-]+)<\/span><h2>([^<]+)<\/h2>/g)].map((m) => [m[1], m[3]]);
  assert.deepStrictEqual(cards, rooms.map(([c, n]) => [c, amp(n)]), 'the All 23 cards');
  const list = [...html.match(/<ul class="room-list">[\s\S]*?<\/ul>/)[0].matchAll(/<a href="\/rooms\/([0-9-]+)">([^<]+)<\/a>/g)].map((m) => [m[1], m[2]]);
  assert.deepStrictEqual(list, rooms.map(([c, n]) => [c, amp(n)]), 'the folded list');
  assert.match(html, /<summary>23 rooms with no open tasks<\/summary>/, 'counted, not the design’s sample 17');
  const opts = [...read('projects.html').matchAll(/<option value="([0-9-]+)">\1 ([^<]+)<\/option>/g)].map((m) => [m[1], m[2]]);
  assert.deepStrictEqual(opts, rooms.map(([c, n]) => [c, amp(n)]), 'the room filter');
});

// A stand-in DOM, just enough for these scripts: elements by id, hidden, textContent, attributes and listeners.
function dom(ids, extra = {}) {
  const els = {};
  const make = (id) => {
    const e = { id, hidden: false, textContent: '', attrs: {}, on: {}, tabIndex: 0, children: [],
      setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; },
      addEventListener(t, f) { (this.on[t] = this.on[t] || []).push(f); }, appendChild(c) { this.children.push(c); return c; }, focus() { dom.focused = this; },
      querySelectorAll: () => [], querySelector: () => null };
    return e;
  };
  for (const id of ids) els[id] = make(id);
  Object.assign(els, extra);
  return { els, make, document: { getElementById: (id) => els[id] || null, createElement: () => make(''), createTextNode: (t) => ({ textContent: t }),
    querySelectorAll: () => [], title: '' } };
}
const settle = () => new Promise((r) => setImmediate(() => setImmediate(() => setImmediate(r))));

function runConsole(answers) {
  const tabIds = ['summary', 'agents', 'projects', 'submissions', 'ledger', 'admins'];
  const d = dom(['summary', 'admin', 'signed-out', 'not-allowed', 'stat-agents'].concat(tabIds.map((t) => 'panel-' + t)));
  const tabs = tabIds.map((t) => { const e = d.make('tab-' + t); e.attrs['aria-controls'] = 'panel-' + t; return e; });
  d.els.admin.hidden = true; d.els['signed-out'].hidden = true; d.els['not-allowed'].hidden = true;
  d.els.admin.querySelectorAll = (q) => (q === '[role="tab"]' ? tabs : []);
  const asked = [];
  const fetch = (u) => { asked.push(u); const [status, body] = answers[u] || [404, {}]; return Promise.resolve({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body) }); };
  vm.runInNewContext(read('admin/console.js'), { document: d.document, fetch, Date, Number, String, Array, Promise });
  return settle().then(() => ({ els: d.els, asked, tabs }));
}

test('/admin/console shows nothing of the console until the server says this is the administrator', async () => {
  const html = read('admin/console.html');
  assert.match(html, /<div id="admin" hidden>/, 'hidden in the HTML');
  assert.match(html, /<meta name="robots" content="noindex">/);
  assert.match(html, /<span class="num" id="stat-agents">…<\/span>/, 'the one live figure is empty until the answer fills it');
  const visitor = await runConsole({ '/auth/me': [200, { signed_in: false }] });
  assert.deepStrictEqual(visitor.asked, ['/auth/me'], 'a visitor is never sent to the administrator API');
  assert.strictEqual(visitor.els.admin.hidden, true);
  assert.strictEqual(visitor.els['signed-out'].hidden, false);
  const member = await runConsole({ '/auth/me': [200, { signed_in: true }], '/api/feed?controls=1': [403, { error: 'Only Aaron can see the owner controls.' }] });
  assert.deepStrictEqual(member.asked, ['/auth/me', '/api/feed?controls=1']);
  assert.strictEqual(member.els.admin.hidden, true, 'a member who isn’t the administrator sees none of it');
  assert.strictEqual(member.els['not-allowed'].hidden, false);
  assert.strictEqual(member.els['stat-agents'].textContent, '', 'and no figure');
  const expired = await runConsole({ '/auth/me': [200, { signed_in: true }], '/api/feed?controls=1': [401, {}] });
  assert.strictEqual(expired.els.admin.hidden, true);
  assert.strictEqual(expired.els['signed-out'].hidden, false);
  const off = await runConsole({ '/auth/me': [503, {}] });
  assert.strictEqual(off.els.admin.hidden, true, 'sign-in off: nothing shown');
  assert.match(off.els.summary.textContent, /Sign-in isn’t available right now/);
  const aaron = await runConsole({ '/auth/me': [200, { signed_in: true }], '/api/feed?controls=1': [200, { totals: { active_agents: 1234 } }] });
  assert.strictEqual(aaron.els.admin.hidden, false, 'the administrator sees the console');
  assert.strictEqual(aaron.els['stat-agents'].textContent, '1,234', 'the live agent count, from the answer');
  // Tabs: arrow keys move and show the next panel; Home and End go to the ends; one tab stop.
  const key = (t, k) => t.on.keydown[0]({ key: k, preventDefault() {} });
  key(aaron.tabs[0], 'ArrowRight');
  assert.strictEqual(aaron.tabs[1].attrs['aria-selected'], 'true');
  assert.strictEqual(aaron.els['panel-agents'].hidden, false);
  assert.strictEqual(aaron.els['panel-summary'].hidden, true);
  assert.deepStrictEqual(aaron.tabs.map((t) => t.tabIndex), [-1, 0, -1, -1, -1, -1]);
  key(aaron.tabs[1], 'End');
  assert.strictEqual(aaron.els['panel-admins'].hidden, false);
  key(aaron.tabs[5], 'ArrowRight');
  assert.strictEqual(aaron.els['panel-summary'].hidden, false, 'wraps round');
  key(aaron.tabs[0], 'ArrowLeft');
  assert.strictEqual(aaron.els['panel-admins'].hidden, false);
});

test('/admin/console: the tabs and panels are wired one to one, and the ledger shows the single public log', () => {
  const m = main('admin/console.html');
  const tabs = [...m.matchAll(/<button type="button" role="tab" id="tab-(\w+)" aria-controls="panel-(\w+)" aria-selected="(true|false)" tabindex="(0|-1)">([^<]+)<\/button>/g)];
  assert.deepStrictEqual(tabs.map((t) => t[5]), ['Summary', 'Agents', 'Projects', 'Submissions', 'Ledger', 'Admins'], 'the design’s tabs');
  for (const t of tabs) {
    assert.strictEqual(t[1], t[2]);
    assert.match(m, new RegExp('<div role="tabpanel" id="panel-' + t[1] + '" aria-labelledby="tab-' + t[1] + '" tabindex="0"' + (t[3] === 'true' ? '>' : ' hidden>')));
  }
  // README "Admin console": "in the new design show the single log: tree size, last checkpoint, witnesses, last
  // consistency check".
  for (const part of ['Tree size', 'Last checkpoint', 'Witnesses', 'Last consistency check']) assert.ok(m.includes('<td>' + part + '</td>'), part);
  assert.ok(!/hash chain per room<\/p>|<h2>Anchors<\/h2>/.test(m), 'not the per-room chains and anchors');
});

test('/projects: one real project, this site; the design’s default chip (Open) and the empty state say so', () => {
  const m = main('projects.html');
  const rows = [...m.matchAll(/<tr data-status="(\w+)" data-room="([0-9-]+)"[^>]*>/g)];
  assert.strictEqual(rows.length, 1, 'one project');
  assert.match(m, /<a href="\/projects\/day-one-great">Build Day One Great<\/a>/);
  assert.match(m, /<caption id="project-count">1 project: this site's own work/);
  for (const id of ['project-q', 'project-room']) assert.match(m, new RegExp('<label class="field-label" for="' + id + '">'), 'a visible label for #' + id);
  // Run projects.js in a stand-in DOM.
  const row = { hidden: false, attrs: { 'data-status': 'claimed', 'data-room': '15-0000', 'data-since': '2026-10-13', 'data-search': 'build day one great day-one-great' },
    getAttribute(k) { return this.attrs[k]; }, querySelector: () => age };
  const age = { textContent: 'Since Oct 13, 2026' };
  const chipEls = ['open', 'claimed', 'submitted', 'completed', 'all'].map((s) => ({ attrs: { 'data-status': s }, getAttribute(k) { return this.attrs[k]; }, setAttribute(k, v) { this.attrs[k] = v; } }));
  const d = dom(['project-q', 'project-room', 'status-chips', 'project-table', 'no-match-text']);
  d.els['status-chips'].querySelectorAll = () => chipEls;
  d.document.querySelectorAll = (q) => (q === '#project-rows tr' ? [row] : []);
  d.els['project-q'].value = '';
  d.els['project-room'].value = '';
  vm.runInNewContext(read('projects.js'), { document: d.document, Date: { parse: Date.parse, now: () => Date.parse('2026-11-05T12:00:00Z') }, Math, String, Array });
  assert.strictEqual(age.textContent, '23d', 'the age, in whole days');
  assert.strictEqual(d.els['status-chips'].hidden, false, 'the chips show once the script runs');
  assert.strictEqual(row.hidden, true, 'Open is the default, and this project is claimed');
  assert.strictEqual(d.els['project-table'].hidden, true);
  assert.match(d.els['no-match-text'].textContent, /^No open projects yet\. The one project here, this site, is claimed/);
  const click = (s) => d.els['status-chips'].on.click[0]({ target: { closest: () => chipEls.find((c) => c.attrs['data-status'] === s) } });
  click('all');
  assert.strictEqual(row.hidden, false);
  assert.strictEqual(d.els['project-table'].hidden, false);
  d.els['project-q'].value = 'tax';
  d.els['project-q'].on.input[0]();
  assert.strictEqual(row.hidden, true);
  assert.strictEqual(d.els['no-match-text'].textContent, 'No projects match “tax”.');
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
