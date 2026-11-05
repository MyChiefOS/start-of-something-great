'use strict';
// The design handoff of Nov 5, 2026, module pages group A: /build, /leaderboard, /loops, /engine, /tasks/{id} (task.html,
// rewritten from /tasks/:id) and /citizens/{handle} (citizen.html, rewritten from /citizens/:handle). Each page is the
// design's static page, with every sample figure replaced by a real one from scripts/build-data.js or an honest empty
// state (Aaron, phase 6: "the first data is the project's own pull requests and work"; phase 7: generated before each
// commit). These tests fail if a page drifts from the shell or the generator, loses a heading, gains an inline style or
// script, or shows any of the design's sample figures.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const shell = require('../scripts/shell');
const gen = require('../scripts/build-data');
const main = (f) => read(f).match(/<main[\s\S]*?<\/main>/)[0];
const text = (h) => h.replace(/<!--[\s\S]*?-->/g, '').replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
const headings = (f) => [...main(f).matchAll(/<h([12])\b[^>]*>([\s\S]*?)<\/h\1>/g)].map((m) => 'h' + m[1] + ' ' + text(m[2]).trim());

const PAGES = {
  'build.html': { path: '/build', css: ['/modules.css', '/build.css'], headings: ['h1 Every proposal Aaron approves becomes work you can watch.', 'h2 Work packages', 'h2 Scope and verified work', 'h2 Who is doing what', 'h2 Four kinds of task', 'h2 Most recent'] },
  'leaderboard.html': { path: '/leaderboard', css: ['/modules.css', '/leaderboard.css'], headings: ['h1 People and AI agents, ranked on the same page.', 'h2 What counts, and what never does', 'h2 Rankings', 'h2 An auditor and a citizen'] },
  'loops.html': { path: '/loops', css: ['/modules.css', '/loops.css'], headings: ['h1 Five feedback loops. No output is the end.', 'h2 Execution and calibration', 'h2 Proposal to telemetry', 'h2 Dispute and anti-collusion', 'h2 Human-agent co-adaptation', 'h2 Public report to work order', 'h2 Each loop feeds the next'] },
  'engine.html': { path: '/engine', css: ['/modules.css', '/engine.css'], headings: ['h1 Trust engine', 'h2 Autonomy licenses', 'h2 Forecasts', 'h2 Precedents', 'h2 Upgrade certificates', 'h2 House model', 'h2 Work orders', 'h2 Immune system', 'h2 Signatures'] },
  'task.html': { path: '/tasks/{id}', css: ['/modules.css'], headings: ['h1 Task', 'h2 Rules that apply'] },
  'citizen.html': { path: '/citizens/{handle}', css: ['/modules.css', '/citizen.css'], headings: ['h1 Citizen profile', 'h2 Receipt chain', 'h2 Recent work'] }
};

// The design's sample set: invented people, agents, scores, receipts, blocks and counts (static/*.html, "Sample").
const SAMPLES = ['@mira', 'gpt-5.2', 'llama-4-maverick', 'claude-sonnet-4.6', 'AP-7841', 'R-99231', 'R-99230', 'R-98112', 'R-99224', 'R-99218', 'T-1012', 'T-1013', 'T-1014', 'T-1015', 'T-1016',
  '#48211', '#48210', 'season 14', 'Season 14', '9,412', '9,105', '8,866', '8,201', '7,540', '3,841', '1,904', 'median impact 612', '0.97 confidence', '0.94', '0.91', '140 verdicts', '2.2%',
  '63%', '83 tasks', '11 days', 'proposal #41', '041.', 'merkle.rs', 'edge_241.json', '0x9f3a', '0x77be', '44 of 44', 'M3 · 86%', 'Spend 62%', 'progress 38%', '200 passed', 'Certificate issued',
  'Pass, 95%', 'Level −1', 'Code review', 'Data entry', 'Contract summary', 'WP-041', 'Rank 2', '10:42:07', 'Sample.'];

for (const [f, spec] of Object.entries(PAGES)) {
  test(f + ' (' + spec.path + '): the shell, the stylesheets, the design’s headings in order', () => {
    const html = read(f);
    assert.ok(shell.pages().includes(f), f + ' is a shell page');
    assert.strictEqual(shell.render(f, html), html, f + ' carries the shell exactly');
    assert.match(html, /<link rel="stylesheet" href="\/styles\.css">\n  <link rel="stylesheet" href="\/design\.css">\n/, f + ': styles.css, then design.css');
    for (const css of spec.css) assert.ok(html.includes('<link rel="stylesheet" href="' + css + '">') && fs.existsSync(path.join(root, css.slice(1))), f + ' loads ' + css);
    assert.match(html, new RegExp('<title>[^<]+: Day One Great</title>'));
    if (!spec.path.includes('{')) assert.ok(html.includes('<link rel="canonical" href="https://dayonegreat.com' + spec.path + '">'), f + ': its canonical path');
    assert.deepStrictEqual(headings(f), spec.headings);
    assert.match(main(f), /^<main id="main" class="(dash|story) [a-z]+" tabindex="-1">\s*<p class="notice"><b>Proposed\.<\/b> /, f + ': the Proposed notice first');
  });

  test(f + ': no inline style, no inline script, no on* handler, scripts only from our own files', () => {
    const html = read(f);
    assert.ok(!/\sstyle=/.test(html), 'no style attribute');
    assert.ok(!/<style\b/.test(html), 'no style element');
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      assert.match(m[1], /\bsrc="\/[^"]+"/, 'every script has a src on this site');
      assert.strictEqual(m[2].trim(), '', 'and no inline code');
    }
    assert.ok(!/\son[a-z]+=/i.test(html), 'no on* handlers');
  });

  test(f + ': shows none of the design’s sample figures', () => {
    const t = text(main(f));
    for (const s of SAMPLES) assert.ok(!t.includes(s), f + ' shows the sample figure ' + JSON.stringify(s));
  });
}

test('the page scripts write text only and ask nothing of the network', () => {
  for (const f of ['leaderboard.js', 'engine.js', 'task.js', 'citizen.js']) {
    const js = read(f);
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(js), f + ': text only');
    assert.ok(!/fetch\(|XMLHttpRequest|WebSocket|sendBeacon/.test(js), f + ': no requests');
  }
  assert.match(read('work-data.js'), /^\/\/ Written by scripts\/build-data\.js[^\n]*\nwindow\.DOG_WORK = Object\.freeze\(\{[\s\S]*\}\);\n$/, 'the data file only sets window.DOG_WORK');
  // The detail pages read their id from the path the rewrites give them.
  assert.match(read('task.js'), /location\.pathname\.match\(\/\^\\\/tasks\\\/\(\\d\{1,2\}-\\d\{1,3\}\)\\\/\?\$\/\)/);
  assert.match(read('citizen.js'), /location\.pathname\.match\(\/\^\\\/citizens\\\/\(\[a-z0-9-\]\{1,40\}\)\\\/\?\$\/\)/);
  for (const f of ['task.html', 'citizen.html']) assert.match(read(f), /<script src="\/work-data\.js" defer><\/script>\n  <script src="\/[a-z]+\.js" defer><\/script>/, f + ': the data before the page script');
  assert.ok(read('engine.html').includes('role="tablist"') && /ArrowRight[\s\S]*ArrowLeft[\s\S]*Home[\s\S]*End/.test(read('engine.js')), 'the engine tabs: arrow keys, Home and End');
});

test('the generator: the committed pages and data match what it makes from the recorded as-of merge', () => {
  const r = spawnSync(process.execPath, [path.join(root, 'scripts', 'build-data.js'), '--check'], { cwd: root, encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  const d = JSON.parse(read('work.json'));
  const fresh = gen.outputs(root, gen.collect(root, d.as_of.commit));
  for (const [f, body] of Object.entries(fresh)) assert.strictEqual(read(f), body, f);
});

test('the generator’s --check fails, naming the file, when a generated block is edited by hand', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'build-data-'));
  try {
    execFileSync('git', ['clone', '--quiet', '--shared', '--no-checkout', root, tmp]);
    // The clone's HEAD is the source's current branch; the as-of merge must be in its history.
    execFileSync('git', ['-C', tmp, 'reset', '--quiet', execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()]);
    for (const f of ['work.json', 'work-data.js', 'build.html', 'leaderboard.html', 'harness/PLAN.md', 'ROADMAP.md']) {
      fs.mkdirSync(path.dirname(path.join(tmp, f)), { recursive: true });
      fs.copyFileSync(path.join(root, f), path.join(tmp, f));
    }
    assert.deepStrictEqual(gen.run(tmp, true).ok, true, 'a faithful copy passes');
    const b = fs.readFileSync(path.join(tmp, 'build.html'), 'utf8');
    fs.writeFileSync(path.join(tmp, 'build.html'), b.replace(/(<!-- work:progress -->[\s\S]*?<span class="num">)\d+%/, '$163%'));
    const r = gen.run(tmp, true);
    assert.strictEqual(r.ok, false);
    assert.match(r.message, /differ[^:]*: build\.html\b/);
    // And a changed plan is caught too: the pages come from harness/PLAN.md.
    fs.copyFileSync(path.join(root, 'build.html'), path.join(tmp, 'build.html'));
    fs.appendFileSync(path.join(tmp, 'harness/PLAN.md'), '');
    const plan = fs.readFileSync(path.join(tmp, 'harness/PLAN.md'), 'utf8');
    fs.writeFileSync(path.join(tmp, 'harness/PLAN.md'), plan.replace('Merkle log, signed checkpoints', 'Merkle log, signed checkpoints, witnesses'));
    assert.strictEqual(gen.run(tmp, true).ok, false, 'a new task in the plan needs the pages regenerated');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('the generator counts only what git and the plan hold: two citizens, every merge Aaron’s, every commit marked Claude’s', () => {
  const d = JSON.parse(read('work.json'));
  const merges = execFileSync('git', ['log', '--merges', '--format=%s%x00%an', d.as_of.commit], { cwd: root, encoding: 'utf8' }).split('\n').filter((l) => /^Merge pull request #\d+ from /.test(l));
  assert.strictEqual(d.totals.prs, merges.length, 'one entry per merged pull request');
  assert.strictEqual(d.citizens.aaron.sign_offs, merges.filter((l) => l.endsWith('\0Aaron Chandler')).length, 'sign-offs are the merges he made');
  assert.deepStrictEqual(Object.keys(d.citizens).sort(), ['aaron', 'claude'], 'no invented people');
  assert.strictEqual(d.citizens.claude.merged, d.prs.filter((p) => p.claude_commits > 0).length);
  assert.strictEqual(d.citizens.aaron.merged, 0, 'he authored no commit without Claude’s marks');
  // The leaderboard has no rank column and no rank anywhere; every row shows its sample size.
  const lb = main('leaderboard.html');
  assert.ok(!/<th scope="col">#<\/th>/.test(lb), 'no rank column');
  assert.match(lb, /<th scope="col">Band<\/th>[\s\S]*<th scope="col">Sample<\/th>/);
  assert.strictEqual((lb.match(/<tr data-type=/g) || []).length, 2, 'two rows');
  for (const row of lb.match(/<tr data-type=[\s\S]*?<\/tr>/g)) {
    assert.match(row, /Not enough history yet \(0\)/, 'calibration under 20 items says so');
    assert.match(row, /<td class="tn">\d[\d,]* pull requests<\/td><\/tr>$/, 'a sample size');
  }
  assert.match(lb, /Reverted<\/dt><dd class="tn">0 of \d+ merged pull requests \(0%; 95% interval 0% to [\d.]+%\), public<\/dd>/, 'the revert rate with its sample and interval');
  // Build: the tasks are the plan's, the merged ones are pull requests titled for their phase.
  const plan = read('harness/PLAN.md');
  for (const t of Object.values(d.tasks)) {
    if (t.pr) assert.ok(d.prs.some((p) => p.number === t.pr && /^Design handoff phase \d/.test(p.title)), t.id);
    else assert.ok(plan.toLowerCase().includes(t.title.toLowerCase()), t.id + ' "' + t.title + '" is in harness/PLAN.md');
  }
  assert.strictEqual(d.packages.length, 8, 'the handoff’s eight phases');
  // task.js finds a task's package by strict equality (Nov 5: a number against a string stopped every task page).
  const slimData = JSON.parse(read('work-data.js').match(/Object\.freeze\(([\s\S]*)\);\n$/)[1]);
  for (const t of Object.values(slimData.tasks)) {
    assert.strictEqual(slimData.packages.filter((p) => p.id === t.package).length, 1, t.id + ': its package is found');
    if (t.pr) assert.ok(slimData.prs.some((p) => p.number === t.pr), t.id + ': its pull request is in work-data.js');
  }
  for (const c of Object.values(slimData.citizens)) for (const num of c.recent.concat([c.first, c.last])) assert.ok(slimData.prs.some((p) => p.number === num), c.handle + ': #' + num + ' is in work-data.js');
});

test('the generator’s rules, on small examples', () => {
  assert.ok(gen.isClaude('noreply@anthropic.com', ''));
  assert.ok(gen.isClaude('aibizprojectx@gmail.com', 'x\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'));
  assert.ok(gen.isClaude('aibizprojectx@gmail.com', 'x\n\nClaude-Session: https://claude.ai/code/session_x'));
  assert.ok(!gen.isClaude('aibizprojectx@gmail.com', 'Initial commit'), 'no mark, not Claude’s');
  const w = gen.wilson(0, 86);
  assert.strictEqual(w.lo, 0);
  assert.ok(Math.abs(w.hi - 0.04276) < 1e-4, 'Wilson 95% upper bound for 0 of 86');
  assert.ok(Math.abs(gen.wilson(5, 20).lo - 0.1119) < 1e-3 && Math.abs(gen.wilson(5, 20).hi - 0.4687) < 1e-3);
  assert.strictEqual(gen.wilson(0, 0), null);
  assert.strictEqual(gen.streak(['2026-11-05T12:00:00Z', '2026-11-04T01:00:00Z', '2026-11-02T00:00:00Z'], '2026-11-05T20:00:00Z'), 2);
  assert.deepStrictEqual(gen.splitList('a (b, c), d', ','), ['a', 'd']);
  const p = gen.readPlan('### The design handoff (Aaron, Nov 5: "Go.").\n\n1. **One** (spec 1): x, y (z, w), v. More.\n2. **Two** (spec 2). 3. Three things; four. 4. A. 5. B. 6. C. 7. D. 8. E, F.\n\n## Next');
  assert.strictEqual(p.quote, 'Go.');
  assert.deepStrictEqual(p.phases.map((x) => x.tasks), [['X', 'Y', 'V'], ['Two'], ['Three things', 'Four'], ['A'], ['B'], ['C'], ['D'], ['E', 'F']]);
  assert.strictEqual(p.phases[0].note, 'More.');
  assert.throws(() => gen.readPlan('### The design handoff (Aaron, Nov 5: "Go.").\n\n1. **One**.\n'), /8 phases/);
  const r = gen.readRoadmap('| Milestone | Target | Actual | Result | Depends on |\n|---|---|---|---|---|\n| A | Oct 13 | Oct 14 | ✅ Done | |\n| B | Not set yet (added Oct 17) | | Merged | |\n| C | Fri, Nov 6 | | Dropped Oct 24 | |\n| D | Fri, Nov 20 | | In progress | |\n| E | Oct 21 | | ❌ Missed | |\n');
  assert.deepStrictEqual(r.map((x) => [x.target_date, x.done_date, x.state]), [['2026-10-13', '2026-10-14', 'Done'], [null, null, 'Built, not proven'], ['2026-11-06', null, 'Dropped'], ['2026-11-20', null, 'In progress'], ['2026-10-21', null, 'Missed']]);
  assert.deepStrictEqual(gen.readNotes('| Phase 3, key-file derivation (3) | Not decided: waits |\n| Phase 8, outside tests | On hold |'), { 3: 'Not decided: waits', 8: 'On hold' });
});
