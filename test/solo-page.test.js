'use strict';
// /solo, the SOLO design handoff (Nov 24, 2026): the design's copy word for word, the sign-up call as the live API takes
// it, the leaderboard's Wilson ranges, every section readable with JavaScript off, reduced motion, the site's rules
// (no inline style, script or handler) and the accessibility roles the handoff's README lists.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const shell = require('../scripts/shell');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const html = read('solo.html');
const css = read('css/solo.css');
const js = read('solo.js');
const main = html.match(/<main[\s\S]*?<\/main>/)[0];
const text = (s) => s.replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const load = () => { global.window = {}; delete require.cache[require.resolve('../solo.js')]; require('../solo.js'); const a = global.window.DOGSolo; delete global.window; return a; };
const solo = load();

test('the page is in the site\'s frame: the shell as scripts/shell.js writes it, design.css then its own sheet, nav.js and solo.js', () => {
  assert.strictEqual(shell.render('solo.html', html), html, 'run node scripts/shell.js');
  assert.ok(shell.pages().includes('solo.html'));
  assert.match(html, /<body>\n<div class="d1"><div class="wrap">\n<!-- shell:top -->\n<a class="skip" href="#main">Skip to content<\/a>/);
  assert.deepStrictEqual([...html.matchAll(/<link rel="stylesheet" href="([^"]+)">/g)].map((m) => m[1]), ['/design.css', '/css/solo.css']);
  assert.ok(html.includes('<script src="/nav.js" defer></script><script src="/solo.js" defer></script>'));
  assert.ok(html.includes('<link rel="canonical" href="https://dayonegreat.com/solo">'));
});

test('no inline style, no inline script, no on* handler, no outside font or script', () => {
  assert.ok(!/\sstyle\s*=/i.test(html), 'no style attribute');
  assert.ok(!/<style\b/i.test(html), 'no style element');
  assert.ok(!/\son[a-z]+\s*=/i.test(html.replace(/<meta[^>]*>/g, '')), 'no on* handler');
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
    assert.match(m[1], /\bsrc="\/[^"]+"/);
    assert.strictEqual(m[2].trim(), '');
  }
  assert.ok(!/fonts\.googleapis|fonts\.gstatic|JetBrains/.test(html + css), 'no Google Fonts, no unhosted font');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(js), 'text only');
  // Its one request is the shared status file; nothing else is fetched or sent.
  assert.deepStrictEqual([...js.matchAll(/fetch\(([^,)]+)/g)].map((m) => m[1].trim()), ["'/solo-status.json'"]);
  assert.ok(!/XMLHttpRequest|sendBeacon|WebSocket/.test(js));
});

test('one h1 (SOLO, its letters hidden from screen readers) and no heading level skipped', () => {
  assert.strictEqual((main.match(/<h1\b/g) || []).length, 1);
  assert.match(main, /<h1 id="solo-h" class="s-word" aria-label="SOLO"><span aria-hidden="true">S<\/span><span class="s-ring" aria-hidden="true"><\/span><span aria-hidden="true">L<\/span><span class="s-disc" id="solo-disc" aria-hidden="true">/);
  let prev = 1;
  for (const m of main.matchAll(/<h([1-6])\b/g)) { const n = Number(m[1]); assert.ok(n <= prev + 1, 'h' + prev + ' then h' + n); prev = n; }
});

test('the design\'s copy, word for word', () => {
  const t = text(main);
  for (const line of [
    'On Day One Great · First wave', 'Prove what your agent can do.',
    'Agent platforms help an agent do things. SOLO proves how well it does them. Put your agent to work, get it checked in public, and leave with a record that\'s yours.',
    'Sign-up, owner-free work, tasks, audits and the leaderboard are live today. The SOLO portfolio is coming soon.',
    'One call and your agent is in.', 'Proof, not promises.', 'Why a range, not just a percentage?',
    'A perfect score isn\'t the best record.', 'Arrive alone. Finish as a team.',
    'Live today: one call makes a sub-agent, with no human step. It\'s never allowed more than its parent, lasts 24 hours unless it asks (a week at most), goes at most three levels down, and a claim can be handed to it.',
    'Anyone can say their agent is good. Here, it gets checked.', 'node tools/verify/dog-verify.mjs <post id>',
    'From one call to a record worth sharing.', 'Every record starts blank.', 'Start tonight.',
    'We hold this page to the same standard as your agent.', 'The straight answers.',
    'The first SOLO agents are being written into the record.', 'Be one of them.', 'Follow SOLO on GitHub',
    'Early access runs through GitHub, so we never need your email address.',
    'Cards, crews and figures on this page are examples, not real agents or results.',
    'Day One Great is not affiliated with or endorsed by Anthropic.'
  ]) assert.ok(t.includes(line), 'missing: ' + line);
  // The three audiences: their labels, sub-lines, actions and checklists.
  for (const s of ['I build agents', 'I use an assistant', 'I\'m looking for an agent', 'Get your agent into SOLO', 'Connect your assistant', 'Browse the leaderboard',
    'Add dayonegreat.com/mcp as a custom connector in your assistant app', 'Share the receipt once the 72-hour window closes', 'Check the work that comes back']) assert.ok(t.includes(s), s);
  assert.deepStrictEqual([...main.matchAll(/<ul class="s-week" data-aud="(\w+)"[^>]*>([\s\S]*?)<\/ul>/g)].map((m) => [m[1], (m[2].match(/<li>/g) || []).length]), [['build', 7], ['assist', 6], ['hire', 6]]);
  assert.strictEqual((main.match(/<details class="s-q">/g) || []).length, 6, 'six questions');
  // Nothing suggests payment; every figure carries an example label.
  assert.ok(!/\b(earn|earning|payout|get paid|\$\d)/i.test(t), 'no payment wording');
  assert.match(main, /aria-label="Example SOLO portfolio card"/);
  assert.match(t, /Example · sample figures/);
  assert.match(t, /Example agents, sample figures\./);
});

test('the sign-up call is the live API\'s: POST /api/agents/register with {"name","description"}, answered 201 with key, recovery_key and claim_url', () => {
  assert.match(read('api/agents.js'), /POST \/api\/agents\/register {3}\{"name", "description"\?\}/);
  const reg = read('api/agents.js').match(/async 'POST register'[\s\S]*?return reply\(res, 201, \{([\s\S]*?)\}\);/)[1];
  for (const k of ['key: k.key', 'recovery_key: rk.key', 'claim_url:']) assert.ok(reg.includes(k), k);
  const curl = text(main.match(/<pre tabindex="0" aria-label="Sign-up request" id="solo-curl">([\s\S]*?)<\/pre>/)[1]);
  assert.strictEqual(curl, solo.CURL, 'the copied command is the one shown');
  assert.match(curl, /^curl -X POST https:\/\/dayonegreat\.com\/api\/agents\/register \\\n {2}-H "Content-Type: application\/json" \\\n {2}-d '\{"name": "relay_7", "description": "Fixes flaky tests"\}'$/);
  assert.ok(main.includes('{ "key": "…", "recovery_key": "dogr_…", "claim_url": "https://dayonegreat.com/…" }'));
  assert.ok(main.includes('201 Created · each key shown once'));
});

test('Wilson ranges are the leaderboard\'s (app.work_wilson, z = 1.96): 3/3 is 44–100%, 47/52 is 79–96%', () => {
  assert.match(read('db/migrations/045_leaderboard.sql'), /1\.96::float8 as z/);
  const pct = (k, n) => solo.wilson(k, n).map((x) => Math.round(x * 100));
  assert.deepStrictEqual(pct(3, 3), [44, 100]);
  assert.deepStrictEqual(pct(47, 52), [79, 96]);
  assert.deepStrictEqual(pct(5, 6), [44, 97]);
  // The SQL's own algebra, reproduced: sqrt((p(1-p) + z²/4n)/n).
  for (const [k, n] of [[1, 2], [5, 6], [47, 52], [0, 4]]) {
    const z = 1.96, p = k / n, lo = (p + z * z / (2 * n) - z * Math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / (1 + z * z / n);
    assert.ok(Math.abs(Math.max(0, lo) - solo.wilson(k, n)[0]) < 1e-12);
  }
  // The page's written figures and bar positions are the function's.
  assert.ok(main.includes('Likely range 44–100%') && main.includes('Likely range 79–96%') && main.includes('Likely range 44–97%. Provisional: under 10 audited tasks.'));
  assert.ok(main.includes('aria-label="quick_win: 100 percent, likely range 44 to 100 percent"'));
  assert.ok(main.includes('aria-label="steady_hand: 90 percent, likely range 79 to 96 percent"'));
  for (const [cls, k, n] of [['56', 5, 6], ['33', 3, 3], ['4752', 47, 52]]) {
    const [lo, hi] = solo.wilson(k, n);
    assert.ok(css.includes('.d1 .s-b' + cls + '{left:' + (lo * 100).toFixed(1) + '%;width:' + ((hi - lo) * 100).toFixed(1) + '%}'), 'band ' + cls);
    assert.ok(css.includes('.d1 .s-p' + cls + '{left:calc(' + (k / n * 100).toFixed(1) + '% - 1.5px)}'), 'marker ' + cls);
  }
  // The card's final state is what the script reaches at step 8.
  const c = solo.cardAt(8);
  assert.deepStrictEqual([c.pct, c.note, c.range], ['83%', 'pass rate · 5 of 6 checked tasks', 'Likely range 44–97%. Provisional: under 10 audited tasks.']);
  assert.ok(main.includes('>' + c.pct + '<') && main.includes('>' + c.note + '<'));
  assert.strictEqual(solo.cardAt(0).pct, '—');
});

test('with JavaScript off every section is written in its final state and no button shows', () => {
  // Each button is hidden itself, or sits in the hidden audience switch.
  const outside = main.replace(/<div class="s-aud"[^>]*hidden>[\s\S]*?<\/div>/, '');
  assert.strictEqual((main.match(/<button\b/g) || []).length - (outside.match(/<button\b/g) || []).length, 3);
  for (const m of outside.matchAll(/<button\b[^>]*>/g)) assert.match(m[0], /\shidden\b/, 'hidden until solo.js: ' + m[0]);
  assert.match(main, /<div class="s-aud" role="radiogroup" aria-label="I'm here as" hidden>/);
  // The card finished and claimed, the crew merged, the stamps as plain cards (solo.js makes them buttons).
  assert.ok(main.includes('<div class="s-stamp" id="solo-stamp">Claimed by @mira</div>'));
  assert.strictEqual((main.match(/<li class="s-(pass|fail|teamrow)">/g) || []).length, 7);
  assert.match(main, /<div class="s-done" id="solo-crew-done">/);
  assert.match(main, /<div class="s-whole" id="solo-crew-whole" hidden>/);
  assert.strictEqual((main.match(/<div class="s-st [^"]*" data-stamp="/g) || []).length, 6);
  // The builder's copy shows; the other audiences' wait.
  for (const m of main.matchAll(/<[a-z]+ [^>]*data-aud="(\w+)"[^>]*>/g)) assert.strictEqual(/\shidden\b/.test(m[0]), m[1] !== 'build', m[0]);
  assert.match(css, /\.d1 \.solo \[hidden\]\{display:none!important\}/);
});

test('reduced motion: spotlight still, check shown, card filled, crew merged', () => {
  const rm = css.match(/@media \(prefers-reduced-motion: reduce\)\{([\s\S]*?)\}\n/)[1];
  assert.match(rm, /transition:none!important;animation:none!important/);
  assert.match(rm, /\.s-disc\.s-pre\{transform:none\}/);
  assert.match(rm, /--sx:50%/);
  assert.match(css, /\.d1 \.s-hero\{--sx:50%/, 'static at 50% by default');
  assert.match(js, /if \(!reduced\(\)\) \{\n {4}disc\.classList\.add\('s-pre'\)/, 'the check is hidden only when motion is allowed');
  assert.match(js, /var crew = reduced\(\) \? 3 : 0/);
  assert.match(js, /if \(reduced\(\)\) \{ step = 8;/);
});

test('the roles and attributes the README lists', () => {
  assert.strictEqual((main.match(/role="radio" aria-checked="(true|false)"/g) || []).length, 3);
  assert.match(main, /<pre tabindex="0" aria-label="Sign-up request"/);
  assert.strictEqual((main.match(/<pre tabindex="0"/g) || []).length, 3, 'every code block focusable');
  assert.strictEqual((main.match(/role="status"/g) || []).length, 3, 'copy, card and checklist status lines');
  assert.match(main, /id="solo-claim" aria-pressed="true"/);
  assert.match(main, /class="s-card s-crew" id="solo-crew" aria-live="polite"/);
  assert.match(main, /class="s-passport" aria-live="polite"/);
  assert.match(main, /role="progressbar" id="solo-prog" aria-label="Checklist progress" aria-valuemin="0" aria-valuemax="7" aria-valuenow="0"/);
  assert.match(main, /aria-describedby="solo-name-hint" aria-invalid="false"/);
  for (const m of main.matchAll(/<div class="s-bar[^"]*" role="img"[^>]*>/g)) assert.match(m[0], /aria-label="[^"]+"/);
  assert.match(main, /<nav class="s-sub" aria-label="SOLO"><a href="#card">The portfolio<\/a><a href="#proof">Proof<\/a><a href="#status">Live and coming<\/a><a href="#faq">Questions<\/a><\/nav>/);
  assert.match(css, /\.d1 \.solo :focus-visible\{outline:2px solid var\(--amber\)/);
  assert.match(css, /@media \(pointer: coarse\)/);
  // Wired later by the integrator: a stable id and the data attribute.
  assert.match(main, /<article class="s-card s-pcard" id="solo-portfolio" data-agent="" data-sample="true"/);
  assert.match(js, /localStorage/);
  assert.match(js, /'solo\.week\.' \+ aud/);
  assert.match(js, /URLSearchParams\(location\.search\)\.get\('for'\)/);
});

test('the name rule and the share line', () => {
  assert.deepStrictEqual(solo.nameHint('relay_7'), { ok: true, bad: false, text: 'Looks like a valid agent name.' });
  assert.strictEqual(solo.nameHint('relay-7').text, 'Use _ instead of a dash.');
  assert.strictEqual(solo.nameHint('a b').text, 'Use 1 to 32 letters, numbers or _.');
  assert.strictEqual(solo.nameHint('x'.repeat(33)).bad, true);
  assert.strictEqual(solo.nameHint('').text, 'Type a name, 1 to 32 characters.');
  assert.strictEqual(solo.shareLine('relay_7'), 'relay_7 is stepping into SOLO on Day One Great: real work, checked in public. https://dayonegreat.com/connect?ref=solo-card');
  assert.match(solo.shareLine('bad-name'), /^My agent is stepping/);
});

test('the proof wall and Live and coming are solo-status.json\'s, word for word, with the README\'s statuses', () => {
  const s = JSON.parse(read('solo-status.json'));
  assert.deepStrictEqual(s.stamps.map((x) => [x.name, x.status]), [['JEVs', 'Enforcing'], ['Public log', 'Live'], ['Third Look', 'On'], ['Second Look', 'On'], ['A person', 'Live'], ['Agentic Wall', 'In shadow']]);
  for (const x of s.stamps) {
    assert.ok(main.includes('<span class="s-pill s-stp" data-status="' + x.id + '">' + x.status + '</span>'), x.id);
    assert.ok(main.includes('class="s-st s-' + x.kind + ' '), x.id + ' ' + x.kind);
  }
  for (const c of s.columns) {
    const col = main.match(new RegExp('<div class="s-col [^"]*" data-col="' + c.id + '"><h3>([^<]*)</h3><ul>([\\s\\S]*?)</ul>'));
    assert.ok(col, c.id);
    assert.strictEqual(col[1], c.title);
    assert.deepStrictEqual([...col[2].matchAll(/<li>([\s\S]*?)<\/li>/g)].map((m) => m[1]), c.items);
  }
  assert.deepStrictEqual(s.columns.map((c) => c.title), ['Live today', 'Running in shadow', 'Coming with SOLO', 'Not offered']);
});
