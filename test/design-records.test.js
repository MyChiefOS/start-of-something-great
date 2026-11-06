// The records pages of the design handoff of Nov 5, 2026 (Aaron: "Please implement the design and details I
// provided"; CODING_AGENT_SPEC.md sections 1.5, 2.5, 5 and 6): /decisions, /receipts, a receipt, the rate-limited
// error and the 404. Per page: it is at its path, carries the shell, has the design's h1 and section headings in order,
// no inline style or script, no figure from the design's sample set; and each page's script, run, shows real data or
// an honest empty state, writes text only and asks only our own /api.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { El, parseMain } = require('./helpers/mini-dom');
const shell = require('../scripts/shell');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const mainOf = (f) => read(f).match(/<main[\s\S]*?<\/main>/)[0];
const strip = (s) => s.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();

// file, its address (cleanUrls: x.html is /x), the h1, the h2s in order, its own script and stylesheet (the design's
// inline styles that only this page uses, as classes in /css/<page>.css: tools/design/build.js).
// The page between the shell's markers: the design draws a page's notice just above its <main>.
const bodyOf = (f) => read(f).match(/<!-- \/shell:top -->([\s\S]*?)<!-- shell:foot -->/)[1];
const PAGES = [
  { file: 'decisions.html', path: '/decisions', h1: 'JEVs decisions', h2: ['Last 24 hours', 'Latest high-risk decisions', 'Second Look', 'Human oversight'], js: 'decisions.js', css: 'css/decisions.css' },
  { file: 'receipts.html', path: '/receipts', h1: 'Receipts', h2: ['Verify a receipt', 'Recent', 'The log now', 'What a receipt shows', 'What else is in the log'], js: 'receipts.js', css: 'css/receipts.css' },
  { file: 'receipt.html', path: '/receipt', h1: 'Receipt', h2: ['Agent post', 'Proposed: execution receipts'], js: 'receipt.js', css: 'css/receipt.css' },
  { file: 'errors/rate-limited.html', path: '/errors/rate-limited', h1: 'Slow down for a moment', h2: ['If something else went wrong'], js: 'errors/rate-limited.js', css: null },
  { file: '404.html', path: null, h1: 'This page doesn’t exist', h2: [], js: null, css: null }
];

// Every figure, name and identifier the design invented for these five pages (static/decisions.html, receipts.html,
// receipt.html, error.html): none may appear as if it were real.
const SAMPLES = ['Sample figures', '63 of 80', '>31<', '>3<', '>4<', '>2<', '2h ago', '5h ago', 'J04 burst', 'J17 impersonation', 'J16 hidden instructions',
  'R-99231', 'P-48211', 'P-48207', 'R-99230', 'claude-sonnet-4.6', 'gpt-5.2-auditor', 'claude_helper', 'build_scribe', '@mira', '@jordan_k', '@aaron',
  'Today, 10:42', 'version 3', 'T-1012', 'scaffold verifier', 'AP-7841', '+412', '0x9f3a', 'c21d', '44 of 44', '+3.2%', '0.97', '0x77be', '#48211',
  'Layer 2', '38 seconds', 'err_8f31c2', 'Anchored'];

test('each page is at its address, carries the shell exactly as scripts/shell.js writes it, and has the design’s headings in order', () => {
  for (const p of PAGES) {
    assert.ok(fs.existsSync(path.join(root, p.file)), p.file);
    const html = read(p.file);
    assert.strictEqual(shell.render(p.file, html), html, p.file + ' differs from the shell: run node scripts/shell.js');
    const main = mainOf(p.file);
    const h1 = [...main.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1>/g)].map((m) => strip(m[1]).replace(/'/g, '’'));
    assert.deepStrictEqual(h1, [p.h1], p.file + ': one h1');
    assert.deepStrictEqual([...main.matchAll(/<h2\b[^>]*>([\s\S]*?)<\/h2>/g)].map((m) => strip(m[1])), p.h2, p.file + ': the sections, in the design’s order');
    // No level skipped: each heading is at most one level below the one before it (the design puts h3 in its cards).
    let level = 1;
    for (const m of main.matchAll(/<h([1-6])\b/g)) { assert.ok(Number(m[1]) <= level + 1, p.file + ': h' + m[1] + ' after h' + level); level = Number(m[1]); }
    assert.match(main, /^<main(?: class="story[^"]*")? id="main" tabindex="-1">/, p.file + ': the design\'s main, focusable for the skip link');
    assert.match(html, /<body>\s*<div class="d1"><div class="wrap">\s*<!-- shell:top -->\s*<a class="skip" href="#main">Skip to content<\/a>/);
    const title = html.match(/<title>([^<]+)<\/title>/)[1];
    assert.ok(title.endsWith(': Day One Great'), p.file + ': title is "<Heading>: Day One Great"');
    if (p.path) assert.ok(shell.exists(p.path) || p.path.startsWith('/errors/'), p.path);
  }
  assert.ok(fs.existsSync(path.join(root, 'errors', 'rate-limited.html')), '/errors/rate-limited is served from errors/rate-limited.html');
});

test('the security policy holds: no inline style, no inline script, no on* handlers; scripts and styles are our own files', () => {
  for (const p of PAGES) {
    const html = read(p.file);
    assert.ok(!/\sstyle\s*=/.test(html), p.file + ': no style=""');
    assert.ok(!/<style\b/.test(html), p.file + ': no <style>');
    assert.ok(!/\son[a-z]+\s*=/i.test(html), p.file + ': no on*= handler');
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      assert.match(m[1], /\bsrc="\/[^"]+"/, p.file + ': every script has a src on this site');
      assert.strictEqual(m[2].trim(), '', p.file + ': no inline script');
    }
    if (p.js) assert.ok(new RegExp('<script defer src="/' + p.js.replace(/[./]/g, '\\$&') + '"></script>').test(html), p.file + ' loads ' + p.js);
    if (p.css) {
      assert.ok(html.includes('<link rel="stylesheet" href="/' + p.css + '">'), p.file + ' loads ' + p.css);
      assert.ok(html.indexOf('href="/design.css"') < html.indexOf('href="/' + p.css + '"'), 'design.css, then the page’s own');
      const css = read(p.css);
      assert.ok(!/#[0-9a-f]{3,8}\b|rgba?\(/i.test(css), p.css + ': the site’s own colour tokens only');
    }
  }
  // The 404 runs no script (pages-load keeps it so); it keeps the Menu, a <details>.
  assert.ok(!/<script/.test(read('404.html')));
  for (const js of PAGES.map((p) => p.js).filter(Boolean)) {
    const s = read(js);
    assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function|\.style\b|setAttribute\('style'/.test(s), js + ': text and classes only');
    for (const m of s.matchAll(/fetch\(([^,)]+)/g)) assert.match(m[1].trim(), /^('\/api\/|url$|next \|\| first$)/, js + ' fetches only our own /api: ' + m[1]);
  }
});

test('no figure from the design’s sample set is shown as real; the "Proposed" notices say what is real today', () => {
  for (const p of PAGES) {
    const main = mainOf(p.file);
    for (const s of SAMPLES) assert.ok(!main.includes(s), p.file + ' shows the design’s sample "' + s + '"');
  }
  for (const js of ['decisions.js', 'receipts.js', 'receipt.js', 'errors/rate-limited.js']) {
    for (const s of ['63 of 80', 'R-99231', 'P-48211', 'claude_helper', '@mira', 'err_8f31c2', 'T-1012']) assert.ok(!read(js).includes(s), js + ': ' + s);
  }
  const dec = bodyOf('decisions.html');
  assert.ok(!dec.includes('administrator only'), 'the counts are public now');
  assert.match(dec, /<b class="x[0-9a-f]{8}">Proposed\.<\/b> These numbers are live and public, as counts and question IDs only\./);
  assert.match(dec, /<span class="pill m">Live counts<\/span>/);
  // The public log is built (038): the receipts are checked against it in the browser, so no "Proposed" notice says
  // otherwise; what is checked is said step by step (the Verify checklist).
  const rec = bodyOf('receipts.html');
  assert.ok(!/nothing here is signed or witnessed yet|comes with the public log \(phase 2\)/.test(rec), 'no notice that the log is still to come');
  assert.match(rec, /<h2 id="verify-heading">Verify a receipt<\/h2>/);
  // Nothing claims to be secure or audited (5.7); "Verified" is said only as a check's result, on the pages that run it.
  for (const p of PAGES) {
    const words = strip(mainOf(p.file)).replace(/an independent audit/g, '');
    assert.ok(!/\b(secure|audited)\b/i.test(words), p.file);
    if (!['receipts.html', 'receipt.html'].includes(p.file)) assert.ok(!/\bverified\b/i.test(words), p.file);
  }
  // The receipt's execution card was all sample figures: an honest empty state instead.
  assert.match(mainOf('receipt.html'), /<div class="empty">No execution receipts yet\./);
});

test('the GitHub gate’s own question titles (J16, J17) are the gate’s, so /api/decisions names them as the gate does', async () => {
  const core = await import(path.join(root, 'supabase/functions/jevs/core.mjs'));
  const { GATE_ONLY, titles } = require('../db/decisions');
  for (const [id, title] of Object.entries(GATE_ONLY)) assert.strictEqual(core.QUESTIONS.find((q) => q.id === id).title, title, id);
  const site = require('../db/jevs').publicQuestions().map((q) => q.id);
  for (const id of Object.keys(GATE_ONLY)) assert.ok(!site.includes(id), id + ' is the gate’s only');
  assert.strictEqual(titles().J07, 'Links and new domains');
});

// ---- /api/decisions, without a database ----
function res() {
  const r = { statusCode: 200, headers: {}, body: '' };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.end = (b) => { r.body = b || ''; };
  return r;
}
async function api(url, run, method = 'GET', headers = {}) {
  const r = res();
  await require('../api/decisions').handle({ method, url, headers }, r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null, headers: r.headers };
}
test('/api/decisions: read-only, no parameters (so the edge cache can’t be skipped), cached a minute, and says so when there is no database', async () => {
  const off = await api('/api/decisions', null);
  assert.deepStrictEqual([off.status, off.json.available], [200, false]);
  assert.match(off.headers['cache-control'], /^public, s-maxage=60, stale-while-revalidate=60$/);
  const param = await api('/api/decisions?x=1', () => assert.fail('the database is not asked'));
  assert.strictEqual(param.status, 400);
  // The edge doesn't cache a request with an Authorization header, so one is refused too (the review, finding 3).
  assert.strictEqual((await api('/api/decisions', () => assert.fail('the database is not asked'), 'GET', { authorization: 'x' })).status, 400);
  assert.strictEqual((await api('/api/decisions', null, 'POST')).status, 405);
  require('../api/decisions')._forget();
  let ctx = null;
  const fake = { generated_at: '2026-11-05T12:00:00Z', jevs_mode: 'enforce', last_24h: { decisions: '7', low: 4, medium_waiting: 1, high: 2, high_held: 2, appeals_open: 0 },
    high_7d: [{ day: '2026-11-05', place: 'github_post', outcome: 'hidden', decisions: 1, questions: ['J16', 'not an id', 'region'] }],
    second_look: { mode: 'shadow', paused: false, agreed_in_a_row: 12, needed: 80, daily_clear_cap: 10, shadow_clears_decided: 12, shadow_clears_removed: 0 },
    oversight: { people: { d7: { decided: 3 }, d30: { decided: 3, approved: 2, removed: 1, undone: 0, median_minutes: 12.5 } }, queue: { open: 1, median_hours: 2, oldest_hours: 2 } } };
  const on = await api('/api/decisions', async (c, fn) => { ctx = c; return fn(async () => [{ d: fake }]); });
  assert.deepStrictEqual(ctx, { actor: 'anon' }, 'asked as a visitor');
  assert.strictEqual(on.status, 200);
  assert.strictEqual(on.json.last_24h.decisions, 7, 'numbers are numbers');
  assert.deepStrictEqual(on.json.high_7d[0].questions, ['J16', 'region'], 'only question IDs pass');
  // A count the database keeps back (1 to 4, 036's k) stays null: "fewer than 5", never a 0.
  assert.deepStrictEqual(on.json.oversight.people.d7, { decided: 3, approved: null, removed: null, undone: null, median_minutes: null });
  assert.strictEqual(on.json.min_sample, 20);
  // This copy keeps its answer a minute: a second visit doesn't ask the database.
  const again = await api('/api/decisions', () => assert.fail('the database is not asked again within the minute'));
  assert.strictEqual(again.status, 200);
  require('../api/decisions')._forget();
  const early = await api('/api/decisions', async () => { throw Object.assign(new Error('no function'), { code: '42883' }); });
  assert.deepStrictEqual([early.status, early.headers['cache-control']], [503, 'no-store'], 'before 036 is applied: not cached');
  assert.match(read('api/index.js'), /decisions: SITE \+ '\/api\/decisions'/, 'listed with the public API');
});

// ---- The page scripts, run on their own <main> ----
// receipt.js has always read the dl's last child (PR 7); the shared stand-in DOM has firstChild only.
if (!Object.getOwnPropertyDescriptor(El.prototype, 'lastChild')) {
  Object.defineProperty(El.prototype, 'lastChild', { get() { return this.children[this.children.length - 1] || null; } });
}
function load(file, script, answers, { search = '', pathname, worker = null, storage = null } = {}) {
  const doc = { focused: null };
  const main = parseMain(read(file), doc);
  const asked = [];
  const location = { hash: '', search, pathname: pathname || '/' + file.replace(/\.html$/, ''), href: null };
  Object.assign(doc, {
    getElementById: (id) => main.all().find((e) => e.id === id) || null,
    createElement: (t) => new El(t, doc),
    createTextNode: (t) => { const n = new El('#text', doc); n._text = String(t); return n; }
  });
  const timers = [];
  const sandbox = { document: doc, location, history: { length: 1, back() {} }, URLSearchParams, Intl, Date, Math, JSON, Promise, Object, String, Number,
    encodeURIComponent, decodeURIComponent,
    setInterval: (f) => { timers.push(f); return timers.length; }, clearInterval() {},
    // The Verify page's worker (verifier/worker.js), answered by the test: worker(message, reply).
    ...(worker ? { Worker: class { constructor(url, opts) { this.url = url; this.opts = opts; (sandboxWorkers.list = sandboxWorkers.list || []).push(this); }
      postMessage(m) { setImmediate(() => worker(m, (r) => this.onmessage({ data: { id: m.id, ...r } }), this)); } terminate() { this.ended = true; } } } : {}),
    ...(storage ? { localStorage: storage } : {}),
    fetch: (url) => {
      asked.push(url);
      const [status, body] = answers(url);
      return Promise.resolve({ ok: status >= 200 && status < 300, status, headers: { get: (h) => (h === 'x-vercel-id' ? 'iad1::test-ref' : null) }, json: () => Promise.resolve(body) });
    } };
  const sandboxWorkers = {};
  vm.runInNewContext(read(script), sandbox);
  return { $: doc.getElementById, asked, location, timers, main, workers: sandboxWorkers };
}
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
const text = (e) => e.textContent.replace(/\s+/g, ' ').trim();

const DAY = (over = {}) => ({ available: true, min_sample: 20, generated_at: new Date().toISOString(), jevs_mode: 'enforce',
  last_24h: { decisions: 9, low: 5, medium_waiting: 1, high: 3, high_held: 2, appeals_open: 1 },
  high_7d: [{ day: '2026-11-04', place: 'github_post', outcome: 'hidden', decisions: 1, questions: ['J16'] },
    { day: '2026-11-04', place: 'site_post', outcome: 'held', decisions: 2, questions: ['J07', 'J08'] },
    { day: '2026-11-03', place: 'signup', outcome: 'declined', decisions: 3, questions: ['region'] }],
  second_look: { mode: 'shadow', paused: false, agreed_in_a_row: 12, needed: 80, daily_clear_cap: 10, shadow_clears_decided: 14, shadow_clears_removed: 1 },
  oversight: { people: { d7: { decided: 3, approved: 2, removed: 1, undone: 0, median_minutes: 12 }, d30: { decided: 25, approved: 20, removed: 4, undone: 1, median_minutes: 95 } },
    queue: { open: 2, median_hours: 3, oldest_hours: 5 } },
  questions: { J07: 'Links and new domains', J08: 'Contact details', J16: 'Hidden instructions' }, ...over });

test('/decisions, run: the four counts, the 7-day rows in words, Second Look’s progress, and rates only from 20 decisions', async () => {
  const p = load('decisions.html', 'decisions.js', () => [200, DAY()]);
  await settle();
  assert.deepStrictEqual(p.asked, ['/api/decisions']);
  assert.deepStrictEqual(['n-low', 'n-medium', 'n-high', 'n-appeals'].map((id) => text(p.$(id))), ['5', '1', '2', '1']);
  assert.match(text(p.$('day-note')), /^Site and GitHub together: 9 decisions in all\. 1 more scored high risk without a hold or a hide/);
  const rows = p.$('high').children.map((tr) => tr.children.map(text));
  assert.deepStrictEqual(rows.map((r) => r.slice(1)), [['GitHub post', 'J16 hidden instructions', 'Hidden, reason sent', '1'],
    ['Site post', 'J07 links and new domains, J08 contact details', 'Held for Aaron', '2'], ['Sign-up', 'Region', 'Declined politely', '3']]);
  assert.match(rows[0][0], /Nov|4/, 'the day, in words');
  assert.strictEqual(p.$('high-empty').hidden, true);
  assert.strictEqual(text(p.$('sl-mode')), 'Shadow mode');
  assert.strictEqual(text(p.$('sl-agree')), '12 of 80');
  // The design's track: a progressbar with its figures, its fill a design.css width (12 of 80 is 15%).
  assert.deepStrictEqual([p.$('sl-track').getAttribute('aria-valuenow'), p.$('sl-track').getAttribute('aria-valuemax'), p.$('sl-bar').className], ['12', '80', 'w15']);
  assert.match(text(p.$('sl-text')), /after Aaron agrees with its last 80 decisions\.$/);
  assert.match(text(p.$('sl-fine')), /^Agreement so far\. At most 10 easy posts a day once on\. It pauses itself if Aaron removes more than 1 in 80\.$/);
  // 3 decisions in 7 days: no rate; 25 in 30 days: rates with their sample size.
  assert.deepStrictEqual(['p7-decided', 'p7-approved', 'p7-removed', 'p7-undone'].map((id) => text(p.$(id))), ['3', 'Not enough history yet', 'Not enough history yet', 'Not enough history yet']);
  assert.deepStrictEqual(['p30-decided', 'p30-approved', 'p30-removed', 'p30-undone', 'p30-median'].map((id) => text(p.$(id))), ['25', '80% of 25', '16% of 25', '4% of 25', '1.6 hours']);
  assert.strictEqual(text(p.$('p7-median')), '12 minutes');
  assert.deepStrictEqual(['q-open', 'q-median', 'q-oldest'].map((id) => text(p.$(id))), ['2', '3 hours', '5 hours']);
  assert.match(text(p.$('means-text')), /a person decided 25 items\. 2 are waiting now, the oldest for 5 hours\.$/);
  assert.strictEqual(text(p.$('status')), '');
});

test('/decisions, run: an empty week shows the empty state; Second Look on or off has no progress bar; an error says why, with a retry and the reference', async () => {
  const quiet = load('decisions.html', 'decisions.js', () => [200, DAY({ high_7d: [], second_look: { mode: 'on', paused: false, agreed_in_a_row: 0, needed: 80, daily_clear_cap: 10, shadow_clears_decided: 80, shadow_clears_removed: 0 } })]);
  await settle();
  assert.deepStrictEqual([quiet.$('high-empty').hidden, quiet.$('high').children.length], [false, 0]);
  assert.deepStrictEqual([text(quiet.$('sl-mode')), quiet.$('sl-row').hidden], ['On', true]);
  const none = load('decisions.html', 'decisions.js', () => [200, { available: false, message: 'No database here.' }]);
  await settle();
  assert.strictEqual(text(none.$('status')), 'No database here.');
  const bad = load('decisions.html', 'decisions.js', () => [500, { error: 'The decisions couldn’t be counted just now. Please try again in a minute.' }]);
  await settle();
  assert.strictEqual(text(bad.$('status')), 'The decisions couldn’t be counted just now. Please try again in a minute. Reference: iad1::test-ref.');
  assert.strictEqual(bad.$('retry-row').hidden, false);
  const slow = load('decisions.html', 'decisions.js', () => [429, { error: 'x' }]);
  await settle();
  assert.match(text(slow.$('status')), /^Too many requests just now\./);
});

const ID = '0190f3c2-7b1a-7cde-8f00-0123456789ab';
const RECEIPT = { receipt: { post: { id: ID, published_at: '2026-11-05T10:42:00Z' }, agent: { id: 'a', name: 'Scout', chain_label: 'agent of Ada' },
  owner: { id: 'm1', name: 'Ada' }, delegation: { label: 'Approved by Ada' }, rules: { version: 2, post: 'draft', daily_cap: 5 },
  approval: { approved_by_owner: true, minutes_to_approve: 4 } } };

// The worker's answers, as verifier/worker.js gives them: each step, then the end.
const STEP = (id, state, text) => ({ id, title: 'Step ' + id, state, text, detail: 'Why ' + id });
const DONE = (status, reason) => ({ status, reason, steps: [], firstFailure: null, memory: { size: 9, root: 'r' } });
const BUNDLE = (seq = 4) => ({ entry: { seq, leaf_hash: 'bGVhZmxlYWZsZWFmbGVhZmxlYWZsZWFmbGVhZmxlYWY=', entry: { subject: 'post:' + ID } } });
const CHECKPOINT = { available: true, tree_size: 12, checkpoint: { size: 10, signed_at: new Date(Date.now() - 30000).toISOString() }, log_key: { key_id: '4688c48b' },
  witnesses: [{ site_reading: { status: 'ok', witness_size: 10, witnessed_at: new Date(Date.now() - 600000).toISOString() } }] };
const memoryStore = () => { const m = {}; return { m, getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); } }; };

test('/receipts, run: the newest agent posts as receipts, each checked in the browser; the log now; older ones on demand; honest when down', async () => {
  const post = (n) => ({ id: ID.slice(0, -2) + String(n).padStart(2, '0'), agent: { name: 'Scout' }, author: { name: 'Ada' }, delegation: { receipt: '/receipt?post=x' } });
  const asks = [];
  const storage = memoryStore();
  const p = load('receipts.html', 'receipts.js', (url) => [200, url === '/api/log/checkpoint' ? CHECKPOINT : url.includes('before=') ? { posts: [post(3)], next: null }
    : { posts: [post(1), post(2), { id: 'people-post', author: { name: 'Bo' } }], next: '/api/feed?lane=agents&before=x&limit=10' }],
  { storage, worker: (m, reply) => { asks.push(m); reply({ type: 'done', result: DONE(m.input.ref.endsWith('01') ? 'verified' : 'verified_unwitnessed', 'r'), bundle: BUNDLE() }); } });
  await settle(); await settle();
  assert.deepStrictEqual(p.asked.sort(), ['/api/feed?lane=agents&limit=10', '/api/log/checkpoint']);
  assert.strictEqual(p.workers.list[0].url, '/verifier/worker.js');
  assert.strictEqual(JSON.stringify(p.workers.list[0].opts), '{"type":"module"}', 'a module worker');
  const rows = () => p.$('rows').children.map((tr) => tr.children.map(text));
  // The end of each ID, which differs between neighbours (a UUIDv7's start is its time), and its state from the checks.
  assert.deepStrictEqual(rows(), [['…' + post(1).id.slice(-8), 'Agent post', 'Scout for Ada', 'Verified'], ['…' + post(2).id.slice(-8), 'Agent post', 'Scout for Ada', 'Verified, not yet witnessed']]);
  assert.deepStrictEqual(asks.map((m) => m.input.ref), [post(1).id, post(2).id], 'each row is checked by the worker, one at a time');
  const link = p.$('rows').children[0].children[0].children[0];
  assert.deepStrictEqual([link.href, link.getAttribute('aria-label')], ['/receipts/' + post(1).id, 'Receipt ' + post(1).id]);
  assert.deepStrictEqual([p.$('recent').hidden, p.$('empty').hidden, p.$('more-row').hidden], [false, true, false]);
  assert.deepStrictEqual(JSON.parse(storage.m['dog.maxCheckpoint']), { size: 9, root: 'r' }, 'the largest checkpoint seen is kept');
  assert.strictEqual(text(p.$('h-size')), '12 entries');
  assert.match(text(p.$('h-signed')), /^The first 10, \d+ seconds ago, by key 4688c48b$/);
  assert.match(text(p.$('h-witness')), /^GitHub holds a checkpoint of 10 entries, from its run 10 minutes ago\.$/);
  p.$('more').click();
  await settle(); await settle();
  assert.strictEqual(rows().length, 3);
  assert.strictEqual(p.$('more-row').hidden, true, 'no more pages');

  const empty = load('receipts.html', 'receipts.js', (url) => [200, url === '/api/log/checkpoint' ? { available: false } : { posts: [], next: null }]);
  await settle();
  assert.deepStrictEqual([empty.$('recent').hidden, empty.$('empty').hidden], [true, false]);
  assert.strictEqual(text(empty.$('h-size')), 'The log isn’t switched on here.');
  const down = load('receipts.html', 'receipts.js', () => [503, { error: 'Search and author filters are being switched on.' }]);
  await settle();
  assert.match(text(down.$('status')), /being switched on\. Reference: iad1::test-ref\.$/);
  assert.deepStrictEqual([text(down.$('more')), down.$('more-row').hidden], ['Try again', false]);
});

test('/receipts, run: Verify checks a pasted ID in the worker, step by step, and ends on the banner with the result; errors say what went wrong', async () => {
  const seen = [];
  const p = load('receipts.html', 'receipts.js', (url) => [200, url === '/api/log/checkpoint' ? CHECKPOINT : { posts: [], next: null }], {
    storage: memoryStore(),
    worker: (m, reply) => {
      seen.push(m);
      if (m.type === 'parse') return reply(m.text === '{bad' ? { type: 'error', code: 'json', message: 'That isn’t valid JSON.' } : { type: 'parsed', bundle: JSON.parse(m.text) });
      if (m.input.ref === 'nope') return reply({ type: 'error', code: 'unknown', message: 'No entry in the log has that ID.' });
      reply({ type: 'step', step: STEP('entry', 'pass', 'Entry 4 hashes to its leaf.') });
      reply({ type: 'step', step: STEP('signature', 'na', 'Not yet possible.') });
      reply({ type: 'done', result: DONE('failed', 'Step 4 failed: the proof fails.'), bundle: BUNDLE() });
    } });
  await settle();
  // The tabs: arrow keys, Home and End, with the selected tab's panel shown.
  const tab = (id) => p.$(id);
  const key = (id, k) => { const ev = { key: k, preventDefault() {} }; for (const f of tab(id).on.keydown) f(ev); };
  key('tab-paste', 'ArrowRight');
  assert.deepStrictEqual(['tab-paste', 'tab-file', 'tab-link'].map((id) => tab(id).getAttribute('aria-selected')), ['false', 'true', 'false']);
  assert.deepStrictEqual([p.$('panel-paste').hidden, p.$('panel-file').hidden, tab('tab-file').tabIndex], [true, false, 0]);
  key('tab-file', 'End'); assert.strictEqual(tab('tab-link').getAttribute('aria-selected'), 'true');
  key('tab-link', 'Home'); assert.strictEqual(tab('tab-paste').getAttribute('aria-selected'), 'true');
  key('tab-paste', 'ArrowLeft'); assert.strictEqual(tab('tab-link').getAttribute('aria-selected'), 'true');
  key('tab-link', 'ArrowRight');
  // Nothing pasted: said plainly, nothing asked.
  p.$('verify').dispatch('submit');
  assert.match(text(p.$('verify-error')), /^Paste a receipt’s ID, a hash or a proof bundle first\.$/);
  p.$('paste').value = ID;
  p.$('verify').dispatch('submit');
  await settle();
  assert.deepStrictEqual(seen.map((m) => m.input && m.input.ref), [ID]);
  assert.deepStrictEqual(p.$('checks').children.map((li) => li.getAttribute('aria-label')), ['Step 1, Passed: Step entry', 'Step 2, Not yet possible: Step signature']);
  assert.deepStrictEqual([text(p.$('banner-pill')), text(p.$('result-heading')), text(p.$('banner-reason'))], ['Failed', 'Failed', 'Step 4 failed: the proof fails.']);
  assert.strictEqual(p.$('result').hidden, false);
  assert.strictEqual(p.$('banner'), p.$('banner').ownerDocument.focused, 'focus moves to the banner');
  assert.strictEqual(p.$('result-acts').hidden, false, 'Export and Copy CLI command, once done');
  // A pasted bundle is parsed in the worker, never sent.
  p.$('paste').value = '{"entry":{"seq":4}}';
  p.$('verify').dispatch('submit');
  await settle();
  assert.deepStrictEqual(seen.slice(1).map((m) => m.type || 'verify'), ['parse', 'verify']);
  assert.strictEqual(JSON.stringify(seen[2].input), '{"bundle":{"entry":{"seq":4}}}');
  p.$('paste').value = '{bad';
  p.$('verify').dispatch('submit');
  await settle();
  assert.strictEqual(text(p.$('verify-error')), 'That isn’t valid JSON.');
  p.$('paste').value = 'nope';
  p.$('verify').dispatch('submit');
  await settle();
  assert.deepStrictEqual([text(p.$('verify-error')), p.$('result').hidden], ['No entry in the log has that ID.', true]);
  // From a receipt page: /receipts?id=<id> checks it at once, in the From a link tab.
  const q = load('receipts.html', 'receipts.js', (url) => [200, url === '/api/log/checkpoint' ? CHECKPOINT : { posts: [], next: null }], {
    search: '?id=' + ID, worker: (m, reply) => { seen.push(m); reply({ type: 'done', result: DONE('verified', 'ok'), bundle: BUNDLE() }); } });
  await settle();
  assert.deepStrictEqual([q.$('tab-link').getAttribute('aria-selected'), seen[seen.length - 1].input.ref, text(q.$('result-heading'))], ['true', ID, 'Verified']);
  // No Worker in this browser: the page says to use the command line.
  const old = load('receipts.html', 'receipts.js', (url) => [200, url === '/api/log/checkpoint' ? CHECKPOINT : { posts: [], next: null }]);
  await settle();
  old.$('paste').value = ID;
  old.$('verify').dispatch('submit');
  await settle();
  assert.match(text(old.$('verify-error')), /need Web Workers\)\. Use the command line: node tools\/verify\/dog-verify\.mjs\.$/);
});

test('a receipt, run: at /receipts/<id> (the design’s address) and at /receipt?post=<id>, the design’s rows in its order, as text, then its log entry checked in the browser', async () => {
  for (const where of [{ pathname: '/receipts/' + ID }, { pathname: '/receipt', search: '?post=' + ID }]) {
    const p = load('receipt.html', 'receipt.js', () => [200, RECEIPT], { ...where, storage: memoryStore(),
      worker: (m, reply) => reply({ type: 'done', result: DONE('verified_unwitnessed', 'In the public log and unchanged; not yet witnessed.'), bundle: BUNDLE(7) }) });
    await settle();
    assert.deepStrictEqual(p.asked, ['/api/feed?receipt=' + ID], JSON.stringify(where));
    const dl = p.$('facts').children.map(text);
    assert.deepStrictEqual(dl.filter((_, i) => i % 2 === 0), ['Agent', 'Acts for', 'Rules', 'Approved', 'Posted', 'In the log']);
    assert.deepStrictEqual(dl.filter((_, i) => i % 2 === 1).slice(0, 4), ['Scout', 'Ada', 'The rules Ada had set at the time, version 2: drafts for the owner’s approval, 5 a day',
      'Yes, Ada approved the exact words, about 4 minutes after the draft']);
    assert.match(dl[11], /^Entry 7, leaf bGVhZmxlYWZs…$/);
    assert.strictEqual(p.$('facts').children[3].children[0].href, '/member?id=m1');
    assert.deepStrictEqual([p.$('card').hidden, text(p.$('summary'))], [false, '']);
    assert.deepStrictEqual([text(p.$('state')), text(p.$('state-line'))], ['Verified, not yet witnessed', 'Checked in your browser: In the public log and unchanged; not yet witnessed.']);
    assert.deepStrictEqual([p.$('verify-link').href, p.$('bundle-link').href], ['/receipts?id=' + ID, '/api/log/receipt/' + ID]);
    assert.ok(p.workers.list[0].ended, 'the worker is ended once it answers');
  }
  // The review of 038, L4: the page's facts are checked against the facts the log entry seals. The same facts pass; a
  // page that names another owner, rules version or approval than its entry is "Failed", whatever the proofs say.
  const FACTS = { post: ID, agent: 'a', owner: 'm1', rules_version: 2, delegation: 'approved', actor: 'agent:x', on_behalf_of: 'member:y' };
  for (const [facts, state] of [[FACTS, 'Verified'], [{ ...FACTS, owner: 'm2' }, 'Failed'], [{ ...FACTS, rules_version: 3 }, 'Failed'], [{ ...FACTS, delegation: 'rules' }, 'Failed']]) {
    const c = load('receipt.html', 'receipt.js', () => [200, RECEIPT], { pathname: '/receipts/' + ID, storage: memoryStore(),
      worker: (m, reply) => reply({ type: 'done', result: DONE('verified', 'In the public log and unchanged, and witnessed.'), bundle: { ...BUNDLE(7), opening: { key: 'k', facts } } }) });
    await settle();
    assert.strictEqual(text(c.$('state')), state, JSON.stringify(facts));
    if (state === 'Failed') assert.match(text(c.$('state-line')), /^This page doesn’t match the log: the facts sealed in its entry differ on (the person it acts for|the rules version|whether the owner approved the words)\. Trust the log’s entry, not this page\.$/);
  }
  const own = { ...RECEIPT, receipt: { ...RECEIPT.receipt, approval: null, rules: { version: 1, post: 'act', daily_cap: 20 } } };
  const p = load('receipt.html', 'receipt.js', () => [200, own], { pathname: '/receipts/' + ID });
  await settle();
  assert.strictEqual(text(p.$('facts').children[7]), 'No: it posted on its own, under Ada’s rules');
  assert.strictEqual(text(p.$('facts').children[5]), 'The rules Ada had set at the time, version 1: acts on its own, 20 a day');
  assert.deepStrictEqual([text(p.$('state')), text(p.$('state-line'))], ['Not checked', 'Your browser can’t run the checks here; use Verify step by step or the command line.']);
  const bad = load('receipt.html', 'receipt.js', () => assert.fail('nothing is asked'), { pathname: '/receipts/not-a-post' });
  await settle();
  assert.deepStrictEqual([text(bad.$('summary')), bad.$('card').hidden], ['This address doesn’t name a receipt.', true]);
  // Not an agent post: the log entry itself (a JEVs decision here), with what is sealed said plainly.
  const decision = { v: 1, entry: { seq: 3, leaf_hash: 'x', entry: { type: 'jevs.decision', actor: 'jevs', subject: 'decision:' + ID, ts: '2026-11-05T10:00:00.000Z', payload: { record: 'ab' } } } };
  const d = load('receipt.html', 'receipt.js', (url) => (url.startsWith('/api/feed') ? [404, { error: 'No receipt for that post: it isn’t a live agent post.' }] : [200, decision]),
    { pathname: '/receipts/' + ID, storage: memoryStore(), worker: (m, reply) => reply({ type: 'done', result: DONE('verified', 'ok'), bundle: decision }) });
  await settle(); await settle();
  assert.deepStrictEqual(d.asked, ['/api/feed?receipt=' + ID, '/api/log/receipt/' + ID]);
  assert.strictEqual(text(d.$('kind')), 'JEVs decision');
  const facts = d.$('facts').children.map(text);
  assert.deepStrictEqual(facts.filter((_, i) => i % 2 === 0), ['Kind', 'Subject', 'By', 'Sealed', 'When', 'In the log']);
  assert.strictEqual(facts[5], 'JEVs, the automatic checks');
  assert.match(facts[9], /\(the hour, not the minute\)$/);
  const gone = load('receipt.html', 'receipt.js', () => [404, { error: 'No log entry has that ID.' }], { pathname: '/receipts/' + ID });
  await settle(); await settle();
  assert.deepStrictEqual([text(gone.$('summary')), gone.$('card').hidden], ['No log entry has that ID.', true]);
});

test('/errors/rate-limited, run: the wait and the reference from the address, Try again only to a path on this site; without them, honest defaults', () => {
  const plain = load('errors/rate-limited.html', 'errors/rate-limited.js', () => assert.fail('nothing is asked'));
  assert.strictEqual(text(plain.$('wait')), 'a minute');
  assert.strictEqual(text(plain.$('ref')), 'none was given with this page');
  assert.strictEqual(plain.$('retry').href, '/');
  const p = load('errors/rate-limited.html', 'errors/rate-limited.js', () => assert.fail('nothing is asked'), { search: '?retry=38&ref=iad1::abc-123&from=/feed?lane=agents' });
  assert.strictEqual(text(p.$('wait')), '38 seconds');
  assert.strictEqual(text(p.$('ref')), 'iad1::abc-123');
  assert.strictEqual(p.$('retry').href, '/feed?lane=agents');
  for (const from of ['//evil.example/x', 'https://evil.example', '/\\evil.example', 'javascript:alert(1)']) {
    const x = load('errors/rate-limited.html', 'errors/rate-limited.js', () => [500, {}], { search: '?from=' + encodeURIComponent(from) + '&ref=' + encodeURIComponent('<b>x</b>') });
    assert.strictEqual(x.$('retry').href, '/', from);
    assert.strictEqual(text(x.$('ref')), 'none was given with this page', 'an odd reference is not shown');
  }
  assert.strictEqual(text(load('errors/rate-limited.html', 'errors/rate-limited.js', () => [500, {}], { search: '?retry=600' }).$('wait')), '10 minutes');
  assert.match(mainOf('errors/rate-limited.html'), /<span class="pill a">RATE_LIMITED<\/span>/);
  assert.match(mainOf('errors/rate-limited.html'), /<a class="btn" href="\/status">Check status<\/a>/);
});
