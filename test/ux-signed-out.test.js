// UX PR D (the UI/UX review of Oct 31, findings 5, 6 and 12's front-end part; Aaron approved all its recommendations on
// Oct 31): signed-out states on /feed, /agents, /account, /review and /controls, Second Look's mode on /controls, and
// the review queue's reasons and empty state. Each page's real HTML and script run here in a small stand-in DOM (no
// browser); scripts/check-signed-out.js runs the same pages in Chromium and checks the first screen.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

// ---- A small DOM: enough of one for these pages' scripts, built from the page's own <main> ----
const VOID = new Set(['input', 'br', 'img', 'meta', 'link', 'hr', 'source', 'wbr']);
class El {
  constructor(tag, doc) {
    this.tagName = tag.toUpperCase(); this.ownerDocument = doc; this.children = []; this.attrs = {}; this.parentNode = null;
    this.hidden = false; this.disabled = false; this.open = false; this.value = ''; this.className = ''; this.on = {}; this._text = '';
    this.classList = { add: (c) => { this.className = (this.className + ' ' + c).trim(); } };
  }
  get id() { return this.attrs.id || ''; } set id(v) { this.attrs.id = String(v); }
  get href() { return this.attrs.href; } set href(v) { this.attrs.href = String(v); }
  get type() { return this.attrs.type; } set type(v) { this.attrs.type = String(v); }
  get textContent() { return this.tagName === '#TEXT' ? this._text : this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this.children.forEach((c) => { c.parentNode = null; }); this.children = []; this._text = String(v); }
  get firstChild() { return this.children[0] || null; }
  get options() { return this.children.filter((c) => c.tagName === 'OPTION'); }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'hidden') this.hidden = true; }
  getAttribute(k) { return Object.hasOwn(this.attrs, k) ? this.attrs[k] : null; }
  appendChild(n) { if (n.parentNode) n.remove(); n.parentNode = this; this.children.push(n); return n; }
  insertBefore(n, ref) { if (n.parentNode) n.remove(); n.parentNode = this; const i = ref ? this.children.indexOf(ref) : -1; this.children.splice(i < 0 ? this.children.length : i, 0, n); return n; }
  after(n) { const p = this.parentNode; if (n.parentNode) n.remove(); n.parentNode = p; p.children.splice(p.children.indexOf(this) + 1, 0, n); }
  remove() { if (!this.parentNode) return; const s = this.parentNode.children; s.splice(s.indexOf(this), 1); this.parentNode = null; }
  addEventListener(t, f) { (this.on[t] = this.on[t] || []).push(f); }
  // Runs the listeners in order, as a browser does; stopImmediatePropagation stops the rest.
  click() { this.dispatch('click'); }
  dispatch(type) {
    let stopped = false;
    const ev = { type, target: this, preventDefault() {}, stopImmediatePropagation() { stopped = true; } };
    for (const f of (this.on[type] || []).slice()) { if (stopped) break; f(ev); }
  }
  remove_(i) { this.options[i].remove(); }
  focus() { this.ownerDocument.focused = this; }
  scrollIntoView() {}
  reset() {}
  all() { return this.children.flatMap((c) => [c, ...c.all()]); }
  // Selectors these scripts use: tag, .class, tag.class, #id, [attr], [attr="v"], tag[attr], and "A B" (descendant).
  matches(sel) {
    const m = /^([a-z0-9]*)(?:#([\w-]+))?(?:\.([\w-]+))?(?:\[([\w-]+)(?:="([^"]*)")?\])?$/i.exec(sel);
    if (!m) throw new Error('selector not supported here: ' + sel);
    return (!m[1] || this.tagName === m[1].toUpperCase()) && (!m[2] || this.id === m[2])
      && (!m[3] || this.className.split(/\s+/).includes(m[3])) && (!m[4] || Object.hasOwn(this.attrs, m[4]))
      && (m[5] === undefined || this.attrs[m[4]] === m[5]);
  }
  querySelectorAll(sel) {
    const parts = sel.trim().split(/\s+/);
    let found = this.all().filter((e) => e.matches(parts[0]));
    for (const p of parts.slice(1)) found = found.flatMap((e) => e.all().filter((x) => x.matches(p)));
    return [...new Set(found)];
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  // Shown: neither it nor anything above it is hidden, and no closed <details> stands between (its summary aside).
  shown() {
    for (let e = this, child = null; e; child = e, e = e.parentNode) {
      if (e.hidden) return false;
      if (e.tagName === 'DETAILS' && !e.open && child && child.tagName !== 'SUMMARY') return false;
    }
    return true;
  }
}
// select.remove(i) removes an option; any other element's remove() removes itself.
const baseRemove = El.prototype.remove;
El.prototype.remove = function (i) { if (this.tagName === 'SELECT' && typeof i === 'number') return this.remove_(i); return baseRemove.call(this); };

function parseMain(html, doc) {
  const src = html.slice(html.indexOf('<main'), html.indexOf('</main>') + 7);
  const root = new El('#root', doc);
  const stack = [root];
  const re = /<!--[\s\S]*?-->|<\/([a-z0-9]+)\s*>|<([a-z0-9]+)((?:\s+[^\s=>]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>|([^<]+)/gi;
  let m;
  while ((m = re.exec(src))) {
    const top = stack[stack.length - 1];
    if (m[1]) { while (stack.length > 1 && stack.pop().tagName !== m[1].toUpperCase()); continue; }
    if (m[2]) {
      const e = new El(m[2], doc);
      const ar = /([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
      let a;
      while ((a = ar.exec(m[3] || ''))) {
        const v = a[2] ?? a[3] ?? a[4] ?? '';
        e.attrs[a[1]] = v;
        if (a[1] === 'class') e.className = v;
        if (a[1] === 'hidden') e.hidden = true;
        if (a[1] === 'open') e.open = true;
      }
      top.appendChild(e);
      if (!VOID.has(m[2].toLowerCase())) stack.push(e);
      continue;
    }
    if (m[4] && m[4].trim()) { const t = new El('#text', doc); t._text = m[4].replace(/\s+/g, ' '); top.appendChild(t); }
  }
  return root.children[0];
}

// Loads a page: its <main>, then its script, with fetch answered by answers(url, init) -> [status, body].
function page(file, script, answers) {
  const doc = { focused: null };
  const main = parseMain(read(file), doc);
  const sent = [];
  const timers = [];
  Object.assign(doc, {
    getElementById: (id) => main.all().find((e) => e.id === id) || (main.id === id ? main : null),
    createElement: (t) => new El(t, doc),
    createTextNode: (t) => { const n = new El('#text', doc); n._text = String(t); return n; },
    querySelectorAll: (s) => main.querySelectorAll(s),
    querySelector: (s) => main.querySelector(s)
  });
  const sandbox = {
    document: doc, location: { hash: '', search: '', pathname: '/' + file.replace(/\.html$/, '') },
    history: { replaceState() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, URLSearchParams, Promise, JSON, Date, Math, Array, Object, String, Number, Boolean, encodeURIComponent,
    setTimeout: (f, ms) => { timers.push({ f, ms }); return timers.length; }, clearTimeout: (n) => { if (timers[n - 1]) timers[n - 1].f = null; },
    fetch: (url, init) => {
      if (init && init.method && init.method !== 'GET') sent.push({ url, body: JSON.parse(init.body) });
      const [status, body] = answers(url, init);
      return Promise.resolve({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body) });
    }
  };
  sandbox.window = sandbox;
  vm.runInNewContext(read(script), sandbox);
  return { main, doc, sent, timers, $: doc.getElementById };
}
const settle = async () => { for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r)); };
// What shows in <main>: its visible children that hold anything, by id or tag.
const showing = (main) => main.children.filter((c) => c.shown() && c.textContent.trim()).map((c) => c.id || c.tagName.toLowerCase());

// ---- Stand-in answers, shaped like the real ones (api/feed.js, db/controls.js, 034's sl_report) ----
const CONTROLS = (mode) => ({
  totals: { brakes_on: 0, active_members: 2, banned_members: 0, disabled_members: 0, active_agents: 0, people_posts_24h: 1, agent_posts_24h: 0, posts_7d: 1, repeats_7d: 0 },
  everyone: null, deletion_reviews: [], owners: [], most_agents: [], repeated_texts: [],
  jevs: { mode: 'shadow', last_24h: [], recent: [] },
  second_look: mode === null ? null : { mode, paused: false, decisions_7d: 0, clears_7d: 0, rejects_7d: 0, failed_closed_7d: 0, published_total: 0,
    reversed_total: 0, shadow_clears_decided: 0, shadow_clears_removed: 0, shadow_error_upper_95: 1 } });
const controls = (status, body) => page('controls.html', 'controls.js', (url, init) => {
  if (init && init.method === 'POST') { const b = JSON.parse(init.body); return [200, { mode: b.mode, message: 'Second Look is now in ' + b.mode + ' mode.' }]; }
  return [status, body];
});
const modeButtons = (p) => p.main.querySelectorAll('button[data-mode]');
const pressed = (p) => modeButtons(p).map((b) => b.getAttribute('data-mode') + '=' + b.getAttribute('aria-pressed'));

// ---- /controls (finding 5) ----

test('/controls, given a 401: only the heading and the sign-in panel show, and nothing is sent', async () => {
  const p = controls(401, { error: 'Sign in to see the owner controls.', join: '/join' });
  await settle();
  assert.deepStrictEqual(showing(p.main), ['h1', 'signed-out']);
  assert.strictEqual(p.$('admin').hidden, true, 'the brake, owners, JEVs and Second Look stay hidden');
  const button = p.$('signed-out').querySelector('a.button');
  assert.strictEqual(button.textContent, 'Sign in with GitHub');
  assert.strictEqual(button.getAttribute('href'), '/join?return_to=%2Fcontrols');
  assert.deepStrictEqual(p.sent, []);
});

test('/controls, signed in but not the administrator (403), or the database off: one line, no controls, no panel', async () => {
  for (const [status, body, line] of [[403, { error: 'Only Aaron can see the owner controls.' }, 'Only Aaron can see the owner controls.'],
    [200, { totals: null, everyone: null, owners: [] }, 'The site’s own database isn’t switched on yet.']]) {
    const p = controls(status, body);
    await settle();
    assert.deepStrictEqual(showing(p.main), ['h1', 'summary'], status);
    assert.strictEqual(p.$('summary').textContent, line);
  }
});

test('/controls, the administrator: the controls show, and Second Look\'s current mode is the one marked', async () => {
  for (const mode of ['off', 'shadow', 'on']) {
    const p = controls(200, CONTROLS(mode));
    await settle();
    assert.strictEqual(p.$('admin').hidden, false);
    assert.strictEqual(p.$('signed-out').hidden, true);
    assert.strictEqual(p.$('sl-modes').shown(), true);
    assert.deepStrictEqual(pressed(p), ['off', 'shadow', 'on'].map((m) => m + '=' + (m === mode)), mode);
  }
  const none = controls(200, CONTROLS(null));
  await settle();
  assert.strictEqual(none.$('sl-modes').hidden, true, 'no mode to switch before 034 is applied');
});

test('/controls: "On" sends nothing on the first tap and switches on at the second; the current mode sends nothing', async () => {
  const p = controls(200, CONTROLS('shadow'));
  await settle();
  const [off, shadow, on] = modeButtons(p);
  on.click();
  await settle();
  assert.deepStrictEqual(p.sent, [], 'one tap sends nothing');
  assert.strictEqual(on.textContent, 'Tap again to let Second Look publish easy held posts');
  assert.strictEqual(p.$('sl-mode-result').textContent, 'Tap On again within 5 seconds to switch it on.', 'said where a screen reader hears it');
  on.click();
  await settle();
  assert.deepStrictEqual(p.sent.map((x) => x.body), [{ second_look: 'mode', mode: 'on' }]);
  assert.strictEqual(on.textContent, 'On');

  // Left alone, the first tap wears off after 5 seconds.
  const q = controls(200, CONTROLS('shadow'));
  await settle();
  const qOn = modeButtons(q)[2];
  qOn.click();
  const wear = q.timers.find((t) => t.ms === 5000 && t.f);
  wear.f();
  assert.strictEqual(qOn.textContent, 'On');
  qOn.click();
  await settle();
  assert.deepStrictEqual(q.sent, [], 'a tap after it wore off arms again, and sends nothing');

  // Off takes one tap; the mode it is already in sends nothing (switching restarts its count of 80).
  shadow.click();
  off.click();
  await settle();
  assert.deepStrictEqual(p.sent.map((x) => x.body.mode), ['on', 'off']);
  const r = controls(200, CONTROLS('on'));
  await settle();
  modeButtons(r)[2].click();
  modeButtons(r)[2].click();
  await settle();
  assert.deepStrictEqual(r.sent, []);
  assert.strictEqual(r.$('sl-mode-result').textContent, 'Second Look is already in on mode.');
});

test('/controls: what each mode does is said beside it, and every number in it is the database\'s (034)', () => {
  const html = read('controls.html');
  const mig = read('db/migrations/034_second_look_v1.sql');
  for (const m of ['off', 'shadow', 'on']) assert.match(html, new RegExp('data-mode="' + m + '" aria-pressed="false" aria-describedby="sl-' + m + '-what"'));
  assert.match(html, /role="group" aria-labelledby="sl-modes-label"/);
  // "Off: Nothing runs." 034: off (nothing runs); it never claims a post in off mode.
  assert.match(html, /<p id="sl-off-what" class="fine">Nothing runs\.<\/p>/);
  assert.match(mig, /off \(nothing runs\)/);
  // "the last 80 ... switches itself on": the unlock, 80 by default.
  assert.match(html, /Once you have approved all of the last 80 posts it would have published, it switches itself on\./);
  assert.match(mig, /unlock_n integer not null default 80/);
  assert.match(mig, /update app\.sl_settings set mode = 'on', counted_since = now\(\)/);
  // "at most 10 a day ... more than 1 in 80 ... pauses itself back to shadow".
  assert.match(html, /It publishes easy held posts itself, at most 10 a day\. If you remove more than 1 in 80 of them, it pauses itself back to shadow\./);
  assert.match(mig, /daily_clear_cap integer not null default 10/);
  assert.match(mig, /update app\.sl_settings set mode = 'shadow', counted_since = now\(\), paused_reason/);
  // "Switching here starts its count of 80 again."
  assert.match(html, /Switching here starts its count of 80 again\. On takes a second tap\./);
  assert.match(mig, /update app\.sl_settings set mode = p_mode, paused_reason = null, counted_since = now\(\)/);
  // "Only the administrator can use them": the server's rule, not the page's.
  assert.match(read('signin/session.js'), /const canControl = \(who\) => Boolean\(who && who\.isAdmin === true\);/);
  assert.match(read('signin/session.js'), /const canReview = \(who\) => Boolean\(who && who\.isAdmin === true\);/);
});

// ---- The signed-out panel (finding 6) ----

const PANELS = { 'feed.html': '/feed', 'agents.html': '/agents', 'account.html': '/account', 'review.html': '/review', 'controls.html': '/controls' };
const JOIN_LINE = '<p class="fine">Joining needs a free GitHub account and a private file of yours as a key. No new password.</p>';

test('one panel, the same on each page that needs sign-in: a sentence, one primary button to /join that comes back, one line on joining', () => {
  for (const [file, url] of Object.entries(PANELS)) {
    const html = read(file);
    const panels = html.match(/<section id="signed-out" class="signed-out" aria-label="Sign in"( hidden)?>[\s\S]*?<\/section>/g) || [];
    assert.strictEqual(panels.length, 1, file);
    const lines = panels[0].split('\n').map((l) => l.trim()).filter(Boolean);
    assert.strictEqual(lines.length, 5, file + ': ' + lines.join(' / '));
    assert.match(lines[1], /^<p>[^<]+\.<\/p>$/, file + ': one sentence on what the page is for');
    assert.strictEqual(lines[2], '<p><a class="button primary" href="/join?return_to=' + encodeURIComponent(url) + '">Sign in with GitHub</a></p>', file);
    assert.strictEqual(lines[3], JOIN_LINE, file);
    assert.ok(!/<script>|<script [^>]*>[^<]/.test(html), file + ': no inline script');
  }
  // What the join line says is what /join says.
  assert.match(read('join.html'), /Join Day One Great with your GitHub account and a private file of yours\. No new password to make\./);
  // Each return_to is one /join will send back to (signin/http.js, returnPath).
  const { returnPath } = require('../signin/http');
  for (const url of Object.values(PANELS)) assert.strictEqual(returnPath(url), url);
});

test('the panel\'s style lives in app.css (the app pages only), so the shared styles.css keeps its page-weight budget', () => {
  assert.match(read('app.css'), /\.story \.signed-out \{/);
  assert.ok(!/\.(signed-out|sl-mode|agent-rules|agents-intro)\b/.test(read('styles.css')));
  for (const file of Object.keys(PANELS)) assert.match(read(file), /<link rel="stylesheet" href="\/app\.css">/, file);
});

// ---- /feed (finding 6) ----

const POSTS = { posts: [{ id: 'p1', author: { name: 'Ada', level: 1 }, published_at: '2026-10-31T10:00:00Z', body: 'Hello.' },
  { id: 'p2', author: { name: 'Grace', level: 2 }, published_at: '2026-10-31T09:00:00Z', body: 'Hi.' }], next: null };
const feed = (signedIn, report = [200, { message: 'Thanks.' }]) => page('feed.html', 'feed.js', (url, init) => {
  if (url === '/auth/me') return [200, { signed_in: signedIn }];
  if (init && init.method === 'POST') return report;
  if (url.startsWith('/api/feed?mine')) return [200, { posts: [] }];
  return [200, POSTS];
});

test('/feed signed out: the panel shows, and "Report" is "Sign in to report", a link to /join that never opens a form', async () => {
  const p = feed(false);
  await settle();
  assert.strictEqual(p.$('signed-out').shown(), true);
  assert.strictEqual(p.$('compose').hidden, true);
  const reports = p.main.querySelectorAll('.report');
  assert.strictEqual(reports.length, 2);
  for (const r of reports) {
    assert.deepStrictEqual(r.querySelectorAll('button'), [], 'no Report button');
    const a = r.querySelector('a');
    assert.strictEqual(a.textContent, 'Sign in to report');
    assert.strictEqual(a.getAttribute('href'), '/join?return_to=%2Ffeed');
    a.click();
  }
  assert.deepStrictEqual(p.main.querySelectorAll('.report-form'), [], 'no form opened');
  assert.deepStrictEqual(p.sent, []);
  // The panel is in the page from the start (no shift for someone signed out); a member never sees it.
  assert.match(read('feed.html'), /<section id="signed-out" class="signed-out" aria-label="Sign in">/);
});

test('/feed signed in: no panel, Report still opens its form; a sign-in that ends meanwhile swaps the form for the link', async () => {
  const p = feed(true, [401, { error: 'Sign in first.' }]);
  await settle();
  assert.strictEqual(p.$('signed-out').hidden, true);
  assert.strictEqual(p.$('compose').hidden, false);
  const r = p.main.querySelector('.report');
  r.querySelector('button').click();
  const form = r.querySelector('.report-form');
  assert.ok(form, 'Report opens its form');
  form.querySelectorAll('button')[0].click();
  await settle();
  assert.deepStrictEqual(r.querySelectorAll('.report-form'), [], 'the form that can\'t be sent goes');
  assert.match(r.textContent, /Your sign-in has ended\. Sign in to report$/);
  assert.strictEqual(r.querySelector('a').getAttribute('href'), '/join?return_to=%2Ffeed');
});

// ---- /agents (finding 6) ----

test('/agents signed out: the panel, three short lines, and the full rules in a closed "How agents work" disclosure', async () => {
  const p = page('agents.html', 'agents.js', () => [401, { error: 'Sign in to manage agents.', join: '/join?return_to=%2Fagents' }]);
  await settle();
  assert.deepStrictEqual(showing(p.main), ['h1', 'p', 'signed-out', 'agents-intro', 'agent-rules']);
  assert.strictEqual(p.$('agents-intro').querySelectorAll('li').length, 3);
  const rules = p.$('agent-rules');
  assert.strictEqual(rules.open, false);
  assert.strictEqual(rules.querySelector('summary').textContent, 'How agents work');
  const paragraphs = rules.querySelectorAll('p');
  assert.strictEqual(paragraphs.length, 5, 'every rule is still in the HTML, for agents and search');
  assert.ok(paragraphs.every((x) => !x.shown()), 'and folded away');
  assert.ok(rules.textContent.split(/\s+/).length > 300);
  // The three lines say only what the rules and the claim form say.
  const html = read('agents.html');
  assert.match(html, /<li>An agent posts and replies for you, under rules you set\.<\/li>/);
  assert.match(html, /up to 20 posts and replies a day under your rules/);
  assert.match(html, /<li>It drafts each post for your approval, or acts on its own up to a daily limit you choose\.<\/li>/);
  assert.match(html, /whether posting is off, drafts for your approval, or acts on its own under your rules, and how many actions a day it may take/);
  assert.match(html, /<li>Every agent post links to a public receipt of how it went out\.<\/li>/);
  assert.match(html, /Every agent post says which it was, and links to a receipt\./);
});

test('/agents signed in: no panel and no short lines; the rules start open, as before', async () => {
  const p = page('agents.html', 'agents.js', (url) => [200, url === '/api/agents/activity' ? { agents: [], inbox: [], containment: null, unread_notices: 0 } : { agents: [], can_own: true }]);
  await settle();
  assert.strictEqual(p.$('signed-out').hidden, true);
  assert.strictEqual(p.$('agents-intro').hidden, true);
  assert.strictEqual(p.$('agent-rules').open, true);
});

// ---- /account (finding 6) ----

test('/account signed out: only the heading and the panel', async () => {
  const p = page('account.html', 'account.js', () => [401, { signed_in: false }]);
  await settle();
  assert.deepStrictEqual(showing(p.main), ['h1', 'signed-out']);
});

// ---- /review (findings 6 and 12) ----

const review = (status, body) => page('review.html', 'review.js', (url) => (url === '/api/notify/appeals' ? [status === 200 ? 200 : status, { containments: [] }] : [status, body]));
const item = (o) => ({ id: 'i', lane: 'people', status: 'waiting', body: 'Text.', author: { name: 'A', level: 1, status: 'active', live_posts: 0 },
  flagged_at: '2026-10-31T09:00:00Z', first_posts: false, reports: 0, reasons: [], notes: [], classifiers: [], appealed: false, actions: ['approve', 'remove'], ...o });

test('/review signed out: the heading, the panel and the note on how decisions work; no Refresh', async () => {
  const p = review(401, { error: 'Sign in to review.' });
  await settle();
  assert.deepStrictEqual(showing(p.main), ['h1', 'signed-out', 'review-note']);
});

test('/review: nothing waiting says what happens instead; JEVs checks every post (032) and owners approve their agents\' drafts', async () => {
  const p = review(200, { open: 0, items: [] });
  await settle();
  assert.strictEqual(p.$('summary').textContent, 'Nothing is waiting.');
  assert.strictEqual(p.$('queue').textContent, 'JEVs checks every post, and owners approve their own agents’ drafts. Anything held, hidden, reported or appealed comes here.');
  assert.match(read('db/migrations/032_guardrails.sql'), /when p_action in \('post\.create', 'post\.approved'\) then/);
});

test('/review: an item with several reasons lists them oldest first, says when it joined the queue, and keeps one-tap buttons and Undo', async () => {
  // The order the database allows (review.js, why()): a first-post flag comes with the post; reports need a live post;
  // an open JEVs flag beside reports came from a report; an appeal needs JEVs's hold first.
  const p = review(200, { open: 3, items: [
    item({ first_posts: true, classifiers: ['jevs'], appealed: true }),
    item({ id: 'j', status: 'removed', reports: 2, reasons: ['spam', 'abuse'], classifiers: ['jevs'], appealed: true, actions: ['remove', 'restore'] }),
    item({ id: 'k', status: 'live', reports: 1, reasons: ['other'], actions: ['keep', 'remove'] })] });
  await settle();
  const why = p.main.querySelectorAll('.why').map((x) => x.textContent);
  assert.deepStrictEqual(why, [
    'Why: one of a new member’s first 3 posts; flagged by JEVs (automatic checks); the author appealed.',
    'Why: 2 reports (spam, abuse); flagged by JEVs (automatic checks); the author appealed.',
    'Why: 1 report (other).']);
  const cards = p.main.querySelectorAll('article');
  assert.match(cards[0].textContent, /In the queue since .+\./);
  assert.deepStrictEqual(cards.map((c) => c.querySelectorAll('button').map((b) => b.textContent)), [['Approve', 'Remove'], ['Remove', 'Undo'], ['Keep', 'Remove']]);
  // These are the rules the order rests on.
  assert.match(read('db/migrations/010_jevs.sql'), /p\.status in \('waiting', 'removed'\)\s+and exists \(select 1 from app\.jevs_decisions d where d\.subject_id = p\.id and d\.applied and d\.effect in \('hold', 'hide'\)\)/);
  assert.match(read('db/migrations/032_guardrails.sql'), /if subj_kind = 'post' and eff in \('challenge', 'hold'\) and post_status = 'live' then\s+update app\.posts p set status = 'waiting'/);
  assert.match(read('db/migrations/032_guardrails.sql'), /when p_action = 'post\.reported' then/);
});
