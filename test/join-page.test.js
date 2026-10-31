// /join's code sign-in in a stand-in browser (no real DOM): the page keeps the code it is waiting for in this tab, so
// the comment box's GitHub round trip (a whole-tab reload) doesn't lose it, and Copy puts the code on a line of its
// own (the sign-in simulation, Oct 30, harness/FACTS.md). The real-browser runs are in the simulation's records.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'join.js'), 'utf8');
const IDS = ['message', 'code-signin', 'code-status', 'code-show', 'code-value', 'code-region', 'code-region-text',
  'code-region-yes', 'code-get', 'key-signin', 'code-copy', 'code-login', 'code-file', 'path-new', 'path-back', 'signin-fields',
  'code-new', 'code-again', 'back-help', 'hello-head', 'code-wait', 'code-time'];
// The ids join.html starts hidden (test/pages-load.test.js holds the page to the same list).
const HIDDEN = ['code-signin', 'code-show', 'code-region', 'message', 'signin-fields', 'code-get', 'key-signin', 'code-again', 'back-help'];
const CODE = 'DOG-7K4M-Q2XH';

// Loads join.js with stand-ins for the page, storage, the network and timers. answers(path) gives each reply.
function page({ stored, answers, path, clipboard = 'ok', now }) {
  const el = {};
  const said = []; // every write to the live region, in order
  for (const id of IDS) {
    el[id] = { id, hidden: HIDDEN.includes(id), value: '', files: [], on: {}, attrs: {}, text: '',
      get textContent() { return this.text; },
      set textContent(v) { if (id === 'code-status') said.push(String(v)); this.text = String(v); },
      addEventListener(t, f) { this.on[t] = f; }, setAttribute(k, v) { this.attrs[k] = String(v); } };
  }
  const store = new Map(stored === undefined ? [] : [['dog-code', stored]]);
  if (path !== undefined) store.set('dog-path', path);
  const calls = [], clip = [], timers = [], selected = [];
  const clock = { t: now || Date.now() };
  const FakeDate = { now: () => clock.t };
  const sandbox = {
    document: { getElementById: (id) => el[id] || null, querySelector: () => null, querySelectorAll: () => ({ forEach() {} }),
      createRange: () => ({ selectNodeContents(n) { this.node = n; } }) },
    getSelection: () => ({ removeAllRanges() {}, addRange(r) { selected.push(r.node && r.node.id); } }),
    location: { search: '', pathname: '/join', href: '' },
    sessionStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) },
    navigator: clipboard === 'none' ? {} : { clipboard: { writeText: (t) => { clip.push(t); return clipboard === 'ok' ? Promise.resolve() : Promise.reject(new Error('refused')); } } },
    fetch: (url, opts) => {
      calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
      return Promise.resolve({ ok: true, json: () => Promise.resolve(answers(url)) });
    },
    setInterval: (f, ms) => { timers.push({ f, ms, kind: 'interval' }); return timers.length; },
    clearInterval: () => {}, setTimeout: (f, ms) => { timers.push({ f, ms, kind: 'timeout' }); return timers.length; }, clearTimeout: () => {},
    URLSearchParams, Promise, JSON, Date: now ? FakeDate : Date, Math, Array, Uint8Array, Object, String, crypto: webcrypto
  };
  sandbox.window = sandbox;
  vm.runInNewContext(SRC, sandbox);
  return { el, store, calls, clip, timers, sandbox, said, selected, clock };
}
// Lets the page's promises (and Web Crypto's digest, which runs off the main thread) finish.
const settle = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 10)); };
const signedOut = (url) => (url === '/auth/me' ? { signed_in: false } : url === '/auth/code/finish' ? { waiting: true } : {});

test('after the comment box sends the tab to GitHub and back, /join shows the kept code again and keeps waiting for it', async () => {
  const p = page({ stored: JSON.stringify({ code: CODE, until: Date.now() + 300000 }), answers: signedOut });
  await settle();
  assert.strictEqual(p.el['code-signin'].hidden, false);
  assert.strictEqual(p.el['code-value'].textContent, CODE, 'the code is shown again');
  assert.strictEqual(p.el['code-show'].hidden, false);
  assert.ok(p.calls.some((c) => c.url === '/auth/code/finish' && c.method === 'POST'), 'it asks at once whether the code has been used');
  assert.ok(p.timers.some((t) => t.kind === 'interval' && t.ms === 2000), 'and keeps asking every 2 seconds');
  const deadline = p.timers.find((t) => t.kind === 'timeout');
  assert.ok(deadline.ms > 290000 && deadline.ms <= 300000, 'it stops when the code expires, not 10 minutes from the reload');
  assert.match(p.el['code-status'].textContent, /press Copy and paste it in the box below/, 'the waiting message still says what to do');
  assert.strictEqual(p.el['path-new'].attrs['aria-pressed'], 'true', 'the first-time path is the one showing');
  assert.strictEqual(p.el['hello-head'].hidden, true, 'the comment box sits right under the code');
});

test('a kept code that has expired, looks wrong or claims to last longer than a code can is dropped, and nothing is asked', async () => {
  for (const stored of [JSON.stringify({ code: CODE, until: Date.now() - 1 }), JSON.stringify({ code: '<b>x</b>', until: Date.now() + 1000 }),
    JSON.stringify({ code: 'DOG-0000-0000', until: Date.now() + 1000 }), JSON.stringify({ code: CODE, until: Date.now() + 3600000 }),
    JSON.stringify({ code: CODE, until: 'soon' }), '{not json', 'null']) {
    const p = page({ stored, answers: signedOut });
    await settle();
    assert.strictEqual(p.store.has('dog-code'), false, stored);
    assert.strictEqual(p.el['code-show'].hidden, true, stored);
    assert.ok(!p.calls.some((c) => c.url === '/auth/code/finish'), stored);
  }
});

test('a browser that is already signed in forgets any kept code; a signed-in, expired or declined answer forgets it too', async () => {
  const kept = JSON.stringify({ code: CODE, until: Date.now() + 300000 });
  const a = page({ stored: kept, answers: (u) => (u === '/auth/me' ? { signed_in: true } : {}) });
  await settle();
  assert.strictEqual(a.store.has('dog-code'), false);
  assert.ok(!a.calls.some((c) => c.url === '/auth/code/finish'));
  for (const [answer, check] of [[{ signed_in: true, go: '/feed' }, (p) => assert.strictEqual(p.sandbox.location.href, '/feed')],
    [{ expired: true }, (p) => assert.match(p.el['code-status'].textContent, /expired or was used/)],
    [{ declined: true }, (p) => assert.match(p.el['code-status'].textContent, /isn’t offered/)],
    [{ refused: 'banned' }, (p) => assert.match(p.el['code-status'].textContent, /isn’t available/)]]) {
    const p = page({ stored: kept, answers: (u) => (u === '/auth/me' ? { signed_in: false } : u === '/auth/code/finish' ? answer : {}) });
    await settle();
    assert.strictEqual(p.store.has('dog-code'), false, JSON.stringify(answer));
    check(p);
  }
});

test('getting a code keeps it for this tab until it expires; Copy puts it on a line of its own', async () => {
  const p = page({ stored: undefined, answers: (u) => (u === '/auth/me' ? { signed_in: false } : u === '/auth/code/start' ? { code: CODE, expires_in: 600 } : { waiting: true }) });
  await settle();
  p.el['path-new'].on.click();
  p.el['code-login'].value = 'coder';
  const bytes = new Uint8Array([1, 2, 3]);
  p.el['code-file'].files = [{ size: 3, arrayBuffer: () => Promise.resolve(bytes.buffer) }];
  p.el['code-get'].on.click();
  await settle();
  assert.ok(p.store.has('dog-code'), 'kept; the page said: ' + p.el['code-status'].textContent);
  const kept = JSON.parse(p.store.get('dog-code'));
  assert.strictEqual(kept.code, CODE);
  assert.ok(kept.until > Date.now() + 590000 && kept.until <= Date.now() + 600000);
  assert.match(p.el['code-status'].textContent, /^Waiting for your post/);
  assert.strictEqual(p.el['code-show'].hidden, false);
  assert.match(p.el['code-time'].textContent, /^Expires in (10:00|9:5\d)$/, 'the time left, from what the server gave');
  p.el['code-copy'].on.click();
  assert.deepStrictEqual(p.clip, ['\n\n' + CODE + '\n\n']);
  await settle();
  assert.strictEqual(p.el['code-copy'].textContent, 'Copied', 'Copy shows it worked');
});

test('what Copy puts in, pasted the ways people wrote in the simulation, is read as a code posted on purpose', async () => {
  const J = await import('../supabase/functions/jevs/core.mjs');
  const copied = '\n\n' + CODE + '\n\n';
  for (const [before, after] of [['', ''], ['Hello.\n\n', '\n\nThank you.'], ['Back again, this time to sign in to the site:\n', ''],
    ['Sorry, me again! Here is my code ', ' thank you!!'], ['Hi, Brenda here.\n\ncode: ', ''], ['Hi everyone, Sam here. Glad to join.\n\n', '']]) {
    const r = J.signinCodes(before + copied + after);
    assert.strictEqual(r.code, CODE, JSON.stringify(before + copied + after));
  }
  assert.strictEqual(J.signinCodes(copied).alone, true, 'the code by itself is still "alone", so it is hidden after use');
  // Wrapped in markup it is still not a sign-in: Copy changes nothing about what counts.
  assert.strictEqual(J.signinCodes('`' + copied + '`').code, null);
});

test('the region question in the middle of a wait keeps the code; the expiry, when it fires, drops it (the review of this PR)', async () => {
  const kept = JSON.stringify({ code: CODE, until: Date.now() + 300000 });
  const p = page({ stored: kept, answers: (u) => (u === '/auth/me' ? { signed_in: false } : u === '/auth/code/finish' ? { region: 'France' } : {}) });
  await settle();
  assert.strictEqual(p.el['code-region'].hidden, false, 'the page asks where the person lives');
  assert.strictEqual(p.store.get('dog-code'), kept, 'and keeps the code for after they answer');
  const q = page({ stored: kept, answers: signedOut });
  await settle();
  q.timers.find((t) => t.kind === 'timeout').f();
  assert.strictEqual(q.store.has('dog-code'), false);
  assert.strictEqual(q.el['code-show'].hidden, true);
  assert.match(q.el['code-status'].textContent, /That code has run out/);
  assert.strictEqual(q.el['code-again'].hidden, false, '"Get a new code" shows in its place');
  assert.strictEqual(q.el['code-get'].hidden, true, 'and only one button for a new code shows');
});

// The UI/UX review of Oct 31 (UX PR A): the panel's two paths, the countdown, Copy's two outcomes and a quiet live region.
const answersFor = (finish) => (u) => (u === '/auth/me' ? { signed_in: false } : u === '/auth/code/start' ? { code: CODE, expires_in: 600 } : u === '/auth/code/finish' ? finish() : {});
async function withCode(opts) {
  const p = page({ stored: undefined, answers: answersFor(() => ({ waiting: true })), ...opts });
  await settle();
  p.el['path-new'].on.click();
  p.el['code-login'].value = 'coder';
  p.el['code-file'].files = [{ size: 3, arrayBuffer: () => Promise.resolve(new Uint8Array([1, 2, 3]).buffer) }];
  p.el['code-get'].on.click();
  await settle();
  return p;
}

test('the panel shows its fields only once a path is chosen, and keeps only the choice, in this tab', async () => {
  const p = page({ stored: undefined, answers: signedOut });
  await settle();
  assert.strictEqual(p.el['code-signin'].hidden, false);
  assert.strictEqual(p.el['signin-fields'].hidden, true, 'nothing to fill in before choosing');
  p.el['path-new'].on.click();
  assert.strictEqual(p.el['signin-fields'].hidden, false);
  assert.deepStrictEqual([p.el['code-get'].hidden, p.el['key-signin'].hidden], [false, true], 'first time: one primary button, Get a sign-in code');
  assert.deepStrictEqual([p.el['path-new'].attrs['aria-pressed'], p.el['path-back'].attrs['aria-pressed']], ['true', 'false']);
  p.el['path-back'].on.click();
  assert.deepStrictEqual([p.el['code-get'].hidden, p.el['key-signin'].hidden, p.el['back-help'].hidden], [true, false, false], 'coming back: Sign in with my key file');
  assert.deepStrictEqual([...p.store.keys()], ['dog-path'], 'only the choice is kept');
  assert.strictEqual(p.store.get('dog-path'), 'back');
  // A reload in the same tab opens on the same path; anything else kept there is ignored.
  const again = page({ stored: undefined, answers: signedOut, path: 'back' });
  await settle();
  assert.strictEqual(again.el['key-signin'].hidden, false);
  const odd = page({ stored: undefined, answers: signedOut, path: '<img>' });
  await settle();
  assert.strictEqual(odd.el['signin-fields'].hidden, true);
  // Signed in already, or sign-in switched off: no panel at all.
  const member = page({ stored: undefined, answers: (u) => (u === '/auth/me' ? { signed_in: true } : {}) });
  await settle();
  assert.strictEqual(member.el['code-signin'].hidden, true);
});

test('the live region changes at most 3 times during a 30-second wait; the seconds go where screen readers skip', async () => {
  const p = await withCode({ now: Date.now() });
  const before = p.said.length;
  assert.ok(before <= 3, 'getting the code: ' + JSON.stringify(p.said));
  const poll = p.timers.find((t) => t.kind === 'interval' && t.ms === 2000).f;
  const tick = p.timers.find((t) => t.kind === 'interval' && t.ms === 1000).f;
  for (let s = 1; s <= 30; s++) {
    p.clock.t += 1000;
    tick();
    if (s % 2 === 0) { poll(); await settle(); }
  }
  assert.ok(p.said.length <= 3, 'the live region was written ' + p.said.length + ' times: ' + JSON.stringify(p.said));
  assert.match(p.el['code-wait'].textContent, /^30 s so far/, 'the seconds still count, out of the live region');
  assert.match(p.el['code-time'].textContent, /^Expires in 9:30$/);
  // A change of state is still announced: a lost connection, then the wait again, then the code used elsewhere.
  const n = p.said.length;
  p.sandbox.fetch = () => Promise.reject(new Error('offline'));
  poll(); await settle();
  assert.match(p.said[p.said.length - 1], /Couldn’t reach the site/);
  poll(); await settle();
  assert.strictEqual(p.said.length, n + 1, 'the same problem is announced once');
});

test('when the server says the code is gone, it hides and "Get a new code" makes another from the same fields', async () => {
  let answer = { waiting: true };
  const p = page({ stored: undefined, answers: answersFor(() => answer) });
  await settle();
  p.el['path-new'].on.click();
  p.el['code-login'].value = 'coder';
  p.el['code-file'].files = [{ size: 3, arrayBuffer: () => Promise.resolve(new Uint8Array([1, 2, 3]).buffer) }];
  p.el['code-get'].on.click();
  await settle();
  answer = { expired: true };
  p.timers.find((t) => t.kind === 'interval' && t.ms === 2000).f();
  await settle();
  assert.match(p.el['code-status'].textContent, /expired or was used/);
  assert.strictEqual(p.el['code-show'].hidden, true);
  assert.strictEqual(p.el['hello-head'].hidden, false, 'the "Say hello" heading comes back');
  assert.strictEqual(p.el['code-again'].hidden, false);
  const starts = p.calls.filter((c) => c.url === '/auth/code/start').length;
  p.el['code-new'].on.click();
  await settle();
  assert.strictEqual(p.calls.filter((c) => c.url === '/auth/code/start').length, starts + 1);
  assert.strictEqual(p.el['code-show'].hidden, false);
  assert.strictEqual(p.el['code-again'].hidden, true);
});

test('if the browser refuses the clipboard, Copy selects the code and says so, and never says "Copied"', async () => {
  for (const clipboard of ['refused', 'none']) {
    const p = await withCode({ clipboard });
    p.el['code-copy'].on.click();
    await settle();
    assert.deepStrictEqual(p.selected, ['code-value'], clipboard);
    assert.match(p.el['code-status'].textContent, /the code is selected/, clipboard);
    assert.strictEqual(p.el['code-copy'].textContent, 'Copy', clipboard);
  }
});

test('the panel sends the same requests with the same bodies as before (front end only)', async () => {
  const p = await withCode({});
  const start = p.calls.find((c) => c.url === '/auth/code/start');
  assert.deepStrictEqual(Object.fromEntries(new URLSearchParams(start.body)), { login: 'coder', file: '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81' });
  p.timers.find((t) => t.kind === 'interval' && t.ms === 2000).f();
  await settle();
  const finish = p.calls.find((c) => c.url === '/auth/code/finish');
  assert.strictEqual(finish.body, '');
  assert.deepStrictEqual([...new Set(p.calls.map((c) => c.url))].sort(), ['/auth/code/finish', '/auth/code/start', '/auth/me']);
});
