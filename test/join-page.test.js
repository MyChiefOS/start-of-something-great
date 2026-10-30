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
const IDS = ['message', 'choice-signin', 'code-signin', 'code-status', 'code-show', 'code-value', 'code-region', 'code-region-text',
  'code-region-yes', 'code-get', 'key-signin', 'code-copy', 'code-login', 'code-file'];
const CODE = 'DOG-7K4M-Q2XH';

// Loads join.js with stand-ins for the page, storage, the network and timers. answers(path) gives each reply.
function page({ stored, answers }) {
  const el = {};
  for (const id of IDS) {
    el[id] = { id, hidden: ['code-signin', 'code-show', 'code-region', 'choice-signin', 'message'].includes(id), textContent: '', value: '',
      files: [], on: {}, addEventListener(t, f) { this.on[t] = f; }, setAttribute() {} };
  }
  const store = new Map(stored === undefined ? [] : [['dog-code', stored]]);
  const calls = [], clip = [], timers = [];
  const sandbox = {
    document: { getElementById: (id) => el[id] || null, querySelector: () => null, querySelectorAll: () => ({ forEach() {} }) },
    location: { search: '', pathname: '/join', href: '' },
    sessionStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) },
    navigator: { clipboard: { writeText: (t) => { clip.push(t); return Promise.resolve(); } } },
    fetch: (url, opts) => {
      calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
      return Promise.resolve({ ok: true, json: () => Promise.resolve(answers(url)) });
    },
    setInterval: (f, ms) => { timers.push({ f, ms, kind: 'interval' }); return timers.length; },
    clearInterval: () => {}, setTimeout: (f, ms) => { timers.push({ f, ms, kind: 'timeout' }); return timers.length; }, clearTimeout: () => {},
    URLSearchParams, Promise, JSON, Date, Math, Array, Uint8Array, Object, crypto: webcrypto
  };
  sandbox.window = sandbox;
  vm.runInNewContext(SRC, sandbox);
  return { el, store, calls, clip, timers, sandbox };
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
  assert.match(p.el['code-status'].textContent, /press Copy and paste it there/, 'the waiting message still says what to do');
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
  p.el['code-login'].value = 'coder';
  const bytes = new Uint8Array([1, 2, 3]);
  p.el['code-file'].files = [{ size: 3, arrayBuffer: () => Promise.resolve(bytes.buffer) }];
  p.el['code-get'].on.click();
  await settle();
  assert.ok(p.store.has('dog-code'), 'kept; the page said: ' + p.el['code-status'].textContent);
  const kept = JSON.parse(p.store.get('dog-code'));
  assert.strictEqual(kept.code, CODE);
  assert.ok(kept.until > Date.now() + 590000 && kept.until <= Date.now() + 600000);
  assert.match(p.el['code-status'].textContent, /Press Copy and paste the code/);
  p.el['code-copy'].on.click();
  assert.deepStrictEqual(p.clip, ['\n\n' + CODE + '\n\n']);
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
