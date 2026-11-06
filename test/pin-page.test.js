// /join/pin (037; the review of 037, M1, and Aaron, Nov 5: "Yes, PIN on its own page"): the one page where the PIN is
// typed and this browser's sign-in key is made and used. pin.js runs in a stand-in browser (no real DOM), with Node's Web
// Crypto doing the real key work and a stand-in IndexedDB keeping what a browser would keep.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const SRC = read('pin.js');
const IDS = ['message', 'pin-signin-card', 'paths', 'path-new', 'path-back', 'pin-lane', 'pin-now', 'pin-signin', 'pin-other', 'file-lane',
  'code-login', 'code-file', 'key-pin', 'key-pin-again-field', 'key-pin-again', 'key-signin', 'pin-set', 'pin-set-title', 'pin-new', 'pin-again',
  'pin-remove-others-field', 'pin-remove-others', 'pin-others-count', 'pin-save', 'code-region', 'code-region-text', 'code-region-yes', 'code-status'];
const HIDDEN = ['message', 'pin-signin-card', 'pin-lane', 'file-lane', 'key-pin-again-field', 'pin-set', 'pin-remove-others-field', 'code-region'];
const CH = 'C'.repeat(43);

function fakeIndexedDB(keys) {
  const later = (f) => setTimeout(f, 0);
  return { open() {
    const req = {};
    later(() => {
      req.result = { createObjectStore() {}, transaction() {
        const tx = {};
        const done = () => later(() => tx.oncomplete && tx.oncomplete());
        tx.objectStore = () => ({ get(k) { const r = {}; later(() => { r.result = keys.get(k); done(); }); return r; },
          put(v, k) { keys.set(k, v); done(); }, delete(k) { keys.delete(k); done(); } });
        return tx;
      } };
      if (req.onsuccess) req.onsuccess();
    });
    return req;
  } };
}
function page({ answers, keys = new Map(), search = '', local = new Map(), session = new Map() }) {
  const el = {};
  const calls = [];
  for (const id of IDS) {
    el[id] = { id, hidden: HIDDEN.includes(id), value: '', files: [], on: {}, text: '', checked: id === 'pin-remove-others',
      get textContent() { return this.text; }, set textContent(v) { this.text = String(v); },
      addEventListener(t, f) { this.on[t] = f; }, focus() { focused.id = id; } };
  }
  const focused = { id: null };
  const sandbox = {
    document: { getElementById: (id) => el[id] || null },
    location: { search, origin: 'https://dayonegreat.com', href: '' },
    indexedDB: fakeIndexedDB(keys), TextEncoder, btoa: (x) => Buffer.from(x, 'binary').toString('base64'),
    localStorage: { getItem: (k) => (local.has(k) ? local.get(k) : null), setItem: (k, v) => local.set(k, String(v)), removeItem: (k) => local.delete(k) },
    sessionStorage: { getItem: (k) => (session.has(k) ? session.get(k) : null), setItem: (k, v) => session.set(k, String(v)), removeItem: (k) => session.delete(k) },
    navigator: { userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0' },
    fetch: (url, opts) => { calls.push({ url, body: opts && opts.body }); return Promise.resolve({ ok: true, json: () => Promise.resolve(answers(url, opts && opts.body)) }); },
    URLSearchParams, Promise, JSON, Math, Array, Uint8Array, Object, String, crypto: webcrypto
  };
  sandbox.window = sandbox;
  vm.runInNewContext(SRC, sandbox);
  return { el, calls, sandbox, keys, local, session, focused };
}
const settle = async () => { for (let i = 0; i < 12; i++) await new Promise((r) => setTimeout(r, 10)); };
async function signedBy(publicRaw, body) {
  const q = new URLSearchParams(body);
  const msg = Buffer.from('dayonegreat-signin-v1\nhttps://dayonegreat.com\n' + q.get('challenge'), 'utf8');
  const pub = await webcrypto.subtle.importKey('raw', publicRaw, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  return webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, Buffer.from(q.get('sig'), 'base64url'), msg);
}
const reply = (map) => (u) => (u in map ? (typeof map[u] === 'function' ? map[u]() : map[u]) : {});
async function storedKey() {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return { pair, raw: Buffer.from(await webcrypto.subtle.exportKey('raw', pair.publicKey)), keys: new Map([['signin', { keyId: '01a1ad69-0d9a-7687-a05a-5544ba899449', privateKey: pair.privateKey }]]) };
}

test('/join/pin runs no outside script: no giscus, only our own pin.js and nav.js, under the site\'s default policy (script-src \'self\')', () => {
  const html = read('join/pin.html');
  assert.doesNotMatch(html, /giscus/);
  assert.deepStrictEqual([...html.matchAll(/<script[^>]*><\/script>/g)].map((m) => m[0]), ['<script src="/pin.js" defer></script>', '<script src="/nav.js" defer></script>']);
  const v = JSON.parse(read('vercel.json'));
  const rule = v.headers.find((h) => new RegExp('^' + h.source + '$').test('/join/pin') && h.headers.some((x) => x.key === 'Content-Security-Policy'));
  const csp = rule.headers.find((x) => x.key === 'Content-Security-Policy').value;
  assert.match(csp, /script-src 'self';/);
  assert.doesNotMatch(csp, /giscus/);
  assert.ok(!v.headers.some((h) => h !== rule && new RegExp('^' + h.source + '$').test('/join/pin') && h.headers.some((x) => x.key === 'Content-Security-Policy')), 'no second policy');
  // The design's card, tabs and fields, in its layout (tools/design/pages/join_pin.main.html).
  assert.match(html, /<div class="card [^"]*" id="pin-signin-card" role="region" aria-labelledby="signin-title"[^>]*hidden><h2 class="h3" id="signin-title">Sign in to the site<\/h2>/);
  for (const id of ['pin-now', 'key-pin', 'key-pin-again', 'pin-new', 'pin-again']) {
    assert.match(html, new RegExp('<input id="' + id + '" name="[a-z_-]+" type="password" inputmode="numeric" pattern="\\[0-9\\]\\{6\\}" maxlength="6" autocomplete="off"'), id);
  }
  assert.match(html, /<input id="pin-remove-others" name="remove_others" type="checkbox" checked>/, 'on by default (the review of 037, L2)');
  // The browser key: Web Crypto, non-extractable, in IndexedDB; only the public half is ever exported.
  assert.match(SRC, /generateKey\(\{ name: 'ECDSA', namedCurve: 'P-256' \}, false, \['sign'\]\)/);
  assert.doesNotMatch(SRC, /exportKey\('(jwk|pkcs8)'/);
  assert.doesNotMatch(SRC, /(sessionStorage|localStorage)\.setItem\([^)]*pin/i, 'the PIN is never kept in the browser');
});

test('lane 3 on /join/pin: a browser that keeps its key asks only for the PIN, signs a fresh challenge with it, and keeps nothing of the PIN', async () => {
  const { raw, keys } = await storedKey();
  const p = page({ keys, answers: reply({ '/auth/me': { signed_in: false }, '/auth/challenge': { challenge: CH }, '/auth/browser': { signed_in: true, go: '/feed' } }) });
  await settle();
  assert.deepStrictEqual([p.el['pin-signin-card'].hidden, p.el['pin-lane'].hidden, p.el['file-lane'].hidden], [false, false, true]);
  assert.strictEqual(p.focused.id, 'pin-now');
  assert.strictEqual(p.local.get('dog-signin-key'), '1', 'the flag /join reads to send this browser here');
  p.el['pin-now'].value = '1234';
  p.el['pin-signin'].on.click();
  await settle();
  assert.strictEqual(p.el['code-status'].textContent, 'Type your six-digit PIN.');
  p.el['pin-now'].value = '135792';
  p.el['pin-signin'].on.click();
  await settle();
  const sent = p.calls.find((c) => c.url === '/auth/browser');
  assert.deepStrictEqual([...new URLSearchParams(sent.body).keys()].sort(), ['challenge', 'key_id', 'pin', 'sig']);
  assert.strictEqual(await signedBy(raw, sent.body), true, 'signed by this browser’s key with the site’s own address');
  assert.strictEqual(p.el['pin-now'].value, '');
  assert.ok(![...p.local.values(), ...p.session.values()].some((v) => String(v).includes('135792')), 'the PIN is kept nowhere');
  assert.strictEqual(p.sandbox.location.href, '/feed');
});

test('lane 3 on /join/pin: a cancelled key is dropped (and the flag), and the key file lane shows', async () => {
  const { keys } = await storedKey();
  const p = page({ keys, local: new Map([['dog-signin-key', '1']]), answers: reply({ '/auth/me': { signed_in: false }, '/auth/challenge': { challenge: CH },
    '/auth/browser': { cancelled: true, error: '10 wrong PINs were tried in this browser, so its sign-in key was cancelled.' } }) });
  await settle();
  p.el['pin-now'].value = '135792';
  p.el['pin-signin'].on.click();
  await settle();
  assert.strictEqual(keys.has('signin'), false);
  assert.strictEqual(p.local.has('dog-signin-key'), false);
  assert.deepStrictEqual([p.el['pin-lane'].hidden, p.el['file-lane'].hidden], [true, false]);
  assert.match(p.el['code-status'].textContent, /cancelled/);
});

test('lane 2 on /join/pin: the key file and the PIN, a first PIN typed twice (the review of 037, L3), and this browser keeps its new key', async () => {
  let answer = { confirm_pin: true, error: 'This is your first PIN. Type it again to set it.' };
  const p = page({ answers: reply({ '/auth/me': { signed_in: false }, '/auth/challenge': { challenge: CH }, '/auth/key': () => answer }) });
  await settle();
  assert.deepStrictEqual([p.el['pin-lane'].hidden, p.el['file-lane'].hidden], [true, false], 'no key here: the key file lane');
  p.el['code-login'].value = 'coder';
  p.el['code-file'].files = [{ size: 3, arrayBuffer: () => Promise.resolve(new Uint8Array([1, 2, 3]).buffer) }];
  p.el['key-pin'].value = '135792';
  p.el['key-signin'].on.click();
  await settle();
  assert.strictEqual(p.el['key-pin-again-field'].hidden, false, 'the second field shows');
  assert.strictEqual(p.el['code-status'].textContent, 'This is your first PIN. Type it again to set it.');
  answer = { signed_in: true, go: '/feed', key_id: '01a1ad69-0d9a-7687-a05a-5544ba899447' };
  p.el['key-pin'].value = '135792'; p.el['key-pin-again'].value = '135792';
  p.el['key-signin'].on.click();
  await settle();
  const sent = p.calls.filter((c) => c.url === '/auth/key').pop();
  const q = new URLSearchParams(sent.body);
  assert.deepStrictEqual([...q.keys()].sort(), ['challenge', 'file', 'label', 'login', 'pin', 'pin_again', 'pub', 'sig']);
  assert.strictEqual(q.get('label'), 'Firefox on Linux');
  assert.strictEqual(await signedBy(Buffer.from(q.get('pub'), 'base64url'), sent.body), true);
  const kept = p.keys.get('signin');
  assert.deepStrictEqual([kept.keyId, kept.privateKey.extractable, Object.keys(kept).sort()], ['01a1ad69-0d9a-7687-a05a-5544ba899447', false, ['keyId', 'privateKey']]);
  assert.strictEqual(p.local.get('dog-signin-key'), '1');
  assert.strictEqual(p.sandbox.location.href, '/feed');
});

test('lane 1\'s last step on /join/pin (?step=set): a new PIN typed twice, easy ones refused, the other browsers offered for removal, then this browser\'s key', async () => {
  let finish = { claimed: true, expires_in: 400, has_pin: true, browsers: 2 };
  const session = new Map([['dog-code', '{"code":"DOG-7K4M-Q2XH","until":1}']]);
  const p = page({ search: '?step=set&return_to=%2Ffeed', session, answers: reply({ '/auth/me': { signed_in: false }, '/auth/challenge': { challenge: CH }, '/auth/code/finish': () => finish }) });
  await settle();
  assert.deepStrictEqual([p.el['pin-set'].hidden, p.el.paths.hidden, p.el['file-lane'].hidden], [false, true, true]);
  assert.strictEqual(p.el['pin-remove-others-field'].hidden, false, 'a PIN set again, with other browsers: offered');
  assert.strictEqual(p.el['pin-others-count'].textContent, '2');
  assert.strictEqual(p.el['pin-remove-others'].checked, true, 'on by default');
  for (const [a, b, said] of [['135792', '135793', /aren’t the same/], ['123456', '123456', /harder to guess/], ['12345', '12345', /six digits/]]) {
    p.el['pin-new'].value = a; p.el['pin-again'].value = b;
    p.el['pin-save'].on.click();
    await settle();
    assert.match(p.el['code-status'].textContent, said, a);
  }
  finish = { signed_in: true, go: '/feed', key_id: '01a1ad69-0d9a-7687-a05a-5544ba899448' };
  p.el['pin-new'].value = '135792'; p.el['pin-again'].value = '135792';
  p.el['pin-save'].on.click();
  await settle();
  const sent = p.calls.filter((c) => c.url === '/auth/code/finish').pop();
  const q = new URLSearchParams(sent.body);
  assert.deepStrictEqual([...q.keys()].sort(), ['challenge', 'label', 'pin', 'pub', 'remove_others', 'return_to', 'sig']);
  assert.strictEqual(q.get('remove_others'), '1');
  assert.strictEqual(await signedBy(Buffer.from(q.get('pub'), 'base64url'), sent.body), true);
  assert.strictEqual(p.keys.get('signin').privateKey.extractable, false);
  assert.strictEqual(p.session.has('dog-code'), false, 'the code kept for the GitHub round trip is done');
  assert.strictEqual(p.session.get('dog-welcome'), '1', '/feed greets a first sign-in');
  assert.strictEqual(p.sandbox.location.href, '/feed');
  // A first PIN, or no other browsers: nothing to remove, so nothing is offered.
  const fresh = page({ search: '?step=set', answers: reply({ '/auth/me': { signed_in: false }, '/auth/code/finish': { claimed: true, expires_in: 400, has_pin: false, browsers: 0 } }) });
  await settle();
  assert.strictEqual(fresh.el['pin-remove-others-field'].hidden, true);
});
