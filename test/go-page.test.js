// /go (088): the click-time link check. GO1 only http and https addresses are used, rebuilt from their parts;
// GO2 a clear link is never followed without the person's click (no open redirect, CWE-601); GO3 blocked hides the
// way on; GO4 a failed check still offers the link, at the person's own risk.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { page, settle } = require('./helpers/mini-dom.js');

const open = (u, verdict, why) => page('go.html', 'go.js', () => (verdict ? [200, { data: { verdict, why } }] : [503, {}]), '?u=' + encodeURIComponent(u));

test('GO1 only http and https links are used; anything else is refused before any check', async () => {
  for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'JaVaScRiPt:alert(1)', '//evil.example', 'not a link', 'x'.repeat(2001)]) {
    const p = open(bad, 'ok');
    await settle();
    assert.strictEqual(p.asked.length, 0, bad);
    assert.strictEqual(p.$('go-acts').hidden, true, bad);
  }
});

test('GO2 a clear link is offered, never followed on its own', async () => {
  const p = open('https://example.org/a?b=1#c', 'ok');
  await settle();
  assert.deepStrictEqual(p.replaced, []);
  assert.strictEqual(p.$('go-on').getAttribute('href'), 'https://example.org/a?b=1#c');
  assert.strictEqual(p.$('go-on').textContent, 'Open the link');
  assert.strictEqual(p.$('go-acts').hidden, false);
});

test('GO3 a blocked link has no way on; GO4 an unchecked one is offered at the person\'s risk', async () => {
  const b = open('https://bad.example/', 'blocked', 'on a threat list');
  await settle();
  assert.strictEqual(b.$('go-on').hidden, true);
  assert.match(b.$('go-status').textContent, /^Stopped: on a threat list/);
  const f = open('https://example.org/', null);
  await settle();
  assert.strictEqual(f.$('go-on').textContent, 'Go on anyway');
  assert.match(f.$('go-status').textContent, /at your own risk/);
});
