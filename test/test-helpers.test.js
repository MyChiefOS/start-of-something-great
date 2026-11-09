// The tests' own helpers, where a mistake would hide a failure or make one up.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { clearOfWindow } = require('./helpers');

test('clearOfWindow waits past a window\'s edge only when a count would cross it (the Nov 9 CI failure at 21:30:00.05 UTC)', async () => {
  const real = Date.now;
  try {
    // 20 seconds before a 10-minute edge: clear enough, no wait.
    Date.now = () => 600000 * 1000 - 20000;
    let t0 = real();
    await clearOfWindow(600);
    assert.ok(real() - t0 < 100, 'no wait when well clear');
    // 300 ms before the edge: it waits until just past it.
    Date.now = () => 600000 * 1000 - 300;
    t0 = real();
    await clearOfWindow(600);
    const waited = real() - t0;
    assert.ok(waited >= 500 && waited < 1000, 'waited ' + waited + ' ms');
  } finally {
    Date.now = real;
  }
});
