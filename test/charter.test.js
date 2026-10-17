// The charter keeps every engagement aligned (Aaron, Oct 16, 2026). This test fails the build if CLAUDE.md stops
// pointing at it, or if any part it must carry goes missing, so drift can't creep in by deletion.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('CLAUDE.md sends every session to the charter first', () => {
  const c = read('CLAUDE.md');
  assert.match(c, /CHARTER\.md/);
  assert.match(c, /engagement checklist/i);
  assert.match(c, /alignment footer/i);
});

test('the charter keeps its goals, standing decisions, handshake, loop, checklist, footer and sub-agent brief', () => {
  const c = read('CHARTER.md');
  for (const h of ['## 1. What we are building, and why', '## 2. Standing decisions', '## 3. How we work (the handshake)', '## 4. The decision loop',
    '## 5. The engagement checklist', '## 6. The alignment footer', '## 7. What drift looks like', '## 8. Sub-agent brief']) {
    assert.ok(c.includes(h), 'missing section: ' + h);
  }
  for (const goal of [/trusted/i, /agents do more/i, /scale/i, /in public/i]) assert.match(c, goal);
  for (const rule of [/Stripe Identity is the planned future check/, /LinkedIn is dropped/, /promoted by hand/, /read-only/, /go-live decision/]) assert.match(c, rule);
  for (const rule of [/Pull requests queue up; Aaron merges every one, in order/, /are you sure\?/, /OPERATIONS\.md/, /never read keys/i, /Game-changing/]) assert.match(c, rule);
  for (const field of ['Loop tier', 'Goals served', 'Standing decisions touched', 'Fresh-agent review', 'Open for Aaron']) assert.ok(c.includes(field), 'footer field: ' + field);
});

test('every standing decision is dated', () => {
  const c = read('CHARTER.md');
  const sec = c.split('## 2. Standing decisions')[1].split('## 3.')[0];
  const rows = sec.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Decision') && !l.startsWith('|---'));
  assert.ok(rows.length >= 5, 'expected the standing decisions table');
  for (const r of rows) assert.match(r, /\| [A-Z][a-z]{2} \d{1,2}, 20\d\d \|$/, 'undated decision: ' + r);
});
