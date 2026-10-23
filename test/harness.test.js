// The harness (Aaron, Oct 23, 2026: "develop a harness for yourself ... to give us a higher probability of getting the
// results and outcomes"). These tests keep it present and working, so it can't drift away by deletion either.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const { evaluate, table, report } = require('../harness/check');

test('CLAUDE.md sends every session to the charter, then the live check and the harness', () => {
  const c = read('CLAUDE.md');
  assert.match(c, /npm run harness/);
  for (const f of ['harness/NORTH-STAR.md', 'harness/RULES.md', 'harness/FACTS.md', 'CHARTER.md']) assert.ok(c.includes(f), f);
  assert.ok(c.indexOf('CHARTER.md') < c.indexOf('npm run harness'), 'the charter is read first, as it says itself');
  assert.strictEqual(JSON.parse(read('package.json')).scripts.harness, 'node harness/check.js');
});

test('the North Star keeps the five outcomes, the goal, the quality bar and the shipping standard', () => {
  const n = read('harness/NORTH-STAR.md');
  for (const s of [/trusted/, /agents do more/i, /pain point/, /remove friction/i, /in public/i, /fully functional production site/, /"Mostly" is a fail/, /Ship small and often, to main/]) assert.match(n, s);
});

test('the rules keep all seven, each with its reason', () => {
  const r = read('harness/RULES.md');
  const rules = r.split('\n').filter((l) => /^\d\. \*\*/.test(l));
  assert.ok(rules.length >= 5, 'the rules are there (deleting one is allowed, with Aaron)');
  for (const s of ['Ship to main', 'Requirement gate', 'Know or say you don\'t', 'Facts survive sessions', 'Ask once', 'Review in proportion', 'The stop list']) assert.ok(r.includes(s), s);
  assert.ok((r.match(/\*Why:/g) || []).length >= 4, 'the rules say why');
});

test('every fact in the ledger has a known status, a source and a date', () => {
  const md = read('harness/FACTS.md');
  const rows = table(md, 'Goal').concat(table(md, 'Systems'));
  assert.ok(rows.length >= 5);
  for (const r of rows) {
    assert.match(r[1], /^(stated|checked|assumed|replaced)$/, 'status of: ' + r[0]);
    assert.ok(r[2].length > 3, 'source of: ' + r[0]);
    assert.match(r[3], /^20\d\d-\d\d-\d\d$/, 'date of: ' + r[0]);
  }
  for (const r of table(md, 'Goal').concat(table(md, 'Systems')).filter((x) => x[1] === 'stated')) assert.match(r[2], /Aaron/, 'a stated fact quotes Aaron: ' + r[0]);
  assert.ok(table(md, 'Launch path').length >= 3);
});

test('the check stops on a PR that does not target main, and warns on work waiting off main', () => {
  const now = Date.parse('2026-10-23T12:00:00Z');
  const f = evaluate({ now, prs: [{ number: 34, base: 'launch-ops', head: 'passkeys-pr17' }, { number: 36, base: 'main', head: 'security-batch-1' }],
    offMainOldest: '2026-10-17T08:00:00Z', mainLastChange: '2026-10-19T23:17:40Z', signIn: 'off', setupRuns: 0, factsMd: read('harness/FACTS.md') });
  const stops = f.filter((x) => x.level === 'stop');
  assert.strictEqual(stops.length, 1);
  assert.match(stops[0].text, /PR #34 .*targets "launch-ops", not main/);
  assert.ok(f.some((x) => /not yet on main was made 6 days ago/.test(x.text)));
  assert.ok(f.some((x) => /Open PRs: #34 passkeys-pr17 -> launch-ops; #36 security-batch-1 -> main/.test(x.text)));
  assert.ok(f.some((x) => /2 PRs are open/.test(x.text)));
  assert.ok(f.some((x) => /Nothing has reached main for 3 days/.test(x.text)));
  assert.ok(f.some((x) => /Sign-in is off on the live site/.test(x.text)));
  assert.ok(f.some((x) => /never run/.test(x.text)));
  assert.ok(f.some((x) => /Launch path, left in order: 1\./.test(x.text)));
});

test('the check flags assumed and stale facts, too many open questions, and a missing ledger', () => {
  const now = Date.parse('2026-11-30T00:00:00Z');
  const md = ['# x', '## Systems', '| Fact | Status | Source | Date |', '|---|---|---|---|', '| a | assumed | s | 2026-10-23 |', '| b | checked | s | 2026-10-01 |',
    '## Open for Aaron', '| Q | Asked | Answer |', '|---|---|---|', '| 1 | d | |', '| 2 | d | |', '| 3 | d | |', '| 4 | d | |', '| 5 | d | yes |'].join('\n');
  const f = evaluate({ now, prs: [], factsMd: md });
  assert.ok(f.some((x) => x.rule === 3 && /1 fact\(s\) are only assumed/.test(x.text)));
  assert.ok(f.some((x) => x.rule === 3 && /over a week old/.test(x.text)));
  assert.ok(f.some((x) => x.rule === 5 && /4 questions are waiting/.test(x.text)));
  assert.ok(evaluate({ now, prs: [], factsMd: '' }).some((x) => x.level === 'stop' && x.rule === 4));
  assert.ok(!evaluate({ now: Date.parse('2026-10-23T12:00:00Z'), prs: [{ number: 36, base: 'main', head: 'x' }], offMainOldest: '2026-10-23T11:00:00Z', factsMd: md }).some((x) => x.level === 'stop'),
    'a PR to main with fresh work raises no stop');
  assert.match(report({ now, notChecked: ['live sign-in'] }, f), /Not checked: live sign-in\./, 'anything unreachable is said, not guessed');
});
