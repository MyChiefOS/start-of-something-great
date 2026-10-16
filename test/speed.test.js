// SF2, SF3, G6, O1: speed, load and review time. The full load test and the browser measurement are recorded in
// PERFORMANCE.md; these keep them working and hold the line between runs.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { weigh, BUDGET } = require('../scripts/page-weight');
const { simulate } = require('../scripts/review-time-sim');

const root = path.join(__dirname, '..');
// Pages over the SF2 budget today, each recorded in the risk register with a fix for Aaron to choose. They may not
// grow, and a page not listed here may not go over at all.
const KNOWN_OVER = { 'research/decision-loop.html': { risk: 'RK14', maxKB: 403 } };

test('SF2: every page\'s first visit is under 400 KB, apart from the recorded exceptions, which may not grow', () => {
  const risks = fs.readFileSync(path.join(root, 'RISKS.md'), 'utf8');
  for (const r of weigh()) {
    const known = KNOWN_OVER[r.page];
    if (known) {
      assert.ok(risks.includes('| ' + known.risk + ' |'), r.page + ' must be in the risk register as ' + known.risk);
      assert.ok(r.bytes <= known.maxKB * 1024, r.page + ' grew to ' + (r.bytes / 1024).toFixed(1) + ' KB');
    } else {
      assert.ok(r.bytes <= BUDGET, r.page + ' transfers ' + (r.bytes / 1024).toFixed(1) + ' KB on a first visit');
    }
  }
});

test('O1: at 1,000 members, Aaron\'s review averages 6 hours a week or less, and 9 weeks in 10 are under 10 hours', () => {
  const out = simulate(10000, 20261016);
  assert.ok(out.meanHours <= 6, 'mean ' + out.meanHours);
  assert.ok(out.under10 >= 0.9, 'under 10 hours in ' + out.under10);
  assert.ok(out.passes);
});

const SERVER = process.env.TEST_DATABASE_URL;
test('G6, SF3: a short load run (members, agents and the break-in checks together) has no errors and no violations', { skip: !SERVER && 'needs TEST_DATABASE_URL' }, () => {
  const out = execFileSync(process.execPath, [path.join(root, 'test', 'perf', 'load-test.js'), '120', '60', '5', '10'], { env: process.env, encoding: 'utf8', timeout: 120000 });
  assert.match(out, /errors: 0/);
  assert.match(out, /, 0 violations/);
  // SF3: uncached reads in under 1 second for 95% of requests (here against a local database).
  const p95 = Number(/read the people feed\s+\d+ requests\s+p50\s+\d+ ms\s+p95\s+(\d+) ms/.exec(out)[1]);
  assert.ok(p95 < 1000, 'p95 ' + p95 + ' ms');
});
