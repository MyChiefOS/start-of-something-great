// The red-team copy's attack plan on every PR (RK141, harness/STANDARDS.md gap 1; OWASP A01, A05, A10; CWE-352, CWE-862).
// redteam/copy.js runs the real API handlers against a throwaway database with made-up accounts; redteam/baseline.json
// is the plan. A step that comes back other than expected fails the build, and so does any answer of 500.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { expand, judge, report, routes } = require('../redteam/plan');
const baseline = require('../redteam/baseline.json');

test('red-team plans: they are data, checked before they run, and every failure is reported', () => {
  assert.throws(() => expand({ steps: [{ path: '/api/feed', as: 'root' }] }), /unknown account/);
  assert.throws(() => expand({ steps: [{ path: 'https://evil.example/' }] }), /under \/api\//);
  assert.throws(() => expand({ steps: [{ path: '/api/feed', method: 'DELETE' }] }), /GET or POST/);
  assert.throws(() => expand({ steps: [{ each: 'everything' }] }), /unknown "each"/);
  assert.throws(() => expand({ steps: Array.from({ length: 501 }, () => ({ path: '/api/feed' })) }), /at most 500/);
  assert.deepStrictEqual(judge({ expect: { status: 403 } }, { status: 403 }), []);
  assert.match(judge({ expect: { status: 403 } }, { status: 200 }).join(), /expected 403/);
  assert.match(judge({}, { status: 500 }).join(), /mishandled/, 'a 500 always fails');
  assert.match(judge({ expect: { range: '4xx' } }, { status: 201 }).join(), /refusal/);
  assert.match(report([{ name: 'x | y', as: 'anon', status: 200, ok: false, why: 'answered 200' }]), /x \\\| y/);
  const r = routes();
  assert.ok(r.write.includes('/api/work/claim') && r.write.includes('/api/agents/rules') && r.read.includes('/api/work/admin'));
  assert.ok(expand(baseline).length > 200, 'the baseline covers every route');
});

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('the red-team copy needs TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the red-team copy against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run it' }, () => {});
  return;
}

const { start } = require('../redteam/copy');
const { runPlan } = require('../redteam/plan');
let copy;
test.before(async () => { copy = await start(SERVER); });
test.after(async () => { if (copy) await copy.close(); });

test('the red-team copy works: its accounts are real, so refusals mean something', async () => {
  // Without this, a broken copy (no session, no database) would refuse everything and every attack would "pass".
  const r = await runPlan(copy, { steps: [
    { name: 'a member reads their own work', as: 'memberA', path: '/api/work/mine', expect: { status: 200 } },
    { name: 'the administrator reads the admin queue', as: 'admin', path: '/api/work/admin', expect: { status: 200 } },
    { name: 'anyone reads the public summary', as: 'anon', path: '/api/work/summary', expect: { status: 200 } },
    { name: 'a member reads their notices', as: 'memberA', path: '/api/notify', expect: { status: 200 } }
  ] });
  assert.deepStrictEqual(r.filter((x) => !x.ok), []);
});

test('RK141, the baseline attack plan: every step comes back as expected', async () => {
  const results = await runPlan(copy, baseline);
  const failed = results.filter((x) => !x.ok);
  assert.deepStrictEqual(failed, [], report(results));
});

test('the 403s come from the origin check: the same write from the site itself gets past it', async () => {
  // So A2 would fail if a route lost its origin check, rather than passing on some other refusal.
  const routesToTry = ['/api/work/claim', '/api/work/projects', '/api/feed', '/api/agents/rules', '/api/notify/read'];
  const cross = await runPlan(copy, { steps: routesToTry.map((p) => ({ name: 'cross ' + p, as: 'memberA', method: 'POST', path: p, body: {},
    headers: { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' }, expect: { status: 403 } })) });
  const same = await runPlan(copy, { steps: routesToTry.map((p) => ({ name: 'same ' + p, as: 'memberA', method: 'POST', path: p, body: {},
    expect: { not: [403] } })) });
  assert.deepStrictEqual(cross.filter((x) => !x.ok), [], 'refused from another site');
  assert.deepStrictEqual(same.filter((x) => !x.ok), [], 'not refused by the origin check from our own site');
});
