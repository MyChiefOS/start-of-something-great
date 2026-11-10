// The red-team copy's first check (RK141, harness/STANDARDS.md gap 1; OWASP A01, CWE-862). See redteam/catalog.js.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const { migrate } = require('../scripts/migrate');
const { unchecked, compare } = require('../redteam/catalog');
const reviewed = require('../redteam/reviewed-functions.json');

test('the red-team catalog check: a function with no reason, or a stale reason, is reported; open holes name their risk', () => {
  const r = { a: { kind: 'public read', why: 'x' }, b: { kind: 'open', risk: 'RK1', why: 'y' }, gone: { kind: 'timer', why: 'z' } };
  assert.deepStrictEqual(compare(['a', 'b', 'new'], r), { unreviewed: ['new'], stale: ['gone'], open: ['b (RK1)'] });
  for (const [name, e] of Object.entries(reviewed)) {
    if (name === '_about') continue;
    assert.ok(e.kind && e.why, name + ' has a kind and a reason');
    if (e.kind === 'open') assert.match(e.risk, /^RK\d+$/, name + ' names its risk');
  }
});

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('the red-team catalog check needs TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the red-team catalog check against a copy', { skip: 'set TEST_DATABASE_URL to a Postgres server to run it' }, () => {});
  return;
}

const NAME = 'dog_redteam_' + crypto.randomBytes(4).toString('hex');
let server, su;
const at = (d) => { const u = new URL(SERVER); u.pathname = '/' + d; return u.toString(); };
test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
});
test.after(async () => {
  if (su) await su.end({ timeout: 5 });
  if (server) { await server.unsafe(`drop database if exists ${NAME} with (force)`); await server.end({ timeout: 5 }); }
});

test('RK141, the catalog: every definer function the site\'s role can run checks who is acting, or has a reviewed reason', async () => {
  const r = compare(await unchecked(su), reviewed);
  assert.deepStrictEqual(r.unreviewed, [], 'definer functions the site\'s role can run with no actor check and no reason in redteam/reviewed-functions.json');
  assert.deepStrictEqual(r.stale, [], 'reasons in redteam/reviewed-functions.json for functions that no longer need one: remove them');
  // The open holes, said plainly in the test output until each is fixed.
  // RK140 closed by 055: app.work_github_sync is no longer the site's to run (only dog_ghsync's, test/github-facts.test.js).
  // RK135, RK144 and RK112 closed by 057: app.tl_claim and app.tl_decide are dog_looks's, app.log_witness_report
  // dog_witness's and app.log_proposal internal to dog_ghsync's batch (test/holes.test.js). None is left open.
  assert.deepStrictEqual(r.open.sort(), []);
});

test('RK141, the catalog: a planted hole is caught, and one that checks who is acting is not', async () => {
  await su.unsafe(`create function app.rt_planted(p text) returns text language sql security definer set search_path = pg_catalog as $$ select p $$;
    grant execute on function app.rt_planted(text) to dog_app;
    create function app.rt_guarded(p text) returns text language plpgsql security definer set search_path = pg_catalog as $$
      begin if app.actor_kind() is null then raise exception 'nobody'; end if; return p; end $$;
    grant execute on function app.rt_guarded(text) to dog_app;
    create function app.rt_via(p text) returns text language sql security definer set search_path = pg_catalog as $$ select app.rt_guarded(p) $$;
    grant execute on function app.rt_via(text) to dog_app;`);
  try {
    const r = compare(await unchecked(su), reviewed);
    assert.deepStrictEqual(r.unreviewed, ['rt_planted']);
  } finally {
    await su.unsafe('drop function app.rt_planted(text); drop function app.rt_via(text); drop function app.rt_guarded(text)');
  }
});
