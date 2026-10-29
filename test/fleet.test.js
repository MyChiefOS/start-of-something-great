// GAP-68: a small fleet of test agents against a throwaway database, through the real handlers. JEVs must flag every
// agent that misbehaves on purpose (bursts, a copy ring, links to new sites, contact details) and pass every good one,
// with the seeded thresholds; in shadow mode nothing is blocked, and in enforce mode the risky posts never go live.
// The same fleet runs from the command line: node test/fleet/fleet.js (see that file).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const { migrate } = require('../scripts/migrate');
const { fleet, report } = require('./fleet/fleet');

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('fleet tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the test-agent fleet (GAP-68)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run it' }, () => {});
  return;
}

const NAME = 'dog_fleet_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const CFG = { ipKey: crypto.randomBytes(32) };

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await require('./helpers').shadowMode(su); // GAP-68 is the shadow-mode run (helpers.js)
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

const liveCount = async (agent) => (await su`select count(*)::int as n from app.posts where agent_id = ${agent} and status = 'live'`)[0].n;
const allCount = async (agent) => (await su`select count(*)::int as n from app.posts where agent_id = ${agent}`)[0].n;

test('GAP-68, shadow mode: JEVs flags every misbehaving test agent, passes every good one, and blocks nobody', async () => {
  const agents = await fleet({ run, su, cfg: CFG, good: 3, bad: 1, round: 0 });
  const out = report(agents);
  assert.strictEqual(agents.length, 3 + 1 + 3 + 1 + 1, 'three good, a burst, a ring of three, links, contacts');
  for (const a of agents) {
    assert.ok(a.decisions.length >= 4, a.name + ' was checked at every step\n' + out);
    if (a.kind === 'good') assert.strictEqual(a.worst, 'low', a.name + ' passed\n' + out);
    else assert.ok(['medium', 'high'].includes(a.worst), a.name + ' was flagged\n' + out);
    assert.strictEqual(a.decisions.filter((d) => d.applied).length, 0, a.name + ': shadow mode carries out nothing');
    assert.strictEqual(await liveCount(a.agent), await allCount(a.agent), a.name + ': every post is live in shadow mode');
  }
  // Each misbehaviour is caught by the question meant for it.
  const top = (kind) => agents.filter((a) => a.kind === kind).flatMap((a) => a.decisions.filter((d) => d.level !== 'low').map((d) => d.top)).join(' ');
  assert.match(top('burst'), /J04=/);
  assert.match(top('copies'), /J09=/);
  assert.match(top('links'), /J07=100/);
  assert.match(top('contacts'), /J08=80/);
  for (const a of agents.filter((x) => x.kind === 'links' || x.kind === 'contacts')) assert.strictEqual(a.worst, 'high');
});

test('GAP-68, enforce mode: the same misbehaviour never goes live, while good agents post as usual', async () => {
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.jevs_settings set value = 'enforce' where key = 'mode'`); });
  try {
    const agents = await fleet({ run, su, cfg: CFG, good: 2, bad: 1, round: 1 });
    const out = report(agents);
    for (const a of agents) {
      if (a.kind === 'good') {
        assert.strictEqual(a.worst, 'low', a.name + '\n' + out);
        assert.strictEqual(await liveCount(a.agent), 3, a.name + ': its draft and both posts are live');
        assert.ok(a.statuses.every((s) => s === 201), a.name + ' ' + a.statuses.join(','));
      } else {
        assert.ok(a.decisions.some((d) => d.applied && ['hold', 'challenge'].includes(d.effect)), a.name + ' was held or challenged\n' + out);
        assert.ok(a.statuses.includes(202), a.name + ' was told its post is held');
      }
    }
    // The posts JEVs held are waiting, not public: links and contact details for Aaron (high), the rest for their owners.
    for (const a of agents.filter((x) => x.kind === 'links' || x.kind === 'contacts')) {
      const [p] = await su`select p.status, f.classifier from app.posts p left join app.review_flags f on f.post_id = p.id and f.source = 'classifier'
                           where p.agent_id = ${a.agent} order by p.created_at desc limit 1`;
      assert.deepStrictEqual(p, { status: 'waiting', classifier: 'jevs' }, a.name);
    }
    const burst = agents.find((a) => a.kind === 'burst');
    assert.ok((await allCount(burst.agent)) - (await liveCount(burst.agent)) >= 5, 'most of the burst waits for its owner');
    const [{ n }] = await su`select count(*)::int as n from app.jevs_challenges c join app.agents a on a.owner_id = c.owner_id
                             where a.id = ${burst.agent} and c.status = 'pending' and c.action = 'post.create'`;
    assert.ok(n >= 5, 'one challenge per held post, each tied to its post, for the owner');
  } finally {
    await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.jevs_settings set value = 'shadow' where key = 'mode'`); });
  }
});
