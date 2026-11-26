// The agent-facing copy for SOLO (Aaron: "SOLO is the home page", the agent copy "in the same release"). Each file an
// agent reads introduces SOLO, and each figure it states is the one the code uses (079, 092). No database needed.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const SOLO = 'https://dayonegreat.com/solo';
const FILES = ['llms.txt', 'connect.html', 'agents/join.html', 'openapi.json', '.well-known/agent-card.json', 'api/mcp.js'];

test('every agent-facing file introduces SOLO with its routes and the /solo link', () => {
  for (const f of FILES) {
    const t = read(f);
    assert.ok(t.includes(SOLO) || t.includes('href="/solo"'), f + ' links /solo');
    assert.match(t, /\/api\/work\/portfolio\?agent=/, f + ' names the portfolio route');
    assert.match(t, /\/api\/work\/crew\/split/, f + ' names the crew route');
    assert.match(t, /no owner/i, f + ' says an agent works with no owner');
  }
});

test('the routes the copy names exist on main', () => {
  const work = require('../api/work.js');
  assert.ok(work.PUBLIC.portfolio, 'GET /api/work/portfolio');
  assert.deepStrictEqual(work.PUBLIC.portfolio.keys, ['agent']);
  assert.ok(work.WRITES['crew/split'], 'POST /api/work/crew/split');
  assert.strictEqual(work.WRITES['crew/split'].agentOnly, true);
  assert.match(read('api/agents.js'), /claim_expires_in_hours: null/, 'the claim link has no time limit');
});

test('the crew figures in the copy are the database’s', () => {
  const sql = read('db/migrations/092_solo_features.sql');
  assert.match(sql, /jsonb_array_length\(p_pieces\) not between 2 and 8/);
  assert.match(sql, /<> all \(array\[1, 2, 3, 5, 8\]\)/);
  assert.match(sql, /if total <> t\.size then/);
  for (const f of ['llms.txt', 'agents/join.html']) assert.match(read(f), /2 to 8 pieces/, f);
  assert.match(read('agents/join.html'), /sized 1, 2, 3, 5 or 8, adding up to the task's own size/);
  // The band's line: provisional under 10 audited (092's work_portfolio).
  assert.match(sql, /'provisional', coalesce\(\(c ->> 'audited'\)::integer, 0\) < 10/);
  assert.match(read('llms.txt'), /provisional under 10 audited/);
});

test('no line says an agent needs an owner to work, and the dropped claims are gone', () => {
  const join = read('agents/join.html');
  for (const gone of ['No points yet.', 'Nothing you write goes out until a person is accountable', 'Day One Great requires it',
    'Not built: connecting from the Claude apps', 'proposed for phase 5 and not built']) {
    assert.ok(!join.includes(gone), 'agents/join.html no longer says ' + JSON.stringify(gone));
  }
  assert.ok(!/once their owner claims them, post/.test(read('llms.txt')));
  assert.ok(!/a registered agent has a human owner/.test(read('llms.txt')));
  assert.ok(!/With a key their owner claims/.test(read('connect.html')));
  assert.ok(!/register, then the person claims it/.test(read('.well-known/agent-card.json')));
});

test('the OpenAPI register limits are the code’s: a name of 1 to 32, a description up to 500', () => {
  assert.match(read('db/agents.js'), /const NAME_MAX = 32;/);
  const reg = JSON.parse(read('openapi.json')).paths['/api/agents/register'].post.requestBody.content['application/json'].schema.properties;
  assert.deepStrictEqual([reg.name.minLength, reg.name.maxLength, reg.description.maxLength], [1, 32, 500]);
  const { build } = require('../scripts/openapi.js');
  assert.deepStrictEqual(JSON.parse(read('openapi.json')), JSON.parse(JSON.stringify(build())), 'openapi.json is regenerated');
});

test('the MCP tools say what a solo agent can and can’t do', () => {
  const act = read('api/_mcp-act.js');
  assert.match(act, /An agent with no owner checks work on its own tasks itself/);
  // 046: the database refuses any agent's dispute.
  assert.match(read('db/migrations/046_disputes.sql'), /a person disputes work, not an agent/);
  assert.match(act, /an agent with no owner can’t dispute/);
});

test('the SOLO copy has no payment or earning language', () => {
  for (const f of FILES) {
    const t = read(f);
    const start = t.indexOf('SOLO');
    const part = t.slice(start, start + 1500);
    assert.ok(!/\b(earn(s|ing)? (money|cash|income)|get paid|payout|path to earning)\b/i.test(part), f + ' has no earning language near SOLO');
  }
});
