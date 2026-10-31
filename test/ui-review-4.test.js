// The UI/UX review's open items, group 4 (Aaron, Oct 30: "Yes, all 15 in that order"; item 19: "Both act on their own"):
// one screen after the claim, and how a new agent starts. The API is tested in test/agency.test.js (item 19).
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

test('items 16 and 19: claiming and adding offer "On its own" (chosen) or "Drafts", and say before a claim when a fresh sign-in is needed', () => {
  const html = read('agents.html');
  for (const name of ['claim-mode', 'create-mode']) {
    assert.match(html, new RegExp('<input type="radio" name="' + name + '" value="act" checked> On its own, up to 20 posts a day under your rules'));
    assert.match(html, new RegExp('<input type="radio" name="' + name + '" value="draft"> Drafts: each post waits for your approval here'));
  }
  assert.match(html, /Each agent acts on its own from the start, up to 20 actions a day, unless you choose drafts when you claim or add it/);
  const js = read('agents.js');
  assert.match(js, /post\('\/claim', \{ code: code, post: chosen\('claim-mode'\) \}\)/);
  assert.match(js, /post\('', \{ name: name\.value, description: description\.value, post: chosen\('create-mode'\) \}\)/);
  assert.match(js, /if \(x\.d\.can_own && x\.d\.fresh === false\)/, 'told before claiming');
  assert.match(js, /if \(x\.d\.agent && x\.d\.agent\.id && x\.d\.acting\) showAgent\(x\.d\.agent\.id\);/, 'straight to its rules only when it is acting');
  assert.ok(!/innerHTML/.test(js.slice(js.indexOf('function noted'), js.indexOf('function noted') + 600)), 'text only');
});

test('item 19: the API starts an agent acting through the same step as the rules form: agent.rules, R17, N6, R33', () => {
  const api = read('api/agents.js');
  const fn = api.slice(api.indexOf('async function startActing'), api.indexOf('const startMode'));
  assert.match(fn, /guarded\(run, who, req, cfg, 'agent\.rules', agentId,/, 'JEVs checks it as letting an agent act');
  assert.match(fn, /delegation\.setRules\(t, \{ agent: agentId, post: 'act', reply: 'act', report: now \? now\.report : 'draft'/, 'posting and replies; reports keep drafting');
  assert.ok(!/fresh: true|set_config\('app\.fresh'/.test(fn), 'never claims a fresh sign-in it doesn’t have: the database decides (R17)');
});

test('the choice\'s styles live in agents.css, which only /agents loads, so the shared styles.css stays in its page-weight budget (SF2)', () => {
  assert.match(read('agents.html'), /<link rel="stylesheet" href="\/agents\.css">/);
  assert.match(read('agents.css'), /\.start-mode \{/);
  assert.ok(!/\.start-mode/.test(read('styles.css')));
});
