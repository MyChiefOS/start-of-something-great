'use strict';
// Item 1.5 of the Nov 5 design handoff (Aaron, Nov 5: "PHASE 1 is cleared to proceed", 1.5 included): the owner's
// agents page moves from /agents to /account/agents, and /agents becomes the public agent directory. Nothing an owner
// already has stops working: a claim link (24 hours) or a notice made before the move is passed on.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { page, settle } = require('./helpers/mini-dom');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const ID = (n) => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');

test('the owner page is at /account/agents with its own script and styles; /agents is the directory', () => {
  const owner = read('account/agents.html');
  assert.match(owner, /<title>Your agents: Day One Great<\/title>/);
  assert.match(owner, /<link rel="canonical" href="https:\/\/dayonegreat\.com\/account\/agents">/);
  // 040: the design's own markup and styles (design.css); the page's old stylesheet is gone.
  assert.match(owner, /<link rel="stylesheet" href="\/design\.css">/);
  assert.ok(!fs.existsSync(path.join(root, 'account/agents.css')));
  assert.match(owner, /<script defer src="\/account\/agents\.js"><\/script>/);
  assert.match(owner, /href="\/join\?return_to=%2Faccount%2Fagents"/);
  const dir = read('agents.html');
  assert.match(dir, /<h1>Agent directory<\/h1>/);
  assert.match(dir, /<script defer src="\/agents\.js"><\/script>/);
  // It only passes a claim link on, to /claim (Nov 10), and claims nothing itself.
  const dirJs = read('agents.js');
  assert.match(dirJs, /if \(\/\(\?:\^#\|&\)claim=\/\.test\(location\.hash\)\) \{ location\.replace\('\/claim' \+ location\.hash\); return; \}/);
  assert.ok(!/claim|account\/agents\.js/.test(dirJs.replace(/^ *\/\/.*$/gm, '').replace(/'\/account\/agents' \+ location\.hash/, '').replace(/.*location\.replace\('\/claim' \+ location\.hash\).*/, '')), 'the directory script claims nothing');
});

test('every link that sends an owner to their agents goes to /account/agents', () => {
  const api = read('api/agents.js');
  // A claim link goes to the claim page, its own since Nov 10 (decided for JEVs, Q5); the code stays after "#".
  assert.match(api, /claim_url: ORIGIN \+ '\/claim#claim=' \+ code/);
  assert.match(api, /const REAUTH = '\/join\?return_to=%2Faccount%2Fagents';/);
  assert.match(read('api/feed.js'), /reauth: '\/join\?return_to=%2Faccount%2Fagents'/);
  assert.match(read('nav.js'), /mine\.setAttribute\('href', '\/account\/agents'\);/);
  assert.match(read('account.html'), /<a href="\/account\/agents">Your agents<\/a>/);
  assert.match(read('llms.txt'), /\[Your agents\]\(https:\/\/dayonegreat\.com\/account\/agents\)/);
  assert.match(read('llms.txt'), /\[Agent directory\]\(https:\/\/dayonegreat\.com\/agents\)/);
  // No page, script or API answer sends an owner to the old address any more.
  for (const f of ['api/agents.js', 'api/feed.js', 'nav.js', 'account.html', 'account/agents.js', 'account/agents.html', 'llms.txt', 'connect.html', 'signin/agentkey.js']) {
    // The shell's footer links the public directory (/agents), which is right; only the page's own links count here.
    // And a link that says it is the public directory (040).
    const s = read(f).replace(/<!-- shell:(top|foot) -->[\s\S]*?<!-- \/shell:\1 -->/g, '').replace(/<a href="\/agents">agent directory<\/a>/g, '').replace(/\/api\/agents/g, '');
    assert.ok(!/return_to=%2Fagents\b|ORIGIN \+ '\/agents[.#' ]|dayonegreat\.com\/agents[.#'"]|href="\/agents"/.test(s), f + ' still points owners to /agents');
  }
});

test('an old claim or notice link to /agents#... is passed on, part after "#" and all: a claim to /claim (Nov 10), the rest to /account/agents', async () => {
  for (const hash of ['#claim=' + 'a'.repeat(43), '#appeal=' + ID(9), '#create']) {
    const p = page('agents.html', 'agents.js', () => [200, { posts: [], next: null }], '', hash);
    await settle();
    assert.deepStrictEqual(p.replaced, [(hash.startsWith('#claim=') ? '/claim' : '/account/agents') + hash]);
    assert.deepStrictEqual(p.asked, [], 'and loads nothing itself');
  }
});

test('notices written before the move open the owner page, not the directory', () => {
  const js = read('account.js');
  assert.match(js, /n\.link\.replace\(\/\^\\\/agents\(\?=\$\|\[#\?\]\)\/, '\/account\/agents'\)/);
  // A challenge notice's sign-in link (011 writes /join?return_to=%2Fagents) comes back to the owner page too.
  assert.match(js, /\.replace\(\/\^\(\\\/join\\\?return_to=\)%2Fagents/);
  const map = (l) => l.replace(/^\/agents(?=$|[#?])/, '/account/agents');
  assert.deepStrictEqual(['/agents', '/agents#appeal=x', '/agentsx', '/account', '/api/agents'].map(map),
    ['/account/agents', '/account/agents#appeal=x', '/agentsx', '/account', '/api/agents']);
});

test('the directory (the design handoff, static/directory.html): one row per listed agent from the registry, who it acts for, its mode, limit and listed sub-agents', async () => {
  // 040: the list comes from the registry's public answer (GET /api/directory), no longer pieced together from posts.
  const ada = { id: ID(1), name: 'Ada', level: 2 };
  const agents = [
    { id: ID(21), name: 'Scout', owner: ada, mode: 'act', daily_cap: 20, sub_agents: 1 },
    { id: ID(22), name: 'Planner', owner: ada, mode: 'draft', daily_cap: 20, sub_agents: 0 },
    { id: ID(23), name: 'Quiet', owner: ada, mode: 'off', daily_cap: 20, sub_agents: 0 },
    { id: 'javascript:alert(1)', name: 'Bad id', owner: ada, mode: 'act', daily_cap: 5, sub_agents: 0 }
  ];
  const p = page('agents.html', 'agents.js', () => [200, { available: true, total: 3, agents, next: '/api/directory?before=' + ID(23) }]);
  await settle();
  assert.deepStrictEqual(p.asked, ['/api/directory']);
  const rows = p.$('dir').querySelectorAll('tr');
  assert.deepStrictEqual(rows.map((tr) => tr.querySelectorAll('td').map((td) => td.textContent)),
    [['Scout', 'Ada', 'Acts on its own', '20 a day', '1'], ['Planner', 'Ada', 'Drafts', 'Approval needed', '0'], ['Quiet', 'Ada', 'Off', 'Not posting', '0']]);
  assert.deepStrictEqual(rows[0].querySelectorAll('a').map((a) => a.getAttribute('href')), ['/agents/' + ID(21), '/member?id=' + ID(1)]);
  assert.deepStrictEqual(rows.map((tr) => tr.querySelector('.pill').className), ['pill a', 'pill', 'pill']);
  assert.strictEqual(p.$('dir-wrap').hidden, false);
  assert.strictEqual(p.$('counted').textContent, '3 agents listed');
  // The next page has an address of its own.
  assert.strictEqual(p.$('more').getAttribute('href'), '/agents?before=' + ID(23));
  const older = page('agents.html', 'agents.js', () => [200, { available: true, total: 3, agents: [], next: null }], '?before=' + ID(23));
  await settle();
  assert.deepStrictEqual(older.asked, ['/api/directory?before=' + ID(23)]);
  assert.match(older.$('dir-status').textContent, /No older agents/);
});

test('the directory says so when no agent is listed, when it isn\'t switched on, and when the list can\'t be read', async () => {
  const empty = page('agents.html', 'agents.js', () => [200, { available: true, total: 0, agents: [], next: null }]);
  await settle();
  assert.strictEqual(empty.$('dir-empty').hidden, false);
  assert.strictEqual(empty.$('dir-wrap').hidden, true);
  assert.strictEqual(empty.$('dir-empty').querySelector('a').getAttribute('href'), '/agents/join');
  const off = page('agents.html', 'agents.js', () => [200, { available: false, agents: [], message: 'The site’s database isn’t switched on here, so there are no agents to list.' }]);
  await settle();
  assert.match(off.$('dir-status').textContent, /isn’t switched on/);
  const down = page('agents.html', 'agents.js', () => [503, { error: 'The agent directory is being switched on. Please try again in a few minutes.' }]);
  await settle();
  assert.strictEqual(down.$('dir-status').textContent, 'The agent directory is being switched on. Please try again in a few minutes.');
  assert.strictEqual(down.$('retry-row').hidden, false);
});
