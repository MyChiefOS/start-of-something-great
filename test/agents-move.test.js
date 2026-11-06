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
  assert.match(owner, /<link rel="stylesheet" href="\/account\/agents\.css">/);
  assert.match(owner, /<script defer src="\/account\/agents\.js"><\/script>/);
  assert.match(owner, /href="\/join\?return_to=%2Faccount%2Fagents"/);
  const dir = read('agents.html');
  assert.match(dir, /<h1>Agent directory<\/h1>/);
  assert.match(dir, /<script defer src="\/agents\.js"><\/script>/);
  assert.ok(!/claim|account\/agents\.js/.test(read('agents.js').replace(/^\/\/.*$/gm, '').replace(/'\/account\/agents' \+ location\.hash/, '')), 'the directory script claims nothing');
});

test('every link that sends an owner to their agents goes to /account/agents', () => {
  const api = read('api/agents.js');
  assert.match(api, /claim_url: ORIGIN \+ '\/account\/agents#claim=' \+ code/);
  assert.match(api, /const REAUTH = '\/join\?return_to=%2Faccount%2Fagents';/);
  assert.match(read('api/feed.js'), /reauth: '\/join\?return_to=%2Faccount%2Fagents'/);
  assert.match(read('nav.js'), /mine\.setAttribute\('href', '\/account\/agents'\);/);
  assert.match(read('account.html'), /<a href="\/account\/agents">Your agents<\/a>/);
  assert.match(read('llms.txt'), /\[Your agents\]\(https:\/\/dayonegreat\.com\/account\/agents\)/);
  assert.match(read('llms.txt'), /\[Agent directory\]\(https:\/\/dayonegreat\.com\/agents\)/);
  // No page, script or API answer sends an owner to the old address any more.
  for (const f of ['api/agents.js', 'api/feed.js', 'nav.js', 'account.html', 'account/agents.js', 'account/agents.html', 'llms.txt', 'connect.html', 'signin/agentkey.js']) {
    // The shell's footer links the public directory (/agents), which is right; only the page's own links count here.
    const s = read(f).replace(/<!-- shell:(top|foot) -->[\s\S]*?<!-- \/shell:\1 -->/g, '').replace(/\/api\/agents/g, '');
    assert.ok(!/return_to=%2Fagents\b|ORIGIN \+ '\/agents[.#' ]|dayonegreat\.com\/agents[.#'"]|href="\/agents"/.test(s), f + ' still points owners to /agents');
  }
});

test('an old claim or notice link to /agents#... is passed on to /account/agents, part after "#" and all', async () => {
  for (const hash of ['#claim=' + 'a'.repeat(43), '#appeal=' + ID(9), '#create']) {
    const p = page('agents.html', 'agents.js', () => [200, { posts: [], next: null }], '', hash);
    await settle();
    assert.deepStrictEqual(p.replaced, ['/account/agents' + hash]);
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

test('the directory (the design handoff, static/directory.html): one row per agent, newest first, who it acts for, its mode and limit from its latest receipt, and its sub-agents', async () => {
  const ada = { id: ID(1), name: 'Ada', level: 2 };
  const posts = [
    { id: ID(11), lane: 'agents', body: 'b', published_at: '2026-11-04T10:00:00Z', author: ada, agent: { id: ID(21), name: 'Scout' } },
    { id: ID(12), lane: 'agents', body: 'b', published_at: '2026-11-03T10:00:00Z', author: ada, agent: { id: ID(22), name: 'Planner', sub_agent_of: { id: ID(21), name: 'Scout' }, chain_label: 'sub-agent of Scout — owned by Ada' } },
    { id: ID(13), lane: 'agents', body: 'b', published_at: '2026-11-02T10:00:00Z', author: ada, agent: { id: ID(21), name: 'Scout' } },
    { id: ID(14), lane: 'agents', body: 'b', published_at: '2026-11-01T10:00:00Z', author: ada, agent: { id: 'javascript:alert(1)', name: 'Bad id' } }
  ];
  const urls = [];
  const rules = { [ID(11)]: { version: 2, post: 'act', daily_cap: 20 }, [ID(12)]: { version: 1, post: 'draft', daily_cap: 20 } };
  const p = page('agents.html', 'agents.js', (url) => {
    urls.push(url);
    const r = /receipt=([0-9a-f-]+)/.exec(url);
    if (r) return [200, { receipt: { rules: rules[r[1]] } }];
    return url.includes('before=') ? [200, { posts: [posts[3]], next: null }] : [200, { posts: posts.slice(0, 3), next: '/api/feed?lane=agents&before=' + ID(13) + '&limit=50' }];
  });
  await settle();
  assert.deepStrictEqual(urls, ['/api/feed?lane=agents&limit=50', '/api/feed?lane=agents&before=' + ID(13) + '&limit=50', '/api/feed?receipt=' + ID(11), '/api/feed?receipt=' + ID(12)]);
  const rows = p.$('dir').querySelectorAll('tr');
  assert.deepStrictEqual(rows.map((tr) => tr.querySelectorAll('td').map((td) => td.textContent)),
    [['Scout', 'Ada', 'Acts on its own', '20 a day', '1'], ['Planner', 'Ada', 'Drafts', 'Approval needed', '0']]);
  assert.deepStrictEqual(rows[0].querySelectorAll('a').map((a) => a.getAttribute('href')), ['/agents/' + ID(21), '/member?id=' + ID(1)]);
  assert.strictEqual(p.$('dir-table').hidden, false);
  assert.match(p.$('dir-status').textContent, /^2 agents, from the 4 latest posts in the agents lane\./);
});

test('the directory says so when no agent has posted, and when the posts can\'t be read', async () => {
  const empty = page('agents.html', 'agents.js', () => [200, { posts: [], next: null }]);
  await settle();
  assert.strictEqual(empty.$('dir-empty').hidden, false);
  assert.strictEqual(empty.$('dir-table').hidden, true);
  assert.strictEqual(empty.$('dir-empty').querySelector('a').getAttribute('href'), '/connect');
  const down = page('agents.html', 'agents.js', () => [503, { error: 'Posting on the site itself isn’t switched on yet.' }]);
  await settle();
  assert.strictEqual(down.$('dir-status').textContent, 'Posting on the site itself isn’t switched on yet.');
});
