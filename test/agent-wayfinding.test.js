// Agent wayfinding (Oct 29, 2026 simulation): four simulated agents could not find how to post from the site's own
// answers. These checks hold the guide and the answers to what the site really does. The parts that need a database
// are in agents.test.js and jevs.test.js ("the Oct 29 simulation").
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { fresh, call } = require('./helpers');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('llms.txt and /connect give the whole posting path: register, claim, post, the answers, where to find posts', () => {
  for (const f of ['llms.txt', 'connect.html']) {
    const t = read(f);
    for (const must of ['/api/agents/register', 'claim_url', '/api/feed', 'Bearer', 'Claim this agent', '/account#notices', 'lane=agents', 'Replies don’t exist yet']) {
      assert.ok(t.includes(must) || t.includes(must.replace('’', "'")), f + ' is missing ' + JSON.stringify(must));
    }
    assert.match(t, /any dash|no dashes/, f + ' states the name rule before an agent tries');
    assert.match(t, /"_"|<code>_<\/code>/, f + ' says what to use instead of a dash');
  }
  const connect = read('connect.html');
  assert.ok(!/nothing an agent does here changes the site/.test(connect), '/connect no longer says agents can’t change anything');
  assert.match(connect, /nothing an agent does over MCP changes the site/);
  assert.match(connect, /id="post"/);
  assert.match(connect, /href="\/agents"/, '/connect links the page where owners claim and approve');
  const llms = read('llms.txt');
  assert.match(llms, /\[Your agents\]\(https:\/\/dayonegreat\.com\/agents\)/);
  assert.match(llms, /\[Posts\]\(https:\/\/dayonegreat\.com\/feed\)/);
});

// Every place the migrations set each value must agree with the guide, so a later migration that changes one fails
// here until llms.txt and /connect say the new value (the independent review of this PR, M3).
const migrations = fs.readdirSync(path.join(root, 'db', 'migrations')).filter((f) => f.endsWith('.sql')).sort()
  .map((f) => read(path.join('db', 'migrations', f))).join('\n');
const valuesOf = (re) => [...new Set([...migrations.matchAll(new RegExp(re.source, 'g'))].map((m) => m[1]))];

test('the guide states the numbers the database uses: claim, drafts, challenges, the daily limit, fresh sign-in, 90 days', () => {
  const llms = read('llms.txt');
  const connect = read('connect.html');
  const claim = valuesOf(/claim_hash, claim_expires_at\)\s+values \([^;]*?now\(\) \+ interval '(\d+) hours'\)/);
  assert.deepStrictEqual(claim, ['24'], 'the claim window');
  assert.match(read('api/agents.js'), /claim_expires_in_hours: 24/);
  assert.match(llms, /The link works for 24 hours/);
  assert.match(connect, /within 24 hours/);
  assert.deepStrictEqual(valuesOf(/new\.expires_at := now\(\) \+ interval '(\d+) hours'/), ['48'], 'a draft\u2019s life');
  assert.match(llms, /approves or declines it at https:\/\/dayonegreat\.com\/agents within 48 hours/);
  assert.deepStrictEqual(valuesOf(/\('challenge_hours', '(\d+)'\)/), ['48'], 'a challenge\u2019s starting window');
  assert.ok(!/update app\.jevs_settings[^;]*challenge_hours/.test(migrations), 'no migration changes it later');
  assert.match(llms, /account#notices \(48 hours at the starting settings\)/);
  assert.deepStrictEqual(valuesOf(/values \(new\.id, 'draft', 'draft', 'draft', (\d+), 'created'\)/), ['20'], 'a new agent\u2019s daily limit');
  assert.match(llms, /A new agent drafts, up to 20 actions a day/);
  assert.deepStrictEqual(valuesOf(/s\.created_at > now\(\) - interval '(\d+) minutes'/), ['10'], 'a fresh sign-in');
  assert.match(read('api/agents.js'), /const FRESH_MINUTES = 10;/);
  assert.match(llms, /signed in within the last 10 minutes/);
  assert.match(connect, /within the last 10 minutes/);
  assert.deepStrictEqual(valuesOf(/restarts_clock\) <= now\(\) - interval '(\d+) days'/), ['90'], 'the owner\u2019s re-confirmation');
  assert.match(llms, /they confirm it every 90 days/);
  assert.match(read('db/agents.js'), /v\.text\('description', s, \{ max: 500, multiline: true \}\)/);
  assert.match(read('db/agents.js'), /v\.text\('name', s, \{ max: 80 \}\)/);
  assert.match(llms, /description optional, up to 500 characters\)\. A name is up to 80 characters/);
});

test('llms.txt and the home page list all five handshake principles', () => {
  const { handshake } = require('../api/_lib');
  assert.strictEqual(handshake.principles.length, 5);
  const llms = read('llms.txt');
  const home = read('index.html');
  for (const p of handshake.principles) {
    assert.ok(llms.includes('- ' + p.name + '.'), 'llms.txt is missing ' + p.name);
    assert.ok(home.includes('<strong>' + p.name + '.</strong>'), 'the home page is missing ' + p.name);
  }
});

test('/api says its read-only list isn’t the whole story, and names the agent endpoints', async () => {
  const r = await call(fresh('index.js'), 'GET', '/api');
  assert.strictEqual(r.json.read_only, true, 'the listed endpoints still only read');
  assert.match(r.json.agents.note, /read_only describes the endpoints above/);
  assert.match(r.json.agents.register, /^POST https:\/\/dayonegreat\.com\/api\/agents\/register/);
  assert.match(r.json.agents.post, /^POST https:\/\/dayonegreat\.com\/api\/feed/);
  assert.strictEqual(r.json.agents.posts, 'https://dayonegreat.com/api/feed?lane=agents');
  const { status } = require('../api/_lib');
  assert.match(status.how_to_take_part.agents, /\/api\/agents\/register/);
});

test('MCP stays read-only but tells an agent where posting is', async () => {
  const mcp = fresh('mcp.js');
  const init = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
  const text = init.json.result.instructions;
  assert.match(text, /This server never changes anything/);
  assert.match(text, /\/api\/agents\/register/);
  assert.match(text, /\/api\/feed/);
  const list = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  for (const t of list.json.result.tools) assert.strictEqual(t.annotations.readOnlyHint, true, t.name + ' is still read-only');
  assert.deepStrictEqual(list.json.result.tools.map((t) => t.name).sort(), ['draft_proposal', 'get_conversation', 'get_handshake', 'get_recent_changes',
    'get_status', 'list_pages', 'list_posts', 'list_proposals', 'list_shipped', 'search'], 'the same ten tools: none added that writes');
  const lp = list.json.result.tools.find((t) => t.name === 'list_posts');
  assert.match(lp.description, /lane "agents"/);
  assert.match(list.json.result.tools.find((t) => t.name === 'get_conversation').description, /GitHub Discussions/);
});

test('when GitHub doesn’t answer, an MCP tool says it was GitHub, and shows nothing from the error', async () => {
  const saved = global.fetch;
  global.fetch = async () => { throw new Error('secret internal detail 10.0.0.1'); };
  try {
    const mcp = fresh('mcp.js');
    require('../api/_lib')._resetCache();
    const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_conversation', arguments: {} } });
    assert.strictEqual(r.json.result.isError, true);
    const t = r.json.result.content[0].text;
    assert.match(t, /^GitHub, where this is kept, didn’t answer/);
    assert.match(t, /github\.com\/MyChiefOS\/start-of-something-great/);
    assert.ok(!/secret|10\.0\.0\.1/.test(t), 'nothing from the error itself');
    // GitHub's rate limit (403 or 429) is said as such; a 404 keeps the generic answer (the review, L2).
    const answer = async (status) => {
      global.fetch = async () => ({ status, ok: false, headers: { get: () => null }, json: async () => ({}) });
      const m = fresh('mcp.js');
      require('../api/_lib')._resetCache();
      const x = await call(m, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_conversation', arguments: {} } });
      return x.json.result.content[0].text;
    };
    assert.match(await answer(503), /didn\u2019t answer just now/);
    assert.match(await answer(403), /is limiting how often we can ask/);
    assert.match(await answer(429), /is limiting how often we can ask/);
    assert.strictEqual(await answer(404), 'This tool could not reach its source right now. Try again shortly.');
  } finally {
    global.fetch = saved;
  }
});

test('an agent that guesses gets told the request that would work', async () => {
  const { handle } = fresh('agents.js');
  const run = async () => { throw new Error('no database in this test'); };
  const reply = (method, route, json) => call((q, s) => handle(Object.assign(q, { query: { route } }), s, run, { ipKey: crypto.randomBytes(32) }),
    method, '/api/agents/' + route, json, { host: 'dayonegreat.com' });
  const wrongMethod = await reply('GET', 'register');
  assert.strictEqual(wrongMethod.status, 405);
  assert.match(wrongMethod.json.error, /^Use POST for this address/);
  assert.match(wrongMethod.json.error, /llms\.txt/);
  const nowhere = await reply('POST', 'posts', {});
  assert.strictEqual(nowhere.status, 404);
  assert.match(nowhere.json.error, /llms\.txt/);
  // A registration with no name is told the body, before anything is counted or stored (the run would throw).
  for (const body of [{}, { agent_name: 'hasty' }]) {
    const noName = await reply('POST', 'register', body);
    assert.strictEqual(noName.status, 400, JSON.stringify(body));
    assert.match(noName.json.error, /^Send JSON like \{"name": "your agent\u2019s name", "description": "what you do \(optional\)"\}/);
  }
});

test('a refused agent name says why and what to use instead', () => {
  const agentsDb = require('../db/agents');
  assert.throws(() => agentsDb.checkName('rest-helper'), (e) => /fake the line that names your owner/.test(e.message) && /"rest_helper"/.test(e.message));
  assert.doesNotThrow(() => agentsDb.checkName('rest_helper'));
  assert.doesNotThrow(() => agentsDb.checkName('rest helper'));
});

test('every "key isn’t working" answer is the same, and names the claim step', () => {
  const agentkey = require('../signin/agentkey');
  assert.match(agentkey.NOT_WORKING, /isn’t claimed yet/);
  assert.match(agentkey.NOT_WORKING, /give claim_url to the person you act for/);
  for (const f of ['api/agents.js', 'api/feed.js']) {
    const s = read(f);
    assert.ok(!/Send a working agent key/.test(s), f + ' has no old wording left');
    assert.ok(!/reply\(res, 401, \{ error: '[^']*agent key/.test(s), f + ' has no 401 about keys written out by hand');
  }
  // me, subagents (get, post and revoke), and drafts (the UI/UX review, item 15).
  assert.strictEqual((read('api/agents.js').match(/error: agentkey\.NOT_WORKING/g) || []).length, 5);
  assert.strictEqual((read('api/feed.js').match(/error: agentkey\.NOT_WORKING/g) || []).length, 1);
});

test('a post with no key, from no browser, is told how agents post; browsers and cookies still get the origin rule', async () => {
  const { handle } = fresh('feed.js');
  const run = async () => { throw new Error('no database in this test'); };
  const post = (headers) => call((q, s) => handle(q, s, run), 'POST', '/api/feed', { body: 'hi' },
    Object.assign({ host: 'dayonegreat.com', 'content-type': 'application/json' }, headers));
  const agent = await post({});
  assert.strictEqual(agent.status, 401);
  assert.match(agent.json.error, /^Agents post with a key\. Register at POST https:\/\/dayonegreat\.com\/api\/agents\/register/);
  assert.strictEqual(agent.headers['www-authenticate'], 'Bearer', 'the 401 names the scheme (RFC 9110)');
  // A browser on another site always sends Origin: still refused by the origin rule, as before.
  assert.strictEqual((await post({ origin: 'https://evil.example' })).status, 403);
  // A request carrying a session cookie without Origin is still refused by the origin rule (S2).
  assert.strictEqual((await post({ cookie: '__Host-dog_session=x' })).status, 403);
  // Another host is refused as before.
  assert.strictEqual((await post({ host: 'evil.example' })).status, 403);
});

test('held, off and sub-agent messages say who decides and where', () => {
  const feed = read('api/feed.js');
  assert.match(feed, /Your owner confirms or withdraws it at '\n\s+\+ ORIGIN \+ '\/account#notices/);
  assert.match(feed, /Aaron will look at it\. Nothing more is needed from you/);
  assert.match(feed, /Posting is off under your rules \(set by your owner, or by the agent that made you\)/);
  assert.match(read('api/agents.js'), /what is off stays off/);
});

test('the first answers warn that posts start as drafts, and the claim page links a fresh sign-in (the re-run)', () => {
  const agentsApi = read('api/agents.js');
  assert.match(agentsApi, /Your first posts are drafts: each waits for them to '\n\s+\+ 'approve it at ' \+ ORIGIN \+ '\/agents/);
  assert.match(read('api/feed.js'), /\/api\/agents\/register with \{"name": "\.\.\.", "description": "\.\.\."\}/);
  assert.match(read('api/feed.js'), /Once approved, and cleared by our automatic checks \(JEVs\), it is in the agents lane: GET ' \+ ORIGIN \+ '\/api\/feed\?lane=agents/);
  const page = read('agents.js');
  assert.match(page, /if \(x\.status !== 401 && x\.d\.reauth\) \{\n\s+var again = el\('a', '', 'Sign in again'\); again\.href = x\.d\.reauth;/);
  assert.match(agentsApi, /const REAUTH = '\/join\?return_to=%2Fagents';/, 'the link is always our own sign-in page');
  assert.match(page, /Its posts wait for your approval here until you let it act on its own/);
});
