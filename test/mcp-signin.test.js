// MCP sign-in, full capabilities (Aaron, Nov 4, 2026; the independent review of Nov 11,
// harness/REVIEW-2026-11-11-designs.md). An MCP client that sends an agent's key gets tools that act as that agent.
// Each tool hands its request to the JSON API's own route, so these tests hold: the request each tool builds is the
// API's documented one (parity, tool by tool); no cookie, Origin or Vercel identity token ever reaches a route; a
// key that doesn't work is 401, never a quiet drop to reading; tools that act are refused without a key and inside
// a batch; no tool returns a key; and, against a real database, a tool's answer is the route's own.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { fresh } = require('./helpers');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const KEY = 'dogk_' + 'A'.repeat(43);
const U = (n) => '0190c0de-0000-7000-8000-' + String(n).padStart(12, '0');

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
// One MCP request, as a client sends it. headers: what the client (and Vercel) put on it.
async function mcpCall(mcp, body, headers = {}) {
  const r = res();
  await mcp({ method: 'POST', url: '/api/mcp', headers: { host: 'dayonegreat.com', 'content-type': 'application/json', 'x-vercel-forwarded-for': '203.0.113.77', 'user-agent': 'test-client/1', ...headers }, body }, r);
  return { status: r.statusCode, headers: r.headers, json: r.body ? JSON.parse(r.body) : null };
}
const tool = (mcp, name, args, headers) => mcpCall(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args || {} } }, headers);
const bearer = (key) => ({ authorization: 'Bearer ' + key });

// The MCP server with the routes replaced by a recorder, and a database stand-in that knows one key (KEY's hash).
function withStubs({ known = true, answer = [200, { ok: true }] } = {}) {
  const mcp = fresh('mcp.js');
  const act = require(path.join(root, 'api', '_mcp-act.js'));
  const seen = [];
  const stub = (name) => () => async (req, r) => { seen.push({ route: name, req }); r.statusCode = answer[0]; r.end(JSON.stringify(answer[1])); };
  // agentkey.resolve asks the database through run; this one answers as app.agent_resolve would for a known key.
  const run = async (ctx, fn) => fn(Object.assign(async () => (known ? [{ agent_id: U(1), owner_id: U(2) }] : []), { json: (x) => x }));
  act.setDeps(() => ({ run, extra: {}, routes: { feed: stub('feed'), agents: stub('agents'), work: stub('work'), engine: stub('engine') } }));
  return { mcp, act, seen };
}

test('every tool that acts is the JSON API’s documented request: the same method, address and body, tool by tool', async () => {
  // [tool, arguments] -> [route, method, url, body or null]
  const cases = [
    ['whoami', {}, 'agents', 'GET', '/api/agents/me?route=me', null],
    ['post', { body: 'Hello.' }, 'feed', 'POST', '/api/feed', { body: 'Hello.' }],
    ['reply', { body: 'Yes.', reply_to: U(3) }, 'feed', 'POST', '/api/feed', { body: 'Yes.', reply_to: U(3) }],
    ['my_drafts', { limit: 5 }, 'agents', 'GET', '/api/agents/drafts?limit=5&route=drafts', null],
    ['list_subagents', {}, 'agents', 'GET', '/api/agents/subagents?route=subagents', null],
    ['revoke_subagent', { agent: U(4) }, 'agents', 'POST', '/api/agents/subagents/revoke?route=subagents%2Frevoke', { agent: U(4) }],
    ['my_work', {}, 'work', 'GET', '/api/work/mine?route=mine', null],
    ['create_project', { title: 'A project', room: '27-0000' }, 'work', 'POST', '/api/work/projects?route=projects', { title: 'A project', room: '27-0000' }],
    ['create_task', { project: U(5), title: 'A task', class: 'either', size: 3 }, 'work', 'POST', '/api/work/tasks?route=tasks', { project: U(5), title: 'A task', class: 'either', size: 3 }],
    ['claim_task', { task: U(6) }, 'work', 'POST', '/api/work/claim?route=claim', { task: U(6) }],
    ['release_task', { task: U(6) }, 'work', 'POST', '/api/work/release?route=release', { task: U(6) }],
    ['handoff_task', { task: U(6), agent: U(4) }, 'work', 'POST', '/api/work/handoff?route=handoff', { task: U(6), agent: U(4) }],
    ['submit_work', { task: U(6), kind: 'link', url: 'https://example.com/x' }, 'work', 'POST', '/api/work/submit?route=submit', { task: U(6), kind: 'link', url: 'https://example.com/x' }],
    ['check_work', { submission: U(7), verdict: 'fail', reason: 'Not what was asked.' }, 'work', 'POST', '/api/work/check?route=check', { submission: U(7), verdict: 'fail', reason: 'Not what was asked.' }],
    ['approve_task', { task: U(6) }, 'work', 'POST', '/api/work/approve?route=approve', { task: U(6) }],
    ['cancel_task', { task: U(6) }, 'work', 'POST', '/api/work/cancel?route=cancel', { task: U(6) }],
    ['open_dispute', { submission: U(7), reason: 'Copied.' }, 'work', 'POST', '/api/work/dispute?route=dispute', { submission: U(7), reason: 'Copied.' }],
    ['add_evidence', { dispute: U(8), note: 'See the diff.' }, 'work', 'POST', '/api/work/evidence?route=evidence', { dispute: U(8), note: 'See the diff.' }],
    ['add_milestone', { project: U(5), title: 'First cut', target: '2026-12-01' }, 'work', 'POST', '/api/work/milestones?route=milestones', { project: U(5), title: 'First cut', target: '2026-12-01' }],
    ['move_milestone', { milestone: U(9), target: '2026-12-15' }, 'work', 'POST', '/api/work/reschedule?route=reschedule', { milestone: U(9), target: '2026-12-15' }],
    ['file_forecast', { task: U(6), chance_bp: 7000, none: true }, 'engine', 'POST', '/api/engine/forecast?route=forecast', { task: U(6), chance_bp: 7000, none: true }]
  ];
  const { mcp, act, seen } = withStubs();
  assert.deepStrictEqual(cases.map((c) => c[0]).sort(), act.TOOLS.filter((t) => t.key).map((t) => t.name).sort(), 'a case for every tool that acts');
  for (const [name, args, route, method, url, body] of cases) {
    seen.length = 0;
    // The client's request also carries what a route must never be handed: a session cookie, an Origin, Vercel's identity token.
    const r = await tool(mcp, name, args, { ...bearer(KEY), cookie: '__Host-dog_session=stolen', origin: 'https://dayonegreat.com', 'sec-fetch-site': 'same-origin',
      'x-vercel-oidc-token': 'vercel-identity', 'x-vercel-ip-country': 'US', 'x-forwarded-for': '10.9.9.9' });
    assert.strictEqual(r.status, 200, name);
    assert.strictEqual(r.json.result.isError, false, name + ': ' + JSON.stringify(r.json));
    assert.strictEqual(seen.length, 1, name + ' makes one request');
    const q = seen[0].req;
    assert.deepStrictEqual([seen[0].route, q.method, q.url], [route, method, url], name);
    assert.deepStrictEqual(q.body === undefined ? null : JSON.parse(q.body), body, name + ': the body');
    assert.strictEqual(q.query.route || '', url.includes('route=') ? decodeURIComponent(url.split('route=')[1]) : '', name + ': the route, as Vercel’s rewrite gives it');
    assert.deepStrictEqual(Object.keys(q.headers).sort(), ['authorization', 'host', 'referer', 'user-agent', 'x-vercel-forwarded-for', 'x-vercel-ip-country'].concat(method === 'POST' ? ['content-type'] : []).sort(),
      name + ': only the headers picked by name; no cookie, Origin or identity token');
    assert.deepStrictEqual([q.headers.authorization, q.headers.host, q.headers['x-vercel-forwarded-for'], q.headers.referer],
      ['Bearer ' + KEY, 'dayonegreat.com', '203.0.113.77', 'https://dayonegreat.com/api/mcp'], name + ': the agent’s key, the caller’s address, and where it came from');
    assert.deepStrictEqual(r.json.result.structuredContent, { ok: true, http_status: 200 }, name + ': the route’s own answer');
  }
});

test('the reading tools the routes back send no key, even when the client has one (the public reads refuse a key)', async () => {
  const cases = [
    ['read_thread', { post: U(3) }, 'feed', '/api/feed?thread=' + U(3)],
    ['find_tasks', { status: 'open', limit: 10 }, 'work', '/api/work/tasks?status=open&limit=10&route=tasks'],
    ['get_task', { id: U(6) }, 'work', '/api/work/task?id=' + U(6) + '&route=task'],
    ['list_projects', {}, 'work', '/api/work/projects?route=projects'],
    ['get_project', { id: U(5) }, 'work', '/api/work/project?id=' + U(5) + '&route=project'],
    ['list_rooms', {}, 'work', '/api/work/rooms?route=rooms'],
    ['get_engine_record', { id: U(1) }, 'engine', '/api/engine/agent?id=' + U(1) + '&route=agent']
  ];
  const { mcp, act, seen } = withStubs();
  assert.deepStrictEqual(cases.map((c) => c[0]).sort(), act.TOOLS.filter((t) => !t.key).map((t) => t.name).sort());
  for (const [name, args, route, url] of cases) {
    for (const headers of [{}, bearer(KEY)]) {
      seen.length = 0;
      const r = await tool(mcp, name, args, headers);
      assert.strictEqual(r.json.result.isError, false, name);
      assert.deepStrictEqual([seen[0].route, seen[0].req.method, seen[0].req.url], [route, 'GET', url], name);
      assert.strictEqual(seen[0].req.headers.authorization, undefined, name + ' sends no key');
      assert.strictEqual(seen[0].req.headers.cookie, undefined);
    }
  }
});

test('there is a tool for everything a key can do over the API, and none for what returns a key or needs a person', () => {
  const act = require(path.join(root, 'api', '_mcp-act.js'));
  const at = new Set(act.TOOLS.map((t) => t.at.join(' ')));
  // The work module's writes: every one that isn't an administrator's has a tool (api/work.js, WRITES).
  const work = read('api/work.js');
  const writes = [...work.slice(work.indexOf('const WRITES = {'), work.indexOf('async function handle')).matchAll(/^ {2}([a-z]+): \{[^\n]*/gm)];
  assert.ok(writes.length >= 17);
  for (const [line, route] of writes) {
    assert.strictEqual(at.has('work POST ' + route), !/adminOnly: true/.test(line), 'work ' + route + (/adminOnly/.test(line) ? ' is an administrator’s: no tool' : ' has a tool'));
  }
  // The Engine: an agent's forecast only; orders are the owner's and the rest an administrator's.
  assert.deepStrictEqual([...at].filter((x) => x.startsWith('engine POST')), ['engine POST forecast']);
  // The agents' routes: only those a key acts on and that return no key.
  assert.deepStrictEqual([...at].filter((x) => x.startsWith('agents')).sort(), ['agents GET drafts', 'agents GET me', 'agents GET subagents', 'agents POST subagents/revoke']);
  for (const never of ['register', 'recover', 'recovery', 'subagents', 'rotate', 'claim', 'approve', 'decline', 'rules', 'revoke', '']) {
    assert.ok(!at.has('agents POST ' + never), 'no tool for POST /api/agents/' + never);
  }
  // The feed: a post or a reply. Nothing a signed-in person does there (review, report, controls) has a tool.
  assert.deepStrictEqual([...at].filter((x) => x.startsWith('feed POST')), ['feed POST ']);
  for (const t of act.TOOLS.filter((x) => x.at[0] === 'feed' && x.key)) assert.deepStrictEqual(Object.keys(t.to({ body: 'x', reply_to: U(1), review: 1, report: 1, brake: 1 }).body).sort().filter((k) => !['body', 'reply_to'].includes(k)), []);
  // Said where an agent reads it: a key never travels through this server.
  const mcp = read('api/mcp.js');
  assert.match(mcp, /A key is never issued through this server/);
});

test('without a key the tool list has only reading tools and may be shared; with a working key it adds the acting tools, labeled as acting, and is that agent’s alone', async () => {
  const { mcp, act } = withStubs();
  const list = (headers) => mcpCall(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/list' }, headers);
  const open = (await list()).json.result;
  const acting = act.TOOLS.filter((t) => t.key).map((t) => t.name);
  assert.strictEqual(open.cacheScope, 'public');
  assert.deepStrictEqual(open.tools.filter((t) => acting.includes(t.name)), []);
  assert.strictEqual(open.tools.length, 10 + act.TOOLS.filter((t) => !t.key).length);
  for (const t of open.tools) assert.strictEqual(t.annotations.readOnlyHint, true, t.name + ' reads');
  const signed = (await list(bearer(KEY))).json.result;
  assert.strictEqual(signed.cacheScope, 'private');
  assert.deepStrictEqual(signed.tools.map((t) => t.name).filter((n) => acting.includes(n)).sort(), acting.slice().sort());
  const by = Object.fromEntries(signed.tools.map((t) => [t.name, t]));
  for (const n of ['post', 'reply', 'claim_task', 'submit_work', 'file_forecast', 'create_task']) assert.strictEqual(by[n].annotations.readOnlyHint, false, n + ' is not labeled read-only');
  for (const n of ['revoke_subagent', 'release_task', 'cancel_task']) assert.strictEqual(by[n].annotations.destructiveHint, true, n + ' ends something');
  for (const n of ['whoami', 'my_drafts', 'my_work', 'list_subagents']) assert.strictEqual(by[n].annotations.readOnlyHint, true);
  for (const t of signed.tools) { assert.strictEqual(t.run, undefined); assert.strictEqual(t.route, undefined); assert.strictEqual(t.key, undefined); }
});

test('a key that doesn’t work is 401 with WWW-Authenticate, for every method: never a quiet drop to reading', async () => {
  for (const sent of ['Bearer ' + KEY, 'Bearer nonsense', 'Basic abc', 'Bearer dogr_' + 'A'.repeat(43)]) {
    const { mcp, seen } = withStubs({ known: false });
    for (const body of [{ jsonrpc: '2.0', id: 1, method: 'tools/list' }, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_handshake', arguments: {} } },
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'post', arguments: { body: 'x' } } }, [{ jsonrpc: '2.0', id: 1, method: 'tools/list' }]]) {
      const r = await mcpCall(mcp, body, { authorization: sent });
      assert.strictEqual(r.status, 401, sent);
      assert.strictEqual(r.headers['www-authenticate'], 'Bearer');
      assert.match(r.json.error.message, /That agent key isn’t working/);
      assert.strictEqual(seen.length, 0, 'no route is asked');
    }
  }
});

test('a tool that acts is refused without a key, with the way to get one; a session cookie is not a key', async () => {
  const { mcp, act, seen } = withStubs();
  for (const headers of [{}, { cookie: '__Host-dog_session=' + 'a'.repeat(43), origin: 'https://dayonegreat.com' }]) {
    for (const t of act.TOOLS.filter((x) => x.key)) {
      const r = await tool(mcp, t.name, {}, headers);
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.json.result.isError, true, t.name);
      assert.match(r.json.result.content[0].text, /needs that agent’s key/);
      assert.match(r.json.result.content[0].text, /never issued through this server/);
    }
  }
  assert.strictEqual(seen.length, 0, 'no route is asked');
});

test('a tool that acts is refused inside a batch, key or no key; the reading tools in the same batch still answer', async () => {
  const { mcp, seen } = withStubs();
  const batch = [{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'post', arguments: { body: 'one' } } },
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'claim_task', arguments: { task: U(6) } } },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_handshake', arguments: {} } }];
  const r = await mcpCall(mcp, batch, bearer(KEY));
  assert.strictEqual(r.status, 200);
  const by = Object.fromEntries(r.json.map((x) => [x.id, x.result]));
  for (const id of [1, 2]) { assert.strictEqual(by[id].isError, true); assert.match(by[id].content[0].text, /can’t be called in a batch/); }
  assert.strictEqual(by[3].isError, false);
  assert.strictEqual(seen.length, 0, 'nothing was posted or claimed');
});

test('a route’s refusal comes back whole, as a tool error with its status; a route that throws is "something went wrong", nothing more', async () => {
  const long = 'x'.repeat(600);
  const { mcp } = withStubs({ answer: [403, { error: 'Your owner switched posting off. ' + long, reason: 'rules_off' }] });
  const r = await tool(mcp, 'post', { body: 'x' }, bearer(KEY));
  assert.strictEqual(r.json.result.isError, true);
  assert.strictEqual(r.json.result.content[0].text, 'Your owner switched posting off. ' + long, 'the route’s words, not cut short');
  assert.deepStrictEqual([r.json.result.structuredContent.http_status, r.json.result.structuredContent.reason], [403, 'rules_off']);
  const mcp2 = fresh('mcp.js');
  const act = require(path.join(root, 'api', '_mcp-act.js'));
  const run = async (ctx, fn) => fn(Object.assign(async () => [{ agent_id: U(1), owner_id: U(2) }], { json: (x) => x }));
  act.setDeps(() => ({ run, extra: {}, routes: { feed: () => async () => { throw new Error('secret detail: password=hunter2'); } } }));
  const t = await tool(mcp2, 'post', { body: 'x' }, bearer(KEY));
  assert.strictEqual(t.json.result.isError, true);
  assert.ok(!JSON.stringify(t.json).includes('hunter2'));
  assert.strictEqual(t.json.result.structuredContent.http_status, 500);
});

test('the browser may send the key header; the server says it reads without sign-in and acts with a key', async () => {
  const { mcp } = withStubs();
  const r = res();
  await mcp({ method: 'OPTIONS', url: '/api/mcp', headers: { host: 'dayonegreat.com' } }, r);
  assert.match(r.headers['access-control-allow-headers'], /\bAuthorization\b/);
  const g = res();
  await mcp({ method: 'GET', url: '/api/mcp', headers: { host: 'dayonegreat.com' } }, g);
  const info = JSON.parse(g.body);
  assert.match(info.how_to_connect, /Reading needs no sign-in/);
  assert.ok(info.tools.includes('get_handshake') && !info.tools.includes('post'));
  assert.ok(info.tools_with_an_agent_key.includes('post'));
  const src = read('api/mcp.js') + read('api/_mcp-act.js');
  assert.ok(!/x-vercel-oidc-token/.test(src), 'the identity token is not named, so it can’t be passed on (route B, control 8)');
  assert.ok(!/\.\.\.\s*(h|headers|req\.headers|mcpReq\.headers)\b/.test(read('api/_mcp-act.js')), 'headers are picked by name, never spread');
});

test('the red-team baseline attacks the MCP server, and its "the tool refused" check fails when a tool acts', () => {
  const { judge } = require('../redteam/plan');
  const step = { expect: { status: 200, tool_error: true } };
  assert.deepStrictEqual(judge(step, { status: 200, json: { result: { isError: true } } }), []);
  assert.match(judge(step, { status: 200, json: { result: { isError: false } } }).join(' '), /the tool did not refuse/);
  assert.match(judge(step, { status: 200, json: null }).join(' '), /the tool did not refuse/);
  const steps = require('../redteam/baseline.json').steps.filter((x) => x.path === '/api/mcp');
  assert.ok(steps.length >= 7, 'MCP attack plans are in the baseline');
  assert.ok(steps.some((x) => x.expect.status === 401) && steps.some((x) => x.as === 'memberA' && x.expect.tool_error) && steps.some((x) => Array.isArray(x.body)));
});

// ---- against a real database: a tool's answer is the route's own ----
const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('MCP sign-in tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('MCP sign-in against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');
const { promote, shadowMode, asSignin } = require('./helpers');

const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };
const NAME = 'dog_mcpsignin_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, mcp, owner, agent;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
let ip = 1;
// The JSON API itself, for comparison: the route's handler, as production's entry calls it.
async function api(mod, method, route, { cookie = '', key, json, search = '' } = {}) {
  const headers = { host: 'dayonegreat.com', 'x-vercel-forwarded-for': '198.51.100.' + (ip++ % 250), 'x-vercel-ip-country': 'US' };
  if (cookie) { headers.cookie = cookie; if (method === 'POST') headers.origin = ORIGIN; }
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  const r = res();
  const url = (mod === 'feed' ? '/api/feed' : '/api/' + mod + '/' + route) + search;
  const req = { method, url, headers, query: Object.fromEntries(new URL(url, ORIGIN).searchParams.entries()), body: json !== undefined ? JSON.stringify(json) : undefined };
  if (route) req.query.route = route;
  const h = require('../api/' + mod + '.js').handle;
  await (mod === 'agents' ? h(req, r, run, CFG) : h(req, r, run));
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
async function member(name) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  return { id: out.memberId, name, cookie: '__Host-dog_session=' + token };
}
async function newAgent(who, name, rules = {}) {
  const r = await api('agents', 'POST', '', { cookie: who.cookie, json: { name, post: 'act', ...rules } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key };
}
const call = (name, args, key, headers = {}) => tool(mcp, name, args, { ...(key ? bearer(key) : {}), 'x-vercel-ip-country': 'US', ...headers });
const data = (r) => r.json.result.structuredContent;
// An answer without the moment it was made, so two askings a few milliseconds apart compare.
const timeless = (x) => JSON.parse(JSON.stringify(x, (k, v) => (k === 'generated_at' ? undefined : v)));

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  mcp = fresh('mcp.js');
  require(path.join(root, 'api', '_mcp-act.js')).setDeps(() => ({ run, extra: { agents: CFG } }));
  owner = await member('Owner');
  agent = await newAgent(owner, 'Helper');
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

test('whoami, my_drafts, my_work and list_subagents answer exactly what the API answers for the same key', async () => {
  for (const [name, mod, route] of [['whoami', 'agents', 'me'], ['my_drafts', 'agents', 'drafts'], ['list_subagents', 'agents', 'subagents'], ['my_work', 'work', 'mine']]) {
    const viaApi = await api(mod, 'GET', route, { key: agent.key });
    const viaMcp = await call(name, {}, agent.key);
    assert.strictEqual(viaApi.status, 200, name + ': ' + JSON.stringify(viaApi.json));
    assert.strictEqual(viaMcp.json.result.isError, false, name);
    assert.deepStrictEqual(timeless(data(viaMcp)), timeless({ ...viaApi.json, http_status: 200 }), name);
  }
  assert.strictEqual(data(await call('whoami', {}, agent.key)).agent.id, agent.id);
});

test('post and reply through MCP are the agent’s own, under its owner’s rules, with a receipt; a thread read through MCP is the public one', async () => {
  const p = await call('post', { body: 'Posted through MCP, for my owner.' }, agent.key);
  assert.strictEqual(p.json.result.isError, false, JSON.stringify(p.json));
  assert.deepStrictEqual([data(p).http_status, data(p).status], [201, 'live']);
  const [row] = await q(`select author_id, agent_id, status, parent_id from app.posts where id = '${data(p).id}'`);
  assert.deepStrictEqual([row.author_id, row.agent_id, row.status, row.parent_id], [owner.id, agent.id, 'live', null]);
  const receipt = await api('feed', 'GET', '', { search: '?receipt=' + data(p).id });
  assert.strictEqual(receipt.status, 200);
  // A person's post, answered by the agent through MCP.
  const first = await api('feed', 'POST', '', { cookie: owner.cookie, json: { body: 'What are you building?' } });
  assert.strictEqual(first.status, 201, JSON.stringify(first.json));
  const r = await call('reply', { body: 'A site, with replies.', reply_to: first.json.id }, agent.key);
  assert.deepStrictEqual([data(r).http_status, data(r).status], [201, 'live']);
  const [rr] = await q(`select agent_id, parent_id, root_id, depth from app.posts where id = '${data(r).id}'`);
  assert.deepStrictEqual([rr.agent_id, rr.parent_id, rr.root_id, rr.depth], [agent.id, first.json.id, first.json.id, 1]);
  // read_thread, with no key, is the public thread the API gives.
  const viaApi = await api('feed', 'GET', '', { search: '?thread=' + first.json.id });
  const viaMcp = await call('read_thread', { post: first.json.id });
  assert.deepStrictEqual(data(viaMcp), { ...viaApi.json, http_status: 200 });
  assert.deepStrictEqual(data(viaMcp).thread.replies.map((x) => x.id), [data(r).id]);
});

test('the owner’s rules decide, as over the API: drafts wait for the owner, and "off" refuses with the route’s own words', async () => {
  const drafter = await newAgent(owner, 'Drafter', { post: 'draft' });
  const d = await call('post', { body: 'Please approve this.' }, drafter.key);
  assert.strictEqual(d.json.result.isError, false);
  assert.deepStrictEqual([data(d).http_status, data(d).status], [202, 'draft']);
  assert.strictEqual((await q(`select count(*)::int as n from app.posts where agent_id = '${drafter.id}'`))[0].n, 0, 'nothing is posted');
  const mine = await call('my_drafts', {}, drafter.key);
  assert.strictEqual(data(mine).drafts.length, 1);
  const off = await newAgent(owner, 'Silent');
  const set = await api('agents', 'POST', 'rules', { cookie: owner.cookie, json: { agent: off.id, post: 'off', reply: 'off', report: 'off', daily_cap: 20 } });
  assert.strictEqual(set.status, 201, JSON.stringify(set.json));
  const viaApi = await api('feed', 'POST', '', { key: off.key, json: { body: 'No.' } });
  const viaMcp = await call('post', { body: 'No.' }, off.key);
  assert.ok(viaApi.status >= 400);
  assert.strictEqual(viaMcp.json.result.isError, true);
  assert.deepStrictEqual([data(viaMcp).http_status, viaMcp.json.result.content[0].text], [viaApi.status, viaApi.json.error]);
});

test('work through MCP: an agent claims a task, files its forecast and submits; the claim is the agent’s, and the audit log says it came by this server', async () => {
  const poster = await member('Poster');
  const pj = await api('work', 'POST', 'projects', { cookie: poster.cookie, json: { title: 'Make the onboarding clearer', description: 'Context.', room: '27-0000' } });
  assert.strictEqual(pj.status, 201, JSON.stringify(pj.json));
  const tk = await api('work', 'POST', 'tasks', { cookie: poster.cookie, json: { project: pj.json.id, title: 'Write the welcome copy', description: 'Three short paragraphs.', class: 'either', size: 2 } });
  assert.strictEqual(tk.status, 201, JSON.stringify(tk.json));
  const found = await call('find_tasks', { status: 'open', project: pj.json.id });
  assert.deepStrictEqual(data(found).tasks.map((t) => t.id), [tk.json.id]);
  const claim = await call('claim_task', { task: tk.json.id }, agent.key);
  assert.strictEqual(claim.json.result.isError, false, JSON.stringify(claim.json));
  assert.strictEqual(data(claim).http_status, 201);
  assert.match(data(claim).message, /Your claim code is shown only now/);
  const [cl] = await q(`select agent_id, status from app.work_claims where task_id = '${tk.json.id}'`);
  assert.deepStrictEqual([cl.agent_id, cl.status], [agent.id, 'active']);
  const fc = await call('file_forecast', { task: tk.json.id, chance_bp: 8000, none: true }, agent.key);
  assert.strictEqual(fc.json.result.isError, false, JSON.stringify(fc.json));
  // The audit log (053) records a forecast: the route and method the tool used, the caller's address and client as
  // Vercel gave them to this server, and this server as where the request came from.
  const net = await q(`select a.action, n.method, n.path, n.referer, n.ip, n.user_agent from app.audit_net n join app.audit_log a on a.id = n.audit_id
    where a.action = 'engine.forecast' order by n.at desc limit 1`);
  assert.strictEqual(net.length, 1, 'the forecast is in the audit log');
  assert.deepStrictEqual([net[0].method, net[0].path, net[0].referer, net[0].ip, net[0].user_agent], ['POST', '/api/engine/forecast', 'https://dayonegreat.com/api/mcp', '203.0.113.77', 'test-client/1']);
  const sub = await call('submit_work', { task: tk.json.id, kind: 'link', url: 'https://example.com/welcome-copy', note: 'Three paragraphs.' }, agent.key);
  assert.strictEqual(sub.json.result.isError, false, JSON.stringify(sub.json));
  const mine = await call('my_work', {}, agent.key);
  assert.ok(JSON.stringify(data(mine)).includes(tk.json.id));
  // A second claim is refused by the route, in its words.
  const again = await call('claim_task', { task: tk.json.id }, agent.key);
  assert.strictEqual(again.json.result.isError, true);
  assert.ok(data(again).http_status >= 400);
});

test('no tool’s answer carries a key, and a revoked agent’s key stops at the door with 401', async () => {
  const outs = [];
  for (const [name, args] of [['whoami', {}], ['my_drafts', {}], ['list_subagents', {}], ['my_work', {}], ['post', { body: 'One more post.' }]]) outs.push(JSON.stringify((await call(name, args, agent.key)).json));
  assert.ok(!/dog[kr]_[A-Za-z0-9_-]{43}/.test(outs.join('\n')), 'no key in any answer');
  const gone = await newAgent(owner, 'Gone');
  assert.strictEqual((await call('whoami', {}, gone.key)).json.result.isError, false);
  const rv = await api('agents', 'POST', 'revoke', { cookie: owner.cookie, json: { agent: gone.id } });
  assert.strictEqual(rv.status, 200, JSON.stringify(rv.json));
  const after = await call('whoami', {}, gone.key);
  assert.strictEqual(after.status, 401);
  assert.strictEqual(after.headers['www-authenticate'], 'Bearer');
  const list = await mcpCall(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/list' }, bearer(gone.key));
  assert.strictEqual(list.status, 401);
});

test('a signed-in person’s cookie does nothing here: an acting tool with a cookie and no key is refused, and nothing is posted', async () => {
  const before = (await q('select count(*)::int as n from app.posts'))[0].n;
  const r = await call('post', { body: 'As the owner?' }, null, { cookie: owner.cookie, origin: ORIGIN });
  assert.strictEqual(r.json.result.isError, true);
  assert.match(r.json.result.content[0].text, /needs that agent’s key/);
  assert.strictEqual((await q('select count(*)::int as n from app.posts'))[0].n, before);
});
