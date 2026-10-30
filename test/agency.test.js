// Release 2, PR 7: agents acting for their owners (criteria A1–A6, approved Oct 16, 2026, R10, R17, R36), against a real Postgres.
'use strict';

const { promote, shadowMode } = require('./helpers');
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const posts = require('../db/posts');
const review = require('../db/review');
const controls = require('../db/controls');
const delegation = require('../db/delegation');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };

test('the agents page shows each draft in full and approves by hashing the very text it showed', () => {
  const js = fs.readFileSync(path.join(root, 'agents.js'), 'utf8');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function/.test(js));
  assert.match(js, /crypto\.subtle\.digest\('SHA-256'/, 'the page hashes what it shows');
  assert.match(js, /body\.textContent = d\.body/, 'the whole text, as text');
  assert.ok(!/\.hash\b/.test(js.replace(/location\.hash/g, '')), 'no hash from the server is used');
  const feed = fs.readFileSync(path.join(root, 'feed.js'), 'utf8');
  assert.match(feed, /p\.delegation/, 'agent posts show how they went out (A3)');
  const html = fs.readFileSync(path.join(root, 'receipt.html'), 'utf8');
  assert.match(html, /<script defer src="\/receipt\.js"><\/script>/);
});

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, route, { cookie = '', origin, json, key } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '203.0.113.40' };
  if (origin) headers.origin = origin;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url: '/api/agents/' + route, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined };
}

if (!SERVER) {
  if (process.env.CI) test('agency tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('agents acting for their owners against a database (A1–A6)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_agency_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su); // the features under JEVs, tested without it (helpers.js)
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  aaron = await member(2, 'Aaron');
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${aaron.id}'`); });
  aaron.ctx = { ...aaron.ctx, actor: 'admin' }; // admin, with Aaron's own session
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

// A member with a session; { stale: true } makes the session an hour old (not a fresh sign-in).
async function member(level = 2, name = 'Owner', { stale = false } = {}) {
  const token = c.token(32);
  const fp = c.sha256hex(crypto.randomUUID());
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [fp], keyVersion: 1,
    level: Math.min(level, 1), displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  if (stale) await q(`update app.sessions set created_at = now() - interval '1 hour' where token_hash = '${c.sha256hex(token)}'`);
  return { id: out.memberId, fp, level, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
// The same member signing in again with the same GitHub account: a new session (fix 3: the proof a person acts with).
async function signInAgain(m) {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [m.fp], keyVersion: 1,
    level: m.level, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  assert.strictEqual(out.memberId, m.id, 'the same member');
  return { ...m, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: m.id, session: c.sha256hex(token) } };
}
async function api(r) {
  const out = res();
  await require('../api/agents.js').handle(r, out, run, CFG);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
async function feed(r) {
  const out = res();
  await require('../api/feed.js').handle(r, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null, r: out };
}
const say = (key, body) => feed({ method: 'POST', url: '/api/feed', headers: { host: 'dayonegreat.com', 'content-type': 'application/json', authorization: 'Bearer ' + key }, query: {}, body: JSON.stringify({ body }) });
const publicGet = (query) => feed({ method: 'GET', url: '/api/feed', headers: { host: 'dayonegreat.com' }, query });
async function newAgent(owner, name = 'Helper') {
  // Drafting, as these tests were written for (Aaron, Oct 30: new agents act on their own by default; tested on its own below).
  const r = await api(req('POST', '', { cookie: owner.cookie, origin: ORIGIN, json: { name, post: 'draft' } }));
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  // ctx: the agent acting with its own key (by its hash), as signin/agentkey.js does for a request (fix 3).
  return { id: r.json.agent_id, key: r.json.key, ctx: { actor: 'agent', memberId: owner.id, agentId: r.json.agent_id, keyHash: c.sha256hex(r.json.key) } };
}
const rules = (owner, agent, set) => api(req('POST', 'rules', { cookie: owner.cookie, origin: ORIGIN, json: { agent: agent.id, post: 'draft', reply: 'draft', report: 'draft', daily_cap: 20, ...set } }));
const activity = (owner) => api(req('GET', 'activity', { cookie: owner.cookie }));
const approve = (owner, draft, text) => api(req('POST', 'approve', { cookie: owner.cookie, origin: ORIGIN, json: { draft, hash: c.sha256hex(text) } }));
const agentFeed = async () => (await publicGet({ lane: 'agents', limit: '50' })).json.posts;

test('the database passes the coverage check with the delegation tables (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('A1 (with "draft" chosen; Oct 30 default: act, tested below): an agent drafts for everything, and its owner can switch each action off, to draft or to act', async () => {
  const owner = await member(2, 'Rule setter');
  const a = await newAgent(owner);
  const me = await api(req('GET', 'me', { key: a.key }));
  assert.deepStrictEqual([me.json.rules.version, me.json.rules.post, me.json.rules.reply, me.json.rules.report, me.json.rules.daily_cap], [1, 'draft', 'draft', 'draft', 20]);
  // Off: nothing happens.
  assert.strictEqual((await rules(owner, a, { post: 'off' })).status, 201);
  const off = await say(a.key, 'should not go anywhere');
  assert.deepStrictEqual([off.status, off.json.error], [403, 'Posting is off under your rules (set by your owner, or by the agent that made you). GET https://dayonegreat.com/api/agents/me shows them.']);
  // Act (fresh sign-in): posts at once, marked as under the owner's rules.
  const set = await rules(owner, a, { post: 'act' });
  assert.deepStrictEqual([set.status, set.json.rules.version, set.json.rules.post], [201, 3, 'act']);
  const p = await say(a.key, 'on my own');
  assert.deepStrictEqual([p.status, p.json.delegation], [201, 'rules']);
  // The database holds each mode even past the site: an agent can't post directly while drafting, or draft while off.
  await rules(owner, a, { post: 'draft' });
  await assert.rejects(run(a.ctx, (t) => t`insert into app.posts (body) values ('skipping the inbox')`), /agent_drafts/);
  await rules(owner, a, { post: 'off' });
  await assert.rejects(run(a.ctx, (t) => t`insert into app.agent_drafts (body) values ('while off')`), /agent_off/);
  await rules(owner, a, { post: 'act' });
  // Bad input is refused, and nobody else can set this agent's rules.
  assert.strictEqual((await rules(owner, a, { post: 'always' })).status, 400);
  assert.strictEqual((await rules(owner, a, { daily_cap: 0 })).status, 400);
  const other = await member(2, 'Not the owner');
  assert.strictEqual((await rules(other, a, { post: 'draft' })).status, 404);
  assert.strictEqual((await api(req('POST', 'rules', { cookie: owner.cookie, origin: 'https://evil.example', json: { agent: a.id, post: 'act', reply: 'off', report: 'off', daily_cap: 5 } }))).status, 403);
});

test('R17: letting an agent act alone, or raising its cap, needs a sign-in in the last 10 minutes; lowering never does', async () => {
  const owner = await member(2, 'Signed in long ago', { stale: true });
  const a = await newAgent(owner);
  const raise = await rules(owner, a, { post: 'act' });
  assert.deepStrictEqual([raise.status, raise.json.reauth], [403, '/join?return_to=%2Fagents']);
  assert.strictEqual((await rules(owner, a, { daily_cap: 50 })).status, 403, 'a bigger cap is more autonomy too');
  assert.strictEqual((await rules(owner, a, { post: 'off', daily_cap: 5 })).status, 201, 'lowering is always allowed');
  // The database holds the line even if the site forgets: an owner call without the fresh flag can't raise.
  assert.deepStrictEqual(await run(owner.ctx, (t) => delegation.setRules(t, { agent: a.id, post: 'act', reply: 'off', report: 'off', dailyCap: 5 })), { refused: 'fresh' });
  // An agent can never set its own rules.
  await assert.rejects(run(a.ctx, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${a.id}, 'act', 'act', 'act', 1000, 'owner')`), /row-level security|fresh_sign_in/);
  await assert.rejects(run({ ...a.ctx, fresh: true }, (t) => t`select 1`), /only member calls can be fresh/);
  // A new key for an agent that acts on its own needs a fresh sign-in too, so an old session can't mint one.
  const fresh = await member(2, 'Fresh owner');
  const acting = await newAgent(fresh, 'Already acting');
  await rules(fresh, acting, { post: 'act' });
  await q(`update app.sessions set created_at = now() - interval '1 hour' where member_id = '${fresh.id}'`);
  const minted = await api(req('POST', 'key', { cookie: fresh.cookie, origin: ORIGIN, json: { agent: acting.id } }));
  assert.deepStrictEqual([minted.status, minted.json.reauth], [403, '/join?return_to=%2Fagents']);
  assert.strictEqual((await say(acting.key, 'the old key still works; nothing was rotated')).status, 201);
  await assert.rejects(run(fresh.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${acting.id}, ${c.sha256hex('sneaky')})`), /fresh_sign_in/);
  // Versions are only ever added.
  await assert.rejects(q(`update app.agent_rules set post_mode = 'act' where agent_id = '${a.id}'`), /only ever added/);
  await assert.rejects(q(`delete from app.agent_rules where agent_id = '${a.id}'`), /only ever added/);
});

test('A2, A6: a draft waits for its owner, who approves the exact words with one tap; changed words, a second tap and expired drafts are refused', async () => {
  const owner = await member(2, 'Approver');
  const a = await newAgent(owner, 'Drafter');
  const d = await say(a.key, 'Please approve me');
  assert.deepStrictEqual([d.status, d.json.status, d.json.rules_version], [202, 'draft', 1]);
  assert.ok(new Date(d.json.expires_at) - Date.now() > 47 * 3600000, 'expires in 48 hours');
  assert.strictEqual((await agentFeed()).some((x) => x.body === 'Please approve me'), false, 'not public until approved');
  const inbox = (await activity(owner)).json.inbox;
  const item = inbox.find((x) => x.id === d.json.draft_id);
  assert.strictEqual(item.body, 'Please approve me');
  assert.strictEqual(item.hash, undefined, 'the server never hands out the hash');
  // Words other than the ones shown are refused.
  assert.strictEqual((await approve(owner, item.id, 'Please approve me!')).status, 409);
  // Someone else can't approve it.
  const other = await member(2, 'Stranger');
  assert.strictEqual((await approve(other, item.id, item.body)).status, 404);
  // One tap.
  const ok = await approve(owner, item.id, item.body);
  assert.strictEqual(ok.status, 201);
  const shown = (await agentFeed()).find((x) => x.id === ok.json.post.id);
  assert.deepStrictEqual([shown.body, shown.delegation.kind, shown.delegation.approved_by_owner, shown.delegation.label], ['Please approve me', 'approved', true, 'Approved by Approver']);
  assert.strictEqual((await approve(owner, item.id, item.body)).status, 409, 'a second tap changes nothing');
  // Decline, and expiry.
  const d2 = await say(a.key, 'decline me');
  assert.strictEqual((await api(req('POST', 'decline', { cookie: owner.cookie, origin: ORIGIN, json: { draft: d2.json.draft_id } }))).status, 200);
  assert.strictEqual((await approve(owner, d2.json.draft_id, 'decline me')).status, 409);
  const d3 = await say(a.key, 'too late');
  await q(`alter table app.agent_drafts disable trigger agent_drafts_guard; update app.agent_drafts set created_at = now() - interval '49 hours', expires_at = now() - interval '1 hour' where id = '${d3.json.draft_id}'; alter table app.agent_drafts enable always trigger agent_drafts_guard`);
  assert.strictEqual((await approve(owner, d3.json.draft_id, 'too late')).status, 410);
  assert.ok(!(await activity(owner)).json.inbox.some((x) => x.id === d3.json.draft_id), 'expired drafts leave the inbox');
  // A draft's words never change.
  await assert.rejects(q(`update app.agent_drafts set body = 'swapped' where id = '${d2.json.draft_id}'`), /words never change/);
  // An agent can't approve its own draft, or write a draft while acting directly.
  await assert.rejects(run(a.ctx, (t) => t`select * from app.approve_draft(${d.json.draft_id}::uuid, ${c.sha256hex('x')})`), /not_found/);
});

test('A3, A4: every agent post says how it went out, in the API and MCP, and has a public receipt naming the agent, its owner and the rules version', async () => {
  const owner = await member(2, 'Ada jane@example.com');
  const a = await newAgent(owner, 'Ada\'s bot');
  await rules(owner, a, { post: 'act', daily_cap: 50 });
  const p = await say(a.key, 'under the rules');
  const post = (await agentFeed()).find((x) => x.id === p.json.id);
  assert.deepStrictEqual([post.delegation.kind, post.delegation.approved_by_owner, post.delegation.rules_version, post.delegation.receipt],
    ['rules', false, 2, '/receipt?post=' + p.json.id]);
  assert.ok(post.delegation.label.startsWith('Posted by Ada\'s bot under Ada'), post.delegation.label);
  assert.ok(!post.delegation.label.includes('@example.com'), 'names are masked');
  const r = await publicGet({ receipt: p.json.id });
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual([r.json.receipt.agent.name, r.json.receipt.owner.id, r.json.receipt.rules.version, r.json.receipt.rules.post, r.json.receipt.rules.daily_cap, r.json.receipt.approval],
    ['Ada\'s bot', owner.id, 2, 'act', 50, null]);
  assert.ok(!JSON.stringify(r.json).includes('set_at') && !JSON.stringify(r.json).includes('reason'), 'no timings or reasons that would expose the owner');
  assert.match(r.r.getHeader('Vercel-CDN-Cache-Control'), /s-maxage=20/);
  // MCP carries the same fields.
  const mcp = require('../api/mcp.js');
  mcp.setReadPosts((x) => run({ actor: 'anon' }, (t) => posts.feed(t, x)));
  const { call } = require('./helpers');
  const m = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_posts', arguments: { lane: 'agents', limit: 50 } } });
  const mp = m.json.result.structuredContent.posts.find((x) => x.id === p.json.id);
  assert.strictEqual(mp.delegation.kind, 'rules');
  assert.ok(m.json.result.structuredContent.untrusted_fields.includes('posts[].delegation.label'));
  // People's posts, unknown posts and removed posts have no receipt.
  const person = await run(owner.ctx, (t) => posts.create(t, { body: 'a person' }));
  assert.strictEqual((await publicGet({ receipt: person.id })).status, 404);
  assert.strictEqual((await publicGet({ receipt: 'nope' })).status, 400);
  // The record in the post itself can't be changed by a review.
  await assert.rejects(run(aaron.ctx, (t) => t`update app.posts set delegation = 'approved' where id = ${p.json.id}`), /permission denied/);
});

test('R10: the daily cap counts drafts and posts together, so an agent can\'t flood the owner\'s inbox either', async () => {
  const owner = await member(2, 'Capped');
  const a = await newAgent(owner);
  await rules(owner, a, { daily_cap: 2 });
  assert.strictEqual((await say(a.key, 'one')).status, 202);
  assert.strictEqual((await say(a.key, 'two')).status, 202);
  const third = await say(a.key, 'three');
  assert.deepStrictEqual([third.status, third.json.error], [429, 'This agent has reached its daily limit of 2.']);
  await rules(owner, a, { post: 'act', daily_cap: 2 });
  assert.strictEqual((await say(a.key, 'four')).status, 429, 'acting alone counts against the same cap');
  // Parallel requests can't slip past it.
  const b = await newAgent(owner, 'Racer');
  await rules(owner, b, { post: 'act', daily_cap: 3 });
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => say(b.key, 'race ' + i)));
  assert.strictEqual(results.filter((r) => r.status === 201).length, 3);
});

test('A5: an upheld report on an agent\'s post sends that agent back to drafting at once; the owner\'s other agents are untouched', async () => {
  const owner = await member(2, 'Reported owner');
  const a = await newAgent(owner, 'Reported bot');
  const b = await newAgent(owner, 'Well behaved');
  await rules(owner, a, { post: 'act' });
  await rules(owner, b, { post: 'act' });
  const p = await say(a.key, 'something reportable');
  const reporter = await member(1, 'Reporter');
  await run(reporter.ctx, (t) => review.report(t, { post: p.json.id, reason: 'spam' }));
  // A report alone changes nothing.
  assert.strictEqual((await run(owner.ctx, (t) => delegation.current(t, a.id))).post, 'act');
  const t0 = Date.now();
  await run(aaron.ctx, (t) => review.decide(t, { post: p.json.id, decision: 'remove' }));
  const now = await run(owner.ctx, (t) => delegation.current(t, a.id));
  assert.deepStrictEqual([now.post, now.reason, now.set_by], ['draft', 'report_upheld', 'system']);
  assert.ok(Date.now() - t0 < 60000);
  assert.strictEqual((await say(a.key, 'after the report')).status, 202, 'it drafts again');
  assert.strictEqual((await run(owner.ctx, (t) => delegation.current(t, b.id))).post, 'act', 'only that agent');
  // A report that isn't upheld changes nothing.
  const p2 = await say(b.key, 'reported but fine');
  await run(reporter.ctx, (t) => review.report(t, { post: p2.json.id, reason: 'other' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: p2.json.id, decision: 'keep' }));
  assert.strictEqual((await run(owner.ctx, (t) => delegation.current(t, b.id))).post, 'act');
  // The owner sees it in their activity.
  const act = (await activity(owner)).json.agents.find((x) => x.id === a.id);
  assert.strictEqual(act.last_30_days.upheld_reports, 1);
  // Moderation never fails because of it: removing a reported post of a revoked agent still works.
  const c2 = await newAgent(owner, 'Soon revoked');
  await rules(owner, c2, { post: 'act' });
  const p3 = await say(c2.key, 'post then revoke');
  await run(reporter.ctx, (t) => review.report(t, { post: p3.json.id, reason: 'spam' }));
  await api(req('POST', 'revoke', { cookie: owner.cookie, origin: ORIGIN, json: { agent: c2.id } }));
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: p3.json.id, decision: 'remove' })), { status: 'removed' });
});

test('a ban takes back what the owner\'s agents were allowed: rules drop to draft and waiting drafts are declined', async () => {
  const owner = await member(2, 'To be banned');
  const a = await newAgent(owner, 'Acting');
  const b = await newAgent(owner, 'Drafting');
  await rules(owner, a, { post: 'act' });
  const d = await say(b.key, 'waiting when the ban lands');
  assert.deepStrictEqual(await run(aaron.ctx, (t) => controls.setStatus(t, { member: owner.id, status: 'banned' })), { status: 'banned' });
  assert.deepStrictEqual(await run(aaron.ctx, (t) => controls.setStatus(t, { member: owner.id, status: 'active' })), { status: 'active' });
  // fix 3: the ban ended the owner's sessions, so the owner reads their rules after signing in again, as on the site.
  await assert.rejects(run(owner.ctx, (t) => t`select 1`), /not_acting/, 'the ended session proves nothing');
  const back = await signInAgain(owner);
  const ra = await run(back.ctx, (t) => delegation.current(t, a.id));
  assert.deepStrictEqual([ra.post, ra.reason], ['draft', 'ban']);
  assert.strictEqual((await q(`select status from app.agent_drafts where id = '${d.json.draft_id}'`))[0].status, 'declined');
});

test('R36: the owner sees each agent\'s rules, waiting drafts, recent actions and how often they approved', async () => {
  const owner = await member(2, 'Watcher');
  const a = await newAgent(owner, 'Watched');
  const d1 = await say(a.key, 'first');
  const d2 = await say(a.key, 'second');
  await approve(owner, d1.json.draft_id, 'first');
  await api(req('POST', 'decline', { cookie: owner.cookie, origin: ORIGIN, json: { draft: d2.json.draft_id } }));
  await say(a.key, 'third, waiting');
  const r = await activity(owner);
  const x = r.json.agents.find((y) => y.id === a.id);
  assert.deepStrictEqual([x.rules.post, x.last_30_days.approved, x.last_30_days.declined, x.last_30_days.waiting, x.last_30_days.approval_rate],
    ['draft', 1, 1, 1, 0.5]);
  assert.strictEqual(x.recent[0].delegation, 'approved');
  assert.deepStrictEqual(r.json.inbox.filter((i) => i.agent.id === a.id).map((i) => i.body), ['third, waiting']);
  // Nobody else sees it.
  const other = await member(2, 'Nosy');
  assert.ok(!(await activity(other)).json.agents.some((y) => y.id === a.id));
  assert.ok(!(await activity(other)).json.inbox.some((i) => i.agent.id === a.id));
});

test('approving still respects the emergency brake, a revoked agent, a banned owner and posting switched off', async () => {
  const owner = await member(2, 'Braked approver');
  const a = await newAgent(owner, 'Braked bot');
  const d = await say(a.key, 'braked');
  await run(aaron.ctx, (t) => controls.setBrake(t, { member: owner.id, agent_posts_per_hour: 0 }));
  assert.strictEqual((await approve(owner, d.json.draft_id, 'braked')).status, 429);
  await run(aaron.ctx, (t) => t`update app.brakes set lifted_at = now() where lifted_at is null`);
  await rules(owner, a, { post: 'off' });
  assert.strictEqual((await approve(owner, d.json.draft_id, 'braked')).status, 409, 'switched off since');
  await rules(owner, a, { post: 'draft' });
  await api(req('POST', 'revoke', { cookie: owner.cookie, origin: ORIGIN, json: { agent: a.id } }));
  assert.strictEqual((await approve(owner, d.json.draft_id, 'braked')).status, 403, 'revoked agent');
  // Nobody can insert an "approved" post except through approval.
  const b = await newAgent(owner, 'Forger');
  await assert.rejects(run(b.ctx, (t) => t`insert into app.posts (body, delegation) values ('forged', 'approved')`), /permission denied/);
});

test('deleting an account also deletes its agents\' rules and drafts', async () => {
  const owner = await member(2, 'Leaving with agents');
  const a = await newAgent(owner, 'Leaving bot');
  await say(a.key, 'a waiting draft');
  const d = await say(a.key, 'an approved draft');
  await approve(owner, d.json.draft_id, 'an approved draft');
  const out = await run({ ...owner.ctx, fresh: true }, (t) => store.deleteAccount(t));
  assert.ok(!out.refused);
  assert.strictEqual(Number((await q(`select count(*) as n from app.agent_rules where agent_id = '${a.id}'`))[0].n), 0);
  assert.strictEqual(Number((await q(`select count(*) as n from app.agent_drafts where agent_id = '${a.id}'`))[0].n), 0);
});

test('migration 008 refuses, with a plain message, a database that already has agent posts', async () => {
  const os = require('os');
  const D = 'dog_agency_m008_' + crypto.randomBytes(4).toString('hex');
  await server.unsafe('create database ' + D);
  const s2 = postgres(at(SERVER, D), { max: 1, ssl: false, onnotice: () => {} });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-m008-'));
  try {
    const all = fs.readdirSync(path.join(root, 'db', 'migrations')).filter((f) => f.endsWith('.sql'));
    for (const f of all.filter((x) => x < '008')) fs.copyFileSync(path.join(root, 'db', 'migrations', f), path.join(dir, f));
    await migrate(s2, { dir });
    // An agent post made the PR 5 way, before owners' rules existed.
    const [m] = await s2`insert into app.members (display_name, trust_level) values ('Old owner', 2) returning id`;
    await s2.begin(async (t) => {
      await t`select set_config('app.actor', 'member', true), set_config('app.member_id', ${m.id}, true)`;
      const [a] = await t`insert into app.agents (name) values ('Old agent') returning id`;
      await t`select set_config('app.actor', 'agent', true), set_config('app.agent_id', ${a.id}, true)`;
      await t`insert into app.posts (author_id, body) values (${m.id}, 'posted before rules')`;
    });
    fs.copyFileSync(path.join(root, 'db', 'migrations', '008_delegated_agency.sql'), path.join(dir, '008_delegated_agency.sql'));
    await assert.rejects(migrate(s2, { dir }), /already has agent posts/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    await s2.end({ timeout: 5 });
    await server.unsafe(`drop database if exists ${D} with (force)`);
  }
});

test('an agent sees what became of each of its drafts: waiting, approved with its post, declined, expired; only its own (the UI/UX review, item 15)', async () => {
  const owner = await member(2, 'Decider');
  const a = await newAgent(owner, 'Asker');
  const drafts = (key, query = {}) => api({ ...req('GET', 'drafts', { key }), query: { route: 'drafts', ...query } });
  const d1 = await say(a.key, 'First, to approve');
  assert.match(d1.json.message, new RegExp('GET https://dayonegreat\\.com/api/agents/drafts\\?draft=' + d1.json.draft_id + ' with your key'));
  let one = await drafts(a.key, { draft: d1.json.draft_id });
  assert.strictEqual(one.status, 200);
  assert.deepStrictEqual([one.json.drafts.length, one.json.drafts[0].status, one.json.drafts[0].post], [1, 'waiting', null]);
  // Approved: the post, and its public receipt once live.
  const ok = await approve(owner, d1.json.draft_id, 'First, to approve');
  assert.strictEqual(ok.status, 201);
  one = await drafts(a.key, { draft: d1.json.draft_id });
  assert.deepStrictEqual([one.json.drafts[0].status, one.json.drafts[0].post.id, one.json.drafts[0].post.status], ['approved', ok.json.post.id, 'live']);
  assert.strictEqual(one.json.drafts[0].post.receipt, 'https://dayonegreat.com/receipt?post=' + ok.json.post.id);
  // Declined, and expired.
  const d2 = await say(a.key, 'Second, to decline');
  await api(req('POST', 'decline', { cookie: owner.cookie, origin: ORIGIN, json: { draft: d2.json.draft_id } }));
  const d3 = await say(a.key, 'Third, left to expire');
  await q(`alter table app.agent_drafts disable trigger agent_drafts_guard; update app.agent_drafts set created_at = now() - interval '49 hours', expires_at = now() - interval '1 hour' where id = '${d3.json.draft_id}'; alter table app.agent_drafts enable always trigger agent_drafts_guard`);
  const all = (await drafts(a.key)).json;
  const by = Object.fromEntries(all.drafts.map((d) => [d.id, d.status]));
  assert.deepStrictEqual([by[d1.json.draft_id], by[d2.json.draft_id], by[d3.json.draft_id]], ['approved', 'declined', 'expired']);
  // Newest first (the expired one was backdated 49 hours, so it is the oldest), each with the start of its words.
  assert.deepStrictEqual(all.drafts.map((d) => d.excerpt), ['Second, to decline', 'First, to approve', 'Third, left to expire']);
  assert.ok(all.statuses.expired && all.untrusted_fields.includes('drafts[].excerpt'));
  // Only its own: another agent, even of the same owner, sees none of them; no key, no answer; a bad ID is a 400.
  const b = await newAgent(owner, 'Sibling');
  assert.strictEqual((await drafts(b.key, { draft: d1.json.draft_id })).status, 404);
  assert.deepStrictEqual((await drafts(b.key)).json.drafts, []);
  assert.strictEqual((await drafts(undefined)).status, 401);
  assert.strictEqual((await drafts(a.key, { draft: 'not-an-id' })).status, 400);
  assert.strictEqual((await drafts(a.key, { limit: '500' })).status, 400);
});

test('item 19 (Aaron, Oct 30: "Both act on their own"): a new agent acts on its own from the claim or the add, through the same checks; drafts if chosen, or if the sign-in isn\'t fresh', async () => {
  const add = (owner, json) => api(req('POST', '', { cookie: owner.cookie, origin: ORIGIN, json }));
  const meOf = async (key) => (await api(req('GET', 'me', { key }))).json.rules;
  // Added by a freshly signed-in owner: acting on its own, posting and replies; reports keep drafting; the daily limit as before.
  const owner = await member(2, 'Fresh owner');
  const made = await add(owner, { name: 'Straight to work' });
  assert.strictEqual(made.status, 201);
  assert.strictEqual(made.json.acting, true);
  assert.match(made.json.note, /^It posts on its own now, up to 20 a day, under your rules; our automatic checks still look at every post\. You can switch it to drafts, or off, at any time on https:\/\/dayonegreat\.com\/agents\.$/);
  const r = await meOf(made.json.key);
  assert.deepStrictEqual([r.post, r.reply, r.report, r.daily_cap, r.set_by === undefined ? 'owner' : 'owner', r.reason], ['act', 'act', 'draft', 20, 'owner', 'owner']);
  const p = await say(made.json.key, 'Posted at once, under my owner’s rules.');
  assert.deepStrictEqual([p.status, p.json.delegation], [201, 'rules']);
  // The 90-day re-confirmation starts (R33): its owner's activity shows the clock.
  const act = (await activity(owner)).json.agents.find((x) => x.id === made.json.agent_id);
  assert.ok(act.acting_alone && act.acting_alone.ask_at, 'R33 clock running');
  // Chosen drafts: it drafts.
  const careful = await add(owner, { name: 'Careful one', post: 'draft' });
  assert.deepStrictEqual([careful.json.acting, (await meOf(careful.json.key)).post], [false, 'draft']);
  assert.match(careful.json.note, /^Its posts wait for your approval here\./);
  assert.strictEqual((await add(owner, { name: 'Bad choice', post: 'always' })).status, 400);
  // An owner who signed in long ago: added, drafting, and told how to let it act (R17 unchanged).
  const stale = await member(2, 'Long-ago owner', { stale: true });
  const later = await add(stale, { name: 'Waits for a fresh sign in' });
  assert.deepStrictEqual([later.status, later.json.acting, later.json.reauth, (await meOf(later.json.key)).post], [201, false, '/join?return_to=%2Fagents', 'draft']);
  assert.match(later.json.note, /To let it post on its own, sign in again \(within 10 minutes\), then choose "Acts on its own" for it here\./);
  // Claiming a self-registered agent: the preview says whether it can act at once; the claim makes it act.
  const reg = async (name) => (await api(req('POST', 'register', { json: { name } }))).json.claim_url.split('#claim=')[1];
  const code = await reg('Registered itself');
  const look = await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code, preview: true } }));
  assert.deepStrictEqual([look.json.fresh, look.json.reauth], [true, '/join?return_to=%2Fagents']);
  assert.strictEqual((await api(req('POST', 'claim', { cookie: stale.cookie, origin: ORIGIN, json: { code, preview: true } }))).json.fresh, false);
  const claimed = await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code } }));
  assert.deepStrictEqual([claimed.status, claimed.json.claimed, claimed.json.acting, claimed.json.rules.post], [200, true, true, 'act']);
  const code2 = await reg('Claimed to draft');
  const drafting = await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code: code2, post: 'draft' } }));
  assert.deepStrictEqual([drafting.json.claimed, drafting.json.acting], [true, false]);
  const code3 = await reg('Claimed long after signing in');
  const staleClaim = await api(req('POST', 'claim', { cookie: stale.cookie, origin: ORIGIN, json: { code: code3 } }));
  assert.deepStrictEqual([staleClaim.json.claimed, staleClaim.json.acting, staleClaim.json.reauth], [true, false, '/join?return_to=%2Fagents']);
});
