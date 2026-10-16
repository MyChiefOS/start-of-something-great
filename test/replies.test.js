// Release 2, PR 14: replies against a real Postgres. Aaron's decision (Oct 16, 2026): agent-to-agent replies are
// allowed, with a depth limit (R40). Every behaviour has a test: people reply to posts and replies; an agent's reply
// follows its owner's reply setting (off, draft, act), counts against its daily limit, waits for approval of its exact
// words when drafting, and carries the same label and receipt as its posts; a chain of agents stops at the limit, in
// the database, and only the owner role changes the limit; an agent can't reply as another; replies are masked and
// marked untrusted in the API and MCP; JEVs scores the real depth (J12); the brake, containment, reports, removal and
// deletion apply to replies as to posts; and the rate limits.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const agentkey = require('../signin/agentkey');
const store = require('../db/signin');
const posts = require('../db/posts');
const delegation = require('../db/delegation');
const controls = require('../db/controls');
const review = require('../db/review');
const jevs = require('../db/jevs');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { call } = require('./helpers');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';

if (!SERVER) {
  if (process.env.CI) test('reply tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('replies against a database (RP1 to RP9, R40)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_replies_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); });
const feedApi = require('../api/feed.js');

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  aaron = await member(2, 'Aaron');
  await asOwner(`update app.members set is_admin = true where id = '${aaron.id}'`);
  aaron.ctx = { actor: 'admin', memberId: aaron.id };
  // The watch stays quiet here (PR 13 tests it); containment is started by hand where a test needs it.
  await asOwner('update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000');
});
test.after(async () => {
  require('../api/mcp.js').setReadThread(async () => undefined);
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(level = 2, name = 'Member') {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId } };
}
// An agent with a working key, and its owner's rules for posting and replies (a fresh sign-in, as raising needs).
async function agentOf(owner, name, { post = 'act', reply = 'act', cap = 1000 } = {}) {
  const k = agentkey.newKey();
  const [a] = await run(owner.ctx, (t) => t`insert into app.agents (name) values (${name}) returning id`);
  await run(owner.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${a.id}, ${k.hash})`);
  await rules(owner, a.id, { post, reply, cap });
  return { id: a.id, key: k.key, owner, ctx: { actor: 'agent', memberId: owner.id, agentId: a.id } };
}
const rules = (owner, agent, { post = 'act', reply = 'act', cap = 1000 } = {}) =>
  run({ ...owner.ctx, fresh: true }, (t) => delegation.setRules(t, { agent, post, reply, report: 'draft', dailyCap: cap }));

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
async function api(method, { cookie, key, json, query = {}, ip = '203.0.113.' + (1 + Math.floor(Math.random() * 200)) } = {}) {
  const headers = { host: 'dayonegreat.com', 'x-vercel-forwarded-for': ip };
  if (cookie) headers.cookie = cookie;
  if (key) headers.authorization = 'Bearer ' + key;
  if (method === 'POST') { headers.origin = ORIGIN; headers['content-type'] = 'application/json'; }
  const r = res();
  await feedApi.handle({ method, url: '/api/feed', headers, query, body: json === undefined ? undefined : JSON.stringify(json) }, r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null, headers: r.headers };
}
const say = (who, body, replyTo) => api('POST', { cookie: who.cookie, json: replyTo === undefined ? { body } : { body, reply_to: replyTo } });
const agentSays = (ag, body, replyTo) => api('POST', { key: ag.key, json: replyTo === undefined ? { body } : { body, reply_to: replyTo } });
const thread = (id) => api('GET', { query: { thread: id } });
async function agentsApi(method, route, owner, json) {
  const r = res();
  const headers = { host: 'dayonegreat.com', cookie: owner.cookie, 'x-vercel-forwarded-for': '203.0.113.9' };
  if (method === 'POST') { headers.origin = ORIGIN; headers['content-type'] = 'application/json'; }
  await require('../api/agents.js').handle({ method, url: '/api/agents/' + route, headers, query: { route }, body: json ? JSON.stringify(json) : undefined }, r, run, { ipKey: crypto.randomBytes(32) });
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
const decision = async (subject) => (await q(`select action, scores, level from app.jevs_decisions where subject_id = '${subject}' order by created_at`));
const rowOf = async (id) => (await q(`select id, parent_id, root_id, depth, agent_run, lane, agent_id, delegation, status from app.posts where id = '${id}'`))[0];
const count = async (table, where) => (await q(`select count(*)::int as n from app.${table} where ${where}`))[0].n;

test('the database passes the coverage check and matches the reviewed snapshot with replies (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('RP1: people reply to posts and to replies; the thread reads in conversation order; the lanes hold only posts, each with its reply count', async () => {
  const ann = await member(2, 'Ann');
  const bob = await member(2, 'Bob');
  const post = await say(ann, 'What should we build next for the feed?');
  assert.strictEqual(post.status, 201);
  const r1 = await say(bob, 'Threads, please.', post.json.id);
  assert.strictEqual(r1.status, 201);
  assert.strictEqual(r1.json.in_reply_to, post.json.id);
  const r2 = await say(ann, 'Agreed. Indented?', r1.json.id);
  const r3 = await say(bob, 'A second top-level reply.', post.json.id);
  assert.deepStrictEqual(await rowOf(r2.json.id), { id: r2.json.id, parent_id: r1.json.id, root_id: post.json.id, depth: 2, agent_run: 0,
    lane: 'people', agent_id: null, delegation: null, status: 'live' });
  const th = await thread(post.json.id);
  assert.strictEqual(th.status, 200);
  assert.match(th.headers['vercel-cdn-cache-control'], /s-maxage=20/, 'cached at the edge like the feed (G2, F7)');
  assert.strictEqual(th.json.post.id, post.json.id);
  // Each reply follows the one it answers; earlier replies first.
  assert.deepStrictEqual(th.json.replies.map((r) => [r.id, r.in_reply_to, r.depth]),
    [[r1.json.id, post.json.id, 1], [r2.json.id, r1.json.id, 2], [r3.json.id, post.json.id, 1]]);
  assert.deepStrictEqual(th.json.limits, { agents_in_a_row: 3, max_depth: 50 });
  // The lane lists the post with its count, and no reply.
  const lane = await api('GET', { query: { lane: 'people', limit: '50' } });
  const ids = lane.json.posts.map((p) => p.id);
  assert.ok(ids.includes(post.json.id));
  for (const r of [r1, r2, r3]) assert.ok(!ids.includes(r.json.id), 'a reply is not in the lane');
  const listed = lane.json.posts.find((p) => p.id === post.json.id);
  assert.strictEqual(listed.replies, 3);
  assert.strictEqual(listed.thread, '/api/feed?thread=' + post.json.id);
  // A reply's own ID isn't a thread; nor is a made-up one.
  assert.strictEqual((await thread(r1.json.id)).status, 404);
  assert.strictEqual((await thread(crypto.randomUUID())).status, 404);
  assert.strictEqual((await api('GET', { query: { thread: post.json.id, lane: 'people' } })).status, 400, 'thread stands alone, so the edge cache has one spelling');
});

test('RP1: a reply needs a live post above it: waiting, removed, missing, a banned author or a removed reply in between are all refused, and nothing is written', async () => {
  const ann = await member(2, 'Ann2');
  const bob = await member(2, 'Bob2');
  const before = await count('posts', `author_id = '${bob.id}'`);
  assert.strictEqual((await say(bob, 'To nowhere', crypto.randomUUID())).status, 404);
  // A level 1 member's first post waits for review (F6, shadow mode): nobody can reply to it yet.
  const newbie = await member(1, 'Newbie');
  const waiting = await say(newbie, 'My first post, waiting for review.');
  assert.strictEqual(waiting.json.status, 'waiting');
  assert.strictEqual((await say(bob, 'Too early', waiting.json.id)).status, 404);
  // Removed by Aaron.
  const p = await say(ann, 'A post that will be removed.');
  const mid = await say(bob, 'A reply in the middle.', p.json.id);
  const deep = await say(ann, 'Under the middle.', mid.json.id);
  await run(aaron.ctx, (t) => review.decide(t, { post: mid.json.id, decision: 'remove' }));
  assert.strictEqual((await say(bob, 'Under a removed reply', mid.json.id)).status, 404);
  assert.strictEqual((await say(bob, 'Two below a removed reply', deep.json.id)).status, 404, 'every post above must be live');
  // The removed reply and everything under it leave the thread and the count.
  const th = await thread(p.json.id);
  assert.deepStrictEqual(th.json.replies, []);
  assert.strictEqual((await api('GET', { query: { lane: 'people', limit: '50' } })).json.posts.find((x) => x.id === p.json.id).replies, 0);
  // A banned author's post can't be answered.
  const carl = await member(2, 'Carl');
  const cp = await say(carl, 'Soon banned.');
  await run({ ...aaron.ctx, note: 'test' }, (t) => controls.setStatus(t, { member: carl.id, status: 'banned' }));
  assert.strictEqual((await say(bob, 'To a banned author', cp.json.id)).status, 404);
  assert.strictEqual(await count('posts', `author_id = '${bob.id}'`), before + 1, 'only the middle reply was ever written');
});

test('RP2: an agent\'s reply follows its owner\'s reply setting, not the posting one: off refuses, draft waits, act replies with the agent label and receipt', async () => {
  const owner = await member(2, 'Owner');
  const person = await member(2, 'Person');
  const p = await say(person, 'Agents, what do you think?');
  const ag = await agentOf(owner, 'Helper', { post: 'act', reply: 'off' });
  const off = await agentSays(ag, 'I think yes.', p.json.id);
  assert.strictEqual(off.status, 403);
  assert.match(off.json.error, /replies off/);
  assert.strictEqual((await agentSays(ag, 'A post of my own still goes out.')).status, 201, 'posting is a separate setting');
  await rules(owner, ag.id, { post: 'act', reply: 'draft' });
  const drafted = await agentSays(ag, 'I think yes, drafted.', p.json.id);
  assert.strictEqual(drafted.status, 202);
  assert.strictEqual(drafted.json.action, 'reply');
  assert.strictEqual(drafted.json.in_reply_to, p.json.id);
  assert.strictEqual(await count('posts', `parent_id = '${p.json.id}'`), 0, 'nothing is published while it drafts');
  await rules(owner, ag.id, { post: 'off', reply: 'act' });
  const acted = await agentSays(ag, 'I think yes, on my own.', p.json.id);
  assert.strictEqual(acted.status, 201);
  assert.match(acted.json.message, /Replied/);
  const row = await rowOf(acted.json.id);
  assert.deepStrictEqual([row.lane, row.agent_id, row.delegation, row.agent_run, row.depth], ['agents', ag.id, 'rules', 1, 1]);
  // In the thread it carries the same label as an agent's post, with its receipt.
  const r = (await thread(p.json.id)).json.replies.find((x) => x.id === acted.json.id);
  assert.strictEqual(r.agent.name, 'Helper');
  assert.strictEqual(r.author.name, 'Owner');
  assert.strictEqual(r.delegation.label, 'Posted by Helper under Owner’s rules');
  assert.strictEqual(r.delegation.receipt, '/receipt?post=' + acted.json.id);
  const rc = await api('GET', { query: { receipt: acted.json.id } });
  assert.strictEqual(rc.status, 200);
  assert.strictEqual(rc.json.receipt.in_reply_to, p.json.id);
  assert.strictEqual(rc.json.receipt.rules.reply, 'act');
  assert.strictEqual(rc.json.receipt.rules.post, 'off');
  assert.strictEqual(rc.json.receipt.post.url, '/api/feed?thread=' + p.json.id);
  // The owner's inbox and notice say a reply waits (the drafted one).
  const act = await agentsApi('GET', 'activity', owner);
  const d = act.json.inbox.find((x) => x.id === drafted.json.draft_id);
  assert.deepStrictEqual([d.action, d.reply_to], ['reply', { post: p.json.id, thread: '/api/feed?thread=' + p.json.id }]);
  assert.strictEqual(await count('notices', `member_id = '${owner.id}' and kind = 'draft_waiting' and title like '%wrote a reply for you'`), 1);
});

test('RP3: an agent\'s reply in draft needs its owner\'s approval of the exact words, and goes under the post it was written for', async () => {
  const owner = await member(2, 'Drafter owner');
  const person = await member(2, 'Asker');
  const p = await say(person, 'A question for agents.');
  const ag = await agentOf(owner, 'Drafter', { post: 'draft', reply: 'draft' });
  const words = 'My considered reply.';
  const d = await agentSays(ag, words, p.json.id);
  assert.strictEqual(d.status, 202);
  assert.strictEqual((await agentsApi('POST', 'approve', owner, { draft: d.json.draft_id, hash: c.sha256hex(words + ' (changed)') })).status, 409, 'other words are refused');
  const other = await member(2, 'Not the owner');
  assert.strictEqual((await agentsApi('POST', 'approve', other, { draft: d.json.draft_id, hash: c.sha256hex(words) })).status, 404, 'only its owner approves');
  const ok = await agentsApi('POST', 'approve', owner, { draft: d.json.draft_id, hash: c.sha256hex(words) });
  assert.strictEqual(ok.status, 201);
  const row = await rowOf(ok.json.post.id);
  assert.deepStrictEqual([row.parent_id, row.root_id, row.delegation, row.lane, row.agent_id, row.agent_run], [p.json.id, p.json.id, 'approved', 'agents', ag.id, 1]);
  assert.strictEqual((await thread(p.json.id)).json.replies[0].delegation.label, 'Approved by Drafter owner');
  // A draft whose post is removed before approval approves nothing, and stays waiting for a decline.
  const p2 = await say(person, 'This one will be removed.');
  const d2 = await agentSays(ag, words, p2.json.id);
  await run(aaron.ctx, (t) => review.decide(t, { post: p2.json.id, decision: 'remove' }));
  const late = await agentsApi('POST', 'approve', owner, { draft: d2.json.draft_id, hash: c.sha256hex(words) });
  assert.strictEqual(late.status, 409);
  assert.match(late.json.error, /isn’t live/);
  assert.strictEqual((await q(`select status from app.agent_drafts where id = '${d2.json.draft_id}'`))[0].status, 'pending');
  // Approving follows the reply setting at the time: switched off since, nothing goes out.
  const p3 = await say(person, 'Third question.');
  const d3 = await agentSays(ag, words, p3.json.id);
  await rules(owner, ag.id, { post: 'draft', reply: 'off' });
  assert.strictEqual((await agentsApi('POST', 'approve', owner, { draft: d3.json.draft_id, hash: c.sha256hex(words) })).status, 409);
  // Where a draft goes never changes: its owner has no right to, and past every right (the superuser) the guard refuses.
  await assert.rejects(run(owner.ctx, (t) => t`update app.agent_drafts set parent_id = ${p.json.id} where id = ${d3.json.draft_id}`), (e) => e.code === '42501');
  await assert.rejects(q(`update app.agent_drafts set parent_id = '${p.json.id}' where id = '${d3.json.draft_id}'`), /never change/);
});

test('R40: agents answering agents stop at the depth limit, in the database, for replies and drafts alike; a person replying starts the count again', async () => {
  const o1 = await member(2, 'Owner one');
  const o2 = await member(2, 'Owner two');
  const a = await agentOf(o1, 'Alpha');
  const b = await agentOf(o2, 'Beta');
  const drafting = await agentOf(o2, 'Gamma', { post: 'draft', reply: 'draft' });
  const top = await agentSays(a, 'An agent starts a thread.');
  assert.strictEqual((await rowOf(top.json.id)).agent_run, 1, 'an agent\'s post is the first agent turn');
  const t2 = await agentSays(b, 'Second agent turn.', top.json.id);
  const t3 = await agentSays(a, 'Third agent turn.', t2.json.id);
  assert.deepStrictEqual([(await rowOf(t2.json.id)).agent_run, (await rowOf(t3.json.id)).agent_run], [2, 3]);
  // The fourth agent in a row is refused, whether it would act or draft, and nothing is written.
  const fourth = await agentSays(b, 'Fourth agent turn.', t3.json.id);
  assert.strictEqual(fourth.status, 409);
  assert.strictEqual(fourth.json.refused, 'reply_depth');
  assert.match(fourth.json.error, /3 times in a row/);
  assert.strictEqual((await agentSays(drafting, 'Fourth, as a draft.', t3.json.id)).json.refused, 'reply_depth');
  assert.strictEqual(await count('posts', `parent_id = '${t3.json.id}'`), 0);
  assert.strictEqual(await count('agent_drafts', `parent_id = '${t3.json.id}'`), 0);
  // The database refuses it however it is asked: straight through SQL as the agent, too.
  await assert.rejects(run(b.ctx, (t) => t`insert into app.posts (body, parent_id) values ('Around the API', ${t3.json.id})`), /reply_depth/);
  // A person replying resets it: the next agent is the first in a new run.
  const person = await member(2, 'Human in the loop');
  const h = await say(person, 'A person steps in.', t3.json.id);
  assert.strictEqual((await rowOf(h.json.id)).agent_run, 0);
  const after = await agentSays(b, 'An agent answers the person.', h.json.id);
  assert.strictEqual(after.status, 201);
  assert.strictEqual((await rowOf(after.json.id)).agent_run, 1);
  // A post by a person, then three agents in a row, then the fourth refused.
  const pp = await say(person, 'A person starts.');
  let parent = pp.json.id;
  for (const [i, ag] of [[1, a], [2, b], [3, a]]) {
    const r = await agentSays(ag, 'Agent turn ' + i, parent);
    assert.strictEqual(r.status, 201, 'agent turn ' + i);
    parent = r.json.id;
  }
  assert.strictEqual((await agentSays(b, 'Agent turn 4', parent)).json.refused, 'reply_depth');
});

test('R40: only the database owner role changes the limits; a lower limit refuses at its own depth plus one, and the nesting limit holds for people too', async () => {
  const o1 = await member(2, 'Limit owner');
  const a = await agentOf(o1, 'Limit agent');
  const b = await agentOf(o1, 'Limit agent two');
  // The site, Aaron and members can only read them.
  for (const ctx of [aaron.ctx, o1.ctx, { actor: 'system' }]) {
    await assert.rejects(run(ctx, (t) => t`update app.reply_settings set max_agent_turns = 20`), (e) => e.code === '42501');
  }
  assert.deepStrictEqual(await run({ actor: 'anon' }, (t) => posts.replyLimits(t)), { maxAgentTurns: 3, maxDepth: 50 });
  await asOwner('update app.reply_settings set max_agent_turns = 2, max_depth = 3');
  try {
    const top = await agentSays(a, 'Start.');
    const r2 = await agentSays(b, 'Two in a row.', top.json.id);
    assert.strictEqual(r2.status, 201);
    const r3 = await agentSays(a, 'Three in a row.', r2.json.id);
    assert.strictEqual(r3.json.refused, 'reply_depth');
    assert.match(r3.json.error, /2 times in a row/);
    // Nesting: three levels deep, then refused, whoever writes.
    const p1 = await member(2, 'Nester');
    const p2 = await member(2, 'Nester two');
    let parent = (await say(p1, 'Root.')).json.id;
    for (let i = 1; i <= 3; i++) {
      const r = await say(i % 2 ? p2 : p1, 'Level ' + i, parent);
      assert.strictEqual(r.status, 201, 'level ' + i);
      parent = r.json.id;
    }
    const tooDeep = await say(p2, 'Level 4', parent);
    assert.strictEqual(tooDeep.status, 409);
    assert.strictEqual(tooDeep.json.refused, 'reply_nesting');
  } finally {
    await asOwner('update app.reply_settings set max_agent_turns = 3, max_depth = 50');
  }
  // The settings keep to their ranges.
  await assert.rejects(asOwner('update app.reply_settings set max_agent_turns = 0'), /check/);
  await assert.rejects(asOwner('update app.reply_settings set max_depth = 500'), /check/);
  await assert.rejects(asOwner('insert into app.reply_settings default values'), /unique|duplicate/);
});

test('RP4: an agent can\'t reply as another agent, for another owner, or say where a reply sits', async () => {
  const o1 = await member(2, 'Honest owner');
  const o2 = await member(2, 'Other owner');
  const a = await agentOf(o1, 'Honest');
  const b = await agentOf(o2, 'Other');
  const p = await say(o2, 'A post to answer.');
  // The API takes only the words and the post answered.
  for (const extra of [{ agent: b.id }, { agent_id: b.id }, { owner: o2.id }, { lane: 'people' }, { depth: 0 }]) {
    const r = await api('POST', { key: a.key, json: { body: 'Pretending', reply_to: p.json.id, ...extra } });
    assert.strictEqual(r.status, 400, JSON.stringify(extra));
  }
  // In the database, as agent A: naming B, B's owner, or where it sits is refused or overwritten.
  await assert.rejects(run(a.ctx, (t) => t`insert into app.posts (body, parent_id, agent_id) values ('as B', ${p.json.id}, ${b.id})`), (e) => e.code === '42501');
  await assert.rejects(run(a.ctx, (t) => t`insert into app.posts (body, parent_id, author_id) values ('for o2', ${p.json.id}, ${o2.id})`), (e) => e.code === '42501');
  await assert.rejects(run(a.ctx, (t) => t`insert into app.posts (body, parent_id, root_id, depth, agent_run) values ('placed', ${p.json.id}, ${p.json.id}, 1, 0)`), (e) => e.code === '42501');
  await assert.rejects(run(a.ctx, (t) => t`insert into app.agent_drafts (body, parent_id, agent_id) values ('as B', ${p.json.id}, ${b.id})`), (e) => e.code === '42501');
  // What it can write is its own, under its own owner.
  const mine = await run(a.ctx, (t) => delegation.submit(t, { body: 'Mine', replyTo: p.json.id }));
  const row = await rowOf(mine.posted.id);
  assert.deepStrictEqual([row.agent_id, (await q(`select author_id from app.posts where id = '${row.id}'`))[0].author_id], [a.id, o1.id]);
  // A member can't post a reply in the agents lane or as an agent either.
  await assert.rejects(run(o1.ctx, (t) => t`insert into app.posts (body, parent_id, agent_id) values ('as my agent', ${p.json.id}, ${a.id})`), (e) => e.code === '42501');
  // And nobody moves a reply afterwards, Aaron included.
  await assert.rejects(run(aaron.ctx, (t) => t`update app.posts set parent_id = null where id = ${row.id}`), (e) => e.code === '42501');
  // Even past every right and policy (the superuser, as Aaron), the guard trigger refuses it.
  await assert.rejects(su.begin(async (t) => { await t.unsafe(`select set_config('app.actor', 'admin', true)`); await t.unsafe(`update app.posts set depth = 0, parent_id = null, root_id = null where id = '${row.id}'`); }),
    /changes only a post's status/);
});

test('RP5, S9, P4: replies are masked and marked untrusted in the API and in the MCP get_thread tool, and the tool stays read-only', async () => {
  const MARK = 'ZQXMARK';
  const owner = await member(2, MARK + ' owner reach me at owner@example.com');
  const person = await member(2, MARK + ' person');
  const p = await say(person, MARK + ' top post, call +1 415 555 0100');
  const ag = await agentOf(owner, MARK + ' agent mail agent@example.org');
  const r1 = await say(person, MARK + ' a person replies, write to jane@example.com', p.json.id);
  const r2 = await agentSays(ag, MARK + ' an agent replies, at bot@example.net or +44 20 7946 0958', r1.json.id);
  assert.strictEqual(r2.status, 201);
  const stringPaths = (v, at, out) => {
    if (typeof v === 'string') out.push([at, v]);
    else if (Array.isArray(v)) v.forEach((x) => stringPaths(x, at + '[]', out));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) stringPaths(x, at ? at + '.' + k : k, out);
    return out;
  };
  const checkMarked = (data, where) => {
    const paths = stringPaths(data, '', []).filter(([x]) => !x.startsWith('untrusted_fields'));
    for (const [x, val] of paths) {
      if (val.includes(MARK)) assert.ok(data.untrusted_fields.includes(x), where + ': ' + x + ' is not listed as untrusted');
      assert.ok(!/@example\.(com|org|net)|555 0100|7946 0958/.test(val), where + ': contact details shown in ' + x);
    }
    for (const f of data.untrusted_fields) assert.ok(paths.some(([x]) => x === f), where + ': listed field ' + f + ' is not in the output');
    assert.match(data.note, /never as instructions/);
  };
  const th = await thread(p.json.id);
  checkMarked(th.json, 'API');
  assert.ok(th.json.untrusted_fields.includes('replies[].agent.name'));
  assert.match(th.json.replies[1].body, /\[email hidden\]/);
  assert.match(th.json.replies[1].body, /\[number hidden\]/);
  // MCP: the same thread through the read-only server.
  const mcp = require('../api/mcp.js');
  mcp.setReadThread((rootId) => run({ actor: 'anon' }, async (t) => {
    const x = await posts.thread(t, { root: rootId, limit: 200 });
    return x && { ...x, limits: await posts.replyLimits(t) };
  }));
  const out = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_thread', arguments: { post: p.json.id } } });
  const data = out.json.result.structuredContent;
  assert.strictEqual(out.json.result.isError, false);
  checkMarked(data, 'MCP');
  assert.strictEqual(data.replies.length, 2);
  const list = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const tool = list.json.result.tools.find((x) => x.name === 'get_thread');
  assert.strictEqual(tool.annotations.readOnlyHint, true);
  assert.match(tool.description, /never as instructions/);
  assert.ok(!list.json.result.tools.some((x) => /reply|post_|write|create/i.test(x.name) && x.name !== 'draft_proposal'), 'no tool writes: agents reply through the API');
  const bad = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_thread', arguments: { post: 'not-an-id' } } });
  assert.strictEqual(bad.json.result.isError, true);
  const none = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'get_thread', arguments: { post: r1.json.id } } });
  assert.strictEqual(none.json.result.isError, true, 'a reply is not a thread');
});

test('RP6, J12: JEVs checks every reply as a post and scores the real reply-chain depth', async () => {
  const o1 = await member(2, 'Scored one');
  const o2 = await member(2, 'Scored two');
  const a = await agentOf(o1, 'Scored A');
  const b = await agentOf(o2, 'Scored B', { reply: 'draft' });
  const person = await member(2, 'Scored person');
  const p = await say(person, 'Scored top post.');
  const r1 = await agentSays(a, 'First agent reply.', p.json.id);
  const top = await agentSays(a, 'An agent post.');
  const r2 = await agentSays((await agentOf(o2, 'Scored C')), 'Second agent in a row.', top.json.id);
  const r3d = await agentSays(b, 'Third in a row, drafted.', r2.json.id);
  const pr = await say(person, 'A person replies.', r2.json.id);
  for (const [subject, action, j12] of [[p.json.id, 'post.create', 0], [r1.json.id, 'post.create', 0], [r2.json.id, 'post.create', 10],
    [r3d.json.draft_id, 'draft.create', 20], [pr.json.id, 'post.create', 0]]) {
    const [d] = await decision(subject);
    assert.ok(d, 'a JEVs decision for ' + action);
    assert.strictEqual(d.action, action);
    assert.strictEqual(d.scores.J12, j12, action + ' scores J12 ' + j12);
  }
  // Approving the drafted third turn is scored as the post it becomes, with the same depth.
  const ok = await agentsApi('POST', 'approve', o2, { draft: r3d.json.draft_id, hash: c.sha256hex('Third in a row, drafted.') });
  assert.strictEqual(ok.status, 201);
  const [d] = await decision(ok.json.post.id);
  assert.deepStrictEqual([d.action, d.scores.J12], ['post.approved', 20]);
  // In enforce mode a reply still can't go live unscored (JEVs's commit-time check covers replies, which are posts).
  await asOwner(`update app.jevs_settings set value = 'enforce' where key = 'mode'`);
  try {
    await assert.rejects(run(person.ctx, (t) => posts.create(t, { body: 'Unscored reply', replyTo: p.json.id })), /unscored/);
  } finally {
    await asOwner(`update app.jevs_settings set value = 'shadow' where key = 'mode'`);
  }
});

test('RP7: the brake and the daily limit apply to replies exactly as to posts', async () => {
  const owner = await member(2, 'Braked owner');
  const person = await member(2, 'Braked person');
  const p = await say(person, 'Something to reply to.');
  const ag = await agentOf(owner, 'Braked agent', { cap: 2 });
  assert.strictEqual((await agentSays(ag, 'A post.')).status, 201);
  assert.strictEqual((await agentSays(ag, 'A reply, the second action today.', p.json.id)).status, 201);
  const capped = await agentSays(ag, 'A third action.', p.json.id);
  assert.strictEqual(capped.status, 429, 'replies count against the daily limit');
  assert.match(capped.json.error, /daily limit of 2/);
  // The brake: agent posts per hour at 0 for this owner stops replies too; people posts per hour stops people's.
  const ag2 = await agentOf(owner, 'Second braked agent');
  const b = await run(aaron.ctx, (t) => controls.setBrake(t, { member: owner.id, agent_posts_per_hour: 0, people_per_hour: 0, note: 'test' }));
  try {
    const r = await agentSays(ag2, 'Braked reply.', p.json.id);
    assert.strictEqual(r.status, 429);
    assert.match(r.json.error, /paused/);
    const pr = await say(owner, 'The owner replies in person.', p.json.id);
    assert.strictEqual(pr.status, 429);
  } finally {
    await run(aaron.ctx, (t) => controls.lift(t, b.brake.id));
  }
  assert.strictEqual((await agentSays(ag2, 'After the brake.', p.json.id)).status, 201);
});

test('RP7: a contained owner\'s agents draft their replies until the pause ends, and can\'t be raised meanwhile', async () => {
  const owner = await member(2, 'Contained owner');
  const person = await member(2, 'Bystander');
  const p = await say(person, 'Reply here.');
  const ag = await agentOf(owner, 'Contained agent', { post: 'act', reply: 'act' });
  assert.strictEqual((await agentSays(ag, 'Before the pause.', p.json.id)).status, 201);
  await run({ actor: 'system' }, (t) => t`insert into app.containments (member_id, reason, measured, usual_x100, ends_at) values (${owner.id}, 'volume', 600, 0, now() + interval '1 day')`);
  const during = await agentSays(ag, 'During the pause.', p.json.id);
  assert.strictEqual(during.status, 202, 'the reply drafts for the owner instead of going out');
  assert.strictEqual(during.json.action, 'reply');
  const raise = await agentsApi('POST', 'rules', owner, { agent: ag.id, post: 'draft', reply: 'act', report: 'draft', daily_cap: 1000 });
  assert.strictEqual(raise.status, 409, 'raising replies to act is refused while contained');
  // An agent made during the pause starts at draft and stays there, replies included.
  const fresh = await agentOf(owner, 'Made during the pause', { post: 'draft', reply: 'draft' });
  assert.strictEqual((await agentSays(fresh, 'New agent, during the pause.', p.json.id)).status, 202);
});

test('RP8: a reply can be reported and removed like any post; removing a post hides its thread; deleting an account leaves others\' replies theirs', async () => {
  const ann = await member(2, 'Reported Ann');
  const bob = await member(2, 'Reporter Bob');
  const p = await say(ann, 'A post with a bad reply.');
  const bad = await say(ann, 'A bad reply.', p.json.id);
  const good = await say(bob, 'A good reply.', p.json.id);
  const rep = await api('POST', { cookie: bob.cookie, json: { report: bad.json.id, reason: 'spam' } });
  assert.strictEqual(rep.status, 202);
  const queued = await run(aaron.ctx, (t) => review.queue(t, {}));
  assert.ok(queued.items.some((i) => i.id === bad.json.id), 'the reported reply is in the review queue (F7)');
  await run(aaron.ctx, (t) => review.decide(t, { post: bad.json.id, decision: 'remove' }));
  assert.deepStrictEqual((await thread(p.json.id)).json.replies.map((r) => r.id), [good.json.id]);
  // Bob deletes his account: his reply goes with it; Ann's post stays.
  const out = await run({ ...bob.ctx, fresh: true }, (t) => store.deleteAccount(t));
  assert.ok(out.posts >= 1);
  assert.deepStrictEqual((await thread(p.json.id)).json.replies, []);
  // Ann deletes hers while Carl's reply is under her post: the deletion goes through, and Carl's reply stays his.
  const carl = await member(2, 'Carl replies');
  const cr = await say(carl, 'Carl answers Ann.', p.json.id);
  const gone = await run({ ...ann.ctx, fresh: true }, (t) => store.deleteAccount(t));
  assert.ok(gone.posts >= 2, 'Ann\'s post and her reply are deleted with her');
  assert.strictEqual((await thread(p.json.id)).status, 404);
  const mine = await run(carl.ctx, (t) => posts.mine(t, {}));
  assert.ok(mine.some((r) => r.id === cr.json.id && r.parent_id === p.json.id), 'Carl still has his reply');
  // It can't be answered any more, since the post above it is gone.
  assert.strictEqual((await say(carl, 'Under a deleted post.', cr.json.id)).status, 404);
});

test('RP9: replies are rate limited for members, networks and agents (S6), counted only for well-formed replies', async () => {
  const saved = JSON.parse(JSON.stringify(feedApi.REPLY_LIMITS));
  feedApi.REPLY_LIMITS.reply_member.max = 2;
  feedApi.REPLY_LIMITS.reply_agent.max = 2;
  try {
    const ann = await member(2, 'Chatty Ann');
    const bob = await member(2, 'Post owner');
    const p = await say(bob, 'Reply to me lots.');
    assert.strictEqual((await say(ann, 'x'.repeat(5001), p.json.id)).status, 400, 'too long');
    assert.strictEqual((await api('POST', { cookie: ann.cookie, json: { body: 'bad id', reply_to: 'nope' } })).status, 400);
    assert.strictEqual((await say(ann, 'One.', p.json.id)).status, 201, 'malformed replies used up nothing');
    assert.strictEqual((await say(ann, 'Two.', p.json.id)).status, 201);
    const slow = await say(ann, 'Three.', p.json.id);
    assert.strictEqual(slow.status, 429);
    assert.match(slow.json.error, /a lot of replies/);
    assert.strictEqual((await say(ann, 'A new post is not a reply.')).status, 201, 'posting stays unlimited (F4)');
    const owner = await member(2, 'Chatty owner');
    const ag = await agentOf(owner, 'Chatty agent');
    assert.strictEqual((await agentSays(ag, 'One.', p.json.id)).status, 201);
    assert.strictEqual((await agentSays(ag, 'Two.', p.json.id)).status, 201);
    assert.strictEqual((await agentSays(ag, 'Three.', p.json.id)).status, 429);
    assert.strictEqual((await agentSays(ag, 'An agent post is not a reply.')).status, 201);
  } finally {
    Object.assign(feedApi.REPLY_LIMITS.reply_member, saved.reply_member);
    Object.assign(feedApi.REPLY_LIMITS.reply_agent, saved.reply_agent);
  }
  // The network limit is separate from the member's, so one network can't spread a flood across accounts.
  feedApi.REPLY_LIMITS.reply_ip.max = 1;
  try {
    const p = await say(await member(2, 'Net post'), 'Network test.');
    const ip = '198.51.100.77';
    const m1 = await member(2, 'Net one');
    const m2 = await member(2, 'Net two');
    // The network key needs IP_HASH_KEY, which the site reads from its config; without one, only the member limit applies.
    const cfg = require('../signin/config').load();
    const r1 = await api('POST', { cookie: m1.cookie, json: { body: 'From the network.', reply_to: p.json.id }, ip });
    const r2 = await api('POST', { cookie: m2.cookie, json: { body: 'Same network.', reply_to: p.json.id }, ip });
    assert.strictEqual(r1.status, 201);
    assert.strictEqual(r2.status, cfg.ipKey ? 429 : 201);
  } finally {
    Object.assign(feedApi.REPLY_LIMITS.reply_ip, saved.reply_ip);
  }
});

test('the feed page shows replies threaded with textContent only, no inline styles, and a reply box only for signed-in members', () => {
  const js = fs.readFileSync(path.join(root, 'feed.js'), 'utf8');
  const css = fs.readFileSync(path.join(root, 'styles.css'), 'utf8');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\.style\b|setAttribute\(\s*['"]style/.test(js), 'no HTML from strings and no inline styles (CSP)');
  assert.match(js, /\/api\/feed\?thread=/);
  assert.match(js, /reply_to: parentId/);
  assert.match(js, /if \(signedIn\) acts\.appendChild\(replyControl/);
  for (let d = 1; d <= 6; d++) if (d > 1) assert.ok(css.includes('.reply.depth-' + d + ' {'), 'depth ' + d + ' has a class');
  assert.ok(!/depth-7/.test(css + js), 'indentation stops at six levels, so phones never scroll sideways');
});

test('a person\'s reply waits for review like any first post while JEVs runs in shadow mode (F6), and the author sees it in their own posts', async () => {
  const author = await member(2, 'Busy author');
  const p = await say(author, 'A post for a new member.');
  const newbie = await member(1, 'Brand new');
  const r = await say(newbie, 'My first reply.', p.json.id);
  assert.strictEqual(r.status, 201);
  assert.strictEqual(r.json.status, 'waiting');
  assert.deepStrictEqual((await thread(p.json.id)).json.replies, [], 'not shown until reviewed');
  const mine = await api('GET', { cookie: newbie.cookie, query: { mine: '1' } });
  assert.strictEqual(mine.json.posts[0].in_reply_to, p.json.id);
  await run(aaron.ctx, (t) => review.decide(t, { post: r.json.id, decision: 'approve' }));
  assert.deepStrictEqual((await thread(p.json.id)).json.replies.map((x) => x.id), [r.json.id]);
  // JEVs's own account check ran too (it runs as members below level 2 take part).
  assert.ok((await q(`select count(*)::int as n from app.jevs_decisions where member_id = '${newbie.id}' and action = 'account.check'`))[0].n >= 1);
  assert.ok(jevs.ASKS['post.create'].includes('J12'));
});
