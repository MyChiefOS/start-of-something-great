// 059: replies, with the agent-to-agent depth limit (ACCEPTANCE.md RP1 to RP9 and R40; Aaron, Oct 16 and Nov 4),
// against a real Postgres, through the site's own API handlers.
'use strict';

const { promote, shadowMode, asSignin } = require('./helpers');
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const review = require('./helpers').reviewWithReasons(require('../db/review'), () => su);
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };

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
  if (process.env.CI) test('replies tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
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
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [fp], keyVersion: 1,
    level: Math.min(level, 1), displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  if (stale) await q(`update app.sessions set created_at = now() - interval '1 hour' where token_hash = '${c.sha256hex(token)}'`);
  return { id: out.memberId, fp, level, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
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

// A signed-in member writing a post or a reply from the site's own pages.
const write = (m, body, replyTo) => feed({ method: 'POST', url: '/api/feed', query: {},
  headers: { host: 'dayonegreat.com', origin: ORIGIN, cookie: m.cookie, 'content-type': 'application/json', 'x-vercel-forwarded-for': '203.0.113.41' },
  body: JSON.stringify(replyTo ? { body, reply_to: replyTo } : { body }) });
// An agent writing a reply with its key.
const answer = (key, body, replyTo) => feed({ method: 'POST', url: '/api/feed', query: {},
  headers: { host: 'dayonegreat.com', 'content-type': 'application/json', authorization: 'Bearer ' + key }, body: JSON.stringify({ body, reply_to: replyTo }) });
const thread = async (id) => (await publicGet({ thread: id }));
const lane = async (l) => (await publicGet({ lane: l, limit: '50' })).json.posts;
// An agent that posts and replies on its own (its owner signed in just now).
async function actingAgent(owner, name) {
  const a = await newAgent(owner, name);
  const r = await rules(owner, a, { post: 'act', reply: 'act' });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return a;
}

test('RP9: the database passes the coverage check with replies and matches the reviewed snapshot (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('RP1: a person replies to a post and to a reply; the thread shows them in order, the lane shows only the first post with its count', async () => {
  const ann = await member(2, 'Ann');
  const bo = await member(2, 'Bo');
  const first = await write(ann, 'What are you building this week?');
  assert.deepStrictEqual([first.status, first.json.status], [201, 'live'], JSON.stringify(first.json));
  const r1 = await write(bo, 'A reply from Bo', first.json.id);
  assert.deepStrictEqual([r1.status, r1.json.status, r1.json.in_reply_to, r1.json.message], [201, 'live', first.json.id, 'Replied.']);
  const r2 = await write(ann, 'Ann answers Bo', r1.json.id);
  assert.strictEqual(r2.status, 201);
  const r3 = await write(bo, 'A second reply to the first post', first.json.id);
  assert.strictEqual(r3.status, 201);

  const t = await thread(first.json.id);
  assert.strictEqual(t.status, 200);
  assert.strictEqual(t.json.thread.post.id, first.json.id);
  assert.strictEqual(t.json.thread.post.replies, 3);
  // Conversation order: each reply after the one it answers, earlier replies first.
  assert.deepStrictEqual(t.json.thread.replies.map((x) => [x.body, x.depth, x.in_reply_to.id]),
    [['A reply from Bo', 1, first.json.id], ['Ann answers Bo', 2, r1.json.id], ['A second reply to the first post', 1, first.json.id]]);
  assert.ok(t.json.thread.replies.every((x) => x.in_reply_to.thread === '/api/feed?thread=' + first.json.id));
  assert.strictEqual(t.json.thread.more_replies, false);

  const people = await lane('people');
  const row = people.find((x) => x.id === first.json.id);
  assert.strictEqual(row.replies, 3, 'the first post carries its reply count');
  assert.ok(!people.some((x) => [r1.json.id, r2.json.id, r3.json.id].includes(x.id)), 'replies stay out of the lane');
  // A member's own list holds first posts only, too.
  const byBo = (await publicGet({ lane: 'people', author: bo.id })).json.posts;
  assert.ok(!byBo.some((x) => x.id === r1.json.id));
  // A search still finds a reply, and says which thread it is in.
  const found = (await publicGet({ lane: 'people', q: 'answers' })).json.posts;
  assert.deepStrictEqual(found.map((x) => [x.id, x.in_reply_to && x.in_reply_to.thread]), [[r2.json.id, '/api/feed?thread=' + first.json.id]]);
});

test('RP2: a reply needs a live post to answer; a thread is asked for by its first post, alone', async () => {
  const ann = await member(2, 'Ann two');
  const gone = await write(ann, 'A post that will be removed');
  const kept = await write(ann, 'A post that stays');
  const child = await write(ann, 'A reply that stays', kept.json.id);
  await run(aaron.ctx, (t) => review.decide(t, { post: gone.json.id, decision: 'remove' }));
  const toGone = await write(ann, 'Too late', gone.json.id);
  assert.strictEqual(toGone.status, 409);
  assert.match(toGone.json.error, /no live post with that ID to reply to/);
  const toNothing = await write(ann, 'To nobody', crypto.randomUUID());
  assert.strictEqual(toNothing.status, 409);
  const malformed = await write(ann, 'Bad ID', 'not-an-id');
  assert.strictEqual(malformed.status, 400);
  assert.match(malformed.json.error, /reply_to must be the ID of the post you answer/);
  assert.strictEqual((await q(`select count(*)::int as n from app.posts where body in ('Too late', 'To nobody', 'Bad ID')`))[0].n, 0, 'nothing was stored');
  // A thread by a reply's ID, a removed post's or an unknown one: not found. With any other parameter: refused.
  assert.strictEqual((await thread(child.json.id)).status, 404);
  assert.strictEqual((await thread(gone.json.id)).status, 404);
  assert.strictEqual((await thread(crypto.randomUUID())).status, 404);
  assert.strictEqual((await publicGet({ thread: kept.json.id, lane: 'people' })).status, 400);
  assert.strictEqual((await publicGet({ thread: 'x' })).status, 400);
});

test('RP3, RP4: an agent\'s reply follows its owner\'s reply setting: off refuses, draft waits for the exact words, act replies; each has a receipt', async () => {
  const owner = await member(2, 'Reply owner');
  const asker = await member(2, 'Asker');
  const first = await write(asker, 'Can an agent help with this?');
  const a = await newAgent(owner, 'Replier'); // drafts for posts and replies

  // Off: refused, in words that say it is replying that is off; posting still drafts.
  assert.strictEqual((await rules(owner, a, { reply: 'off' })).status, 201);
  const off = await answer(a.key, 'I can help', first.json.id);
  assert.strictEqual(off.status, 403);
  assert.match(off.json.error, /^Replying is off under your rules/);
  assert.strictEqual((await say(a.key, 'A post still drafts')).status, 202);

  // Draft: the reply waits in the owner's inbox, named as a reply to that post; nothing is public until approved.
  assert.strictEqual((await rules(owner, a, { reply: 'draft' })).status, 201);
  const d = await answer(a.key, 'I can help with that', first.json.id);
  assert.deepStrictEqual([d.status, d.json.status, d.json.in_reply_to], [202, 'draft', first.json.id]);
  const item = (await activity(owner)).json.inbox.find((x) => x.id === d.json.draft_id);
  assert.deepStrictEqual([item.kind, item.in_reply_to.id, item.in_reply_to.thread], ['reply', first.json.id, '/api/feed?thread=' + first.json.id]);
  assert.strictEqual((await thread(first.json.id)).json.thread.replies.length, 0);
  const notice = await q(`select title from app.notices where member_id = '${owner.id}' and kind = 'draft_waiting' order by created_at desc limit 1`);
  assert.match(notice[0].title, /wrote a reply for you$/);
  // Other words are refused; the exact words are approved and land under the post they were written for.
  assert.strictEqual((await approve(owner, d.json.draft_id, 'I can help with that!')).status, 409);
  const ok = await approve(owner, d.json.draft_id, 'I can help with that');
  assert.strictEqual(ok.status, 201, JSON.stringify(ok.json));
  const shown = (await thread(first.json.id)).json.thread.replies;
  assert.deepStrictEqual(shown.map((x) => [x.body, x.agent.name, x.author.name, x.delegation.kind, x.in_reply_to.id]),
    [['I can help with that', 'Replier', 'Reply owner', 'approved', first.json.id]]);
  // Its receipt names the post it answered and what the rules said about replies.
  const rc = (await publicGet({ receipt: shown[0].id })).json.receipt;
  assert.deepStrictEqual([rc.post.in_reply_to.id, rc.post.in_reply_to.thread, rc.rules.reply, rc.approval.approved_by_owner],
    [first.json.id, '/api/feed?thread=' + first.json.id, 'draft', true]);

  // Act: the reply goes out under the rules, with a receipt.
  assert.strictEqual((await rules(owner, a, { reply: 'act' })).status, 201);
  const acted = await answer(a.key, 'And here is more', first.json.id);
  assert.deepStrictEqual([acted.status, acted.json.status, acted.json.in_reply_to, acted.json.message], [201, 'live', first.json.id, 'Replied, under your owner’s rules.']);
  assert.strictEqual((await publicGet({ receipt: acted.json.id })).json.receipt.rules.reply, 'act');
  // The posting setting was never touched: a post still drafts.
  assert.strictEqual((await say(a.key, 'Still a draft')).status, 202);
});

test('RP5: replies count against the agent\'s daily limit like posts', async () => {
  const owner = await member(2, 'Cap owner');
  const first = await write(owner, 'Count with me');
  const a = await newAgent(owner, 'Counter');
  assert.strictEqual((await rules(owner, a, { post: 'act', reply: 'act', daily_cap: 2 })).status, 201);
  assert.strictEqual((await say(a.key, 'One post')).status, 201);
  assert.strictEqual((await answer(a.key, 'One reply', first.json.id)).status, 201);
  const over = await answer(a.key, 'One too many', first.json.id);
  assert.strictEqual(over.status, 429);
  assert.match(over.json.error, /daily limit of 2/);
});

test('R40: agents may answer agents 3 times in a row; then a person has to reply before another agent can', async () => {
  const o1 = await member(2, 'Owner one');
  const o2 = await member(2, 'Owner two');
  const a = await actingAgent(o1, 'Alpha');
  const b = await actingAgent(o2, 'Beta');
  const p1 = await say(a.key, 'Alpha opens a thread'); // agent turn 1
  assert.strictEqual(p1.status, 201, JSON.stringify(p1.json));
  const p2 = await answer(b.key, 'Beta answers', p1.json.id); // 2
  assert.strictEqual(p2.status, 201, JSON.stringify(p2.json));
  const p3 = await answer(a.key, 'Alpha follows up', p2.json.id); // 3
  assert.strictEqual(p3.status, 201);
  const p4 = await answer(b.key, 'Beta again', p3.json.id); // a fourth agent turn in a row
  assert.strictEqual(p4.status, 409);
  assert.match(p4.json.error, /Agents have replied to agents 3 times in a row here, which is the limit\. A person needs to reply before another agent can\./);
  assert.strictEqual((await q(`select count(*)::int as n from app.posts where body = 'Beta again'`))[0].n, 0);
  // A draft can't get round it either.
  assert.strictEqual((await rules(o2, b, { post: 'act', reply: 'draft' })).status, 201);
  assert.strictEqual((await answer(b.key, 'Beta drafts instead', p3.json.id)).status, 409);
  assert.strictEqual((await q(`select count(*)::int as n from app.agent_drafts where body = 'Beta drafts instead'`))[0].n, 0);
  assert.strictEqual((await rules(o2, b, { post: 'act', reply: 'act' })).status, 201);
  // A person replies: the count starts again.
  const person = await write(o1, 'A person steps in', p3.json.id);
  assert.strictEqual(person.status, 201);
  const p5 = await answer(b.key, 'Beta, after a person', person.json.id);
  assert.strictEqual(p5.status, 201);
  const rows = await q(`select body, depth, agent_run from app.posts where root_id = '${p1.json.id}' or id = '${p1.json.id}' order by depth`);
  assert.deepStrictEqual(rows.map((r) => [r.body, r.depth, r.agent_run]),
    [['Alpha opens a thread', 0, 1], ['Beta answers', 1, 2], ['Alpha follows up', 2, 3], ['A person steps in', 3, 0], ['Beta, after a person', 4, 1]]);
  // Nobody sends where a reply sits: the site's role can't write those columns.
  await assert.rejects(run(o1.ctx, (t) => t`insert into app.posts (body, parent_id, depth) values ('forged depth', ${p1.json.id}, 9)`), /permission denied/);
  await assert.rejects(run(o1.ctx, (t) => t`insert into app.posts (body, agent_run) values ('forged run', 0)`), /permission denied/);
});

test('RP6: a removed reply, and everything under it, leaves the thread and the count; restoring it brings them back', async () => {
  const ann = await member(2, 'Ann six');
  const first = await write(ann, 'A thread with a branch');
  const r1 = await write(ann, 'Branch root', first.json.id);
  const r2 = await write(ann, 'Under the branch', r1.json.id);
  const r3 = await write(ann, 'Beside the branch', first.json.id);
  assert.strictEqual((await thread(first.json.id)).json.thread.post.replies, 3);
  await run(aaron.ctx, (t) => review.decide(t, { post: r1.json.id, decision: 'remove' }));
  const after = (await thread(first.json.id)).json.thread;
  assert.deepStrictEqual([after.post.replies, after.replies.map((x) => x.id)], [1, [r3.json.id]], 'the removed reply and the reply under it are gone');
  // The reply under it is still its author's, and nobody can answer it while it isn't shown.
  assert.strictEqual((await q(`select status from app.posts where id = '${r2.json.id}'`))[0].status, 'live');
  assert.strictEqual((await write(ann, 'To a hidden reply', r2.json.id)).status, 409);
});

test('RP7: a reply\'s draft is refused at approval if its post is gone, and stays undecided', async () => {
  const owner = await member(2, 'Late owner');
  const asker = await member(2, 'Late asker');
  const first = await write(asker, 'Answer me later');
  const a = await newAgent(owner, 'Late');
  const d = await answer(a.key, 'A late answer', first.json.id);
  assert.strictEqual(d.status, 202);
  await run(aaron.ctx, (t) => review.decide(t, { post: first.json.id, decision: 'remove' }));
  const r = await approve(owner, d.json.draft_id, 'A late answer');
  assert.strictEqual(r.status, 409);
  assert.match(r.json.error, /no longer live/);
  assert.strictEqual((await q(`select status from app.agent_drafts where id = '${d.json.draft_id}'`))[0].status, 'pending');
  assert.strictEqual((await q(`select count(*)::int as n from app.posts where body = 'A late answer'`))[0].n, 0);
});

test('RP8: JEVs scores the real chain (J12): with the limit raised by the database owner, the fifth agent turn in a row scores 40', async () => {
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe('update app.reply_settings set max_agent_turns = 6'); });
  try {
    const o1 = await member(2, 'Chain one');
    const o2 = await member(2, 'Chain two');
    const a = await actingAgent(o1, 'Gamma');
    const b = await actingAgent(o2, 'Delta');
    let last = (await say(a.key, 'Turn 1')).json.id;
    for (let turn = 2; turn <= 5; turn++) {
      const r = await answer(turn % 2 ? a.key : b.key, 'Turn ' + turn, last);
      assert.strictEqual(r.status === 201 || r.status === 202, true, 'turn ' + turn + ': ' + JSON.stringify(r.json));
      last = r.json.id;
    }
    const scores = async (body) => (await q(`select d.scores from app.jevs_decisions d join app.posts p on p.id = d.subject_id where p.body = '${body}' order by d.created_at desc limit 1`))[0].scores;
    assert.strictEqual((await scores('Turn 1')).J12, 0);
    assert.strictEqual((await scores('Turn 4')).J12, 0);
    assert.strictEqual((await scores('Turn 5')).J12, 40, 'five agents in a row');
    // A person's reply never scores it.
    const person = await write(o1, 'A person, deep in the chain', last);
    assert.strictEqual((await scores('A person, deep in the chain')).J12, 0);
    assert.strictEqual(person.status, 201);
  } finally {
    await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe('update app.reply_settings set max_agent_turns = 3'); });
  }
});

test('the reply limits are the database owner\'s alone: the site\'s role can neither read nor change them', async () => {
  const m = await member(2, 'Reader');
  assert.deepStrictEqual((await q('select max_agent_turns, max_depth from app.reply_settings')).map((r) => [r.max_agent_turns, r.max_depth]), [[3, 50]]);
  for (const ctx of [m.ctx, aaron.ctx]) {
    await assert.rejects(run(ctx, (t) => t`select max_agent_turns from app.reply_settings`), /permission denied/);
    await assert.rejects(run(ctx, (t) => t`update app.reply_settings set max_agent_turns = 20`), /permission denied/);
  }
});
