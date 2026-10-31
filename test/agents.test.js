// Release 2, PR 5: agents (F2, F3, S3, S4, S5), against a real Postgres.
'use strict';

const { promote, shadowMode } = require('./helpers');
const test = require('node:test');
const assert = require('node:assert');
// Acting as an administrator straight in the database (the test superuser), the way the site does it.
// fix 3: settings set by hand count as an anonymous visitor, so this asks app.act_as with the admin's real session.
const actAsAdmin = (t, ctx) => t`select app.act_as('admin', ${ctx.memberId}::uuid, null, false, ${ctx.session}, null, null)`;
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const posts = require('../db/posts');
const agents = require('../db/agents');
const agentkey = require('../signin/agentkey');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };

test('the agents page keeps the claim code out of requests until Claim is pressed, and shows names as text only', () => {
  const html = fs.readFileSync(path.join(root, 'agents.html'), 'utf8');
  assert.match(html, /name="robots" content="noindex"/);
  assert.match(html, /<script defer src="\/agents\.js"><\/script>/);
  const js = fs.readFileSync(path.join(root, 'agents.js'), 'utf8');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(js), 'no HTML injection points');
  assert.ok(!/\b(confirm|prompt|alert)\s*\(/.test(js));
  assert.match(js, /location\.hash/, 'the code is read from after "#"');
  assert.match(js, /history\.replaceState\(null, '', '\/agents'\)/, 'and cleared from the address once used');
  const feed = fs.readFileSync(path.join(root, 'feed.js'), 'utf8');
  assert.match(feed, /if \(p\.agent\) \{/, 'agent posts name the agent and its owner (F3)');
});

test('keys: 32 random bytes, prefixed, stored only as SHA-256; only well-formed Bearer keys are looked up', () => {
  const a = agentkey.newKey(), b = agentkey.newKey();
  assert.match(a.key, /^dogk_[A-Za-z0-9_-]{43}$/);
  assert.notStrictEqual(a.key, b.key);
  assert.strictEqual(a.hash, c.sha256hex(a.key));
  const h = (v) => agentkey.fromRequest({ headers: { authorization: v } });
  assert.deepStrictEqual(h('Bearer ' + a.key), { present: true, hash: a.hash });
  for (const bad of ['Bearer', 'Bearer ' + a.key + 'x', 'Basic ' + a.key, 'Bearer dogk_short', a.key, 'Bearer  ' + a.key + ' extra']) {
    assert.strictEqual(h(bad).hash, null, bad);
  }
  assert.deepStrictEqual(agentkey.fromRequest({ headers: {} }), { present: false, hash: null });
});

test('without a database the agents endpoints answer safely', async () => {
  const { handle } = require('../api/agents.js');
  const r = res();
  await handle(req('POST', 'register', { json: { name: 'x' } }), r, null, CFG);
  assert.strictEqual(r.statusCode, 503);
  const off = res();
  await handle(req('POST', 'register', { json: { name: 'x' }, host: 'evil.example' }), off, null, CFG);
  assert.strictEqual(off.statusCode, 403);
  const nf = res();
  await handle(req('GET', 'nope'), nf, null, CFG);
  assert.strictEqual(nf.statusCode, 404);
});

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, route, { cookie = '', origin, json, key, host = 'dayonegreat.com', ip = '203.0.113.9', url } = {}) {
  const headers = { host, cookie, 'x-vercel-forwarded-for': ip };
  if (origin) headers.origin = origin;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url: url || '/api/agents/' + route, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined };
}

if (!SERVER) {
  if (process.env.CI) test('agents tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('agents against a database (F2, F3, S3, S4)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_agents_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
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
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(level = 2, name = 'Owner') {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())],
    keyVersion: 1, level: Math.min(level, 1), displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
let adminMember; // a real member with a session, and (fix 3: the database now checks it) really an administrator
const theAdmin = async () => {
  if (!adminMember) {
    adminMember = await member(2, 'Admin');
    await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${adminMember.id}'`); });
  }
  return adminMember;
};
const asAdmin = async (sqlText) => { const adm = await theAdmin(); return su.begin(async (t) => { await actAsAdmin(t, adm.ctx); await t.unsafe(sqlText); }); };
// Agents start by drafting (PR 7). Tests of other behaviour let an agent act on its own first, as its owner could
// after a fresh sign-in.
const letAct = (sql, agentId) => sql.begin(async (t) => {
  await t`select set_config('app.fresh', '1', true)`;
  await t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${agentId}, 'act', 'draft', 'draft', 1000, 'owner')`;
});
async function api(r, { drafting = false } = {}) {
  const out = res();
  await require('../api/agents.js').handle(r, out, run, CFG);
  const x = { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null, r: out };
  if (!drafting && r.method === 'POST' && x.status === 201 && r.query.route === '' && x.json.agent_id) await letAct(su, x.json.agent_id);
  if (!drafting && r.method === 'POST' && x.status === 200 && r.query.route === 'claim' && x.json.claimed) await letAct(su, x.json.agent.id);
  return x;
}
async function feedPost(key, json) {
  const out = res();
  const r = { method: 'POST', url: '/api/feed', headers: { host: 'dayonegreat.com', 'content-type': 'application/json', authorization: 'Bearer ' + key }, query: {}, body: JSON.stringify(json) };
  await require('../api/feed.js').handle(r, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
const agentFeed = () => run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'agents', limit: 50 }));

test('the database passes the coverage check with the agents tables (S1, S5, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('F2, F3: an agent registers, its owner claims it, and it posts in the agents lane under its owner\'s name, in well under 3 minutes', async () => {
  const t0 = Date.now();
  const owner = await member(2, 'Ada Owner');
  const reg = await api(req('POST', 'register', { json: { name: 'Ada\'s helper', description: 'Summarises threads' } }));
  assert.strictEqual(reg.status, 201);
  assert.match(reg.json.key, /^dogk_/);
  const code = /#claim=([A-Za-z0-9_-]{43})$/.exec(reg.json.claim_url)[1];
  assert.strictEqual(reg.r.getHeader('Cache-Control'), 'no-store');
  // Unclaimed: the key does nothing yet, and says so with the next step (the Oct 29 simulation): every agent there
  // read the old "Send a working agent key" as a broken key, and one registered again.
  const early = await feedPost(reg.json.key, { body: 'too early' });
  assert.strictEqual(early.status, 401);
  assert.match(early.json.error, /isn\u2019t claimed yet\. If you registered just now, give claim_url to the person you act for/);
  const earlyMe = await api(req('GET', 'me', { key: reg.json.key }));
  assert.strictEqual(earlyMe.status, 401);
  assert.strictEqual(earlyMe.json.error, early.json.error, 'GET /api/agents/me gives the same answer as posting');
  assert.strictEqual(earlyMe.r.getHeader('WWW-Authenticate'), 'Bearer');
  const claimed = await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code, post: 'draft' } }), { drafting: true });
  assert.strictEqual(claimed.status, 200);
  assert.strictEqual(claimed.json.agent.name, 'Ada\'s helper');
  // A new agent drafts (PR 7): its first post waits for its owner, who approves the exact words with one tap.
  const d = await feedPost(reg.json.key, { body: 'Hello from an agent' });
  assert.deepStrictEqual([d.status, d.json.status], [202, 'draft']);
  const inbox = await api(req('GET', 'activity', { cookie: owner.cookie }));
  const item = inbox.json.inbox.find((x) => x.id === d.json.draft_id);
  assert.strictEqual(item.body, 'Hello from an agent');
  const approved = await api(req('POST', 'approve', { cookie: owner.cookie, origin: ORIGIN, json: { draft: item.id, hash: c.sha256hex(item.body) } }));
  assert.strictEqual(approved.status, 201);
  const p = { json: { id: approved.json.post.id } };
  const [shown] = (await agentFeed()).filter((x) => x.id === p.json.id);
  assert.deepStrictEqual([shown.agent.name, shown.author.id, shown.author.name], ['Ada\'s helper', owner.id, 'Ada Owner']);
  assert.strictEqual((await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 50 }))).some((x) => x.id === p.json.id), false, 'not in the people lane (F5)');
  assert.ok(Date.now() - t0 < 180000);
  // The API names the agent as untrusted text alongside its owner.
  const out = res();
  await require('../api/feed.js').handle({ method: 'GET', url: '/api/feed?lane=agents', headers: { host: 'dayonegreat.com' }, query: { lane: 'agents' } }, out, run);
  const body = JSON.parse(out.body);
  assert.ok(body.untrusted_fields.includes('posts[].agent.name'));
  assert.strictEqual(body.posts.find((x) => x.id === p.json.id).agent.name, 'Ada\'s helper');
});

test('an owner creates an agent while signed in and gets its key once; nobody can read a key back', async () => {
  const owner = await member(2);
  const made = await api(req('POST', '', { cookie: owner.cookie, origin: ORIGIN, json: { name: 'Builder bot' } }));
  assert.strictEqual(made.status, 201);
  assert.strictEqual((await feedPost(made.json.key, { body: 'first' })).status, 201);
  const listed = await api(req('GET', '', { cookie: owner.cookie }));
  const a = listed.json.agents.find((x) => x.id === made.json.agent_id);
  assert.deepStrictEqual([a.status, a.keys.length], ['active', 1]);
  assert.ok(!JSON.stringify(listed.json).includes(made.json.key) && !JSON.stringify(listed.json).includes(c.sha256hex(made.json.key)));
  // The hash can't be read by the owner, by Aaron, or by the agent itself.
  await assert.rejects(run(owner.ctx, (t) => t`select key_hash from app.agent_keys`), /permission denied/);
  await assert.rejects(run({ ...(await theAdmin()).ctx, actor: 'admin' }, (t) => t`select key_hash from app.agent_keys`), /permission denied/); // fix 3: a real admin
  await assert.rejects(run(owner.ctx, (t) => t`select claim_hash from app.agents`), /permission denied/);
});

test('owning an agent needs level 2: level 0 and 1 members can neither create nor claim one, and a refused claim leaves the code usable', async () => {
  const low = await member(1);
  assert.strictEqual((await api(req('POST', '', { cookie: low.cookie, origin: ORIGIN, json: { name: 'nope' } }))).status, 403);
  const reg = await api(req('POST', 'register', { json: { name: 'Orphan' }, ip: '203.0.113.20' }));
  const code = reg.json.claim_url.split('#claim=')[1];
  assert.strictEqual((await api(req('POST', 'claim', { cookie: low.cookie, origin: ORIGIN, json: { code } }))).status, 403);
  const high = await member(2);
  assert.strictEqual((await api(req('POST', 'claim', { cookie: high.cookie, origin: ORIGIN, json: { code } }))).status, 200);
});

test('claim codes: single use, 24 hours, from our own pages while signed in; unknown, used and expired look the same', async () => {
  const owner = await member(2);
  const other = await member(2);
  const reg = await api(req('POST', 'register', { json: { name: 'Claimable' }, ip: '203.0.113.21' }));
  const code = reg.json.claim_url.split('#claim=')[1];
  assert.strictEqual((await api(req('POST', 'claim', { origin: ORIGIN, json: { code } }))).status, 401);
  assert.strictEqual((await api(req('POST', 'claim', { cookie: owner.cookie, origin: 'https://evil.com', json: { code } }))).status, 403);
  assert.strictEqual((await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code: c.token(32) } }))).status, 404);
  assert.strictEqual((await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code } }))).status, 200);
  assert.strictEqual((await api(req('POST', 'claim', { cookie: other.cookie, origin: ORIGIN, json: { code } }))).status, 404, 'used');
  const late = await api(req('POST', 'register', { json: { name: 'Late' }, ip: '203.0.113.22' }));
  // Backdating needs the guard switched off by the table's owner, inside one transaction: nothing else can.
  await su.begin(async (t) => {
    await t.unsafe('alter table app.agents disable trigger agents_guard');
    await t.unsafe(`update app.agents set claim_expires_at = now() - interval '1 minute' where id = '${late.json.agent_id}'`);
    await t.unsafe('alter table app.agents enable always trigger agents_guard');
  });
  assert.strictEqual((await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code: late.json.claim_url.split('#claim=')[1] } }))).status, 404, 'expired');
});

test('S4: a key acts only as its own agent, and stops at once when rotated, revoked, or its owner is banned or loses level 2', async () => {
  const owner = await member(2, 'Grace');
  const a = await api(req('POST', '', { cookie: owner.cookie, origin: ORIGIN, json: { name: 'Agent A' } }));
  const b = await api(req('POST', '', { cookie: owner.cookie, origin: ORIGIN, json: { name: 'Agent B' } }));
  // The request can't choose a lane, an agent or an author.
  assert.strictEqual((await feedPost(a.json.key, { body: 'x', lane: 'people' })).status, 400);
  assert.strictEqual((await feedPost(a.json.key, { body: 'x', agent_id: b.json.agent_id })).status, 400);
  const pa = await feedPost(a.json.key, { body: 'from A' });
  const [row] = await q(`select lane, agent_id, author_id from app.posts where id = '${pa.json.id}'`);
  assert.deepStrictEqual({ ...row }, { lane: 'agents', agent_id: a.json.agent_id, author_id: owner.id });
  // Even straight to the table, an agent posts only as itself, for its owner.
  const ctxA = { actor: 'agent', memberId: owner.id, agentId: a.json.agent_id, keyHash: c.sha256hex(a.json.key) };
  const [direct] = await run(ctxA, (t) => t`insert into app.posts (body) values ('direct') returning agent_id, lane`);
  assert.deepStrictEqual({ ...direct }, { agent_id: a.json.agent_id, lane: 'agents' });
  const stranger = await member(2);
  // fix 3: claiming another owner for a real key is now refused before anything runs: the database reads the owner from the key.
  await assert.rejects(run({ ...ctxA, memberId: stranger.id }, (t) => posts.create(t, { body: 'not my owner' })), /not_acting/);
  await assert.rejects(run(ctxA, (t) => t`insert into app.posts (body, lane) values ('x', 'people')`), /permission denied/);
  // The second lock: even a role with every column right (the superuser here) gets the lane and agent from who is acting.
  const [forced] = await su.begin(async (t) => {
    // fix 3: acting as agent A with its real key, the way the site does (settings set by hand would count as anonymous).
    await t`select app.act_as('agent', ${owner.id}::uuid, ${a.json.agent_id}::uuid, false, null, ${ctxA.keyHash}, null)`;
    return t`insert into app.posts (body, lane, agent_id) values ('forged', 'people', ${b.json.agent_id}) returning lane, agent_id`;
  });
  assert.deepStrictEqual({ ...forced }, { lane: 'agents', agent_id: a.json.agent_id });

  // Rotating: the old key stops on its very next request.
  const rotated = await api(req('POST', 'key', { cookie: owner.cookie, origin: ORIGIN, json: { agent: a.json.agent_id } }));
  assert.strictEqual((await feedPost(a.json.key, { body: 'old key' })).status, 401);
  assert.strictEqual((await feedPost(rotated.json.key, { body: 'new key' })).status, 201);
  // Revoking the agent: every key stops, and revoking is final.
  assert.strictEqual((await api(req('POST', 'revoke', { cookie: owner.cookie, origin: ORIGIN, json: { agent: a.json.agent_id } }))).status, 200);
  assert.strictEqual((await feedPost(rotated.json.key, { body: 'after revoke' })).status, 401);
  await assert.rejects(run(owner.ctx, (t) => t`update app.agents set status = 'active' where id = ${a.json.agent_id}`), /only go from active to revoked/);
  // Banning the owner, or the owner's level lapsing, stops their agents at once (F10 groundwork).
  assert.strictEqual((await feedPost(b.json.key, { body: 'B works' })).status, 201);
  await asAdmin(`update app.members set trust_level = 1 where id = '${owner.id}'`);
  assert.strictEqual((await feedPost(b.json.key, { body: 'owner at level 1' })).status, 401);
  // No level is raised by hand (Oct 16, 2026), Aaron included; only a verified sign-in or JEVs brings it back.
  await assert.rejects(asAdmin(`update app.members set trust_level = 2 where id = '${owner.id}'`), /never by hand/);
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set level_set_by_admin = null where id = '${owner.id}'`); });
  await su.begin(async (t) => { await t.unsafe('set local role dog_jevs'); await t.unsafe(`update app.members set jevs_level2_at = now(), trust_level = 2 where id = '${owner.id}'`); });
  assert.strictEqual((await feedPost(b.json.key, { body: 'level back' })).status, 201);
  await asAdmin(`update app.members set status = 'banned' where id = '${owner.id}'`);
  assert.strictEqual((await feedPost(b.json.key, { body: 'owner banned' })).status, 401);
});

test('S3: member A can never read or change member B\'s agents or keys', async () => {
  const a = await member(2);
  const b = await member(2);
  const agentA = await api(req('POST', '', { cookie: a.cookie, origin: ORIGIN, json: { name: 'A\'s agent' } }));
  const id = agentA.json.agent_id;
  assert.strictEqual((await api(req('GET', '', { cookie: b.cookie }))).json.agents.length, 0);
  assert.strictEqual((await run(b.ctx, (t) => t`select id from app.agents where id = ${id}`)).length, 0);
  assert.strictEqual((await run(b.ctx, (t) => t`select id from app.agent_keys`)).length, 0);
  assert.strictEqual((await api(req('POST', 'revoke', { cookie: b.cookie, origin: ORIGIN, json: { agent: id } }))).status, 404);
  assert.strictEqual((await api(req('POST', 'key', { cookie: b.cookie, origin: ORIGIN, json: { agent: id } }))).status, 404);
  assert.strictEqual((await run(b.ctx, (t) => t`update app.agents set name = 'hijacked' where id = ${id}`)).count, 0);
  await assert.rejects(run(b.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${id}, ${c.sha256hex('mine now')})`), /row-level security/);
  await assert.rejects(run(a.ctx, (t) => t`update app.agents set owner_id = ${b.id} where id = ${id}`), /permission denied/);
  // Someone not signed in sees no agents and no keys; an agent sees only itself.
  assert.strictEqual((await run({ actor: 'anon' }, (t) => t`select id from app.agents`)).length, 0);
  const other = await api(req('POST', '', { cookie: a.cookie, origin: ORIGIN, json: { name: 'A\'s second' } }));
  const ctxAgentA = { actor: 'agent', memberId: a.id, agentId: id, keyHash: c.sha256hex(agentA.json.key) };
  assert.deepStrictEqual((await run(ctxAgentA, (t) => t`select id from app.agents`)).map((r) => r.id), [id]);
  assert.ok(other.json.agent_id);
  // Agents can't create agents or issue keys.
  await assert.rejects(run(ctxAgentA, (t) => t`insert into app.agents (name) values ('child')`), /only a signed-in owner/);
});

test('the record: registering, claiming, keys and revoking are all in the audit log, written by the database', async () => {
  const owner = await member(2);
  const reg = await api(req('POST', 'register', { json: { name: 'Audited' }, ip: '203.0.113.23' }));
  const id = reg.json.agent_id;
  await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code: reg.json.claim_url.split('#claim=')[1] } }));
  await api(req('POST', 'key', { cookie: owner.cookie, origin: ORIGIN, json: { agent: id } }));
  await api(req('POST', 'revoke', { cookie: owner.cookie, origin: ORIGIN, json: { agent: id } }));
  const rows = (await q(`select action, actor_kind, actor_id from app.audit_log where subject_id = '${id}'`)).map((r) => [r.action, r.actor_kind, r.actor_id]);
  const has = (a, k, who) => rows.some((r) => r[0] === a && r[1] === k && r[2] === who);
  assert.ok(has('agent.register', 'anon', null), JSON.stringify(rows));
  assert.ok(has('agent.claim', 'member', owner.id));
  assert.strictEqual(rows.filter((r) => r[0] === 'agent.key_issue').length, 2);
  assert.ok(has('agent.key_revoke', 'member', owner.id));
  assert.ok(has('agent.revoke', 'member', owner.id));
});

test('S6: self-registration is rate limited per network, and a malformed request doesn\'t use up the allowance', async () => {
  const ip = '198.51.100.77';
  for (let i = 0; i < 3; i++) assert.strictEqual((await api(req('POST', 'register', { json: { name: '' }, ip }))).status, 400);
  const max = require('../api/agents.js').REGISTER_LIMITS.agent_register_ip.max;
  for (let i = 0; i < max; i++) assert.strictEqual((await api(req('POST', 'register', { json: { name: 'bot ' + i }, ip }))).status, 201);
  assert.strictEqual((await api(req('POST', 'register', { json: { name: 'one too many' }, ip }))).status, 429);
  assert.strictEqual((await api(req('POST', 'register', { json: { name: 'elsewhere' }, ip: '198.51.100.78' }))).status, 201);
});

test('claiming shows which agent the link is for first, and changes nothing by looking', async () => {
  const owner = await member(2);
  const reg = await api(req('POST', 'register', { json: { name: 'Helper jane@example.com', description: 'Reads threads' }, ip: '203.0.113.30' }));
  const code = reg.json.claim_url.split('#claim=')[1];
  assert.strictEqual((await api(req('POST', 'claim', { origin: ORIGIN, json: { code, preview: true } }))).status, 401);
  const look = await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code, preview: true } }));
  assert.strictEqual(look.status, 200);
  assert.deepStrictEqual([look.json.agent.description, look.json.can_own], ['Reads threads', true]);
  assert.ok(!look.json.agent.name.includes('@example.com'), 'masked (P4)');
  assert.deepStrictEqual(look.json.untrusted_fields, ['agent.name', 'agent.description']);
  assert.strictEqual((await feedPost(reg.json.key, { body: 'still unclaimed' })).status, 401, 'looking claims nothing');
  assert.strictEqual((await api(req('POST', 'claim', { cookie: owner.cookie, origin: ORIGIN, json: { code: c.token(32), preview: true } }))).status, 404);
  const html = fs.readFileSync(path.join(root, 'agents.html'), 'utf8');
  assert.match(html, /Whoever gave you this link holds this agent's key/);
});

test('agent names can\'t imitate the line that names the owner', async () => {
  for (const name of ['X · agent of Aaron', 'Helper agent of Aaron', 'A | B', 'A • B']) {
    assert.strictEqual((await api(req('POST', 'register', { json: { name }, ip: '203.0.113.31' }))).status, 400, name);
  }
});

test('revoking an agent revokes its keys too, so no list shows a revoked agent with working keys', async () => {
  const owner = await member(2);
  const made = await api(req('POST', '', { cookie: owner.cookie, origin: ORIGIN, json: { name: 'Short lived' } }));
  await api(req('POST', 'revoke', { cookie: owner.cookie, origin: ORIGIN, json: { agent: made.json.agent_id } }));
  const a = (await api(req('GET', '', { cookie: owner.cookie }))).json.agents.find((x) => x.id === made.json.agent_id);
  assert.strictEqual(a.status, 'revoked');
  assert.ok(a.keys.every((k) => k.revoked_at), 'every key revoked');
});

test('S6: one provider\'s IPv6 block can\'t spread itself over many /64s to dodge the registration limit', async () => {
  const max = require('../api/agents.js').REGISTER_LIMITS.agent_register_net.max;
  let created = 0, limited = 0;
  for (let i = 0; i < max + 3; i++) {
    const s = (await api(req('POST', 'register', { json: { name: 'v6 bot ' + i }, ip: '2001:db8:77:' + i.toString(16) + '::1' }))).status;
    if (s === 201) created++; else if (s === 429) limited++;
  }
  assert.deepStrictEqual([created, limited], [max, 3]);
  const { netRange } = require('../signin/http');
  assert.strictEqual(netRange({ headers: { 'x-vercel-forwarded-for': '2001:db8:77:5::1' } }), '2001:db8:77::/48');
  assert.strictEqual(netRange({ headers: { 'x-vercel-forwarded-for': '198.51.100.7' } }), '198.51.100.0/24');
});

test('MCP stays read-only (Aaron, Oct 16): no posting tool; list_posts names agents as untrusted and masks them', async () => {
  const owner = await member(2, 'Mallory jane@example.com');
  const made = await api(req('POST', '', { cookie: owner.cookie, origin: ORIGIN, json: { name: 'Mcp bot mail@example.com' } }));
  const p = await feedPost(made.json.key, { body: 'via the API' });
  const mcp = require('../api/mcp.js');
  mcp.setReadPosts((a) => run({ actor: 'anon' }, (t) => posts.feed(t, a)));
  const { call } = require('./helpers');
  const list = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.ok(list.json.result.tools.every((t) => t.annotations.readOnlyHint === true), 'every tool is read-only');
  assert.ok(!list.json.result.tools.some((t) => t.name === 'create_post'));
  const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_posts', arguments: { lane: 'agents', limit: 50 } } });
  const data = r.json.result.structuredContent;
  assert.ok(data.untrusted_fields.includes('posts[].agent.name'));
  assert.ok(data.posts.some((x) => x.id === p.json.id));
  assert.ok(!JSON.stringify(data).includes('@example.com'), 'agent and owner names masked (P4)');
});

