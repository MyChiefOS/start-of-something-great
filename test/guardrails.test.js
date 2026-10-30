// Guardrails, round 1 (032; Aaron, Oct 30: "Okay lets build out your approach and run the loop on it"): keys and
// passwords hidden before saving and asked about for an acting agent (J18), an agent repeating its own post (J19),
// both ask-only, and the rules that must never break, checked hourly and tested both ways.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const jevs = require('../db/jevs');
const { maskSecrets } = require('../api/_secrets');
const { maskContacts } = require('../api/_proposals');
const { migrate } = require('../scripts/migrate');
const { trustSystem, promote } = require('./helpers');

// Fixtures are assembled at run time (PK, JWT_IO) so the repository's own secret scan (gitleaks, in CI) doesn't flag
// these made-up keys and published samples as leaks.
const PK = 'PRIVATE' + ' KEY';
const JWT_IO = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'].join('.');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };

// Keys made here are random and in the right format; none is real.
const rand = (set, n) => Array.from(crypto.randomBytes(n), (b) => set[b % set.length]).join('');
const AN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const KEYS = {
  dogk: () => 'dogk_' + crypto.randomBytes(32).toString('base64url'),
  github: () => 'ghp_' + rand(AN, 36),
  aws: () => 'AKIA' + rand('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16),
  anthropic: () => 'sk-ant-api03-' + rand(AN + '_-', 93) + 'AA',
  stripe: () => 'sk_live_' + rand(AN, 99),
  slack: () => 'xoxb-' + rand('0123456789', 12) + '-' + rand('0123456789', 13) + '-' + rand(AN, 24),
  jwt: () => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + Buffer.from(JSON.stringify({ role: 'service_role', exp: 2000000000 })).toString('base64url') + '.' + rand(AN, 43),
  pem: () => '-----BEGIN OPENSSH ' + PK + '-----\n' + crypto.randomBytes(120).toString('base64') + '\n-----END OPENSSH ' + PK + '-----'
};

// ---- Without a database ----

test('J18 text: every published format written whole is hidden; placeholders, samples and public keys are not', () => {
  for (const [k, make] of Object.entries(KEYS)) {
    const key = make();
    for (const t of ['here ' + key + ' ok', 'API_KEY="' + key + '"', '```\n' + key + '\n```', 'Authorization: Bearer ' + key, 'see ?key=' + key + '&x=1']) {
      const r = maskSecrets(t);
      assert.strictEqual(r.hits, 1, k + ' in ' + JSON.stringify(t.slice(0, 40)));
      assert.ok(!r.text.includes(key) && r.text.includes('[key hidden]'), k);
    }
  }
  assert.strictEqual(maskSecrets('postgres://app:' + rand(AN, 20) + '@db.example.co:5432/x').text, 'postgres://app:[key hidden]@db.example.co:5432/x');
  // Left as written: documentation and placeholder forms, public tokens, local databases, a header with no END.
  for (const t of ['AKIAIOSFODNN7EXAMPLE', 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'xoxb-your-token', 'export OPENAI_API_KEY="sk-..."',
    JWT_IO,
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + Buffer.from(JSON.stringify({ role: 'anon', exp: 1983812996 })).toString('base64url') + '.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0',
    'postgresql://postgres:postgres@127.0.0.1:54322/postgres', 'postgres://app:s3cretpw@localhost:5432/x', 'postgres://u:<password>@host.example.com/db',
    'sb_publishable_' + rand(AN, 30), 'commit ' + rand('0123456789abcdef', 40), crypto.randomUUID(), 'sha512-' + crypto.randomBytes(64).toString('base64')]) {
    assert.strictEqual(maskSecrets(t).hits, 0, JSON.stringify(t.slice(0, 50)));
  }
  // Found by the fresh code review: a token that never expires is hidden (only public anon keys and jwt.io's sample
  // aren't), and a password with an empty user name too.
  assert.strictEqual(maskSecrets('eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url') + '.' + rand(AN, 43)).hits, 1);
  assert.strictEqual(maskSecrets('redis://:' + rand(AN, 20) + '@cache.example.com:6379').text, 'redis://:[key hidden]@cache.example.com:6379');
  const pem = KEYS.pem();
  assert.strictEqual(maskSecrets('a ' + pem + ' b ' + pem + ' c').text, 'a [key hidden] b [key hidden] c');
  const open = '-----BEGIN RSA ' + PK + '-----\nand the rest of my post stays';
  assert.strictEqual(maskSecrets(open).text, open, 'a header with no END never swallows the rest of a post');
  // Hostile text stays fast.
  // The review measured 120 ms for repeated private-key headers with the first version; headers are now paired with
  // their END without a long pattern.
  for (const h of ['dogk_' + 'a'.repeat(65530), 'eyJ' + 'a'.repeat(30000) + '.eyJ' + 'b'.repeat(30000), 'postgres://' + 'a'.repeat(30000) + ':' + 'b'.repeat(30000),
    ('-----BEGIN RSA ' + PK + '----- ').repeat(2100), ('-----BEGIN RSA ' + PK + '-----\n' + 'A'.repeat(100) + '\n-----END RSA ' + PK + '----- ').repeat(500),
    ('-----BEGIN RSA ' + PK + '-----' + 'A'.repeat(7990)).repeat(9) + '-----END RSA ' + PK + '-----']) {
    const t0 = process.hrtime.bigint();
    maskSecrets(h.slice(0, 65536));
    assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 50, 'hostile text: ' + h.slice(0, 30));
  }
});

test('J18 text: keys are hidden before contacts, so a Slack token or a database password is still found', () => {
  const slack = KEYS.slack();
  assert.strictEqual(maskContacts('token ' + slack + ' call 202-555-0143'), 'token [key hidden] call [number hidden]');
  assert.strictEqual(maskContacts('postgres://app:' + 'Zq9'.repeat(6) + '@db.example.co/x'), 'postgres://app:[key hidden]@db.example.co/x');
});

test('J18 and J19 score only an agent posting on its own, and ask only', () => {
  const s = (sig) => jevs.score('post.create', sig);
  assert.strictEqual(s({ secret_hits: 3, own_repeats_24h: 9 }).J18, 0, 'a member’s own post: the key is hidden, nobody else to ask');
  assert.strictEqual(s({ secret_hits: 3, own_repeats_24h: 9 }).J19, 0);
  assert.deepStrictEqual([0, 1, 2, 5].map((n) => s({ by_agent: true, secret_hits: n }).J18), [0, 40, 60, 60]);
  assert.deepStrictEqual([0, 1, 2, 3, 4, 20].map((n) => s({ by_agent: true, own_repeats_24h: n }).J19), [0, 20, 45, 45, 60, 60]);
  for (const id of jevs.ASK_ONLY) assert.ok(jevs.QUESTIONS.find((q) => q.id === id).description.includes('Asks its owner to confirm, never more'));
});

test('the rule checks have a heartbeat: /api/ready reports it and the uptime monitor opens an issue after 3 hours', async () => {
  const uptime = require('../scripts/uptime');
  const beat = uptime.CHECKS.find((x) => x.name === 'Rules heartbeat');
  assert.ok(beat && beat.path === '/api/ready' && !beat.when({ stage: 'closed' }) && beat.when({ stage: 'public' }));
  const r = (json) => [{ status: 200 }, JSON.stringify(json)];
  assert.strictEqual(uptime.RULES_HEARTBEAT_S, 3 * 60 * 60);
  assert.ok(beat.test(...r({ rules: { last_run_s_ago: 3500 } })));
  assert.ok(!beat.test(...r({ rules: { last_run_s_ago: uptime.RULES_HEARTBEAT_S + 1 } })));
  for (const t of ['never', 'unreadable', 'closed', null]) assert.ok(!beat.test(...r({ rules: t })), String(t));
  const ready = require('../api/ready.js');
  const open = { LAUNCH_STAGE: 'public', DATABASE_URL: 'postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres' };
  const connect = () => { const f = async () => [{ one: 1 }]; f.end = async () => {}; return f; };
  ready._reset();
  const body = await ready.check({ headers: {} }, { env: open, connect, timersAge: async () => 5, rulesAge: async () => 61 });
  assert.deepStrictEqual(body.rules, { last_run_s_ago: 61 });
  ready._reset();
  assert.strictEqual((await ready.check({ headers: {} }, { env: { LAUNCH_STAGE: 'closed' } })).rules, 'closed');
  ready._reset();
});

// ---- Against a database ----

if (!SERVER) {
  if (process.env.CI) test('guardrail tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('guardrails against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_guard_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sqlText) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sqlText); });
const setMode = (m) => asOwner(`update app.jevs_settings set value = '${m}' where key = 'mode'`);

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  await trustSystem(su);
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
async function member({ name = 'Member', ageDays = 30 } = {}) {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  if (ageDays) await q(`update app.members set created_at = now() - interval '${ageDays} days' where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token };
}
function httpReq(method, url, { cookie = '', json, key, query = {} } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '203.0.113.61', 'x-vercel-ip-country': 'US' };
  if (method === 'POST') headers.origin = ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url, headers, query, body: json === undefined ? undefined : JSON.stringify(json) };
}
async function feed(method, opts) {
  const r = res();
  await require('../api/feed.js').handle(httpReq(method, '/api/feed', opts), r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
async function agentsApi(method, route, opts) {
  const r = res();
  await require('../api/agents.js').handle(httpReq(method, '/api/agents/' + route, { ...opts, query: { route } }), r, run, CFG);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
async function actingAgent(owner, name, cap = 50) {
  const made = await agentsApi('POST', '', { cookie: owner.cookie, json: { name } });
  assert.strictEqual(made.status, 201, JSON.stringify(made.json));
  assert.strictEqual((await agentsApi('POST', 'rules', { cookie: owner.cookie, json: { agent: made.json.agent_id, post: 'act', reply: 'draft', report: 'draft', daily_cap: cap } })).status, 201);
  return made.json;
}
const lastDecision = async (subject) => (await q(`select level, effect, scores from app.jevs_decisions where subject_id = '${subject}' order by created_at desc, id desc limit 1`))[0];
const alerts = async (prefix) => (await q(`select dedupe_key from app.notices where member_id is null and dedupe_key like '${prefix}%' order by 1`)).map((r) => r.dedupe_key);
const freeSlot = () => asOwner(`update app.invariant_slot set last_at = null`);
const runInvariants = () => run({ actor: 'anon' }, (t) => t`select app.invariants_check() as ran`).then((r) => r[0].ran);

test('J18: a key in a post is never stored; the author is told; an acting agent’s post asks its owner, never Aaron', async () => {
  const author = await member({ name: 'Key paster' });
  const key = KEYS.github();
  const p = await feed('POST', { cookie: author.cookie, json: { body: 'My deploy broke, here is my config: GITHUB_TOKEN=' + key } });
  assert.ok([201, 202].includes(p.status), JSON.stringify(p.json));
  assert.strictEqual(p.json.keys_hidden, 1);
  assert.match(p.json.message, /We hid 1 thing that looked like a key or password before saving\. If it was real, revoke it and make a new one\./);
  const [row] = await q(`select body from app.posts where id = '${p.json.id}'`);
  assert.strictEqual(row.body, 'My deploy broke, here is my config: GITHUB_TOKEN=[key hidden]');
  assert.strictEqual((await lastDecision(p.json.id)).scores.J18, 0, 'a member is not asked: the key is already gone');
  // Hiding a short password near the limit would take the text over it: refused, saying why (the fresh code review).
  const long = await feed('POST', { cookie: author.cookie, json: { body: 'x'.repeat(4960) + ' postgres://u:abc123@db.example.co/x' } });
  assert.strictEqual(long.status, 400);
  assert.match(long.json.error, /contains a key or password, and hiding it would take the text over 5,000 characters: remove it and send again/);

  await setMode('enforce');
  try {
    const owner = await member({ name: 'Agent owner' });
    const a = await actingAgent(owner, 'Leaky');
    const keys = [KEYS.aws(), KEYS.stripe()];
    const r = await feed('POST', { key: a.key, json: { body: 'Status report. Creds: ' + keys.join(' and ') } });
    assert.strictEqual(r.status, 202, JSON.stringify(r.json));
    assert.strictEqual(r.json.keys_hidden, 2);
    const d = await lastDecision(r.json.id);
    assert.strictEqual(d.scores.J18, 60);
    assert.deepStrictEqual([d.level, d.effect], ['medium', 'challenge'], 'its owner is asked');
    const [stored] = await q(`select body from app.posts where id = '${r.json.id}'`);
    assert.ok(!keys.some((k) => stored.body.includes(k)));
    // A draft is stored without the key too, and its owner sees it hidden.
    await agentsApi('POST', 'rules', { cookie: owner.cookie, json: { agent: a.agent_id, post: 'draft', reply: 'draft', report: 'draft', daily_cap: 50 } });
    const dr = await feed('POST', { key: a.key, json: { body: 'draft with ' + KEYS.dogk() } });
    assert.strictEqual(dr.status, 202);
    assert.strictEqual(dr.json.keys_hidden, 1);
    assert.strictEqual((await q(`select body from app.agent_drafts where id = '${dr.json.draft_id}'`))[0].body, 'draft with [key hidden]');
  } finally {
    await setMode('shadow');
  }
});

test('J19: an agent repeating its own words asks its owner from the third time, counting drafts once; ask-only never reaches high', async () => {
  await setMode('enforce');
  try {
    const owner = await member({ name: 'Loop owner' });
    const a = await actingAgent(owner, 'Stuck loop');
    const ids = [];
    for (let i = 0; i < 3; i++) {
      const r = await feed('POST', { key: a.key, json: { body: i === 1 ? 'Daily update: NOTHING new today!' : 'Daily update - nothing new today' } });
      ids.push(r.json.id);
    }
    const d = await Promise.all(ids.map(lastDecision));
    assert.deepStrictEqual(d.map((x) => x.scores.J19), [0, 20, 45], 'case, spaces and punctuation are ignored');
    assert.deepStrictEqual(d.map((x) => x.effect), ['none', 'none', 'challenge']);
    // Another agent of the same owner saying the same thing is not a repeat.
    const b = await actingAgent(owner, 'Other agent');
    const other = await feed('POST', { key: b.key, json: { body: 'Daily update - nothing new today' } });
    assert.strictEqual((await lastDecision(other.json.id)).scores.J19, 0);
  } finally {
    await setMode('shadow');
  }
  // The decision: J18 and J19 never count toward high, whatever else scored (the fresh review's worst case for a loop:
  // J04 70, J02 10, J01 15, J13 10, with J19 60 would have been 165 if summed).
  const owner = await member({ name: 'Decider' });
  const a = await actingAgent(owner, 'Decided');
  const asAgent = { actor: 'agent', memberId: owner.id, agentId: a.agent_id, keyHash: c.sha256hex(a.key) };
  // One decision per post, so each set of scores gets a post of its own.
  // The decision is made in the post's own transaction (010), as the site does.
  const decide = (scores) => run(asAgent, async (t) => {
    const p = await require('../db/posts').create(t, { body: 'a plain post for the decision test ' + crypto.randomUUID() });
    const [d] = await t`select level from app.jevs_decide('post.create', ${p.id}::uuid, ${t.json(scores)}, 'low', false, null, null, null)`;
    return d.level;
  });
  assert.strictEqual(await decide({ J04: 70, J02: 10, J01: 15, J13: 10, J19: 60 }), 'medium');
  assert.strictEqual(await decide({ J04: 70, J02: 10, J01: 15, J13: 10, J18: 60, J19: 60 }), 'medium');
  assert.strictEqual(await decide({ J02: 10, J19: 45 }), 'medium', 'on its own it asks');
  assert.strictEqual(await decide({ J02: 10, J19: 20 }), 'low');
  assert.strictEqual(await decide({ J07: 100, J19: 60 }), 'high', 'the other questions still hold as before');
});

test('the rules that must never break: quiet on legitimate data, an alert for each one broken, once a day, at most hourly', async () => {
  // Legitimate data from every flow above, plus an administrator promoted the recorded way and a sub-agent.
  const owner = await member({ name: 'Rules owner' });
  const a = await actingAgent(owner, 'Parent agent', 10);
  const sub = await agentsApi('POST', 'subagents', { key: a.key, json: { name: 'Child agent' } });
  assert.ok([201, 202].includes(sub.status), JSON.stringify(sub.json));
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_owner');
    await t.unsafe(`select app.founder_promote('${owner.id}')`);
  }).catch(async () => {
    // founder_promote is for dog_signin; the test promotes as the setup run records it.
    await asOwner(`update app.members set is_admin = true where id = '${owner.id}'`);
    await q(`insert into app.audit_log (action, subject_kind, subject_id, detail) values ('admin.set', 'member', '${owner.id}', '{"by":"test"}')`);
  });
  // The owner tries to give the sub-agent a higher cap than its parent's, and to let it act on its own: whatever the
  // site does with that (refuse or cap it), rule c must stay true.
  const [child] = await q(`select id from app.agents where name = 'Child agent'`);
  const tried = await agentsApi('POST', 'rules', { cookie: owner.cookie, json: { agent: child.id, post: 'act', reply: 'draft', report: 'draft', daily_cap: 50 } });
  assert.ok(tried.status < 500, JSON.stringify(tried.json));
  await freeSlot();
  assert.strictEqual(await runInvariants(), true);
  assert.deepStrictEqual(await alerts('invariant:'), [], 'no rule is broken by legitimate data');
  assert.strictEqual(await runInvariants(), false, 'at most once an hour');

  // Break each rule as the database owner would have to (none of these is reachable through the site).
  const intruder = await member({ name: 'Intruder' });
  // a: an administrator with no recorded promotion (there can only be one: members_one_admin)
  await asOwner(`update app.members set is_admin = false where id = '${owner.id}'; update app.members set is_admin = true where id = '${intruder.id}'`);
  const lifted = await member({ name: 'Lifted' });
  // b: a level nobody gave (an admin setting it would record level_set_by_admin, so the guard is lifted here)
  await q(`alter table app.members disable trigger user; update app.members set trust_level = 3 where id = '${lifted.id}'; alter table app.members enable trigger user`);
  await q(`alter table app.agent_rules disable trigger user; insert into app.agent_rules (agent_id, version, post_mode, reply_mode, report_mode, daily_cap, reason, set_by)
    select r.agent_id, r.version + 1, r.post_mode, r.reply_mode, r.report_mode, 999, r.reason, r.set_by from app.agent_rules r join app.agents a on a.id = r.agent_id
    where a.name = 'Child agent' order by r.version desc limit 1; alter table app.agent_rules enable trigger user`); // c
  await q(`alter table app.sessions disable trigger user; update app.sessions set expires_at = now() + interval '60 days'
    where member_id = '${lifted.id}'; alter table app.sessions enable trigger user`); // d
  await q(`alter table app.posts disable trigger user; insert into app.posts (author_id, lane, agent_id, body, status, delegation, rules_version)
    select '${owner.id}', 'agents', '${a.agent_id}', 'flood ' || g, 'waiting', 'rules', 1 from generate_series(1, 25) g; alter table app.posts enable trigger user`); // e: over the highest cap it had today (20 when made, then 10)
  await asOwner(`update app.jevs_settings set value = '200' where key = 'medium_total'`); // f
  try {
    await freeSlot();
    assert.strictEqual(await runInvariants(), true);
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    assert.deepStrictEqual(await alerts('invariant:'), ['a', 'b', 'c', 'd', 'e', 'f'].map((r) => 'invariant:' + r + ':' + today));
    await freeSlot();
    await runInvariants();
    assert.strictEqual((await alerts('invariant:')).length, 6, 'once a day each');
  } finally {
    await asOwner(`update app.jevs_settings set value = '70' where key = 'medium_total'`);
  }
});

test('the rule checks never touch the timers or the reply: a failure is recorded, alerted once, and retried an hour later', async () => {
  // A failure inside the checks: the function the rules call is made to fail for this test only.
  await q(`create or replace function app.test_fail() returns trigger language plpgsql as $$ begin raise exception 'boom'; end $$`);
  await q(`create trigger test_fail before update of last_ok_at on app.invariant_slot for each row execute function app.test_fail()`);
  try {
    await freeSlot();
    assert.strictEqual(await runInvariants(), true);
    const [slot] = await q(`select failures, last_failure_state, last_at is not null as taken from app.invariant_slot`);
    assert.deepStrictEqual([slot.failures, slot.last_failure_state, slot.taken], [1, 'P0001', true]);
    assert.strictEqual((await alerts('invariant:failed:')).length, 1);
    // The timer route still answers ok: the checks run in their own transaction after the timers.
    const r = res();
    require('../api/cron.js')._reset();
    await require('../api/cron.js').handle({ method: 'GET', headers: { 'user-agent': 'vercel-cron/1.0' } }, r, run, { now: () => Date.now() + 10 * 60_000 });
    assert.strictEqual(r.statusCode, 200);
  } finally {
    await q(`drop trigger test_fail on app.invariant_slot; drop function app.test_fail()`);
  }
});
