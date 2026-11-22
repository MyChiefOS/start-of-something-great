// 067, the zero-payment launch (Aaron, Nov 21, 2026), against a real Postgres built from the migrations, through the
// real handler (api/work.js) and the timer's jobs: people and their agents agree to tasks, do them, have them verified,
// dispute and appeal them, and the result is reputation with no money anywhere. ACCEPTANCE.md ZP1 to ZP8.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const workjobs = require('../db/workjobs');
const { migrate } = require('../scripts/migrate');

const { promote, shadowMode, asSignin } = require('./helpers');
const ORIGIN = 'https://dayonegreat.com';const CFG = { ipKey: crypto.randomBytes(32) };const SERVER = process.env.TEST_DATABASE_URL;
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
let ip = 1;
async function call(handler, method, route, { cookie = '', json, key, search = '', host = 'dayonegreat.com', origin } = {}, runner) {
  const headers = { host, cookie, 'x-vercel-forwarded-for': '198.51.' + (ip >> 8) + '.' + (ip++ & 255), 'x-vercel-ip-country': 'US' };
  if (method === 'GET') headers['sec-fetch-site'] = 'same-origin'; // as a browser on the site's own pages sends it (RK145)
  if (method === 'POST' && cookie) headers.origin = origin || ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  const r = res();
  await handler({ method, url: '/api/work/' + route + search, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined }, r, runner);
  return { status: r.statusCode, headers: r.headers, json: r.body ? JSON.parse(r.body) : null, text: r.body };
}

if (!SERVER) {
  if (process.env.CI) test('work tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('work against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_067_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); });
const asWork = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_work'); return t.unsafe(sql); });

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await asOwner('update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000');
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  aaron = await member('Aaron', { admin: true });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(name, { admin = false, level = 2 } = {}) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  if (admin) await asOwner(`update app.members set is_admin = true where id = '${out.memberId}'`);
  return { id: out.memberId, name, cookie: '__Host-dog_session=' + token };
}
const work = (method, route, opts = {}) => call(require('../api/work.js').handle, method, route, opts, run);
async function agents(method, route, { cookie = '', json, key } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '198.51.' + (ip >> 8) + '.' + (ip++ & 255), 'x-vercel-ip-country': 'US' };
  if (method === 'POST' && cookie) headers.origin = ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  const r = res();
  await require('../api/agents.js').handle({ method, url: '/api/agents/' + route, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined }, r, run, CFG);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
async function newAgent(owner, name, post = 'act') {
  const r = await agents('POST', '', { cookie: owner.cookie, json: { name, post } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key };
}
async function project(owner, title = 'Make the onboarding clearer', room = '27-0000', opts = {}) {
  const r = await work('POST', 'projects', { ...opts, cookie: owner.cookie, json: { title, description: 'Context for ' + title, room } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return r.json.id;
}
async function task(owner, pj, over = {}, opts = {}) {
  const r = await work('POST', 'tasks', { ...opts, cookie: owner.cookie, json: { project: pj, title: 'Write the welcome copy', description: 'Three short paragraphs.', class: 'either', size: 3, ...over } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return r.json.id;
}
const page = async (id) => (await work('GET', 'task', { search: '?id=' + id })).json;
const tick = async () => { await asWork('update app.work_settings set last_tick_at = null'); return workjobs.run(run); };
const moneyRows = async () => (await q(`select (select count(*) from app.pay_requests)::int + (select count(*) from app.pay_ledger)::int + (select count(*) from app.work_bounties)::int + (select count(*) from app.pay_accounts)::int as n`))[0].n;

test('ZP1: a person posts, another person’s agent claims and submits, the poster verifies it, and the points go final, with no money anywhere', async () => {
  const ada = await member('Ada');
  const bo = await member('Bo');
  const agent = await newAgent(bo, 'Bo_helper', 'act');
  const pj = await project(ada, 'Zero-payment trial');
  const id = await task(ada, pj, { title: 'Summarize the three onboarding pages', description: 'Acceptance: one paragraph each, under 120 words.', size: 2 });
  const cl = await work('POST', 'claim', { key: agent.key, json: { task: id } });
  assert.strictEqual(cl.status, 201, JSON.stringify(cl.json));
  const sub = await work('POST', 'submit', { key: agent.key, json: { task: id, kind: 'link', url: 'https://example.org/summary', note: 'Three paragraphs.' } });
  assert.deepStrictEqual([sub.status, sub.json.status], [201, 'review']);
  assert.strictEqual((await work('POST', 'check', { cookie: bo.cookie, json: { submission: sub.json.submission, verdict: 'pass', reason: 'mine' } })).status, 403, 'nobody verifies their own agent’s work');
  const d = await work('POST', 'check', { cookie: ada.cookie, json: { submission: sub.json.submission, verdict: 'pass', reason: 'Each paragraph is under 120 words.' } });
  assert.deepStrictEqual([d.status, d.json.result], [200, 'pass']);
  assert.strictEqual((await page(id)).submissions[0].points.status, 'pending', 'reputation waits for the dispute window');
  await asWork(`update app.work_points set final_at = now() - interval '1 minute' where submission_id = '${sub.json.submission}'`);
  await tick();
  assert.strictEqual((await q(`select status from app.work_points where submission_id = '${sub.json.submission}'`))[0].status, 'final');
  const types = (await q(`select type from app.log_entries where subject in ('task:${id}', 'submission:${sub.json.submission}') order by seq`)).map((e) => e.type);
  assert.deepStrictEqual(types, ['task.claimed', 'task.submitted', 'audit.verdict', 'audit.verdict', 'task.approved']);
  assert.strictEqual((await work('POST', 'fund', { cookie: ada.cookie, json: { task: id, dollars: 50 } })).status, 503, 'funding is refused');
  assert.strictEqual(await moneyRows(), 0, 'no money row anywhere');
});

test('ZP2: the money lock holds in the database itself, whoever writes: the funding function as a person, and the payment role directly', async () => {
  const ada = await member('Ada2');
  const pj = await project(ada, 'Lock trial');
  const id = await task(ada, pj);
  await assert.rejects(run({ actor: 'member', memberId: ada.id, session: c.sha256hex(ada.cookie.split('=')[1]), fresh: true }, (t) => t`select app.bounty_fund_request(${id}, 5000)`), /money_off|no payments/i);
  await assert.rejects(su.begin(async (t) => { await t.unsafe('set local role dog_pay'); await t.unsafe(`insert into app.pay_requests (member_id, kind) values ('${ada.id}', 'connect_onboard')`); }), /money_off/);
  for (const tb of ['work_bounties', 'pay_requests', 'pay_accounts', 'pay_ledger', 'pay_events']) {
    const [{ n, ev }] = await q(`select count(*)::int as n, bool_and(tgtype & 28 = 28) as ev from pg_trigger where tgname = 'money_locked' and tgrelid = 'app.${tb}'::regclass and tgenabled <> 'D'`);
    assert.strictEqual(n, 1, tb + ' has the lock, enabled');
    assert.strictEqual(ev, true, tb + ': the lock covers insert, update and delete (the fresh review, H1)');
  }
  // A row written while the lock was lifted can't be changed or removed once it is back.
  await su.begin(async (t) => {
    await t.unsafe('alter table app.pay_requests disable trigger money_locked');
    await t.unsafe(`insert into app.pay_requests (member_id, kind) values ('${ada.id}', 'connect_onboard')`);
    await t.unsafe('alter table app.pay_requests enable trigger money_locked');
    await assert.rejects(t.unsafe(`update app.pay_requests set kind = kind where member_id = '${ada.id}'`), /money_off/);
    throw new Error('rollback');
  }).catch((e) => { if (e.message !== 'rollback') throw e; });
  // The fresh review (M2): emptying a money table is refused too, and the lock fires in replica mode.
  await assert.rejects(q('truncate app.pay_ledger'), /money_off/);
  await su.begin(async (t) => {
    await t.unsafe("set local session_replication_role = replica");
    await assert.rejects(t.unsafe(`insert into app.pay_requests (member_id, kind) values ('${ada.id}', 'connect_onboard')`), /money_off/);
    throw new Error('rollback');
  }).catch((e) => { if (e.message !== 'rollback') throw e; });
  assert.strictEqual(await moneyRows(), 0);
  const [{ d }] = await q(`select obj_description('app.work_point_entries'::regclass) as d`);
  assert.match(d, /never money/, 'the points ledger says what it is');
});

test('ZP3: a third person disputes a pass; the worker adds evidence; the administrator settles it with a reason', async () => {
  const ada = await member('Ada3'); const bo = await member('Bo3'); const cy = await member('Cy3');
  const id = await task(ada, await project(ada, 'Dispute trial'));
  await work('POST', 'claim', { cookie: bo.cookie, json: { task: id } });
  const sub = await work('POST', 'submit', { cookie: bo.cookie, json: { task: id, kind: 'link', url: 'https://example.org/x' } });
  await work('POST', 'check', { cookie: ada.cookie, json: { submission: sub.json.submission, verdict: 'pass', reason: 'Looks done.' } });
  const dp = await work('POST', 'dispute', { cookie: cy.cookie, json: { submission: sub.json.submission, reason: 'The page linked is empty.' } });
  assert.strictEqual(dp.status, 201, JSON.stringify(dp.json));
  const did = dp.json.dispute || dp.json.id;
  assert.strictEqual((await work('POST', 'evidence', { cookie: bo.cookie, json: { dispute: did, note: 'The page has the copy now.' } })).status, 201);
  const st = await work('POST', 'settle', { cookie: aaron.cookie, json: { dispute: did, decision: 'dismiss', reason: 'The work meets the task.' } });
  assert.deepStrictEqual([st.status, st.json.result], [200, 'dismiss']);
});

test('ZP4: a claim nobody finishes expires: the task reopens and nobody is credited', async () => {
  const ada = await member('Ada4'); const bo = await member('Bo4');
  const id = await task(ada, await project(ada, 'Expiry trial'));
  await work('POST', 'claim', { cookie: bo.cookie, json: { task: id } });
  await asWork(`update app.work_claims set expires_at = now() - interval '1 minute' where task_id = '${id}'`);
  await tick();
  assert.strictEqual((await page(id)).status, 'open');
  assert.strictEqual((await q(`select count(*)::int as n from app.work_points p join app.work_submissions s on s.id = p.submission_id where s.task_id = '${id}'`))[0].n, 0);
});

test('ZP5 (gap G4): an agent in draft mode can read the work but not take part in it', async () => {
  const ada = await member('Ada5'); const bo = await member('Bo5');
  const draft = await newAgent(bo, 'Bo_drafter', 'draft');
  const id = await task(ada, await project(ada, 'Draft trial'), { size: 2 });
  const cl = await work('POST', 'claim', { key: draft.key, json: { task: id } });
  assert.strictEqual(cl.json.reason, 'work_draft', JSON.stringify(cl.json));
  assert.match(cl.json.error, /draft mode/);
  // Reading is public and takes no key, for agents and people alike, so a draft-mode agent still reads the task.
  const rd = await work('GET', 'task', { search: '?id=' + id });
  assert.strictEqual(rd.status, 200);
  assert.strictEqual(rd.json.status, 'open', 'the refused claim left the task open');
  // The fresh review (H2): only the steps that commit are held. The agent still reads its own work with its key.
  const mine = await work('GET', 'mine', { key: draft.key });
  assert.notStrictEqual(mine.json && mine.json.reason, 'work_draft', 'a draft agent reads its own work: ' + JSON.stringify(mine.json));
  assert.ok(mine.status < 400, 'mine answers: ' + mine.status + ' ' + JSON.stringify(mine.json));
});

test('ZP6 (gap G4): every agent work action records the version of its owner’s rules', async () => {
  const ada = await member('Ada6'); const bo = await member('Bo6');
  const agent = await newAgent(bo, 'Bo_versioned', 'act');
  const id = await task(ada, await project(ada, 'Version trial'), { size: 2 });
  assert.strictEqual((await work('POST', 'claim', { key: agent.key, json: { task: id } })).status, 201);
  const [{ v }] = await q(`select max(version) as v from app.agent_rules where agent_id = '${agent.id}'`);
  const rows = await q(`select rules_version from app.work_actions where agent_id = '${agent.id}'`);
  assert.ok(rows.length >= 1 && rows.every((r) => r.rules_version === v), JSON.stringify(rows) + ' vs ' + v);
  const mine = await q(`select rules_version from app.work_actions where member_id = '${ada.id}' and agent_id is null`);
  assert.ok(mine.every((r) => r.rules_version === null), 'a person’s own actions have no rules version');
});

test('ZP7 (gap G11): the worker appeals a poster’s fail; an administrator overturns it; nothing is reversed and the worker is told', async () => {
  const ada = await member('Ada7'); const bo = await member('Bo7'); const cy = await member('Cy7');
  const id = await task(ada, await project(ada, 'Appeal trial'));
  await work('POST', 'claim', { cookie: bo.cookie, json: { task: id } });
  const sub = (await work('POST', 'submit', { cookie: bo.cookie, json: { task: id, kind: 'link', url: 'https://example.org/f' } })).json.submission;
  assert.strictEqual((await work('POST', 'check', { cookie: ada.cookie, json: { submission: sub, verdict: 'fail', reason: 'Not what was asked.' } })).status, 200);
  assert.strictEqual((await work('POST', 'appeal', { cookie: cy.cookie, json: { submission: sub, reason: 'Not mine' } })).status, 403, 'only the worker or the poster');
  const ap = await work('POST', 'appeal', { cookie: bo.cookie, json: { submission: sub, reason: 'It does what the task asked.' } });
  assert.deepStrictEqual([ap.status, ap.json.result], [201, 'appealed'], JSON.stringify(ap.json));
  const [k] = await q(`select id, why, appealed_by from app.work_checks where submission_id = '${sub}'`);
  assert.deepStrictEqual([k.why, k.appealed_by], ['fail_appeal', bo.id]);
  const rv = await work('POST', 'review', { cookie: aaron.cookie, json: { check: k.id, decision: 'reverse', reason: 'The work was fine.' } });
  assert.strictEqual(rv.status, 200, JSON.stringify(rv.json));
  assert.strictEqual((await q(`select status from app.work_submissions where id = '${sub}'`))[0].status, 'failed', 'an overturned fail is never turned into anything');
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id = '${bo.id}' and dedupe_key = 'work:fail-overturned:${k.id}'`))[0].n, 1, 'the worker is told');
  assert.strictEqual((await work('POST', 'appeal', { cookie: bo.cookie, json: { submission: sub, reason: 'Again please.' } })).status, 409, 'once only');
  // The administrator's own fail can't be appealed: it would go back to him.
  const id2 = await task(ada, await project(ada, 'Appeal trial 2'));
  await work('POST', 'claim', { cookie: bo.cookie, json: { task: id2 } });
  const sub2 = (await work('POST', 'submit', { cookie: bo.cookie, json: { task: id2, kind: 'link', url: 'https://example.org/g' } })).json.submission;
  await asWork(`update app.work_submissions set status = 'failed', decided_by = 'person', decided_at = now() where id = '${sub2}'`);
  assert.strictEqual((await work('POST', 'appeal', { cookie: bo.cookie, json: { submission: sub2, reason: 'Please look again.' } })).json.reason, 'work_appeal_not_appealable');
  assert.strictEqual(await moneyRows(), 0);
});

test('ZP8: the public pages say there is no money, and nothing invites anyone to pay or be paid', () => {
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  const home = read('index.html');
  assert.doesNotMatch(home, /Post a Funded Task|join\/buyer/);
  for (const f of ['index.html', 'build.html', 'talk.html']) assert.match(read(f), /class="paybar"[^>]*>Day One Great has no payments/, f);
  assert.match(read('llms.txt'), /## No money/);
  assert.match(read('terms.html'), /does not offer payments/);
});
