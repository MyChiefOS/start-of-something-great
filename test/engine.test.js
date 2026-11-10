// 056, the trust Engine's steps E1 to E3 (design/engine-e1-e3.md; Rev 4.2, section 12), against a Postgres built from
// the migrations, through the real handlers (api/engine.js, api/work.js, api/agents.js):
//   - the maths: the 95% Wilson lower bound and the Brier score against known values, and Rev 4.2's climb of levels;
//   - E1: a license comes only from settled outcomes decided by someone else, through one writer, with a history nobody
//     can edit and a notice to the owner; a forecast is an agent's, before it submits, once, never changed, and
//     resolves itself at the first settled verdict; nothing the Engine does stops the work it follows;
//   - E2: precedents only from an administrator, never edited, overturned once in their own room, cited as the rules
//     say; findings drop a license to 0 until an administrator who isn't the owner confirms the fix;
//   - E3: work orders from the agent's owner, their state worked out from the facts, paused and resumed as Rev 4.2
//     says, and the owner told once per pause;
//   - every refusal, the site's role reading nothing directly, the guards holding for the owner and a superuser too,
//     and everything going with the agent's account.
// Needs TEST_DATABASE_URL (skipped without it, required in CI), like the other database tests.
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
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { promote, shadowMode, asSignin } = require('./helpers');

const root = path.join(__dirname, '..');
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };
const SERVER = process.env.TEST_DATABASE_URL;

// The same formula, written independently, to check the database's against (z = 1.96).
const wilson = (k, n) => { if (!n) return 0; const p = k / n, z = 1.96; return (p + z * z / (2 * n) - z * Math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / (1 + z * z / n); };

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
let ip = 1;
async function call(handler, base, method, route, { cookie = '', json, key, search = '', host = 'dayonegreat.com', origin } = {}, runner) {
  const headers = { host, cookie, 'x-vercel-forwarded-for': '198.51.' + (ip >> 8) + '.' + (ip++ & 255), 'x-vercel-ip-country': 'US' };
  if (method === 'POST' && cookie) headers.origin = origin || ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  const r = res();
  await handler({ method, url: base + route + search, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined }, r, runner, CFG);
  return { status: r.statusCode, headers: r.headers, json: r.body ? JSON.parse(r.body) : null };
}

test('without a database the Engine API answers safely and routes only what it offers', async () => {
  const { handle } = require('../api/engine.js');
  const e = (method, route, opts = {}) => call(handle, '/api/engine/', method, route, opts, null);
  assert.strictEqual((await e('GET', 'summary')).status, 503);
  assert.strictEqual((await e('GET', 'nope')).status, 404);
  assert.strictEqual((await e('POST', 'summary', { json: {} })).status, 405);
  assert.strictEqual((await e('GET', 'forecast')).status, 405);
  assert.strictEqual((await e('GET', 'summary', { host: 'evil.example' })).status, 403);
  assert.strictEqual((await e('PUT', 'summary')).status, 405);
  // Through Vercel's rewrite the query also carries path; any other key, or one twice, is refused before the database.
  const stub = async () => ({ policy: {} });
  const get = async (url) => { const r = res(); await handle({ method: 'GET', url, headers: { host: 'dayonegreat.com' }, query: { route: 'summary' } }, r, stub); return r.statusCode; };
  assert.strictEqual(await get('/api/engine?route=summary&path=summary'), 200);
  assert.strictEqual(await get('/api/engine?route=summary&path=summary&x=1'), 400);
  const vercel = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  assert.ok(vercel.rewrites.some((r) => r.source === '/api/engine/:path*' && r.destination === '/api/engine?route=:path*'), 'vercel.json routes /api/engine/*');
});

if (!SERVER) {
  if (process.env.CI) test('Engine tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the Engine against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_engine_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const as = (role, sql) => su.begin(async (t) => { await t.unsafe('set local role ' + role); return t.unsafe(sql); });

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await as('dog_owner', 'update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000');
  // The poster's limits (the same pair, points a day) and the random check after are the work module's; set out of the
  // way here so each test decides its own outcomes.
  await q('update app.work_settings set pair_limit = 100, poster_daily_points = 10000, check_rate = 0');
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
  if (admin) await as('dog_owner', `update app.members set is_admin = true where id = '${out.memberId}'`);
  return { id: out.memberId, name, cookie: '__Host-dog_session=' + token, ctx: { actor: admin ? 'admin' : 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
const work = (method, route, opts = {}) => call(require('../api/work.js').handle, '/api/work/', method, route, opts, run);
const eng = (method, route, opts = {}) => call(require('../api/engine.js').handle, '/api/engine/', method, route, opts, run);
async function newAgent(owner, name) {
  const r = await call(require('../api/agents.js').handle, '/api/agents/', 'POST', '', { cookie: owner.cookie, json: { name, post: 'act' } }, run);
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key, owner };
}
async function project(owner, room = '27-0000') {
  const r = await work('POST', 'projects', { cookie: owner.cookie, json: { title: 'Engine project ' + crypto.randomUUID().slice(0, 8), description: 'Context.', room } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return r.json.id;
}
async function task(owner, pj, size = 2) { // size 2: what any agent may claim at level 0
  const r = await work('POST', 'tasks', { cookie: owner.cookie, json: { project: pj, title: 'Write the welcome copy', description: 'Three short paragraphs.', class: 'either', size } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return r.json.id;
}
async function claim(agent, id) {
  const r = await work('POST', 'claim', { key: agent.key, json: { task: id } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
}
async function submit(agent, id) {
  const r = await work('POST', 'submit', { key: agent.key, json: { task: id, kind: 'link', url: 'https://example.org/work/' + id, note: 'Done.' } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return r.json.submission;
}
async function check(poster, sub, verdict) {
  const r = await work('POST', 'check', { cookie: poster.cookie, json: { submission: sub, verdict, ...(verdict === 'fail' ? { reason: 'The page is empty.' } : {}) } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  return r.json.result;
}
const forecast = (agent, id, chance, extra = {}) => eng('POST', 'forecast', { key: agent.key, json: { task: id, chance_bp: chance, ...extra } });
// One task done start to end by an agent: claimed, forecast, submitted, checked by the poster.
async function piece(agent, poster, pj, { chance = 8000, verdict = 'pass', extra = {} } = {}) {
  const id = await task(poster, pj);
  await claim(agent, id);
  const f = await forecast(agent, id, chance, extra);
  assert.strictEqual(f.status, 201, JSON.stringify(f.json));
  const sub = await submit(agent, id);
  assert.strictEqual(await check(poster, sub, verdict), verdict);
  return { task: id, sub, forecast: f.json.forecast };
}
// The 72 hours over: the timer's own statement, as the work module's role.
const settle = (sub) => as('dog_work', `update app.work_points set status = 'final' where submission_id = '${sub}' and status = 'pending'`);
const license = async (agent, room = '27-0000') => (await q(`select l.* from app.engine_licenses l join app.work_rooms r on r.id = l.room_id where l.agent_id = '${agent.id}' and r.code = '${room}'`))[0];
const summary = async () => { const r = await eng('GET', 'summary'); assert.strictEqual(r.status, 200, JSON.stringify(r.json)); return r.json; };

// ---- The database itself ----

test('the database passes the coverage check and matches the reviewed snapshot, with the Engine (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('the Wilson lower bound matches known values (Rev 4.2: 20 of 21 is about 0.77, short of level 2’s 0.80) and the leaderboard’s own', async () => {
  const lb = async (k, n) => Number((await su`select app.engine_wilson_lb(${k}::bigint, ${n}::bigint) as v`)[0].v);
  // Published values of the Wilson score interval's lower end at 95%: 8 of 10 is 0.4902, 1 of 1 is 0.2065.
  for (const [k, n, want] of [[0, 0, 0], [0, 10, 0], [1, 1, 0.2065], [5, 5, 0.5655], [8, 10, 0.4902], [19, 20, 0.7639], [20, 21, 0.7733],
    [20, 20, 0.8389], [47, 50, 0.8378], [50, 50, 0.9287]]) {
    const got = await lb(k, n);
    assert.ok(Math.abs(got - want) < 0.00006, k + ' of ' + n + ': ' + got + ' not ' + want);
    assert.ok(Math.abs(got - wilson(k, n)) < 0.000001, k + ' of ' + n + ' against the formula written here');
  }
  // The same as 045's interval, which the leaderboard shows, on every k of n up to 60.
  const rows = await su`select k, n, app.engine_wilson_lb(k, n) as a, (app.work_wilson(k, n) ->> 'lo')::numeric as b
                          from generate_series(1, 60) n, generate_series(0, 60) k where k <= n`;
  for (const r of rows) assert.ok(Math.abs(Number(r.a) - Number(r.b)) < 0.00006, r.k + '/' + r.n);
});

test('the Brier score matches known values: 0 is perfect, 0.25 is always saying 50%', async () => {
  const brier = async (rows) => Number((await su`select avg(app.engine_brier_term(x.bp, x.held)) as v
    from jsonb_to_recordset(${su.json(rows)}::jsonb) as x(bp integer, held boolean)`)[0].v);
  assert.strictEqual(await brier([{ bp: 10000, held: true }, { bp: 0, held: false }]), 0);
  assert.strictEqual(await brier([{ bp: 5000, held: true }, { bp: 5000, held: false }]), 0.25);
  assert.strictEqual(await brier([{ bp: 7000, held: true }, { bp: 7000, held: false }]), 0.29);
  assert.ok(Math.abs(await brier([{ bp: 9000, held: true }, { bp: 8000, held: true }, { bp: 6000, held: false }]) - 0.41 / 3) < 1e-12);
  assert.strictEqual(await brier([{ bp: 10000, held: false }]), 1, 'confidently wrong is the worst score');
});

test('the levels are climbed in order and the first unmet one stops the climb; level 4 is not set, so the climb stops at 3', async () => {
  const level = async (n, k, fn, br) => (await su`select app.engine_level(${n}::bigint, ${k}::bigint, ${fn}::bigint, ${br}::numeric) as v`)[0].v;
  assert.strictEqual(await level(0, 0, 0, null), 0);
  assert.strictEqual(await level(4, 4, 0, null), 0, 'level 1 needs 5 verified outcomes');
  assert.strictEqual(await level(5, 5, 0, null), 1);
  assert.strictEqual(await level(5, 4, 0, null), 0, '4 of 5 has a lower bound of 0.38');
  assert.strictEqual(await level(21, 20, 50, 0), 1, '20 of 21 is not enough for level 2 (Rev 4.2)');
  assert.strictEqual(await level(20, 20, 9, 0.1), 1, 'level 2 needs 10 resolved forecasts');
  assert.strictEqual(await level(20, 20, 10, 0.15), 2);
  assert.strictEqual(await level(20, 20, 10, 0.16), 1, 'and a Brier score of 0.15 or less');
  assert.strictEqual(await level(20, 20, 10, null), 1, 'no score, no level 2');
  assert.strictEqual(await level(50, 50, 30, 0.1), 3);
  assert.strictEqual(await level(50, 50, 30, 0.11), 2);
  assert.strictEqual(await level(50, 47, 30, 0.05), 2, '47 of 50 (0.838) passes level 2’s bound but not level 3’s 0.90');
  assert.strictEqual(await level(100000, 100000, 100000, 0), 3, 'no level 4 until it is set');
  assert.deepStrictEqual((await q('select level, min_verified, min_lower_bound::text, min_forecasts, max_brier::text from app.engine_policy order by level'))
    .map((r) => Object.values(r).join(' ')), ['1 5 0.5000 0 ', '2 20 0.8000 10 0.1500', '3 50 0.9000 30 0.1000']);
});

test('the site’s role can read or change no Engine table directly, and the guards hold for the owner and a superuser too', async () => {
  for (const tbl of ['engine_policy', 'engine_licenses', 'engine_license_history', 'engine_forecasts', 'engine_precedents', 'engine_citations',
    'engine_findings', 'engine_orders', 'engine_order_resumes']) {
    await assert.rejects(run({ actor: 'anon' }, (t) => t.unsafe('select * from app.' + tbl)), /permission denied/, tbl);
  }
  await assert.rejects(run(aaron.ctx, (t) => t.unsafe(`insert into app.engine_licenses (agent_id, room_id, level, verified, succeeded, lower_bound, forecasts)
    select g.id, r.id, 4, 0, 0, 0, 0 from app.agents g, app.work_rooms r limit 1`)), /permission denied/);
  // Not even directly: the work module's role has no right to change a precedent, and the guard stops a superuser.
  // (The owner's role sees no row at all: row-level security is forced on it too.)
  const pid = (await q(`insert into app.engine_precedents (room_id, facts, decision, reason, decided_by)
    select r.id, 'Facts of a case.', 'Pass', 'A reason for it.', '${aaron.id}' from app.work_rooms r where r.code = '43-0000' returning id`))[0].id;
  await assert.rejects(q(`update app.engine_precedents set decision = 'Fail' where id = '${pid}'`), /engine_precedent_fixed/, 'a superuser');
  await assert.rejects(q(`delete from app.engine_precedents where id = '${pid}'`), /engine_precedent_fixed/, 'a superuser can\u2019t delete one');
  await assert.rejects(as('dog_work', `update app.engine_precedents set decision = 'Fail' where id = '${pid}'`), /permission denied/);
  assert.strictEqual((await as('dog_owner', `update app.engine_precedents set decision = 'Fail' where id = '${pid}' returning id`)).length, 0);
  assert.strictEqual((await q(`select decision from app.engine_precedents where id = '${pid}'`))[0].decision, 'Pass');
});

// ---- E1: licenses and forecasts ----

test('E1: an agent forecasts before it works; the forecast resolves itself; settled outcomes earn level 1, with its history and a notice', async () => {
  const ada = await member('Ada');
  const bo = await member('Bo');
  const cy = await member('Cy');
  const ag = await newAgent(ada, 'Scribe');
  const pj = await project(bo);
  const pieces = [];
  for (let i = 0; i < 5; i++) pieces.push(await piece(ag, i % 2 ? cy : bo, i % 2 ? await project(cy) : pj));
  // Passed, but the points are pending (the dispute window): not verified yet, and the forecasts are open.
  assert.strictEqual(await license(ag), undefined, 'a pending pass doesn’t count');
  assert.deepStrictEqual((await q(`select distinct resolution from app.engine_forecasts where agent_id = '${ag.id}'`)).map((r) => r.resolution), [null]);
  // The first one settles through the work module's own timer; the rest by the same statement.
  await as('dog_work', `update app.work_points set final_at = now() - interval '1 minute' where submission_id = '${pieces[0].sub}'`);
  await q('update app.work_settings set last_tick_at = null');
  await run({ actor: 'anon' }, (t) => t`select app.work_tick() as r`);
  let l = await license(ag);
  assert.deepStrictEqual([l.level, l.verified, l.succeeded, l.forecasts], [0, 1, 1, 1]);
  assert.deepStrictEqual((await q(`select resolution from app.engine_forecasts where id = '${pieces[0].forecast}'`))[0].resolution, 'held');
  for (const p of pieces.slice(1)) await settle(p.sub);
  l = await license(ag);
  assert.deepStrictEqual([l.level, l.verified, l.succeeded, l.forecasts, Number(l.lower_bound)], [1, 5, 5, 5, 0.56551]);
  assert.ok(Math.abs(Number(l.brier) - 0.04) < 1e-9, 'five forecasts of 80% that held: (0.2)^2 each');
  const hist = await q(`select old_level, new_level, reason, verified from app.engine_license_history where agent_id = '${ag.id}' order by changed_at`);
  assert.deepStrictEqual(hist.map((h) => [h.old_level, h.new_level, h.reason, h.verified]), [[0, 1, 'evidence', 5]]);
  const notes = await q(`select kind, title, body, link from app.notices where member_id = '${ada.id}' and kind = 'engine'`);
  assert.strictEqual(notes.length, 1);
  assert.match(notes[0].body, /^Scribe is now at level 1 in Arts, Design, Entertainment, Sports & Media \(it was 0\)\..*sets the largest task it may claim there on its own/);
  assert.strictEqual(notes[0].link, '/engine');
  // The history can't be edited or deleted, by anyone.
  await assert.rejects(q(`update app.engine_license_history set new_level = 3 where agent_id = '${ag.id}'`), /engine_history_append_only/);
  await assert.rejects(q(`delete from app.engine_license_history where agent_id = '${ag.id}'`), /engine_history_append_only/);
  // A forecast can't be changed, or resolved again, by anyone: not the owner, not a superuser.
  await assert.rejects(q(`update app.engine_forecasts set chance_bp = 9999 where id = '${pieces[1].forecast}'`), /engine_forecast_fixed/);
  await assert.rejects(as('dog_work', `update app.engine_forecasts set resolution = 'failed' where id = '${pieces[1].forecast}'`), /engine_forecast_resolved/);
  await assert.rejects(q(`update app.engine_forecasts set resolution = 'failed' where id = '${pieces[1].forecast}'`), /engine_forecast_resolved/);
  await assert.rejects(as('dog_work', `delete from app.engine_forecasts where id = '${pieces[1].forecast}'`), /permission denied|engine_forecast_fixed/);
  // The page's figures: a lower bound from 5 outcomes, no Brier score below 10 forecasts.
  const s = await summary();
  const row = s.licenses.find((x) => x.agent.id === ag.id);
  assert.deepStrictEqual({ level: row.level, verified: row.verified, lb: row.lower_bound, f: row.forecasts, room: row.room.code },
    { level: 1, verified: { k: 5, n: 5 }, lb: 0.56551, f: { n: 5, brier: null }, room: '27-0000' });
  assert.strictEqual(row.agent.name, 'Scribe');
  assert.strictEqual(row.agent.owner.name, 'Ada');
  assert.strictEqual(s.changes.find((x) => x.agent.id === ag.id).new_level, 1);
  assert.strictEqual(s.calibration.find((x) => x.agent.id === ag.id).brier, null, 'not enough data yet: 5 of 10');
  assert.match(s.policy.holds_up, /^claims above the level/);
  assert.deepStrictEqual(s.policy.size_cap, { 0: 2, 1: 5, 2: 8, 3: 8 });
  const one = await eng('GET', 'agent', { search: '?id=' + ag.id });
  assert.deepStrictEqual([one.status, one.json.licenses[0].level, one.json.forecasts.length, one.json.changes.length], [200, 1, 5, 1]);
  assert.strictEqual((await eng('GET', 'agent', { search: '?id=' + crypto.randomUUID() })).status, 404);
  assert.match((await eng('GET', 'summary')).headers['cache-control'], /s-maxage=30/);
});

test('E1: failures count against the bound at once; a claim released with nothing submitted settles its forecast as failed; a handed claim’s is unscored', async () => {
  const dee = await member('Dee');
  const bo = await member('Bo2');
  const ag = await newAgent(dee, 'Tester');
  const pj = await project(bo);
  const f1 = await piece(ag, bo, pj, { chance: 9000, verdict: 'fail' });
  assert.strictEqual((await q(`select resolution from app.engine_forecasts where id = '${f1.forecast}'`))[0].resolution, 'failed');
  const l = await license(ag);
  assert.deepStrictEqual([l.level, l.verified, l.succeeded, l.forecasts, Number(l.brier)], [0, 1, 0, 1, 0.81]);
  // Released before any work: the forecast predicted success, and nothing came.
  const id = await task(bo, pj);
  await claim(ag, id);
  assert.strictEqual((await forecast(ag, id, 6000)).status, 201);
  assert.strictEqual((await work('POST', 'release', { key: ag.key, json: { task: id } })).status, 200);
  assert.strictEqual((await q(`select f.resolution from app.engine_forecasts f join app.work_claims c on c.id = f.claim_id where c.task_id = '${id}'`))[0].resolution, 'released');
  assert.strictEqual((await license(ag)).forecasts, 2);
  // Handed to its own sub-agent: closed as handed, and scored nowhere; the sub-agent may forecast its own claim.
  const id2 = await task(bo, pj);
  await claim(ag, id2);
  assert.strictEqual((await forecast(ag, id2, 9900)).status, 201);
  const sub = await call(require('../api/agents.js').handle, '/api/agents/', 'POST', 'subagents', { key: ag.key, json: { name: 'Helper', post: 'act' } }, run);
  assert.strictEqual(sub.status, 201, JSON.stringify(sub.json));
  assert.strictEqual((await work('POST', 'handoff', { key: ag.key, json: { task: id2, agent: sub.json.agent_id } })).status, 201);
  const [h] = await q(`select f.resolution from app.engine_forecasts f join app.work_claims c on c.id = f.claim_id where c.task_id = '${id2}' and f.agent_id = '${ag.id}'`);
  assert.strictEqual(h.resolution, 'handed');
  assert.strictEqual((await license(ag)).forecasts, 2, 'a handed forecast isn’t scored');
  assert.strictEqual((await forecast({ key: sub.json.key }, id2, 7000)).status, 201);
});

test('E1: forecasts are refused unless they come from the agent, for its own live claim, before it submits, once, in basis points', async () => {
  const eve = await member('Eve');
  const fay = await member('Fay');
  const ag = await newAgent(eve, 'Planner');
  const other = await newAgent(fay, 'Other');
  const pj = await project(fay);
  const id = await task(fay, pj);
  assert.deepStrictEqual([(await forecast(ag, id, 5000)).status, (await forecast(ag, id, 5000)).json.reason], [409, 'engine_no_claim'], 'not claimed');
  await claim(ag, id);
  const byOwner = await eng('POST', 'forecast', { cookie: eve.cookie, json: { task: id, chance_bp: 5000 } });
  assert.strictEqual(byOwner.status, 403, 'a person can’t file an agent’s forecast');
  assert.strictEqual((await forecast(other, id, 5000)).json.reason, 'engine_no_claim', 'another agent has no claim on it');
  assert.strictEqual((await forecast(ag, id, 10001)).status, 400);
  assert.strictEqual((await forecast(ag, id, 50.5)).status, 400);
  assert.strictEqual((await forecast(ag, id, -1)).status, 400);
  assert.strictEqual((await eng('POST', 'forecast', { key: ag.key, json: { task: id, chance_bp: 5000, mood: 'sure' } })).status, 400, 'only its keys');
  assert.strictEqual((await eng('POST', 'forecast', { key: 'dog_' + 'x'.repeat(40), json: { task: id, chance_bp: 5000 } })).status, 401);
  // At the database too: a member's own call is refused, whatever the page does.
  await assert.rejects(run(eve.ctx, (t) => t`select app.engine_forecast(${id}::uuid, 5000, '[]'::jsonb, false)`), /engine_agents_only/);
  const ok = await forecast(ag, id, 7500);
  assert.deepStrictEqual([ok.status, ok.json.chance_bp], [201, 7500]);
  assert.strictEqual((await forecast(ag, id, 9000)).json.reason, 'engine_already', 'once per claim');
  await submit(ag, id);
  const id2 = await task(fay, pj);
  await claim(ag, id2);
  await submit(ag, id2);
  assert.strictEqual((await forecast(ag, id2, 9000)).json.reason, 'engine_late', 'after the work is submitted');
  // Its own audit row, as the agent.
  const [a] = await q(`select actor_kind, action, detail from app.audit_log where action = 'engine.forecast' and subject_id = '${ok.json.forecast}'`);
  assert.deepStrictEqual([a.actor_kind, a.detail.chance_bp], ['agent', 7500]);
});

test('E1: an Engine failure inside a work trigger never stops the work; Aaron gets one alert a day', async () => {
  const gil = await member('Gil');
  const hal = await member('Hal');
  const ag = await newAgent(gil, 'Fragile');
  const pj = await project(hal);
  const id = await task(hal, pj);
  await claim(ag, id);
  await q('revoke select on app.engine_policy from dog_work');
  try {
    const sub = await submit(ag, id);
    assert.strictEqual(await check(hal, sub, 'pass'), 'pass', 'the work went through');
    await settle(sub);
    assert.strictEqual((await q(`select status from app.work_points where submission_id = '${sub}'`))[0].status, 'final');
  } finally {
    await q('grant select on app.engine_policy to dog_work');
  }
  const alerts = await q(`select title from app.notices where member_id is null and dedupe_key like 'engine:trouble:%'`);
  assert.deepStrictEqual(alerts.map((x) => x.title), ['The trust Engine missed an update']);
});

// ---- E2: precedents and the immune system ----

test('E2: only an administrator sets a precedent; it is never edited; it is overturned once, in its own room', async () => {
  const ivy = await member('Ivy');
  const body = { room: '27-0000', facts: 'Welcome copy that links to an outside page. Write to ivy@example.org.', decision: 'Pass', reason: 'Outside links are fine when they are https and named.' };
  assert.strictEqual((await eng('POST', 'precedent', { cookie: ivy.cookie, json: body })).status, 403);
  await assert.rejects(run(ivy.ctx, (t) => t`select app.engine_precedent_add('27-0000', 'Some facts here.', 'Pass', 'A reason here.', null)`), /engine_admin_only/);
  assert.strictEqual((await eng('POST', 'precedent', { cookie: aaron.cookie, json: { ...body, reason: 'short' } })).status, 400);
  assert.strictEqual((await eng('POST', 'precedent', { cookie: aaron.cookie, json: { ...body, room: '99-0000' } })).status, 400);
  const p1 = await eng('POST', 'precedent', { cookie: aaron.cookie, json: body });
  assert.strictEqual(p1.status, 201, JSON.stringify(p1.json));
  const [row] = await q(`select facts, decided_by from app.engine_precedents where id = '${p1.json.precedent}'`);
  assert.strictEqual(row.facts, 'Welcome copy that links to an outside page. Write to [email hidden].', 'contact details hidden before saving');
  assert.strictEqual(row.decided_by, aaron.id);
  const p2 = await eng('POST', 'precedent', { cookie: aaron.cookie, json: { ...body, decision: 'Fail', reason: 'Links must point at this repository.', overturns: p1.json.precedent } });
  assert.strictEqual(p2.status, 201);
  assert.strictEqual((await eng('POST', 'precedent', { cookie: aaron.cookie, json: { ...body, overturns: p1.json.precedent } })).json.reason, 'engine_overturned_already');
  assert.strictEqual((await eng('POST', 'precedent', { cookie: aaron.cookie, json: { ...body, room: '15-0000', overturns: p2.json.precedent } })).json.reason, 'engine_overturn_room');
  assert.strictEqual((await eng('POST', 'precedent', { cookie: aaron.cookie, json: { ...body, overturns: crypto.randomUUID() } })).status, 404);
  const s = await summary();
  const one = s.precedents.find((x) => x.id === p1.json.precedent);
  assert.deepStrictEqual([one.overturned_by, s.precedents.find((x) => x.id === p2.json.precedent).overturns], [p2.json.precedent, p1.json.precedent]);
  assert.ok((await q(`select count(*)::int as n from app.audit_log where action = 'engine.precedent' and actor_kind = 'admin'`))[0].n >= 2);
});

test('E2: where a room has precedents, a forecast cites a current one of that room or says none applies', async () => {
  const jo = await member('Jo');
  const kim = await member('Kim');
  const ag = await newAgent(jo, 'Citer');
  const pj = await project(kim, '41-0000');
  const mk = async (room, extra = {}) => (await eng('POST', 'precedent', { cookie: aaron.cookie, json: { room, facts: 'A sales page with prices in it.', decision: 'Pass', reason: 'Prices are public on the page.', ...extra } })).json.precedent;
  const open = async () => { const id = await task(kim, pj); await claim(ag, id); return id; };
  // No precedents in the room yet: nothing to cite.
  const t0 = await open();
  const f0 = await forecast(ag, t0, 6000, { none: true });
  assert.deepStrictEqual([f0.status, f0.json.no_precedent, f0.json.precedents_in_room], [201, false, 0]);
  const old = await mk('41-0000');
  const cur = await mk('41-0000', { overturns: old });
  const elsewhere = await mk('13-0000');
  const t1 = await open();
  assert.strictEqual((await forecast(ag, t1, 6000)).json.reason, 'engine_cite_needed');
  assert.strictEqual((await forecast(ag, t1, 6000, { cites: [elsewhere] })).json.reason, 'engine_cite_room', 'another room’s precedent (Rev 4.2: another organisation’s)');
  assert.strictEqual((await forecast(ag, t1, 6000, { cites: [old] })).json.reason, 'engine_cite_overturned');
  assert.strictEqual((await forecast(ag, t1, 6000, { cites: [crypto.randomUUID()] })).json.reason, 'engine_cite_unknown');
  assert.strictEqual((await forecast(ag, t1, 6000, { cites: [cur], none: true })).status, 400, 'not both');
  assert.strictEqual((await forecast(ag, t1, 6000, { cites: 'all' })).status, 400);
  const ok = await forecast(ag, t1, 6000, { cites: [cur] });
  assert.deepStrictEqual([ok.status, ok.json.cites], [201, [cur]]);
  const t2 = await open();
  const none = await forecast(ag, t2, 6000, { none: true });
  assert.deepStrictEqual([none.status, none.json.no_precedent], [201, true], '"no precedent applies" is recorded');
  await assert.rejects(q(`delete from app.engine_citations where precedent_id = '${cur}'`), /engine_citation_fixed/);
  const s = await summary();
  assert.deepStrictEqual(s.forecasts.find((x) => x.id === ok.json.forecast).cites, [cur]);
  assert.strictEqual(s.precedents.find((x) => x.id === cur).cited, 1);
});

test('E2: a successful attack drops the agent to level 0 in that room at once; only an administrator who isn’t its owner confirms the fix', async () => {
  const lou = await member('Lou');
  const mo = await member('Mo');
  const ag = await newAgent(lou, 'Target');
  const pj = await project(mo, '25-0000');
  for (let i = 0; i < 5; i++) await settle((await piece(ag, mo, pj, { chance: 9000 })).sub);
  assert.strictEqual((await license(ag, '25-0000')).level, 1);
  const body = { agent: ag.id, room: '25-0000', class: 'ASI01', succeeded: true, vaccine: 'test/redteam-attacks.test.js: goal hijack through a task note' };
  assert.strictEqual((await eng('POST', 'finding', { cookie: lou.cookie, json: body })).status, 403, 'not the owner');
  await assert.rejects(run(mo.ctx, (t) => t`select app.engine_finding_add(${ag.id}::uuid, '27-0000', 'ASI01', true, 'a test')`), /engine_admin_only/);
  assert.strictEqual((await eng('POST', 'finding', { cookie: aaron.cookie, json: { ...body, class: 'ASI11' } })).status, 400);
  assert.strictEqual((await eng('POST', 'finding', { cookie: aaron.cookie, json: { ...body, agent: crypto.randomUUID() } })).status, 404);
  const f = await eng('POST', 'finding', { cookie: aaron.cookie, json: body });
  assert.deepStrictEqual([f.status, f.json.license], [201, 0]);
  const l = await license(ag, '25-0000');
  assert.deepStrictEqual([l.level, l.suspended], [0, true]);
  assert.match((await q(`select title from app.notices where member_id = '${lou.id}' and kind = 'engine' order by created_at desc limit 1`))[0].title, /suspended/);
  // Open: the vaccine isn't published.
  let s = await summary();
  assert.deepStrictEqual([s.findings.find((x) => x.id === f.json.finding).vaccine, s.counts.findings_open >= 1], [null, true]);
  // Nobody edits it around the function: not a superuser, not the owner of the database.
  await assert.rejects(q(`update app.engine_findings set fixed_at = now(), fixed_by = '${aaron.id}' where id = '${f.json.finding}'`), /engine_finding_fix_only/);
  await assert.rejects(q(`update app.engine_findings set vaccine = 'x' where id = '${f.json.finding}'`), /engine_finding_fixed/);
  await assert.rejects(q(`delete from app.engine_findings where id = '${f.json.finding}'`), /engine_finding_fixed/);
  assert.strictEqual((await eng('POST', 'fixed', { cookie: lou.cookie, json: { finding: f.json.finding } })).status, 403, 'the owner, who fixes it, can’t confirm it');
  const fx = await eng('POST', 'fixed', { cookie: aaron.cookie, json: { finding: f.json.finding, note: 'The note field is now read as data.' } });
  assert.deepStrictEqual([fx.status, fx.json.license], [200, 1]);
  assert.strictEqual((await eng('POST', 'fixed', { cookie: aaron.cookie, json: { finding: f.json.finding } })).json.reason, 'engine_not_open', 'once');
  const hist = await q(`select old_level, new_level, reason from app.engine_license_history where agent_id = '${ag.id}' order by changed_at, id`);
  assert.deepStrictEqual(hist.map((h) => [h.old_level, h.new_level, h.reason]), [[0, 1, 'evidence'], [1, 0, 'suspended'], [0, 1, 'fix_confirmed']]);
  s = await summary();
  assert.strictEqual(s.findings.find((x) => x.id === f.json.finding).vaccine, body.vaccine, 'published once fixed');
  // A failed attack is recorded and changes nothing.
  const miss = await eng('POST', 'finding', { cookie: aaron.cookie, json: { ...body, class: 'ASI06', succeeded: false } });
  assert.deepStrictEqual([miss.status, (await license(ag, '25-0000')).level], [201, 1]);
  assert.strictEqual((await eng('POST', 'fixed', { cookie: aaron.cookie, json: { finding: miss.json.finding } })).json.reason, 'engine_not_open');
  // Aaron's own agent: as the only administrator he may confirm its fix himself, but only with a reason (Nov 10), and
  // the audit log says it was the owner's own confirmation (the database allows one administrator: members_one_admin).
  const mine = await newAgent(aaron, 'Helper bot');
  const own = await eng('POST', 'finding', { cookie: aaron.cookie, json: { ...body, agent: mine.id } });
  assert.strictEqual((await eng('POST', 'fixed', { cookie: aaron.cookie, json: { finding: own.json.finding } })).json.reason, 'engine_fixer', 'no reason given');
  const ok = await eng('POST', 'fixed', { cookie: aaron.cookie, json: { finding: own.json.finding, note: 'Patched the prompt handling and added the test.' } });
  assert.strictEqual(ok.json.fixed, true, JSON.stringify(ok.json));
  const [a] = await q(`select detail from app.audit_log where action = 'engine.fixed' and subject_id = '${own.json.finding}'`);
  assert.strictEqual(a.detail.by_owner, true);
  assert.ok((await q(`select count(*)::int as n from app.audit_log where action in ('engine.finding', 'engine.fixed')`))[0].n >= 4);
});

// ---- What a level does: the size of task an agent may claim on its own (Aaron, Nov 10) ----

test('a level caps the size of task an agent may claim in that room: up to 2 at level 0, 5 at level 1, any from 2; a larger claim is refused with the reason, and a hand-off keeps the size its first claimer was allowed', async () => {
  const pam = await member('Pam');
  const quin = await member('Quin');
  const ag = await newAgent(quin, 'Sizer');
  const pj = await project(pam, '29-0000');
  const big = await task(pam, pj, 3);
  const r = await work('POST', 'claim', { key: ag.key, json: { task: big } });
  assert.strictEqual(r.status, 409, JSON.stringify(r.json));
  assert.match(JSON.stringify(r.json), /level 0, which allows tasks up to size 2; this one is size 3/);
  await claim(ag, await task(pam, pj, 2)); // small work is always open to it
  // Level 1 in that room: up to 5, still not 8.
  await q(`insert into app.engine_licenses (agent_id, room_id, level, verified, succeeded, lower_bound, forecasts)
    select '${ag.id}', r.id, 1, 5, 5, 0.6, 0 from app.work_rooms r where r.code = '29-0000'`);
  await claim(ag, await task(pam, pj, 5));
  const r8 = await work('POST', 'claim', { key: ag.key, json: { task: await task(pam, pj, 8) } });
  assert.match(JSON.stringify(r8.json), /level 1, which allows tasks up to size 5/);
  // A hand-off keeps the size its first claimer was allowed, at any depth: a level-1 agent's size-5 claim goes to its
  // sub-agent (level 0) and on to that one's sub-agent.
  const t5 = await task(pam, pj, 5);
  await claim(ag, t5);
  const sub1 = await call(require('../api/agents.js').handle, '/api/agents/', 'POST', 'subagents', { key: ag.key, json: { name: 'Sizer child', post: 'act' } }, run);
  assert.strictEqual(sub1.status, 201, JSON.stringify(sub1.json));
  const h1 = await work('POST', 'handoff', { key: ag.key, json: { task: t5, agent: sub1.json.agent_id } });
  assert.strictEqual(h1.status, 201, JSON.stringify(h1.json));
  const sub2 = await call(require('../api/agents.js').handle, '/api/agents/', 'POST', 'subagents', { key: sub1.json.key, json: { name: 'Sizer grandchild', post: 'act' } }, run);
  assert.strictEqual(sub2.status, 201, JSON.stringify(sub2.json));
  const h2 = await work('POST', 'handoff', { key: sub1.json.key, json: { task: t5, agent: sub2.json.agent_id } });
  assert.strictEqual(h2.status, 201, JSON.stringify(h2.json));
  // But the child can't claim a size-5 task on its own (its own level is 0).
  const own5 = await work('POST', 'claim', { key: sub1.json.key, json: { task: await task(pam, pj, 5) } });
  assert.match(JSON.stringify(own5.json), /level 0, which allows tasks up to size 2/);
  // People are never capped.
  const pj2 = await project(quin, '29-0000');
  const ppl = await work('POST', 'claim', { cookie: pam.cookie, json: { task: await task(quin, pj2, 8) } });
  assert.strictEqual(ppl.status, 201, JSON.stringify(ppl.json));
});

// ---- E3: work orders ----

test('E3: an owner gives an agent a work order; it pauses when spending runs ahead of progress, tells the owner once, and resumes by its maker', async () => {
  const ned = await member('Ned');
  const oli = await member('Oli');
  const ag = await newAgent(ned, 'Builder');
  const pj = await project(oli);
  const body = { agent: ag.id, project: pj, goal: 6, budget: 10, hours: 48, rollback: 'Revert the merged pull requests in reverse order.' };
  assert.strictEqual((await eng('POST', 'order', { key: ag.key, json: body })).status, 403, 'not the agent itself');
  assert.strictEqual((await eng('POST', 'order', { cookie: oli.cookie, json: body })).json.reason, 'engine_not_owner');
  assert.strictEqual((await eng('POST', 'order', { cookie: ned.cookie, json: { ...body, rollback: 'none' } })).status, 400, 'a rollback plan is required');
  assert.strictEqual((await eng('POST', 'order', { cookie: ned.cookie, json: { ...body, project: crypto.randomUUID() } })).status, 404);
  assert.strictEqual((await eng('POST', 'order', { cookie: ned.cookie, json: { ...body, goal: 0 } })).status, 400);
  const o = await eng('POST', 'order', { cookie: ned.cookie, json: body });
  assert.deepStrictEqual([o.status, o.json.state, o.json.spend, o.json.progress], [201, 'active', 0, 0], 'it starts clean');
  assert.strictEqual((await eng('POST', 'order', { cookie: ned.cookie, json: body })).json.reason, 'engine_order_open', 'one open order per agent and project');
  // Two claims and a submission with nothing verified yet: 30% spent, 0% done, more than 20 points ahead: paused.
  const t1 = await task(oli, pj);
  await claim(ag, t1);
  const t2 = await task(oli, pj);
  await claim(ag, t2);
  let st = (await summary()).orders.find((x) => x.id === o.json.order);
  assert.deepStrictEqual([st.state, st.spend, st.spend_pct], ['active', 2, 20], 'exactly 20 points ahead is still active');
  const s1 = await submit(ag, t1);
  st = (await summary()).orders.find((x) => x.id === o.json.order);
  assert.deepStrictEqual([st.state, st.why, st.spend], ['paused', 'ahead', 3]);
  const told = async () => (await q(`select count(*)::int as n from app.notices where member_id = '${ned.id}' and kind = 'engine' and dedupe_key like 'engine:order:%'`))[0].n;
  assert.strictEqual(await told(), 1);
  // The pause stops nothing: the agent's work goes on, and the owner is told once per pause.
  await submit(ag, t2);
  assert.strictEqual(await told(), 1);
  // Verified progress brings it back: 2 of 6 done (33.3%) against 40% spent (less than 20 points ahead).
  assert.strictEqual(await check(oli, s1, 'pass'), 'pass');
  st = (await summary()).orders.find((x) => x.id === o.json.order);
  assert.deepStrictEqual([st.state, st.progress, st.progress_pct, st.spend_pct], ['active', 2, 33.3, 40]);
  // Resumes: by its maker or an administrator, adding something.
  assert.strictEqual((await eng('POST', 'resume', { cookie: oli.cookie, json: { order: o.json.order, budget: 5 } })).json.reason, 'engine_not_maker');
  assert.strictEqual((await eng('POST', 'resume', { cookie: ned.cookie, json: { order: o.json.order } })).status, 400);
  assert.strictEqual((await eng('POST', 'resume', { key: ag.key, json: { order: o.json.order, budget: 5 } })).status, 403);
  const r = await eng('POST', 'resume', { cookie: ned.cookie, json: { order: o.json.order, budget: 10, hours: 24 } });
  assert.deepStrictEqual([r.status, r.json.budget, r.json.resumes], [200, 20, 1]);
  assert.strictEqual((await eng('POST', 'resume', { cookie: aaron.cookie, json: { order: o.json.order, hours: 1 } })).status, 200, 'an administrator may');
  // The order and its resumes never change.
  await assert.rejects(q(`update app.engine_orders set budget = 1000 where id = '${o.json.order}'`), /engine_order_fixed/);
  await assert.rejects(q(`delete from app.engine_order_resumes where order_id = '${o.json.order}'`), /engine_resume_fixed/);
});

test('E3: the budget spent, or the deadline passed, pauses an order; reaching the goal makes it done; 10 orders a day at most', async () => {
  const pat = await member('Pat');
  const quin = await member('Quin');
  const ag = await newAgent(pat, 'Runner');
  const pj = await project(quin);
  const o = (await eng('POST', 'order', { cookie: pat.cookie, json: { agent: ag.id, project: pj, goal: 2, budget: 1, hours: 24, rollback: 'Close the pull request unmerged.' } })).json.order;
  const t1 = await task(quin, pj);
  await claim(ag, t1);
  const s1 = await submit(ag, t1);
  let st = (await summary()).orders.find((x) => x.id === o);
  assert.deepStrictEqual([st.state, st.why], ['paused', 'budget']);
  assert.strictEqual(await check(quin, s1, 'pass'), 'pass');
  st = (await summary()).orders.find((x) => x.id === o);
  assert.deepStrictEqual([st.state, st.progress], ['done', 2], 'the goal reached: done, whatever the budget');
  // A deadline already passed (written here directly, as no request can set one in the past).
  const pj2 = await project(quin);
  const late = (await q(`insert into app.engine_orders (agent_id, project_id, created_by, goal_size, budget, deadline, rollback)
    values ('${ag.id}', '${pj2}', '${pat.id}', 5, 100, now() - interval '1 hour', 'Undo the changes by hand.') returning id`))[0].id;
  st = (await summary()).orders.find((x) => x.id === late);
  assert.deepStrictEqual([st.state, st.why], ['paused', 'deadline']);
  const back = await eng('POST', 'resume', { cookie: pat.cookie, json: { order: late, hours: 48 } });
  assert.strictEqual(back.json.state, 'active', 'more time resumes it');
  // The cap: 10 a day per member (2 made above).
  const made = [];
  for (let i = 0; i < 8; i++) made.push((await eng('POST', 'order', { cookie: pat.cookie, json: { agent: ag.id, project: await project(quin), goal: 1, budget: 5, hours: 5, rollback: 'Nothing to undo here.' } })).status);
  assert.deepStrictEqual(made, Array(8).fill(201));
  assert.strictEqual((await eng('POST', 'order', { cookie: pat.cookie, json: { agent: ag.id, project: await project(quin), goal: 1, budget: 5, hours: 5, rollback: 'Nothing to undo here.' } })).status, 429);
});

// ---- Privacy and the public view ----

test('everything an agent has here goes with its owner’s account, and a banned member’s agents leave the public lists', async () => {
  const ray = await member('Ray');
  const sam = await member('Sam');
  const ag = await newAgent(ray, 'Leaving');
  const pj = await project(sam, '31-0000');
  for (let i = 0; i < 5; i++) await settle((await piece(ag, sam, pj)).sub);
  const t = await task(sam, pj);
  await claim(ag, t);
  await forecast(ag, t, 5000, { none: true });
  await eng('POST', 'finding', { cookie: aaron.cookie, json: { agent: ag.id, room: '31-0000', class: 'ASI02', succeeded: true, vaccine: 'a vaccine test' } });
  await eng('POST', 'order', { cookie: ray.cookie, json: { agent: ag.id, project: pj, goal: 2, budget: 20, hours: 10, rollback: 'Revert by hand.' } });
  const count = async () => (await q(`select (select count(*) from app.engine_licenses where agent_id = '${ag.id}') + (select count(*) from app.engine_license_history where agent_id = '${ag.id}')
    + (select count(*) from app.engine_forecasts where agent_id = '${ag.id}') + (select count(*) from app.engine_findings where agent_id = '${ag.id}')
    + (select count(*) from app.engine_orders where agent_id = '${ag.id}') as n`))[0].n;
  assert.ok(Number(await count()) >= 10);
  // Deleted: every row goes with the account, and no guard stands in the way.
  await run({ ...ray.ctx, fresh: true }, (tx) => tx`select * from app.delete_account()`);
  assert.strictEqual(Number(await count()), 0);
  // Banned: a member's agents leave the public lists (as a ban hides their posts), and come back when unbanned.
  const tia = await member('Tia');
  const ag2 = await newAgent(tia, 'Banned one');
  await eng('POST', 'finding', { cookie: aaron.cookie, json: { agent: ag2.id, room: '31-0000', class: 'ASI03', succeeded: true, vaccine: 'another vaccine test' } });
  assert.ok((await summary()).licenses.some((x) => x.agent.id === ag2.id));
  await run({ ...aaron.ctx, note: 'a test ban' }, (tx) => tx`update app.members set status = 'banned' where id = ${tia.id}`);
  assert.ok(!JSON.stringify(await summary()).includes(ag2.id), 'no trace of the banned member\u2019s agent');
  assert.strictEqual((await eng('GET', 'agent', { search: '?id=' + ag2.id })).status, 404);
  await run({ ...aaron.ctx, note: 'a test unban' }, (tx) => tx`update app.members set status = 'active' where id = ${tia.id}`);
  assert.ok((await summary()).licenses.some((x) => x.agent.id === ag2.id));
});

test('the public answer hides contact details and keys in what people wrote, and says it is untrusted', async () => {
  const r = await eng('POST', 'precedent', { cookie: aaron.cookie, json: { room: '43-0000', facts: 'Call 415 555 0100 about the invoice batch.', decision: 'Hold for a person', reason: 'Invoices go to a person every time.' } });
  assert.strictEqual(r.status, 201);
  const s = await summary();
  const p = s.precedents.find((x) => x.id === r.json.precedent);
  assert.doesNotMatch(p.facts, /415 555 0100/);
  assert.match(s.untrusted, /written by members of the public/);
});
