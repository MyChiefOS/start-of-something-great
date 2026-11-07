// 050, project plans: milestones with target dates for every project, and planned against verified work, filled in by
// themselves as tasks are posted and approved (Aaron, Nov 7: "the system should auto populate as more data comes in on
// this project and as new projects join"). Through the real handler (api/work.js), against a Postgres built from the
// migrations. Needs TEST_DATABASE_URL (skipped without it, required in CI).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');
const { promote, shadowMode, asSignin } = require('./helpers');

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('plan tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('project plans against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const ORIGIN = 'https://dayonegreat.com';
const NAME = 'dog_plan_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); });
const asWork = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_work'); return t.unsafe(sql); });
const day = (offset) => new Date(Date.now() + offset * 86400000).toISOString().slice(0, 10);

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
  // Everything up to entry 1000 is in a signed checkpoint.
  await q(`insert into app.log_checkpoints (size, root, note, signature) values (1000, decode(repeat('ab', 32), 'hex'), 'test', decode(repeat('cd', 64), 'hex'))`);
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(name, { admin = false } = {}) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  if (admin) await asOwner(`update app.members set is_admin = true where id = '${out.memberId}'`);
  return { id: out.memberId, name, cookie: '__Host-dog_session=' + token };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
let ip = 1;
async function work(method, route, { cookie = '', json, search = '' } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '198.51.100.' + (ip++ % 250), 'x-vercel-ip-country': 'US' };
  if (method === 'POST' && cookie) headers.origin = ORIGIN;
  if (json !== undefined) headers['content-type'] = 'application/json';
  const params = Object.fromEntries(new URLSearchParams(search.replace(/^\?/, '')));
  const r = res();
  await require('../api/work.js').handle({ method, url: '/api/work/' + route + search, headers, query: { route, ...params }, body: json !== undefined ? JSON.stringify(json) : undefined }, r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
// An agent of the member's, made through the real agents API (only a signed-in owner makes one).
async function agentOf(owner) {
  const headers = { host: 'dayonegreat.com', cookie: owner.cookie, origin: ORIGIN, 'content-type': 'application/json', 'x-vercel-forwarded-for': '198.51.100.' + (ip++ % 250), 'x-vercel-ip-country': 'US' };
  const r = res();
  await require('../api/agents.js').handle({ method: 'POST', url: '/api/agents/', headers, query: { route: '' }, body: JSON.stringify({ name: owner.name + ' agent', post: 'act' }) }, r, run, { ipKey: crypto.randomBytes(32) });
  assert.strictEqual(r.statusCode, 201, r.body);
  return JSON.parse(r.body).agent_id;
}
async function project(owner, title) {
  const r = await work('POST', 'projects', { cookie: owner.cookie, json: { title, description: 'About ' + title, room: '27-0000' } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return r.json.id;
}
// A task posted on a given day; approved on a given day, with its approval entry inside the signed checkpoint, or not.
async function task(pj, owner, { size, posted, approved = null, seq = 5 }) {
  const [r] = await q(`select id from app.work_rooms where code = '27-0000'`);
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, status, created_at, approved_at, approved_seq)
    values ('${pj}', '${r.id}', 'Task of size ${size}', 'either', ${size}, 'member', '${owner.id}', '${approved ? 'approved' : 'open'}',
            '${posted}T12:00:00Z', ${approved ? `'${approved}T12:00:00Z'` : 'null'}, ${approved ? seq : 'null'}) returning id`);
  return t.id;
}
const plan = async (pj) => (await work('GET', 'plan', { search: '?project=' + pj })).json;

test('tasks fall into milestones by the day they were posted, and the plan, the figures and the forecast follow by themselves', async () => {
  const ann = await member('Ann');
  const pj = await project(ann, 'A plan that fills itself');
  const m1 = await work('POST', 'milestones', { cookie: ann.cookie, json: { project: pj, title: 'First cut', target: day(-10) } });
  assert.strictEqual(m1.status, 201, JSON.stringify(m1.json));
  assert.deepStrictEqual([m1.json.milestone.code, m1.json.milestone.target, m1.json.milestone.first_target, m1.json.milestone.moved], ['M1', day(-10), day(-10), false]);
  const m2 = await work('POST', 'milestones', { cookie: ann.cookie, json: { project: pj, title: 'Release', target: day(10), gate: true } });
  assert.strictEqual(m2.json.milestone.code, 'M2');
  // No tasks yet: a plan with nothing in it.
  let p = await plan(pj);
  assert.deepStrictEqual([p.figures.scope, p.figures.planned, p.figures.verified, p.figures.index, p.figures.forecast], [0, 0, 0, null, null]);
  await task(pj, ann, { size: 3, posted: day(-20), approved: day(-12) });     // M1, verified on time
  await task(pj, ann, { size: 5, posted: day(-15) });                          // M1, overdue
  await task(pj, ann, { size: 8, posted: day(-3), approved: day(-2) });       // M2, verified this week
  await task(pj, ann, { size: 1, posted: day(0) });                            // M2
  await task(pj, ann, { size: 2, posted: day(-1), approved: day(-1), seq: 5000 }); // M2: approved, but not yet in a signed checkpoint
  p = await plan(pj);
  assert.deepStrictEqual(p.milestones.map((m) => [m.code, m.tasks, m.size, m.done_size, m.share, m.gate]),
    [['M1', 2, 8, 3, 0.375, false], ['M2', 3, 11, 8, 0.7273, true]]);
  const f = p.figures;
  assert.deepStrictEqual([f.scope, f.planned, f.verified, f.variance, f.index, f.left, f.unplanned, f.tasks, f.tasks_done], [19, 8, 11, 3, 1.38, 8, 0, 5, 2]);
  // The pace of the last seven days is 8 a week; 8 left at 8/7 a day is 7 days: the forecast is 7 days from today, 3
  // before the gate.
  assert.deepStrictEqual([f.pace, f.forecast, f.gate, f.days_to_gate, f.slip_days, f.need], [1.14, day(7), day(10), 10, -3, 0.8]);
  // Day by day: scope as posted, planned as targets come due, verified up to today only.
  const on = (d) => p.days.find((x) => x.day === d);
  assert.deepStrictEqual(on(day(-11)), { day: day(-11), scope: 8, planned: 0, verified: 3 });
  assert.deepStrictEqual(on(day(-10)), { day: day(-10), scope: 8, planned: 8, verified: 3 });
  assert.deepStrictEqual(on(day(0)), { day: day(0), scope: 19, planned: 8, verified: 11 });
  assert.deepStrictEqual(on(day(10)), { day: day(10), scope: 19, planned: 19, verified: null });
  assert.strictEqual(p.days[p.days.length - 1].day, day(17), 'a week past the gate');
  // A task posted after the last target is unplanned until a later milestone takes it.
  const late = await q(`select id from app.work_rooms where code = '27-0000'`);
  await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, created_at)
    values ('${pj}', '${late[0].id}', 'After the plan', 'either', 2, 'member', '${ann.id}', now() + interval '11 days')`);
  p = await plan(pj);
  assert.strictEqual(p.figures.unplanned, 2);
  const m3 = await work('POST', 'milestones', { cookie: ann.cookie, json: { project: pj, title: 'Follow-up', target: day(30) } });
  assert.strictEqual(m3.status, 201);
  p = await plan(pj);
  assert.deepStrictEqual([p.figures.unplanned, p.milestones[2].size], [0, 2]);
});

test('moving a target keeps the first one beside it; only the poster (or an administrator) plans a project', async () => {
  const bo = await member('Bo');
  const cy = await member('Cy');
  const pj = await project(bo, 'Who plans this');
  const m = (await work('POST', 'milestones', { cookie: bo.cookie, json: { project: pj, title: 'Beta', target: day(-5) } })).json.milestone;
  await task(pj, bo, { size: 8, posted: day(-9) });
  const before = await plan(pj);
  assert.deepStrictEqual([before.figures.planned, before.figures.index], [8, 0]);
  const moved = await work('POST', 'reschedule', { cookie: bo.cookie, json: { milestone: m.id, target: day(12) } });
  assert.strictEqual(moved.status, 200, JSON.stringify(moved.json));
  assert.deepStrictEqual([moved.json.milestone.target, moved.json.milestone.first_target, moved.json.milestone.moved], [day(12), day(-5), true]);
  // Moving a date never rewrites the plan: planned, the index and the day's planned line stay on the first target.
  const after = await plan(pj);
  assert.deepStrictEqual([after.figures.planned, after.figures.index, after.days.find((d) => d.day === day(-5)).planned], [8, 0, 8]);
  assert.deepStrictEqual([after.figures.gate, after.figures.gate_target], [day(-5), day(12)]);
  // Someone else can't add or move; an administrator can.
  assert.strictEqual((await work('POST', 'milestones', { cookie: cy.cookie, json: { project: pj, title: 'Mine now', target: day(3) } })).status, 403);
  assert.strictEqual((await work('POST', 'reschedule', { cookie: cy.cookie, json: { milestone: m.id, target: day(1) } })).status, 403);
  assert.strictEqual((await work('POST', 'reschedule', { cookie: aaron.cookie, json: { milestone: m.id, target: day(14) } })).status, 200);
  assert.strictEqual((await work('POST', 'milestones', { cookie: '', json: { project: pj, title: 'Anon', target: day(3) } })).status, 403, 'a write from no one is refused');
  // Bad input: the date's form, its range, the title, a second gate, more than 12.
  for (const json of [{ project: pj, title: 'Bad date', target: '2026-13-01' }, { project: pj, title: 'No such day', target: '2026-02-31' }, { project: pj, title: 'Far', target: day(800) },
    { project: pj, title: 'x', target: day(3) }, { project: pj, title: 'Gate?', target: day(3), gate: 'yes' }]) {
    assert.strictEqual((await work('POST', 'milestones', { cookie: bo.cookie, json })).status, 400, JSON.stringify(json));
  }
  const g1 = (await work('POST', 'milestones', { cookie: bo.cookie, json: { project: pj, title: 'Gate one, mail bo@example.org', target: day(20), gate: true } }));
  assert.strictEqual(g1.status, 201);
  assert.strictEqual(g1.json.milestone.title, 'Gate one, mail [email hidden]', 'a title is public words: contact details hidden');
  assert.strictEqual((await work('POST', 'milestones', { cookie: bo.cookie, json: { project: pj, title: 'Gate two', target: day(21), gate: true } })).status, 409);
  // A project an agent posted is planned by the agent's owner, and nobody else; one whose poster is gone, by an
  // administrator only (the fresh review of Nov 7: a stranger got through when the poster column was empty).
  const ag = { id: await agentOf(bo) };
  const [rm] = await q(`select id from app.work_rooms where code = '27-0000'`);
  const [byAgent] = await q(`insert into app.work_projects (title, room_id, source, poster_agent) values ('Posted by an agent', '${rm.id}', 'member', '${ag.id}') returning id`);
  const [orphan] = await q(`insert into app.work_projects (title, room_id, source) values ('Its poster left', '${rm.id}', 'member') returning id`);
  for (const p2 of [byAgent.id, orphan.id]) {
    assert.strictEqual((await work('POST', 'milestones', { cookie: cy.cookie, json: { project: p2, title: 'Not mine', target: day(3) } })).status, 403, p2);
  }
  assert.strictEqual((await work('POST', 'milestones', { cookie: bo.cookie, json: { project: byAgent.id, title: 'My agent posted it', target: day(3) } })).status, 201);
  assert.strictEqual((await work('POST', 'milestones', { cookie: bo.cookie, json: { project: orphan.id, title: 'Not mine either', target: day(3) } })).status, 403);
  assert.strictEqual((await work('POST', 'milestones', { cookie: aaron.cookie, json: { project: orphan.id, title: 'An administrator', target: day(3) } })).status, 201);
  for (let i = 3; i <= 12; i++) assert.strictEqual((await work('POST', 'milestones', { cookie: bo.cookie, json: { project: pj, title: 'Step ' + i, target: day(i) } })).status, 201);
  assert.strictEqual((await work('POST', 'milestones', { cookie: bo.cookie, json: { project: pj, title: 'Step 13', target: day(13) } })).status, 429);
});

test('the site\'s own build gets ROADMAP.md\'s milestones once; only an administrator plans it; the Build page features a planned project', async () => {
  const [r] = await q(`select id from app.work_rooms where code = '15-0000'`);
  const [pj] = await asWork(`insert into app.work_projects (title, room_id, source, github_milestone) values ('The site''s own build', '${r.id}', 'github', 0) returning id`);
  assert.strictEqual((await asWork('select app.work_roadmap_milestones() as n'))[0].n, 3);
  assert.strictEqual((await asWork('select app.work_roadmap_milestones() as n'))[0].n, 0, 'running it again adds nothing');
  const p = await plan(pj.id);
  assert.deepStrictEqual(p.milestones.map((m) => [m.code, m.title, m.target, m.gate]), [
    ['M1', 'Release 1: proposals', '2026-10-16', false], ['M2', 'Release 2\'s checks, notices, sign-in fixes and sub-agents', '2026-11-06', false],
    ['M3', 'Release 2 public: every role working', '2026-11-20', true]]);
  const dee = await member('Dee');
  assert.strictEqual((await work('POST', 'milestones', { cookie: dee.cookie, json: { project: pj.id, title: 'Mine', target: day(3) } })).status, 403);
  // A merged pull request's changes, as GitHub publishes them.
  await asWork(`insert into app.work_github_prs (number, title, author, state, merged_at, base, merge_sha, created_at, additions, deletions, merged_by)
    values (115, 'Looks live', 'mychiefos', 'closed', now(), 'main', '${'a'.repeat(40)}', now() - interval '1 hour', 412, 38, 'mychiefos')`);
  const ch = (await su.begin(async (t) => { await t.unsafe('set local role dog_app'); return t.unsafe('select app.work_pr_changes(115) as c'); }))[0].c;
  assert.deepStrictEqual([ch.additions, ch.deletions, ch.merge_sha, ch.merged_by], [412, 38, 'a'.repeat(40), 'mychiefos']);
  // The summary carries the featured project's plan: with no project given, the plan read is the same one.
  const s = (await work('GET', 'summary')).json;
  const featured = (await work('GET', 'plan')).json;
  assert.ok(s.plan && s.plan.project && s.plan.project.id === featured.project.id);
  assert.strictEqual(featured.project.id, pj.id, 'the Build page features this repository\'s own build, which no member can take over');
  assert.strictEqual(ch.base, 'main');
  assert.strictEqual((await work('GET', 'plan', { search: '?project=nope' })).status, 400);
});
