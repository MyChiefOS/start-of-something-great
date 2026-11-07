// 045, the leaderboard and citizen profiles (CODING_AGENT_SPEC.md 4.1, 4.2, 4.4, 4.5, 4.6), against a real Postgres
// built from the migrations:
//   - six dimensions per citizen, each with its sample size; every rate with a Wilson 95% interval, never without n;
//   - impact: final points with a 30-day half-life, with all-time, season and pending beside it;
//   - bands, not ranks: provisional under 10 audited items, an exact place only in the top 10;
//   - a citizen's profile: the receipt chain with its log entries; a new member is provisional, not zero;
//   - From my network: a ring of 20 accounts passing each other's work gets no weight from an honest viewer (4.6);
//     trust halves at each hop and stops after 3; two citizens of one owner never make an edge.
// Needs TEST_DATABASE_URL (skipped without it, required in CI).
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
  if (process.env.CI) test('leaderboard tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the leaderboard against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_lb_test_' + crypto.randomBytes(4).toString('hex');
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
  await shadowMode(su);
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe('update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000'); });
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

function res() {
  const r = { statusCode: 200, headers: {}, body: '' };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.end = (b) => { r.body = b || ''; };
  return r;
}
async function member(name) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token };
}
async function work(route, { cookie = '', search = '' } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '198.51.100.' + crypto.randomInt(1, 250), 'x-vercel-ip-country': 'US' };
  const r = res();
  const query = { route };
  for (const [k, v] of new URLSearchParams(search)) query[k] = v;
  await require('../api/work.js').handle({ method: 'GET', url: '/api/work/' + route + search, headers, query }, r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
const room = async (code) => (await q(`select id from app.work_rooms where code = '${code}'`))[0].id;
let ghn = 5000;

// One audited item: a task posted by `poster` ({member} or {agent} or null for this repository), done by `worker`
// ({member}, {agent, owner} or {github}), decided by `by`, with points `pts` (final or pending) `age` days ago.
async function item({ poster = null, worker, code = '15-0000', by = 'jevs', status = 'passed', pts = 10, final = true, age = 0, vote = null }) {
  const rid = await room(code);
  const pm = poster && poster.member ? `'${poster.member}'` : 'null';
  const pa = poster && poster.agent ? `'${poster.agent}'` : 'null';
  const gh = !poster;
  const [pj] = await q(`insert into app.work_projects (title, room_id, source, poster_member, poster_agent${gh ? ', github_milestone' : ''}) values ('P', '${rid}', '${gh ? 'github' : 'member'}', ${pm}, ${pa}${gh ? ', ' + (ghn++) : ''}) returning id`);
  const [tk] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, poster_agent${gh ? ', github_kind, github_number' : ''}, status)
    values ('${pj.id}', '${rid}', 'Task', 'either', 2, '${gh ? 'github' : 'member'}', ${pm}, ${pa}${gh ? ", 'pr', " + (ghn++) : ''}, 'approved') returning id`);
  const wk = worker.github ? 'github' : worker.agent ? 'agent' : 'member';
  const wm = worker.github ? 'null' : `'${worker.owner || worker.member}'`;
  const [sb] = await q(`insert into app.work_submissions (task_id, worker_kind, worker_member, worker_agent, worker_github, artifact_kind, artifact_url, seal_key, seal, status, decided_by, decided_at, confidence, decided_seq)
    values ('${tk.id}', '${wk}', ${wm}, ${worker.agent ? `'${worker.agent}'` : 'null'}, ${worker.github ? `'${worker.github}'` : 'null'}, 'link', 'https://example.org/w',
            decode(repeat('ab', 32), 'hex'), repeat('d', 64), '${status}', '${by}', now() - interval '${age} days', 100, 7) returning id`);
  if (vote) await q(`insert into app.work_person_votes (submission_id, member_id, verdict, reason) values ('${sb.id}', '${vote}', 'pass', 'Looks right')`);
  if (status !== 'failed') {
    await q(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, citizen_agent, citizen_github, size, confidence, independence, points, status, created_at, final_at)
      values ('${sb.id}', '${tk.id}', '${rid}', '${wk}', ${worker.github || worker.agent ? 'null' : `'${worker.member}'`}, ${worker.agent ? `'${worker.agent}'` : 'null'}, ${worker.github ? `'${worker.github}'` : 'null'},
              2, 100, 100, ${pts}, '${status === 'reversed' ? 'removed' : final ? 'final' : 'pending'}', now() - interval '${age} days', now() - interval '${age} days' + interval '3 days')`);
  }
  return { task: tk.id, submission: sb.id };
}
const find = (list, ref) => list.find((x) => x.id === ref || x.github === ref);

test('Wilson 95% intervals, and no rate without its sample size', async () => {
  const [r] = await q(`select app.work_wilson(8, 10) as a, app.work_wilson(0, 0) as b, app.work_wilson(10, 10) as c`);
  assert.deepStrictEqual([r.a.rate, r.a.lo, r.a.hi], [0.8, 0.4902, 0.9433]);
  assert.deepStrictEqual(r.b, { k: 0, n: 0, rate: null, lo: null, hi: null });
  assert.deepStrictEqual([r.c.rate, r.c.hi], [1, 1]);
  assert.ok(r.c.lo < 1, 'a perfect record of 10 still has an interval');
});

test('impact: final points with a 30-day half-life; pending, all-time and season beside it', async () => {
  const ada = await member('AdaLB');
  await item({ worker: { member: ada.id }, pts: 40, age: 30 });   // half weight
  await item({ worker: { member: ada.id }, pts: 10, age: 0 });    // full weight
  await item({ worker: { member: ada.id }, pts: 8, final: false }); // pending: not in impact yet
  const r = await work('board', { search: '?kind=people' });
  assert.strictEqual(r.status, 200);
  const a = find(r.json.citizens, ada.id);
  assert.ok(Math.abs(a.impact.score - 30) < 0.05, 'a 30-day-old 40 counts 20, today’s 10 counts 10: ' + a.impact.score);
  assert.deepStrictEqual([a.impact.pending, a.impact.all_time, a.impact.n, a.band], [8, 50, 3, 'provisional']);
  assert.strictEqual(a.place, null, 'a provisional citizen has no place');
  assert.strictEqual(r.json.half_life_days, 30);
  for (const c of r.json.citizens) for (const k of ['calibration', 'reliability', 'revert']) assert.ok(Number.isInteger(c[k].n), 'every rate carries its n');
});

test('bands: provisional under 10 audited items; a place only in the top 10; rates sort by their cautious end', async () => {
  const people = [];
  for (let i = 0; i < 12; i++) {
    const m = await member('Est' + i);
    for (let j = 0; j < 10; j++) await item({ worker: { member: m.id }, pts: 1 + i, code: '17-0000' });
    people.push(m);
  }
  const r = await work('board', { search: '?room=17-0000' });
  assert.strictEqual(r.status, 200);
  const list = r.json.citizens;
  assert.strictEqual(list.length, 12, 'only citizens with work in the room');
  assert.strictEqual(list[0].id, people[11].id);
  assert.deepStrictEqual(list.map((x) => x.place), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, null, null]);
  assert.strictEqual(list[0].band, 'top10');
  assert.ok(list.slice(-2).every((x) => x.band === 'established'));
  assert.strictEqual(list[3].band, 'strong');
  // A revert-rate board puts the cautious end first: 1 reversed in 10 sorts after 0 in 10.
  const bad = people[0];
  await item({ worker: { member: bad.id }, status: 'reversed', code: '17-0000' });
  const rv = (await work('board', { search: '?room=17-0000&sort=revert' })).json.citizens;
  assert.strictEqual(rv[rv.length - 1].id, bad.id);
  assert.deepStrictEqual([rv[rv.length - 1].revert.k, rv[rv.length - 1].revert.n], [1, 11]);
  for (const bad2 of ['?sort=overall', '?kind=bots', '?room=99', '?x=1']) assert.strictEqual((await work('board', { search: bad2 })).status, 400, bad2);
});

test('calibration, reliability and disputes; the auditors board; the integrity panel', async () => {
  const pat = await member('PatLB');
  const wes = await member('WesLB');
  // Pat passed two pieces of Wes's work as the poster: one held, one was reversed.
  await item({ poster: { member: pat.id }, worker: { member: wes.id }, by: 'poster', vote: pat.id });
  await item({ poster: { member: pat.id }, worker: { member: wes.id }, by: 'poster', vote: pat.id, status: 'reversed' });
  // Wes passed Pat's work as its poster: a reciprocal pair.
  await item({ poster: { member: wes.id }, worker: { member: pat.id }, by: 'poster', vote: wes.id, final: false });
  const aud = (await work('board', { search: '?kind=auditors' })).json;
  const p = find(aud.citizens, pat.id);
  assert.deepStrictEqual([p.calibration.k, p.calibration.n], [1, 2]);
  assert.ok(!find(aud.citizens, wes.id), 'a pass still pending hasn’t settled, so Wes isn’t scored yet');
  assert.ok(aud.integrity.reciprocal_pairs >= 1);
  assert.ok(aud.integrity.passes_reversed >= 1);
  // Reliability: one claim done, one expired.
  const [tk] = await q(`select id from app.work_tasks limit 1`);
  await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at, status, ended_at) values ('${tk.id}', '${wes.id}', repeat('e', 64), now(), 'done', now()), ('${tk.id}', '${wes.id}', repeat('f', 64), now(), 'expired', now())`);
  const w = find((await work('board')).json.citizens, wes.id);
  assert.deepStrictEqual([w.reliability.k, w.reliability.n], [1, 2]);
  assert.deepStrictEqual([w.revert.k, w.revert.n], [1, 2]);
});

test('a citizen’s profile: the receipt chain with its log entries; a new member is provisional, not zero; GitHub credit', async () => {
  const kim = await member('KimLB');
  const it = await item({ worker: { member: kim.id }, pts: 12 });
  const r = await work('citizen', { search: '?kind=member&ref=' + kim.id });
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual([r.json.name, r.json.kind, r.json.band, r.json.receipts.length], ['KimLB', 'member', 'provisional', 1]);
  assert.deepStrictEqual([r.json.receipts[0].submission, r.json.receipts[0].seq, r.json.receipts[0].points.points], [it.submission, 7, 12]);
  assert.strictEqual(r.json.rooms[0].code, '15-0000');
  const fresh = await member('FreshLB');
  const f = await work('citizen', { search: '?kind=member&ref=' + fresh.id });
  assert.deepStrictEqual([f.status, f.json.band, f.json.impact.score, f.json.receipts.length], [200, 'provisional', 0, 0]);
  await item({ worker: { github: 'mychiefos' } });
  const g = await work('citizen', { search: '?kind=github&ref=mychiefos' });
  assert.deepStrictEqual([g.status, g.json.name], [200, 'Aaron Chandler and Claude']);
  for (const s of ['?kind=github&ref=nobody-here', '?kind=member&ref=' + crypto.randomUUID(), '?kind=robot&ref=x']) assert.strictEqual((await work('citizen', { search: s })).status, 404, s);
  assert.strictEqual((await work('citizen', { search: '?kind=member' })).status, 400);
});

test('From my network: a ring of 20 gets nothing from an honest viewer; trust halves each hop and stops after 3', async () => {
  const viewer = await member('ViewerLB');
  const chain = [];
  for (let i = 0; i < 4; i++) chain.push(await member('Chain' + i));
  // viewer - chain0 - chain1 - chain2 - chain3: audited collaborations (passed by the rules).
  let prev = viewer;
  for (const m of chain) { await item({ poster: { member: prev.id }, worker: { member: m.id }, by: 'jevs' }); prev = m; }
  // A ring of 20 fake accounts, each passing the next one's work, with plenty of points.
  const ring = [];
  for (let i = 0; i < 20; i++) ring.push(await member('Ring' + i));
  for (let i = 0; i < 20; i++) for (let k = 0; k < 3; k++) await item({ poster: { member: ring[i].id }, worker: { member: ring[(i + 1) % 20].id }, by: 'jevs', pts: 100 });
  // A poster's own pass (no third party) isn't an edge.
  const pal = await member('PalLB');
  await item({ poster: { member: viewer.id }, worker: { member: pal.id }, by: 'poster', vote: viewer.id });
  // Two citizens of one owner never make an edge: the viewer's own agent doing the viewer's task.
  const [ag] = await run({ actor: 'member', memberId: viewer.id, session: c.sha256hex(viewer.cookie.split('=')[1]) }, (t) => t`insert into app.agents (name) values ('Helper') returning id`);
  await item({ poster: { member: viewer.id }, worker: { agent: ag.id, owner: viewer.id }, by: 'jevs' });

  const out = await work('network', { cookie: viewer.cookie });
  assert.strictEqual(out.status, 200);
  const ids = out.json.citizens.map((x) => x.id);
  assert.ok(ring.every((m) => !ids.includes(m.id)), 'the ring gets no weight');
  assert.ok(!ids.includes(pal.id), 'a poster’s own pass is not an audited collaboration');
  assert.deepStrictEqual(ids, [chain[0].id, chain[1].id, chain[2].id], 'three hops, nearest first; the fourth is out of reach');
  const t = out.json.citizens.map((x) => x.trust);
  assert.strictEqual(t[0], 100);
  assert.ok(t[1] < t[0] && t[2] < t[1]);
  // The ring's own members see each other: the rule is about honest viewers.
  const inRing = await work('network', { cookie: ring[0].cookie });
  assert.ok(inRing.json.citizens.length > 0);
  // Signed out: not available.
  assert.strictEqual((await work('network')).status, 401);
});
