// 051, the administrator's console: six tabs of the work module, for administrators only, every read logged by the
// database itself. Through the real handler (api/work.js), against a Postgres built from the migrations. Needs
// TEST_DATABASE_URL (skipped without it, required in CI).
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
  if (process.env.CI) test('console tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the console against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const ORIGIN = 'https://dayonegreat.com';
const NAME = 'dog_console_test_' + crypto.randomBytes(4).toString('hex');
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

const audit = async () => (await q(`select detail->>'tab' as tab from app.audit_log where action = 'console.read' order by at, id`)).map((r) => r.tab);

test('an administrator reads each tab, and every read is in the audit log; nobody else reads any', async () => {
  const ann = await member('Ann');
  const pj = await project(ann, 'Console test project');
  await task(pj, ann, { size: 3, posted: day(-3), approved: day(-1) });
  await task(pj, ann, { size: 5, posted: day(-2) });
  const before = (await audit()).length;
  const tabs = {};
  for (const tab of ['summary', 'agents', 'projects', 'submissions', 'ledger', 'admins']) {
    const r = await work('GET', 'console', { cookie: aaron.cookie, search: '?tab=' + tab });
    assert.strictEqual(r.status, 200, tab + ' ' + JSON.stringify(r.json));
    assert.strictEqual(r.json.tab, tab);
    tabs[tab] = r.json;
  }
  assert.deepStrictEqual((await audit()).slice(before), ['summary', 'agents', 'projects', 'submissions', 'ledger', 'admins'], 'one audit row a read');
  // The summary: the tasks by status, and the ledger's check.
  assert.deepStrictEqual([tabs.summary.tasks.open, tabs.summary.tasks.approved], [1, 1]);
  assert.strictEqual(tabs.summary.ledger.log_size, 1000);
  assert.strictEqual(tabs.summary.ledger.intact, true, JSON.stringify(tabs.summary.ledger));
  // Projects: the tasks, newest first, filtered by status.
  assert.strictEqual(tabs.projects.tasks.length, 2);
  const open = (await work('GET', 'console', { cookie: aaron.cookie, search: '?tab=projects&status=open' })).json;
  assert.deepStrictEqual(open.tasks.map((t) => t.status), ['open']);
  assert.strictEqual(open.tasks[0].poster.name, 'Ann');
  // Ledger: the latest checkpoints. Admins: the one administrator, and the console reads in the activity log.
  assert.deepStrictEqual(tabs.ledger.checkpoints.map((c) => c.size), [1000]);
  assert.deepStrictEqual(tabs.admins.admins.map((a) => a.name), ['Aaron']);
  assert.strictEqual(tabs.admins.one_admin, true);
  assert.ok(tabs.admins.activity.some((a) => a.action === 'console.read' && a.detail.tab === 'ledger'), 'its own reads show');
  // Anyone else: a member is refused, and so is a visitor; their attempts write nothing.
  const n = (await audit()).length;
  assert.strictEqual((await work('GET', 'console', { cookie: ann.cookie, search: '?tab=summary' })).status, 403);
  assert.strictEqual((await work('GET', 'console', { search: '?tab=summary' })).status, 401);
  assert.strictEqual((await audit()).length, n, 'a refused read writes no audit row');
  // Bad input: an unknown tab or status, an unknown key, a bad time.
  for (const search of ['?tab=secrets', '?tab=projects&status=everything', '?tab=summary&x=1', '?tab=agents&before=2026-11-01T00:00:00Z',
    '?tab=agents&cursor=yesterday', '?tab=agents&cursor=' + encodeURIComponent('2026-02-31T10:00:00Z~' + aaron.id), '?tab=agents&cursor=' + encodeURIComponent('2026-19-99T99:99Z~' + aaron.id)]) {
    assert.strictEqual((await work('GET', 'console', { cookie: aaron.cookie, search })).status, 400, search);
  }
});

test('the ledger check says when the points ledger and the points disagree', async () => {
  const bo = await member('Bo');
  const pj = await project(bo, 'Ledger check');
  const tk = await task(pj, bo, { size: 2, posted: day(-1) });
  const [rm] = await q(`select room_id from app.work_tasks where id = '${tk}'`);
  // A points row written with its ledger trigger off, as 048's backfill found production: no entries for it.
  await q('alter table app.work_points disable trigger work_points_ledger');
  try {
    const [sb] = await q(`insert into app.work_submissions (task_id, worker_kind, worker_member, artifact_kind, artifact_url, status, seal_key, seal)
      values ('${tk}', 'member', '${bo.id}', 'link', 'https://example.org/x', 'passed', decode(repeat('ab', 32), 'hex'), repeat('a', 64)) returning id`);
    await q(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, size, confidence, independence, points, status, final_at)
      values ('${sb.id}', '${tk}', '${rm.room_id}', 'member', '${bo.id}', 2, 90, 100, 20, 'pending', now() + interval '3 days')`);
  } finally { await q('alter table app.work_points enable always trigger work_points_ledger'); }
  const l = (await work('GET', 'console', { cookie: aaron.cookie, search: '?tab=ledger' })).json.integrity;
  assert.deepStrictEqual([l.intact, l.rows_without_entries], [false, 1]);
});

test('the database itself refuses anyone but an administrator, and writes nothing for them', async () => {
  const n = (await audit()).length;
  for (const role of ['dog_app', 'dog_work']) {
    await assert.rejects(su.begin(async (t) => { await t.unsafe('set local role ' + role); await t.unsafe(`select app.work_console('summary', null, null)`); }),
      (e) => e.code === '42501' || e.code === '42883' || /permission denied|only an administrator/.test(e.message), role);
  }
  // Nor can the work module's role read the audit log, or write a console read, when no administrator is acting.
  assert.strictEqual((await asWork('select count(*)::int as n from app.audit_log'))[0].n, 0);
  await assert.rejects(asWork(`insert into app.audit_log (action, detail) values ('console.read', '{}')`), /row-level security|violates/);
  assert.strictEqual((await audit()).length, n);
});

test('the ledger check reads every points row: two errors that cancel out in the totals are still found, and so is the wrong citizen', async () => {
  const cy = await member('Cy');
  const pj = await project(cy, 'Cancelling errors');
  const base = (await work('GET', 'console', { cookie: aaron.cookie, search: '?tab=ledger' })).json.integrity;
  // A row of points, with ledger rows written by hand (the ledger's trigger off), for a task of its own.
  async function points(status, pts, entries, citizen = cy.id) {
    const tk = await task(pj, cy, { size: 2, posted: day(-1) });
    const [rm] = await q(`select room_id from app.work_tasks where id = '${tk}'`);
    await q('alter table app.work_points disable trigger work_points_ledger');
    try {
      const [sb] = await q(`insert into app.work_submissions (task_id, worker_kind, worker_member, artifact_kind, artifact_url, status, seal_key, seal)
        values ('${tk}', 'member', '${cy.id}', 'link', 'https://example.org/x', 'passed', decode(repeat('ab', 32), 'hex'), repeat('a', 64)) returning id`);
      const [p] = await q(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, size, confidence, independence, points, status, final_at)
        values ('${sb.id}', '${tk}', '${rm.room_id}', 'member', '${cy.id}', 2, 90, 100, ${pts}, '${status}', now() + interval '3 days') returning id`);
      for (const [kind, bucket, amount] of entries) {
        await q(`insert into app.work_point_entries (points_id, submission_id, citizen_kind, citizen_member, room_id, kind, bucket, amount)
          values ('${p.id}', '${sb.id}', 'member', '${citizen}', '${rm.room_id}', '${kind}', '${bucket}', ${amount})`);
      }
    } finally { await q('alter table app.work_points enable always trigger work_points_ledger'); }
  }
  // Pending points whose ledger says final, and final points whose ledger says pending: the totals still match.
  await points('pending', 10, [['earned', 'pending', 10], ['final', 'pending', -10], ['final', 'final', 10]]);
  await points('final', 10, [['earned', 'pending', 10]]);
  let l = (await work('GET', 'console', { cookie: aaron.cookie, search: '?tab=ledger' })).json.integrity;
  assert.strictEqual(l.pending_balance - base.pending_balance, l.pending_points - base.pending_points, 'the totals agree');
  assert.strictEqual(l.final_balance - base.final_balance, l.final_points - base.final_points, 'the totals agree');
  assert.deepStrictEqual([l.intact, l.rows_wrong - base.rows_wrong], [false, 2]);
  // Right amounts, but credited to someone else.
  await points('pending', 4, [['earned', 'pending', 4]], aaron.id);
  l = (await work('GET', 'console', { cookie: aaron.cookie, search: '?tab=ledger' })).json.integrity;
  assert.strictEqual(l.rows_wrong - base.rows_wrong, 3);
});

test('every list pages by time and id: rows that share a time are neither skipped nor shown twice at a page\'s edge', async () => {
  const di = await member('Di');
  const pj = await project(di, 'Paging');
  const [r] = await q(`select id from app.work_rooms where code = '27-0000'`);
  await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member, status)
    select '${pj}', '${r.id}', 'Paged task ' || g, 'either', 1, 'member', '${di.id}', 'open' from generate_series(1, 130) g`);
  await q(`update app.work_tasks set updated_at = '2026-11-01T00:00:00Z' where project_id = '${pj}'`);
  const all = (await q(`select count(*)::int as n from app.work_tasks where status = 'open'`))[0].n;
  const seen = [];
  let cursor = null, pages = 0;
  do {
    const r2 = await work('GET', 'console', { cookie: aaron.cookie, search: '?tab=projects&status=open' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : '') });
    assert.strictEqual(r2.status, 200, JSON.stringify(r2.json));
    seen.push(...r2.json.tasks.map((t) => t.id));
    cursor = r2.json.next; pages++;
  } while (cursor && pages < 10);
  assert.strictEqual(pages, Math.ceil(all / 100));
  assert.strictEqual(seen.length, all, 'every open task, once');
  assert.strictEqual(new Set(seen).size, all, 'none twice');
  const [pg] = await q(`select count(*)::int as n from app.audit_log where action = 'console.read' and detail->>'page' = 'true'`);
  assert.ok(pg.n >= 1, 'a page past the first is logged as one');
});

test('the admins tab lists the sign-in alerts Aaron\'s rules for wrong tries raise (Oct 28, Nov 5, and 053\'s lock, Nov 8), and only those', async () => {
  const eve = await member('EveSignin');
  const alert = (key, title) => q(`insert into app.notices (member_id, kind, title, body, link, subject_kind, subject_id, dedupe_key)
    values (null, 'alert', '${title}', 'x', '/controls', 'member', '${eve.id}', '${key}')`);
  await alert('watch:paused:' + crypto.randomUUID() + ':202611080101', 'Key-file sign-in paused for one account');
  await alert('watch:pin5:browser:' + crypto.randomUUID() + ':20261108', 'Wrong PINs for one account');
  await alert('watch:cancelled:' + crypto.randomUUID(), 'A member\'\'s key file was cancelled');
  await alert('watch:locked:' + eve.id + ':202611080102', 'Sign-in locked for one account'); // 053's lock after 3 failures
  await alert('watch:travel:' + crypto.randomUUID(), 'Travel too fast to be possible'); // another kind of alert: not shown
  const a = (await work('GET', 'console', { cookie: aaron.cookie, search: '?tab=admins' })).json;
  assert.deepStrictEqual(a.signin.map((x) => x.what).sort(), ['A member\'s key file was cancelled', 'Key-file sign-in paused for one account', 'Sign-in locked for one account', 'Wrong PINs for one account']);
  assert.ok(a.signin.every((x) => x.member === 'EveSignin'));
  // Nobody else reads them, and the work module's role sees none without an administrator acting.
  assert.strictEqual((await work('GET', 'console', { cookie: eve.cookie, search: '?tab=admins' })).status, 403);
  assert.strictEqual((await asWork(`select count(*)::int as n from app.notices`))[0].n, 0);
});
