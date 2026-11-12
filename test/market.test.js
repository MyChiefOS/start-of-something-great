// 064: funded work on the public pages without public prices (Aaron, Nov 12, 2026), against a real Postgres.
// Signed out: counts and tier badges, never a dollar sum (Aaron, Nov 12, after the fresh review's differencing leak). Signed in: the exact net on
// open tasks. Claimed or later: amounts only for the payer, the payee and the administrator. ACCEPTANCE.md MK1 to MK5.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const work = require('../db/work');
const { migrate } = require('../scripts/migrate');
const { promote, shadowMode, asSignin } = require('./helpers');

const SERVER = process.env.TEST_DATABASE_URL;
const NAME = 'dog_064_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
const ANON = { actor: 'anon' };
let server, su, web, poster, stranger, roomA, roomB, project;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const ctxOf = (m) => ({ actor: 'member', memberId: m.id, session: m.session, fresh: true });
const asPay = (fn) => su.begin(async (t) => { await t.unsafe('set local role dog_pay'); return fn(t); });

let n = 0;
async function member(name) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('gh:' + name + (n++))], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  return { id: out.memberId, name, session: c.sha256hex(token) };
}
// A funded open task of `cents` in a room, as the payment function would leave it.
async function funded(room, cents) {
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member)
    values ('${project}', '${room}', 'Funded', 'either', 1, 'member', '${poster.id}') returning id`);
  await run(ctxOf(poster), (x) => x`select app.bounty_fund_request(${t.id}, ${cents})`);
  const [b] = await q(`select id from app.work_bounties where task_id = '${t.id}'`);
  await asPay((x) => x.unsafe(`update app.work_bounties set status = 'funded', livemode = false, stripe_payment_intent_id = 'pi_${b.id.replace(/-/g, '')}',
    charged_cents = bounty_cents, funded_at = now() where id = '${b.id}'`));
  return t.id;
}

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  poster = await member('Poster');
  stranger = await member('Stranger');
  [{ id: roomA }, { id: roomB }] = await q(`select id from app.work_rooms order by ord limit 2`);
  [{ id: project }] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('P', '${roomA}', 'member', '${poster.id}') returning id`);
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

test('MK1: signed out, nobody reads a bounty’s amount through the site’s role (061 let them); signed in, an open task’s is readable', async () => {
  const id = await funded(roomB, 12345);
  const read = (ctx) => run(ctx, (t) => t`select bounty_cents from app.work_bounties where task_id = ${id}`);
  assert.strictEqual((await read(ANON)).length, 0, 'signed out: no row');
  assert.strictEqual((await read(ctxOf(stranger)))[0].bounty_cents, 12345, 'a signed-in member sees an open task’s');
  assert.strictEqual((await read(ctxOf(poster)))[0].bounty_cents, 12345, 'its payer, always');
});

test('MK2: the public figures are counts and tier badges only, with no dollar sum, so funding or claiming one task never gives its price away', async () => {
  const before = await run(ANON, (t) => work.market(t));
  const dollars = (m) => JSON.stringify(m).match(/"[a-z_]*(?:pool|dollar|cents|amount|price)[a-z_]*"/g);
  assert.strictEqual(dollars(before), null, 'no dollar field at all');
  await funded(roomA, 4321);
  const one = await run(ANON, (t) => work.market(t));
  assert.strictEqual(one.funded_tasks, before.funded_tasks + 1);
  // The fresh review of PR #4 (critical): differencing two reads. What changed is a count in one tier, nothing more:
  // a task's tier is public, so the change can't place its price any closer than its tier.
  const diff = (a, b) => { const out = []; const walk = (x, y, p) => { if (typeof x === 'object' && x && y) { for (const k of new Set([...Object.keys(x), ...Object.keys(y)])) walk(x[k], y[k], p + '.' + k); } else if (x !== y) out.push(p); }; walk(a, b, ''); return out; };
  const changed = diff(before, one).filter((p) => !/^\.rooms\.\d+\.(code|name)$/.test(p));
  assert.ok(changed.every((p) => /funded_tasks$|\.tasks$|\.tiers\.[1-4]$|^\.rooms(\.\d+)?$/.test(p)), 'only counts change: ' + changed.join(', '));
  assert.ok(!/4321|43\.21/.test(JSON.stringify(one)), 'no price anywhere in the figures');
  const roomA1 = one.rooms.find((r) => r.funded_tasks >= 1 && r.tiers['1'] >= 1);
  assert.ok(roomA1, 'the room shows its tier badge: ' + JSON.stringify(one.rooms));
  assert.deepStrictEqual(one.tiers.map((x) => x.label), ['$10 to $100', '$100 to $500', '$500 to $2,500', '$2,500 and up']);
  await funded(roomA, 9999);
  await funded(roomA, 250000);
  const m = await run(ANON, (t) => work.market(t));
  const tiers = Object.fromEntries(m.tiers.map((x) => [x.tier, x.tasks]));
  assert.ok(tiers[1] >= 2 && tiers[4] >= 1, 'tier edges: $99.99 is tier 1, $2,500 tier 4: ' + JSON.stringify(m.tiers));
  assert.strictEqual(dollars(m), null);
  // A claimed task leaves the figures.
  const t4 = await funded(roomA, 50000);
  const withIt = await run(ANON, (t) => work.market(t));
  await q(`update app.work_tasks set status = 'claimed' where id = '${t4}'`);
  const after = await run(ANON, (t) => work.market(t));
  assert.strictEqual(after.funded_tasks, withIt.funded_tasks - 1, 'a claimed task isn’t counted as open funded work');
});

test('MK3: one task’s bounty: signed out its tier; signed in its exact net; claimed, only its parties', async () => {
  const id = await funded(roomB, 20000);
  assert.deepStrictEqual(await run(ANON, (t) => work.bountyOf(t, id)), { tier: 2, status: 'funded' });
  assert.deepStrictEqual(await run(ctxOf(stranger), (t) => work.bountyOf(t, id)), { tier: 2, status: 'funded', net_cents: 17000 }, '$200 less the 15% fee');
  await q(`update app.work_tasks set status = 'claimed' where id = '${id}'`);
  assert.strictEqual(await run(ctxOf(stranger), (t) => work.bountyOf(t, id)), null, 'once claimed, a stranger sees nothing');
  assert.strictEqual(await run(ANON, (t) => work.bountyOf(t, id)), null);
  const mine = await run(ctxOf(poster), (t) => work.bountyOf(t, id));
  assert.strictEqual(mine.bounty_cents, 20000);
  assert.strictEqual(mine.net_cents, 17000);
  assert.strictEqual(await run(ANON, (t) => work.bountyOf(t, crypto.randomUUID())), null, 'no bounty, nothing');
});

test('MK4: the API: /api/work/market is public and cached; /api/work/bounty is never cached and reads as the asker', async () => {
  const api = require('../api/work');
  const call = async (url, headers = {}) => {
    const r = { statusCode: 200, headers: {}, body: '' };
    r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
    r.getHeader = (k) => r.headers[k.toLowerCase()];
    r.end = (b) => { r.body = b || ''; r.headersSent = true; };
    const u = new URL(url, 'https://dayonegreat.com');
    await api.handle({ method: 'GET', url: u.pathname + u.search, headers: { host: 'dayonegreat.com', ...headers }, query: Object.fromEntries(u.searchParams) }, r, run);
    return { status: r.statusCode, cache: r.headers['cache-control'], body: JSON.parse(r.body) };
  };
  assert.strictEqual(typeof api.handle, 'function', 'the handler is exported, so this test runs');
  const m = await call('/api/work?route=market');
  assert.strictEqual(m.status, 200);
  assert.ok(Number.isInteger(m.body.funded_tasks));
  const id = await funded(roomB, 30000);
  const b = await call('/api/work?route=bounty&task=' + id);
  assert.strictEqual(b.status, 200);
  assert.deepStrictEqual(b.body.bounty, { tier: 2, status: 'funded' });
  assert.strictEqual(b.body.signed_in, false);
  assert.match(String(b.cache), /no-store/);
});

test('MK5: the home page and /build say so: the two calls to action, funded figures without prices, track records', () => {
  const fs = require('fs');
  const home = fs.readFileSync(require('path').join(__dirname, '..', 'index.html'), 'utf8');
  assert.match(home, /href="\/join\/buyer"[^>]*>Post a Funded Task</);
  assert.match(home, /href="\/connect"[^>]*>Deploy an Agent \/ Earn</);
  assert.match(home, /id="market"/);
  assert.match(home, /id="records"/);
  assert.ok(home.indexOf('id="records"') < home.indexOf('<!-- shell:foot -->'));
  // No claim that paying works while payments are off (the fresh review of PR #4, medium).
  assert.doesNotMatch(home, /needs only a passkey|paying for work needs/);
  assert.match(home, /Funded tasks, posted with a passkey alone, open when payments do\./);
  const build = fs.readFileSync(require('path').join(__dirname, '..', 'build.html'), 'utf8');
  assert.match(build, /id="market"/);
  assert.match(build, /never a dollar sum/);
  assert.match(fs.readFileSync(require('path').join(__dirname, '..', 'workpages.js'), 'utf8'), /fetch\('\/api\/work\/market'/, '/rooms shows each room\u2019s funded tasks and tier badges');
});
