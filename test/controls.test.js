// Release 2, PR 6: owner controls (F4 the numbers, F9 the emergency brake, F10 banning), against a real Postgres.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
// Acting as an administrator straight in the database (the test superuser), the way the site does it.
// fix 3: settings set by hand count as an anonymous visitor, so this asks app.act_as with Aaron's real session.
const actAsAdmin = (t, ctx) => t`select app.act_as('admin', ${ctx.memberId}::uuid, null, false, ${ctx.session}, null, null)`;
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const posts = require('../db/posts');
const controls = require('../db/controls');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { keyFor, promote, shadowMode } = require('./helpers');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };

test('the owner-controls page is private, phone-sized, shows names as text only, and asks twice before the biggest steps', () => {
  const html = fs.readFileSync(path.join(root, 'controls.html'), 'utf8');
  assert.match(html, /name="robots" content="noindex"/);
  assert.match(html, /name="viewport" content="width=device-width, initial-scale=1"/);
  assert.match(html, /<script defer src="\/controls\.js"><\/script>/);
  const js = fs.readFileSync(path.join(root, 'controls.js'), 'utf8');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function/.test(js), 'no HTML injection points');
  assert.ok(!/\b(confirm|prompt|alert)\s*\(/.test(js), 'no browser dialogs');
  assert.match(js, /fetch\('\/api\/feed\?controls=1'/);
  // Banning and braking everyone take a second tap on the same button.
  assert.match(js, /armed/);
  assert.match(js, /member: scope\.value === '' \? null : scope\.value/, 'an everyone-brake says so explicitly');
});

test('without a database the controls answer safely, and a malformed request is refused', async () => {
  const { handle } = require('../api/feed.js');
  const r = res();
  await handle(req('GET', { query: { controls: '1' } }), r, null);
  assert.strictEqual(r.statusCode, 200);
  assert.deepStrictEqual(JSON.parse(r.body), { totals: null, everyone: null, owners: [] });
  assert.strictEqual(r.getHeader('Cache-Control'), 'no-store');
  const bad = res();
  await handle(req('GET', { query: { controls: 'yes' } }), bad, null);
  assert.strictEqual(bad.statusCode, 400);
});

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, { query = {}, cookie = '', origin, json, key, host = 'dayonegreat.com', route } = {}) {
  const headers = { host, cookie, 'x-vercel-forwarded-for': '203.0.113.21' };
  if (origin) headers.origin = origin;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  if (route !== undefined) query = { route };
  return { method, url: route !== undefined ? '/api/agents/' + route : '/api/feed', headers, query, body: json !== undefined ? JSON.stringify(json) : undefined };
}

if (!SERVER) {
  if (process.env.CI) test('controls tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('owner controls against a database (F4, F9, F10)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_controls_test_' + crypto.randomBytes(4).toString('hex');
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
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 6 });
  aaron = await member(1, 'Aaron');
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

// A member made the way sign-in makes them, with a session cookie and the account fingerprint they signed in with.
async function member(level = 2, name = 'Owner') {
  const token = c.token(32);
  const fp = c.sha256hex(crypto.randomUUID());
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [fp],
    keyVersion: 1, level: Math.min(level, 1), displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, fp, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
async function feedApi(r) {
  const out = res();
  await require('../api/feed.js').handle(r, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
async function agentsApi(r) {
  const out = res();
  await require('../api/agents.js').handle(r, out, run, CFG);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
// Agents start by drafting (PR 7). Tests of other behaviour let an agent act on its own first, as its owner could
// after a fresh sign-in.
const letAct = (sql, agentId) => sql.begin(async (t) => {
  await t`select set_config('app.fresh', '1', true)`;
  await t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${agentId}, 'act', 'draft', 'draft', 1000, 'owner')`;
});
// An owner's new agent, made while signed in and allowed to act on its own; returns its ID and key.
async function newAgent(owner, name = 'Helper') {
  const r = await agentsApi(req('POST', { route: '', cookie: owner.cookie, origin: ORIGIN, json: { name } }));
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  await letAct(su, r.json.agent_id);
  return { id: r.json.agent_id, key: r.json.key };
}
const say = (m, body) => feedApi(req('POST', { cookie: m.cookie, origin: ORIGIN, json: { body } }));
const agentSay = (a, body) => feedApi(req('POST', { key: a.key, json: { body } }));
const control = (json, who = aaron) => feedApi(req('POST', { cookie: who.cookie, origin: ORIGIN, json }));
const board = (who = aaron) => feedApi(req('GET', { cookie: who.cookie, query: { controls: '1' } }));
const audit = (id) => q(`select action, actor_kind, actor_id, detail from app.audit_log where subject_id = '${id}' order by id`);
// Switches every brake off between tests, in Aaron's name (a brake always records who switched it off).
const liftAll = () => run(aaron.ctx, (t) => t`update app.brakes set lifted_at = now() where lifted_at is null`);

test('the database passes the coverage check with the owner-controls tables (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('F4: posting has no limits until a brake is switched on', async () => {
  const m = await member(2, 'Busy');
  for (let i = 0; i < 25; i++) assert.strictEqual((await say(m, 'post number ' + i)).status, 201);
});

test('F9: a brake on one owner takes effect on their very next post, leaves others alone, and lifting it works at once', async () => {
  const m = await member(2, 'Braked');
  const other = await member(2, 'Unbraked');
  assert.strictEqual((await say(m, 'before the brake')).status, 201);
  const t0 = Date.now();
  const on = await control({ brake: { member: m.id, people_per_hour: 2, note: 'flooding the lane' } });
  assert.strictEqual(on.status, 201);
  assert.strictEqual(on.json.brake.people_per_hour, 2);
  // One post already counts in this hour: one more is allowed, then the next is refused, in plain words.
  assert.strictEqual((await say(m, 'second')).status, 201);
  const refused = await say(m, 'third');
  assert.strictEqual(refused.status, 429);
  assert.strictEqual(refused.json.error, 'Posting is limited for now: at most 2 an hour.');
  assert.ok(Date.now() - t0 < 60000, 'in effect within a minute (here: the next request)');
  for (let i = 0; i < 3; i++) assert.strictEqual((await say(other, 'unaffected ' + i)).status, 201, 'other owners are not limited');
  const off = await control({ lift: on.json.brake.id });
  assert.strictEqual(off.status, 200);
  assert.strictEqual((await say(m, 'after the brake')).status, 201, 'lifted at once');
  assert.strictEqual((await control({ lift: on.json.brake.id })).status, 404, 'already off');
  // The record: both steps, in Aaron's name, with the limits and the note.
  const rows = await audit(on.json.brake.id);
  assert.deepStrictEqual(rows.map((r) => [r.action, r.actor_kind, r.actor_id]), [['brake.on', 'admin', aaron.id], ['brake.off', 'admin', aaron.id]]);
  // The note stays on the brake (deleted with the member it names); the record says only that there was one (PR 8).
  assert.deepStrictEqual(rows[0].detail, { scope: 'member', member: m.id, people_per_hour: 2, has_note: true });
});

test('F9: an owner\'s agents share one allowance, so more agents don\'t mean more posts', async () => {
  const owner = await member(2, 'Many agents');
  const a1 = await newAgent(owner, 'One'), a2 = await newAgent(owner, 'Two'), a3 = await newAgent(owner, 'Three');
  const on = await control({ brake: { member: owner.id, agent_posts_per_hour: 3 } });
  assert.strictEqual(on.status, 201);
  assert.strictEqual((await agentSay(a1, 'one')).status, 201);
  assert.strictEqual((await agentSay(a2, 'two')).status, 201);
  assert.strictEqual((await agentSay(a3, 'three')).status, 201);
  for (const a of [a1, a2, a3]) {
    const r = await agentSay(a, 'one too many');
    assert.strictEqual(r.status, 429);
    assert.strictEqual(r.json.error, 'Posting is limited for now: at most 3 an hour.');
  }
  // The agent limit doesn't touch the owner's own posts.
  assert.strictEqual((await say(owner, 'still me')).status, 201);
  await control({ lift: on.json.brake.id });
});

test('F9: a brake for everyone gives every owner the limits, 0 stops posting, the stricter brake wins, and Aaron is never limited', async () => {
  const a = await member(2, 'Everyone A');
  const b = await member(2, 'Everyone B');
  const all = await control({ brake: { member: null, people_per_hour: 1 } });
  assert.strictEqual(all.status, 201);
  assert.strictEqual(all.json.brake.member, null);
  // Each owner gets their own allowance of 1.
  assert.strictEqual((await say(a, 'a1')).status, 201);
  assert.strictEqual((await say(b, 'b1')).status, 201);
  assert.strictEqual((await say(a, 'a2')).status, 429);
  // A looser brake on one owner doesn't loosen the everyone brake; a stricter one tightens it.
  const c1 = await member(2, 'Looser');
  await control({ brake: { member: c1.id, people_per_hour: 50 } });
  assert.strictEqual((await say(c1, 'c1')).status, 201);
  assert.strictEqual((await say(c1, 'c2')).status, 429, 'the everyone limit of 1 still applies');
  const d = await member(2, 'Stopped');
  await control({ brake: { member: d.id, people_per_hour: 0 } });
  const stopped = await say(d, 'nothing');
  assert.deepStrictEqual([stopped.status, stopped.json.error], [429, 'Posting is paused for now.']);
  for (let i = 0; i < 3; i++) assert.strictEqual((await say(aaron, 'from Aaron ' + i)).status, 201, 'Aaron runs the brake and is never limited');
  // A new brake for the same scope replaces the old one; the record shows both steps.
  const again = await control({ brake: { member: null, people_per_hour: 100 } });
  assert.strictEqual(again.status, 201);
  assert.deepStrictEqual((await audit(all.json.brake.id)).map((r) => r.action), ['brake.on', 'brake.off']);
  assert.strictEqual((await say(a, 'a3')).status, 201);
  await liftAll();
});

test('F9: parallel posts can\'t slip past a brake', async () => {
  const m = await member(2, 'Racer');
  await control({ brake: { member: m.id, people_per_hour: 3 } });
  const results = await Promise.all(Array.from({ length: 10 }, (_, i) => say(m, 'race ' + i)));
  assert.strictEqual(results.filter((r) => r.status === 201).length, 3);
  assert.strictEqual(results.filter((r) => r.status === 429).length, 7);
  await liftAll();
});

test('F9: a brake on new agents stops both creating and claiming one', async () => {
  const owner = await member(2, 'Agent maker');
  await newAgent(owner, 'First');
  const on = await control({ brake: { member: owner.id, new_agents_per_day: 1 } });
  const made = await agentsApi(req('POST', { route: '', cookie: owner.cookie, origin: ORIGIN, json: { name: 'Second' } }));
  assert.deepStrictEqual([made.status, made.json.error], [429, 'New agents are limited for now: at most 1 a day.']);
  // Claiming runs as the sign-in role; the brake still applies, and the code stays usable for later.
  const reg = await agentsApi(req('POST', { route: 'register', json: { name: 'Self registered' } }));
  assert.strictEqual(reg.status, 201);
  const code = /#claim=([A-Za-z0-9_-]{43})$/.exec(reg.json.claim_url)[1];
  const claimed = await agentsApi(req('POST', { route: 'claim', cookie: owner.cookie, origin: ORIGIN, json: { code } }));
  assert.deepStrictEqual([claimed.status, claimed.json.error], [429, 'New agents are limited for now: at most 1 a day.']);
  await control({ lift: on.json.brake.id });
  assert.strictEqual((await agentsApi(req('POST', { route: 'claim', cookie: owner.cookie, origin: ORIGIN, json: { code } }))).status, 200, 'claimable once lifted');
});

test('F9: only Aaron sees or sets brakes; a brake request must name its scope; a brake only ever switches off', async () => {
  const m = await member(2, 'Not Aaron');
  assert.strictEqual((await control({ brake: { member: null, people_per_hour: 0 } }, m)).status, 403);
  assert.strictEqual((await board(m)).status, 403);
  assert.strictEqual((await feedApi(req('GET', { query: { controls: '1' } }))).status, 401);
  // Leaving "member" out never brakes the whole site by accident.
  assert.strictEqual((await control({ brake: { people_per_hour: 0 } })).status, 400);
  assert.strictEqual((await control({ brake: { member: null } })).status, 400, 'at least one limit');
  assert.strictEqual((await control({ brake: { member: null, people_per_hour: -1 } })).status, 400);
  assert.strictEqual((await control({ brake: { member: crypto.randomUUID().replace(/^(.{14})./, '$17') } })).status, 400);
  // In the database: members can't read, write or lift brakes at all.
  const on = await run(aaron.ctx, (t) => controls.setBrake(t, { member: m.id, people_per_hour: 5 }));
  assert.strictEqual((await run(m.ctx, (t) => t`select id from app.brakes`)).length, 0);
  await assert.rejects(run(m.ctx, (t) => t`insert into app.brakes (member_id, people_per_hour) values (${m.id}, 1000)`), /row-level security/);
  const lifted = await run(m.ctx, (t) => t`update app.brakes set lifted_at = now() where id = ${on.brake.id}`);
  assert.strictEqual(lifted.count, 0);
  // The second lock: even the owner of the tables can't change a brake's limits, or switch one off twice.
  await assert.rejects(q(`update app.brakes set people_per_hour = 1000 where id = '${on.brake.id}'`), /a brake can only be switched off/);
  // Not even by switching it off and loosening it in the same step.
  await assert.rejects(run(aaron.ctx, (t) => t`update app.brakes set lifted_at = now(), member_id = null where id = ${on.brake.id}`), /permission denied|switched off/);
  await assert.rejects(su.begin(async (t) => {
    await actAsAdmin(t, aaron.ctx);
    await t`update app.brakes set lifted_at = now(), people_per_hour = 1000 where id = ${on.brake.id}`;
  }), /a brake can only be switched off/);
  // Switching off records who did it, so even the owner can't do it without saying who is acting.
  await assert.rejects(q(`update app.brakes set lifted_at = now() where id = '${on.brake.id}'`), /brakes_check1/);
  assert.strictEqual(await run(aaron.ctx, (t) => controls.lift(t, on.brake.id)), true);
  await assert.rejects(q(`update app.brakes set lifted_at = now() where id = '${on.brake.id}'`), /already off/);
});

test('F9, the second lock: the brake applies however a post is written, even past row-level security', async () => {
  const m = await member(2, 'Direct writer');
  await control({ brake: { member: m.id, people_per_hour: 0 } });
  await assert.rejects(su.begin(async (t) => {
    await t`select set_config('app.actor', 'member', true), set_config('app.member_id', ${m.id}, true)`;
    await t`insert into app.posts (author_id, body) values (${m.id}, 'as the superuser')`;
  }), /brake/);
  await liftAll();
});

test('F10: banning an owner stops their sessions and every agent at once, hides their posts, and the same account can\'t come back', async () => {
  const owner = await member(2, 'To be banned');
  const a1 = await newAgent(owner, 'Banned one'), a2 = await newAgent(owner, 'Banned two');
  const p = await say(owner, 'a post before the ban');
  const ap = await agentSay(a1, 'an agent post before the ban');
  assert.strictEqual(ap.status, 201);
  const t0 = Date.now();
  const ban = await control({ ban: owner.id, note: 'spam network' });
  assert.deepStrictEqual([ban.status, ban.json.status], [200, 'banned']);
  // Agents: every key stops on its next request.
  for (const a of [a1, a2]) assert.strictEqual((await agentSay(a, 'after the ban')).status, 401);
  // The session stops.
  assert.strictEqual((await say(owner, 'after the ban')).status, 401);
  // Posts and profile leave public view.
  const people = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 50 }));
  const agentLane = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'agents', limit: 50 }));
  assert.ok(!people.some((x) => x.id === p.json.id) && !agentLane.some((x) => x.id === ap.json.id));
  assert.strictEqual(await run({ actor: 'anon' }, (t) => posts.profile(t, owner.id)), null);
  assert.ok(Date.now() - t0 < 60000);
  // The same GitHub account can't sign up again.
  const back = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [owner.fp], keyVersion: 1, level: 1,
    displayName: 'Back again', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
  assert.deepStrictEqual(back, { refused: 'banned' });
  assert.strictEqual(Number((await q(`select count(*) as n from app.members where display_name = 'Back again'`))[0].n), 0, 'no new account was made');
  // The record names Aaron and points at his note, which is kept where it can be deleted with the member (PR 8).
  const rec = (await audit(owner.id)).filter((r) => r.action.startsWith('member.ban'));
  assert.deepStrictEqual(rec.map((r) => [r.action, r.actor_kind, r.actor_id]), [['member.ban', 'admin', aaron.id]]);
  assert.deepStrictEqual((await q(`select note from app.admin_notes where id = '${rec[0].detail.note_id}'`)).map((r) => r.note), ['spam network']);
  assert.strictEqual((await control({ ban: owner.id })).status, 409, 'already banned');

  // The ban ended the sessions and revoked the keys in the database, not just on the next check: an unban is a fresh
  // start, so nothing an intruder held (if the account had been taken over) works again.
  assert.strictEqual(Number((await q(`select count(*) as n from app.sessions where member_id = '${owner.id}'`))[0].n), 0);
  assert.strictEqual(Number((await q(`select count(*) as n from app.agent_keys k join app.agents a on a.id = k.agent_id where a.owner_id = '${owner.id}' and k.revoked_at is null`))[0].n), 0);
  const un = await control({ unban: owner.id, note: 'appeal upheld' });
  assert.deepStrictEqual([un.status, un.json.status], [200, 'active']);
  for (const a of [a1, a2]) assert.strictEqual((await agentSay(a, 'old key after the unban')).status, 401);
  assert.strictEqual((await say(owner, 'old session after the unban')).status, 401);
  // The owner signs in again and gives an agent a new key; it works, and the agent is still theirs.
  const fresh = c.token(32);
  const again = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [owner.fp], keyVersion: 1, level: 1,
    displayName: 'x', sessionHash: c.sha256hex(fresh), sessionDays: 30 }));
  assert.strictEqual(again.memberId, owner.id);
  const rotated = await agentsApi(req('POST', { route: 'key', cookie: '__Host-dog_session=' + fresh, origin: ORIGIN, json: { agent: a2.id } }));
  assert.strictEqual(rotated.status, 201, JSON.stringify(rotated.json));
  // The ban also set the agent back to drafting (PR 7), so its first words after the unban wait for the owner.
  assert.strictEqual((await agentSay({ key: rotated.json.key }, 'back after the appeal')).status, 202);
  const unbanned = (await audit(owner.id)).filter((r) => r.action === 'member.unban');
  assert.deepStrictEqual((await q(`select note from app.admin_notes where id = '${unbanned[0].detail.note_id}'`)).map((r) => r.note), ['appeal upheld']);
});

test('F10: a ban racing a new key or a sign-in still wins: nothing made during the ban works after the unban', async () => {
  const owner = await member(2, 'Racing the ban');
  const a = await newAgent(owner, 'Racer agent');
  // A new key that started before the ban committed: the ban waits for it, then revokes it.
  let release;
  const gate = new Promise((r) => { release = r; });
  const keying = run({ ...owner.ctx, fresh: true }, async (t) => {
    const k = require('../signin/agentkey').newKey();
    const ok = await require('../db/agents').rotate(t, { agent: a.id, keyHash: k.hash });
    await gate;
    return ok ? k.key : null;
  });
  await new Promise((r) => setTimeout(r, 200));
  const banning = control({ ban: owner.id });
  await new Promise((r) => setTimeout(r, 200));
  release();
  const newKey = await keying;
  assert.strictEqual((await banning).status, 200);
  assert.ok(newKey, 'the key was issued before the ban landed');
  // A key requested after the ban committed is refused outright.
  // fix 3: the ban ended the owner's sessions, so the database now refuses the old session itself, before rotate runs.
  await assert.rejects(run(owner.ctx, (t) => require('../db/agents').rotate(t, { agent: a.id, keyHash: c.sha256hex('late') })), /not_acting/);
  // A sign-in that started before the ban: the ban waits, then ends that session too.
  const back = await member(2, 'Signing in during the ban');
  let open;
  const held = new Promise((r) => { open = r; });
  const signing = run({ actor: 'anon' }, async (t) => {
    const out = await store.signIn(t, { provider: 'github', fingerprints: [back.fp], keyVersion: 1, level: 1, displayName: 'x',
      sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 });
    await held;
    return out;
  });
  await new Promise((r) => setTimeout(r, 200));
  const banning2 = control({ ban: back.id });
  await new Promise((r) => setTimeout(r, 200));
  open();
  await signing;
  assert.strictEqual((await banning2).status, 200);
  await control({ unban: owner.id });
  await control({ unban: back.id });
  assert.strictEqual((await agentSay({ key: newKey }, 'a key made while being banned')).status, 401);
  assert.strictEqual(Number((await q(`select count(*) as n from app.sessions where member_id = '${back.id}'`))[0].n), 0);
  // The database refuses a key for a banned owner even past the site's own check.
  await control({ ban: owner.id });
  await assert.rejects(su.begin(async (t) => {
    await t`select set_config('app.actor', 'member', true), set_config('app.member_id', ${owner.id}, true)`;
    await t`insert into app.agent_keys (agent_id, key_hash) values (${a.id}, ${c.sha256hex('direct')})`;
  }), /owner_not_active/);
  await control({ unban: owner.id });
});

test('F10: Aaron can\'t be banned, members can\'t ban, and bans need a real member', async () => {
  const m = await member(2, 'Would-be banner');
  assert.strictEqual((await control({ ban: aaron.id })).status, 409);
  await assert.rejects(su.begin(async (t) => {
    await actAsAdmin(t, aaron.ctx);
    await t`update app.members set status = 'banned' where id = ${aaron.id}`;
  }), /administrator can't be banned/, 'not even directly');
  assert.strictEqual((await control({ ban: aaron.id }, m)).status, 403);
  await assert.rejects(run(m.ctx, (t) => t`update app.members set status = 'banned' where id = ${m.id}`), /only an administrator/);
  assert.strictEqual((await control({ ban: '01890a5d-ac96-774b-bcce-b302099a8057' })).status, 404);
  assert.strictEqual((await control({ ban: m.id, note: 'x'.repeat(201) })).status, 400, 'notes are at most 200 characters');
  assert.strictEqual((await control({ ban: m.id, extra: 1 })).status, 400);
  assert.strictEqual((await control({ ban: m.id, unban: m.id })).status, 400);
  // A note travels only with Aaron's own calls.
  await assert.rejects(run({ ...m.ctx, note: 'sneaky' }, (t) => t`select 1`), /only admin calls carry a note/);
});

test('F4: the numbers show agents per owner, posts per owner by lane, and near-duplicate posts, exactly', async () => {
  // A fresh database keeps the counts exact.
  const D = 'dog_controls_f4_' + crypto.randomBytes(4).toString('hex');
  await server.unsafe('create database ' + D);
  const s2 = postgres(at(SERVER, D), { max: 2, ssl: false, onnotice: () => {} });
  const W2 = D + '_web';
  let w2;
  try {
    await migrate(s2);
    await s2.unsafe(`create role ${W2} login noinherit password '${PW}'; grant dog_app to ${W2}`);
    w2 = db.connect(at(SERVER, D, W2, PW), { ssl: false, max: 2 });
    const r2 = (ctx, fn) => db.tx(w2, ctx, fn);
    const mk = async (name, level = 2) => {
      const sessionHash = c.sha256hex(c.token(32));
      const o = await r2({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
        level: Math.min(level, 1), displayName: name, sessionHash, sessionDays: 30 }));
      if (level >= 2) await promote(s2, o.memberId);
      return { id: o.memberId, sessionHash, ctx: { actor: 'member', memberId: o.memberId, session: sessionHash } };
    };
    const boss = await mk('Boss');
    await s2.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${boss.id}'`); });
    const bossCtx = { actor: 'admin', memberId: boss.id, session: boss.sessionHash };
    const ann = await mk('Ann'), ben = await mk('Ben'), quiet = await mk('Quiet');
    // Ann: 2 agents; 3 people posts (two the same text apart from case and punctuation), 4 agent posts.
    const agentIds = [], agentKeys = [];
    for (const n of ['A1', 'A2']) {
      const [a] = await r2(ann.ctx, (t) => t`insert into app.agents (name) values (${n}) returning id`);
      await letAct(s2, a.id);
      agentIds.push(a.id);
      agentKeys.push(await keyFor(s2, a.id)); // fix 3: an agent acts with a real key
    }
    for (const b of ['Buy now!', 'buy NOW', 'something else']) await r2(ann.ctx, (t) => posts.create(t, { body: b }));
    for (const [i, b] of ['agent hello', 'agent hello', 'Agent... hello!', 'unique agent text'].entries()) {
      await r2({ actor: 'agent', memberId: ann.id, agentId: agentIds[i % 2], keyHash: agentKeys[i % 2] }, (t) => posts.create(t, { body: b }));
    }
    // Ben: 1 post, the same text as one of Ann's, so it is a repeat too.
    await r2(ben.ctx, (t) => posts.create(t, { body: 'Something else.' }));
    // An old post (8 days ago) counts in the total, not in the 7-day numbers.
    await s2.unsafe(`insert into app.posts (author_id, body) values ('${ben.id}', 'old post')`);
    await s2.unsafe(`alter table app.posts disable trigger posts_review_guard; update app.posts set created_at = now() - interval '8 days' where body = 'old post'; alter table app.posts enable always trigger posts_review_guard`);
    await r2(bossCtx, (t) => controls.setBrake(t, { member: quiet.id, people_per_hour: 0 }));

    const d = await r2(bossCtx, (t) => controls.dashboard(t, {}));
    assert.deepStrictEqual(d.totals, { active_members: 4, banned_members: 0, disabled_members: 0, active_agents: 2, people_posts_24h: 4, agent_posts_24h: 4,
      posts_7d: 8, repeats_7d: 7, brakes_on: 1 });
    const byName = Object.fromEntries(d.owners.map((o) => [o.name, o]));
    assert.deepStrictEqual(Object.keys(byName).sort(), ['Ann', 'Ben', 'Quiet'], 'owners with posts, agents or a brake; Boss has none');
    const pick = (o) => [o.agents, o.new_agents_24h, o.people_posts_24h, o.agent_posts_24h, o.posts_7d, o.repeats_7d, o.posts_total];
    assert.deepStrictEqual(pick(byName.Ann), [2, 2, 3, 4, 7, 6, 7]);
    assert.deepStrictEqual(pick(byName.Ben), [0, 0, 1, 0, 1, 1, 2]);
    assert.strictEqual(byName.Quiet.brake.people_per_hour, 0);
    assert.deepStrictEqual(d.owners.map((o) => o.name), ['Quiet', 'Ann', 'Ben'], 'owners under a brake first, then the busiest');
    // A braked owner past the cut-off still shows, with their real numbers.
    await r2(bossCtx, (t) => controls.setBrake(t, { member: ben.id, people_per_hour: 5 }));
    const top = await r2(bossCtx, (t) => controls.dashboard(t, { limit: 2 }));
    assert.deepStrictEqual(top.owners.map((o) => [o.name, o.posts_total]), [['Ben', 2], ['Quiet', 0]]);
    // Two lists the busiest-owners list can miss.
    assert.deepStrictEqual(d.most_agents.map((o) => [o.name, o.agents]), [['Ann', 2]]);
    assert.deepStrictEqual(d.repeated_texts.map((r) => [r.posts, r.authors]), [[2, 2], [3, 1], [2, 1]]);
    assert.strictEqual(d.repeated_texts[0].sample, 'something else');
    assert.strictEqual(d.everyone, null);
    // Members see none of it: run as one, the same queries count only what that member may see anyway.
    const own = await r2(ann.ctx, (t) => controls.dashboard(t, {}));
    assert.deepStrictEqual([own.totals.banned_members, own.totals.brakes_on, own.everyone], [0, 0, null], 'a member counts only their own rows and no brakes');
  } finally {
    if (w2) await w2.end({ timeout: 5 });
    await s2.end({ timeout: 5 });
    await server.unsafe(`drop database if exists ${D} with (force)`);
    await server.unsafe(`drop role if exists ${W2}`);
  }
});

test('F4: the controls API shows the numbers to Aaron only, with member text masked and marked untrusted', async () => {
  const r = await board();
  assert.strictEqual(r.status, 200);
  assert.ok(r.json.totals.active_members >= 1);
  assert.ok(r.json.untrusted_fields.includes('owners[].name'));
  assert.ok(Array.isArray(r.json.owners));
});
