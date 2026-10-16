// Release 2, PR 8: your account and deleting it (F8, SF4), against a real Postgres.
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
const posts = require('../db/posts');
const review = require('../db/review');
const controls = require('../db/controls');
const { make, SESSION } = require('../signin/flow');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';

test('the account page: private, forms post to our own sign-in routes, deleting needs DELETE typed, and no form has more than 5 fields', () => {
  const html = fs.readFileSync(path.join(root, 'account.html'), 'utf8');
  assert.match(html, /name="robots" content="noindex"/);
  assert.match(html, /<script defer src="\/account\.js"><\/script>/);
  for (const action of ['/auth/account/name', '/auth/logout', '/auth/logout-all', '/auth/account/delete']) assert.ok(html.includes('action="' + action + '"'), action);
  assert.match(html, /name="confirm"[^>]*pattern="DELETE"/);
  for (const f of html.match(/<form[\s\S]*?<\/form>/g)) assert.ok((f.match(/<input|<select|<textarea/g) || []).length <= 5, 'SF4');
  const js = fs.readFileSync(path.join(root, 'account.js'), 'utf8');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function/.test(js));
  assert.ok(!/\b(confirm|prompt|alert)\s*\(/.test(js));
  const { ROUTES } = require('../api/auth.js');
  for (const r of ['GET account', 'POST account/name', 'POST account/delete', 'POST account/unlink']) assert.ok(ROUTES[r], r);
  // PR 15: each sign-in method gets an Unlink form, built without HTML strings, posting to our own sign-in route.
  assert.match(js, /f\.action = '\/auth\/account\/unlink'/);
  assert.match(js, /f\.method = 'post'/);
  assert.match(js, /d\.sign_ins\.length > 1/, 'never offered for the only method');
});

if (!SERVER) {
  if (process.env.CI) test('account tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('accounts against a database (F8)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_account_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, flow, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, url, { cookie = '', origin = ORIGIN, body } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '203.0.113.30' };
  if (origin) headers.origin = origin;
  if (body !== undefined) headers['content-type'] = 'application/x-www-form-urlencoded';
  return { method, url, headers, body: body === undefined ? undefined : new URLSearchParams(body).toString(), query: {} };
}

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  const cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: crypto.randomBytes(32),
    fingerprintKeys: [{ version: 1, key: crypto.randomBytes(32) }], github: { clientId: 'g', clientSecret: 's' }, x: { clientId: 'x', clientSecret: 's' } };
  flow = make({ config: cfg, run, providers: {}, sendEmail: null });
  aaron = await member(2, 'Aaron');
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${aaron.id}'`); });
  aaron.ctx = { actor: 'admin', memberId: aaron.id };
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(level = 2, name = 'Member') {
  const token = c.token(32);
  const fp = c.sha256hex(crypto.randomUUID());
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [fp], keyVersion: 1,
    level, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, fp, cookie: SESSION + '=' + token, ctx: { actor: 'member', memberId: out.memberId } };
}
const count = async (sqlText) => Number((await q(sqlText))[0].n);
async function everything(id) {
  return {
    member: await count(`select count(*) as n from app.members where id = '${id}'`),
    identities: await count(`select count(*) as n from app.identities where member_id = '${id}'`),
    sessions: await count(`select count(*) as n from app.sessions where member_id = '${id}'`),
    posts: await count(`select count(*) as n from app.posts where author_id = '${id}'`),
    reports: await count(`select count(*) as n from app.review_flags where reporter_id = '${id}'`),
    agents: await count(`select count(*) as n from app.agents where owner_id = '${id}'`),
    brakes: await count(`select count(*) as n from app.brakes where member_id = '${id}'`)
  };
}
const del = (m, body = { confirm: 'DELETE' }, opts = {}) => { const r = res(); return flow.deleteAccount(req('POST', '/auth/account/delete', { cookie: m.cookie, body, ...opts }), r).then(() => r); };

test('the database passes the coverage check with account deletion (S1, S7)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('the account page shows your name, level and how you sign in, and only to you', async () => {
  const m = await member(2, 'Page owner');
  const r = res();
  await flow.account(req('GET', '/auth/account', { cookie: m.cookie }), r);
  const d = JSON.parse(r.body);
  assert.deepStrictEqual([r.statusCode, d.signed_in, d.display_name, d.trust_level, d.sessions, d.is_admin], [200, true, 'Page owner', 2, 1, false]);
  assert.deepStrictEqual(d.sign_ins.map((s) => [s.provider, s.level]), [['github', 2]]);
  assert.ok(!r.body.includes(m.fp), 'fingerprints are never shown');
  assert.strictEqual(r.getHeader('Cache-Control'), 'no-store');
  const anon = res();
  await flow.account(req('GET', '/auth/account'), anon);
  assert.strictEqual(anon.statusCode, 401);
});

test('a member renames themselves from our own pages only, within 80 characters on one line', async () => {
  const m = await member(1, 'Old name');
  const r = res();
  await flow.rename(req('POST', '/auth/account/name', { cookie: m.cookie, body: { name: 'New name' } }), r);
  assert.strictEqual(r.getHeader('Location'), '/account?saved=name');
  assert.strictEqual((await q(`select display_name from app.members where id = '${m.id}'`))[0].display_name, 'New name');
  for (const bad of ['', 'x'.repeat(81), 'two\nlines']) {
    const b = res();
    await flow.rename(req('POST', '/auth/account/name', { cookie: m.cookie, body: { name: bad } }), b);
    assert.strictEqual(b.getHeader('Location'), '/account?error=name', JSON.stringify(bad));
  }
  const cross = res();
  await flow.rename(req('POST', '/auth/account/name', { cookie: m.cookie, origin: 'https://evil.example', body: { name: 'Hijacked' } }), cross);
  assert.strictEqual((await q(`select display_name from app.members where id = '${m.id}'`))[0].display_name, 'New name');
});

test('F8: deleting an account removes the member and all their personal data at once, and the record keeps only counts', async () => {
  const m = await member(2, 'Leaving');
  const other = await member(2, 'Staying');
  // Their footprint: posts in both lanes, an agent with keys, a report they made, a report someone made on their
  // post, a brake on them, and two sessions.
  const p = await run(m.ctx, (t) => posts.create(t, { body: 'my words' }));
  const [ag] = await run(m.ctx, (t) => t`insert into app.agents (name) values ('My agent') returning id`);
  await run(m.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${ag.id}, ${c.sha256hex('k1')})`);
  await su.begin(async (t) => { await t`select set_config('app.fresh', '1', true)`; await t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${ag.id}, 'act', 'draft', 'draft', 100, 'owner')`; });
  await run({ actor: 'agent', memberId: m.id, agentId: ag.id }, (t) => posts.create(t, { body: 'my agent\'s words' }));
  const theirs = await run(other.ctx, (t) => posts.create(t, { body: 'someone else\'s post' }));
  await run(m.ctx, (t) => review.report(t, { post: theirs.id, reason: 'spam' }));
  await run(other.ctx, (t) => review.report(t, { post: p.id, reason: 'other' }));
  await run(aaron.ctx, (t) => controls.setBrake(t, { member: m.id, people_per_hour: 100, note: 'Leaving posts too fast' }));
  // Aaron's notes about them: a ban, an unban and a hand-set level, each with a note naming them.
  await run({ ...aaron.ctx, note: 'Leaving was rude to Bob' }, (t) => controls.setStatus(t, { member: m.id, status: 'banned' }));
  await run({ ...aaron.ctx, note: 'Leaving apologised' }, (t) => controls.setStatus(t, { member: m.id, status: 'active' }));
  // A hand-set level (only ever lower since Oct 16, 2026: no level is raised by hand), with a note naming them.
  await run({ ...aaron.ctx, note: 'Leaving slowed down for now' }, (t) => t`update app.members set trust_level = 1 where id = ${m.id}`);
  // The ban ended their sessions; they sign in again.
  m.cookie = SESSION + '=' + await (async () => { const tok = c.token(32); await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github',
    fingerprints: [m.fp], keyVersion: 1, level: 2, displayName: 'x', sessionHash: c.sha256hex(tok), sessionDays: 30 })); return tok; })();
  await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [m.fp], keyVersion: 1, level: 2, displayName: 'x',
    sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
  assert.deepStrictEqual(await everything(m.id), { member: 1, identities: 1, sessions: 2, posts: 2, reports: 1, agents: 1, brakes: 1 });

  const r = await del(m);
  assert.strictEqual(r.getHeader('Location'), '/join?deleted=1');
  assert.match(String(r.getHeader('Set-Cookie')), new RegExp(SESSION + '=;.*Max-Age=0'), 'the session cookie is cleared');
  assert.deepStrictEqual(await everything(m.id), { member: 0, identities: 0, sessions: 0, posts: 0, reports: 0, agents: 0, brakes: 0 });
  assert.strictEqual(await count(`select count(*) as n from app.agent_keys where agent_id = '${ag.id}'`), 0);
  assert.strictEqual(await count(`select count(*) as n from app.review_flags where post_id = '${p.id}'`), 0, 'reports on their posts went with them');
  // Nothing anywhere still holds their name or words.
  const dump = JSON.stringify(await q(`select * from app.members`)) + JSON.stringify(await q(`select body from app.posts`)) + JSON.stringify(await q(`select detail from app.audit_log`));
  for (const s of ['Leaving', 'Bob', 'apologised', 'phone', 'too fast', 'my words', 'my agent\'s words', 'My agent', m.fp]) assert.ok(!dump.includes(s), s);
  assert.strictEqual(await count(`select count(*) as n from app.admin_notes where member_id = '${m.id}'`), 0, 'Aaron\'s notes about them went too');
  // Everyone else's things stay: the other member and their post.
  assert.strictEqual(await count(`select count(*) as n from app.posts where id = '${theirs.id}'`), 1);
  // The record: one row, the member by ID, counts only.
  const [rec] = await q(`select actor_kind, actor_id, detail from app.audit_log where action = 'member.deleted' and subject_id = '${m.id}'`);
  assert.deepStrictEqual([rec.actor_kind, rec.actor_id], ['member', m.id]);
  // jevs_decisions: JEVs's own check of the deletion (PR 12); notices: the brake set on them left a notice in their
  // inbox (PR 13). Both are removed with everything else.
  assert.deepStrictEqual(rec.detail, { posts: 2, reports_on_posts: 1, reports_made: 1, agents: 1, keys: 1, drafts: 0, brakes: 1, sessions: 2, identities: 1,
    jevs_decisions: 1, deletion_reviews: 0, notices: 1 });
  // The old session is gone, and the public feed and profile no longer have them.
  const after = res();
  await flow.account(req('GET', '/auth/account', { cookie: m.cookie }), after);
  assert.strictEqual(after.statusCode, 401);
  assert.strictEqual(await run({ actor: 'anon' }, (t) => posts.profile(t, m.id)), null);
  // They can come back with the same account, as a new member.
  const back = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [m.fp], keyVersion: 1, level: 2,
    displayName: 'New member', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
  assert.ok(back.isNew && back.memberId !== m.id);
});

test('F8: nothing is deleted without DELETE typed, from another site, or when signed out', async () => {
  const m = await member(1, 'Careful');
  await run(m.ctx, (t) => posts.create(t, { body: 'keep me' }));
  for (const body of [{}, { confirm: 'delete' }, { confirm: 'DELETE ' }, { confirm: 'yes' }]) {
    assert.strictEqual((await del(m, body)).getHeader('Location'), '/account?error=confirm', JSON.stringify(body));
  }
  assert.strictEqual((await del(m, { confirm: 'DELETE' }, { origin: 'https://evil.example' })).getHeader('Location'), '/account');
  assert.strictEqual((await del({ cookie: '' })).getHeader('Location'), '/join?error=signin');
  assert.strictEqual((await everything(m.id)).member, 1);
});

test('RK3: a session that started more than 10 minutes ago can\'t delete the account, by the page or calling the database directly', async () => {
  const m = await member(2, 'Stale session');
  await su`update app.sessions set created_at = now() - interval '11 minutes' where member_id = ${m.id}`;
  assert.strictEqual((await del(m)).getHeader('Location'), '/account?error=fresh');
  await assert.rejects(run(m.ctx, (t) => t`select * from app.delete_account()`), /fresh_sign_in/);
  assert.deepStrictEqual(await run(m.ctx, (t) => store.deleteAccount(t)), { refused: 'fresh' });
  // Claiming freshness doesn't work for anyone but a member, and the session's start time is the database's own.
  await assert.rejects(run({ actor: 'anon', fresh: true }, (t) => t`select 1`), /fresh/);
  assert.strictEqual((await everything(m.id)).member, 1);
  // Signing in again (a new session) makes it possible.
  await su`update app.sessions set created_at = now() where member_id = ${m.id}`;
  assert.strictEqual((await del(m)).getHeader('Location'), '/join?deleted=1');
  assert.strictEqual((await everything(m.id)).member, 0);
});

test('F8: Aaron, a banned member, an agent and anyone signed out can\'t use it, even calling the database directly', async () => {
  assert.strictEqual((await del(aaron)).getHeader('Location'), '/account?error=admin');
  await assert.rejects(run(aaron.ctx, (t) => t`select * from app.delete_account()`), /not_member/);
  await assert.rejects(run({ actor: 'anon' }, (t) => t`select * from app.delete_account()`), /not_member/);
  const owner = await member(2, 'Agent owner');
  const [ag] = await run(owner.ctx, (t) => t`insert into app.agents (name) values ('Bot') returning id`);
  await assert.rejects(run({ actor: 'agent', memberId: owner.id, agentId: ag.id }, (t) => t`select * from app.delete_account()`), /not_member/, 'an agent can\'t delete its owner');
  // Aaron's own ID with a member actor is refused too, so the administrator can't be deleted by any route here.
  await assert.rejects(run({ actor: 'member', memberId: aaron.id, fresh: true }, (t) => t`select * from app.delete_account()`), /not_active/);
  const banned = await member(2, 'Banned');
  await run(aaron.ctx, (t) => controls.setStatus(t, { member: banned.id, status: 'banned' }));
  await assert.rejects(run({ ...banned.ctx, fresh: true }, (t) => t`select * from app.delete_account()`), /not_active/);
  assert.strictEqual((await del(banned)).getHeader('Location'), '/join?error=signin', 'a banned member has no session');
  assert.strictEqual((await everything(aaron.id)).member, 1);
  assert.strictEqual((await everything(banned.id)).member, 1);
  // The site's own role still can't delete members directly.
  const m = await member(1, 'Direct');
  await assert.rejects(run(m.ctx, (t) => t`delete from app.members where id = ${m.id}`), /permission denied/);
});

test('F8: a post written while the account is being deleted can\'t outlive it', async () => {
  const m = await member(2, 'Racing deletion');
  let release;
  const gate = new Promise((r) => { release = r; });
  const deleting = run({ ...m.ctx, fresh: true }, async (t) => { const out = await store.deleteAccount(t); await gate; return out; });
  await new Promise((r) => setTimeout(r, 150));
  const posting = run(m.ctx, (t) => posts.create(t, { body: 'sneaking in' })).then(() => 'posted', (e) => 'refused: ' + e.code);
  await new Promise((r) => setTimeout(r, 150));
  release();
  assert.ok((await deleting).posts === 0);
  assert.match(await posting, /^refused/);
  assert.deepStrictEqual(await everything(m.id), { member: 0, identities: 0, sessions: 0, posts: 0, reports: 0, agents: 0, brakes: 0 });
});

test('F8: a post already being written when the deletion starts is waited for, then deleted with everything else', async () => {
  const m = await member(2, 'Mid-post');
  let release;
  const gate = new Promise((r) => { release = r; });
  const posting = run(m.ctx, async (t) => { const p = await posts.create(t, { body: 'started first' }); await gate; return p; });
  await new Promise((r) => setTimeout(r, 150));
  const deleting = del(m);
  await new Promise((r) => setTimeout(r, 150));
  release();
  await posting;
  assert.strictEqual((await deleting).getHeader('Location'), '/join?deleted=1', 'the deletion waits, then succeeds');
  assert.deepStrictEqual(await everything(m.id), { member: 0, identities: 0, sessions: 0, posts: 0, reports: 0, agents: 0, brakes: 0 });
});

test('F8: a report or a sign-in already under way when the deletion starts is waited for, then cleaned up; neither gives an error', async () => {
  const m = await member(2, 'Busy leaver');
  const other = await member(2, 'Reporter');
  const p = await run(m.ctx, (t) => posts.create(t, { body: 'reported as I leave' }));
  // A report in flight.
  let release;
  let gate = new Promise((r) => { release = r; });
  const reporting = run(other.ctx, async (t) => { const out = await review.report(t, { post: p.id, reason: 'spam' }); await gate; return out; });
  await new Promise((r) => setTimeout(r, 150));
  let deleting = del(m);
  await new Promise((r) => setTimeout(r, 150));
  release();
  assert.deepStrictEqual(await reporting, { status: 'reported' });
  assert.strictEqual((await deleting).getHeader('Location'), '/join?deleted=1');
  assert.strictEqual(await count(`select count(*) as n from app.review_flags where post_id = '${p.id}'`), 0);
  // A sign-in in flight with the same account.
  const n = await member(2, 'Signing in as I leave');
  gate = new Promise((r) => { release = r; });
  const signing = run({ actor: 'anon' }, async (t) => {
    const out = await store.signIn(t, { provider: 'github', fingerprints: [n.fp], keyVersion: 1, level: 2, displayName: 'x', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 });
    await gate;
    return out;
  });
  await new Promise((r) => setTimeout(r, 150));
  deleting = del(n);
  await new Promise((r) => setTimeout(r, 150));
  release();
  assert.strictEqual((await signing).memberId, n.id);
  assert.strictEqual((await deleting).getHeader('Location'), '/join?deleted=1');
  assert.deepStrictEqual(await everything(n.id), { member: 0, identities: 0, sessions: 0, posts: 0, reports: 0, agents: 0, brakes: 0 });
});

test('F8: a sign-in that starts while a deletion is waiting can\'t deadlock with it', async () => {
  const m = await member(2, 'Slow leaver');
  const p = await run(m.ctx, (t) => posts.create(t, { body: 'locked by a slow review' }));
  // Something else holds the member's post for a moment (as a slow review decision would).
  let release;
  const gate = new Promise((r) => { release = r; });
  const holding = su.begin(async (t) => { await t`select id from app.posts where id = ${p.id} for update`; await gate; });
  await new Promise((r) => setTimeout(r, 150));
  const deleting = del(m);
  await new Promise((r) => setTimeout(r, 150));
  const signing = run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [m.fp], keyVersion: 1, level: 2, displayName: 'x',
    sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 })).then((x) => x, (e) => ({ error: e.code }));
  await new Promise((r) => setTimeout(r, 150));
  release();
  await holding;
  const [d, s] = await Promise.all([deleting, signing]);
  assert.strictEqual(d.getHeader('Location'), '/join?deleted=1', 'the deletion finishes');
  assert.notDeepStrictEqual(s, { error: '40P01' }, 'no deadlock');
  // The sign-in waited for the deletion and then made a fresh account; the old one is gone.
  assert.strictEqual((await everything(m.id)).member, 0);
});
