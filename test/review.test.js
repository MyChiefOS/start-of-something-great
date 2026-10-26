// Release 2, PR 4: the review queue and reports (F6, F7, G5, SF5, O3, S6), against a real Postgres.
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
const review = require('../db/review');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { trustSystem, TEST_SYSTEM_SECRET, promote } = require('./helpers');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';

test('SF5: the review page decides each post with one tap, shows member text as text only, and asks no "are you sure"', () => {
  const html = fs.readFileSync(path.join(root, 'review.html'), 'utf8');
  assert.match(html, /name="robots" content="noindex"/);
  assert.match(html, /name="viewport" content="width=device-width, initial-scale=1"/);
  assert.match(html, /<script defer src="\/review\.js"><\/script>/);
  const js = fs.readFileSync(path.join(root, 'review.js'), 'utf8');
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(js), 'no HTML injection points');
  assert.ok(!/\b(confirm|prompt|alert)\s*\(/.test(js), 'no dialog between the tap and the decision');
  // One button per action the API offers; the tap sends the decision.
  assert.match(js, /i\.actions\.map\(function \(a\)/);
  assert.match(js, /JSON\.stringify\(\{ review: i\.id, decision: decision \}\)/);
  const feed = fs.readFileSync(path.join(root, 'feed.js'), 'utf8');
  assert.match(feed, /JSON\.stringify\(\{ report: id, reason: sel\.value, note: note\.value \}\)/);
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(feed));
});

test('F7: the MCP server keeps posts at most 30 seconds and the edge at most 60, so a removal shows everywhere within a minute', () => {
  const mcp = require('../api/mcp.js');
  assert.ok(mcp.POSTS_CACHE_MS > 0 && mcp.POSTS_CACHE_MS <= 30000);
  const src = fs.readFileSync(path.join(root, 'api', 'feed.js'), 'utf8');
  const fresh = Number(/const CACHE = (\d+);/.exec(src)[1]), stale = Number(/const STALE = (\d+);/.exec(src)[1]);
  // The edge copy can be up to fresh + stale old, plus the time its own refresh takes (database reads stop at 5
  // seconds): 45 leaves that margin inside the minute.
  assert.ok(fresh > 0 && fresh + stale <= 45, fresh + ' + ' + stale);
});

test('the queue and decisions need a database; without one they answer safely', async () => {
  const { handle } = require('../api/feed.js');
  const r = res();
  await handle(req('GET', '/api/feed', { query: { queue: '1' } }), r, null);
  assert.strictEqual(r.statusCode, 200);
  assert.deepStrictEqual(JSON.parse(r.body), { open: 0, items: [] });
  assert.strictEqual(r.getHeader('Cache-Control'), 'no-store');
  const bad = res();
  await handle(req('GET', '/api/feed', { query: { queue: 'yes' } }), bad, null);
  assert.strictEqual(bad.statusCode, 400);
});

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, url, { query = {}, cookie = '', origin, json, host = 'dayonegreat.com', ip = '203.0.113.7' } = {}) {
  const headers = { host, cookie, 'x-forwarded-for': ip };
  if (origin) headers.origin = origin;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url, headers, query, body: json !== undefined ? JSON.stringify(json) : undefined };
}

if (!SERVER) {
  if (process.env.CI) test('review tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('review against a database (F6, F7, G5, O3, S6)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_review_test_' + crypto.randomBytes(4).toString('hex');
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
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 3 });
  await trustSystem(su); // fix 3: the site itself acts only with its own secret
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

// A member at a given level, with a session cookie, made the way sign-in makes them.
async function member(level = 1, name = 'New member') {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: level === 0 ? 'email' : 'github', fingerprints: [c.sha256hex(crypto.randomUUID())],
    keyVersion: 1, level: Math.min(level, 1), displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  if (name !== 'New member') await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
const queue = () => run(aaron.ctx, (t) => review.queue(t, { limit: 100 }));
const inQueue = async (id) => (await queue()).items.find((i) => i.id === id);
const audit = (id) => q(`select action, actor_kind, actor_id, detail from app.audit_log where subject_id = '${id}' order by id`);
const feedHas = async (id) => (await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 50 }))).some((p) => p.id === id);

test('the database still passes the coverage check with the review tables (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('F6: a waiting post is in the queue as it is written; one tap approves it and it goes live at the top of the feed', async () => {
  const m = await member(0);
  const p = await run(m.ctx, (t) => posts.create(t, { body: 'my first post' }));
  assert.strictEqual(p.status, 'waiting');
  const item = await inQueue(p.id);
  assert.ok(item, 'in the queue at once');
  assert.strictEqual(item.firstPosts, true);
  assert.strictEqual(item.reports, 0);
  assert.strictEqual(await feedHas(p.id), false);
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'approve' })), { status: 'live' });
  assert.strictEqual(await inQueue(p.id), undefined, 'gone from the queue');
  const top = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 1 }));
  assert.strictEqual(top[0].id, p.id);
  // A second tap (another device) is told it was already decided, and changes nothing.
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'approve' })), { refused: 'stale' });
});

test('F6: declining a first post removes it; level 2 and Aaron\'s posts never enter the queue', async () => {
  const m = await member(1);
  const p = await run(m.ctx, (t) => posts.create(t, { body: 'not suitable' }));
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'remove' })), { status: 'removed' });
  assert.strictEqual((await run(m.ctx, (t) => posts.mine(t))).find((x) => x.id === p.id).status, 'removed', 'the author sees it was removed');
  const two = await member(2);
  const live = await run(two.ctx, (t) => posts.create(t, { body: 'verified' }));
  const mine = await run(aaron.ctx, (t) => posts.create(t, { body: 'from Aaron' }));
  assert.strictEqual(await inQueue(live.id), undefined);
  assert.strictEqual(await inQueue(mine.id), undefined);
});

test('F7: a reported post is in the queue as soon as the report answers; removing it takes it off the feed, profile and MCP at once', async () => {
  const author = await member(2, 'Author');
  const reporter = await member(1);
  const p = await run(author.ctx, (t) => posts.create(t, { body: 'reported post' }));
  const before = (await run({ actor: 'anon' }, (t) => posts.profile(t, author.id))).livePosts;
  const t0 = Date.now();
  assert.deepStrictEqual(await run(reporter.ctx, (t) => review.report(t, { post: p.id, reason: 'spam', note: 'selling things' })), { status: 'reported' });
  const item = await inQueue(p.id);
  assert.ok(item && Date.now() - t0 < 60000, 'in the queue within a minute (here: at once)');
  assert.deepStrictEqual([item.reports, item.reasons, item.notes, item.firstPosts], [1, ['spam'], ['selling things'], false]);
  assert.strictEqual(await feedHas(p.id), true, 'a report alone doesn\'t hide a post');

  // The MCP server reads the same feed function; give it this database.
  const mcp = require('../api/mcp.js');
  mcp.setReadPosts((a) => run({ actor: 'anon' }, (t) => posts.feed(t, a)));
  const { call } = require('./helpers');
  const callMcp = async () => {
    const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_posts', arguments: { lane: 'people', limit: 50 } } });
    return r.json.result.structuredContent.posts.map((x) => x.id);
  };
  assert.ok((await callMcp()).includes(p.id));

  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'remove' })), { status: 'removed' });
  assert.strictEqual(await feedHas(p.id), false, 'off the feed (and so the API) at once');
  assert.strictEqual((await run({ actor: 'anon' }, (t) => posts.profile(t, author.id))).livePosts, before - 1);
  mcp.setReadPosts((a) => run({ actor: 'anon' }, (t) => posts.feed(t, a))); // a new instance: no cached copy
  assert.ok(!(await callMcp()).includes(p.id), 'off the MCP server once its cache (at most 30 seconds) turns over');
  assert.strictEqual(await inQueue(p.id), undefined);
});

test('F7: a report racing a removal never leaves an open flag on the removed post', async () => {
  const author = await member(2);
  const reporter = await member(1);
  const p = await run(author.ctx, (t) => posts.create(t, { body: 'race' }));
  let release;
  const gate = new Promise((r) => { release = r; });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  // Aaron's removal holds the post locked while the report arrives.
  const removal = run(aaron.ctx, async (t) => { const r = await review.decide(t, { post: p.id, decision: 'remove' }); await gate; return r; });
  await sleep(300);
  const reporting = run(reporter.ctx, (t) => review.report(t, { post: p.id, reason: 'spam' }));
  await sleep(300);
  release();
  assert.deepStrictEqual(await removal, { status: 'removed' });
  assert.deepStrictEqual(await reporting, { refused: 'not_found' });
  assert.strictEqual(await inQueue(p.id), undefined);
  assert.strictEqual((await q(`select count(*)::int as n from app.review_flags where post_id = '${p.id}' and resolved_at is null`))[0].n, 0);
});

test('a flag left open on a removed post can be cleared with Remove, which is offered for it', async () => {
  const author = await member(2);
  const p = await run(author.ctx, (t) => posts.create(t, { body: 'leftover' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'remove' }));
  // However it got there (here, written straight to the table as the site itself), Remove closes it.
  await su.begin(async (t) => {
    await t`select app.act_as('system', null, null, false, null, null, ${TEST_SYSTEM_SECRET})`; // fix 3: with the site's own secret
    await t.unsafe(`insert into app.review_flags (post_id, source, classifier, score) values ('${p.id}', 'classifier', 'late', 0.5)`);
  });
  assert.strictEqual((await inQueue(p.id)).status, 'removed');
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'remove' })), { status: 'removed' });
  assert.strictEqual(await inQueue(p.id), undefined);
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'remove' })), { refused: 'stale' }, 'nothing left to close');
});

test('Undo puts a removed post back where it was: live if it had been approved, waiting if it never was', async () => {
  const m = await member(1);
  const first = await run(m.ctx, (t) => posts.create(t, { body: 'never approved' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: first.id, decision: 'remove' }));
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: first.id, decision: 'restore' })), { status: 'waiting' });
  assert.strictEqual(await feedHas(first.id), false, 'not published by an undo');
  assert.strictEqual((await inQueue(first.id)).firstPosts, true, 'back in the queue for a real decision');
  await assert.rejects(run(aaron.ctx, (t) => t`update app.posts set status = 'removed' where id = ${first.id}`).then(() =>
    run(aaron.ctx, (t) => t`update app.posts set status = 'live' where id = ${first.id}`)), /can't go from removed to live/);
  const two = await member(2);
  const live = await run(two.ctx, (t) => posts.create(t, { body: 'was live' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: live.id, decision: 'remove' }));
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: live.id, decision: 'restore' })), { status: 'live' });
  assert.strictEqual(await feedHas(live.id), true);
});

test('reports: only someone else\'s live post, once per member; reporting can\'t find hidden posts', async () => {
  const author = await member(2);
  const other = await member(1);
  const live = await run(author.ctx, (t) => posts.create(t, { body: 'live' }));
  const newbie = await member(1);
  const waiting = await run(newbie.ctx, (t) => posts.create(t, { body: 'waiting' }));
  const removed = await run(author.ctx, (t) => posts.create(t, { body: 'to remove' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: removed.id, decision: 'remove' }));
  const refused = { refused: 'not_found' };
  assert.deepStrictEqual(await run(author.ctx, (t) => review.report(t, { post: live.id, reason: 'spam' })), refused, 'own post');
  assert.deepStrictEqual(await run(other.ctx, (t) => review.report(t, { post: waiting.id, reason: 'spam' })), refused, 'waiting post');
  assert.deepStrictEqual(await run(other.ctx, (t) => review.report(t, { post: removed.id, reason: 'spam' })), refused, 'removed post');
  assert.deepStrictEqual(await run(other.ctx, (t) => review.report(t, { post: crypto.randomUUID(), reason: 'spam' })), refused, 'no such post');
  for (let i = 0; i < 3; i++) assert.deepStrictEqual(await run(other.ctx, (t) => review.report(t, { post: live.id, reason: 'abuse' })), { status: 'reported' });
  assert.strictEqual((await inQueue(live.id)).reports, 1, 'reporting again changes nothing');
  // Once the report is decided, a new report is a new flag (things can get worse after a "keep").
  await run(aaron.ctx, (t) => review.decide(t, { post: live.id, decision: 'keep' }));
  assert.deepStrictEqual(await run(other.ctx, (t) => review.report(t, { post: live.id, reason: 'illegal' })), { status: 'reported' });
  assert.deepStrictEqual((await inQueue(live.id)).reasons, ['illegal']);
  // Members can't set a classifier's score on their own flags.
  await assert.rejects(run(other.ctx, (t) => t`insert into app.review_flags (post_id, source, reason, reporter_id, score) values (${live.id}, 'report', 'spam', ${other.id}, 0.9)`), /violates check constraint/);
  await assert.rejects(run(other.ctx, (t) => review.report(t, { post: live.id, reason: 'boring' })), /reason/);
  await assert.rejects(run(other.ctx, (t) => review.report(t, { post: live.id, reason: 'spam', note: 'x'.repeat(501) })), /note/);
  // Even Aaron, who can see every post, can report only a live one.
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.report(t, { post: waiting.id, reason: 'spam' })), refused, 'Aaron, waiting post');
  // A banned member's live posts are hidden like any other: reporting one looks the same as a post that doesn't exist.
  const banned = await member(2);
  const hidden = await run(banned.ctx, (t) => posts.create(t, { body: 'by a banned member' }));
  await su.begin(async (t) => { await actAsAdmin(t, aaron.ctx); await t.unsafe(`update app.members set status = 'banned' where id = '${banned.id}'`); });
  assert.deepStrictEqual(await run(other.ctx, (t) => review.report(t, { post: hidden.id, reason: 'spam' })), refused, 'banned author');
  assert.strictEqual((await run(other.ctx, (t) => t`select id from app.posts where id = ${hidden.id}`)).length, 0, 'members don\'t read other members\' posts directly');
  // Someone not signed in can't report, even straight to the table.
  await assert.rejects(run({ actor: 'anon' }, (t) => t`insert into app.review_flags (post_id, source, reason) values (${live.id}, 'report', 'spam')`), /row-level security|violates/);
  // Nobody reports in someone else's name.
  await assert.rejects(run(other.ctx, (t) => t`insert into app.review_flags (post_id, source, reason, reporter_id) values (${live.id}, 'report', 'spam', ${newbie.id})`), /row-level security/);
  // A member sees their own reports and nobody else's.
  assert.strictEqual((await run(other.ctx, (t) => t`select id from app.review_flags`)).length, 2, 'their first report and the one after "keep"');
  assert.strictEqual((await run(author.ctx, (t) => t`select id from app.review_flags`)).length, 0);
});

test('only a reviewer decides: members can\'t approve, remove, close flags or rewrite a post, even straight to the tables', async () => {
  const m = await member(1);
  const p = await run(m.ctx, (t) => posts.create(t, { body: 'waiting for Aaron' }));
  await assert.rejects(run(m.ctx, (t) => review.decide(t, { post: p.id, decision: 'approve' })), /only a reviewer/);
  assert.strictEqual((await run(m.ctx, (t) => t`update app.posts set status = 'live' where id = ${p.id}`)).count, 0);
  assert.strictEqual((await run(m.ctx, (t) => t`update app.review_flags set decision = 'approve' where post_id = ${p.id}`)).count, 0);
  await assert.rejects(run(m.ctx, (t) => t`delete from app.review_flags where post_id = ${p.id}`), /permission denied/);
  await assert.rejects(run(m.ctx, (t) => t`insert into app.review_flags (post_id, source, classifier, score) values (${p.id}, 'classifier', 'fake', 0.9)`), /row-level security/);
  assert.ok(await inQueue(p.id), 'still waiting');
  // Even the reviewer changes only the status, along the allowed moves, and never chooses when it went live.
  await assert.rejects(run(aaron.ctx, (t) => t`update app.posts set body = 'edited' where id = ${p.id}`), /permission denied/);
  await assert.rejects(run(aaron.ctx, (t) => t`update app.posts set published_at = now() where id = ${p.id}`), /permission denied/);
  await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'approve' }));
  await assert.rejects(run(aaron.ctx, (t) => t`update app.posts set status = 'waiting' where id = ${p.id}`), /can't go from live to waiting/);
  // A closed flag stays closed, in the name of whoever closed it.
  await assert.rejects(run(aaron.ctx, (t) => t`update app.review_flags set decision = 'remove' where post_id = ${p.id}`), /already closed/);
  const [flag] = await q(`select resolved_by, decision from app.review_flags where post_id = '${p.id}'`);
  assert.deepStrictEqual(flag, { resolved_by: aaron.id, decision: 'approve' });
  // The second locks hold even for a role that skips the row rules (the database superuser here):
  // no status change without a reviewer, and a closed flag names whoever really closed it.
  const w = await run(m.ctx, (t) => posts.create(t, { body: 'second lock' }));
  await assert.rejects(q(`update app.posts set status = 'live' where id = '${w.id}'`), /only a reviewer can change a post/);
  const someone = crypto.randomUUID();
  await su.begin(async (t) => {
    await actAsAdmin(t, aaron.ctx);
    await t.unsafe(`update app.review_flags set decision = 'remove', resolved_by = '${someone}', resolved_at = now() - interval '1 day' where post_id = '${w.id}'`);
  });
  const [closed] = await q(`select resolved_by, resolved_at > now() - interval '1 minute' as fresh from app.review_flags where post_id = '${w.id}'`);
  assert.deepStrictEqual(closed, { resolved_by: aaron.id, fresh: true });
  // Decisions that don't fit the post's state are refused, not guessed at.
  for (const d of ['approve', 'restore']) assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: d })), { refused: 'stale' });
  assert.deepStrictEqual(await run(aaron.ctx, (t) => review.decide(t, { post: crypto.randomUUID(), decision: 'remove' })), { refused: 'not_found' });
  await assert.rejects(run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'delete' })), /decision/);
});

test('O3: every report, approval, removal, keep and undo is in the audit log with who did it, written by the database itself', async () => {
  const author = await member(1);
  const reporter = await member(1);
  const p = await run(author.ctx, (t) => posts.create(t, { body: 'audited' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'approve' }));
  await run(reporter.ctx, (t) => review.report(t, { post: p.id, reason: 'other' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'keep' }));
  await run(reporter.ctx, (t) => review.report(t, { post: p.id, reason: 'abuse' })); // after "keep", a new report is a new flag
  const other = await member(1);
  await run(other.ctx, (t) => review.report(t, { post: p.id, reason: 'abuse' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'remove' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'restore' }));
  // Rows written in one transaction share a time, so they are compared as a set.
  const log = (await audit(p.id)).map((r) => JSON.stringify([r.action, r.actor_kind, r.actor_id, r.detail.decision || r.detail.reason || r.detail.source || r.detail.to])).sort();
  assert.deepStrictEqual(log, [
    ['review.flag', 'member', author.id, 'first_posts'],
    ['post.approve', 'admin', aaron.id, 'live'],
    ['review.close', 'admin', aaron.id, 'approve'],
    ['review.flag', 'member', reporter.id, 'other'],
    ['review.close', 'admin', aaron.id, 'keep'],
    ['review.flag', 'member', reporter.id, 'abuse'],
    ['review.flag', 'member', other.id, 'abuse'],
    ['review.close', 'admin', aaron.id, 'remove'],
    ['post.remove', 'admin', aaron.id, 'removed'],
    ['review.close', 'admin', aaron.id, 'remove'],
    ['post.restore', 'admin', aaron.id, 'live']
  ].map((x) => JSON.stringify(x)).sort());
  // The record can't be skipped: a reviewer changing a post directly, not through review_decide, is recorded too.
  const q2 = await run(author.ctx, (t) => posts.create(t, { body: 'second' }));
  await run(aaron.ctx, (t) => t`update app.posts set status = 'removed' where id = ${q2.id}`);
  assert.ok((await audit(q2.id)).some((r) => r.action === 'post.remove' && r.actor_id === aaron.id));
  assert.strictEqual(await inQueue(q2.id), undefined, 'and its flags are closed with it');
});

test('G5: a classifier adds a flag through the same pipeline, and its post is decided like any other', async () => {
  const author = await member(2);
  const p = await run(author.ctx, (t) => posts.create(t, { body: 'looks like spam' }));
  await run({ actor: 'system' }, (t) => t`insert into app.review_flags (post_id, source, classifier, score) values (${p.id}, 'classifier', 'spam_v1', 0.97)`);
  const item = await inQueue(p.id);
  assert.deepStrictEqual([item.classifiers, item.reports, item.firstPosts], [['spam_v1'], 0, false]);
  // The site itself can't pose as a member reporting.
  await assert.rejects(run({ actor: 'system' }, (t) => t`insert into app.review_flags (post_id, source, reason) values (${p.id}, 'report', 'spam')`), /violates/);
  await run(aaron.ctx, (t) => review.decide(t, { post: p.id, decision: 'keep' }));
  assert.strictEqual(await inQueue(p.id), undefined);
  assert.strictEqual(await feedHas(p.id), true);
});

test('the API: the queue is Aaron\'s only, masked and private; decisions and reports need a session on our own pages', async () => {
  const { handle } = require('../api/feed.js');
  const call = async (r) => { const out = res(); await handle(r, out, run); return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null, r: out }; };
  const author = await member(2, 'Mallory');
  const reporter = await member(1);
  const p = await run(author.ctx, (t) => posts.create(t, { body: 'call me at jane@example.com' }));
  const aaronCookie = aaron.cookie;

  // Reporting through the API.
  assert.strictEqual((await call(req('POST', '/api/feed', { origin: ORIGIN, json: { report: p.id, reason: 'private_info' } }))).status, 401);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: reporter.cookie, origin: 'https://evil.com', json: { report: p.id, reason: 'spam' } }))).status, 403);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: reporter.cookie, origin: ORIGIN, json: { report: p.id, reason: 'nope' } }))).status, 400);
  const ok = await call(req('POST', '/api/feed', { cookie: reporter.cookie, origin: ORIGIN, json: { report: p.id, reason: 'private_info', note: 'mail me: bob@example.com' } }));
  assert.strictEqual(ok.status, 202);
  assert.strictEqual(ok.r.getHeader('Cache-Control'), 'no-store');

  // The queue: signed out 401, members 403, Aaron sees it masked, private and marked untrusted.
  assert.strictEqual((await call(req('GET', '/api/feed', { query: { queue: '1' } }))).status, 401);
  assert.strictEqual((await call(req('GET', '/api/feed', { query: { queue: '1' }, cookie: reporter.cookie }))).status, 403);
  const qd = await call(req('GET', '/api/feed', { query: { queue: '1' }, cookie: aaronCookie }));
  assert.strictEqual(qd.status, 200);
  assert.strictEqual(qd.r.getHeader('Cache-Control'), 'no-store');
  assert.ok(!qd.r.getHeader('Vercel-CDN-Cache-Control'), 'never cached at the edge');
  const item = qd.json.items.find((i) => i.id === p.id);
  assert.ok(!JSON.stringify(qd.json).includes('@example.com'), 'contacts masked (P4)');
  assert.deepStrictEqual(item.actions, ['keep', 'remove']);
  assert.deepStrictEqual(qd.json.untrusted_fields, ['items[].body', 'items[].author.name', 'items[].notes[]']);

  // Deciding: members 403, wrong origin 403, Aaron one call.
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: reporter.cookie, origin: ORIGIN, json: { review: p.id, decision: 'remove' } }))).status, 403);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: aaronCookie, origin: 'https://evil.com', json: { review: p.id, decision: 'remove' } }))).status, 403);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: aaronCookie, origin: ORIGIN, json: { review: p.id, decision: 'nuke' } }))).status, 400);
  const done = await call(req('POST', '/api/feed', { cookie: aaronCookie, origin: ORIGIN, json: { review: p.id, decision: 'remove' } }));
  assert.deepStrictEqual([done.status, done.json.status], [200, 'removed']);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: aaronCookie, origin: ORIGIN, json: { review: p.id, decision: 'remove' } }))).status, 409);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: aaronCookie, origin: ORIGIN, json: { review: crypto.randomUUID(), decision: 'remove' } }))).status, 404);
});

test('S6: reporting is rate limited per member, and a malformed report doesn\'t use up the allowance; posting stays unlimited', async () => {
  const { handle, REPORT_LIMITS } = require('../api/feed.js');
  const call = async (r) => { const out = res(); await handle(r, out, run); return out.statusCode; };
  const author = await member(2);
  const p = await run(author.ctx, (t) => posts.create(t, { body: 'reported a lot' }));
  const m = await member(1);
  const send = (json, ip) => call(req('POST', '/api/feed', { cookie: m.cookie, origin: ORIGIN, json, ip }));
  for (let i = 0; i < 5; i++) assert.strictEqual(await send({ report: p.id, reason: 'bad' }), 400);
  const max = REPORT_LIMITS.report_member.max;
  // Spread over many networks, so only the per-member limit applies.
  for (let i = 0; i < max; i++) assert.strictEqual(await send({ report: p.id, reason: 'spam' }, '198.51.' + i + '.1'), 202, 'report ' + (i + 1));
  assert.strictEqual(await send({ report: p.id, reason: 'spam' }, '198.51.200.1'), 429);
  // Posting is not a report: a level 2 member keeps posting (F4).
  for (let i = 0; i < 5; i++) assert.strictEqual((await run(author.ctx, (t) => posts.create(t, { body: 'still posting ' + i }))).status, 'live');
});
