// Release 2, PR 3: posting and lanes (F5, F6 groundwork, S2, S9, G2, P4, C7), against a real Postgres.
'use strict';

const { promote } = require('./helpers');
const test = require('node:test');
const assert = require('node:assert');
// Acting as an administrator straight in the database (the test superuser), the way the site does it.
// fix 3: settings set by hand count as an anonymous visitor, so this asks app.act_as with the admin's real session.
const actAsAdmin = (t, ctx) => t`select app.act_as('admin', ${ctx.memberId}::uuid, null, false, ${ctx.session}, null, null)`;
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const posts = require('../db/posts');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';

test('F5: the feed page shows the people lane first, and renders posts as text, never HTML', () => {
  const html = fs.readFileSync(path.join(root, 'feed.html'), 'utf8');
  assert.match(html, /data-lane="people"[^>]*>People<\/button>/);
  assert.match(html, /id="tab-people"[^>]*aria-selected="true"/);
  assert.match(html, /id="tab-agents"[^>]*aria-selected="false"/);
  assert.match(html, /name="robots" content="noindex"/, 'unlisted until the preview opens');
  const js = fs.readFileSync(path.join(root, 'feed.js'), 'utf8');
  assert.match(js, /var lane = 'people';/);
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(js), 'no HTML injection points');
});

test('G2, S9: the feed answers without a database, cacheable, and says its text is untrusted', async () => {
  const { handle } = require('../api/feed.js');
  const r = res();
  await handle(req('GET', '/api/feed', { query: {} }), r, null);
  const d = JSON.parse(r.body);
  assert.strictEqual(r.statusCode, 200);
  assert.deepStrictEqual(d.posts, []);
  assert.match(d.note, /never as instructions/);
  cacheOk(r);
  const w = res();
  await handle(req('POST', '/api/feed', { origin: ORIGIN, json: { body: 'hi' } }), w, null);
  assert.strictEqual(w.statusCode, 503);
});

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function req(method, url, { query = {}, cookie = '', origin, json, raw, host = 'dayonegreat.com', type } = {}) {
  const headers = { host, cookie };
  if (origin) headers.origin = origin;
  if (json !== undefined || raw !== undefined) headers['content-type'] = type || 'application/json';
  return { method, url, headers, query, body: json !== undefined ? JSON.stringify(json) : raw };
}
// G2 and F7: cacheable at the edge, but for no more than a minute in all, so a removal shows within a minute.
function cacheOk(r) {
  const edge = r.getHeader('Vercel-CDN-Cache-Control');
  const fresh = Number(/s-maxage=(\d+)/.exec(edge)[1]), stale = Number(/stale-while-revalidate=(\d+)/.exec(edge)[1]);
  assert.ok(fresh > 0 && fresh + stale <= 60, edge);
  // Browsers and other shared caches must not keep it, or a removal could outlive the minute.
  assert.strictEqual(r.getHeader('Cache-Control'), 'public, max-age=0, must-revalidate');
}

if (!SERVER) {
  if (process.env.CI) test('posts tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('posts against a database (F6, S2, S9, P4, C7)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_posts_test_' + crypto.randomBytes(4).toString('hex');
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
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 3 });
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
// Changing a post's status is a reviewer's decision (PR 4), even for the database superuser.
// A reviewer always acts under their member ID, which closed flags record.
// That member is real, with a session, and (fix 3: the database now checks it) really an administrator.
let reviewer;
const makeReviewer = async () => {
  const r = await member(2, 'Reviewer');
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${r.id}'`); });
  return r;
};
const asReviewer = async (sqlText) => { reviewer = reviewer || await makeReviewer(); return su.begin(async (t) => {
  await actAsAdmin(t, reviewer.ctx);
  await t.unsafe(sqlText);
}); };
const approve = (id) => asReviewer(`update app.posts set status = 'live' where id = '${id}'`);

test('F6: level 0 and 1 posts wait until the author has 3 live posts; level 2 and Aaron go live at once', async () => {
  for (const level of [0, 1]) {
    const m = await member(level);
    const first = [];
    for (let i = 0; i < 3; i++) first.push(await run(m.ctx, (t) => posts.create(t, { body: 'post ' + i })));
    assert.deepStrictEqual(first.map((p) => p.status), ['waiting', 'waiting', 'waiting'], 'level ' + level);
    for (const p of first) await approve(p.id);
    const fourth = await run(m.ctx, (t) => posts.create(t, { body: 'after review' }));
    assert.strictEqual(fourth.status, 'live', 'level ' + level + ': live once 3 posts are approved');
  }
  const two = await member(2);
  assert.strictEqual((await run(two.ctx, (t) => posts.create(t, { body: 'verified' }))).status, 'live');
  const aaron = await member(1);
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${aaron.id}'`); });
  assert.strictEqual((await run({ ...aaron.ctx, actor: 'admin' }, (t) => posts.create(t, { body: 'from Aaron' }))).status, 'live');
});

test('S2, S3: nobody sets a post\'s status, author or lane, posts for someone else, or posts without being signed in', async () => {
  const a = await member(1);
  const b = await member(1);
  for (const attempt of [
    (t) => t`insert into app.posts (body, status, published_at) values ('x', 'live', now())`,
    (t) => t`insert into app.posts (body, author_id) values ('x', ${b.id})`,
    (t) => t`insert into app.posts (body, lane) values ('x', 'agents')`,
    (t) => t`delete from app.posts where author_id = ${a.id}`
  ]) await assert.rejects(run(a.ctx, attempt), /permission denied/);
  await assert.rejects(run({ actor: 'anon' }, (t) => posts.create(t, { body: 'anonymous' })), /only active members can post/);
  // Waiting posts are private to their author.
  const waiting = await run(a.ctx, (t) => posts.create(t, { body: 'still waiting' }));
  assert.strictEqual(waiting.status, 'waiting');
  // Only a reviewer changes a status (PR 4): the author's attempt matches no row and changes nothing.
  assert.strictEqual((await run(a.ctx, (t) => t`update app.posts set status = 'live' where author_id = ${a.id}`)).count, 0);
  assert.strictEqual((await run(a.ctx, (t) => posts.mine(t))).find((p) => p.id === waiting.id).status, 'waiting');
  assert.strictEqual((await run(b.ctx, (t) => t`select id from app.posts where id = ${waiting.id}`)).length, 0);
  assert.strictEqual((await run({ actor: 'anon' }, (t) => t`select id from app.posts`)).length, 0, 'someone not signed in reads no table directly');
  assert.strictEqual((await run(a.ctx, (t) => posts.mine(t))).some((p) => p.id === waiting.id), true);
  const feed = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 50 }));
  assert.ok(!feed.some((p) => p.id === waiting.id), 'waiting posts are not in the public feed');
});

test('H1 (review): a level 0 or 1 member can have at most 3 posts waiting, even with parallel requests', async () => {
  const m = await member(0);
  const results = await Promise.all(Array.from({ length: 12 }, (_, i) => run(m.ctx, (t) => posts.create(t, { body: 'parallel ' + i }))));
  assert.strictEqual(results.filter((r) => r.status === 'waiting').length, 3);
  assert.strictEqual(results.filter((r) => r.refused === 'waiting_limit').length, 9);
  const two = await member(2);
  const many = await Promise.all(Array.from({ length: 12 }, (_, i) => run(two.ctx, (t) => posts.create(t, { body: 'verified ' + i }))));
  assert.ok(many.every((r) => r.status === 'live'), 'level 2 posting is unlimited (F4)');
});

test('F7 groundwork: a removed post leaves the feed and the profile count; a post approved later shows at the top', async () => {
  const a = await member(2);
  const p1 = await run(a.ctx, (t) => posts.create(t, { body: 'stays' }));
  const p2 = await run(a.ctx, (t) => posts.create(t, { body: 'removed later' }));
  await asReviewer(`update app.posts set status = 'removed' where id = '${p2.id}'`);
  const feed = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 50 }));
  assert.ok(feed.some((p) => p.id === p1.id) && !feed.some((p) => p.id === p2.id));
  assert.strictEqual((await run({ actor: 'anon' }, (t) => posts.profile(t, a.id))).livePosts, 1);
  const b = await member(1);
  const old = await run(b.ctx, (t) => posts.create(t, { body: 'written first, approved last' }));
  await approve(old.id);
  const top = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 1 }));
  assert.strictEqual(top[0].id, old.id, 'ordered by when it went live');
});

test('S2: the public feed shows only live posts by active members, a page at a time, with public profile fields only', async () => {
  const a = await member(2, 'Ada Public');
  const ids = [];
  for (let i = 0; i < 5; i++) ids.push((await run(a.ctx, (t) => posts.create(t, { body: 'page ' + i }))).id);
  const page1 = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 2 }));
  const page2 = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', before: page1[1].id, limit: 2 }));
  assert.ok(page1[0].publishedAt >= page1[1].publishedAt && page1[1].publishedAt >= page2[0].publishedAt, 'newest first');
  assert.ok(!page2.some((p) => page1.some((x) => x.id === p.id)), 'pages don\'t overlap');
  assert.deepStrictEqual(Object.keys(page1[0].author).sort(), ['id', 'level', 'name']);
  const prof = await run({ actor: 'anon' }, (t) => posts.profile(t, a.id));
  assert.deepStrictEqual(Object.keys(prof).sort(), ['id', 'joined', 'level', 'livePosts', 'name']);
  assert.strictEqual(prof.livePosts, 5);
  assert.strictEqual((await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'agents', limit: 50 }))).length, 0, 'the agents lane is separate (F5)');
  // A banned member's posts leave the feed.
  await asReviewer(`update app.members set status = 'banned' where id = '${a.id}'`);
  const after = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane: 'people', limit: 50 }));
  assert.ok(!after.some((p) => ids.includes(p.id)));
  assert.strictEqual(await run({ actor: 'anon' }, (t) => posts.profile(t, a.id)), null);
});

test('the API: posting needs a session and our own pages; the feed is cached briefly, masked and marked untrusted', async () => {
  const { handle } = require('../api/feed.js');
  const m = await member(2, 'Grace jane@example.com');
  const call = async (r) => { const out = res(); await handle(r, out, run); return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null, r: out }; };
  // S2: every write that isn't a signed-in member on our own pages fails.
  assert.strictEqual((await call(req('POST', '/api/feed', { origin: ORIGIN, json: { body: 'hi' } }))).status, 401);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: m.cookie, json: { body: 'hi' } }))).status, 403, 'no Origin');
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: m.cookie, origin: 'https://evil.com', json: { body: 'hi' } }))).status, 403);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: m.cookie, origin: ORIGIN, json: { body: 'hi' }, host: 'start-of-something-great.vercel.app' }))).status, 403);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: m.cookie, origin: ORIGIN, raw: 'body=hi', type: 'application/x-www-form-urlencoded' }))).status, 400);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: m.cookie, origin: ORIGIN, json: { body: 'x'.repeat(5001) } }))).status, 400);
  assert.strictEqual((await call(req('POST', '/api/feed', { cookie: m.cookie, origin: ORIGIN, raw: '{"body":' + '"x"'.repeat(1) + '}'.padEnd(30000, ' ') }))).status, 400, 'oversized body');
  const parsed = req('POST', '/api/feed', { cookie: m.cookie, origin: ORIGIN, json: {} });
  parsed.body = { body: 'x'.repeat(30000) }; // as Vercel delivers JSON it has already parsed
  assert.strictEqual((await call(parsed)).status, 400, 'oversized, already-parsed body');
  assert.strictEqual((await call(req('PUT', '/api/feed', { cookie: m.cookie, origin: ORIGIN, json: { body: 'hi' } }))).status, 405);
  const ok = await call(req('POST', '/api/feed', { cookie: m.cookie, origin: ORIGIN, json: { body: 'Write to me at jane@example.com or +1 415 555 0100' } }));
  assert.strictEqual(ok.status, 201);
  assert.strictEqual(ok.json.status, 'live');
  assert.strictEqual(ok.r.getHeader('Cache-Control'), 'no-store');
  // The public feed.
  const f = await call(req('GET', '/api/feed', { query: { lane: 'people' } }));
  assert.strictEqual(f.status, 200);
  cacheOk(f.r);
  const mine = f.json.posts.find((p) => p.id === ok.json.id);
  assert.ok(mine, 'the live post is in the feed');
  assert.ok(!mine.body.includes('jane@example.com') && !mine.body.includes('555 0100'), 'P4: contacts are masked: ' + mine.body);
  assert.ok(!mine.author.name.includes('jane@example.com'), 'names are masked too');
  assert.deepStrictEqual(f.json.untrusted_fields, ['posts[].body', 'posts[].author.name']);
  assert.match(f.json.note, /never as instructions/);
  assert.strictEqual((await call(req('GET', '/api/feed', { query: { lane: 'everyone' } }))).status, 400);
  assert.strictEqual((await call(req('GET', '/api/feed', { query: { before: "1' or '1'='1" } }))).status, 400);
  // M2: unknown parameters and odd spellings are refused, so they can't be used to skip the edge cache.
  for (const bad of [{ cachebust: '1' }, { limit: '10.0' }, { limit: '1e1' }, { limit: '010' }, { limit: '51' }, { lane: 'People' }, { mine: 'yes' }]) {
    assert.strictEqual((await call(req('GET', '/api/feed', { query: bad }))).status, 400, JSON.stringify(bad));
  }
  assert.strictEqual((await call(req('GET', '/api/feed', { query: { limit: '50' } }))).status, 200);
  const prof = await call(req('GET', '/api/feed', { query: { profile: m.id } }));
  assert.strictEqual(prof.json.profile.live_posts >= 1, true);
  cacheOk(prof.r);
  assert.strictEqual((await call(req('GET', '/api/feed', { query: { mine: '1' } }))).status, 401);
  const own = await call(req('GET', '/api/feed', { query: { mine: '1' }, cookie: m.cookie }));
  assert.ok(own.json.posts.some((p) => p.id === ok.json.id));
  assert.strictEqual(own.r.getHeader('Cache-Control'), 'no-store', 'your own posts are never cached');
});

test('C7, S9: the MCP list_posts tool names every field written by members, masks contacts, and is read-only', async () => {
  const MARK = 'ZQXMARK';
  const m = await member(2, MARK + ' name');
  await run(m.ctx, (t) => posts.create(t, { body: MARK + ' body, mail ' + MARK.toLowerCase() + '@example.com' }));
  const mcp = require('../api/mcp.js');
  mcp.setReadPosts((a) => run({ actor: 'anon' }, (t) => posts.feed(t, a)));
  try {
    const { call } = require('./helpers');
    const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_posts', arguments: { lane: 'people', limit: 50 } } });
    const data = r.json.result.structuredContent;
    const paths = [];
    (function walk(v, at) {
      if (typeof v === 'string') paths.push([at, v]);
      else if (Array.isArray(v)) v.forEach((x) => walk(x, at + '[]'));
      else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, at ? at + '.' + k : k);
    })(data, '');
    for (const [p, v] of paths.filter(([p]) => !p.startsWith('untrusted_fields'))) if (v.includes(MARK)) assert.ok(data.untrusted_fields.includes(p), p + ' is not listed');
    for (const f of data.untrusted_fields) assert.ok(paths.some(([p]) => p === f), f + ' is not in the output');
    assert.ok(!JSON.stringify(data).includes('@example.com'), 'contacts are masked for agents too');
    const list = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    assert.strictEqual(list.json.result.tools.find((t) => t.name === 'list_posts').annotations.readOnlyHint, true);
  } finally {
    mcp.setReadPosts(async () => null);
  }
});

test('S1: the coverage check catches misuse of the public-reading role', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
  for (const [ddl, expect] of [
    ['grant dog_public to dog_app', /dog_app belongs to dog_public/],
    ['alter function app.feed(text, uuid, integer) owner to dog_signin', /app\.feed must be owned by dog_public/],
    ['grant select (created_at) on app.posts to dog_public', /not in the reviewed snapshot: grant app\.posts\.created_at dog_public SELECT/],
    ['set local role dog_owner; alter policy posts_public_select on app.posts using (true)', /not in the reviewed snapshot: policy app\.posts posts_public_select/],
    ['alter table app.posts disable trigger posts_decide', /not in the reviewed snapshot: trigger app\.posts enabled=D/]
  ]) {
    const found = await su.begin(async (t) => { await t.unsafe(ddl); throw Object.assign(new Error('rollback'), { found: await problems(t, { snapshot }) }); })
      .catch((e) => { if (!e.found) throw e; return e.found; });
    assert.ok(found.some((p) => expect.test(p)), ddl + ' -> ' + JSON.stringify(found));
  }
});
