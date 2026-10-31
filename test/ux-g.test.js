// UX PR G (the UI/UX review of Oct 31, findings 8, 12, 13 and 14; Aaron, Oct 31: "We address the remaining items 7 to
// 14"): the question IDs in Aaron's queue, the administrator's badge, the people feed in the /api index, and search and
// an author filter over live posts (035). The parts that need a database are below the first few checks.
'use strict';

const { promote, shadowMode, fresh, call } = require('./helpers');
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
const jevs = require('../db/jevs');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };
// Read when used, so each check below fails on its own where 035 is missing.
const migration = () => (fs.existsSync(path.join(root, 'db/migrations/035_feed_search.sql')) ? read('db/migrations/035_feed_search.sql') : '');

test('finding 12: /review names the questions by their public titles, the same as db/jevs.js, and stays blind to the other reviewer', () => {
  const js = read('review.js');
  const map = js.match(/var TITLES = \{([\s\S]*?)\};/)[1];
  const titles = Object.fromEntries([...map.matchAll(/(J\d\d): '((?:[^'\\]|\\.)*)'/g)].map((m) => [m[1], JSON.parse('"' + m[2] + '"')]));
  assert.deepStrictEqual(titles, Object.fromEntries(jevs.QUESTIONS.map((q) => [q.id, q.title])), 'review.js and db/jevs.js name the same questions the same way');
  assert.match(js, /'Our checks asked about: ' \+ ids\.map\(function \(id\) \{ return TITLES\[id\] \? TITLES\[id\] \+ ' \(' \+ id \+ '\)' : id; \}\)\.join\(', '\)/);
  assert.doesNotMatch(js, /second.?look/i);
  assert.doesNotMatch(js.replace(/\/\/.*$/gm, ''), /score/i, 'the page\u2019s code never reads a score');
});

test('finding 14: /api lists the people feed beside the agents lane, with the parameters both take', async () => {
  const r = await call(fresh('index.js'), 'GET', '/api');
  assert.strictEqual(r.json.endpoints.posts, 'https://dayonegreat.com/api/feed?lane=people');
  assert.strictEqual(r.json.agents.posts, 'https://dayonegreat.com/api/feed?lane=agents', 'the agents entry stays');
  for (const p of ['limit (1 to 50)', 'before', 'author (a member ID', 'q (2 to 100 characters']) assert.ok(r.json.posts_note.includes(p), 'the note names ' + p);
  assert.strictEqual(r.json.read_only, true);
});

test('the guides name the filters and what search won’t look for', () => {
  const llms = read('llms.txt');
  assert.match(llms, /author=<member ID> for one member's posts/);
  assert.match(llms, /q=<2 to 100 characters> for posts containing every word of the search/);
  assert.match(llms, /a search that is an email address, a phone number or a key is refused \(400\), no word with a digit or an @ is searched/);
  assert.match(llms, /author\.role "administrator"/);
  const connect = read('connect.html');
  assert.match(connect, /<a href="\/api\/feed\?lane=people">\/api\/feed\?lane=people<\/a>/);
  assert.match(connect, /<code>author=&lt;member ID&gt;<\/code>/);
  assert.match(connect, /<code>q=&lt;words&gt;<\/code> \(2 to 100 characters\)/);
});

test('/api/status and the home page say what Second Look may do: easy holds only; appeals and hard cases go to Aaron', () => {
  const { status } = fresh('_lib.js');
  const line = status.phase.live.find((x) => /automated checks/.test(x.text)).text;
  assert.strictEqual(line, 'Every account and post checked by our automated checks: low risk goes ahead, high risk is held for review; a narrow AI may clear only easy holds, when it is switched on, and appeals and hard cases go to Aaron.');
  for (const f of ['api/_lib.js', 'index.html']) assert.ok(!read(f).includes('high risk waits for a person'), f + ' has no old line left');
  // True of the code: 034's gate refuses any post with a report, an appeal or a first-post flag open, or any question
  // other than the five easy ones above 0.
  const gate = read('db/migrations/034_second_look_v1.sql');
  assert.match(gate, /and not exists \(select 1 from app\.review_flags f where f\.post_id = p\.id and f\.resolved_at is null\s+and not \(f\.source = 'classifier' and f\.classifier = 'jevs'\)\)/);
  assert.match(gate, /e\.key <> all \(array\['J01', 'J02', 'J04', 'J07', 'J13'\]\)/);
});

test('/feed: a labelled search box above the list, with Clear and one status line; the administrator’s name says so', () => {
  const html = read('feed.html');
  const form = html.match(/<form id="search" class="search" role="search">[\s\S]*?<\/form>/);
  assert.ok(form, 'the search form');
  assert.match(form[0], /<label for="q">Search posts<\/label>/);
  assert.match(form[0], /<input id="q" name="q" type="search" minlength="2" maxlength="100"/);
  assert.match(form[0], /<button type="button" id="clear" class="button" hidden>Clear<\/button>/);
  assert.ok(html.indexOf('id="search"') < html.indexOf('id="posts"'), 'above the list');
  const js = read('feed.js');
  assert.match(js, /if \(p\.author\.role === 'administrator'\) meta\.appendChild\(document\.createTextNode\(' · Administrator'\)\);/);
  assert.match(js, /from \+ \(n === 1 \? ' matches' : ' match'\)/);
  assert.match(js, /'&q=' \+ encodeURIComponent\(query\)/);
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(js), 'still no HTML injection points');
});

test('GET /api/feed: author and q are checked before anything is read', async () => {
  const { handle } = fresh('feed.js');
  const get = async (query) => {
    const out = { statusCode: 200, headers: {}, setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b; } };
    await handle({ method: 'GET', url: '/api/feed', headers: { host: 'dayonegreat.com' }, query }, out, null);
    return { status: out.statusCode, json: JSON.parse(out.body) };
  };
  const A = '0190a000-0000-7000-8000-000000000001';
  assert.strictEqual((await get({ author: A })).status, 200);
  assert.strictEqual((await get({ q: 'hello world', lane: 'agents', limit: '5' })).status, 200);
  for (const bad of [{ author: 'nobody' }, { author: A, profile: A }, { q: 'hello', mine: '1' }, { q: 'hello', queue: '1' }, { q: 'hello', receipt: A }]) {
    const r = await get(bad);
    assert.strictEqual(r.status, 400, JSON.stringify(bad));
    assert.match(r.json.error, /author \(a member ID\), q \(words to search for, 2 to 100 characters\)/);
  }
  assert.match((await get({ q: 'x' })).json.error, /^q must be 2 to 100 characters\.$/);
  assert.match((await get({ q: 'y'.repeat(101) })).json.error, /^q must be 2 to 100 characters\.$/);
  for (const contact of ['jane@example.com', 'call +1 415 555 0100', 'ｊａｎｅ＠ｅｘａｍｐｌｅ．ｃｏｍ']) {
    assert.match((await get({ q: contact })).json.error, /^q can’t search for email addresses, phone numbers or keys/, contact);
  }
  assert.match((await get({ q: '2026' })).json.error, /^q needs at least one word of letters/);
});

test('MCP list_posts takes author and q, refuses the same searches, and stays read-only with the same ten tools', async () => {
  const mcp = fresh('mcp.js');
  const list = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  const lp = list.json.result.tools.find((t) => t.name === 'list_posts');
  assert.deepStrictEqual(Object.keys(lp.inputSchema.properties).sort(), ['author', 'lane', 'limit', 'q']);
  assert.strictEqual(lp.annotations.readOnlyHint, true);
  assert.strictEqual(list.json.result.tools.length, 10);
  const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_posts', arguments: { q: 'jane@example.com' } } });
  assert.strictEqual(r.json.result.isError, true);
  assert.match(r.json.result.content[0].text, /can’t search for email addresses/);
  const r2 = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_posts', arguments: { author: 'nobody' } } });
  assert.match(r2.json.result.content[0].text, /^author must be a member ID\.$/);
});

test('035 changes no sign-in, Second Look or infrastructure object, and uses no extension', () => {
  assert.doesNotMatch(migration(), /create extension|pg_trgm/i);
  assert.doesNotMatch(migration().replace(/^--.*$/gm, ''), /app\.(sl_|sign_in|session|identity|code_|file_|agent_resolve|actor_|act_as)/, 'only the feed, its search table and words, and one column');
  assert.match(migration(), /^grant select \(is_admin\) on app\.members to dog_public;$/m);
  // Every right it grants: the words function and the search table to dog_public, the one column, the feed to the site,
  // and create on app only while ownership changes (taken back at once).
  assert.deepStrictEqual(migration().match(/^grant .*$/gm), [
    'grant execute on function app.post_search_text(text) to dog_public;',
    'grant select, insert, update, delete on app.post_search to dog_public;',
    'grant create on schema app to dog_public;',
    'grant select (is_admin) on app.members to dog_public;',
    'grant execute on function app.feed(text, uuid, integer, uuid, text) to dog_app;',
    'grant create on schema app to dog_public;']);
  assert.strictEqual((migration().match(/^revoke create on schema app from dog_public;$/gm) || []).length, 2);
});

// ---- Against a database ----

if (!SERVER) {
  if (process.env.CI) test('UX PR G tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('UX PR G against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_uxg_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sqlText) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sqlText); });
const setMode = (m) => asOwner(`update app.jevs_settings set value = '${m}' where key = 'mode'`);

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su); // the features under JEVs; the queue's test switches enforce on for itself
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  aaron = await member(2, 'Aaron');
  await asOwner(`update app.members set is_admin = false where is_admin; update app.members set is_admin = true where id = '${aaron.id}'`);
  aaron.ctx = { ...aaron.ctx, actor: 'admin' };
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
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: Math.min(level, 1), displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function httpReq(method, url, { cookie = '', json, key, query = {} } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '203.0.113.70', 'x-vercel-ip-country': 'US' };
  if (method === 'POST') headers.origin = ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url, headers, query, body: json === undefined ? undefined : JSON.stringify(json) };
}
async function feed(method, opts) {
  const r = res();
  await require('../api/feed.js').handle(httpReq(method, '/api/feed', opts), r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null, r };
}
async function agentsApi(method, route, opts) {
  const r = res();
  await require('../api/agents.js').handle(httpReq(method, '/api/agents/' + route, { ...opts, query: { route } }), r, run, CFG);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
const say = async (who, body) => {
  const r = await feed('POST', { cookie: who.cookie, json: { body } });
  assert.ok([201, 202].includes(r.status), JSON.stringify(r.json));
  return r.json.id;
};
const get = (query) => feed('GET', { query });
const links = (n) => 'new sites ' + Array.from({ length: n }, (_, i) => 'https://s' + i + '-' + crypto.randomBytes(3).toString('hex') + '.example').join(' ');
const word = () => 'w' + crypto.randomBytes(5).toString('hex').replace(/\d/g, (d) => 'abcdefghij'[d]); // letters only, unique to a test

test('the database passes the coverage check with 035, and matches the reviewed snapshot (S1)', async () => {
  const snapshot = read('db/snapshot.txt').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('finding 8: the administrator’s posts carry author.role in both lanes; nobody else’s have a role field', async () => {
  const tag = word();
  const ada = await member(2, 'Ada');
  const mine = await say(aaron, 'From the administrator ' + tag);
  const hers = await say(ada, 'From a member ' + tag);
  const people = (await get({ lane: 'people', limit: '50' })).json.posts;
  assert.deepStrictEqual(people.find((p) => p.id === mine).author.role, 'administrator');
  assert.ok(!Object.hasOwn(people.find((p) => p.id === hers).author, 'role'), 'no role field for a member');
  assert.deepStrictEqual(Object.keys(people.find((p) => p.id === hers).author).sort(), ['id', 'level', 'name', 'profile']);
  // The agents lane: the author is the agent's owner.
  const made = await agentsApi('POST', '', { cookie: aaron.cookie, json: { name: 'Aaron helper', post: 'act' } });
  assert.strictEqual(made.status, 201, JSON.stringify(made.json));
  const posted = await feed('POST', { key: made.json.key, json: { body: 'An agent of the administrator ' + tag } });
  assert.strictEqual(posted.status, 201, JSON.stringify(posted.json));
  const agents = (await get({ lane: 'agents', limit: '50' })).json.posts;
  assert.strictEqual(agents.find((p) => p.id === posted.json.id).author.role, 'administrator');
  // The MCP tool shapes posts the same way.
  const mcp = require('../api/mcp.js');
  mcp.setReadPosts((a) => run({ actor: 'anon' }, (t) => posts.feed(t, a)));
  try {
    const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_posts', arguments: { q: tag, limit: 50 } } });
    const got = r.json.result.structuredContent.posts;
    assert.deepStrictEqual(got.map((p) => p.id).sort(), [mine, hers].sort(), 'list_posts searches too');
    assert.strictEqual(got.find((p) => p.id === mine).author.role, 'administrator');
  } finally { mcp.setReadPosts(async () => null); }
});

test('finding 8: anonymous readers gain only that one yes or no; the site’s role still can’t read it directly', async () => {
  const cols = await q(`select column_name from information_schema.column_privileges
                        where table_schema = 'app' and table_name = 'members' and grantee = 'dog_public' and privilege_type = 'SELECT' order by 1`);
  assert.deepStrictEqual(cols.map((r) => r.column_name), ['created_at', 'display_name', 'id', 'is_admin', 'trust_level']);
  // Someone not signed in reads no table directly, as before.
  assert.strictEqual((await run({ actor: 'anon' }, (t) => t`select id from app.members`)).length, 0);
  // The profile answer is unchanged: no flag there.
  const prof = await get({ profile: aaron.id });
  assert.deepStrictEqual(Object.keys(prof.json.profile).sort(), ['id', 'joined', 'level', 'live_posts', 'name']);
  // The old three-argument call still works, so the site and 035 can reach production in either order.
  const rows = await run({ actor: 'anon' }, (t) => t`select * from app.feed('people', null::uuid, 5::integer)`);
  assert.ok(rows.length >= 1 && Object.hasOwn(rows[0], 'author_admin'));
});

test('finding 12: the queue names the questions that flagged a held post, above pass_max and highest first, never a score', async () => {
  await setMode('enforce');
  try {
    const m = await member(2, 'Linker');
    // High risk: four links to new sites and contact details (as jevs.test.js holds a post for Aaron).
    const held = await feed('POST', { cookie: m.cookie, json: { body: links(4) + ' or mail me at linker@example.com' } });
    assert.strictEqual(held.status, 202, JSON.stringify(held.json));
    const [d] = await q(`select scores from app.jevs_decisions where subject_id = '${held.json.id}' and effect = 'hold' and applied`);
    const [{ value: passMax }] = await q(`select value from app.jevs_settings where key = 'pass_max'`);
    const want = Object.entries(d.scores).filter(([, v]) => v > Number(passMax)).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([k]) => k);
    assert.ok(want.length >= 2 && want[0] === 'J07', 'links scored highest: ' + JSON.stringify(d.scores));
    const queue = await feed('GET', { cookie: aaron.cookie, query: { queue: '1' } });
    const item = queue.json.items.find((i) => i.id === held.json.id);
    assert.deepStrictEqual(item.questions, want);
    assert.ok(item.questions.every((x) => /^J\d\d$/.test(x)), 'IDs only');
    assert.ok(!JSON.stringify(item).includes('"scores"') && !JSON.stringify(item.questions).match(/\d{3}|:\s*\d/), 'no scores');
    assert.strictEqual(item.second_look, undefined, 'still blind to the other reviewer');
    // A score at pass_max isn't named: J02 for a GitHub member scores exactly 10 (db/jevs.js).
    assert.strictEqual(d.scores.J02, 10);
    assert.ok(!item.questions.includes('J02'));
    // A post that is only reported has no JEVs decision behind it: no questions.
    await setMode('shadow');
    const author = await member(2, 'Reported');
    const reporter = await member(2, 'Reporter');
    const p = await say(author, 'Something plain to report ' + word());
    assert.strictEqual((await feed('POST', { cookie: reporter.cookie, json: { report: p, reason: 'spam' } })).status, 202);
    const q2 = await run(aaron.ctx, (t) => review.queue(t, {}));
    assert.deepStrictEqual(q2.items.find((i) => i.id === p).questions, []);
  } finally {
    await setMode('shadow');
  }
});

test('finding 3 of the review: the queue never fails on pass_max, and names questions by today’s line', async () => {
  // The post the test above held is still waiting for Aaron.
  const heldItem = async () => (await feed('GET', { cookie: aaron.cookie, query: { queue: '1' } })).json.items.find((i) => i.questions.length);
  const before = await heldItem();
  assert.ok(before && before.questions.length >= 2, 'a held item to read');
  // Aaron raises the line: only questions above it are named now (the decision keeps scores, not the line of its day).
  await asOwner(`update app.jevs_settings set value = '30' where key = 'pass_max'`);
  try {
    assert.deepStrictEqual((await heldItem()).questions, ['J07']);
    // A value that isn't a whole number (010's trigger refuses one; a superuser forces it here) counts as 10, the seed,
    // and the queue still loads.
    await su.begin(async (t) => {
      await t.unsafe('alter table app.jevs_settings disable trigger jevs_settings_check');
      await t.unsafe(`update app.jevs_settings set value = 'ten' where key = 'pass_max'`);
      await t.unsafe('alter table app.jevs_settings enable always trigger jevs_settings_check');
    });
    const r = await feed('GET', { cookie: aaron.cookie, query: { queue: '1' } });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.json.items.find((i) => i.id === before.id).questions, before.questions);
  } finally {
    await asOwner(`update app.jevs_settings set value = '10' where key = 'pass_max'`);
  }
  assert.ok(/coalesce\(\(select case when s\.value ~ '\^\[0-9\]\{1,4\}\$' then s\.value::integer end/.test(read('db/review.js')));
});

test('finding 13: author= lists one member’s live posts, newest first, a page at a time with the filter kept', async () => {
  const a = await member(2, 'Author A');
  const b = await member(2, 'Author B');
  const ids = [];
  for (let i = 0; i < 5; i++) ids.push(await say(a, 'A writes ' + i));
  await say(b, 'B writes');
  const p1 = await get({ author: a.id, limit: '2' });
  assert.strictEqual(p1.status, 200);
  assert.deepStrictEqual(p1.json.posts.map((p) => p.id), [ids[4], ids[3]]);
  assert.strictEqual(p1.json.next, '/api/feed?lane=people&author=' + a.id + '&before=' + ids[3] + '&limit=2');
  const all = [];
  let next = '/api/feed?lane=people&author=' + a.id + '&limit=2';
  while (next) {
    const u = new URL(next, ORIGIN);
    const page = await get(Object.fromEntries(u.searchParams));
    all.push(...page.json.posts.map((p) => p.id));
    next = page.json.next;
  }
  assert.deepStrictEqual(all, [...ids].reverse(), 'every page, no repeats, only A');
  assert.deepStrictEqual((await get({ author: a.id, lane: 'agents' })).json.posts, [], 'lanes stay separate');
  // A banned member's posts leave the list, as they leave the feed.
  await su.begin(async (t) => { await t`select app.act_as('admin', ${aaron.id}::uuid, null, false, ${aaron.ctx.session}, null, null)`; await t.unsafe(`update app.members set status = 'banned' where id = '${b.id}'`); });
  assert.deepStrictEqual((await get({ author: b.id })).json.posts, []);
});

test('finding 13: q finds live posts with every word, any case, a page at a time, masked as everywhere', async () => {
  const tag = word();
  const m = await member(2, 'Gardener');
  const both = await say(m, 'Our ' + tag + ' GARDEN needs volunteers on Saturday. Mail garden@example.com');
  const one = await say(m, 'The ' + tag + ' garden is closed.');
  await say(m, 'Volunteers wanted for something else.');
  const r = await get({ q: tag.toUpperCase() + ' garden volunteers' });
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(r.json.posts.map((p) => p.id), [both]);
  assert.ok(r.json.posts[0].body.includes('[email hidden]'), 'masked as in the feed');
  assert.deepStrictEqual(r.json.untrusted_fields, ['posts[].body', 'posts[].author.name']);
  const two = await get({ q: tag + ' garden', limit: '1' });
  assert.deepStrictEqual(two.json.posts.map((p) => p.id), [one]);
  assert.strictEqual(two.json.next, '/api/feed?lane=people&q=' + encodeURIComponent(tag + ' garden') + '&before=' + one + '&limit=1');
  const after = await get({ q: tag + ' garden', before: one, limit: '1' });
  assert.deepStrictEqual(after.json.posts.map((p) => p.id), [both]);
  // With author too.
  const other = await member(2, 'Other gardener');
  await say(other, 'A ' + tag + ' garden of my own');
  assert.deepStrictEqual((await get({ q: tag + ' garden', author: m.id })).json.posts.map((p) => p.id).sort(), [both, one].sort());
  // Removed posts are never found.
  await su.begin(async (t) => { await t`select app.act_as('admin', ${aaron.id}::uuid, null, false, ${aaron.ctx.session}, null, null)`; await t.unsafe(`update app.posts set status = 'removed' where id = '${one}'`); });
  assert.deepStrictEqual((await get({ q: tag + ' garden', author: m.id })).json.posts.map((p) => p.id), [both]);
});

const wordsOf = async (postId) => (await q(`select words::text as w from app.post_search where post_id = '${postId}'`)).map((r) => r.w)[0];

test('finding 13: app.post_search holds one row per live post, kept in step as posts go live, leave and come back', async () => {
  const m = await member(2, 'Kept');
  const id = await say(m, 'Kept in step ' + word());
  assert.ok(await wordsOf(id), 'a live post has its row');
  const admin = (sqlText) => su.begin(async (t) => { await t`select app.act_as('admin', ${aaron.id}::uuid, null, false, ${aaron.ctx.session}, null, null)`; await t.unsafe(sqlText); });
  await admin(`update app.posts set status = 'removed' where id = '${id}'`);
  assert.strictEqual(await wordsOf(id), undefined, 'a removed post has none');
  await admin(`update app.posts set status = 'live' where id = '${id}'`);
  const [r] = await q(`select s.published_at = p.published_at as same, s.lane, s.author_id from app.post_search s join app.posts p on p.id = s.post_id where s.post_id = '${id}'`);
  assert.deepStrictEqual([r.same, r.lane, r.author_id], [true, 'people', m.id], 'back, with the time it went live again');
  // Only dog_public writes it, and only through the trigger; the site's role can't read or write it at all.
  await assert.rejects(run({ actor: 'anon' }, (t) => t`select post_id from app.post_search`), /permission denied/);
  await assert.rejects(run(m.ctx, (t) => t`delete from app.post_search`), /permission denied/);
});

test('finding 2 of the review: the index never holds hidden contact text, nor any part of it, in any script', async () => {
  const m = await member(2, 'Hidden parts');
  const cases = {
    plus: 'Write jane+label@example.com today',
    idn: 'Write to zebra@exämple.com today',
    wide: 'Mail ｊａｎｅ＠ｅｘａｍｐｌｅ．ｃｏｍ today',
    small: 'Mail jane﹫example.com today',
    arabic: 'Call ٥٥٥١٢٣٤٥٦٧ today',
    persian: 'Call ۵۵۵۱۲۳۴۵۶۷ today',
    devanagari: 'Call ५५५१२३४५६७ today',
    fullwidth: 'Call ５５５-１２３-４５６７ today',
    ascii: 'Call +1 (415) 555-0100 today'
  };
  for (const [name, body] of Object.entries(cases)) {
    const id = await say(m, body);
    const w = await wordsOf(id);
    assert.ok(/'today'/.test(w), name + ': the rest is searchable: ' + w);
    assert.ok(!/jane|label|zebra|exämple|example|ｊａｎｅ|ｅｘａｍｐｌｅ|[\p{Nd}]/u.test(w), name + ': nothing of the address or number: ' + w);
  }
});

test('finding 2 of the review: what the database strips is exactly what the masking reads as an at sign or a digit', async () => {
  // Node's own Unicode tables, as api/_proposals.js's fold uses them: any decimal digit, and anything NFKC makes an at
  // sign or a digit. The database must strip every one of them, and nothing else, in the first two planes.
  const want = [];
  for (let cp = 32; cp < 0x20000; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const ch = String.fromCodePoint(cp);
    if (/[@\p{Nd}]/u.test(ch) || /[@\p{Nd}]/u.test(ch.normalize('NFKC'))) want.push(cp);
  }
  const [{ have }] = await q(`select coalesce(array_agg(cp order by cp), '{}') as have from generate_series(32, 131071) cp
    where (cp < 55296 or cp > 57343) and app.post_search_text('x' || chr(cp) || 'x') = ' '`);
  assert.deepStrictEqual(have.map(Number), want);
  // The site refuses the same searches the database would leave empty.
  const { searchProblem } = require('../api/feed.js');
  assert.match(searchProblem('gpt4 2026'), /^q needs at least one word of letters/);
  assert.strictEqual(searchProblem('gpt4 release'), null);
});

test('finding 2 of the review: with 3 hidden-only matches newer than a visible one, the visible one is still found', async () => {
  const tag = word();
  const m = await member(2, 'Reachable');
  const shown = await say(m, 'A ' + tag + ' crossing near the park.');
  // Newer, with the word only inside hidden addresses (each would have been indexed before the review).
  const hidden = [];
  for (const body of [tag + '+label@example.com', 'Write to ' + tag + '@exämple.com', 'Mail ' + tag + '＠example.com']) hidden.push(await say(m, body));
  const [{ found }] = await q(`select count(*)::int as found from app.post_search where words @@ plainto_tsquery('pg_catalog.simple'::regconfig, '${tag}')`);
  assert.strictEqual(found, 1, 'only the visible one is in the index');
  for (const limit of ['1', '2', '20']) {
    const page = await get({ q: tag, limit });
    assert.deepStrictEqual(page.json.posts.map((p) => p.id), [shown], 'limit ' + limit);
    assert.ok(!hidden.some((h) => JSON.stringify(page.json).includes(h)));
  }
  // Words and numbers together: the number must be shown, and here it is hidden.
  const phone = await say(m, 'hello, call +1 415 555 0100');
  assert.ok(!(await get({ q: 'hello 0100' })).json.posts.some((p) => p.id === phone));
  assert.strictEqual(await wordsOf(phone), "'call' 'hello'");
});

test('finding 1 of the review: at 100,000 posts, as dog_public, search uses post_search_words and a member’s posts use posts_live_author', async (t) => {
  // The plans of app.feed's own statements, as it really runs them: as dog_public, under every policy, read with
  // auto_explain (LOG lines sent to this client). Building 100,000 posts this fast and loading auto_explain need a
  // superuser, so this skips on Supabase's image, where the tests aren't one; it runs on the postgres:17 job and locally.
  const [{ rolsuper }] = await q(`select rolsuper from pg_roles where rolname = current_user`);
  if (!rolsuper) return t.skip('needs a superuser (not on Supabase’s image)');
  const logs = [];
  const one = postgres(at(SERVER, NAME), { max: 1, ssl: false, onnotice: (n) => logs.push(n.message) });
  try {
    const out = await one.begin(async (x) => {
      // Tests only, rolled back: the superuser adds the posts with the table's triggers off, and their search rows itself.
      const [a] = await x`insert into app.members (display_name) values ('Bulk') returning id`;
      const [b] = await x`insert into app.members (display_name) values ('Rare author') returning id`;
      await x.unsafe('alter table app.posts disable trigger all');
      await x.unsafe(`insert into app.posts (author_id, body, status, published_at, created_at)
        select case when i % 100 = 0 then '${b.id}'::uuid else '${a.id}'::uuid end,
               'post ' || i || ' about ' || (array['gardens', 'music', 'code', 'trust', 'food'])[1 + i % 5] || case when i % 5000 = 0 then ' rareword' else '' end,
               'live', now() - make_interval(secs => i), now() - make_interval(secs => i)
        from generate_series(1, 100000) i`);
      await x.unsafe(`insert into app.post_search (post_id, lane, author_id, published_at, words)
        select p.id, p.lane, p.author_id, p.published_at, strip(to_tsvector('pg_catalog.simple'::regconfig, app.post_search_text(p.body)))
        from app.posts p where p.status = 'live' and not exists (select 1 from app.post_search s where s.post_id = p.id)`);
      await x.unsafe('alter table app.posts enable trigger all');
      await x.unsafe('analyze app.posts; analyze app.post_search; analyze app.members');
      await x.unsafe(`load 'auto_explain'; set local auto_explain.log_min_duration = 0; set local auto_explain.log_nested_statements = on;
        set local auto_explain.log_analyze = on; set local client_min_messages = log; set local role dog_public`);
      const timed = async (call) => { logs.length = 0; const t0 = process.hrtime.bigint(); const rows = await x.unsafe(call);
        return { rows: rows.length, ms: Number(process.hrtime.bigint() - t0) / 1e6, plan: logs.join('\n') }; };
      const r = {
        search: await timed(`select * from app.feed('people', null, 20, null, 'rareword')`),
        common: await timed(`select * from app.feed('people', null, 20, null, 'gardens')`),
        author: await timed(`select * from app.feed('people', null, 20, '${b.id}', null)`)
      };
      throw Object.assign(new Error('rollback'), { r });
    }).catch((e) => { if (!e.r) throw e; return e.r; });
    const words = out.search.plan.split('Query Text:').find((p) => /post_search s/.test(p)) || '';
    assert.match(words, /Bitmap Index Scan on post_search_words/, out.search.plan);
    assert.strictEqual(out.search.rows, 20);
    assert.match(out.author.plan, /Index (Only )?Scan using posts_live_author/, out.author.plan);
    assert.strictEqual(out.author.rows, 20);
    assert.strictEqual(out.common.rows, 20);
    t.diagnostic(`as dog_public at 100,000 posts: rare word ${out.search.ms.toFixed(1)} ms, common word ${out.common.ms.toFixed(1)} ms, author ${out.author.ms.toFixed(1)} ms (with auto_explain's timing on)`);
    assert.ok(out.search.ms < 1000 && out.author.ms < 1000, 'well under the second a search took before');
  } finally {
    await one.end({ timeout: 5 });
  }
  assert.strictEqual((await q(`select count(*)::int as n from app.posts where body like '%rareword%'`))[0].n, 0, 'rolled back');
  // The function's search is the statement marked in the migration, through the side table's index.
  assert.match(migration(), /-- search:begin[\s\S]*from app\.post_search s\s+where s\.words @@ v_words[\s\S]*-- search:end/);
  assert.match(migration(), /create index post_search_words on app\.post_search using gin \(words\);/);
  assert.doesNotMatch(migration().replace(/^\s*--.*$/gm, ''), /posts_live_words|to_tsvector\([^)]*p\.body\) @@/, 'no search on app.posts left');
});

test('the database refuses a search outside 2 to 100 characters itself', async () => {
  for (const s of ['x', 'y'.repeat(101)]) {
    await assert.rejects(run({ actor: 'anon' }, (t) => t`select * from app.feed('people', null::uuid, 5::integer, null::uuid, ${s}::text)`), /bad feed request/);
  }
  assert.strictEqual((await run({ actor: 'anon' }, (t) => t`select * from app.feed('people', null::uuid, 5::integer, null::uuid, '2026 ...'::text)`)).length, 0, 'nothing left to look for: nothing');
  await assert.rejects(run({ actor: 'anon' }, (t) => posts.feed(t, { q: 'two\nlines' })), /control characters/);
});

test('/team: JEVs\'s card says high risk is held for review, by Aaron or, for easy holds only, Second Look when on (034)', () => {
  const read = (f) => require('fs').readFileSync(require('path').join(__dirname, '..', f), 'utf8');
  const team = read('team.html');
  assert.match(team, /high risk is held for review: by Aaron, or for easy holds only, by Second Look when it is on\./);
  assert.ok(!/high risk waits for Aaron/.test(team));
  assert.match(read('db/migrations/034_second_look_v1.sql'), /if v_decision <> 'clear' or s\.mode <> 'on' or s\.paused_reason is not null then/);
});
