// Fix 2 (harness/PLAN.md; USE-CASES.md row 10): posts JEVs hid on GitHub are kept from agents. GitHub's REST API, which
// the site reads the conversation from, doesn't say which comments are hidden; the database (018) does.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const { fresh, call } = require('./helpers');
const { migrate } = require('../scripts/migrate');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;

// A fake GitHub with one discussion and three replies, one of which JEVs hid.
function fakeGitHub() {
  global.fetch = async (url) => {
    const u = String(url);
    const body = u.includes('/discussions/1/comments')
      ? ['DC_ok1', 'DC_hidden', 'DC_ok2'].map((id, i) => ({ node_id: id, user: { login: 'p' + i }, created_at: 't', body: 'reply ' + id, html_url: 'h' + i }))
      : { node_id: 'D_thread', title: 'Hi', html_url: 'h', user: { login: 'a' }, body: 'b', comments: 3 };
    return { status: 200, ok: true, headers: { get: () => '5000' }, json: async () => body };
  };
}

test('fix 2: a post JEVs hid on GitHub never reaches an agent (API and MCP), and the answer says it was left out', async () => {
  fakeGitHub();
  const lib = fresh('_lib.js');
  const asked = [];
  lib.setHiddenCheck(async (ids) => { asked.push(...ids); return new Set(['DC_hidden']); });
  const c = await lib.getConversation(20);
  assert.deepStrictEqual(c.replies.map((r) => r.body), ['reply DC_ok1', 'reply DC_ok2']);
  assert.deepStrictEqual({ filter: c.hidden_posts.filter, left_out: c.hidden_posts.left_out }, { filter: 'on', left_out: 1 });
  assert.deepStrictEqual(asked, ['D_thread', 'DC_ok1', 'DC_hidden', 'DC_ok2'], 'it asks about exactly the posts it read from GitHub');
  const mcp = fresh('mcp.js');
  require(path.join(root, 'api', '_lib.js')).setHiddenCheck(async () => new Set(['DC_hidden']));
  const m = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_conversation', arguments: {} } });
  assert.ok(!m.text.includes('reply DC_hidden'), 'get_conversation leaves it out too');
});

test('R-6: a reply\'s agent tag line is named and marked not verified; the site and the gate read tag lines the same way', async () => {
  global.fetch = async (url) => {
    const u = String(url);
    const body = u.includes('/discussions/1/comments')
      ? [{ node_id: 'DC_t1', user: { login: 'someone' }, created_at: 't', body: 'Report.\n\n— agent scout for @aaron', html_url: 'h1' },
         { node_id: 'DC_t2', user: { login: 'other' }, created_at: 't', body: 'Plain reply.', html_url: 'h2' }]
      : { node_id: 'D_thread', title: 'Hi', html_url: 'h', user: { login: 'a' }, body: 'Opening post.\n\n— agent lead for @aaron', comments: 2 };
    return { status: 200, ok: true, headers: { get: () => '5000' }, json: async () => body };
  };
  const lib = fresh('_lib.js');
  lib.setHiddenCheck(async () => new Set());
  const c = await lib.getConversation(20);
  assert.deepStrictEqual(c.replies[0].agent_tag && { agent: c.replies[0].agent_tag.agent, for: c.replies[0].agent_tag.for, verified: c.replies[0].agent_tag.verified },
    { agent: 'scout', for: 'aaron', verified: false });
  assert.match(c.replies[0].agent_tag.note, /not verified/);
  assert.strictEqual(c.replies[1].agent_tag, null);
  assert.deepStrictEqual(c.thread.agent_tag && { agent: c.thread.agent_tag.agent, verified: c.thread.agent_tag.verified }, { agent: 'lead', verified: false }, 'the opening post too (the CSO\'s review, N5)');
  const J = await import('../supabase/functions/jevs/core.mjs');
  const samples = ['x\n— agent scout for @aaron', 'x\n-- agent a-1 for @B-c', 'x\n–agent  z for @q  ', 'x\n- agent scout for @aaron\n', 'agent scout for @aaron',
    'x\n— agent Scout for @aaron', 'x\n— agent scout for aaron', 'x\n— agent scout for @aaron and more', '— agent ' + 'a'.repeat(41) + ' for @x'];
  for (const b of samples) {
    const g = J.agentTag(b), l = lib.agentTagOf(b);
    assert.deepStrictEqual(l && { name: l.agent, owner: l.for }, g, 'in step with the gate: ' + JSON.stringify(b));
  }
});

test('fix 2: if the hidden-post check fails, the replies are left out and the answer says why; nobody is locked out', async () => {
  fakeGitHub();
  const lib = fresh('_lib.js');
  lib.setHiddenCheck(async () => { throw new Error('database down'); });
  const c = await lib.getConversation(20);
  assert.deepStrictEqual(c.replies, []);
  assert.strictEqual(c.thread.title, 'Hi', 'the thread itself is still there');
  assert.strictEqual(c.hidden_posts.filter, 'unavailable');
  assert.match(c.hidden_posts.note, /Read them on GitHub/);
});

test('fix 2: until the site has its database, the check is off and the answer says so plainly', async () => {
  fakeGitHub();
  delete process.env.DATABASE_URL;
  const lib = fresh('_lib.js');
  const c = await lib.getConversation(20);
  assert.strictEqual(c.replies.length, 3, 'unchanged from today');
  assert.strictEqual(c.hidden_posts.filter, 'off');
  assert.match(c.hidden_posts.note, /not switched on yet/);
});

test('fix 2: the conversation is cached a minute fresh and a minute stale, and an answer whose check failed is not cached', async () => {
  fakeGitHub();
  const lib = fresh('_lib.js');
  const route = require(path.join(root, 'api', 'conversation.js'));
  lib.setHiddenCheck(async () => new Set());
  const ok = await call(route, 'GET', '/api/conversation');
  assert.strictEqual(ok.headers['cache-control'], 'public, s-maxage=60, stale-while-revalidate=60');
  lib.setHiddenCheck(async () => { throw new Error('down'); });
  const bad = await call(route, 'GET', '/api/conversation');
  assert.strictEqual(bad.headers['cache-control'], 'no-store');
});

test('fix 2: list_posts no longer promises a date that has passed', () => {
  const src = fs.readFileSync(path.join(root, 'api', 'mcp.js'), 'utf8');
  assert.ok(!/November 6/.test(src));
});

if (SERVER) {
  let sql, admin, name, G;
  test.before(async () => {
    G = await import('../supabase/functions/jevs/gate.mjs');
    admin = postgres(SERVER, { max: 1, onnotice: () => {} });
    name = 'dog_hidden_' + crypto.randomBytes(4).toString('hex');
    await admin.unsafe('create database ' + name);
    const u = new URL(SERVER); u.pathname = '/' + name;
    sql = postgres(u.toString(), { max: 1, prepare: false, onnotice: () => {} });
    await migrate(sql);
  });
  test.after(async () => {
    await sql.end({ timeout: 5 });
    await admin.unsafe('drop database if exists ' + name + ' with (force)');
    await admin.end({ timeout: 5 });
  });
  const post = (id, login, node, bans = []) => G.handle(sql, {
    event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1, bans,
    post: { node_id: node, thread_node_id: 'D_thread', body: 'a post from ' + login, created_at: new Date().toISOString() },
    author: { id, login, type: 'User', created_at: '2015-01-01T00:00:00Z' }
  }, { key: 'k'.repeat(32) });

  test('fix 2 (018): the site, as dog_app, learns only which of its post IDs JEVs hid, and can read nothing else of GitHub\'s tables', async () => {
    await post(7001, 'fine', 'DC_fine');
    const h = await post(7002, 'banned', 'DC_banned', [7002]);
    assert.strictEqual(h.hide, true);
    assert.strictEqual((await post(7003, 'banned2', 'DC_other_hidden', [7003])).hide, true);
    const db = require('../db');
    const out = await db.tx(sql, { actor: 'anon' }, (t) => require('../db/github').hidden(t, ['DC_fine', 'DC_banned', 'DC_unknown', 'bad id!']));
    assert.deepStrictEqual([...out], ['DC_banned'], 'only the asked-about hidden post, never another (DC_other_hidden)');
    // The 200-ID limit counts every element, also of a two-dimensional array (fix 2 review: [1:200] sliced one dimension).
    const flat = Array.from({ length: 299 }, (_, i) => 'X' + i).concat(['DC_banned']);
    const grid = '{{' + flat.slice(0, 150).join(',') + '},{' + flat.slice(150).join(',') + '}}';
    const [{ n }] = await db.tx(sql, { actor: 'anon' }, (t) => t`select count(*)::int as n from app.gh_hidden(${grid}::text[])`);
    assert.strictEqual(n, 0, 'the 300th ID is past the limit');
    await assert.rejects(db.tx(sql, { actor: 'anon' }, (t) => t`select node_id from app.gh_posts`), /permission denied/, 'no direct read of the table');
    await assert.rejects(sql.begin(async (t) => { await t`set local role dog_public`; await t`select * from app.gh_hidden(array['DC_banned'])`; }),
      /permission denied/, 'only dog_app may call it');
  });

  test('fix 2 (018): the database still passes the coverage check, with app.gh_hidden on its reviewed list', async () => {
    const { problems } = require('../db/checks');
    const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
    assert.deepStrictEqual(await problems(sql, { snapshot }), []);
  });
}
