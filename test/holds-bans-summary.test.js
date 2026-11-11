// 060: the legal hold (RK22; Aaron, Oct 16, 2026), linked bans and the daily summary (Aaron's check of Nov 10, 2026:
// part 8 of the one large PR), against a real Postgres, through the site's own handlers and the JEVs gate.
// ACCEPTANCE.md LH1 to LH5, LB1 to LB5, DS1 to DS2.
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
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { promote, shadowMode, asSignin } = require('./helpers');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const KEY = 'k'.repeat(32); // the gate's hash key (Vault's dog_fingerprint_key_1 in production)

test('the words: the join page tells a held member the truth, the gate takes the ban list only from the push run, and the timer sends the summary', () => {
  assert.match(read('join.js'), /held: 'Your account is closed and hidden, and you are signed out\. Nothing was deleted yet: the account is kept under a legal hold/);
  assert.match(read('join.js'), /q\.get\('deleted'\) === 'held' \? 'held'/);
  const index = read('supabase/functions/jevs/index.ts');
  assert.ok(index.includes('events: ["discussion", "discussion_comment", "push"]'));
  assert.ok(index.includes('if ((ev && ev.event === "bans") !== (claims.event_name === "push")) return reply(400'), 'a list only from the push run, and the push run sends only a list');
  const wf = read('.github/workflows/jevs.yml');
  assert.match(wf, /push:\n {4}branches: \[main\]\n {4}paths: \[moderation\/bans\.json\]/);
  assert.match(wf, /if: github\.repository_id == 1418125608 && github\.event_name != 'push'/, 'the posts job never runs for a push');
  assert.match(wf, /bans:\n {4}if: github\.repository_id == 1418125608 && github\.event_name == 'push'/);
  const job = wf.slice(wf.indexOf('\n  bans:'));
  assert.match(job, /permissions:\n {6}contents: read\n {6}id-token: write/, 'the bans job has only the rights it needs');
  assert.ok(!/discussions: write|issues: write/.test(job));
  assert.ok(!/\$\{\{\s*github\.event/.test(job), 'no event text in a command');
  assert.match(job, /jq -e 'type == "object" and \(\(\.ids \/\/ \[\]\) \| type == "array"\)' moderation\/bans\.json/, 'a file that can’t be read is an error, never an empty list');
  assert.match(read('api/cron.js'), /select app\.daily_summary\(\)/);
});

if (!SERVER) {
  if (process.env.CI) test('060 tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('060 against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_060_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron, G, J;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); return t.unsafe(sql); });

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
// The owner controls, as Aaron's browser on the site's own pages.
async function control(who, body) {
  const out = res();
  await require('../api/feed.js').handle({ method: 'POST', url: '/api/feed', query: {}, headers: { host: 'dayonegreat.com', origin: ORIGIN, cookie: who.cookie,
    'content-type': 'application/json', 'sec-fetch-site': 'same-origin', 'x-vercel-forwarded-for': '203.0.113.9' }, body: JSON.stringify(body) }, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
async function controls(who) {
  const out = res();
  await require('../api/feed.js').handle({ method: 'GET', url: '/api/feed?controls=1', query: { controls: '1' }, headers: { host: 'dayonegreat.com', cookie: who.cookie,
    'sec-fetch-site': 'same-origin', 'x-vercel-forwarded-for': '203.0.113.9' } }, out, run);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
}
// A member whose GitHub account is `github` (a number): signed in with the fingerprint the gate makes for that account.
let nextGithub = 5000;
async function member(name, { admin = false, github = nextGithub++ } = {}) {
  const token = c.token(32);
  const fp = await J.keyed(KEY, 'github:' + github);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [fp], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  if (admin) await asOwner(`update app.members set is_admin = true where id = '${out.memberId}'`);
  return { id: out.memberId, name, github, cookie: '__Host-dog_session=' + token, session: c.sha256hex(token) };
}
const statusOf = async (m) => (await q(`select status, banned_via from app.members where id = '${m.id}'`))[0] || null;
const sessionsOf = async (m) => (await q(`select count(*)::int as n from app.sessions where member_id = '${m.id}'`))[0].n;
const erase = (m) => run({ actor: 'member', memberId: m.id, session: m.session, fresh: true }, (t) => store.deleteAccount(t));
const post = async (m, body) => {
  const out = res();
  await require('../api/feed.js').handle({ method: 'POST', url: '/api/feed', query: {}, headers: { host: 'dayonegreat.com', origin: ORIGIN, cookie: m.cookie,
    'content-type': 'application/json', 'x-vercel-forwarded-for': '203.0.113.20' }, body: JSON.stringify({ body }) }, out, run);
  return { status: out.statusCode, json: JSON.parse(out.body) };
};
const lane = async () => {
  const out = res();
  await require('../api/feed.js').handle({ method: 'GET', url: '/api/feed?lane=people', query: { lane: 'people' }, headers: { host: 'dayonegreat.com' } }, out, run);
  return JSON.parse(out.body).posts;
};
// A GitHub comment by an account, through the gate, in enforce mode.
const ghPost = (github, login, node, bans = []) => G.handle(su, {
  event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1, bans,
  post: { node_id: node, thread_node_id: 'D_1', body: 'a post from ' + login, created_at: new Date().toISOString() },
  author: { id: github, login, type: 'User', created_at: '2015-01-01T00:00:00Z' }
}, { key: KEY });
const sendBans = (ids) => G.handle(su, { event: 'bans', bans: ids }, { key: KEY });
const notices = async (like) => q(`select title, body, link, dedupe_key from app.notices where member_id is null and dedupe_key like '${like}' order by created_at`);

test.before(async () => {
  G = await import('../supabase/functions/jevs/gate.mjs');
  J = await import('../supabase/functions/jevs/core.mjs');
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  aaron = await member('Aaron', { admin: true });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

// ---- The legal hold ----

test('LH1: only an administrator places a hold, with a reason; the audit log names the hold and never its reason', async () => {
  const m = await member('Held');
  const other = await member('Other');
  assert.strictEqual((await control(other, { hold: m.id, reason: 'A member trying to hold someone.' })).status, 403);
  for (const bad of [{ hold: m.id }, { hold: m.id, reason: 'short' }, { hold: 'not-an-id', reason: 'A good enough reason.' }, { hold: m.id, reason: 'x'.repeat(501) },
    { hold: m.id, reason: 'A good enough reason.', note: 'extra' }]) {
    assert.strictEqual((await control(aaron, bad)).status, 400, JSON.stringify(bad).slice(0, 60));
  }
  assert.strictEqual((await control(aaron, { hold: crypto.randomUUID(), reason: 'Nobody has this ID at all.' })).status, 404);
  assert.strictEqual((await control(aaron, { hold: aaron.id, reason: 'An administrator can’t be held.' })).status, 409);
  const r = await control(aaron, { hold: m.id, reason: 'Preservation letter received Nov 11; secret-word-xyz.' });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  assert.strictEqual((await control(aaron, { hold: m.id, reason: 'A second hold on the same account.' })).status, 409);
  const [a] = await q(`select detail::text as d from app.audit_log where action = 'legal_hold.placed' and subject_id = '${m.id}'`);
  assert.ok(a && a.d.includes(r.json.hold) && !a.d.includes('secret-word-xyz'));
  // Placing a hold changes nothing for the member: still active, still signed in.
  assert.deepStrictEqual([(await statusOf(m)).status, await sessionsOf(m)], ['active', 1]);
  // The administrator sees it under the controls; the site's role alone can't read the table.
  const list = (await controls(aaron)).json.legal_holds;
  assert.deepStrictEqual(list.map((h) => [h.id, h.member.id, h.member.name, h.reason, h.deletion_requested_at]), [[r.json.hold, m.id, 'Held', 'Preservation letter received Nov 11; secret-word-xyz.', null]]);
  await assert.rejects(run({ actor: 'anon' }, (t) => t`select id from app.legal_holds`), /permission denied/);
  await assert.rejects(run({ actor: 'member', memberId: m.id, session: m.session }, (t) => t`select * from app.legal_holds_list()`), /not_admin/);
});

test('LH2: a held member who deletes their account is closed and hidden instead; nothing is deleted, and they are told', async () => {
  const m = await member('Leaver');
  const p = await post(m, 'A post that must be kept.');
  assert.strictEqual(p.status, 201, JSON.stringify(p.json));
  assert.ok((await lane()).some((x) => x.id === p.json.id));
  const h = await control(aaron, { hold: m.id, reason: 'Suspected fraud; keep everything.' });
  assert.strictEqual(h.status, 201);
  const out = await erase(m);
  assert.deepStrictEqual(out, { held: true });
  assert.deepStrictEqual(await statusOf(m), { status: 'disabled', banned_via: null });
  assert.strictEqual(await sessionsOf(m), 0, 'signed out');
  assert.strictEqual((await q(`select count(*)::int as n from app.posts where author_id = '${m.id}'`))[0].n, 1, 'the post is kept');
  assert.ok(!(await lane()).some((x) => x.id === p.json.id), 'and hidden');
  const [row] = await q(`select deletion_requested_at from app.legal_holds where id = '${h.json.hold}'`);
  assert.ok(row.deletion_requested_at);
  assert.strictEqual((await q(`select count(*)::int as n from app.audit_log where action = 'legal_hold.deletion_deferred' and subject_id = '${m.id}'`))[0].n, 1);
  assert.ok((await controls(aaron)).json.legal_holds.find((x) => x.id === h.json.hold).deletion_requested_at);
  // The flow's redirect for it (signin/flow.js) and the words the member reads (join.js) are checked above.
  assert.match(read('signin/flow.js'), /out\.held \? '\/join\?deleted=held' : '\/join\?deleted=1'/);
});

test('LH3: nothing deletes a held account: not the member, not a deletion review, not the database’s own function', async () => {
  const m = await member('Kept');
  await control(aaron, { hold: m.id, reason: 'A court order to preserve.' });
  await assert.rejects(su.begin(async (t) => { await t.unsafe('set local role dog_erase'); await t`select * from app.erase_member(${m.id}::uuid)`; }), /legal_hold/);
  // The deletion role may close an account (active to disabled) and nothing else about a status or a level.
  const asErase = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_erase'); return t.unsafe(sql); });
  await assert.rejects(asErase(`update app.members set status = 'banned' where id = '${m.id}'`), /only a deletion review|administrator|permission denied/);
  await assert.rejects(asErase(`update app.members set trust_level = 3 where id = '${m.id}'`), /permission denied|administrator/);
  assert.strictEqual((await statusOf(m)).status, 'active');
  // A deletion review Aaron tries to allow (JEVs would have opened it; made here as JEVs).
  const [d] = await su.begin(async (t) => {
    await t.unsafe('set local role dog_jevs');
    const [dec] = await t`insert into app.jevs_decisions (action, subject_kind, member_id, level, mode, effect, applied, error, total, scores)
      values ('account.delete', 'member', ${m.id}, 'high', 'enforce', 'hold', true, false, 0, '{}'::jsonb) returning id`;
    return t`insert into app.deletion_reviews (member_id, decision_id) values (${m.id}, ${dec.id}) returning id`;
  });
  const r = await control(aaron, { deletion_review: d.id, decision: 'delete' });
  assert.strictEqual(r.status, 409);
  assert.match(r.json.error, /under a legal hold/);
  assert.ok(await statusOf(m), 'the account is still there');
});

test('LH4: lifting a hold needs a reason; if the member had asked to be deleted, the account is deleted then, and otherwise it just can be again', async () => {
  const asked = await member('Asked');
  const quiet = await member('Quiet');
  const h1 = await control(aaron, { hold: asked.id, reason: 'Held while the matter is open.' });
  const h2 = await control(aaron, { hold: quiet.id, reason: 'Held while the matter is open.' });
  assert.deepStrictEqual(await erase(asked), { held: true });
  assert.strictEqual((await control(aaron, { lift_hold: h1.json.hold })).status, 400);
  assert.strictEqual((await control(aaron, { lift_hold: crypto.randomUUID(), reason: 'No such hold exists here.' })).status, 404);
  const l1 = await control(aaron, { lift_hold: h1.json.hold, reason: 'The matter is closed; request honored.' });
  assert.deepStrictEqual([l1.status, l1.json.result], [200, 'lifted_deleted']);
  assert.strictEqual(await statusOf(asked), null, 'the account is gone');
  assert.strictEqual((await q(`select count(*)::int as n from app.legal_holds where member_id = '${asked.id}'`))[0].n, 0, 'and its hold with it');
  assert.strictEqual((await q(`select count(*)::int as n from app.audit_log where action = 'member.deleted' and subject_id = '${asked.id}'`))[0].n, 1);
  const l2 = await control(aaron, { lift_hold: h2.json.hold, reason: 'The matter is closed; nothing to do.' });
  assert.deepStrictEqual([l2.status, l2.json.result], [200, 'lifted']);
  assert.strictEqual((await control(aaron, { lift_hold: h2.json.hold, reason: 'Lifting it a second time.' })).status, 409);
  assert.strictEqual((await statusOf(quiet)).status, 'active');
  // With the hold lifted, the member's own deletion works as before.
  const gone = await erase(quiet);
  assert.strictEqual(gone.held, undefined);
  assert.strictEqual(await statusOf(quiet), null);
});

// ---- Linked bans ----

test('LB1: a ban on the site reaches the same person’s posts on GitHub, and their linked machine account’s; an unban ends it', async () => {
  const m = await member('Banned here');
  const before = await ghPost(m.github, 'bannedhere', 'DC_lb1_before');
  assert.strictEqual(before.hide, false);
  const b = await control(aaron, { ban: m.id, note: 'Spam.' });
  assert.strictEqual(b.status, 200, JSON.stringify(b.json));
  assert.match(b.json.message, /posts on GitHub are hidden from now on too/);
  const after = await ghPost(m.github, 'bannedhere', 'DC_lb1_after');
  assert.strictEqual(after.hide, true);
  assert.ok(after.decisions.some((d) => d.reason === 'banned'));
  assert.match(after.reply, /this account is banned, on the ban list or on dayonegreat\.com/);
  // Someone else's GitHub account is untouched.
  assert.strictEqual((await ghPost(777001, 'bystander', 'DC_lb1_other')).hide, false);
  const u = await control(aaron, { unban: m.id });
  assert.strictEqual(u.status, 200);
  assert.strictEqual((await ghPost(m.github, 'bannedhere', 'DC_lb1_unbanned')).hide, false);
});

test('LB2: a ban on GitHub reaches the site: the member is banned, signed out and told why it ends on GitHub; off the list, they are unbanned', async () => {
  const m = await member('Banned there');
  const p = await post(m, 'Visible until the ban.');
  const r = await sendBans([m.github, 999001]);
  assert.deepStrictEqual(r, { ok: true, bans: { listed: 2, banned: 1, unbanned: 0 } });
  assert.deepStrictEqual(await statusOf(m), { status: 'banned', banned_via: 'github' });
  assert.strictEqual(await sessionsOf(m), 0);
  assert.ok(!(await lane()).some((x) => x.id === p.json.id), 'their posts are hidden');
  assert.strictEqual((await q(`select count(*)::int as n from app.audit_log where action = 'member.ban_linked' and subject_id = '${m.id}'`))[0].n, 1);
  assert.strictEqual((await notices('banlink:on:' + m.id + '%')).length, 1, 'the administrators are told');
  // Sending the same list again changes nothing.
  assert.deepStrictEqual((await sendBans([m.github, 999001])).bans, { listed: 2, banned: 0, unbanned: 0 });
  // An administrator can't end it on the site: it ends on GitHub.
  const u = await control(aaron, { unban: m.id });
  assert.strictEqual(u.status, 409);
  assert.match(u.json.error, /moderation\/bans\.json/);
  // Off the list: unbanned.
  assert.deepStrictEqual((await sendBans([999001])).bans, { listed: 1, banned: 0, unbanned: 1 });
  assert.deepStrictEqual(await statusOf(m), { status: 'active', banned_via: null });
  assert.strictEqual((await notices('banlink:off:' + m.id + '%')).length, 1);
});

test('LB3: the link never bans an administrator, and never ends a ban an administrator made on the site', async () => {
  // The founder's own account on the list: never sent on, and an administrator is never banned by it.
  assert.deepStrictEqual((await sendBans([aaron.github, G.FOUNDER_ID])).bans.banned, 0);
  assert.strictEqual((await statusOf(aaron)).status, 'active');
  const m = await member('Site ban');
  await control(aaron, { ban: m.id, note: 'Abuse.' });
  // Not on the GitHub list: the empty list unbans nobody a person banned.
  assert.deepStrictEqual((await sendBans([])).bans, { listed: 0, banned: 0, unbanned: 0 });
  assert.deepStrictEqual(await statusOf(m), { status: 'banned', banned_via: null });
  // Banned on GitHub first, then made a site ban by an administrator: it now stays when the list drops them.
  const n = await member('Both');
  await sendBans([n.github]);
  const both = await control(aaron, { ban: n.id, note: 'Also banned here.' });
  assert.strictEqual(both.status, 200, JSON.stringify(both.json));
  assert.match(both.json.message, /Banned on the site too/);
  assert.deepStrictEqual((await sendBans([])).bans.unbanned, 0);
  assert.deepStrictEqual(await statusOf(n), { status: 'banned', banned_via: null });
  assert.strictEqual((await control(aaron, { unban: n.id })).status, 200, 'and it ends on the site');
});

test('LB4: only the gate’s role carries a ban, only between active and banned, and a bad list is refused whole', async () => {
  const m = await member('Guarded');
  const fp = await J.keyed(KEY, 'github:' + m.github);
  // The site's role can't call either function, signed in or not.
  await assert.rejects(run({ actor: 'anon' }, (t) => t`select app.gh_bans_apply(${[fp]}::text[])`), /permission denied/);
  await assert.rejects(run({ actor: 'member', memberId: m.id, session: m.session }, (t) => t`select app.gh_site_banned(${[fp]}::text[])`), /permission denied/);
  // The gate's role can't change a status any other way, or mark a ban it didn't carry.
  const asJevs = (sql) => su.begin(async (t) => { await t.unsafe('set local role dog_jevs'); return t.unsafe(sql); });
  await assert.rejects(asJevs(`update app.members set status = 'banned' where id = '${m.id}'`), /JEVs changes a status only to carry a GitHub ban/);
  await assert.rejects(asJevs(`update app.members set status = 'disabled' where id = '${m.id}'`), /JEVs changes a status only to carry a GitHub ban|only a deletion review/);
  // A member can't set the mark on themselves (refused, or no row of theirs to change): it stays unset.
  await run({ actor: 'member', memberId: m.id, session: m.session }, (t) => t.savepoint((x) => x`update app.members set banned_via = 'github' where id = ${m.id}`)).catch(() => {});
  assert.deepStrictEqual(await statusOf(m), { status: 'active', banned_via: null });
  for (const bad of [{ event: 'bans' }, { event: 'bans', bans: ['12'] }, { event: 'bans', bans: [0] }, { event: 'bans', bans: [1.5] }, { event: 'bans', bans: [5], mode: 'enforce' },
    { event: 'bans', bans: Array.from({ length: 10001 }, (_, i) => i + 1) }]) {
    await assert.rejects(G.handle(su, bad, { key: KEY }), (e) => e instanceof G.BadEvent, JSON.stringify(bad).slice(0, 60));
  }
  await assert.rejects(su.begin(async (t) => { await t.unsafe('set local role dog_jevs'); await t`select app.gh_bans_apply(${['not-a-fingerprint']}::text[])`; }), /bad ban list/);
  assert.strictEqual((await statusOf(m)).status, 'active');
});

test('LB5: before migration 060 the gate scores a post as before (the function isn’t there yet: not banned, no failure)', async () => {
  // The same as production between the gate's deploy and the migration: the function is missing.
  await su.unsafe('alter function app.gh_site_banned(text[]) rename to gh_site_banned_away');
  try {
    const r = await ghPost(777002, 'early', 'DC_lb5');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.hide, false);
  } finally {
    await su.unsafe('alter function app.gh_site_banned_away(text[]) rename to gh_site_banned');
  }
});

// ---- The daily summary ----

test('DS1: one summary a day reaches the administrators: counts only, sent once however often the timer asks', async () => {
  await q(`update app.summary_state set last_day = null`);
  const first = await run({ actor: 'anon' }, (t) => t`select app.daily_summary() as sent`);
  assert.strictEqual(first[0].sent, true);
  for (let i = 0; i < 3; i++) assert.strictEqual((await run({ actor: 'anon' }, (t) => t`select app.daily_summary() as sent`))[0].sent, null);
  const today = new Date().toISOString().slice(0, 10);
  const got = await notices('daily:%');
  assert.strictEqual(got.length, 1);
  assert.strictEqual(got[0].dedupe_key, 'daily:' + today);
  assert.strictEqual(got[0].link, '/admin/controls');
  assert.match(got[0].title, /^Daily summary, [A-Z][a-z]+ \d{1,2}, \d{4}$/);
  // The figures are this database's: the members, posts, holds and decisions the tests above made.
  const n = async (sql) => (await q(sql))[0].n;
  const members = await n(`select count(*)::int as n from app.members where created_at > now() - interval '24 hours'`);
  const posts = await n(`select count(*)::int as n from app.posts where created_at > now() - interval '24 hours' and parent_id is null`);
  const gh = await n(`select count(*)::int as n from app.gh_decisions where at > now() - interval '24 hours'`);
  const hidden = await n(`select count(*)::int as n from app.gh_decisions where at > now() - interval '24 hours' and effect = 'hide'`);
  const holds = await n(`select count(*)::int as n from app.legal_holds where lifted_at is null`);
  const asked = await n(`select count(*)::int as n from app.legal_holds where lifted_at is null and deletion_requested_at is not null`);
  assert.ok(members >= 8 && gh >= 5 && hidden >= 1 && holds >= 2 && asked >= 1, 'the tests above left something to count: ' + JSON.stringify({ members, gh, hidden, holds, asked }));
  assert.ok(got[0].body.includes('In the last 24 hours: ' + members + ' new members, '), got[0].body);
  assert.ok(got[0].body.includes(posts + ' posts and 0 replies.'), got[0].body);
  assert.ok(got[0].body.includes('Checks on GitHub: ' + gh + ' decisions, ' + hidden + ' posts hidden.'), got[0].body);
  assert.ok(got[0].body.includes(holds + ' legal holds (' + asked + ' with a deletion asked for)'), got[0].body);
  // No names, no post text, no reasons.
  for (const secret of ['Leaver', 'Held', 'secret-word-xyz', 'A post that must be kept', 'Suspected fraud']) assert.ok(!got[0].body.includes(secret), secret);
  // Aaron reads it in his inbox; a member doesn't.
  const mine = await run({ actor: 'admin', memberId: aaron.id, session: aaron.session }, (t) => t`select count(*)::int as n from app.notices where dedupe_key = ${'daily:' + today}`);
  assert.strictEqual(mine[0].n, 1);
  const m = await member('Reader');
  const theirs = await run({ actor: 'member', memberId: m.id, session: m.session }, (t) => t`select count(*)::int as n from app.notices where dedupe_key = ${'daily:' + today}`);
  assert.strictEqual(theirs[0].n, 0);
});

test('DS2: the next day brings the next summary, and nobody but the timer’s function can move the day', async () => {
  await q(`update app.summary_state set last_day = current_date - 1`);
  await q(`delete from app.notices where dedupe_key like 'daily:%'`);
  assert.strictEqual((await run({ actor: 'anon' }, (t) => t`select app.daily_summary() as sent`))[0].sent, true);
  assert.strictEqual((await notices('daily:%')).length, 1);
  await assert.rejects(run({ actor: 'anon' }, (t) => t`update app.summary_state set last_day = null`), /permission denied/);
});

test('the privacy request runbook names every table that points at a member, and says what a hold does not cover', async () => {
  const doc = read('PRIVACY-REQUESTS.md');
  const fks = await q(`select c.relname as tbl, a.attname as col from pg_constraint k join pg_class c on c.oid = k.conrelid join pg_namespace n on n.oid = c.relnamespace
    join pg_attribute a on a.attrelid = k.conrelid and a.attnum = k.conkey[1]
    where k.contype = 'f' and k.confrelid = 'app.members'::regclass and n.nspname = 'app' order by 1, 2`);
  assert.ok(fks.length >= 35);
  for (const f of fks) {
    assert.ok(new RegExp('`' + f.tbl + '` \\([^)]*\\b' + f.col + '\\b').test(doc), 'PRIVACY-REQUESTS.md lists ' + f.tbl + ' (' + f.col + ')');
  }
  assert.match(doc, /What a hold does not cover/);
  assert.match(doc, /It adds no tool that erases an account on an administrator’s word alone|It adds no tool that erases an account on an administrator's word alone/);
  // The times are the privacy page's own.
  const privacy = read('privacy.html');
  assert.match(privacy, /confirm receipt of a request within 10 business days and respond within 45 days/);
  assert.match(doc, /10 business days/);
  assert.match(doc, /45 days/);
});

test('060: the database still passes the coverage check and matches the reviewed snapshot', async () => {
  const snapshot = read('db/snapshot.txt').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});
