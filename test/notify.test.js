// Release 2, PR 13: notifications against a real Postgres. Every behaviour has a test: the inbox first, the outbox in
// the same transaction, once; email copies (confirm first, one an hour, quiet hours, one-click unsubscribe, bounces);
// safe one-tap links (R16); the 90-day check on agents acting alone (R33); the watch, containment and the copier rule.
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
const delegation = require('../db/delegation');
const controls = require('../db/controls');
const review = require('../db/review');
const notices = require('../db/notify');
const ncfg = require('../notify/config');
const mime = require('../notify/mime');
const { logTransport } = require('../notify/transport');
const { drain } = require('../notify/drain');
const fx = require('./notify-helpers');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const SECRET = crypto.randomBytes(24).toString('base64url');

if (!SERVER) {
  if (process.env.CI) test('notification tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('notifications against a database (N1 to N10, R16, R33)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_notify_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, aaron, cert;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const SYSTEM = { actor: 'system' };
const cfg = ncfg.load({ NOTIFY_KEY: crypto.randomBytes(32).toString('base64'), EMAIL_TRANSPORT: 'log', SNS_TOPIC_ARN: fx.TOPIC, CRON_SECRET: SECRET });
cfg.transport = logTransport({ keep: 500, log: () => {} });

// The watch stays quiet unless a test turns it up (and then puts it back).
const QUIET_WATCH = 'update app.watch_settings set alert_floor = 1000000, hard_limit_per_hour = 10000000, copy_limit_per_hour = 10000000, repeat_alert_count = 10000000, signup_floor = 1000000';
async function asOwner(sql) { await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sql); }); }
// Moves a row's clock (tests only): the guard trigger is switched off and back on (always) inside one transaction.
async function rewrite(table, trigger, sql) {
  await su.begin(async (t) => {
    await t.unsafe(`alter table app.${table} disable trigger ${trigger}`);
    await t.unsafe(sql);
    await t.unsafe(`alter table app.${table} enable always trigger ${trigger}`);
  });
}

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  aaron = await member(2, 'Aaron');
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${aaron.id}'`); });
  aaron.ctx = { actor: 'admin', memberId: aaron.id };
  await asOwner(QUIET_WATCH);
  cert = fx.makeCert();
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(level = 2, name = 'Owner') {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId } };
}
async function agentOf(owner, name = 'Helper', { act = false } = {}) {
  const [a] = await run(owner.ctx, (t) => t`insert into app.agents (name) values (${name}) returning id`);
  const ag = { id: a.id, ctx: { actor: 'agent', memberId: owner.id, agentId: a.id } };
  if (act) await run({ ...owner.ctx, fresh: true }, (t) => delegation.setRules(t, { agent: a.id, post: 'act', reply: 'draft', report: 'draft', dailyCap: 1000 }));
  return ag;
}
const say = (ag, body) => run(ag.ctx, (t) => delegation.submit(t, { body }));

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
async function napi(method, route, { cookie = '', json, query = {}, origin = method === 'POST' ? ORIGIN : undefined, contentType, body, deps } = {}) {
  const headers = { host: 'dayonegreat.com', cookie };
  if (origin) headers.origin = origin;
  if (json !== undefined) headers['content-type'] = 'application/json';
  if (contentType) headers['content-type'] = contentType;
  const r = res();
  await require('../api/notify.js').handle({ method, url: '/api/notify/' + route, headers, query: { route, ...query },
    body: json !== undefined ? JSON.stringify(json) : body }, r, run, cfg, deps || {});
  let parsed = null;
  try { parsed = r.body ? JSON.parse(r.body) : null; } catch { parsed = null; }
  return { status: r.statusCode, json: parsed, r };
}
async function agentsApi(method, route, owner, json) {
  const r = res();
  const headers = { host: 'dayonegreat.com', cookie: owner.cookie, 'x-vercel-forwarded-for': '203.0.113.9' };
  if (method === 'POST') { headers.origin = ORIGIN; headers['content-type'] = 'application/json'; }
  await require('../api/agents.js').handle({ method, url: '/api/agents/' + route, headers, query: { route }, body: json ? JSON.stringify(json) : undefined }, r, run, { ipKey: crypto.randomBytes(32) });
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
const timers = () => run(SYSTEM, (t) => notices.runTimers(t));
const drainNow = () => drain({ run, cfg });
// Emails the log transport "sent" to one address since a mark.
const mark = () => cfg.transport.sent.length;
const mailTo = (address, since = 0) => cfg.transport.sent.slice(since).map((m) => mime.parse(m.raw)).filter((m) => m.headers.to === address);
const tokenIn = (mail, kind) => { const m = new RegExp('/act#' + kind + '=([A-Za-z0-9_-]{43})').exec(mail.text); return m && m[1]; };
const inbox = async (who) => (await napi('GET', '', { cookie: who.cookie })).json;

// A member with a confirmed address, copies on and no quiet hours (unless a test sets some).
async function withEmail(who, address) {
  const since = mark();
  const add = await napi('POST', 'email', { cookie: who.cookie, json: { address, time_zone: 'UTC' } });
  assert.strictEqual(add.status, 202, JSON.stringify(add.json));
  await drainNow();
  const [confirm] = mailTo(address, since);
  assert.ok(confirm, 'a confirmation email went to ' + address);
  const used = await napi('POST', 'link', { cookie: who.cookie, json: { t: tokenIn(confirm, 'confirm') } });
  assert.strictEqual(used.status, 200, JSON.stringify(used.json));
  assert.strictEqual((await napi('POST', 'settings', { cookie: who.cookie, json: { quiet_start: 0, quiet_end: 0, time_zone: 'UTC' } })).status, 200);
}

test('the database passes the coverage check and matches the reviewed snapshot with the notification tables (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('N1, N2: a draft leaves its owner a notice and an email copy in the same transaction; nothing exists if that transaction fails', async () => {
  const owner = await member(2, 'Inbox owner');
  const ag = await agentOf(owner);
  const d = await say(ag, 'Please look at this');
  assert.ok(d.drafted);
  const [n] = await q(`select n.kind, n.member_id, n.send_copy, o.status, o.idempotency_key from app.notices n join app.outbox o on o.notice_id = n.id
                       where n.subject_id = '${d.drafted.id}'`);
  assert.deepStrictEqual({ ...n }, { kind: 'draft_waiting', member_id: owner.id, send_copy: true, status: 'pending', idempotency_key: 'notice:' + (await q(`select id from app.notices where subject_id = '${d.drafted.id}'`))[0].id });
  // A draft whose transaction rolls back leaves no notice and no email behind.
  const before = (await q(`select count(*)::int as n from app.notices`))[0].n;
  await assert.rejects(run(ag.ctx, async (t) => { await delegation.submit(t, { body: 'rolled back' }); throw new Error('stop'); }), /stop/);
  assert.strictEqual((await q(`select count(*)::int as n from app.notices`))[0].n, before);
  assert.strictEqual((await q(`select count(*)::int as n from app.outbox o left join app.notices n on n.id = o.notice_id where o.purpose = 'notice' and n.id is null`))[0].n, 0);
  // The owner sees it, unread; nobody else does: another member, the agent itself, someone not signed in.
  const box = await inbox(owner);
  assert.strictEqual(box.unread, 1);
  assert.deepStrictEqual([box.notices[0].kind, box.notices[0].title, box.notices[0].link], ['draft_waiting', 'Helper wrote a draft for you', '/agents']);
  const other = await member(2, 'Nosy');
  assert.strictEqual((await inbox(other)).notices.length, 0);
  assert.strictEqual((await run(ag.ctx, (t) => t`select count(*)::int as n from app.notices`))[0].n, 0, 'an agent can\'t read its owner\'s inbox');
  assert.strictEqual((await run({ actor: 'anon' }, (t) => t`select count(*)::int as n from app.notices`))[0].n, 0);
  assert.strictEqual((await napi('GET', '')).status, 401);
});

test('N1: marking read is the only change a notice allows; the unread count follows; nobody marks someone else\'s', async () => {
  const owner = await member(2, 'Reader');
  const ag = await agentOf(owner);
  await say(ag, 'one'); await say(ag, 'two');
  const box = await inbox(owner);
  assert.strictEqual(box.unread, 2);
  const other = await member(2, 'Other reader');
  assert.strictEqual((await napi('POST', 'read', { cookie: other.cookie, json: { ids: [box.notices[0].id] } })).json.marked, 0);
  assert.strictEqual((await napi('POST', 'read', { cookie: owner.cookie, json: { ids: [box.notices[0].id] } })).json.marked, 1);
  assert.strictEqual((await inbox(owner)).unread, 1);
  assert.strictEqual((await napi('POST', 'read', { cookie: owner.cookie, json: { all: true } })).json.marked, 1);
  assert.strictEqual((await inbox(owner)).unread, 0);
  assert.strictEqual((await napi('POST', 'read', { cookie: owner.cookie, json: { all: true }, origin: 'https://evil.example' })).status, 403);
  await assert.rejects(run(owner.ctx, (t) => t`update app.notices set title = 'changed' where member_id = ${owner.id}`), /permission denied|only be marked read/);
  await assert.rejects(q(`update app.notices set body = 'x' where member_id = '${owner.id}'`), /only be marked read/);
});

test('N2: the same event never leaves two notices or two emails (idempotency key), and JEVs can leave its own', async () => {
  const m = await member(2, 'Challenged');
  const once = () => run(SYSTEM, (t) => notices.challenge(t, { memberId: m.id, title: 'Please confirm it was you', body: 'A new sign-in from a new place.', dedupeKey: 'jevs:check-1' }));
  assert.strictEqual(await once(), true);
  assert.strictEqual(await once(), false);
  const [r] = await q(`select count(*)::int as n, (select count(*)::int from app.outbox o join app.notices x on x.id = o.notice_id where x.dedupe_key = 'jevs:check-1') as e
                       from app.notices where dedupe_key = 'jevs:check-1'`);
  assert.deepStrictEqual([r.n, r.e], [1, 1]);
  // A member's own transaction may leave a challenge for that member only; an alert for Aaron is open to anyone signed in.
  await assert.rejects(run(m.ctx, (t) => notices.challenge(t, { memberId: aaron.id, title: 't', body: 'b', dedupeKey: 'jevs:check-2' })), /row-level security/);
  assert.strictEqual(await run(m.ctx, (t) => notices.alertAaron(t, { title: 'High risk held', body: 'Held for review.', dedupeKey: 'jevs:hold-1' })), true);
  assert.ok((await inbox(aaron)).notices.some((n) => n.title === 'High risk held' && n.for_admins));
  assert.ok(!(await inbox(m)).notices.some((n) => n.title === 'High risk held'));
  await assert.rejects(run({ actor: 'anon' }, (t) => notices.alertAaron(t, { title: 't', body: 'b', dedupeKey: 'anon:1' })), /row-level security/);
});

test('N3: email copies need a confirmed address; the address is stored sealed; confirmation is a safe one-tap link', async () => {
  const m = await member(2, 'Emailer');
  const since = mark();
  assert.strictEqual((await napi('POST', 'email', { cookie: m.cookie, json: { address: 'not an address' } })).status, 400);
  assert.strictEqual((await napi('POST', 'email', { cookie: m.cookie, json: { address: 'ada@example.com', time_zone: 'Mars/Olympus' } })).status, 400);
  const add = await napi('POST', 'email', { cookie: m.cookie, json: { address: 'ada@example.com', time_zone: 'UTC' } });
  assert.deepStrictEqual([add.status, add.json.address], [202, 'a***@example.com']);
  const dump = JSON.stringify(await q(`select * from app.email_contacts where member_id = '${m.id}'`));
  assert.ok(!dump.includes('ada@example.com') && !dump.includes('example.com'), 'the address is never stored in the clear');
  // Copies wait for the confirmation: a notice now is not emailed.
  await run(SYSTEM, (t) => notices.challenge(t, { memberId: m.id, title: 'Before confirming', body: 'x', dedupeKey: 'n3:' + m.id }));
  await drainNow();
  const mails = mailTo('ada@example.com', since);
  assert.strictEqual(mails.length, 1);
  assert.strictEqual(mails[0].headers.subject, 'Confirm email copies from Day One Great');
  assert.strictEqual((await q(`select status, last_error from app.outbox o join app.notices n on n.id = o.notice_id where n.dedupe_key = 'n3:${m.id}'`))[0].last_error, 'unconfirmed');
  const token = tokenIn(mails[0], 'confirm');
  // Looking changes nothing; another member can't use it; the member can, once.
  assert.strictEqual((await napi('POST', 'link', { cookie: m.cookie, json: { t: token, preview: true } })).json.purpose, 'confirm_email');
  assert.strictEqual((await inbox(m)).email.status, 'pending');
  const other = await member(2, 'Not Ada');
  assert.strictEqual((await napi('POST', 'link', { cookie: other.cookie, json: { t: token } })).status, 404);
  assert.strictEqual((await napi('POST', 'link', { json: { t: token } })).status, 401);
  assert.strictEqual((await napi('POST', 'link', { cookie: m.cookie, json: { t: token } })).status, 200);
  assert.deepStrictEqual([(await inbox(m)).email.status, (await inbox(m)).email.confirmed], ['active', true]);
  assert.strictEqual((await napi('POST', 'link', { cookie: m.cookie, json: { t: token } })).status, 409, 'used once');
  // A member can't switch copies on without confirming, even with their own SQL rights.
  await run(m.ctx, (t) => t`update app.email_contacts set address_sealed = 'x', address_fp = ${c.sha256hex('new')} where member_id = ${m.id}`);
  assert.strictEqual((await q(`select status from app.email_contacts where member_id = '${m.id}'`))[0].status, 'pending', 'a new address is confirmed first');
  await assert.rejects(run(m.ctx, (t) => t`update app.email_contacts set status = 'active' where member_id = ${m.id}`), /confirmation email/);
  // The rate limit on confirmation emails (S6).
  const r = [];
  for (let i = 0; i < 6; i++) r.push((await napi('POST', 'email', { cookie: other.cookie, json: { address: 'x' + i + '@example.com', time_zone: 'UTC' } })).status);
  assert.deepStrictEqual(r, [202, 202, 202, 202, 202, 429]);
});

test('N4: at most one email an hour per member, with everything waiting in one digest; quiet hours hold email back', async () => {
  const m = await member(2, 'Digest');
  await withEmail(m, 'digest@example.com');
  const ag = await agentOf(m, 'Writer');
  const since = mark();
  await say(ag, 'first words'); await say(ag, 'second words');
  await drainNow();
  let mails = mailTo('digest@example.com', since);
  assert.strictEqual(mails.length, 1, 'two notices, one email');
  assert.strictEqual(mails[0].headers.subject, 'Day One Great: 2 things for you');
  assert.match(mails[0].text, /> first words/);
  assert.match(mails[0].text, /> second words/);
  // Another notice within the hour waits for the hour to pass.
  await say(ag, 'third words');
  await drainNow();
  assert.strictEqual(mailTo('digest@example.com', since).length, 1);
  const [w] = await q(`select o.status, o.next_attempt_at > now() + interval '50 minutes' as later from app.outbox o join app.notices n on n.id = o.notice_id
                       where n.member_id = '${m.id}' and o.status = 'pending'`);
  assert.deepStrictEqual({ ...w }, { status: 'pending', later: true });
  // When the hour has passed it goes, unless it's quiet hours where the member is.
  await run(SYSTEM, (t) => t`update app.email_contacts set next_email_at = now() - interval '1 second' where member_id = ${m.id}`);
  await q(`update app.outbox set next_attempt_at = now() where status = 'pending' and member_id = '${m.id}'`);
  const h = new Date().getUTCHours();
  assert.strictEqual((await napi('POST', 'settings', { cookie: m.cookie, json: { quiet_start: h, quiet_end: (h + 1) % 24, time_zone: 'UTC' } })).status, 200);
  await drainNow();
  assert.strictEqual(mailTo('digest@example.com', since).length, 1, 'quiet hours: nothing sent');
  const [quiet] = await q(`select o.next_attempt_at = date_trunc('hour', now()) + interval '1 hour' as at_end from app.outbox o where o.member_id = '${m.id}' and o.status = 'pending'`);
  assert.strictEqual(quiet.at_end, true, 'rescheduled for when quiet hours end');
  await napi('POST', 'settings', { cookie: m.cookie, json: { quiet_start: 0, quiet_end: 0, time_zone: 'UTC' } });
  await q(`update app.outbox set next_attempt_at = now() where status = 'pending' and member_id = '${m.id}'`);
  await drainNow();
  mails = mailTo('digest@example.com', since);
  assert.strictEqual(mails.length, 2);
  assert.match(mails[1].text, /> third words/);
  // The quiet-hours sum itself, across midnight and in a named time zone.
  const [z] = await q(`select app.quiet_until(22::smallint, 7::smallint, 'UTC') as a, app.quiet_until(5::smallint, 5::smallint, 'UTC') as none`);
  assert.strictEqual(z.none, null, 'start = end means no quiet hours');
  if (h >= 22 || h < 7) assert.ok(z.a > new Date()); else assert.strictEqual(z.a, null);
});

test('N5: one-click unsubscribe (RFC 8058) from the header address; a GET only shows a button; a forged signature does nothing', async () => {
  const m = await member(2, 'Leaver');
  await withEmail(m, 'leaver@example.com');
  const since = mark();
  await run(SYSTEM, (t) => notices.challenge(t, { memberId: m.id, title: 'Hello', body: 'x', dedupeKey: 'n5:' + m.id }));
  await drainNow();
  const [mail] = mailTo('leaver@example.com', since);
  assert.strictEqual(mail.headers['list-unsubscribe-post'], 'List-Unsubscribe=One-Click');
  const u = new URL(mail.headers['list-unsubscribe'].slice(1, -1));
  assert.strictEqual(u.origin + u.pathname, ORIGIN + '/api/notify/unsubscribe');
  const query = Object.fromEntries(u.searchParams);
  // A scanner or a person opening it: a redirect to the page with the button, nothing changed.
  const get = await napi('GET', 'unsubscribe', { query });
  assert.deepStrictEqual([get.status, get.r.getHeader('Location')], [303, '/act#unsub=' + query.c + '.' + query.s]);
  assert.strictEqual((await inbox(m)).email.status, 'active');
  const form = 'application/x-www-form-urlencoded';
  assert.strictEqual((await napi('POST', 'unsubscribe', { query: { c: query.c, s: 'f'.repeat(64) }, origin: null, contentType: form, body: 'List-Unsubscribe=One-Click' })).status, 400);
  assert.strictEqual((await napi('POST', 'unsubscribe', { query, origin: null, contentType: form, body: 'something=else' })).status, 400);
  // The mail provider's one-click POST: no cookie, no Origin.
  const one = await napi('POST', 'unsubscribe', { query, origin: null, contentType: form, body: 'List-Unsubscribe=One-Click' });
  assert.deepStrictEqual([one.status, one.json.unsubscribed], [200, true]);
  assert.strictEqual((await inbox(m)).email.status, 'off');
  await run(SYSTEM, (t) => notices.challenge(t, { memberId: m.id, title: 'After', body: 'x', dedupeKey: 'n5b:' + m.id }));
  await run(SYSTEM, (t) => t`update app.email_contacts set next_email_at = now() where member_id = ${m.id}`);
  await drainNow();
  assert.strictEqual(mailTo('leaver@example.com', since).length, 1, 'no more email');
  assert.strictEqual((await q(`select last_error from app.outbox o join app.notices n on n.id = o.notice_id where n.dedupe_key = 'n5b:${m.id}'`))[0].last_error, 'email_off');
  assert.ok((await inbox(m)).notices.some((n) => n.title === 'After'), 'the notice is still in the inbox');
  // The member can turn copies back on from their account, since the address was confirmed.
  assert.strictEqual((await napi('POST', 'email', { cookie: m.cookie, json: { copies: 'on' } })).json.status, 'active');
  // The page's own button posts the same signature as JSON.
  assert.strictEqual((await napi('POST', 'unsubscribe', { json: { c: query.c, s: query.s } })).status, 200);
  assert.strictEqual((await inbox(m)).email.status, 'off');
});

test('R16: an approval link shows the words on a look and approves only from the owner\'s session, once, for the exact words, within the draft\'s life', async () => {
  const owner = await member(2, 'Link owner');
  await withEmail(owner, 'linkowner@example.com');
  const ag = await agentOf(owner, 'Courier');
  const since = mark();
  const d = await say(ag, 'Exact words to approve');
  await drainNow();
  const [mail] = mailTo('linkowner@example.com', since);
  assert.match(mail.text, /Courier wrote, word for word:\n\n> Exact words to approve/);
  const t = tokenIn(mail, 'approve');
  assert.ok(t, 'the email carries a link to /act with the token after "#"');
  const [link] = await q(`select l.token_hash, l.bound_hash, l.member_id, l.expires_at = d.expires_at as same_life, l.bound_hash = d.body_hash as same_words
                          from app.action_links l join app.agent_drafts d on d.id = l.subject_id where l.subject_id = '${d.drafted.id}'`);
  assert.deepStrictEqual([link.token_hash, link.member_id, link.same_life, link.same_words], [c.sha256hex(t), owner.id, true, true], 'stored hashed, bound by the database');
  assert.ok(!JSON.stringify(await q(`select * from app.action_links`)).includes(t), 'the token itself is never stored');
  // A GET does nothing at all (and the page that shows it is static, with the token after "#").
  assert.strictEqual((await napi('GET', 'link', { cookie: owner.cookie, query: { t } })).status, 405);
  // A look shows the words and changes nothing.
  const look = await napi('POST', 'link', { cookie: owner.cookie, json: { t, preview: true } });
  assert.deepStrictEqual([look.status, look.json.draft.body, look.json.draft.agent, look.json.draft.status], [200, 'Exact words to approve', 'Courier', 'pending']);
  assert.strictEqual((await q(`select used_at from app.action_links where token_hash = '${c.sha256hex(t)}'`))[0].used_at, null);
  // Another session (another member) gets nothing, not even the words.
  const stranger = await member(2, 'Stranger');
  assert.strictEqual((await napi('POST', 'link', { cookie: stranger.cookie, json: { t, preview: true } })).status, 404);
  assert.strictEqual((await napi('POST', 'link', { cookie: stranger.cookie, json: { t, hash: c.sha256hex('Exact words to approve') } })).status, 404);
  // Not from another site, and not without signing in.
  assert.strictEqual((await napi('POST', 'link', { cookie: owner.cookie, json: { t, hash: c.sha256hex('Exact words to approve') }, origin: 'https://evil.example' })).status, 403);
  assert.strictEqual((await napi('POST', 'link', { json: { t, hash: c.sha256hex('Exact words to approve') } })).status, 401);
  // Changed words: refused, and the link stays usable.
  assert.strictEqual((await napi('POST', 'link', { cookie: owner.cookie, json: { t, hash: c.sha256hex('Exact words to approve!') } })).status, 409);
  assert.strictEqual((await napi('POST', 'link', { cookie: owner.cookie, json: { t } })).status, 409, 'no hash is no approval');
  // The owner's own session, the exact words: approved and posted, marked "approved".
  const ok = await napi('POST', 'link', { cookie: owner.cookie, json: { t, hash: c.sha256hex('Exact words to approve') } });
  assert.deepStrictEqual([ok.status, ok.json.done], [201, 'approve_draft']);
  assert.strictEqual((await q(`select delegation from app.posts where id = '${ok.json.post.id}'`))[0].delegation, 'approved');
  // Used once.
  assert.strictEqual((await napi('POST', 'link', { cookie: owner.cookie, json: { t, hash: c.sha256hex('Exact words to approve') } })).status, 409);
  // A link can't outlive its draft: an expired draft's link is refused, and a link can't be minted for a decided draft.
  const d2 = await say(ag, 'Too late');
  await drainNow(); // the hour is reserved, so this draft's email waits; mint its link by hand as the site would
  const t2 = c.token(32);
  await run(SYSTEM, (x) => x`insert into app.action_links (purpose, subject_id, token_hash) values ('approve_draft', ${d2.drafted.id}, ${c.sha256hex(t2)})`);
  await rewrite('agent_drafts', 'agent_drafts_guard', `update app.agent_drafts set expires_at = now() - interval '1 second' where id = '${d2.drafted.id}'`);
  await rewrite('action_links', 'action_links_guard', `update app.action_links set expires_at = now() - interval '1 second' where token_hash = '${c.sha256hex(t2)}'`);
  assert.strictEqual((await napi('POST', 'link', { cookie: owner.cookie, json: { t: t2, hash: c.sha256hex('Too late') } })).status, 410);
  await assert.rejects(run(SYSTEM, (x) => x`insert into app.action_links (purpose, subject_id, token_hash) values ('approve_draft', ${d.drafted.id}, ${c.sha256hex(c.token(32))})`), /no waiting draft/);
  // Nobody but the site mints links, and the database fills in who and what they are bound to.
  const d3 = await say(ag, 'Still waiting');
  await assert.rejects(run(owner.ctx, (x) => x`insert into app.action_links (purpose, subject_id, token_hash) values ('approve_draft', ${d3.drafted.id}, ${c.sha256hex('mine')})`), /row-level security/);
});

test('scanner-safe sign-in links (item 4): the email link opens a page that changes nothing; only a same-site POST uses it', () => {
  // Built and tested in PR 2 (test/signin.test.js, "email links"): GET /auth/email/continue shows a Continue button and
  // uses nothing up; only POST /auth/email/finish does, from our own page. PR 13 sends that email through SES once on.
  const flow = fs.readFileSync(path.join(root, 'signin', 'flow.js'), 'utf8');
  assert.match(flow, /'\/auth\/email\/continue#t=' \+ token/, 'the token is after "#", so opening the link sends it nowhere');
  const auth = require('../api/auth.js');
  assert.ok(auth.ROUTES['GET email/continue'] && auth.ROUTES['POST email/finish'] && !auth.ROUTES['GET email/finish']);
  const signin = fs.readFileSync(path.join(root, 'test', 'signin.test.js'), 'utf8');
  assert.match(signin, /Opening the link \(as a mail scanner would\) only shows a button/);
});

test('R33: at day 80 the owner is asked (one tap keeps it); with no answer by day 90 it drafts again, never off, recorded, with a notice', async () => {
  const owner = await member(2, 'Long runner');
  await withEmail(owner, 'longrunner@example.com');
  const ag = await agentOf(owner, 'Veteran', { act: true });
  const backdate = (days) => rewrite('agent_rules', 'agent_rules_guard', `update app.agent_rules set created_at = now() - interval '${days} days' where agent_id = '${ag.id}'`);
  await backdate(79);
  await timers();
  assert.ok(!(await inbox(owner)).notices.some((n) => n.kind === 'act_reconfirm'), 'nothing before day 80');
  await backdate(81);
  const since = mark();
  await timers();
  await timers(); // twice: still one notice
  const asked = (await inbox(owner)).notices.filter((n) => n.kind === 'act_reconfirm');
  assert.strictEqual(asked.length, 1);
  assert.match(asked[0].title, /^Keep Veteran acting on its own\?$/);
  await drainNow();
  const [mail] = mailTo('longrunner@example.com', since);
  const t = tokenIn(mail, 'keep');
  assert.ok(t, 'the email has a one-tap keep link');
  const look = await napi('POST', 'link', { cookie: owner.cookie, json: { t, preview: true } });
  assert.deepStrictEqual([look.json.purpose, look.json.agent.name, look.json.rules.post], ['keep_acting', 'Veteran', 'act']);
  const stranger = await member(2, 'Not the owner');
  assert.strictEqual((await napi('POST', 'link', { cookie: stranger.cookie, json: { t } })).status, 404);
  const kept = await napi('POST', 'link', { cookie: owner.cookie, json: { t } });
  assert.deepStrictEqual([kept.status, kept.json.done], [201, 'keep_acting']);
  const [r] = await q(`select version, post_mode, reason, set_by from app.agent_rules where agent_id = '${ag.id}' order by version desc limit 1`);
  assert.deepStrictEqual({ ...r }, { version: 3, post_mode: 'act', reason: 'reconfirmed', set_by: 'owner' }, 'the same rules, confirmed, with no fresh sign-in needed');
  assert.strictEqual((await napi('POST', 'link', { cookie: owner.cookie, json: { t } })).status, 409, 'once');
  await timers();
  assert.strictEqual((await q(`select count(*)::int as n from app.agent_rules where agent_id = '${ag.id}'`))[0].n, 3, 'confirmed: the clock restarted');
  // A keep link minted before the rules change no longer applies after it.
  const stale = c.token(32);
  await run(SYSTEM, (x) => x`insert into app.action_links (purpose, subject_id, token_hash) values ('keep_acting', ${ag.id}, ${c.sha256hex(stale)})`);
  // No answer by day 90: back to drafting (never off), recorded, with a notice; the agent's other modes are untouched.
  await backdate(91);
  await timers();
  const [low] = await q(`select post_mode, reply_mode, report_mode, reason, set_by from app.agent_rules where agent_id = '${ag.id}' order by version desc limit 1`);
  assert.deepStrictEqual({ ...low }, { post_mode: 'draft', reply_mode: 'draft', report_mode: 'draft', reason: 'act_expired', set_by: 'system' });
  assert.ok((await q(`select 1 from app.audit_log where action = 'agent.rules' and subject_id = '${ag.id}' and detail->>'reason' = 'act_expired'`)).length === 1);
  assert.ok((await inbox(owner)).notices.some((n) => n.kind === 'act_expired'));
  const d = await say(ag, 'now I draft');
  assert.ok(d.drafted, 'it drafts for approval rather than posting');
  assert.strictEqual((await napi('POST', 'link', { cookie: owner.cookie, json: { t: stale } })).status, 409, 'the rules changed since that link');
  // From the agents page, signed in: the same one-tap keep, bound to the version the page showed.
  const owner2 = await member(2, 'Page keeper');
  const ag2 = await agentOf(owner2, 'Steady', { act: true });
  const act = await agentsApi('GET', 'activity', owner2);
  const row = act.json.agents.find((a) => a.id === ag2.id);
  assert.ok(row.acting_alone && new Date(row.acting_alone.drafts_at) - new Date(row.acting_alone.confirmed_at) === 90 * 86400000);
  assert.strictEqual((await agentsApi('POST', 'reconfirm', owner2, { agent: ag2.id, version: row.rules.version - 1 })).status, 409, 'a stale page is refused');
  assert.strictEqual((await agentsApi('POST', 'reconfirm', owner2, { agent: ag2.id, version: row.rules.version })).status, 201);
  assert.strictEqual((await agentsApi('POST', 'reconfirm', owner, { agent: ag2.id, version: row.rules.version + 1 })).status, 404, 'not your agent');
  // Confirming can never raise anything.
  await assert.rejects(run(owner2.ctx, (x) => x`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${ag2.id}, 'act', 'act', 'act', 1000, 'reconfirmed')`), /keeps rules that act exactly/);
});

test('draft expiry: an undecided draft tells its owner once when it expires (in the inbox only)', async () => {
  const owner = await member(2, 'Forgetful');
  const ag = await agentOf(owner, 'Patient');
  const d = await say(ag, 'nobody decides');
  await rewrite('agent_drafts', 'agent_drafts_guard', `update app.agent_drafts set expires_at = now() - interval '1 minute' where id = '${d.drafted.id}'`);
  await timers(); await timers();
  const exp = (await inbox(owner)).notices.filter((n) => n.kind === 'draft_expired');
  assert.strictEqual(exp.length, 1);
  assert.strictEqual((await q(`select count(*)::int as n from app.outbox o join app.notices n on n.id = o.notice_id where n.kind = 'draft_expired' and n.member_id = '${owner.id}'`))[0].n, 0);
});

test('N6: the outbox sends at most once: finished rows never change, a lost outcome is closed as failed, transient failures retry', async () => {
  const m = await member(2, 'Once');
  await withEmail(m, 'once@example.com');
  await run(SYSTEM, (t) => notices.challenge(t, { memberId: m.id, title: 'One', body: 'x', dedupeKey: 'n6:' + m.id }));
  // A transport that fails "for now", then works.
  const real = cfg.transport;
  let calls = 0;
  cfg.transport = { name: 'flaky', async send() { calls++; return { ok: false, retry: true, error: 'ses_503' }; } };
  try { await drainNow(); } finally { cfg.transport = real; }
  const [w] = await q(`select o.status, o.attempts, o.last_error, o.next_attempt_at > now() as later from app.outbox o join app.notices n on n.id = o.notice_id where n.dedupe_key = 'n6:${m.id}'`);
  assert.deepStrictEqual({ ...w }, { status: 'pending', attempts: 1, last_error: 'ses_503', later: true });
  assert.strictEqual((await q(`select next_email_at <= now() as free from app.email_contacts where member_id = '${m.id}'`))[0].free, true, 'the hour is given back');
  await q(`update app.outbox set next_attempt_at = now() where member_id = '${m.id}' and status = 'pending'`);
  const since = mark();
  await drainNow();
  assert.strictEqual(mailTo('once@example.com', since).length, 1);
  const [sent] = await q(`select o.id, o.status, o.provider_id from app.outbox o join app.notices n on n.id = o.notice_id where n.dedupe_key = 'n6:${m.id}'`);
  assert.strictEqual(sent.status, 'sent');
  assert.match(sent.provider_id, /^log-/);
  await drainNow();
  assert.strictEqual(mailTo('once@example.com', since).length, 1, 'never twice');
  await assert.rejects(run(SYSTEM, (t) => t`update app.outbox set status = 'pending' where id = ${sent.id}`), /already finished/);
  await assert.rejects(q(`update app.outbox set status = 'pending' where id = '${sent.id}'`), /already finished/);
  // A run that claimed a row and never reported back: the row is closed as failed, not sent again.
  await run(SYSTEM, (t) => notices.challenge(t, { memberId: m.id, title: 'Lost', body: 'x', dedupeKey: 'n6b:' + m.id }));
  const [lost] = await q(`select o.id from app.outbox o join app.notices n on n.id = o.notice_id where n.dedupe_key = 'n6b:${m.id}'`);
  await run(SYSTEM, (t) => t`update app.outbox set status = 'sending' where id = ${lost.id}`);
  await rewrite('outbox', 'outbox_guard', `update app.outbox set claimed_at = now() - interval '20 minutes' where id = '${lost.id}'`);
  await drainNow();
  assert.deepStrictEqual({ ...(await q(`select status, last_error from app.outbox where id = '${lost.id}'`))[0] }, { status: 'failed', last_error: 'unknown_outcome' });
  // A second run while one holds the lock (Vercel Cron can deliver a run twice) does nothing; so do the timers.
  await su.begin(async (t) => {
    await t.unsafe(`select pg_advisory_xact_lock(hashtext('dayonegreat.drain'), 0), pg_advisory_xact_lock(hashtext('dayonegreat.timers'), 0)`);
    assert.deepStrictEqual(await drainNow(), { busy: true });
    assert.deepStrictEqual(await timers(), { busy: true });
  });
  assert.strictEqual(calls, 1);
});

test('N7: bounces and complaints arrive through SNS only with a verified signature for our topic, and stop email to that address', async () => {
  const m = await member(2, 'Bouncer');
  await withEmail(m, 'bounce@example.com');
  const getCert = async () => cert.cert;
  const post = (msg) => napi('POST', 'sns', { contentType: 'text/plain; charset=UTF-8', origin: null, body: JSON.stringify(msg), deps: { getCert } });
  // Forged: signed with another key, another topic, or changed after signing.
  const other = fx.makeCert();
  assert.strictEqual((await post(fx.signed(other.key, { Message: fx.bounce('bounce@example.com') }))).status, 403);
  assert.strictEqual((await post({ ...fx.signed(cert.key, { Message: fx.bounce('someone@example.com') }), Message: fx.bounce('bounce@example.com') })).status, 403);
  assert.strictEqual((await post(fx.signed(cert.key, { Message: fx.bounce('bounce@example.com'), TopicArn: 'arn:aws:sns:us-east-1:999999999999:other' }))).status, 403);
  assert.strictEqual((await post('not json')).status, 403);
  assert.strictEqual((await inbox(m)).email.status, 'active', 'nothing trusted, nothing changed');
  // A soft bounce changes nothing; a permanent one suppresses the address (by fingerprint only).
  assert.strictEqual((await post(fx.signed(cert.key, { Message: fx.bounce('bounce@example.com', 'Transient') }))).json.suppressed, 0);
  const hit = await post(fx.signed(cert.key, { Message: fx.bounce('Bounce@Example.com') }));
  assert.deepStrictEqual([hit.status, hit.json.suppressed, hit.json.contacts], [200, 1, 1]);
  assert.strictEqual((await inbox(m)).email.status, 'suppressed');
  assert.ok(!JSON.stringify(await q(`select * from app.email_suppressions`)).includes('example.com'));
  const since = mark();
  await run(SYSTEM, (t) => notices.challenge(t, { memberId: m.id, title: 'Not emailed', body: 'x', dedupeKey: 'n7:' + m.id }));
  await run(SYSTEM, (t) => t`update app.email_contacts set next_email_at = now() where member_id = ${m.id}`);
  await drainNow();
  assert.strictEqual(mailTo('bounce@example.com', since).length, 0);
  // The same address added again by anyone is never mailed again: the confirmation is skipped too.
  const n = await member(2, 'Same address');
  await napi('POST', 'email', { cookie: n.cookie, json: { address: 'bounce@example.com', time_zone: 'UTC' } });
  await drainNow();
  assert.strictEqual(mailTo('bounce@example.com', since).length, 0);
  // A complaint suppresses too; a subscription confirmation is followed only to an SNS address.
  await withEmail(n, 'complainer@example.com');
  assert.strictEqual((await post(fx.signed(cert.key, { Message: fx.complaint('complainer@example.com') }))).json.contacts, 1);
  let visited = null;
  const conf = fx.signed(cert.key, { Type: 'SubscriptionConfirmation', Message: 'confirm', Token: 'tok', SubscribeURL: 'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=tok' });
  const confirmed = await napi('POST', 'sns', { contentType: 'text/plain', origin: null, body: JSON.stringify(conf), deps: { getCert, confirm: async (u) => { visited = u; } } });
  assert.deepStrictEqual([confirmed.status, visited], [200, conf.SubscribeURL]);
});

test('N8: an owner far busier than their own last 7 days alerts Aaron; a burst of new accounts too; an owner\'s normal busy hour doesn\'t', async () => {
  await asOwner('update app.watch_settings set alert_floor = 5, alert_multiplier = 3, signup_floor = 3, signup_multiplier = 3');
  try {
    const busy = await member(2, 'Suddenly busy');
    const ag = await agentOf(busy, 'Burst', { act: true });
    for (let i = 0; i < 6; i++) await say(ag, 'burst post ' + i);
    // An owner who is always this busy: the same hour is their usual, so no alert.
    const steady = await member(2, 'Always busy');
    const ag2 = await agentOf(steady, 'Steady', { act: true });
    for (let i = 0; i < 6; i++) await say(ag2, 'steady post ' + i);
    // History written straight in (tests only): the triggers that would treat a direct insert as a person's post, count
    // it against today's cap, or wait at commit for a JEVs decision (PR 12) are off for this one transaction.
    const TRIGS = ['posts_agent_lane', 'posts_delegation', 'posts_limit', 'posts_review_guard', 'posts_after_review', 'posts_scored'];
    await su.begin(async (t) => {
      for (const x of TRIGS) await t.unsafe(`alter table app.posts disable trigger ${x}`);
      await t.unsafe(`insert into app.posts (author_id, lane, agent_id, body, delegation, rules_version)
        select '${steady.id}', 'agents', '${ag2.id}', 'history ' || g, 'rules', 2 from generate_series(1, 1000) g`);
      // Inserting sets the time to now (posts_decide); the history is then moved back 2 days.
      await t.unsafe(`update app.posts set created_at = now() - interval '2 days' where body like 'history %' and author_id = '${steady.id}'`);
      for (const x of TRIGS) await t.unsafe(`alter table app.posts enable always trigger ${x}`);
    });
    const [{ n: hist }] = await q(`select count(*)::int as n from app.posts where author_id = '${steady.id}' and lane = 'agents' and created_at < now() - interval '1 day'`);
    assert.strictEqual(hist, 1000, 'about 6 an hour over the last 7 days');
    await timers(); await timers();
    const alerts = (await inbox(aaron)).notices.filter((n) => n.kind === 'alert' && n.title === 'An owner\'s agents are unusually busy');
    const about = await q(`select subject_id from app.notices where kind = 'alert' and title = 'An owner''s agents are unusually busy'`);
    assert.ok(about.some((r) => r.subject_id === busy.id), 'the sudden owner is flagged');
    assert.ok(!about.some((r) => r.subject_id === steady.id), 'the always-busy owner is not');
    assert.ok(alerts.length >= 1);
    assert.ok(!(await inbox(busy)).notices.some((n) => n.kind === 'contained'), 'an alert is not a containment');
    assert.ok((await inbox(aaron)).notices.some((n) => n.title === 'A burst of new accounts'), 'every member here joined within the hour');
    assert.ok(!(await inbox(busy)).notices.some((n) => n.kind === 'alert'), 'alerts go to Aaron only');
  } finally { await asOwner(QUIET_WATCH); }
});

test('N9: past the hard limit an owner\'s agents draft for 24 hours, with a notice and an appeal; then they go back to the rules by themselves', async () => {
  await asOwner('update app.watch_settings set hard_limit_per_hour = 10');
  try {
    const owner = await member(2, 'Flooder');
    await withEmail(owner, 'flooder@example.com');
    const a1 = await agentOf(owner, 'Fast one', { act: true });
    const a2 = await agentOf(owner, 'Drafter');
    for (let i = 0; i < 11; i++) await say(a1, 'flood ' + i);
    const since = mark();
    await timers(); await timers();
    const [cn] = await q(`select id, reason, measured, ends_at > now() + interval '23 hours' as day, lifted_at from app.containments where member_id = '${owner.id}'`);
    assert.deepStrictEqual([cn.reason, cn.measured, cn.day, cn.lifted_at], ['volume', 11, true, null]);
    assert.strictEqual((await q(`select count(*)::int as n from app.containments where member_id = '${owner.id}'`))[0].n, 1, 'once');
    const cur = async (ag) => (await q(`select post_mode, reason from app.agent_rules where agent_id = '${ag.id}' order by version desc limit 1`))[0];
    assert.deepStrictEqual({ ...(await cur(a1)) }, { post_mode: 'draft', reason: 'containment' });
    assert.deepStrictEqual({ ...(await cur(a2)) }, { post_mode: 'draft', reason: 'created' }, 'an agent already drafting is left alone');
    assert.ok((await say(a1, 'after the limit')).drafted, 'it drafts now: approve, not off');
    const notice = (await inbox(owner)).notices.find((n) => n.kind === 'contained');
    assert.ok(notice && notice.link === '/agents#appeal=' + cn.id);
    await drainNow();
    assert.ok(mailTo('flooder@example.com', since).some((m) => /appeal/.test(m.text)), 'the email copy names the appeal');
    assert.ok((await inbox(aaron)).notices.some((n) => n.title === 'An owner\'s agents were set back to drafting'));
    assert.ok((await q(`select 1 from app.audit_log where action = 'containment.start' and subject_id = '${owner.id}'`)).length === 1);
    // The owner sees it on the agents page and appeals once; Aaron sees the appeal in the review queue.
    const page = await agentsApi('GET', 'activity', owner);
    assert.deepStrictEqual([page.json.containment.id, page.json.containment.appealed], [cn.id, false]);
    const stranger = await member(2, 'Not them');
    assert.strictEqual((await napi('POST', 'appeal', { cookie: stranger.cookie, json: { containment: cn.id, note: 'me?' } })).status, 404);
    assert.strictEqual((await napi('POST', 'appeal', { cookie: owner.cookie, json: { containment: cn.id, note: 'A product launch, not spam.' } })).status, 202);
    assert.strictEqual((await napi('POST', 'appeal', { cookie: owner.cookie, json: { containment: cn.id, note: 'again' } })).status, 409);
    assert.ok((await inbox(aaron)).notices.some((n) => n.title === 'An owner appealed a containment'));
    assert.strictEqual((await napi('GET', 'appeals', { cookie: owner.cookie })).status, 403);
    const list = await napi('GET', 'appeals', { cookie: aaron.cookie });
    const item = list.json.containments.find((x) => x.id === cn.id);
    assert.deepStrictEqual([item.appeal.note, item.member.name, item.measured], ['A product launch, not spam.', 'Flooder', 11]);
    assert.ok(!JSON.stringify(await q(`select detail from app.audit_log where action like 'containment.%'`)).includes('product launch'), 'the record holds no words');
    // Aaron keeps it; it then ends on time by itself, and only agents still on the containment's version go back.
    assert.strictEqual((await napi('POST', 'appeals', { cookie: aaron.cookie, json: { containment: cn.id, decision: 'keep' } })).status, 200);
    assert.ok((await inbox(owner)).notices.some((n) => n.kind === 'appeal_decided'));
    await timers();
    assert.strictEqual((await q(`select lifted_at from app.containments where id = '${cn.id}'`))[0].lifted_at, null, 'not before its time');
    await assert.rejects(run(SYSTEM, (t) => t`update app.containments set lifted_at = now() where id = ${cn.id}`), /only when its time is up/);
    // A day later the flood is over (the watch would otherwise see this same busy hour and pause them again).
    await asOwner(QUIET_WATCH);
    await rewrite('containments', 'containments_guard', `update app.containments set ends_at = now() - interval '1 second' where id = '${cn.id}'`);
    await timers();
    const [lifted] = await q(`select lifted_by from app.containments where id = '${cn.id}'`);
    assert.strictEqual(lifted.lifted_by, 'timer');
    assert.deepStrictEqual({ ...(await cur(a1)) }, { post_mode: 'act', reason: 'containment_lifted' }, 'back to exactly the rules it had');
    assert.ok((await inbox(owner)).notices.some((n) => n.kind === 'containment_lifted'));
    // The site itself can never raise an agent except by restoring what a containment replaced.
    await assert.rejects(run(SYSTEM, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${a2.id}, 'act', 'act', 'act', 1000, 'containment_lifted')`), /only restores/);
  } finally { await asOwner(QUIET_WATCH); }
});

test('N9: Aaron can lift a pause early after an appeal; an owner\'s own change during the pause is never overwritten', async () => {
  await asOwner('update app.watch_settings set hard_limit_per_hour = 10');
  try {
    const owner = await member(2, 'Appealer');
    const a1 = await agentOf(owner, 'Changed', { act: true });
    const a2 = await agentOf(owner, 'Unchanged', { act: true });
    for (let i = 0; i < 11; i++) await say(i % 2 ? a1 : a2, 'many ' + i);
    await timers();
    const [cn] = await q(`select id from app.containments where member_id = '${owner.id}' and lifted_at is null`);
    // During the pause the owner switches one agent off themselves.
    await run(owner.ctx, (t) => delegation.setRules(t, { agent: a1.id, post: 'off', reply: 'off', report: 'off', dailyCap: 1000 }));
    assert.strictEqual((await napi('POST', 'appeals', { cookie: owner.cookie, json: { containment: cn.id, decision: 'lift' } })).status, 403);
    await napi('POST', 'appeal', { cookie: owner.cookie, json: { containment: cn.id } });
    assert.strictEqual((await napi('POST', 'appeals', { cookie: aaron.cookie, json: { containment: cn.id, decision: 'lift' } })).status, 200);
    const [x] = await q(`select lifted_by, appeal_decision from app.containments where id = '${cn.id}'`);
    assert.deepStrictEqual({ ...x }, { lifted_by: 'admin', appeal_decision: 'lifted' });
    const mode = async (ag) => (await q(`select post_mode from app.agent_rules where agent_id = '${ag.id}' order by version desc limit 1`))[0].post_mode;
    assert.strictEqual(await mode(a1), 'off', 'the owner\'s own choice stays');
    assert.strictEqual(await mode(a2), 'act');
    assert.strictEqual((await napi('POST', 'appeals', { cookie: aaron.cookie, json: { containment: cn.id, decision: 'lift' } })).status, 404, 'already ended');
  } finally { await asOwner(QUIET_WATCH); }
});

test('N10, the copier rule: repeated text brakes whoever repeats it, never the first author', async () => {
  await asOwner('update app.watch_settings set copy_limit_per_hour = 5, repeat_alert_count = 5');
  try {
    const author = await member(2, 'First author');
    const original = await agentOf(author, 'Original', { act: true });
    await say(original, 'A genuinely good idea, written once.');
    const copier = await member(2, 'Copier');
    const parrot = await agentOf(copier, 'Parrot', { act: true });
    for (let i = 0; i < 5; i++) await say(parrot, i % 2 ? 'a genuinely GOOD idea, written once' : 'A genuinely good idea, written once.');
    // Other owners copying the author once each, many times over, never count against the author.
    for (let i = 0; i < 4; i++) { const o = await member(2, 'Echo ' + i); await say(await agentOf(o, 'Echo', { act: true }), 'A genuinely good idea, written once.'); }
    await timers();
    const [cp] = await q(`select reason, measured from app.containments where member_id = '${copier.id}' and lifted_at is null`);
    assert.deepStrictEqual({ ...cp }, { reason: 'copies', measured: 5 }, 'the copier is contained (case and punctuation ignored)');
    assert.strictEqual((await q(`select count(*)::int as n from app.containments where member_id = '${author.id}'`))[0].n, 0, 'the first author is not');
    assert.strictEqual((await q(`select post_mode from app.agent_rules where agent_id = '${original.id}' order by version desc limit 1`))[0].post_mode, 'act');
    assert.ok((await inbox(aaron)).notices.some((n) => n.title === 'The same text keeps being posted'));
    // An owner repeating their own text is a copier of it too.
    const self = await member(2, 'Self repeater');
    const loop = await agentOf(self, 'Loop', { act: true });
    for (let i = 0; i < 6; i++) await say(loop, 'my slogan');
    await timers();
    assert.strictEqual((await q(`select measured from app.containments where member_id = '${self.id}'`))[0].measured, 5, 'every post after the first');
  } finally { await asOwner(QUIET_WATCH); }
});

test('the watch\'s settings: the site and members read nothing they shouldn\'t and change nothing; only the owner role does', async () => {
  const m = await member(2, 'Settings poker');
  assert.strictEqual((await run(m.ctx, (t) => t`select count(*)::int as n from app.watch_settings`))[0].n, 0);
  await assert.rejects(run(aaron.ctx, (t) => t`update app.watch_settings set hard_limit_per_hour = 10000000`), /permission denied/);
  await assert.rejects(run(SYSTEM, (t) => t`update app.watch_settings set hard_limit_per_hour = 10000000`), /permission denied/);
  await assert.rejects(run(SYSTEM, (t) => t`insert into app.watch_settings default values`), /permission denied/);
  assert.strictEqual((await run(SYSTEM, (t) => t`select count(*)::int as n from app.watch_settings`))[0].n, 1);
  // The timers run only as the site itself.
  await assert.rejects(run(aaron.ctx, (t) => t`select app.run_timers()`), /only the site/);
  await assert.rejects(run(m.ctx, (t) => t`select app.watch_job()`), /only the site/);
});

test('notices the rest of the system already causes: an upheld report and a brake on one owner tell that owner', async () => {
  const owner = await member(2, 'Reported owner');
  const ag = await agentOf(owner, 'Reported', { act: true });
  const p = await say(ag, 'a post someone reports');
  const reporter = await member(2, 'Reporter');
  await run(reporter.ctx, (t) => review.report(t, { post: p.posted.id, reason: 'spam' }));
  await run(aaron.ctx, (t) => review.decide(t, { post: p.posted.id, decision: 'remove' }));
  const n = (await inbox(owner)).notices.find((x) => x.kind === 'report_upheld');
  assert.ok(n && n.title === 'Reported is drafting again');
  await run(aaron.ctx, (t) => controls.setBrake(t, { member: owner.id, agent_posts_per_hour: 0, people_per_hour: 5 }));
  const b = (await inbox(owner)).notices.find((x) => x.kind === 'brake_on');
  assert.match(b.body, /at most 5 of your own posts an hour; your agents' posts are paused/);
  await run(aaron.ctx, (t) => controls.setBrake(t, { member: null, new_agents_per_day: 50 }));
  assert.strictEqual((await inbox(reporter)).notices.filter((x) => x.kind === 'brake_on').length, 0, 'a brake for everyone tells nobody one by one');
});

test('the cron route runs the timers and the drain, only with the right secret', async () => {
  const cron = require('../api/cron.js');
  const call = async (h) => { const r = res(); await cron.handle({ method: 'GET', headers: { authorization: h } }, r, run, cfg); return { status: r.statusCode, json: JSON.parse(r.body) }; };
  assert.strictEqual((await call('Bearer wrong')).status, 401);
  const ok = await call('Bearer ' + SECRET);
  assert.strictEqual(ok.status, 200, JSON.stringify(ok.json));
  assert.ok('lifted' in ok.json.timers && 'contained' in ok.json.timers && 'batches' in ok.json.email);
  assert.ok(!JSON.stringify(ok.json).includes('@'), 'no addresses in what it reports');
});

test('F8: deleting an account deletes its notices, its alerts to Aaron, its address, links and pauses', async () => {
  await asOwner('update app.watch_settings set hard_limit_per_hour = 10');
  let gone;
  try {
    gone = await member(2, 'Leaving for good');
    await withEmail(gone, 'leaving@example.com');
    const ag = await agentOf(gone, 'Last', { act: true });
    for (let i = 0; i < 11; i++) await say(ag, 'last words ' + i);
    await timers();
    await drainNow();
  } finally { await asOwner(QUIET_WATCH); }
  const counts = async () => (await q(`select (select count(*) from app.notices where member_id = '${gone.id}' or subject_id = '${gone.id}')::int as notices,
    (select count(*) from app.email_contacts where member_id = '${gone.id}')::int as contacts, (select count(*) from app.action_links where member_id = '${gone.id}')::int as links,
    (select count(*) from app.containments where member_id = '${gone.id}')::int as paused, (select count(*) from app.outbox where member_id = '${gone.id}')::int as outbox`))[0];
  const before = await counts();
  assert.ok(before.notices > 0 && before.contacts === 1 && before.links > 0 && before.paused === 1, JSON.stringify(before));
  const out = await run({ ...gone.ctx, fresh: true }, (t) => store.deleteAccount(t));
  assert.ok(!out.refused, JSON.stringify(out));
  assert.deepStrictEqual({ ...(await counts()) }, { notices: 0, contacts: 0, links: 0, paused: 0, outbox: 0 });
});
