// Release 2, PR 13: notifications against a real Postgres, in-app only (Aaron, Oct 16, 2026). Every behaviour has a
// test: the inbox, in the same transaction, once; no member address stored and nothing emailed; one tap on the notice
// (R16, R33, held posts); safe links and masked titles; bounces on sign-in emails; the watch, containment (no evasion,
// lifted on time even without a timer run) and the copier rule; JEVs through the inbox.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { stepUpFor } = require('./passkey-helpers');
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
const { logTransport } = require('../notify/transport');
const { signinSender } = require('../notify/sender');
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
const cfg = ncfg.load({ EMAIL_TRANSPORT: 'log', SNS_TOPIC_ARN: fx.TOPIC, CRON_SECRET: SECRET });
// The sign-in fingerprint keys (signin/config.js), which also key the bounce fingerprints.
const KEYS = [{ version: 1, key: crypto.randomBytes(32) }];
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
  aaron.ctx = { ...aaron.ctx, actor: 'admin' }; // admin, with Aaron's own session and its passkey check
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
  await stepUpFor(su, out.memberId); // PR 17: a passkey, already checked
  return { id: out.memberId, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, stepUp: true, session: c.sha256hex(token) } };
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
    body: json !== undefined ? JSON.stringify(json) : body }, r, run, cfg, { keys: KEYS, ...(deps || {}) });
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
const inbox = async (who) => (await napi('GET', '', { cookie: who.cookie })).json;
// Leaves a notice the way the database's own triggers do (app.notify), as whoever the transaction acts as.
const leave = async (t, { memberId, kind, title, body = '', link = null, dedupeKey }) =>
  (await t`select app.notify(${memberId}::uuid, ${kind}, ${title}, ${body}, ${link}, null, null::uuid, ${dedupeKey}) as fresh`)[0].fresh;

test('the database passes the coverage check and matches the reviewed snapshot with the notification tables (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('N1, N2: a draft leaves its owner a notice in the same transaction; nothing exists if that transaction fails', async () => {
  const owner = await member(2, 'Inbox owner');
  const ag = await agentOf(owner);
  const d = await say(ag, 'Please look at this');
  assert.ok(d.drafted);
  const [n] = await q(`select kind, member_id, subject_kind, subject_id from app.notices where subject_id = '${d.drafted.id}'`);
  assert.deepStrictEqual({ ...n }, { kind: 'draft_waiting', member_id: owner.id, subject_kind: 'draft', subject_id: d.drafted.id });
  // A draft whose transaction rolls back leaves no notice behind.
  const before = (await q(`select count(*)::int as n from app.notices`))[0].n;
  await assert.rejects(run(ag.ctx, async (t) => { await delegation.submit(t, { body: 'rolled back' }); throw new Error('stop'); }), /stop/);
  assert.strictEqual((await q(`select count(*)::int as n from app.notices`))[0].n, before);
  // The owner sees it, unread; nobody else does: another member, the agent itself, someone not signed in.
  const box = await inbox(owner);
  assert.strictEqual(box.unread, 1);
  assert.deepStrictEqual([box.notices[0].kind, box.notices[0].title, box.notices[0].link, box.notices[0].subject], ['draft_waiting', 'Helper wrote a draft for you', '/agents',
    { kind: 'draft', id: d.drafted.id }]);
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

test('N2: the same event never leaves two notices (dedupe key); who may leave one for whom', async () => {
  const m = await member(2, 'Challenged');
  const once = () => run(SYSTEM, (t) => leave(t, { memberId: m.id, kind: 'challenge', title: 'Please confirm it was you', body: 'A new sign-in.', dedupeKey: 'check:1' }));
  assert.strictEqual(await once(), true);
  assert.strictEqual(await once(), false);
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where dedupe_key = 'check:1'`))[0].n, 1);
  // A member's own transaction may leave a notice for that member only; an alert for Aaron is open to anyone signed in.
  await assert.rejects(run(m.ctx, (t) => leave(t, { memberId: aaron.id, kind: 'challenge', title: 't', body: 'b', dedupeKey: 'check:2' })), /row-level security/);
  assert.strictEqual(await run(m.ctx, (t) => leave(t, { memberId: null, kind: 'alert', title: 'High risk held', body: 'Held for review.', dedupeKey: 'hold:1' })), true);
  assert.ok((await inbox(aaron)).notices.some((n) => n.title === 'High risk held' && n.for_admins));
  assert.ok(!(await inbox(m)).notices.some((n) => n.title === 'High risk held'));
  await assert.rejects(run({ actor: 'anon' }, (t) => leave(t, { memberId: null, kind: 'alert', title: 't', body: 'b', dedupeKey: 'anon:1' })), /row-level security/);
});

test('N3: in-app only: no member email address is stored anywhere and no notice is emailed; the inbox has no email settings', async () => {
  // No table or column can hold a member's address or an email copy (the in-app-only decision, Oct 16, 2026).
  const cols = (await q(`select table_name || '.' || column_name as c from information_schema.columns where table_schema = 'app'`)).map((r) => r.c);
  for (const gone of ['email_contacts.address_sealed', 'outbox.id', 'action_links.token_hash', 'notices.send_copy']) assert.ok(!cols.includes(gone), gone);
  assert.deepStrictEqual(cols.filter((x) => /^email/.test(x)).sort(), ['email_suppressions.address_fp', 'email_suppressions.created_at', 'email_suppressions.id',
    'email_suppressions.reason', 'email_tokens.browser_hash', 'email_tokens.created_at', 'email_tokens.email_fingerprints', 'email_tokens.expires_at',
    'email_tokens.id', 'email_tokens.key_version', 'email_tokens.token_hash', 'email_tokens.used_at'].sort(), 'only keyed fingerprints and sign-in link hashes');
  // Notices, timers and all, send nothing: the log transport (where any email would go) stays empty.
  const m = await member(2, 'Inbox only');
  const ag = await agentOf(m);
  const before = cfg.transport.sent.length;
  await say(ag, 'a draft that only shows on the site');
  await timers();
  assert.strictEqual(cfg.transport.sent.length, before);
  const box = await inbox(m);
  assert.ok(box.notices.length >= 1);
  assert.ok(!('email' in box), 'the inbox offers no email settings');
  // The email routes are gone.
  for (const r of ['email', 'settings', 'link', 'unsubscribe']) assert.strictEqual((await napi('POST', r, { cookie: m.cookie, json: {} })).status, 404, r);
  // Sign-in emails still go out, and the address typed at sign-in is used to send, never stored (PR 2's own tests).
  assert.match(fs.readFileSync(path.join(root, 'signin', 'flow.js'), 'utf8'), /sendEmail\(email, link\)/);
});

test('N4, R16: one tap on the notice approves the draft\'s exact words, from the owner\'s own session only; nothing is a bearer link', async () => {
  const owner = await member(2, 'Tapper');
  const ag = await agentOf(owner, 'Writer');
  const d = await say(ag, 'Exactly these words, and no others.');
  const [n] = (await inbox(owner)).notices.filter((x) => x.kind === 'draft_waiting' && x.subject.id === d.drafted.id);
  // The page finds the words by the notice's subject, and approves them with their SHA-256 (account.js does this).
  const act = await agentsApi('GET', 'activity', owner);
  const shown = act.json.inbox.find((x) => x.id === n.subject.id);
  assert.strictEqual(shown.body, 'Exactly these words, and no others.');
  const hash = c.sha256hex(shown.body);
  const stranger = await member(2, 'Stranger');
  assert.notStrictEqual((await agentsApi('POST', 'approve', stranger, { draft: shown.id, hash })).status, 201, 'another member\'s session can\'t');
  assert.strictEqual((await agentsApi('POST', 'approve', owner, { draft: shown.id, hash: c.sha256hex('other words') })).status, 409, 'changed words fail');
  const ok = await agentsApi('POST', 'approve', owner, { draft: shown.id, hash });
  assert.strictEqual(ok.status, 201, JSON.stringify(ok.json));
  assert.strictEqual((await agentsApi('POST', 'approve', owner, { draft: shown.id, hash })).status, 409, 'once');
  // A notice carries no token: nothing in the inbox works without the owner's session.
  assert.ok(!JSON.stringify(await q(`select title, body, link from app.notices where member_id = '${owner.id}'`)).match(/[A-Za-z0-9_-]{43}/));
  const page = fs.readFileSync(path.join(root, 'account.js'), 'utf8');
  assert.match(page, /sha256\(words\.textContent\)\.then\(function \(h\) \{ return postJson\('\/api\/agents\/approve', \{ draft: d\.id, hash: h \}\)/);
  assert.match(page, /el\('blockquote', 'draft-words', d\.body\)/, 'the words are shown as text, never as HTML');
});

test('N5: notice links are paths on this site only; agent names in titles are masked and marked untrusted', async () => {
  const m = await member(2, 'Linked');
  for (const bad of ['//evil.example/x', 'https://evil.example', '/\\evil', 'javascript:alert(1)']) {
    await assert.rejects(run(SYSTEM, (t) => leave(t, { memberId: m.id, kind: 'challenge', title: 't', link: bad, dedupeKey: 'bad:' + crypto.randomUUID() })), /check constraint/, bad);
    await assert.rejects(q(`insert into app.notices (member_id, kind, title, body, link, dedupe_key) values ('${m.id}', 'challenge', 't', '', '${bad.replace(/'/g, "''")}', 'raw:${crypto.randomUUID()}')`), /check constraint/, bad);
  }
  assert.strictEqual(await run(SYSTEM, (t) => leave(t, { memberId: m.id, kind: 'challenge', title: 'fine', link: '/agents#appeal=1', dedupeKey: 'good:1' })), true);
  // An agent named to look like contact details: the title is masked on the way out, and listed as untrusted.
  const ag = await agentOf(m, 'Mail me at bob@example.com now');
  await say(ag, 'hello');
  const box = await inbox(m);
  const t = box.notices.find((x) => x.kind === 'draft_waiting');
  assert.ok(!t.title.includes('bob@example.com'), t.title);
  assert.match(t.title, /\[email hidden\]/);
  assert.deepStrictEqual(box.untrusted_fields, ['notices[].title', 'notices[].body']);
  assert.match(fs.readFileSync(path.join(root, 'account.js'), 'utf8'), /n\.link && \/\^\\\/\(\?!\\\/\)\/\.test\(n\.link\)/, 'the page checks again before linking');
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
  const ag = await agentOf(owner, 'Veteran', { act: true });
  const backdate = (days) => rewrite('agent_rules', 'agent_rules_guard', `update app.agent_rules set created_at = now() - interval '${days} days' where agent_id = '${ag.id}'`);
  await backdate(79);
  await timers();
  assert.ok(!(await inbox(owner)).notices.some((n) => n.kind === 'act_reconfirm'), 'nothing before day 80');
  await backdate(81);
  await timers();
  await timers(); // twice: still one notice
  const asked = (await inbox(owner)).notices.filter((n) => n.kind === 'act_reconfirm');
  assert.strictEqual(asked.length, 1);
  assert.match(asked[0].title, /^Keep Veteran acting on its own\?$/);
  assert.deepStrictEqual(asked[0].subject, { kind: 'agent', id: ag.id }, 'the notice names the agent, for its one tap');
  // One tap on the notice keeps it: the rules version the page showed, from the owner's session (account.js).
  const shown = (await agentsApi('GET', 'activity', owner)).json.agents.find((x) => x.id === asked[0].subject.id);
  const stranger = await member(2, 'Not the owner');
  assert.strictEqual((await agentsApi('POST', 'reconfirm', stranger, { agent: ag.id, version: shown.rules.version })).status, 404);
  const kept = await agentsApi('POST', 'reconfirm', owner, { agent: ag.id, version: shown.rules.version });
  assert.strictEqual(kept.status, 201, JSON.stringify(kept.json));
  const [r] = await q(`select version, post_mode, reason, set_by from app.agent_rules where agent_id = '${ag.id}' order by version desc limit 1`);
  assert.deepStrictEqual({ ...r }, { version: 3, post_mode: 'act', reason: 'reconfirmed', set_by: 'owner' }, 'the same rules, confirmed, from a fresh session (PR 15)');
  assert.strictEqual((await agentsApi('POST', 'reconfirm', owner, { agent: ag.id, version: shown.rules.version })).status, 409, 'a stale version is refused');
  await timers();
  assert.strictEqual((await q(`select count(*)::int as n from app.agent_rules where agent_id = '${ag.id}'`))[0].n, 3, 'confirmed: the clock restarted');
  assert.match(fs.readFileSync(path.join(root, 'account.js'), 'utf8'), /postJson\('\/api\/agents\/reconfirm', \{ agent: a\.id, version: a\.rules\.version \}\)/);
  // No answer by day 90: back to drafting (never off), recorded, with a notice; the agent's other modes are untouched.
  await backdate(91);
  await timers();
  const [low] = await q(`select post_mode, reply_mode, report_mode, reason, set_by from app.agent_rules where agent_id = '${ag.id}' order by version desc limit 1`);
  assert.deepStrictEqual({ ...low }, { post_mode: 'draft', reply_mode: 'draft', report_mode: 'draft', reason: 'act_expired', set_by: 'system' });
  assert.ok((await q(`select 1 from app.audit_log where action = 'agent.rules' and subject_id = '${ag.id}' and detail->>'reason' = 'act_expired'`)).length === 1);
  assert.ok((await inbox(owner)).notices.some((n) => n.kind === 'act_expired'));
  const d = await say(ag, 'now I draft');
  assert.ok(d.drafted, 'it drafts for approval rather than posting');
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

// PR 15: keeping an agent acting on its own for another 90 days is letting it act without approval, so it needs a
// fresh sign-in (the last 10 minutes, by the database clock), like raising it to act did. From the notice, from the
// agents page, and calling the database directly.
test('PR 15: keeping an agent acting on its own (R33) needs a fresh sign-in, from the notice, the agents page or the database', async () => {
  const owner = await member(2, 'Stale keeper');
  const ag = await agentOf(owner, 'Keeper', { act: true });
  const shown = (await agentsApi('GET', 'activity', owner)).json.agents.find((x) => x.id === ag.id);
  const versions = async () => (await q(`select count(*)::int as n from app.agent_rules where agent_id = '${ag.id}'`))[0].n;
  const n0 = await versions();
  await q(`update app.sessions set created_at = now() - interval '11 minutes' where member_id = '${owner.id}'`);
  const stale = await agentsApi('POST', 'reconfirm', owner, { agent: ag.id, version: shown.rules.version });
  assert.strictEqual(stale.status, 403, JSON.stringify(stale.json));
  assert.match(stale.json.error, /sign in again/i);
  assert.strictEqual(stale.json.reauth, '/join?return_to=%2Fagents');
  assert.strictEqual(await versions(), n0, 'nothing was confirmed');
  const same = (x) => x`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${ag.id}, 'act', 'draft', 'draft', 1000, 'reconfirmed')`;
  await assert.rejects(run(owner.ctx, same), /fresh_sign_in/, 'the database refuses it without a fresh sign-in');
  await run({ ...owner.ctx, fresh: true }, same);
  await q(`update app.sessions set created_at = now() where member_id = '${owner.id}'`);
  const now = (await agentsApi('GET', 'activity', owner)).json.agents.find((x) => x.id === ag.id);
  assert.strictEqual((await agentsApi('POST', 'reconfirm', owner, { agent: ag.id, version: now.rules.version })).status, 201);
  assert.match(fs.readFileSync(path.join(root, 'account.js'), 'utf8'), /x\.d\.reauth/, 'the notice offers to sign in again');
});

test('draft expiry: an undecided draft tells its owner once when it expires (in the inbox only)', async () => {
  const owner = await member(2, 'Forgetful');
  const ag = await agentOf(owner, 'Patient');
  const d = await say(ag, 'nobody decides');
  await rewrite('agent_drafts', 'agent_drafts_guard', `update app.agent_drafts set expires_at = now() - interval '1 minute' where id = '${d.drafted.id}'`);
  await timers(); await timers();
  const exp = (await inbox(owner)).notices.filter((n) => n.kind === 'draft_expired');
  assert.strictEqual(exp.length, 1);
});

test('N6: while a pause is in force the owner can\'t raise any agent, existing or new, until it ends; lowering stays open', async () => {
  await asOwner('update app.watch_settings set hard_limit_per_hour = 10');
  try {
    const owner = await member(2, 'Evader');
    const a1 = await agentOf(owner, 'Was acting', { act: true });
    for (let i = 0; i < 11; i++) await say(a1, 'busy ' + i);
    await timers();
    const [cn] = await q(`select id from app.containments where member_id = '${owner.id}' and lifted_at is null`);
    assert.ok(cn, 'contained');
    // Signed in again (fresh), the owner tries to put it back to acting: refused, with a plain answer (the review's
    // probe "evasion" set it back to act and posted live).
    await q(`update app.sessions set created_at = now() where member_id = '${owner.id}'`);
    const raise = await agentsApi('POST', 'rules', owner, { agent: a1.id, post: 'act', reply: 'draft', report: 'draft', daily_cap: 1000 });
    assert.strictEqual(raise.status, 409, JSON.stringify(raise.json));
    assert.match(raise.json.error, /until the pause on them ends/);
    assert.ok((await say(a1, 'still drafting')).drafted, 'it can\'t post live');
    // A new agent made during the pause starts at draft and can't be raised either.
    const made = await agentsApi('POST', '', owner, { name: 'Fresh helper' });
    assert.strictEqual(made.status, 201, JSON.stringify(made.json));
    const fresh = { id: made.json.agent_id, ctx: { actor: 'agent', memberId: owner.id, agentId: made.json.agent_id } };
    assert.strictEqual((await agentsApi('POST', 'rules', owner, { agent: fresh.id, post: 'act', reply: 'draft', report: 'draft', daily_cap: 20 })).status, 409);
    assert.ok((await say(fresh, 'new agent, still drafting')).drafted);
    // Lowering is always open; a cap raised is a raise too.
    assert.strictEqual((await agentsApi('POST', 'rules', owner, { agent: a1.id, post: 'off', reply: 'off', report: 'off', daily_cap: 10 })).status, 201);
    await assert.rejects(run({ ...owner.ctx, fresh: true }, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${a1.id}, 'off', 'off', 'off', 20, 'owner')`), /contained/);
    // Once it has ended, raising works again.
    await asOwner(QUIET_WATCH);
    await rewrite('containments', 'containments_guard', `update app.containments set ends_at = now() - interval '1 second' where id = '${cn.id}'`);
    await timers();
    assert.strictEqual((await agentsApi('POST', 'rules', owner, { agent: fresh.id, post: 'act', reply: 'draft', report: 'draft', daily_cap: 20 })).status, 201);
  } finally { await asOwner(QUIET_WATCH); }
});

test('N9: a pause whose time is up ends when its owner\'s rules are read or written, even if no timer runs', async () => {
  await asOwner('update app.watch_settings set hard_limit_per_hour = 10');
  try {
    const owner = await member(2, 'Missed timer');
    const a1 = await agentOf(owner, 'Waiting', { act: true });
    for (let i = 0; i < 11; i++) await say(a1, 'flood ' + i);
    await timers();
    const [cn] = await q(`select id from app.containments where member_id = '${owner.id}' and lifted_at is null`);
    await asOwner(QUIET_WATCH);
    // Before its time is up, reading ends nothing.
    assert.strictEqual(await run(owner.ctx, (t) => notices.liftDue(t)), false);
    // Its time is up, and the timer doesn't run (Vercel Cron is best effort).
    await rewrite('containments', 'containments_guard', `update app.containments set ends_at = now() - interval '1 minute' where id = '${cn.id}'`);
    // The owner opens their agents page: the pause ends there and then, as the timer would have ended it.
    const page = await agentsApi('GET', 'activity', owner);
    assert.strictEqual(page.json.containment, null);
    const [x] = await q(`select lifted_at is not null as lifted, lifted_by from app.containments where id = '${cn.id}'`);
    assert.deepStrictEqual({ ...x }, { lifted: true, lifted_by: 'timer' });
    assert.strictEqual((await q(`select post_mode from app.agent_rules where agent_id = '${a1.id}' order by version desc limit 1`))[0].post_mode, 'act', 'back on its rules');
    assert.ok((await inbox(owner)).notices.some((n) => n.kind === 'containment_lifted'));
    // An owner can't end a pause early this way, or end anyone else's.
    await asOwner('update app.watch_settings set hard_limit_per_hour = 10');
    const other = await member(2, 'Still paused');
    const b1 = await agentOf(other, 'Busy', { act: true });
    for (let i = 0; i < 11; i++) await say(b1, 'again ' + i);
    await timers();
    await asOwner(QUIET_WATCH);
    assert.ok((await q(`select 1 from app.containments where member_id = '${other.id}' and lifted_at is null`)).length === 1);
    assert.strictEqual(await run(other.ctx, (t) => notices.liftDue(t)), false, 'not before its time');
    await assert.rejects(run(other.ctx, (t) => t`update app.containments set lifted_at = now() where member_id = ${other.id}`), /an owner can only appeal/);
    assert.strictEqual(await run(owner.ctx, (t) => notices.liftDue(t)), false, 'nobody lifts someone else\'s');
  } finally { await asOwner(QUIET_WATCH); }
});

test('N7: bounces and complaints on sign-in emails arrive only through verified SNS messages, are kept as fingerprints, and stop sign-in email to that address', async () => {
  const getCert = async () => cert.cert;
  const post = (m) => napi('POST', 'sns', { contentType: 'text/plain; charset=UTF-8', body: JSON.stringify(m), deps: { getCert } });
  // Not trusted: a bad signature, someone else's topic, SignatureVersion 1, or a certificate from another region.
  const good = fx.signed(cert.key, { Message: fx.bounce('bounce@example.com') });
  assert.strictEqual((await post({ ...good, Signature: Buffer.from('nope').toString('base64') })).status, 403);
  assert.strictEqual((await post(fx.signed(cert.key, { Message: fx.bounce('bounce@example.com'), TopicArn: 'arn:aws:sns:us-east-1:999999999999:other' }))).status, 403);
  assert.strictEqual((await post(fx.signed(cert.key, { Message: fx.bounce('bounce@example.com') }, { version: '1' }))).status, 403);
  assert.strictEqual((await post(fx.signed(cert.key, { Message: fx.bounce('bounce@example.com'), SigningCertURL: 'https://sns.eu-west-1.amazonaws.com/x.pem' }))).status, 403);
  assert.strictEqual((await q(`select count(*)::int as n from app.email_suppressions`))[0].n, 0, 'nothing trusted, nothing kept');
  // Trusted: kept as a keyed fingerprint, never the address.
  const ok = await post(good);
  assert.deepStrictEqual([ok.status, ok.json.new], [200, 1]);
  assert.ok(!JSON.stringify(await q(`select * from app.email_suppressions`)).includes('example.com'));
  assert.strictEqual((await post(fx.signed(cert.key, { Message: fx.complaint('Complainer@Example.com ') }))).json.new, 1);
  // A temporary bounce is not a reason to stop.
  assert.strictEqual((await post(fx.signed(cert.key, { Message: fx.bounce('soft@example.com', 'Transient') }))).json.suppressed, 0);
  // The sign-in sender skips them (the reply on /join is the same either way); everyone else still gets their link.
  const sent = [];
  const ses = { name: 'ses', async send(m) { sent.push(m.to); return { ok: true, id: 'x' }; } };
  const send = signinSender({ ...cfg, transport: ses }, { run, keys: KEYS });
  await send('bounce@example.com', 'https://dayonegreat.com/auth/email/continue#t=x');
  await send('complainer@example.com', 'https://dayonegreat.com/auth/email/continue#t=y');
  await send('fine@example.com', 'https://dayonegreat.com/auth/email/continue#t=z');
  assert.deepStrictEqual(sent, ['fine@example.com']);
  // Without SES there is no sign-in sender at all (the log transport would swallow the link).
  assert.strictEqual(signinSender(cfg, { run, keys: KEYS }), null);
  // Subscribing: only our topic's own SNS address is visited, with a time limit.
  const visited = [];
  const conf = fx.signed(cert.key, { Type: 'SubscriptionConfirmation', Token: 't', Message: 'confirm', SubscribeURL: 'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=t' });
  const r = await napi('POST', 'sns', { contentType: 'text/plain', body: JSON.stringify(conf), deps: { getCert, confirm: async (u) => visited.push(u) } });
  assert.deepStrictEqual([r.status, visited.length], [200, 1]);
  const elsewhere = fx.signed(cert.key, { Type: 'SubscriptionConfirmation', Token: 't', Message: 'confirm', SubscribeURL: 'https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription&Token=t' });
  assert.strictEqual((await napi('POST', 'sns', { contentType: 'text/plain', body: JSON.stringify(elsewhere), deps: { getCert, confirm: async (u) => visited.push(u) } })).status, 403);
  assert.strictEqual(visited.length, 1);
  assert.match(fs.readFileSync(path.join(root, 'api', 'notify.js'), 'utf8'), /signal: AbortSignal\.timeout\(SUBSCRIBE_TIMEOUT_MS\)/);
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
    const a1 = await agentOf(owner, 'Fast one', { act: true });
    const a2 = await agentOf(owner, 'Drafter');
    for (let i = 0; i < 11; i++) await say(a1, 'flood ' + i);
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
    assert.match(notice.body, /you can appeal/);
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

test('N10, the copier rule: repeating another owner\'s live post brakes the copier, never the first author, and taken-down posts count for nothing', async () => {
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
    // Front-running (the review's probe): someone posts the text an honest owner is about to post, then has it taken
    // down. Copies count only against another owner's earlier post that is still live, so the honest owner isn't paused.
    const attacker = await member(2, 'Front runner');
    const shill = await agentOf(attacker, 'Shill', { act: true });
    const forecast = 'Tomorrow will be sunny with light winds in the bay area, highs near seventy.';
    for (let i = 0; i < 5; i++) {
      const r = await say(shill, forecast + ' #' + i);
      await run(aaron.ctx, (t) => review.decide(t, { post: r.posted.id, decision: 'remove' }));
    }
    const honest = await member(2, 'Weather bot owner');
    const bot = await agentOf(honest, 'Weather', { act: true });
    for (let i = 0; i < 5; i++) await say(bot, forecast + ' #' + i);
    await timers();
    assert.strictEqual((await q(`select count(*)::int as n from app.containments where member_id = '${honest.id}'`))[0].n, 0, 'removed posts count for nothing');
    // An owner repeating their own text isn't copying anyone (their volume still counts against the hard limit).
    const self = await member(2, 'Self repeater');
    const loop = await agentOf(self, 'Loop', { act: true });
    for (let i = 0; i < 6; i++) await say(loop, 'my slogan');
    await timers();
    assert.strictEqual((await q(`select count(*)::int as n from app.containments where member_id = '${self.id}'`))[0].n, 0);
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

test('N11: the cron route runs the timers, JEVs\'s deletion-review timer and mark sweep included, only with the right secret', async () => {
  const cron = require('../api/cron.js');
  const call = async (h) => { const r = res(); await cron.handle({ method: 'GET', headers: { authorization: h } }, r, run, cfg); return { status: r.statusCode, json: JSON.parse(r.body) }; };
  assert.strictEqual((await call('Bearer wrong')).status, 401);
  const ok = await call('Bearer ' + SECRET);
  assert.strictEqual(ok.status, 200, JSON.stringify(ok.json));
  for (const k of ['lifted', 'contained', 'deletion_reviews_disabled', 'marks_swept']) assert.ok(k in ok.json.timers, k);
  assert.ok(!('email' in ok.json), 'nothing is emailed');
  assert.ok(!JSON.stringify(ok.json).includes('@'), 'no addresses in what it reports');
});

test('F8: deleting an account deletes its notices, its alerts to Aaron and its pauses', async () => {
  await asOwner('update app.watch_settings set hard_limit_per_hour = 10');
  let gone;
  try {
    gone = await member(2, 'Leaving for good');
    const ag = await agentOf(gone, 'Last', { act: true });
    for (let i = 0; i < 11; i++) await say(ag, 'last words ' + i);
    await timers();
  } finally { await asOwner(QUIET_WATCH); }
  const counts = async () => (await q(`select (select count(*) from app.notices where member_id = '${gone.id}' or subject_id = '${gone.id}')::int as notices,
    (select count(*) from app.containments where member_id = '${gone.id}')::int as paused`))[0];
  const before = await counts();
  assert.ok(before.notices > 0 && before.paused === 1, JSON.stringify(before));
  const out = await run({ ...gone.ctx, fresh: true }, (t) => store.deleteAccount(t));
  assert.ok(!out.refused, JSON.stringify(out));
  assert.deepStrictEqual({ ...(await counts()) }, { notices: 0, paused: 0 });
});

// ---- JEVs (PR 12) speaks through the inbox (PR 13 on top of PR 12) ----
const jevs = require('../db/jevs');
const posts = require('../db/posts');
const setMode = (m) => asOwner(`update app.jevs_settings set value = '${m}' where key = 'mode'`);
const throwaway = (who) => run(who.ctx, (t) => jevs.mark(t, { kind: 'disposable', keyHash: c.sha256hex('jevs disposable') }));
const owner2Cookie = (who) => who.cookie;
async function feedApi(method, cookie, query = {}, json) {
  const r = res();
  const headers = { host: 'dayonegreat.com', cookie };
  if (method === 'POST') { headers.origin = ORIGIN; headers['content-type'] = 'application/json'; }
  await require('../api/feed.js').handle({ method, url: '/api/feed', headers, query, body: json ? JSON.stringify(json) : undefined }, r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
const noticesOf = (memberId) => q(`select kind, title, body, link, subject_kind, subject_id from app.notices where member_id ${memberId === null ? 'is null' : "= '" + memberId + "'"} order by created_at, id`);

test('JEVs: a challenge reaches its owner\'s inbox in the same transaction and is marked delivered; one a fresh sign-in already answered needs none', async () => {
  await setMode('enforce');
  try {
    const o = await member(2, 'Challenged owner');
    await throwaway(o);
    // An hour-old session: a new agent waits for the owner to sign in again.
    await q(`update app.sessions set created_at = now() - interval '1 hour' where member_id = '${o.id}'`);
    const made = await agentsApi('POST', '', o, { name: 'Bot' });
    assert.strictEqual(made.status, 403);
    const [ch] = await q(`select delivered_at from app.jevs_challenges where id = '${made.json.challenge}'`);
    assert.ok(ch.delivered_at, 'delivered_at is filled when the notice is written');
    const mine = (await noticesOf(o.id)).filter((n) => n.kind === 'challenge');
    assert.strictEqual(mine.length, 1);
    assert.deepStrictEqual([mine[0].title, mine[0].link, mine[0].subject_kind, mine[0].subject_id],
      ['Please confirm making a new agent', '/join?return_to=%2Fagents', 'challenge', made.json.challenge]);
    assert.match(mine[0].body, /Sign in, then do it once more/);
    assert.ok((await inbox(o)).notices.some((n) => n.kind === 'challenge'), 'it shows in the inbox on /account');
    // Signed in again: confirmed at once, so nothing to tell them, and the earlier request is answered.
    await q(`update app.sessions set created_at = now() where member_id = '${o.id}'`);
    assert.strictEqual((await agentsApi('POST', '', o, { name: 'Bot' })).status, 201);
    const [fresh] = await q(`select status, delivered_at from app.jevs_challenges where owner_id = '${o.id}' order by created_at desc limit 1`);
    assert.deepStrictEqual(fresh, { status: 'confirmed', delivered_at: null });
    assert.strictEqual((await noticesOf(o.id)).filter((n) => n.kind === 'challenge').length, 1);
    // A post's challenge carries its ID, so the owner can answer it on the notice.
    const body = 'Write to me about the meetup next week at deals@example.com and I will send the details';
    const p = await run(o.ctx, async (t) => { const r = await posts.create(t, { body }); r.jevs = await jevs.check(t, { action: 'post.create', subject: r.id, body }); return r; });
    assert.strictEqual(p.jevs.effect, 'challenge');
    const [pn] = (await noticesOf(o.id)).filter((n) => n.subject_id === p.jevs.challenge);
    assert.deepStrictEqual([pn.title, pn.link, pn.subject_kind], ['A post is waiting for you to confirm it', null, 'challenge']);
    // The owner answers it on the notice (account.js): confirming puts the held post live.
    const held = (await feedApi('GET', owner2Cookie(o), { challenges: '1' })).json.challenges.find((x) => x.id === p.jevs.challenge);
    assert.deepStrictEqual([held.subject.kind, held.body], ['post', body]);
    const yes = await feedApi('POST', owner2Cookie(o), {}, { challenge: p.jevs.challenge, answer: 'confirm' });
    assert.strictEqual(yes.status, 200, JSON.stringify(yes.json));
    assert.strictEqual((await q(`select status from app.posts where id = '${p.id}'`))[0].status, 'live');
  } finally { await setMode('shadow'); }
});

test('JEVs: each high-risk item that reaches Aaron alerts his inbox, about the member, and the alert goes with the account', async () => {
  await setMode('enforce');
  try {
    const before = (await noticesOf(null)).length;
    const o = await member(2, 'High risk owner');
    await throwaway(o);
    // A throwaway address on a new account, with high_any lowered for this test: a new key is held for Aaron.
    const [ag] = await run(o.ctx, (t) => t`insert into app.agents (name) values ('Keyed') returning id`);
    await asOwner(`update app.jevs_settings set value = '60' where key = 'high_any'`);
    const d = await run({ ...o.ctx, fresh: true }, (t) => jevs.check(t, { action: 'agent.key', subject: ag.id }));
    assert.deepStrictEqual([d.level, d.effect, d.applied], ['high', 'hold', true]);
    const alerts = (await noticesOf(null)).slice(before);
    assert.strictEqual(alerts.length, 1);
    assert.deepStrictEqual([alerts[0].kind, alerts[0].title, alerts[0].link, alerts[0].subject_kind, alerts[0].subject_id],
      ['alert', 'JEVs held a step for you', '/controls', 'member', o.id]);
    assert.ok(!/@|J0|J1/.test(alerts[0].body), 'no words or question IDs in the alert');
    // Low and medium risk, and anything shadow mode only records, alert nobody.
    await setMode('shadow');
    await run({ ...o.ctx, fresh: true }, (t) => jevs.check(t, { action: 'agent.key', subject: ag.id }));
    assert.strictEqual((await noticesOf(null)).length, before + 1);
    // Deleting the account takes the alert about them with it.
    await run({ ...o.ctx, fresh: true }, (t) => store.deleteAccount(t));
    assert.strictEqual((await q(`select count(*)::int as n from app.notices where subject_id = '${o.id}' or member_id = '${o.id}'`))[0].n, 0);
  } finally {
    await asOwner(`update app.jevs_settings set value = '80' where key = 'high_any'`);
    await setMode('shadow');
  }
});

test('JEVs: a deletion review tells the member their account was flagged and alerts Aaron; the timers disable it after 24 hours and sweep old marks', async () => {
  await setMode('enforce');
  try {
    const o = await member(0, 'Leaving owner');
    await throwaway(o);
    const d = await run({ ...o.ctx, fresh: true }, (t) => jevs.check(t, { action: 'account.delete' }));
    assert.deepStrictEqual([d.level, d.effect], ['high', 'hold']);
    const [r] = await q(`select id from app.deletion_reviews where member_id = '${o.id}'`);
    const told = (await noticesOf(o.id)).find((n) => n.kind === 'account_flagged');
    assert.deepStrictEqual([told.title, told.link], ['Your account was flagged as high risk', '/account']);
    assert.match(told.body, /hasn't been deleted\. Aaron will review it and decide\. If he hasn't decided within 24 hours, your account will be disabled/);
    const alert = (await noticesOf(null)).find((n) => n.title === 'A deletion needs your decision' && n.subject_id === o.id);
    assert.ok(alert && alert.link === '/controls');
    // The cron's timers: nothing before 24 hours; after, the account is disabled (not deleted), and the timers say so.
    let out = await timers();
    assert.strictEqual(out.deletion_reviews_disabled, 0);
    await rewrite('deletion_reviews', 'deletion_reviews_guard', `update app.deletion_reviews set created_at = now() - interval '25 hours' where id = '${r.id}'`);
    await run(o.ctx, (t) => jevs.mark(t, { kind: 'net', keyHash: c.sha256hex('an old network') }));
    await q(`update app.jevs_marks set created_at = now() - interval '31 days' where member_id = '${o.id}' and kind = 'net'`);
    out = await timers();
    assert.strictEqual(out.deletion_reviews_disabled, 1);
    assert.ok(out.marks_swept >= 1, 'old marks are swept by the same run');
    assert.strictEqual((await q(`select status from app.members where id = '${o.id}'`))[0].status, 'disabled');
    assert.strictEqual((await timers()).deletion_reviews_disabled, 0, 'never twice');
  } finally { await setMode('shadow'); }
});
