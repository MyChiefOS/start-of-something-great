// Release 2, PR 12: JEVs, the automated checking layer (Aaron's definition, Oct 16, 2026), against a real Postgres.
// Every behaviour in the build list has a test here: the questions, publishing questions but not thresholds, decisions,
// shadow and enforce modes (and F6's single switch), the fail-safe, auto-hide and appeals, automatic level 2, the
// sign-up bot checks and the regional gate. The fleet of test agents is in test/fleet.test.js.
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
const jevs = require('../db/jevs');
const region = require('../signin/region');
const { make, LIMITS, MIN_FILL_MS } = require('../signin/flow');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };
const MIGRATION = fs.readFileSync(path.join(root, 'db', 'migrations', '010_jevs.sql'), 'utf8');

// ---- Without a database: the questions, the lists, the text checks, the regional list ----

test('JEVs questions: stable IDs J01 to J14, each with a public title and description, scoring 0 to 100', () => {
  assert.deepStrictEqual(jevs.QUESTIONS.map((q) => q.id), Array.from({ length: 14 }, (_, i) => 'J' + String(i + 1).padStart(2, '0')));
  for (const q of jevs.QUESTIONS) {
    assert.ok(q.title.length >= 4 && q.title.length <= 60, q.id + ' title');
    assert.ok(q.description.length >= 40, q.id + ' needs a plain description');
    assert.strictEqual(typeof q.score, 'function');
  }
  // Every action asks only questions that exist, and the account questions are exactly the ones the database requires
  // before it promotes anyone (010: p_scores ?& array[...]).
  for (const [action, ids] of Object.entries(jevs.ASKS)) for (const id of ids) assert.ok(jevs.QUESTIONS.find((q) => q.id === id), action + ' asks ' + id);
  assert.deepStrictEqual(Object.keys(jevs.ASKS).sort(), Object.keys(jevs.ACTIONS).sort(), 'every action has its questions');
  const sqlList = MIGRATION.match(/p_scores \?& array\[([^\]]+)\]/)[1].match(/J\d\d/g);
  assert.deepStrictEqual(sqlList, jevs.ACCOUNT);
  assert.ok(jevs.ACCOUNT.every((id) => jevs.ASKS['account.check'].includes(id)));
});

test('JEVs scoring is deterministic: the same signals give the same scores, always within 0 to 100', () => {
  let seed = 3;
  const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  for (let i = 0; i < 300; i++) {
    const s = { account: true, age_hours: Math.floor(rnd() * 900), best_identity: Math.floor(rnd() * 4) - 1, providers: Math.floor(rnd() * 3), admin: false,
      disposable: rnd() < 0.2, posts_1h: Math.floor(rnd() * 90), posts_before: Math.floor(rnd() * 400), net_members_24h: Math.floor(rnd() * 15),
      domain_members_7d: Math.floor(rnd() * 15), net_signups_1h: Math.floor(rnd() * 30), site_signups_1h: Math.floor(rnd() * 200), site_signups_7d: Math.floor(rnd() * 999),
      owner_agents_24h: Math.floor(rnd() * 40), net_agents_24h: Math.floor(rnd() * 40), new_domains: Math.floor(rnd() * 6), links: Math.floor(rnd() * 9),
      mask_hits: Math.floor(rnd() * 5), copies: Math.floor(rnd() * 7), upheld_90d: Math.floor(rnd() * 4), braked: rnd() < 0.1, banned_links: Math.floor(rnd() * 2),
      credible_reports: Math.floor(rnd() * 5) };
    for (const action of Object.keys(jevs.ASKS)) {
      const a = jevs.score(action, s, { country: rnd() < 0.5 ? 'US' : null });
      const b = jevs.score(action, JSON.parse(JSON.stringify(s)), { country: a.J13 === 10 ? null : 'US' });
      assert.deepStrictEqual(a, b);
      for (const v of Object.values(a)) assert.ok(Number.isInteger(v) && v >= 0 && v <= 100);
    }
  }
  // A few fixed points, so a change to a question's scoring is a visible change to this test.
  const s = (o) => jevs.score('post.create', { account: true, age_hours: 500, best_identity: 2, ...o }, { country: 'US' });
  assert.deepStrictEqual(s({}), { J01: 0, J02: 0, J03: 0, J04: 0, J05: 0, J06: 0, J10: 0, J13: 0, J07: 0, J08: 0, J09: 0, J12: 0 });
  assert.strictEqual(s({ age_hours: 0 }).J01, 25);
  assert.strictEqual(s({ new_domains: 4, links: 4 }).J07, 100);
  assert.strictEqual(s({ mask_hits: 3 }).J08, 80);
  assert.strictEqual(s({ copies: 2 }).J09, 60);
  assert.strictEqual(s({ posts_1h: 13 }).J04, 70);
  assert.strictEqual(s({ posts_1h: 60 }).J04, 85);
  assert.strictEqual(s({ owner_agents_24h: 500 }).J06, 70, 'agents per owner alone never holds anyone: there is no cap');
  assert.strictEqual(jevs.score('agent.key', { account: true, age_hours: 500, best_identity: 1, providers: 1 }, { country: 'DE' }).J13, 40);
  assert.strictEqual(jevs.score('post.reported', { account: true, credible_reports: 3 }).J14, 100);
  assert.strictEqual(s({ reply_depth: undefined }).J12, 0, 'reply depth is a hook: 0 until replies exist');
});

test('JEVs publishes its questions, not its thresholds: llms.txt and db/README list every question; the code holds no threshold', () => {
  const llms = fs.readFileSync(path.join(root, 'llms.txt'), 'utf8');
  const readme = fs.readFileSync(path.join(root, 'db', 'README.md'), 'utf8');
  for (const q of jevs.publicQuestions()) {
    assert.ok(llms.includes(q.id + ' ' + q.title), 'llms.txt lists ' + q.id + ' ' + q.title);
    assert.ok(readme.includes('**' + q.id + ' ' + q.title + '**'), 'db/README.md lists ' + q.id + ' ' + q.title);
    assert.ok(readme.includes(q.description), 'db/README.md has ' + q.id + '\'s description word for word');
  }
  const code = fs.readFileSync(path.join(root, 'db', 'jevs.js'), 'utf8');
  for (const k of ['medium_any', 'high_any', 'medium_total', 'high_total', 'pass_max', 'promote_min_age_hours', 'credible_reporter_age_hours']) {
    assert.ok(!code.includes(k), 'db/jevs.js never names the threshold ' + k);
    assert.ok(MIGRATION.includes("('" + k + "'"), 'the migration seeds ' + k);
  }
  assert.match(MIGRATION, /\('mode', 'shadow'\)/, 'JEVs starts in shadow mode');
});

test('JEVs reads posts: link domains (lower case, no www. or port), contact details masking hides, and near-copies', () => {
  assert.deepStrictEqual(jevs.links('see https://www.Example.com/x, http://spam.biz:8080/y and www.third.net/z; not node.js or a.b'), ['example.com', 'spam.biz', 'third.net']);
  const a = jevs.analyze('two links https://one.example and https://one.example/again');
  assert.strictEqual(a.links, 2);
  assert.deepStrictEqual(a.domains, ['one.example']);
  assert.strictEqual(a.domainHashes.length, 1);
  assert.strictEqual(jevs.maskHits('write to jane@example.com or call +1 415 555 0100'), 2);
  assert.strictEqual(jevs.maskHits('nothing to hide here, and [email hidden] already written out'), 0);
  const text = 'We are planning a small community garden on the corner lot next to the library this spring and would love volunteers to help with planting.';
  const near = text.replace('volunteers', 'helpers');
  const other = 'Completely different words about databases, row level security, and how a pooled connection keeps nothing between requests in our design.';
  assert.ok(jevs.hamming(jevs.simhash(text), jevs.simhash(near)) <= jevs.NEAR_BITS, 'one word changed is a near-copy');
  assert.ok(jevs.hamming(jevs.simhash(text), jevs.simhash(other)) > jevs.NEAR_BITS + 4, 'unrelated text is far away');
  assert.strictEqual(jevs.simhash('too short to print'), null);
  assert.match(MIGRATION, new RegExp('bit_count\\(int8send\\(r\\.simhash # p_simhash\\)\\) <= ' + jevs.NEAR_BITS + '\\)'), 'the database uses the same distance');
});

test('JEVs lists: disposable domains match with their subdomains; common domains leave no mark', () => {
  assert.ok(jevs.DISPOSABLE.size >= 40 && jevs.COMMON.size >= 30);
  assert.ok(jevs.onList(jevs.DISPOSABLE, 'mailinator.com') && jevs.onList(jevs.DISPOSABLE, 'x.y.mailinator.com'));
  assert.ok(!jevs.onList(jevs.DISPOSABLE, 'notmailinator.com') && !jevs.onList(jevs.DISPOSABLE, 'com'));
  const key = crypto.randomBytes(32);
  assert.deepStrictEqual(jevs.emailMarks('a@gmail.com', key), [], 'no mark for an address on a domain everyone uses');
  const m = jevs.emailMarks('Someone@Sub.Mailinator.com', key);
  assert.deepStrictEqual(m.map((x) => x.kind), ['email_domain', 'disposable']);
  assert.ok(m.every((x) => /^[0-9a-f]{64}$/.test(x.keyHash)) && !JSON.stringify(m).includes('mailinator'), 'only hashes, never the domain');
  assert.notStrictEqual(jevs.emailMarks('a@acme.example', key)[0].keyHash, jevs.emailMarks('a@acme.example', crypto.randomBytes(32))[0].keyHash, 'keyed');
});

test('the regional gate\'s list: the 27 EU states and their own-coded regions, the EEA, the UK and Switzerland', () => {
  assert.strictEqual(region.EU.length, 27);
  assert.deepStrictEqual([...region.EU].sort(), ['AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GR', 'HR', 'HU', 'IE', 'IT', 'LT', 'LU', 'LV',
    'MT', 'NL', 'PL', 'PT', 'RO', 'SE', 'SI', 'SK']);
  assert.deepStrictEqual([...region.EEA].sort(), ['IS', 'LI', 'NO']);
  assert.deepStrictEqual(region.UK, ['GB', 'UK']);
  assert.deepStrictEqual(region.SWITZERLAND, ['CH']);
  assert.deepStrictEqual([...region.EU_REGIONS].sort(), ['AX', 'GF', 'GP', 'MF', 'MQ', 'RE', 'YT']);
  assert.strictEqual(new Set(region.DECLINED).size, region.DECLINED.length);
  const at = (h) => ({ headers: { 'x-vercel-ip-country': h } });
  for (const cc of ['FR', 'de', ' gb ', 'CH', 'NO', 'IS', 'LI', 'RE', 'GR', 'IE']) assert.ok(region.declined(at(cc)), cc + ' is declined');
  for (const cc of ['US', 'CA', 'IN', 'JP', 'BR', 'AU', 'TR', 'UA', 'RS', 'AL', 'GG', 'JE', 'IM', 'GI']) assert.strictEqual(region.declined(at(cc)), null, cc + ' is open');
  assert.strictEqual(region.declined({ headers: {} }), null, 'no header: not declined (JEVs scores the unknown region instead)');
  assert.strictEqual(region.declined(at('<script>')), null);
  assert.match(region.page(), /We haven’t kept anything about you/);
});

// ---- Against a database ----

if (!SERVER) {
  if (process.env.CI) test('JEVs tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('JEVs against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_jevs_test_' + crypto.randomBytes(4).toString('hex');
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
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  aaron = await member({ level: 2, name: 'Aaron' });
  await asOwner(`update app.members set is_admin = true where id = '${aaron.id}'`);
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

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
// A member signed in with a session. provider: github (level 1), x (level 2 when level 2), email (level 0).
// ageDays makes the account that old; stale makes the session an hour old (not a fresh sign-in).
async function member({ level = 2, name = 'Member', provider, ageDays = 0, stale = false } = {}) {
  const token = c.token(32);
  const prov = provider || (level === 2 ? 'x' : level === 1 ? 'github' : 'email');
  const fp = c.sha256hex(crypto.randomUUID());
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: prov, fingerprints: [fp], keyVersion: 1,
    level, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await q(`update app.members set display_name = '${name}' where id = '${out.memberId}'`);
  if (ageDays) await q(`update app.members set created_at = now() - interval '${ageDays} days' where id = '${out.memberId}'`);
  if (stale) await q(`update app.sessions set created_at = now() - interval '1 hour' where token_hash = '${c.sha256hex(token)}'`);
  return { id: out.memberId, fp, provider: prov, level, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId } };
}
function httpReq(method, url, { cookie = '', json, key, query = {}, ip = '203.0.113.60', country = 'US' } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': ip };
  if (country) headers['x-vercel-ip-country'] = country;
  if (method === 'POST') headers.origin = ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url, headers, query, body: json === undefined ? undefined : JSON.stringify(json) };
}
async function feed(method, opts) {
  const r = res();
  await require('../api/feed.js').handle(httpReq(method, '/api/feed', opts), r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
async function agentsApi(method, route, opts) {
  const r = res();
  await require('../api/agents.js').handle(httpReq(method, '/api/agents/' + route, { ...opts, query: { route } }), r, run, CFG);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
const say = (who, body, opts = {}) => feed('POST', { cookie: who.cookie, json: { body }, ...opts });
const agentSay = (key, body) => feed('POST', { key, json: { body } });
const statusOf = async (id) => (await q(`select status from app.posts where id = '${id}'`))[0].status;
const decisionsFor = (subject) => q(`select * from app.jevs_decisions where subject_id = '${subject}' order by created_at, id`);
const links = (n) => 'new sites ' + Array.from({ length: n }, (_, i) => 'https://s' + i + '-' + crypto.randomBytes(3).toString('hex') + '.example').join(' ');
const counts = async () => Object.fromEntries((await q(`select c.relname as t from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'app' and c.relkind = 'r' order by 1`)).map((r) => r.t).map((t) => [t, null]));
async function tableCounts() {
  const out = await counts();
  for (const t of Object.keys(out)) out[t] = (await q(`select count(*)::int as n from app.${t}`))[0].n;
  return out;
}

test('the database passes the coverage check with JEVs, and matches the reviewed snapshot (S1, S7, S8, G3)', async () => {
  const snapshot = fs.readFileSync(path.join(root, 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
});

test('thresholds: only the database owner changes them; the site sees only the mode (Aaron sees all); every change is recorded', async () => {
  const m = await member({ level: 1, name: 'Curious' });
  assert.deepStrictEqual((await run(m.ctx, (t) => t`select key, value from app.jevs_settings`)).map((r) => r.key), ['mode'], 'a member sees only the mode');
  assert.deepStrictEqual((await run({ actor: 'anon' }, (t) => t`select key from app.jevs_settings`)).map((r) => r.key), ['mode']);
  assert.strictEqual((await run(aaron.ctx, (t) => t`select key from app.jevs_settings`)).length, 9, 'Aaron sees every setting on the site');
  for (const ctx of [m.ctx, aaron.ctx, { actor: 'system' }]) {
    await assert.rejects(run(ctx, (t) => t`update app.jevs_settings set value = '1' where key = 'high_any'`), /permission denied/);
    await assert.rejects(run(ctx, (t) => t`insert into app.jevs_settings (key, value) values ('pass_max', '99')`), /permission denied/);
  }
  await assert.rejects(asOwner(`update app.jevs_settings set value = 'loose' where key = 'mode'`), /shadow or enforce/);
  await assert.rejects(asOwner(`update app.jevs_settings set value = '-1' where key = 'high_any'`), /whole number/);
  await assert.rejects(asOwner(`update app.jevs_settings set key = 'pass_max' where key = 'high_any'`), /keeps its name|duplicate/);
  await asOwner(`update app.jevs_settings set value = '81' where key = 'high_any'`);
  const [rec] = await q(`select actor_kind, detail from app.audit_log where action = 'jevs.setting' order by at desc limit 1`);
  assert.deepStrictEqual(rec.detail, { key: 'high_any', from: '80', to: '81' });
  await asOwner(`update app.jevs_settings set value = '80' where key = 'high_any'`);
});

test('shadow mode (the default): JEVs scores and records every post but holds nothing, and first-post review keeps running (F6)', async () => {
  await setMode('shadow');
  const owner = await member({ level: 2, name: 'Shadow poster' });
  const bad = await say(owner, links(4) + ' and write to me at shadow@example.com');
  assert.strictEqual(bad.status, 201, 'shadow mode never stops a post');
  assert.strictEqual(await statusOf(bad.json.id), 'live');
  const [d] = await decisionsFor(bad.json.id);
  assert.strictEqual(d.action, 'post.create');
  assert.strictEqual(d.level, 'high');
  assert.strictEqual(d.effect, 'hold', 'what enforce mode would have done');
  assert.strictEqual(d.applied, false);
  assert.strictEqual(d.scores.J07, 100);
  // The record holds question IDs and scores, never the words or an address.
  assert.ok(Object.keys(d.scores).every((k) => /^J\d\d$/.test(k)));
  assert.ok(!JSON.stringify(d).includes('example') && !JSON.stringify(d).includes('203.0.113'));
  // A level 1 member's first post still waits for review in shadow mode, whatever JEVs says.
  const newcomer = await member({ level: 1, name: 'Newcomer' });
  const first = await say(newcomer, 'Hello everyone, glad to be here.');
  assert.strictEqual(first.status, 201);
  assert.strictEqual(await statusOf(first.json.id), 'waiting');
  assert.strictEqual((await decisionsFor(first.json.id))[0].level, 'low');
  const queue = await run(aaron.ctx, (t) => review.queue(t, {}));
  assert.ok(queue.items.find((i) => i.id === first.json.id && i.firstPosts));
});

test('enforce mode is one switch: first-post review stops, medium risk waits for its owner, high risk is held for Aaron', async () => {
  await setMode('enforce');
  try {
    const newcomer = await member({ level: 1, name: 'Trusted by default' });
    const first = await say(newcomer, 'My first post goes live straight away now.');
    assert.strictEqual(first.status, 201);
    assert.strictEqual(await statusOf(first.json.id), 'live', 'first-post review is off once JEVs enforces');
    // Medium: two links to new sites (50). Held, and a challenge waits for the member, tied to this one post.
    const m = await member({ level: 2, name: 'Linker' });
    const medium = await say(m, 'Two places worth a look: ' + links(2));
    assert.strictEqual(medium.status, 202);
    assert.ok(medium.json.challenge);
    assert.strictEqual(await statusOf(medium.json.id), 'waiting');
    const feedNow = await feed('GET', { query: { lane: 'people', limit: '50' } });
    assert.ok(!feedNow.json.posts.some((p) => p.id === medium.json.id), 'a held post is never public');
    const mine = await feed('GET', { cookie: m.cookie, query: { challenges: '1' } });
    assert.deepStrictEqual(mine.json.challenges.map((x) => x.id), [medium.json.challenge]);
    assert.strictEqual(mine.json.challenges[0].subject.id, medium.json.id);
    // Someone else can't answer it.
    const other = await member({ level: 2, name: 'Not the owner' });
    assert.strictEqual((await feed('POST', { cookie: other.cookie, json: { challenge: medium.json.challenge, answer: 'confirm' } })).status, 404);
    // The owner confirms: live. Answering twice changes nothing.
    const ok = await feed('POST', { cookie: m.cookie, json: { challenge: medium.json.challenge, answer: 'confirm' } });
    assert.strictEqual(ok.status, 200);
    assert.strictEqual(await statusOf(medium.json.id), 'live');
    assert.strictEqual((await feed('POST', { cookie: m.cookie, json: { challenge: medium.json.challenge, answer: 'decline' } })).status, 409);
    // Declining withdraws it.
    const again = await say(m, 'Two more: ' + links(2));
    assert.strictEqual((await feed('POST', { cookie: m.cookie, json: { challenge: again.json.challenge, answer: 'decline' } })).json.status, 'declined');
    assert.strictEqual(await statusOf(again.json.id), 'removed');
    // An expired challenge can't be answered.
    const late = await say(m, 'Late ones: ' + links(2));
    // (Expiry is set by the database; a superuser moves it back for the test, and the guard allows nothing else.)
    await q(`alter table app.jevs_challenges disable trigger jevs_challenges_guard`);
    await q(`update app.jevs_challenges set expires_at = now() - interval '1 second' where id = '${late.json.challenge}'`);
    await q(`alter table app.jevs_challenges enable always trigger jevs_challenges_guard`);
    assert.strictEqual((await feed('POST', { cookie: m.cookie, json: { challenge: late.json.challenge, answer: 'confirm' } })).status, 410);
    // High: four links to new sites and contact details. Held at once, in Aaron's queue with JEVs's flag.
    const high = await say(m, links(4) + ' or mail me at linker@example.com');
    assert.strictEqual(high.status, 202);
    assert.strictEqual(high.json.challenge, undefined, 'high risk is not the owner\'s to release');
    assert.strictEqual(await statusOf(high.json.id), 'waiting');
    const queue = await run(aaron.ctx, (t) => review.queue(t, {}));
    const item = queue.items.find((i) => i.id === high.json.id);
    assert.deepStrictEqual(item.classifiers, ['jevs']);
    assert.strictEqual(item.firstPosts, false);
    assert.strictEqual((await run(aaron.ctx, (t) => review.decide(t, { post: high.json.id, decision: 'approve' }))).status, 'live', 'Aaron can release it');
    // The record: held by JEVs, released by Aaron.
    const log = await q(`select action from app.audit_log where subject_id = '${high.json.id}' order by at, id`);
    assert.deepStrictEqual(log.map((r) => r.action), ['jevs.hold', 'review.flag', 'post.approve', 'review.close']);
    // Aaron himself is never held (he runs the controls).
    const mine2 = await feed('POST', { cookie: aaron.cookie, json: { body: links(4) } });
    assert.strictEqual(mine2.status, 201);
  } finally {
    await setMode('shadow');
  }
});

test('enforce: an agent\'s risky post waits for its human owner, and the agent can never answer the challenge', async () => {
  await setMode('enforce');
  try {
    const owner = await member({ level: 2, name: 'Agent owner' });
    const made = await agentsApi('POST', '', { cookie: owner.cookie, json: { name: 'Linky' } });
    assert.strictEqual(made.status, 201);
    assert.strictEqual((await agentsApi('POST', 'rules', { cookie: owner.cookie, json: { agent: made.json.agent_id, post: 'act', reply: 'draft', report: 'draft', daily_cap: 50 } })).status, 201);
    const p = await agentSay(made.json.key, 'Have a look: ' + links(2));
    assert.strictEqual(p.status, 202);
    assert.strictEqual(p.json.challenge, undefined, 'the agent is never handed the challenge');
    const [ch] = (await feed('GET', { cookie: owner.cookie, query: { challenges: '1' } })).json.challenges;
    assert.strictEqual(ch.subject.id, p.json.id);
    // An agent can't answer, by any path: the API takes only {"body"} from a key, and the database refuses an agent.
    assert.strictEqual((await feed('POST', { key: made.json.key, json: { challenge: ch.id, answer: 'confirm' } })).status, 400);
    const asAgent = { actor: 'agent', memberId: owner.id, agentId: made.json.agent_id };
    assert.deepStrictEqual(await run(asAgent, (t) => jevs.answer(t, { challenge: ch.id, answer: 'confirm' })), { refused: 'not_found' });
    assert.strictEqual(await statusOf(p.json.id), 'waiting');
    assert.strictEqual((await feed('POST', { cookie: owner.cookie, json: { challenge: ch.id, answer: 'confirm' } })).status, 200);
    assert.strictEqual(await statusOf(p.json.id), 'live');
  } finally {
    await setMode('shadow');
  }
});

test('auto-hide: credible reports hide a post at once in enforce mode; Aaron can put it back; its author can appeal; shadow only records', async () => {
  const author = await member({ level: 2, name: 'Reported' });
  const reporters = [];
  for (let i = 0; i < 3; i++) reporters.push(await member({ level: 1, name: 'Old reporter ' + i, ageDays: 30 }));
  const fresh = [];
  for (let i = 0; i < 3; i++) fresh.push(await member({ level: 1, name: 'New reporter ' + i }));
  const report = (who, post) => feed('POST', { cookie: who.cookie, json: { report: post, reason: 'spam' } });

  // Shadow: three credible reports are recorded as "would hide", and the post stays up.
  await setMode('shadow');
  const p1 = await say(author, 'A perfectly ordinary post that some people dislike.');
  for (const r of reporters) assert.strictEqual((await report(r, p1.json.id)).status, 202);
  assert.strictEqual(await statusOf(p1.json.id), 'live');
  const last = (await decisionsFor(p1.json.id)).pop();
  assert.deepStrictEqual([last.action, last.level, last.effect, last.applied, last.scores.J14], ['post.reported', 'high', 'hide', false, 100]);

  await setMode('enforce');
  try {
    // Reports from brand-new accounts aren't credible: the post stays up (they still reach Aaron's queue, F7).
    const p2 = await say(author, 'Another ordinary post that new accounts gang up on.');
    for (const r of fresh) await report(r, p2.json.id);
    assert.strictEqual(await statusOf(p2.json.id), 'live');
    assert.strictEqual((await decisionsFor(p2.json.id)).pop().scores.J14, 0);
    // Credible reports: hidden at once, on the third.
    const p3 = await say(author, 'A post that three long-standing members report.');
    await report(reporters[0], p3.json.id);
    await report(reporters[1], p3.json.id);
    assert.strictEqual(await statusOf(p3.json.id), 'live', 'two credible reports are not enough');
    await report(reporters[2], p3.json.id);
    assert.strictEqual(await statusOf(p3.json.id), 'removed', 'hidden at once');
    const pub = await feed('GET', { query: { lane: 'people', limit: '50' } });
    assert.ok(!pub.json.posts.some((p) => p.id === p3.json.id), 'gone from the public feed');
    // Its author appeals (only the author, only for a post JEVs held or hid); Aaron sees it in the queue.
    const stranger = await member({ level: 2, name: 'Stranger' });
    assert.strictEqual((await feed('POST', { cookie: stranger.cookie, json: { appeal: p3.json.id } })).status, 404);
    assert.strictEqual((await feed('POST', { cookie: author.cookie, json: { appeal: p2.json.id } })).status, 404, 'nothing to appeal');
    assert.strictEqual((await feed('POST', { cookie: author.cookie, json: { appeal: p3.json.id } })).status, 202);
    assert.strictEqual((await feed('POST', { cookie: author.cookie, json: { appeal: p3.json.id } })).status, 202, 'appealing twice changes nothing');
    const item = (await run(aaron.ctx, (t) => review.queue(t, {}))).items.find((i) => i.id === p3.json.id);
    assert.ok(item.appeals === 1 && item.classifiers.includes('jevs') && item.reports === 3);
    // Aaron reverses it: live again, everything closed.
    assert.strictEqual((await run(aaron.ctx, (t) => review.decide(t, { post: p3.json.id, decision: 'restore' }))).status, 'live');
    assert.strictEqual((await q(`select count(*)::int as n from app.review_flags where post_id = '${p3.json.id}' and resolved_at is null`))[0].n, 0);
    const log = (await q(`select action from app.audit_log where subject_id = '${p3.json.id}' order by at, id`)).map((r) => r.action);
    assert.ok(log.includes('jevs.hide') && log.indexOf('post.restore') > log.indexOf('jevs.hide'));
  } finally {
    await setMode('shadow');
  }
});

test('fail-safe: if scoring throws, a sensitive action is held and a post goes ahead, both recorded as errors (enforce); shadow holds nothing', async () => {
  const owner = await member({ level: 2, name: 'Unlucky' });
  const made = await agentsApi('POST', '', { cookie: owner.cookie, json: { name: 'Keyed' } });
  assert.strictEqual(made.status, 201);
  // Scoring breaks: the site can no longer read JEVs's signals.
  await q('revoke execute on function app.jevs_signals(text, uuid, text, text[], bigint) from dog_app');
  try {
    await setMode('enforce');
    const p = await say(owner, 'A low-impact post while scoring is broken.');
    assert.strictEqual(p.status, 201, 'a post goes ahead');
    assert.strictEqual(await statusOf(p.json.id), 'live');
    const [pd] = await decisionsFor(p.json.id);
    assert.deepStrictEqual([pd.error, pd.level, pd.effect], [true, 'low', 'none']);
    const key = await agentsApi('POST', 'key', { cookie: owner.cookie, json: { agent: made.json.agent_id } });
    assert.strictEqual(key.status, 403, 'a new key is held');
    assert.match(key.json.error, /held for review/);
    const [kd] = await q(`select * from app.jevs_decisions where action = 'agent.key' and agent_id = '${made.json.agent_id}' order by created_at desc limit 1`);
    assert.deepStrictEqual([kd.error, kd.level, kd.effect, kd.applied], [true, 'high', 'hold', true]);
    // The old key still works (the new one never happened).
    assert.strictEqual((await agentSay(made.json.key, 'still here')).status, 202);
    // Shadow mode never stops anything, even when scoring fails: the error is recorded and the key is made.
    await setMode('shadow');
    const key2 = await agentsApi('POST', 'key', { cookie: owner.cookie, json: { agent: made.json.agent_id } });
    assert.strictEqual(key2.status, 201);
    const [kd2] = await q(`select * from app.jevs_decisions where action = 'agent.key' and agent_id = '${made.json.agent_id}' order by created_at desc limit 1`);
    assert.deepStrictEqual([kd2.error, kd2.effect, kd2.applied], [true, 'hold', false]);
  } finally {
    await q('grant execute on function app.jevs_signals(text, uuid, text, text[], bigint) to dog_app');
    await setMode('shadow');
  }
});

test('sensitive actions at medium risk ask the owner to sign in again (the challenge), then go ahead; nothing caps agents', async () => {
  await setMode('enforce');
  try {
    const owner = await member({ level: 2, name: 'Busy owner' });
    // Ten agents already made today score J06 50 (medium), so the eleventh needs a fresh sign-in; this session is fresh,
    // so it goes ahead. (Four to nine score 25: low on their own.)
    const ids = [];
    for (let i = 0; i < 11; i++) {
      const r = await agentsApi('POST', '', { cookie: owner.cookie, json: { name: 'Helper ' + i } });
      assert.strictEqual(r.status, 201, 'agent ' + i + ': ' + JSON.stringify(r.json));
      ids.push(r.json.agent_id);
    }
    const confirmed = await q(`select status from app.jevs_challenges where owner_id = '${owner.id}' and action = 'agent.create'`);
    assert.ok(confirmed.length >= 1 && confirmed.every((x) => x.status === 'confirmed'), 'a fresh sign-in answers the challenge');
    // With an hour-old session, the same step waits: a pending challenge, and a request to sign in again.
    await q(`update app.sessions set created_at = now() - interval '1 hour' where member_id = '${owner.id}'`);
    const waiting = await agentsApi('POST', '', { cookie: owner.cookie, json: { name: 'Helper 11' } });
    assert.strictEqual(waiting.status, 403);
    assert.match(waiting.json.error, /sign in again/);
    assert.strictEqual(waiting.json.reauth, '/join?return_to=%2Fagents');
    const [pending] = await q(`select status, action from app.jevs_challenges where id = '${waiting.json.challenge}'`);
    assert.deepStrictEqual(pending, { status: 'pending', action: 'agent.create' });
    assert.strictEqual((await q(`select count(*)::int as n from app.agents where owner_id = '${owner.id}'`))[0].n, 11, 'the twelfth wasn\'t made');
  } finally {
    await setMode('shadow');
  }
});

test('automatic level 2: when every standard question passes and the account is old enough, JEVs promotes it, recorded with the question IDs', async () => {
  // Young: not yet. (Shadow mode: promotion still happens, since it stops nobody.)
  const young = await member({ level: 1, name: 'Young', ageDays: 3 });
  assert.strictEqual((await agentsApi('GET', '', { cookie: young.cookie })).json.can_own, false);
  // Old enough, signed in with GitHub, nothing risky: promoted the moment they open the agents page.
  const steady = await member({ level: 1, name: 'Steady', ageDays: 15 });
  const page = await agentsApi('GET', '', { cookie: steady.cookie });
  assert.strictEqual(page.json.can_own, true);
  const [row] = await q(`select trust_level, jevs_level2_at, level_set_by_admin from app.members where id = '${steady.id}'`);
  assert.strictEqual(row.trust_level, 2);
  assert.ok(row.jevs_level2_at);
  assert.strictEqual(row.level_set_by_admin, null, 'not a hand-set level');
  const [rec] = await q(`select actor_kind, actor_id, detail from app.audit_log where action = 'member.level_changed' and subject_id = '${steady.id}'`);
  assert.deepStrictEqual(rec.detail.questions, jevs.ACCOUNT);
  assert.deepStrictEqual([rec.detail.reason, rec.detail.from, rec.detail.to], ['jevs', 1, 2]);
  assert.ok(rec.detail.decision);
  // They can own an agent now, and a later sign-in keeps the level (sign-in counts JEVs's level as verified).
  assert.strictEqual((await agentsApi('POST', '', { cookie: steady.cookie, json: { name: 'First agent' } })).status, 201);
  const again = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: steady.provider, fingerprints: [steady.fp], keyVersion: 1,
    level: 1, displayName: 'x', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
  assert.strictEqual(again.memberId, steady.id);
  assert.strictEqual(again.trustLevel, 2, 'GitHub verifies level 1, and JEVs\'s level 2 still counts');
  // Not promoted: an email-only account (J02 30), a disposable address (J03), a hand-lowered level, or Aaron's demotion later.
  const emailOnly = await member({ level: 0, name: 'Email only', ageDays: 30 });
  assert.strictEqual((await agentsApi('GET', '', { cookie: emailOnly.cookie })).json.can_own, false);
  const throwaway = await member({ level: 1, name: 'Throwaway', ageDays: 30 });
  await run(throwaway.ctx, (t) => jevs.mark(t, { kind: 'disposable', keyHash: c.sha256hex('jevs disposable') }));
  assert.strictEqual((await agentsApi('GET', '', { cookie: throwaway.cookie })).json.can_own, false);
  const slowed = await member({ level: 1, name: 'Slowed', ageDays: 30 });
  assert.strictEqual(await run(aaron.ctx, (t) => require('../db/members').lowerTrustLevel(t, slowed.id, 0)), true);
  assert.strictEqual((await agentsApi('GET', '', { cookie: slowed.cookie })).json.can_own, false, 'Aaron\'s lower level holds');
  // Promoting by hand is gone: Aaron can't, the site can't, and nobody can write JEVs's own record of it.
  const waiting = await member({ level: 1, name: 'Waiting' });
  await assert.rejects(run(aaron.ctx, (t) => t`update app.members set trust_level = 2 where id = ${waiting.id}`), /never by hand/);
  await assert.rejects(run(aaron.ctx, (t) => t`update app.members set jevs_level2_at = now() where id = ${waiting.id}`), /permission denied/);
  // Even perfect scores sent straight to the database don't promote an account younger than the owner's minimum age.
  const [young2] = await run(waiting.ctx, (t) => t`select * from app.jevs_decide('account.check', null, ${t.json({ J01: 0, J02: 0, J03: 0, J04: 0, J05: 0, J06: 0, J10: 0, J13: 0 })}, 'low', false, null, null)`);
  assert.strictEqual(young2.effect, 'none');
  assert.strictEqual((await q(`select trust_level from app.members where id = '${waiting.id}'`))[0].trust_level, 1, 'too young, whatever the scores say');
  // Not every standard question asked: no promotion, even for an old account.
  const partial = await member({ level: 1, name: 'Partial', ageDays: 30 });
  const [d] = await run(partial.ctx, (t) => t`select * from app.jevs_decide('account.check', null, ${t.json({ J01: 0 })}, 'low', false, null, null)`);
  assert.strictEqual(d.effect, 'none');
});

test('decisions are append-only: nobody edits or deletes one, not even the database owner; deleting an account removes what JEVs kept about it', async () => {
  const m = await member({ level: 2, name: 'Leaving soon' });
  const p = await say(m, 'A post with enough words in it to leave a text print behind for later comparisons.');
  await run(m.ctx, (t) => jevs.mark(t, { kind: 'net', keyHash: c.sha256hex('leaving net') }));
  const [d] = await decisionsFor(p.json.id);
  for (const ctx of [m.ctx, aaron.ctx]) {
    await assert.rejects(run(ctx, (t) => t`update app.jevs_decisions set level = 'low' where id = ${d.id}`), /permission denied/);
    await assert.rejects(run(ctx, (t) => t`delete from app.jevs_decisions where id = ${d.id}`), /permission denied/);
  }
  // The database owner has no policy on decisions, so its update and delete reach no row; a superuser, who skips the
  // policies, is stopped by the trigger.
  const touched = await su.begin(async (t) => { await t.unsafe('set local role dog_owner');
    return (await t.unsafe(`update app.jevs_decisions set level = 'low' where id = '${d.id}'`)).count + (await t.unsafe(`delete from app.jevs_decisions where id = '${d.id}'`)).count; });
  assert.strictEqual(touched, 0);
  await assert.rejects(q(`update app.jevs_decisions set level = 'low' where id = '${d.id}'`), /only ever added/, 'even a superuser');
  await assert.rejects(q(`delete from app.jevs_decisions where id = '${d.id}'`), /only ever added/, 'even a superuser');
  assert.strictEqual((await q(`select level from app.jevs_decisions where id = '${d.id}'`))[0].level, d.level);
  // Aaron reads them; a member doesn't.
  assert.strictEqual((await run(m.ctx, (t) => t`select id from app.jevs_decisions`)).length, 0);
  assert.ok((await run(aaron.ctx, (t) => t`select id from app.jevs_decisions where id = ${d.id}`)).length === 1);
  // Deleting the account (a fresh sign-in) clears its decisions, marks and text prints.
  await run({ ...m.ctx, fresh: true }, (t) => store.deleteAccount(t));
  for (const [table, col] of [['jevs_decisions', 'member_id'], ['jevs_marks', 'member_id'], ['jevs_prints', 'author_id'], ['jevs_challenges', 'owner_id']]) {
    assert.strictEqual((await q(`select count(*)::int as n from app.${table} where ${col} = '${m.id}'`))[0].n, 0, table);
  }
});

// ---- Sign-up: the regional gate and the bot checks (signin/flow.js) ----

function signinSetup(mail = []) {
  const accounts = { 'github:7001': { accountId: '7001', level: 1, recheckAfter: null } };
  const challenges = new Map();
  const fake = (name) => ({
    authorizeUrl(cr, { state, challenge }) { challenges.set(state, challenge); return 'https://' + name + '.example/authorize?state=' + state; },
    async identify(cr, { code, verifier }) {
      const [state, account] = code.split('|');
      if (crypto.createHash('sha256').update(verifier).digest('base64url') !== challenges.get(state)) return null;
      return accounts[name + ':' + account] || null;
    }
  });
  const cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: crypto.randomBytes(32),
    fingerprintKeys: [{ version: 1, key: crypto.randomBytes(32) }], github: { clientId: 'g', clientSecret: 's' }, x: { clientId: 'x', clientSecret: 's' } };
  const flow = make({ config: cfg, run, providers: { github: fake('github'), x: fake('x') }, sendEmail: async (to, link) => mail.push({ to, link }) });
  return { flow, cfg, mail };
}
function formReq(url, body, { country = 'US', ip = '192.0.2.77', cookie = '' } = {}) {
  return { method: 'POST', url, headers: { host: 'dayonegreat.com', origin: ORIGIN, cookie, 'x-vercel-forwarded-for': ip, 'x-vercel-ip-country': country,
    'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString(), query: {} };
}
const getReq = (url, { country = 'US', ip = '192.0.2.77', cookie = '' } = {}) => ({ method: 'GET', url, headers: { host: 'dayonegreat.com', cookie,
  'x-vercel-forwarded-for': ip, 'x-vercel-ip-country': country }, query: {} });
const stampFor = (env, ageMs) => c.seal(c.subkey(env.cfg.sessionKey, 'form time'), { k: 'join', t: Date.now() - ageMs });

test('regional gate: sign-up from the EU, EEA, UK and Switzerland is declined politely before anything is kept but a daily count', async () => {
  const env = signinSetup();
  const before = await tableCounts();
  const steps = [
    ['GitHub start (FR)', 'FR', (r) => env.flow.start(getReq('/auth/github/start', { country: 'FR' }), r, 'github')],
    ['X start (DE)', 'DE', (r) => env.flow.start(getReq('/auth/x/start', { country: 'DE' }), r, 'x')],
    ['GitHub callback (GB)', 'GB', (r) => env.flow.callback(getReq('/auth/github/callback?code=x|7001&state=y', { country: 'GB' }), r, 'github')],
    ['email start (CH)', 'CH', (r) => env.flow.emailStart(formReq('/auth/email/start', { email: 'someone@example.ch', ft: stampFor(env, 5000) }, { country: 'CH' }), r)],
    ['email finish (NO)', 'NO', (r) => env.flow.emailFinish(formReq('/auth/email/finish', { t: c.token(32) }, { country: 'NO' }), r)],
    ['email start (lower-case fr)', 'FR', (r) => env.flow.emailStart(formReq('/auth/email/start', { email: 'quelqu.un@example.fr', ft: stampFor(env, 5000) }, { country: 'fr' }), r)]
  ];
  for (const [label, , step] of steps) {
    const r = res();
    await step(r);
    assert.strictEqual(r.statusCode, 451, label);
    assert.match(r.body, /We haven’t kept anything about you/, label);
    assert.ok(!r.body.includes('example'), label + ': nothing from the request is echoed');
    const cookies = [].concat(r.getHeader('Set-Cookie') || []);
    assert.ok(cookies.every((x) => /Max-Age=0/.test(x)), label + ': no cookie is set (' + cookies.join(' ') + ')');
  }
  // An agent registering itself from the EU is declined the same way.
  const ag = await agentsApi('POST', 'register', { json: { name: 'Euro agent' }, country: 'IT' });
  assert.strictEqual(ag.status, 451);
  assert.match(ag.json.error, /haven’t kept anything/);
  // Nothing was written anywhere except the daily counts: no member, no session, no email link, no mark, no rate
  // limit counter, no audit row, no JEVs decision.
  const after = await tableCounts();
  for (const t of Object.keys(before)) if (t !== 'region_declines') assert.strictEqual(after[t], before[t], t + ' changed');
  const declines = await run(aaron.ctx, (t) => t`select country, declines from app.region_declines where day = current_date order by country`);
  const byCountry = Object.fromEntries(declines.map((r) => [r.country, r.declines]));
  for (const cc of ['CH', 'DE', 'GB', 'IT', 'NO']) assert.ok(byCountry[cc] >= 1, cc);
  assert.ok(byCountry.FR >= 2, 'counted per visit, per country, per day');
  assert.deepStrictEqual(Object.keys((await q(`select * from app.region_declines limit 1`))[0]).sort(), ['country', 'day', 'declines', 'id'], 'nothing but the count');
  assert.strictEqual((await run({ actor: 'member', memberId: aaron.id }, (t) => t`select * from app.region_declines`)).length, 0, 'only Aaron reads the counts');
  // Elsewhere, sign-up carries on.
  const ok = res();
  await env.flow.start(getReq('/auth/github/start', { country: 'US' }), ok, 'github');
  assert.strictEqual(ok.statusCode, 302);
});

test('sign-up bot checks: a hidden field, a sealed time stamp at least a second old, and rates per network and overall', async () => {
  const mail = [];
  const env = signinSetup(mail);
  const post = async (body, opts) => { const r = res(); await env.flow.emailStart(formReq('/auth/email/start', body, opts), r); return r.getHeader('Location'); };
  const tokens = async () => (await q(`select count(*)::int as n from app.email_tokens`))[0].n;
  // The page gets its stamp from /auth/form, never cached.
  const f = res();
  await env.flow.formToken(getReq('/auth/form'), f);
  assert.strictEqual(f.statusCode, 200);
  assert.strictEqual(f.getHeader('Cache-Control'), 'no-store');
  const issued = JSON.parse(f.body).token;
  assert.match(issued, /^[A-Za-z0-9_-]+$/);
  // Honeypot: a script that fills in the hidden field is told the link was sent; nothing is sent or kept.
  const t0 = await tokens();
  assert.strictEqual(await post({ email: 'bot@example.com', website: 'https://spam.example', ft: stampFor(env, 5000) }), '/join?sent=1');
  assert.strictEqual(mail.length, 0);
  assert.strictEqual(await tokens(), t0);
  // Too fast: sent within a second of the page opening (the stamp just issued). A person pressing again gets through.
  assert.strictEqual(await post({ email: 'quick@example.com', ft: issued }), '/join?error=fast');
  assert.ok(MIN_FILL_MS >= 1000);
  // No stamp, a forged one, one from another form, or one over two hours old: turned back.
  assert.strictEqual(await post({ email: 'nostamp@example.com' }), '/join?error=expired');
  assert.strictEqual(await post({ email: 'forged@example.com', ft: c.seal(crypto.randomBytes(32), { k: 'join', t: Date.now() - 5000 }) }), '/join?error=expired');
  assert.strictEqual(await post({ email: 'other@example.com', ft: c.seal(c.subkey(env.cfg.sessionKey, 'form time'), { k: 'other', t: Date.now() - 5000 }) }), '/join?error=expired');
  assert.strictEqual(await post({ email: 'old@example.com', ft: stampFor(env, 3 * 3600 * 1000) }), '/join?error=expired');
  assert.strictEqual(mail.length, 0);
  // A person: the stamp is a few seconds old and the hidden field empty.
  assert.strictEqual(await post({ email: 'person@example.com', website: '', ft: stampFor(env, 4000) }), '/join?sent=1');
  assert.strictEqual(mail.length, 1);
  // The address left JEVs's marks with the link (here: its uncommon domain), as hashes only.
  const marks = await q(`select kind, key_hash, token_hash, member_id from app.jevs_marks where token_hash is not null`);
  assert.ok(marks.some((x) => x.kind === 'email_domain'));
  assert.ok(!JSON.stringify(marks).includes('example'));
  // Rates: per network (existing) and a ceiling over all GitHub and X starts (new), checked here with a lowered ceiling.
  const saved = LIMITS.signin_all.max;
  LIMITS.signin_all.max = 2;
  await q(`delete from app.rate_limits where bucket = 'signin_all'`);
  try {
    const outcomes = [];
    for (let i = 0; i < 3; i++) { const r = res(); await env.flow.start(getReq('/auth/github/start', { ip: '198.18.' + i + '.1' }), r, 'github'); outcomes.push(r.getHeader('Location').startsWith('/join') ? r.getHeader('Location') : 'provider'); }
    assert.deepStrictEqual(outcomes, ['provider', 'provider', '/join?error=slow']);
  } finally {
    LIMITS.signin_all.max = saved;
    await q(`delete from app.rate_limits where bucket = 'signin_all'`);
  }
});

test('signing in leaves JEVs\'s network mark and an account check; a sign-in from an EU address is refused only at sign-up steps', async () => {
  const env = signinSetup();
  const r1 = res();
  await env.flow.start(getReq('/auth/github/start', { ip: '198.19.5.5' }), r1, 'github');
  const state = new URL(r1.getHeader('Location')).searchParams.get('state');
  const cookie = [].concat(r1.getHeader('Set-Cookie'))[0].split(';')[0];
  const r2 = res();
  await env.flow.callback(getReq('/auth/github/callback?code=' + encodeURIComponent(state + '|7001') + '&state=' + state, { ip: '198.19.5.5', cookie }), r2, 'github');
  assert.strictEqual(r2.statusCode, 303);
  const [m] = await q(`select m.id from app.members m join app.identities i on i.member_id = m.id where i.provider = 'github' order by m.created_at desc limit 1`);
  const [mark] = await q(`select kind from app.jevs_marks where member_id = '${m.id}'`);
  assert.strictEqual(mark.kind, 'net');
  const [d] = await q(`select action, level from app.jevs_decisions where member_id = '${m.id}' and action = 'signup'`);
  assert.deepStrictEqual(d, { action: 'signup', level: 'low' });
});
