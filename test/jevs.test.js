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

test('JEVs questions: stable IDs J01 to J15, each with a public title and description, scoring 0 to 100', () => {
  assert.deepStrictEqual(jevs.QUESTIONS.map((q) => q.id), Array.from({ length: 15 }, (_, i) => 'J' + String(i + 1).padStart(2, '0')));
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
  for (const k of ['medium_any', 'high_any', 'medium_total', 'high_total', 'pass_max', 'credible_reporter_age_hours']) {
    assert.ok(!code.includes(k), 'db/jevs.js never names the threshold ' + k);
    assert.ok(MIGRATION.includes("('" + k + "'"), 'the migration seeds ' + k);
  }
  // No wait for level 2 (Aaron, Oct 16, 2026): there is no minimum-age setting any more.
  assert.ok(!MIGRATION.includes("('promote_min_age_hours'"), 'no minimum age is seeded');
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
  // The wording promises exactly what is true (the JEVs review, F9): our code stores nothing but the count, and our
  // host keeps its usual request logs for a short time. No absolute claim about network addresses.
  assert.match(region.page(), /We don’t store anything about you/);
  assert.match(region.page(), /hosting provider keeps standard request logs for a short time/);
  assert.doesNotMatch(region.page(), /network address/);
  // The traveller's page: Aaron's words, worded as residence, the country by name from the fixed list only.
  assert.strictEqual(region.confirmText('DE'), 'You appear to be in Germany. Day One Great isn’t offered to people who live in the EU, the EEA, '
    + 'the UK or Switzerland. By continuing, you confirm that you live outside these regions and are using your account lawfully and in line with our terms.');
  assert.match(region.confirmText('GB'), /^You appear to be in the United Kingdom\./);
  for (const cc of region.DECLINED) assert.ok(region.countryName(cc), cc + ' has a name');
  assert.strictEqual(region.countryName('US'), null);
  assert.strictEqual(region.countryName('<b>'), null);
  const page = region.confirmPage('FR');
  assert.match(page, /action="\/auth\/region\/continue"/);
  assert.match(page, /action="\/auth\/region\/cancel"/);
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
  aaron.ctx = { ...aaron.ctx, actor: 'admin' }; // admin, with Aaron's own session
});
const aaronCookie = () => aaron.cookie;
// Audit rows written in one transaction share one time, and their order within it isn't fixed (UUIDv7s made in the
// same millisecond differ only in random bits), so records are compared transaction by transaction.
const inTransactions = (rows) => {
  const out = [];
  for (const r of rows) {
    const last = out[out.length - 1];
    if (last && +last.at === +r.at) last.items.push(r.action); else out.push({ at: r.at, items: [r.action] });
  }
  return out.map((g) => g.items.sort());
};
// Tests only: move a row back in time. The guard that refuses this everywhere else is lifted for this one statement,
// inside one transaction, by the superuser the tests run as.
const backdate = (table, guard, sqlText) => su.begin(async (t) => {
  await t.unsafe(`alter table app.${table} disable trigger ${guard}`);
  await t.unsafe(sqlText);
  await t.unsafe(`alter table app.${table} enable always trigger ${guard}`);
});
const backdateReview = (memberId, interval) => backdate('deletion_reviews', 'deletion_reviews_guard',
  `update app.deletion_reviews set created_at = now() - interval '${interval}' where member_id = '${memberId}'`);
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
  return { id: out.memberId, fp, provider: prov, level, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
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
  assert.strictEqual((await run(aaron.ctx, (t) => t`select key from app.jevs_settings`)).length, 8, 'Aaron sees every setting on the site');
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
    const log = await q(`select action, at from app.audit_log where subject_id = '${high.json.id}' order by at`);
    assert.deepStrictEqual(inTransactions(log), [['jevs.hold', 'review.flag'], ['post.approve', 'review.close']]);
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
  for (let i = 0; i < 3; i++) reporters.push(await member({ level: 2, name: 'Old reporter ' + i, ageDays: 30 }));
  const fresh = [];
  for (let i = 0; i < 3; i++) fresh.push(await member({ level: 2, name: 'New reporter ' + i }));
  // Credible means level 2, more than a week old, and independent (the JEVs review, F1): old level-1 accounts don't
  // count, and old level-2 accounts that signed up from one network count as one.
  const level1 = [];
  for (let i = 0; i < 3; i++) level1.push(await member({ level: 1, name: 'Old level 1 reporter ' + i, ageDays: 30 }));
  const ring = [];
  for (let i = 0; i < 3; i++) {
    const r = await member({ level: 2, name: 'Ring reporter ' + i, ageDays: 30 });
    await run(r.ctx, (t) => jevs.mark(t, { kind: 'net', keyHash: c.sha256hex('one ring network') }));
    ring.push(r);
  }
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
    const pL1 = await say(author, 'A post that three old level one accounts report together.');
    for (const r of level1) await report(r, pL1.json.id);
    assert.strictEqual(await statusOf(pL1.json.id), 'live', 'level 1 reporters are not credible');
    assert.strictEqual((await decisionsFor(pL1.json.id)).pop().scores.J14, 0);
    const pRing = await say(author, 'A post that three old accounts from one network report together.');
    for (const r of ring) await report(r, pRing.json.id);
    assert.strictEqual(await statusOf(pRing.json.id), 'live', 'reporters from one network count as one');
    assert.strictEqual((await decisionsFor(pRing.json.id)).pop().scores.J14, 35);
    // A report scores the post's own questions only, never its author's account (F1).
    assert.deepStrictEqual(Object.keys((await decisionsFor(pRing.json.id)).pop().scores).sort(), ['J07', 'J08', 'J09', 'J14']);
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

test('automatic level 2, with no wait: JEVs promotes an account as soon as every standard question passes, recorded with the question IDs', async () => {
  // A brand-new GitHub account with nothing risky is promoted at its first account check (Aaron, Oct 16, 2026: "No
  // wait at all"). J01 (age) still scores, and counts towards the level, but doesn't stop promotion.
  const brandNew = await member({ level: 1, name: 'Brand new' });
  const d0 = await run(brandNew.ctx, (t) => jevs.check(t, { action: 'account.check', country: 'US' }));
  assert.deepStrictEqual([d0.effect, d0.applied, d0.scores.J01], ['promote', true, 25]);
  const [row] = await q(`select trust_level, jevs_level2_at, level_set_by_admin from app.members where id = '${brandNew.id}'`);
  assert.strictEqual(row.trust_level, 2);
  assert.ok(row.jevs_level2_at);
  assert.strictEqual(row.level_set_by_admin, null, 'not a hand-set level');
  const [rec] = await q(`select detail from app.audit_log where action = 'member.level_changed' and subject_id = '${brandNew.id}'`);
  assert.deepStrictEqual(rec.detail.questions, jevs.ACCOUNT);
  assert.deepStrictEqual([rec.detail.reason, rec.detail.from, rec.detail.to], ['jevs', 1, 2]);
  assert.ok(rec.detail.decision);
  // They can own an agent now, and a later sign-in keeps the level (sign-in counts JEVs's level as verified).
  assert.strictEqual((await agentsApi('POST', '', { cookie: brandNew.cookie, json: { name: 'First agent' } })).status, 201);
  const again = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: brandNew.provider, fingerprints: [brandNew.fp], keyVersion: 1,
    level: 1, displayName: 'x', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
  assert.strictEqual(again.trustLevel, 2, 'GitHub verifies level 1, and JEVs\'s level 2 still counts');
  // Not promoted: an email-only account (J02 30), a disposable address (J03), a hand-lowered level.
  const check = (m, extra = {}) => run(m.ctx, (t) => jevs.check(t, { action: 'account.check', country: 'US', ...extra }));
  const emailOnly = await member({ level: 0, name: 'Email only', ageDays: 30 });
  assert.strictEqual((await check(emailOnly)).effect, 'none');
  const throwaway = await member({ level: 1, name: 'Throwaway', ageDays: 30 });
  await run(throwaway.ctx, (t) => jevs.mark(t, { kind: 'disposable', keyHash: c.sha256hex('jevs disposable') }));
  assert.strictEqual((await check(throwaway)).effect, 'none');
  const slowed = await member({ level: 1, name: 'Slowed', ageDays: 30 });
  assert.strictEqual(await run(aaron.ctx, (t) => require('../db/members').lowerTrustLevel(t, slowed.id, 0)), true);
  assert.strictEqual((await check(slowed)).effect, 'none', 'Aaron\'s lower level holds');
  // A member travelling in a declined region: J13 scores 40 and stops promotion, unless they confirmed at sign-in that
  // they live outside it, which scores 0 for that session.
  const traveller = await member({ level: 1, name: 'Traveller' });
  assert.deepStrictEqual([(await check(traveller, { country: 'FR' })).scores.J13, (await check(traveller, { country: 'FR' })).effect], [40, 'none']);
  const confirmed = await check(traveller, { country: 'FR', confirmed: true });
  assert.deepStrictEqual([confirmed.scores.J13, confirmed.effect], [0, 'promote']);
  // Promoting by hand is gone: Aaron can't, the site can't, and nobody but JEVs writes its record of it, not even the
  // database owner (the JEVs review, F5).
  const waiting = await member({ level: 0, name: 'Waiting', ageDays: 30 });
  await assert.rejects(run(aaron.ctx, (t) => t`update app.members set trust_level = 2 where id = ${waiting.id}`), /never by hand/);
  await assert.rejects(run(aaron.ctx, (t) => t`update app.members set jevs_level2_at = now() where id = ${waiting.id}`), /permission denied/);
  await assert.rejects(asOwner(`update app.members set jevs_level2_at = now() where id = '${waiting.id}'`), /only JEVs records its own promotion/);
  // Perfect scores sent straight to the database don't promote an email-only account: the database works out the
  // account questions itself (F5; the review's repro R5 promoted this account).
  const zeros = { J01: 0, J02: 0, J03: 0, J04: 0, J05: 0, J06: 0, J10: 0, J13: 0 };
  const [forged] = await run(waiting.ctx, (t) => t`select * from app.jevs_decide('account.check', null, ${t.json(zeros)}, 'low', false, null, null, null)`);
  assert.strictEqual(forged.effect, 'none');
  assert.strictEqual((await q(`select trust_level from app.members where id = '${waiting.id}'`))[0].trust_level, 0, 'still level 0, whatever the scores say');
  const [stored] = await q(`select scores from app.jevs_decisions where id = '${forged.decision_id}'`);
  assert.strictEqual(stored.scores.J02, 30, 'the record holds the database\'s own score');
  // Not every standard question asked (no J13 from the site): no promotion, even for a clean account.
  const partial = await member({ level: 1, name: 'Partial' });
  const [d] = await run(partial.ctx, (t) => t`select * from app.jevs_decide('account.check', null, ${t.json({ J01: 0 })}, 'low', false, null, null, null)`);
  assert.strictEqual(d.effect, 'none');
  // Opening the agents page reads and records nothing (the JEVs review: no decision rows for page views).
  const viewer = await member({ level: 0, name: 'Viewer' });
  const before = (await q(`select count(*)::int as n from app.jevs_decisions where member_id = '${viewer.id}'`))[0].n;
  for (let i = 0; i < 3; i++) assert.strictEqual((await agentsApi('GET', '', { cookie: viewer.cookie })).json.can_own, false);
  assert.strictEqual((await q(`select count(*)::int as n from app.jevs_decisions where member_id = '${viewer.id}'`))[0].n, before);
});

test('the database scores the account questions exactly as db/jevs.js does (F5), over thousands of cases', async () => {
  // A fixed pseudo-random walk, so the cases are the same every run.
  let x = 0x2545f491;
  const rnd = (n) => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return Math.abs(x) % n; };
  const pick = (a) => a[rnd(a.length)];
  const cases = [];
  for (let i = 0; i < 3000; i++) {
    cases.push({ age_hours: pick([0, 0.5, 1, 5, 23, 24, 100, 167, 168, 5000]), admin: rnd(10) === 0, best_identity: pick([-1, 0, 1, 2]),
      providers: pick([0, 1, 2, 3]), disposable: rnd(5) === 0, posts_1h: pick([0, 1, 3, 4, 6, 7, 12, 13, 59, 60, 200]),
      posts_before: pick([0, 10, 336, 1000, 5000]), established: rnd(3) === 0, net_members_24h: pick([0, 1, 2, 4, 5, 9, 10, 30]),
      domain_members_7d: pick([0, 2, 3, 9, 10]), net_signups_1h: pick([0, 4, 5, 19, 20]), site_signups_1h: pick([0, 50, 51, 400]),
      site_signups_7d: pick([0, 840, 5000, 10000]), owner_agents_24h: pick([0, 3, 4, 9, 10, 24, 25]), net_agents_24h: pick([0, 4, 10, 25]),
      upheld_90d: pick([0, 1, 2, 3, 7]), braked: rnd(4) === 0 });
  }
  const sqlScores = await q(`select app.jevs_account_scores(c) as s from jsonb_array_elements('${JSON.stringify(cases)}'::jsonb) with ordinality as t(c, n) order by n`);
  const keys = ['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10'];
  cases.forEach((sig, i) => {
    const js = jevs.score('account.check', sig, { country: 'US' });
    for (const k of keys) assert.strictEqual(sqlScores[i].s[k], js[k], k + ' differs for ' + JSON.stringify(sig));
  });
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

// ---- High-risk account deletion goes to Aaron (Oct 16, 2026) ----
// "JEVs scores and provide deletion as high risk. The member should be informed their account was flagged as high
// risk. A review will be provided to me and I will make a decision on account status. If I have not responded to a
// high risk account in 24 hours the account should be disabled but not deleted until I make a decision."

// A member whose deletion scores high: email only (J02 30), a throwaway address (J03 60), new (J01 25), deleting (J11 30).
async function riskyMember(env, name, account) {
  const { r2 } = await oauthFlow(env, 'github', account, { country: 'US' });
  const cookie = cookieOf(r2, '__Host-dog_session');
  const [m] = await q(`select member_id as id from app.sessions where token_hash = '${c.sha256hex(cookie.split('=')[1])}'`);
  await run({ actor: 'member', memberId: m.id }, (t) => jevs.mark(t, { kind: 'disposable', keyHash: c.sha256hex('jevs disposable') }));
  await q(`update app.identities set level = 0 where member_id = '${m.id}'`);
  return { id: m.id, cookie, ctx: { actor: 'member', memberId: m.id, session: c.sha256hex(cookie.split('=')[1]) }, account };
}
async function askToDelete(env, who) {
  const r = res();
  await env.flow.deleteAccount(formReq('/auth/account/delete', { confirm: 'DELETE' }, { cookie: who.cookie }), r);
  return r.getHeader('Location');
}
const reviewOf = async (id) => (await q(`select * from app.deletion_reviews where member_id = '${id}'`))[0];
const statusOfMember = async (id) => ((await q(`select status from app.members where id = '${id}'`))[0] || {}).status;

test('deletion review: a high-risk deletion deletes nothing, tells the member, and puts the scores in Aaron\'s queue', async () => {
  const env = signinSetup([], { 'github:7401': { accountId: '7401', level: 1, recheckAfter: null }, 'github:7402': { accountId: '7402', level: 1, recheckAfter: null } });
  await setMode('enforce');
  try {
    const m = await riskyMember(env, 'Flagged', '7401');
    // An old session can't even start a review (a stolen cookie can't start the clock on someone's account).
    await q(`update app.sessions set created_at = now() - interval '1 hour' where member_id = '${m.id}'`);
    assert.strictEqual(await askToDelete(env, m), '/account?error=fresh');
    assert.strictEqual(await reviewOf(m.id), undefined);
    await q(`update app.sessions set created_at = now() where member_id = '${m.id}'`);
    // Signed in just now: flagged, not deleted.
    assert.strictEqual(await askToDelete(env, m), '/account?error=review');
    assert.strictEqual(await statusOfMember(m.id), 'active', 'nothing is deleted or disabled yet');
    const r = await reviewOf(m.id);
    assert.ok(r && r.decision === null && r.disabled_at === null);
    const [dec] = await q(`select action, level, effect, applied, scores from app.jevs_decisions where id = '${r.decision_id}'`);
    assert.deepStrictEqual([dec.action, dec.level, dec.effect, dec.applied], ['account.delete', 'high', 'hold', true]);
    assert.deepStrictEqual([dec.scores.J03, dec.scores.J11], [60, 30], 'the data Aaron decides on: the question IDs and scores');
    assert.ok((await q(`select 1 from app.audit_log where action = 'deletion_review.opened' and subject_id = '${m.id}'`)).length === 1);
    // The member sees it on their account page, with when it would disable the account; asking again opens nothing new.
    const acct = res();
    await env.flow.account(getReq('/auth/account', { cookie: m.cookie }), acct);
    const a = JSON.parse(acct.body).deletion_review;
    assert.ok(a.since && new Date(a.disables_at) - new Date(a.since) === 24 * 3600 * 1000);
    assert.strictEqual(await askToDelete(env, m), '/account?error=review');
    assert.strictEqual((await q(`select count(*)::int as n from app.deletion_reviews where member_id = '${m.id}'`))[0].n, 1);
    const page = fs.readFileSync(path.join(root, 'account.js'), 'utf8');
    assert.match(page, /Your account was flagged as high risk by our automatic checks \(JEVs\), so it hasn’t been deleted/);
    assert.ok(!/hello@dayonegreat\.com/.test(page), 'no more "please email us"');
    // Aaron's queue: the review, the account and the scores. Nobody else sees it or can decide it.
    const ctl = await feed('GET', { cookie: aaronCookie(), query: { controls: '1' } });
    assert.strictEqual(ctl.status, 200);
    const item = ctl.json.deletion_reviews.find((x) => x.member.id === m.id);
    assert.deepStrictEqual([item.state, item.jevs.level, item.jevs.scores.J03], ['open', 'high', 60]);
    assert.strictEqual(new Date(item.due_at) - new Date(item.opened_at), 24 * 3600 * 1000);
    assert.ok(ctl.json.untrusted_fields.includes('deletion_reviews[].member.name'), 'a member\'s name is marked as untrusted text');
    const other = await member({ level: 2, name: 'Nosy' });
    assert.strictEqual((await run(other.ctx, (t) => t`select id from app.deletion_reviews`)).length, 0);
    assert.strictEqual((await run(m.ctx, (t) => t`select id from app.deletion_reviews`)).length, 1, 'the member sees their own');
    await assert.rejects(run(other.ctx, (t) => t`select app.deletion_review_decide(${r.id}::uuid, 'restore')`), /not_admin/);
    assert.strictEqual((await feed('POST', { cookie: other.cookie, json: { deletion_review: r.id, decision: 'delete' } })).status, 403);
    await assert.rejects(run(aaron.ctx, (t) => t`update app.deletion_reviews set decision = 'restore', decided_at = now() where id = ${r.id}`), /permission denied/);
    // Shadow mode stops nobody, so there the same request deletes (recorded as "would have held").
    await setMode('shadow');
    const s = await riskyMember(env, 'Shadow leaver', '7402');
    assert.strictEqual(await askToDelete(env, s), '/join?deleted=1');
    assert.strictEqual(await statusOfMember(s.id), undefined);
  } finally { await setMode('shadow'); }
});

test('deletion review: after 24 hours without Aaron\'s decision the account is disabled, keeping every record, and never deleted on its own', async () => {
  const env = signinSetup([], { 'github:7501': { accountId: '7501', level: 1, recheckAfter: null } });
  await setMode('enforce');
  try {
    const m = await riskyMember(env, 'Waiting', '7501');
    // An agent of theirs that acts on its own, with a key and a draft waiting: all of it must stop. (They reached
    // level 2 at sign-up, with no wait.)
    const [agent] = await run({ ...m.ctx, fresh: true }, (t) => t`insert into app.agents (name) values ('Waiting agent') returning id`);
    await run({ ...m.ctx, fresh: true }, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${agent.id}, ${c.sha256hex('waiting-key')})`);
    await run({ ...m.ctx, fresh: true }, (t) => t`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason) values (${agent.id}, 'draft', 'act', 'draft', 20, 'owner')`);
    await run({ actor: 'agent', memberId: m.id, agentId: agent.id }, (t) => t`insert into app.agent_drafts (body) values ('a waiting draft')`);
    await say({ cookie: m.cookie }, 'A post the member wrote before asking to leave.');
    assert.strictEqual(await askToDelete(env, m), '/account?error=review');
    const before = { posts: (await q(`select count(*)::int as n from app.posts where author_id = '${m.id}'`))[0].n,
      ids: (await q(`select count(*)::int as n from app.identities where member_id = '${m.id}'`))[0].n };
    assert.strictEqual((await feed('GET', { query: { profile: m.id } })).status, 200, 'their profile is public while active');
    // Within the 24 hours nothing changes, and only the site's job (or Aaron) runs the timer.
    await assert.rejects(run(m.ctx, (t) => require('../db/controls').expireDeletionReviews(t)), /not_system/);
    assert.strictEqual(await run({ actor: 'system' }, (t) => require('../db/controls').expireDeletionReviews(t)), 0);
    assert.strictEqual(await statusOfMember(m.id), 'active');
    // Past 24 hours: from that moment sessions, sign-in and agent keys stop, even before the timer next runs.
    await backdateReview(m.id, '24 hours 1 minute');
    assert.strictEqual(await run({ actor: 'anon' }, (t) => store.sessionResolve(t, c.sha256hex(m.cookie.split('=')[1]), 7)), null);
    assert.strictEqual(await run({ actor: 'anon' }, (t) => require('../db/agents').resolve(t, c.sha256hex('waiting-key'))), null);
    const { r2: early } = await oauthFlow(env, 'github', '7501');
    assert.strictEqual(early.getHeader('Location'), '/join?error=disabled');
    // The timer disables it: every session ends, keys are revoked, agents are switched off, drafts declined.
    assert.strictEqual(await run({ actor: 'system' }, (t) => require('../db/controls').expireDeletionReviews(t)), 1);
    assert.strictEqual(await statusOfMember(m.id), 'disabled');
    assert.strictEqual((await q(`select count(*)::int as n from app.sessions where member_id = '${m.id}'`))[0].n, 0);
    assert.strictEqual((await q(`select count(*)::int as n from app.agent_keys where agent_id = '${agent.id}' and revoked_at is null`))[0].n, 0);
    const [rules] = await q(`select post_mode, reply_mode, report_mode, reason, set_by from app.agent_rules where agent_id = '${agent.id}' order by version desc limit 1`);
    // (the agent's replies acted alone; now nothing does)
    assert.deepStrictEqual(rules, { post_mode: 'off', reply_mode: 'off', report_mode: 'off', reason: 'disabled', set_by: 'system' });
    assert.strictEqual((await q(`select status from app.agent_drafts where owner_id = '${m.id}'`))[0].status, 'declined');
    // Nothing is deleted: posts and sign-in methods stay; the record says when and why.
    assert.strictEqual((await q(`select count(*)::int as n from app.posts where author_id = '${m.id}'`))[0].n, before.posts);
    assert.strictEqual((await q(`select count(*)::int as n from app.identities where member_id = '${m.id}'`))[0].n, before.ids);
    const log = (await q(`select action from app.audit_log where subject_id = '${m.id}' order by at, id`)).map((r) => r.action);
    assert.ok(log.includes('deletion_review.disabled') && log.includes('member.disable'));
    assert.ok((await reviewOf(m.id)).disabled_at);
    assert.strictEqual((await feed('GET', { query: { profile: m.id } })).status, 404, 'hidden from the public while disabled, like a ban');
    // Sign-in is refused with a plain message; the timer never disables twice; the account is never deleted on its own.
    const { r2: later } = await oauthFlow(env, 'github', '7501');
    assert.strictEqual(later.getHeader('Location'), '/join?error=disabled');
    assert.match(fs.readFileSync(path.join(root, 'join.js'), 'utf8'), /This account is disabled while a request to delete it is reviewed\. Nothing has been deleted\./);
    for (let i = 0; i < 3; i++) assert.strictEqual(await run({ actor: 'system' }, (t) => require('../db/controls').expireDeletionReviews(t)), 0);
    await backdateReview(m.id, '400 days');
    assert.strictEqual(await run({ actor: 'system' }, (t) => require('../db/controls').expireDeletionReviews(t)), 0);
    assert.strictEqual(await statusOfMember(m.id), 'disabled', 'still there, a year on, until Aaron decides');
    // Only a deletion review moves an account to or from disabled: not Aaron's ban or unban, not the site.
    await assert.rejects(run(aaron.ctx, (t) => t`update app.members set status = 'active' where id = ${m.id}`), /only a deletion review/);
    await assert.rejects(run(aaron.ctx, (t) => t`update app.members set status = 'banned' where id = ${m.id}`), /only a deletion review/);
    assert.strictEqual((await feed('POST', { cookie: aaronCookie(), json: { unban: m.id } })).status, 409);
  } finally { await setMode('shadow'); }
});

test('deletion review: Aaron allows the deletion, keeps the account disabled, or restores it; each is recorded', async () => {
  const env = signinSetup([], { 'github:7601': { accountId: '7601', level: 1, recheckAfter: null }, 'github:7602': { accountId: '7602', level: 1, recheckAfter: null },
    'github:7603': { accountId: '7603', level: 1, recheckAfter: null } });
  const decide = (review, decision) => feed('POST', { cookie: aaronCookie(), json: { deletion_review: review, decision } });
  await setMode('enforce');
  try {
    // Restore, after the timer disabled it: active again; the owner signs in again (old sessions and keys stay ended).
    const back = await riskyMember(env, 'Restored', '7601');
    await askToDelete(env, back);
    await backdateReview(back.id, '25 hours');
    await run({ actor: 'system' }, (t) => require('../db/controls').expireDeletionReviews(t));
    const rb = await reviewOf(back.id);
    const restored = await decide(rb.id, 'restore');
    assert.deepStrictEqual([restored.status, restored.json.result], [200, 'restored']);
    assert.strictEqual(await statusOfMember(back.id), 'active');
    assert.strictEqual((await reviewOf(back.id)).decision, 'restore');
    const { r2: signedIn } = await oauthFlow(env, 'github', '7601');
    assert.ok(cookieOf(signedIn, '__Host-dog_session'), 'they can sign in again');
    assert.strictEqual((await decide(rb.id, 'delete')).status, 409, 'a restored review is closed');
    // Keep disabled, before the 24 hours are up: disabled now; later, Aaron deletes it after all.
    const kept = await riskyMember(env, 'Kept', '7602');
    await askToDelete(env, kept);
    const rk = await reviewOf(kept.id);
    assert.strictEqual((await decide(rk.id, 'keep_disabled')).json.result, 'disabled');
    assert.strictEqual(await statusOfMember(kept.id), 'disabled');
    assert.strictEqual((await q(`select count(*)::int as n from app.sessions where member_id = '${kept.id}'`))[0].n, 0);
    assert.strictEqual((await decide(rk.id, 'keep_disabled')).status, 409, 'already so');
    const listed = await run(aaron.ctx, (t) => require('../db/controls').deletionReviews(t));
    assert.strictEqual(listed.find((x) => x.id === rk.id).state, 'kept_disabled', 'it stays in his list, to delete or restore later');
    const gone = await decide(rk.id, 'delete');
    assert.deepStrictEqual([gone.status, gone.json.result], [200, 'deleted']);
    for (const [table, col] of [['members', 'id'], ['identities', 'member_id'], ['deletion_reviews', 'member_id'], ['jevs_decisions', 'member_id'], ['jevs_marks', 'member_id']]) {
      assert.strictEqual((await q(`select count(*)::int as n from app.${table} where ${col} = '${kept.id}'`))[0].n, 0, table);
    }
    const log = (await q(`select action, actor_kind, detail, at from app.audit_log where subject_id = '${kept.id}' and action in ('deletion_review.decided', 'member.deleted') order by at`));
    assert.deepStrictEqual(inTransactions(log), [['deletion_review.decided'], ['deletion_review.decided', 'member.deleted']], 'kept disabled, then deleted');
    assert.ok(log.every((r) => r.actor_kind === 'admin'), 'both by Aaron');
    assert.strictEqual(log.find((r) => r.action === 'member.deleted').detail.deletion_reviews, 1);
    // Allow deletion straight from an open review.
    const now = await riskyMember(env, 'Deleted now', '7603');
    await askToDelete(env, now);
    assert.strictEqual((await decide((await reviewOf(now.id)).id, 'delete')).json.result, 'deleted');
    assert.strictEqual(await statusOfMember(now.id), undefined);
    assert.strictEqual((await decide(crypto.randomUUID(), 'delete')).status, 404);
  } finally { await setMode('shadow'); }
});

test('deletion review: Aaron himself is never flagged, disabled or deleted this way', async () => {
  await setMode('enforce');
  try {
    // JEVs never holds Aaron, so no review opens for him, whatever the scores.
    const [d] = await run({ ...aaron.ctx, fresh: true }, (t) => t`select * from app.jevs_decide('account.delete', null, ${t.json({ J03: 100, J11: 30 })}, 'high', false, null, null, null)`);
    assert.strictEqual(d.effect, 'none');
    assert.strictEqual(await reviewOf(aaron.id), undefined);
    // Even a review written for him directly can't disable or delete him.
    await su.begin(async (t) => { await t.unsafe('set local role dog_jevs'); await t.unsafe(`insert into app.deletion_reviews (member_id, decision_id) values ('${aaron.id}', '${d.decision_id}')`); });
    await backdateReview(aaron.id, '2 days');
    await run({ actor: 'system' }, (t) => require('../db/controls').expireDeletionReviews(t));
    assert.strictEqual(await statusOfMember(aaron.id), 'active');
    const r = await reviewOf(aaron.id);
    await assert.rejects(run(aaron.ctx, (t) => t`select app.deletion_review_decide(${r.id}::uuid, 'keep_disabled')`), /administrator can't be disabled/);
    await assert.rejects(run(aaron.ctx, (t) => t`select app.deletion_review_decide(${r.id}::uuid, 'delete')`), /not_active/);
    assert.strictEqual(await statusOfMember(aaron.id), 'active');
    // He can't delete his own account from /account either.
    const env = signinSetup();
    const out = res();
    await env.flow.deleteAccount(formReq('/auth/account/delete', { confirm: 'DELETE' }, { cookie: aaronCookie() }), out);
    assert.strictEqual(out.getHeader('Location'), '/account?error=admin');
  } finally {
    await su.begin(async (t) => { await t.unsafe('set local role dog_erase'); await t.unsafe(`delete from app.deletion_reviews where member_id = '${aaron.id}'`); });
    await setMode('shadow');
  }
});

// ---- The independent review's findings, each a scenario that succeeded before its fix (review-jevs, Oct 16) ----

test('F1: copying an honest member\'s post and reporting it never hides the original; the copies are what score', async () => {
  await setMode('enforce');
  try {
    const honest = await member({ level: 2, name: 'Honest', ageDays: 60 });
    const text = 'Here is my original thought about building trust with agents in small communities today.';
    const orig = await say(honest, text);
    assert.strictEqual(orig.status, 201);
    const socks = [];
    for (let i = 0; i < 5; i++) { const sock = await member({ level: 0, name: 'Sock ' + i }); socks.push(await say(sock, text)); }
    const reporter = await member({ level: 0, name: 'Fresh reporter' });
    assert.strictEqual((await feed('POST', { cookie: reporter.cookie, json: { report: orig.json.id, reason: 'spam' } })).status, 202);
    const d = (await decisionsFor(orig.json.id)).pop();
    assert.deepStrictEqual([d.action, d.scores.J09, d.effect], ['post.reported', 0, 'none'], 'whoever posted first is never scored as a copy');
    assert.strictEqual(await statusOf(orig.json.id), 'live', 'the honest original stays up');
    // The first copy is scored against the live original; later copies don't count each other while they wait.
    assert.strictEqual((await decisionsFor(socks[0].json.id)).pop().scores.J09, 30);
    assert.strictEqual((await decisionsFor(socks[4].json.id)).pop().scores.J09, 30, 'held or waiting copies count for nothing');
  } finally { await setMode('shadow'); }
});

test('F2: a common short phrase is never a copy, whoever said it first', async () => {
  await setMode('enforce');
  try {
    for (let i = 0; i < 5; i++) { const m = await member({ level: 2, name: 'Thanker ' + i, ageDays: 60 }); await say(m, 'Thank you!'); }
    const sixth = await member({ level: 2, name: 'Sixth', ageDays: 60 });
    const r = await say(sixth, 'thank you');
    assert.strictEqual(r.status, 201, 'goes live');
    const d = (await decisionsFor(r.json.id)).pop();
    assert.deepStrictEqual([d.scores.J09, d.level, d.effect], [0, 'low', 'none']);
    assert.strictEqual(jevs.simhash('thank you so much for all of this'), null, 'under 40 characters: no print, never compared');
    assert.ok(jevs.simhash('thank you so much for all of this hard and careful work'), '8 words and 40 characters: compared');
  } finally { await setMode('shadow'); }
});

test('F5: in enforce mode a post with no JEVs decision is refused when its transaction commits', async () => {
  const m = await member({ level: 1, name: 'Unscored' });
  const body = 'https://a.example https://b.example https://c.example https://d.example mail x@example.com';
  // Shadow mode keeps first-post review, so an unscored post still waits for review.
  const shadow = await run(m.ctx, (t) => posts.create(t, { body }));
  assert.strictEqual(await statusOf(shadow.id), 'waiting');
  await setMode('enforce');
  try {
    await assert.rejects(run(m.ctx, (t) => posts.create(t, { body })), /unscored/);
    assert.strictEqual((await q(`select count(*)::int as n from app.posts where author_id = '${m.id}'`))[0].n, 1, 'nothing was published');
    // Through the site, every post is scored, and goes ahead.
    const ok = await say(m, 'An ordinary scored post from the same member.');
    assert.ok([201, 202].includes(ok.status));
  } finally { await setMode('shadow'); }
});

test('F6: a domain counts as seen only once a low-risk post linking it has stayed live for a day, and not after Aaron removes it', async () => {
  await setMode('enforce');
  try {
    const m = await member({ level: 2, name: 'Launderer', ageDays: 30 });
    const doms = Array.from({ length: 3 }, (_, i) => 'spam' + i + '-' + crypto.randomBytes(3).toString('hex') + '.example');
    const firsts = [];
    for (const d of doms) { const r = await say(m, 'Nice read https://' + d); assert.strictEqual(r.status, 201); firsts.push(r.json.id); }
    const spam = await say(m, 'BUY NOW https://' + doms.join(' https://'));
    assert.strictEqual((await decisionsFor(spam.json.id)).pop().scores.J07, 75, 'a quick harmless post doesn\'t launder a domain');
    // A day later the domains are seen...
    await backdate('posts', 'posts_review_guard', `update app.posts set created_at = now() - interval '25 hours' where id in ('${firsts.join("','")}')`);
    const later = await say(m, 'Still worth reading https://' + doms.join(' https://'));
    assert.strictEqual((await decisionsFor(later.json.id)).pop().scores.J07, 0);
    // ...until Aaron removes the posts that vouched for them.
    for (const id of firsts) await run(aaron.ctx, (t) => review.decide(t, { post: id, decision: 'remove' }));
    const after = await say(m, 'Once more https://' + doms.join(' https://'));
    assert.strictEqual((await decisionsFor(after.json.id)).pop().scores.J07, 75);
  } finally { await setMode('shadow'); }
});

test('F7: a sensitive step is confirmed by signing in again, never by a session cookie alone, and then goes ahead without a loop', async () => {
  await setMode('enforce');
  try {
    const o = await member({ level: 2, name: 'Confirming owner', stale: true });
    await run(o.ctx, (t) => jevs.mark(t, { kind: 'disposable', keyHash: c.sha256hex('jevs disposable') }));
    const made = await agentsApi('POST', '', { cookie: o.cookie, json: { name: 'Bot' } });
    assert.strictEqual(made.status, 403);
    const ch = made.json.challenge;
    assert.ok(ch);
    // The API answer from this old session can't confirm it, and says plainly what to do.
    const ans = await feed('POST', { cookie: o.cookie, json: { challenge: ch, answer: 'confirm' } });
    assert.strictEqual(ans.status, 403);
    assert.match(ans.json.error, /sign in again/);
    assert.strictEqual((await q(`select status from app.jevs_challenges where id = '${ch}'`))[0].status, 'pending');
    // Signed in again: the same step goes ahead at once, and the earlier request is answered by it.
    await q(`update app.sessions set created_at = now() where member_id = '${o.id}'`);
    const again = await agentsApi('POST', '', { cookie: o.cookie, json: { name: 'Bot' } });
    assert.strictEqual(again.status, 201);
    assert.strictEqual((await q(`select status from app.jevs_challenges where id = '${ch}'`))[0].status, 'confirmed');
    // The check and the step are one transaction: the decision exists only with its agent.
    const [dec] = await q(`select count(*)::int as n from app.jevs_decisions where member_id = '${o.id}' and action = 'agent.create' and effect = 'challenge'`);
    assert.strictEqual(dec.n, 2);
  } finally { await setMode('shadow'); }
});

test('F10: after an account is deleted, the audit log keeps what JEVs did, never which questions fired', async () => {
  await setMode('enforce');
  try {
    const m = await member({ level: 2, name: 'Leaver' });
    await run(m.ctx, (t) => jevs.mark(t, { kind: 'disposable', keyHash: c.sha256hex('jevs disposable') }));
    const d = await run(m.ctx, (t) => jevs.check(t, { action: 'agent.create' }));
    assert.strictEqual(d.effect, 'challenge');
    await run({ ...m.ctx, fresh: true }, (t) => store.deleteAccount(t));
    const left = await q(`select action, detail from app.audit_log where subject_id = '${m.id}' and action like 'jevs.%'`);
    assert.ok(left.length >= 1);
    for (const r of left) assert.ok(!('questions' in r.detail), JSON.stringify(r.detail));
    assert.strictEqual((await q(`select count(*)::int as n from app.jevs_decisions where member_id = '${m.id}'`))[0].n, 0);
  } finally { await setMode('shadow'); }
});

test('the scheduled sweep keeps marks no longer than promised, and only the site\'s job or Aaron runs it', async () => {
  const m = await member({ level: 1, name: 'Marked long ago' });
  await run(m.ctx, (t) => jevs.mark(t, { kind: 'net', keyHash: c.sha256hex('old network') }));
  await run({ actor: 'anon' }, (t) => jevs.mark(t, { kind: 'disposable', keyHash: c.sha256hex('jevs disposable'), token: c.sha256hex('unused link') }));
  await q(`update app.jevs_marks set created_at = now() - interval '31 days' where member_id = '${m.id}'`);
  await q(`update app.jevs_marks set created_at = now() - interval '25 hours' where token_hash = '${c.sha256hex('unused link')}'`);
  await assert.rejects(run(m.ctx, (t) => jevs.sweep(t)), /not_system/);
  assert.ok((await run({ actor: 'system' }, (t) => jevs.sweep(t))) >= 2);
  assert.strictEqual((await q(`select count(*)::int as n from app.jevs_marks where member_id = '${m.id}' or token_hash = '${c.sha256hex('unused link')}'`))[0].n, 0);
  assert.ok(!MIGRATION.includes('random()'), 'nothing is left to chance');
});

// ---- Sign-up: the regional gate and the bot checks (signin/flow.js) ----

function signinSetup(mail = [], more = {}) {
  const accounts = { 'github:7001': { accountId: '7001', level: 1, recheckAfter: null }, ...more };
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

const setCookies = (r) => [].concat(r.getHeader('Set-Cookie') || []);
const cookieOf = (r, name) => { const x = setCookies(r).find((k) => k.startsWith(name + '=') && !/Max-Age=0/.test(k)); return x ? x.split(';')[0] : null; };
// GitHub or X from start to callback, from a country, with the browser's cookies. Returns both responses.
async function oauthFlow(env, provider, account, { country = 'US', ip = '192.0.2.88', cookie = '', query = '' } = {}) {
  const r1 = res();
  const startReq = getReq('/auth/' + provider + '/start' + query, { country, ip, cookie });
  // A link starts only from our own pages (PR 15), as the /account button does.
  if (/link=1/.test(query)) startReq.headers['sec-fetch-site'] = 'same-origin';
  await env.flow.start(startReq, r1, provider);
  const loc = r1.getHeader('Location');
  if (!/^https:/.test(loc)) return { r1, r2: null };
  const state = new URL(loc).searchParams.get('state');
  const st = cookieOf(r1, '__Host-dog_oauth_' + provider);
  const r2 = res();
  await env.flow.callback(getReq('/auth/' + provider + '/callback?code=' + encodeURIComponent(state + '|' + account) + '&state=' + state,
    { country, ip, cookie: [cookie, st].filter(Boolean).join('; ') }), r2, provider);
  return { r1, r2 };
}
const declinesFor = async (cc) => ((await q(`select declines from app.region_declines where day = current_date and country = '${cc}'`))[0] || { declines: 0 }).declines;

test('regional gate, new sign-ups: declined politely after the provider confirms who they are, before anything is stored but a daily count', async () => {
  const mail = [];
  const env = signinSetup(mail, { 'github:7101': { accountId: '7101', level: 1, recheckAfter: null }, 'x:7102': { accountId: '7102', level: 1, recheckAfter: null } });
  // An email link asked for outside the declined regions, for an address with no account, opened in Norway.
  const okStart = res();
  await env.flow.emailStart(formReq('/auth/email/start', { email: 'nobody-yet@example.no', ft: stampFor(env, 5000) }, { country: 'US' }), okStart);
  const link = mail.pop().link.split('#t=')[1];
  const before = await tableCounts();
  const counts = { GB: await declinesFor('GB'), DE: await declinesFor('DE'), CH: await declinesFor('CH'), NO: await declinesFor('NO'), FR: await declinesFor('FR') };
  // Starting from a declined region goes to the provider (nobody can be told apart before that) and stores nothing,
  // not even a rate-limit count.
  const { r1: started } = await oauthFlow(env, 'github', 'none', { country: 'FR' });
  assert.strictEqual(started.statusCode, 302);
  const steps = [
    ['GitHub sign-up (GB)', async (r) => { const { r2 } = await oauthFlow(env, 'github', '7101', { country: 'GB' }); Object.assign(r, r2); }],
    ['X sign-up (DE)', async (r) => { const { r2 } = await oauthFlow(env, 'x', '7102', { country: 'DE' }); Object.assign(r, r2); }],
    ['email link opened (NO)', (r) => env.flow.emailFinish(formReq('/auth/email/finish', { t: link }, { country: 'NO', cookie: cookieOf(okStart, '__Host-dog_email') }), r)]
  ];
  for (const [label, step] of steps) {
    const r = res();
    await step(r);
    assert.strictEqual(r.statusCode, 451, label);
    assert.match(r.body, /We don’t store anything about you/, label);
    assert.ok(!r.body.includes('example'), label + ': nothing from the request is echoed');
    assert.ok(!cookieOf(r, '__Host-dog_session') && !cookieOf(r, '__Host-dog_region'), label + ': no session, nothing waiting');
  }
  // Asking for an email link from a declined region: the same answer whether or not the address has an account, and
  // for a new address no link is sent and nothing is kept.
  const asked = res();
  await env.flow.emailStart(formReq('/auth/email/start', { email: 'someone@example.ch', ft: stampFor(env, 5000) }, { country: 'CH' }), asked);
  assert.strictEqual(asked.getHeader('Location'), '/join?sent=region');
  assert.strictEqual(mail.length, 0);
  // An agent registering itself from the EU is declined the same way.
  const ag = await agentsApi('POST', 'register', { json: { name: 'Euro agent' }, country: 'IT' });
  assert.strictEqual(ag.status, 451);
  assert.match(ag.json.error, /don’t store anything about you/);
  // Nothing was written anywhere except the daily counts: no member, identity, session, email link, mark, rate limit
  // counter, audit row or JEVs decision. (The email link opened in Norway was already stored, from the US.)
  const after = await tableCounts();
  for (const t of Object.keys(before)) if (t !== 'region_declines') assert.strictEqual(after[t], before[t], t + ' changed');
  for (const cc of ['GB', 'DE', 'CH', 'NO']) assert.strictEqual(await declinesFor(cc), counts[cc] + 1, cc);
  assert.strictEqual(await declinesFor('FR'), counts.FR, 'going to the provider is not a decline');
  assert.deepStrictEqual(Object.keys((await q(`select * from app.region_declines limit 1`))[0]).sort(), ['country', 'day', 'declines', 'id'], 'nothing but the count');
  assert.strictEqual((await run({ actor: 'member', memberId: aaron.id }, (t) => t`select * from app.region_declines`)).length, 0, 'only Aaron reads the counts');
  // The database itself refuses to make an account for a confirmed traveller.
  const refused = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('never seen')], keyVersion: 1, level: 1,
    displayName: 'x', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30, region: 'FR' }));
  assert.deepStrictEqual(refused, { refused: 'region' });
  // Elsewhere, sign-up carries on.
  const { r2: home } = await oauthFlow(env, 'github', '7101', { country: 'US' });
  assert.strictEqual(home.statusCode, 303);
  assert.ok(cookieOf(home, '__Host-dog_session'));
});

test('regional gate, members travelling: a confirmation page first; Cancel stores nothing; Continue signs in and records only that they confirmed', async () => {
  const mail = [];
  const env = signinSetup(mail, { 'github:7201': { accountId: '7201', level: 1, recheckAfter: null }, 'github:7202': { accountId: '7202', level: 1, recheckAfter: null } });
  // A member who joined from the US.
  const { r2: joined } = await oauthFlow(env, 'github', '7201', { country: 'US' });
  const [mem] = await q(`select m.id from app.members m join app.sessions s on s.member_id = m.id where s.token_hash = '${c.sha256hex(cookieOf(joined, '__Host-dog_session').split('=')[1])}'`);
  // Signing in from France: the provider confirms who it is, then the page, before any session.
  const before = await tableCounts();
  const frDeclines = await declinesFor('FR');
  const { r2: asked } = await oauthFlow(env, 'github', '7201', { country: 'FR', query: '?return_to=/proposals' });
  assert.strictEqual(asked.statusCode, 200);
  assert.ok(asked.body.includes(region.confirmText('FR')), 'Aaron\'s words, with the country by name');
  assert.match(asked.body, /By continuing, you confirm that you live outside these regions/);
  assert.ok(!cookieOf(asked, '__Host-dog_session'), 'not signed in yet');
  const waiting = cookieOf(asked, '__Host-dog_region');
  assert.ok(waiting, 'what the sign-in needs waits in a sealed cookie');
  assert.ok(!waiting.includes('7201'), 'sealed: the account isn\'t readable in it');
  assert.deepStrictEqual(await tableCounts(), before, 'nothing stored before they choose');
  // Cancel: the cookie goes, nothing is stored.
  const cancel = res();
  await env.flow.regionCancel(formReq('/auth/region/cancel', {}, { country: 'FR', cookie: waiting }), cancel);
  assert.ok(setCookies(cancel).some((x) => x.startsWith('__Host-dog_region=;') && /Max-Age=0/.test(x)));
  assert.deepStrictEqual(await tableCounts(), before, 'Cancel stores nothing');
  // Continue, from another site or with no waiting sign-in: refused.
  const forged = res();
  await env.flow.regionContinue({ ...formReq('/auth/region/continue', {}, { country: 'FR', cookie: waiting }), headers: { ...formReq('/auth/region/continue', {}, { country: 'FR', cookie: waiting }).headers, origin: 'https://evil.example' } }, forged);
  assert.strictEqual(forged.getHeader('Location'), '/join?error=expired');
  const none = res();
  await env.flow.regionContinue(formReq('/auth/region/continue', {}, { country: 'FR' }), none);
  assert.strictEqual(none.getHeader('Location'), '/join?error=expired');
  // Continue: signed in, back where they started, and the record is exactly when, the country and the member.
  const { r2: again } = await oauthFlow(env, 'github', '7201', { country: 'FR', query: '?return_to=/proposals' });
  const go = res();
  await env.flow.regionContinue(formReq('/auth/region/continue', {}, { country: 'FR', cookie: cookieOf(again, '__Host-dog_region') }), go);
  assert.strictEqual(go.statusCode, 303);
  assert.strictEqual(go.getHeader('Location'), '/proposals');
  const session = cookieOf(go, '__Host-dog_session');
  const residentCookie = cookieOf(go, jevs.RESIDENT);
  assert.ok(session && residentCookie);
  const [conf] = await q(`select actor_kind, actor_id, subject_kind, subject_id, detail, at from app.audit_log where action = 'member.region_confirmed' and subject_id = '${mem.id}'`);
  assert.deepStrictEqual([conf.subject_kind, conf.subject_id, conf.detail], ['member', mem.id, { country: 'FR' }]);
  assert.ok(conf.at);
  assert.strictEqual(await declinesFor('FR'), frDeclines, 'a member is not counted as a declined sign-up');
  // While they travel, that session isn't challenged for where it is: J13 scores 0 with the tag, 40 without it, and
  // a tag copied to another session counts for nothing.
  const memberCtx = { actor: 'member', memberId: mem.id };
  const j13 = async (cookieHeader) => (await run(memberCtx, (t) => jevs.check(t, { action: 'account.check',
    ...jevs.facts({ headers: { cookie: cookieHeader, 'x-vercel-ip-country': 'FR' } }, env.cfg.ipKey) }))).scores.J13;
  assert.strictEqual(await j13(session + '; ' + residentCookie), 0);
  assert.strictEqual(await j13(session), 40);
  const otherSession = (await member({ level: 2, name: 'Other' })).cookie;
  assert.strictEqual(await j13(otherSession + '; ' + residentCookie), 40, 'the tag is bound to its own session');
  // Email: the same answer for an address with an account and one without; only the member's gets a link.
  const em = res();
  await env.flow.emailStart(formReq('/auth/email/start', { email: 'member@example.org', ft: stampFor(env, 5000) }, { country: 'US' }), em);
  const usLink = mail.pop().link.split('#t=')[1];
  const usFinish = res();
  await env.flow.emailFinish(formReq('/auth/email/finish', { t: usLink }, { country: 'US', cookie: cookieOf(em, '__Host-dog_email') }), usFinish);
  assert.ok(cookieOf(usFinish, '__Host-dog_session'), 'an email member joined from the US');
  const known = res();
  await env.flow.emailStart(formReq('/auth/email/start', { email: 'member@example.org', ft: stampFor(env, 5000) }, { country: 'DE' }), known);
  const unknown = res();
  await env.flow.emailStart(formReq('/auth/email/start', { email: 'stranger@example.org', ft: stampFor(env, 5000) }, { country: 'DE' }), unknown);
  assert.strictEqual(known.getHeader('Location'), unknown.getHeader('Location'), 'the reply never says whether an account exists');
  assert.strictEqual(mail.length, 1);
  assert.strictEqual(mail[0].to, 'member@example.org');
  const deLink = mail.pop().link.split('#t=')[1];
  const deFinish = res();
  await env.flow.emailFinish(formReq('/auth/email/finish', { t: deLink }, { country: 'DE', cookie: cookieOf(known, '__Host-dog_email') }), deFinish);
  assert.strictEqual(deFinish.statusCode, 200);
  assert.match(deFinish.body, /You appear to be in Germany\./);
  const deGo = res();
  await env.flow.regionContinue(formReq('/auth/region/continue', {}, { country: 'DE', cookie: cookieOf(deFinish, '__Host-dog_region') }), deGo);
  assert.strictEqual(deGo.getHeader('Location'), '/');
  assert.ok(cookieOf(deGo, '__Host-dog_session'));
  // A signed-in member linking another sign-in method from a declined region confirms too, then it is linked.
  const { r2: linkAsk } = await oauthFlow(env, 'github', '7202', { country: 'CH', query: '?link=1', cookie: session });
  assert.match(linkAsk.body, /You appear to be in Switzerland\./);
  const linked = res();
  await env.flow.regionContinue(formReq('/auth/region/continue', {}, { country: 'CH', cookie: session + '; ' + cookieOf(linkAsk, '__Host-dog_region') }), linked);
  // Linked, and like every link it signs the member out everywhere, here too (PR 15's re-review, R4).
  assert.strictEqual(linked.getHeader('Location'), '/join?linked=1');
  assert.ok(setCookies(linked).some((x) => x.startsWith('__Host-dog_session=') && /Max-Age=0/.test(x)), 'the session cookie is cleared');
  assert.strictEqual((await q(`select count(*)::int as n from app.identities where member_id = '${mem.id}'`))[0].n, 2);
  const logout = res();
  await env.flow.logout(formReq('/auth/logout', {}, { cookie: session }), logout);
  assert.ok(setCookies(logout).some((x) => x.startsWith(jevs.RESIDENT + '=;')), 'signing out clears the tag');
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
  // Rates: per network. There is no ceiling over all GitHub and X sign-ins together, which one attacker with many
  // addresses could fill to lock everyone out (the JEVs review, F8; its repro R10 did).
  assert.ok(!Object.hasOwn(LIMITS, 'signin_all'));
  const outcomes = [];
  for (let i = 0; i < 31; i++) { const r = res(); await env.flow.start(getReq('/auth/github/start', { ip: '198.18.200.7' }), r, 'github'); outcomes.push(r.getHeader('Location').startsWith('/join') ? r.getHeader('Location') : 'provider'); }
  assert.deepStrictEqual([outcomes[0], outcomes[29], outcomes[30]], ['provider', 'provider', '/join?error=slow'], 'one network is limited');
  const elsewhere = res();
  await env.flow.start(getReq('/auth/github/start', { ip: '198.18.201.7' }), elsewhere, 'github');
  assert.ok(/^https:/.test(elsewhere.getHeader('Location')), 'another network is not');
});

test('a sign-up leaves JEVs\'s network mark and lands at level 2 at once; later sign-ins leave none, and an established member is never judged by neighbours (F3)', async () => {
  const env = signinSetup([], { 'github:7301': { accountId: '7301', level: 1, recheckAfter: null } });
  const { r2 } = await oauthFlow(env, 'github', '7301', { ip: '198.19.5.5' });
  assert.strictEqual(r2.statusCode, 303);
  const [m] = await q(`select m.id, m.trust_level from app.members m join app.sessions s on s.member_id = m.id where s.token_hash = '${c.sha256hex(cookieOf(r2, '__Host-dog_session').split('=')[1])}'`);
  assert.strictEqual(m.trust_level, 2, 'a clean GitHub sign-up is promoted at once (no wait)');
  assert.deepStrictEqual((await q(`select kind from app.jevs_marks where member_id = '${m.id}'`)).map((r) => r.kind), ['net']);
  const [d] = await q(`select action, level, effect from app.jevs_decisions where member_id = '${m.id}' and action = 'signup'`);
  assert.deepStrictEqual(d, { action: 'signup', level: 'low', effect: 'promote' });
  // Signing in again, from another network: an account check, and no new mark.
  await oauthFlow(env, 'github', '7301', { ip: '198.19.99.9' });
  assert.strictEqual((await q(`select count(*)::int as n from app.jevs_marks where member_id = '${m.id}'`))[0].n, 1);
  assert.ok((await q(`select 1 from app.jevs_decisions where member_id = '${m.id}' and action = 'account.check'`)).length >= 1);
  // Ten new accounts sign up on an office network. An established member there scores 0 for clusters and posts as
  // usual (the review's repro R3 held this member's post); a new account there is still a cluster.
  await setMode('enforce');
  try {
    const net = c.sha256hex('busy office network');
    const veteran = await member({ level: 2, name: 'Veteran', ageDays: 90 });
    const newcomer = await member({ level: 2, name: 'Newcomer' });
    for (const x of [veteran, newcomer]) await run(x.ctx, (t) => jevs.mark(t, { kind: 'net', keyHash: net }));
    for (let i = 0; i < 10; i++) { const o = await member({ level: 1, name: 'Office ' + i }); await run(o.ctx, (t) => jevs.mark(t, { kind: 'net', keyHash: net })); }
    const vp = await say(veteran, 'An ordinary update from someone who has been here for months.');
    assert.strictEqual(vp.status, 201);
    assert.strictEqual((await decisionsFor(vp.json.id)).pop().scores.J05, 0);
    const np = await say(newcomer, 'An ordinary update from someone who joined on the same network today.');
    assert.strictEqual((await decisionsFor(np.json.id)).pop().scores.J05, 80);
    // A banned member on the same network says nothing about anyone else (F4; the review's repro R4 challenged them).
    const troll = await member({ level: 1, name: 'Troll', ageDays: 2 });
    await run(troll.ctx, (t) => jevs.mark(t, { kind: 'net', keyHash: net }));
    await run(aaron.ctx, (t) => require('../db/controls').setStatus(t, { member: troll.id, status: 'banned' }));
    const vp2 = await say(veteran, 'Another ordinary update, after someone on this network was banned.');
    assert.strictEqual(vp2.status, 201);
    assert.strictEqual((await decisionsFor(vp2.json.id)).pop().scores.J10, 0);
  } finally {
    await setMode('shadow');
  }
});
