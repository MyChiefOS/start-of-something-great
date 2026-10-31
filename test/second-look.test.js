// Second Look v0 (033; Aaron, Oct 30: "lets build second look"): it records, blind, what it would suggest for each post
// JEVs holds for Aaron; it never clears one, never past the floor (checked again by the database), learned only from
// public human-labelled data, and nothing shows its record while it is tested.
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
const sl = require('../secondlook');
const { migrate } = require('../scripts/migrate');
const { trustSystem, promote } = require('./helpers');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

// ---- Without a database ----

test('the floor: a hold that involves anyone but the poster is never "clear", whatever the words', () => {
  const ordinaryWords = 'Great song, I have loved it since the first time I heard it on the radio.';
  for (const q of ['J03', 'J05', 'J06', 'J08', 'J09', 'J10', 'J11', 'J12', 'J14', 'J15', 'J16', 'J17', 'J18', 'J19']) {
    const r = sl.review({ text: ordinaryWords, scores: { J01: 25, [q]: 40 } });
    assert.deepStrictEqual([r.eligible, r.suggestion], [false, 'leave'], q);
    assert.match(r.reasons[0], /^never Second Look’s to clear: /, q);
  }
  assert.deepStrictEqual(sl.review({ text: ordinaryWords, scores: {}, error: true }).suggestion, 'leave', 'a scoring error is never eligible');
  assert.strictEqual(sl.review({ text: ordinaryWords, scores: { J02: 10 } }).eligible, false, 'no single question explains the hold');
  // A small score on a floor question blocks too: a hold can come from small scores adding up (the fresh review's probe).
  const small = sl.review({ text: ordinaryWords, scores: { J05: 20, J07: 25, J01: 10 } });
  assert.deepStrictEqual([small.eligible, small.suggestion, small.reasons], [false, 'leave', ['never Second Look’s to clear: a cluster of new accounts']]);
  assert.strictEqual(sl.review({ text: ordinaryWords, scores: { J07: 50, J09: 'x' } }).eligible, false, 'a score that is not a number blocks');
  assert.deepStrictEqual(sl.ELIGIBLE, ['J01', 'J02', 'J04', 'J07', 'J13']);
  // Within the floor, the words decide.
  assert.strictEqual(sl.review({ text: ordinaryWords, scores: { J01: 25, J07: 50 } }).suggestion, 'clear');
  const spam = sl.review({ text: 'CHECK OUT MY CHANNEL!!! free money http://x.example subscribe now and win', scores: { J07: 75 } });
  assert.deepStrictEqual([spam.eligible, spam.suggestion], [true, 'leave']);
  for (const r of [spam, sl.review({ text: ordinaryWords, scores: { J01: 25 } })]) {
    assert.ok(r.reasons.length >= 1 && r.reasons.length <= 6 && r.reasons.every((x) => x.length <= 200));
    assert.ok(!r.reasons.some((x) => /\d\.\d|threshold/.test(x)), 'reasons never give its score or line');
  }
});

test('v0 learned only from public data people labelled, never from Claude or members; it is small, fast and deterministic', () => {
  const m = sl.MODEL;
  assert.strictEqual(m.version, 'v0');
  assert.strictEqual(m.weights.length, m.buckets);
  assert.ok(m.threshold > 0.5 && m.threshold < 1);
  assert.deepStrictEqual(m.trained.sources, ['UCI YouTube Spam Collection (CC BY 4.0), videos 01-03 for training, 04-05 held out', 'UCI SMS Spam Collection (CC BY 4.0)']);
  assert.ok(fs.statSync(path.join(root, 'secondlook', 'model-v0.json')).size < 200 * 1024);
  const card = read('research/second-look/MODEL-CARD.md');
  assert.match(card, /Nothing in v0 came from:/);
  assert.match(card, /Claude's outputs, as a label or an example \(Anthropic's rule\)/);
  // The same text always gets the same score; hostile text stays fast.
  const t = 'hello there, nice video';
  assert.strictEqual(sl.ordinary(t), sl.ordinary(t));
  const t0 = process.hrtime.bigint();
  sl.review({ text: 'a'.repeat(5000) + ' http://x '.repeat(400), scores: { J07: 100 } });
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 200);
});

test('it is described honestly where people read about it: /team, /privacy, llms.txt', () => {
  assert.match(read('team.html'), /A narrow AI · in testing: decides nothing yet/);
  const p = read('privacy.html');
  assert.match(p, /is also read by Second Look, a small automated model in testing/);
  assert.match(p, /It never decides: a person still decides every held post\./);
  assert.match(p, /never from posts on GitHub/);
  assert.match(read('llms.txt'), /It only suggests: Aaron decides every held post\./);
});

// ---- Against a database ----

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('Second Look tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('Second Look against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const ORIGIN = 'https://dayonegreat.com';
const NAME = 'dog_sl_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
const asOwner = (sqlText) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sqlText); });

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  await trustSystem(su);
  await asOwner(`update app.jevs_settings set value = 'enforce' where key = 'mode'`);
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
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
async function member(name, { admin = false } = {}) {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  await q(`update app.members set created_at = now() - interval '30 days' where id = '${out.memberId}'`);
  if (admin) await asOwner(`update app.members set is_admin = true where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
async function feed(method, { cookie, json, query = {} }) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '203.0.113.62', 'x-vercel-ip-country': 'US' };
  if (method === 'POST') { headers.origin = ORIGIN; headers['content-type'] = 'application/json'; }
  const r = res();
  await require('../api/feed.js').handle({ method, url: '/api/feed', headers, query, body: json === undefined ? undefined : JSON.stringify(json) }, r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
const links = (n) => Array.from({ length: n }, (_, i) => 'https://s' + i + '-' + crypto.randomBytes(3).toString('hex') + '.example').join(' ');

test('a held post gets a blind record beside it; nothing shows it; the database checks the floor itself; it changes nothing', async () => {
  const aaron = await member('Aaron', { admin: true });
  const poster = await member('Poster');
  // Held for links only (eligible): four new sites score J07 at 100, high.
  const a = await feed('POST', { cookie: poster.cookie, json: { body: 'I wrote up my notes from the meetup, they are on these pages ' + links(4) } });
  assert.strictEqual(a.status, 202, JSON.stringify(a.json));
  // Held for contact details too (never eligible).
  const b = await feed('POST', { cookie: poster.cookie, json: { body: 'Reach me at one@example.com, two@example.com or three@example.com about the meetup ' + links(4) } });
  assert.strictEqual(b.status, 202, JSON.stringify(b.json));
  const rows = await q(`select post_id, model, eligible, suggestion, reasons from app.sl_reviews order by created_at`);
  assert.strictEqual(rows.length, 2);
  assert.deepStrictEqual([rows[0].post_id, rows[0].model, rows[0].eligible], [a.json.id, 'v0', true]);
  assert.ok(['clear', 'leave'].includes(rows[0].suggestion));
  assert.deepStrictEqual([rows[1].post_id, rows[1].eligible, rows[1].suggestion], [b.json.id, false, 'leave']);
  assert.match(rows[1].reasons, /never Second Look’s to clear: contact details/);
  // It changed nothing: both posts still wait for Aaron.
  assert.deepStrictEqual((await q(`select status from app.posts where id in ('${a.json.id}', '${b.json.id}')`)).map((r) => r.status), ['waiting', 'waiting']);
  // Blind while it is tested: Aaron's queue doesn't show it, so his decisions stay his own.
  const queue = await feed('GET', { cookie: aaron.cookie, query: { queue: '1' } });
  const item = queue.json.items.find((i) => i.id === b.json.id);
  assert.ok(item, 'the held post is in the queue');
  assert.strictEqual(item.second_look, undefined);
  assert.doesNotMatch(read('review.js'), /second.?look/i);
  // Nobody else reads the record, not even the poster.
  const asPoster = await run(poster.ctx, (t) => t`select count(*)::int as n from app.sl_reviews`);
  assert.strictEqual(asPoster[0].n, 0);
  // Only for a hold JEVs just made: a live post's decision, a second record, or an unknown model gets nothing.
  const live = await feed('POST', { cookie: poster.cookie, json: { body: 'An ordinary post about the meetup, with nothing to hold.' } });
  const decisionOf = async (post) => (await q(`select id from app.jevs_decisions where subject_id = '${post}' order by created_at desc limit 1`))[0].id;
  const record = (decision, eligible, suggestion = eligible ? 'clear' : 'leave', model = 'v0') => run(poster.ctx,
    (t) => t`select app.sl_record(${decision}::uuid, ${model}, ${eligible}, 0.9, ${suggestion}, 'x') as ok`).then((r) => r[0].ok);
  assert.strictEqual(await record(await decisionOf(live.json.id), true), false, 'not a hold');
  assert.strictEqual(await record(await decisionOf(a.json.id), true), false, 'already recorded by this model');
  await assert.rejects(record(await decisionOf(a.json.id), true, 'clear', 'v9'), /unknown Second Look model/);
  // The database works out eligibility from the decision itself and refuses a caller who claims otherwise, small
  // scores included (the second review's finding): a hold on links (J07 30) with a small cluster score (J05 5).
  await q(`delete from app.sl_reviews where post_id in ('${a.json.id}', '${b.json.id}')`);
  const [fake] = await q(`insert into app.jevs_decisions (action, subject_kind, subject_id, member_id, level, mode, effect, applied, error, total, scores)
    values ('post.create', 'post', '${a.json.id}', '${poster.id}', 'high', 'enforce', 'hold', true, false, 35, '{"J07": 30, "J05": 5}') returning id`);
  await assert.rejects(record(fake.id, true), /disagree on eligibility/, 'a small floor score blocks in the database too');
  await assert.rejects(record(await decisionOf(b.json.id), true), /disagree on eligibility/, 'held for contact details: never eligible');
  assert.strictEqual(await record(fake.id, false), true);
  // A failure in Second Look never breaks posting: with its record refused, a post is still held as usual.
  await q(`revoke execute on function app.sl_record(uuid, text, boolean, real, text, text) from dog_app`);
  const c = await feed('POST', { cookie: poster.cookie, json: { body: 'More notes from the meetup on these pages ' + links(4) } });
  await q(`grant execute on function app.sl_record(uuid, text, boolean, real, text, text) to dog_app`);
  assert.strictEqual(c.status, 202, JSON.stringify(c.json));
  assert.deepStrictEqual((await q(`select status from app.posts where id = '${c.json.id}'`)).map((r) => r.status), ['waiting']);
  assert.strictEqual((await q(`select count(*)::int as n from app.sl_reviews where post_id = '${c.json.id}'`))[0].n, 0);
  // The floor holds in the database too: an ineligible "clear" is refused.
  await assert.rejects(q(`insert into app.sl_reviews (post_id, model, eligible, score, suggestion, reasons) values ('${a.json.id}', 'v1', false, 0.9, 'clear', 'x')`), /check/);
  // Deleting the post deletes its record (account deletion deletes posts).
  await q(`delete from app.review_flags where post_id = '${b.json.id}'; delete from app.jevs_prints where post_id = '${b.json.id}'; delete from app.jevs_post_domains where post_id = '${b.json.id}'; delete from app.posts where id = '${b.json.id}'`);
  assert.strictEqual((await q(`select count(*)::int as n from app.sl_reviews where post_id = '${b.json.id}'`))[0].n, 0);
});
