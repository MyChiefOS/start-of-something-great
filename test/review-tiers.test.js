// Review for a limited, fallible human (041; the design handoff of Nov 5, 2026, CODING_AGENT_SPEC.md section 2, phase
// 4, as Aaron decided it: JEVs and Second Look take the volume, items reach him by risk, no second reviewer, planted
// tests test Second Look). The acceptance tests of 2.6, against a real database:
//   * a synthetic reviewer who approves everything in 1 second sets off the rubber-stamp alert within 50 items;
//   * a canary's truth is committed in the audit log before Second Look decides and revealed after, and tampering
//     with it is caught; a canary is never published; a known-bad one it misses tells Aaron, privately;
//   * no public answer carries a per-person oversight figure;
//   * the overflow rule never approves anything.
// And the parts they rest on: tiers, the hash a decision binds, reasons, Undo, the sample, and held posts first.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const tiers = require('../db/review-tiers');
const { migrate } = require('../scripts/migrate');
const { trustSystem, promote, asSignin } = require('./helpers');

// ---- Without a database ----

test('the canary check: a reveal that hashes to the logged commitment passes; a changed truth, nonce, text or order fails', () => {
  const id = '0190a000-0000-7000-8000-000000000c01';
  const nonce = 'ab'.repeat(16);
  const body = 'A planted test, made from a template.';
  const textSha = tiers.sha256hex(body);
  // 041, after its review (L6): the commitment covers the text too, "id:truth:nonce:SHA-256(text)".
  const commitment = tiers.sha256hex(id + ':bad:' + nonce + ':' + textSha);
  const row = { id, truth: 'bad', nonce, commitment, body, text_sha256: textSha };
  const log = [{ subject_id: id, action: 'review.canary', at: '2026-11-05T10:00:00Z', detail: { commitment } },
    { subject_id: id, action: 'review.canary_result', at: '2026-11-05T10:00:03Z', detail: { truth: 'bad', nonce, commitment, text_sha256: textSha } }];
  assert.deepStrictEqual(tiers.checkCanaries([row], log), { checked: 1, ok: true, problems: [] });
  assert.ok(!tiers.checkCanaries([{ ...row, truth: 'good' }], log).ok, 'the table changed after the fact');
  const flipped = [log[0], { ...log[1], detail: { ...log[1].detail, truth: 'good' } }];
  assert.match(tiers.checkCanaries([{ ...row, truth: 'good' }], flipped).problems.join(), /don’t hash to the commitment/);
  assert.match(tiers.checkCanaries([{ ...row, body: 'Another text.' }], log).problems.join(), /isn’t the text whose hash was committed/);
  assert.match(tiers.checkCanaries([row], [log[1]]).problems.join(), /no commitment/);
  assert.match(tiers.checkCanaries([row], [{ ...log[0], at: '2026-11-05T10:00:09Z' }, log[1]]).problems.join(), /after the decision/);
});

// ---- Against a database ----

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('review tier tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('review tiers against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const ORIGIN = 'https://dayonegreat.com';
const NAME = 'dog_rt_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
const TOKEN = 'oidc.' + 'x'.repeat(40);
const CLEAN = { q1: 'no', q2: 'no', q3: 'no', q4: 'no', q5: 'no', q6: 'no', q7: 'no', q8: 'no', q9: 'yes' };
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
// Since 057 (RK100) Second Look runs in the dog-looks function: its own code, as dog_looks.
const second = async (opts) => (await import('../supabase/functions/dog-looks/core.mjs')).runSecond(su, TOKEN, opts);
const looks = (fn) => su.begin(async (t) => { await t.unsafe('set local role dog_looks'); return fn(t); });
const q = (s) => su.unsafe(s);
const asOwner = (sqlText) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sqlText); });
const answer = (a = CLEAN) => JSON.stringify({ ...a, reason: 'An ordinary post.' });
function gateway(content) {
  return async () => ({ status: 200, json: async () => ({ choices: [{ message: { content: typeof content === 'function' ? content() : content } }] }) });
}

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  // 047 switches Second Look on and its sample re-read to 5% (Aaron, Nov 6: no shadow modes); these tests start from
  // shadow and no sample, as before, to test each step.
  await su.unsafe("update app.sl_settings set mode = 'shadow'");
  await su.unsafe('update app.review_settings set sample_rate = 0');
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
  await trustSystem(su);
  await asOwner(`update app.jevs_settings set value = 'enforce' where key = 'mode'`);
  // No canary at random: the canary test plants its own (the default is a 2% chance with each held post).
  await q('update app.review_settings set canary_rate = 0');
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
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  await q(`update app.members set created_at = now() - interval '30 days' where id = '${out.memberId}'`);
  if (admin) await asOwner(`update app.members set is_admin = true where id = '${out.memberId}'`);
  return { id: out.memberId, cookie: '__Host-dog_session=' + token,
    ctx: { actor: admin ? 'admin' : 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
async function feed(method, { cookie, json, query = {} }) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': '203.0.113.62', 'x-vercel-ip-country': 'US' };
  if (method === 'GET') headers['sec-fetch-site'] = 'same-origin'; // as a browser on the site's own pages sends it (RK145)
  if (method === 'POST') { headers.origin = ORIGIN; headers['content-type'] = 'application/json'; }
  const r = res();
  await require('../api/feed.js').handle({ method, url: '/api/feed', headers, query, body: json === undefined ? undefined : JSON.stringify(json) }, r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
}
async function publicDecisions() {
  const api = require('../api/decisions.js');
  api._forget();
  const r = res();
  await api.handle({ method: 'GET', url: '/api/decisions', headers: {} }, r, run);
  return JSON.parse(r.body);
}
const letters = (k) => Array.from(crypto.randomBytes(k), (x) => String.fromCharCode(97 + (x % 26))).join('');
const links = (n) => Array.from({ length: n }, () => 'https://' + letters(8) + '.example/' + letters(10)).join(' ');
// Random words, so no post reads as a copy of another to J09 (word prints within 10 of 64 bits). The links' shared
// "https" and "example" pull prints together: with 40 words, 3.7 in 10,000 pairs of these posts came within 10 bits
// (measured Nov 9, after a CI run failed on one), with 300, 2 in 8 million. 300 words of 7 letters stay under the
// 5,000-character limit.
const unique = () => Array.from({ length: 300 }, () => letters(7)).join(' ');
// A post JEVs holds for links alone (J07), the kind Second Look may look at.
const held = async (poster, words = 'Notes from the meetup are on these pages') => {
  const r = await feed('POST', { cookie: poster.cookie, json: { body: words + ', ' + unique() + ' ' + links(4) } });
  assert.strictEqual(r.status, 202, JSON.stringify(r.json));
  return r.json.id;
};
const queueOf = async (who) => (await feed('GET', { cookie: who.cookie, query: { queue: '1' } })).json;
const itemOf = async (who, id) => (await queueOf(who)).items.find((i) => i.id === id);
const decideAs = (who, item, decision, reason, extra = {}) => feed('POST', { cookie: who.cookie,
  json: { review: item.id, decision, reason, sha256: item.sha256, ...extra } });
const status = async (id) => (await q(`select status from app.posts where id = '${id}'`))[0].status;
const fresh = () => q('update app.sl_settings set last_claim_at = null');
const tick = async () => { await q('update app.review_settings set last_tick_at = null'); return (await run({ actor: 'anon' }, (t) => t`select app.review_tick() as r`))[0].r; };
// Every held post in the queue decided, so each test starts from an empty queue.
async function drain(who) {
  // A sensitive item (tier 3) needs 10 seconds on screen first, as the page reports it.
  for (const i of (await queueOf(who)).items) await decideAs(who, i, i.actions[0] === 'remove' ? 'remove' : i.actions[0], i.actions[0] === 'remove' ? 'spam' : 'ordinary', i.tier >= 3 ? { seen_ms: 10000 } : {});
}

let aaron, poster;

test('each item has its tier, kind and the SHA-256 of its words; a decision binds that hash and names a reason', async () => {
  aaron = await member('Aaron', { admin: true });
  poster = await member('Poster');
  const id = await held(poster);
  const reads = async () => (await q(`select count(*)::int as n from app.audit_log where action = 'admin.read' and detail->>'area' = 'post_queue'`))[0].n;
  const was = await reads();
  const i = await itemOf(aaron, id);
  assert.strictEqual(await reads(), was + 1, '053 (V-222465): Aaron\'s read of the review queue is recorded');
  const [{ body }] = await q(`select body from app.posts where id = '${id}'`);
  assert.strictEqual(i.sha256, crypto.createHash('sha256').update(body, 'utf8').digest('hex'));
  assert.deepStrictEqual([i.tier, i.item_type], [2, 'held']);
  assert.deepStrictEqual(i.decision_reasons.approve, ['ordinary', 'checked', 'other']);
  assert.deepStrictEqual(i.history, { decided: 0, approved: 0, removed: 0 });
  // No reason, a reason that doesn't fit, "other" without words, or a hash of other words: refused, nothing changes.
  assert.strictEqual((await decideAs(aaron, i, 'approve', undefined)).status, 400);
  assert.strictEqual((await decideAs(aaron, i, 'approve', 'spam')).status, 400);
  assert.strictEqual((await decideAs(aaron, i, 'approve', 'other')).status, 400);
  const wrong = await decideAs(aaron, { ...i, sha256: 'a'.repeat(64) }, 'approve', 'ordinary');
  assert.strictEqual(wrong.status, 409);
  assert.match(wrong.json.error, /aren’t the ones you read/);
  assert.strictEqual(await status(id), 'waiting');
  const ok = await decideAs(aaron, i, 'approve', 'other', { note: 'A friend of the project, links checked', seen_ms: 4200 });
  assert.strictEqual(ok.status, 200, JSON.stringify(ok.json));
  assert.strictEqual(await status(id), 'live');
  const [d] = await q(`select decision, tier, item_type, reason, note, bound_sha256, seen_ms, decided_by from app.review_decisions where post_id = '${id}'`);
  assert.deepStrictEqual(d, { decision: 'approve', tier: 2, item_type: 'held', reason: 'other', note: 'A friend of the project, links checked',
    bound_sha256: i.sha256, seen_ms: 4200, decided_by: aaron.id });
  // A member who isn't a reviewer can't decide, or read the decisions.
  assert.strictEqual((await decideAs(poster, i, 'remove', 'spam')).status, 403);
  assert.strictEqual((await run(poster.ctx, (t) => t`select count(*)::int as n from app.review_decisions`))[0].n, 0);
});

test('Undo: a removal put back within 2 minutes by the same reviewer; nothing else counts as an undo', async () => {
  const id = await held(poster, 'Undo notes');
  const i = await itemOf(aaron, id);
  assert.strictEqual((await decideAs(aaron, i, 'restore', 'undo')).status, 409, 'nothing to undo yet');
  assert.strictEqual((await decideAs(aaron, i, 'remove', 'spam')).status, 200);
  assert.strictEqual(await status(id), 'removed');
  const u = await decideAs(aaron, i, 'restore', 'undo', { seen_ms: 0 });
  assert.strictEqual(u.status, 200, JSON.stringify(u.json));
  assert.strictEqual(await status(id), 'waiting', 'a never-approved post goes back to the queue');
  assert.strictEqual((await decideAs(aaron, i, 'restore', 'undo')).status, 409, 'once');
  await drain(aaron);
});

test('sensitive items are tier 3 and come first: a report of private information, or contact details JEVs found', async () => {
  const a = await held(poster, 'Ordinary held notes');
  const live = (await feed('POST', { cookie: poster.cookie, json: { body: 'A plain post about the reading group and the next meeting, nothing more to it.' } })).json.id;
  assert.strictEqual(await status(live), 'live');
  const reporter = await member('Reporter');
  const rep = await feed('POST', { cookie: reporter.cookie, json: { report: live, reason: 'private_info' } });
  assert.strictEqual(rep.status, 202, JSON.stringify(rep.json));
  const items = (await queueOf(aaron)).items;
  assert.deepStrictEqual(items.map((i) => [i.id, i.tier, i.item_type]).slice(0, 2), [[live, 3, 'reported'], [a, 2, 'held']], 'highest tier first');
  // Sensitive: 10 seconds on screen first (the database refuses a quicker decision), then it is decided.
  const quick = await decideAs(aaron, items[0], 'keep', 'not_upheld', { seen_ms: 4000 });
  assert.deepStrictEqual([quick.status, /10 seconds on screen/.test(quick.json.error)], [409, true]);
  assert.strictEqual((await decideAs(aaron, items[0], 'keep', 'not_upheld', { seen_ms: 10000 })).status, 200);
  const [d] = await q(`select tier, item_type from app.review_decisions where post_id = '${live}'`);
  assert.deepStrictEqual(d, { tier: 3, item_type: 'reported' });
  await drain(aaron);
});

test('2.6: a synthetic reviewer approving everything in 1 second sets off the rubber-stamp alert within 50 items, and Aaron is told in-app', async () => {
  const ids = [];
  for (let n = 0; n < 50; n++) ids.push(await held(poster, 'Batch ' + n));
  const items = (await queueOf(aaron)).items;
  let fired = null;
  for (let n = 0; n < 50; n++) {
    const i = items.find((x) => x.id === ids[n]);
    const r = await decideAs(aaron, i, 'approve', 'ordinary', { seen_ms: 1000 });
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    const [a] = await q(`select app.review_alerts_core(now() + interval '1 second', false) as a`);
    if (fired === null && a.a.some((x) => x.id === 'rubber_stamp')) fired = n + 1;
  }
  // The earlier tests' 2 approvals took 4.2 and 0 seconds, so the 7-day window passes 50 decisions within this batch.
  assert.ok(fired !== null && fired <= 50, 'fired at ' + fired);
  const t = await tick();
  assert.strictEqual(t.ran, true);
  const [n] = await q(`select count(*)::int as n from app.notices where member_id is null and kind = 'alert' and dedupe_key like 'review:alert:rubber_stamp:%'`);
  assert.strictEqual(n.n, 1, 'one in-app notice');
  await tick();
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where dedupe_key like 'review:alert:rubber_stamp:%'`))[0].n, 1, 'once a day');
  // Never public: it is about Aaron's own decisions, which are his (Nov 5). The public alerts are about JEVs and Second
  // Look only (the planted tests and the sample).
  const [p] = await su.begin(async (x) => { await x.unsafe("set local role dog_jevs"); return x`select app.review_alerts_core(date_trunc('hour', now()) + interval '1 hour', true) as a`; });
  assert.ok(!p.a.some((x) => x.id === 'rubber_stamp'));
  assert.ok(!(await publicDecisions()).review.alerts.some((x) => x.id === 'rubber_stamp'));
});

test('2.6: no public answer carries a per-person oversight figure: the public figures are JEVs\'s and Second Look\'s only, and Aaron\'s are his', async () => {
  const id = await held(poster, 'Removed notes');
  assert.strictEqual((await decideAs(aaron, await itemOf(aaron, id), 'remove', 'spam', { seen_ms: 9000 })).status, 200);
  const d = await publicDecisions();
  assert.ok(d.review, JSON.stringify(d).slice(0, 300));
  const text = JSON.stringify(d.review);
  for (const who of [aaron, poster]) assert.ok(!text.includes(who.id), 'no member id');
  for (const k of ['decided_by', 'member', 'reviewer', 'people', 'Aaron', 'median_seconds', 'hours']) assert.ok(!text.includes(k), 'no ' + k);
  // What JEVs and Second Look did, by window, from days counted once (never recounted), and the limits they run under.
  assert.deepStrictEqual(Object.keys(d.review).sort(), ['alerts', 'counted_through', 'd30', 'd7', 'limits']);
  assert.ok(d.review.alerts.every((x) => ['canary_catch', 'sample_cap', 'sample_unread'].includes(x.id)), JSON.stringify(d.review.alerts));
  // The function itself: whoever is asking, the same counts, with nothing grouped by person or read from his decisions.
  const src = (await q(`select prosrc from pg_proc where proname = 'public_oversight'`))[0].prosrc;
  assert.doesNotMatch(src, /decided_by|review_decisions/);
  assert.doesNotMatch((read('decisions.js') + read('status.js')).replace(/\/\/.*$/gm, ''), /decided_by|per[_ ]person|reviewer_id/);
  // His own figures are on /admin/controls, for him only.
  const mine = await run(aaron.ctx, (t) => tiers.adminView(t));
  assert.ok(mine && mine.mine, 'the administrator sees his own');
  await assert.rejects(run(poster.ctx, (t) => tiers.adminView(t)));
});

test('2.6: over the budget, items wait with their age shown and nothing is ever approved to clear them', async () => {
  await drain(aaron);
  await q('update app.review_settings set daily_budget = 1');
  const ids = [await held(poster, 'Over budget one'), await held(poster, 'Over budget two'), await held(poster, 'Over budget three')];
  let qd = await queueOf(aaron);
  const used0 = qd.budget.used;
  assert.ok(used0 >= 1, 'already past today\'s budget of 1');
  // The timers, Second Look in shadow and the tick all run: nothing waiting changes.
  await fresh();
  await second({ fetchImpl: gateway(answer()) });
  await tick();
  await require('../api/cron.js').handle({ method: 'GET', headers: {} }, res(), run, { now: () => Date.now() + 3600e3 });
  for (const id of ids) assert.strictEqual(await status(id), 'waiting', id);
  assert.strictEqual((await q(`select count(*)::int as n from app.review_flags where post_id in ('${ids.join("','")}') and resolved_at is null`))[0].n >= 3, true);
  assert.strictEqual((await q(`select count(*)::int as n from app.review_decisions where post_id in ('${ids.join("','")}')`))[0].n, 0, 'no decision by anyone');
  qd = await queueOf(aaron);
  assert.deepStrictEqual(qd.budget, { daily: 1, used: used0 });
  assert.ok(ids.every((id) => qd.items.some((i) => i.id === id && i.flagged_at)), 'all still listed, each with its age');
  // He can keep deciding: the budget is a measure, never a lock.
  assert.strictEqual((await decideAs(aaron, qd.items.find((i) => i.id === ids[0]), 'approve', 'ordinary')).status, 200);
  // The budget is his to set, 1 to 500, and recorded.
  assert.strictEqual((await feed('POST', { cookie: aaron.cookie, json: { review_settings: { daily_budget: 30 } } })).status, 200);
  assert.strictEqual((await feed('POST', { cookie: aaron.cookie, json: { review_settings: { daily_budget: 0 } } })).status, 400);
  assert.strictEqual((await feed('POST', { cookie: poster.cookie, json: { review_settings: { daily_budget: 30 } } })).status, 403);
  assert.strictEqual((await q(`select daily_budget from app.review_settings`))[0].daily_budget, 30);
  assert.strictEqual((await q(`select count(*)::int as n from app.audit_log where action = 'review.settings' and detail ? 'daily_budget'`))[0].n, 1); // 047's sample switch is the other
  await drain(aaron);
});

test('2.6: a canary\'s truth is committed in the log before Second Look decides and revealed after; it is never published; tampering is caught', async () => {
  await q('update app.review_settings set canary_rate = 1');
  // 041, after its review: canaries are made ahead of time from templates filled with random words, and handed out
  // only once 5 minutes old. Here: only known-bad templates, one canary made and aged, and none other waiting.
  await q(`update app.review_canary_templates set retired = (truth = 'good')`);
  await q(`update app.review_canaries set claimed_at = now() where claimed_at is null`);
  const [made] = await q(`select app.review_canary_make() as id`);
  await q(`update app.review_canaries set created_at = created_at - interval '6 minutes' where id = '${made.id}'`);
  const id = await held(poster, 'Canary carrier notes');
  await fresh();
  const seen = [];
  const claimed = await looks((t) => t`select * from app.sl_claim(3)`);
  assert.strictEqual(claimed.length, 2, 'the held post and one canary');
  const canary = claimed.find((x) => x.post_id !== id);
  // The same shape as a held post: words, the questions that held it, an account, a sign-in, the model.
  assert.deepStrictEqual(Object.keys(canary).sort(), Object.keys(claimed.find((x) => x.post_id === id)).sort());
  assert.ok(canary.held.length > 0 && canary.body.length > 0);
  const [planted] = await q(`select at, detail from app.audit_log where action = 'review.canary' and subject_id = '${canary.post_id}'`);
  assert.match(planted.detail.commitment, /^[0-9a-f]{64}$/);
  assert.strictEqual(JSON.stringify(planted.detail).includes('bad'), false, 'the truth isn\'t in the commitment entry');
  // Second Look clears both (a known-bad canary slips through).
  const decide = (post) => looks((t) => t`select app.sl_decide(${post}::uuid, 'v1', 'mistral/ministral-3b', 'clear', ${t.json(CLEAN)}::jsonb, 0, 'fine', false, null, 10) as r`).then((r) => r[0].r);
  seen.push(await decide(canary.post_id), await decide(id));
  assert.deepStrictEqual(seen, ['logged', 'logged']);
  assert.strictEqual(await decide(canary.post_id), 'refused', 'once');
  const [result] = await q(`select at, detail from app.audit_log where action = 'review.canary_result' and subject_id = '${canary.post_id}'`);
  assert.ok(new Date(planted.at) <= new Date(result.at));
  assert.strictEqual(result.detail.truth, 'bad');
  assert.strictEqual(result.detail.caught, false);
  assert.strictEqual(canary.post_id, made.id, 'the one made ahead');
  assert.strictEqual(result.detail.text_sha256, crypto.createHash('sha256').update(canary.body).digest('hex'), 'the text shown is the text committed');
  assert.strictEqual(crypto.createHash('sha256').update(canary.post_id + ':bad:' + result.detail.nonce + ':' + result.detail.text_sha256).digest('hex'), planted.detail.commitment);
  // Never a post; a private, non-punitive notice to Aaron saying what it was.
  assert.strictEqual((await q(`select count(*)::int as n from app.posts where id = '${canary.post_id}'`))[0].n, 0);
  const [note] = await q(`select title, body from app.notices where dedupe_key = 'review:canary:${canary.post_id}'`);
  assert.strictEqual(note.title, 'A planted test slipped through Second Look');
  assert.match(note.body, /Here is what it was/);
  // The administrator's view checks every reveal against the log.
  const view = await run(aaron.ctx, (t) => tiers.adminView(t));
  assert.deepStrictEqual(view.canaries.check, { checked: 1, ok: true, problems: [] });
  assert.deepStrictEqual([view.canaries.bad, view.canaries.bad_caught], [1, 0]);
  // Tampering: the log can't be changed, and a changed table is caught.
  await assert.rejects(q(`update app.audit_log set detail = '{}' where action = 'review.canary' and subject_id = '${canary.post_id}'`));
  // (As the test's superuser, who passes row-level security: the site's roles can't write the table at all.)
  await q(`update app.review_canaries set truth = 'good' where id = '${canary.post_id}'`);
  const after = await run(aaron.ctx, (t) => tiers.adminView(t));
  assert.strictEqual(after.canaries.check.ok, false);
  assert.match(after.canaries.check.problems.join(), /differs/);
  // Nobody but JEVs's role reads a canary's truth: not the site's role, not the administrator.
  await assert.rejects(run(aaron.ctx, (t) => t`select truth from app.review_canaries`), /permission denied/);
  // In public, counts only (exact: they are about Second Look, not anyone's posts), once its day has ended a day ago.
  await q(`update app.review_canaries set truth = 'bad' where id = '${canary.post_id}'`); // the tampering above, put back
  await q(`update app.review_canaries set created_at = created_at - interval '3 days', claimed_at = claimed_at - interval '3 days', decided_at = decided_at - interval '3 days' where id = '${canary.post_id}'`);
  const [{ d: day }] = await q(`select ((claimed_at at time zone 'UTC')::date)::text as d from app.review_canaries where id = '${canary.post_id}'`);
  await q(`update app.review_settings set counted_through = '${day}'::date - 1`);
  await tick();
  const pub = await publicDecisions();
  assert.ok(pub.review.d30.canaries.bad >= 1, JSON.stringify(pub.review.d30.canaries));
  assert.strictEqual(pub.review.d30.canaries.bad_caught, 0, 'it slipped through, and the public figure says so');
  assert.ok(!JSON.stringify(pub.review).includes(canary.post_id) && !JSON.stringify(pub.review).includes(canary.body), 'never the canary itself');
  await q(`update app.review_settings set canary_rate = 0`);
  await q(`update app.review_canary_templates set retired = false`);
});

test('the sample: 5% of low-risk posts drawn while Second Look runs, re-read after held posts, a reject comes to Aaron and stays up', async () => {
  await drain(aaron);
  await q('update app.review_settings set sample_rate = 1');
  // A poster of its own: the batch above makes the first poster's next posts unusually busy for them (J04).
  const quiet = await member('Quiet poster');
  const live = (await feed('POST', { cookie: quiet.cookie, json: { body: 'A plain note on the reading group, nothing to hold: ' + unique() } })).json.id;
  assert.strictEqual(await status(live), 'live');
  await q(`update app.sl_settings set mode = 'off'`);
  assert.strictEqual((await tick()).sampled, 0, 'not while Second Look is off');
  await q(`update app.sl_settings set mode = 'shadow'`);
  const live2 = (await feed('POST', { cookie: quiet.cookie, json: { body: 'Another plain note on the reading group: ' + unique() } })).json.id;
  assert.strictEqual((await tick()).sampled, 1);
  assert.strictEqual((await q(`select count(*)::int as n from app.review_samples where post_id = '${live2}'`))[0].n, 1);
  // Held posts come first: with one slot, the held post is claimed and the sample waits.
  // (Its own poster too: the first poster's removed posts now count against its track record, J10, outside the gate.)
  const h = await held(quiet, 'Held before the sample');
  await fresh();
  let claimed = await looks((t) => t`select post_id, held from app.sl_claim(1)`);
  assert.deepStrictEqual(claimed.map((x) => x.post_id), [h], JSON.stringify(claimed) + JSON.stringify(await q(`select key, value from app.jevs_decisions d, jsonb_each(d.scores) where d.subject_id = '${h}' and value::text <> '0'`)) + JSON.stringify(await q(`select source, classifier, resolved_at from app.review_flags where post_id = '${h}'`)));
  await fresh();
  claimed = await looks((t) => t`select post_id, held from app.sl_claim(1)`);
  assert.deepStrictEqual(claimed.map((x) => [x.post_id, x.held]), [[live2, []]]);
  // Its re-read rejects it: it stays live and comes to Aaron as a sample, flagged by Second Look.
  const r = await looks((t) => t`select app.sl_decide(${live2}::uuid, 'v1', 'mistral/ministral-3b', 'reject', ${t.json({ ...CLEAN, q8: 'yes' })}::jsonb, 90, 'breaks the terms', false, null, 10) as r`);
  assert.strictEqual(r[0].r, 'logged');
  assert.strictEqual(await status(live2), 'live');
  const item = await itemOf(aaron, live2);
  assert.deepStrictEqual([item.item_type, item.classifiers, item.actions], ['sampled', ['secondlook'], ['keep', 'remove']]);
  assert.match(item.classifier_labels.secondlook, /5% sample/);
  // Not counted as one of Second Look's held-post decisions (its unlock and report stay as they were).
  assert.strictEqual((await q(`select count(*)::int as n from app.sl_decisions where post_id = '${live2}'`))[0].n, 0);
  assert.strictEqual((await decideAs(aaron, item, 'keep', 'ordinary')).status, 200);
  // Counted once a day, for days that ended at least a day ago, and never recounted; in public, 1 to 4 is "fewer than 5".
  // Six days back: a day the canary test above didn't count (a counted day is never recounted).
  await q(`update app.review_samples set sampled_at = sampled_at - interval '6 days'`);
  const [{ d: day }] = await q(`select (min(sampled_at) at time zone 'UTC')::date::text as d from app.review_samples`);
  await q(`update app.review_settings set counted_through = '${day}'::date - 1`);
  await tick();
  const [row] = await q(`select sample_drawn, sample_flagged from app.review_public_days where day = '${day}'`);
  assert.ok(row.sample_drawn >= 1 && row.sample_flagged >= 1, JSON.stringify(row));
  const pub = await publicDecisions();
  assert.strictEqual(pub.review.d7.sample_flagged, null, 'fewer than 5 shows as null, never the number');
  await q('update app.review_settings set sample_rate = 0.05');
  void live;
});

const read = (f) => require('fs').readFileSync(require('path').join(__dirname, '..', f), 'utf8');
