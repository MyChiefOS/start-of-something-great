// 036, app.public_decisions (the design handoff of Nov 5, 2026: /decisions and /api/decisions), against a real
// Postgres built from the migrations: the counts the design shows, from rows in each table it counts; nothing in the
// answer names a member, an agent or a post, or carries a score; any visitor may ask, through the site's role only;
// it changes nothing. Needs TEST_DATABASE_URL (skipped without it, required in CI), like the other database tests.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const decisions = require('../db/decisions');
const { migrate } = require('../scripts/migrate');

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('public decisions tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('public decisions against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_pubdec_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const ask = () => run({ actor: 'anon' }, (t) => decisions.summary(t));
const raw = () => run({ actor: 'anon' }, (t) => t`select app.public_decisions() as d`).then((r) => r[0].d);

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 2 });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

async function member(name) {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  return out.memberId;
}
// A JEVs decision on the site, as the gate's own write would leave it (rows are only ever added, 010).
async function site({ ago = '1 hour', level, effect = 'none', applied = true, error = false, action = 'post.create', agent = null, member = null, scores = {} }) {
  await su`insert into app.jevs_decisions (created_at, action, subject_kind, subject_id, member_id, agent_id, level, mode, effect, applied, error, total, scores)
           values (now() - ${ago}::interval, ${action}, 'post', ${crypto.randomUUID()}, ${member}, ${agent}, ${level}, 'enforce', ${effect}, ${applied}, ${error}, 0, ${su.json(scores)})`;
}
async function github({ ago = '1 hour', risk, effect = 'none', applied = true, action = 'post.create', account, scores = {} }) {
  await su`insert into app.gh_decisions (at, action, member_id, scores, total, risk, mode, effect, applied)
           values (now() - ${ago}::interval, ${action}, ${account}, ${su.json(scores)}, 0, ${risk}, 'enforce', ${effect}, ${applied})`;
}

test('an empty site: every count is zero, the lists are empty, Second Look is in shadow with 0 of 80, and the shape is complete', async () => {
  const d = await ask();
  assert.deepStrictEqual(d.last_24h, { decisions: 0, low: 0, medium_waiting: 0, high: 0, high_held: 0, appeals_open: 0 });
  assert.deepStrictEqual(d.high_7d, []);
  assert.deepStrictEqual(d.second_look, { mode: 'shadow', paused: false, agreed_in_a_row: 0, needed: 80, daily_clear_cap: 10, shadow_clears_decided: 0, shadow_clears_removed: 0 });
  assert.deepStrictEqual(d.oversight, { people: { d7: { decided: 0, approved: 0, removed: 0, undone: 0, median_minutes: null },
    d30: { decided: 0, approved: 0, removed: 0, undone: 0, median_minutes: null } }, queue: { open: 0, median_hours: null, oldest_hours: null } });
  assert.ok(['shadow', 'enforce'].includes(d.jevs_mode));
  assert.ok(!Number.isNaN(Date.parse(d.generated_at)));
});

test('the counts: the last 24 hours from site and GitHub decisions, high-risk days grouped with question IDs only, region declines, Second Look and the queue', async () => {
  const ada = await member('Ada');
  const acct = (await su`insert into app.gh_accounts (github_id, login) values (424242, 'octo-test') returning id`)[0].id;
  // Last 24 hours: 3 low on the site and 2 on GitHub; 2 medium challenges carried out (and 1 in shadow, not counted as
  // waiting); high: 1 held, 1 hidden, 1 recorded only on the site, 1 hidden on GitHub; one older than a day.
  for (let i = 0; i < 3; i++) await site({ level: 'low', member: ada });
  for (let i = 0; i < 2; i++) await github({ risk: 'low', account: acct });
  await site({ level: 'medium', effect: 'challenge' });
  await site({ level: 'medium', effect: 'challenge', action: 'agent.rules' });
  await site({ level: 'medium', effect: 'challenge', applied: false });
  await site({ level: 'high', effect: 'hold', member: ada, scores: { J07: 61, J08: 31, J04: 5 } });
  await site({ level: 'high', effect: 'hold', member: ada, scores: { J09: 25 } });
  await site({ level: 'high', effect: 'hide', applied: false, scores: { J07: 91 } });
  await github({ risk: 'high', effect: 'hide', account: acct, scores: { J16: 41, J17: 83, J01: 10 } });
  await site({ ago: '3 days', level: 'high', effect: 'hold', agent: crypto.randomUUID(), scores: { J04: 70 } });
  await site({ ago: '8 days', level: 'high', effect: 'hold', scores: { J04: 70 } }); // outside the 7 days
  await su`insert into app.region_declines (day, country, declines) values (current_date, 'FR', 2), (current_date, 'DE', 1)`;

  const d = await ask();
  assert.deepStrictEqual(d.last_24h, { decisions: 12, low: 5, medium_waiting: 2, high: 4, high_held: 3, appeals_open: 0 });
  const today = new Date().toISOString().slice(0, 10);
  const find = (place, outcome) => d.high_7d.find((r) => r.place === place && r.outcome === outcome);
  // Two holds of site posts today are one row: a count and the questions that scored 25 or more, sorted; J04 (5) is not.
  assert.deepStrictEqual(find('site_post', 'held'), { day: today, place: 'site_post', outcome: 'held', decisions: 2, questions: ['J07', 'J08', 'J09'] });
  assert.deepStrictEqual(find('site_post', 'recorded_only').questions, ['J07']);
  assert.deepStrictEqual(find('github_post', 'hidden'), { day: today, place: 'github_post', outcome: 'hidden', decisions: 1, questions: ['J16', 'J17'] });
  assert.strictEqual(find('agent_post', 'held').decisions, 1);
  assert.notStrictEqual(find('agent_post', 'held').day, today);
  // Region declines: today's countries added together, and no country named.
  assert.deepStrictEqual(find('signup', 'declined'), { day: today, place: 'signup', outcome: 'declined', decisions: 3, questions: ['region'] });
  assert.strictEqual(d.high_7d.reduce((n, r) => n + r.decisions, 0), 2 + 1 + 1 + 1 + 3, 'the 8-day-old hold is left out');

  // Nothing in the answer names a member, an agent or a post, carries a score or a country, or a time of day.
  const text = JSON.stringify(await raw());
  assert.ok(!text.includes(ada) && !text.includes(acct) && !text.includes('octo-test'), 'no member or account');
  assert.ok(!/"(member|agent|subject|post)(_id)?"|"scores"|"total"|"FR"|"DE"/.test(text), 'no IDs, scores or countries: ' + text.slice(0, 200));
  assert.ok(!/:(61|31|91|41|83)\b/.test(text), 'no score values');
  for (const r of d.high_7d) assert.match(r.day, /^\d{4}-\d{2}-\d{2}$/);
});

test('Second Look: the approvals since its latest removal, out of the unlock count; paused and on are reported as they are', async () => {
  await su`update app.sl_settings set counted_since = now() - interval '1 day'`;
  await su`insert into app.sl_outcomes (decided_at, approved) select now() - (g || ' minutes')::interval, true from generate_series(30, 40) g`;
  await su`insert into app.sl_outcomes (decided_at, approved) values (now() - interval '20 minutes', false)`;
  await su`insert into app.sl_outcomes (decided_at, approved) select now() - (g || ' minutes')::interval, true from generate_series(1, 5) g`;
  let s = (await ask()).second_look;
  assert.deepStrictEqual([s.agreed_in_a_row, s.needed, s.shadow_clears_decided, s.shadow_clears_removed], [5, 80, 17, 1], 'the 11 before the removal do not count');
  await su`update app.sl_settings set paused_reason = 'Paused: test', counted_since = now() - interval '1 day'`;
  s = (await ask()).second_look;
  assert.strictEqual(s.paused, true);
  await su`update app.sl_settings set mode = 'on', paused_reason = null`;
  assert.strictEqual((await ask()).second_look.mode, 'on');
  await su`update app.sl_settings set mode = 'shadow', counted_since = now()`;
  assert.strictEqual((await ask()).second_look.agreed_in_a_row, 0, 'only decisions after counted_since count, as for the unlock');
});

test('human oversight: one row per decision a person made (all flags on a post close together), its median time, and the open queue by post', async () => {
  const ada = await member('Grace');
  // A post with the JEVs decision every post has (010's commit-time rule, app.posts_scored), in one transaction.
  const post = (ago) => su.begin(async (t) => {
    const [p] = await t`insert into app.posts (author_id, body, status, created_at) values (${ada}, 'A post to review', 'waiting', now() - ${ago}::interval) returning id`;
    await t`insert into app.jevs_decisions (action, subject_kind, subject_id, member_id, level, mode, effect, applied, error, total, scores)
            values ('post.create', 'post', ${p.id}, ${ada}, 'low', 'enforce', 'none', true, false, 0, '{}'::jsonb)`;
    return p.id;
  });
  // Three decisions in the last 7 days (an approval, a keep and a removal), one 20 days ago (a removal undone), one
  // 40 days ago (left out); and two posts waiting, one with two open flags.
  const flags = [];
  for (const [ago, took, decision, n] of [['1 day', 10, 'approve', 2], ['2 days', 30, 'keep', 1], ['3 days', 50, 'remove', 1], ['20 days', 120, 'restore', 1], ['40 days', 5, 'remove', 1]]) {
    const p = await post(ago);
    for (let i = 0; i < n; i++) flags.push({ p, ago, took, decision, src: i === 0 ? 'first_posts' : 'classifier' });
  }
  // One transaction, so one decision's flags close at the same moment, as app.review_decide closes them.
  await su.begin(async (t) => { for (const f of flags) {
    await t.unsafe(`insert into app.review_flags (post_id, source, classifier, created_at, resolved_at, resolved_by, decision)
      values ('${f.p}', '${f.src}', ${f.src === 'classifier' ? "'jevs'" : 'null'}, now() - interval '${f.ago}' - interval '${f.took} minutes',
              now() - interval '${f.ago}', '${ada}', '${f.decision}')`);
  } });
  const w1 = await post('5 hours');
  const w2 = await post('1 hour');
  await su`insert into app.review_flags (post_id, source, created_at) values (${w1}, 'first_posts', now() - interval '5 hours')`;
  await su`insert into app.review_flags (post_id, source, classifier, created_at) values (${w1}, 'classifier', 'jevs', now() - interval '2 hours')`;
  await su`insert into app.review_flags (post_id, source, classifier, created_at) values (${w2}, 'classifier', 'jevs', now() - interval '1 hour')`;
  await su`insert into app.review_flags (post_id, source, created_at) values (${w2}, 'appeal', now() - interval '30 minutes')`;

  const d = await ask();
  assert.deepStrictEqual(d.oversight.people.d7, { decided: 3, approved: 2, removed: 1, undone: 0, median_minutes: 30 });
  assert.deepStrictEqual(d.oversight.people.d30, { decided: 4, approved: 2, removed: 1, undone: 1, median_minutes: 40 });
  assert.deepStrictEqual(d.oversight.queue, { open: 2, median_hours: 3, oldest_hours: 5 });
  assert.strictEqual(d.last_24h.appeals_open, 1);
});

test('rights: any visitor may ask through the site’s role; it runs as JEVs’s role, reads only, and no other role may call it', async () => {
  const [f] = await su`select pg_get_userbyid(p.proowner) as owner, p.prosecdef as definer, p.provolatile as vol, p.proconfig as config,
                              has_function_privilege('dog_app', p.oid, 'execute') as app, has_function_privilege('public', p.oid, 'execute') as everyone,
                              has_function_privilege('dog_public', p.oid, 'execute') as pub
                       from pg_proc p where p.proname = 'public_decisions'`;
  assert.deepStrictEqual([f.owner, f.definer, f.vol, f.config, f.app, f.everyone, f.pub], ['dog_jevs', true, 's', ['search_path=pg_catalog'], true, false, false]);
  // Signed out, a member or an agent: the same answer, and the site's role still can't read the tables themselves.
  const [{ n }] = await su`select count(*)::int as n from app.jevs_decisions`;
  assert.ok(n > 0, 'the table has rows');
  await run({ actor: 'anon' }, async (t) => {
    const [seen] = await t`select count(*)::int as n from app.jevs_decisions`;
    assert.strictEqual(seen.n, 0, 'row-level security still hides every decision row from a visitor');
    await assert.rejects(t.savepoint((s) => s`select * from app.gh_decisions limit 1`), (e) => e.code === '42501');
  });
  // Stable and read-only: a write inside it would fail; calling it changes no row.
  const before = await su`select (select count(*) from app.jevs_decisions) a, (select count(*) from app.review_flags) b, (select count(*) from app.sl_outcomes) c`;
  await ask();
  const after = await su`select (select count(*) from app.jevs_decisions) a, (select count(*) from app.review_flags) b, (select count(*) from app.sl_outcomes) c`;
  assert.deepStrictEqual(after, before);
  // The coverage check accepts it: a reviewed definer, owned by its narrow role, callable by the site's role only.
  const { problems } = require('../db/checks');
  const found = (await problems(su)).filter((p) => /public_decisions/.test(p));
  assert.deepStrictEqual(found, []);
});

test('/api/decisions answers from the database: the counts, the question titles and the 20-decision rule, cached a minute', async () => {
  const r = { statusCode: 200, headers: {}, body: '' };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.end = (b) => { r.body = b || ''; };
  await require('../api/decisions').handle({ method: 'GET', url: '/api/decisions', headers: {} }, r, run);
  assert.strictEqual(r.statusCode, 200);
  const d = JSON.parse(r.body);
  assert.strictEqual(d.available, true);
  assert.strictEqual(d.min_sample, 20);
  assert.ok(d.last_24h.decisions > 0);
  assert.strictEqual(d.questions.J16, 'Hidden instructions');
  assert.match(r.headers['cache-control'], /s-maxage=60/);
});
