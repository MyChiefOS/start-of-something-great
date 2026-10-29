// 030: the JEVs behaviour watch's web indicators (Aaron, Oct 29). Each one alerts Aaron's inbox, once, and nothing it
// does refuses, slows past a lock or signs anyone out. What the database keeps is keyed or sealed, never readable.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const controls = require('../db/controls');
const agents = require('../db/agents');
const watch = require('../signin/watch');
const session = require('../signin/session');
const { migrate } = require('../scripts/migrate');
const { trustSystem, shadowMode, promote } = require('./helpers');

// The site's first fingerprint key, as the key broker hands it over (route B). A stand-in.
const GATE_KEY = Buffer.from('w'.repeat(40), 'utf8');
process.env.FINGERPRINT_KEY_1 = GATE_KEY.toString('base64');

const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0';
const FIREFOX_NEXT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0';
const SAFARI_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
const NYC = { lat: '40.7128', lon: '-74.0060', country: 'US' };
const BOSTON = { lat: '42.3601', lon: '-71.0589', country: 'US' };
const MOSCOW = { lat: '55.7558', lon: '37.6173', country: 'RU' };

test('browser kinds keep only the name and system, places only whole degrees, and distances are great-circle km', () => {
  assert.strictEqual(watch.family(FIREFOX), 'firefox/windows');
  assert.strictEqual(watch.family(FIREFOX_NEXT), 'firefox/windows', 'an update is not a different browser');
  assert.strictEqual(watch.family(SAFARI_IOS), 'safari/ios');
  assert.strictEqual(watch.family('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'), 'chrome/mac');
  assert.strictEqual(watch.family('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0'), 'edge/windows');
  assert.strictEqual(watch.family('curl/8.5.0'), 'script/other');
  assert.strictEqual(watch.family(''), null);
  assert.deepStrictEqual(watch.place({ headers: { 'x-vercel-ip-latitude': '40.7128', 'x-vercel-ip-longitude': '-74.0060' } }), { la: 41, lo: -74 });
  assert.strictEqual(watch.place({ headers: {} }), null);
  assert.strictEqual(watch.place({ headers: { 'x-vercel-ip-latitude': '91', 'x-vercel-ip-longitude': '0' } }), null);
  assert.strictEqual(watch.place({ headers: { 'x-vercel-ip-latitude': 'x', 'x-vercel-ip-longitude': '0' } }), null);
  const d = watch.km({ la: 41, lo: -74 }, { la: 56, lo: 38 });
  assert.ok(d > 7300 && d < 7700, 'New York to Moscow is about 7,500 km: ' + d);
  assert.strictEqual(Math.round(watch.km({ la: 10, lo: 10 }, { la: 10, lo: 10 })), 0);
  assert.strictEqual(watch.key({}), null, 'no key, no watch');
  // A sealed place is the same length wherever it is, and opens only with the key (the CSO's review, S2).
  const k = Buffer.from('k'.repeat(40));
  const places = [{ la: 41, lo: -74 }, { la: 1, lo: 1 }, { la: -23, lo: -120 }, { la: 51, lo: 0 }, { la: -90, lo: 180 }];
  const sealed = places.map((p) => watch.sealPlace(k, p));
  assert.strictEqual(new Set(sealed.map((x) => x.length)).size, 1, sealed.map((x) => x.length).join());
  assert.deepStrictEqual(sealed.map((x) => watch.openPlace(k, x)), places);
  assert.strictEqual(watch.openPlace(Buffer.from('x'.repeat(40)), sealed[0]), null, 'another key opens nothing');
});

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('watch tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the web behaviour watch (030)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
} else {
  const NAME = 'dog_watchweb_test_' + crypto.randomBytes(4).toString('hex');
  const WEB = NAME + '_web';
  const PW = crypto.randomBytes(18).toString('base64url');
  const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
  let server, su, web;
  const run = (ctx, fn) => db.tx(web, ctx, fn);
  const owner = async (q) => [...await su.unsafe(q)];
  const asOwner = (q) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); return t.unsafe(q); });

  test.before(async () => {
    server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
    await server.unsafe('create database ' + NAME);
    su = postgres(at(NAME), { max: 2, ssl: false, onnotice: () => {} });
    await migrate(su);
    await shadowMode(su);
    await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
    web = db.connect(at(NAME, WEB, PW), { ssl: false, max: 3 });
    await trustSystem(su);
  });
  test.after(async () => {
    for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
    if (server) {
      await server.unsafe(`drop database if exists ${NAME} with (force)`);
      await server.unsafe(`drop role if exists ${WEB}`);
      await server.end({ timeout: 5 });
    }
  });

  // A member signed in in one browser: its session token, as the cookie carries it.
  async function member(name) {
    const token = c.token(32);
    const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())],
      keyVersion: 1, level: 1, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
    return { id: out.memberId, token, hash: c.sha256hex(token) };
  }
  async function browser(m) {
    const token = c.token(32);
    const [{ fingerprint }] = await owner(`select fingerprint from app.identities where member_id = '${m.id}'`);
    await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [fingerprint],
      keyVersion: 1, level: 1, displayName: 'x', sessionHash: c.sha256hex(token), sessionDays: 30 }));
    return { ...m, token, hash: c.sha256hex(token) };
  }
  // A request with that session, as Vercel delivers it.
  const ask = (s, { ua = FIREFOX, where = NYC } = {}) => {
    const headers = { cookie: session.SESSION + '=' + s.token, 'user-agent': ua };
    if (where) {
      headers['x-vercel-ip-country'] = where.country;
      if (where.lat) { headers['x-vercel-ip-latitude'] = where.lat; headers['x-vercel-ip-longitude'] = where.lon; }
    }
    return session.current({ headers }, run);
  };
  const alerts = async (like, about = null) => (await owner(`select title from app.notices where member_id is null and kind = 'alert'
    and dedupe_key like '${like}'` + (about ? ` and subject_id = '${about}'` : '') + ' order by created_at')).map((r) => r.title);

  test('a session used from another browser or country alerts once for the session, and the request is served', async () => {
    const m = await member('Mover');
    assert.ok(await ask(m), 'signed in');
    assert.ok(await ask(m, { ua: FIREFOX_NEXT }), 'an update to the same browser');
    assert.deepStrictEqual(await alerts('watch:moved:%', m.id), []);
    assert.ok(await ask(m, { ua: SAFARI_IOS }), 'still signed in: the watch never refuses');
    assert.ok(await ask(m, { ua: SAFARI_IOS }));
    assert.deepStrictEqual(await alerts('watch:moved:browser:%', m.id), ['A session moved to another browser'], 'once for the session');
    assert.ok(await ask(m, { where: BOSTON }), 'the same country');
    assert.ok(await ask(m, { where: { country: 'CA' } }));
    assert.ok(await ask(m, { where: { country: 'MX' } }));
    assert.deepStrictEqual(await alerts('watch:moved:country:%', m.id), ['A session was used from another country'], 'once for the session');
    // Only keyed hashes are kept, and each includes the member's ID.
    const [w] = await owner(`select w.ua_hash, w.country_hash from app.watch_sessions w join app.sessions s on s.id = w.session_id where s.token_hash = '${m.hash}'`);
    assert.strictEqual(w.ua_hash, c.hmacHex(GATE_KEY, 'watch-ua:' + m.id + ':firefox/windows'));
    assert.strictEqual(w.country_hash, c.hmacHex(GATE_KEY, 'watch-country:' + m.id + ':US'));
    // A second browser of the same member is its own session, with its own first browser.
    const other = await browser(m);
    assert.ok(await ask(other, { ua: SAFARI_IOS }));
    assert.strictEqual((await alerts('watch:moved:browser:%', m.id)).length, 1);
    // The row goes with the session.
    await run({ actor: 'member', memberId: m.id, session: other.hash }, (t) => store.sessionEnd(t, other.hash));
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_sessions w where not exists (select 1 from app.sessions s where s.id = w.session_id)`))[0].n, 0);
  });

  test('travel faster than possible alerts once a day; a nearby place, or one that wasn\'t estimated, doesn\'t', async () => {
    const m = await member('Traveller');
    assert.ok(await ask(m, { where: NYC }));
    // The place is sealed: the database can't read it, and it is no coordinate.
    const [a] = await owner(`select place, place_at from app.watch_activity where member_id = '${m.id}'`);
    assert.ok(a.place && a.place_at && a.place.length >= 40);
    assert.ok(!a.place.includes('"la"'), 'not readable');
    const near = await browser(m);
    assert.ok(await ask(near, { where: BOSTON }), 'Boston, about 300 km: not past the minimum distance');
    assert.deepStrictEqual(await alerts('watch:travel:%', m.id), []);
    const far = await browser(m);
    assert.ok(await ask(far, { where: MOSCOW }), 'still served');
    assert.deepStrictEqual(await alerts('watch:travel:%', m.id), ['Travel too fast to be possible']);
    const [body] = await owner(`select body from app.notices where dedupe_key like 'watch:travel:%' and subject_id = '${m.id}'`);
    assert.match(body.body, /about 7\d{3} km apart within \d+ minutes?, faster than 1000 km\/h/);
    const back = await browser(m);
    assert.ok(await ask(back, { where: NYC }));
    assert.strictEqual((await alerts('watch:travel:%', m.id)).length, 1, 'once a day');
    // The same session is compared at most once an hour: its next request costs no comparison.
    const before = (await owner(`select place from app.watch_activity where member_id = '${m.id}'`))[0].place;
    assert.ok(await ask(back, { where: MOSCOW }));
    assert.strictEqual((await owner(`select place from app.watch_activity where member_id = '${m.id}'`))[0].place, before);
    // A slow journey is fine: the same distance over a day is about 300 km/h.
    const slow = await member('Slow traveller');
    assert.ok(await ask(slow, { where: NYC }));
    await su.unsafe(`update app.watch_activity set place_at = now() - interval '20 hours' where member_id = '${slow.id}'`);
    assert.ok(await ask(await browser(slow), { where: MOSCOW }));
    assert.deepStrictEqual(await alerts('watch:travel:%', slow.id), []);
    // No estimate from the host: nothing compared, nothing kept for the request.
    const none = await member('Nowhere');
    assert.ok(await ask(none, { where: { country: 'US' } }));
    assert.strictEqual((await owner(`select place from app.watch_activity where member_id = '${none.id}'`))[0].place, null);
  });

  test('activity at an hour an account with a long history has never used alerts once a day', async () => {
    const m = await member('Night owl');
    assert.ok(await ask(m, { where: null }));
    const [{ h }] = await owner(`select extract(hour from now() at time zone 'UTC')::int as h`);
    // 30 days of history, 120 active hours, none in this hour or the hours either side.
    await su.unsafe(`delete from app.watch_hours where member_id = '${m.id}'`);
    const hours = [...Array(24).keys()].filter((x) => ![h, (h + 23) % 24, (h + 1) % 24].includes(x));
    await su.unsafe(`insert into app.watch_hours (member_id, hour, n) select '${m.id}', x, 6 from unnest(array[${hours.join(',')}]::smallint[]) x`);
    await su.unsafe(`update app.watch_activity set first_seen = now() - interval '30 days', counted_hour = null where member_id = '${m.id}'`);
    assert.ok(await ask(m, { where: null }), 'served');
    assert.deepStrictEqual(await alerts('watch:hours:%', m.id), ['Activity at an unusual hour']);
    await su.unsafe(`update app.watch_activity set counted_hour = null where member_id = '${m.id}'`);
    assert.ok(await ask(m, { where: null }));
    assert.strictEqual((await alerts('watch:hours:%', m.id)).length, 1, 'once a day');
    // A short history never alerts.
    const n = await member('Newcomer');
    assert.ok(await ask(n, { where: null }));
    await su.unsafe(`update app.watch_activity set first_seen = now() - interval '5 days', counted_hour = null where member_id = '${n.id}'`);
    await su.unsafe(`insert into app.watch_hours (member_id, hour, n) select '${n.id}', x, 6 from unnest(array[${hours.join(',')}]::smallint[]) x on conflict (member_id, hour) do nothing`);
    assert.ok(await ask(n, { where: null }));
    assert.deepStrictEqual(await alerts('watch:hours:%', n.id), []);
    // Counted once an hour; past four times the minimum history it is halved, and hours counted once go.
    await su.unsafe(`update app.watch_hours set n = 30 where member_id = '${m.id}'`);
    await su.unsafe(`insert into app.watch_hours (member_id, hour, n) values ('${m.id}', ${(h + 12) % 24}, 1) on conflict (member_id, hour) do update set n = 1`);
    await su.unsafe(`update app.watch_activity set counted_hour = null where member_id = '${m.id}'`);
    assert.ok(await ask(m, { where: null }));
    const rows = await owner(`select hour, n from app.watch_hours where member_id = '${m.id}' order by hour`);
    assert.ok(rows.every((r) => r.n === 15 || (r.hour === h && r.n === 2)), JSON.stringify(rows));
    assert.ok(!rows.some((r) => r.hour === (h + 12) % 24), 'an hour counted once went');
  });

  test('requests past the floor and many times the usual hour of use alert once a day', async () => {
    await asOwner('update app.watch_settings set requests_floor = 10');
    const m = await member('Scraper');
    for (let i = 0; i < 9; i++) assert.ok(await ask(m, { where: null }));
    assert.deepStrictEqual(await alerts('watch:requests:%', m.id), []);
    assert.ok(await ask(m, { where: null }), 'the 10th is served too');
    assert.deepStrictEqual(await alerts('watch:requests:%', m.id), ['Unusually many requests from one account']);
    for (let i = 0; i < 15; i++) await ask(m, { where: null });
    assert.strictEqual((await alerts('watch:requests:%', m.id)).length, 1, 'once a day');
    // An account that is always this busy doesn't alert.
    // An account as busy as this every day, though only for an hour a day, doesn't alert: its usual hour is the hours it
    // was used in (the CSO's review, S3).
    const busy = await member('Busy');
    await su.unsafe(`insert into app.watch_counts (member_id, kind, hour, n) select '${busy.id}', 'requests', date_trunc('hour', now()) - make_interval(days => x), 10
                     from generate_series(1, 6) x`);
    for (let i = 0; i < 10; i++) await ask(busy, { where: null });
    assert.deepStrictEqual(await alerts('watch:requests:%', busy.id), []);
    // The threshold change itself alerted (6).
    assert.deepStrictEqual(await alerts('watch:settings:watch_settings:%'), ['A safety setting changed']);
    const [s] = await owner(`select body from app.notices where dedupe_key like 'watch:settings:watch_settings:%'`);
    assert.match(s.body, /the behaviour watch's thresholds: requests_floor\./);
    await asOwner('update app.watch_settings set requests_floor = 300');
  });

  test('many removals by one account in an hour, a new administrator, a JEVs setting and the brake for everyone alert', async () => {
    const aaron = await member('Aaron');
    await asOwner(`update app.members set is_admin = false where is_admin; update app.members set is_admin = true where id = '${aaron.id}'`);
    const admin = { actor: 'admin', memberId: aaron.id, session: aaron.hash };
    await asOwner('update app.watch_settings set removals_per_hour = 3');
    const targets = [];
    for (let i = 0; i < 4; i++) targets.push(await member('Target ' + i));
    for (const t of targets.slice(0, 2)) await run(admin, (x) => controls.setStatus(x, { member: t.id, status: 'banned' }));
    assert.deepStrictEqual(await alerts('watch:removals:%', aaron.id), []);
    for (const t of targets.slice(2)) await run(admin, (x) => controls.setStatus(x, { member: t.id, status: 'banned' }));
    assert.deepStrictEqual(await alerts('watch:removals:%', aaron.id), ['Many removals by one account'], 'at the 3rd, once');
    const [b] = await owner(`select body from app.notices where dedupe_key like 'watch:removals:%' and subject_id = '${aaron.id}'`);
    assert.match(b.body, /^3 members banned by one account within the hour/);
    // The brake for everyone, switched off.
    const on = await run(admin, (x) => controls.setBrake(x, { member: null, people_per_hour: 5 }));
    await run(admin, (x) => controls.lift(x, on.brake.id));
    assert.deepStrictEqual(await alerts('watch:brake:%'), ['The brake for everyone was switched off']);
    // A JEVs setting, changed by a migration.
    const was = (await alerts('watch:setting:%')).length; // the tests' own switch to shadow mode, at the start
    await asOwner(`update app.jevs_settings set value = value where key = 'mode'`);
    assert.strictEqual((await alerts('watch:setting:%')).length, was, 'no change, no alert');
    await asOwner(`update app.jevs_settings set value = 'enforce' where key = 'mode'`);
    assert.deepStrictEqual((await alerts('watch:setting:%')).slice(was), ['A JEVs setting changed']);
    await asOwner(`update app.jevs_settings set value = 'shadow' where key = 'mode'`);
    // A member made administrator through the reviewed path.
    await asOwner(`update app.members set is_admin = false where is_admin`);
    const next = await member('Next');
    await su.begin(async (t) => {
      await t.unsafe('set local role dog_owner');
      await t.unsafe(`select set_config('app.actor', 'system', true), set_config('app.member_id', '', true), set_config('app.agent_id', '', true), set_config('app.fresh', '', true), set_config('app.session', '', true)`);
      await t.unsafe(`select set_config('app.stamp', app.actor_stamp('system', '', '', '', ''), true)`);
      await t.unsafe(`select app.set_administrator('${next.id}')`);
    });
    assert.deepStrictEqual(await alerts('watch:admin:%', next.id), ['A member was made administrator']);
    await asOwner(`update app.members set is_admin = false where is_admin`);
    await asOwner('update app.watch_settings set removals_per_hour = 10');
  });

  test('the right key file after wrong ones alerts', async () => {
    const m = await member('Forgetful');
    const fp = (await owner(`select fingerprint from app.identities where member_id = '${m.id}'`))[0].fingerprint;
    const login = c.sha256hex('login forgetful'), file = c.sha256hex('file forgetful');
    await su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(`insert into app.file_keys (member_id, fingerprint, login_hash, key_hash) values ('${m.id}', '${fp}', '${login}', '${file}')`); });
    const tryFile = (key) => run({ actor: 'anon' }, (t) => store.fileSignIn(t, { loginHash: login, keyHash: key, displayName: 'Forgetful', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
    for (let i = 0; i < 2; i++) assert.strictEqual((await tryFile(c.sha256hex('wrong ' + i))).status, 'no_match');
    assert.strictEqual((await tryFile(file)).status, 'ok');
    assert.deepStrictEqual(await alerts('watch:afterfail:%', m.id), [], 'two wrong ones: an ordinary mistake');
    for (let i = 0; i < 3; i++) await tryFile(c.sha256hex('wrong again ' + i));
    assert.strictEqual((await tryFile(file)).status, 'ok', 'signed in');
    assert.deepStrictEqual(await alerts('watch:afterfail:%', m.id), ['A sign-in after wrong key files']);
    assert.strictEqual((await owner(`select failed from app.file_keys where member_id = '${m.id}'`))[0].failed, 0);
  });

  test('a failing watch never stops a request, and the hourly sweep keeps no more than promised', async () => {
    const m = await member('Unwatched');
    await su.unsafe('revoke execute on function app.watch_session(text, text, text) from dog_app');
    try {
      const who = await ask(m);
      assert.ok(who && who.memberId === m.id, 'signed in with the watch failing');
    } finally {
      await su.unsafe('grant execute on function app.watch_session(text, text, text) to dog_app');
    }
    assert.ok(await ask(m));
    await su.unsafe(`update app.watch_activity set place_at = now() - interval '25 hours' where member_id = '${m.id}' and place is not null`);
    await su.unsafe(`insert into app.watch_counts (member_id, kind, hour) values ('${m.id}', 'requests', date_trunc('hour', now()) - interval '9 days')`);
    const gone = await member('Gone quiet');
    assert.ok(await ask(gone));
    await su.unsafe(`update app.watch_activity set last_seen = now() - interval '91 days' where member_id = '${gone.id}'`);
    const [r] = await su.begin(async (t) => { await t.unsafe('set local role dog_timers'); return t.unsafe('select app.watch_sweep() as out'); });
    assert.ok(r.out.watch_swept >= 3, JSON.stringify(r.out));
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_activity where place_at < now() - interval '1 day'`))[0].n, 0, 'no place older than a day');
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_counts where hour < now() - interval '8 days'`))[0].n, 0);
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_activity where member_id = '${gone.id}'`))[0].n, 0);
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_hours where member_id = '${gone.id}'`))[0].n, 0, 'its hours went with it');
    // Only the sign-in role can read any of it; the site's role sees nothing.
    for (const tbl of ['watch_sessions', 'watch_activity', 'watch_hours', 'watch_counts']) {
      await assert.rejects(run({ actor: 'member', memberId: m.id, session: m.hash }, (t) => t.unsafe(`select * from app.${tbl}`)), /permission denied/, tbl);
    }
    // And the timers run the sweep.
    const [t] = await run({ actor: 'anon' }, (x) => x`select app.timers_run(false) as out`);
    assert.deepStrictEqual({ ran: t.out.ran, failed: t.out.failed }, { ran: true, failed: false }, 'the timers, sweep included, ran and didn\'t fail');
    assert.match((await owner(`select prosrc from pg_proc where oid = 'app.run_timers()'::regprocedure`))[0].prosrc, /out := out \|\| app\.watch_sweep\(\);/);
  });
  test('a member revoking many agents in an hour alerts', async () => {
    await asOwner('update app.watch_settings set removals_per_hour = 3');
    try {
      const m = await member('Revoker');
      await promote(su, m.id); // making agents needs level 2
      const ctx = { actor: 'member', memberId: m.id, session: m.hash };
      const ids = [];
      for (let i = 0; i < 3; i++) ids.push((await run(ctx, (t) => t`insert into app.agents (name) values (${'Agent ' + i}) returning id`))[0].id);
      for (const id of ids.slice(0, 2)) assert.strictEqual(await run(ctx, (t) => agents.revoke(t, id)), true);
      assert.deepStrictEqual(await alerts('watch:removals:%', m.id), []);
      assert.strictEqual(await run(ctx, (t) => agents.revoke(t, ids[2])), true, 'the 3rd is revoked too: the watch never refuses');
      assert.deepStrictEqual(await alerts('watch:removals:%', m.id), ['Many removals by one account']);
      const [b] = await owner(`select body from app.notices where dedupe_key like 'watch:removals:%' and subject_id = '${m.id}'`);
      assert.match(b.body, /^3 agents revoked by one account within the hour/);
    } finally {
      await asOwner('update app.watch_settings set removals_per_hour = 10');
    }
  });

  test('a lock the watch can\'t get within 300 ms skips it for that request; the request is served', async () => {
    const m = await member('Locked out of the watch, not the site');
    assert.ok(await ask(m, { where: null }));
    const count = async () => (await owner(`select coalesce(sum(n), 0)::int as n from app.watch_counts where member_id = '${m.id}' and kind = 'requests'`))[0].n;
    const before = await count();
    let served, took;
    await su.begin(async (t) => {
      await t.unsafe(`select 1 from app.watch_counts where member_id = '${m.id}' and kind = 'requests' for update`);
      const t0 = Date.now();
      served = await ask(m, { where: null });
      took = Date.now() - t0;
    });
    assert.ok(served && served.memberId === m.id, 'signed in');
    assert.ok(took < 2000, 'not held long: ' + took + ' ms');
    assert.strictEqual(await count(), before, 'that request went uncounted');
    assert.ok(await ask(m, { where: null }));
    assert.strictEqual(await count(), before + 1, 'the next one counts');
  });

  test('deleting an account deletes everything the watch kept about it', async () => {
    const m = await member('Leaving');
    assert.ok(await ask(m, { where: NYC }));
    await su.unsafe(`insert into app.watch_counts (member_id, kind, hour) values ('${m.id}', 'post.remove', date_trunc('hour', now()))`);
    const rows = async () => (await owner(`select
      (select count(*) from app.watch_sessions w join app.sessions s on s.id = w.session_id where s.member_id = '${m.id}')
      + (select count(*) from app.watch_activity where member_id = '${m.id}')
      + (select count(*) from app.watch_hours where member_id = '${m.id}')
      + (select count(*) from app.watch_counts where member_id = '${m.id}') as n`))[0].n;
    assert.ok(Number(await rows()) >= 5, 'a session row, the activity row, an hour and two counts');
    const out = await run({ actor: 'member', memberId: m.id, session: m.hash, fresh: true }, (t) => store.deleteAccount(t));
    assert.ok(!out.refused, JSON.stringify(out));
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_activity where member_id = '${m.id}'`))[0].n, 0);
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_hours where member_id = '${m.id}'`))[0].n, 0);
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_counts where member_id = '${m.id}'`))[0].n, 0);
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_sessions w where not exists (select 1 from app.sessions s where s.id = w.session_id)`))[0].n, 0);
  });

  test('the sweep deletes the row of a session that ran out', async () => {
    const m = await member('Expired');
    assert.ok(await ask(m, { where: null }));
    await su.unsafe(`update app.sessions set expires_at = now() - interval '1 minute' where token_hash = '${m.hash}'`);
    await su.begin(async (t) => { await t.unsafe('set local role dog_timers'); await t.unsafe('select app.watch_sweep()'); });
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_sessions w join app.sessions s on s.id = w.session_id where s.token_hash = '${m.hash}'`))[0].n, 0);
  });
  test('the site\'s roles can\'t record the actions that raise a new-administrator or JEVs-setting alert', async () => {
    const m = await member('Forger');
    const ctx = { actor: 'member', memberId: m.id, session: m.hash };
    for (const action of ['admin.set', 'jevs.setting']) {
      await assert.rejects(run(ctx, (t) => t`insert into app.audit_log (action, subject_kind, subject_id, detail)
        values (${action}, 'member', ${m.id}, ${t.json({ key: 'mode', from: 'a', to: 'b' })})`), /row-level security/, action);
    }
    assert.deepStrictEqual(await alerts('watch:admin:%', m.id), []);
  });

  test('a removal is never held up by another one being counted at the same moment', async () => {
    const aaron = await member('Aaron again');
    await asOwner(`update app.members set is_admin = false where is_admin; update app.members set is_admin = true where id = '${aaron.id}'`);
    const admin = { actor: 'admin', memberId: aaron.id, session: aaron.hash };
    const target = await member('Held target');
    try {
      let took;
      await su.begin(async (t) => {
        // The counting lock for this account, action and hour, taken as another removal would hold it.
        await t.unsafe(`select pg_advisory_xact_lock(hashtext('dayonegreat.watch_audit'),
          hashtext('${aaron.id}' || 'member.ban' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24')))`);
        const t0 = Date.now();
        await run(admin, (x) => controls.setStatus(x, { member: target.id, status: 'banned' }));
        took = Date.now() - t0;
      });
      assert.ok(took < 1000, 'the ban went through at once: ' + took + ' ms');
      assert.strictEqual((await owner(`select status from app.members where id = '${target.id}'`))[0].status, 'banned');
      assert.strictEqual((await owner(`select count(*)::int as n from app.watch_counts where member_id = '${aaron.id}' and kind = 'member.ban'`))[0].n, 0,
        'that one went uncounted, as the lock was taken');
    } finally {
      await asOwner(`update app.members set is_admin = false where is_admin`);
    }
  });
}
