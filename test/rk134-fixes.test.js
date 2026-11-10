// RK134's fix and its two reviews (Nov 10). None of these needs a database, so they run everywhere (the review of #123,
// F6: in preopen-safety.test.js they sat behind its database check and were skipped without one).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
test('RK134: the uptime monitor alerts (only) when Vercel\'s identity token stops checking out while the site is open', () => {
  const uptime = require('../scripts/uptime');
  const id = uptime.CHECKS.find((x) => x.name === 'Identity token');
  assert.ok(id && id.path === '/api/ready' && !id.when({ stage: 'closed' }) && id.when({ stage: 'public' }));
  const r = (json) => [{ status: 200 }, JSON.stringify(json)];
  assert.ok(id.test(...r({ identity_token: true, identity_token_verified: true })));
  for (const v of [false, undefined, null]) assert.ok(!id.test(...r({ identity_token: true, identity_token_verified: v })), String(v));
});

test('RK134: the token check gives up after 2 seconds, and the feed checks only when Second Look is asked', async () => {
  const sitekeys = require('../db/sitekeys');
  const req = () => ({ headers: { 'x-vercel-oidc-token': 'h.' + 'z'.repeat(40) + '.s' } });
  const started = Date.now();
  assert.strictEqual(await sitekeys.verifiedToken(req(), { verify: () => new Promise(() => {}) }), null, 'a check that never answers is no token');
  const took = Date.now() - started;
  assert.ok(took >= 1900 && took < 4000, 'about 2 seconds: ' + took);
  // tokenCheck reads now, checks later and once.
  let checks = 0;
  const r = req();
  const later = sitekeys.tokenCheck(r, { verify: async () => { checks++; return {}; } });
  delete r.headers['x-vercel-oidc-token']; // as ensure() does
  assert.strictEqual(checks, 0, 'nothing is checked until asked');
  assert.match(await later(), /^h\./);
  await later();
  assert.strictEqual(checks, 1, 'checked once');
  assert.match(fs.readFileSync(path.join(root, 'api', 'feed.js'), 'utf8'), /const oidc = require\('\.\.\/db\/sitekeys'\)\.tokenCheck\(req\);/);
});

test('RK134: a call whose token didn\'t check out can\'t turn away one whose token did (two clocks)', async () => {
  const cron = require('../api/cron.js');
  cron._reset();
  let clock = 5_000_000;
  const looked = [];
  const run = async () => ({}); // the timers' transactions, answered without a database
  const res = () => { const o = { statusCode: 0, setHeader() {}, end(b) { o.body = b; } }; return o; };
  const mods = ['secondlook', 'thirdlook', 'logjobs', 'workjobs'].map((m) => require('../db/' + m));
  const saved = mods.map((m) => m.run);
  // Since 057 Second and Third Look run in their own project, never here; the clocks are seen through the log jobs.
  mods[0].run = async () => { looked.push('second'); };
  mods[1].run = async () => { looked.push('third'); };
  mods[2].run = async () => { looked.push('log'); };
  mods[3].run = async () => {};
  try {
    await cron.handle({ method: 'GET', headers: {} }, res(), run, { now: () => clock }); // a call whose token didn't check out (or had none)
    assert.deepStrictEqual(looked, ['log']);
    looked.length = 0;
    clock += 10_000;
    await cron.handle({ method: 'GET', headers: { 'user-agent': 'vercel-cron/1.0' } }, res(), run, { now: () => clock, oidc: 'signed-token' });
    assert.deepStrictEqual(looked, ['log'], 'the call with a good token still runs, on its own clock; and no look runs in the site');
    looked.length = 0;
    clock += 5_000;
    await cron.handle({ method: 'GET', headers: {} }, res(), run, { now: () => clock, oidc: 'signed-token' });
    assert.deepStrictEqual(looked, [], 'and its own clock still holds it to once in 25 seconds');
  } finally {
    mods.forEach((m, i) => { m.run = saved[i]; }); cron._reset();
  }
});


test('RK134 (F4): a check that hands back no claims is no token, whatever it returns', async () => {
  const sitekeys = require('../db/sitekeys');
  const req = () => ({ headers: { 'x-vercel-oidc-token': 'h.' + 'z'.repeat(40) + '.s' } });
  for (const v of [false, null, undefined, 0, '', 'yes']) {
    assert.strictEqual(await sitekeys.verifiedToken(req(), { verify: async () => v }), null, String(v));
  }
  assert.match(await sitekeys.verifiedToken(req(), { verify: async () => ({ sub: 'x' }) }), /^h\./);
});

test('RK134 (F5): Vercel\'s keys are fetched once for every request waiting, within 2 seconds, and a failure isn\'t retried for 30', async () => {
  const sitekeys = require('../db/sitekeys');
  sitekeys._reset();
  const issuer = 'https://oidc.vercel.com/chief-os';
  let calls = 0;
  const slow = (url, init) => { calls++; return new Promise((resolve, reject) => { init.signal.addEventListener('abort', () => reject(new Error('aborted'))); }); };
  const keys = sitekeys.siteKeys(slow);
  const started = Date.now();
  const alive = setTimeout(() => {}, 5000); // the limit's own timer doesn't hold the process open; in the site, the check's does
  const all = await Promise.allSettled([keys(issuer), keys(issuer), keys(issuer)]);
  clearTimeout(alive);
  assert.strictEqual(calls, 1, 'one fetch for all three');
  assert.ok(all.every((r) => r.status === 'rejected'));
  assert.ok(Date.now() - started < 3500, 'given up within about 2 seconds');
  await assert.rejects(keys(issuer));
  assert.strictEqual(calls, 1, 'a failure is kept, not asked again at once');
  sitekeys._reset();
  let n = 0;
  const good = sitekeys.siteKeys(async () => { n++; return { ok: true, json: async () => ({ keys: [{ kid: 'a', kty: 'RSA' }] }) }; });
  assert.deepStrictEqual(await good(issuer), [{ kid: 'a', kty: 'RSA' }]);
  await good(issuer);
  assert.strictEqual(n, 1, 'kept for the hour');
  sitekeys._reset();
});

test('RK134 (F3): /api/ready\'s identity_token_verified is each caller\'s own, never the minute\'s shared answer', async () => {
  const ready = require('../api/ready.js');
  const sitekeys = require('../db/sitekeys');
  ready._reset(); sitekeys._reset();
  const call = async (headers, verify) => {
    const r = { statusCode: 0, setHeader() {}, end(b) { r.body = b; } };
    await ready.handle({ method: 'GET', headers }, r, { env: {}, verify });
    return JSON.parse(r.body);
  };
  const tok = () => ({ 'x-vercel-oidc-token': 'h.' + 'q'.repeat(40) + '.s' });
  const first = await call({}, async () => ({}));
  assert.strictEqual(first.identity_token_verified, false, 'no token, not verified');
  const good = await call(tok(), async () => ({}));
  assert.strictEqual(good.identity_token_verified, true, 'within the same minute, a good token reads true');
  const bad = await call(tok(), async () => { throw new Error('refused'); });
  assert.strictEqual(bad.identity_token_verified, false, 'and a refused one false');
  ready._reset(); sitekeys._reset();
});
