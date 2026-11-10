// RK145 (the independent review of the web app, Nov 10, F4): the administrator's reads that write audit rows are GETs,
// and a session cookie is SameSite=Lax, so a link on another site could make Aaron's browser write false "revealed
// this post" or "read the queue" records. These reads now answer only a request the browser says came from the site
// itself (Sec-Fetch-Site: same-origin, with an Origin, where sent, that is ours), or that Aaron typed or bookmarked
// (Sec-Fetch-Site: none, which no other site can cause). Anything else, including no Sec-Fetch-Site at all, gets a
// clear 403 before the database is touched, so nothing is read, written or recorded. Public reads are unchanged.
// No database: a stand-in that records every call shows the refusal comes before any of them.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const feed = require('../api/feed');
const work = require('../api/work');

const ORIGIN = 'https://dayonegreat.com';
const POST = '00000000-0000-4000-8000-000000000001';
const COOKIE = '__Host-dog_session=' + 'A'.repeat(43);

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
// A database stand-in: records each call and finds nobody signed in.
function recorder() {
  const calls = [];
  const run = async (ctx, fn) => { calls.push(ctx); return null; };
  return { run, calls };
}
const READS = [
  ['GET /api/feed?reveal=', (h, r, run) => feed.handle({ method: 'GET', url: '/api/feed?reveal=' + POST, headers: h, query: { reveal: POST } }, r, run)],
  ['GET /api/feed?queue=1', (h, r, run) => feed.handle({ method: 'GET', url: '/api/feed?queue=1', headers: h, query: { queue: '1' } }, r, run)],
  ['GET /api/feed?controls=1', (h, r, run) => feed.handle({ method: 'GET', url: '/api/feed?controls=1', headers: h, query: { controls: '1' } }, r, run)],
  ['GET /api/work/admin', (h, r, run) => work.handle({ method: 'GET', url: '/api/work?route=admin', headers: h, query: { route: 'admin' } }, r, run)],
  ['GET /api/work/console', (h, r, run) => work.handle({ method: 'GET', url: '/api/work?route=console&tab=summary', headers: h, query: { route: 'console' } }, r, run)]
];
async function ask(fn, extra) {
  const r = res();
  const { run, calls } = recorder();
  const headers = { host: 'dayonegreat.com', cookie: COOKIE, 'x-vercel-forwarded-for': '203.0.113.9', ...extra };
  await fn(headers, r, run);
  return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null, calls };
}

for (const [name, fn] of READS) {
  test('RK145: ' + name + ' is refused from another site, or with no Sec-Fetch-Site, before the database is touched', async () => {
    for (const extra of [{ 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': 'same-site' }, {}, { 'sec-fetch-site': 'same-origin', origin: 'https://evil.example' }]) {
      const r = await ask(fn, extra);
      assert.strictEqual(r.status, 403, name + ' ' + JSON.stringify(extra));
      assert.match(r.json.error, /only from dayonegreat\.com/, name);
      assert.strictEqual(r.calls.length, 0, name + ': nothing read, written or recorded ' + JSON.stringify(extra));
    }
  });
  test('RK145: ' + name + ' from the site\'s own pages, or typed by Aaron, goes on to the sign-in check', async () => {
    for (const extra of [{ 'sec-fetch-site': 'same-origin' }, { 'sec-fetch-site': 'same-origin', origin: ORIGIN }, { 'sec-fetch-site': 'none' }]) {
      const r = await ask(fn, extra);
      assert.strictEqual(r.status, 401, name + ' ' + JSON.stringify(extra));
      assert.ok(r.calls.length > 0, 'the session was looked up');
    }
  });
}

test('RK145: ordinary public reads are not affected', async () => {
  const r = res();
  await feed.handle({ method: 'GET', url: '/api/feed?lane=people', headers: { host: 'dayonegreat.com', 'sec-fetch-site': 'cross-site' }, query: { lane: 'people' } }, r, null);
  assert.strictEqual(r.statusCode, 200);
  const w = res();
  await work.handle({ method: 'GET', url: '/api/work?route=rooms', headers: { host: 'dayonegreat.com', 'sec-fetch-site': 'cross-site' }, query: { route: 'rooms' } }, w, async () => []);
  assert.strictEqual(w.statusCode, 200);
});

test('RK145: an agent with its key is not asked for Sec-Fetch-Site (no browser sends its key), and is still not an administrator', async () => {
  const r = res();
  const { calls } = recorder();
  await work.handle({ method: 'GET', url: '/api/work?route=admin', headers: { host: 'dayonegreat.com', authorization: 'Bearer dog_agent_' + 'k'.repeat(40) }, query: { route: 'admin' } }, r, async (ctx, f) => { calls.push(ctx); return null; });
  assert.notStrictEqual(r.statusCode, 200);
  assert.ok(!/only from dayonegreat\.com/.test(r.body), r.body);
});
