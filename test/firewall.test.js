// 083, the Agentic Wall's firewall (Aaron, Nov 25): wall/firewall.js decides; middleware.js only reads and answers.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const fw = require('../wall/firewall');

const SINCE = '2026-11-26T00:00:00Z'; // when 083 went live (from the database)
const LATER = Date.parse(SINCE) + 8 * 86400000; // after the log-only week
const req = (o = {}) => Object.assign({ method: 'GET', path: '/', query: '', ua: 'Mozilla/5.0', ip: '198.51.100.20', country: 'US' }, o);
const d = (o, opt = {}) => fw.decide(req(o), Object.assign({ now: LATER, since: SINCE }, opt));

test('FWL1: North Korea is refused from day one; other countries pass', () => {
  const kp = fw.decide(req({ country: 'KP' }), { now: Date.parse(SINCE) });
  assert.deepStrictEqual([kp.rule, kp.action, kp.status, kp.enforced], ['W34', 'block', 403, true]);
  assert.strictEqual(d({ country: 'kp' }).rule, 'W34');
  for (const c of ['US', 'KR', 'GB', '']) assert.strictEqual(d({ country: c }).action, 'allow', c);
});

test('FWL2: web attacks in the path or query are refused, decoded; honest searches pass', () => {
  for (const [p, q] of [['/api/feed', 'id=1%27%20OR%20%271%27%3D%271'], ['/', "id=1 UNION ALL SELECT password FROM users"], ['/search', 'name=%253Cscript%253Ealert(1)%253C%2Fscript%253E'],
    ['/../../etc/passwd', ''], ['/', 'f=..%2F..%2Fwin.ini'], ['/', 'x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%7D'], ['/', 'cmd=;cat /etc/hosts'], ['/', 'u=javascript:alert(1)'],
    ['/', 'p=php://filter'], ['/', 'a=1;%20DROP%20TABLE%20x'], ['/', "id=1' and sleep(5)--"], ['/', 'x=%00']]) {
    const r = d({ path: p, query: q });
    assert.deepStrictEqual([r.rule, r.action], ['W35', 'block'], p + '?' + q);
  }
  // 083 review: attack-like words in a search box are only flagged, never refused.
  for (const q of ['q=javascript: tutorial', 'q=%3Cscript%3E', 'q=union select', 'q=sleep (insomnia)', 'q=file://', 'q=a | sh', 'q=onload=fn']) {
    const r = d({ path: '/api/work/wiki', query: q });
    assert.notStrictEqual(r.action, 'block', q);
  }
  for (const q of ['q=how to select a union rep', 'q=rock and roll', 'q=O%27Brien', 'q=C%23 and .NET', 'q=what is 1=1', 'page=2&sort=new', 'q=javascript tutorial']) {
    assert.strictEqual(d({ path: '/api/feed', query: q }).action, 'allow', q);
  }
});

test('FWL3: attack scanners are refused; no user agent is only flagged; real browsers and GitHub pass', () => {
  for (const ua of ['sqlmap/1.7', 'Mozilla/5.0 Nikto', 'Nuclei - Open-source project', 'masscan/1.3', 'gobuster/3.6']) assert.deepStrictEqual([d({ ua }).rule, d({ ua }).action], ['W37', 'block'], ua);
  assert.deepStrictEqual([d({ ua: '' }).rule, d({ ua: '' }).action, d({ ua: '' }).enforced], ['W37', 'flag', false]);
  for (const ua of ['GitHub-Hookshot/abc', 'vercel-cron/1.0', 'curl/8.4.0', 'claude-agent/1.0']) assert.strictEqual(d({ ua }).action, 'allow', ua);
});

test('FWL4: threat-list addresses and ranges are refused; others pass', () => {
  const badAddresses = ['203.0.113.66', '192.0.2.0/24'];
  assert.strictEqual(d({ ip: '203.0.113.66' }, { badAddresses }).rule, 'W38');
  assert.strictEqual(d({ ip: '192.0.2.200' }, { badAddresses }).rule, 'W38');
  assert.strictEqual(d({ ip: '192.0.3.1' }, { badAddresses }).action, 'allow');
  assert.ok(fw.inRange('10.1.2.3', '10.0.0.0/8') && !fw.inRange('11.0.0.1', '10.0.0.0/8') && fw.inRange('1.2.3.4', '1.2.3.4'));
  // 083 review: nested ranges, and 7,000 ranges checked fast.
  const many = Array.from({ length: 7000 }, (_, i) => (10 + (i >> 8)) + '.' + (i & 255) + '.0.0/16').concat(['44.0.0.0/8', '44.5.6.7']);
  assert.ok(fw.listed('44.5.6.7', many) && fw.listed('44.9.9.9', many) && !fw.listed('45.0.0.1', many));
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < 10000; i++) fw.listed('198.51.' + (i & 255) + '.1', many);
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 200, '10,000 lookups in under 200 ms');
});

test('FWL5: over the rate, 429 with try again; never a lockout (the next minute is served)', () => {
  const ip = '198.51.100.77';
  let last;
  for (let i = 0; i <= fw.RATE_PER_MINUTE; i++) last = fw.decide(req({ ip }), { now: LATER, since: SINCE });
  assert.deepStrictEqual([last.rule, last.status, last.action], ['W36', 429, 'block']);
  assert.strictEqual(fw.decide(req({ ip }), { now: LATER + 60000, since: SINCE }).action, 'allow');
});

test('FWL5b (083 review): the rate map is dropped each minute, bounded, and an IPv6 /64 counts as one', () => {
  assert.strictEqual(fw.rateKey('2001:db8:1:2:aaaa::1'), fw.rateKey('2001:db8:1:2:bbbb::9'));
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < 60000; i++) fw.decide(req({ ip: '2001:db8:' + i.toString(16) + '::1' }), { now: LATER + 120000, since: SINCE });
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 3000, '60,000 new addresses in one minute stay fast');
  const t1 = process.hrtime.bigint();
  for (let i = 0; i < 1000; i++) fw.decide(req({ ip: '198.51.100.' + (i & 255) }), { now: LATER + 120000, since: SINCE });
  assert.ok(Number(process.hrtime.bigint() - t1) / 1e6 < 200, 'later requests aren\'t slowed');
});

test('FWL6: every rule but the country logs only for its first week, then enforces by itself', () => {
  const first = fw.decide(req({ ua: 'sqlmap' }), { now: Date.parse(SINCE) + 86400000, since: SINCE });
  assert.deepStrictEqual([first.action, first.enforced], ['block', false]);
  assert.strictEqual(fw.decide(req({ ua: 'sqlmap' }), { now: LATER, since: SINCE }).enforced, true);
  // 083 review: the week runs from when the rules went live, never a date in the code; unknown means log only.
  assert.strictEqual(fw.decide(req({ ua: 'sqlmap' }), { now: LATER }).enforced, false);
  assert.strictEqual(fw.decide(req({ country: 'KP' }), { now: LATER }).enforced, true);
});

test('FWL7: middleware.js lets everything through if the firewall fails, writes no address or path, and skips its own list', () => {
  const s = fs.readFileSync(path.join(__dirname, '..', 'middleware.js'), 'utf8');
  assert.match(s, /catch \{\n\s+return next\(\);/);
  assert.match(s, /if \(url\.pathname === LIST\) return next\(\);/);
  assert.match(s, /matcher: \[/, 'static files are left out');
  const refresh = s.slice(s.indexOf('function refresh'), s.indexOf('\n}\n', s.indexOf('function refresh')));
  assert.ok(refresh.length > 20 && !/await/.test(refresh), 'a request never waits for the list');
  // 087: the body is read from a copy, capped at 64 KB, and for at most 1.5 s.
  assert.match(s, /request\.clone\(\)/);
  assert.match(s, /setTimeout\(\(\) => ok\(''\), 1500\)/);
  assert.match(s, /console\.log\(JSON\.stringify\(\{ wall: d\.rule, kind: d\.kind, action: d\.action, enforced: d\.enforced \}\)\)/);
  assert.ok(!/console\.log\([^)]*(ip|path|url)\b/.test(s.replace(/console\.log\(JSON\.stringify\(\{ wall[^\n]*/, '')));
});

test('FWL8 (CWE-1333, Aaron Nov 25 "Rewrite without regex"): no regular expression reads request input; the worst inputs stay fast', () => {
  for (const f of ['wall/firewall.js', 'wall/match.js', 'wall/normalize.js', 'middleware.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    assert.ok(!/new RegExp|\.test\(|\.exec\(|\.match\(|\.replace\(\//.test(src), f + ' uses no regular expressions');
  }
  const worst = ['union ' + ' '.repeat(4000) + 'select', '<script ' + 'a'.repeat(4000), '<img ' + 'x'.repeat(4000) + ' on', "' or " + '('.repeat(4000),
    '%2525'.repeat(1300), 'javascript: ' + 'a'.repeat(4000), '<'.repeat(4000), '${'.repeat(2000), ';'.repeat(4000), "'".repeat(4000), 'on'.repeat(2000)];
  for (const q of worst) {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < 20; i++) fw.decide(req({ query: 'id=' + q }), { now: LATER, since: SINCE });
    assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 500, q.slice(0, 20) + ': 20 checks in under 500 ms');
  }
  const long = d({ query: 'id=' + 'a'.repeat(9000) });
  assert.deepStrictEqual([long.rule, long.status], ['W35', 414]);
});
