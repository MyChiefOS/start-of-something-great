// 083, the Agentic Wall's firewall (Aaron, Nov 25): wall/firewall.js decides; middleware.js only reads and answers.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const fw = require('../wall/firewall');

const LATER = fw.SHIPPED + 8 * 86400000; // after the log-only week
const req = (o = {}) => Object.assign({ method: 'GET', path: '/', query: '', ua: 'Mozilla/5.0', ip: '198.51.100.20', country: 'US' }, o);
const d = (o, opt = {}) => fw.decide(req(o), Object.assign({ now: LATER }, opt));

test('FWL1: North Korea is refused from day one; other countries pass', () => {
  const kp = fw.decide(req({ country: 'KP' }), { now: fw.SHIPPED });
  assert.deepStrictEqual([kp.rule, kp.action, kp.status, kp.enforced], ['W34', 'block', 403, true]);
  assert.strictEqual(d({ country: 'kp' }).rule, 'W34');
  for (const c of ['US', 'KR', 'GB', '']) assert.strictEqual(d({ country: c }).action, 'allow', c);
});

test('FWL2: web attacks in the path or query are refused, decoded; honest searches pass', () => {
  for (const [p, q] of [['/api/feed', 'q=1%27%20OR%20%271%27%3D%271'], ['/', "id=1 UNION ALL SELECT password FROM users"], ['/search', 'q=%253Cscript%253Ealert(1)%253C%2Fscript%253E'],
    ['/../../etc/passwd', ''], ['/', 'f=..%2F..%2Fwin.ini'], ['/', 'x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%7D'], ['/', 'cmd=;cat /etc/hosts'], ['/', 'u=javascript:alert(1)'],
    ['/', 'p=php://filter'], ['/', 'a=1;%20DROP%20TABLE%20x'], ['/', "q=1' and sleep(5)--"], ['/', 'x=%00']]) {
    const r = d({ path: p, query: q });
    assert.deepStrictEqual([r.rule, r.action], ['W35', 'block'], p + '?' + q);
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
});

test('FWL5: over the rate, 429 with try again; never a lockout (the next minute is served)', () => {
  const ip = '198.51.100.77';
  let last;
  for (let i = 0; i <= fw.RATE_PER_MINUTE; i++) last = fw.decide(req({ ip }), { now: LATER });
  assert.deepStrictEqual([last.rule, last.status, last.action], ['W36', 429, 'block']);
  assert.strictEqual(fw.decide(req({ ip }), { now: LATER + 60000 }).action, 'allow');
});

test('FWL6: every rule but the country logs only for its first week, then enforces by itself', () => {
  const first = fw.decide(req({ ua: 'sqlmap' }), { now: fw.SHIPPED + 86400000 });
  assert.deepStrictEqual([first.action, first.enforced], ['block', false]);
  assert.strictEqual(fw.decide(req({ ua: 'sqlmap' }), { now: LATER }).enforced, true);
});

test('FWL7: middleware.js lets everything through if the firewall fails, writes no address or path, and skips its own list', () => {
  const s = fs.readFileSync(path.join(__dirname, '..', 'middleware.js'), 'utf8');
  assert.match(s, /catch \{\n\s+return next\(\);/);
  assert.match(s, /if \(url\.pathname === LIST\) return next\(\);/);
  assert.match(s, /console\.log\(JSON\.stringify\(\{ wall: d\.rule, kind: d\.kind, action: d\.action, enforced: d\.enforced \}\)\)/);
  assert.ok(!/console\.log\([^)]*(ip|path|url)\b/.test(s.replace(/console\.log\(JSON\.stringify\(\{ wall[^\n]*/, '')));
});
