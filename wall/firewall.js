// The Agentic Wall's firewall (083; Aaron, Nov 25: "It needs to catch things like a firewall would"; "Firewall:
// blocking by country or network ... Yes North Korea"). Runs in front of every request (middleware.js), before any
// page or API code. Pure: given what a request looks like, it says allow, flag or block, and which rule.
//
//   W34 country  a request from a blocked country (North Korea, KP; the list is BLOCKED_COUNTRIES) is refused.
//   W35 attack   SQL injection, cross-site scripting, path traversal, command injection, file inclusion, Log4Shell-style
//                lookups and null bytes in the path or query (decoded up to twice) are refused.
//   W36 rate     more than RATE_PER_MINUTE requests a minute from one address, in this instance, gets 429 with
//                Retry-After: slowed, never locked out (Aaron, Oct 23). Per instance only: the app's per-level limits
//                (080) are the shared ones.
//   W37 bot      a known attack scanner's user agent is refused; a request with no user agent at all is flagged.
//   W38 address  an address on the security wiki's threat lists (Spamhaus DROP ranges, Feodo Tracker) is refused.
//
// A new rule logs for LOG_DAYS from the day it ships, then enforces by itself, so a badly tuned rule can't block real
// visitors from day one (Claude's plan, Nov 25). W34 enforces at once: Aaron named it.
'use strict';

const SHIPPED = Date.parse('2026-11-26T00:00:00Z');
const LOG_DAYS = 7;
const BLOCKED_COUNTRIES = ['KP'];
const RATE_PER_MINUTE = 300;
const ENFORCE_NOW = new Set(['W34']);

// What an attack looks like in a path or query, after decoding. Each pattern is anchored to attack syntax, not to
// words people write (a search for "select a union" isn't an attack; "union select" with SQL around it is).
const ATTACKS = [
  ['sql', /\bunion\b[\s/*+]+(all[\s/*+]+)?select\b/i],
  ['sql', /'[\s)]*(or|and)[\s(]+'?\d+'?\s*=\s*'?\d+/i],
  ['sql', /;\s*(drop|truncate|shutdown|exec(ute)?)\s/i],
  ['sql', /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i],
  ['sql', /\binformation_schema\b|\bxp_cmdshell\b/i],
  ['xss', /<\s*(script|iframe|object|embed|svg|img)[^>]*>/i],
  ['xss', /\bjavascript\s*:/i],
  ['xss', /\bon(error|load|click|mouseover|focus)\s*=/i],
  ['traversal', /(^|[/\\])\.\.([/\\]|$)/],
  ['traversal', /\/etc\/(passwd|shadow|hosts)\b|\bwin\.ini\b|\bboot\.ini\b/i],
  ['command', /[;|`]\s*(cat|curl|wget|bash|sh|nc|ncat|python|perl|powershell)\b/i],
  ['command', /\$\(\s*[a-z]/i],
  ['inclusion', /\b(php|file|expect|data|zip|phar):\/\//i],
  ['lookup', /\$\{\s*(jndi|env|sys|java|lower|upper)\s*:/i],
  ['nullbyte', /\u0000/]
];

const SCANNERS = /\b(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|wpscan|dirbuster|gobuster|ffuf|wfuzz|hydra|netsparker|w3af|openvas|nessus|havij|jaeles|whatweb|feroxbuster|commix|xsstrike)\b/i;

function decode(s) {
  let out = String(s || '');
  for (let i = 0; i < 2; i++) {
    try { const d = decodeURIComponent(out.replace(/\+/g, ' ')); if (d === out) break; out = d; } catch { break; }
  }
  return out;
}

// IPv4 in a CIDR range (Spamhaus DROP is ranges; Feodo is single addresses).
function ipv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || ''));
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function inRange(ip, cidr) {
  const [base, bits] = String(cidr).split('/');
  const a = ipv4(ip); const b = ipv4(base);
  if (a === null || b === null) return false;
  const n = bits === undefined ? 32 : Number(bits);
  if (!(n >= 0 && n <= 32)) return false;
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

// Per-instance counts for W36, a minute at a time.
const seen = new Map();
function overRate(ip, now) {
  if (!ip) return false;
  const minute = Math.floor(now / 60000);
  const k = ip + '|' + minute;
  const n = (seen.get(k) || 0) + 1;
  seen.set(k, n);
  if (seen.size > 50000) for (const key of seen.keys()) { if (!key.endsWith('|' + minute)) seen.delete(key); }
  return n > RATE_PER_MINUTE;
}

function mode(rule, now) {
  if (ENFORCE_NOW.has(rule)) return 'enforce';
  return now >= SHIPPED + LOG_DAYS * 86400000 ? 'enforce' : 'log';
}

// req: { method, path, query, ua, ip, country }. badAddresses: the wiki's list (addresses and ranges).
// Returns { rule, kind, action: 'allow' | 'flag' | 'block', status, enforced }.
function decide(req, { badAddresses = [], now = Date.now() } = {}) {
  const hit = (rule, kind, action, status) => {
    const m = mode(rule, now);
    return { rule, kind, action, status, enforced: m === 'enforce' && action === 'block' };
  };
  const country = String(req.country || '').toUpperCase();
  if (BLOCKED_COUNTRIES.includes(country)) return hit('W34', 'country ' + country, 'block', 403);
  const ip = String(req.ip || '');
  if (ip && badAddresses.some((x) => (String(x).includes('/') ? inRange(ip, x) : x === ip))) return hit('W38', 'threat-list address', 'block', 403);
  const ua = String(req.ua || '');
  if (SCANNERS.test(ua)) return hit('W37', 'attack scanner', 'block', 403);
  const target = decode(req.path) + '?' + decode(req.query);
  for (const [kind, re] of ATTACKS) if (re.test(target)) return hit('W35', kind, 'block', 403);
  if (overRate(ip, now)) return hit('W36', 'rate', 'block', 429);
  if (!ua.trim()) return hit('W37', 'no user agent', 'flag', 200);
  return { rule: null, kind: null, action: 'allow', status: 200, enforced: false };
}

module.exports = { decide, inRange, ipv4, decode, mode, ATTACKS, SCANNERS, BLOCKED_COUNTRIES, RATE_PER_MINUTE, SHIPPED, LOG_DAYS, _seen: seen };
