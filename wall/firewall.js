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
// A new rule logs for LOG_DAYS from when 083 went live, then enforces by itself, so a badly tuned rule can't block real
// visitors from day one (Claude's plan, Nov 25). W34 enforces at once: Aaron named it.
'use strict';

const LOG_DAYS = 7;
const BLOCKED_COUNTRIES = ['KP'];
const RATE_PER_MINUTE = 300;
const ENFORCE_NOW = new Set(['W34']);

// What an attack looks like in a path or query, after decoding. Each pattern is anchored to attack syntax, not to
// words people write (a search for "select a union" isn't an attack; "union select" with SQL around it is).
// Strong: unmistakable attack syntax, refused (after the log week). Weak: attack-like words a person might search for,
// only flagged (083 review: on a security site people search for "<script>" and "union select").
const ATTACKS = [
  ['sql', /\bunion\b[\s/*+]+(all[\s/*+]+)?select\b[\s\S]*\bfrom\b/i],
  ['sql', /'[\s)]*(or|and)[\s(]+'?\d+'?\s*=\s*'?\d+/i],
  ['sql', /;\s*(drop|truncate|shutdown|exec(ute)?)\s/i],
  ['sql', /\b(sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\s+'/i],
  ['sql', /\binformation_schema\b|\bxp_cmdshell\b/i],
  ['xss', /<\s*(script|iframe|object|embed|svg|img)\b[^>]*>[\s\S]*(<\s*\/\s*script|\bon[a-z]+\s*=|\bsrc\s*=)/i],
  ['xss', /<\s*(img|svg|body|iframe)\b[^>]*\bon[a-z]+\s*=\s*[^\s>]/i],
  ['xss', /\bjavascript\s*:\s*[a-z_$][\w$.]*\s*\(/i],
  ['traversal', /(^|[/\\])\.\.([/\\]|$)/],
  ['traversal', /\/etc\/(passwd|shadow|hosts)\b|\bwin\.ini\b|\bboot\.ini\b/i],
  ['command', /[;|`]\s*(cat|curl|wget|bash|sh|nc|ncat|python|perl|powershell)\s+[-/.\w]/i],
  ['command', /\$\(\s*(cat|curl|wget|id|whoami|uname|bash|sh)\b/i],
  ['inclusion', /\b(php|expect|phar):\/\/|\bfile:\/\/\/(etc|proc|windows)\b/i],
  ['lookup', /\$\{\s*(jndi|env|sys|java|lower|upper)\s*:/i],
  ['nullbyte', /\u0000/]
];

// Attack-like words in free text (a search box): flagged only, never refused.
const WEAK = [/\bunion\b\s+select\b/i, /<\s*script/i, /\bjavascript\s*:/i, /\bon(error|load)\s*=/i, /\b(sleep|benchmark)\s*\(/i, /\bfile:\/\//i, /\|\s*(sh|bash)\b/i];
const FREE_TEXT = new Set(['q', 'query', 'search', 's', 'text', 'term']);

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

// Per-instance counts for W36, one map per minute, dropped whole when the minute turns (083 review: no scan, no growth
// past MAX_TRACKED). An IPv6 address counts by its /64, so rotating addresses inside one network doesn't reset it.
const MAX_TRACKED = 50000;
let seen = new Map();
let seenMinute = -1;
function rateKey(ip) {
  if (!ip.includes(':')) return ip;
  return ip.toLowerCase().split(':').slice(0, 4).join(':') + '::/64';
}
function overRate(ip, now) {
  if (!ip) return false;
  const minute = Math.floor(now / 60000);
  if (minute !== seenMinute) { seen = new Map(); seenMinute = minute; }
  const k = rateKey(ip);
  const n = (seen.get(k) || 0) + 1;
  if (seen.has(k) || seen.size < MAX_TRACKED) seen.set(k, n);
  return n > RATE_PER_MINUTE;
}

// The log week runs from when the firewall's rules went live (083's migration, read with the threat list), never from
// a fixed date (083 review). Until that time is known, everything but the country only logs.
function mode(rule, now, since = null) {
  if (ENFORCE_NOW.has(rule)) return 'enforce';
  const start = since === null || since === undefined ? null : Date.parse(since);
  if (start === null || Number.isNaN(start)) return 'log';
  return now >= start + LOG_DAYS * 86400000 ? 'enforce' : 'log';
}

// The threat list as sorted [start, end] ranges, built once per list (083 review: no linear scan per request).
let built = { from: null, ranges: [] };
function rangesOf(list) {
  if (built.from === list) return built.ranges;
  const out = [];
  for (const x of list) {
    const [base, bits] = String(x).split('/');
    const b = ipv4(base); const n = bits === undefined ? 32 : Number(bits);
    if (b === null || !(n >= 0 && n <= 32)) continue;
    const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
    const start = (b & mask) >>> 0;
    out.push([start, start + (2 ** (32 - n)) - 1]);
  }
  out.sort((a, c) => a[0] - c[0]);
  built = { from: list, ranges: out };
  return out;
}
function listed(ip, list) {
  const a = ipv4(ip);
  if (a === null) return false;
  const rs = rangesOf(list);
  let lo = 0; let hi = rs.length - 1;
  // Ranges can nest (a /32 inside a /16), so walk back from the last start at or below the address.
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (rs[mid][0] <= a) lo = mid + 1; else hi = mid - 1; }
  for (let i = hi; i >= 0 && i > hi - 64; i--) if (a <= rs[i][1]) return true;
  return false;
}

// req: { method, path, query, ua, ip, country }. badAddresses: the wiki's list (addresses and ranges).
// Returns { rule, kind, action: 'allow' | 'flag' | 'block', status, enforced }.
function decide(req, { badAddresses = [], now = Date.now(), since = null } = {}) {
  const hit = (rule, kind, action, status) => {
    const m = mode(rule, now, since);
    return { rule, kind, action, status, enforced: m === 'enforce' && action === 'block' };
  };
  const country = String(req.country || '').toUpperCase();
  if (BLOCKED_COUNTRIES.includes(country)) return hit('W34', 'country ' + country, 'block', 403);
  const ip = String(req.ip || '');
  if (ip && listed(ip, badAddresses)) return hit('W38', 'threat-list address', 'block', 403);
  const ua = String(req.ua || '');
  if (SCANNERS.test(ua)) return hit('W37', 'attack scanner', 'block', 403);
  // Free-text values (a search box) are left out of the strong check and only flagged if they look like an attack.
  let free = '';
  const rest = String(req.query || '').split('&').filter((pair) => {
    const name = decode(pair.split('=')[0]).toLowerCase();
    if (FREE_TEXT.has(name)) { free += ' ' + decode(pair.slice(pair.indexOf('=') + 1)); return false; }
    return true;
  }).join('&');
  const target = decode(req.path) + '?' + decode(rest);
  for (const [kind, re] of ATTACKS) if (re.test(target)) return hit('W35', kind, 'block', 403);
  if (WEAK.some((re) => re.test(free) || re.test(target))) return hit('W35', 'attack-like words', 'flag', 200);
  if (overRate(ip, now)) return hit('W36', 'rate', 'block', 429);
  if (!ua.trim()) return hit('W37', 'no user agent', 'flag', 200);
  return { rule: null, kind: null, action: 'allow', status: 200, enforced: false };
}

module.exports = { decide, inRange, ipv4, decode, mode, listed, rateKey, ATTACKS, WEAK, SCANNERS, BLOCKED_COUNTRIES, RATE_PER_MINUTE, LOG_DAYS, MAX_TRACKED };
