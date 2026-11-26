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
//   W38 address  an address on the security wiki's threat lists (Spamhaus DROP ranges, Feodo Tracker), IPv4 or IPv6,
//                is refused.
//
// 087 (Aaron, Nov 26, after the simulation): headers (user agent, referer, cookies and the rest) and request bodies are
// read too; probes for files this site never serves are refused (W37); rates are also counted per network (/24 and
// /48), and a flood across many networks raises an alert (never a block). Every check reads the request after
// wall/normalize.js has undone its disguises, so one check covers every spelling of an attack.
//
// A new rule logs for LOG_DAYS from when 083 went live, then enforces by itself, so a badly tuned rule can't block real
// visitors from day one (Claude's plan, Nov 25). W34 enforces at once: Aaron named it.
'use strict';

const LOG_DAYS = 7;
const BLOCKED_COUNTRIES = ['KP'];
const RATE_PER_MINUTE = 300;
const ENFORCE_NOW = new Set(['W34']);

// The attack checks are wall/match.js: plain text scans, no regular expressions (Aaron, Nov 25, after the scanner's
// ReDoS finding). Free-text values (a search box) are only flagged if they look like an attack.
const match = require('./match');
const upload = require('./upload');
const MAX_TARGET = 8192;
const MAX_BODY = 65536;
const FREE_TEXT = new Set(['q', 'query', 'search', 's', 'text', 'term']);
// Headers whose values are the browser's own (never typed by a person) are skipped; every other header is read.
const SKIP_HEADERS = new Set(['accept', 'accept-encoding', 'accept-language', 'connection', 'content-length', 'content-type', 'host', 'cache-control', 'pragma',
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'upgrade-insecure-requests',
  'if-none-match', 'if-modified-since', 'priority', 'te', 'dnt', 'authorization', 'x-vercel-id', 'x-vercel-ip-country', 'x-vercel-ip-city', 'x-vercel-ip-latitude',
  'x-vercel-ip-longitude', 'x-vercel-ip-timezone', 'x-vercel-ip-country-region', 'x-vercel-ip-postal-code', 'x-real-ip', 'x-forwarded-for', 'x-forwarded-proto',
  'x-forwarded-host', 'x-forwarded-port', 'x-vercel-forwarded-for', 'x-vercel-deployment-url', 'x-vercel-proxied-for', 'forwarded', 'x-wall-internal', 'baggage', 'traceparent', 'tracestate']);

function decode(s) {
  let out = String(s || '');
  for (let i = 0; i < 2; i++) {
    try { const d = decodeURIComponent(out.split('+').join(' ')); if (d === out) break; out = d; } catch { break; }
  }
  return out;
}

// IPv4 as a number.
function ipv4(s) {
  const parts = String(s || '').split('.');
  if (parts.length !== 4) return null;
  const p = [];
  for (const x of parts) {
    if (x.length < 1 || x.length > 3) return null;
    for (const c of x) if (c < '0' || c > '9') return null;
    const n = Number(x);
    if (n > 255) return null;
    p.push(n);
  }
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
// IPv6 as a BigInt (087): full, compressed (::) and IPv4-mapped forms; a zone (%eth0) is dropped.
function ipv6(s) {
  let t = String(s || '').toLowerCase();
  const z = t.indexOf('%'); if (z !== -1) t = t.slice(0, z);
  if (!t.includes(':') || t.length > 45) return null;
  let tail4 = null;
  const lastColon = t.lastIndexOf(':');
  if (t.slice(lastColon + 1).includes('.')) { tail4 = ipv4(t.slice(lastColon + 1)); if (tail4 === null) return null; t = t.slice(0, lastColon + 1) + '0:0'; }
  const dbl = t.split('::');
  if (dbl.length > 2) return null;
  const left = dbl[0] ? dbl[0].split(':') : [];
  const right = dbl.length === 2 && dbl[1] ? dbl[1].split(':') : [];
  const fill = 8 - left.length - right.length;
  if ((dbl.length === 1 && fill !== 0) || fill < 0) return null;
  const groups = [...left, ...Array(dbl.length === 2 ? fill : 0).fill('0'), ...right];
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) {
    if (g.length < 1 || g.length > 4) return null;
    for (const c of g) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return null;
    n = (n << 16n) + BigInt(parseInt(g, 16));
  }
  if (tail4 !== null) n = (n & ~0xffffffffn) | BigInt(tail4);
  return n;
}
// An IPv4-mapped IPv6 address (::ffff:1.2.3.4) is the IPv4 address.
function mapped(ip) {
  const n = ipv6(ip);
  if (n !== null && n >> 32n === 0xffffn) { const v = Number(n & 0xffffffffn); return [v >>> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255].join('.'); }
  return ip;
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
// past MAX_TRACKED). An address counts by itself; IPv6 by its /64, so rotating addresses inside one network doesn't
// reset it. 087: each request also counts toward its network (IPv4 /24, IPv6 /48) at NETWORK_FACTOR times the limit,
// and toward the instance's total: past INSTANCE_ALERT a minute, every request is flagged (an alert in the log), never
// refused, since a real crowd can look the same (Aaron, Oct 23: checks alert, never lock out).
const MAX_TRACKED = 50000;
const NETWORK_FACTOR = 4;
const INSTANCE_ALERT = 3000;
let seen = new Map();
let seenMinute = -1;
let total = 0;
function rateKey(ip) {
  if (!ip.includes(':')) return ip;
  return ip.toLowerCase().split(':').slice(0, 4).join(':') + '::/64';
}
function netKey(ip) {
  if (!ip.includes(':')) return 'n4:' + ip.split('.').slice(0, 3).join('.');
  const n = ipv6(ip); return n === null ? 'n6:?' : 'n6:' + (n >> 80n).toString(16);
}
function bump(k) { const n = (seen.get(k) || 0) + 1; if (seen.has(k) || seen.size < MAX_TRACKED) seen.set(k, n); return n; }
function overRate(ip, now) {
  const minute = Math.floor(now / 60000);
  if (minute !== seenMinute) { seen = new Map(); seenMinute = minute; total = 0; }
  total++;
  if (!ip) return total > INSTANCE_ALERT ? 'instance' : null;
  if (bump(rateKey(ip)) > RATE_PER_MINUTE) return 'address';
  if (bump(netKey(ip)) > RATE_PER_MINUTE * NETWORK_FACTOR) return 'network';
  return total > INSTANCE_ALERT ? 'instance' : null;
}

// The log week runs from when the firewall's rules went live (083's migration, read with the threat list), never from
// a fixed date (083 review). Until that time is known, everything but the country only logs.
function mode(rule, now, since = null) {
  if (ENFORCE_NOW.has(rule)) return 'enforce';
  const start = since === null || since === undefined ? null : Date.parse(since);
  if (start === null || Number.isNaN(start)) return 'log';
  return now >= start + LOG_DAYS * 86400000 ? 'enforce' : 'log';
}

// The threat list as sorted [start, end] ranges, IPv4 as numbers and IPv6 as BigInts, built once per list.
let built = { from: null, v4: [], v6: [] };
function rangesOf(list) {
  if (built.from === list) return built;
  const v4 = []; const v6 = [];
  for (const x of list) {
    const [base, bits] = String(x).split('/');
    if (base.includes(':')) {
      const b = ipv6(base); const n = bits === undefined ? 128 : Number(bits);
      if (b === null || !(n >= 0 && n <= 128)) continue;
      const span = (1n << BigInt(128 - n)) - 1n;
      const start = b & ~span & ((1n << 128n) - 1n);
      v6.push([start, start + span]);
      continue;
    }
    const b = ipv4(base); const n = bits === undefined ? 32 : Number(bits);
    if (b === null || !(n >= 0 && n <= 32)) continue;
    const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
    const start = (b & mask) >>> 0;
    v4.push([start, start + (2 ** (32 - n)) - 1]);
  }
  v4.sort((a, c) => a[0] - c[0]);
  v6.sort((a, c) => (a[0] < c[0] ? -1 : a[0] > c[0] ? 1 : 0));
  built = { from: list, v4, v6 };
  return built;
}
function inSorted(rs, a) {
  let lo = 0; let hi = rs.length - 1;
  // Ranges can nest (a /32 inside a /16), so walk back from the last start at or below the address.
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (rs[mid][0] <= a) lo = mid + 1; else hi = mid - 1; }
  for (let i = hi; i >= 0 && i > hi - 64; i--) if (a <= rs[i][1]) return true;
  return false;
}
function listed(ip, list) {
  const addr = mapped(String(ip || ''));
  const r = rangesOf(list);
  const a = ipv4(addr);
  if (a !== null) return inSorted(r.v4, a);
  const b = ipv6(addr);
  return b !== null && inSorted(r.v6, b);
}

// The query split into its free-text part (a search box: only flagged) and the rest.
function splitQuery(query) {
  let free = '';
  const rest = String(query || '').split('&').filter((pair) => {
    const name = decode(pair.split('=')[0]).toLowerCase();
    if (FREE_TEXT.has(name)) { free += ' ' + pair.slice(pair.indexOf('=') + 1); return false; }
    return true;
  }).join('&');
  return { free, rest };
}

// req: { method, path, query, ua, ip, country, headers: { name: value }, body }. badAddresses: the wiki's list.
// Returns { rule, kind, action: 'allow' | 'flag' | 'block', status, enforced }.
function decide(req, { badAddresses = [], now = Date.now(), since = null } = {}) {
  const hit = (rule, kind, action, status) => {
    const m = mode(rule, now, since);
    return { rule, kind, action, status, enforced: m === 'enforce' && action === 'block' };
  };
  const country = String(req.country || '').toUpperCase();
  if (BLOCKED_COUNTRIES.includes(country)) return hit('W34', 'country ' + country, 'block', 403);
  const ip = mapped(String(req.ip || ''));
  if (ip && listed(ip, badAddresses)) return hit('W38', 'threat-list address', 'block', 403);
  const ua = String(req.ua || '');
  if (match.scanner(ua)) return hit('W37', 'attack scanner', 'block', 403);
  // What is read is capped, and a request too long to read in full is refused outright.
  if (String(req.path || '').length + String(req.query || '').length > MAX_TARGET) return hit('W35', 'oversized request', 'block', 414);
  if (match.probe(req.path)) return hit('W37', 'probe for a file this site does not serve', 'block', 404);
  const { free, rest } = splitQuery(req.query);
  // The path and query: an attack in any spelling is refused.
  const kind = match.attackRaw(String(req.path || '') + '?' + rest, MAX_TARGET);
  if (kind) return hit('W35', kind, 'block', 403);
  // Headers: the user agent, the referer, cookies and any other header a person or a tool can set.
  const headers = Object.assign({}, req.headers || {});
  if (ua) headers['user-agent'] = ua;
  for (const [name, value] of Object.entries(headers)) {
    const n = String(name).toLowerCase();
    if (SKIP_HEADERS.has(n)) continue;
    let v = String(value || '').slice(0, MAX_TARGET);
    // A referer is a URL from another page: its search box is free text, like this site's own.
    if (n === 'referer' || n === 'origin') { const q = v.indexOf('?'); if (q !== -1) { const sp = splitQuery(v.slice(q + 1)); v = v.slice(0, q) + '?' + sp.rest; } }
    // A cookie or header value is one value, not a shell line: ";" separates cookies, so commands need a stronger sign.
    let k;
    if (n === 'cookie') {
      // Each cookie's value as one value; and the whole header for anything but commands (";" is its separator).
      // A piece with no "=" belongs to the value before it (pref=x;id is pref "x;id" to a careless server).
      const vals = [];
      for (const part of v.split(';')) { if (part.includes('=') || !vals.length) vals.push(part.slice(part.indexOf('=') + 1)); else vals[vals.length - 1] += ';' + part; }
      k = match.attackRaw(vals.join(' '), MAX_TARGET);
      if (!k) { const w = match.attackRaw(v, MAX_TARGET); if (w && w !== 'command') k = w; }
    } else k = match.attackRaw(v, MAX_TARGET);
    if (k) return hit('W35', k + ' in header ' + n.slice(0, 40), 'block', 403);
  }
  // The body (the first 64 KB). The site's own forms and API carry people's writing, which can talk about attacks, so
  // a body that looks like one is flagged for the Wall's reviewers (code people submit can hold templates and shell
  // lines honestly); a Log4Shell lookup in a body is refused, since no honest form sends one.
  // 088: files sent in the body (a multipart form) go through the Wall's file scanner before any route sees them.
  if (req.bodyBytes && req.contentType) {
    const u = upload.check(req.bodyBytes, req.contentType);
    if (u) return hit(u.rule, u.kind, 'block', 403);
  }
  const bodyText = req.bodyBytes && upload.boundaryOf(req.contentType) ? upload.textOnly(req.bodyBytes, req.contentType) : req.body;
  if (bodyText) {
    const k = match.attackRaw(String(bodyText).slice(0, MAX_BODY), MAX_BODY);
    if (k === 'lookup') return hit('W35', k + ' in body', 'block', 403);
    if (k) return hit('W35', k + ' in body', 'flag', 200);
  }
  if (match.weakRaw(rest + ' ' + free, MAX_TARGET)) return hit('W35', 'attack-like words', 'flag', 200);
  const rate = overRate(ip, now);
  if (rate === 'address' || rate === 'network') return hit('W36', 'rate (' + rate + ')', 'block', 429);
  if (rate === 'instance') return hit('W36', 'rate (whole site, alert)', 'flag', 200);
  if (!ua.trim()) return hit('W37', 'no user agent', 'flag', 200);
  return { rule: null, kind: null, action: 'allow', status: 200, enforced: false };
}

module.exports = { decide, inRange, ipv4, ipv6, decode, mode, listed, rateKey, netKey, BLOCKED_COUNTRIES, RATE_PER_MINUTE, LOG_DAYS, MAX_TRACKED, MAX_TARGET, MAX_BODY, NETWORK_FACTOR, INSTANCE_ALERT };
