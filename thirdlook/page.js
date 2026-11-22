// Third Look reads a submitted link (070; Aaron, Nov 21, 2026: "I want the full capabilities of third look
// implemented"). The timer fetches the page itself, carefully, because the address comes from the public:
//   - https only, on port 443, to a name that resolves only to public addresses (never this computer, a private
//     network, link-local or cloud metadata addresses), checked again on every redirect, at most 3 redirects;
//   - no credentials, no cookies and no identity token are ever sent: a plain GET with our own user agent;
//   - at most 500 KB and 8 seconds; text only (HTML, plain text, Markdown, JSON or XML). Anything else, and any failure,
//     is "couldn't read": the work stays with a person.
// The page's text (tags, scripts and styles removed) is what the model reads; its SHA-256 is recorded beside the answer.
'use strict';

const dnsCb = require('dns');
const dns = dnsCb.promises;
const https = require('https');
const net = require('net');
const crypto = require('crypto');

const MAX_BYTES = 500 * 1024;
const TIMEOUT_MS = 8000;
const MAX_TEXT = 30000;
const TYPES = /^(text\/(html|plain|markdown)|application\/(json|xml|xhtml\+xml)|text\/xml)\b/i;

function privateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
      || (a === 100 && b >= 64 && b <= 127) || a >= 224 || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    if (x === '::' || x === '::1') return true;
    if (x.startsWith('::ffff:')) return privateAddress(x.slice(7));
    // Unique-local, link- and site-local, multicast, NAT64, documentation, 6to4 (which can wrap a private IPv4
    // address), IPv4-compatible and the discard prefix (the fresh review, L1).
    return /^(fc|fd|fe[89ab]|fe[c-f]|ff)/.test(x) || x.startsWith('64:ff9b:') || x.startsWith('2001:db8') || x.startsWith('2002:')
      || /^::(\d+\.){3}\d+$/.test(x) || x.startsWith('100::');
  }
  return true;
}

// Whether a URL may be fetched: https, port 443, a name (not an address) that resolves only to public addresses.
async function allowed(raw, { lookup = (h) => dns.lookup(h, { all: true }) } = {}) {
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== 'https:' || (u.port && u.port !== '443') || u.username || u.password) return null;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) || !/\./.test(host) || /\.(local|internal|localhost)$/i.test(host)) return null;
  let addrs;
  try { addrs = await lookup(host); } catch { return null; }
  if (!Array.isArray(addrs) || !addrs.length || addrs.some((a) => privateAddress(a.address))) return null;
  return u;
}

function toText(body, type) {
  let s = body;
  if (/html|xml/i.test(type)) {
    s = s.replace(/<(script|style|noscript|template)[\s\S]*?<\/\1>/gi, ' ').replace(/<!--[\s\S]*?-->/g, ' ').replace(/<[^>]+>/g, ' ')
      .replace(/&#x([0-9a-f]{1,6});/gi, (m, h) => { const n = parseInt(h, 16); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ' '; })
      .replace(/&#(\d{1,7});/g, (m, d) => { const n = Number(d); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ' '; })
      .replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      // &amp; last, so "&amp;lt;" stays "&lt;" (CodeQL, double unescaping).
      .replace(/&amp;/g, '&');
  }
  return s.replace(/[ \t\r\f\v]+/g, ' ').replace(/\n\s*\n+/g, '\n\n').trim();
}

// The fetch itself, with the address checked at the moment of connecting (the fresh review, M1: a name can resolve
// one way when checked and another when fetched). The socket only ever opens to an address the check allowed.
function pinnedLookup(host, opts, cb) {
  dnsCb.lookup(host, { all: true }, (err, addrs) => {
    if (err) return cb(err);
    if (!addrs.length || addrs.some((a) => privateAddress(a.address))) return cb(new Error('address not allowed'));
    if (opts && opts.all) return cb(null, addrs);
    return cb(null, addrs[0].address, addrs[0].family);
  });
}
function pinnedFetch(url, { headers }) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: 'GET', headers, lookup: pinnedLookup, timeout: TIMEOUT_MS }, (res) => {
      const chunks = [];
      let size = 0;
      let cut = false;
      if (res.statusCode >= 300 && res.statusCode < 400) { res.resume(); return resolve({ status: res.statusCode, headers: { get: (k) => res.headers[k.toLowerCase()] || null }, text: async () => '' }); }
      res.on('data', (c) => { if (cut) return; size += c.length; if (size > MAX_BYTES) { cut = true; chunks.push(c.subarray(0, c.length - (size - MAX_BYTES))); req.destroy(); } else chunks.push(c); });
      const done = () => resolve({ status: res.statusCode, headers: { get: (k) => res.headers[k.toLowerCase()] || null }, cut, text: async () => Buffer.concat(chunks).toString('utf8') });
      res.on('end', done);
      res.on('close', () => { if (cut) done(); });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { name: 'TimeoutError' })));
    req.on('error', reject);
    req.end();
  });
}

// { text, sha256, truncated, url } or { error }. Never throws.
async function read(raw, { fetchImpl, lookup } = {}) {
  let url = raw;
  for (let hop = 0; hop <= 3; hop++) {
    const u = await allowed(url, lookup ? { lookup } : {});
    if (!u) return { error: 'address not allowed' };
    let r;
    try {
      const headers = { 'user-agent': 'DayOneGreat-ThirdLook/1 (+https://dayonegreat.com/checks)', accept: 'text/html, text/plain, application/json;q=0.9, */*;q=0.1' };
      r = fetchImpl ? await fetchImpl(u.toString(), { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS), headers })
        : await pinnedFetch(u.toString(), { headers });
    } catch (e) {
      return { error: e && (e.name === 'TimeoutError' || e.name === 'AbortError') ? 'timeout' : e && e.message === 'address not allowed' ? 'address not allowed' : 'network' };
    }
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get('location');
      if (!loc) return { error: 'redirect without an address' };
      url = new URL(loc, u).toString();
      continue;
    }
    if (r.status !== 200) return { error: 'page answered ' + r.status };
    const type = String(r.headers.get('content-type') || '');
    if (!TYPES.test(type)) return { error: 'not text' };
    const len = Number(r.headers.get('content-length'));
    if (len && len > MAX_BYTES) return { error: 'too large' };
    let buf = Buffer.alloc(0);
    let truncated = Boolean(r.cut);
    try {
      if (r.body && r.body.getReader) {
        const reader = r.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf = Buffer.concat([buf, Buffer.from(value)]);
          if (buf.length > MAX_BYTES) { truncated = true; buf = buf.subarray(0, MAX_BYTES); try { await reader.cancel(); } catch { /* fine */ } break; }
        }
      } else {
        buf = Buffer.from(await r.text());
        if (buf.length > MAX_BYTES) { truncated = true; buf = buf.subarray(0, MAX_BYTES); }
      }
    } catch { return { error: 'network' }; }
    let text = toText(buf.toString('utf8'), type);
    if (text.length > MAX_TEXT) { truncated = true; text = text.slice(0, MAX_TEXT); }
    if (!text) return { error: 'empty page' };
    return { text, truncated, url: u.toString(), sha256: crypto.createHash('sha256').update(text).digest('hex') };
  }
  return { error: 'too many redirects' };
}

module.exports = { read, allowed, pinnedLookup, privateAddress, toText, MAX_BYTES, MAX_TEXT };
