// Request and response helpers for sign-in: cookies, same-site checks, form bodies, return paths and IP ranges.
'use strict';

const { hmacHex } = require('./crypto');
const { ORIGIN, HOST } = require('./config');

function cookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

// __Host- cookies: Secure, no Domain, Path=/, so only dayonegreat.com itself can set or read them.
function cookie(name, value, { maxAge }) {
  return name + '=' + value + '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=' + maxAge;
}
const clear = (name) => cookie(name, '', { maxAge: 0 });

function addCookie(res, c) {
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, c) : [c]);
}

// Only the real site answers sign-in requests: not preview deployments, other hosts, or plain HTTP.
function onSite(req) {
  return String(req.headers.host || '').toLowerCase() === HOST;
}

// A form post that changes something must come from our own pages: the Origin header must be ours, and if the
// browser says where the request came from, it must say same-origin. A request with no Origin is refused.
function sameSite(req) {
  if (req.headers.origin !== ORIGIN) return false;
  const site = req.headers['sec-fetch-site'];
  return site === undefined || site === 'same-origin';
}

// Reads a small urlencoded form body (at most 2 KB).
async function form(req, max = 2048) {
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/x-www-form-urlencoded') return null;
  if (req.body !== undefined && req.body !== null) {
    // Vercel may have parsed it already.
    if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      return Buffer.byteLength(JSON.stringify(req.body)) > max ? null : req.body;
    }
    const s = String(req.body);
    return s.length > max ? null : Object.fromEntries(new URLSearchParams(s));
  }
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > max) return null;
    chunks.push(c);
  }
  return Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
}

// Where to go after signing in: a path on this site only. Anything else (other sites, "//host", "/\\host",
// schemes, control characters) goes home.
function returnPath(p) {
  if (typeof p !== 'string' || p.length > 200) return '/';
  if (!/^\/(?![/\\])[A-Za-z0-9\-._~/?=&%]*$/.test(p)) return '/';
  return p;
}

// A keyed, daily-changing hash of the visitor's IP range, for rate limits only (S6). The raw address is never kept.
// IPv4 is used whole; IPv6 is grouped by /64, the block one household or phone usually gets.
// On Vercel, x-vercel-forwarded-for is set by Vercel itself and can't be supplied by the visitor.
function ipRange(req) {
  let raw = String(req.headers['x-vercel-forwarded-for'] || '').split(',')[0].trim();
  // An IPv4 address written the IPv6 way (::ffff:1.2.3.4) is the IPv4 address.
  const mapped = raw.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mapped) raw = mapped[1];
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) return raw;
  if (raw.includes(':')) {
    const parts = expand6(raw);
    if (parts) return parts.slice(0, 4).join(':') + '::/64';
  }
  return 'unknown';
}
function expand6(a) {
  if (!/^[0-9a-fA-F:]+$/.test(a)) return null;
  const [head, tail] = a.split('::');
  if (a.split('::').length > 2) return null;
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail ? tail.split(':') : [];
  const fill = tail !== undefined ? 8 - h.length - t.length : 0;
  if (fill < 0 || (tail === undefined && h.length !== 8)) return null;
  return [...h, ...Array(fill).fill('0'), ...t].map((x) => x.toLowerCase().replace(/^0+(?=.)/, ''));
}
function ipKey(req, key, day = new Date().toISOString().slice(0, 10)) {
  return hmacHex(hmacHex(key, 'ip ' + day), ipRange(req));
}

function redirect(res, location, status = 303) {
  res.statusCode = status;
  res.setHeader('Location', location);
  res.setHeader('Cache-Control', 'no-store');
  res.end();
}

module.exports = { cookies, cookie, clear, addCookie, onSite, sameSite, form, returnPath, ipRange, ipKey, redirect };
