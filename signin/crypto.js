// Small cryptographic helpers for sign-in, all from Node's own crypto module (no packages).
'use strict';

const crypto = require('crypto');

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const token = (bytes = 32) => b64url(crypto.randomBytes(bytes)); // 256 bits by default
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hmacHex = (key, s) => crypto.createHmac('sha256', key).update(s, 'utf8').digest('hex');

// Constant-time comparison of two strings, so a wrong guess takes as long as a nearly right one.
function same(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// PKCE (RFC 7636), S256 only.
function pkce() {
  const verifier = token(32);
  return { verifier, challenge: b64url(crypto.createHash('sha256').update(verifier).digest()) };
}

// Separate keys for separate jobs, all derived from SESSION_SECRET (HKDF, RFC 5869).
function subkey(material, purpose) {
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(material, 'base64'), Buffer.alloc(0), 'dayonegreat ' + purpose, 32));
}

// Sealed values (AES-256-GCM): the browser can carry them but can't read or change them. Used for the short-lived
// OAuth state cookie, so it needs no database row.
function seal(key, obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const body = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return b64url(Buffer.concat([iv, c.getAuthTag(), body]));
}
function open(key, sealed) {
  try {
    const raw = Buffer.from(String(sealed), 'base64url');
    if (raw.length < 29 || raw.length > 2048) return null;
    // The tag length is pinned at 16 bytes, so a shortened tag can't be accepted.
    const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12), { authTagLength: 16 });
    d.setAuthTag(raw.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8'));
  } catch {
    return null;
  }
}

// A provider account's fingerprint under each key still in use, current key first (S12). It is keyed
// pseudonymization: without the keys (kept outside the database) a fingerprint can't be traced back to an account.
function fingerprints(keys, provider, accountId) {
  return keys.map((k) => hmacHex(k.key, provider + ':' + String(accountId)));
}

module.exports = { token, sha256hex, hmacHex, same, pkce, subkey, seal, open, fingerprints };
