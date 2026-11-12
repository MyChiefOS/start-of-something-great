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

// 037 (Aaron, Nov 5, 2026): what a browser key signs at every sign-in, the same bytes as app.signin_message in the
// database: a fixed label, this site's address and the one-time challenge, one per line.
const signinMessage = (origin, challenge) => Buffer.from('dayonegreat-signin-v1\n' + origin + '\n' + challenge, 'utf8');

// Whether sig (r || s, 64 bytes, as Web Crypto gives it) is an ECDSA P-256 SHA-256 signature of msg by pub (the raw
// uncompressed point, 65 bytes). Node's own crypto; the database checks the same signature again itself
// (app.p256_verify), and only its answer signs anyone in.
function p256Verify(pub, msg, sig) {
  try {
    if (!Buffer.isBuffer(pub) || pub.length !== 65 || pub[0] !== 4 || !Buffer.isBuffer(sig) || sig.length !== 64) return false;
    const key = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64url(pub.subarray(1, 33)), y: b64url(pub.subarray(33)) }, format: 'jwk' });
    return crypto.verify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, sig);
  } catch {
    return false;
  }
}

// 063, buyer keys (WebAuthn): the browser hands over the public key as SubjectPublicKeyInfo DER. Only an uncompressed
// P-256 key is accepted: the fixed 26-byte header for id-ecPublicKey with prime256v1, then the 65-byte point.
const P256_SPKI = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
function p256FromSpki(der) {
  if (!Buffer.isBuffer(der) || der.length !== 91 || !der.subarray(0, 26).equals(P256_SPKI) || der[26] !== 4) return null;
  return Buffer.from(der.subarray(26));
}
// A WebAuthn signature is DER (SEQUENCE of two INTEGERs); the database checks r || s, 32 bytes each.
function derToRaw(der) {
  if (!Buffer.isBuffer(der) || der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) return null;
  let i = 2;
  const part = () => {
    if (der[i] !== 0x02) return null;
    const len = der[i + 1];
    if (len < 1 || len > 33 || i + 2 + len > der.length) return null;
    let x = der.subarray(i + 2, i + 2 + len);
    i += 2 + len;
    if (x.length === 33) { if (x[0] !== 0) return null; x = x.subarray(1); }
    const out = Buffer.alloc(32);
    x.copy(out, 32 - x.length);
    return out;
  };
  const r = part();
  const s2 = r && part();
  return r && s2 && i === der.length ? Buffer.concat([r, s2]) : null;
}

module.exports = { token, sha256hex, hmacHex, same, pkce, subkey, seal, open, fingerprints, signinMessage, p256Verify, p256FromSpki, derToRaw };
