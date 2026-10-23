// Sign-in settings, read from environment variables that Aaron sets in Vercel (Production only). Claude never sees
// their values. If anything required is missing, sign-in stays switched off rather than running half set up, and
// preview deployments, which don't get production secrets, are always off.
'use strict';

const ORIGIN = 'https://dayonegreat.com';
const HOST = 'dayonegreat.com';

const SESSION_DAYS = 30; // absolute limit
const IDLE_DAYS = 7; // ends after a week unused
const STATE_MINUTES = 10; // an unfinished GitHub or X sign-in expires after this

// Fingerprint keys, one setting each: FINGERPRINT_KEY_1, FINGERPRINT_KEY_2, ... The highest number is the
// current key; older ones stay so people can be recognised and moved over at their next sign-in. Separate settings
// mean a rotation only adds one, and no key ever has to be read back (each is stored as a Vercel secret).
function keysFromEnv(env) {
  const found = Object.keys(env).map((k) => k.match(/^FINGERPRINT_KEY_(\d{1,3})$/)).filter(Boolean)
    .map((m) => ({ version: Number(m[1]), b64: env[m[0]] })).filter((k) => k.version >= 1)
    .sort((a, b) => b.version - a.version);
  if (!found.length) return null;
  return parseKeys(found.map((k) => k.version + ':' + k.b64).join(','));
}

// "2:base64key,1:base64key": current key first. Each key at least 32 bytes.
function parseKeys(s) {
  if (!s) return null;
  const keys = [];
  for (const part of String(s).split(',')) {
    const m = part.trim().match(/^(\d{1,3}):([A-Za-z0-9+/=_-]+)$/);
    if (!m) return null;
    const key = Buffer.from(m[2], 'base64');
    if (key.length < 32) return null;
    keys.push({ version: Number(m[1]), key });
  }
  if (!keys.length || keys.length > 5 || new Set(keys.map((k) => k.version)).size !== keys.length) return null;
  return keys;
}

// A base64 key of at least 32 bytes, or null.
const strong = (b64) => (b64 && Buffer.from(b64, 'base64').length >= 32 ? b64 : null);

function load(env = process.env) {
  const sessionKey = strong(env.SESSION_SECRET);
  const fingerprintKeys = keysFromEnv(env);
  const ipKey = strong(env.IP_HASH_KEY) && Buffer.from(env.IP_HASH_KEY, 'base64');
  const ready = Boolean(sessionKey && fingerprintKeys && ipKey);
  const pair = (id, s) => (env[id] && env[s] ? { clientId: env[id], clientSecret: env[s] } : null);
  return {
    ready,
    sessionKey,
    fingerprintKeys,
    ipKey,
    // The JEVs gateway holds only GitHub's (public) client ID: it checks tokens, and Vercel, which holds the secret,
    // swaps codes for them (GATEWAY.md). In-process sign-in still needs both.
    github: pair('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET') || (env.GITHUB_CLIENT_ID && env.DOG_GATEWAY === '1' ? { clientId: env.GITHUB_CLIENT_ID, clientSecret: null } : null),
    x: pair('X_CLIENT_ID', 'X_CLIENT_SECRET'),
    // LinkedIn was dropped on Oct 16, 2026 (CHARTER.md). The provider name stays in the schema, unused, as built.
    linkedin: null
    // Email links go out through Amazon SES (notify/sender.js, EMAIL-SETUP.md); without it they stay off.
  };
}

module.exports = { ORIGIN, HOST, SESSION_DAYS, IDLE_DAYS, STATE_MINUTES, load, parseKeys, keysFromEnv };
