// Sign-in settings, read from environment variables that Aaron sets in Vercel (Production only). Claude never sees
// their values. If anything required is missing, sign-in stays switched off rather than running half set up, and
// preview deployments, which don't get production secrets, are always off.
'use strict';

const ORIGIN = 'https://dayonegreat.com';
const HOST = 'dayonegreat.com';

const SESSION_DAYS = 30; // absolute limit
const IDLE_DAYS = 7; // ends after a week unused
const STATE_MINUTES = 10; // an unfinished GitHub or X sign-in expires after this

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
  const fingerprintKeys = parseKeys(env.FINGERPRINT_KEYS);
  const ipKey = strong(env.IP_HASH_KEY) && Buffer.from(env.IP_HASH_KEY, 'base64');
  const ready = Boolean(sessionKey && fingerprintKeys && ipKey);
  const pair = (id, s) => (env[id] && env[s] ? { clientId: env[id], clientSecret: env[s] } : null);
  return {
    ready,
    sessionKey,
    fingerprintKeys,
    ipKey,
    github: pair('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'),
    x: pair('X_CLIENT_ID', 'X_CLIENT_SECRET'),
    // LinkedIn's "Verified on LinkedIn" waits for LinkedIn's app review; it stays off until then.
    linkedin: null,
    // The email service is still Aaron's choice; until it is set up, email links are off.
    email: null
  };
}

module.exports = { ORIGIN, HOST, SESSION_DAYS, IDLE_DAYS, STATE_MINUTES, load, parseKeys };
