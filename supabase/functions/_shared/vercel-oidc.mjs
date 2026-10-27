// Checks a Vercel identity token (OIDC), so the site's key broker (dog-keys) can tell for certain that the caller is a
// production function of our own Vercel project (route B, Aaron, Oct 26; harness/PLAN.md fix 8). Vercel signs the
// token and hands it to each function request in the x-vercel-oidc-token header; anyone can check the signature
// against Vercel's published keys (https://vercel.com/docs/oidc/reference).
// Our project uses the team issuer (checked Oct 26 by the oidc-probe branch). The global issuer is accepted too (the
// CSO's control 5), so a change of that project setting can't lock the site out; every other claim is checked the
// same either way. Plain JavaScript with Web Crypto, so it runs in Supabase (Deno) and in the tests (Node), like
// github-oidc.mjs.

export const TEAM_SLUG = 'chief-os';
export const TEAM_ID = 'team_Hv5YS8LhIiKe06SSiDrUucd4';
export const PROJECT_ID = 'prj_cXnWySYVpJE9TVZaNPSocXMMzkZI';
export const ISSUERS = ['https://oidc.vercel.com/' + TEAM_SLUG, 'https://oidc.vercel.com'];
export const AUDIENCE = 'https://vercel.com/' + TEAM_SLUG;
const MAX_TOKEN = 8192;
const MAX_LIFE = 2 * 3600 + 300; // Vercel's function tokens last two hours
const SKEW = 60; // seconds of clock difference allowed

const b64url = (s) => {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const json = (s) => JSON.parse(new TextDecoder().decode(b64url(s)));

const caches = new Map();
// Each issuer's keys, cached for an hour; an unknown key ID refetches once, at most once a minute.
async function vercelKeys(issuer, { refresh = false } = {}) {
  const c = caches.get(issuer) || { at: 0, keys: null };
  const age = Date.now() - c.at;
  if (c.keys && age < 3600_000 && !(refresh && age > 60_000)) return c.keys;
  const r = await fetch(issuer + '/.well-known/jwks', { redirect: 'error' });
  if (!r.ok) throw new Error('Vercel keys unavailable: ' + r.status);
  const body = await r.json();
  const next = { at: Date.now(), keys: body.keys || [] };
  caches.set(issuer, next);
  return next.keys;
}

class Refused extends Error {}

// Returns the token's claims if every check passes; throws Refused otherwise, naming the first failed check.
// Only production is accepted: a preview deployment of any branch also gets a token, and must get nothing.
export async function verify(token, { now = Date.now() / 1000, keys = vercelKeys, environment = 'production' } = {}) {
  const no = (why) => { throw new Refused(why); };
  if (typeof token !== 'string' || !token || token.length > MAX_TOKEN) no('token missing or too large');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) no('not a signed token');
  let header, claims;
  try { header = json(parts[0]); claims = json(parts[1]); } catch { no('unreadable token'); }
  if (!header || !claims || typeof claims !== 'object') no('unreadable token');
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') no('wrong signature type');
  // The issuer picks which published keys to check against; an unknown issuer is refused before any fetch.
  if (!ISSUERS.includes(claims.iss)) no('wrong issuer');
  const find = (list) => list.find((k) => k.kid === header.kid && k.kty === 'RSA');
  const jwk = find(await keys(claims.iss)) || find(await keys(claims.iss, { refresh: true }));
  if (!jwk) no('signed by an unknown key');
  const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64url(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
  if (!ok) no('signature does not match');

  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(AUDIENCE)) no('wrong audience');
  if (typeof claims.exp !== 'number' || claims.exp < now - SKEW) no('expired');
  if (typeof claims.iat !== 'number' || claims.iat > now + SKEW) no('from the future');
  if (claims.exp - claims.iat > MAX_LIFE) no('lives too long');
  if (typeof claims.nbf === 'number' && claims.nbf > now + SKEW) no('not valid yet');
  if (claims.owner_id !== TEAM_ID) no('wrong team');
  if (claims.project_id !== PROJECT_ID) no('wrong project');
  if (claims.environment !== environment) no('wrong environment');
  if (typeof claims.sub !== 'string' || !claims.sub.startsWith('owner:' + TEAM_SLUG + ':project:') || !claims.sub.endsWith(':environment:' + environment)) no('wrong subject');
  return claims;
}

export { Refused };
