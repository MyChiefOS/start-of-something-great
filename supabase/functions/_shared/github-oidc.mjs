// Checks a GitHub Actions identity token (OIDC), so a Supabase function can tell for certain which workflow, on
// which branch of which repository, is calling it (USE-CASES.md row 16). No password or key is shared: GitHub signs
// the token, and anyone can check the signature against GitHub's published keys.
// Used by the database runner (dog-migrate) and, from PR 3, the JEVs gate. Plain JavaScript with Web Crypto, so the
// same file runs in Supabase (Deno) and in the tests (Node).

export const ISSUER = 'https://token.actions.githubusercontent.com';
export const JWKS_URL = ISSUER + '/.well-known/jwks';
// MyChiefOS/start-of-something-great and its owner, by number: a renamed or re-created repository gets new numbers.
export const REPOSITORY_ID = '1418125608';
export const OWNER_ID = '304218593';
const MAX_TOKEN = 8192;
const MAX_AGE = 600; // seconds since GitHub made the token
const SKEW = 60; // seconds of clock difference allowed

const b64url = (s) => {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const json = (s) => JSON.parse(new TextDecoder().decode(b64url(s)));

let cache = { at: 0, keys: null };
async function githubKeys() {
  if (cache.keys && Date.now() - cache.at < 3600_000) return cache.keys;
  const r = await fetch(JWKS_URL, { redirect: 'error' });
  if (!r.ok) throw new Error('GitHub keys unavailable: ' + r.status);
  const body = await r.json();
  cache = { at: Date.now(), keys: body.keys || [] };
  return cache.keys;
}

class Refused extends Error {}

// Returns the token's claims if every check passes; throws Refused otherwise, naming the first failed check.
//   audience     the exact "aud" the workflow asked for (the function's own address)
//   workflow     the workflow file that may call, e.g. '.github/workflows/database.yml'
//   events       the GitHub events allowed to start that workflow
export async function verify(token, { audience, workflow, events, now = Date.now() / 1000, keys = githubKeys, seen = async () => false } = {}) {
  const no = (why) => { throw new Refused(why); };
  if (typeof token !== 'string' || !token || token.length > MAX_TOKEN) no('token missing or too large');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) no('not a signed token');
  let header, claims;
  try { header = json(parts[0]); claims = json(parts[1]); } catch { no('unreadable token'); }
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') no('wrong signature type');
  const jwk = (await keys()).find((k) => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk) no('signed by an unknown key');
  const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64url(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
  if (!ok) no('signature does not match');

  if (claims.iss !== ISSUER) no('wrong issuer');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audience || !aud.includes(audience)) no('wrong audience');
  if (typeof claims.exp !== 'number' || claims.exp < now - SKEW) no('expired');
  if (typeof claims.iat !== 'number' || claims.iat > now + SKEW || now - claims.iat > MAX_AGE) no('too old or from the future');
  if (typeof claims.nbf === 'number' && claims.nbf > now + SKEW) no('not valid yet');
  if (String(claims.repository_id) !== REPOSITORY_ID) no('wrong repository');
  if (String(claims.repository_owner_id) !== OWNER_ID) no('wrong repository owner');
  if (claims.ref !== 'refs/heads/main') no('not the main branch');
  if (claims.workflow_ref !== 'MyChiefOS/start-of-something-great/' + workflow + '@refs/heads/main') no('wrong workflow');
  if (!events.includes(claims.event_name)) no('wrong event');
  if (typeof claims.sha !== 'string' || !/^[0-9a-f]{40}$/.test(claims.sha)) no('no commit');
  if (typeof claims.jti !== 'string' || !claims.jti || claims.jti.length > 100) no('no token ID');
  if (await seen(claims.jti)) no('token already used');
  return claims;
}

export { Refused };
