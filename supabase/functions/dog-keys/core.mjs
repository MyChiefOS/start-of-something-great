// The site's key broker, route B (Aaron, Oct 26; harness/PLAN.md fixes 5 and 8). It hands the site its database login
// and its three keys, and only to a production function of our own Vercel project, proved by Vercel's identity token
// (../_shared/vercel-oidc.mjs). Nothing is pasted anywhere: migration 022 made the login's password inside the database,
// and the keys were already in Supabase Vault.
// The CSO's control 1, "hand out less": exactly what the site needs to sign people in and reach the database, nothing
// else (not the timer secret: the site never holds one under route B; not the JEVs gate's or the runner's).
// Plain JavaScript, so the tests run it in Node with a fake database and fake tokens.

export const PROJECT_REF = 'nksagchwpyljvjiwolmp';
// Supabase's shared pooler in transaction mode. Which of its two us-east-1 clusters serves this project isn't
// recorded; the site's readiness check (/api/ready) tries each and reports which one answers.
export const POOLER_HOSTS = ['aws-0-us-east-1.pooler.supabase.com', 'aws-1-us-east-1.pooler.supabase.com'];
// Vault name -> the setting name the site reads (signin/config.js). The keys are sent as base64 of their exact bytes,
// which is the form the site reads, so the site and the JEVs gate use the same key bytes.
export const KEYS = { dog_session_secret: 'SESSION_SECRET', dog_ip_hash_key: 'IP_HASH_KEY', dog_fingerprint_key_1: 'FINGERPRINT_KEY_1' };
// The Vault entry's name (not a secret): migration 022 keeps the site login's password under it.
const LOGIN_ENTRY = 'dog_web_password';
const MIN_KEY_BYTES = 32;

const b64 = (s) => {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const x of bytes) bin += String.fromCharCode(x);
  return btoa(bin);
};

// Reads the four values from Vault in one query. Never logged or kept beyond the reply.
export async function read(sql) {
  const names = [LOGIN_ENTRY, ...Object.keys(KEYS)];
  const rows = await sql`select name, decrypted_secret as v from vault.decrypted_secrets where name = any(${names})`;
  return Object.fromEntries(rows.map((r) => [r.name, r.v]));
}

// What the site gets, or which part is missing (names only). A key shorter than 32 bytes is reported as unusable
// rather than sent, so the site never runs with a weak key.
export function shape(v) {
  const missing = [];
  if (typeof v[LOGIN_ENTRY] !== 'string' || v[LOGIN_ENTRY].length < 32) missing.push(LOGIN_ENTRY);
  const keys = {};
  for (const [name, setting] of Object.entries(KEYS)) {
    if (typeof v[name] !== 'string' || new TextEncoder().encode(v[name]).length < MIN_KEY_BYTES) missing.push(name);
    else keys[setting] = b64(v[name]);
  }
  if (missing.length) return { missing };
  return {
    database: { user: 'dog_web.' + PROJECT_REF, password: v[LOGIN_ENTRY], hosts: POOLER_HOSTS, port: 6543, database: 'postgres' },
    keys
  };
}

// One request: { method, token } -> { status, body }. verify throws Refused for a token that isn't ours.
export async function handle({ method, token }, { verify, Refused, values }) {
  if (method !== 'POST') return { status: 405, body: { ok: false, error: 'POST only' } };
  try {
    await verify(token);
  } catch (e) {
    if (Refused && e instanceof Refused) return { status: 401, body: { ok: false, error: 'refused: ' + e.message } };
    throw e;
  }
  const out = shape(await values());
  if (out.missing) return { status: 503, body: { ok: false, error: 'not set up', missing: out.missing } };
  return { status: 200, body: { ok: true, ...out } };
}
