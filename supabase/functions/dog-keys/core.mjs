// The site's key broker, route B (Aaron, Oct 26; harness/PLAN.md fixes 5 and 8). It hands the site its database login
// and its three keys, and only to a production function of our own Vercel project, proved by Vercel's identity token
// (../_shared/vercel-oidc.mjs). The same code deployed to the preview copy's Supabase branch serves only that branch's
// own login and keys, and only to preview functions of the same project (./target.mjs; design/preview-copy.md). Nothing is pasted anywhere: migration 022 made the login's password inside the database,
// and the keys were already in Supabase Vault.
// The CSO's control 1, "hand out less": exactly what the site needs to sign people in and reach the database, nothing
// else (not the timer secret: the site never holds one under route B; not the JEVs gate's or the runner's).
// Plain JavaScript, so the tests run it in Node with a fake database and fake tokens.
// Since 057 (RK135, RK100; Aaron, Nov 10) it also answers Second and Third Look's own Vercel project ("looks"), proved
// by that project's own identity token, with the looks login (dog_looks_web) and nothing else: none of the site's
// keys, not the site's login. The site's token gets exactly what it got before, and never the looks login.

export const PROJECT_REF = 'nksagchwpyljvjiwolmp';
// Supabase's shared pooler in transaction mode. Which of its two us-east-1 clusters serves this project isn't
// recorded; the site's readiness check (/api/ready) tries each and reports which one answers.
export const POOLER_HOSTS = ['aws-0-us-east-1.pooler.supabase.com', 'aws-1-us-east-1.pooler.supabase.com'];
// Vault name -> the setting name the site reads (signin/config.js). The keys are sent as base64 of their exact bytes,
// which is the form the site reads, so the site and the JEVs gate use the same key bytes.
export const KEYS = { dog_session_secret: 'SESSION_SECRET', dog_ip_hash_key: 'IP_HASH_KEY', dog_fingerprint_key_1: 'FINGERPRINT_KEY_1' };
// The Vault entry's name (not a secret): migration 022 keeps the site login's password under it.
const LOGIN_ENTRY = 'dog_web_password';
// And migration 057 the looks login's.
const LOOKS_ENTRY = 'dog_looks_web_password';
const MIN_KEY_BYTES = 32;

const b64 = (s) => {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const x of bytes) bin += String.fromCharCode(x);
  return btoa(bin);
};

// Reads the four values from Vault in one query (for the looks project, its login's password only, 057). Never logged
// or kept beyond the reply. extra: on the preview branch only, the preview copy's mark (./target.mjs); production asks
// for exactly the four (or the one).
export async function read(sql, project = 'site', extra = []) {
  const names = [...(project === 'looks' ? [LOOKS_ENTRY] : [LOGIN_ENTRY, ...Object.keys(KEYS)]), ...extra];
  const rows = await sql`select name, decrypted_secret as v from vault.decrypted_secrets where name = any(${names})`;
  return Object.fromEntries(rows.map((r) => [r.name, r.v]));
}

// What the looks project gets (057): its database login, and nothing else. ref and marker: as shape() takes them.
export function shapeLooks(v, { ref = PROJECT_REF, marker = null } = {}) {
  const missing = [];
  if (marker && v[marker] !== 'yes') missing.push(marker);
  if (typeof v[LOOKS_ENTRY] !== 'string' || v[LOOKS_ENTRY].length < 32) missing.push(LOOKS_ENTRY);
  if (missing.length) return { missing };
  return { database: { user: 'dog_looks_web.' + ref, password: v[LOOKS_ENTRY], hosts: POOLER_HOSTS, port: 6543, database: 'postgres' } };
}

// What the site gets, or which part is missing (names only). A key shorter than 32 bytes is reported as unusable
// rather than sent, so the site never runs with a weak key. ref: the project whose pooler login is handed out
// (production's unless this is the preview branch, ./target.mjs). marker: a Vault name that must hold "yes" before
// anything is handed out (the preview branch's mark; production requires none).
export function shape(v, { ref = PROJECT_REF, marker = null } = {}) {
  const missing = [];
  if (marker && v[marker] !== 'yes') missing.push(marker);
  if (typeof v[LOGIN_ENTRY] !== 'string' || v[LOGIN_ENTRY].length < 32) missing.push(LOGIN_ENTRY);
  const keys = {};
  for (const [name, setting] of Object.entries(KEYS)) {
    if (typeof v[name] !== 'string' || new TextEncoder().encode(v[name]).length < MIN_KEY_BYTES) missing.push(name);
    else keys[setting] = b64(v[name]);
  }
  if (missing.length) return { missing };
  return {
    database: { user: 'dog_web.' + ref, password: v[LOGIN_ENTRY], hosts: POOLER_HOSTS, port: 6543, database: 'postgres' },
    keys
  };
}

// The CSO's control 3 (027): each hand-out, and each failure once the database is reached, adds one to this hour's
// count (app.broker_note; counts only, never a value). The timers alert Aaron on an unusual hour and on any failure.
// Counting is best effort: if it fails, the answer is the same. Refused tokens aren't counted here (counting them
// would let anyone make the broker open database connections); they stay in the function's log.
async function count(note, outcome) {
  if (!note) return;
  try { await note(outcome); } catch { /* the answer never depends on the count */ }
}

// One request: { method, token } -> { status, body }. verify throws Refused for a token that isn't ours, and hands back
// which of our projects it is (057): the site's gets the site's login and keys, the looks project's its login only.
// ref and marker: as shape() takes them, fixed when the function starts (./target.mjs), never from the request.
export async function handle({ method, token }, { verify, Refused, values, note, ref = PROJECT_REF, marker = null }) {
  if (method !== 'POST') return { status: 405, body: { ok: false, error: 'POST only' } };
  let claims;
  try {
    claims = await verify(token);
  } catch (e) {
    if (Refused && e instanceof Refused) return { status: 401, body: { ok: false, error: 'refused: ' + e.message } };
    throw e;
  }
  const project = claims && claims.our_project;
  if (project !== 'site' && project !== 'looks') return { status: 401, body: { ok: false, error: 'refused: wrong project' } };
  let v;
  try {
    v = await values(project);
  } catch (e) {
    await count(note, 'failed');
    throw e;
  }
  const out = project === 'looks' ? shapeLooks(v, { ref, marker }) : shape(v, { ref, marker });
  if (out.missing) {
    await count(note, 'failed');
    return { status: 503, body: { ok: false, error: 'not set up', missing: out.missing } };
  }
  await count(note, 'handed');
  return { status: 200, body: { ok: true, ...out } };
}
