// Route B (Aaron, Oct 26; harness/PLAN.md fixes 5 and 8): the site gets its database login and its three keys from the
// key broker (supabase/functions/dog-keys), proving itself with the Vercel identity token each production request
// carries (x-vercel-oidc-token). Nothing is pasted into Vercel.
//   * The fallback to Vercel settings (CHARTER.md §2): when the database address is set in Vercel, the broker isn't asked at all
//     and every setting comes from Vercel, exactly as before route B.
//   * The CSO's control 4, site resilience: what the broker gave is kept for this function instance and refreshed in
//     the background after 10 minutes; if the broker can't be reached, the last good answer keeps working.
//   * Settings already present (from Vercel) are never overwritten.
//   * Only while the site is open (launch.js stage "public"), or for the readiness check (/api/ready). While closed,
//     nothing is fetched, so the closed site behaves exactly as before.
// The values are kept only in this function instance's memory (process.env, which is where the rest of the site already
// reads them; the address through db/index.js, G1), never written to a log, a file or a reply.
'use strict';

const BROKER = 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-keys';
const REFRESH_MS = 10 * 60_000;
const TIMEOUT_MS = 3000;

let last = null; // { at, body }
let inflight = null;

function urlFor(d, host) {
  const u = new URL('postgres://' + host + ':' + d.port + '/' + d.database);
  u.username = d.user;
  u.password = d.password;
  return u.toString();
}

// Puts the broker's answer where the site reads it, without overwriting anything Vercel set.
function apply(body, env = process.env) {
  require('./index').setAddress(urlFor(body.database, body.database.hosts[0]), env);
  for (const [k, v] of Object.entries(body.keys || {})) if (!env[k]) env[k] = v;
}

function tokenOf(req) {
  const h = req && req.headers ? req.headers['x-vercel-oidc-token'] : null;
  return typeof h === 'string' && h.length > 20 && h.length <= 8192 ? h : null;
}

async function ask(token, fetchImpl) {
  const r = await fetchImpl(BROKER, { method: 'POST', headers: { authorization: 'Bearer ' + token }, redirect: 'error',
    signal: AbortSignal.timeout(TIMEOUT_MS) });
  let body = null;
  try { body = await r.json(); } catch { /* not JSON */ }
  if (r.status !== 200 || !body || body.ok !== true || !body.database) {
    const e = new Error('broker ' + r.status + (body && body.error ? ': ' + String(body.error).slice(0, 80) : ''));
    e.status = r.status;
    throw e;
  }
  return body;
}

// Makes sure this instance has its settings. Returns where they came from, for /api/ready: 'vercel', 'broker',
// 'cached' (the broker failed; the last good answer is used), 'closed' (not asked) or 'none' (with the reason).
async function ensure(req, { fetchImpl = fetch, force = false, env = process.env, stage = () => require('../launch').stage(env) } = {}) {
  if (require('./index').hasAddress(env) && !last) return { source: 'vercel' };
  if (!force && stage() !== 'public') return { source: 'closed' };
  if (last && Date.now() - last.at < REFRESH_MS) { apply(last.body, env); return { source: 'broker' }; }
  const token = tokenOf(req);
  if (!token) {
    if (last) { apply(last.body, env); return { source: 'cached', error: 'no_token' }; }
    return { source: 'none', error: 'no_token' };
  }
  try {
    if (!inflight) inflight = ask(token, fetchImpl).finally(() => { inflight = null; });
    const body = await inflight;
    last = { at: Date.now(), body };
    apply(body, env);
    return { source: 'broker' };
  } catch (e) {
    if (last) { apply(last.body, env); return { source: 'cached', error: e.message }; }
    return { source: 'none', error: e.message };
  }
}

// For /api/ready: every pooler address the broker named, each with the login it gave.
function candidates() {
  return last ? last.body.database.hosts.map((h) => ({ host: h, url: urlFor(last.body.database, h) })) : [];
}

const _reset = () => { last = null; inflight = null; };

module.exports = { ensure, candidates, apply, BROKER, _reset };
