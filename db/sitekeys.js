// Route B (Aaron, Oct 26; harness/PLAN.md fixes 5 and 8): the site gets its database login and its three keys from the
// key broker (supabase/functions/dog-keys), proving itself with the Vercel identity token each production request
// carries (x-vercel-oidc-token). Nothing is pasted into Vercel.
//   * The fallback to Vercel settings (CHARTER.md §2): when the database address is set in Vercel, the broker isn't
//     asked at all and every setting comes from Vercel, exactly as before route B.
//   * The CSO's control 4, site resilience: what the broker gave is kept for this function instance and asked again
//     after 10 minutes; if the broker can't be reached, the last good answer keeps working. A changed password (a
//     rotation) replaces the address and ends the old connection pool (the CSO's review, M1).
//   * Settings Vercel set are never overwritten; only what the broker gave is replaced.
//   * The token is removed from the request as soon as it is read, so no later code can echo or forward it (M3).
//   * The site's settings are written only while the site is open (launch.js stage "public"). The readiness check
//     (/api/ready) can ask the broker while closed, but its answer stays inside the check (L2).
//   * The CSO's controls 2 and 4, a refused password never cuts the site off (027's PR): if the database refuses the
//     site's password (a rotation reached the database before this instance's next refresh), db/index.js calls
//     refetch(), which asks the broker again at once, and retries the request once on the new address. For that, the
//     latest identity token the broker accepted is kept in this file's memory for at most 50 minutes (Vercel's are
//     valid for two hours and meant to be reused); it is sent only to the broker's fixed address, never logged, replied
//     or forwarded. A refetch that gave back the same address isn't repeated for 30 seconds.
// The values are kept only in this function instance's memory (process.env, where the rest of the site already reads
// them; the address through db/index.js, G1), never written to a log, a file or a reply.
'use strict';

const BROKER = 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-keys';
const REFRESH_MS = 10 * 60_000;
const TIMEOUT_MS = 3000;
const TOKEN_KEEP_MS = 50 * 60_000;
const REFETCH_COOL_MS = 30_000;

let last = null; // { at, body }
let applied = null; // { url, keys: {name: value} } what this instance put in place from the broker
const inflight = new Map(); // token -> promise, so one bad token can't fail another request (L1)
let kept = null; // { token, at }: the latest identity token the broker accepted, only while open, for refetch()
let refetching = null;
let lastRefetch = null; // { at, same }: when the last refetch ran, and whether it gave back the address already set

function urlFor(d, host) {
  const u = new URL('postgres://' + host + ':' + d.port + '/' + d.database);
  u.username = d.user;
  u.password = d.password;
  return u.toString();
}

// Puts the broker's answer where the site reads it. Values Vercel set are left alone; values the broker gave earlier
// are replaced when they change.
function apply(body, env = process.env) {
  const db = require('./index');
  const url = urlFor(body.database, body.database.hosts[0]);
  if (!applied) {
    if (db.hasAddress(env)) return; // Vercel's settings win
    db.setAddress(url, env);
    const keys = {};
    for (const [k, v] of Object.entries(body.keys || {})) if (!env[k]) { env[k] = v; keys[k] = v; }
    applied = { url, keys };
    return;
  }
  if (applied.url !== url) { db.replaceAddress(url, env); applied.url = url; }
  for (const [k, v] of Object.entries(body.keys || {})) {
    if (k in applied.keys && applied.keys[k] !== v) { env[k] = v; applied.keys[k] = v; }
  }
}

// Second Look (034): the token, read without removing it, for the one other place it may go: Vercel's own AI Gateway
// (secondlook/v1.js's fixed address, never redirected). Vercel issues the token and runs the gateway, so this gives no
// new party anything (an exception to the CSO's control 8 that Aaron approves with the Second Look v1 PR). Read before
// ensure() below takes the token off the request.
function peekToken(req) {
  const h = req && req.headers && req.headers['x-vercel-oidc-token'];
  return typeof h === 'string' && h.length > 20 && h.length <= 8192 ? h : null;
}

// Reads the token and removes it from the request (M3).
function takeToken(req) {
  const headers = req && req.headers;
  if (!headers) return null;
  const h = headers['x-vercel-oidc-token'];
  delete headers['x-vercel-oidc-token'];
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

function askOnce(token, fetchImpl) {
  if (!inflight.has(token)) inflight.set(token, ask(token, fetchImpl).finally(() => inflight.delete(token)));
  return inflight.get(token);
}

// Makes sure this instance has its settings. Returns where they came from: 'vercel', 'broker', 'cached' (the broker
// failed; the last good answer is used), 'closed' (not asked) or 'none' (with the reason). With force (the readiness
// check), it also returns the broker's answer, which is applied only while the site is open.
async function ensure(req, { fetchImpl = fetch, force = false, env = process.env, stage = () => require('../launch').stage(env) } = {}) {
  const token = takeToken(req);
  const open = stage() === 'public';
  if (require('./index').hasAddress(env) && !applied && !last) return { source: 'vercel' };
  if (!open && !force) return { source: 'closed' };
  const use = (body, source, extra = {}) => { if (open) apply(body, env); return { source, body, ...extra }; };
  if (last && Date.now() - last.at < REFRESH_MS) return use(last.body, 'broker');
  if (!token) return last ? use(last.body, 'cached', { error: 'no_token' }) : { source: 'none', error: 'no_token' };
  try {
    const body = await askOnce(token, fetchImpl);
    if (open) {
      last = { at: Date.now(), body }; // while closed, the answer stays inside the check (L2)
      kept = { token, at: Date.now() }; // only a token the broker accepted (the CSO's review, N1)
    }
    return use(body, 'broker');
  } catch (e) {
    return last ? use(last.body, 'cached', { error: e.message }) : { source: 'none', error: e.message };
  }
}

// After the database refused the site's password: asks the broker again at once (ignoring the 10-minute cache) and
// puts its answer in place. True when it got an answer, so the caller retries on whatever address is now set; false
// when there is nothing to ask with (closed, Vercel's settings in use, no recent token) or the broker failed. One ask
// at a time per instance: concurrent refusals share it. A cool-down (the CSO's review, S3): if the last refetch was
// under 30 seconds ago and gave back the address already set, the broker isn't asked again, since it would only give
// the same refused password.
async function refetch({ fetchImpl = fetch, env = process.env, stage = () => require('../launch').stage(env), now = Date.now } = {}) {
  if (stage() !== 'public' || !applied || !kept || now() - kept.at > TOKEN_KEEP_MS) return false;
  if (refetching) return refetching;
  if (lastRefetch && lastRefetch.same && now() - lastRefetch.at < REFETCH_COOL_MS) return false;
  const token = kept.token;
  refetching = (async () => {
    const before = applied.url;
    try {
      const body = await askOnce(token, fetchImpl);
      last = { at: now(), body };
      apply(body, env);
      kept = { token, at: now() };
      lastRefetch = { at: now(), same: applied.url === before };
      return true;
    } catch {
      lastRefetch = { at: now(), same: true };
      return false;
    }
  })().finally(() => { refetching = null; });
  return refetching;
}

// For /api/ready: every pooler address the broker named, each with the login it gave.
function candidates(body = last && last.body) {
  return body ? body.database.hosts.map((h) => ({ host: h, url: urlFor(body.database, h) })) : [];
}

const _reset = () => { last = null; applied = null; inflight.clear(); kept = null; refetching = null; lastRefetch = null; };

module.exports = { ensure, refetch, candidates, peekToken, BROKER, _reset };
