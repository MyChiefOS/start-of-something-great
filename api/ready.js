// GET /api/ready: whether every piece the site's own system needs is in place on this deployment, so route B can be
// proven live while the site is still closed (harness/STATUS.md). It answers only present/absent and which step
// failed: never a value, a key, a password or an address with its login.
//   identity_token  Vercel's identity token reached this function (x-vercel-oidc-token)
//   broker          the key broker answered with the login and keys ("ok"), or why not
//   keys            the three keys the site signs people in with are present (from Vercel, or in the broker's answer)
//   github_signin   the GitHub sign-in app's settings are present in Vercel, under the names the site reads
//   github_setting_names  the names (never the values) of any GitHub-like settings, so a misnamed one can be fixed by
//                   a PR that reads the right name (the CLJO's review: X's settings turned out misnamed)
//   database        the pooler addresses tried, in order, until one logs dog_web in and runs "select 1" ("reached")
//   stage           the go-live stage, and whether LAUNCH_STAGE is set in Vercel
// It reads no table and changes nothing. One check runs at a time per function instance, and its answer, good or bad,
// is kept for a minute, so calling it often costs the database almost nothing (the CSO's review, M2). The pooler
// address that answered is remembered for the instance, so later checks log in once.
'use strict';

const sitekeys = require('../db/sitekeys');
const launch = require('../launch');

let cached = null; // { at, body }
let running = null;
let goodHost = null;

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

// What a failed login says, in a word (never the message itself, which can echo the address).
function why(e) {
  const m = String((e && e.message) || '');
  if (/tenant or user not found/i.test(m)) return 'tenant_not_found';
  if (/password authentication failed/i.test(m)) return 'password_refused';
  if (/timeout|timed out/i.test(m)) return 'timeout';
  return 'error' + (e && e.code ? '_' + String(e.code).replace(/[^A-Za-z0-9_]/g, '').slice(0, 12) : '');
}

async function probe(url, { connect }) {
  try {
    return (await require('../db').ping(url, connect ? { connectImpl: connect } : {})) ? 'reached' : 'error';
  } catch (e) {
    return why(e);
  }
}

const KEY_NAMES = ['SESSION_SECRET', 'IP_HASH_KEY', 'FINGERPRINT_KEY_1'];

async function check(req, { env = process.env, connect, fetchImpl } = {}) {
  // Noted before ensure(), which removes the token from the request (M3).
  const identityToken = Boolean(req.headers && req.headers['x-vercel-oidc-token']);
  const got = await sitekeys.ensure(req, { force: true, env, ...(fetchImpl ? { fetchImpl } : {}) });
  const database = {};
  if (got.source === 'vercel') {
    database.vercel = await probe(null, { connect });
  } else {
    const list = sitekeys.candidates(got.body);
    // The address that answered before goes first; stop at the first that answers.
    list.sort((a, b) => (b.host === goodHost) - (a.host === goodHost));
    for (const c of list) {
      const r = await probe(c.url, { connect });
      database[c.host.split('.')[0]] = r;
      if (r === 'reached') { goodHost = c.host; break; }
    }
  }
  const keys = got.body ? KEY_NAMES.every((k) => Boolean(env[k] || (got.body.keys && got.body.keys[k]))) : KEY_NAMES.every((k) => Boolean(env[k]));
  return {
    identity_token: identityToken,
    broker: got.source === 'broker' || got.source === 'cached' ? 'ok' : got.source === 'vercel' ? 'not_used' : (got.error || 'none'),
    keys,
    github_signin: Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET),
    github_setting_names: Object.keys(env).filter((k) => /git_?hub/i.test(k) && /^[A-Z0-9_]{1,64}$/.test(k)).sort(),
    database,
    stage: launch.stage(env),
    launch_stage_set: Boolean(String(env.LAUNCH_STAGE || '').trim())
  };
}

async function handle(req, res, deps = {}) {
  if (req.method !== 'GET') return reply(res, 405, { error: 'Method not allowed.' });
  if (cached && Date.now() - cached.at < 60_000) return reply(res, 200, cached.body);
  if (!running) {
    running = check(req, deps)
      .catch(() => ({ error: 'check_failed' }))
      .then((body) => { cached = { at: Date.now(), body }; return body; })
      .finally(() => { running = null; });
  } else if (req.headers) {
    delete req.headers['x-vercel-oidc-token']; // never left on a request that didn't run the check (M3)
  }
  return reply(res, 200, await running);
}

module.exports = async (req, res) => {
  try {
    await handle(req, res);
  } catch {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong.' });
  }
};
module.exports.handle = handle;
module.exports.check = check;
module.exports._reset = () => { cached = null; running = null; goodHost = null; };
