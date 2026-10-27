// GET /api/ready: whether every piece the site's own system needs is in place on this deployment, so route B can be
// proven live while the site is still closed (harness/STATUS.md). It answers only present/absent and which step
// failed: never a value, a key, a password or an address with its login.
//   identity_token  Vercel's identity token reached this function (x-vercel-oidc-token)
//   broker          the key broker answered with the login and keys ("ok"), or why not
//   keys            the three keys the site signs people in with are present
//   github_signin   the GitHub sign-in app's settings are present in Vercel
//   database        for each pooler address: "reached" (logged in as dog_web and ran "select 1"), or the failure
//   stage           the go-live stage, and whether LAUNCH_STAGE is set in Vercel
// It reads no table and changes nothing. The answer is kept for a minute per function instance, so calling it often
// costs the database almost nothing.
'use strict';

const sitekeys = require('../db/sitekeys');
const launch = require('../launch');

let cached = null; // { at, body }

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

async function check(req, { env = process.env, connect, fetchImpl } = {}) {
  const got = await sitekeys.ensure(req, { force: true, env, ...(fetchImpl ? { fetchImpl } : {}) });
  const database = {};
  if (got.source === 'vercel') {
    database.vercel = await probe(null, { connect });
  } else {
    for (const c of sitekeys.candidates()) database[c.host.split('.')[0]] = await probe(c.url, { connect });
  }
  return {
    identity_token: Boolean(req.headers && req.headers['x-vercel-oidc-token']),
    broker: got.source === 'broker' || got.source === 'cached' ? 'ok' : got.source === 'vercel' ? 'not_used' : (got.error || 'none'),
    keys: ['SESSION_SECRET', 'IP_HASH_KEY', 'FINGERPRINT_KEY_1'].every((k) => Boolean(env[k])),
    github_signin: Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET),
    database,
    stage: launch.stage(env),
    launch_stage_set: Boolean(String(env.LAUNCH_STAGE || '').trim())
  };
}

async function handle(req, res, deps = {}) {
  if (req.method !== 'GET') return reply(res, 405, { error: 'Method not allowed.' });
  if (cached && Date.now() - cached.at < 60_000) return reply(res, 200, cached.body);
  const body = await check(req, deps);
  cached = { at: Date.now(), body };
  return reply(res, 200, body);
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
module.exports._reset = () => { cached = null; };
