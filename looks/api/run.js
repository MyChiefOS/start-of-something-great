// Second and Third Look's own Vercel project, "looks" (migration 057; RISKS.md RK135, RK100; Aaron, Nov 10: "I want you
// to implement that solution"). This folder is that project's Root Directory; it has this one route, which its cron
// (looks/vercel.json) calls every minute. It reuses the repository's own code from outside the folder (db/,
// secondlook/, thirdlook/, launch.js), which Vercel's "Include files outside the root directory in the Build Step"
// setting allows, and installs the repository's one package at the repository root (looks/vercel.json).
// Why its own project: Vercel stamps each project's identity token with that project's ID. The key broker (dog-keys)
// answers this project's token with the looks login (dog_looks_web, which may act as dog_looks only) and nothing else,
// and the site's token never gets it. Each project's token goes only to the broker and Vercel's AI Gateway (route B,
// the CSO's control 8): nothing is forwarded between services, and the site's role can't run the looks' functions.
// This route:
//   * answers GET only, {ok:true} or {ok:false}, never counts;
//   * reads its own token from the request and runs only on one Vercel signed for the looks project's production
//     (db/sitekeys.js verifiedToken, project 'looks'); while LOOKS_PROJECT_ID is empty, no token passes and nothing runs;
//   * gets its login from the broker with that token (db/sitekeys.js ensure), only while the site is open (launch.js);
//   * runs Second Look, then Third Look, each claim and answer in its own transaction as dog_looks (db/index.js
//     looksRun), and asks the gateway with its own token, at the one fixed address, never redirected;
//   * skips the database when this instance ran under 25 seconds ago; the database itself paces each look (50 seconds,
//     daily caps), so a caller asking more often changes nothing. It logs nothing.
'use strict';

const db = require('../../db');
const sitekeys = require('../../db/sitekeys');

const SKIP_MS = 25_000;
let lastRun = 0;

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

async function handle(req, res, { oidc = null, runTx = null, now = Date.now, fetchImpl } = {}) {
  if (req.method !== 'GET') return reply(res, 405, { error: 'Method not allowed.' });
  if (!oidc || !runTx) return reply(res, 503, { ok: false });
  if (now() - lastRun < SKIP_MS) return reply(res, 200, { ok: true });
  lastRun = now();
  const opts = fetchImpl ? { fetchImpl } : {};
  try { await require('../../db/secondlook').run(runTx, oidc, opts); } catch { /* every failure leaves the posts held for Aaron */ }
  try { await require('../../db/thirdlook').run(runTx, oidc, opts); } catch { /* nothing passes; the work waits */ }
  return reply(res, 200, { ok: true });
}

module.exports = async (req, res) => {
  try {
    // Only a token Vercel signed for the looks project's production, read before sitekeys takes it off the request.
    const oidc = await sitekeys.verifiedToken(req, { project: 'looks' });
    await sitekeys.ensure(req); // the looks login from the broker, only while open
    await handle(req, res, { oidc, runTx: oidc && db.configured() ? db.looksRun : null });
  } catch {
    if (!res.headersSent) reply(res, 500, { ok: false });
  }
};
module.exports.handle = handle;
module.exports._reset = () => { lastRun = 0; };
