// Vercel Cron (vercel.json "crons", every minute): /api/cron. Runs the timers (draft expiry, the 90-day check on agents
// acting alone, the watch and containment, R33 and N8, and JEVs's 24-hour deletion-review timer and mark sweep, PR 12).
// Notices are in-app only, so nothing is emailed here. Vercel sends "Authorization: Bearer <CRON_SECRET>"; it is
// compared in constant time and never logged. Delivery is best effort (a run can be missed or arrive twice), and Vercel
// calls only the production deployment, so every step is safe to repeat and catches up on everything due: the timers
// take a database lock and skip if another run holds it, and every notice has its own dedupe key. A containment whose
// time is up also ends when its owner's rules are read or written, so a missed run never makes a pause longer.
'use strict';

const db = require('../db');
const ncfg = require('../notify/config');
const store = require('../db/notify');

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

async function handle(req, res, run, cfg = ncfg.load()) {
  if (req.method !== 'GET') return reply(res, 405, { error: 'Method not allowed.' });
  if (!cfg.cronSecret) return reply(res, 503, { error: 'Timers are not switched on here.' });
  const h = req.headers && (req.headers.authorization || req.headers.Authorization);
  if (!ncfg.cronOk(cfg, h)) return reply(res, 401, { error: 'Unauthorized.' });
  if (!run) return reply(res, 503, { error: 'No database here.' });
  let timers;
  try {
    timers = await run({ actor: 'system' }, (t) => store.runTimers(t));
  } catch {
    return reply(res, 500, { timers: { error: true } });
  }
  // Counts only, for the cron log: no words, no secrets.
  return reply(res, 200, { timers });
}

module.exports = async (req, res) => {
  try {
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong.' });
  }
};
module.exports.handle = handle;
