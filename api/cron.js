// Vercel Cron (vercel.json "crons", every minute): /api/cron. Runs the timers (draft expiry, the 90-day check on agents
// acting alone, the watch and containment, R33 and N8) and then sends the email copies that are due (the outbox drain).
// Vercel sends "Authorization: Bearer <CRON_SECRET>"; it is compared in constant time and never logged. Delivery is
// best effort (a run can be missed or arrive twice), so every step is safe to repeat: the timers and the drain each
// take a database lock and skip if another run holds it, and every notice has its own dedupe key.
'use strict';

const db = require('../db');
const ncfg = require('../notify/config');
const store = require('../db/notify');
const { drain } = require('../notify/drain');

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
  const out = {};
  try {
    out.timers = await run({ actor: 'system' }, (t) => store.runTimers(t));
  } catch {
    out.timers = { error: true };
  }
  try {
    out.email = await drain({ run, cfg });
  } catch {
    out.email = { error: true };
  }
  // Counts only, for the cron log: no addresses, no words, no secrets.
  return reply(res, out.timers.error || out.email.error ? 500 : 200, out);
}

module.exports = async (req, res) => {
  try {
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong.' });
  }
};
module.exports.handle = handle;
