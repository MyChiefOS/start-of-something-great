// Vercel Cron (vercel.json "crons", every minute): /api/cron. Runs the timers (draft expiry, the 90-day check on agents
// acting alone, the watch and containment, R33 and N8, JEVs's 24-hour deletion-review timer and mark sweep, PR 12,
// and the key broker check, 027). Notices are in-app only, so nothing is emailed here.
// The timer slot (the CSO's control 6, route B; the conditions Aaron accepted on Oct 26, harness/FACTS.md): the address
// is open to anyone and needs no secret. The database runs the timers as the site itself at most once every 50
// seconds (app.timers_run, 027), and the slot and the timers are one transaction, so a failed run gives its slot back.
// This route:
//   * replies only {ok:true} (or {ok:false} with 500 when the run failed, and 503 while the site is closed): never
//     counts or anything else from the run;
//   * skips the database when this function instance asked under 25 seconds ago;
//   * passes whether the caller's user-agent is Vercel Cron's ("vercel-cron/1.0") as evidence only: it decides
//     nothing, and the database alerts Aaron when other callers start the timers often.
// CRON_SECRET is no longer read here. It is still read by db/index.js for the site itself ("system") as route B's
// fallback to Vercel settings (route A, CHARTER.md §2), which api/notify.js's bounce handling uses; under route B it is
// never set and app.actor_keys.system_hash stays empty (RISKS.md RK85).
// Delivery is best effort (a run can be missed or arrive twice), and every step is safe to repeat and catches up on
// everything due: the timers take a database lock and skip if another run holds it, and every notice has its own
// dedupe key. A containment whose time is up also ends when its owner's rules are read or written, and an agent past
// its 90 days drafts at its next post even if no timer ran (027), so a missed run never makes a pause longer or lets
// an agent act on its own longer.
'use strict';

const db = require('../db');
const store = require('../db/notify');

const SKIP_MS = 25_000;
let lastAsked = 0;

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

const fromCron = (req) => /^vercel-cron\//i.test(String((req.headers && req.headers['user-agent']) || ''));

async function handle(req, res, run, { now = Date.now } = {}) {
  if (req.method !== 'GET') return reply(res, 405, { error: 'Method not allowed.' });
  if (!run) return reply(res, 503, { ok: false });
  if (now() - lastAsked < SKIP_MS) return reply(res, 200, { ok: true });
  lastAsked = now();
  let out;
  try {
    out = await run({ actor: 'anon' }, (t) => store.timerSlot(t, fromCron(req)));
  } catch {
    return reply(res, 500, { ok: false });
  }
  return out && out.failed ? reply(res, 500, { ok: false }) : reply(res, 200, { ok: true });
}

module.exports = async (req, res) => {
  try {
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) reply(res, 500, { ok: false });
  }
};
module.exports.handle = handle;
module.exports._reset = () => { lastAsked = 0; };
