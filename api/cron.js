// Vercel Cron (vercel.json "crons", every minute): /api/cron. Runs the timers (draft expiry, the 90-day check on agents
// acting alone, the watch and containment, R33 and N8, JEVs's 24-hour deletion-review timer and mark sweep, PR 12,
// and the key broker check, 027). Notices are in-app only, so nothing is emailed here.
// The timer slot (the CSO's control 6, route B; the conditions Aaron accepted on Oct 26, harness/FACTS.md): the address
// is open to anyone and needs no secret. The database runs the timers as the site itself at most once every 50
// seconds (app.timers_run, 027). The slot and the timers are one transaction: a failed run's work is undone and recorded, and
// the slot stays taken for its 50 seconds (the CSO's review of 027, S1), so Vercel Cron's next call retries it.
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
// dedupe key. A containment whose time is up also ends when its owner's rules are read or written, so a missed run
// never makes a pause longer. Past its tree's 90 days, an agent's posts become drafts and the sub-agents it makes
// draft, even if no timer ran (027); until the timers run, its rules still read "act" on the owner's page and the
// owner hasn't been told. The timer slot: every run that takes the slot holds it for 50 seconds, a failed one too.
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
  // The rules that must never break (032), at most once an hour, in their own transaction after the timers': a
  // failure here is recorded and alerted by the database and never changes this reply or the timers' work.
  try {
    await run({ actor: 'anon' }, (t) => t`select app.invariants_check()`);
  } catch {
    // The check alerts Aaron itself when it fails inside the database. Failing to reach it at all (the function not
    // there yet, a lost grant, the connection) shows in /api/ready's "rules" heartbeat, which the uptime monitor reads:
    // it opens an issue if the checks haven't finished for 3 hours (the fresh review of round 1). This route logs
    // nothing (027).
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
