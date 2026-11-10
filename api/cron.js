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
// Two clocks (the review of RK134's fix, finding 2): a call whose token checks out and any other call, so a call with a
// junk token header can't take the 25 seconds from one with a good token. Vercel gives a signed token to every call
// that reaches this function, not only to Vercel Cron's (corrected by the review of #123, F1: OPERATIONS, Oct 27), so
// the token is never proof that Vercel Cron called, and nothing here may treat it as one; an outsider's call runs the
// same capped work Cron's would. Each clock lets one run through every 25 seconds per instance; the timers' work itself
// is held once a minute by the database (timerSlot).
let lastAsked = { signed: 0, other: 0 };

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

const fromCron = (req) => /^vercel-cron\//i.test(String((req.headers && req.headers['user-agent']) || ''));

async function handle(req, res, run, { now = Date.now, oidc = null, fetchImpl, proposals = null, logFetch = null, workGithub = null } = {}) {
  if (req.method !== 'GET') return reply(res, 405, { error: 'Method not allowed.' });
  if (!run) return reply(res, 503, { ok: false });
  const clock = oidc ? 'signed' : 'other';
  if (now() - lastAsked[clock] < SKIP_MS) return reply(res, 200, { ok: true });
  lastAsked[clock] = now();
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
  // Audit upkeep (053): sessions past their end are swept, so each expiry is in the audit log; once an hour, request
  // records a year old are deleted and the database's size is checked against its plan (an alert at 75%). Each in its
  // own transaction; a failure changes nothing else.
  try {
    await run({ actor: 'anon' }, (t) => t`select app.session_sweep()`);
  } catch { /* logs nothing (027) */ }
  try {
    await run({ actor: 'anon' }, (t) => t`select app.audit_upkeep_run()`);
  } catch { /* logs nothing (027) */ }
  // The points against the points ledger, row by row (052): an alert to Aaron at most once a day if they differ. Its
  // own transaction; it changes nothing, and a failure changes nothing else.
  try {
    await run({ actor: 'anon' }, (t) => t`select app.work_ledger_alert()`);
  } catch { /* logs nothing (027) */ }
  // Review oversight (041): the 5% sample of low-risk posts for Second Look to re-read, and the alerts to Aaron (in-app,
  // once a day each while they hold). The database runs it at most once every 10 minutes, in its own transaction; a
  // failure here changes nothing else and this reply stays the same.
  try {
    await run({ actor: 'anon' }, (t) => t`select app.review_tick()`);
  } catch { /* logs nothing (027); before 041 is applied the function isn't there */ }
  // Second Look v1 (034): the next eligible held posts put to the model, in their own transactions after the timers'
  // and the rules', with the site's Vercel identity token for the AI Gateway (read before sitekeys removes it from the
  // request, and passed only to the gateway). Off, paused, capped or failing, it changes nothing and this reply is the
  // same; every failure leaves the posts held for Aaron.
  if (oidc) {
    try { await require('../db/secondlook').run(run, oidc, fetchImpl ? { fetchImpl } : {}); } catch { /* logs nothing (027) */ }
  }
  // Third Look (044), in shadow: the next work waiting for a person that is a merged pull request, put to its model with
  // the same identity token, after Second Look. Off, capped or failing, it changes nothing; in shadow it only records.
  if (oidc) {
    try { await require('../db/thirdlook').run(run, oidc, { gh: workGithub, ...(fetchImpl ? { fetchImpl } : {}) }); } catch { /* logs nothing (027) */ }
  }
  // The public log (038): JEVs's last whole hour, Aaron's proposal decisions from GitHub, the next signed checkpoint and
  // the witness's copy, each in its own transaction. A failure changes nothing here; the next minute tries again.
  try {
    await require('../db/logjobs').run(run, { getProposals: proposals, fetchImpl: logFetch });
  } catch { /* logs nothing (027) */ }
  // The work module (042): its timer, and this repository's pull requests and issues from GitHub (at most every 15
  // minutes), each in its own transaction. A failure changes nothing here; a later minute tries again.
  try {
    await require('../db/workjobs').run(run, { gh: workGithub });
  } catch { /* logs nothing (027); before 042 is applied the functions aren't there */ }
  return out && out.failed ? reply(res, 500, { ok: false }) : reply(res, 200, { ok: true });
}

module.exports = async (req, res) => {
  try {
    // The identity token, for Second and Third Look's model calls, before sitekeys takes it off the request (M3); only
    // a token Vercel signed for this project's production (RK134). Without one, neither runs this minute.
    const oidc = await require('../db/sitekeys').verifiedToken(req);
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    // The log's two reads from GitHub (the proposals and the witness's copy) happen only here, in production.
    await handle(req, res, db.configured() ? db.run : null, { oidc, proposals: require('./_lib').getProposals, logFetch: globalThis.fetch,
      workGithub: require('./_lib').githubRead });
  } catch {
    if (!res.headersSent) reply(res, 500, { ok: false });
  }
};
module.exports.handle = handle;
module.exports._reset = () => { lastAsked = { signed: 0, other: 0 }; };
// Every database call in this route knows its request, for the audit log (053).
module.exports = require('../db').entry(module.exports);
