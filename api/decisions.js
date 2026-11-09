// GET /api/decisions: what JEVs, the automatic checks, decided, in public (the design handoff of Nov 5, 2026: the
// /decisions page, CODING_AGENT_SPEC.md section 6 and 2.4 to 2.5). Read-only, no sign-in, no parameters.
// Counts and question IDs only (036, app.public_decisions): never a post's text, an account name, a score or a time of
// day. A rate is shown on the page only from MIN_SAMPLE decisions up ("Not enough history yet" below it, spec 2.2).
// One answer for everyone, cached at the edge for a minute. Any query string and any Authorization header is refused
// (Vercel's edge doesn't cache a request that carries one: the independent review of Nov 5, finding 3), and each running
// copy also keeps its last answer for a minute, so the database is asked about once a minute per copy at most.
'use strict';

const db = require('../db');
const decisions = require('../db/decisions');
const tiers = require('../db/review-tiers');
const { send, onlyGet } = require('./_lib');

const CACHE = 60; // seconds fresh at the edge, then as long again while it refreshes
const MIN_SAMPLE = 20;
const NOTE = 'Counts and question IDs only: never a post’s text, an account name, a score or a time of day. Counted to the start '
  + 'of the hour (review: once a day, for days that ended at least a day ago); a count from 1 to 4 is null (fewer than 5) and a smaller group isn’t listed, so no number points to one person. '
  + 'The figures describe the automated reviewers, JEVs and Second Look, not the person who reviews what they pass on. '
  + 'Rates are given only from ' + MIN_SAMPLE + ' decisions up. The questions are listed in https://dayonegreat.com/llms.txt.';
let kept = null; // { at, body }: this copy's last answer

async function handle(req, res, run) {
  if (!onlyGet(req, res)) return;
  if (new URL(req.url || '/', 'https://dayonegreat.com').search || (req.headers && req.headers.authorization)) {
    return send(res, 400, { error: 'This endpoint takes no parameters: GET /api/decisions.' }, CACHE, CACHE);
  }
  if (!run) {
    return send(res, 200, { available: false, min_sample: MIN_SAMPLE,
      message: 'The site’s database isn’t switched on here, so there are no decisions to count.', note: NOTE }, CACHE, CACHE);
  }
  if (kept && Date.now() - kept.at < CACHE * 1000) return send(res, 200, kept.body, CACHE, CACHE);
  let d;
  try {
    d = await run({ actor: 'anon' }, async (t) => ({ ...(await decisions.summary(t)),
      // 041 (phase 4): review oversight by role and kind of item, Second Look's planted tests and sample, and the alerts.
      // Best effort: before 041 is applied it is null and the page says it isn't counted yet.
      review: await (async () => { try { return await t.savepoint((x) => tiers.oversight(x)); } catch { return null; } })() }));
  } catch (e) {
    // The site reached production before migration 036: not cached, so it clears itself once 036 is applied.
    if (e && e.code === '42883') return send(res, 503, { error: 'The public counts are being switched on. Please try again in a few minutes.' });
    throw e;
  }
  // Aaron, Nov 5: the public figures describe the automated reviewers ("I gave guidance to use JEVs, and Second Look"),
  // so his own review figures (036's oversight: his decisions, their times, his queue) aren't published; they are on
  // /admin/controls for him. What JEVs and Second Look passed on, decided and caught is in "review" (041).
  const { oversight, ...rest } = d;
  void oversight;
  const body = { available: true, min_sample: MIN_SAMPLE, ...rest, questions: decisions.titles(), note: NOTE };
  kept = { at: Date.now(), body };
  return send(res, 200, body, CACHE, CACHE);
}

module.exports = async (req, res) => {
  // (Tests reset this copy's kept answer through module.exports._forget.)
  try {
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) send(res, 500, { error: 'The decisions couldn’t be counted just now. Please try again in a minute.' });
  }
};
module.exports.handle = handle;
module.exports.MIN_SAMPLE = MIN_SAMPLE;

module.exports._forget = () => { kept = null; };
// Every database call in this route knows its request, for the audit log (053).
module.exports = require('../db').entry(module.exports);
