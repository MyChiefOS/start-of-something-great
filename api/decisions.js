// GET /api/decisions: what JEVs, the automatic checks, decided, in public (the design handoff of Nov 5, 2026: the
// /decisions page, CODING_AGENT_SPEC.md section 6 and 2.4 to 2.5). Read-only, no sign-in, no parameters.
// Counts and question IDs only (036, app.public_decisions): never a post's text, an account name, a score or a time of
// day. A rate is shown on the page only from MIN_SAMPLE decisions up ("Not enough history yet" below it, spec 2.2).
// One answer for everyone, cached at the edge for a minute, and any query string is refused, so the database is asked
// about once a minute however many people look (the edge cache is this endpoint's rate limit).
'use strict';

const db = require('../db');
const decisions = require('../db/decisions');
const { send, onlyGet } = require('./_lib');

const CACHE = 60; // seconds fresh at the edge, then as long again while it refreshes
const MIN_SAMPLE = 20;
const NOTE = 'Counts and question IDs only: never a post’s text, an account name, a score or a time of day. '
  + 'Rates are given only from ' + MIN_SAMPLE + ' decisions up. The questions are listed in https://dayonegreat.com/llms.txt.';

async function handle(req, res, run) {
  if (!onlyGet(req, res)) return;
  if (new URL(req.url || '/', 'https://dayonegreat.com').search) {
    return send(res, 400, { error: 'This endpoint takes no parameters: GET /api/decisions.' }, CACHE, CACHE);
  }
  if (!run) {
    return send(res, 200, { available: false, min_sample: MIN_SAMPLE,
      message: 'The site’s database isn’t switched on here, so there are no decisions to count.', note: NOTE }, CACHE, CACHE);
  }
  let d;
  try {
    d = await run({ actor: 'anon' }, (t) => decisions.summary(t));
  } catch (e) {
    // The site reached production before migration 036: not cached, so it clears itself once 036 is applied.
    if (e && e.code === '42883') return send(res, 503, { error: 'The public counts are being switched on. Please try again in a few minutes.' });
    throw e;
  }
  return send(res, 200, { available: true, min_sample: MIN_SAMPLE, ...d, questions: decisions.titles(), note: NOTE }, CACHE, CACHE);
}

module.exports = async (req, res) => {
  try {
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) send(res, 500, { error: 'The decisions couldn’t be counted just now. Please try again in a minute.' });
  }
};
module.exports.handle = handle;
module.exports.MIN_SAMPLE = MIN_SAMPLE;
