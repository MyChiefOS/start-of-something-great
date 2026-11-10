// Third Look's runner (044). Since 057 (RISKS.md RK135) Third Look runs in the Supabase function dog-looks, not here: the
// site's database role can no longer claim Third Look's work or record its answers (only dog_looks, dog-looks's role,
// can), and the site no longer reads the pull request's changed files: the GitHub facts workflow reads them from
// GitHub, and dog-github records them (app.tl_files). The timer route (/api/cron, every minute) only asks dog-looks to
// run, sending the site's own Vercel identity token, which dog-looks checks (as the key broker does) and uses for
// Vercel's AI Gateway. dog-looks claims the next work itself (at most 3, at most once every 50 seconds, within the
// daily cap, never when off), asks the model, suggests by code and records the answer; a refused or failed model call
// gives the work back instead of spending its try. The caller chooses nothing but that Third Look runs now.
'use strict';

const { callLooks } = require('./secondlook');

// runTx is no longer used: dog-looks reaches the database itself. Kept so the timer route's call is unchanged.
async function run(runTx, token, { fetchImpl } = {}) {
  return callLooks('third', token, { fetchImpl, timeoutMs: 90_000 });
}

module.exports = { run };
