// Second Look v1's runner (034). Since 057 (RISKS.md RK100) it runs in Second and Third Look's own Vercel project
// (looks/api/run.js, every minute), never in the site: the site's role can no longer claim held posts or record
// Second Look's decisions. runTx is that project's transaction (db/index.js looksRun): its own login, from the key
// broker for its own identity token, acting as dog_looks, the one role the functions accept. It asks the database for
// the next eligible held posts (at most 3, at most once every 50 seconds, never in off mode), puts each one to the model
// through Vercel's AI Gateway with the looks project's own token (secondlook/v1.js), and records the decision; in on
// mode the database publishes a clear. Each post is its own transaction, after the model has answered, so no database
// lock waits on the network. Every failure leaves the post held for Aaron, as it is today.
'use strict';

const v1 = require('../secondlook/v1');

async function run(runTx, token, { fetchImpl, n = 3 } = {}) {
  let claimed;
  try {
    claimed = await runTx((t) => t`select * from app.sl_claim(${n})`);
  } catch {
    return { claimed: 0, decided: 0 };
  }
  let decided = 0;
  for (const p of claimed) {
    const r = await v1.review({ text: p.body, held: p.held || [], accountDays: p.account_days, signIn: p.sign_in, token,
      model: p.model, fetchImpl });
    try {
      await runTx((t) => t`select app.sl_decide(${p.post_id}::uuid, ${r.version}, ${r.model}, ${r.decision},
        ${r.answers ? t.json(r.answers) : null}::jsonb, ${r.risk}, ${r.reason}, ${r.failClosed}, ${r.error}, ${r.latencyMs})`);
      decided++;
    } catch {
      // The post stays held, and is never claimed again (one try each): Aaron decides it as before.
    }
  }
  return { claimed: claimed.length, decided };
}

module.exports = { run };
