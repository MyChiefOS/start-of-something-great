// Third Look's runner (044). Since 057 (RISKS.md RK135) it runs in Second and Third Look's own Vercel project
// (looks/api/run.js, every minute), never in the site: the site's role can no longer claim Third Look's work or record
// its answers. runTx is that project's transaction (db/index.js looksRun): its own login, from the key broker for its
// own identity token, acting as dog_looks. It asks the database for the next work it may look at (at most 3, at most
// once every 50 seconds, within its daily cap, never when off), each with the changed files GitHub gave the GitHub
// facts workflow (app.tl_files: the site never reads GitHub for this), puts each to the model with the looks project's
// own token (thirdlook/v1.js) and records the suggestion. Each item is its own transaction, after the model has
// answered. A refused or failed model call, or a missing read of GitHub, gives the work back (app.tl_release): its try
// isn't spent. Anything else is recorded once; a record that fails is given back by the next claim after 3 minutes.
'use strict';

const v1 = require('../thirdlook/v1');

async function run(runTx, token, { fetchImpl, n = 3 } = {}) {
  let claimed;
  try {
    claimed = await runTx((t) => t`select * from app.tl_claim(${n})`);
  } catch {
    return { claimed: 0, decided: 0, released: 0 };
  }
  let decided = 0, released = 0;
  for (const it of claimed) {
    const r = await v1.review({ item: { taskTitle: it.task_title, taskDescription: it.task_description, note: it.note, prTitle: it.pr_title },
      files: Array.isArray(it.files) ? it.files : null, token, model: it.model, fetchImpl });
    try {
      if (r.release) {
        await runTx((t) => t`select app.tl_release(${it.submission_id}::uuid, ${r.release}) as r`);
        released++;
      } else {
        await runTx((t) => t`select app.tl_decide(${it.submission_id}::uuid, ${r.version}, ${r.model}::text, ${r.suggestion},
          ${r.answers ? t.json(r.answers) : null}::jsonb, ${r.reason}, ${r.failClosed}, ${r.truncated}, ${r.latencyMs}::integer)`);
        decided++;
      }
    } catch { /* not recorded: the claim runs out after 3 minutes and the next claim gives the work back (057) */ }
  }
  return { claimed: claimed.length, decided, released };
}

module.exports = { run };
