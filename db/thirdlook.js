// Third Look's runner (044), from the timer route (/api/cron, every minute), after Second Look's: asks the database for
// the next work it may look at (at most 3, at most once every 50 seconds, within its daily cap, never when off), each
// with the changed files GitHub gave the GitHub facts workflow (057: app.tl_files; the site reads nothing from GitHub
// for this), puts each to the model (thirdlook/v1.js) and records the suggestion. Each item is its own transaction,
// after the model has answered. A refused or failed model call, or a missing read of GitHub, gives the work back
// (app.tl_release): its try isn't spent. Anything else is recorded once; a record that fails is given back by the next
// claim after 3 minutes.
'use strict';

const v1 = require('../thirdlook/v1');

async function run(runTx, token, { fetchImpl, n = 3, pageImpl, pageOpts } = {}) {
  let claimed;
  try {
    claimed = await runTx({ actor: 'anon' }, (t) => t`select * from app.tl_claim(${n})`);
  } catch {
    return { claimed: 0, decided: 0, released: 0 };
  }
  let decided = 0, released = 0;
  for (const it of claimed) {
    let r;
    if (it.artifact_kind === 'link') {
      // 070: a link, read by the timer itself (thirdlook/page.js); what was read is recorded before the answer.
      const page = await (pageImpl || require('../thirdlook/page').read)(it.artifact_url, pageOpts || {});
      if (page && page.sha256) {
        try { await runTx({ actor: 'anon' }, (t) => t`select app.tl_read(${it.submission_id}::uuid, ${page.url}, ${page.sha256})`); } catch { /* the answer still counts */ }
      }
      r = await v1.reviewPage({ item: { taskTitle: it.task_title, taskDescription: it.task_description, note: it.note }, page, token, model: it.model, fetchImpl });
    } else {
      r = await v1.review({ item: { taskTitle: it.task_title, taskDescription: it.task_description, note: it.note, prTitle: it.pr_title },
        files: Array.isArray(it.files) ? it.files : null, token, model: it.model, fetchImpl });
    }
    try {
      if (r.release) {
        await runTx({ actor: 'anon' }, (t) => t`select app.tl_release(${it.submission_id}::uuid, ${r.release}) as r`);
        released++;
      } else {
        await runTx({ actor: 'anon' }, (t) => t`select app.tl_decide(${it.submission_id}::uuid, ${r.version}, ${r.model}::text, ${r.suggestion},
          ${r.answers ? t.json(r.answers) : null}::jsonb, ${r.reason}, ${r.failClosed}, ${r.truncated}, ${r.latencyMs}::integer)`);
        decided++;
      }
    } catch { /* not recorded: the claim runs out after 3 minutes and the next claim gives the work back (057) */ }
  }
  return { claimed: claimed.length, decided, released };
}

module.exports = { run };
