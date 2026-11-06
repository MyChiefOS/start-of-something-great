// Third Look's runner (044), from the timer route (/api/cron, every minute), after Second Look's: asks the database for
// the next work it may look at (at most 3, at most once every 50 seconds, within its daily cap, never when off), reads
// each pull request's changed lines from GitHub's public API, puts each to the model (thirdlook/v1.js) and records the
// suggestion. In shadow that is all: nothing changes for the work, and the people deciding don't see it. Each item is
// its own transaction, after the model has answered, so no database lock waits on the network. Every failure is
// recorded as "a person", and the item is never given again (one try each).
'use strict';

const v1 = require('../thirdlook/v1');

async function run(runTx, token, { gh = null, fetchImpl, n = 3 } = {}) {
  let claimed;
  try {
    claimed = await runTx({ actor: 'anon' }, (t) => t`select * from app.tl_claim(${n})`);
  } catch {
    return { claimed: 0, decided: 0 };
  }
  let decided = 0;
  for (const it of claimed) {
    let files = null;
    if (gh && Number.isSafeInteger(it.pr_number)) {
      try { const f = await gh('/pulls/' + it.pr_number + '/files?per_page=100'); files = Array.isArray(f) ? f : null; } catch { files = null; }
    }
    const r = await v1.review({ item: { taskTitle: it.task_title, taskDescription: it.task_description, note: it.note, prTitle: it.pr_title },
      files, token, model: it.model, fetchImpl });
    try {
      await runTx({ actor: 'anon' }, (t) => t`select app.tl_decide(${it.submission_id}::uuid, ${r.version}, ${r.model}::text, ${r.suggestion},
        ${r.answers ? t.json(r.answers) : null}::jsonb, ${r.reason}, ${r.failClosed}, ${r.truncated}, ${r.latencyMs}::integer)`);
      decided++;
    } catch { /* never given again: one try each */ }
  }
  return { claimed: claimed.length, decided };
}

module.exports = { run };
