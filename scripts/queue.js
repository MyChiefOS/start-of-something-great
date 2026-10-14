// Checks D3 and D4: each morning, re-sort every open proposal, then update Aaron's daily queue
// (one pinned issue labelled "daily queue"). Run by .github/workflows/sorting.yml.
const rules = require('./_rules');
const github = require('./_github');
const { sweep } = require('./sort');

async function main() {
  const manual = process.env.MANUAL === 'true';
  const existing = (await github.listIssues('labels=' + encodeURIComponent(rules.QUEUE_LABEL) + '&state=open'))[0];
  const now = new Date();
  if (!rules.queueShouldRun(now, existing && rules.lastQueueDate(existing.body), manual)) {
    console.log('Queue already updated today, or it is not yet 7 a.m. Pacific. Nothing to do.');
    return;
  }
  try {
    await sweep(null);
  } catch (e) {
    console.error('Sorting could not finish; building the queue anyway. Per-proposal errors are logged above.');
  }
  const proposals = await github.listProposals();
  // A manual run keeps the previous "done" date so the scheduled 7 a.m. run still happens.
  const body = rules.buildQueue(proposals, now, manual ? (existing && rules.lastQueueDate(existing.body)) || null : undefined);
  if (existing) {
    await github.gh('/issues/' + existing.number, { method: 'PATCH', body: { body } });
    console.log('Updated queue issue #' + existing.number);
  } else {
    const created = await github.gh('/issues', { method: 'POST', body: { title: 'Daily queue', body, labels: [rules.QUEUE_LABEL] } });
    console.log('Created queue issue #' + created.number + ' (pin it once in GitHub to keep it on top)');
  }
}

main().catch((e) => { console.error(e.message); process.exit(1); });
