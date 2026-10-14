// Check D1: tag a proposal when it's filed or edited. Run by .github/workflows/sorting.yml.
// Usage: ISSUE_NUMBER=12 node scripts/sort.js   (or with no ISSUE_NUMBER: sweep every open proposal)
const rules = require('./_rules');
const github = require('./_github');

const LABELS = {
  'from an agent': ['5b6cff', 'The filer says it is an AI agent acting for a person (not verified)'],
  'needs info': ['fbca04', 'A required part of the proposal is empty'],
  'possible duplicate': ['c5def5', 'The title closely matches an earlier proposal'],
  'contains contact info': ['d93f0b', 'Looks like it includes an email address or phone number'],
  'daily queue': ['ededed', "Aaron's daily queue, updated automatically"]
};

async function ensureLabels() {
  for (const [name, [color, description]] of Object.entries(LABELS)) await github.ensureLabel(name, color, description);
}

async function sweep(onlyNumber) {
  await ensureLabels();
  const proposals = await github.listProposals();
  const targets = proposals.filter((i) => i.state === 'open' && rules.isProposal(i) && (!onlyNumber || i.number === onlyNumber));
  let failed = 0;
  for (const issue of targets) {
    try {
      // Only labels the automation added itself may be removed; check who added each one.
      const candidates = rules.labelChanges(issue, proposals, () => true).remove;
      const byBot = new Set();
      if (candidates.length) {
        const events = await github.listEvents(issue.number); // full history, every page
        for (const l of candidates) if (rules.addedByBotLast(events, l)) byBot.add(l);
      }
      const changes = rules.labelChanges(issue, proposals, (l) => byBot.has(l));
      if (changes.add.length || changes.remove.length) {
        await github.applyLabelChanges(issue.number, changes);
        console.log('#' + issue.number + ' +[' + changes.add.join(', ') + '] -[' + changes.remove.join(', ') + ']');
      }
    } catch (e) {
      failed++; // keep going: one failure must not stop the rest, or the daily queue (check D3)
      console.error('#' + issue.number + ': ' + e.message);
    }
  }
  if (failed) console.error(failed + ' proposal(s) could not be sorted this run; they will be retried next run.');
  return { count: targets.length, failed };
}

if (require.main === module) {
  const n = Number(process.env.ISSUE_NUMBER) || null;
  sweep(n).then((r) => {
    console.log('Sorted ' + r.count + ' proposal(s).');
    if (r.failed) process.exitCode = 1; // a missed D1 shows as a failed run
  }).catch((e) => { console.error(e.message); process.exit(1); });
}

module.exports = { sweep };
