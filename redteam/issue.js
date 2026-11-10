// Runs an attack plan written in a GitHub issue (.github/workflows/red-team.yml) against the red-team copy, and posts
// the report as a comment on that issue. The plan is the issue's first ```json block, read from the event file GitHub
// writes; it is data and never reaches a shell. Only issues opened by the repository's owner and labelled red-team by
// the owner reach here (the workflow checks both).
'use strict';

const fs = require('fs');
const { start } = require('./copy');
const { runPlan, report } = require('./plan');

async function main() {
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const issue = event.issue;
  const body = String(issue && issue.body || '');
  const m = body.match(/```json\s*\n([\s\S]*?)\n```/);
  let text;
  try {
    if (!m) throw new Error('no ```json block in the issue');
    const results = await (async () => {
      const copy = await start(process.env.TEST_DATABASE_URL);
      try { return await runPlan(copy, JSON.parse(m[1])); } finally { await copy.close(); }
    })();
    text = report(results) + '\n\nRun on `' + String(process.env.GITHUB_SHA || '').slice(0, 7) + '` against a throwaway copy; nothing reached the live site.';
  } catch (e) {
    text = '**Red-team copy:** the plan could not run: ' + String(e && e.message || e).slice(0, 300);
  }
  const r = await fetch('https://api.github.com/repos/' + process.env.GITHUB_REPOSITORY + '/issues/' + Number(issue.number) + '/comments', {
    method: 'POST', redirect: 'error',
    headers: { authorization: 'Bearer ' + process.env.GITHUB_TOKEN, accept: 'application/vnd.github+json', 'content-type': 'application/json', 'x-github-api-version': '2022-11-28' },
    body: JSON.stringify({ body: text.slice(0, 60000) })
  });
  if (!r.ok) throw new Error('could not comment: ' + r.status);
}

main().catch((e) => { console.error(String(e && e.message || e)); process.exit(1); });
