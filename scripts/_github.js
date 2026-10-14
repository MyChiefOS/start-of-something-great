// Minimal GitHub REST client for the repository's own automations (run inside GitHub Actions
// with the workflow's short-lived GITHUB_TOKEN). Never logs the token.
const REPO = process.env.GITHUB_REPOSITORY || 'MyChiefOS/start-of-something-great';
const API = 'https://api.github.com/repos/' + REPO;

async function gh(path, opts) {
  opts = opts || {};
  const r = await fetch(API + path, {
    method: opts.method || 'GET',
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'dayonegreat-automation',
      Authorization: 'Bearer ' + process.env.GITHUB_TOKEN,
      ...(opts.body ? { 'Content-Type': 'application/json' } : {})
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  if (r.status === 204) return null;
  const data = await r.json().catch(() => null);
  if (!r.ok && !(opts.okStatuses || []).includes(r.status)) {
    throw new Error('GitHub ' + (opts.method || 'GET') + ' ' + path.split('?')[0] + ' returned ' + r.status);
  }
  return data;
}

async function listIssues(query) {
  const all = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await gh('/issues?' + query + '&per_page=100&page=' + page);
    all.push(...batch);
    if (batch.length < 100) break;
  }
  return all;
}

const listEvents = async (number) => {
  const all = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await gh('/issues/' + number + '/events?per_page=100&page=' + page);
    all.push(...batch);
    if (batch.length < 100) break;
  }
  return all;
};

const listProposals = () => listIssues('labels=proposal&state=all&sort=created&direction=asc');

async function ensureLabel(name, color, description) {
  await gh('/labels', { method: 'POST', body: { name, color, description }, okStatuses: [422] }); // 422 = already exists
}

async function applyLabelChanges(number, changes) {
  if (changes.add.length) await gh('/issues/' + number + '/labels', { method: 'POST', body: { labels: changes.add } });
  for (const l of changes.remove) {
    await gh('/issues/' + number + '/labels/' + encodeURIComponent(l), { method: 'DELETE', okStatuses: [404] });
  }
}

module.exports = { gh, listIssues, listEvents, listProposals, ensureLabel, applyLabelChanges, REPO };
