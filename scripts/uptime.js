// Check U1: every 15 minutes, confirm the site, API and MCP server answer correctly.
// A check fails only if it fails twice in a row about 20 seconds apart. On a confirmed failure,
// open (or update) one issue labelled "uptime"; when everything passes again, close it.
const github = require('./_github');

const SITE = process.env.SITE_URL || 'https://dayonegreat.com';
const LABEL = 'uptime';

const CHECKS = [
  { name: 'Home page', path: '/', test: (r, t) => r.status === 200 && t.includes('Day One Great') },
  { name: 'Status API', path: '/api/status', test: (r, t) => r.status === 200 && JSON.parse(t).name === 'Day One Great' },
  { name: 'Proposals API', path: '/api/proposals', test: (r, t) => r.status === 200 && Array.isArray(JSON.parse(t).proposals) },
  {
    name: 'MCP server', path: '/api/mcp',
    init: { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }) },
    test: (r, t) => r.status === 200 && JSON.parse(t).id === 1
  }
];

async function runOnce(check, fetchImpl) {
  const started = Date.now();
  try {
    const r = await fetchImpl(SITE + check.path, { ...(check.init || {}), signal: AbortSignal.timeout(10000) });
    const text = await r.text();
    let ok = false;
    try { ok = check.test(r, text); } catch (e) { ok = false; }
    return { ok, status: r.status, ms: Date.now() - started };
  } catch (e) {
    return { ok: false, status: 'no response', ms: Date.now() - started };
  }
}

async function checkAll(fetchImpl, wait) {
  fetchImpl = fetchImpl || fetch;
  wait = wait || ((ms) => new Promise((res) => setTimeout(res, ms)));
  const results = [];
  for (const c of CHECKS) {
    let r = await runOnce(c, fetchImpl);
    if (!r.ok) { await wait(20000); r = await runOnce(c, fetchImpl); } // confirm before alerting
    results.push({ name: c.name, path: c.path, ...r });
  }
  return results;
}

function report(results, now) {
  const rows = results.map((r) => '| ' + (r.ok ? 'OK' : '**DOWN**') + ' | ' + r.name + ' | `' + r.path + '` | ' + r.status + ' | ' + r.ms + ' ms |');
  return ['Checked ' + now.toISOString() + ' (failures confirmed twice, about 20 seconds apart).', '',
    '| Result | Check | Path | Status | Time |', '|---|---|---|---|---|', ...rows].join('\n');
}

const MARKER = /<!-- failing: ([^>]*) -->/;

// What to do, given this run's results and the open uptime issue (if any). Pure, so it is tested.
// Comments only when the set of failing checks changes, so an outage doesn't notify every 15 minutes.
function decide(results, open) {
  const failing = results.filter((r) => !r.ok).map((r) => r.name).join(', ');
  const before = open ? ((String(open.body || '').match(MARKER) || [])[1] || '') : null;
  if (!failing) return { action: open ? 'close' : 'none', failing };
  if (!open) return { action: 'open', failing };
  return { action: failing === before ? 'none' : 'update', failing };
}

function issueBody(results, failing, now) {
  return '<!-- failing: ' + failing + ' -->\n**Problem detected:** ' + failing + '.\n\n' + report(results, now) +
    '\n\nThis issue closes itself when every check passes again. Note: the Proposals API also fails if GitHub itself is down.';
}

async function main() {
  const results = await checkAll();
  const open = (await github.listIssues('labels=' + LABEL + '&state=open'))[0];
  const now = new Date();
  console.log(results.map((r) => (r.ok ? 'OK   ' : 'DOWN ') + r.name + ' ' + r.status + ' ' + r.ms + 'ms').join('\n'));
  const d = decide(results, open);
  if (d.action === 'open') {
    await github.ensureLabel(LABEL, 'b60205', 'The uptime monitor found a problem');
    await github.gh('/issues', { method: 'POST', body: { title: 'Uptime: ' + d.failing + ' down', body: issueBody(results, d.failing, now), labels: [LABEL] } });
  } else if (d.action === 'update') {
    await github.gh('/issues/' + open.number, { method: 'PATCH', body: { body: issueBody(results, d.failing, now) } });
    await github.gh('/issues/' + open.number + '/comments', { method: 'POST', body: { body: '**Changed:** now failing: ' + d.failing + '.\n\n' + report(results, now) } });
  } else if (d.action === 'close') {
    await github.gh('/issues/' + open.number + '/comments', { method: 'POST', body: { body: '**Recovered.** Every check passes again.\n\n' + report(results, now) } });
    await github.gh('/issues/' + open.number, { method: 'PATCH', body: { state: 'closed', state_reason: 'completed' } });
  }
  // The run stays green: the issue is the alert. A red run every 15 minutes would email the owner each time.
}

if (require.main === module) main().catch((e) => { console.error(e.message); process.exit(1); });

module.exports = { checkAll, report, decide, CHECKS };
