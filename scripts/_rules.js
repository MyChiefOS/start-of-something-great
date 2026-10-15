// The daily sorting run's rules. Plain, repeatable rules (no AI): the same input always
// gives the same output (check D5). Used by scripts/sort.js, scripts/queue.js and the tests.
const { parseBody, hasContactInfo, maskContacts } = require('../api/_proposals');

// The only labels automation may add or remove (check D2). Status labels are Aaron's alone.
const AUTO_LABELS = ['from an agent', 'needs info', 'possible duplicate', 'contains contact info'];
const AGENT_CHOICE = 'An AI agent acting for a person';
const QUEUE_LABEL = 'daily queue';
const STALE_DAYS = 7;
const DUPLICATE_THRESHOLD = 0.6;

const STOP = new Set(('a an and are as at be by for from has have in into is it its of on or our so that the this ' +
  'to was we will with add make let should new page site day one great proposal').split(' '));

function labelNames(issue) {
  return (issue.labels || []).map((l) => String(typeof l === 'string' ? l : l.name).toLowerCase());
}

function words(title) {
  return new Set(String(title || '').toLowerCase().replace(/^proposal:\s*/, '').replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/).filter((w) => w.length > 2 && !STOP.has(w)));
}

function similarity(a, b) {
  const A = words(a), B = words(b);
  if (A.size < 2 || B.size < 2) return 0;
  let both = 0;
  for (const w of A) if (B.has(w)) both++;
  return both / (A.size + B.size - both);
}

function isProposal(issue) {
  return !issue.pull_request && labelNames(issue).includes('proposal');
}

// Which automatic labels an issue should carry, given the other proposals (check D1).
function autoLabelsFor(issue, others) {
  const f = parseBody(issue.body);
  const out = [];
  if (f.filer === AGENT_CHOICE) out.push('from an agent');
  const title = String(issue.title || '').replace(/^proposal:\s*/i, '').trim();
  if (!title || !f.change || !f.why) out.push('needs info');
  const dup = findDuplicate(issue, others);
  if (dup) out.push('possible duplicate');
  if (hasContactInfo(issue.title) || hasContactInfo(issue.body)) out.push('contains contact info');
  return out;
}

function findDuplicate(issue, others) {
  let best = null;
  for (const o of others || []) {
    if (o.number === issue.number || !isProposal(o) || o.number > issue.number) continue; // only earlier proposals
    const s = similarity(issue.title, o.title);
    if (s >= DUPLICATE_THRESHOLD && (!best || s > best.score)) best = { number: o.number, score: s };
  }
  return best;
}

// What to add and remove. Never touches anything outside AUTO_LABELS (check D2).
// addedByBot(label) says whether the automation itself added that label. A label a person added
// (for example Aaron adding "needs info" by hand) is never removed automatically.
function labelChanges(issue, others, addedByBot) {
  const have = labelNames(issue);
  const want = autoLabelsFor(issue, others);
  const add = want.filter((l) => !have.includes(l));
  const remove = AUTO_LABELS.filter((l) => l !== 'from an agent' && have.includes(l) && !want.includes(l) && !!addedByBot && addedByBot(l));
  for (const l of add.concat(remove)) {
    if (!AUTO_LABELS.includes(l)) throw new Error('automation tried to touch a label it does not own: ' + l);
  }
  return { add, remove };
}

// Who most recently added a label, from an issue's full event history (oldest first).
function addedByBotLast(events, label) {
  const adds = (events || []).filter((e) => e.event === 'labeled' && e.label && String(e.label.name).toLowerCase() === label);
  const last = adds[adds.length - 1];
  return !!last && !!last.actor && last.actor.login === 'github-actions[bot]';
}

function statusOf(issue) {
  const names = labelNames(issue);
  for (const s of ['shipped', 'declined', 'approved', 'in review']) if (names.includes('status: ' + s)) return s;
  return issue.state === 'closed' ? 'closed' : 'waiting';
}

function ageDays(iso, now) {
  return Math.floor((now.getTime() - new Date(iso).getTime()) / 86400000);
}

// Pacific date and hour for a moment in time, e.g. { date: '2026-10-19', hour: 7 }.
function pacific(now) {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Los_Angeles', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23' })
    .formatToParts(now).reduce((o, p) => ((o[p.type] = p.value), o), {});
  return { date: parts.year + '-' + parts.month + '-' + parts.day, hour: Number(parts.hour) };
}

// Check D3: the queue updates once a day, from 7 a.m. Pacific (the job is scheduled twice so
// it lands on 7 a.m. in both daylight and standard time; the second run of the day is skipped).
function queueShouldRun(now, lastUpdatedDate, manual) {
  if (manual) return true;
  const p = pacific(now);
  return p.hour >= 7 && p.hour < 12 && lastUpdatedDate !== p.date;
}

const MARKER = /<!-- queue-date: (\d{4}-\d{2}-\d{2}) -->/;
function lastQueueDate(body) {
  const m = String(body || '').match(MARKER);
  return m ? m[1] : null;
}

// Titles are public text: hide contacts, strip markup, and break @mentions and #references so the
// queue never pings anyone or links issues by accident.
function safeTitle(t) {
  return maskContacts(String(t || '').replace(/^proposal:\s*/i, '')).slice(0, 100)
    .replace(/[\[\]<>`*_|]/g, '').replace(/([@#])/g, '$1\u200b');
}

function line(i, now) {
  return '- [#' + i.number + '](' + i.html_url + ') ' + safeTitle(i.title) + ' · ' + ageDays(i.created_at, now) + ' d';
}

// Check D4: the daily queue. Titles only (contacts masked), never proposal text or usernames.
// markDate is the date recorded as "done for today": a manual run passes the previous date so it
// never stops the 7 a.m. run (check D3).
function buildQueue(issues, now, markDate) {
  const proposals = (issues || []).filter(isProposal);
  const open = proposals.filter((i) => i.state === 'open');
  const waiting = open.filter((i) => ['waiting', 'in review'].includes(statusOf(i)))
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at) || a.number - b.number);
  // Open only: a proposal already closed needs no decision, so it doesn't belong in the queue (found live Oct 14).
  const fresh = open.filter((i) => ageDays(i.created_at, now) < 1 && now - new Date(i.created_at) < 86400000)
    .sort((a, b) => a.number - b.number);
  const flagged = open.filter((i) => labelNames(i).some((l) => ['needs info', 'possible duplicate', 'contains contact info', 'edited after approval'].includes(l)))
    .sort((a, b) => a.number - b.number);
  const stale = waiting.filter((i) => ageDays(i.created_at, now) > STALE_DAYS);
  const p = pacific(now);
  const sec = (title, list, extra) => '### ' + title + ' (' + list.length + ')\n\n' +
    (list.length ? list.map((i) => line(i, now) + (extra ? extra(i) : '')).join('\n') : '_None._') + '\n';
  const flags = (i) => ' · ' + labelNames(i).filter((l) => ['needs info', 'possible duplicate', 'contains contact info', 'edited after approval'].includes(l)).join(', ');
  return [
    '<!-- queue-date: ' + (markDate === undefined ? p.date : markDate || 'none') + ' -->',
    '**Daily queue for ' + p.date + '.** Updated automatically each morning at 7 a.m. Pacific. Plain rules, no AI.',
    '',
    'Decide by adding a status label on the proposal: `status: in review`, `status: approved`, `status: declined` or `status: shipped`.',
    '',
    sec('New since yesterday', fresh),
    sec('Waiting for a decision, oldest first', waiting),
    sec('Flagged', flagged, flags),
    sec('Waiting more than ' + STALE_DAYS + ' days', stale),
    '_Titles only, with contact details hidden. Open a proposal for its full text._'
  ].join('\n');
}

module.exports = {
  AUTO_LABELS, QUEUE_LABEL, STALE_DAYS, safeTitle, addedByBotLast,
  hasContactInfo, maskContacts, similarity, autoLabelsFor, labelChanges, findDuplicate,
  statusOf, pacific, queueShouldRun, lastQueueDate, buildQueue, isProposal
};
