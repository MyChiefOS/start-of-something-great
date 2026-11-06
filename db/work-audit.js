// The JEVs auditor's rules (042), in JavaScript: the same rules as app.work_jevs_rules, in the same order, so anyone can
// run them on a submission's facts without the database. test/work.test.js runs both on the same facts and fails if
// they ever differ. Deterministic, no AI, no clock.
// facts: class, worker_kind, own, late, reused, artifact (pr | link | file), github_task (pr | issue | null), issue, task_source (member | github), claim_open, wait_over,
// pr (null until GitHub has been read: { merged, state, base, code_ok, author_ok, refs_issue }), url_https, url_ip,
// url_short, note_hits.
// Returns { verdict: pass | fail | person | waiting, rules: [the rules that fired, in order] }.
'use strict';

const RULES = {
  W01: 'The task’s class says who may do it: an agent’s task done by a person, or a person’s by an agent.',
  W02: 'Nobody audits or is paid for their own task: the worker’s owner posted it.',
  W03: 'Submitted after the claim’s hold ran out.',
  W04: 'The same artifact was already submitted for another task.',
  W05: 'A task from this repository’s GitHub is done by a pull request in this repository.',
  W06: 'The pull request was closed without being merged, or merged somewhere other than main.',
  W07: 'The pull request’s description doesn’t carry the claim’s code, and the worker isn’t its author: who wrote it can’t be checked by code.',
  W08: 'For an issue’s task, the pull request doesn’t name the issue (#N).',
  W09: 'A link that isn’t https, points at a bare address, or goes through a link shortener: refused; submit an https link to the page itself.',
  W10: 'A file is known only by its SHA-256: a person checks what it is.',
  W11: 'The note had contact details or keys, which were hidden: a person checks it.',
  W12: 'A member\u2019s task done by a pull request: whether it does that task is a person\u2019s call.',
  W13: 'The pull request wasn\u2019t merged into main (or wasn\u2019t found) by the time the claim\u2019s hold and the audit\u2019s time after it ran out.'
};
// The rules that fail work outright; the others send it to a person.
const HARD = new Set(['W01', 'W02', 'W03', 'W04', 'W05', 'W06', 'W09', 'W13']);
// The rules the worker can fix (the claim's code, or "#N", in the pull request's description): it waits while the claim holds.
const FIXABLE = new Set(['W07', 'W08']);

const yes = (x) => x === true || x === 'true';

function rules(f) {
  const fired = [];
  let hard = false, machine = false, waiting = false, fixable = false;
  const fire = (r) => { fired.push(r); if (HARD.has(r)) hard = true; if (FIXABLE.has(r)) fixable = true; };
  if ((f.class === 'agent' && f.worker_kind === 'member') || (f.class === 'person' && f.worker_kind === 'agent')) fire('W01');
  if (yes(f.own)) fire('W02');
  if (yes(f.late)) fire('W03');
  if (yes(f.reused)) fire('W04');
  if (f.github_task !== null && f.github_task !== undefined && f.artifact !== 'pr') fire('W05');
  if (f.artifact === 'pr') {
    const pr = f.pr;
    if (pr === null || pr === undefined || typeof pr !== 'object' || Array.isArray(pr)) {
      waiting = true; // GitHub hasn't been read for this pull request yet
    } else {
      const merged = yes(pr.merged);
      if (pr.state === 'closed' && !merged) fire('W06');
      else if (merged && pr.base !== 'main') fire('W06');
      else if (!merged) waiting = true; // still open: wait for the merge
      if (!(yes(pr.code_ok) || yes(pr.author_ok))) fire('W07');
      if (f.github_task === 'issue' && !yes(pr.refs_issue)) fire('W08');
      if (f.task_source === 'member') fire('W12');
      if (merged && pr.base === 'main' && !fired.includes('W07') && !fired.includes('W08') && !fired.includes('W12')) machine = true;
    }
  }
  if (f.artifact === 'pr' && yes(f.wait_over) && (f.pr === null || f.pr === undefined || typeof f.pr !== 'object' || Array.isArray(f.pr) || !yes(f.pr.merged))) fire('W13');
  if (f.artifact === 'link' && (!yes(f.url_https) || yes(f.url_ip) || yes(f.url_short))) fire('W09');
  if (f.artifact === 'file') fire('W10');
  if (Number(f.note_hits || 0) > 0) { fire('W11'); machine = false; }
  return { verdict: hard ? 'fail' : waiting ? 'waiting' : fixable ? (yes(f.claim_open) ? 'waiting' : 'fail') : machine ? 'pass' : 'person', rules: fired };
}

module.exports = { rules, RULES, HARD, FIXABLE };
