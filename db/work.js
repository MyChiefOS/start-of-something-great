// The work module (042; the design handoff of Nov 5, 2026: /build, /tasks/<id>, /rooms, /rooms/<code>, /projects,
// /projects/<id>). The database decides everything (who may act, the limits, the JEVs auditor, points, the log); this
// file checks inputs first, hides contact details and keys in what people write, makes the claim code, and turns the
// database's refusals into plain words. Every call runs inside a transaction the caller opened as the acting person
// or agent (or as an anonymous visitor, for the public reads).
'use strict';

const c = require('../signin/crypto');
const v = require('./validate');
const { maskContacts } = require('../api/_proposals');
const { maskSecrets } = require('../api/_secrets');

const ROOM = /^[0-9]{2}-0000$/;
const CLASSES = ['agent', 'person', 'either'];
const SIZES = [1, 2, 3, 5, 8];
// 'funding' (063): a buyer's task waiting for its bounty, listed only to its poster and the administrator.
const TASK_STATES = ['open', 'claimed', 'submitted', 'audited', 'approved', 'closed', 'funding', 'all'];
const PROJECT_STATES = ['open', 'claimed', 'submitted', 'completed', 'all'];
const REPO_PR = /^https:\/\/github\.com\/MyChiefOS\/start-of-something-great\/pull\/[1-9][0-9]{0,6}$/;
const LIMIT = 50;
// A claim code: "dogw_" and 16 random bytes. Shown once to the claimer; only its SHA-256 is stored. Written in a pull
// request's description, it shows the pull request was made by whoever held the code.
const CODE_PREFIX = 'dogw_';
const CODE = /dogw_[A-Za-z0-9_-]{22}/g;
const newCode = () => { const code = CODE_PREFIX + c.token(16); return { code, hash: c.sha256hex(code) }; };
// The codes in a pull request's description, as SHA-256 (at most 20; the database keeps at most 20).
const codesIn = (body) => [...new Set((String(body || '').match(CODE) || []).slice(0, 20))].map((x) => c.sha256hex(x));

// Text people write for the work: keys and passwords, then email addresses and phone numbers, hidden. Returns the text
// and how many things were hidden (the JEVs auditor's W11 sends a note with any to a person).
function clean(field, value, { min = 0, max, multiline = true }) {
  if ((value === undefined || value === null || value === '') && min === 0) return { text: '', hits: 0 };
  const s = v.text(field, value, { min: Math.max(1, min), max, multiline });
  const keys = maskSecrets(s);
  const out = maskContacts(keys.text);
  const count = (t) => (t.match(/\[(?:email|number) hidden\]/g) || []).length;
  return { text: out, hits: keys.hits + Math.max(0, count(out) - count(keys.text)) };
}

// The database's refusals, in plain words. The hint is the database's own sentence, written for people.
class WorkError extends Error {
  constructor(status, message, code) { super(message); this.name = 'WorkError'; this.status = status; this.code = code; }
}
function refusal(e) {
  if (!e || typeof e !== 'object') return null;
  if (e.code === 'P0001' && /^work_[a-z_]+$/.test(String(e.message))) {
    const status = e.message === 'work_cap' || e.message === 'work_brake' ? 429 : e.message === 'work_off' || e.message === 'work_own' || e.message === 'work_class' || e.message === 'work_party' || e.message === 'work_peer_person' || e.message === 'work_peer_blocked' ? 403 : 409;
    return new WorkError(status, String(e.hint || 'This can’t be done now.'), e.message);
  }
  if (e.code === '42501') return new WorkError(403, String(e.message || 'Not allowed.').replace(/^./, (x) => x.toUpperCase()) + '.', 'forbidden');
  if (e.code === 'P0002') return new WorkError(404, 'No such ' + (/project/.test(e.message) ? 'open project' : /dispute/.test(e.message) ? 'dispute' : 'task') + '.', 'not_found');
  if (e.code === '22023') return new WorkError(400, 'Check the request: ' + String(e.message) + '.', 'bad_request');
  return null;
}
// Runs one database call in a savepoint, so a refusal leaves the transaction usable, and turns refusals into WorkError.
async function call(t, fn) {
  try {
    return await t.savepoint(fn);
  } catch (e) {
    const r = refusal(e);
    if (r) throw r;
    throw e;
  }
}

const opt = (x) => (x === undefined || x === null || x === '' ? null : x);

// ---- Reading: everything here is public on the site ----
// The Build page: the counts, the board and the latest receipt, with the featured project's plan (050) and, for a
// merged pull request, its changes as GitHub publishes them.
async function summary(t) {
  const [r] = await call(t, (s) => s`select app.work_summary() as d, app.work_plan(app.work_featured()) as p`);
  const d = r.d;
  if (!d || typeof d !== 'object') return d;
  d.plan = r.p || null;
  const lr = d.latest_receipt;
  const m = lr && lr.artifact && lr.artifact.kind === 'pr' ? /\/pull\/([1-9][0-9]{0,6})$/.exec(String(lr.artifact.url || '')) : null;
  if (m) { const [c2] = await call(t, (s) => s`select app.work_pr_changes(${Number(m[1])}::integer) as c`); lr.changes = c2.c || null; }
  return d;
}
// A project's plan (050): its milestones, scope, planned and verified work by day, and its schedule figures. No project:
// the featured one.
async function plan(t, id) {
  const pid = id === null || id === undefined ? null : v.uuid('project', id);
  const [r] = await call(t, (s) => (pid ? s`select app.work_plan(${pid}::uuid) as d` : s`select app.work_plan(app.work_featured()) as d`));
  return r.d;
}

async function tasks(t, { status = null, room = null, project = null, q = null, before = null, limit = LIMIT } = {}) {
  const st = opt(status) === null ? null : v.oneOf('status', status, TASK_STATES);
  const rm = opt(room) === null ? null : v.text('room', room, { max: 7, pattern: ROOM });
  const pj = opt(project) === null ? null : v.uuid('project', project);
  const qq = opt(q) === null ? null : v.text('q', q, { min: 2, max: 100 });
  const b = opt(before) === null ? null : v.uuid('before', before);
  const n = v.int('limit', limit, { min: 1, max: 100 });
  const [r] = await call(t, (s) => s`select app.work_tasks(${st}::text, ${rm}::text, ${pj}::uuid, ${qq}::text, ${b}::uuid, ${n}::integer) as d`);
  return r.d;
}
async function taskOf(t, submissionId) { const [r] = await call(t, (s) => s`select app.work_task_of(${v.uuid('submission', submissionId)}::uuid) as id`); return r.id; }
async function task(t, id) { const [r] = await call(t, (s) => s`select app.work_task(${v.uuid('task', id)}::uuid) as d`); return r.d; }
async function rooms(t) { const [r] = await call(t, (s) => s`select app.work_rooms_list() as d`); return r.d; }
async function room(t, code) { const [r] = await call(t, (s) => s`select app.work_room(${v.text('room', code, { max: 7, pattern: ROOM })}::text) as d`); return r.d; }
async function projects(t, { status = null, room = null, q = null, before = null, limit = LIMIT } = {}) {
  const st = opt(status) === null ? null : v.oneOf('status', status, PROJECT_STATES);
  const rm = opt(room) === null ? null : v.text('room', room, { max: 7, pattern: ROOM });
  const qq = opt(q) === null ? null : v.text('q', q, { min: 2, max: 100 });
  const b = opt(before) === null ? null : v.uuid('before', before);
  const n = v.int('limit', limit, { min: 1, max: 100 });
  const [r] = await call(t, (s) => s`select app.work_projects_list(${st}::text, ${rm}::text, ${qq}::text, ${b}::uuid, ${n}::integer) as d`);
  return r.d;
}
async function project(t, id) { const [r] = await call(t, (s) => s`select app.work_project(${v.uuid('project', id)}::uuid) as d`); return r.d; }
// 054: the next 25 of a project's tasks, before the task named (the cursor its previous page gave).
async function projectTasks(t, id, before) {
  const [r] = await call(t, (s) => s`select app.work_project_tasks(${v.uuid('project', id)}::uuid, ${v.uuid('before', before)}::uuid) as d`);
  return r.d;
}

// The leaderboard (045): one board, one citizen, and (signed in) the viewer's network.
const BOARD_KINDS = ['everyone', 'people', 'agents', 'auditors'];
const BOARD_SORTS = ['impact', 'season', 'all_time', 'calibration', 'reliability', 'revert', 'breadth'];
async function board(t, { kind = null, room = null, sort = null } = {}) {
  const k = opt(kind) === null ? null : v.oneOf('kind', kind, BOARD_KINDS);
  const rm = opt(room) === null ? null : v.text('room', room, { max: 7, pattern: ROOM });
  const so = opt(sort) === null ? null : v.oneOf('sort', sort, BOARD_SORTS);
  const [r] = await call(t, (s) => s`select app.work_board(${k}::text, ${rm}::text, ${so}::text) as d`);
  return r.d;
}
async function citizen(t, kind, ref) {
  if (!['member', 'agent', 'github'].includes(kind) || typeof ref !== 'string' || ref.length > 39) return null;
  const [r] = await call(t, (s) => s`select app.work_citizen(${kind}::text, ${ref}::text) as d`);
  return r.d;
}
// The disputes pages (046).
const DISPUTE_STATES = ['open', 'upheld', 'dismissed', 'settled', 'all'];
async function disputes(t, { status = null, before = null, limit = LIMIT } = {}) {
  const st = opt(status) === null ? null : v.oneOf('status', status, DISPUTE_STATES);
  const b = opt(before) === null ? null : v.uuid('before', before);
  const n = v.int('limit', limit, { min: 1, max: 100 });
  const [r] = await call(t, (s) => s`select app.work_disputes_list(${st}::text, ${b}::uuid, ${n}::integer) as d`);
  return r.d;
}
async function disputeOne(t, id) { const [r] = await call(t, (s) => s`select app.work_dispute_page(${v.uuid('dispute', id)}::uuid) as d`); return r.d; }
// Evidence on an open dispute: email addresses, phone numbers and keys hidden before it is stored.
async function evidence(t, disputeId, { note }) {
  const text = clean('note', note, { min: 3, max: 1000 }).text;
  const [r] = await call(t, (s) => s`select app.work_evidence_add(${v.uuid('dispute', disputeId)}::uuid, ${text}) as d`);
  return { id: r.d };
}
async function network(t) { const [r] = await call(t, (s) => s`select app.work_network() as d`); return r.d; }

// 064 (Aaron, Nov 12): funded work without public prices. The figures anyone may read (counts, tiers, pools of at
// least 3 tasks rounded down to the $100), and one task's bounty as the asker may see it (signed out: its tier; signed
// in: its exact net while the task is open; claimed or later: amounts only for its payer, payee and the administrator).
// 065 (Aaron, Nov 11 and 12): the paid peer reviewer queue. Take the oldest held work on a funded task you may review
// (24 hours), decide it pass or fail with a reason (2% of the bounty either way), or give it back.
async function peerTake(t) { const [r] = await call(t, (s) => s`select app.peer_review_take() as d`); return r.d; }
async function peerDecide(t, { review, verdict, reason }) {
  const vd = v.oneOf('verdict', verdict, ['pass', 'fail']);
  const why = v.text('reason', reason, { min: 3, max: 300 });
  const [r] = await call(t, (s) => s`select app.peer_review_decide(${v.uuid('review', review)}::uuid, ${vd}, ${why}) as d`);
  return { result: r.d };
}
async function peerRelease(t, { review }) { const [r] = await call(t, (s) => s`select app.peer_review_release(${v.uuid('review', review)}::uuid) as d`); return { result: r.d }; }
async function market(t) { const [r] = await call(t, (s) => s`select app.work_market() as d`); return r.d; }
async function bountyOf(t, taskId) { const [r] = await call(t, (s) => s`select app.work_bounty_of(${v.uuid('task', taskId)}::uuid) as d`); return r.d; }

// ---- People and agents ----
async function mine(t) { const [r] = await call(t, (s) => s`select app.work_mine() as d`); return r.d; }

async function projectCreate(t, { title, description, room: rm }) {
  const ti = clean('title', title, { min: 3, max: 140, multiline: false });
  const de = clean('description', description, { max: 4000 });
  const code = v.text('room', rm, { max: 7, pattern: ROOM });
  const [r] = await call(t, (s) => s`select app.work_project_create(${ti.text}, ${de.text}, ${code}) as id`);
  return { id: r.id };
}
async function taskCreate(t, { project: pj, title, description, class: cls, size }) {
  const ti = clean('title', title, { min: 3, max: 140, multiline: false });
  const de = clean('description', description, { max: 4000 });
  const k = v.oneOf('class', cls, CLASSES);
  const sz = v.oneOf('size', size, SIZES);
  const [r] = await call(t, (s) => s`select app.work_task_create(${v.uuid('project', pj)}::uuid, ${ti.text}, ${de.text}, ${k}, ${sz}::integer) as id`);
  return { id: r.id };
}
// Claims an open task: { claim, task, expires_at, seq, code }. The code is shown once and never stored.
async function claim(t, taskId) {
  const k = newCode();
  const [r] = await call(t, (s) => s`select app.work_claim(${v.uuid('task', taskId)}::uuid, ${k.hash}) as d`);
  return { ...r.d, code: k.code };
}
async function release(t, taskId) { const [r] = await call(t, (s) => s`select app.work_release(${v.uuid('task', taskId)}::uuid) as d`); return { result: r.d }; }
// An agent hands its claim to one of its own direct sub-agents, which gets a new code.
async function handoff(t, taskId, agentId) {
  const k = newCode();
  const [r] = await call(t, (s) => s`select app.work_handoff(${v.uuid('task', taskId)}::uuid, ${v.uuid('agent', agentId)}::uuid, ${k.hash}) as d`);
  return { ...r.d, code: k.code };
}
// kind: pr (a pull request in this repository), link (an https link) or file (its SHA-256).
async function submit(t, taskId, { kind, url = null, sha256 = null, note = '' }) {
  const k = v.oneOf('kind', kind, ['pr', 'link', 'file']);
  let u = null, h = null;
  if (k === 'pr') u = v.text('url', url, { max: 100, pattern: REPO_PR });
  if (k === 'link') {
    u = v.text('url', url, { max: 500, pattern: /^https?:\/\/[^\s<>"]+$/ });
    // A link to this repository's pull request is submitted as one, so the JEVs auditor can check it.
    if (REPO_PR.test(u)) throw new v.ValidationError('url', 'is a pull request in this repository: submit it with kind "pr"');
  }
  if (k === 'file') h = v.text('sha256', sha256, { max: 64, pattern: /^[0-9a-f]{64}$/ });
  if (k !== 'file' && opt(sha256) !== null) throw new v.ValidationError('sha256', 'is only for kind "file"');
  if (k === 'file' && opt(url) !== null) throw new v.ValidationError('url', 'isn’t taken with kind "file"');
  const n = clean('note', note, { max: 2000 });
  const [r] = await call(t, (s) => s`select app.work_submit(${v.uuid('task', taskId)}::uuid, ${k}, ${u}::text, ${h}::text, ${n.text}, ${n.hits}::integer) as d`);
  return r.d;
}
async function approve(t, taskId) { const [r] = await call(t, (s) => s`select app.work_approve(${v.uuid('task', taskId)}::uuid) as d`); return { result: r.d }; }
async function cancel(t, taskId) { const [r] = await call(t, (s) => s`select app.work_cancel(${v.uuid('task', taskId)}::uuid) as d`); return { result: r.d }; }

// The poster's check of work the rules couldn't decide: pass, or fail with a reason. { result: pass | fail | held }.
async function posterCheck(t, submissionId, { verdict, reason = null }) {
  const vd = v.oneOf('verdict', verdict, ['pass', 'fail']);
  const why = opt(reason) === null ? null : clean('reason', reason, { min: 3, max: 300, multiline: false }).text;
  const [r] = await call(t, (s) => s`select app.work_poster_decide(${v.uuid('submission', submissionId)}::uuid, ${vd}, ${why}::text) as d`);
  return { result: r.d };
}
// A dispute on a pass whose points are pending: { id }.
async function dispute(t, submissionId, { reason }) {
  const why = clean('reason', reason, { min: 3, max: 500 }).text;
  const [r] = await call(t, (s) => s`select app.work_dispute(${v.uuid('submission', submissionId)}::uuid, ${why}) as d`);
  return { id: r.d };
}

// ---- Aaron ----
async function admin(t) { const [r] = await call(t, (s) => s`select app.work_admin() as d`); return r.d; }
async function decide(t, submissionId, { verdict, size = null, reason }) {
  const vd = v.oneOf('verdict', verdict, ['pass', 'fail']);
  const sz = size === null || size === undefined ? null : v.oneOf('size', size, SIZES);
  const why = v.text('reason', reason, { min: 3, max: 300 });
  const [r] = await call(t, (s) => s`select app.work_person_decide(${v.uuid('submission', submissionId)}::uuid, ${vd}, ${sz}::integer, ${why}) as d`);
  return { result: r.d };
}
async function settle(t, disputeId, { decision, reason }) {
  const [r] = await call(t, (s) => s`select app.work_dispute_decide(${v.uuid('dispute', disputeId)}::uuid, ${v.oneOf('decision', decision, ['uphold', 'dismiss'])},
    ${v.text('reason', reason, { min: 3, max: 300 })}) as d`);
  return { result: r.d };
}
async function review(t, checkId, { decision, reason }) {
  const [r] = await call(t, (s) => s`select app.work_check_decide(${v.uuid('check', checkId)}::uuid, ${v.oneOf('decision', decision, ['confirm', 'reverse'])},
    ${v.text('reason', reason, { min: 3, max: 300 })}) as d`);
  return { result: r.d };
}
// The administrator's console (051): one tab; the database logs the read. A status filters the projects tab; a cursor
// pages back by time and id together.
async function console_(t, { tab, status, cursor }) {
  const tb = v.oneOf('tab', tab, ['summary', 'agents', 'projects', 'submissions', 'ledger', 'admins']);
  const st = status === undefined || status === null || status === '' ? null : v.oneOf('status', status, ['open', 'claimed', 'submitted', 'audited', 'approved', 'closed']);
  // The last row shown, "time~id", as the previous page gave it; the database refuses a time that isn't real.
  const cu = cursor === undefined || cursor === null || cursor === '' ? null
    : v.text('cursor', cursor, { max: 80, pattern: /^20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-9:.]+(Z|[+-][0-9]{2}(:?[0-9]{2})?)~[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/ });
  const [r] = await call(t, (s) => s`select app.work_console(${tb}, ${st}, ${cu}) as d`);
  // 053: the sign-in locks in force now, on the Admins tab's first page, each with a way to release it.
  if (tb === 'admins' && !cu) {
    const [l] = await call(t, (s) => s`select app.signin_locks_open() as l`);
    return { ...r.d, locks: l.l };
  }
  return r.d;
}
// 053: an administrator releases a member's sign-in lock early, with a reason (in the audit log).
async function unlock(t, member, reason) {
  const m = v.uuid('member', member);
  const r = v.text('reason', reason, { min: 3, max: 200 });
  const [x] = await call(t, (s) => s`select app.signin_unlock(${m}::uuid, ${r}) as released`);
  return { result: x.released ? 'released' : 'not_locked' };
}
// A day as YYYY-MM-DD; the database checks the range (a year back to two years ahead).
const DAY = /^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$/;
// A real day: one that reads back the same (2026-02-31 doesn't; Postgres would store it as March 3).
function realDay(field, value) {
  const s = v.text(field, value, { max: 10, pattern: DAY });
  if (new Date(s + 'T00:00:00Z').toISOString().slice(0, 10) !== s) throw new v.ValidationError(field, 'is not a real date');
  return s;
}
async function milestoneAdd(t, { project: pj, title, target, gate = false }) {
  // A title is public words, like a project's: keys and contact details hidden first.
  const ti = clean('title', title, { min: 3, max: 80, multiline: false });
  const [r] = await call(t, (s) => s`select app.work_milestone_add(${v.uuid('project', pj)}::uuid, ${ti.text},
    ${realDay('target', target)}::date, ${v.oneOf('gate', gate, [true, false])}) as d`);
  return { milestone: r.d };
}
async function milestoneMove(t, { milestone, target }) {
  const [r] = await call(t, (s) => s`select app.work_milestone_move(${v.uuid('milestone', milestone)}::uuid, ${realDay('target', target)}::date) as d`);
  return { milestone: r.d };
}
async function remove(t, kind, id) {
  const [r] = await call(t, (s) => s`select app.work_remove(${v.oneOf('kind', kind, ['task', 'project'])}, ${v.uuid('id', id)}::uuid) as d`);
  return { result: r.d };
}

module.exports = { peerTake, peerDecide, peerRelease, market, bountyOf, summary, plan, milestoneAdd, milestoneMove, console: console_, unlock, tasks, task, taskOf, rooms, room, projects, project, projectTasks, board, citizen, network, disputes, disputeOne, evidence, DISPUTE_STATES, BOARD_KINDS, BOARD_SORTS, mine, projectCreate, taskCreate, claim, release, handoff, submit,
  approve, cancel, posterCheck, dispute, admin, decide, settle, review, remove, clean, codesIn, newCode, refusal, call, WorkError, LIMIT, ROOM, CLASSES, SIZES, TASK_STATES, PROJECT_STATES, REPO_PR };
