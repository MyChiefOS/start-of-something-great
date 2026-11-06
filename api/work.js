// /api/work/*: the work module (042; the design handoff of Nov 5, 2026: /build, /tasks/<id>, /rooms, /rooms/<code>,
// /projects, /projects/<id>). The database decides who may do what; this file reads the request, says who is acting,
// and hides contact details and keys in what anyone wrote before it is shown.
//   Public, no sign-in, cached at the edge for 30 seconds:
//     GET  summary                                   the Build page: counts, the board, packages, the latest receipt, live entries
//     GET  tasks?status=&room=&project=&q=&before=&limit=   tasks, newest first (limit 1 to 100, 50 by default)
//     GET  task?id=                                  one task: its claim, submissions, audits, seals and points
//     GET  rooms                                     the 23 rooms
//     GET  room?code=                                one room: its open projects and tasks, and who did audited work there
//     GET  projects?status=&room=&q=&before=&limit=  projects
//     GET  project?id=                               one project and its tasks
//   Signed in (a person on our own pages, or an agent with "Authorization: Bearer <key>"):
//     GET  mine                                      your claims and the tasks you posted
//     POST projects {title, description?, room}      a new project
//     POST tasks {project, title, description?, class, size}   a new task in your project
//     POST claim {task}                              claim an open task for 72 hours; the answer has your claim code, once
//     POST release {task}                            let your claim go
//     POST handoff {task, agent}                     an agent hands its claim to one of its direct sub-agents
//     POST submit {task, kind, url?, sha256?, note?} submit work: kind pr (this repository), link (https) or file (SHA-256)
//     POST check {submission, verdict, reason?}      the poster checks work the rules couldn't decide (a fail needs a reason)
//     POST dispute {submission, reason}              dispute a pass whose points are pending (anyone but the worker)
//     POST approve {task}                            the poster approves work that passed its audit
//     POST cancel {task}                             the poster closes an open task nobody claimed
//   Aaron only:
//     GET  admin                                     the repository's tasks the rules couldn't decide, checks after a poster's pass, disputes
//     POST decide {submission, verdict, size?, reason}   pass or fail work on the repository's own task, with a reason
//     POST review {check, decision, reason}          confirm or reverse a pass picked for the check after
//     POST settle {dispute, decision, reason}        uphold (the pass is reversed) or dismiss a dispute
//     POST remove {kind, id}                         remove a task or project that breaks the terms
'use strict';

const db = require('../db');
const work = require('../db/work');
const session = require('../signin/session');
const agentkey = require('../signin/agentkey');
const { onSite, sameSite } = require('../signin/http');
const { ValidationError } = require('../db/validate');
const { maskContacts } = require('./_proposals');
const { UNTRUSTED_NOTE } = require('./_lib');

const ORIGIN = 'https://dayonegreat.com';
const CACHE = 30;
const MAX_BODY_BYTES = 8192;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const JOIN = '/join?return_to=%2Fbuild';
const STEPS = 'The steps for agents are in ' + ORIGIN + '/llms.txt.';

function reply(res, code, body, cache = 0) {
  res.statusCode = code;
  if (code === 401 && body && body.error === agentkey.NOT_WORKING) res.setHeader('WWW-Authenticate', 'Bearer');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', cache ? 'public, max-age=0, s-maxage=' + cache + ', stale-while-revalidate=' + cache : 'no-store');
  res.end(JSON.stringify(body, null, 2));
}

async function readJson(req) {
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') return null;
  let raw;
  if (req.body !== undefined && req.body !== null) {
    raw = Buffer.isBuffer(req.body) || typeof req.body === 'string' ? String(req.body) : JSON.stringify(req.body);
  } else {
    let size = 0;
    const chunks = [];
    for await (const ch of req) { size += ch.length; if (size > MAX_BODY_BYTES) return null; chunks.push(ch); }
    raw = Buffer.concat(chunks).toString('utf8');
  }
  if (Buffer.byteLength(raw) > MAX_BODY_BYTES) return null;
  try { const x = JSON.parse(raw); return x && typeof x === 'object' && !Array.isArray(x) ? x : null; } catch { return null; }
}

// Everything people and agents wrote, and every name, with contact details and keys hidden, walked through the answer.
const TEXT_KEYS = new Set(['title', 'description', 'note', 'name', 'reason']);
function shown(x, key) {
  if (Array.isArray(x)) return x.map((y) => shown(y, key));
  if (x && typeof x === 'object') { const o = {}; for (const [k, v] of Object.entries(x)) o[k] = shown(v, k); return o; }
  if (typeof x === 'string' && TEXT_KEYS.has(key)) return maskContacts(x);
  return x;
}
const UNTRUSTED = 'Titles, descriptions, notes and names are written by members of the public and their agents.';
const pub = (res, body) => reply(res, 200, { ...shown(body), untrusted: UNTRUSTED, note_on_content: UNTRUSTED_NOTE }, CACHE);

// The query, with only the keys this route takes, each once. Vercel's rewrite (vercel.json: /api/work/:path* to
// /api/work?route=:path*) also passes the rewrite's own parameter, path, in the query string (Vercel's docs: "named
// parameters pass through in the query string"); route and path are the rewrite's, never the visitor's to choose.
// Before this was known, every read answered 400 in production (#110).
const REWRITE_KEYS = ['route', 'path'];
function query(req, keys) {
  const url = new URL(req.url || '/', ORIGIN);
  const p = url.searchParams;
  const seen = [...p.keys()].filter((k) => !REWRITE_KEYS.includes(k) || keys.includes(k));
  if (seen.length !== new Set(seen).size || seen.some((k) => !keys.includes(k))) return null;
  const out = {};
  for (const k of keys) out[k] = p.has(k) ? p.get(k) : null;
  return out;
}
const limitOf = (s) => (s === null ? work.LIMIT : /^[1-9][0-9]{0,2}$/.test(s) && Number(s) <= 100 ? Number(s) : NaN);

// Who is acting: an agent with its key, or a person signed in on our own pages. Returns the database actor, or null
// after replying.
async function actor(req, res, run, { write }) {
  if (agentkey.fromRequest(req).present) {
    const a = await agentkey.resolve(req, run);
    if (!a) { reply(res, 401, { error: agentkey.NOT_WORKING }); return null; }
    return { ctx: agentkey.actorFor(a), agent: true };
  }
  if (write && !sameSite(req)) { reply(res, 403, { error: 'This can only be done from dayonegreat.com, or by an agent with its key. ' + STEPS }); return null; }
  const who = await session.current(req, run);
  if (!who) { reply(res, 401, { error: 'Sign in to take part in the work.', join: JOIN }); return null; }
  return { ctx: session.actorFor(who), admin: who.isAdmin === true };
}

const PUBLIC = {
  summary: { keys: [], fn: (t) => work.summary(t) },
  tasks: { keys: ['status', 'room', 'project', 'q', 'before', 'limit'],
    fn: (t, q) => work.tasks(t, { ...q, limit: limitOf(q.limit) }) },
  task: { keys: ['id'], fn: (t, q) => work.task(t, q.id), one: 'No task has that ID (or it was removed).' },
  rooms: { keys: [], fn: (t) => work.rooms(t) },
  room: { keys: ['code'], fn: (t, q) => work.room(t, q.code), one: 'No room has that code. The 23 rooms are at ' + ORIGIN + '/rooms.' },
  projects: { keys: ['status', 'room', 'q', 'before', 'limit'], fn: (t, q) => work.projects(t, { ...q, limit: limitOf(q.limit) }) },
  project: { keys: ['id'], fn: (t, q) => work.project(t, q.id), one: 'No project has that ID (or it was removed).' }
};

// Each write's body: only these keys.
const WRITES = {
  projects: { keys: ['title', 'description', 'room'], fn: (t, b) => work.projectCreate(t, b), code: 201 },
  tasks: { keys: ['project', 'title', 'description', 'class', 'size'], fn: (t, b) => work.taskCreate(t, b), code: 201 },
  claim: { keys: ['task'], fn: (t, b) => work.claim(t, b.task), code: 201,
    say: (r) => ({ ...r, message: 'Claimed until ' + r.expires_at + '. Your claim code is shown only now: put it in the description of the pull request that does this task, '
      + 'and the site matches the merged pull request to your claim. Keep it to yourself until then.' }) },
  release: { keys: ['task'], fn: (t, b) => work.release(t, b.task) },
  handoff: { keys: ['task', 'agent'], fn: (t, b) => work.handoff(t, b.task, b.agent), code: 201, agentOnly: true },
  submit: { keys: ['task', 'kind', 'url', 'sha256', 'note'], fn: (t, b) => work.submit(t, b.task, b), code: 201,
    say: (r) => ({ ...r, message: r.status === 'waiting' ? 'Submitted. The JEVs auditor waits for GitHub to show the pull request merged into main, then decides.'
      : r.status === 'review' ? 'Submitted. The JEVs auditor’s rules couldn’t decide it, so the task’s poster checks it (a sample is checked again).'
        : r.status === 'passed' ? 'Submitted and passed its audit.' : 'Submitted, and the JEVs auditor’s rules refused it: see the task page for which.' }) },
  approve: { keys: ['task'], fn: (t, b) => work.approve(t, b.task) },
  cancel: { keys: ['task'], fn: (t, b) => work.cancel(t, b.task) },
  check: { keys: ['submission', 'verdict', 'reason'], fn: (t, b) => work.posterCheck(t, b.submission, b),
    say: (r) => ({ ...r, message: r.result === 'held' ? 'A limit was reached (the same pair\u2019s passes, a day\u2019s points, or JEVs\u2019s level), so this work waits for Third Look. The task page says which.'
      : r.result === 'pass' ? 'Passed and approved. A sample of passes is checked again; its points are pending for 72 hours.' : 'Not passed. The worker may submit again while the claim holds.' }) },
  dispute: { keys: ['submission', 'reason'], fn: (t, b) => work.dispute(t, b.submission, b), code: 201 },
  decide: { keys: ['submission', 'verdict', 'size', 'reason'], fn: (t, b) => work.decide(t, b.submission, b), adminOnly: true },
  settle: { keys: ['dispute', 'decision', 'reason'], fn: (t, b) => work.settle(t, b.dispute, b), adminOnly: true },
  review: { keys: ['check', 'decision', 'reason'], fn: (t, b) => work.review(t, b.check, b), adminOnly: true },
  remove: { keys: ['kind', 'id'], fn: (t, b) => work.remove(t, b.kind, b.id), adminOnly: true }
};

async function handle(req, res, run) {
  const route = String((req.query && req.query.route) || new URL(req.url || '/', ORIGIN).searchParams.get('route') || '').replace(/^\/+|\/+$/g, '');
  if (!onSite(req)) return reply(res, 403, { error: 'Use https://dayonegreat.com.' });
  const reads = { ...PUBLIC, mine: true, admin: true };
  if (req.method === 'GET' && !(route in reads)) return reply(res, route in WRITES ? 405 : 404, { error: (route in WRITES ? 'Use POST for this address. ' : 'Not found. ') + STEPS });
  if (req.method === 'POST' && !(route in WRITES)) return reply(res, route in reads ? 405 : 404, { error: (route in reads ? 'Use GET for this address. ' : 'Not found. ') + STEPS });
  if (req.method !== 'GET' && req.method !== 'POST') return reply(res, 405, { error: 'Use GET or POST.' });
  if (!run) return reply(res, 503, { error: 'The work module isn’t switched on here.' });
  try {
    if (req.method === 'GET' && PUBLIC[route]) {
      const p = PUBLIC[route];
      const q = query(req, p.keys);
      if (!q || (req.headers && req.headers.authorization) || ('limit' in q && Number.isNaN(limitOf(q.limit)))) {
        return reply(res, 400, { error: 'This address takes only ' + (p.keys.length ? p.keys.join(', ') : 'nothing') + ', each once, and no sign-in. ' + STEPS }, CACHE);
      }
      if (p.one && q[p.keys[0]] === null) return reply(res, 400, { error: 'Give ' + p.keys[0] + '.' }, CACHE);
      if (p.keys[0] === 'id' && !UUID.test(q.id)) return reply(res, 404, { error: p.one }, CACHE);
      const out = await run({ actor: 'anon' }, (t) => p.fn(t, q));
      if (p.one && !out) return reply(res, 404, { error: p.one }, CACHE);
      return pub(res, out);
    }
    if (req.method === 'GET') {
      if (!query(req, [])) return reply(res, 400, { error: 'This address takes no query. ' + STEPS });
      const who = await actor(req, res, run, { write: false });
      if (!who) return;
      if (route === 'admin' && !who.admin) return reply(res, 403, { error: 'Only an administrator sees this.' });
      const out = await run(who.ctx, (t) => (route === 'admin' ? work.admin(t) : work.mine(t)));
      return reply(res, 200, shown(out));
    }
    const w = WRITES[route];
    const body = await readJson(req);
    if (!body) return reply(res, 400, { error: 'Send a JSON object (Content-Type: application/json, at most 8 KB).' });
    const extra = Object.keys(body).filter((k) => !w.keys.includes(k));
    if (extra.length) return reply(res, 400, { error: 'This address takes only ' + w.keys.join(', ') + '.' });
    const who = await actor(req, res, run, { write: true });
    if (!who) return;
    if (w.adminOnly && !who.admin) return reply(res, 403, { error: 'Only an administrator does this.' });
    if (w.agentOnly && !who.agent) return reply(res, 403, { error: 'Only an agent hands work to its sub-agents.' });
    // A step on a task or a submission answers with the task as it now stands, read in the same transaction, so the
    // page never redraws from a copy the edge cache kept (the public reads are cached for 30 seconds).
    const out = await run(who.ctx, async (t) => {
      const r = await w.fn(t, body);
      const id = typeof body.task === 'string' ? body.task : typeof body.submission === 'string' ? await work.taskOf(t, body.submission) : null;
      return id && UUID.test(id) && !w.adminOnly ? { ...r, task: await work.task(t, id) } : r;
    });
    return reply(res, w.code || 200, shown(w.say ? w.say(out) : out));
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Check the request: ' + e.message + '.' });
    if (e instanceof work.WorkError) return reply(res, e.status, { error: e.message, reason: e.code, ...(e.status === 401 ? { join: JOIN } : {}) });
    // The site reached production before migration 042: not cached, so it clears itself once 042 is applied.
    if (e && e.code === '42883') return reply(res, 503, { error: 'The work module is being switched on. Please try again in a few minutes.' });
    throw e;
  }
}

module.exports = async (req, res) => {
  try {
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
module.exports.handle = handle;
module.exports.shown = shown;
