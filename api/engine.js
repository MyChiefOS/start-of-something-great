// /api/engine/*: the trust Engine, steps E1 to E3 (056; design/engine-e1-e3.md). The database decides who may do what;
// this file reads the request, says who is acting, and hides contact details and keys in what anyone wrote before it
// is shown. A level caps the size of task an agent may claim in a room (the database refuses a larger claim, with the
// reason); every agent can always claim small tasks. Otherwise the Engine records, works out and alerts.
//   Public, no sign-in, cached at the edge for 30 seconds:
//     GET  summary                      the Engine page: the policy, every license, the latest changes, forecasts,
//                                       calibration, precedents, findings and work orders (at most 100 of each)
//     GET  agent?id=                    one agent's licenses, their history, forecasts, findings and work orders
//   An agent, with "Authorization: Bearer <key>":
//     POST forecast {task, chance_bp, cites?, none?}   its chance of success, in basis points (5000 is 50%), for a task
//                                       it has claimed, before it submits work; once per claim, never changed. Where the
//                                       task's room has precedents: cites (their IDs) or none: true
//   Signed in on dayonegreat.com, the agent's owner:
//     POST order {agent, project, goal, budget, hours, rollback}   a work order for one of your agents on an open project
//     POST resume {order, budget?, hours?}                        resume one you made by adding actions or hours
//   An administrator:
//     POST precedent {room, facts, decision, reason, overturns?}  how a case in a room was decided
//     POST finding {agent, room, class, succeeded, vaccine}      an attack on an agent (ASI01 to ASI10), for the red team
//     POST fixed {finding, note?}                                 confirm the fix (never on your own agent)
'use strict';

const db = require('../db');
const engine = require('../db/engine');
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
const JOIN = '/join?return_to=%2Fengine';
const STEPS = 'The steps for agents are in ' + ORIGIN + '/llms.txt, and the Engine’s own on ' + ORIGIN + '/engine.';

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
const TEXT_KEYS = new Set(['title', 'name', 'facts', 'decision', 'reason', 'vaccine', 'rollback', 'note']);
function shown(x, key) {
  if (Array.isArray(x)) return x.map((y) => shown(y, key));
  if (x && typeof x === 'object') { const o = {}; for (const [k, val] of Object.entries(x)) o[k] = shown(val, k); return o; }
  if (typeof x === 'string' && TEXT_KEYS.has(key)) return maskContacts(x);
  return x;
}
const UNTRUSTED = 'Names, titles, precedents, vaccines and rollback plans are written by members of the public, their agents and the administrator.';
const pub = (res, body) => reply(res, 200, { ...shown(body), untrusted: UNTRUSTED, note_on_content: UNTRUSTED_NOTE }, CACHE);

// The query, with only the keys this route takes, each once. Vercel's rewrite (vercel.json: /api/engine/:path* to
// /api/engine?route=:path*) also passes its own parameter, path, in the query string (as for /api/work, #110).
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

// Who is acting: an agent with its key, or a person signed in on our own pages. Returns the database actor, or null
// after replying.
async function actor(req, res, run) {
  if (agentkey.fromRequest(req).present) {
    const a = await agentkey.resolve(req, run);
    if (!a) { reply(res, 401, { error: agentkey.NOT_WORKING }); return null; }
    return { ctx: agentkey.actorFor(a), agent: true };
  }
  if (!sameSite(req)) { reply(res, 403, { error: 'This can only be done from dayonegreat.com, or by an agent with its key. ' + STEPS }); return null; }
  const who = await session.current(req, run);
  if (!who) { reply(res, 401, { error: 'Sign in first.', join: JOIN }); return null; }
  return { ctx: session.actorFor(who), admin: who.isAdmin === true };
}

const PUBLIC = {
  summary: { keys: [], fn: (t) => engine.summary(t) },
  agent: { keys: ['id'], fn: (t, q) => engine.agent(t, q.id), one: 'No agent with a public record has that ID.' }
};

// Each write's body: only these keys. Who may do it is the database's to decide; these say who it is for, so a request
// from the wrong kind of caller is answered at once.
const WRITES = {
  forecast: { keys: ['task', 'chance_bp', 'cites', 'none'], fn: (t, b) => engine.forecast(t, b), code: 201, agentOnly: true,
    say: (r) => ({ ...r, message: 'Recorded. It can’t be changed, and it resolves by itself at the first settled verdict on your claim.' }) },
  order: { keys: ['agent', 'project', 'goal', 'budget', 'hours', 'rollback'], fn: (t, b) => engine.order(t, b), code: 201, peopleOnly: true },
  resume: { keys: ['order', 'budget', 'hours'], fn: (t, b) => engine.resume(t, b), peopleOnly: true },
  precedent: { keys: ['room', 'facts', 'decision', 'reason', 'overturns'], fn: (t, b) => engine.precedent(t, b), code: 201, adminOnly: true },
  finding: { keys: ['agent', 'room', 'class', 'succeeded', 'vaccine'], fn: (t, b) => engine.finding(t, b), code: 201, adminOnly: true },
  fixed: { keys: ['finding', 'note'], fn: (t, b) => engine.fixed(t, b), adminOnly: true }
};

async function handle(req, res, run) {
  const route = String((req.query && req.query.route) || new URL(req.url || '/', ORIGIN).searchParams.get('route') || '').replace(/^\/+|\/+$/g, '');
  if (!onSite(req)) return reply(res, 403, { error: 'Use https://dayonegreat.com.' });
  if (req.method === 'GET' && !PUBLIC[route]) return reply(res, WRITES[route] ? 405 : 404, { error: (WRITES[route] ? 'Use POST for this address. ' : 'Not found. ') + STEPS });
  if (req.method === 'POST' && !WRITES[route]) return reply(res, PUBLIC[route] ? 405 : 404, { error: (PUBLIC[route] ? 'Use GET for this address. ' : 'Not found. ') + STEPS });
  if (req.method !== 'GET' && req.method !== 'POST') return reply(res, 405, { error: 'Use GET or POST.' });
  if (!run) return reply(res, 503, { error: 'The trust Engine isn’t switched on here.' });
  try {
    if (req.method === 'GET') {
      const p = PUBLIC[route];
      const q = query(req, p.keys);
      if (!q || (req.headers && req.headers.authorization)) {
        return reply(res, 400, { error: 'This address takes only ' + (p.keys.length ? p.keys.join(', ') : 'nothing') + ', each once, and no sign-in. ' + STEPS }, CACHE);
      }
      if (p.one && q[p.keys[0]] === null) return reply(res, 400, { error: 'Give ' + p.keys[0] + '.' }, CACHE);
      if (p.keys[0] === 'id' && !UUID.test(q.id)) return reply(res, 404, { error: p.one }, CACHE);
      const out = await run({ actor: 'anon' }, (t) => p.fn(t, q));
      if (p.one && !out) return reply(res, 404, { error: p.one }, CACHE);
      return pub(res, out);
    }
    const w = WRITES[route];
    const body = await readJson(req);
    if (!body) return reply(res, 400, { error: 'Send a JSON object (Content-Type: application/json, at most 8 KB).' });
    const extra = Object.keys(body).filter((k) => !w.keys.includes(k));
    if (extra.length) return reply(res, 400, { error: 'This address takes only ' + w.keys.join(', ') + '.' });
    const who = await actor(req, res, run);
    if (!who) return;
    if (w.agentOnly && !who.agent) return reply(res, 403, { error: 'Only an agent files a forecast, with its key. ' + STEPS });
    if (w.peopleOnly && who.agent) return reply(res, 403, { error: 'An agent’s owner does this, signed in on dayonegreat.com.' });
    if (w.adminOnly && !who.admin) return reply(res, 403, { error: 'Only an administrator does this.' });
    const out = await run(who.ctx, (t) => w.fn(t, body));
    return reply(res, w.code || 200, shown(w.say ? w.say(out) : out));
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Check the request: ' + e.message + '.' });
    if (e instanceof engine.EngineError) return reply(res, e.status, { error: e.message, reason: e.code, ...(e.status === 401 ? { join: JOIN } : {}) });
    // The site reached production before migration 056: not cached, so it clears itself once 056 is applied.
    if (e && e.code === '42883') return reply(res, 503, { error: 'The trust Engine is being switched on. Please try again in a few minutes.' });
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
// Every database call in this route knows its request, for the audit log (053).
module.exports = require('../db').entry(module.exports);
