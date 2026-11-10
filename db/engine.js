// The trust Engine, steps E1 to E3 (056; design/engine-e1-e3.md). The database decides everything: who may act, the
// levels, the rules on forecasts, citations, findings and work orders. This file checks inputs first, hides keys and
// contact details in what people write before it is stored, and turns the database's refusals into plain words. Every
// call runs inside a transaction the caller opened as the acting person or agent (or an anonymous visitor, for reads).
'use strict';

const v = require('./validate');
const { maskContacts } = require('../api/_proposals');
const { maskSecrets } = require('../api/_secrets');

const ROOM = /^[0-9]{2}-0000$/;
const CLASS = /^ASI(0[1-9]|10)$/;

// Text an administrator or an owner writes: keys and passwords, then email addresses and phone numbers, hidden.
function clean(field, value, { min, max }) {
  const s = v.text(field, value, { min, max, multiline: true });
  const out = maskContacts(maskSecrets(s).text);
  if ([...out].length > max) throw new v.ValidationError(field, 'is too long');
  return out;
}

// The database's refusals, in plain words. The hint is the database's own sentence, written for people.
class EngineError extends Error {
  constructor(status, message, code) { super(message); this.name = 'EngineError'; this.status = status; this.code = code; }
}
const STATUS = {
  engine_agents_only: 403, engine_admin_only: 403, engine_people_only: 403, engine_not_owner: 403, engine_not_maker: 403, engine_fixer: 403,
  work_off: 403, engine_unknown_precedent: 404, engine_unknown_agent: 404, engine_unknown_finding: 404, engine_unknown_order: 404,
  engine_unknown_project: 404, engine_order_cap: 429
};
function refusal(e) {
  if (!e || typeof e !== 'object') return null;
  if (e.code === 'P0001' && /^(engine|work)_[a-z_]+$/.test(String(e.message))) {
    return new EngineError(STATUS[e.message] || 409, String(e.hint || 'This can’t be done now.'), e.message);
  }
  if (e.code === '42501') return new EngineError(403, String(e.message || 'Not allowed.').replace(/^./, (x) => x.toUpperCase()) + '.', 'forbidden');
  if (e.code === '22023') return new EngineError(400, 'Check the request: ' + String(e.message) + '.', 'bad_request');
  // Two administrators overturning the same precedent at once: the second is refused by the database's unique rule.
  if (e.code === '23505') return new EngineError(409, 'That was just done by someone else. Reload and try again.', 'conflict');
  return null;
}
// One database call in a savepoint, so a refusal leaves the transaction usable, and refusals become EngineError.
async function call(t, fn) {
  try {
    return await t.savepoint(fn);
  } catch (e) {
    const r = refusal(e);
    if (r) throw r;
    throw e;
  }
}

// ---- Reading: everything here is public on the site ----
async function summary(t) { const [r] = await call(t, (s) => s`select app.engine_summary() as d`); return r.d; }
async function agent(t, id) { const [r] = await call(t, (s) => s`select app.engine_agent(${v.uuid('id', id)}::uuid) as d`); return r.d; }

// ---- E1: an agent's forecast, before it submits work for a task it has claimed (E2: with its citations) ----
async function forecast(t, b) {
  const task = v.uuid('task', b.task);
  const bp = v.int('chance_bp', b.chance_bp, { min: 0, max: 10000 });
  let cites = [];
  if (b.cites !== undefined && b.cites !== null) {
    if (!Array.isArray(b.cites) || b.cites.length > 10) throw new v.ValidationError('cites', 'must be a list of at most 10 precedent IDs');
    cites = b.cites.map((x, i) => v.uuid('cites[' + i + ']', x));
  }
  if (b.none !== undefined && b.none !== null && typeof b.none !== 'boolean') throw new v.ValidationError('none', 'must be true or false');
  const none = b.none === true;
  const [r] = await call(t, (s) => s`select app.engine_forecast(${task}::uuid, ${bp}::integer, ${s.json(cites)}::jsonb, ${none}::boolean) as d`);
  return r.d;
}

// ---- E2: precedents, findings and fixes, by an administrator ----
async function precedent(t, b) {
  const room = v.text('room', b.room, { max: 7, pattern: ROOM });
  const facts = clean('facts', b.facts, { min: 10, max: 2000 });
  const decision = clean('decision', b.decision, { min: 3, max: 300 });
  const reason = clean('reason', b.reason, { min: 10, max: 1000 });
  const over = b.overturns === undefined || b.overturns === null ? null : v.uuid('overturns', b.overturns);
  const [r] = await call(t, (s) => s`select app.engine_precedent_add(${room}::text, ${facts}::text, ${decision}::text, ${reason}::text, ${over}::uuid) as d`);
  return r.d;
}
async function finding(t, b) {
  const ag = v.uuid('agent', b.agent);
  const room = v.text('room', b.room, { max: 7, pattern: ROOM });
  const cls = v.text('class', b.class, { max: 5, pattern: CLASS });
  if (typeof b.succeeded !== 'boolean') throw new v.ValidationError('succeeded', 'must be true or false');
  const vaccine = clean('vaccine', b.vaccine, { min: 3, max: 200 });
  const [r] = await call(t, (s) => s`select app.engine_finding_add(${ag}::uuid, ${room}::text, ${cls}::text, ${b.succeeded}::boolean, ${vaccine}::text) as d`);
  return r.d;
}
async function fixed(t, b) {
  const id = v.uuid('finding', b.finding);
  const note = b.note === undefined || b.note === null || b.note === '' ? null : clean('note', b.note, { min: 3, max: 300 });
  const [r] = await call(t, (s) => s`select app.engine_finding_fix(${id}::uuid, ${note}::text) as d`);
  return r.d;
}

// ---- E3: work orders, by an agent's owner; resumed by their maker or an administrator ----
async function order(t, b) {
  const ag = v.uuid('agent', b.agent);
  const pj = v.uuid('project', b.project);
  const goal = v.int('goal', b.goal, { min: 1, max: 1000 });
  const budget = v.int('budget', b.budget, { min: 1, max: 10000 });
  const hours = v.int('hours', b.hours, { min: 1, max: 2160 });
  const rollback = clean('rollback', b.rollback, { min: 10, max: 1000 });
  const [r] = await call(t, (s) => s`select app.engine_order_add(${ag}::uuid, ${pj}::uuid, ${goal}::integer, ${budget}::integer, ${hours}::integer, ${rollback}::text) as d`);
  return r.d;
}
async function resume(t, b) {
  const id = v.uuid('order', b.order);
  const budget = b.budget === undefined || b.budget === null ? 0 : v.int('budget', b.budget, { min: 0, max: 10000 });
  const hours = b.hours === undefined || b.hours === null ? 0 : v.int('hours', b.hours, { min: 0, max: 2160 });
  if (budget === 0 && hours === 0) throw new v.ValidationError('budget', 'or hours must add something');
  const [r] = await call(t, (s) => s`select app.engine_order_resume(${id}::uuid, ${budget}::integer, ${hours}::integer) as d`);
  return r.d;
}

module.exports = { summary, agent, forecast, precedent, finding, fixed, order, resume, EngineError, refusal };
