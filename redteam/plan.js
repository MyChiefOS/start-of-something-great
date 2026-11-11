// Runs an attack plan against the red-team copy (redteam/copy.js) and reports every step. A plan is JSON data:
//   { "steps": [ { "name": "...", "as": "anon" | "memberA" | "memberB" | "admin", "method": "GET" | "POST",
//                  "path": "/api/...", "body": {...}, "headers": {"name": "value" | null},
//                  "expect": { "status": 403 | [401, 403], "not": [200, 201], "tool_error": true } } ] }
// "tool_error": true is for a call to an MCP tool (/api/mcp): the tool must have refused (result.isError), since a
// refused tool call still answers 200.
// A step may instead say "each": "write-routes" or "each": "read-routes" to be repeated for every such address the API
// has (read from the handlers themselves, so a new route is attacked the day it is added), with "params" for reads.
// "except" names addresses an "each" step leaves out, each with its reason, so every exception is written down.
// Two rules hold for every step whatever the plan says: an answer of 500 (the handler mishandled it, OWASP A10) and
// a handler that throws are failures, and an unknown account or address is a failure of the plan itself.
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const ACCOUNTS = ['anon', 'memberA', 'memberB', 'admin'];
const MAX_STEPS = 500;

// The API's own route tables: agents and notify export theirs; work's are read from its source (top-level keys).
function routes() {
  const out = { write: [], read: [] };
  const add = (method, p) => out[method === 'GET' ? 'read' : 'write'].push(p);
  for (const mod of ['agents', 'notify']) {
    for (const k of Object.keys(require('../api/' + mod + '.js').ROUTES)) {
      const [method, route] = k.split(' ');
      if (mod === 'notify' && route === 'sns') continue; // Amazon's bounce notices, signed by Amazon: not a member route
      add(method, '/api/' + mod + (route ? '/' + route : ''));
    }
  }
  const src = fs.readFileSync(path.join(ROOT, 'api', 'work.js'), 'utf8');
  const keys = (name) => {
    const i = src.indexOf('const ' + name + ' = {');
    if (i < 0) return [];
    const block = src.slice(i, src.indexOf('\n};', i));
    return [...new Set([...block.matchAll(/^ {2}'?([a-z][a-z0-9/_-]*)'?\s*:/gm)].map((m) => m[1]))];
  };
  for (const r of keys('PUBLIC')) add('GET', '/api/work/' + r);
  for (const r of ['mine', 'admin', 'network', 'console']) add('GET', '/api/work/' + r);
  for (const r of keys('WRITES')) add('POST', '/api/work/' + r);
  add('GET', '/api/feed'); add('POST', '/api/feed');
  add('GET', '/api/decisions'); add('GET', '/api/directory');
  out.write = [...new Set(out.write)].sort();
  out.read = [...new Set(out.read)].sort();
  return out;
}

function expand(plan) {
  if (!plan || !Array.isArray(plan.steps)) throw new Error('a plan is {"steps": [...]}');
  const r = routes();
  const steps = [];
  for (const s of plan.steps) {
    if (!s || typeof s !== 'object') throw new Error('every step is an object');
    const skip = (p) => Boolean(s.except && Object.prototype.hasOwnProperty.call(s.except, p));
    if (s.each === 'write-routes') {
      for (const p of r.write) if (!skip(p)) steps.push({ ...s, each: undefined, except: undefined, method: 'POST', path: p, name: s.name + ': POST ' + p });
    }
    else if (s.each === 'read-routes') {
      for (const p of r.read) {
        if (skip(p)) continue;
        for (const params of (s.params && s.params.length ? s.params : [{}])) {
          const q = new URLSearchParams(params).toString();
          steps.push({ ...s, each: undefined, params: undefined, method: 'GET', path: p + (q ? '?' + q : ''), name: s.name + ': GET ' + p + (q ? ' ' + Object.keys(params).join(',') : '') });
        }
      }
    } else if (s.each) throw new Error('unknown "each": ' + s.each);
    else steps.push(s);
  }
  if (steps.length > MAX_STEPS) throw new Error('a plan may have at most ' + MAX_STEPS + ' steps after expanding (it has ' + steps.length + ')');
  for (const s of steps) {
    if (s.as && !ACCOUNTS.includes(s.as)) throw new Error('unknown account "' + s.as + '" (use ' + ACCOUNTS.join(', ') + ')');
    if (typeof s.path !== 'string' || !s.path.startsWith('/api/')) throw new Error('every step needs a path under /api/');
    if (s.method && !['GET', 'POST'].includes(String(s.method).toUpperCase())) throw new Error('method is GET or POST');
  }
  return steps;
}

function judge(step, got) {
  const why = [];
  if (got.status === 0) why.push(got.error);
  if (got.status === 500) why.push('answered 500' + (got.error ? ' (' + got.error + ')' : '') + ': the handler mishandled it');
  const e = step.expect || {};
  const list = (v) => (v === undefined ? null : Array.isArray(v) ? v : [v]);
  const want = list(e.status);
  if (want && !want.includes(got.status)) why.push('answered ' + got.status + ', expected ' + want.join(' or '));
  const not = list(e.not);
  if (not && not.includes(got.status)) why.push('answered ' + got.status + ', which it must not');
  if (e.range === '4xx' && !(got.status >= 400 && got.status < 500)) why.push('answered ' + got.status + ', expected a refusal (4xx)');
  if (e.tool_error === true && !(got.json && got.json.result && got.json.result.isError === true)) why.push('the tool did not refuse (expected result.isError)');
  return why;
}

async function runPlan(copy, plan) {
  const steps = expand(plan);
  const results = [];
  for (const s of steps) {
    const got = await copy.call(s);
    const why = judge(s, got);
    results.push({ name: s.name || (s.method + ' ' + s.path), as: s.as || 'anon', status: got.status, ok: why.length === 0, why: why.join('; ') });
  }
  return results;
}

function report(results) {
  const failed = results.filter((r) => !r.ok);
  const esc = (t) => String(t).replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').slice(0, 300);
  const lines = ['**Red-team copy:** ' + results.length + ' steps, ' + (results.length - failed.length) + ' as expected, ' + failed.length + ' not.', ''];
  if (failed.length) {
    lines.push('| Step | As | Answer | Why |', '|---|---|---|---|');
    for (const r of failed) lines.push('| ' + esc(r.name) + ' | ' + r.as + ' | ' + r.status + ' | ' + esc(r.why) + ' |');
  }
  return lines.join('\n');
}

module.exports = { routes, expand, judge, runPlan, report, ACCOUNTS, MAX_STEPS };
