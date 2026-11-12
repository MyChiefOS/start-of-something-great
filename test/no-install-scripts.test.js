// Scripts that a workflow runs without installing packages must load without them. The uptime check broke on Nov 10
// (PR #126): scripts/uptime.js loads launch.js, which began loading db/index.js, which needs the database library, and
// uptime.yml never runs "npm ci". No test ran a script the way such a workflow does, so nothing caught it.
//
// For every workflow job with no "npm ci" or "npm install", each "node <script>" it runs is found, and every file that
// script loads by a relative path is loaded here in a fresh process where no installed package can be found (only
// Node's own modules and the repository's files). The scripts themselves aren't run: they call the network.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const WORKFLOWS = path.join(ROOT, '.github', 'workflows');

// Each job's text, split on the two-space-indented job names under "jobs:".
function jobs(text) {
  const at = text.search(/^jobs:\s*$/m);
  if (at < 0) return [];
  return text.slice(at).split(/^ {2}(?=[A-Za-z0-9_-]+:\s*$)/m).slice(1);
}

function noInstallScripts() {
  const found = new Map(); // script -> the workflows that run it
  for (const f of fs.readdirSync(WORKFLOWS).filter((n) => /\.ya?ml$/.test(n)).sort()) {
    for (const job of jobs(fs.readFileSync(path.join(WORKFLOWS, f), 'utf8'))) {
      if (/\bnpm (ci|install)\b/.test(job)) continue;
      for (const m of job.matchAll(/\bnode\s+((?:\.\/)?[A-Za-z0-9_./-]+\.(?:js|mjs|cjs))\b/g)) {
        const script = path.normalize(m[1]);
        if (!fs.existsSync(path.join(ROOT, script))) continue;
        found.set(script, [...(found.get(script) || []), f]);
      }
    }
  }
  return found;
}

// The files a script loads by a relative path, at any depth of its own text.
function relativeLoads(script) {
  const text = fs.readFileSync(path.join(ROOT, script), 'utf8');
  const out = new Set();
  for (const m of text.matchAll(/\brequire\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g)) out.add(path.join(path.dirname(script), m[1]));
  return [...out];
}

// A fresh process in which a bare name that isn't one of Node's own modules can't be found, as on a runner that never
// ran "npm ci".
const PRELOAD = `
const Module = require('module');
const real = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  const bare = !request.startsWith('.') && !request.startsWith('/') && !request.startsWith('node:');
  if (bare && !Module.builtinModules.includes(request)) {
    const e = new Error("Cannot find module '" + request + "'");
    e.code = 'MODULE_NOT_FOUND';
    throw e;
  }
  return real.call(this, request, ...rest);
};
`;

function loadWithoutPackages(file) {
  const code = PRELOAD + 'require(' + JSON.stringify(path.join(ROOT, file)) + ');';
  return spawnSync(process.execPath, ['-e', code], { cwd: ROOT, encoding: 'utf8', env: { PATH: process.env.PATH }, timeout: 20000 });
}

test('workflows that install nothing run at least the uptime check', () => {
  const found = noInstallScripts();
  assert.ok(found.has(path.normalize('scripts/uptime.js')), 'scripts/uptime.js is run by a job that installs nothing');
});

test('every file a no-install workflow script loads can load without installed packages', () => {
  const failures = [];
  for (const [script, flows] of noInstallScripts()) {
    for (const file of relativeLoads(script)) {
      const r = loadWithoutPackages(file);
      if (r.status !== 0) failures.push(script + ' (' + [...new Set(flows)].join(', ') + ') loads ' + file + ': ' + String(r.stderr || r.error).split('\n').find((l) => /Error/.test(l)));
    }
  }
  assert.deepStrictEqual(failures, []);
});

test('the check itself notices a missing package', () => {
  const r = spawnSync(process.execPath, ['-e', PRELOAD + "require('postgres');"], { cwd: ROOT, encoding: 'utf8', timeout: 20000 });
  assert.notStrictEqual(r.status, 0);
  assert.match(r.stderr, /Cannot find module 'postgres'/);
});
