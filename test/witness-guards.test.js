// RK149: the public log's witness never forgets what it kept. Two halves, no database and no network:
//   * the workflow's own shell steps (read from .github/workflows/log-witness.yml and run as written, against local git
//     repositories standing in for GitHub): a fresh branch only when the branch doesn't exist; any other failure to
//     read it fails the job; the record job fails if the branch moved after the check read it;
//   * tools/verify/witness.mjs record(): it refuses a state that drops or changes a standing alarm, lowers the last good
//     checkpoint, changes the pinned key or doesn't raise the run count.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');
const { pathToFileURL } = require('node:url');

const root = path.join(__dirname, '..');
const WORKFLOW = fs.readFileSync(path.join(root, '.github/workflows/log-witness.yml'), 'utf8');

// The `run: |` block of the step whose name starts with `name`, dedented, exactly as GitHub would run it.
function stepScript(name) {
  const lines = WORKFLOW.split('\n');
  const at = lines.findIndex((l) => l.trim().startsWith('- name: ' + name));
  assert.ok(at >= 0, 'the workflow has a step named ' + name);
  const r = lines.findIndex((l, i) => i > at && /^\s+run: \|\s*$/.test(l));
  const indent = lines[r].match(/^\s*/)[0].length;
  const body = [];
  for (let i = r + 1; i < lines.length; i++) {
    if (lines[i].trim() && lines[i].match(/^\s*/)[0].length <= indent) break;
    body.push(lines[i]);
  }
  const pad = Math.min(...body.filter((l) => l.trim()).map((l) => l.match(/^\s*/)[0].length));
  return body.map((l) => l.slice(pad)).join('\n') + '\n';
}

// A stand-in for GitHub: a bare repository that https://github.com/test/witness.git is rewritten to, through a global
// git config that only these runs see.
function fakeGitHub({ branch = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'witness-guards-'));
  const origin = path.join(dir, 'origin.git');
  const git = (cwd, ...a) => execFileSync('git', a, { cwd, env: gitEnv(dir), encoding: 'utf8' }).trim();
  git(dir, 'init', '-q', '--bare', origin);
  const seed = path.join(dir, 'seed');
  fs.mkdirSync(seed);
  git(seed, 'init', '-q');
  const commit = (msg) => {
    fs.writeFileSync(path.join(seed, 'state.json'), JSON.stringify({ v: 1, msg }) + '\n');
    git(seed, 'add', 'state.json');
    git(seed, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-m', msg);
    git(seed, 'push', '-q', 'file://' + origin, 'HEAD:refs/heads/log-witness');
    return git(seed, 'rev-parse', 'HEAD');
  };
  const sha = branch ? commit('first') : null;
  return { dir, origin, sha, commit };
}

function gitEnv(dir, reachable = true) {
  const cfg = path.join(dir, 'gitconfig');
  const target = reachable ? 'file://' + path.join(dir, 'origin.git') : 'file://' + path.join(dir, 'no-such-repository.git');
  fs.writeFileSync(cfg, '[url "' + target + '"]\n\tinsteadOf = https://github.com/test/witness.git\n[init]\n\tdefaultBranch = main\n');
  return { PATH: process.env.PATH, HOME: dir, GIT_CONFIG_GLOBAL: cfg, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };
}

// Runs a step's script in a fresh folder, as a runner would. Returns its exit code, its outputs and the folder.
function runStep(gh, name, { reachable = true, env = {} } = {}) {
  const work = fs.mkdtempSync(path.join(gh.dir, 'run-'));
  const out = path.join(work, 'github-output');
  fs.writeFileSync(out, '');
  const r = spawnSync('bash', ['-e', '-c', stepScript(name)], {
    cwd: work, encoding: 'utf8',
    env: { ...gitEnv(gh.dir, reachable), GITHUB_REPOSITORY: 'test/witness', GITHUB_OUTPUT: out, ...env },
  });
  const outputs = Object.fromEntries(fs.readFileSync(out, 'utf8').split('\n').filter(Boolean).map((l) => l.split(/=(.*)/s).slice(0, 2)));
  return { code: r.status, stderr: r.stderr + r.stdout, outputs, witness: path.join(work, 'witness') };
}

const CHECK = 'Read the witness branch';
const RECORD = 'Check out the witness branch';

test('RK149, check job: an existing branch is read and its commit passed on; a missing one starts fresh', () => {
  const gh = fakeGitHub();
  let r = runStep(gh, CHECK);
  assert.strictEqual(r.code, 0, r.stderr);
  assert.strictEqual(r.outputs.base, gh.sha, 'the check passes on the commit it built on');
  assert.match(fs.readFileSync(path.join(r.witness, 'state.json'), 'utf8'), /"first"/);
  r = runStep(fakeGitHub({ branch: false }), CHECK);
  assert.strictEqual(r.code, 0, r.stderr);
  assert.strictEqual(r.outputs.base, 'none', 'a branch that really doesn’t exist starts fresh');
});

test('RK149, check job: a branch that can’t be read fails the job, and never starts a fresh one', () => {
  const r = runStep(fakeGitHub(), CHECK, { reachable: false });
  assert.notStrictEqual(r.code, 0, 'a failed read is a red run, not an empty state');
  assert.ok(!('base' in r.outputs), 'no base is passed on');
  assert.match(r.stderr, /won’t start a fresh one|won't start a fresh one/);
});

test('RK149, record job: it records only on the commit the check built on', () => {
  const gh = fakeGitHub();
  const tok = { GITHUB_TOKEN: 'not-a-token' };
  let r = runStep(gh, RECORD, { env: { ...tok, WITNESS_BASE: gh.sha } });
  assert.strictEqual(r.code, 0, 'the branch as the check saw it: ' + r.stderr);
  // The branch moves between the check and the record (another run, or a person's commit): this run records nothing.
  gh.commit('a commit after the check');
  r = runStep(gh, RECORD, { env: { ...tok, WITNESS_BASE: gh.sha } });
  assert.notStrictEqual(r.code, 0, 'the branch moved since the check');
  assert.match(r.stderr, /moved after the check/);
  // The check saw no branch, and now there is one.
  r = runStep(gh, RECORD, { env: { ...tok, WITNESS_BASE: 'none' } });
  assert.notStrictEqual(r.code, 0, 'a branch made since the check');
  // The branch can't be read.
  r = runStep(gh, RECORD, { reachable: false, env: { ...tok, WITNESS_BASE: gh.sha } });
  assert.notStrictEqual(r.code, 0, 'a failed read fails the record job too');
  // The check saw a branch that is gone now: no fresh start.
  const empty = fakeGitHub({ branch: false });
  r = runStep(empty, RECORD, { env: { ...tok, WITNESS_BASE: gh.sha } });
  assert.notStrictEqual(r.code, 0, 'a branch deleted since the check');
  // A first run, honestly: no branch for the check, none for the record.
  r = runStep(empty, RECORD, { env: { ...tok, WITNESS_BASE: 'none' } });
  assert.strictEqual(r.code, 0, r.stderr);
});

test('RK149, the workflow: no text from the event, and no ${{ }} at all, inside a shell step; every action pinned', () => {
  // Every run step, one-line or a block (a block is every deeper-indented line after `run: |`).
  const lines = WORKFLOW.split('\n');
  const runs = [];
  lines.forEach((l, i) => {
    const m = /^(\s+)run: (.*)$/.exec(l);
    if (!m) return;
    if (m[2].trim() !== '|') { runs.push(m[2]); return; }
    const block = [];
    for (let j = i + 1; j < lines.length && (!lines[j].trim() || lines[j].match(/^\s*/)[0].length > m[1].length); j++) block.push(lines[j]);
    runs.push(block.join('\n'));
  });
  assert.strictEqual(runs.length, 6, 'found the six run steps (the sixth, the report job\'s, since 057)');
  for (const r of runs) assert.ok(!r.includes('${{'), 'a run step interpolates an expression: ' + r.slice(0, 80));
  for (const m of WORKFLOW.matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, 'pinned: ' + m[1]);
  assert.match(WORKFLOW, /WITNESS_BASE: \$\{\{ needs\.check\.outputs\.base \}\}/, 'the check’s commit reaches the record job through env');
});

// record(): the branch's state.json against the check's.
const KEY = 'dayonegreat.com/log+54880135+AYTmrGBbZMMDtCc57uZ/T40AM/Aklvh4+owep85+eWl8';
const OTHER_KEY = 'dayonegreat.com/log+0a0b0c0d+' + Buffer.concat([Buffer.from([1]), Buffer.alloc(32, 7)]).toString('base64');
const ROOT_A = Buffer.alloc(32, 1).toString('base64');
const ROOT_B = Buffer.alloc(32, 2).toString('base64');
const ALARM = { reason: 'Split view: two different signed checkpoints of 9 entries.', at: '2026-11-10T10:00:00.000Z', seen: 'the forged note' };
const branchState = (over = {}) => ({ v: 1, log: 'dayonegreat.com/log', runs: 40, last_run: '2026-11-10T10:00:00.000Z', key: KEY, good: { size: 453, root: ROOT_A, seen_at: '2026-11-10T10:00:00.000Z' }, ...over });
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
let WIT;
async function recordInto(current, next) {
  WIT = WIT || (await import(pathToFileURL(path.join(root, 'tools/verify/witness.mjs')).href));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'witness-record-'));
  if (current !== undefined) fs.writeFileSync(path.join(dir, 'state.json'), typeof current === 'string' ? current : JSON.stringify(current, null, 1) + '\n');
  const before = fs.existsSync(path.join(dir, 'state.json')) ? fs.readFileSync(path.join(dir, 'state.json'), 'utf8') : null;
  let error = null;
  try { WIT.record(dir, b64(next), ''); } catch (e) { error = e; }
  const after = fs.existsSync(path.join(dir, 'state.json')) ? fs.readFileSync(path.join(dir, 'state.json'), 'utf8') : null;
  return { error, kept: before === after, after };
}

test('RK149, record(): an ordinary next state is written', async () => {
  const r = await recordInto(branchState(), branchState({ runs: 41, last_run: '2026-11-10T11:00:00.000Z', good: { size: 460, root: ROOT_B, seen_at: '2026-11-10T11:00:00.000Z' } }));
  assert.strictEqual(r.error, null, String(r.error));
  assert.match(r.after, /"runs": 41/);
  // The first run on a new branch: nothing to keep.
  assert.strictEqual((await recordInto(undefined, branchState({ runs: 1 }))).error, null);
  // An alarm kept as it was, and a new alarm added, are both fine.
  assert.strictEqual((await recordInto(branchState({ alarm: ALARM }), branchState({ runs: 41, alarm: ALARM }))).error, null);
  assert.strictEqual((await recordInto(branchState(), branchState({ runs: 41, alarm: ALARM }))).error, null);
});

test('RK149, record(): refuses a state that drops or changes a standing alarm', async () => {
  let r = await recordInto(branchState({ alarm: ALARM }), branchState({ runs: 41 }));
  assert.match(String(r.error), /refused: .*standing alarm/);
  assert.ok(r.kept, 'the branch keeps its alarm');
  r = await recordInto(branchState({ alarm: ALARM }), branchState({ runs: 41, alarm: { ...ALARM, reason: 'something milder' } }));
  assert.match(String(r.error), /standing alarm/);
});

test('RK149, record(): refuses a smaller last good checkpoint, or another root for the same size', async () => {
  let r = await recordInto(branchState(), branchState({ runs: 41, good: { size: 12, root: ROOT_A, seen_at: 'x' } }));
  assert.match(String(r.error), /smaller last good checkpoint than the branch’s 453/);
  assert.ok(r.kept);
  r = await recordInto(branchState(), branchState({ runs: 41, good: undefined }));
  assert.match(String(r.error), /smaller last good checkpoint/, 'no good checkpoint at all is smaller');
  r = await recordInto(branchState(), branchState({ runs: 41, good: { size: 453, root: ROOT_B, seen_at: 'x' } }));
  assert.match(String(r.error), /another root/);
});

test('RK149, record(): refuses another pinned key', async () => {
  let r = await recordInto(branchState(), branchState({ runs: 41, key: OTHER_KEY }));
  assert.match(String(r.error), /another pinned key/);
  assert.ok(r.kept);
  r = await recordInto(branchState(), branchState({ runs: 41, key: undefined }));
  assert.match(String(r.error), /another pinned key/, 'dropping the key is changing it');
});

test('RK149, record(): refuses a run count that isn’t higher than the branch’s (the reset’s mark)', async () => {
  let r = await recordInto(branchState(), branchState({ runs: 1, key: KEY }));
  assert.match(String(r.error), /run 1 times, not more than the branch’s 40/);
  assert.ok(r.kept);
  r = await recordInto(branchState(), branchState({ runs: 40 }));
  assert.match(String(r.error), /not more than/);
});

test('RK149, record(): a branch state.json that can’t be read is not treated as empty', async () => {
  const r = await recordInto('{ not json', branchState({ runs: 1 }));
  assert.match(String(r.error), /can’t be read/);
  assert.ok(r.kept, 'the branch is left for a person to repair');
});

test('RK149, the reset end to end: one failed read in the check gives a fresh state, and record() refuses it', async () => {
  WIT = WIT || (await import(pathToFileURL(path.join(root, 'tools/verify/witness.mjs')).href));
  // The check, starting from an empty folder (what the old workflow did on any failed fetch), with the site down.
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'witness-reset-'));
  const out = await WIT.witness({ dir: empty, pinned: KEY, site: '', fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }) });
  assert.strictEqual(out.state.runs, 1);
  // The record job, on the real branch with its alarm.
  const r = await recordInto(branchState({ alarm: ALARM }), out.state);
  assert.match(String(r.error), /refused/);
  assert.ok(r.kept, 'the alarm, the good checkpoint, the key and the count all stay');
});
