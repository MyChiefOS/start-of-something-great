#!/usr/bin/env node
// The public log's witness (038; CODING_AGENT_SPEC.md 1.3; Aaron, Nov 5: "Phase 2 we can use GItHUB for now"). Run by
// .github/workflows/log-witness.yml every 15 minutes, in two jobs (the independent review of Nov 5, M4):
//   node tools/verify/witness.mjs <branch folder> [--site https://dayonegreat.com]     check (read-only, no token)
//   node tools/verify/witness.mjs --record <branch folder>                              record (writes the branch)
// The check reads the latest signed checkpoint from the site, and:
//   * checks it is signed by the log's key: the one pinned in this repository (verifier/log-key.js), or, until that is
//     set, the one it pinned on its first run (only if entry 0 of the log states the same key);
//   * checks it is consistent with the last good checkpoint it kept: never smaller, never another root for the same
//     size, and a valid consistency proof (RFC 9162) from the old tree to the new one (the split-view check);
//   * re-hashes the entries themselves (the monitor): every entry's canonical JSON must hash to its leaf, and the
//     leaves must rebuild the signed root. Up to 20,000 entries a run; past that it continues next run from where it
//     stopped, and proves the part it has re-hashed is the start of the signed tree;
//   * checks every proposal decision the log records against GitHub's own record of the issue's labels (M3);
//   * writes checkpoint (the last good one, as signed) and state.json, which the site and the Verify page read.
// Only a contradiction is an alarm (H2): another key, a smaller tree, another root for the same size, a consistency
// proof that fails, an entry that doesn't hash to its leaf, entries that don't rebuild the signed root, a proposal
// decision GitHub has no record of. state.json keeps an alarm (with the checkpoint it saw); the last good checkpoint
// stays as it was; the record job opens one issue labelled log-witness. A site or GitHub that doesn't answer, answers
// with an error or with something that isn't JSON or a checkpoint is never an alarm: it is recorded as last_error and
// tried again next run. The site keeps running either way.
// What the job can't do (RK149): record() refuses a state.json that drops or changes the branch's alarm, lowers its
// last good checkpoint, changes its pinned key or doesn't raise its run count, and the workflow starts a fresh branch
// only when GitHub says the branch doesn't exist, and fails if the branch moved between the check and the record. So
// the job never removes an alarm or forgets what it kept. A person with write access to the repository can still do
// either with an ordinary commit to the branch: the log-witness ruleset stops deleting the branch or rewriting its
// history, not adding to it, so that commit stays in the branch's public history. The repository's owner could switch
// the ruleset off. Each failure is a red run that alerts and blocks nothing.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import * as L from '../../verifier/lib.js';
import { PINNED_VKEY } from '../../verifier/log-key.js';

const CAP = 20000;
const PAGE = 100;
const GH_API = 'https://api.github.com/repos/' + L.REPO;

export async function witness({ dir, site = L.SITE, fetchImpl = globalThis.fetch, now = () => new Date(), cap = CAP, pinned = PINNED_VKEY } = {}) {
  const file = (f) => path.join(dir, f);
  let state;
  try { state = fs.existsSync(file('state.json')) ? JSON.parse(fs.readFileSync(file('state.json'), 'utf8')) : null; } catch { state = null; }
  if (!state || typeof state !== 'object') state = { v: 1, log: L.ORIGIN, runs: 0 };
  state.runs = (Number(state.runs) || 0) + 1;
  state.last_run = now().toISOString();
  const result = { alarm: null, wrote: false, size: null };
  // Every network or parse failure is "not checked", never an alarm.
  const notChecked = (msg) => Object.assign(new Error(msg), { notChecked: true });
  const get = async (u) => {
    let r;
    try { r = await fetchImpl(u, { headers: { Accept: 'application/json', 'User-Agent': 'dayonegreat-log-witness' } }); }
    catch (e) { throw notChecked(u.replace(site, '').split('?')[0] + ' didn’t answer (' + String(e && e.message || e).slice(0, 80) + ')'); }
    if (!r.ok) throw notChecked(u.replace(site, '').split('?')[0] + ' answered ' + r.status);
    try { return await r.json(); } catch { throw notChecked(u.replace(site, '').split('?')[0] + ' didn’t answer with JSON'); }
  };
  const alarm = (reason, seen) => {
    result.alarm = reason;
    if (!state.alarm) state.alarm = { reason, at: state.last_run, seen: seen || null };
    return save();
  };

  try {
    const cp = await get(site + '/api/log/checkpoint');
    if (!cp || !cp.checkpoint || typeof cp.checkpoint.note !== 'string') throw notChecked('no checkpoint signed yet');
    let note;
    try { note = L.parseCheckpoint(cp.checkpoint.note); } catch (e) { throw notChecked('the checkpoint isn’t in the signed-note form (' + e.message + ')'); }
    if (note.origin !== L.ORIGIN) throw notChecked('the checkpoint is for "' + String(note.origin).slice(0, 60) + '", not ' + L.ORIGIN);
    // The key: the repository's pin, or the one pinned on the first run if entry 0 of the log states it.
    if (pinned) {
      if (state.key && state.key !== pinned) return alarm('The key this branch pinned (' + state.key + ') isn’t the key pinned in the repository (' + pinned + ').', cp.checkpoint.note);
      if (!state.key) { state.key = pinned; state.key_pinned_at = state.last_run; state.key_from = 'verifier/log-key.js'; }
    } else if (!state.key) {
      let k;
      try { k = L.parseVkey(cp.log_key && cp.log_key.vkey); } catch (e) { throw notChecked('the site’s key isn’t a verifier key'); }
      const e0 = await get(site + '/api/log/entry/0');
      if (!e0 || !e0.entry || e0.entry.type !== 'key.registered' || !e0.entry.payload || e0.entry.payload.public_key !== L.b64(k.pub)) {
        return alarm('Entry 0 of the log doesn’t register the key the log signs with.', cp.checkpoint.note);
      }
      if (L.b64(await L.leafHash(L.utf8(L.jcs(e0.entry)))) !== e0.leaf_hash) return alarm('Entry 0 doesn’t hash to its leaf.', cp.checkpoint.note);
      state.key = await L.vkey(k.name, k.pub);
      state.key_pinned_at = state.last_run;
      state.key_from = 'first run (entry 0)';
    }
    const k = L.parseVkey(state.key);
    if (!(await L.checkpointSigned(note, k.name, k.pub))) {
      return alarm('The checkpoint of ' + note.size + ' entries isn’t signed by the log’s key (' + state.key + ', pinned ' + state.key_pinned_at + ').', cp.checkpoint.note);
    }
    result.size = note.size;

    // Consistency with the last good checkpoint.
    const good = state.good;
    if (good) {
      const old = L.unb64(good.root);
      if (note.size < good.size) return alarm('The log now shows ' + note.size + ' entries, fewer than the ' + good.size + ' it signed before.', cp.checkpoint.note);
      if (note.size === good.size && !L.equal(old, note.root)) return alarm('Split view: two different signed checkpoints of ' + note.size + ' entries.', cp.checkpoint.note);
      if (note.size > good.size) {
        const p = await get(site + '/api/log/proof/consistency?from=' + good.size + '&to=' + note.size);
        let path2;
        try { path2 = (p.proof || []).map(L.unb64); } catch { throw notChecked('the consistency proof isn’t base64'); }
        if (!(await L.verifyConsistency(good.size, note.size, old, note.root, path2))) {
          return alarm('The checkpoint of ' + note.size + ' entries isn’t consistent with the one of ' + good.size + ' kept before: the log may have rewritten its history.', cp.checkpoint.note);
        }
      }
    }

    // The monitor: re-hash the entries and rebuild the root. Proposal decisions are collected to check against GitHub.
    const f = state.frontier || { size: 0, hashes: [] };
    let stack = f.hashes.map((h) => ({ level: h.level, hash: L.unb64(h.hash) }));
    let size = f.size;
    const stop = Math.min(note.size, size + cap);
    const proposals = Array.isArray(state.proposals_pending) ? state.proposals_pending.slice(0, 200) : [];
    while (size < stop) {
      const page = await get(site + '/api/log/entries?from=' + size + '&limit=' + Math.min(PAGE, stop - size));
      if (!page || !Array.isArray(page.entries) || !page.entries.length) throw notChecked('the log returned no entries from ' + size);
      for (const e of page.entries) {
        if (!e || e.seq !== size) throw notChecked('the log returned entry ' + (e && e.seq) + ' where entry ' + size + ' belongs');
        let leaf;
        try { leaf = await L.leafHash(L.utf8(L.jcs(e.entry))); } catch { throw notChecked('entry ' + size + ' isn’t JSON the log could have written'); }
        if (L.b64(leaf) !== e.leaf_hash) return alarm('Entry ' + e.seq + ' doesn’t hash to its leaf.', cp.checkpoint.note);
        if (e.entry.type === 'proposal.decided' && e.entry.payload) proposals.push({ seq: e.seq, proposal: e.entry.payload.proposal, decision: e.entry.payload.decision });
        stack.push({ level: 0, hash: leaf });
        while (stack.length > 1 && stack[stack.length - 1].level === stack[stack.length - 2].level) {
          const r = stack.pop(), l = stack.pop();
          stack.push({ level: l.level + 1, hash: await L.nodeHash(l.hash, r.hash) });
        }
        size++;
        if (size === stop) break;
      }
    }
    let root = stack[stack.length - 1].hash;
    for (let i = stack.length - 2; i >= 0; i--) root = await L.nodeHash(stack[i].hash, root);
    if (size === note.size) {
      if (!L.equal(root, note.root)) return alarm('The entries don’t rebuild the signed root of ' + note.size + ' entries.', cp.checkpoint.note);
    } else {
      const p = await get(site + '/api/log/proof/consistency?from=' + size + '&to=' + note.size);
      if (!(await L.verifyConsistency(size, note.size, root, note.root, (p.proof || []).map(L.unb64)))) {
        return alarm('The first ' + size + ' entries, re-hashed, aren’t the start of the signed tree of ' + note.size + '.', cp.checkpoint.note);
      }
    }
    state.frontier = { size, hashes: stack.map((h) => ({ level: h.level, hash: L.b64(h.hash) })) };
    state.rehashed = size;
    if (!good || note.size > good.size) {
      state.good = { size: note.size, root: L.b64(note.root), seen_at: state.last_run };
      fs.writeFileSync(file('checkpoint'), cp.checkpoint.note);
      result.wrote = true;
    }
    // Each proposal decision against GitHub's own record (the issue's label events). GitHub unreachable or rate limited:
    // checked next run. A record that has no such label: an alarm.
    const pending = [];
    for (const p of proposals) {
      if (!Number.isSafeInteger(p.proposal) || !['approved', 'declined', 'shipped'].includes(p.decision)) { pending.push(p); continue; }
      let events;
      try { events = await get(GH_API + '/issues/' + p.proposal + '/events?per_page=100'); } catch { pending.push(p); continue; }
      if (!Array.isArray(events)) { pending.push(p); continue; }
      const shown = events.some((ev) => ev && ev.event === 'labeled' && ev.label && String(ev.label.name).toLowerCase() === 'status: ' + p.decision);
      if (!shown) return alarm('Entry ' + p.seq + ' records proposal ' + p.proposal + ' as ' + p.decision + ', but GitHub’s record of that issue shows no such label.', cp.checkpoint.note);
    }
    state.proposals_pending = pending;
    delete state.last_error;
  } catch (e) {
    if (!e || !e.notChecked) state.last_error = { at: state.last_run, error: 'not checked: ' + String(e && e.message || e).slice(0, 200) };
    else state.last_error = { at: state.last_run, error: String(e.message).slice(0, 200) };
  }
  return save();

  function save() {
    fs.writeFileSync(file('state.json'), JSON.stringify(state, null, 1) + '\n');
    if (!fs.existsSync(file('README.md'))) fs.writeFileSync(file('README.md'), README);
    return { ...result, state };
  }
}

const README = '# The public log\'s witness\n\nThis branch is written by .github/workflows/log-witness.yml on main, every 15 minutes. `checkpoint` is the last signed checkpoint of dayonegreat.com/log that passed every check; `state.json` is the key pinned, the last good checkpoint, how far the entries were re-hashed, and any alarm. The Verify page (https://dayonegreat.com/receipts) and `node tools/verify/dog-verify.mjs` read these files to check that the log showed everyone the same tree. The history of this branch is the witness\'s record.\n';
const MAX_STATE = 64 * 1024, MAX_CHECKPOINT = 4000;

// The record job: takes the check job's two files (base64, from its outputs), checks they are what the check writes,
// and writes only state.json, checkpoint and README.md into the branch folder. Returns { alarm }.
// It never writes a state that forgets what the branch already holds (RK149): one that drops or changes a standing
// alarm, has a smaller last good checkpoint (or another root for the same size), another pinned key, or a run count no
// higher than the branch's. Any of these throws, so the run fails red and the branch keeps what it had. Only a person,
// with a commit to the branch, can remove an alarm or change the key there, and that commit stays in its history.
export function record(dir, stateB64, checkpointB64) {
  const state = Buffer.from(String(stateB64 || ''), 'base64');
  if (!state.length || state.length > MAX_STATE) throw new Error('state.json is missing or too big');
  const s = JSON.parse(state.toString('utf8'));
  if (!s || s.v !== 1 || s.log !== L.ORIGIN || typeof s.last_run !== 'string') throw new Error('state.json isn’t the witness’s');
  if (s.key !== undefined) L.parseVkey(s.key);
  if (s.good !== undefined && (!Number.isSafeInteger(s.good.size) || !/^[A-Za-z0-9+/]{43}=$/.test(String(s.good.root)))) throw new Error('state.json’s good checkpoint is malformed');
  if (!Number.isSafeInteger(s.runs) || s.runs < 1) throw new Error('state.json’s run count is malformed');
  keepsBranch(dir, s);
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify(s, null, 1) + '\n');
  if (checkpointB64) {
    const c = Buffer.from(String(checkpointB64), 'base64').toString('utf8');
    if (c.length > MAX_CHECKPOINT) throw new Error('checkpoint is too big');
    const n = L.parseCheckpoint(c);
    if (n.origin !== L.ORIGIN || (s.good && n.size !== s.good.size)) throw new Error('checkpoint isn’t the good one state.json names');
    fs.writeFileSync(path.join(dir, 'checkpoint'), c);
  }
  if (!fs.existsSync(path.join(dir, 'README.md'))) fs.writeFileSync(path.join(dir, 'README.md'), README);
  return { alarm: s.alarm ? String(s.alarm.reason || s.alarm) : null };
}

// The branch's state as checked out, against the new one. No state.json on the branch (its first run): nothing to keep.
// One that can't be read is not treated as empty, since that is the reset RK149 describes: the run fails until a
// person repairs the branch.
function keepsBranch(dir, s) {
  const f = path.join(dir, 'state.json');
  if (!fs.existsSync(f)) return;
  let cur;
  try { cur = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { cur = null; }
  if (!cur || typeof cur !== 'object' || Array.isArray(cur)) throw new Error('refused: the branch’s state.json can’t be read, so a new one could drop what it holds; a person must repair the branch');
  const refuse = (why) => { throw new Error('refused: the new state.json ' + why + ' (RK149); the branch keeps what it had'); };
  if (cur.alarm && JSON.stringify(s.alarm) !== JSON.stringify(cur.alarm)) refuse('drops or changes the branch’s standing alarm');
  if (cur.good) {
    if (!s.good || s.good.size < cur.good.size) refuse('has a smaller last good checkpoint than the branch’s ' + cur.good.size);
    if (s.good.size === cur.good.size && s.good.root !== cur.good.root) refuse('has another root for the branch’s last good checkpoint of ' + cur.good.size);
  }
  if (cur.key !== undefined && s.key !== cur.key) refuse('has another pinned key than the branch’s');
  if (Number.isSafeInteger(cur.runs) && s.runs <= cur.runs) refuse('has run ' + s.runs + ' times, not more than the branch’s ' + cur.runs);
}

// The issue's text: the alarm's reason with nobody mentioned and nothing linked, inside a code block.
export function issueBody(reason) {
  const clean = String(reason || '').slice(0, 500).replace(/https?:\/\/\S+/gi, '[link removed]').replace(/@/g, '(at)').replace(/`/g, "'").replace(/[\r\n]+/g, ' ');
  return 'The witness raised an alarm:\n\n```\n' + clean + '\n```\n\nThe witness keeps the last good checkpoint and this alarm in `state.json` on the `log-witness` branch. '
    + 'The site shows the log as unverified, with this reason, and keeps running. Nothing changes until a person looks: /security#log on the site says what to check.';
}

async function raise(reason) {
  const require = createRequire(import.meta.url);
  const { gh, listIssues, ensureLabel } = require('../../scripts/_github.js');
  await ensureLabel('log-witness', 'b60205', 'The public log’s witness raised an alarm');
  const open = await listIssues('labels=log-witness&state=open');
  if (open.length) return;
  await gh('/issues', { method: 'POST', body: { title: 'The public log’s witness raised an alarm', labels: ['log-witness'], body: issueBody(reason) } });
}

if (process.argv[1] && process.argv[1].endsWith('witness.mjs')) {
  const args = process.argv.slice(2);
  if (args[0] === '--record') {
    const out = record(args[1], process.env.WITNESS_STATE_B64, process.env.WITNESS_CHECKPOINT_B64);
    console.log(out.alarm ? 'recorded, with the alarm: ' + out.alarm : 'recorded');
    if (out.alarm && process.env.GITHUB_TOKEN) await raise(out.alarm);
  } else {
    const dir = args.find((a) => !a.startsWith('--'));
    const i = args.indexOf('--site');
    if (!dir) { console.error('usage: node tools/verify/witness.mjs <branch folder> [--site https://dayonegreat.com] | --record <branch folder>'); process.exit(2); }
    const out = await witness({ dir, site: i >= 0 ? args[i + 1] : L.SITE });
    console.log(out.alarm ? 'ALARM: ' + out.alarm : out.state.last_error ? 'not checked: ' + out.state.last_error.error : 'ok: checkpoint of ' + out.size + ' entries; re-hashed ' + out.state.rehashed);
    if (process.env.GITHUB_OUTPUT) {
      const b = (f) => (fs.existsSync(path.join(dir, f)) ? fs.readFileSync(path.join(dir, f)).toString('base64') : '');
      fs.appendFileSync(process.env.GITHUB_OUTPUT, 'state=' + b('state.json') + '\ncheckpoint=' + b('checkpoint') + '\n');
    }
  }
}
