// The public log's verifier (CODING_AGENT_SPEC.md 1.5; migration 038). One file for every place that checks a
// receipt: the Verify page (in a Web Worker, verifier/worker.js), the command line (tools/verify/dog-verify.mjs) and the
// witness on GitHub (tools/verify/witness.mjs). It trusts nothing from dayonegreat.com: it recomputes every hash itself
// with WebCrypto, checks Ed25519 signatures with the vendored noble-ed25519 2.3.0 (strict RFC 8032), and reads the
// witness's copy from GitHub, at an address written here, never one a bundle names.
//
// The checks, in order (each result: pass, fail, warn, info or na, with a plain sentence):
//   1 the entry hashes to its leaf (canonical JSON, RFC 8785, recomputed here), and a receipt's sealed facts open
//   2 the actor's signature (no actor has a signing key yet in phase 2: "na", said plainly, never a pass)
//   3 the actor's key was registered in the log before the entry (the same)
//   4 the inclusion proof reaches the checkpoint's root (RFC 9162 2.1.3.2)
//   5 the checkpoint is signed by the log's key (c2sp signed note, Ed25519), the key confirmed against a pin
//   6 the witness on GitHub saw the same log (its copy is signed by the same key and consistent with this checkpoint)
//   7 this checkpoint is consistent with the largest one this verifier has seen before
//   8 the delegation chain (no delegation entries are logged yet in phase 2: "na")
// Overall: "verified" (1, 4, 5 and 7 pass and the witness covers the entry), "verified_unwitnessed" (the same, but the
// witness's copy doesn't cover it yet or couldn't be read), "key_unconfirmed" (everything checks out but the signing key
// couldn't be confirmed against a pin), "unverified" (the entry isn't in a signed checkpoint yet, or the witness or this
// verifier's memory disagrees with the log: Aaron's "marks the log unverified"), "failed" (a check of this receipt failed).

import * as ed from './noble-ed25519-2.3.0.js';
import { PINNED_VKEY } from './log-key.js';

export const ORIGIN = 'dayonegreat.com/log';
export const SITE = 'https://dayonegreat.com';
export const REPO = 'MyChiefOS/start-of-something-great';
export const WITNESS_BRANCH = 'log-witness';
export const WITNESS = {
  name: 'GitHub',
  about: 'A scheduled job in the public repository ' + REPO + ' keeps each checkpoint on its branch ' + WITNESS_BRANCH + '.',
  checkpoint: 'https://raw.githubusercontent.com/' + REPO + '/' + WITNESS_BRANCH + '/checkpoint',
  state: 'https://raw.githubusercontent.com/' + REPO + '/' + WITNESS_BRANCH + '/state.json',
  branch: 'https://github.com/' + REPO + '/tree/' + WITNESS_BRANCH,
  history: 'https://github.com/' + REPO + '/commits/' + WITNESS_BRANCH
};
export const STEPS = [
  ['entry', 'The entry hashes to its leaf'],
  ['signature', 'The actor’s signature'],
  ['key', 'The actor’s key was in the log first'],
  ['inclusion', 'The entry is in the signed tree'],
  ['checkpoint', 'The checkpoint is signed by the log’s key'],
  ['witness', 'The witness saw the same log'],
  ['memory', 'Consistent with what this verifier saw before'],
  ['delegation', 'The delegation chain']
];

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });
const subtle = () => globalThis.crypto.subtle;

// ---- Bytes ----
export const utf8 = (s) => te.encode(s);
export function hex(b) { return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''); }
export function unhex(s) {
  if (typeof s !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(s)) throw new Error('not hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function b64(b) { let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s); }
export function unb64(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4) throw new Error('not base64');
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const is32 = (b) => b instanceof Uint8Array && b.length === 32;
export const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
export async function sha256(bytes) { return new Uint8Array(await subtle().digest('SHA-256', bytes)); }
export const leafHash = (bytes) => sha256(concat(new Uint8Array([0]), bytes));
export const nodeHash = (l, r) => sha256(concat(new Uint8Array([1]), l, r));

// ---- Canonical JSON (RFC 8785): sorted keys (UTF-16 code units, JavaScript's own string order), no spaces,
// ECMAScript number and string forms ----
export function jcs(v) {
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('not a finite number'); return JSON.stringify(v); }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
  throw new Error('not JSON');
}

// ---- RFC 9162 verification ----
// Inclusion (2.1.3.2): leaf at index in a tree of size reaches root through proof.
export async function verifyInclusion(index, size, leaf, proof, root) {
  if (!(Number.isSafeInteger(index) && Number.isSafeInteger(size)) || index < 0 || index >= size) return false;
  if (!is32(leaf) || !is32(root) || !proof.every(is32)) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && equal(r, root);
}
// Consistency (2.1.4.2): a tree of size1 with root1 is a prefix of the tree of size2 with root2.
export async function verifyConsistency(size1, size2, root1, root2, proof) {
  // As transparency-dev/merkle does: every hash is 32 bytes, and there is no consistency from an empty tree.
  if (!(Number.isSafeInteger(size1) && Number.isSafeInteger(size2)) || size1 < 1 || size2 < size1) return false;
  if (size1 === size2) return proof.length === 0 && equal(root1, root2);
  if (!is32(root1) || !is32(root2) || !proof.every(is32)) return false;
  if (proof.length === 0) return false;
  let path = proof;
  if (2 ** Math.round(Math.log2(size1)) === size1) path = [root1, ...proof];
  let fn = size1 - 1, sn = size2 - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr); sr = await nodeHash(c, sr);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return equal(fr, root1) && equal(sr, root2) && sn === 0;
}

// ---- Signed notes (c2sp.org/signed-note, tlog-checkpoint) ----
export async function keyId(name, pub) { return (await sha256(concat(utf8(name), new Uint8Array([0x0a, 0x01]), pub))).slice(0, 4); }
export async function vkey(name, pub) { return name + '+' + hex(await keyId(name, pub)) + '+' + b64(concat(new Uint8Array([1]), pub)); }
export function parseVkey(s) {
  const m = /^([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/]+={0,2})$/.exec(String(s || '').trim());
  if (!m) throw new Error('not a verifier key');
  const raw = unb64(m[3]);
  if (raw.length !== 33 || raw[0] !== 1) throw new Error('not an Ed25519 verifier key');
  return { name: m[1], id: unhex(m[2]), pub: raw.slice(1) };
}
// Text -> { body, origin, size, root, sigs }; throws on anything not a checkpoint.
export function parseCheckpoint(text) {
  if (typeof text !== 'string' || text.length > 4000) throw new Error('not a checkpoint');
  const cut = text.indexOf('\n\n');
  if (cut < 0 || !text.endsWith('\n')) throw new Error('not a signed note');
  const body = text.slice(0, cut + 1);
  const lines = body.slice(0, -1).split('\n');
  if (lines.length < 3) throw new Error('a checkpoint has an origin, a size and a root');
  const [origin, sizeText, rootText] = lines;
  if (!/^(0|[1-9][0-9]{0,15})$/.test(sizeText)) throw new Error('the size isn’t a number');
  const root = unb64(rootText);
  if (root.length !== 32) throw new Error('the root isn’t 32 bytes');
  const sigs = text.slice(cut + 2, -1).split('\n').map((l) => {
    const m = /^— (\S+) ([A-Za-z0-9+/]+={0,2})$/.exec(l);
    if (!m) throw new Error('a signature line is malformed');
    const raw = unb64(m[2]);
    if (raw.length < 5) throw new Error('a signature is too short');
    return { name: m[1], id: raw.slice(0, 4), sig: raw.slice(4) };
  });
  return { body, origin, size: Number(sizeText), root, sigs };
}
export async function verifyEd25519(sig, msg, pub) {
  try { return sig.length === 64 && pub.length === 32 && (await ed.verifyAsync(sig, msg, pub, { zip215: false })); } catch { return false; }
}
// The checkpoint carries a valid signature by this key (name and key ID match).
export async function checkpointSigned(note, name, pub) {
  const id = await keyId(name, pub);
  for (const s of note.sigs) if (s.name === name && equal(s.id, id) && (await verifyEd25519(s.sig, utf8(note.body), pub))) return true;
  return false;
}

// ---- The bundle ----
const typedId = (s, kind) => { const m = new RegExp('^' + kind + ':(.+)$').exec(String(s || '')); return m ? m[1] : null; };
const step = (id, state, text, detail) => ({ id, title: STEPS.find((s) => s[0] === id)[1], state, text, detail: detail || '' });

// opts: { fetch (absent offline), site (base for proof requests, default dayonegreat.com), memory ({size, root} or null:
// the largest checkpoint seen before), pinnedKey (a vkey given by the person checking, e.g. the CLI's --key), onStep }.
// Returns { status, reason, steps, firstFailure, memory (the largest checkpoint seen, to keep: only ever one signed by
// the confirmed key and not failed; otherwise the memory given, unchanged) }.
//
// The log's key is never taken from the bundle alone (the independent review of Nov 5, H1): a bundle names a key, and the
// checks confirm it against a pin, in this order: the key given (--key), the key pinned in this repository
// (verifier/log-key.js, once 038 has made it in production), or the key the witness on GitHub pinned (its state.json).
// A key that differs from the pin fails step 5. With no pin at all (offline, before the key is pinned in the
// repository, or GitHub unreachable), the result is "Key not confirmed", never any kind of "Verified".
// Network and HTTP failures are never failures of the receipt (M1): they leave a step "not checked".
export async function verifyBundle(bundle, opts = {}) {
  const steps = [];
  const site = opts.site === undefined ? SITE : opts.site;
  const net = typeof opts.fetch === 'function' ? opts.fetch : null;
  const push = (s) => { steps.push(s); if (opts.onStep) opts.onStep(s); return s; };
  const given = opts.memory && Number.isSafeInteger(opts.memory.size) ? opts.memory : null;
  let memory = given;
  let note = null, pub = null, name = ORIGIN, seq = null, leaf = null, inCheckpoint = false, keyConfirmed = false, memoryOk = false;
  const soft = (msg) => Object.assign(new Error(msg), { soft: true });
  const getJson = async (url) => {
    let r;
    try { r = await net(url, { headers: { Accept: 'application/json' } }); } catch (err) { throw soft('the site didn’t answer (' + String(err && err.message || err).slice(0, 80) + ')'); }
    let body = null;
    try { body = await r.json(); } catch { body = null; }
    if (!r.ok) throw Object.assign(soft('the site answered ' + r.status + (body && body.error ? ': ' + String(body.error).slice(0, 120) : '')), { status: r.status });
    if (!body) throw soft('the site’s answer wasn’t JSON');
    return body;
  };
  const proof = async (from, to) => {
    const j = await getJson(site + '/api/log/proof/consistency?from=' + from + '&to=' + to);
    return (j.proof || []).map(unb64);
  };

  if (!bundle || typeof bundle !== 'object' || !bundle.entry || typeof bundle.entry !== 'object') {
    push(step('entry', 'fail', 'This isn’t a proof bundle: it has no entry.'));
    return finish();
  }

  // The pins, before anything is trusted. The witness's state.json is read once, here, and used at steps 5 and 6.
  let pin = null, pinFrom = null, wstate = null, wstateNote = 'not read: no network';
  if (opts.pinnedKey) { pin = opts.pinnedKey; pinFrom = 'the key you gave'; }
  else if (PINNED_VKEY) { pin = PINNED_VKEY; pinFrom = 'the key pinned in the repository (verifier/log-key.js)'; }
  if (net) {
    try {
      const r = await net(WITNESS.state, { cache: 'no-store' });
      if (r.ok) { wstate = await r.json(); wstateNote = 'read'; } else wstateNote = 'GitHub answered ' + r.status;
    } catch (err) { wstateNote = 'GitHub didn’t answer'; }
    if (wstate && (typeof wstate !== 'object' || Array.isArray(wstate))) { wstate = null; wstateNote = 'not a witness state'; }
  }
  if (!pin && wstate && typeof wstate.key === 'string') { pin = wstate.key; pinFrom = 'the key the witness on GitHub pinned on its first run'; }

  // 1. The entry hashes to its leaf.
  try {
    const e = bundle.entry.entry;
    seq = bundle.entry.seq;
    if (!Number.isSafeInteger(seq) || seq < 0) throw new Error('the entry has no number');
    if (!e || e.v !== 1 || typeof e.type !== 'string') throw new Error('the entry isn’t a version 1 log entry');
    const bytes = utf8(jcs(e));
    leaf = await leafHash(bytes);
    const stated = unb64(String(bundle.entry.leaf_hash || ''));
    if (!equal(leaf, stated)) throw new Error('its canonical JSON hashes to ' + b64(leaf) + ', not the leaf ' + b64(stated));
    let opened = '';
    if (bundle.opening) {
      const o = bundle.opening;
      const k = unhex(String(o.key || ''));
      const sealed = hex(await sha256(concat(k, utf8(jcs(o.facts)))));
      if (k.length !== 32 || !e.payload || sealed !== e.payload.facts) throw new Error('its sealed facts don’t open with the key given');
      const f = o.facts;
      // The entry names the agent and owner by their log names; the facts carry the same names (and the accounts).
      const same = f.post === typedId(e.subject, 'post') && f.actor === e.actor && f.on_behalf_of === e.on_behalf_of;
      if (!same) throw new Error('its sealed facts name another post, agent or owner');
      opened = ' Its sealed facts open with the key in the bundle: post ' + f.post + ', by agent ' + f.agent + ' for member ' + f.owner
        + ', ' + (f.delegation === 'approved' ? 'with the owner’s approval of the exact words' : 'under the owner’s rules') + ', rules version ' + f.rules_version + '.';
    }
    push(step('entry', 'pass', 'Entry ' + seq + ' hashes to its leaf: its canonical JSON was recomputed here.' + opened,
      'Every entry is written as canonical JSON (RFC 8785) and its leaf is SHA-256 of a zero byte and those bytes. Recomputing it here means a changed entry can’t pass as the original.'));
  } catch (err) {
    push(step('entry', 'fail', 'The entry doesn’t match its leaf: ' + err.message + '.', 'A changed entry no longer hashes to the leaf the log committed to.'));
  }

  // 2 and 3. The actor's signature and key.
  const e = bundle.entry.entry || {};
  if (e.sig === null || e.sig === undefined) {
    push(step('signature', 'na', 'Not yet possible: in this phase people and agents have no signing keys of their own, so the entry carries no actor signature. The log’s own signature (step 5) covers it.',
      'When members and agents get keys (phase 3), each entry will be signed by whoever acted, so not even the log could write an entry in their name.'));
    push(step('key', 'na', 'Not yet possible: there is no actor key to look up.', 'Each actor’s key will be registered in the log (a key.registered entry) before it signs anything.'));
  } else {
    // Fail closed (the review of 038, L5): no actor keys are registered in this phase, and this log writes no signed
    // entries, so a signed entry isn't one of its own. A key named only in the bundle proves nothing, so the
    // signature is checked for what it says, and the key step fails until actor keys are registered in the log itself.
    const keys = Array.isArray(bundle.actor_keys) ? bundle.actor_keys : [];
    const k = keys.find((x) => x && x.actor === e.actor);
    let ok = false;
    try { const unsigned = { ...e, sig: null }; ok = Boolean(k) && (await verifyEd25519(unb64(e.sig), utf8(jcs(unsigned)), unb64(k.public_key))); } catch { ok = false; }
    push(step('signature', ok ? 'pass' : 'fail', ok ? 'The signature is valid for the key the bundle names, but that key isn’t confirmed (step 3).' : 'The entry is signed, but the signature doesn’t match a key for its actor.'));
    push(step('key', 'fail', 'The entry is signed, but no actor keys are registered in this log yet, so its signer can’t be confirmed: this isn’t an entry the log wrote.',
      'Actor keys come with phase 3, each registered in the log before it signs. Until then a signed entry is treated as forged.'));
  }

  // 4. Inclusion.
  try {
    const inc = bundle.inclusion;
    if (!inc) {
      push(step('inclusion', 'warn', 'Not in a signed checkpoint yet. The log signs a new checkpoint about once a minute; try again shortly.',
        'An entry is covered once a signed checkpoint’s tree includes it.'));
    } else {
      const root = unb64(String(bundle.checkpoint && bundle.checkpoint.root || ''));
      const path = (inc.path || []).map(unb64);
      if (inc.index !== seq) throw new Error('the proof is for entry ' + inc.index + ', not ' + seq);
      const ok = leaf && (await verifyInclusion(seq, inc.size, leaf, path, root));
      if (!ok) throw new Error('the ' + path.length + ' hashes of the proof don’t reach the checkpoint’s root');
      inCheckpoint = true;
      push(step('inclusion', 'pass', 'The inclusion proof (' + path.length + ' hashes) leads from the entry’s leaf to the root of the checkpoint of ' + inc.size + ' entries.',
        'The proof is the few hashes needed to rebuild the tree’s root from this one leaf (RFC 9162). It shows the entry is in the tree the checkpoint describes, without downloading the rest.'));
    }
  } catch (err) {
    push(step('inclusion', 'fail', 'The inclusion proof fails: ' + err.message + '.', 'A changed proof, or an entry that isn’t in the tree, can’t reach the signed root.'));
  }

  // 5. The checkpoint's signature, by the confirmed key.
  try {
    const cp = bundle.checkpoint || {};
    note = parseCheckpoint(String(cp.note || ''));
    if (note.origin !== ORIGIN) throw new Error('it is for “' + note.origin + '”, not ' + ORIGIN);
    if (note.size !== cp.size || b64(note.root) !== cp.root) throw new Error('the signed text says size ' + note.size + ', not ' + cp.size + ', or another root');
    if (bundle.inclusion && note.size !== bundle.inclusion.size) throw new Error('the proof is for a tree of ' + bundle.inclusion.size + ' entries, the checkpoint for ' + note.size);
    const lk = bundle.log_key || {};
    const v = parseVkey(lk.vkey);
    if (v.name !== ORIGIN) throw new Error('the key is named ' + v.name);
    let p = null;
    if (pin) { try { p = parseVkey(pin); } catch { throw new Error('the pinned key (' + pinFrom + ') isn’t a verifier key'); } }
    if (p && !equal(p.pub, v.pub)) throw new Error('it names the key ' + hex(v.id) + ', but the log’s key is ' + hex(p.id) + ' (' + pinFrom + ')');
    pub = v.pub; name = v.name;
    if (!(await checkpointSigned(note, name, pub))) throw new Error('the signature doesn’t verify with the key ' + lk.vkey);
    keyConfirmed = Boolean(p);
    if (keyConfirmed) {
      push(step('checkpoint', 'pass', 'The checkpoint of ' + note.size + ' entries is signed by the log’s key ' + hex(v.id) + ' (Ed25519), confirmed against ' + pinFrom + '.',
        'The log signs its tree’s size and root (a c2sp signed note). The key is checked against a copy kept away from this site, so a bundle can’t bring its own key.'));
    } else {
      push(step('checkpoint', 'warn', 'The checkpoint of ' + note.size + ' entries is signed by the key ' + hex(v.id) + ' that the bundle names, but that key couldn’t be confirmed as the log’s: the witness’s pin on GitHub was ' + wstateNote
        + ', and no key is pinned in the repository or given (--key). Until it is confirmed, this result is “Key not confirmed”.',
        'Anyone can sign a checkpoint with a key of their own. What makes it the log’s is that the key matches one kept apart from the site: the witness’s pin on GitHub, or the one pinned in the repository.'));
    }
  } catch (err) {
    note = note && note.size ? note : null;
    push(step('checkpoint', 'fail', 'The checkpoint isn’t validly signed by the log’s key: ' + err.message + '.', 'A changed checkpoint or signature, or a checkpoint signed by another key, doesn’t verify with the log’s public key.'));
    pub = null;
  }

  // 6. The witness.
  if (!pub || !note) {
    push(step('witness', 'warn', 'Not checked: the checkpoint itself didn’t verify.'));
  } else if (!net) {
    push(step('witness', 'warn', 'Not checked: this check needs the network, to read the witness’s copy on GitHub. Everything above was checked offline.',
      'The witness is a job in the public repository that keeps each checkpoint, so anyone can see whether the log showed everyone the same tree.'));
  } else {
    try {
      let wtext;
      try { const r = await net(WITNESS.checkpoint, { cache: 'no-store' }); if (!r.ok) throw new Error('GitHub answered ' + r.status); wtext = await r.text(); }
      catch (err) { throw soft('the witness’s copy couldn’t be read from GitHub (' + err.message + ')'); }
      let w;
      try { w = parseCheckpoint(wtext); } catch (err) { throw soft('the witness’s copy on GitHub isn’t a checkpoint (' + err.message + ')'); }
      if (w.origin !== ORIGIN || !(await checkpointSigned(w, name, pub))) throw new Error('the witness’s copy isn’t signed by this log’s key');
      if (wstate && wstate.key && wstate.key !== (await vkey(name, pub))) throw new Error('the witness pinned another key for this log: ' + String(wstate.key).slice(0, 120));
      if (wstate && wstate.alarm) throw new Error('the witness raised an alarm: ' + String(wstate.alarm.reason || wstate.alarm).slice(0, 200));
      const lo = Math.min(w.size, note.size), hi = Math.max(w.size, note.size);
      const [r1, r2] = w.size <= note.size ? [w.root, note.root] : [note.root, w.root];
      const ok = lo === hi ? equal(r1, r2) : await verifyConsistency(lo, hi, r1, r2, await proof(lo, hi));
      if (!ok) throw new Error('the witness’s checkpoint of ' + w.size + ' entries isn’t consistent with this one of ' + note.size + ': the log may have shown different trees to different people');
      const covered = seq !== null && w.size > seq;
      push(step('witness', covered ? 'pass' : 'warn', covered
        ? 'Witnessed by GitHub (1 of 1): its copy, a checkpoint of ' + w.size + ' entries, is signed by the same key, consistent with this checkpoint, and includes this entry.'
        : 'Not yet witnessed: the witness’s latest copy (' + w.size + ' entries) is consistent with this checkpoint but older than this entry. The witness runs every 15 minutes.',
        'The witness is GitHub: a scheduled job in our public repository fetches each checkpoint, checks it against the last, and commits it to the branch ' + WITNESS_BRANCH
        + '. Its copy is a record GitHub keeps, not a cryptographic cosignature. Witnesses run by others are not arranged yet.'));
    } catch (err) {
      push(step('witness', err.soft ? 'warn' : 'fail', (err.soft ? 'Not checked: ' : 'The witness disagrees: ') + err.message + '.',
        'If the witness’s copy doesn’t match, the log may have shown different trees to different people, so the record is unverified until that is explained.'));
    }
  }

  // 7. The largest checkpoint this verifier has seen. Only a checkpoint signed by the confirmed key is ever kept (M1).
  if (!note || !pub) {
    push(step('memory', 'warn', 'Not checked: the checkpoint itself didn’t verify.'));
  } else if (!given) {
    memoryOk = true;
    push(step('memory', 'info', keyConfirmed ? 'No earlier checkpoint seen by this verifier. This one (' + note.size + ' entries) is kept to compare with next time.'
      : 'No earlier checkpoint seen by this verifier. This one isn’t kept, because its key wasn’t confirmed.',
      'Remembering the largest checkpoint means a log that later shows a different history is caught.'));
  } else {
    try {
      const m = { size: given.size, root: unb64(given.root) };
      const lo = Math.min(m.size, note.size), hi = Math.max(m.size, note.size);
      const [r1, r2] = m.size <= note.size ? [m.root, note.root] : [note.root, m.root];
      let ok;
      if (lo === hi) ok = equal(r1, r2);
      else if (!net) throw soft('the consistency proof needs the network');
      else {
        let pr;
        try { pr = await proof(lo, hi); } catch (err) {
          if (err.status === 400 && m.size > note.size) throw soft('this verifier saw a checkpoint of ' + m.size + ' entries before, and the site’s tree is smaller now, so the two can’t be compared. If it stays smaller, the log may have shown different trees to different people');
          throw err;
        }
        ok = await verifyConsistency(lo, hi, r1, r2, pr);
      }
      if (!ok) throw new Error('the checkpoint of ' + note.size + ' entries isn’t consistent with the one of ' + m.size + ' seen before: the log may have shown different trees to different people');
      memoryOk = true;
      push(step('memory', 'pass', 'Consistent with the largest checkpoint seen before (' + m.size + ' entries).',
        'A consistency proof shows the earlier tree is the start of this one, unchanged.'));
    } catch (err) {
      push(step('memory', err.soft ? 'warn' : 'fail', (err.soft ? 'Not checked: ' : '') + err.message + '.', 'A log that rewrote its history can’t produce this proof.'));
    }
  }

  // 8. Delegation.
  push(step('delegation', 'na', e.type === 'post'
    ? 'Not yet possible: delegations aren’t logged yet. The receipt’s own facts (step 1) say whether the owner approved the exact words or the agent posted under the owner’s rules.'
    : 'Not applicable: this entry wasn’t made for someone else.',
    'When delegations are logged (delegation.granted entries), this step will check the chain from the owner to the agent was valid at the time.'));

  return finish();

  function finish() {
    const by = Object.fromEntries(steps.map((s) => [s.id, s]));
    // Steps 6 and 7 judge the log, not this receipt: a disagreement makes the record unverified, never "failed".
    const hard = steps.find((s) => s.state === 'fail' && s.id !== 'witness' && s.id !== 'memory');
    let status, reason;
    if (hard) { status = 'failed'; reason = 'Step ' + (STEPS.findIndex((s) => s[0] === hard.id) + 1) + ' failed: ' + hard.text; }
    else if (by.witness && by.witness.state === 'fail') { status = 'unverified'; reason = by.witness.text; }
    else if (by.memory && by.memory.state === 'fail') { status = 'unverified'; reason = by.memory.text; }
    else if (!inCheckpoint) { status = 'unverified'; reason = (by.inclusion && by.inclusion.text) || 'Not in a signed checkpoint.'; }
    else if (!keyConfirmed) { status = 'key_unconfirmed'; reason = 'The entry and its proof check out, but the key that signed the checkpoint couldn’t be confirmed as the log’s (step 5).'; }
    else if (by.witness && by.witness.state === 'pass') { status = 'verified'; reason = 'In the public log, unchanged, and witnessed by GitHub.'; }
    else { status = 'verified_unwitnessed'; reason = 'In the public log and unchanged; not yet witnessed.'; }
    const keep = keyConfirmed && memoryOk && status !== 'failed' && note && (!given || note.size > given.size);
    return { status, reason, steps, firstFailure: hard ? hard.id : null, memory: keep ? { size: note.size, root: b64(note.root) } : given };
  }
}

export const LABELS = { verified: 'Verified', verified_unwitnessed: 'Verified, not yet witnessed', key_unconfirmed: 'Key not confirmed', unverified: 'Unverified', failed: 'Failed' };
export function parseUtf8(bytes) { return td.decode(bytes); }
