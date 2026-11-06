// The public log's tree on the server (038; RFC 9162, section 2.1): which complete subtrees a root or a proof needs,
// and the proofs themselves, from those subtrees' hashes (app.log_nodes). The verifier (verifier/lib.js) is written
// separately, from the RFC's verification steps, so a mistake here can't hide by being made twice.
'use strict';

const crypto = require('crypto');

const H = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
const leafHash = (bytes) => H(Buffer.from([0]), Buffer.from(bytes));
const nodeHash = (l, r) => H(Buffer.from([1]), l, r);
// The largest power of two smaller than n (n > 1).
function split(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
// Exact for every safe integer: n & (n - 1) works on 32 bits only, so trees past 2^31 entries would split wrongly
// (the review of 038, L7).
const isPow2 = (n) => Number.isSafeInteger(n) && n > 0 && 2 ** log2(n) === n;
const log2 = (n) => Math.round(Math.log2(n));

// The complete subtrees, as [level, idx], that make up the leaves lo..hi-1, in the order MTH folds them.
function subtrees(lo, hi, out = []) {
  const n = hi - lo;
  if (n <= 0) return out;
  if (isPow2(n) && lo % n === 0) { out.push([log2(n), lo / n]); return out; }
  const k = split(n);
  subtrees(lo, lo + k, out);
  subtrees(lo + k, hi, out);
  return out;
}
// The hash of leaves lo..hi-1, given get(level, idx) -> Buffer for complete subtrees.
function mth(lo, hi, get) {
  const n = hi - lo;
  if (n === 0) return H(Buffer.alloc(0));
  if (isPow2(n) && lo % n === 0) return get(log2(n), lo / n);
  const k = split(n);
  return nodeHash(mth(lo, lo + k, get), mth(lo + k, hi, get));
}

// The ranges whose hashes make the inclusion proof of leaf m in a tree of n leaves (RFC 9162 2.1.3.1), leaf first.
function inclusionRanges(m, n, lo = 0, out = []) {
  if (n - lo <= 1) return out;
  const k = split(n - lo);
  if (m < lo + k) { inclusionRanges(m, lo + k, lo, out); out.push([lo + k, n]); }
  else { inclusionRanges(m, n, lo + k, out); out.push([lo, lo + k]); }
  return out;
}
// The ranges of the consistency proof from m leaves to n leaves (RFC 9162 2.1.4.1, SUBPROOF).
function consistencyRanges(m, n) {
  const out = [];
  (function sub(m2, lo, hi, b) {
    const size = hi - lo;
    if (m2 === size) { if (!b) out.push([lo, hi]); return; }
    const k = split(size);
    if (m2 <= k) { sub(m2, lo, lo + k, b); out.push([lo + k, hi]); }
    else { sub(m2 - k, lo + k, hi, false); out.push([lo, lo + k]); }
  })(m, 0, n, true);
  return out;
}

// Every [level, idx] a list of ranges needs, without repeats.
function needed(ranges) {
  const seen = new Map();
  for (const [lo, hi] of ranges) for (const [l, i] of subtrees(lo, hi)) seen.set(l + ':' + i, [l, i]);
  return [...seen.values()];
}
// fetchNodes(list of [level, idx]) -> Promise<Map('level:idx' -> Buffer)>; a missing node is an error, never a guess.
async function resolve(ranges, fetchNodes) {
  const want = needed(ranges);
  const got = want.length ? await fetchNodes(want) : new Map();
  const get = (l, i) => { const h = got.get(l + ':' + i); if (!h) throw new Error('the log has no subtree ' + i + ' at level ' + l); return h; };
  return ranges.map(([lo, hi]) => mth(lo, hi, get));
}
const inclusionProof = (m, n, fetchNodes) => resolve(inclusionRanges(m, n), fetchNodes);
const consistencyProof = (m, n, fetchNodes) => (m === 0 || m === n ? Promise.resolve([]) : resolve(consistencyRanges(m, n), fetchNodes));
const root = async (n, fetchNodes) => (n === 0 ? H(Buffer.alloc(0)) : (await resolve([[0, n]], fetchNodes))[0]);

// An in-memory tree from leaf hashes (for tests and the witness): every complete subtree, as fetchNodes wants them.
function memoryTree(leaves) {
  const nodes = new Map();
  let level = leaves.map((h) => Buffer.from(h));
  for (let l = 0; level.length; l++) {
    level.forEach((h, i) => nodes.set(l + ':' + i, h));
    const up = [];
    for (let i = 0; i + 1 < level.length; i += 2) up.push(nodeHash(level[i], level[i + 1]));
    level = up;
  }
  return { size: leaves.length, fetchNodes: async (want) => new Map(want.filter(([l, i]) => nodes.has(l + ':' + i)).map(([l, i]) => [l + ':' + i, nodes.get(l + ':' + i)])) };
}

module.exports = { H, leafHash, nodeHash, split, subtrees, mth, inclusionRanges, consistencyRanges, needed, inclusionProof, consistencyProof, root, memoryTree };
