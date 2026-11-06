// The public log (038), read by the site: entries, checkpoints, proofs and proof bundles. Everything here only reads,
// as an anonymous visitor; the database alone writes the log. Hashes leave as base64 (the c2sp convention), entries as
// the exact canonical JSON the database hashed.
'use strict';

const crypto = require('crypto');
const merkle = require('./merkle');

const ORIGIN = 'dayonegreat.com/log';
const REPO = 'MyChiefOS/start-of-something-great';
const WITNESS_BRANCH = 'log-witness';
const WITNESS = {
  name: 'GitHub',
  about: 'A scheduled job in the public repository ' + REPO + ' fetches each checkpoint, checks it against the last and the entries, and commits it to the branch ' + WITNESS_BRANCH + '. Its copy is a record GitHub keeps, not a cryptographic cosignature.',
  checkpoint: 'https://raw.githubusercontent.com/' + REPO + '/' + WITNESS_BRANCH + '/checkpoint',
  state: 'https://raw.githubusercontent.com/' + REPO + '/' + WITNESS_BRANCH + '/state.json',
  branch: 'https://github.com/' + REPO + '/tree/' + WITNESS_BRANCH,
  workflow: 'https://github.com/' + REPO + '/blob/main/.github/workflows/log-witness.yml'
};
const b64 = (b) => Buffer.from(b).toString('base64');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function vkey(name, pub) {
  const id = crypto.createHash('sha256').update(Buffer.concat([Buffer.from(name), Buffer.from([0x0a, 0x01]), Buffer.from(pub)])).digest().subarray(0, 4);
  return name + '+' + id.toString('hex') + '+' + b64(Buffer.concat([Buffer.from([1]), Buffer.from(pub)]));
}

async function head(t) { const [r] = await t`select size from app.log_head`; return r ? Number(r.size) : 0; }
async function key(t) {
  const [k] = await t`select name, public_key, key_id, created_at from app.log_keys`;
  if (!k) return null;
  const fp = crypto.createHash('sha256').update(k.public_key).digest('hex');
  return { name: k.name, algorithm: 'Ed25519', vkey: vkey(k.name, k.public_key), public_key: b64(k.public_key), key_id: k.key_id.toString('hex'),
    fingerprint: 'SHA256:' + fp, created_at: new Date(k.created_at).toISOString(), registered_in_entry: 0 };
}
async function checkpoint(t) {
  const [c] = await t`select size, root, note, created_at from app.log_checkpoints order by size desc limit 1`;
  return c ? { size: Number(c.size), root: b64(c.root), note: c.note, signed_at: new Date(c.created_at).toISOString() } : null;
}
async function witness(t) {
  const [w] = await t`select status, reason, alarm, witness_size, witnessed_at, checked_at, self_ok from app.log_witness`;
  return { ...WITNESS, site_reading: w ? { status: w.status, reason: w.reason || null, alarm_until_cleared: w.alarm, witness_size: w.witness_size === null ? null : Number(w.witness_size),
    witnessed_at: w.witnessed_at ? new Date(w.witnessed_at).toISOString() : null, checked_at: w.checked_at ? new Date(w.checked_at).toISOString() : null,
    tree_matches_checkpoints: w.self_ok } : null };
}
// The complete subtrees asked for, in one query.
const nodes = (t) => async (want) => {
  const levels = want.map((x) => x[0]), idxs = want.map((x) => String(x[1]));
  const rows = await t`select n.level, n.idx, n.hash from app.log_nodes n
                       join unnest(${levels}::int[], ${idxs}::bigint[]) w(level, idx) on n.level = w.level and n.idx = w.idx`;
  return new Map(rows.map((r) => [r.level + ':' + r.idx, r.hash]));
};

const shapeEntry = (r) => ({ seq: Number(r.seq), leaf_hash: b64(r.leaf_hash), entry: JSON.parse(r.entry_jcs) });
async function entries(t, from, limit) {
  const rows = await t`select seq, leaf_hash, entry_jcs from app.log_entries where seq >= ${from} and seq < ${from + limit} order by seq`;
  return rows.map(shapeEntry);
}
async function entry(t, seq) { const [r] = await t`select seq, leaf_hash, entry_jcs from app.log_entries where seq = ${seq}`; return r ? shapeEntry(r) : null; }

// A receipt ID: a post's or decision's UUID, an entry's number, a leaf hash (base64 or hex), or "proposal-N".
async function find(t, ref) {
  const s = String(ref || '').trim();
  let rows = [];
  if (UUID.test(s.toLowerCase())) {
    const id = s.toLowerCase();
    rows = await t`select seq, leaf_hash, entry_jcs from app.log_entries where subject = any (${['post:' + id, 'decision:' + id]}::text[]) order by seq desc limit 1`;
  } else if (/^(0|[1-9][0-9]{0,14})$/.test(s)) {
    rows = await t`select seq, leaf_hash, entry_jcs from app.log_entries where seq = ${Number(s)}`;
  } else if (/^proposal-[1-9][0-9]{0,7}$/.test(s)) {
    rows = await t`select seq, leaf_hash, entry_jcs from app.log_entries where subject = ${'proposal:' + s.slice(9)} order by seq desc limit 1`;
  } else {
    const leaf = leafFrom(s);
    if (leaf) rows = await t`select seq, leaf_hash, entry_jcs from app.log_entries where leaf_hash = ${leaf}`;
  }
  return rows[0] ? shapeEntry(rows[0]) : null;
}
function leafFrom(s) {
  if (/^[0-9a-f]{64}$/i.test(s)) return Buffer.from(s, 'hex');
  if (/^[A-Za-z0-9+/]{43}=$/.test(s)) return Buffer.from(s, 'base64');
  if (/^[A-Za-z0-9_-]{43}$/.test(s)) return Buffer.from(s, 'base64url');
  return null;
}

async function inclusion(t, index, size) { return { index, size, path: (await merkle.inclusionProof(index, size, nodes(t))).map(b64) }; }
async function consistency(t, from, to) { return { from, to, proof: (await merkle.consistencyProof(from, to, nodes(t))).map(b64) }; }

// The proof bundle (spec 1.4): everything needed to check one entry offline, except the witness's copy, which a
// verifier reads from GitHub itself.
async function bundle(t, ref) {
  const e = await find(t, ref);
  if (!e) return null;
  const [cp, k, w] = [await checkpoint(t), await key(t), await witness(t)];
  const covered = cp && cp.size > e.seq;
  let opening = null;
  if (e.entry.type === 'post') {
    const [o] = await t`select key, facts from app.log_opening(${e.seq})`;
    if (o) opening = { key: o.key.toString('hex'), facts: o.facts };
  }
  const status = !covered ? 'unverified' : w.site_reading && w.site_reading.status === 'unverified' ? 'unverified'
    : w.site_reading && w.site_reading.status === 'ok' && w.site_reading.witness_size > e.seq ? 'verified' : 'verified_unwitnessed';
  return {
    v: 1,
    kind: 'dayonegreat.com/log proof bundle',
    generated_at: new Date().toISOString(),
    entry: e,
    inclusion: covered ? await inclusion(t, e.seq, cp.size) : null,
    checkpoint: covered ? cp : null,
    log_key: k,
    witness: w,
    actor_keys: [],
    actor_keys_note: 'In this phase people and agents have no signing keys of their own, so entries carry no actor signature; the log’s signed checkpoint covers them.',
    opening,
    opening_note: opening ? 'The key that opens this post’s sealed facts. It is shown while the post is live and deleted with the post.' : null,
    site_status: { status, note: 'The site’s own reading. A verifier recomputes everything itself: https://dayonegreat.com/receipts, or node tools/verify/dog-verify.mjs ' + (e.entry.subject.startsWith('post:') ? e.entry.subject.slice(5) : e.seq) + '.' }
  };
}

module.exports = { ORIGIN, WITNESS, WITNESS_BRANCH, vkey, head, key, checkpoint, witness, nodes, entries, entry, find, leafFrom, inclusion, consistency, bundle };
