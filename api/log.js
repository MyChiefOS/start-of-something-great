// GET /api/log/...: the public log (038; CODING_AGENT_SPEC.md 1.4). Read-only, no sign-in, cacheable.
//   /api/log/checkpoint                         the latest signed checkpoint, the log's key and the witness (30 s)
//   /api/log/entries?from=&limit=               up to 100 entries from one number on
//   /api/log/entry/{seq}                        one entry
//   /api/log/proof/inclusion?leaf={hash}&size={n}  an entry's inclusion proof in the tree of n entries
//   /api/log/proof/consistency?from={m}&to={n}  the tree of m entries is the start of the tree of n
//   /api/log/receipt/{id}                       a proof bundle: entry, proof, checkpoint, keys (30 s)
// Entries and proofs never change once made, so they are cached for a year; a page of entries that isn't full yet,
// the checkpoint and bundles (which name the latest checkpoint) for 30 seconds.
'use strict';

const db = require('../db');
const log = require('../db/log');
const { onlyGet } = require('./_lib');

const IMMUTABLE = 'public, max-age=31536000, immutable';
const SHORT = 'public, max-age=30, s-maxage=30, stale-while-revalidate=30';
const NOTE = 'The public log of what agents, JEVs and Aaron did on Day One Great: every entry holds only random IDs and keyed hashes. Check any of it yourself at https://dayonegreat.com/receipts or with node tools/verify/dog-verify.mjs.';

function send(res, code, body, cache) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', cache || 'no-store');
  res.end(JSON.stringify(body, null, 2));
}
const bad = (res, msg) => send(res, 400, { error: msg }, SHORT);
// Leading and trailing slashes off, without a regular expression on the visitor's text.
function trimSlashes(s) { let a = 0, b = s.length; while (a < b && s[a] === '/') a++; while (b > a && s[b - 1] === '/') b--; return s.slice(a, b); }
const int = (s) => (/^(0|[1-9][0-9]{0,14})$/.test(String(s)) ? Number(s) : null);

async function handle(req, res, run) {
  if (!onlyGet(req, res)) return;
  const url = new URL(req.url || '/', 'https://dayonegreat.com');
  const q = url.searchParams;
  const route = trimSlashes(String((req.query && req.query.route) || q.get('route') || '').slice(0, 300));
  if (!run) return send(res, 200, { available: false, message: 'The site’s database isn’t switched on here, so there is no log to read.' }, SHORT);
  const as = (fn) => run({ actor: 'anon' }, fn);
  try {
    if (route === 'checkpoint') {
      const out = await as(async (t) => ({ size: await log.head(t), checkpoint: await log.checkpoint(t), log_key: await log.key(t), witness: await log.witness(t) }));
      return send(res, 200, { available: true, origin: log.ORIGIN, tree_size: out.size, checkpoint: out.checkpoint,
        message: out.checkpoint ? undefined : 'No checkpoint has been signed yet. The log signs one within a minute of its first entries.',
        log_key: out.log_key, witnesses: [out.witness], witnesses_required: 1, note: NOTE }, SHORT);
    }
    if (route === 'entries') {
      const from = int(q.get('from') === null ? 0 : q.get('from'));
      const limit = q.get('limit') === null ? 100 : int(q.get('limit'));
      if (from === null) return bad(res, 'from is an entry number: 0 or more.');
      if (limit === null || limit < 1 || limit > 100) return bad(res, 'limit is from 1 to 100.');
      const out = await as(async (t) => ({ size: await log.head(t), cp: await log.checkpoint(t), list: await log.entries(t, from, limit) }));
      const full = out.list.length === limit && out.cp && from + limit <= out.cp.size;
      const next = from + out.list.length < out.size ? from + out.list.length : null;
      return send(res, 200, { tree_size: out.size, from, entries: out.list, next }, full ? IMMUTABLE : SHORT);
    }
    if (route.startsWith('entry/')) {
      const seq = int(route.slice(6));
      if (seq === null) return bad(res, 'An entry is named by its number: /api/log/entry/0.');
      const e = await as((t) => log.entry(t, seq));
      return e ? send(res, 200, e, IMMUTABLE) : send(res, 404, { error: 'The log has no entry ' + seq + ' yet.' }, SHORT);
    }
    if (route === 'proof/inclusion') {
      const leaf = log.leafFrom(String(q.get('leaf') || ''));
      const size = int(q.get('size'));
      if (!leaf) return bad(res, 'leaf is a leaf hash: 32 bytes in base64 or hex.');
      if (size === null || size < 1) return bad(res, 'size is the tree size the proof is for: 1 or more.');
      const out = await as(async (t) => {
        const n = await log.head(t);
        const [r] = await t`select seq from app.log_entries where leaf_hash = ${leaf}`;
        if (!r) return { error: 404, msg: 'No entry has that leaf hash.' };
        const index = Number(r.seq);
        if (size > n) return { error: 400, msg: 'The tree has only ' + n + ' entries.' };
        if (index >= size) return { error: 400, msg: 'Entry ' + index + ' isn’t in the first ' + size + ' entries.' };
        return { proof: await log.inclusion(t, index, size) };
      });
      return out.error ? send(res, out.error, { error: out.msg }, SHORT) : send(res, 200, { leaf_index: out.proof.index, tree_size: size, path: out.proof.path }, IMMUTABLE);
    }
    if (route === 'proof/consistency') {
      const from = int(q.get('from')), to = int(q.get('to'));
      if (from === null || to === null || from < 1 || to < from) return bad(res, 'from and to are tree sizes, 1 ≤ from ≤ to.');
      const out = await as(async (t) => {
        const n = await log.head(t);
        if (to > n) return { error: 'The tree has only ' + n + ' entries.' };
        return { proof: await log.consistency(t, from, to) };
      });
      return out.error ? bad(res, out.error) : send(res, 200, out.proof, IMMUTABLE);
    }
    if (route.startsWith('receipt/') && route.length > 8) {
      let ref;
      try { ref = decodeURIComponent(route.slice(8)); } catch { ref = null; }
      if (ref === null || ref.length > 100) return bad(res, 'That isn’t a receipt ID.');
      const b = await as((t) => log.bundle(t, ref));
      if (!b) return send(res, 404, { error: 'No log entry has that ID. A receipt’s ID is its post’s ID (36 letters, digits and dashes), an entry’s number, or its leaf hash.' }, SHORT);
      res.setHeader('Content-Disposition', 'inline; filename="' + String(b.entry.seq) + '.dogproof.json"');
      return send(res, 200, b, SHORT);
    }
    return send(res, 404, { error: 'No such log endpoint. See /api/log/checkpoint, /api/log/entries, /api/log/entry/{seq}, /api/log/proof/inclusion, /api/log/proof/consistency and /api/log/receipt/{id}.' }, SHORT);
  } catch (e) {
    // The site reached production before 038: not cached, so it clears itself once 038 is applied.
    if (e && (e.code === '42P01' || e.code === '42883')) return send(res, 503, { error: 'The public log is being switched on. Please try again in a few minutes.' });
    throw e;
  }
}

module.exports = async (req, res) => {
  try {
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) send(res, 500, { error: 'The log couldn’t be read just now. Please try again in a minute.' });
  }
};
module.exports.handle = handle;
