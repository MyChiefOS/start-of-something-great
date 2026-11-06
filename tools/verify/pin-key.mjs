#!/usr/bin/env node
// Pin the public log's key in the repository (the independent review of Nov 5, H1): once migration 038 has made the key in
// production, run this and open the pull request it prepares; nothing changes until Aaron merges it.
//   node tools/verify/pin-key.mjs [--site https://dayonegreat.com] [--out verifier/log-key.js]
// It writes verifier/log-key.js only if three sources agree on the key: the site's /api/log/checkpoint, entry 0 of the log
// (the key.registered entry, which must hash to its leaf), and the witness's pin on GitHub (if the witness has run). And
// the latest checkpoint must be signed by it. Any disagreement stops it, with the reason, and writes nothing.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as L from '../../verifier/lib.js';

export async function pinKey({ site = L.SITE, fetchImpl = globalThis.fetch, out } = {}) {
  const get = async (u) => { const r = await fetchImpl(u, { headers: { Accept: 'application/json' } }); if (!r.ok) throw new Error(u + ' answered ' + r.status); return r.json(); };
  const cp = await get(site + '/api/log/checkpoint');
  if (!cp.log_key || !cp.checkpoint) throw new Error('the site has no key or no signed checkpoint yet');
  const k = L.parseVkey(cp.log_key.vkey);
  if (k.name !== L.ORIGIN) throw new Error('the key is named ' + k.name);
  const e0 = await get(site + '/api/log/entry/0');
  if (!e0.entry || e0.entry.type !== 'key.registered' || e0.entry.payload.public_key !== L.b64(k.pub)) throw new Error('entry 0 of the log doesn’t register this key');
  if (L.b64(await L.leafHash(L.utf8(L.jcs(e0.entry)))) !== e0.leaf_hash) throw new Error('entry 0 doesn’t hash to its leaf');
  if (!(await L.checkpointSigned(L.parseCheckpoint(cp.checkpoint.note), k.name, k.pub))) throw new Error('the latest checkpoint isn’t signed by this key');
  const r = await fetchImpl(L.WITNESS.state, {});
  if (r.ok) { const w = await r.json(); if (w.key && w.key !== cp.log_key.vkey) throw new Error('the witness on GitHub pinned another key: ' + w.key); }
  const vkey = await L.vkey(k.name, k.pub);
  const text = fs.readFileSync(new URL('../../verifier/log-key.js', import.meta.url), 'utf8')
    .replace(/^export const PINNED_VKEY = .*;$/m, 'export const PINNED_VKEY = ' + JSON.stringify(vkey) + ';');
  if (out) fs.writeFileSync(out, text);
  return { vkey, text };
}

if (process.argv[1] && process.argv[1].endsWith('pin-key.mjs')) {
  const a = process.argv.slice(2);
  const flag = (n) => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : null; };
  const out = flag('--out') || path.join(path.dirname(fileURLToPath(import.meta.url)), '../../verifier/log-key.js');
  try { const r = await pinKey({ site: flag('--site') || L.SITE, out }); console.log('pinned ' + r.vkey + ' in ' + out + '. Open a pull request with this file for Aaron to approve.'); }
  catch (e) { console.error('not pinned: ' + e.message); process.exitCode = 1; }
}
