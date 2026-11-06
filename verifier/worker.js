// The Verify page's worker (CODING_AGENT_SPEC.md 1.5): every check runs here, off the page's thread, with
// verifier/lib.js. The page sends { id, input, memory } where input is { bundle } (pasted or dropped: never sent
// anywhere) or { ref } (a receipt ID, entry number, leaf hash or link: its bundle is fetched from this site). The worker
// answers { id, type: 'step', step } as each check finishes, then { id, type: 'done', result, bundle } or
// { id, type: 'error', code, message }. It fetches only this site's /api/log (the bundle and consistency proofs) and
// the witness's copy on GitHub (raw.githubusercontent.com), at addresses written in lib.js.
import * as L from './lib.js';

const ERR = {
  json: 'That isn’t valid JSON. Paste a whole proof bundle (a .dogproof.json file’s contents), or just a receipt’s ID.',
  ref: 'That isn’t a receipt ID, an entry number, a leaf hash or a receipts link.',
  unknown: 'No entry in the log has that ID. A receipt’s ID is its post’s ID: 36 letters, digits and dashes, shown on every receipt.',
  network: 'The site didn’t answer, so the receipt’s proof couldn’t be fetched. Check your connection and try again; a bundle file can be checked offline with the command line.',
  busy: 'The log is busy. Please wait a minute, then try again.',
  server: 'The site couldn’t make the proof just now. Please try again in a minute.'
};

export function refOf(text) {
  const s = String(text || '').trim();
  const link = s.match(/(?:\/receipts\/|receipt\?post=)([^/?#\s]+)/);
  const v = link ? decodeURIComponent(link[1]) : s;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return v.toLowerCase();
  if (/^(0|[1-9][0-9]{0,14})$/.test(v) || /^proposal-[1-9][0-9]{0,7}$/.test(v)) return v;
  if (/^(?:sha256:)?[0-9a-f]{64}$/i.test(v)) return v.replace(/^sha256:/i, '').toLowerCase();
  if (/^[A-Za-z0-9+/]{43}=$/.test(v)) return v;
  return null;
}

async function run({ id, input, memory }) {
  const say = (m) => self.postMessage({ id, ...m });
  let bundle = input && input.bundle;
  if (!bundle) {
    const ref = refOf(input && input.ref);
    if (!ref) return say({ type: 'error', code: 'ref', message: ERR.ref });
    let r;
    try { r = await fetch('/api/log/receipt/' + encodeURIComponent(ref), { headers: { Accept: 'application/json' } }); }
    catch { return say({ type: 'error', code: 'network', message: ERR.network }); }
    if (r.status === 404) return say({ type: 'error', code: 'unknown', message: ERR.unknown });
    if (r.status === 429) return say({ type: 'error', code: 'busy', message: ERR.busy });
    if (!r.ok) return say({ type: 'error', code: 'server', message: ERR.server + ' (' + r.status + (r.headers.get('x-vercel-id') ? ', reference ' + r.headers.get('x-vercel-id') : '') + ')' });
    try { bundle = await r.json(); } catch { return say({ type: 'error', code: 'server', message: ERR.server }); }
  }
  const result = await L.verifyBundle(bundle, { fetch: (u, o) => fetch(u, o), site: '', memory, onStep: (step) => say({ type: 'step', step }) });
  say({ type: 'done', result, bundle });
}

self.onmessage = (ev) => {
  const m = ev.data || {};
  if (m.type === 'parse') {
    try { self.postMessage({ id: m.id, type: 'parsed', bundle: JSON.parse(m.text) }); }
    catch { self.postMessage({ id: m.id, type: 'error', code: 'json', message: ERR.json }); }
    return;
  }
  run(m).catch(() => self.postMessage({ id: m.id, type: 'error', code: 'server', message: 'The checks stopped unexpectedly. Please reload the page and try again.' }));
};
