#!/usr/bin/env node
// Check a Day One Great receipt from the command line, with the same checks as the Verify page (verifier/lib.js):
//   node tools/verify/dog-verify.mjs <receipt ID | entry number | receipts link | bundle.dogproof.json>
//     --offline          check a bundle file without the network (the witness and consistency checks are skipped)
//     --key <vkey>       require the log's key to be this one (see /security for the published key)
//     --remember <file>  keep the largest checkpoint seen in this file and check every later one against it
//     --site <url>       another copy of the site (default https://dayonegreat.com)
//     --json             print the result as JSON
// Exit code 0 only when every check passes, the key is confirmed and the witness covers the entry ("Verified"); 1 for
// "Verified, not yet witnessed", "Key not confirmed" or "Unverified"; 2 for "Failed"; 3 when the input can't be read.
// Offline, the key is confirmed by --key or by the key pinned in the repository (verifier/log-key.js); online, also by the
// witness's pin on GitHub. A bundle's own key is never enough. Needs Node 20 or later, nothing else.
// (Published only in this repository; an npm package, `npx dog-verify`, needs an npm account Aaron hasn't made.)
import fs from 'node:fs';
import * as L from '../../verifier/lib.js';

const MARK = { pass: 'PASS', fail: 'FAIL', warn: 'WAIT', info: 'NOTE', na: ' -- ' };

// repoPin is for tests only (a log with a key of its own); the command line always uses verifier/log-key.js.
export async function main(argv, { fetchImpl = globalThis.fetch, out = (s) => process.stdout.write(s + '\n'), ...test } = {}) {
  const flag = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
  const offline = argv.includes('--offline');
  const site = (flag('--site') || L.SITE).replace(/\/+$/, '');
  const values = new Set(['--key', '--remember', '--site'].map(flag).filter(Boolean));
  const input = argv.find((a) => !a.startsWith('--') && !values.has(a));
  if (!input) { out('usage: node tools/verify/dog-verify.mjs <receipt ID | entry number | link | bundle.dogproof.json> [--offline] [--key vkey] [--remember file] [--json]'); return 3; }
  let bundle;
  try {
    if (fs.existsSync(input)) bundle = JSON.parse(fs.readFileSync(input, 'utf8'));
    else {
      if (offline) throw new Error('offline, a receipt can only be checked from a bundle file');
      const m = input.match(/(?:receipts\/|receipt\?post=)([^/?#]+)/);
      const id = m ? decodeURIComponent(m[1]) : input;
      const r = await fetchImpl(site + '/api/log/receipt/' + encodeURIComponent(id), { headers: { Accept: 'application/json' } });
      if (r.status === 404) throw new Error('no log entry has the ID ' + id);
      if (!r.ok) throw new Error('the site answered ' + r.status);
      bundle = await r.json();
    }
  } catch (e) { out('Can’t read the receipt: ' + e.message); return 3; }
  const rememberFile = flag('--remember');
  let memory = null;
  if (rememberFile && fs.existsSync(rememberFile)) { try { memory = JSON.parse(fs.readFileSync(rememberFile, 'utf8')); } catch { memory = null; } }
  const res = await L.verifyBundle(bundle, { fetch: offline ? null : fetchImpl, site, memory, pinnedKey: flag('--key'), ...('repoPin' in test ? { repoPin: test.repoPin } : {}) });
  if (rememberFile && res.memory) fs.writeFileSync(rememberFile, JSON.stringify(res.memory) + '\n');
  if (argv.includes('--json')) out(JSON.stringify(res, null, 2));
  else {
    out(L.LABELS[res.status] + ': ' + res.reason);
    res.steps.forEach((s, i) => out(MARK[s.state] + '  ' + (i + 1) + '. ' + s.title + ': ' + s.text));
  }
  return res.status === 'verified' ? 0 : res.status === 'failed' ? 2 : 1;
}

if (process.argv[1] && process.argv[1].endsWith('dog-verify.mjs')) process.exitCode = await main(process.argv.slice(2));
