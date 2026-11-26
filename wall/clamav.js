// The Agentic Wall's antivirus (088; Aaron, Nov 25: "scan files with antivirus engines"; Nov 26 plan, Phase 1 item 3).
// ClamAV, the open-source engine, with its signatures fresh from ClamAV's own free updates (freshclam), runs in the
// GitHub facts workflow on each pull request's changed files. Built into the Wall's pipeline: no outside service, no
// account. A file ClamAV names is W46 (block); if the engine or its signatures aren't there, every file it was asked
// to check gets W46b (flag), so a skipped check is never silent.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// items: [{ key, name, bytes }]. Returns Map key -> [flags]. db: a signature file or folder (tests; normally ClamAV's own).
function scan(items, { bin = 'clamscan', db = null } = {}) {
  const out = new Map();
  const list = (Array.isArray(items) ? items : []).filter((x) => x && Buffer.isBuffer(x.bytes)).slice(0, 400);
  if (!list.length) return out;
  const flagAll = (why) => { for (const x of list) out.set(x.key, [('W46b antivirus check did not run (' + why + '): ' + String(x.name || '')).slice(0, 240)]); return out; };
  let dir;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clam-'));
    list.forEach((x, i) => fs.writeFileSync(path.join(dir, String(i)), x.bytes));
    const r = spawnSync(bin, [...(db ? ['--database=' + db] : []), '--no-summary', '--infected', '--stdout', '--max-filesize=20M', '--max-scansize=60M', dir], { encoding: 'utf8', timeout: 300000, maxBuffer: 4 << 20 });
    if (r.error) return flagAll(String(r.error.code || 'not installed').slice(0, 30));
    // Exit 0: nothing found; 1: something found; anything else: an error (signatures missing, and the like).
    if (r.status !== 0 && r.status !== 1) return flagAll('engine error ' + r.status);
    for (const line of String(r.stdout || '').split('\n')) {
      if (!line.endsWith(' FOUND')) continue;
      const c = line.indexOf(': ');
      if (c === -1) continue;
      const idx = Number(path.basename(line.slice(0, c)));
      const sig = line.slice(c + 2, -6).trim().slice(0, 80);
      const x = list[idx];
      if (!x || !Number.isSafeInteger(idx)) continue;
      out.set(x.key, [...(out.get(x.key) || []), ('W46 antivirus: ClamAV found ' + sig + ': ' + String(x.name || '')).slice(0, 240)].slice(0, 3));
    }
    return out;
  } catch (e) {
    return flagAll(String((e && e.code) || 'error').slice(0, 30));
  } finally {
    if (dir) try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* left for the runner to clear */ }
  }
}

module.exports = { scan };
