// The work module's jobs (042). The timer route (api/cron.js) runs one of them every minute, in its own transaction,
// as an anonymous visitor:
//   * the work timer (app.work_tick: claims whose hold ran out reopen, points whose 72 hours passed become final, and
//     Aaron's daily alert while work waits for him); the database runs it at most once every 50 seconds.
// Since 055 (RISKS.md RK140) the site no longer reads this repository's pull requests and issues for the work module,
// and its role can't record them: GitHub's facts come only from GitHub. The "GitHub facts" workflow
// (.github/workflows/github-facts.yml) runs gather() below inside GitHub, on GitHub's own events and hourly, with the
// workflow's own GitHub token, and sends what it read to the dog-github function (supabase/functions/dog-github), which
// accepts only that workflow on main, proved by GitHub's identity token, and records it as dog_ghsync. Each run reads two
// pages of pull requests, one of issues, and GitHub's read of up to 20 merged pull requests the database asks for
// (app.work_github_wanted: their changed lines, their merge and who merged it, by login and GitHub ID): at most 23 calls
// a run, well inside the 1,000 an hour GitHub gives a workflow's token in one repository (inferred from GitHub's
// published limits). A refused read changes nothing; the database alerts Aaron in-app once a day.
// Only public GitHub data reaches the database, and only these fields: a pull request's number, title (hidden markup,
// contact details and keys removed), author, state, merge, base, merge commit, the issue numbers it names (#N), its
// milestone, its room label and the SHA-256 of any claim codes in its description; never the description itself. From
// GitHub's read of one pull request: its changed lines, state, merge, base, merge commit and who merged it.
// An issue becomes an open task only when it has the "task" label: the repository's other issues (uptime alarms,
// JEVs's alerts, proposals) are the site's own business, not work for the public.
// Since 057 (RK135, RK112) each run also reads, for the database: the changed files of up to 5 merged pull requests
// Third Look is waiting to read (app.tl_files_wanted; each file's name, status, size of change and patch, within
// 80,000 bytes a pull request: a file whose patch doesn't fit is sent without it, so Third Look sees the change wasn't
// read whole and leaves it to a person), and Aaron's decisions on proposals, from the labels of the issues labelled
// "proposal" (api/_proposals.js reads them, as /proposals does). Both are public GitHub data. At most 29 calls a run.
// A failure in one step never stops the other or the timers: it changes nothing, and a later run tries again.
'use strict';

const { stripHidden, maskContacts } = require('../api/_proposals');
const { maskSecrets } = require('../api/_secrets');
const work = require('./work');

const fs = require('fs');
const path = require('path');

// The detail (GitHub's read of one pull request) of at most this many a run: app.work_github_wanted gives at most 20.
const DETAILS = 20;
// The changed files of at most this many pull requests a run (app.tl_files_wanted gives at most 5), each within this
// many bytes of JSON (the database takes at most 100,000).
const FILES = 5;
const FILES_BYTES = 80_000;
// 084: the files of one pull request the Wall scans, and the largest it reads.
const SCAN_FILES = 30;
const SCAN_BYTES = 10 * 1024 * 1024;
// 085 review: a rule matching files in this many pull requests, or this many files, in one run is only flagged.
const MASS_PRS = 3;
const MASS_FILES = 10;
const wallFiles = require('../wall/files');
const DECIDED = new Set(['approved', 'declined', 'shipped']);
const REPO_API = 'https://api.github.com/repos/MyChiefOS/start-of-something-great';

const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const ROOM_LABEL = /^room:\s?([0-9]{2}-0000)$/i;
const TASK_LABEL = 'task';

async function step(name, out, fn) {
  try { out[name] = await fn(); } catch (e) { out[name] = { failed: String((e && (e.code || e.name)) || 'error').replace(/[^A-Za-z0-9_]/g, '').slice(0, 32) }; }
}

const login = (u) => (u && typeof u.login === 'string' && LOGIN.test(u.login) ? u.login.toLowerCase() : null);
const title = (s) => maskContacts(maskSecrets(stripHidden(String(s || '')).text.replace(/\s+/g, ' ').trim()).text).slice(0, 140);
const labelsOf = (x) => (Array.isArray(x.labels) ? x.labels : []).map((l) => String(typeof l === 'string' ? l : (l && l.name) || ''));
const roomOf = (x) => { for (const l of labelsOf(x)) { const m = ROOM_LABEL.exec(l.trim()); if (m) return m[1]; } return null; };
const at = (s) => (typeof s === 'string' && !Number.isNaN(Date.parse(s)) ? new Date(s).toISOString() : null);
const milestone = (m) => (m && Number.isSafeInteger(m.number) && m.number > 0 ? { milestone: m.number, milestone_title: title(m.title) } : { milestone: null, milestone_title: null });
// The issue numbers a pull request names ("#12"), in its title and description: at most 40, written "12,40".
function refsOf(...texts) {
  const out = new Set();
  for (const t of texts) {
    const s = String(t || '');
    for (let i = s.indexOf('#'); i !== -1 && out.size < 40; i = s.indexOf('#', i + 1)) {
      const digit = (ch) => ch >= '0' && ch <= '9';
      let j = i + 1;
      while (j < s.length && digit(s[j])) j++;
      const prev = i > 0 ? s[i - 1] : ' ';
      const wordBefore = digit(prev) || (prev >= 'A' && prev <= 'Z') || (prev >= 'a' && prev <= 'z') || prev === '&';
      // 1 to 7 digits, not starting with 0, not part of a word ("abc#12") or an HTML entity ("&#12;").
      if (j - i - 1 >= 1 && j - i - 1 <= 7 && s[i + 1] !== '0' && !wordBefore) out.add(Number(s.slice(i + 1, j)));
    }
  }
  return [...out].sort((a, b) => a - b).join(',').slice(0, 400);
}

function shapePr(p) {
  const author = login(p.user);
  if (!p || !Number.isSafeInteger(p.number) || p.number < 1 || !author || !['open', 'closed'].includes(p.state)) return null;
  return { number: p.number, title: title(p.title) || 'Pull request', author, state: p.state, merged_at: at(p.merged_at),
    base: String((p.base && p.base.ref) || '').slice(0, 100),
    merge_sha: p.merged_at && typeof p.merge_commit_sha === 'string' && /^[0-9a-f]{40}$/.test(p.merge_commit_sha) ? p.merge_commit_sha : null,
    refs: refsOf(p.title, p.body), ...milestone(p.milestone), room: roomOf(p), created_at: at(p.created_at) || new Date().toISOString(),
    codes: work.codesIn(p.body) };
}
function shapeIssue(x) {
  const author = login(x.user);
  if (!x || x.pull_request || !Number.isSafeInteger(x.number) || x.number < 1 || !author || !['open', 'closed'].includes(x.state)) return null;
  if (!labelsOf(x).some((l) => l.trim().toLowerCase() === TASK_LABEL)) return null;
  return { number: x.number, title: title(x.title) || 'Issue', author, state: x.state, ...milestone(x.milestone), room: roomOf(x),
    created_at: at(x.created_at) };
}
// GitHub's read of one pull request: its changed lines, its merge and who merged it, by login and by GitHub ID (055: a
// pass by rule needs Aaron's account by ID, which a rename doesn't change).
const userId = (u) => (u && Number.isSafeInteger(u.id) && u.id > 0 && u.id < 1e11 ? u.id : null);
function shapeDetail(p) {
  if (!p || !Number.isSafeInteger(p.number) || p.number < 1 || !Number.isSafeInteger(p.additions) || !Number.isSafeInteger(p.deletions)
      || !['open', 'closed'].includes(p.state)) return null;
  const merged = at(p.merged_at);
  return { number: p.number, additions: Math.min(Math.max(p.additions, 0), 99999999), deletions: Math.min(Math.max(p.deletions, 0), 99999999),
    state: p.state, merged_at: merged, base: String((p.base && p.base.ref) || '').slice(0, 100),
    merge_sha: merged && typeof p.merge_commit_sha === 'string' && /^[0-9a-f]{40}$/.test(p.merge_commit_sha) ? p.merge_commit_sha : null,
    merged_by: merged ? login(p.merged_by) : null, merged_by_id: merged ? userId(p.merged_by) : null };
}

// GitHub's list of one pull request's changed files, shaped for Third Look: name, status, size of change and patch.
// Patches are kept in order while they fit in FILES_BYTES; a file whose patch doesn't fit is sent without one. The
// whole list stays under FILES_TOTAL, counted as the database counts it (jsonb's text adds a space after each colon and
// comma, allowed for here), so the database never skips it (057, tl_files_record) (the independent review of PR 2, F5). Files that
// don't fit are left out and one entry without a patch says so, which Third Look reads as "not read whole": a person
// decides.
const FILES_TOTAL = 95_000;
const OMITTED = { filename: '(more changed files than could be sent)', status: 'omitted', changes: 0 };
function shapeFiles(list) {
  if (!Array.isArray(list)) return null;
  const size = (v) => Buffer.byteLength(JSON.stringify(v)) + 8; // + jsonb's spaces and the separator
  const room = FILES_TOTAL - size(OMITTED);
  let bytes = 2;
  const out = [];
  for (const f of list.slice(0, 100)) {
    if (!f || typeof f.filename !== 'string') continue;
    const x = { filename: f.filename.slice(0, 300), status: String(f.status || 'changed').slice(0, 20),
      changes: Number.isSafeInteger(f.changes) && f.changes >= 0 ? f.changes : 0 };
    // 084: the Wall's scan of the file's contents (wall/files.js), made in this workflow.
    if (f.scan && typeof f.scan.type === 'string' && Array.isArray(f.scan.flags)) x.scan = { type: f.scan.type.slice(0, 12), flags: f.scan.flags.slice(0, 20).map((g) => String(g).slice(0, 240)) };
    const base = size(x);
    if (bytes + base > room) { out.push({ ...OMITTED }); return out; }
    const patch = typeof f.patch === 'string' ? Buffer.byteLength(JSON.stringify(f.patch)) + 12 : 0;
    if (patch && bytes + base + patch <= Math.min(FILES_BYTES, room)) { x.patch = f.patch; bytes += patch; }
    bytes += base;
    out.push(x);
  }
  return out;
}

// Aaron's decisions on proposals, from GitHub's labels (api/_proposals.js, as /proposals reads them): number and status.
function shapeProposals(issues) {
  if (!Array.isArray(issues)) return [];
  const { shapeList } = require('../api/_proposals');
  return shapeList(issues).proposals.filter((p) => DECIDED.has(p.status) && Number.isSafeInteger(p.number) && p.number > 0)
    .map((p) => ({ number: p.number, status: p.status })).slice(0, 100);
}

// The work timer, every minute from the timer route. Since 055 it reads nothing from GitHub.
async function run(runDb) {
  const out = {};
  await step('tick', out, () => runDb({ actor: 'anon' }, (t) => t`select app.work_tick() as r`).then((r) => r[0].r));
  // 068: peers' decisions nobody appealed take effect when their window ends.
  await step('peer cases', out, () => runDb({ actor: 'anon' }, (t) => t`select app.peer_cases_due() as r`).then((r) => r[0].r));
  // 075: the watchtower (spam, points-gaming, swarms, repeated Wall flags), every 10 minutes; alerts only.
  await step('watchtower', out, () => runDb({ actor: 'anon' }, (t) => t`select app.watchtower_run() as r`).then((r) => r[0].r));
  // 076: incidents at once, and the daily review digest (lanes A and B, grouped).
  await step('review digest', out, () => runDb({ actor: 'anon' }, (t) => t`select app.review_digest_run() as r`).then((r) => r[0].r));
  return out;
}

// What the GitHub facts workflow reads, inside GitHub. get(path) returns the JSON of GitHub's API for this repository,
// or throws with githubStatus; wanted: the pull request numbers dog-github asked for. Returns the facts, shaped.
// 086: the npm packages a pull request adds to a package.json (its patch's added lines), for OSV.dev. An exact version
// ("1.2.3") is checked as that version; anything else (a range, "latest", a git link) is checked by name alone (086
// review: a range can install any version it allows). Plain string work: no regular expression reads the patch.
function addedPackages(files) {
  const out = [];
  for (const f of files || []) {
    if (!f || typeof f.patch !== 'string' || !(f.filename === 'package.json' || String(f.filename).endsWith('/package.json'))) continue;
    for (const line of f.patch.split('\n')) {
      if (!line.startsWith('+') || line.startsWith('+++')) continue;
      const t = line.slice(1).trim();
      if (t[0] !== '"') continue;
      const a = t.indexOf('"', 1); if (a < 2) continue;
      const name = t.slice(1, a);
      const rest = t.slice(a + 1).trim();
      if (rest[0] !== ':') continue;
      const v = rest.slice(1).trim();
      if (v[0] !== '"') continue;
      const spec = v.slice(1, v.indexOf('"', 1)).trim();
      if (['version', 'node', 'npm', 'name', 'description', 'main', 'license', 'type'].includes(name) || name.length > 214 || !spec) continue;
      const parts = spec.split('.');
      const exact = parts.length === 3 && parts.every((x) => x.length && [...x].every((c) => c >= '0' && c <= '9'));
      out.push({ name, version: exact ? spec : null, spec: spec.slice(0, 60), file: f.filename });
    }
  }
  return out.slice(0, 100);
}

// 086: OSV.dev (no key; GitHub advisories CC-BY 4.0, OpenSSF malicious packages Apache-2.0) on the packages a pull
// request adds. An exact version that is malicious blocks (W25); a range or tag that names a package with any malicious
// version is flagged (W25b), since the version that installs may be an honest one; a known vulnerability in an exact
// version is flagged (W25b). If OSV can't be reached, that is flagged too, so a skipped check is never silent.
async function osvFlags(pkgs, { fetchImpl = globalThis.fetch } = {}) {
  if (!pkgs.length) return [];
  try {
    const r = await fetchImpl('https://api.osv.dev/v1/querybatch', { method: 'POST', signal: AbortSignal.timeout(20_000), headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: pkgs.map((p) => (p.version ? { package: { name: p.name, ecosystem: 'npm' }, version: p.version } : { package: { name: p.name, ecosystem: 'npm' } })) }) });
    if (!r.ok) return unchecked(pkgs, 'OSV answered ' + r.status);
    const b = await r.json();
    const out = [];
    (Array.isArray(b && b.results) ? b.results : []).forEach((res, i) => {
      const ids = (Array.isArray(res && res.vulns) ? res.vulns : []).map((v) => String(v && v.id)).filter((x) => x.length < 60);
      if (!ids.length || !pkgs[i]) return;
      const mal = ids.find((x) => x.startsWith('MAL-'));
      const p = pkgs[i];
      if (p.version) {
        out.push({ file: p.file, flag: (mal ? 'W25 malicious package (OSV ' + mal + '): ' : 'W25b known vulnerability (OSV ' + ids.slice(0, 3).join(', ') + '): ') + p.name + '@' + p.version });
      } else if (mal) {
        out.push({ file: p.file, flag: 'W25b package with a malicious version (OSV ' + mal + '), range ' + p.spec + ': ' + p.name });
      }
    });
    return out;
  } catch (e) { return unchecked(pkgs, 'OSV not reached'); }
}
function unchecked(pkgs, why) {
  return [{ file: pkgs[0].file, flag: ('W25b package check did not run (' + why + '): ' + pkgs.map((p) => p.name).slice(0, 5).join(', ')).slice(0, 240) }];
}

// The repository's own files this workflow checked out (db/ and the rest): honest code no rule may match (085 review).
function repoCanaries() {
  const out = [];
  const root = path.join(__dirname, '..');
  const walk = (d) => { for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true })) {
    if (out.length >= 300) return;
    const p = path.join(d, e.name);
    if (e.isDirectory()) { if (!['node_modules', '.git', 'vendor'].includes(e.name)) walk(p); } else if (e.name.endsWith('.js') || e.name.endsWith('.sql') || e.name.endsWith('.md')) {
      try { const b = fs.readFileSync(path.join(root, p)); if (b.length <= 1024 * 1024) out.push(b); } catch { /* skip */ }
    }
  } };
  try { for (const d of ['db', 'api', 'wall']) if (fs.existsSync(path.join(root, d))) walk(d); } catch { /* fewer canaries */ }
  return out;
}

// 085: YARA Forge's core pack, read once a run (at most 20 MB), its rules prepared by wall/yara.js. 087: if it can't be
// read or doesn't compile, the result says so ({ broken }) and every file scanned that run carries a W42b flag saying
// the signature check didn't run (never silent); wall/files.js still scans them, and the next run tries again.
// 088: pin { tag, sha256 } from the wiki: that exact release is read and its digest checked; a mismatch is a broken
// pack (W42b on every file), never a silent switch to whatever is newest. With no pin, the latest release is read.
async function forgeRules(pin = null, { fetchImpl = globalThis.fetch } = {}) {
  try {
    const yara = require('../wall/yara');
    // Checked character by character, so the pin's shape is tested without a pattern over outside input.
    const only = (v, chars, min, max) => typeof v === 'string' && v.length >= min && v.length <= max && [...v].every((c) => chars.includes(c));
    const TAG = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-';
    const pinned = pin && typeof pin === 'object' && only(pin.tag, TAG, 1, 41) && only(pin.sha256, '0123456789abcdef', 64, 64);
    const url = pinned ? yara.FORGE_RELEASE + encodeURIComponent(pin.tag) + '/yara-forge-rules-core.zip' : yara.FORGE_CORE;
    const r = await fetchImpl(url, { signal: AbortSignal.timeout(30_000), headers: { 'User-Agent': 'dayonegreat-github-facts' } });
    if (!r.ok) return { broken: 'rules not reachable, ' + r.status };
    const zip = Buffer.from(await r.arrayBuffer());
    if (zip.length > 20 * 1024 * 1024) return { broken: 'rules too large' };
    if (pinned && require('crypto').createHash('sha256').update(zip).digest('hex') !== pin.sha256) return { broken: 'rules digest does not match the wiki\'s pin ' + pin.tag };
    const entry = (wallFiles.zipEntries(zip) || []).find((e) => e.name.endsWith('.yar'));
    if (!entry || entry.usize > 40 * 1024 * 1024) return { broken: 'rules file missing or too large' };
    const p = await yara.prepare(wallFiles.zipRead(zip, entry).toString('utf8'), { extraCanaries: repoCanaries() });
    return p.kept || p.broken ? p : { broken: 'no usable rules' };
  } catch { return { broken: 'rules could not be read' }; }
}

// 088: clam: wall/clamav.js's scan (the facts workflow passes it; tests may pass a stand-in). sandbox: the sandbox job's
// findings, { 'number:filename': [flags] }, each kept only if it is W47 or W47b in the Wall's own words. 095: links, the
// link sandbox job's findings, { submission id: { flags, seen } }, each flag kept only if it is W51 or W51b.
async function gather({ get, getRaw = null, wanted = [], files: filesWanted = [], rules = undefined, osvFetch = null, clam = null, sandbox = null, links = null }) {
  let refused = 0;
  const read = (p) => get(p).catch((e) => { if (e && (e.githubStatus === 403 || e.githubStatus === 429)) refused++; return null; });
  const pages = await Promise.all([1, 2].map((n) => read('/pulls?state=all&per_page=100&sort=updated&direction=desc&page=' + n)));
  const prs = pages.map((x) => (Array.isArray(x) ? x : [])).flat().map(shapePr).filter(Boolean).slice(0, 200);
  const iss = await read('/issues?state=all&labels=' + TASK_LABEL + '&per_page=100&sort=updated&direction=desc');
  const issues = (Array.isArray(iss) ? iss : []).map(shapeIssue).filter(Boolean).slice(0, 100);
  const details = [];
  for (const n of (Array.isArray(wanted) ? wanted : []).filter((x) => Number.isSafeInteger(x) && x > 0 && x < 1e7).slice(0, DETAILS)) {
    const d = shapeDetail(await read('/pulls/' + n)); // null when refused: the next run asks again
    if (d) details.push(d);
  }
  const files = [];
  for (const n of (Array.isArray(filesWanted) ? filesWanted : []).filter((x) => Number.isSafeInteger(x) && x > 0 && x < 1e7).slice(0, FILES)) {
    const raw = await read('/pulls/' + n + '/files?per_page=100'); // null when refused: the next run asks again
    // 084: each changed file's contents, scanned by the Wall (real type, archives opened, active documents). At most
    // SCAN_FILES files of at most SCAN_BYTES each per pull request; a file that can't be read isn't scanned, and the
    // Wall flags a changed file it couldn't read (W27).
    if (Array.isArray(raw) && getRaw) {
      if (rules === undefined) rules = await forgeRules();
      let scanned = 0;
      const forClam = [];
      for (const f of raw) {
        if (scanned >= SCAN_FILES || !f || f.status === 'removed' || typeof f.contents_url !== 'string' || !f.contents_url.startsWith(REPO_API + '/contents/')) continue;
        scanned++;
        try {
          const bytes = await getRaw(f.contents_url.slice(REPO_API.length));
          if (bytes && bytes.length <= SCAN_BYTES) {
            f.scan = wallFiles.summary(bytes, f.filename);
            // 085: YARA's malware signatures on the file itself.
            if (rules) for (const g of await require('../wall/yara').scan(rules, bytes, f.filename)) if (f.scan.flags.length < 20) f.scan.flags.push(g);
            forClam.push({ key: f.filename, name: f.filename, bytes, f });
          }
        } catch { /* not scanned: the next run asks again */ }
      }
      // 088: ClamAV on every scanned file of this pull request, in one engine run.
      if (clam && forClam.length) {
        const found = clam(forClam);
        for (const x of forClam) for (const g of found.get(x.key) || []) if (x.f.scan.flags.length < 20) x.f.scan.flags.push(String(g).slice(0, 240));
      }
      // 088: the sandbox's findings for this pull request's files.
      if (sandbox && typeof sandbox === 'object') {
        for (const f of raw) {
          const got = f && Object.prototype.hasOwnProperty.call(sandbox, n + ':' + f.filename) ? sandbox[n + ':' + f.filename] : null;
          if (!Array.isArray(got)) continue;
          for (const g of got.slice(0, 5)) {
            const t = String(g);
            if (!(t.startsWith('W47 sandbox: ') || t.startsWith('W47b sandbox: ')) || t.length > 240) continue;
            f.scan = f.scan || { type: 'other', flags: [] };
            if (f.scan.flags.length < 20) f.scan.flags.push(t);
          }
        }
      }
    }
    // 086: OSV on the packages this pull request adds; the flags go with the package.json that adds them.
    if (Array.isArray(raw) && getRaw) {
      for (const { file, flag } of await osvFlags(addedPackages(raw), osvFetch ? { fetchImpl: osvFetch } : {})) {
        const f = raw.find((x) => x && x.filename === file);
        if (!f) continue;
        f.scan = f.scan || { type: 'other', flags: [] };
        if (f.scan.flags.length < 20) f.scan.flags.push(flag.slice(0, 240));
      }
    }
    const list = shapeFiles(raw);
    if (list) files.push({ number: n, files: list });
  }
  // 085 review: one YARA rule matching across many pull requests or files in one run is more likely a bad rule than
  // that many attacks, so its matches are flagged (W42b), not blocked, for this run; the reviewers see them.
  const hits = new Map();
  for (const pr of files) for (const f of pr.files) for (const g of (f.scan && f.scan.flags) || []) {
    if (!g.startsWith('W42 ')) continue;
    const rule = g.slice(0, g.indexOf(':'));
    const h = hits.get(rule) || { prs: new Set(), n: 0 };
    h.prs.add(pr.number); h.n++; hits.set(rule, h);
  }
  for (const pr of files) for (const f of pr.files) if (f.scan && f.scan.flags) {
    f.scan.flags = f.scan.flags.map((g) => {
      const h = g.startsWith('W42 ') ? hits.get(g.slice(0, g.indexOf(':'))) : null;
      return h && (h.prs.size >= MASS_PRS || h.n >= MASS_FILES) ? ('W42b' + g.slice(3) + ' (matched widely this run: flagged)').slice(0, 240) : g;
    });
  }
  const proposals = shapeProposals(await read('/issues?labels=proposal&state=all&per_page=100&sort=created&direction=desc'));
  return { prs, issues, details, refused, files, proposals, links: linkFindings(links) };
}

// 095: the link sandbox's findings as dog-github takes them: at most 10, each its flags in the sandbox's own words and
// the hosts and links the page reached (for the threat lists). Anything else is dropped here; the database checks again.
function linkFindings(links) {
  if (!links || typeof links !== 'object' || Array.isArray(links)) return [];
  const out = [];
  for (const [id, v] of Object.entries(links)) {
    if (out.length >= 10 || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || !v || typeof v !== 'object') continue;
    const flags = (Array.isArray(v.flags) ? v.flags : []).map(String).filter((t) => (t.startsWith('W51 link sandbox: ') || t.startsWith('W51b link sandbox: ')) && t.length <= 240).slice(0, 10);
    const seen = (Array.isArray(v.seen) ? v.seen : []).map(String).filter((t) => t.length <= 500).slice(0, 50);
    out.push({ id, flags, seen });
  }
  return out;
}

// The facts as dog-github's sync requests: at most 100 pull requests each (the database's limit); the issues, details,
// refused count, changed files and proposal decisions go with the first.
function requests(facts) {
  const out = [];
  for (let i = 0; i < Math.max(facts.prs.length, 1); i += 100) {
    out.push({ mode: 'sync', facts: { prs: facts.prs.slice(i, i + 100), issues: i === 0 ? facts.issues : [], details: i === 0 ? facts.details : [],
      refused: i === 0 ? facts.refused : 0, files: i === 0 ? facts.files || [] : [], proposals: i === 0 ? facts.proposals || [] : [],
      ...(i === 0 && facts.links && facts.links.length ? { links: facts.links } : {}) } });
  }
  return out;
}

// GitHub's API for this repository, with the workflow's own token (read-only here).
function githubGet(token, { fetchImpl = globalThis.fetch, timeoutMs = 20_000 } = {}) {
  return async (p) => {
    const r = await fetchImpl(REPO_API + p, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs), headers: { Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'dayonegreat-github-facts', ...(token ? { Authorization: 'Bearer ' + token } : {}) } });
    if (!r.ok) throw Object.assign(new Error('GitHub returned ' + r.status), { githubStatus: r.status });
    return r.json();
  };
}

// A file's raw bytes (084), with the same token, read-only; at most SCAN_BYTES (a larger answer is cut off and not scanned).
function githubRaw(token, { fetchImpl = globalThis.fetch, timeoutMs = 20_000 } = {}) {
  return async (p) => {
    const r = await fetchImpl(REPO_API + p, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs), headers: { Accept: 'application/vnd.github.raw',
      'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'dayonegreat-github-facts', ...(token ? { Authorization: 'Bearer ' + token } : {}) } });
    if (!r.ok) throw Object.assign(new Error('GitHub returned ' + r.status), { githubStatus: r.status });
    const len = Number(r.headers && r.headers.get ? r.headers.get('content-length') : 0);
    if (len > SCAN_BYTES) return null;
    // Read as a stream and stop past SCAN_BYTES, whether or not GitHub sent a length (084 review).
    if (!r.body || typeof r.body.getReader !== 'function') { const b = Buffer.from(await r.arrayBuffer()); return b.length > SCAN_BYTES ? null : b; }
    const reader = r.body.getReader();
    const parts = []; let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > SCAN_BYTES) { await reader.cancel().catch(() => {}); return null; }
      parts.push(Buffer.from(value));
    }
    return Buffer.concat(parts);
  };
}

// The workflow's step: node db/workjobs.js gather <dog-github's wanted answer> <folder>. Writes 1.json, 2.json, ...:
// the requests to send, in order. Prints counts only.
async function main(argv, env = process.env) {
  if (argv[0] !== 'gather' || argv.length !== 3) throw new Error('usage: node db/workjobs.js gather <wanted.json> <folder>');
  const answer = JSON.parse(fs.readFileSync(argv[1], 'utf8'));
  if (!answer || answer.ok !== true || !Array.isArray(answer.wanted)) throw new Error('dog-github\'s wanted answer is not usable');
  // 088: the antivirus runs when the workflow installed it (WALL_CLAMAV=1); the sandbox job's findings arrive in
  // WALL_SANDBOX as JSON (a broken or missing value means no findings, never a failed run).
  let sandbox = null;
  try { sandbox = env.WALL_SANDBOX ? JSON.parse(env.WALL_SANDBOX) : null; } catch { sandbox = null; }
  // 095: the link sandbox job's findings, the same way.
  let links = null;
  try { links = env.WALL_LINKS ? JSON.parse(env.WALL_LINKS) : null; } catch { links = null; }
  const clam = env.WALL_CLAMAV === '1' ? (items) => require('../wall/clamav').scan(items) : null;
  // 088: the YARA release the wiki pinned (served with the firewall's list), when the site answers.
  let pin = null;
  try { const r = await fetch('https://dayonegreat.com/api/work/wall_edge', { signal: AbortSignal.timeout(15000) }); if (r.ok) { const j = await r.json(); pin = (j && (j.data || j).yara) || null; } } catch { pin = null; }
  const rules = await forgeRules(pin);
  const facts = await gather({ get: githubGet(env.GH_TOKEN || ''), getRaw: githubRaw(env.GH_TOKEN || ''), wanted: answer.wanted, files: Array.isArray(answer.files) ? answer.files : [], clam, sandbox, links, rules });
  const dir = path.resolve(argv[2]);
  fs.mkdirSync(dir, { recursive: true });
  const reqs = requests(facts);
  reqs.forEach((r, i) => fs.writeFileSync(path.join(dir, String(i + 1) + '.json'), JSON.stringify(r)));
  console.log('read ' + facts.prs.length + ' pull requests, ' + facts.issues.length + ' task issues, ' + facts.details.length + ' details, '
    + facts.files.length + ' changed-file lists, ' + facts.proposals.length + ' proposal decisions (' + facts.refused + ' refused); ' + reqs.length + ' request(s)');
}

if (require.main === module) main(process.argv.slice(2)).catch((e) => { console.error(String((e && e.message) || e)); process.exit(1); });

module.exports = { forgeRules, run, gather, requests, linkFindings, githubGet, githubRaw, addedPackages, osvFlags, main, shapePr, shapeIssue, shapeDetail, shapeFiles, shapeProposals, refsOf, DETAILS, FILES, FILES_BYTES, SCAN_FILES, SCAN_BYTES };
