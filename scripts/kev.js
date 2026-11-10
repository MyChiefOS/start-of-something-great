#!/usr/bin/env node
// The daily watch's KEV check (harness/STANDARDS.md gap 8; FedRAMP VDR: fix CISA's Known Exploited Vulnerabilities
// by CISA's due dates). It takes the npm audit answers the watch already made, reads each advisory's CVE from GitHub's
// advisory database (GitHub only: npm audit gives GitHub advisory IDs, not CVEs), and looks each CVE up in CISA's
// public catalog. It only reports, like the rest of the watch.
//
//   node scripts/kev.js <findings out file> <npm audit --json file>...
//
// Findings (a KEV match, or anything not checked) go to the out file, for the alert; the detail goes to stdout, for
// the run's summary. If CISA's catalog can't be read, the finding is "KEV not checked", never a pass.
'use strict';
const fs = require('fs');

// CISA's catalog in JSON, as linked from cisa.gov/known-exploited-vulnerabilities-catalog (checked Nov 10, 2026:
// 200, application/json, catalogVersion 2026.11.09, 1,773 entries). Pinned here and nowhere else.
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CVE = /^CVE-\d{4}-\d{4,}$/;
const GHSA_URL = /^https:\/\/github\.com\/advisories\/(GHSA(?:-[0-9a-z]{4}){3})$/i;

// npm audit --json: { vulnerabilities: { name: { severity, via: [advisory object | name of a dependency] } } }.
function advisories(audit) {
  const out = []; const seen = new Set();
  for (const v of Object.values((audit && audit.vulnerabilities) || {})) {
    for (const via of v.via || []) {
      if (!via || typeof via !== 'object') continue; // a string names the dependency that carries the advisory
      const m = GHSA_URL.exec(String(via.url || ''));
      if (!m) continue;
      const pkg = String(via.name || v.name); const ghsa = m[1];
      if (seen.has(pkg + ' ' + ghsa)) continue;
      seen.add(pkg + ' ' + ghsa);
      out.push({ pkg, severity: String(via.severity || v.severity), ghsa, title: String(via.title || '') });
    }
  }
  return out;
}

// CISA's catalog as a map from CVE ID to its entry. Anything not shaped like it is refused, so a captive portal, an
// error page or a cut-off download can never count as "checked".
function kevIndex(catalog) {
  const bad = (why) => { throw new Error('not CISA\'s catalog: ' + why); };
  if (!catalog || typeof catalog !== 'object' || !Array.isArray(catalog.vulnerabilities)) bad('no vulnerabilities list');
  if (!catalog.vulnerabilities.length) bad('an empty list');
  if (typeof catalog.count === 'number' && catalog.count !== catalog.vulnerabilities.length) bad('count ' + catalog.count + ' but ' + catalog.vulnerabilities.length + ' entries');
  const map = new Map();
  for (const e of catalog.vulnerabilities) {
    if (!e || !CVE.test(String(e.cveID))) bad('an entry without a CVE ID');
    map.set(e.cveID, e);
  }
  map.version = String(catalog.catalogVersion || 'unknown');
  return map;
}

// advs from advisories(); cves: Map GHSA -> { cve: 'CVE-…' | null, published } (missing: the lookup failed);
// kev: kevIndex() or null, with kevError saying why it is null.
function report(advs, cves, kev, kevError) {
  const findings = []; const summary = [];
  if (!kev) {
    findings.push('- KEV not checked: CISA\'s catalog could not be read (' + kevError + '). ' +
      (advs.length ? 'The ' + advs.length + ' advisories found were not compared with it.' : 'No advisories were found today, but none could have been compared.'));
    summary.push('KEV not checked: CISA\'s catalog could not be read (' + kevError + ').');
    return { findings, summary };
  }
  summary.push('KEV: compared with CISA\'s catalog ' + kev.version + ', ' + kev.size + ' entries; ' + (advs.length ? advs.length + ' advisories.' : 'no advisories to compare.'));
  for (const a of advs) {
    const info = cves.get(a.ghsa);
    const who = a.pkg + ', ' + a.ghsa;
    if (!info) { findings.push('- KEV not checked for ' + who + ': its CVE could not be read from GitHub\'s advisory database'); continue; }
    if (!info.cve) { summary.push('- ' + a.pkg + ', ' + a.ghsa + ' (no CVE, ' + a.severity + '): has no CVE, so it can\'t be on KEV'); continue; }
    const k = kev.get(info.cve);
    if (k) findings.push('- ON CISA\'S KEV LIST: ' + who + ' (' + info.cve + ', ' + a.severity + '): added to KEV ' + k.dateAdded + ', CISA\'s due date ' + k.dueDate + ', ransomware use ' + k.knownRansomwareCampaignUse);
    else summary.push('- ' + who + ' (' + info.cve + ', ' + a.severity + '): not on KEV (advisory published ' + (info.published || 'unknown') + ')');
  }
  return { findings, summary };
}

async function main(argv) {
  const [outFile, ...auditFiles] = argv;
  const advs = [];
  for (const f of auditFiles) {
    let audit = null;
    try { audit = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; } // the audit step reports a missing or unreadable answer itself
    for (const a of advisories(audit)) if (!advs.some((x) => x.pkg === a.pkg && x.ghsa === a.ghsa)) advs.push(a);
  }
  let kev = null; let kevError = '';
  try {
    const r = await fetch(KEV_URL, { signal: AbortSignal.timeout(60000) });
    if (!r.ok) throw new Error('GET answered ' + r.status);
    kev = kevIndex(await r.json());
  } catch (e) { kevError = e.message; }
  const cves = new Map();
  if (kev) {
    const headers = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' };
    if (process.env.GH_TOKEN) headers.authorization = 'Bearer ' + process.env.GH_TOKEN;
    for (const ghsa of new Set(advs.map((a) => a.ghsa))) {
      try {
        const r = await fetch('https://api.github.com/advisories/' + ghsa, { headers, signal: AbortSignal.timeout(30000) });
        if (!r.ok) continue;
        const g = await r.json();
        if (String(g.ghsa_id).toUpperCase() !== ghsa.toUpperCase()) continue;
        if (g.cve_id !== null && !CVE.test(String(g.cve_id))) continue;
        cves.set(ghsa, { cve: g.cve_id, published: g.published_at ? String(g.published_at).slice(0, 10) : null });
      } catch { /* left out of cves: reported as "KEV not checked" for that advisory */ }
    }
  }
  const { findings, summary } = report(advs, cves, kev, kevError);
  fs.writeFileSync(outFile, findings.map((l) => l + '\n').join(''));
  console.log(summary.join('\n'));
}

if (require.main === module) main(process.argv.slice(2)).catch((e) => { console.error('KEV check failed: ' + e.message); process.exit(1); });
module.exports = { KEV_URL, advisories, kevIndex, report };
