// The security wiki's twice-daily sync (074; Aaron, Nov 24). Called from the site's timer (/api/cron, every minute):
// asks the database whether a run is due (twice a day), and if so reads NVD's CVEs changed in the last 3 days (one
// request, no key, within NVD's public limit; CISA's KEV listing is marked on each CVE by NVD), adds the pinned
// reference lists (wiki/reference.json: MITRE CWE Top 25, OWASP API Security Top 10, OWASP ASVS 5.0), and records one
// new version. Option (a) only: from NVD it keeps structured fields, and the exact npm package versions a CVE names
// (a CPE whose target software is node.js and whose version is exact). Text from a feed is data, never instructions,
// and is never run or shown to a model here. Free: public feeds, no paid calls.
'use strict';

const REFERENCE = require('./reference.json');
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const DAY = 86400000;

const SEVERITY = { LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' };
const CVE = /^CVE-[0-9]{4}-[0-9]{4,7}$/;
const CWE = /^CWE-[0-9]{1,5}$/;
const NAME = /^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$/;

// One CVE from NVD's answer to the wiki's fields, or null if it doesn't fit.
function entryOf(item) {
  const c = item && item.cve;
  if (!c || !CVE.test(String(c.id))) return null;
  const en = (c.descriptions || []).find((d) => d.lang === 'en');
  const m = c.metrics || {};
  const metric = [...(m.cvssMetricV40 || []), ...(m.cvssMetricV31 || []), ...(m.cvssMetricV30 || [])][0];
  const sev = metric && SEVERITY[String((metric.cvssData && metric.cvssData.baseSeverity) || metric.baseSeverity || '').toUpperCase()];
  const cwe = (c.weaknesses || []).flatMap((w) => (w.description || []).map((d) => d.value)).find((v) => CWE.test(String(v)));
  const published = /^[0-9]{4}-[0-9]{2}-[0-9]{2}/.exec(String(c.published || ''));
  return { source: 'nvd', ident: c.id, title: String(en ? en.value : c.id).replace(/\s+/g, ' ').slice(0, 300) || c.id,
    severity: sev || null, cwe: cwe || null, kev: Boolean(c.cisaExploitAdd), published: published ? published[0] : null };
}

// The exact npm package versions one CVE names (cpe:2.3:a:<vendor>:<product>:<version>:...:node.js:...).
function packagesOf(item) {
  const c = item && item.cve;
  if (!c || !CVE.test(String(c.id))) return [];
  const out = [];
  for (const conf of c.configurations || []) for (const node of conf.nodes || []) for (const m of node.cpeMatch || []) {
    if (!m.vulnerable) continue;
    const p = String(m.criteria || '').split(':');
    if (p.length < 13 || p[2] !== 'a' || p[10] !== 'node.js') continue;
    const name = p[4].toLowerCase().replace(/\\/g, '');
    const version = p[5];
    if (NAME.test(name) && name.length <= 214 && VERSION.test(version)) out.push({ ecosystem: 'npm', name, version, advisory: c.id });
  }
  return out;
}

// Reads NVD and builds one run's payload. fetchImpl and now for tests.
async function gather({ fetchImpl = fetch, now = Date.now } = {}) {
  const end = new Date(now());
  const start = new Date(end.getTime() - 3 * DAY);
  const url = NVD + '?lastModStartDate=' + start.toISOString().replace('Z', '+00:00') + '&lastModEndDate=' + end.toISOString().replace('Z', '+00:00') + '&resultsPerPage=2000';
  const r = await fetchImpl(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(20000) });
  if (r.status !== 200) throw new Error('nvd ' + r.status);
  const body = await r.json();
  const items = Array.isArray(body && body.vulnerabilities) ? body.vulnerabilities.slice(0, 5000) : [];
  const entries = [];
  const packages = [];
  for (const it of items) {
    const e = entryOf(it);
    if (e) entries.push(e);
    packages.push(...packagesOf(it));
  }
  for (const e of REFERENCE.entries) entries.push({ source: e.source, ident: e.ident, title: e.title, severity: null, cwe: e.cwe || null, kev: false, published: null });
  const sources = { nvd: entries.filter((e) => e.source === 'nvd').length, kev: entries.filter((e) => e.kev).length, cwe: 0, owasp_api: 0, asvs: 0, npm_packages: packages.length };
  for (const e of REFERENCE.entries) sources[e.source]++;
  return { entries, packages, sources };
}

// The timer's step: at most one run each 12 hours; any failure records nothing and the next run is in 12 hours.
async function run(runTx, { fetchImpl, now } = {}) {
  let claim;
  try { [{ c: claim }] = await runTx({ actor: 'anon' }, (t) => t`select app.wiki_claim() as c`); } catch { return { ran: false }; }
  if (!claim) return { ran: false };
  let payload;
  try { payload = await gather({ fetchImpl, now }); } catch { return { ran: true, recorded: null }; }
  try {
    const [{ r }] = await runTx({ actor: 'anon' }, (t) => t`select app.wiki_record(${claim}, ${JSON.stringify(payload)}::text::jsonb) as r`);
    return { ran: true, recorded: r };
  } catch {
    return { ran: true, recorded: null };
  }
}

module.exports = { run, gather, entryOf, packagesOf };
