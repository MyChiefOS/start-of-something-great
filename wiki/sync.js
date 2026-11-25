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
// 082: threat feeds for the Wall. Feodo Tracker needs no account (CC0). URLhaus, ThreatFox and MalwareBazaar need an
// abuse.ch key and may need a paid license for commercial use, so they run only when the site has ABUSECH_AUTH_KEY
// (Aaron's call; the key is set in Vercel by him, never seen here).
const FEODO = 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json';
const URLHAUS = 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/';
const THREATFOX = 'https://threatfox-api.abuse.ch/api/v1/';
const MALWAREBAZAAR = 'https://mb-api.abuse.ch/api/v1/';
const IP = /^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$/;
const DOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const URL_RE = /^https?:\/\/[^\s"'<>]+$/;
const SHA = /^[0-9a-f]{64}$/;
const INJECTION = /^[!-~]([ -~]*[!-~])?$/; // printable ASCII, matched as a literal phrase (never a pattern)
const REF = /^[A-Za-z0-9 ._:/-]*$/;

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

// One indicator to the wiki's fields, or null if it doesn't fit (a feed is data: anything odd is dropped).
function indicatorOf(kind, value, source, ref) {
  let v = String(value == null ? '' : value).trim();
  if (kind !== 'url') v = v.toLowerCase();
  if (kind === 'injection') v = v.replace(/\s+/g, ' ');
  const ok = { ip: IP, domain: DOMAIN, url: URL_RE, sha256: SHA, injection: INJECTION }[kind];
  if (!ok || v.length < 6 || v.length > (kind === 'injection' ? 120 : kind === 'domain' ? 253 : 500) || !ok.test(v)) return null;
  const r = String(ref == null ? '' : ref).replace(/[^A-Za-z0-9 ._:/-]/g, '').slice(0, 60);
  return { kind, value: v, source, ref: REF.test(r) ? r : '' };
}

// The threat feeds. Each one that fails is skipped (and counted as 0); the others still record.
async function feeds({ fetchImpl = fetch, key = process.env.ABUSECH_AUTH_KEY } = {}) {
  const out = [];
  const counts = { feodo: 0, urlhaus: 0, threatfox: 0, malwarebazaar: 0, keyed_sources: key ? 'on' : 'off' };
  const get = async (url, init) => {
    const r = await fetchImpl(url, Object.assign({ signal: AbortSignal.timeout(20000) }, init));
    if (r.status !== 200) throw new Error(url + ' ' + r.status);
    return r.json();
  };
  const add = (name, x) => { if (x) { out.push(x); counts[name]++; } };
  try {
    const list = await get(FEODO, { headers: { accept: 'application/json' } });
    for (const it of (Array.isArray(list) ? list : []).slice(0, 20000)) add('feodo', indicatorOf('ip', it && it.ip_address, 'feodo', it && it.malware));
  } catch { /* skipped this run */ }
  if (key) {
    const headers = { 'Auth-Key': key, accept: 'application/json' };
    try {
      const b = await get(URLHAUS, { headers });
      for (const u of (b && Array.isArray(b.urls) ? b.urls : []).slice(0, 20000)) if (u && u.url_status !== 'offline') add('urlhaus', indicatorOf('url', u.url, 'urlhaus', u.threat));
    } catch { /* skipped */ }
    try {
      const b = await get(THREATFOX, { method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, headers), body: JSON.stringify({ query: 'get_iocs', days: 3 }) });
      for (const i of (b && Array.isArray(b.data) ? b.data : []).slice(0, 50000)) {
        const t = String(i && i.ioc_type);
        const kind = t === 'domain' ? 'domain' : t === 'url' ? 'url' : t === 'ip:port' ? 'ip' : t === 'sha256_hash' ? 'sha256' : null;
        const v = kind === 'ip' ? String(i.ioc).split(':')[0] : i && i.ioc;
        if (kind) add('threatfox', indicatorOf(kind, v, 'threatfox', i.malware_printable));
      }
    } catch { /* skipped */ }
    try {
      const b = await get(MALWAREBAZAAR, { method: 'POST', headers: Object.assign({ 'content-type': 'application/x-www-form-urlencoded' }, headers), body: 'query=get_recent&selector=time' });
      for (const m of (b && Array.isArray(b.data) ? b.data : []).slice(0, 20000)) add('malwarebazaar', indicatorOf('sha256', m && m.sha256_hash, 'malwarebazaar', m && m.signature));
    } catch { /* skipped */ }
  }
  return { indicators: out, counts };
}

// Reads NVD and builds one run's payload. fetchImpl and now for tests.
async function gather({ fetchImpl = fetch, now = Date.now, key } = {}) {
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
  // 082: the threat feeds and the wiki's own injection patterns, for the Wall.
  const f = await feeds({ fetchImpl, key: key === undefined ? process.env.ABUSECH_AUTH_KEY : key });
  const indicators = f.indicators;
  for (const p of REFERENCE.injection || []) { const x = indicatorOf('injection', p, 'reference', 'wiki'); if (x) indicators.push(x); }
  Object.assign(sources, f.counts, { injection: (REFERENCE.injection || []).length });
  return { entries, packages, indicators, sources };
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

module.exports = { run, gather, entryOf, packagesOf, indicatorOf, feeds };
