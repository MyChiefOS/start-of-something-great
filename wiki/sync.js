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
const { KEV_URL: KEV } = require('../scripts/kev'); // pinned in one place (the KEV check's own test)
const DAY = 86400000;
// 082: threat feeds for the Wall. Feodo Tracker needs no account (CC0). URLhaus, ThreatFox and MalwareBazaar need an
// abuse.ch key and may need a paid license for commercial use, so they run only when the site has ABUSECH_AUTH_KEY
// (Aaron's call; the key is set in Vercel by him, never seen here).
const FEODO = 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json';
// 083: Spamhaus DROP, hijacked and criminal ranges. Free for any use with credit to The Spamhaus Project (shown on
// /checks); its terms ask for at most one download a day, so it is read on the run before noon UTC and carried over
// from the active version on the other.
const SPAMHAUS = 'https://www.spamhaus.org/drop/drop_v4.json';
const CIDR = /^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\/([89]|[12][0-9]|3[0-2])$/;
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

function isNetwork(cidr) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(String(cidr));
  if (!m) return false;
  const n = Number(m[5]);
  if (n > 32 || m.slice(1, 5).some((x) => Number(x) > 255)) return false;
  const a = ((Number(m[1]) << 24) >>> 0) + (Number(m[2]) << 16) + (Number(m[3]) << 8) + Number(m[4]);
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return ((a & mask) >>> 0) === a;
}

// One indicator to the wiki's fields, or null if it doesn't fit (a feed is data: anything odd is dropped).
function indicatorOf(kind, value, source, ref) {
  let v = String(value == null ? '' : value).trim();
  if (kind !== 'url') v = v.toLowerCase();
  if (kind === 'injection' || kind === 'injection_flag') v = v.replace(/\s+/g, ' ');
  const ok = { ip: IP, cidr: CIDR, domain: DOMAIN, url: URL_RE, sha256: SHA, injection: INJECTION, injection_flag: INJECTION }[kind];
  if (!ok || v.length < 6 || v.length > (kind.startsWith('injection') ? 120 : kind === 'domain' ? 253 : 500) || !ok.test(v)) return null;
  const r = String(ref == null ? '' : ref).replace(/[^A-Za-z0-9 ._:/-]/g, '').slice(0, 60);
  return { kind, value: v, source, ref: REF.test(r) ? r : '' };
}

// The threat feeds. Each one that fails is skipped (and counted as 0); the others still record.
async function feeds({ fetchImpl = fetch, key = process.env.ABUSECH_AUTH_KEY, now = Date.now } = {}) {
  const out = [];
  const counts = { feodo: 0, spamhaus: 0, urlhaus: 0, threatfox: 0, malwarebazaar: 0, keyed_sources: key ? 'on' : 'off' };
  const carry = [];
  // 082 review: each feed's answer is capped at 8 MB before it is parsed, and each feed at a fixed count, so the whole
  // run stays well under the database's 16 MB limit (an oversized feed is skipped; the CVEs still record).
  const get = async (url, init) => {
    const r = await fetchImpl(url, Object.assign({ signal: AbortSignal.timeout(20000) }, init));
    if (r.status !== 200) throw new Error(url + ' ' + r.status);
    const body = typeof r.text === 'function' ? await r.text() : JSON.stringify(await r.json());
    if (body.length > 8000000) throw new Error(url + ' too large');
    return JSON.parse(body);
  };
  const add = (name, x) => { if (x) { out.push(x); counts[name]++; } };
  try {
    const list = await get(FEODO, { headers: { accept: 'application/json' } });
    for (const it of (Array.isArray(list) ? list : []).slice(0, 5000)) add('feodo', indicatorOf('ip', it && it.ip_address, 'feodo', it && it.malware));
  } catch { /* skipped this run */ }
  if (new Date(now()).getUTCHours() < 12) {
    try {
      const r = await fetchImpl(SPAMHAUS, { headers: { accept: 'application/x-ndjson' }, signal: AbortSignal.timeout(20000) });
      if (r.status !== 200) throw new Error('spamhaus ' + r.status);
      const text = await r.text();
      if (text.length > 2000000) throw new Error('spamhaus too large');
      for (const line of text.split('\n').slice(0, 5000)) {
        let o; try { o = JSON.parse(line); } catch { continue; }
        // Only a true network (no host bits set): 1.2.3.4/8 would be refused by the database and lose the whole run.
        if (o && o.cidr && isNetwork(o.cidr)) add('spamhaus', indicatorOf('cidr', o.cidr, 'spamhaus', o.sblid));
      }
    } catch { carry.push('spamhaus'); }
  } else carry.push('spamhaus');
  if (key) {
    const headers = { 'Auth-Key': key, accept: 'application/json' };
    try {
      const b = await get(URLHAUS, { headers });
      for (const u of (b && Array.isArray(b.urls) ? b.urls : []).slice(0, 20000)) if (u && u.url_status !== 'offline') add('urlhaus', indicatorOf('url', u.url, 'urlhaus', u.threat));
    } catch { /* skipped */ }
    try {
      const b = await get(THREATFOX, { method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, headers), body: JSON.stringify({ query: 'get_iocs', days: 3 }) });
      for (const i of (b && Array.isArray(b.data) ? b.data : []).slice(0, 30000)) {
        const t = String(i && i.ioc_type);
        const kind = t === 'domain' ? 'domain' : t === 'url' ? 'url' : t === 'ip:port' ? 'ip' : t === 'sha256_hash' ? 'sha256' : null;
        const v = kind === 'ip' ? String(i.ioc).split(':')[0] : i && i.ioc;
        if (kind) add('threatfox', indicatorOf(kind, v, 'threatfox', i.malware_printable));
      }
    } catch { /* skipped */ }
    try {
      const b = await get(MALWAREBAZAAR, { method: 'POST', headers: Object.assign({ 'content-type': 'application/x-www-form-urlencoded' }, headers), body: 'query=get_recent&selector=time' });
      for (const m of (b && Array.isArray(b.data) ? b.data : []).slice(0, 10000)) add('malwarebazaar', indicatorOf('sha256', m && m.sha256_hash, 'malwarebazaar', m && m.signature));
    } catch { /* skipped */ }
  }
  return { indicators: out, counts, carry };
}

// Reads NVD and builds one run's payload. fetchImpl and now for tests.
async function gather({ fetchImpl = fetch, now = Date.now, key, nvdKey: nvdKeyOpt, pause = (ms) => new Promise((ok) => setTimeout(ok, ms)) } = {}) {
  const end = new Date(now());
  const start = new Date(end.getTime() - 3 * DAY);
  // The offset's plus sign must be encoded: a bare + in a query reads as a space, and NVD answers 404 (found Nov 25: the
  // live wiki had never recorded a version because of it).
  const iso = (d) => encodeURIComponent(d.toISOString().replace('Z', '+00:00'));
  // NVD's limits (developer docs, Nov 25): 2,000 results a page, paged by startIndex up to totalResults; 5 requests in 30
  // seconds without a key, 50 with one (header apiKey). A 3-day window held 5,307 CVEs on Nov 25, so one page missed most
  // of them: read every page, 6.5 s apart without a key (1 s with one), at most 4 pages (8,000 CVEs, about 20 seconds).
  const nvdKey = nvdKeyOpt === undefined ? process.env.NVD_API_KEY : nvdKeyOpt;
  const headers = Object.assign({ accept: 'application/json' }, nvdKey ? { apiKey: nvdKey } : {});
  const items = [];
  for (let page = 0, startIndex = 0; page < 4; page++) {
    if (page > 0) await pause(nvdKey ? 1000 : 6500);
    const url = NVD + '?lastModStartDate=' + iso(start) + '&lastModEndDate=' + iso(end) + '&resultsPerPage=2000&startIndex=' + startIndex;
    const r = await fetchImpl(url, { headers, signal: AbortSignal.timeout(20000) });
    if (r.status !== 200) { if (page === 0) throw new Error('nvd ' + r.status); break; }
    const body = await r.json();
    const got = Array.isArray(body && body.vulnerabilities) ? body.vulnerabilities.slice(0, 2000) : [];
    items.push(...got);
    startIndex += got.length;
    if (!got.length || startIndex >= Number(body.totalResults || 0)) break;
  }
  const entries = [];
  const packages = [];
  for (const it of items) {
    const e = entryOf(it);
    if (e) entries.push(e);
    packages.push(...packagesOf(it));
  }
  // CISA's full Known Exploited Vulnerabilities catalog (public, no key): every listed CVE is kept, not only those NVD
  // changed in the window. One failing read skips it this run.
  try {
    const r = await fetchImpl(KEV, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(20000) });
    if (r.status === 200) {
      const body = await r.json();
      const have = new Map(entries.map((e) => [e.ident, e]));
      for (const v of (body && Array.isArray(body.vulnerabilities) ? body.vulnerabilities : []).slice(0, 5000)) {
        const id = String(v && v.cveID);
        if (!CVE.test(id)) continue;
        if (have.has(id)) { have.get(id).kev = true; continue; }
        const cwe = (Array.isArray(v.cwes) ? v.cwes : []).find((c) => CWE.test(String(c)));
        const added = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.exec(String(v.dateAdded || ''));
        const e = { source: 'nvd', ident: id, title: String(v.vulnerabilityName || id).replace(/\s+/g, ' ').slice(0, 300) || id, severity: null, cwe: cwe || null, kev: true, published: added ? added[0] : null };
        entries.push(e); have.set(id, e);
      }
    }
  } catch { /* skipped this run */ }
  for (const e of REFERENCE.entries) entries.push({ source: e.source, ident: e.ident, title: e.title, severity: null, cwe: e.cwe || null, kev: false, published: null });
  const sources = { nvd: entries.filter((e) => e.source === 'nvd').length, kev: entries.filter((e) => e.kev).length, cwe: 0, owasp_api: 0, asvs: 0, npm_packages: packages.length };
  for (const e of REFERENCE.entries) sources[e.source]++;
  // 082: the threat feeds and the wiki's own injection patterns, for the Wall.
  const f = await feeds({ fetchImpl, key: key === undefined ? process.env.ABUSECH_AUTH_KEY : key, now });
  const indicators = f.indicators;
  for (const p of REFERENCE.injection || []) { const x = indicatorOf('injection', p, 'reference', 'wiki'); if (x) indicators.push(x); }
  for (const p of REFERENCE.injection_flag || []) { const x = indicatorOf('injection_flag', p, 'reference', 'wiki'); if (x) indicators.push(x); }
  Object.assign(sources, f.counts, { injection: (REFERENCE.injection || []).length, injection_flag: (REFERENCE.injection_flag || []).length });
  return { entries, packages, indicators, sources, carry: f.carry };
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
