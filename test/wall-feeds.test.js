// 086, the no-account threat feeds and the OSV package check (Aaron, Nov 26: "Lets implement your recommendations").
// No network: every feed is a stub. Covers parsing, the shared-host filter, carry-over, and OSV's three cases.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const zlib = require('zlib');
const sync = require('../wiki/sync');
const { addedPackages, osvFlags } = require('../db/workjobs');

const res = (body, status = 200) => ({ status, ok: status === 200, text: async () => String(body), json: async () => JSON.parse(body), arrayBuffer: async () => body });
function stub(map) {
  return async (url) => {
    for (const [k, v] of Object.entries(map)) if (String(url).startsWith(k)) return typeof v === 'function' ? v(url) : v;
    return res('', 404);
  };
}
const MORNING = () => Date.parse('2026-11-26T06:00:00Z');
const EVENING = () => Date.parse('2026-11-26T18:00:00Z');
const values = (f, source) => (f.groups.find((g) => g.source === source) || { values: [] }).values;

const csv = ['phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target',
  '1,http://evil-login.example/pay,x,t,yes,t,yes,Bank',
  '2,https://docs.google.com/forms/d/abc,x,t,yes,t,yes,Other',
  '3,https://bit.ly/3xyz,x,t,yes,t,yes,Other',
  '4,https://user@phish.sub.dropbox.com/x,x,t,yes,t,yes,Other',
  '5,"http://a.example/a,b",x,t,yes,t,yes,Other'].join('\n');

test('FD1 the lists parse: CERT Polska domains, ET and CINS addresses, PhishTank links, ESET hashes', async () => {
  const sha = 'a'.repeat(64);
  const f = await sync.feeds({ key: '', now: MORNING, fetchImpl: stub({
    'https://hole.cert.pl': res('# comment\nbad-shop.pl\n\nfake-bank.com.pl\n'),
    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt': res('203.0.113.7\n198.51.100.9\n'),
    'https://cinsscore.com': res('192.0.2.44\n'),
    'https://data.phishtank.com': res(zlib.gzipSync(Buffer.from(csv))),
    'https://api.github.com/repos/eset': res(JSON.stringify({ tree: [{ path: 'x/y.sha256' }, { path: 'x/readme.md' }, { path: '../z.sha256' }] })),
    'https://raw.githubusercontent.com/eset/malware-ioc/master/x/y.sha256': res(sha + '  dropper.exe\n'),
    'https://feodotracker': res('[]'), 'https://www.spamhaus.org': res('')
  }) });
  assert.deepStrictEqual(values(f, 'certpl'), ['bad-shop.pl', 'fake-bank.com.pl']);
  assert.deepStrictEqual(values(f, 'et'), ['203.0.113.7', '198.51.100.9']);
  assert.deepStrictEqual(values(f, 'cins'), ['192.0.2.44']);
  assert.deepStrictEqual(values(f, 'eset'), [sha]);
  assert.deepStrictEqual(f.carry, []);
});

test('FD2 a phishing link on a shared platform or a shortener is left out; a quoted link is skipped', async () => {
  const f = await sync.feeds({ key: '', now: MORNING, fetchImpl: stub({ 'https://data.phishtank.com': res(zlib.gzipSync(Buffer.from(csv))) }) });
  const urls = values(f, 'phishtank');
  assert.strictEqual(urls.length, 1);
  assert.ok(urls[0].includes('evil-login.example'));
  for (const u of ['https://docs.google.com/x', 'https://bit.ly/a', 'https://x.dropbox.com', 'https://a@t.co/b', 'http://SITES.GOOGLE.COM:80/p']) assert.ok(sync.sharedHost(u), u);
  for (const u of ['https://google.com.evil.example/', 'https://notgoogle.com/', 'https://dropbox.com.phish.example']) assert.ok(!sync.sharedHost(u), u);
});

test('FD3 a list that fails keeps its last copy (carried over), never emptied', async () => {
  const f = await sync.feeds({ key: '', now: MORNING, fetchImpl: stub({}) });
  for (const s of ['certpl', 'et', 'cins', 'phishtank', 'eset', 'spamhaus']) assert.ok(f.carry.includes(s), s);
  const g = await sync.feeds({ key: '', now: EVENING, fetchImpl: stub({}) });
  for (const s of ['phishtank', 'eset', 'spamhaus']) assert.ok(g.carry.includes(s), 'daily ' + s);
});

test('FD4 the Emerging Threats block file (its DShield part is non-commercial) is not read', async () => {
  const asked = [];
  await sync.feeds({ key: '', now: MORNING, fetchImpl: async (u) => { asked.push(String(u)); return res('', 404); } });
  assert.ok(!asked.some((u) => u.includes('emerging-Block-IPs')));
  assert.ok(asked.some((u) => u.includes('compromised-ips.txt')));
});

const patch = (lines) => [{ filename: 'package.json', patch: lines.map((l) => '+' + l).join('\n') }];

test('FD5 added packages: exact versions keep the version; ranges, tags and links are checked by name', () => {
  const p = addedPackages(patch(['  "flatmap-stream": "0.1.1",', '  "lodash": "^4.17.15",', '  "left-pad": "latest",', '  "x": "github:a/b",', '  "version": "1.0.0",']));
  assert.deepStrictEqual(p.map((x) => [x.name, x.version]), [['flatmap-stream', '0.1.1'], ['lodash', null], ['left-pad', null], ['x', null]]);
});

const osv = (results) => async (url, init) => { osv.last = JSON.parse(init.body); return res(JSON.stringify({ results })); };

test('FD6 OSV: a malicious exact version blocks; a malicious package behind a range is flagged; a vulnerable exact version is flagged', async () => {
  const pkgs = addedPackages(patch(['"bad": "1.0.0",', '"maybe": "^2.0.0",', '"old": "4.17.15",', '"fine": "~1.0.0",']));
  const out = await osvFlags(pkgs, { fetchImpl: osv([{ vulns: [{ id: 'MAL-2025-1' }] }, { vulns: [{ id: 'MAL-2025-2' }, { id: 'GHSA-x' }] }, { vulns: [{ id: 'GHSA-y' }] }, { vulns: [{ id: 'GHSA-z' }] }]) });
  assert.deepStrictEqual(osv.last.queries[1], { package: { name: 'maybe', ecosystem: 'npm' } });
  assert.strictEqual(osv.last.queries[0].version, '1.0.0');
  const f = out.map((x) => x.flag);
  assert.ok(f[0].startsWith('W25 malicious package (OSV MAL-2025-1)'));
  assert.ok(f[1].startsWith('W25b package with a malicious version (OSV MAL-2025-2)'));
  assert.ok(f[2].startsWith('W25b known vulnerability (OSV GHSA-y)'));
  assert.strictEqual(f.length, 3, 'a range with only ordinary advisories says nothing');
});

test('FD7 OSV unreachable or erroring: flagged that the check did not run, never silent', async () => {
  const pkgs = addedPackages(patch(['"a": "1.0.0",']));
  const down = await osvFlags(pkgs, { fetchImpl: async () => { throw new Error('offline'); } });
  assert.ok(down[0].flag.startsWith('W25b package check did not run (OSV not reached)'));
  const err = await osvFlags(pkgs, { fetchImpl: async () => res('', 503) });
  assert.ok(err[0].flag.includes('OSV answered 503'));
  assert.deepStrictEqual(await osvFlags([], { fetchImpl: async () => { throw new Error('never'); } }), []);
});

test('WT1 (Nov 26, Vercel\'s 300 s limit): every download shares one deadline; when feeds hang, the run stops on time and carries the rest over', async () => {
  const sync = require('../wiki/sync');
  let clock = Date.parse('2026-11-26T12:38:00Z');
  const start = clock;
  const asked = [];
  // Every download takes its whole timeout and fails, as if each source hung.
  const fetchImpl = async (url, init) => {
    asked.push(String(url));
    if (/nvd\.nist\.gov|cisa\.gov/.test(String(url))) return { status: 200, json: async () => ({ vulnerabilities: [], totalResults: 0 }), text: async () => '{"vulnerabilities":[]}' };
    clock += 30000;
    throw new Error('timed out');
  };
  let got;
  try { got = await sync.gather({ fetchImpl, key: 'k', nvdKey: '', now: () => clock, pause: async (ms) => { clock += ms; } }); } catch (e) { got = { error: e.message }; }
  assert.ok(clock - start <= sync.GATHER_BUDGET_MS + 30000, 'stopped within the budget: ' + (clock - start) + ' ms');
  assert.ok(sync.GATHER_BUDGET_MS + 60000 < 300000, 'the gather and the 60 s write fit in 300 s');
  assert.ok(!got.error, got.error);
  assert.ok(got.carry.length > 0, 'the feeds that ran out of time carry over');
  assert.ok(asked.length > 3, 'the feeds were tried: ' + asked.length);
});

test('WT2 the timer\'s function asks Vercel for 300 s, the most every plan allows with Fluid compute', () => {
  const v = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, '..', 'vercel.json'), 'utf8'));
  assert.strictEqual(v.functions['api/cron.js'].maxDuration, 300);
});

test('FD6 (Nov 26) today\'s real formats parse, and an afternoon run never asks PhishTank or ESET (why the first live runs after 086 held 0)', async () => {
  // Shapes observed Nov 26, 21:27 UTC: data.phishtank.com answers 302 to a signed cdn.phishtank.com URL serving
  // application/gzip (1.5 MB, 8.2 MB unpacked, 42,542 rows, this header); ESET's tree (truncated: false) nests lists as
  // <family>/samples.sha256 or <group>/<family>/samples.sha256 beside .sha1 and .md5 files, one lowercase hash a line.
  const pt = ['phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target',
    '9565973,https://shop-login.example,http://www.phishtank.com/phish_detail.php?phish_id=9565973,2026-11-26T21:08:11+00:00,yes,2026-11-26T21:11:47+00:00,yes,Allegro',
    '9565971,https://allegro.example-pay.sbs/x,http://www.phishtank.com/phish_detail.php?phish_id=9565971,2026-11-26T21:06:14+00:00,yes,2026-11-26T21:11:47+00:00,yes,Other'].join('\n') + '\n';
  const h1 = 'b'.repeat(64); const h2 = 'c'.repeat(64);
  const map = {
    'https://data.phishtank.com/data/online-valid.csv.gz': res(zlib.gzipSync(Buffer.from(pt))),
    'https://api.github.com/repos/eset/malware-ioc/git/trees/master?recursive=1': res(JSON.stringify({ truncated: false, tree: [
      { path: 'asyncrat', type: 'tree' }, { path: 'asyncrat/samples.sha256', type: 'blob' }, { path: 'asyncrat/samples.sha1', type: 'blob' },
      { path: 'UAC-0099/MATCHBOIL/samples.sha256', type: 'blob' }, { path: 'turla/samples.md5', type: 'blob' }] })),
    'https://raw.githubusercontent.com/eset/malware-ioc/master/asyncrat/samples.sha256': res(h1 + '\n'),
    'https://raw.githubusercontent.com/eset/malware-ioc/master/UAC-0099/MATCHBOIL/samples.sha256': res(h2 + '\n')
  };
  const asked = [];
  const fetchImpl = async (url) => { asked.push(String(url)); return map[String(url)] || res('', 404); };
  const f = await sync.feeds({ key: '', now: MORNING, fetchImpl });
  assert.deepStrictEqual(values(f, 'phishtank').length, 2);
  assert.deepStrictEqual(values(f, 'eset'), [h1, h2]);
  assert.ok(!f.carry.includes('phishtank') && !f.carry.includes('eset'));
  assert.ok(!asked.some((u) => /\.sha1$|\.md5$/.test(u)), 'only the .sha256 lists are read');
  // After noon UTC (the 12:39 UTC run, Nov 26) both are carried over without a request: with no earlier copy, 0 rows.
  asked.length = 0;
  const g = await sync.feeds({ key: '', now: () => Date.parse('2026-11-26T12:39:00Z'), fetchImpl });
  assert.ok(g.carry.includes('phishtank') && g.carry.includes('eset'));
  assert.strictEqual(g.counts.phishtank + g.counts.eset, 0);
  assert.ok(!asked.some((u) => /phishtank|eset/.test(u)), 'not asked after noon');
});
