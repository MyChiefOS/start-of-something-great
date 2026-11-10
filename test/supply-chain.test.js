// STANDARDS.md gap 8 (SSDF PS.3, OWASP A03, FedRAMP VDR), with no new outside service: a software bill of materials
// from the lockfile on every CI run, a lockfile that only names the npm registry, and the daily watch flagging any
// advisory whose CVE is on CISA's Known Exploited Vulnerabilities list, saying "KEV not checked" when it can't tell.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

// ---- The SBOM

test('SBOM: CI makes a CycloneDX and an SPDX bill of materials from package-lock.json and keeps it as an artifact', () => {
  const y = read('.github/workflows/checks.yml');
  const [checksJob, sbomJob] = y.split(/^  sbom:$/m);
  assert.ok(sbomJob, 'a separate sbom job');
  assert.doesNotMatch(checksJob, /npm sbom --/, 'not in the required checks job: a failure here alerts, it never blocks the gate');
  assert.match(sbomJob, /npm sbom --package-lock-only --sbom-format cyclonedx/);
  assert.match(sbomJob, /npm sbom --package-lock-only --sbom-format spdx/);
  assert.match(sbomJob, /uses: actions\/upload-artifact@[0-9a-f]{40} # v4\.6\.2/);
  assert.match(sbomJob, /if-no-files-found: error/);
  assert.match(sbomJob, /persist-credentials: false/);
  // The required checks step keeps Semgrep on line 97, where the build instructions read it from.
  assert.match(y.split('\n')[96], /^\s+semgrep scan --config \.semgrep\//);
});

test('SBOM: the command CI runs works on this lockfile with this npm, and lists every locked package with its hash', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-'));
  const d = path.join(dir, 'dayonegreat');
  try {
    fs.mkdirSync(d);
    for (const f of ['package.json', 'package-lock.json']) fs.copyFileSync(path.join(root, f), path.join(d, f));
    const npm = (args) => execFileSync('npm', args, { cwd: d, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    npm(['pkg', 'set', 'version=0.0.0-git.test']);
    const bom = JSON.parse(npm(['sbom', '--package-lock-only', '--sbom-format', 'cyclonedx', '--sbom-type', 'application']));
    const lockPkgs = Object.entries(JSON.parse(read('package-lock.json')).packages).filter(([k]) => k);
    assert.strictEqual(bom.bomFormat, 'CycloneDX');
    assert.strictEqual(bom.metadata.component.name, 'dayonegreat');
    assert.strictEqual(bom.components.length, lockPkgs.length);
    for (const [k, v] of lockPkgs) {
      const name = k.replace(/^.*node_modules\//, '');
      const c = bom.components.find((x) => x.name === name && x.version === v.version);
      assert.ok(c, name + '@' + v.version + ' is in the SBOM');
      // A scoped package's "@" is written %40 in a package URL, as the purl standard says (seen once ESLint brought the
      // first scoped packages).
      assert.strictEqual(c.purl, 'pkg:npm/' + name.replace(/^@/, '%40') + '@' + v.version);
      const hex = Buffer.from(v.integrity.replace(/^sha512-/, ''), 'base64').toString('hex');
      assert.deepStrictEqual(c.hashes, [{ alg: 'SHA-512', content: hex }], name + ': the lockfile\'s sha512');
    }
    const spdx = JSON.parse(npm(['sbom', '--package-lock-only', '--sbom-format', 'spdx', '--sbom-type', 'application']));
    assert.match(spdx.spdxVersion, /^SPDX-2\./);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---- The lockfile: what a Dependabot pull request (or anyone's) may put there

test('lockfile: every locked package comes from the npm registry with a sha512 hash, and none runs install scripts', () => {
  const lock = JSON.parse(read('package-lock.json'));
  assert.strictEqual(lock.lockfileVersion, 3);
  for (const [k, v] of Object.entries(lock.packages)) {
    if (!k) continue;
    assert.match(v.resolved || '', /^https:\/\/registry\.npmjs\.org\/(@[a-z0-9._-]+\/)?[a-z0-9._-]+\/-\/[a-z0-9._-]+\.tgz$/, k + ' resolves to the npm registry');
    assert.match(v.integrity || '', /^sha512-[A-Za-z0-9+/]+=*$/, k + ' has a sha512 integrity hash');
    assert.ok(!v.hasInstallScript, k + ' runs an install script');
  }
});

// ---- KEV in the daily watch

const kev = require('../scripts/kev');

const audit = {
  vulnerabilities: {
    postgres: { name: 'postgres', severity: 'high', via: [
      { source: 1, name: 'postgres', title: 'A flaw', url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', severity: 'high' },
      { source: 2, name: 'postgres', title: 'Another', url: 'https://github.com/advisories/GHSA-dddd-eeee-ffff', severity: 'moderate' }] },
    wrapper: { name: 'wrapper', severity: 'high', via: ['postgres'] },
  },
};
const catalog = { title: 'CISA Catalog of Known Exploited Vulnerabilities', catalogVersion: '2026.11.09', count: 2, vulnerabilities: [
  { cveID: 'CVE-2026-0001', dateAdded: '2026-11-01', dueDate: '2026-11-22', knownRansomwareCampaignUse: 'Known' },
  { cveID: 'CVE-2025-9999', dateAdded: '2025-01-01', dueDate: '2025-01-22', knownRansomwareCampaignUse: 'Unknown' }] };

test('KEV: CISA\'s catalog address is pinned in one place, scripts/kev.js', () => {
  assert.strictEqual(kev.KEV_URL, 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  const hits = [];
  const walk = (d) => { for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) { if (!['node_modules', '.git', 'test', 'research', 'design'].includes(e.name)) walk(p); }
    else if (/\.(js|mjs|ts|yml|yaml|json)$/.test(e.name) && read(p).includes('known_exploited_vulnerabilities.json')) hits.push(p);
  } };
  walk('.');
  assert.deepStrictEqual(hits, [path.join('scripts', 'kev.js')]);
});

test('KEV: advisories are read from npm audit\'s JSON by their GitHub advisory ID, once each', () => {
  assert.deepStrictEqual(kev.advisories(audit), [
    { pkg: 'postgres', severity: 'high', ghsa: 'GHSA-aaaa-bbbb-cccc', title: 'A flaw' },
    { pkg: 'postgres', severity: 'moderate', ghsa: 'GHSA-dddd-eeee-ffff', title: 'Another' }]);
  assert.deepStrictEqual(kev.advisories({}), []);
  assert.deepStrictEqual(kev.advisories(null), []);
});

test('KEV: a catalog that is not CISA\'s shape is refused, so it can never pass as checked', () => {
  assert.strictEqual(kev.kevIndex(catalog).get('CVE-2026-0001').dueDate, '2026-11-22');
  for (const bad of [null, {}, { vulnerabilities: [] }, { vulnerabilities: [{ cve: 'x' }] }, { count: 5, vulnerabilities: catalog.vulnerabilities }, '<html>']) {
    assert.throws(() => kev.kevIndex(bad), /not CISA's catalog/, JSON.stringify(bad));
  }
});

test('KEV: an advisory whose CVE is on the list is flagged with CISA\'s dates', () => {
  const cves = new Map([['GHSA-aaaa-bbbb-cccc', { cve: 'CVE-2026-0001', published: '2026-10-30' }], ['GHSA-dddd-eeee-ffff', { cve: 'CVE-2026-0002', published: '2026-10-01' }]]);
  const { findings, summary } = kev.report(kev.advisories(audit), cves, kev.kevIndex(catalog), null);
  assert.deepStrictEqual(findings, ['- ON CISA\'S KEV LIST: postgres, GHSA-aaaa-bbbb-cccc (CVE-2026-0001, high): added to KEV 2026-11-01, CISA\'s due date 2026-11-22, ransomware use Known']);
  assert.match(summary.join('\n'), /GHSA-dddd-eeee-ffff \(CVE-2026-0002, moderate\): not on KEV/);
  assert.match(summary.join('\n'), /catalog 2026\.11\.09, 2 entries/);
});

test('KEV: if the catalog could not be read, the finding is "KEV not checked", never a pass, with or without advisories', () => {
  for (const advs of [kev.advisories(audit), []]) {
    const { findings } = kev.report(advs, new Map(), null, 'GET answered 503');
    assert.strictEqual(findings.length, 1);
    assert.match(findings[0], /^- KEV not checked: CISA's catalog could not be read \(GET answered 503\)/);
  }
});

test('KEV: an advisory whose CVE could not be read from GitHub is "KEV not checked" for that advisory; one with no CVE says so', () => {
  const cves = new Map([['GHSA-aaaa-bbbb-cccc', { cve: null, published: '2026-10-30' }]]);
  const { findings, summary } = kev.report(kev.advisories(audit), cves, kev.kevIndex(catalog), null);
  assert.deepStrictEqual(findings, ['- KEV not checked for postgres, GHSA-dddd-eeee-ffff: its CVE could not be read from GitHub\'s advisory database']);
  assert.match(summary.join('\n'), /GHSA-aaaa-bbbb-cccc \(no CVE, high\): has no CVE, so it can't be on KEV/);
});

test('KEV: nothing to flag gives no finding, and the summary says what was checked', () => {
  const { findings, summary } = kev.report([], new Map(), kev.kevIndex(catalog), null);
  assert.deepStrictEqual(findings, []);
  assert.match(summary.join('\n'), /no advisories to compare/);
});

test('KEV: the daily watch runs the check in the dependency audit, and a crash still reports "KEV not checked"', () => {
  const y = read('.github/workflows/watch.yml');
  const step = y.split('- name: Dependency audit')[1].split('\n      - name: ')[0];
  assert.match(step, /node scripts\/kev\.js kev\.txt root\.json fn\.json > kev-summary\.txt 2>&1 \|\| echo "- KEV not checked: [^"]+" >> kev\.txt/);
  assert.match(step, /cat kev\.txt >> audit\.txt/);
  assert.match(step, /GH_TOKEN: \$\{\{ github\.token \}\}/);
  assert.ok(step.indexOf('report "the site') < step.indexOf('node scripts/kev.js'), 'after the audits it reads');
});
