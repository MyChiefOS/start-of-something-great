// S10 gate: reads CodeQL's SARIF files and fails if any finding is critical (security severity 9.0 or more, the CVSS
// critical band). Lower findings are listed for the risk register (RISKS.md) but don't block.
// Usage: node scripts/sarif-gate.js <directory or .sarif file>
'use strict';

const fs = require('fs');
const path = require('path');

const CRITICAL = 9.0;

function files(target) {
  const st = fs.statSync(target);
  if (st.isFile()) return [target];
  return fs.readdirSync(target).filter((f) => f.endsWith('.sarif')).map((f) => path.join(target, f));
}

// Every result with its rule's security severity (from the rule's properties, as CodeQL writes them).
function findings(sarif) {
  const out = [];
  for (const run of sarif.runs || []) {
    const rules = new Map();
    for (const r of (run.tool && run.tool.driver && run.tool.driver.rules) || []) rules.set(r.id, r);
    for (const ext of (run.tool && run.tool.extensions) || []) for (const r of ext.rules || []) rules.set(r.id, r);
    for (const res of run.results || []) {
      const rule = rules.get(res.ruleId) || (res.rule && rules.get(res.rule.id)) || {};
      const sev = Number((rule.properties || {})['security-severity'] || (res.properties || {})['security-severity'] || 0);
      const loc = (((res.locations || [])[0] || {}).physicalLocation || {});
      out.push({ rule: res.ruleId, severity: sev, file: (loc.artifactLocation || {}).uri || '?', line: (loc.region || {}).startLine || 0,
        message: ((res.message || {}).text || '').slice(0, 200) });
    }
  }
  return out;
}

function gate(target) {
  const all = files(target).flatMap((f) => findings(JSON.parse(fs.readFileSync(f, 'utf8'))));
  return { all, critical: all.filter((x) => x.severity >= CRITICAL) };
}

if (require.main === module) {
  const target = process.argv[2];
  if (!target) { console.error('usage: node scripts/sarif-gate.js <dir or file>'); process.exit(2); }
  const { all, critical } = gate(target);
  for (const x of all) console.log((x.severity >= CRITICAL ? 'CRITICAL ' : 'finding  ') + x.severity.toFixed(1) + ' ' + x.rule + ' ' + x.file + ':' + x.line + ' ' + x.message);
  console.log(all.length + ' findings, ' + critical.length + ' critical');
  process.exit(critical.length ? 1 : 0);
}

module.exports = { gate, findings, CRITICAL };
