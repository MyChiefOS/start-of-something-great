// Prints the golden set (heal/golden.json) as the lines migration 096 seeds into app.heal_golden, one per row.
'use strict';
const g = require('./golden.json');

function lines() {
  const out = [...g.base];
  for (const t of g.tools) for (const p of g.packages.slice(0, 7)) out.push(t + (t === 'go' ? ' get ' : ' install ') + p);
  for (const tp of g.topics) {
    out.push('Write-up: how we added ' + tp + ' to the site, and what it costs.');
    out.push('Question: what is a good default for ' + tp + ' in a small web app?');
    out.push('Checklist item done: ' + tp + ' reviewed against NIST SSDF.');
    out.push('PR: tests for ' + tp + ', all green.');
    out.push('Reading list on ' + tp + ' for new contributors.');
  }
  return out;
}
module.exports = { lines };
if (require.main === module) {
  const q = (s) => "('" + s.replace(/'/g, "''") + "')";
  process.stdout.write('insert into app.heal_golden (line) values\n  ' + lines().map(q).join(',\n  ') + ';\n');
}
