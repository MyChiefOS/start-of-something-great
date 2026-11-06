// node css.js <design static dir> <site dir>: writes <site>/design.css: the design's stylesheet (mkcss.js) and the
// inline styles several pages share (used on 3 or more of the 52 design pages, which takes in the header and footer,
// or used by the generated pages: scripts/pages.js's X('...') calls). A style only one or two pages use goes in that
// page's own /css/<page>.css, written by build.js, so no page carries the other pages' styles.
'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { cls } = require('./port');
const [dir, site] = process.argv.slice(2);
const uses = {};
const decls = {};
for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.html'))) {
  const seen = new Set();
  for (const m of fs.readFileSync(path.join(dir, f), 'utf8').matchAll(/ style="([^"]*)"/g)) { const d = m[1].trim().replace(/;$/, ''); decls[cls(d)] = d; seen.add(cls(d)); }
  for (const c of seen) uses[c] = (uses[c] || 0) + 1;
}
const shared = {};
for (const c of Object.keys(decls)) if (uses[c] >= 3) shared[c] = decls[c];
const gen = fs.readFileSync(path.join(site, 'scripts/pages.js'), 'utf8');
for (const m of gen.matchAll(/X\('([^']+)'\)/g)) shared[cls(m[1])] = m[1];
const json = path.join(__dirname, 'shared.json');
fs.writeFileSync(json, JSON.stringify(shared, null, 1));
execFileSync(process.execPath, [path.join(__dirname, 'mkcss.js'), path.join(dir, 'css/styles.css'), path.join(site, 'styles.css'), json, path.join(site, 'design.css')], { stdio: 'inherit' });
