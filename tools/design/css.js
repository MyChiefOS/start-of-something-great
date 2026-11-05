// node css.js <design static dir> <site dir>: writes <site>/design.css from the design's stylesheet and every inline
// style the design uses anywhere (all 52 pages, header and footer included) plus the production templates in pages/.
// Generated pages (scripts/pages.js) may only use these declarations: shell.cls() of one of them.
'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { cls } = require('./port');
const [dir, site] = process.argv.slice(2);
const styles = {};
const add = (html) => { for (const m of html.matchAll(/ style="([^"]*)"/g)) { const d = m[1].trim().replace(/;$/, ''); styles[cls(d)] = d; } };
for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.html'))) add(fs.readFileSync(path.join(dir, f), 'utf8'));
const pages = path.join(__dirname, 'pages');
for (const f of fs.readdirSync(pages).filter((x) => x.endsWith('.html'))) add(fs.readFileSync(path.join(pages, f), 'utf8'));
const json = path.join(__dirname, 'styles.json');
fs.writeFileSync(json, JSON.stringify(styles, null, 1));
execFileSync(process.execPath, [path.join(__dirname, 'mkcss.js'), path.join(dir, 'css/styles.css'), path.join(site, 'styles.css'), json, path.join(site, 'design.css')], { stdio: 'inherit' });
