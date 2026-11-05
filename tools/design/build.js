// node build.js <static dir> <worktree> <design page> <target file> [extra css]
// Writes the production page: the target's existing <head> (title, description, canonical, og, insights) with its
// stylesheets replaced by /design.css, then the design's own wrapper and markup, ported by port.js.
'use strict';
const fs = require('fs');
const path = require('path');
const { port, convert } = require('./port');
const PATCHES = require('./patches');
const [dir, wt, page, target] = process.argv.slice(2);
const src = fs.readFileSync(path.join(dir, page), 'utf8');
// A page with live parts has its production markup in pages/<target>.main.html: the design's own markup, with the ids,
// roles and templates its script needs. Every other page is the design's markup as written.
const own = path.join(__dirname, 'pages', target.replace(/\.html$/, '').replace(/\//g, '_') + '.main.html');
let { body, styles } = fs.existsSync(own) ? convert(fs.readFileSync(own, 'utf8')) : port(src);
for (const [a, b] of PATCHES[target] || []) {
  if (typeof a === 'string' ? !body.includes(a) : !a.test(body)) throw new Error(target + ': patch text not found: ' + a);
  body = body.replace(a, b);
}
const file = path.join(wt, target);
const old = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : fs.readFileSync(path.join(wt, 'team.html'), 'utf8');
let head = old.slice(0, old.indexOf('</head>'));
head = head.replace(/\s*<link rel="stylesheet"[^>]*>/g, '').replace(/(<link rel="preload"[^>]*>)/, '$1\n  <link rel="stylesheet" href="/design.css">');
// Scripts the old page ran after the footer (its own behaviour) stay; nav.js always.
const tail = old.slice(old.lastIndexOf('</footer>'));
const scripts = (tail.match(/<script [^>]*><\/script>/g) || ['<script src="/nav.js" defer></script>']);
// The design's pages mostly carry their own <main class="story" id="main">; the two that don't get a plain one.
const main = /<main[\s>]/.test(body) ? body : '<main id="main" tabindex="-1">\n' + body + '\n</main>';
const out = head + '</head>\n<body>\n<div class="d1"><div class="wrap">\n<!-- shell:top -->\n<!-- /shell:top -->\n'
  + main + '\n<!-- shell:foot -->\n<!-- /shell:foot -->\n</div></div>\n' + scripts.join('\n') + '\n</body>\n</html>\n';
fs.writeFileSync(file, out);
const all = path.join(__dirname, 'styles.json');
const kept = fs.existsSync(all) ? JSON.parse(fs.readFileSync(all, 'utf8')) : {};
Object.assign(kept, styles);
fs.writeFileSync(all, JSON.stringify(kept, null, 1));
console.log('wrote', target, Object.keys(styles).length, 'inline classes');
