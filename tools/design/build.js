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
// The page as it was before the rebuild (PR #100's tip, c5018bb), for two things the design's static copy can't carry:
// the ids other pages link to (/team#levels, /connect#add) and the exact addresses of its links (/join?here=1).
function before(t) {
  try { return require('child_process').execFileSync('git', ['-C', wt, 'show', 'c5018bb:' + t], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch (e) { return ''; }
}
const was = before(target);
const plain = (h) => h.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
for (const m of was.matchAll(/<(h[1-4])([^>]*) id="([^"]+)"([^>]*)>([\s\S]*?)<\/\1>/g)) {
  const text = plain(m[5]);
  body = body.replace(new RegExp('<' + m[1] + '((?: class="[^"]*")?)>((?:(?!</' + m[1] + '>)[\\s\\S])*?)</' + m[1] + '>', 'g'), (all, c, inner) => (plain(inner) === text && !/ id="/.test(all) ? '<' + m[1] + c + ' id="' + m[3] + '">' + inner + '</' + m[1] + '>' : all));
}
const hrefs = {};
for (const m of was.matchAll(/<a [^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g)) { const t = plain(m[2]); if (t && /[?#]/.test(m[1]) && !hrefs[t]) hrefs[t] = m[1]; }
body = body.replace(/<a ([^>]*)href="([^"]+)"([^>]*)>([\s\S]*?)<\/a>/g, (all, a, h, b, inner) => {
  const old = hrefs[plain(inner)];
  return old && old.split(/[?#]/)[0] === h.split(/[?#]/)[0] && old !== h ? '<a ' + a + 'href="' + old + '"' + b + '>' + inner + '</a>' : all;
});
const file = path.join(wt, target);
const old = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : fs.readFileSync(path.join(wt, 'team.html'), 'utf8');
let head = old.slice(0, old.indexOf('</head>'));
// A page with parts the design doesn't style (the paper's figures and maths) also loads its own sheet.
const EXTRA = { 'research/decision-loop.html': ['/paper.css'] };
// The page's own inline styles (those design.css doesn't share) go in /css/<page>.css.
const shared = fs.existsSync(path.join(__dirname, 'shared.json')) ? JSON.parse(fs.readFileSync(path.join(__dirname, 'shared.json'), 'utf8')) : {};
const mine = {};
for (const [c, d] of Object.entries(styles)) if (!shared[c]) mine[c] = d;
const slug = target.replace(/\.html$/, '').replace(/\//g, '-');
const ownCss = path.join(wt, 'css', slug + '.css');
if (Object.keys(mine).length) {
  fs.mkdirSync(path.dirname(ownCss), { recursive: true });
  fs.writeFileSync(ownCss, '/* ' + target + ': its own inline styles from Aaron\'s design, as classes. Written by tools/design/build.js. */\n' + require("./mkcss").classes(mine));
  EXTRA[target] = (EXTRA[target] || []).concat('/css/' + slug + '.css');
} else if (fs.existsSync(ownCss)) fs.unlinkSync(ownCss);
head = head.replace(/\s*<link rel="stylesheet"[^>]*>/g, '').replace(/(<link rel="preload"[^>]*>)/, '$1\n  <link rel="stylesheet" href="/design.css">' + (EXTRA[target] || []).map((h) => '\n  <link rel="stylesheet" href="' + h + '">').join(''));
// Scripts the old page ran after the footer (its own behaviour) stay; nav.js always.
const tail = old.slice(old.lastIndexOf('</footer>'));
const wasTail = was ? was.slice(was.lastIndexOf('</footer>')) : tail;
// A page that ran no script before (the 404, Terms, Privacy, the paper: the Menu is a <details>, so it needs none) runs none.
const scripts = was ? (wasTail.match(/<script [^>]*><\/script>/g) || []) : (tail.match(/<script [^>]*><\/script>/g) || ['<script src="/nav.js" defer></script>']);
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
