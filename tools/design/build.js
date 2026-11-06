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
// What the page carried before the rebuild (PR #100's tip, c5018bb) that the design's static copy can't: the ids other
// pages link to (/team#levels, /connect#add), the exact addresses of its links (/join?here=1) and the scripts it ran.
// Read once from git into before.json, which is committed, so a rebuild needs no history (CI checks out one commit).
const plain = (h) => h.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
const BEFORE_FILE = path.join(__dirname, 'before.json');
const BEFORE = fs.existsSync(BEFORE_FILE) ? JSON.parse(fs.readFileSync(BEFORE_FILE, 'utf8')) : {};
if (!BEFORE[target]) {
  let was = '';
  try { was = require('child_process').execFileSync('git', ['-C', wt, 'show', 'c5018bb:' + target], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch (e) { /* a new page */ }
  const ids = [...was.matchAll(/<(h[1-4])([^>]*) id="([^"]+)"([^>]*)>([\s\S]*?)<\/\1>/g)].map((m) => [m[1], m[3], plain(m[5])]);
  const links = {};
  for (const m of was.matchAll(/<a [^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g)) { const t = plain(m[2]); if (t && /[?#]/.test(m[1]) && !links[t]) links[t] = m[1]; }
  const scripts = was ? (was.slice(was.lastIndexOf('</footer>')).match(/<script [^>]*><\/script>/g) || []) : null;
  BEFORE[target] = { ids, links, scripts };
  fs.writeFileSync(BEFORE_FILE, JSON.stringify(Object.fromEntries(Object.keys(BEFORE).sort().map((k) => [k, BEFORE[k]])), null, 1) + '\n');
}
const was = BEFORE[target];
for (const [tag, id, text] of was.ids) {
  body = body.replace(new RegExp('<' + tag + '((?: class="[^"]*")?)>((?:(?!</' + tag + '>)[\\s\\S])*?)</' + tag + '>', 'g'), (all, c, inner) => (plain(inner) === text && !/ id="/.test(all) ? '<' + tag + c + ' id="' + id + '">' + inner + '</' + tag + '>' : all));
}
const hrefs = was.links;
body = body.replace(/<a ([^>]*)href="([^"]+)"([^>]*)>([\s\S]*?)<\/a>/g, (all, a, h, b, inner) => {
  const old = hrefs[plain(inner)];
  return old && old.split(/[?#]/)[0] === h.split(/[?#]/)[0] && old !== h ? '<a ' + a + 'href="' + old + '"' + b + '>' + inner + '</a>' : all;
});
const file = path.join(wt, target);
const old = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : fs.readFileSync(path.join(wt, 'team.html'), 'utf8');
let head = old.slice(0, old.indexOf('</head>'));
// A page with parts the design doesn't style (the paper's figures and maths) also loads its own sheet.
// A page with parts the design doesn't style also loads its own sheet: the paper's figures and maths; the signed-in
// pages' forms and lists (app.css and the page's own), until each is rebuilt from its design page.
const EXTRA = { 'research/decision-loop.html': ['/paper.css'], 'account.html': ['/app.css', '/account.css'],
  'account/agents.html': ['/app.css', '/account/agents.css'], 'join.html': ['/join.css'],
  'admin/review.html': ['/app.css', '/admin/review.css'], 'admin/controls.html': ['/app.css', '/admin/controls.css'] };
// The page's own inline styles (those design.css doesn't share) go in /css/<page>.css.
const shared = fs.existsSync(path.join(__dirname, 'shared.json')) ? JSON.parse(fs.readFileSync(path.join(__dirname, 'shared.json'), 'utf8')) : {};
const mine = {};
for (const [c, d] of Object.entries(styles)) if (!shared[c]) mine[c] = d;
// Rules a page's script needs that its markup doesn't carry: /decisions' Second Look track, whose fill the design writes
// inline (width:63%), as classes in steps of 5% that decisions.js sets (no style from a script).
// A member's or an agent's chosen name is their page's h1, and a long one wraps rather than running off a phone's screen.
const ADD = { 'decisions.html': Array.from({ length: 21 }, (_, i) => '.d1 .trk i.w' + i * 5 + '{width:' + i * 5 + '%}').join('') + '\n',
  'member.html': '.d1 h1{overflow-wrap:anywhere}\n', 'agent.html': '.d1 h1{overflow-wrap:anywhere}\n' };
const slug = target.replace(/\.html$/, '').replace(/\//g, '-');
const ownCss = path.join(wt, 'css', slug + '.css');
if (Object.keys(mine).length || ADD[target]) {
  fs.mkdirSync(path.dirname(ownCss), { recursive: true });
  // One short line of comment: these files count toward each page's first-visit weight (SF2).
  fs.writeFileSync(ownCss, '/* ' + target + ': its own design styles. tools/design/build.js */\n' + require("./mkcss").classes(mine) + (ADD[target] || ''));
  EXTRA[target] = (EXTRA[target] || []).concat('/css/' + slug + '.css');
} else if (fs.existsSync(ownCss)) fs.unlinkSync(ownCss);
const sheets = '\n  <link rel="stylesheet" href="/design.css">' + (EXTRA[target] || []).map((h) => '\n  <link rel="stylesheet" href="' + h + '">').join('');
head = head.replace(/\s*<link rel="stylesheet"[^>]*>/g, '');
// After the font preload when the page has one; otherwise at the end of the head.
head = /<link rel="preload"[^>]*>/.test(head) ? head.replace(/(<link rel="preload"[^>]*>)/, '$1' + sheets) : head + sheets.slice(1) + '\n';
// Scripts the old page ran after the footer (its own behaviour) stay; nav.js always.
const tail = old.slice(old.lastIndexOf('</footer>'));
// A page that ran no script before (the 404, Terms, Privacy, the paper: the Menu is a <details>, so it needs none) runs none.
const scripts = was.scripts || (tail.match(/<script [^>]*><\/script>/g) || ['<script src="/nav.js" defer></script>']);
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
