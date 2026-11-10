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
// <!-- sha256:path --> in a page's own markup: that repository file's SHA-256, so a published hash is always the file's.
body = body.replace(/<!-- sha256:([A-Za-z0-9._/-]+) -->/g, (m, f) => require('crypto').createHash('sha256').update(fs.readFileSync(path.join(wt, f))).digest('hex'));
// <!-- pinned-key -->: what verifier/log-key.js pins today, so /security never says more than the file does.
body = body.replace(/<!-- pinned-key -->/g, () => {
  const m = fs.readFileSync(path.join(wt, 'verifier/log-key.js'), 'utf8').match(/^export const PINNED_VKEY = (null|"[^"]+");$/m);
  if (!m) throw new Error('verifier/log-key.js has no PINNED_VKEY line');
  return m[1] === 'null' ? 'Not pinned in the repository yet: the key is made when the log is switched on in production, and then pinned by a reviewed pull request. Until then, verifiers use the witness’s pin.'
    : 'Pinned in the repository: <code>' + JSON.parse(m[1]).replace(/[<>&"]/g, '') + '</code>.';
});
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
  'account/agents.html': ['/app.css'],
  // The administrator's pages (040, in the design's markup): the shared approval screen's sheet (approval.js) and their
  // own, for the parts their scripts build.
  'admin/review.html': ['/approval.css', '/admin/review.css'], 'admin/controls.html': ['/admin/controls.css'] };
// The page's own inline styles (those design.css doesn't share) go in /css/<page>.css.
const shared = fs.existsSync(path.join(__dirname, 'shared.json')) ? JSON.parse(fs.readFileSync(path.join(__dirname, 'shared.json'), 'utf8')) : {};
const mine = {};
for (const [c, d] of Object.entries(styles)) if (!shared[c]) mine[c] = d;
// Rules a page's script needs that its markup doesn't carry: /decisions' Second Look track, whose fill the design writes
// inline (width:63%), as classes in steps of 5% that decisions.js sets (no style from a script).
const SIGNIN = '.d1 main.story{padding-top:4px}.d1 main.story h1{font-size:clamp(1.75rem,7vw,3.25rem)}.d1 main.story .dek{font-size:17px;margin-bottom:8px}'
  + '.d1 .card .btn,.d1 .card .tabs button{display:inline-flex;align-items:center;justify-content:center;min-height:44px}'
  + '.d1 .card summary{display:list-item;min-height:44px;padding:8px 0;box-sizing:border-box}'
  // While a code shows, the comment box sits close under it (finding 1): no empty line, and the cards closer together.
  + '.d1 #code-copied:empty{display:none}.d1 #code-signin,.d1 #pin-signin-card{margin:12px 0!important}.d1 #code-signin{padding-bottom:8px}.d1 #say-hello{padding-top:8px}.d1 #code-show p.fine:last-of-type{margin-top:6px!important}.d1 main.story>p:not(.dek){margin-bottom:8px}.d1 #post-here{margin-bottom:4px}\n';
// A member's or an agent's chosen name is their page's h1, and a long one wraps rather than running off a phone's screen.
const WIDTHS = Array.from({ length: 21 }, (_, i) => '.d1 .trk i.w' + i * 5 + '{width:' + i * 5 + '%}').join('') + '\n';
// A project's plan (050; plan.js): the design's chart, its pills and the schedule figures.
const PLAN = '.d1 .plan-svg{display:block;font-family:var(--display);font-size:11px;overflow:visible}.d1 .plan-svg .grid line{stroke:var(--rule)}'
  + '.d1 .plan-svg .axis{stroke:var(--muted)}.d1 .plan-svg .lab text{fill:var(--muted)}.d1 .plan-svg .mark{stroke:var(--rule);stroke-dasharray:3 4}'
  + '.d1 .plan-svg .now{stroke:var(--amber);stroke-dasharray:3 4;opacity:.7}.d1 .plan-svg .nowl{fill:var(--amber);font-weight:600}'
  + '.d1 .plan-svg path,.d1 .plan-svg .forecast{fill:none}.d1 .plan-svg .scope{stroke:var(--muted);stroke-width:1;opacity:.8}'
  + '.d1 .plan-svg .planned{stroke:var(--muted);stroke-width:1.5;stroke-dasharray:4 4}.d1 .plan-svg .verified{stroke:var(--amber);stroke-width:2.5;stroke-linejoin:round}'
  + '.d1 .plan-svg .forecast{stroke:var(--amber);stroke-width:2;stroke-dasharray:1 5;stroke-linecap:round}.d1 .plan-svg .dot,.d1 .plan-svg .fdot{fill:var(--ink);stroke:var(--amber);stroke-width:2.5}'
  + '.d1 .plan-box{min-height:260px}.d1 .figs{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-top:22px}'
  + '.d1 .figs div{border-top:1px solid var(--rule);padding-top:8px;min-width:0}.d1 .figs b{display:block;font-family:var(--display);font-size:24px;font-weight:700;letter-spacing:-.02em;line-height:1.1;font-variant-numeric:tabular-nums}'
  + '.d1 .figs small{display:block;color:var(--muted);font-family:var(--display);font-size:12.5px;line-height:1.35;margin-top:2px}'
  + '@media(max-width:520px){.d1 .figs{grid-template-columns:repeat(2,minmax(0,1fr))}}'
  // Aaron's chart canvas of Nov 7 (design/canvas-2026-11-07): the shaded time after the planned finish, the values at
  // now, the forecast's label, the milestone rows and their marks, the legend, five figures, and the milestone table
  // that stacks on a phone.
  + '.d1 .plan-svg .shade{fill:var(--amber);opacity:.06}.d1 .plan-svg .after,.d1 .plan-svg .val{fill:var(--muted)}.d1 .plan-svg .val.strong{fill:var(--text)}'
  + '.d1 .plan-svg .pdot{fill:var(--muted)}.d1 .plan-svg .fl{fill:var(--amber)}.d1 .plan-svg .row{stroke:var(--rule)}'
  + '.d1 .plan-svg .span{stroke:var(--muted);stroke-width:1.5}.d1 .plan-svg .span.fc{stroke:var(--amber);stroke-dasharray:2 3}'
  + '.d1 .plan-svg .dia.plan{fill:var(--ink);stroke:var(--muted);stroke-width:1.5}.d1 .plan-svg .dia.done{fill:var(--amber)}'
  + '.d1 .plan-svg .dia.fc{fill:var(--ink);stroke:var(--amber);stroke-width:1.5;stroke-dasharray:2 2}'
  + '.d1 .lgd{display:flex;flex-wrap:wrap;gap:8px 22px;margin:0 0 12px}.d1 .lgd span{display:inline-flex;align-items:center;gap:8px;font-family:var(--display);font-size:13px;color:var(--muted)}'
  + '.d1 .lgd i{display:inline-block;width:26px;height:0;border-top:1.5px dashed var(--muted)}.d1 .lgd i.v{border-top:2.5px solid var(--amber)}.d1 .lgd i.s{border-top:1px solid var(--muted)}'
  + '.d1 .lgd i.f{border-top:2px dotted var(--amber)}.d1 .figs.f5{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}'
  + '.d1 .mlist{list-style:none;margin:0;padding:0;display:none}.d1 .mlist .ms{border-top:1px solid var(--rule);padding:12px 0;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:start}'
  + '.d1 .mlist .ms:last-child{border-bottom:1px solid var(--rule)}.d1 .mlist .ms b{font-family:var(--display);font-weight:600}.d1 .mlist .ms .fine{grid-column:1/-1}'
  + '@media(max-width:600px){.d1 .mtab{display:none}.d1 .mlist{display:block}.d1 .lgd{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px 12px}}\n';
const ADD = { 'decisions.html': WIDTHS,
  // The home page's progress card (home.js): its bar in steps of 5%, and on a phone its figure, words and buttons stacked.
  'index.html': WIDTHS + '@media(max-width:600px){.d1 #next{grid-template-columns:minmax(0,1fr)!important;gap:12px!important}}\n',
  'member.html': '.d1 h1{overflow-wrap:anywhere}\n', 'agent.html': '.d1 h1{overflow-wrap:anywhere}\n',
  // The work pages (042): progress bars in steps of 5% that workpages.js sets, and long titles that wrap.
  'build.html': WIDTHS + PLAN + '.d1 td.tn{white-space:nowrap}'
    // The design's four task cards in one row; two to a row below 900 px and one on a phone (spec 5.6), never squeezed.
    + '@media(max-width:900px){.d1 .k4{grid-template-columns:repeat(2,minmax(0,1fr))!important}}@media(max-width:520px){.d1 .k4{grid-template-columns:minmax(0,1fr)!important}}\n', 'project.html': WIDTHS + PLAN + '.d1 h1{overflow-wrap:anywhere}\n', 'projects.html': WIDTHS + '.d1 td.tn{white-space:nowrap}\n', 'task.html': '.d1 h1{overflow-wrap:anywhere}.d1 dd code{overflow-wrap:anywhere}\n',
  // The sign-in pages (UX PR A, kept with the design): every control at least 44 px at every width, and a shorter top, so
  // the chosen way's button is in the first screen at 390 by 844 and 1280 by 800 (scripts/check-join-panel.js).
  'join.html': SIGNIN, 'join/pin.html': SIGNIN };
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
