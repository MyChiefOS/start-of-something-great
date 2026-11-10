'use strict';
// Aaron's design on every page built from it (the handoff of Nov 5, 2026; tools/design/built.list): Nov 5, "Please
// implement the design and details I provided", and "Make the details for the site match the production system". The
// pages are written by tools/design/build.js from the handoff (sh tools/design/all.sh <its static folder>); these hold
// what they must keep between rebuilds: the design's frame, every class a page uses defined, no inline style or
// script, no link to a page that isn't built, logical headings, and the design's colours readable in both schemes.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const shell = require('../scripts/shell');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const BUILT = read('tools/design/built.list').trim().split('\n').map((l) => l.split(' '));
const TARGETS = BUILT.map(([, t]) => t);
// The page between the shell's markers, with its <template>s taken out (they are not part of the page).
const bodyOf = (html) => html.slice(html.indexOf('<!-- /shell:top -->'), html.indexOf('<!-- shell:foot -->')).replace(/<template[\s\S]*?<\/template>/g, '');

test('every built page is in the design\'s frame: the wrapper, the shell, design.css first, then its own sheets', () => {
  assert.ok(TARGETS.length >= 38, TARGETS.length + ' pages');
  const before = JSON.parse(read('tools/design/before.json'));
  for (const t of TARGETS) {
    const html = read(t);
    assert.match(html, /<body>\n<div class="d1"><div class="wrap">\n<!-- shell:top -->[\s\S]*<!-- \/shell:foot -->\n<\/div><\/div>\n/, t + ': the design\'s wrapper');
    assert.strictEqual(shell.render(t, html), html, t + ' carries the shell as scripts/shell.js writes it');
    const sheets = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)">/g)].map((m) => m[1]);
    assert.strictEqual(sheets[0], '/design.css', t + ': design.css first');
    for (const s of sheets) assert.ok(fs.existsSync(path.join(root, s.slice(1))), t + ' loads ' + s + ', which exists');
    assert.ok(before[t], t + ': tools/design/before.json keeps what the build needs from the page before the design');
  }
});

test('no inline style, script or handler, and every class a page uses is defined in the sheets it loads', () => {
  for (const t of TARGETS) {
    const html = read(t);
    assert.ok(!/\sstyle\s*=/i.test(html), t + ': no style attribute');
    assert.ok(!/<style\b/i.test(html), t + ': no style element');
    assert.ok(!/\son[a-z]+\s*=\s*"/i.test(html.replace(/<meta[^>]*>/g, '')), t + ': no on* handler');
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      if (/type="application\/ld\+json"/.test(m[1])) continue;
      assert.match(m[1], /\bsrc="(\/|https:\/\/giscus\.app\/client\.js")/, t + ': a script file of ours (or giscus, as before)');
      assert.strictEqual(m[2].trim(), '', t + ': nothing inside a script tag');
    }
    // The design's inline styles became classes (x + 8 hex); each must be defined, or the page loses that style.
    const css = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)">/g)].map((m) => read(m[1].slice(1))).join('\n');
    for (const c of new Set([...html.matchAll(/class="([^"]*)"/g)].flatMap((m) => m[1].split(/\s+/)).filter((c) => /^x[0-9a-f]{8}$/.test(c)))) {
      assert.ok(css.includes('.' + c + '{') || css.includes('.' + c + '.'), t + ': .' + c + ' is defined in its stylesheets');
    }
  }
});

test('no link on a built page goes to a page that isn\'t built, and the design\'s prototype words are gone', () => {
  const vercel = JSON.parse(read('vercel.json'));
  const routes = (vercel.rewrites || []).map((r) => r.source).concat((vercel.redirects || []).map((r) => r.source))
    .filter((s) => !/^\/:path\(/.test(s)).map((s) => new RegExp('^' + s.replace(/:[a-z]+\([^)]*\)/g, '[^/]+').replace(/:[a-z]+\*/g, '.*').replace(/:[a-z]+/g, '[^/]+') + '$'));
  const reaches = (p) => p === '/' || shell.exists(p) || fs.existsSync(path.join(root, p.slice(1))) || /^\/api(\/|$)/.test(p) || routes.some((r) => r.test(p));
  for (const t of TARGETS) {
    const body = bodyOf(read(t));
    for (const m of body.matchAll(/href="(\/[^"#?]*)/g)) assert.ok(reaches(m[1]), t + ' links ' + m[1] + ', which is not built');
    assert.ok(!/href="[a-z][\w-]*\.html"/.test(body), t + ': no link left in the design\'s file form (x.html)');
    assert.ok(!/this prototype|Sample figures|Sample entries|Prototype views/i.test(body), t + ': no prototype words');
  }
});

test('one h1 and no heading level skipped on any built page (spec 5.3), a notice above <main> included', () => {
  for (const t of TARGETS) {
    const body = bodyOf(read(t));
    assert.strictEqual((body.match(/<h1\b/g) || []).length, 1, t + ': one h1');
    let prev = 1;
    for (const m of body.matchAll(/<h([1-6])\b/g)) { const n = Number(m[1]); assert.ok(n <= prev + 1, t + ': h' + prev + ' then h' + n); prev = n; }
  }
});

// WCAG 2.2 contrast, from design.css's own tokens: text 4.5:1, large text and controls 3:1.
function lum(hex) {
  const c = hex.replace('#', '').match(/../g).map((x) => parseInt(x, 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
test('the design\'s colours are readable in both schemes: text and muted text 4.5:1, amber and field borders 3:1', () => {
  const css = read('design.css');
  const dark = css.match(/\n\.d1\{([^}]*)\}/)[1];
  const light = css.match(/@media \(prefers-color-scheme: light\)\{\.d1\{([^}]*)\}\}/)[1];
  for (const [name, block] of [['dark', dark], ['light', light]]) {
    const v = Object.fromEntries([...block.matchAll(/--([a-z-]+):(#[0-9a-f]{6})/gi)].map((m) => [m[1], m[2]]));
    assert.ok(ratio(v.text, v.ink) >= 4.5, name + ': text ' + ratio(v.text, v.ink).toFixed(2));
    assert.ok(ratio(v.muted, v.ink) >= 4.5, name + ': muted ' + ratio(v.muted, v.ink).toFixed(2));
    assert.ok(ratio(v.amber, v.ink) >= 3, name + ': amber ' + ratio(v.amber, v.ink).toFixed(2));
    assert.ok(ratio(v['rule-strong'], v.ink) >= 3, name + ': field borders ' + ratio(v['rule-strong'], v.ink).toFixed(2));
  }
  // The logo and colours are the site's own (Aaron's limits): the dark scheme's tokens are styles.css's.
  const site = read('styles.css');
  for (const k of ['ink', 'text', 'muted', 'rule', 'amber']) assert.ok(new RegExp('--' + k + ': ' + dark.match(new RegExp('--' + k + ':(#[0-9a-f]{6})', 'i'))[1]).test(site), '--' + k + ' is the site\'s');
});

test('every page\'s patches are one entry (a second entry for a page silently replaced the first: the home page lost its PIN step), and the design records are never served', () => {
  const src = read('tools/design/patches.js');
  const keys = [...src.matchAll(/^ {2}'([^']+)': \[/gm)].map((m) => m[1]);
  assert.deepStrictEqual(keys.filter((k, i) => keys.indexOf(k) !== i), []);
  assert.match(read('index.html'), /a one-time code, a key file and a six-digit PIN/);
  // The handoff and canvas copies the design check reads (scripts/check-design.js) are records, not pages of the site.
  const vercel = JSON.parse(read('vercel.json'));
  assert.ok(vercel.redirects.some((r) => r.source === '/design/:path*' && /^https:\/\/github\.com\/MyChiefOS\/start-of-something-great\/tree\/main\/design\//.test(r.destination) && !r.has), 'vercel.json sends /design/* to GitHub');
  assert.match(read('.vercelignore'), /^\/design\/$/m);
});

test('the home page\'s progress card is the Build page\'s figure and sentence, from progress.js, and never says "done"', () => {
  const home = read('index.html');
  assert.match(home, /<p class="kick">Work<\/p><div id="next" class="card [^"]*"><span class="num [^"]*" id="next-pct">–<\/span>/);
  assert.match(home, /<script src="\/progress\.js" defer><\/script>\n<script src="\/home\.js" defer><\/script>/);
  assert.match(read('home.js'), /window\.DOGProgress\(plan\)/);
  assert.match(read('buildpage.js'), /window\.DOGProgress\(plan\)/);
  assert.match(read('build.html'), /<script defer src="\/progress\.js"><\/script>\n {2}<script defer src="\/buildpage\.js"><\/script>/);
  // The plan's sentence: all of it verified is "all posted work verified".
  global.window = {};
  require('../progress.js');
  const progress = global.window.DOGProgress;
  delete global.window;
  const pg = progress({ project: { title: 'The site\'s own build' }, milestones: [{ code: 'M1', first_target: '2026-11-20', target: '2026-11-20', gate: true }],
    figures: { scope: 439, verified: 439, left: 0, tasks: 108 } });
  assert.deepStrictEqual([pg.pct, pg.note], [100, 'The site\'s own build · 1 milestone · 108 tasks · all posted work verified, the gate Fri, Nov 20']);
  assert.doesNotMatch(pg.note, /\bdone\b|complete/i);
  assert.strictEqual(progress({ figures: { scope: 3, verified: 2, left: 1, tasks: 2 }, milestones: [] }).pct, 66, 'rounded down');
});
