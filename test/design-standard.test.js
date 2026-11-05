'use strict';
// The design standard (the design handoff of Nov 5, 2026, CODING_AGENT_SPEC.md section 5): contrast is checked
// from the stylesheet's own tokens, so a colour change can't quietly break it (5.6: "Contrast checked automatically
// from tokens in CI (fail under 4.5:1 for text, 3:1 for UI borders)").
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const css = read('styles.css');

function tokens(block) {
  const out = {};
  for (const m of block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})\s*;/gi)) out[m[1]] = m[2].toLowerCase();
  return out;
}
const darkBlock = css.match(/:root\s*\{([^}]*)\}/)[1];
const lightBlock = css.match(/@media \(prefers-color-scheme: light\)\s*\{\s*:root\s*\{([^}]*)\}/)[1];
const dark = tokens(darkBlock);
const light = { ...dark, ...tokens(lightBlock) };

function lum(hex) {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
function ratio(a, b) {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

test('both themes define every colour token, --rule-strong included', () => {
  for (const [name, t] of [['dark', dark], ['light', light]]) {
    for (const k of ['ink', 'text', 'muted', 'rule', 'rule-strong', 'amber']) assert.ok(t[k], `${name} theme has --${k}`);
  }
  assert.strictEqual(dark['rule-strong'], '#626160');
  assert.strictEqual(light['rule-strong'], '#8c8e91');
});

test('text tokens reach 4.5:1 on the page, and text on amber does too, in both themes', () => {
  // Text on amber is fixed in the stylesheet: #15110a in dark, #ffffff in light (the Join pill, primary buttons).
  for (const [name, t, onAmber] of [['dark', dark, '#15110a'], ['light', light, '#ffffff']]) {
    for (const k of ['text', 'muted', 'amber']) {
      const r = ratio(t[k], t.ink);
      assert.ok(r >= 4.5, `${name}: --${k} on --ink is ${r.toFixed(2)}:1, under 4.5:1`);
    }
    const r = ratio(onAmber, t.amber);
    assert.ok(r >= 4.5, `${name}: text on amber is ${r.toFixed(2)}:1, under 4.5:1`);
  }
});

test('--rule-strong reaches 3:1 on the page in both themes (WCAG 1.4.11), and --rule does not', () => {
  for (const [name, t] of [['dark', dark], ['light', light]]) {
    const r = ratio(t['rule-strong'], t.ink);
    assert.ok(r >= 3, `${name}: --rule-strong is ${r.toFixed(2)}:1`);
    // Why form fields can't use --rule: it is a decorative line colour, well under 3:1.
    assert.ok(ratio(t.rule, t.ink) < 3, `${name}: --rule is decorative only`);
  }
});

test('every form field border uses a colour with 3:1 against the page, never the decorative --rule', () => {
  const strong = ['rule-strong', 'muted', 'text', 'amber'];
  for (const k of strong) {
    assert.ok(ratio(dark[k], dark.ink) >= 3 && ratio(light[k], light.ink) >= 3, `--${k} passes 3:1 in both themes`);
  }
  const files = fs.readdirSync(root).filter((f) => f.endsWith('.css'));
  let checked = 0;
  for (const f of files) {
    for (const m of read(f).matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      const selector = m[1].trim();
      const body = m[2];
      // Fields: inputs, selects and textareas (not the file input's button, which is a button with a label).
      const parts = selector.split(',').map((s) => s.trim()).filter((s) => /(^|[\s>.#\]])?(input|select|textarea)\b/.test(s) && !/::file-selector-button/.test(s));
      if (!parts.length) continue;
      const border = body.match(/(?:^|;|\s)border(?:-color)?\s*:\s*([^;]+)/);
      if (!border) continue;
      if (/\bnone\b|\b0\b/.test(border[1]) && !/var\(/.test(border[1])) continue;
      checked++;
      const v = border[1].match(/var\(--([a-z-]+)\)/);
      assert.ok(v, `${f}: ${selector} sets a border colour without a token`);
      assert.ok(strong.includes(v[1]), `${f}: ${selector} uses --${v[1]} for a field border; use --rule-strong`);
    }
  }
  assert.ok(checked >= 8, `found ${checked} field border rules`);
});

// 5.3: "Every page has: one <h1>, logical heading order, landmark regions (header, nav, main, footer), a skip link to
// #main, and a unique <title>"; 5.4: breadcrumbs on every detail page.
test('every page: one h1, the landmarks, a skip link to #main, and a title of its own', () => {
  const shell = require('../scripts/shell');
  const titles = new Map();
  for (const f of shell.pages()) {
    const html = read(f);
    assert.strictEqual((html.match(/<h1\b/g) || []).length, 1, f + ': one h1');
    for (const tag of ['<header class="site-header">', '<nav class="site-nav" aria-label="Main">', '<main id="main"', '<footer class="site-footer">']) assert.ok(html.includes(tag), f + ' has ' + tag);
    assert.match(html, /<body>\s*<a class="skip-link" href="#main">Skip to content<\/a>/, f + ': the skip link comes first');
    const title = (html.match(/<title>([^<]+)<\/title>/) || [])[1];
    assert.ok(title, f + ': a title');
    assert.ok(!titles.has(title), f + ' and ' + titles.get(title) + ' share the title ' + title);
    titles.set(title, f);
    // No heading level is skipped going down (h2 to h4 with no h3 between).
    let prev = 1;
    for (const m of html.slice(html.indexOf('<main')).matchAll(/<h([1-6])\b/g)) {
      const n = Number(m[1]);
      assert.ok(n <= prev + 1, f + ': h' + prev + ' then h' + n);
      prev = n;
    }
  }
});

test('the detail pages (a receipt, a member) say where they sit, one step back', () => {
  for (const [f, back] of [['receipt.html', '<a href="/feed?lane=agents">Posts from agents</a>'], ['member.html', '<a href="/feed">Posts</a>']]) {
    const main = read(f).match(/<main[\s\S]*?<\/main>/)[0];
    assert.match(main, /<nav class="crumbs" aria-label="Breadcrumb"><ol><li>/, f);
    assert.ok(main.includes(back), f);
    assert.ok(main.indexOf('class="crumbs"') < main.indexOf('<h1'), f + ': above the heading');
  }
});
