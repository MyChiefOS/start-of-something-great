// SF1, SF2, L3 (PR 16, RK14): the smaller italic and the fallback fonts.
// - The italic is a Modified Version of Source Serif 4 Italic, so the font license (SIL OFL 1.1) says it must not use
//   the Reserved Font Name "Source"; it must keep the copyright and every character of the original.
// - Every page gets a fallback sized for desktops (Arial, Times New Roman) and one for Android (Roboto, Noto Serif).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const woff2 = require('./woff2');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const font = (f) => woff2.read(fs.readFileSync(path.join(root, 'fonts', f)));
const css = read('styles.css');
const faces = [...css.matchAll(/@font-face\s*\{([^}]*)\}/g)].map((m) => {
  const get = (k) => (new RegExp('(?:^|;|\\s)' + k + ':\\s*([^;]+);').exec(m[1]) || [])[1];
  return { family: (get('font-family') || '').replace(/"/g, ''), src: get('src') || '', style: get('font-style') || 'normal', weight: get('font-weight') || '' };
});

test('RK14: the italic is one weight at one optical size, with every character of the original', () => {
  const ital = font('day-one-serif-italic.woff2'), orig = font('source-serif-4-italic.woff2');
  for (const t of ['fvar', 'gvar', 'avar', 'STAT', 'HVAR', 'MVAR']) assert.ok(!ital.tags.includes(t), 'still has ' + t);
  assert.deepStrictEqual([...woff2.codepoints(ital.tables.cmap)].sort((a, b) => a - b), [...woff2.codepoints(orig.tables.cmap)].sort((a, b) => a - b));
  const size = fs.statSync(path.join(root, 'fonts', 'day-one-serif-italic.woff2')).size;
  assert.ok(size < 30 * 1024, 'the italic is ' + size + ' bytes');
});

test('L3: the modified italic doesn\'t use the Reserved Font Name, keeps Adobe\'s copyright and says what it is', () => {
  assert.match(read('fonts/OFL-source-serif-4.txt'), /Reserved Font Name 'Source'/);
  const n = woff2.names(font('day-one-serif-italic.woff2').tables.name);
  for (const r of n.filter((x) => [1, 2, 3, 4, 6, 16, 17, 18, 21, 22, 25].includes(x.id))) {
    assert.ok(!/source/i.test(r.text), 'name ID ' + r.id + ' says ' + r.text);
  }
  assert.ok(n.some((r) => r.id === 1 && r.text === 'Day One Serif'));
  assert.ok(n.some((r) => r.id === 0 && /Adobe/.test(r.text)), 'copyright notice kept');
  assert.ok(n.some((r) => r.id === 10 && /Modified Version of Source Serif 4 Italic/.test(r.text) && /Open Font License/.test(r.text)));
  const register = read('CONTENT-LICENSE.md');
  assert.match(register, /\| `fonts\/day-one-serif-italic\.woff2` \| [^|]*Modified Version[^|]*\| SIL Open Font License 1\.1/);
});

test('RK14: the body family has a new name, its regular face is the unmodified file and its italic the small one', () => {
  assert.ok(!faces.some((f) => /Source Serif 4/.test(f.family)), 'no face is called Source Serif 4 any more');
  const body = faces.filter((f) => f.family === 'Day One Serif');
  assert.deepStrictEqual(body.map((f) => [f.style, f.src]), [
    ['normal', 'url("/fonts/source-serif-4.woff2") format("woff2")'],
    ['italic', 'url("/fonts/day-one-serif-italic.woff2") format("woff2")']]);
  assert.strictEqual(body[1].weight, '400', 'one weight, so the browser draws bold italic itself rather than using the wrong weight');
  assert.match(css, /--body: "Day One Serif",/);
  for (const f of fs.readdirSync(root).filter((x) => /\.(html|css|js)$/.test(x)).concat(['research/decision-loop.html', 'research.html'])) {
    assert.ok(!read(f).includes('source-serif-4-italic.woff2'), f + ' still loads the big italic');
  }
});

test('SF1: every family has a sized fallback for desktops and one for Android, in that order', () => {
  assert.match(css, /--display: "Bricolage Grotesque", "Bricolage Fallback", "Bricolage Android Fallback", /);
  assert.match(css, /--body: "Day One Serif", "Source Serif Fallback", "Source Serif Android Fallback", /);
  const want = {
    'Bricolage Fallback': [/local\("Arial"\)/, /local\("Arial Bold"\)/],
    'Bricolage Android Fallback': [/local\("Roboto"\)/, /local\("Roboto Bold"\)/],
    'Source Serif Fallback': [/local\("Times New Roman"\)/, /local\("Times New Roman Bold"\)/, /local\("Times New Roman Italic"\)/, /local\("Times New Roman Bold Italic"\)/],
    'Source Serif Android Fallback': [/local\("Noto Serif"\)/, /local\("Noto Serif Bold"\)/, /local\("Noto Serif Italic"\)/, /local\("Noto Serif Bold Italic"\)/]
  };
  for (const [family, srcs] of Object.entries(want)) {
    const fs_ = faces.filter((f) => f.family === family);
    assert.strictEqual(fs_.length, srcs.length, family);
    srcs.forEach((re, i) => assert.match(fs_[i].src, re, family + ' face ' + i));
    for (const f of fs_) assert.ok(/^local\(/.test(f.src) && !/url\(/.test(f.src), family + ': a fallback only uses fonts already on the device');
  }
  for (const m of css.matchAll(/@font-face\s*\{([^}]*Fallback[^}]*)\}/g)) {
    for (const k of ['size-adjust', 'ascent-override', 'descent-override', 'line-gap-override', 'unicode-range']) assert.ok(m[1].includes(k + ':'), k + ' in ' + m[1].slice(0, 60));
  }
});

const py = (() => { try { execFileSync('python3', ['-c', 'import fontTools, brotli; assert fontTools.version == "4.65.0"'], { stdio: 'ignore' }); return true; } catch { return false; } })();
test('RK14: scripts/build-fonts.py rebuilds the italic byte for byte', { skip: !py && 'needs python3 with fontTools 4.65.0 and brotli' }, () => {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fonts-')), 'x.woff2');
  execFileSync('python3', [path.join(root, 'scripts', 'build-fonts.py'), out], { stdio: 'ignore' });
  assert.ok(fs.readFileSync(out).equals(fs.readFileSync(path.join(root, 'fonts', 'day-one-serif-italic.woff2'))));
});
