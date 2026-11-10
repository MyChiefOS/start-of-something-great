// RK139 and RK14: the site's smaller font files (tools/fonts/build.py). Each font is read here as a browser would get
// it (WOFF2, unpacked with Node's own brotli), so CI checks the files themselves: the license's name rule, the
// characters and weights they keep, the CSS that names them, and every page under the 400 KB budget with no exceptions.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { weigh, BUDGET } = require('../scripts/page-weight');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

// ---- A small WOFF2 reader: enough to get the cmap, name and fvar tables (none of which WOFF2 transforms). ----
const KNOWN = ['cmap', 'head', 'hhea', 'hmtx', 'maxp', 'name', 'OS/2', 'post', 'cvt ', 'fpgm', 'glyf', 'loca', 'prep', 'CFF ', 'VORG',
  'EBDT', 'EBLC', 'gasp', 'hdmx', 'kern', 'LTSH', 'PCLT', 'VDMX', 'vhea', 'vmtx', 'BASE', 'GDEF', 'GPOS', 'GSUB', 'EBSC', 'JSTF', 'MATH',
  'CBDT', 'CBLC', 'COLR', 'CPAL', 'SVG ', 'sbix', 'acnt', 'avar', 'bdat', 'bloc', 'bsln', 'cvar', 'fdsc', 'feat', 'fmtx', 'fvar', 'gvar',
  'hsty', 'just', 'lcar', 'mort', 'morx', 'opbd', 'prop', 'trak', 'Zapf', 'Silf', 'Glat', 'Gloc', 'Feat', 'Sill'];
function woff2Tables(file) {
  const b = fs.readFileSync(path.join(root, file));
  assert.strictEqual(b.toString('latin1', 0, 4), 'wOF2', file + ' is a WOFF2 file');
  const numTables = b.readUInt16BE(12);
  const compressed = b.readUInt32BE(20);
  let o = 48;
  const base128 = () => { let v = 0; for (let i = 0; i < 5; i++) { const x = b[o++]; v = v * 128 + (x & 0x7f); if (!(x & 0x80)) return v; } throw new Error('bad UIntBase128'); };
  const dir = [];
  for (let i = 0; i < numTables; i++) {
    const flags = b[o++];
    let tag = KNOWN[flags & 0x3f];
    if ((flags & 0x3f) === 63) { tag = b.toString('latin1', o, o + 4); o += 4; }
    const orig = base128();
    const version = flags >> 6;
    const transformed = (tag === 'glyf' || tag === 'loca') ? version === 0 : version !== 0;
    dir.push({ tag, length: transformed ? base128() : orig });
  }
  const data = zlib.brotliDecompressSync(b.subarray(o, o + compressed));
  const tables = {};
  let at = 0;
  for (const t of dir) { tables[t.tag] = data.subarray(at, at + t.length); at += t.length; }
  return tables;
}
function codepoints(cmap) {
  const n = cmap.readUInt16BE(2);
  const subs = [];
  for (let i = 0; i < n; i++) subs.push({ p: cmap.readUInt16BE(4 + i * 8), e: cmap.readUInt16BE(6 + i * 8), off: cmap.readUInt32BE(8 + i * 8) });
  const pick = subs.find((s) => s.p === 3 && s.e === 10) || subs.find((s) => s.p === 3 && s.e === 1);
  const t = cmap.subarray(pick.off);
  const out = new Set();
  if (t.readUInt16BE(0) === 12) {
    for (let i = 0, groups = t.readUInt32BE(12); i < groups; i++) {
      for (let c = t.readUInt32BE(16 + i * 12); c <= t.readUInt32BE(20 + i * 12); c++) out.add(c);
    }
  } else {
    const segs = t.readUInt16BE(6) / 2;
    for (let i = 0; i < segs; i++) {
      const end = t.readUInt16BE(14 + i * 2), start = t.readUInt16BE(16 + segs * 2 + i * 2);
      const delta = t.readInt16BE(16 + segs * 4 + i * 2), roff = t.readUInt16BE(16 + segs * 6 + i * 2);
      for (let c = start; c <= end && c !== 0xffff; c++) {
        let g;
        if (roff === 0) g = (c + delta) & 0xffff;
        else { const at = 16 + segs * 6 + i * 2 + roff + (c - start) * 2; g = t.readUInt16BE(at); if (g) g = (g + delta) & 0xffff; }
        if (g) out.add(c);
      }
    }
  }
  return out;
}
function names(name) {
  const count = name.readUInt16BE(2), strings = name.readUInt16BE(4);
  const out = [];
  for (let i = 0; i < count; i++) {
    const r = 6 + i * 12;
    if (name.readUInt16BE(r) !== 3) continue; // Windows records, UTF-16BE
    const id = name.readUInt16BE(r + 6), len = name.readUInt16BE(r + 8), off = name.readUInt16BE(r + 10);
    const raw = name.subarray(strings + off, strings + off + len);
    out.push({ id, text: Buffer.from(raw).swap16().toString('utf16le') });
  }
  return out;
}
function axes(fvar) {
  const off = fvar.readUInt16BE(4), count = fvar.readUInt16BE(8), size = fvar.readUInt16BE(10);
  const out = {};
  for (let i = 0; i < count; i++) {
    const a = off + i * size;
    out[fvar.toString('latin1', a, a + 4)] = [fvar.readInt32BE(a + 4) / 65536, fvar.readInt32BE(a + 12) / 65536];
  }
  return out;
}
const fromRange = (s) => {
  const out = new Set();
  for (const part of s.split(',').map((x) => x.trim())) {
    const [lo, hi] = part.replace(/^U\+/i, '').split('-').map((h) => parseInt(h, 16));
    for (let c = lo; c <= (hi === undefined ? lo : hi); c++) out.add(c);
  }
  return out;
};

const css = read('styles.css');
const faces = [...css.matchAll(/@font-face \{([\s\S]*?)\}/g)].map((m) => m[1]);
const face = (family, extra = '') => faces.filter((f) => f.includes('font-family: "' + family + '";') && f.includes(extra));
const FONTS = {
  'fonts/bricolage-grotesque.woff2': { family: 'Bricolage Grotesque', fallback: 'Bricolage Fallback', style: 'normal', axes: { opsz: [12, 96], wght: [200, 800] } },
  'fonts/day-one-serif.woff2': { family: 'Day One Serif', fallback: 'Day One Serif Fallback', style: 'normal', axes: { wght: [400, 900], opsz: [8, 60] } },
  'fonts/day-one-serif-italic.woff2': { family: 'Day One Serif', fallback: 'Day One Serif Fallback', style: 'italic', axes: { wght: [400, 900], opsz: [8, 60] } },
};

test('RK139: the CSS names exactly these font files, by these families, with the weights the files have', () => {
  const srcs = faces.map((f) => /url\("([^"]+)"\)/.exec(f)).filter(Boolean).map((m) => m[1].slice(1)).sort();
  assert.deepStrictEqual(srcs, Object.keys(FONTS).sort());
  for (const [file, f] of Object.entries(FONTS)) {
    const [decl] = faces.filter((x) => x.includes('url("/' + file + '")'));
    assert.ok(decl.includes('font-family: "' + f.family + '";'), file);
    if (f.family !== 'Bricolage Grotesque') assert.ok(decl.includes('font-style: ' + f.style + ';'), file);
    assert.ok(decl.includes('font-weight: ' + f.axes.wght.join(' ') + ';'), file + ': the CSS weight range is the file\'s');
    assert.deepStrictEqual(axes(woff2Tables(file).fvar), f.axes, file + ': its axes (Bricolage\'s width is pinned at its default)');
  }
  // The design's stylesheet carries the same faces (tools/design/mkcss.js copies them) and the same body font.
  const design = read('design.css');
  for (const file of Object.keys(FONTS)) assert.ok(design.includes('url("/' + file + '")'), 'design.css names ' + file);
  assert.match(design, /--body:"Day One Serif",/);
  assert.match(css, /--body: "Day One Serif", "Day One Serif Fallback",/);
  // The italic face's file name says italic: page-weight.js and check-design.js count it by that.
  assert.ok(Object.keys(FONTS).some((f) => /italic/.test(f)));
});

test('RK139, the OFL: the renamed serif says "Source" only in Adobe\'s notices; every font keeps its copyright notice', () => {
  for (const file of Object.keys(FONTS)) {
    const n = names(woff2Tables(file).name);
    assert.ok(n.some((r) => r.id === 0 && /Copyright|©/.test(r.text)), file + ' keeps its copyright notice');
    if (/day-one-serif/.test(file)) {
      for (const r of n) if (r.id !== 0 && r.id !== 7) assert.doesNotMatch(r.text, /Source/, file + ' name ' + r.id + ': ' + r.text);
      assert.ok(n.some((r) => r.id === 1 && r.text === 'Day One Serif'), file + ' is named Day One Serif');
    }
  }
  // Nowhere the site serves names the reserved family: only comments explain where the serif came from.
  const served = ['styles.css', 'design.css', ...fs.readdirSync(path.join(root, 'css')).map((f) => 'css/' + f)];
  for (const f of served) assert.doesNotMatch(read(f).replace(/\/\*[\s\S]*?\*\//g, ''), /Source Serif/, f);
  assert.match(read('fonts/OFL-source-serif-4.txt'), /Reserved Font Name 'Source'/);
  const register = read('CONTENT-LICENSE.md');
  for (const file of Object.keys(FONTS)) assert.ok(register.includes('| `' + file + '` |'), file + ' is in the media register');
});

test('RK139: each font keeps the characters the site draws, and its fallback covers exactly the same ones', () => {
  // Basic Latin, the Latin-1 letters, and the punctuation and signs the pages use (Nov 10 scan of the site's files).
  const drawn = [];
  for (let c = 0x20; c <= 0x7e; c++) drawn.push(c);
  for (let c = 0xc0; c <= 0xff; c++) drawn.push(c);
  drawn.push(0xa0, 0xa7, 0xa9, 0xab, 0xae, 0xb0, 0xb1, 0xb7, 0xbb, 0x2013, 0x2014, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2026, 0x2032,
    0x2039, 0x203a, 0x20ac, 0x2122, 0x2212);
  for (const [file, f] of Object.entries(FONTS)) {
    const have = codepoints(woff2Tables(file).cmap);
    for (const c of drawn) assert.ok(have.has(c), file + ' lacks U+' + c.toString(16).toUpperCase());
    // The fallback faces are sized to match and cover only what the font has, so anything else comes from the next
    // font in the list, as before (styles.css).
    for (const fb of face(f.fallback)) {
      const range = fromRange(/unicode-range: ([^;]+);/.exec(fb)[1]);
      assert.deepStrictEqual([...range].sort((a, b) => a - b), [...have].filter((c) => c >= 0x20).sort((a, b) => a - b), f.fallback + ' covers what ' + file + ' has');
    }
  }
});

test('RK139: nothing asks for what the files no longer have: no width axis, no weight under 400', () => {
  const files = require('child_process').execSync('git ls-files', { cwd: root }).toString().split('\n')
    .filter((f) => /\.(css|html|js)$/.test(f) && !/^(test|design|tools|node_modules)\//.test(f) && f !== 'eslint.config.cjs');
  for (const f of files) {
    const text = read(f).replace(/@font-face \{[\s\S]*?\}/g, '');
    assert.doesNotMatch(text, /font-stretch|font-variation-settings|fontStretch|fontVariationSettings/, f + ' sets the width axis, which the files pin at 100');
    assert.doesNotMatch(text, /font-weight\s*[:=]\s*["']?(100|200|300|lighter)\b/, f + ' asks for a weight under 400');
  }
});

test('RK14, RK139: every page\'s first visit is under 400 KB, the paper and a project\'s page included', () => {
  for (const r of weigh()) assert.ok(r.bytes <= BUDGET, r.page + ' transfers ' + (r.bytes / 1024).toFixed(1) + ' KB on a first visit');
  const paper = weigh().find((r) => r.page === 'research/decision-loop.html');
  assert.ok(paper.files.includes('fonts/day-one-serif-italic.woff2'), 'the paper is weighed with all three fonts');
});
