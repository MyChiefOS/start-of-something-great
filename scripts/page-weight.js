// SF2: what a first visit to each page transfers. For every page it adds up the page and everything the page makes a
// browser fetch: stylesheets, scripts, images and the fonts it uses. Things fetched from other sites (the giscus
// comments on /talk) aren't counted here; the browser measurement in PERFORMANCE.md includes them. Text is counted gzipped (Vercel
// sends text compressed; brotli is a little smaller still, so this errs high); fonts and images as they are.
// Usage: node scripts/page-weight.js   (prints each page; exits 1 if any page is over the budget)
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.join(__dirname, '..');
const BUDGET = 400 * 1024;
const TEXT = /\.(html|css|js|svg|txt|json)$/;

function local(ref) {
  if (!ref || /^(https?:|data:|mailto:|#)/.test(ref) || ref.startsWith('//')) return null;
  const clean = ref.split(/[?#]/)[0];
  const p = path.join(ROOT, clean.startsWith('/') ? clean.slice(1) : clean);
  return fs.existsSync(p) && fs.statSync(p).isFile() ? p : null;
}
function size(file) {
  const buf = fs.readFileSync(file);
  return TEXT.test(file) ? zlib.gzipSync(buf, { level: 9 }).length : buf.length;
}

// Everything one page makes the browser fetch on a first visit (each file once).
function assets(page) {
  const html = fs.readFileSync(page, 'utf8');
  const found = new Set();
  const refs = [];
  for (const m of html.matchAll(/<link\b[^>]*\brel="(?:stylesheet|icon|preload)"[^>]*\bhref="([^"]+)"/g)) refs.push(m[1]);
  for (const m of html.matchAll(/<link\b[^>]*\bhref="([^"]+)"[^>]*\brel="(?:stylesheet|icon|preload)"/g)) refs.push(m[1]);
  for (const m of html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)) refs.push(m[1]);
  for (const m of html.matchAll(/<img\b[^>]*\bsrc="([^"]+)"/g)) refs.push(m[1]);
  for (const r of refs) {
    const p = local(r);
    if (!p || found.has(p)) continue;
    found.add(p);
    if (p.endsWith('.css')) {
      // A browser fetches a font only if the page uses it: the italic face only where something is set in italics.
      const italic = /<em\b|<i\b|<cite\b|<blockquote\b|class="[^"]*\b(signoff|note)\b/.test(html);
      for (const m of fs.readFileSync(p, 'utf8').matchAll(/url\(["']?([^"')]+)["']?\)/g)) {
        const f = local(m[1]);
        if (f && (italic || !/italic/.test(f))) found.add(f);
      }
    }
  }
  return [...found];
}

function pages() {
  const top = fs.readdirSync(ROOT).filter((f) => f.endsWith('.html')).map((f) => path.join(ROOT, f));
  const research = fs.existsSync(path.join(ROOT, 'research')) ? fs.readdirSync(path.join(ROOT, 'research')).filter((f) => f.endsWith('.html')).map((f) => path.join(ROOT, 'research', f)) : [];
  return top.concat(research);
}

function weigh() {
  return pages().map((p) => {
    const files = [p].concat(assets(p));
    return { page: path.relative(ROOT, p), bytes: files.reduce((n, f) => n + size(f), 0), files: files.map((f) => path.relative(ROOT, f)) };
  }).sort((a, b) => b.bytes - a.bytes);
}

if (require.main === module) {
  const rows = weigh();
  for (const r of rows) console.log((r.bytes / 1024).toFixed(1).padStart(7) + ' KB  ' + r.page);
  const over = rows.filter((r) => r.bytes > BUDGET);
  console.log(over.length ? over.length + ' over the ' + BUDGET / 1024 + ' KB budget' : 'all pages under ' + BUDGET / 1024 + ' KB');
  process.exit(over.length ? 1 : 0);
}

module.exports = { weigh, BUDGET };
