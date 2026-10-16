// SF1 (layout shift): how well the fallback fonts stand in for the real ones. Each page is laid out twice in Chromium
// at phone width: once with our font files blocked, so only the sized fallbacks in styles.css draw the text, and once
// with the fonts loaded. It reports how far the page's blocks move between the two (the shift a visitor sees when the
// fonts arrive late), which fallback faces the browser could use, and the page height in each.
// Timing-free, so the same fonts give the same numbers every run. Results: PERFORMANCE.md.
// To check Android, run it with only Android's fonts installed (Roboto and Noto Serif), through a fontconfig file:
//   FONTCONFIG_FILE=android-fonts.conf CHROMIUM=/path/to/headless_shell node test/perf/fallback-fit.js . /connect /proposals
// Needs playwright-core and a Chromium (not part of the site's dependencies), as test/perf/browser-measure.js does.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path');
const { chromium } = require('playwright-core');
const ROOT = path.resolve(process.argv[2] || '.');
const PAGES = process.argv.slice(3).length ? process.argv.slice(3) : ['/', '/handshake', '/connect', '/proposals', '/shipped', '/join', '/talk', '/research/decision-loop'];
const TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.jpg': 'image/jpeg' };

const srv = http.createServer((req, res) => {
  const p = decodeURIComponent(req.url.split('?')[0]);
  let f = path.join(ROOT, p);
  if (!path.extname(f)) f = f.endsWith('/') ? f + 'index.html' : f + '.html';
  if (p.startsWith('/api/') || !fs.existsSync(f)) { res.statusCode = 404; return res.end(); }
  res.setHeader('Content-Type', TYPES[path.extname(f)] || 'application/octet-stream');
  res.end(fs.readFileSync(f));
}).listen(0, async () => {
  const base = 'http://127.0.0.1:' + srv.address().port;
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM });
  // Where every block in <main> sits, and which fallback faces could load.
  const layout = async (p, blockFonts) => {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const page = await ctx.newPage();
    if (blockFonts) await page.route('**/*.woff2', (r) => r.abort());
    await page.goto(base + p, { waitUntil: 'load' });
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(100);
    const out = await page.evaluate(() => {
      const boxes = [...document.querySelectorAll('main p, main h1, main h2, main h3, main li, main blockquote, main pre, main table, main figure, main ol, main ul')]
        .map((e) => { const r = e.getBoundingClientRect(); return { top: r.top + scrollY, h: r.height }; });
      const faces = [...document.fonts].filter((f) => /Fallback/.test(f.family)).map((f) => f.family + ' ' + f.style + ' ' + f.weight + ': ' + f.status);
      return { boxes, faces, height: document.documentElement.scrollHeight };
    });
    await ctx.close();
    return out;
  };
  for (const p of PAGES) {
    const a = await layout(p, true), b = await layout(p, false);
    const n = Math.min(a.boxes.length, b.boxes.length);
    let worst = 0, sum = 0, inView = 0;
    for (let i = 0; i < n; i++) {
      const d = Math.abs(a.boxes[i].top - b.boxes[i].top);
      worst = Math.max(worst, d); sum += d;
      if (b.boxes[i].top < 844) inView = Math.max(inView, d);
    }
    console.log(p.padEnd(24), 'blocks', String(n).padStart(4), ' worst move', worst.toFixed(0).padStart(5), 'px  mean', (n ? sum / n : 0).toFixed(1).padStart(6),
      'px  worst in the first screen', inView.toFixed(0).padStart(4), 'px  height', a.height, '->', b.height);
    if (process.env.FACES) console.log('   ', [...new Set(a.faces)].join(' | '));
  }
  await browser.close(); srv.close();
});
