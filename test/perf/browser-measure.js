// SF1, SF2 browser measurement: loads each page in Chromium from a local copy served like Vercel (text compressed),
// sums the bytes actually transferred on a first visit (things other sites serve included), and with PHONE=1 times
// the largest paint and the layout shift on a slow phone (slow 4G, CPU 4x slower). The API isn't running, so pages
// that fill in from it are measured without their data. Results: PERFORMANCE.md.
// Needs playwright-core and a Chromium (not part of the site's dependencies):
//   npm i --no-save playwright-core@1.48.2 && CHROMIUM=/path/to/headless_shell [PHONE=1] node test/perf/browser-measure.js .
const http = require('http'), fs = require('fs'), path = require('path'), zlib = require('zlib');
const { chromium } = require('playwright-core');
const ROOT = path.resolve(process.argv[2] || '.');
const TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.jpg': 'image/jpeg', '.png': 'image/png', '.json': 'application/json' };
const srv = http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p.startsWith('/api/') || p.startsWith('/auth/')) { res.statusCode = 404; return res.end('{}'); }
  let f = path.join(ROOT, p);
  if (!path.extname(f)) f = f.endsWith('/') ? f + 'index.html' : f + '.html';
  if (!fs.existsSync(f)) { res.statusCode = 404; return res.end(); }
  let body = fs.readFileSync(f);
  const ext = path.extname(f);
  res.setHeader('Content-Type', TYPES[ext] || 'application/octet-stream');
  if (/\.(html|css|js|svg|json)$/.test(ext)) { body = zlib.gzipSync(body, { level: 6 }); res.setHeader('Content-Encoding', 'gzip'); }
  res.setHeader('Content-Length', body.length);
  res.end(body);
}).listen(0, async () => {
  const port = srv.address().port;
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM });
  const pages = fs.readdirSync(ROOT).filter((x) => x.endsWith('.html')).map((x) => '/' + x.replace(/\.html$/, '').replace(/^index$/, ''))
    .concat(fs.readdirSync(path.join(ROOT, 'research')).filter((x) => x.endsWith('.html')).map((x) => '/research/' + x.replace(/\.html$/, '')))
    .filter((p) => !process.env.PAGES || process.env.PAGES.split(',').includes(p));
  const out = [];
  for (const p of pages) {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('Network.enable');
    if (process.env.PHONE) {
      // A mid-range phone on a slow 4G connection (Lighthouse's mobile settings): 150 ms, 1.6 Mbps down, CPU 4x slower.
      await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: 150, downloadThroughput: 1.6 * 1024 * 1024 / 8, uploadThroughput: 750 * 1024 / 8 });
      await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
      await page.addInitScript(() => { window.__lcp = 0; window.__cls = 0; window.__shifts = []; new PerformanceObserver((l) => { for (const e of l.getEntries()) window.__lcp = e.startTime; }).observe({ type: 'largest-contentful-paint', buffered: true });
        new PerformanceObserver((l) => { for (const e of l.getEntries()) if (!e.hadRecentInput) { window.__cls += e.value; window.__shifts.push(+e.value.toFixed(3) + ' at ' + Math.round(e.startTime) + ' ms: ' + (e.sources || []).map((x) => x.node ? (x.node.nodeName + (x.node.className ? '.' + String(x.node.className).split(' ')[0] : '')) : '?').join(', ')); } }).observe({ type: 'layout-shift', buffered: true }); });
    }
    let total = 0; const files = [];
    cdp.on('Network.loadingFinished', (e) => { total += e.encodedDataLength; });
    cdp.on('Network.responseReceived', (e) => files.push(new URL(e.response.url).pathname));
    await page.goto('http://127.0.0.1:' + port + p, { waitUntil: 'networkidle' });
    await page.waitForTimeout(300);
    const v = process.env.PHONE ? await page.evaluate(() => ({ lcp: Math.round(window.__lcp), cls: +window.__cls.toFixed(3), shifts: window.__shifts })) : {};
    out.push({ page: p, kb: +(total / 1024).toFixed(1), fonts: files.filter((f) => f.endsWith('.woff2')).length, ...v });
    await ctx.close();
  }
  await browser.close(); srv.close();
  out.sort((a, b) => b.kb - a.kb);
  for (const r of out) console.log(String(r.kb).padStart(7), 'KB', r.fonts, 'fonts', r.page, r.lcp !== undefined ? 'LCP ' + r.lcp + ' ms, CLS ' + r.cls : '');
  // Which elements moved, for pages over 0.1.
  for (const r of out) if (r.cls > 0.1) console.log(r.page, r.shifts.join(' | '));
});
