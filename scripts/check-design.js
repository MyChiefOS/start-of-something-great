#!/usr/bin/env node
// The design as a check (Aaron, Nov 9: "Why don't the page align to design ... the design should align"; harness/PLAN.md,
// "Design alignment", item 1). Every page built from his handoff of Nov 5 (design/handoff-2026-11-05/static, mapped by
// tools/design/built.list), from a local copy of this folder, against the handoff page it was built from, in a real
// browser at 1280 and 390 px. Plus the chart canvas of Nov 7 (design/canvas-2026-11-07): its parts on the project page,
// the Build page and the home page.
//
//   node scripts/check-design.js [--empty] [--shots DIR] [--only page,page] [--json FILE]
//
// Data: the pages read the live site's public API, GET only and signed out (nothing is sent, nothing signed in), so
// they are measured with real data. --empty answers every list empty and every count 0, for the empty states.
// Fields this branch adds that the live API doesn't serve until its migration runs (054: task_count, next) are filled
// in here from what it does serve, and said so in the output.
//
// Measured on each pair, the handoff page against ours: the column (width, padding), the headline, kicker, intro and
// section heading (size, weight, spacing), the first card (padding, corners, top rule), how many cards share the first
// row of each row of cards, sideways scroll, and script errors. A difference over 1 px (0.5 px for type) fails unless
// it is listed in ACCEPTED below with its reason. --shots DIR saves the pair side by side, full length, at each width.
// Needs Playwright with Chromium; not part of the test suite.
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DESIGN = path.join(ROOT, 'design/handoff-2026-11-05/static');
const CANVAS = path.join(ROOT, 'design/canvas-2026-11-07');
const LIVE = 'https://dayonegreat.com';
const arg = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; };
const EMPTY = process.argv.includes('--empty');
const SHOTS = arg('--shots');
const ONLY = arg('--only') ? arg('--only').split(',') : null;
const JSON_OUT = arg('--json');
const WIDTHS = [1280, 390];
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json',
  '.woff2': 'font/woff2', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain', '.xml': 'application/xml', '.webmanifest': 'application/manifest+json' };

// Differences the design itself leaves open, each with its reason. Key: "<handoff page>:<width>:<measure>".
const ACCEPTED = {
  // The design draws Build's four task cards four to a row at every width (70 px each on a phone); the spec stacks
  // them (CODING_AGENT_SPEC.md 5.6; decided for JEVs, Nov 10, Q2).
  'build:390:cards.first-row': 'four cards stack on a phone (spec 5.6)',
};

// Our pages from their handoff pages (tools/design/built.list), and the address each is opened at.
function pairs() {
  const list = fs.readFileSync(path.join(ROOT, 'tools/design/built.list'), 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  return list.map((l) => { const [from, to] = l.split(/\s+/); return { from, to }; }).filter((p) => !ONLY || ONLY.includes(p.from.replace(/\.html$/, '')));
}
const ADDRESS = { 'index.html': '/', 'project.html': '/projects/:project', 'task.html': '/tasks/:task', 'agent.html': '/agents/:agent', 'room.html': '/rooms/:room',
  'receipt.html': '/receipts/:receipt', 'member.html': '/members/:member', 'citizen.html': '/citizens/:citizen', 'dispute.html': '/disputes/:dispute' };

// One real id of each kind, from the live public API (or none: the page then shows its "not found" state).
async function ids() {
  const get = async (p) => { try { const r = await fetch(LIVE + p); return r.ok ? r.json() : null; } catch { return null; } };
  const out = {};
  const pj = await get('/api/work/projects'); const p0 = pj && (pj.projects || [])[0];
  if (p0) out.project = p0.id;
  const pg = p0 && await get('/api/work/project?id=' + p0.id); const t0 = pg && (pg.tasks || [])[0];
  if (t0) out.task = t0.id;
  if (p0 && p0.room) out.room = p0.room.code;
  const ag = await get('/api/agents/'); const a0 = ag && (ag.agents || [])[0];
  if (a0) out.agent = a0.id || a0.agent_id;
  return out;
}

// The site, as Vercel serves it: its rewrites and clean addresses, its 404 page. The handoff under /__design/.
function server(vercel) {
  const rewrites = (vercel.rewrites || []).filter((r) => !r.destination.startsWith('/api')).map((r) => ({
    re: new RegExp('^' + r.source.replace(/:[a-z]+\*/gi, '.*').replace(/:[a-z]+(?=\()/gi, '').replace(/:[a-z]+/gi, '[^/]+') + '$'), to: r.destination }));
  return http.createServer((req, res) => {
    let url = decodeURIComponent(req.url.split('?')[0]);
    let base = ROOT;
    if (url.startsWith('/__design/')) { base = DESIGN; url = url.slice('/__design'.length); }
    else for (const r of rewrites) if (r.re.test(url)) { url = r.to; break; }
    let file = url === '/' ? 'index.html' : url.slice(1);
    if (!path.extname(file)) file += '.html';
    let full = path.resolve(base, file), body = null;
    if (full.startsWith(base + path.sep)) { try { body = fs.readFileSync(full); } catch { body = null; } }
    if (body === null) { res.statusCode = 404; if (path.extname(url)) return res.end('not found'); full = path.join(ROOT, '404.html'); body = fs.readFileSync(full); }
    res.setHeader('Content-Type', TYPES[path.extname(full)] || 'application/octet-stream');
    res.end(body);
  });
}

// --empty: every list emptied, every count 0, every percentage 0; ids, names and dates kept.
function emptied(x, key) {
  if (Array.isArray(x)) return [];
  if (x && typeof x === 'object') { const o = {}; for (const [k, v] of Object.entries(x)) o[k] = emptied(v, k); return o; }
  if (typeof x === 'number' && !/^(level|size|version|seq|number|limit|max|min|days)$/.test(key || '')) return 0;
  return x;
}
// 054's fields, from what the live API serves until 054 runs (said so in the output).
let shimmed = false;
function shim(pathname, search, d) {
  if (pathname === '/api/work/project' && d && Array.isArray(d.tasks) && d.task_count === undefined) {
    shimmed = true;
    const all = d.tasks, before = search.get('before');
    const from = before ? all.findIndex((t) => t.id === before) + 1 : 0;
    d.task_count = all.length; d.tasks = all.slice(from, from + 25); d.next = all.length > from + 25 ? all[from + 24].id : null;
  }
  return d;
}

const probe = () => {
  const px = (v) => Math.round(parseFloat(v) * 10) / 10;
  const box = (e) => { if (!e) return null; const s = getComputedStyle(e);
    return { fs: px(s.fontSize), fw: s.fontWeight, mt: px(s.marginTop), mb: px(s.marginBottom) }; };
  const shown = (e) => e && e.getClientRects().length > 0;
  const all = (sel) => [...document.querySelectorAll(sel)].filter((e) => shown(e) && !e.closest('header, footer, .hd, .sub2, nav'));
  const h1 = all('h1')[0] || null;
  const after = (e) => { let p = e && e.previousElementSibling; while (p && !shown(p)) p = p.previousElementSibling; return p; };
  // Like with like: the kicker over the headline; a section heading under a kicker, and one without.
  const kickTop = h1 && after(h1) && after(h1).classList.contains('kick') ? after(h1) : null;
  const h2s = all('h2').filter((e) => !e.classList.contains('h3')); // an h2.h3 is drawn as the design's h3 (spec 5.3)
  const h2k = h2s.find((e) => after(e) && after(e).classList.contains('kick')) || null;
  const h2 = h2s.find((e) => !(after(e) && after(e).classList.contains('kick'))) || null;
  const kickSec = h2k ? after(h2k) : null;
  const intro = all('.dek, .lede')[0] || null;
  const col = h1 ? h1.parentElement : document.body;
  const card = all('.card')[0], cs = card && getComputedStyle(card);
  // Rows of cards: for each element holding three or more cards, how many sit in its first row.
  const rows = all('*').filter((e) => [...e.children].filter((c) => c.classList.contains('card')).length >= 3)
    .map((e) => { const cards = [...e.children].filter((c) => c.classList.contains('card')); const top = cards[0].getBoundingClientRect().top; return cards.filter((c) => Math.abs(c.getBoundingClientRect().top - top) < 2).length + '/' + cards.length; });
  return {
    column: { w: Math.round(col.getBoundingClientRect().width), x: Math.round(col.getBoundingClientRect().left) },
    h1: box(h1), kick: box(kickTop), intro: box(intro), 'section kicker': box(kickSec), 'heading under a kicker': box(h2k), heading: box(h2),
    card: cs ? { p: cs.padding, r: cs.borderRadius, bt: cs.borderTopWidth } : null,
    rows: rows.join(' '),
    sideways: document.documentElement.scrollWidth > innerWidth + 1,
  };
};

// Each measure, ours against the design's: type within 0.5 px, everything else within 1 px, words exactly.
function compare(name, w, d, o) {
  const out = [];
  const note = (k, a, b) => { const key = name + ':' + w + ':' + k; if (!ACCEPTED[key]) out.push({ key, design: a, ours: b }); };
  const near = (a, b, tol) => Math.abs(a - b) <= tol;
  for (const part of ['h1', 'kick', 'intro', 'section kicker', 'heading under a kicker', 'heading']) {
    // A part the design's page doesn't have is compared on the next page that has it; one ours lacks is a difference.
    if (!d[part]) continue;
    if (!o[part]) { note(part, 'present', 'none'); continue; }
    if (!near(d[part].fs, o[part].fs, 0.5)) note(part + '.size', d[part].fs, o[part].fs);
    if (d[part].fw !== o[part].fw) note(part + '.weight', d[part].fw, o[part].fw);
    if (!near(d[part].mt, o[part].mt, 1)) note(part + '.above', d[part].mt, o[part].mt);
    if (!near(d[part].mb, o[part].mb, 1)) note(part + '.below', d[part].mb, o[part].mb);
  }
  if (d.card && o.card) for (const k of ['p', 'r', 'bt']) if (d.card[k] !== o.card[k]) note('card.' + k, d.card[k], o.card[k]);
  if (!near(d.column.w, o.column.w, 1) || !near(d.column.x, o.column.x, 1)) note('column', d.column, o.column);
  if (d.rows && o.rows && d.rows.split(' ')[0].split('/')[0] !== o.rows.split(' ')[0].split('/')[0]) note('cards.first-row', d.rows, o.rows);
  if (o.sideways) note('sideways', false, true);
  if (o.errors) note('script-errors', 0, o.errors);
  return out;
}

// The Nov 7 canvas's parts, on our pages (by the names its markup uses: design/canvas-2026-11-07).
const CANVAS_CHECKS = {
  '/projects/:project': [
    ['legend: planned, verified, scope, forecast', () => document.querySelectorAll('.lgd span').length >= 4],
    ['the chart', () => !!document.querySelector('#plan-chart svg')],
    ['milestone rows under the chart', () => document.querySelectorAll('#plan-chart .dia').length > 0],
    ['five figures: planned, verified, variance, index, forecast', () => ['f-planned', 'f-verified', 'f-variance', 'f-index', 'f-forecast'].every((i) => (document.getElementById(i) || {}).textContent !== '–')],
    ['status pills', () => document.querySelectorAll('#plan-status .pill').length >= 1],
    ['"Planned and actual dates"', () => document.querySelectorAll('#ms-rows tr, #ms-list li').length > 0],
    ['"Plan changes" and "How it’s figured"', () => !!document.getElementById('plan-changes').textContent.trim() && /How it.s figured/.test(document.body.textContent)],
    ['tasks a page at a time', () => document.querySelectorAll('#tasks tr').length <= 25],
  ],
  '/build': [
    ['the chart', () => !!document.querySelector('#plan-chart svg')],
    ['milestone pills', () => document.querySelectorAll('#plan-pills .pill').length > 0],
    ['four figures: planned scope, verified, share, milestones done', () => ['f-scope', 'f-verified', 'f-share', 'f-done'].every((i) => (document.getElementById(i) || {}).textContent !== '–')],
    ['"See the plan"', () => /\/projects\/[0-9a-f-]{36}$/.test((document.getElementById('plan-link') || {}).href || '')],
  ],
  '/': [
    ['the progress card: figure, bar, Open build and Leaderboard', () => { const c = document.getElementById('next'); return !!c && !c.hidden && /\d+%/.test(c.textContent) && !!c.querySelector('a[href="/build"]') && !!c.querySelector('a[href="/leaderboard"]'); }],
  ],
};

async function sideBySide(browser, a, b, w, file) {
  const page = await browser.newPage({ viewport: { width: w * 2 + 24, height: 400 } });
  const src = (buf) => 'data:image/png;base64,' + buf.toString('base64');
  await page.setContent('<body style="margin:0;background:#888;display:flex;gap:24px;align-items:flex-start"><img src="' + src(a) + '" width="' + w + '"><img src="' + src(b) + '" width="' + w + '"></body>');
  await page.waitForTimeout(200);
  await page.screenshot({ path: file, fullPage: true });
  await page.close();
}

(async () => {
  const { chromium } = require('playwright');
  if (!fs.existsSync(DESIGN)) { console.error('No handoff at ' + DESIGN); process.exit(2); }
  const vercel = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
  const known = await ids();
  const srv = server(vercel);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const browser = await chromium.launch();
  if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
  const report = { data: EMPTY ? 'empty' : 'live public API', pages: {}, canvas: {}, failures: [] };

  async function open(url, w) {
    const ctx = await browser.newContext({ viewport: { width: w, height: 900 }, colorScheme: 'dark' });
    await ctx.route(base + '/auth/me', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"signed_in":false}' }));
    await ctx.route(/giscus\.app/, (r) => r.abort());
    await ctx.route(base + '/api/**', async (r) => {
      if (r.request().method() !== 'GET') return r.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"not sent: a local design check"}' });
      const u = new URL(r.request().url());
      let status = 502, body = '{}';
      try { const live = await fetch(LIVE + u.pathname + u.search); status = live.status; body = await live.text();
        const d = shim(u.pathname, u.searchParams, JSON.parse(body)); body = JSON.stringify(EMPTY ? emptied(d) : d); } catch { /* left as answered */ }
      return r.fulfill({ status, contentType: 'application/json', body });
    });
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 });
    await page.waitForTimeout(600);
    return { ctx, page, errors };
  }

  for (const { from, to } of pairs()) {
    const tmpl = ADDRESS[to] || '/' + to.replace(/\.html$/, '').replace(/(^|\/)index$/, '');
    const missing = (tmpl.match(/:([a-z]+)/g) || []).map((m) => m.slice(1)).filter((k) => !known[k]);
    const ours = tmpl.replace(/:([a-z]+)/g, (m, k) => encodeURIComponent(known[k] || 'none'));
    const key = from + ' → ' + ours;
    report.pages[key] = {};
    for (const w of WIDTHS) {
      const d = await open(base + '/__design/' + from, w);
      const o = await open(base + ours, w);
      const dm = await d.page.evaluate(probe), om = { ...(await o.page.evaluate(probe)), errors: o.errors.length };
      const diffs = compare(from.replace(/\.html$/, ''), w, dm, om);
      report.pages[key][w] = { differences: diffs, note: missing.length ? 'no live ' + missing.join(', ') + ' to open it with' : undefined };
      for (const x of diffs) report.failures.push(key + ' @' + w + ' ' + x.key.split(':').pop() + ': design ' + JSON.stringify(x.design) + ', ours ' + JSON.stringify(x.ours));
      if (CANVAS_CHECKS[tmpl] && !EMPTY) {
        const res = [];
        for (const [label, fn] of CANVAS_CHECKS[tmpl]) { let ok = false; try { ok = await o.page.evaluate(fn); } catch { ok = false; } res.push([label, ok]); if (!ok) report.failures.push('canvas ' + tmpl + ' @' + w + ': ' + label); }
        report.canvas[tmpl + ' @' + w] = res;
      }
      if (SHOTS) {
        const a = await d.page.screenshot({ fullPage: true }), b = await o.page.screenshot({ fullPage: true });
        await sideBySide(browser, a, b, w, path.join(SHOTS, from.replace(/\.html$/, '') + '--' + to.replace(/[\/.]/g, '_') + '-' + w + (EMPTY ? '-empty' : '') + '.png'));
      }
      await d.ctx.close(); await o.ctx.close();
    }
  }
  await browser.close(); srv.close();
  if (shimmed) report.shim = 'The live API does not serve 054\'s task_count and next yet; they were filled in here from its task list.';
  if (JSON_OUT) fs.writeFileSync(JSON_OUT, JSON.stringify(report, null, 1));
  const n = Object.keys(report.pages).length;
  console.log('Design check (' + report.data + '): ' + n + ' page pairs at ' + WIDTHS.join(' and ') + ' px' + (fs.existsSync(CANVAS) ? ', with the Nov 7 canvas' : ''));
  if (report.shim) console.log(report.shim);
  for (const f of report.failures) console.log('  differs: ' + f);
  console.log(report.failures.length ? report.failures.length + ' differences.' : 'Every page matches its design.');
  process.exit(report.failures.length ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
