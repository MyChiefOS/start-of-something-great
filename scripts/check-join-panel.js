#!/usr/bin/env node
// /join's sign-in panel in a real browser, on a local copy of the site (UX PR A, the UI/UX review of Oct 31, findings
// 1, 7 and 15). It serves the files itself, with /join's own security policy from vercel.json, and answers the three
// sign-in requests with stand-ins, so nothing reaches the live site and no real code is made. giscus is blocked: its
// box stays an empty container, which is all the layout checks need.
//
//   node scripts/check-join-panel.js [--root DIR] [--shots DIR] [--no-checks]
//
// Checks, at 390 by 844 px and at 1280 by 800 px, in dark and light:
//   - once a path is chosen, the username field and that path's primary button are in the first screen;
//   - every control in the panel (buttons, fields, disclosures) is at least 44 px tall;
//   - the comment box starts within 200 px below the Copy button;
//   - Copy changes to "Copied"; when the clipboard is refused, the code is selected and the page says so;
//   - the countdown shows the code's time left, and "Get a new code" appears when it runs out;
//   - the live region's text changes at most 3 times during a 30-second wait;
//   - no sideways scrolling, and no script errors or security-policy refusals.
// --shots DIR saves screenshots; --no-checks only takes them (for the "before" copy, which has no panel).
// Needs Playwright with Chromium (`require('playwright')`); not part of the test suite, which runs without a browser.
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const arg = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; };
const ROOT = path.resolve(arg('--root') || path.join(__dirname, '..'));
const SHOTS = arg('--shots');
const CHECKS = !process.argv.includes('--no-checks');
const CODE = 'DOG-7K4M-Q2XH';
const SIZES = [{ name: '390', width: 390, height: 844 }, { name: '1280', width: 1280, height: 800 }];
const SCHEMES = ['dark', 'light'];
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2', '.png': 'image/png', '.txt': 'text/plain', '.json': 'application/json' };

// A static copy of the site with Vercel's clean addresses (/join is join.html) and /join's security policy.
function serve() {
  const vercel = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
  const csp = vercel.headers.find((h) => h.source === '/join').headers.find((x) => x.key === 'Content-Security-Policy').value
    .replace(/;\s*upgrade-insecure-requests/, ''); // the local copy is plain http
  return http.createServer((req, res) => {
    const url = decodeURIComponent(req.url.split('?')[0]);
    let file = url === '/' ? 'index.html' : url.slice(1);
    if (!path.extname(file)) file += '.html';
    const full = path.join(ROOT, file);
    if (!full.startsWith(ROOT + path.sep) || !fs.existsSync(full) || !fs.statSync(full).isFile()) { res.statusCode = 404; return res.end('not found'); }
    res.setHeader('Content-Type', TYPES[path.extname(full)] || 'application/octet-stream');
    if (url === '/join') res.setHeader('Content-Security-Policy', csp);
    res.end(fs.readFileSync(full));
  });
}

async function main() {
  const { chromium } = require('playwright');
  const server = serve();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch();
  const problems = [];
  const fail = (where, what) => problems.push(where + ': ' + what);
  if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
  try {
    for (const size of SIZES) {
      for (const scheme of SCHEMES) {
        const where = size.name + ' ' + scheme;
        const ctx = await browser.newContext({ viewport: { width: size.width, height: size.height }, colorScheme: scheme });
        const p = await open(ctx, base, where, fail, {});
        const shot = async (name, full) => { if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'join-' + size.name + '-' + scheme + '-' + name + '.png'), fullPage: full }); };
        await shot('fold', false);
        await shot('full', true);
        const panel = CHECKS || (await p.locator('#path-new').count());
        if (panel) {
          await p.click('#path-new');
          if (CHECKS) {
            await inFirstScreen(p, ['#code-login', '#code-get'], where + ', first time', fail);
            await tallEnough(p, where + ', first time', fail);
          }
          await shot('first-time-fold', false);
        }
        await p.fill('#code-login', 'coder');
        await p.setInputFiles('#code-file', { name: 'key.jpg', mimeType: 'image/jpeg', buffer: Buffer.from('a private file') });
        await p.click('#code-get');
        await p.waitForSelector('#code-show', { state: 'visible', timeout: 5000 });
        if (CHECKS) {
          await tallEnough(p, where + ', code shown', fail);
          const gap = await p.evaluate(() => document.querySelector('.talk-replies').getBoundingClientRect().top - document.getElementById('code-copy').getBoundingClientRect().bottom);
          if (!(gap >= 0 && gap <= 200)) fail(where, 'the comment box is ' + Math.round(gap) + ' px below Copy (at most 200)');
          const left = await p.textContent('#code-time');
          if (!/^Expires in (10:00|9:[0-5]\d)$/.test(left.trim())) fail(where, 'the countdown says "' + left + '"');
          if ((await p.textContent('#code-value')) !== CODE) fail(where, 'the code shown is not the code the server gave');
          await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: base });
          await p.click('#code-copy');
          await p.waitForTimeout(200);
          if ((await p.textContent('#code-copy')).trim() !== 'Copied') fail(where, 'Copy did not change to "Copied"');
          const copied = await p.evaluate(() => navigator.clipboard.readText());
          if (copied !== '\n\n' + CODE + '\n\n') fail(where, 'Copy put ' + JSON.stringify(copied) + ' on the clipboard');
          const sideways = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
          if (sideways > 0) fail(where, 'the page scrolls sideways by ' + sideways + ' px');
        }
        await p.locator('#code-copy').scrollIntoViewIfNeeded();
        await shot('code-fold', false);
        await shot('code-full', true);
        if (CHECKS) {
          await p.click('#path-back');
          await inFirstScreen(p, ['#code-login', '#key-signin'], where + ', signed in before', fail);
          await tallEnough(p, where + ', signed in before', fail);
        }
        await ctx.close();
      }
    }
    if (CHECKS) await clipboardRefused(browser, base, fail);
    if (CHECKS) await waitAndExpire(browser, base, fail);
  } finally {
    await browser.close();
    server.close();
  }
  if (problems.length) {
    console.log('FAIL /join panel (local copy of ' + ROOT + ')\n' + problems.map((x) => '  ' + x).join('\n'));
    process.exitCode = 1;
  } else {
    console.log('OK /join panel (local copy of ' + ROOT + '): ' + (CHECKS ? 'all checks at 390 and 1280 px, dark and light' : 'screenshots only') + (SHOTS ? '; screenshots in ' + SHOTS : ''));
  }
}

// One page of /join, signed out, with the sign-in requests answered by stand-ins and giscus blocked.
async function open(ctx, base, where, fail, { clock }) {
  await ctx.route('https://giscus.app/**', (r) => r.abort());
  await ctx.route('**/_vercel/**', (r) => r.abort());
  await ctx.route('**/auth/me', (r) => r.fulfill({ json: { signed_in: false } }));
  await ctx.route('**/auth/code/start', (r) => r.fulfill({ json: { code: CODE, expires_in: 600 } }));
  await ctx.route('**/auth/code/finish', (r) => r.fulfill({ json: { waiting: true } }));
  const p = await ctx.newPage();
  if (clock) await p.clock.install();
  p.on('pageerror', (e) => fail(where, 'script error: ' + e.message));
  p.on('console', (m) => { if (m.type() === 'error' && !/giscus|ERR_FAILED|_vercel/.test(m.text() + JSON.stringify(m.location()))) fail(where, 'console: ' + m.text()); });
  await p.goto(base + '/join', { waitUntil: 'domcontentloaded' });
  await p.waitForSelector('#code-signin', { state: 'visible', timeout: 5000 });
  return p;
}

async function inFirstScreen(p, sels, where, fail) {
  await p.evaluate(() => window.scrollTo(0, 0));
  for (const sel of sels) {
    const box = await p.evaluate((s) => { const r = document.querySelector(s).getBoundingClientRect(); return { top: r.top, bottom: r.bottom, h: window.innerHeight, shown: r.height > 0 }; }, sel);
    if (!box.shown || box.top < 0 || box.bottom > box.h) fail(where, sel + ' is not in the first screen (' + Math.round(box.top) + ' to ' + Math.round(box.bottom) + ' of ' + box.h + ' px)');
  }
}

// Every control a person can tap in the panel: buttons, fields and disclosures, wherever they show.
async function tallEnough(p, where, fail) {
  const small = await p.evaluate(() => [...document.querySelectorAll('#code-signin button, #code-signin input, #code-signin summary')]
    .filter((e) => e.getClientRects().length).map((e) => ({ id: e.id || e.textContent.trim().slice(0, 30), h: e.getBoundingClientRect().height }))
    .filter((x) => x.h < 44));
  for (const s of small) fail(where, '"' + s.id + '" is ' + s.h.toFixed(1) + ' px tall (at least 44)');
}

// A browser that refuses the clipboard: the code is selected and the page says how to copy it by hand.
async function clipboardRefused(browser, base, fail) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  await ctx.addInitScript(() => { Object.defineProperty(navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('refused')) } }); });
  const p = await open(ctx, base, 'clipboard refused', fail, {});
  await p.click('#path-new');
  await p.fill('#code-login', 'coder');
  await p.setInputFiles('#code-file', { name: 'key.jpg', mimeType: 'image/jpeg', buffer: Buffer.from('a private file') });
  await p.click('#code-get');
  await p.waitForSelector('#code-show', { state: 'visible' });
  await p.click('#code-copy');
  await p.waitForTimeout(200);
  if ((await p.evaluate(() => String(window.getSelection()))) !== CODE) fail('clipboard refused', 'the code is not selected');
  if (!/selected/.test(await p.textContent('#code-status'))) fail('clipboard refused', 'the page does not say the code is selected: "' + (await p.textContent('#code-status')) + '"');
  if ((await p.textContent('#code-copy')).trim() === 'Copied') fail('clipboard refused', 'Copy says "Copied" though nothing was copied');
  if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'join-390-light-clipboard-refused.png') });
  await ctx.close();
}

// A 30-second wait with the page's own clock: the live region changes at most 3 times; then the code runs out.
async function waitAndExpire(browser, base, fail) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const q = await open(ctx, base, 'wait', fail, { clock: true });
  await q.click('#path-new');
  await q.fill('#code-login', 'coder');
  await q.setInputFiles('#code-file', { name: 'key.jpg', mimeType: 'image/jpeg', buffer: Buffer.from('a private file') });
  await q.evaluate(() => {
    window.__said = [];
    const s = document.getElementById('code-status');
    new MutationObserver(() => window.__said.push(s.textContent)).observe(s, { childList: true, characterData: true, subtree: true });
  });
  await q.click('#code-get');
  await q.waitForSelector('#code-show', { state: 'visible' });
  for (let i = 0; i < 30; i++) { await q.clock.runFor(1000); await q.waitForTimeout(5); }
  const said = await q.evaluate(() => window.__said);
  if (said.length > 3) fail('wait', 'the live region changed ' + said.length + ' times in 30 seconds: ' + JSON.stringify(said));
  const waited = await q.textContent('#code-wait');
  if (!/\b(29|30|31) s\b/.test(waited)) fail('wait', 'the seconds line says "' + waited + '" after 30 seconds');
  await q.clock.runFor(10 * 60 * 1000);
  await q.waitForTimeout(50);
  if (!(await q.isVisible('#code-new'))) fail('expiry', '"Get a new code" does not show once the code runs out');
  if (await q.isVisible('#code-show')) fail('expiry', 'the expired code still shows');
  if (await q.isVisible('#code-get')) fail('expiry', 'two buttons for a new code show at once');
  if (SHOTS) await q.screenshot({ path: path.join(SHOTS, 'join-390-light-expired.png') });
  console.log('live region during a 30-second wait: ' + said.length + ' change(s): ' + JSON.stringify(said));
  await ctx.close();
}

main().catch((e) => { console.error(e && e.stack); process.exitCode = 2; });
