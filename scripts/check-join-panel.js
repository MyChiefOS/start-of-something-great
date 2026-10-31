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
//   - the borders of the fields and the path buttons are at least 3:1 against the page (WCAG 2.2, 1.4.11);
//   - right after "Get a sign-in code", with no scrolling by hand: the fields fold to the username and "Change", the
//     Get button hides, focus is on the "Post your code" heading and Copy's bottom edge is on the screen;
//   - the "Post your code here" heading and the comment box start within 200 px below the Copy button;
//   - Copy says "Copied. Paste it in the box below." once, in its own line; when the clipboard is refused, the code is
//     selected and that line says so, still after 5 seconds of waiting checks;
//   - the countdown shows the code's time left; when the server says the code is gone, or it runs out, "Get a new code"
//     appears and has focus;
//   - back from GitHub (a fresh load of /join with a kept code): the code step is on the screen, its heading has focus, and the page
//     says "Your code is still here. Press Copy again, then paste it below." (and after a reload); with a code that ran out meanwhile, it says
//     so, with the username (focused), that message and "Get a new code" all on the screen;
//   - no promised time ("usually", "10 to 20 seconds") anywhere on the page;
//   - the live region's text changes at most 3 times during a 30-second wait;
//   - no sideways scrolling, and no script errors or security-policy refusals.
// --shots DIR saves screenshots: the first screen, right after Get, the expired state and the returned state;
// --no-checks only takes them (for the "before" copy).
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
        const finish = { answer: { waiting: true } };
        const p = await open(ctx, base, where, fail, { finish });
        const shot = async (name, full) => { if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'join-' + size.name + '-' + scheme + '-' + name + '.png'), fullPage: full }); };
        await shot('1-first-screen', false);
        const panel = CHECKS || (await p.locator('#path-new').count());
        if (panel) {
          await p.click('#path-new');
          if (CHECKS) {
            await inFirstScreen(p, ['#code-login', '#code-get'], where + ', first time', fail);
            await tallEnough(p, where + ', first time', fail);
            await bordersContrast(p, where, fail);
            await noPromisedTime(p, where, fail);
          }
        }
        await p.evaluate(() => window.scrollTo(0, 0));
        await p.fill('#code-login', 'coder');
        await p.setInputFiles('#code-file', { name: 'key.jpg', mimeType: 'image/jpeg', buffer: Buffer.from('a private file') });
        await p.click('#code-get');
        await p.waitForSelector('#code-show', { state: 'visible', timeout: 5000 });
        await p.waitForTimeout(100);
        await shot('2-after-get', false);
        if (CHECKS) {
          await afterGet(p, where, fail);
          await tallEnough(p, where + ', code shown', fail);
          const gap = await p.evaluate(() => {
            const copy = document.getElementById('code-copy').getBoundingClientRect().bottom;
            return { box: document.querySelector('.talk-replies').getBoundingClientRect().top - copy, head: document.getElementById('post-here').getBoundingClientRect().top - copy,
              headShown: document.getElementById('post-here').getClientRects().length > 0, label: document.getElementById('say-hello').getAttribute('aria-labelledby') };
          });
          if (!(gap.box >= 0 && gap.box <= 200)) fail(where, 'the comment box is ' + Math.round(gap.box) + ' px below Copy (at most 200)');
          if (!gap.headShown || !(gap.head >= 0 && gap.head <= 200)) fail(where, 'the "Post your code here" heading is ' + (gap.headShown ? Math.round(gap.head) + ' px below Copy (at most 200)' : 'not shown'));
          if (gap.label !== 'post-here') fail(where, 'the comment box section is named by #' + gap.label + ', not its heading');
          const left = await p.textContent('#code-time');
          if (!/^Expires in (10:00|9:[0-5]\d)$/.test(left.trim())) fail(where, 'the countdown says "' + left + '"');
          if ((await p.textContent('#code-value')) !== CODE) fail(where, 'the code shown is not the code the server gave');
          await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: base });
          await p.evaluate(() => {
            window.__copied = [];
            const s = document.getElementById('code-copied');
            new MutationObserver(() => window.__copied.push(s.textContent)).observe(s, { childList: true, characterData: true, subtree: true });
          });
          await p.click('#code-copy');
          await p.waitForTimeout(200);
          if ((await p.textContent('#code-copy')).trim() !== 'Copied') fail(where, 'Copy did not change to "Copied"');
          const said = (await p.evaluate(() => window.__copied)).filter((x) => x);
          if (said.length !== 1 || said[0] !== 'Copied. Paste it in the box below.') fail(where, 'after Copy the copy line said ' + JSON.stringify(said));
          const copied = await p.evaluate(() => navigator.clipboard.readText());
          if (copied !== '\n\n' + CODE + '\n\n') fail(where, 'Copy put ' + JSON.stringify(copied) + ' on the clipboard');
          const sideways = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
          if (sideways > 0) fail(where, 'the page scrolls sideways by ' + sideways + ' px');
          await p.click('#code-change');
          if (!(await p.isVisible('#code-login')) || !(await p.isVisible('#code-get'))) fail(where, '"Change" does not open the fields again');
          await p.click('#path-back');
          await inFirstScreen(p, ['#code-login', '#key-signin'], where + ', has a key file', fail);
          await tallEnough(p, where + ', has a key file', fail);
          await p.click('#path-new');
        }
        // The server says the code is gone: "Get a new code" takes its place, with focus.
        finish.answer = { expired: true };
        await p.waitForSelector('#code-new', { state: 'visible', timeout: 5000 });
        await p.waitForTimeout(100);
        if (CHECKS) {
          if ((await p.evaluate(() => document.activeElement && document.activeElement.id)) !== 'code-new') fail(where + ', gone', 'focus is not on "Get a new code"');
          if (await p.isVisible('#code-show')) fail(where + ', gone', 'the used code still shows');
        }
        await shot('3-expired', false);
        // Back from GitHub with the code kept, in this same tab.
        finish.answer = { waiting: true };
        // giscus sends the tab back to /join with its own ?giscus= parameter: a fresh page load, not a reload.
        await p.evaluate((c) => sessionStorage.setItem('dog-code', JSON.stringify({ code: c, until: Date.now() + 300000 })), CODE);
        await p.goto(base + '/join?giscus=x', { waitUntil: 'domcontentloaded' });
        await p.waitForSelector('#code-show', { state: 'visible', timeout: 5000 });
        await p.waitForTimeout(150);
        if (CHECKS) await returned(p, where, fail);
        await shot('4-returned', false);
        // A reload of the same tab, where the browser restores the old scroll position: three times, as it raced once.
        if (CHECKS) {
          for (let i = 0; i < 3; i++) {
            await p.evaluate(() => window.scrollTo(0, 0));
            await p.reload({ waitUntil: 'load' });
            await p.waitForSelector('#code-show', { state: 'visible', timeout: 5000 });
            await p.waitForTimeout(150);
            await returned(p, where + ', reload ' + (i + 1), fail);
          }
        }
        // Back from GitHub after the code ran out meanwhile.
        if (CHECKS) {
          await p.evaluate((c) => sessionStorage.setItem('dog-code', JSON.stringify({ code: c, until: Date.now() - 1000 })), CODE);
          await p.goto(base + '/join?giscus=y', { waitUntil: 'domcontentloaded' });
          await p.waitForSelector('#code-new', { state: 'visible', timeout: 5000 });
          await p.waitForTimeout(100);
          const st = await p.textContent('#code-status');
          if (!/^Your code ran out\./.test(st)) fail(where + ', ran out while away', 'the page says "' + st + '"');
          if (await p.isVisible('#code-show')) fail(where + ', ran out while away', 'the old code shows');
          if ((await p.evaluate(() => document.activeElement && document.activeElement.id)) !== 'code-login') fail(where + ', ran out while away', 'focus is not on the username, which is needed again');
          for (const sel of ['#code-login', '#code-status', '#code-new']) {
            const r = await p.evaluate((x) => { const b = document.querySelector(x).getBoundingClientRect(); return { top: b.top, bottom: b.bottom, h: window.innerHeight }; }, sel);
            if (!(r.top >= 0 && r.bottom <= r.h)) fail(where + ', ran out while away', sel + ' is at ' + Math.round(r.top) + ' to ' + Math.round(r.bottom) + ' px of ' + r.h + ' (should be on the screen)');
          }
          if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'join-' + size.name + '-' + scheme + '-5-ran-out-away.png') });
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
async function open(ctx, base, where, fail, { clock, finish }) {
  await ctx.route('https://giscus.app/**', (r) => r.abort());
  await ctx.route('**/_vercel/**', (r) => r.abort());
  await ctx.route('**/auth/me', (r) => r.fulfill({ json: { signed_in: false } }));
  await ctx.route('**/auth/code/start', (r) => r.fulfill({ json: { code: CODE, expires_in: 600 } }));
  await ctx.route('**/auth/code/finish', (r) => r.fulfill({ json: finish ? finish.answer : { waiting: true } }));
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

// Right after "Get a sign-in code", before anyone scrolls: the fields fold to one line, Get hides, the code step's
// heading has focus and Copy is on the screen (the design review of PR A, fix 1).
async function afterGet(p, where, fail) {
  const s = await p.evaluate(() => {
    const copy = document.getElementById('code-copy').getBoundingClientRect();
    return { bottom: copy.bottom, top: copy.top, h: window.innerHeight, focus: document.activeElement && document.activeElement.id,
      line: document.getElementById('signin-as').getClientRects().length ? document.getElementById('signin-as').textContent.replace(/\s+/g, ' ').trim() : null,
      fields: document.getElementById('field-set').getClientRects().length > 0, get: document.getElementById('code-get').getClientRects().length > 0 };
  });
  if (!(s.top >= 0 && s.bottom <= s.h)) fail(where + ', after Get', 'Copy is at ' + Math.round(s.top) + ' to ' + Math.round(s.bottom) + ' px of ' + s.h + ' (should be on the screen)');
  if (s.focus !== 'code-title') fail(where + ', after Get', 'focus is on #' + s.focus + ', not the "Post your code" heading');
  if (s.line !== 'Signing in as coder Change') fail(where + ', after Get', 'the folded line says ' + JSON.stringify(s.line));
  if (s.fields) fail(where + ', after Get', 'the fields still show');
  if (s.get) fail(where + ', after Get', 'the Get button still shows');
}

// Back from GitHub with a kept code (the sign-in simulation, fix 3).
async function returned(p, where, fail) {
  const s = await p.evaluate(() => {
    const copy = document.getElementById('code-copy').getBoundingClientRect();
    const title = document.getElementById('code-title').getBoundingClientRect();
    return { top: title.top, bottom: copy.bottom, h: window.innerHeight, focus: document.activeElement && document.activeElement.id, said: document.getElementById('code-status').textContent };
  });
  where += ', returned';
  if (!(s.top >= 0 && s.bottom <= s.h)) fail(where, 'the code step runs ' + Math.round(s.top) + ' to ' + Math.round(s.bottom) + ' px of ' + s.h + ' (should be on the screen)');
  if (s.focus !== 'code-title') fail(where, 'focus is on #' + s.focus + ', not the code step');
  if (s.said !== 'Your code is still here. Press Copy again, then paste it below.') fail(where, 'the page says "' + s.said + '"');
}

// WCAG 2.2, 1.4.11: the edges of the fields and the path buttons against the page behind them, at least 3:1.
async function bordersContrast(p, where, fail) {
  const out = await p.evaluate(() => {
    const rgb = (c) => (c.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
    const lum = ([r, g, b]) => [r, g, b].map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }).reduce((a, v, i) => a + v * [0.2126, 0.7152, 0.0722][i], 0);
    const ratio = (a, b) => { const x = lum(rgb(a)), y = lum(rgb(b)); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
    const page = getComputedStyle(document.body).backgroundColor;
    return ['#path-new', '#path-back', '#code-login', '#code-file'].map((s) => ({ s, r: ratio(getComputedStyle(document.querySelector(s)).borderTopColor, page) }));
  });
  for (const o of out) if (!(o.r >= 3)) fail(where, o.s + "'s border is " + o.r.toFixed(2) + ':1 against the page (at least 3:1)');
  if (where === '390 dark' || where === '390 light') console.log('borders, ' + where + ': ' + out.map((o) => o.s + ' ' + o.r.toFixed(2) + ':1').join(', '));
}

// Nothing measures how long GitHub takes to pass a post on, so the page promises no time (the design review, fix 4).
async function noPromisedTime(p, where, fail) {
  const text = await p.evaluate(() => document.querySelector('main').textContent);
  for (const re of [/\busually\b/i, /10 to 20 seconds/, /within 20 seconds/]) if (re.test(text)) fail(where, 'the page promises a time: ' + re);
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
  if (!/the code is selected/.test(await p.textContent('#code-copied'))) fail('clipboard refused', 'the copy line does not say the code is selected: "' + (await p.textContent('#code-copied')) + '"');
  if ((await p.textContent('#code-copy')).trim() === 'Copied') fail('clipboard refused', 'Copy says "Copied" though nothing was copied');
  // The waiting checks run every 2 seconds and write the status line, never the copy line (the design review, fix 2).
  await p.waitForTimeout(5200);
  if (!/the code is selected/.test(await p.textContent('#code-copied'))) fail('clipboard refused', 'after 5 seconds the copy line says "' + (await p.textContent('#code-copied')) + '"');
  if (/selected/.test(await p.textContent('#code-status'))) fail('clipboard refused', 'the copy answer is in the waiting line too');
  const line = await p.evaluate(() => { const b = document.getElementById('code-copied').getBoundingClientRect(); return { bottom: b.bottom, h: window.innerHeight }; });
  if (line.bottom > line.h + 1) fail('clipboard refused', 'the copy line ends at ' + Math.round(line.bottom) + ' px of ' + line.h + ', off the screen');
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
  if ((await q.evaluate(() => document.activeElement && document.activeElement.id)) !== 'code-new') fail('expiry', 'focus is not on "Get a new code"');
  if (SHOTS) await q.screenshot({ path: path.join(SHOTS, 'join-390-light-expired.png') });
  console.log('live region during a 30-second wait: ' + said.length + ' change(s): ' + JSON.stringify(said));
  await ctx.close();
}

main().catch((e) => { console.error(e && e.stack); process.exitCode = 2; });
