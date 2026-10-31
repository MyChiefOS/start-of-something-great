#!/usr/bin/env node
// The one shell (UX PR B, the UI/UX review of Oct 31, findings 3, 4 and the menu part of 15) in a real browser, on a
// local copy of the site. It serves the files itself, with each address's security policy from vercel.json, answers
// /auth/me with a stand-in (signed out, or signed in with 3 unread notices) and every /api request with a refusal, so
// nothing reaches the live site. giscus is blocked.
//
//   node scripts/check-shell.js [--root DIR] [--shots DIR] [--no-checks]
//
// Checks, on every page (the 404 too), signed out and signed in:
//   - at 390 by 844 px: the header is at most 72 px tall with the menu closed, and nothing scrolls sideways;
//   - at 1280 by 800 px: the header's links sit in one row;
//   - the Menu opens and closes by keyboard (Enter and Space; Escape too where nav.js runs), and every control in the
//     header shows a visible focus ring (at both widths);
//   - no script errors and no security-policy refusals from our own files.
// --shots DIR saves screenshots of /, /feed, /talk, /team, /proposals and the 404 at 390 and 1280 px in dark and light,
// and the open Menu at 390; --no-checks only takes them (for the "before" copy).
// Needs Playwright with Chromium (`require('playwright')`); not part of the test suite, which runs without a browser.
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const arg = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; };
const ROOT = path.resolve(arg('--root') || path.join(__dirname, '..'));
const SHOTS = arg('--shots');
const CHECKS = !process.argv.includes('--no-checks');
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2', '.png': 'image/png', '.jpg': 'image/jpeg', '.txt': 'text/plain', '.json': 'application/json' };
const SHOT_PAGES = [['home', '/'], ['feed', '/feed'], ['talk', '/talk'], ['team', '/team'], ['proposals', '/proposals'], ['404', '/no-such-page']];

// Every page's address: x.html is /x, index.html is /, research/x.html is /research/x; and one address that doesn't exist.
function addresses() {
  const top = fs.readdirSync(ROOT).filter((f) => f.endsWith('.html') && f !== '404.html').map((f) => (f === 'index.html' ? '/' : '/' + f.replace(/\.html$/, '')));
  const research = fs.readdirSync(path.join(ROOT, 'research')).filter((f) => f.endsWith('.html')).map((f) => '/research/' + f.replace(/\.html$/, ''));
  return top.concat(research, ['/no-such-page']);
}

// The security policy Vercel sends for a page: /talk, /join and /account have their own rule in vercel.json, and every
// other page the default one. A missing rule stops the check rather than serving a page with no policy.
const OWN_POLICY = ['/talk', '/join', '/account'];
const DEFAULT_POLICY = '/((?!talk/?$|join/?$|account/?$|auth/).*)';
function policyFor(url, rules) {
  const source = OWN_POLICY.includes(url) ? url : DEFAULT_POLICY;
  const rule = rules.find((r) => r.source === source && r.csp);
  if (!rule) throw new Error('vercel.json has no security policy for ' + source);
  return rule.csp.replace(/;\s*upgrade-insecure-requests/, ''); // the local copy is plain http
}

function serve() {
  const vercel = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
  const rules = vercel.headers.map((h) => ({ source: h.source, csp: (h.headers.find((x) => x.key === 'Content-Security-Policy') || {}).value }));
  return http.createServer((req, res) => {
    const url = decodeURIComponent(req.url.split('?')[0]);
    let file = url === '/' ? 'index.html' : url.slice(1);
    if (!path.extname(file)) file += '.html';
    let full = path.join(ROOT, file);
    const csp = policyFor(url, rules);
    if (csp) res.setHeader('Content-Security-Policy', csp);
    if (!full.startsWith(ROOT + path.sep) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
      if (path.extname(url)) { res.statusCode = 404; return res.end('not found'); }
      res.statusCode = 404; // a page address that doesn't exist gets the 404 page, as on Vercel
      full = path.join(ROOT, '404.html');
    }
    res.setHeader('Content-Type', TYPES[path.extname(full)] || 'application/octet-stream');
    res.end(fs.readFileSync(full));
  });
}

async function context(browser, base, { width, height, scheme, signedIn }) {
  const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme });
  await ctx.route('https://giscus.app/**', (r) => r.abort());
  await ctx.route(base + '/auth/me', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify(signedIn ? { signed_in: true, unread: 3 } : { signed_in: false }) }));
  await ctx.route(base + '/api/**', (r) => r.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"local copy"}' }));
  return ctx;
}

async function open(ctx, base, url, where, fail) {
  const p = await ctx.newPage();
  p.on('pageerror', (e) => fail(where, 'script error: ' + e.message));
  p.on('console', (m) => { if (m.type() === 'error' && /Content Security Policy/i.test(m.text())) fail(where, 'security policy: ' + m.text().slice(0, 160)); });
  await p.goto(base + url, { waitUntil: 'load' });
  await p.waitForTimeout(150); // nav.js answers from the stand-in
  return p;
}

// The header's size, and the top of each visible control in it.
const measure = (p) => p.evaluate(() => {
  const h = document.querySelector('.site-header');
  // checkVisibility: a closed <details> skips its content without display: none, so size alone would count it.
  const shown = (el) => { const r = el.getBoundingClientRect(); return el.checkVisibility({ visibilityProperty: true }) && r.width > 0 && r.height > 0; };
  const controls = [...h.querySelectorAll('a, summary')].filter(shown).map((el) => {
    const r = el.getBoundingClientRect();
    return { text: el.textContent.trim(), top: Math.round(r.top), bottom: Math.round(r.bottom), mid: Math.round(r.top + r.height / 2) };
  });
  return { height: Math.round(h.getBoundingClientRect().height), controls, sideways: document.documentElement.scrollWidth - window.innerWidth };
});

// What has focus, and whether it shows a ring a sighted keyboard user can see.
const focused = (p) => p.evaluate(() => {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const s = getComputedStyle(el);
  return { text: el.textContent.trim(), tag: el.tagName, ring: s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) >= 2, inHeader: !!el.closest('.site-header') };
});

async function tabTo(p, match, limit = 20) {
  for (let i = 0; i < limit; i++) {
    await p.keyboard.press('Tab');
    const f = await focused(p);
    if (f && match(f)) return f;
  }
  return null;
}

async function keyboard(p, where, fail, phone) {
  // Every control in the header, in order, has a visible ring.
  const seen = [];
  for (let i = 0; i < 20; i++) {
    await p.keyboard.press('Tab');
    const f = await focused(p);
    if (!f || !f.inHeader) { if (seen.length) break; continue; }
    seen.push(f.text);
    if (!f.ring) fail(where, '"' + f.text + '" has focus with no visible ring');
  }
  if (!seen.length) fail(where, 'the keyboard never reaches the header');
  if (!phone) return;
  // The Menu: Enter opens it and closes it, Space too; where nav.js runs (every page but the four that run no
  // script), Escape also closes it and puts focus back on Menu.
  const isOpen = () => p.evaluate(() => document.querySelector('.site-header details').open);
  const linksShown = () => p.evaluate(() => [...document.querySelectorAll('.site-header details a')].filter((a) => a.checkVisibility()).length);
  const onMenu = async () => { const f = await focused(p); return f && f.tag === 'SUMMARY'; };
  if (!(await p.locator('.site-header details > summary').count())) return fail(where, 'there is no Menu to open');
  await p.evaluate(() => document.querySelector('.site-header summary').focus());
  await p.keyboard.press('Enter');
  if (!(await isOpen()) || !(await linksShown())) fail(where, 'Enter on Menu did not open it');
  const first = await tabTo(p, () => true, 1);
  if (!first || !first.inHeader || !first.ring) fail(where, 'the first link in the open Menu has no visible focus (' + JSON.stringify(first) + ')');
  await p.keyboard.press('Shift+Tab');
  if (!(await onMenu())) fail(where, 'Shift+Tab from the first link does not return to Menu');
  await p.keyboard.press('Enter');
  if ((await isOpen()) || (await linksShown())) fail(where, 'Enter on Menu did not close it');
  await p.keyboard.press(' ');
  if (!(await isOpen())) fail(where, 'Space on Menu did not open it');
  if (await p.evaluate(() => !!document.querySelector('script[src="/nav.js"]'))) {
    await tabTo(p, () => true, 2);
    await p.keyboard.press('Escape');
    if (await isOpen()) fail(where, 'Escape did not close the Menu');
    if (!(await onMenu())) fail(where, 'after Escape, focus is not back on Menu');
  } else {
    await p.keyboard.press(' ');
    if (await isOpen()) fail(where, 'Space on Menu did not close it');
  }
}

async function main() {
  const { chromium } = require('playwright');
  const server = serve();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch();
  const problems = [];
  const fail = (where, what) => problems.push(where + ': ' + what);
  let pages = 0;
  try {
    if (SHOTS) {
      fs.mkdirSync(SHOTS, { recursive: true });
      for (const [width, height] of [[390, 844], [1280, 800]]) {
        for (const scheme of ['dark', 'light']) {
          const ctx = await context(browser, base, { width, height, scheme, signedIn: false });
          for (const [name, url] of SHOT_PAGES) {
            const p = await open(ctx, base, url, 'shot ' + name, () => {});
            await p.screenshot({ path: path.join(SHOTS, name + '-' + width + '-' + scheme + '-fold.png') });
            await p.screenshot({ path: path.join(SHOTS, name + '-' + width + '-' + scheme + '-full.png'), fullPage: true });
            if (width === 390 && name === 'feed' && (await p.locator('.site-header summary').count())) {
              await p.click('.site-header summary');
              await p.screenshot({ path: path.join(SHOTS, 'menu-open-390-' + scheme + '.png') });
            }
            await p.close();
          }
          await ctx.close();
        }
      }
      // Signed in, the header's two widths (the stand-in answers 3 unread notices).
      for (const [width, height] of [[390, 844], [1280, 800]]) {
        const ctx = await context(browser, base, { width, height, scheme: 'dark', signedIn: true });
        const p = await open(ctx, base, '/feed', 'shot signed in', () => {});
        await p.screenshot({ path: path.join(SHOTS, 'signed-in-feed-' + width + '-dark-fold.png') });
        if (width === 390 && (await p.locator('.site-header summary').count())) {
          await p.click('.site-header summary');
          await p.screenshot({ path: path.join(SHOTS, 'signed-in-menu-open-390-dark.png') });
        }
        await ctx.close();
      }
    }
    if (CHECKS) {
      for (const signedIn of [false, true]) {
        const phone = await context(browser, base, { width: 390, height: 844, scheme: 'dark', signedIn });
        const wide = await context(browser, base, { width: 1280, height: 800, scheme: 'light', signedIn });
        for (const url of addresses()) {
          const who = (signedIn ? 'signed in' : 'signed out') + ' ' + url;
          let p = await open(phone, base, url, '390 ' + who, fail);
          let m = await measure(p);
          if (m.height > 72) fail('390 ' + who, 'the header is ' + m.height + ' px tall (at most 72)');
          if (m.sideways > 0) fail('390 ' + who, 'the page scrolls sideways by ' + m.sideways + ' px');
          if (new Set(m.controls.map((c) => Math.round(c.mid / 8))).size > 1) fail('390 ' + who, 'the header is more than one row: ' + JSON.stringify(m.controls));
          if (!m.controls.some((c) => c.text === 'Menu')) fail('390 ' + who, 'no Menu in the header');
          await keyboard(p, '390 ' + who, fail, true);
          await p.close();
          p = await open(wide, base, url, '1280 ' + who, fail);
          m = await measure(p);
          const rows = new Set(m.controls.map((c) => Math.round(c.mid / 8)));
          if (rows.size > 1) fail('1280 ' + who, 'the header is ' + rows.size + ' rows: ' + JSON.stringify(m.controls));
          if (m.controls.some((c) => c.text === 'Menu')) fail('1280 ' + who, 'Menu shows on a wide screen');
          if (m.sideways > 0) fail('1280 ' + who, 'the page scrolls sideways by ' + m.sideways + ' px');
          await keyboard(p, '1280 ' + who, fail, false);
          await p.close();
          pages++;
        }
        await phone.close();
        await wide.close();
      }
    }
  } finally {
    await browser.close();
    server.close();
  }
  if (problems.length) {
    console.log('FAIL the shell (local copy of ' + ROOT + ')\n' + problems.map((x) => '  ' + x).join('\n'));
    process.exitCode = 1;
  } else {
    console.log('OK the shell (local copy of ' + ROOT + '): ' + (CHECKS ? pages / 2 + ' pages, each at 390 and 1280 px, signed out and signed in' : 'screenshots only') + (SHOTS ? '; screenshots in ' + SHOTS : ''));
  }
}

main().catch((e) => { console.error(e && e.stack); process.exitCode = 2; });
