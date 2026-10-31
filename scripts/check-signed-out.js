#!/usr/bin/env node
// Signed-out states and the owner controls (UX PR D, the UI/UX review of Oct 31, findings 5, 6 and 12's front-end
// part) in a real browser, on a local copy of the site. It serves the files itself with each address's security policy
// from vercel.json, as scripts/check-shell.js does, and answers /auth and /api with stand-ins, so nothing reaches the
// live site: signed out (every private answer is the server's 401), a member, or the administrator. giscus is blocked.
//
//   node scripts/check-signed-out.js [--root DIR] [--shots DIR] [--no-checks]
//
// Checks, at 390 by 844 and 1280 by 800 px, in dark and light:
//   - signed out, on /feed, /agents, /account, /review and /controls: the first screen holds the signed-out panel, with
//     exactly one primary button in the page, "Sign in with GitHub", to /join?return_to=<the page>; nothing scrolls
//     sideways;
//   - /controls signed out: nothing in the page shows but its heading and the panel (no brake, no Second Look);
//   - /feed signed out: each post's "Sign in to report" is a link to /join?return_to=%2Ffeed, a tap on it goes there,
//     and no report form ever opens; signed in, Report still opens its form;
//   - /agents signed out: three short lines show, and the full rules sit in a closed "How agents work" disclosure;
//   - /controls as the administrator: Second Look's current mode is marked (aria-pressed), "On" sends nothing on the
//     first tap and switches on the second;
//   - /review as the administrator: an item with several reasons lists them oldest first, and an empty queue says what
//     happens when nothing is waiting;
//   - no script errors and no security-policy refusals.
// --shots DIR saves the first screen and the full page of each, and the administrator's /controls and /review;
// --no-checks only takes them (for the "before" copy). Needs Playwright with Chromium; not part of the test suite.
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
const PAGES = ['/feed', '/agents', '/account', '/review', '/controls'];

const OWN_POLICY = ['/talk', '/join', '/account'];
const DEFAULT_POLICY = '/((?!talk/?$|join/?$|account/?$|auth/).*)';
function policyFor(url, rules) {
  const source = OWN_POLICY.includes(url) ? url : DEFAULT_POLICY;
  const rule = rules.find((r) => r.source === source && r.csp);
  if (!rule) throw new Error('vercel.json has no security policy for ' + source);
  return rule.csp.replace(/;\s*upgrade-insecure-requests/, '');
}
function serve() {
  const vercel = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
  const rules = vercel.headers.map((h) => ({ source: h.source, csp: (h.headers.find((x) => x.key === 'Content-Security-Policy') || {}).value }));
  return http.createServer((req, res) => {
    const url = decodeURIComponent(req.url.split('?')[0]);
    let file = url === '/' ? 'index.html' : url.slice(1);
    if (!path.extname(file)) file += '.html';
    const csp = policyFor(url, rules);
    if (csp) res.setHeader('Content-Security-Policy', csp);
    // Resolved, kept inside ROOT, then read in one step (as check-shell.js; CodeQL on #87 and #88, Oct 31).
    let full = path.resolve(ROOT, file);
    let body = null;
    if (full.startsWith(ROOT + path.sep)) { try { body = fs.readFileSync(full); } catch { body = null; } } // missing, or a folder
    if (body === null) {
      if (path.extname(url)) { res.statusCode = 404; return res.end('not found'); }
      res.statusCode = 404;
      full = path.join(ROOT, '404.html');
      body = fs.readFileSync(full);
    }
    res.setHeader('Content-Type', TYPES[path.extname(full)] || 'application/octet-stream');
    res.end(body);
  });
}

// Stand-in data, shaped like the real answers (api/feed.js, db/controls.js, 034's sl_report).
const AGO = (h) => new Date(Date.now() - h * 3600e3).toISOString();
const POSTS = { posts: [
  { id: '0190a000-0000-7000-8000-000000000001', author: { name: 'Ada', level: 1 }, published_at: AGO(2), body: 'Hello from the people lane.\n\nSecond paragraph.' },
  { id: '0190a000-0000-7000-8000-000000000002', author: { name: 'Grace', level: 2 }, published_at: AGO(5), body: 'Glad to be here.' }], next: null };
const CONTROLS = (mode) => ({
  totals: { brakes_on: 0, active_members: 12, banned_members: 0, disabled_members: 0, active_agents: 3, people_posts_24h: 9, agent_posts_24h: 4, posts_7d: 40, repeats_7d: 2 },
  everyone: null, deletion_reviews: [],
  owners: [{ id: '0190a000-0000-7000-8000-0000000000a1', name: 'Ada', level: 2, status: 'active', admin: false, agents: 2, new_agents_24h: 0,
    people_posts_24h: 3, agent_posts_24h: 4, posts_7d: 12, repeats_7d: 0, posts_total: 30, brake: null }],
  most_agents: [{ name: 'Ada', agents: 2, status: 'active' }],
  jevs: { mode: 'shadow', last_24h: [{ level: 'low', effect: 'none', applied: true, error: false, decisions: 13 }], recent: [] },
  second_look: { mode, paused: false, decisions_7d: 5, clears_7d: 3, rejects_7d: 1, failed_closed_7d: 1, published_total: 0, reversed_total: 0,
    shadow_clears_decided: 3, shadow_clears_removed: 0, shadow_error_upper_95: 0.5615 },
  repeated_texts: [] });
// One item held for several reasons (its first post, JEVs, then an appeal) and one reported, removed and appealed.
const QUEUE = { open: 2, items: [
  { id: '0190a000-0000-7000-8000-0000000000b1', lane: 'people', status: 'waiting', body: 'My first post, held.', author: { name: 'New member', level: 1, status: 'active', live_posts: 0 },
    flagged_at: AGO(30), first_posts: true, reports: 0, reasons: [], notes: [], classifiers: ['jevs'], appealed: true, actions: ['approve', 'remove'] },
  { id: '0190a000-0000-7000-8000-0000000000b2', lane: 'people', status: 'removed', body: 'A reported post that JEVs hid after the reports; its author appealed.', author: { name: 'Grace', level: 2, status: 'active', live_posts: 4 },
    flagged_at: AGO(3), first_posts: false, reports: 2, reasons: ['spam'], notes: ['Looks like an advert.'], classifiers: ['jevs'], appealed: true, actions: ['remove', 'restore'] }] };

async function context(browser, base, { width, height, scheme, who, queue = QUEUE }) {
  const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme });
  const sent = [];
  await ctx.route('https://giscus.app/**', (r) => r.abort());
  await ctx.route('**/_vercel/**', (r) => r.abort());
  const json = (r, status, body) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  const out = who === 'out';
  await ctx.route(base + '/auth/**', (r) => {
    const u = new URL(r.request().url());
    if (u.pathname === '/auth/me') return json(r, 200, out ? { signed_in: false } : { signed_in: true, unread: 0 });
    if (u.pathname === '/auth/account') return out ? json(r, 401, { signed_in: false }) : json(r, 200, { signed_in: true, display_name: 'Aaron', trust_level: 2,
      joined: AGO(500), member_id: 'm1', sign_ins: [{ provider: 'github', level: 1 }], admin: who === 'admin', sessions: 1 });
    return json(r, 404, { error: 'local copy' });
  });
  await ctx.route(base + '/api/**', (r) => {
    const req = r.request();
    const u = new URL(req.url());
    if (req.method() !== 'GET') {
      sent.push({ path: u.pathname, body: req.postData() });
      if (out) return json(r, 401, { error: 'Sign in first.', join: '/join' });
      const b = JSON.parse(req.postData() || '{}');
      if (b.second_look === 'mode') return json(r, 200, { mode: b.mode, message: 'Second Look is now in ' + b.mode + ' mode.' });
      return json(r, 200, { message: 'Done.' });
    }
    if (u.pathname === '/api/feed' && u.searchParams.get('lane')) return json(r, 200, POSTS);
    if (u.pathname === '/api/feed' && u.searchParams.get('mine')) return json(r, 200, { posts: [] });
    if (out) {
      if (u.searchParams.has('controls')) return json(r, 401, { error: 'Sign in to see the owner controls.', join: '/join' });
      if (u.searchParams.has('queue')) return json(r, 401, { error: 'Sign in to review.', join: '/join' });
      if (u.pathname.startsWith('/api/agents')) return json(r, 401, { error: 'Sign in to manage agents.', join: '/join?return_to=%2Fagents' });
      return json(r, 401, { error: 'Sign in to see your notices.', join: '/join?return_to=%2Faccount' });
    }
    if (u.searchParams.has('controls')) return json(r, 200, CONTROLS('shadow'));
    if (u.searchParams.has('queue')) return json(r, 200, queue);
    if (u.pathname === '/api/notify/appeals') return json(r, 200, { containments: [] });
    if (u.pathname === '/api/notify') return json(r, 200, { unread: 0, notices: [] });
    return json(r, 503, { error: 'local copy' });
  });
  return { ctx, sent };
}

async function open(ctx, base, url, where, fail) {
  const p = await ctx.newPage();
  p.on('pageerror', (e) => fail(where, 'script error: ' + e.message));
  p.on('console', (m) => { if (m.type() === 'error' && /Content Security Policy/i.test(m.text())) fail(where, 'security policy: ' + m.text().slice(0, 160)); });
  await p.goto(base + url, { waitUntil: 'load' });
  await p.waitForTimeout(250); // the page's own requests answer from the stand-ins
  return p;
}

// The signed-out panel: whether it shows on the first screen, and every visible primary button in <main>.
const panel = (p) => p.evaluate(() => {
  const shown = (el) => el.checkVisibility({ visibilityProperty: true }) && el.getBoundingClientRect().height > 0;
  const box = document.querySelector('main .signed-out');
  const r = box && box.getBoundingClientRect();
  const primaries = [...document.querySelectorAll('main .button.primary')].filter(shown)
    .map((b) => ({ text: b.textContent.trim(), href: b.getAttribute('href'), bottom: b.getBoundingClientRect().bottom }));
  const other = [...document.querySelector('main').children].filter((c) => c !== box && c.tagName !== 'H1' && shown(c)).map((c) => c.id || c.className || c.tagName);
  return { shown: !!box && shown(box), top: r ? r.top : null, bottom: r ? r.bottom : null, primaries, other, height: innerHeight,
    sideways: document.documentElement.scrollWidth - innerWidth };
});

async function shot(p, name) {
  if (!SHOTS) return;
  await p.screenshot({ path: path.join(SHOTS, name + '-fold.png') });
  await p.screenshot({ path: path.join(SHOTS, name + '-full.png'), fullPage: true });
}

async function main() {
  const { chromium } = require('playwright');
  if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
  const server = serve();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch();
  const problems = [];
  const fail = (where, what) => problems.push(where + ': ' + what);
  let checked = 0;
  try {
    for (const [width, height] of [[390, 844], [1280, 800]]) {
      for (const scheme of ['dark', 'light']) {
        const tag = width + '-' + scheme;
        // Signed out, each page.
        const { ctx, sent } = await context(browser, base, { width, height, scheme, who: 'out' });
        for (const url of PAGES) {
          const where = tag + ' signed out ' + url;
          const p = await open(ctx, base, url, where, fail);
          await shot(p, url.slice(1) + '-' + tag + '-out');
          if (CHECKS) {
            const m = await panel(p);
            if (!m.shown) fail(where, 'no signed-out panel shows');
            else if (m.bottom > m.height) fail(where, 'the panel ends at ' + Math.round(m.bottom) + ' px, below the first screen (' + m.height + ')');
            if (m.primaries.length !== 1) fail(where, m.primaries.length + ' primary buttons show (one wanted): ' + JSON.stringify(m.primaries));
            else {
              const b = m.primaries[0];
              if (b.text !== 'Sign in with GitHub') fail(where, 'the primary button says "' + b.text + '"');
              if (b.href !== '/join?return_to=' + encodeURIComponent(url)) fail(where, 'the primary button goes to ' + b.href);
              if (b.bottom > m.height) fail(where, 'the primary button is below the first screen');
            }
            if (m.sideways > 0) fail(where, 'the page scrolls sideways by ' + m.sideways + ' px');
            if (url === '/controls' && m.other.length) fail(where, 'more than the panel shows: ' + m.other.join(', '));
            if (url === '/feed') {
              const links = await p.$$eval('.report a', (as) => as.map((a) => ({ text: a.textContent, href: a.getAttribute('href') })));
              if (links.length !== POSTS.posts.length) fail(where, links.length + ' "Sign in to report" links for ' + POSTS.posts.length + ' posts');
              if (links.some((l) => l.text !== 'Sign in to report' || l.href !== '/join?return_to=%2Ffeed')) fail(where, 'a report link is wrong: ' + JSON.stringify(links));
              if (await p.locator('.report button').count()) fail(where, 'a Report button that opens a form is still on the page');
              if (width === 390 && scheme === 'dark') {
                await p.locator('.report a').first().click();
                await p.waitForURL('**/join?return_to=%2Ffeed');
              }
              if (await p.locator('.report-form').count()) fail(where, 'a report form opened');
            }
            if (url === '/agents') {
              const a = await p.evaluate(() => {
                const d = document.querySelector('details.agent-rules');
                return { lines: [...document.querySelectorAll('#agents-intro li')].filter((x) => x.checkVisibility()).length, open: d && d.open,
                  summary: d && d.querySelector('summary').textContent.trim(), words: d ? d.textContent.split(/\s+/).length : 0 };
              });
              if (a.lines !== 3) fail(where, a.lines + ' short lines show (three wanted)');
              if (a.summary !== 'How agents work' || a.open) fail(where, 'the rules are not in a closed "How agents work" disclosure: ' + JSON.stringify(a));
              if (a.words < 300) fail(where, 'the rules lost words: ' + a.words);
            }
          }
          await p.close();
          checked++;
        }
        if (CHECKS && sent.length) fail(tag + ' signed out', 'a page sent ' + JSON.stringify(sent));
        await ctx.close();

        // The administrator: /controls and /review (with items, then empty); a member's /feed.
        const admin = await context(browser, base, { width, height, scheme, who: 'admin' });
        let p = await open(admin.ctx, base, '/controls', tag + ' admin /controls', fail);
        if (CHECKS) {
          const where = tag + ' admin /controls';
          const m = await p.evaluate(() => ({ panel: document.querySelector('.signed-out').checkVisibility(), brake: document.getElementById('brake-form').checkVisibility(),
            modes: [...document.querySelectorAll('#sl-modes button')].map((b) => [b.dataset.mode, b.getAttribute('aria-pressed')]) }));
          if (m.panel) fail(where, 'the signed-out panel shows to the administrator');
          if (!m.brake) fail(where, 'the brake is hidden from the administrator');
          if (JSON.stringify(m.modes) !== JSON.stringify([['off', 'false'], ['shadow', 'true'], ['on', 'false']])) fail(where, 'the current mode is not marked: ' + JSON.stringify(m.modes));
        }
        if (SHOTS) {
          const h = p.locator('#second-look-heading').or(p.locator('h2', { hasText: 'Second Look' })).first();
          await h.scrollIntoViewIfNeeded();
          await p.screenshot({ path: path.join(SHOTS, 'controls-' + tag + '-admin-second-look.png') });
        }
        await shot(p, 'controls-' + tag + '-admin');
        if (CHECKS) {
          const where = tag + ' admin /controls';
          const on = p.locator('#sl-modes button[data-mode="on"]');
          await on.click();
          await p.waitForTimeout(100);
          if (admin.sent.length) fail(where, 'the first tap on "On" sent ' + JSON.stringify(admin.sent));
          const armed = (await on.textContent()).trim();
          if (armed !== 'Tap again to let Second Look publish easy held posts') fail(where, 'the first tap on "On" says "' + armed + '"');
          if (SHOTS && width === 390) await p.locator('#sl-modes').screenshot({ path: path.join(SHOTS, 'controls-' + tag + '-admin-on-armed.png') });
          await on.click();
          await p.waitForTimeout(200);
          if (admin.sent.length !== 1 || JSON.parse(admin.sent[0].body).mode !== 'on') fail(where, 'the second tap on "On" did not switch it on: ' + JSON.stringify(admin.sent));
        }
        await p.close();
        p = await open(admin.ctx, base, '/review', tag + ' admin /review', fail);
        if (CHECKS) {
          // Oldest first by the database's rules (review.js, why()): the first-post flag, reports, JEVs, then the appeal.
          const why = await p.$$eval('#queue .why', (x) => x.map((e) => e.textContent + ' | ' + e.nextElementSibling.textContent));
          if (!/^Why: one of a new member’s first 3 posts; flagged by JEVs \(automatic checks\); the author appealed\. \| In the queue since /.test(why[0] || '')) fail(tag + ' admin /review', 'the reasons are not oldest first, or no "In the queue since": ' + why[0]);
          if (!/^Why: 2 reports \(spam\); flagged by JEVs \(automatic checks\); the author appealed\. \| In the queue since /.test(why[1] || '')) fail(tag + ' admin /review', 'the second item reads: ' + why[1]);
        }
        await shot(p, 'review-' + tag + '-admin');
        await p.close();
        await admin.ctx.close();
        const empty = await context(browser, base, { width, height, scheme, who: 'admin', queue: { open: 0, items: [] } });
        p = await open(empty.ctx, base, '/review', tag + ' admin /review empty', fail);
        if (CHECKS) {
          const t = await p.evaluate(() => document.getElementById('summary').textContent + ' | ' + (document.querySelector('#queue .empty') || { textContent: '' }).textContent);
          if (!/^Nothing is waiting\. \| /.test(t) || !/JEVs checks every post/.test(t)) fail(tag + ' admin /review empty', 'no empty state: ' + t);
        }
        await shot(p, 'review-' + tag + '-admin-empty');
        await p.close();
        await empty.ctx.close();
        const member = await context(browser, base, { width, height, scheme, who: 'member' });
        p = await open(member.ctx, base, '/feed', tag + ' member /feed', fail);
        if (CHECKS) {
          const where = tag + ' member /feed';
          if (await p.locator('main .signed-out').isVisible()) fail(where, 'the signed-out panel shows to a member');
          await p.locator('.report button').first().click();
          if (!(await p.locator('.report-form').count())) fail(where, 'Report no longer opens its form for a member');
        }
        await p.close();
        await member.ctx.close();
      }
    }
  } finally {
    await browser.close();
    server.close();
  }
  if (problems.length) {
    console.log('FAIL signed-out states and controls (local copy of ' + ROOT + ')\n' + problems.map((x) => '  ' + x).join('\n'));
    process.exitCode = 1;
  } else {
    console.log('OK signed-out states and controls (local copy of ' + ROOT + '): ' + (CHECKS ? checked + ' signed-out page views (5 pages at 390 and 1280 px, dark and light), the administrator\'s /controls and /review, a member\'s /feed' : 'screenshots only') + (SHOTS ? '; screenshots in ' + SHOTS : ''));
  }
}

main().catch((e) => { console.error(e && e.stack); process.exitCode = 2; });
