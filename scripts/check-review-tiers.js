#!/usr/bin/env node
// Phase 4 of the design handoff (041; CODING_AGENT_SPEC.md section 2): the administrator's /admin/review and
// /admin/controls and the public /decisions, from a local copy of this folder (never the live site), at 390 and 1280
// px, dark and light, with stand-in answers shaped like the real ones. It checks:
//   - no script error and no security-policy error; no sideways scroll;
//   - /admin/review: every decision button drawn alike (border, background, colour, font) and at least 44 px tall,
//     their words and edges in contrast (4.5:1 and 3:1); a sensitive item's buttons wait for 10 seconds on screen;
//     J goes to an item and A to its Publish reasons, Enter publishes after 30 seconds unless U undoes it (nothing sent);
//     Remove is sent at once with its reason, the hash and the time on screen; this browser's hash of the words matches;
//   - /admin/controls: the brake's red in each theme and its contrast; Allow deletion waits 10 seconds; the review
//     budget and the planted tests show;
//   - /decisions: the human oversight figures, planted tests and alerts from the answer.
// --shots DIR saves each view. Needs Playwright with Chromium; not part of the test suite.
'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { serve } = require('./check-signed-out');

const arg = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; };
const SHOTS = arg('--shots');
const AGO = (h) => new Date(Date.now() - h * 3600e3).toISOString();
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const REASONS = { approve: ['ordinary', 'checked', 'other'], keep: ['not_upheld', 'ordinary', 'checked', 'other'], remove: ['spam', 'abuse', 'private_info', 'illegal', 'other'], restore: ['mistake', 'other'] };
const BODY1 = 'My first post here: notes from the meetup on agent permissions.\n\nThe slides are linked below.';
const QUEUE = { open: 3, budget: { daily: 25, used: 4 }, items: [
  { id: '0190a000-0000-7000-8000-0000000000c3', lane: 'people', status: 'live', body: 'A post someone reported for private information.', tier: 3, item_type: 'reported', sha256: sha('x'),
    author: { name: 'Grace', level: 2, status: 'active', live_posts: 4 }, flagged_at: AGO(2), first_posts: false, reports: 1, reasons: ['private_info'], notes: [], classifiers: [],
    appealed: false, questions: [], actions: ['keep', 'remove'], decision_reasons: REASONS, history: { decided: 24, approved: 22, removed: 2 } },
  { id: '0190a000-0000-7000-8000-0000000000c1', lane: 'people', status: 'waiting', body: BODY1, tier: 2, item_type: 'held', sha256: sha(BODY1),
    author: { name: 'New member', level: 1, status: 'active', live_posts: 0 }, flagged_at: AGO(5), first_posts: false, reports: 0, reasons: [], notes: [], classifiers: ['jevs'],
    appealed: false, questions: ['J07', 'J01'], actions: ['approve', 'remove'], decision_reasons: REASONS, history: { decided: 0, approved: 0, removed: 0 } },
  { id: '0190a000-0000-7000-8000-0000000000c2', lane: 'agents', status: 'live', body: 'An agent post the 5% sample flagged.', tier: 2, item_type: 'sampled', sha256: sha('An agent post the 5% sample flagged.'),
    author: { name: 'Ada', level: 2, status: 'active', live_posts: 9 }, flagged_at: AGO(1), first_posts: false, reports: 0, reasons: [], notes: [], classifiers: ['secondlook'],
    classifier_labels: { secondlook: 'Second Look, re-reading a 5% sample of low-risk posts after they went live' }, appealed: false, questions: [], actions: ['keep', 'remove'],
    decision_reasons: REASONS, history: { decided: 3, approved: 3, removed: 0 } }] };
const CONTROLS = {
  totals: { brakes_on: 0, active_members: 12, banned_members: 0, disabled_members: 0, active_agents: 3, people_posts_24h: 9, agent_posts_24h: 4, posts_7d: 40, repeats_7d: 2 },
  everyone: null,
  deletion_reviews: [{ id: '0190a000-0000-7000-8000-0000000000d1', state: 'open', opened_at: AGO(3), due_at: AGO(-21),
    member: { id: '0190a000-0000-7000-8000-0000000000d2', name: 'Bea', level: 1, joined: AGO(100), posts: 3, agents: 0 }, jevs: { level: 'high', total: 47, error: false, scores: { J01: 9, J05: 31 } } }],
  owners: [{ id: '0190a000-0000-7000-8000-0000000000a1', name: 'Ada', level: 2, status: 'active', admin: false, agents: 2, new_agents_24h: 0, people_posts_24h: 3, agent_posts_24h: 4, posts_7d: 12, repeats_7d: 0, posts_total: 30, brake: null }],
  most_agents: [{ name: 'Ada', agents: 2, status: 'active' }],
  jevs: { mode: 'enforce', last_24h: [{ level: 'low', effect: 'none', applied: true, error: false, decisions: 13 }], recent: [] },
  second_look: { mode: 'shadow', paused: false, decisions_7d: 5, clears_7d: 3, rejects_7d: 1, failed_closed_7d: 1, published_total: 0, reversed_total: 0, shadow_clears_decided: 3, shadow_clears_removed: 0, shadow_error_upper_95: 0.5615 },
  review: { daily_budget: 25, decided_today: 4, sample_rate: 0.05, sample_daily_cap: 100, samples_today: 2, canary_rate: 0.02, canaries_waiting: 0,
    alerts: [], canaries: { revealed: 3, no_answer: 1, bad: 1, bad_caught: 1, good: 1, good_cleared: 1, check: { checked: 3, ok: true, problems: [] } } },
  repeated_texts: [] };
const W = (o) => ({ decided: 24, approved: 21, removed: null, undone: 0, measured: 24, median_seconds: 14.2, p10_seconds: 4.1, hours: 0.2, ...o });
// The administrator's own reviewing, as db/review-tiers.js always shapes it: without it /admin/controls stopped drawing
// partway, and said it couldn't load, while this check still passed (found by scripts/check-design.js, Nov 10).
CONTROLS.review.mine = { d7: W({ median_wait_minutes: 12 }), d30: W({ decided: 90, median_wait_minutes: 20 }) };
// One counted window of the public figures, as db/review-tiers.js shapes it.
const WIN = (o = {}) => ({ days: 7, jevs_held: 7, github_hidden: 0, sample_flagged: null, sl_decisions: 12, sl_clears: 9, sl_published: 2,
  sample: { parts: [8, 0, null], other: null, shown: 8 }, canaries: { used: 0, no_answer: 0, bad: 0, bad_caught: 0, good: 0, good_cleared: 0 }, ...o });
const DECISIONS = { available: true, min_sample: 20, generated_at: AGO(0), jevs_mode: 'enforce', min_count: 5,
  last_24h: { decisions: 40, low: 33, medium_waiting: 0, high: 7, high_held: 7, appeals_open: 0 }, high_7d: [],
  second_look: { mode: 'shadow', paused: false, agreed_in_a_row: 3, needed: 80, daily_clear_cap: 10, shadow_clears_decided: 3, shadow_clears_removed: 0 },
  // 041, after its review: the public figures are JEVs's and Second Look's only, by counted day; never a person's.
  review: { counted_through: '2026-11-03', limits: { sample_on: true, sample_rate: 0.05, sample_daily_cap: 100, canary_rate: 0.02 },
    d7: WIN({ days: 7 }), d30: WIN({ days: 30, jevs_held: 22, sl_published: 6, canaries: { used: 3, no_answer: 1, bad: 1, bad_caught: 1, good: 1, good_cleared: 1 } }),
    alerts: [{ id: 'sample_unread', title: 'Sampled posts went unread for 24 hours', text: '1 sampled post waited over 24 hours for Second Look.' }] },
  questions: {}, note: 'Counts only.' };

function lum(rgb) {
  const m = rgb.match(/[\d.]+/g).map(Number);
  const c = m.slice(0, 3).map((v) => v / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };

async function main() {
  const { chromium } = require('playwright');
  if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
  const server = serve();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch();
  const problems = [];
  const fail = (where, what) => problems.push(where + ': ' + what);
  let views = 0;
  try {
    for (const [width, height] of [[390, 844], [1280, 900]]) {
      for (const scheme of ['dark', 'light']) {
        const tag = width + '-' + scheme;
        const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme });
        const sent = [];
        await ctx.route('**/_vercel/**', (r) => r.abort());
        const json = (r, status, body) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
        await ctx.route(base + '/auth/**', (r) => json(r, 200, { signed_in: true, unread: 0, admin: true }));
        await ctx.route(base + '/api/**', (r) => {
          const req = r.request();
          const u = new URL(req.url());
          if (req.method() !== 'GET') { sent.push(JSON.parse(req.postData() || '{}')); return json(r, 200, { status: 'removed', message: 'Done.' }); }
          if (u.pathname === '/api/decisions') return json(r, 200, DECISIONS);
          if (u.searchParams.has('controls')) return json(r, 200, CONTROLS);
          if (u.searchParams.has('queue')) return json(r, 200, QUEUE);
          if (u.pathname === '/api/notify/appeals') return json(r, 200, { containments: [] });
          return json(r, 503, { error: 'local copy' });
        });
        const open = async (url) => {
          const p = await ctx.newPage();
          p.on('pageerror', (e) => fail(tag + ' ' + url, 'script error: ' + e.message));
          p.on('console', (m) => { if (m.type() === 'error' && /Content Security Policy/i.test(m.text())) fail(tag + ' ' + url, 'security policy: ' + m.text().slice(0, 160)); });
          await p.goto(base + url, { waitUntil: 'load' });
          await p.waitForTimeout(400);
          const side = await p.evaluate(() => document.documentElement.scrollWidth - innerWidth);
          if (side > 0) fail(tag + ' ' + url, 'scrolls sideways by ' + side + ' px');
          views++;
          return p;
        };

        // ---- /admin/review ----
        let p = await open('/admin/review');
        let where = tag + ' /admin/review';
        const look = await p.evaluate(() => {
          const bg = getComputedStyle(document.body).backgroundColor;
          return { bg, buttons: [...document.querySelectorAll('.ap-choice')].filter((b) => b.offsetParent).map((b) => {
            const s = getComputedStyle(b);
            return { text: b.textContent, h: b.getBoundingClientRect().height, border: s.borderTopColor, back: s.backgroundColor, color: s.color, font: s.fontWeight + ' ' + s.fontSize, disabled: b.disabled };
          }), pills: [...document.querySelectorAll('#queue .pill')].map((x) => x.textContent), hash: [...document.querySelectorAll('.ap-hash-note')].map((x) => x.textContent) };
        });
        if (look.pills.join(' | ') !== 'Sensitive · Reported | Held · links and new domains | Sampled · flagged after it went live') fail(where, 'pills: ' + look.pills.join(' | '));
        const kinds = new Set(look.buttons.map((b) => [b.border, b.back, b.color, b.font].join(' ')));
        if (kinds.size !== 1) fail(where, 'decision buttons are not drawn alike: ' + [...kinds].join(' / '));
        if (look.buttons.some((b) => b.h < 44)) fail(where, 'a decision button is under 44 px: ' + JSON.stringify(look.buttons.filter((b) => b.h < 44).map((b) => b.text)));
        const b0 = look.buttons[0];
        const bodyBg = look.bg === 'rgba(0, 0, 0, 0)' ? (scheme === 'dark' ? 'rgb(13, 15, 20)' : 'rgb(246, 247, 249)') : look.bg;
        if (ratio(b0.color, bodyBg) < 4.5) fail(where, 'button words ' + ratio(b0.color, bodyBg).toFixed(2) + ':1');
        if (ratio(b0.border, bodyBg) < 3) fail(where, 'button edge ' + ratio(b0.border, bodyBg).toFixed(2) + ':1');
        const tier3 = await p.$$eval('#queue article:first-of-type .ap-choice', (bs) => bs.map((b) => b.disabled));
        if (!tier3.every(Boolean)) fail(where, 'the sensitive item can be decided before 10 seconds');
        if (look.hash[1] !== 'This browser got the same hash from the words above.') fail(where, 'hash note: ' + look.hash[1]);
        if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'admin-review-' + tag + '.png'), fullPage: true });
        // Keys: J twice to the held item, A to its Publish reasons, Enter; nothing is sent; U undoes.
        await p.keyboard.press('j');
        await p.keyboard.press('j');
        await p.keyboard.press('a');
        const focused = await p.evaluate(() => document.activeElement && document.activeElement.textContent);
        if (focused !== 'Publishan ordinary post') fail(where, 'A focused "' + focused + '"');
        await p.keyboard.press('Enter');
        await p.waitForTimeout(200);
        const toast = await p.$eval('#ap-toast', (t) => (t.hidden ? '' : t.textContent));
        if (toast !== 'Publishing in 30 seconds. Undo') fail(where, 'toast: ' + toast);
        if (SHOTS && width === 390) await p.screenshot({ path: path.join(SHOTS, 'admin-review-' + tag + '-undo.png') });
        await p.keyboard.press('u');
        await p.waitForTimeout(200);
        if (sent.length) fail(where, 'publish was sent before its 30 seconds or after Undo: ' + JSON.stringify(sent));
        // Remove on the sample: sent at once, with its reason, hash and time.
        await p.locator('#queue article').nth(2).locator('.ap-choice', { hasText: 'spam' }).click();
        await p.waitForTimeout(300);
        const r = sent[0] || {};
        if (!(r.decision === 'remove' && r.reason === 'spam' && r.sha256 === QUEUE.items[2].sha256 && Number.isInteger(r.seen_ms))) fail(where, 'remove sent ' + JSON.stringify(sent));
        if (width === 390 && scheme === 'dark') {
          // Time on screen only: back to it, then 10 seconds.
          await p.locator('#queue article').first().scrollIntoViewIfNeeded();
          await p.waitForTimeout(10800);
          const later = await p.$$eval('#queue article:first-of-type .ap-choice', (bs) => bs.map((b) => b.disabled));
          if (later.some(Boolean)) fail(where, 'the sensitive item still can\'t be decided after 10 seconds on screen');
        }
        await p.close();

        // ---- /admin/controls ----
        p = await open('/admin/controls');
        where = tag + ' /admin/controls';
        const c = await p.evaluate(() => {
          const b = document.getElementById('brake-go');
          const s = getComputedStyle(b);
          const del = [...document.querySelectorAll('#deletion-reviews button')].find((x) => x.textContent === 'Allow deletion');
          return { color: s.color, border: s.borderTopColor, bg: getComputedStyle(document.body).backgroundColor, del: del && del.disabled,
            review: document.getElementById('review-stats').textContent, budget: document.getElementById('r-budget').value,
            nums: [...document.querySelectorAll('#totals .num')].map((n) => n.textContent) };
        });
        const cbg = c.bg === 'rgba(0, 0, 0, 0)' ? (scheme === 'dark' ? 'rgb(13, 15, 20)' : 'rgb(246, 247, 249)') : c.bg;
        const want = scheme === 'dark' ? 'rgb(241, 133, 127)' : 'rgb(163, 48, 42)';
        if (c.color !== want) fail(where, 'the brake\'s words are ' + c.color + ', not ' + want);
        if (ratio(c.color, cbg) < 4.5) fail(where, 'the brake\'s words ' + ratio(c.color, cbg).toFixed(2) + ':1');
        if (ratio(c.border, cbg) < 3) fail(where, 'the brake\'s edge ' + ratio(c.border, cbg).toFixed(2) + ':1');
        if (!c.del) fail(where, 'Allow deletion works before 10 seconds');
        if (c.budget !== '25' || !/Today: 4 of your 25 held items decided\./.test(c.review) || !/Each of the 3 revealed tests hashes to the commitment/.test(c.review)) fail(where, 'review section: ' + c.budget + ' / ' + c.review);
        if (c.nums.join() !== '12,3,13,3') fail(where, 'stat cards: ' + c.nums.join());
        if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'admin-controls-' + tag + '.png'), fullPage: true });
        await p.close();

        // ---- /decisions ----
        p = await open('/decisions');
        where = tag + ' /decisions';
        const d = await p.evaluate(() => ['r-held-7', 'r-flagged-7', 'r-published-30', 's-drawn-7', 'c-bad-30', 'c-good-30', 'sample-state', 'alerts']
          .map((id) => document.getElementById(id).textContent));
        const wantD = '7 | Fewer than 5 | 6 | 8 and fewer than 5 more | Not enough history yet: 1 of 1 | 1 of 1 | The sample is on: 5% of low-risk posts, at most 100 a day. | Sampled posts went unread for 24 hours. 1 sampled post waited over 24 hours for Second Look.';
        if (d.join(' | ') !== wantD) fail(where, d.join(' | '));
        // Never a person's own figures (Aaron, Nov 5): no time on an item, no hours, nothing by reviewer.
        const txt = await p.evaluate(() => document.querySelector('main').textContent);
        if (/seconds on each|hours on the queue|decided by|per person/i.test(txt)) fail(where, 'a person\'s own figure is shown');
        if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'decisions-' + tag + '.png'), fullPage: true });
        await p.close();
        await ctx.close();
      }
    }
  } finally {
    await browser.close();
    server.close();
  }
  if (problems.length) { console.log('FAIL review tiers (' + views + ' views)\n' + problems.map((x) => '  ' + x).join('\n')); process.exitCode = 1; }
  else console.log('OK review tiers: ' + views + ' views (/admin/review, /admin/controls, /decisions at 390 and 1280 px, dark and light)' + (SHOTS ? '; screenshots in ' + SHOTS : ''));
}

// Run as a check; required, it lends its stand-in answers to scripts/check-design.js.
if (require.main === module) main().catch((e) => { console.error(e && e.stack); process.exitCode = 2; });
module.exports = { QUEUE, CONTROLS, DECISIONS };
