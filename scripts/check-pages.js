#!/usr/bin/env node
// A signed-out visitor's check of the pages a person needs to get a result, in a real browser (Oct 29, 2026: /join
// had lost its script and nobody could sign in, while every file-reading test passed).
//
//   node scripts/check-pages.js [base]        base defaults to https://dayonegreat.com
//
// Read-only: it opens pages and looks; it never presses a button, signs in or gets a sign-in code. It exits 1 if a
// page throws a script error, the sign-in on /join doesn't show, or a form that needs sign-in shows to a visitor.
// Needs Playwright with Chromium (`require('playwright')`); not part of the test suite, which runs without a browser.
'use strict';

const base = (process.argv[2] || 'https://dayonegreat.com').replace(/\/+$/, '');

// What a signed-out visitor must and mustn't see on each page.
const PAGES = [
  // The sign-in panel's two paths (UX PR A): the fields and buttons show once one is chosen (scripts/check-join-panel.js).
  { path: '/join', visible: ['#code-signin', '#path-new', '#path-back'], hidden: ['#code-show'] },
  { path: '/feed', visible: [], hidden: ['#compose'] },
  { path: '/agents', visible: [], hidden: ['#create'] },
  { path: '/account', visible: [], hidden: ['#details'] }
];

async function main() {
  const { chromium } = require('playwright');
  const browser = await chromium.launch();
  const problems = [];
  try {
    for (const page of PAGES) {
      const ctx = await browser.newContext();
      // giscus is a third party; its frame is not ours to check, and leaving it out keeps the check about our pages.
      await ctx.route('https://giscus.app/**', (r) => r.abort());
      const p = await ctx.newPage();
      p.on('pageerror', (e) => problems.push(page.path + ': script error: ' + e.message));
      await p.goto(base + page.path, { waitUntil: 'domcontentloaded' });
      await p.waitForTimeout(2000);
      for (const sel of page.visible) if (!(await p.isVisible(sel))) problems.push(page.path + ': ' + sel + ' should show to a signed-out visitor');
      for (const sel of page.hidden) if ((await p.locator(sel).count()) && (await p.isVisible(sel))) problems.push(page.path + ': ' + sel + ' should not show to a signed-out visitor');
      await ctx.close();
    }
  } finally {
    await browser.close();
  }
  if (problems.length) {
    console.log('FAIL ' + base + '\n' + problems.map((x) => '  ' + x).join('\n'));
    process.exitCode = 1;
  } else {
    console.log('OK ' + base + ': ' + PAGES.map((x) => x.path).join(', ') + ' (signed out, no script errors)');
  }
}

main().catch((e) => { console.error(e && e.message); process.exitCode = 2; });
