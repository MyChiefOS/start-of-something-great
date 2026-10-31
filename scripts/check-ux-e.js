// UX PR E (the UI/UX review of Oct 31, findings 7, 8, 9, 10, 11 and 14's page part), in a real browser on a local copy,
// with the same stand-in answers as scripts/check-signed-out.js (whose local server and stand-ins it borrows):
//   - /feed: screen readers hear one short line when posts load, not the list; the character count is heard only at
//     4,500 and at the limit; names show "GitHub member" or "Verified", with "What the levels mean" once;
//   - /feed after a sign-in with a code: the welcome shows once, takes focus, and is gone after a reload;
//   - /account#notices: Notices come first and are scrolled to, in the first screen on a phone;
//   - /agents with a claim link, below level 2: the way to level 2 in words, with its link;
//   - /team#levels: the levels explained;
//   - /feed's search (UX PR G, findings 8 and 13): a labelled field; results replace the list with "N posts match" and
//     the administrator's name says so; Clear brings the lane back.
// Checked at 390 by 844 and 1280 by 800, dark and light. Exits 1 on any problem. --root DIR checks another copy.
'use strict';

const { serve, context, open, ROOT } = require('./check-signed-out');

const SIZES = [{ width: 390, height: 844 }, { width: 1280, height: 800 }];
const SCHEMES = ['dark', 'light'];
const CODE = 'A'.repeat(43);

async function main() {
  const { chromium } = require('playwright');
  const server = serve();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch();
  const problems = [];
  const fail = (where, what) => problems.push(where + ': ' + what);
  let views = 0;
  try {
    for (const { width, height } of SIZES) {
      for (const scheme of SCHEMES) {
        const tag = width + ' ' + scheme;
        // A member, signed in.
        const { ctx } = await context(browser, base, { width, height, scheme, who: 'member' });
        // The claim preview, for a member below level 2.
        await ctx.route(base + '/api/agents/claim', (r) => r.fulfill({ status: 200, contentType: 'application/json',
          body: JSON.stringify({ agent: { name: 'Helper', description: '', registered_at: new Date().toISOString() }, can_own: false, fresh: true }) }));

        // /feed: what screen readers hear, and the level names.
        let p = await open(ctx, base, '/feed', tag + ' /feed', fail);
        let where = tag + ' /feed';
        let m = await p.evaluate(() => ({
          live: [...document.querySelectorAll('main [aria-live]')].map((e) => e.id),
          postsLive: document.getElementById('posts').getAttribute('aria-live'),
          say: document.getElementById('posts-say').textContent,
          sayRole: document.getElementById('posts-say').getAttribute('role'),
          sayShown: document.getElementById('posts-say').getBoundingClientRect().width > 1,
          metas: [...document.querySelectorAll('#posts .post-meta')].map((x) => x.textContent),
          levelsLink: [...document.querySelectorAll('main a[href="/team#levels"]')].filter((a) => a.checkVisibility()).length,
          alternates: [...document.querySelectorAll('link[rel="alternate"][type="application/json"]')].map((l) => l.getAttribute('href')),
          welcome: document.getElementById('welcome').checkVisibility(),
          sideways: document.documentElement.scrollWidth > innerWidth
        }));
        views++;
        if (m.postsLive !== null) fail(where, 'the post list is still a live region');
        if (m.sayRole !== 'status' || m.say !== '2 posts from people loaded.') fail(where, 'the load is announced as: ' + JSON.stringify(m.say));
        if (m.sayShown) fail(where, 'the screen-reader line is visible');
        if (!m.metas.some((x) => /Ada · GitHub member · /.test(x)) || !m.metas.some((x) => /Grace · Verified · /.test(x))) fail(where, 'level names: ' + JSON.stringify(m.metas));
        if (m.metas.some((x) => /GitHub or X|level \d/.test(x))) fail(where, 'an old level label is left');
        if (m.levelsLink < 1) fail(where, 'no "What the levels mean" link');
        if (JSON.stringify(m.alternates) !== JSON.stringify(['/api/feed?lane=people', '/api/feed?lane=agents'])) fail(where, 'alternate links: ' + m.alternates);
        if (m.welcome) fail(where, 'the welcome shows without a sign-in');
        if (m.sideways) fail(where, 'the page scrolls sideways');
        // The count: typing to 4,499 says nothing; 4,500 says what's left; the limit says so; under 4,500 clears it.
        const typed = await p.evaluate(() => {
          const body = document.getElementById('body');
          const sayEl = document.getElementById('count-say');
          const out = [];
          const set = (n) => { body.value = 'x'.repeat(n); body.dispatchEvent(new Event('input')); out.push(sayEl.textContent); };
          [10, 4499, 4500, 4600, 5000, 100].forEach(set);
          return { out, countLive: document.getElementById('count').getAttribute('aria-live'), role: sayEl.getAttribute('role') };
        });
        const want = ['', '', '500 characters or fewer left.', '500 characters or fewer left.', 'You have reached the 5,000-character limit.', ''];
        if (JSON.stringify(typed.out) !== JSON.stringify(want)) fail(where, 'the count is heard as ' + JSON.stringify(typed.out));
        if (typed.countLive !== null || typed.role !== 'status') fail(where, 'the visible count is still announced on every key');
        await p.close();

        // /feed's search (UX PR G): the results replace the list, one line says how many match, and Clear undoes it.
        let asked = null;
        await ctx.route((u) => u.pathname === '/api/feed' && u.searchParams.has('q'), (r) => {
          asked = new URL(r.request().url()).searchParams.get('q');
          return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ next: null, posts: [
            { id: '0190a000-0000-7000-8000-000000000003', author: { name: 'Aaron', level: 2, role: 'administrator' }, published_at: new Date().toISOString(), body: 'The garden opens.' }] }) });
        });
        p = await open(ctx, base, '/feed', tag + ' /feed search', fail);
        where = tag + ' /feed search';
        const label = await p.evaluate(() => { const q = document.getElementById('q'); return { label: q.labels.length ? q.labels[0].textContent : null, type: q.type,
          above: q.getBoundingClientRect().top < document.getElementById('posts').getBoundingClientRect().top, clear: document.getElementById('clear').checkVisibility() }; });
        if (label.label !== 'Search posts' || label.type !== 'search' || !label.above || label.clear) fail(where, 'the field: ' + JSON.stringify(label));
        await p.fill('#q', '  garden   party ');
        await p.press('#q', 'Enter');
        await p.waitForFunction(() => /match/.test(document.getElementById('posts-say').textContent));
        m = await p.evaluate(() => ({ say: document.getElementById('posts-say').textContent, metas: [...document.querySelectorAll('#posts .post-meta')].map((x) => x.textContent),
          clear: document.getElementById('clear').checkVisibility(), sideways: document.documentElement.scrollWidth > innerWidth }));
        views++;
        if (asked !== 'garden party') fail(where, 'the search sent was ' + JSON.stringify(asked));
        if (m.say !== '1 post from people matches.') fail(where, 'announced as ' + JSON.stringify(m.say));
        if (m.metas.length !== 1 || !/^Aaron · Administrator · Verified · /.test(m.metas[0])) fail(where, 'results: ' + JSON.stringify(m.metas));
        if (!m.clear) fail(where, 'no Clear button');
        if (m.sideways) fail(where, 'the page scrolls sideways');
        await p.click('#clear');
        await p.waitForFunction(() => /loaded/.test(document.getElementById('posts-say').textContent));
        m = await p.evaluate(() => ({ say: document.getElementById('posts-say').textContent, value: document.getElementById('q').value,
          clear: document.getElementById('clear').checkVisibility(), focus: document.activeElement && document.activeElement.id }));
        if (m.say !== '2 posts loaded.' || m.value !== '' || m.clear || m.focus !== 'q') fail(where, 'after Clear: ' + JSON.stringify(m));
        await p.close();

        // /feed after a sign-in with a code (join.js sets the flag): once, with focus, then gone.
        p = await ctx.newPage();
        p.on('pageerror', (e) => fail(tag + ' /feed welcome', 'script error: ' + e.message));
        await p.goto(base + '/feed', { waitUntil: 'load' });
        await p.evaluate(() => sessionStorage.setItem('dog-welcome', '1'));
        await p.reload({ waitUntil: 'load' });
        await p.waitForTimeout(250);
        where = tag + ' /feed welcome';
        m = await p.evaluate(() => ({ shown: document.getElementById('welcome').checkVisibility(), focus: document.activeElement && document.activeElement.id,
          links: [...document.querySelectorAll('#welcome a')].map((a) => a.getAttribute('href')),
          top: Math.round(document.getElementById('welcome').getBoundingClientRect().top), flag: sessionStorage.getItem('dog-welcome') }));
        views++;
        if (!m.shown) fail(where, 'the welcome does not show');
        if (m.focus !== 'welcome-heading') fail(where, 'focus is on ' + m.focus);
        if (JSON.stringify(m.links) !== JSON.stringify(['/account#name', '#body', '/connect', '/team#levels'])) fail(where, 'links: ' + m.links);
        if (m.top > height) fail(where, 'the welcome starts below the first screen (' + m.top + ')');
        if (m.flag !== null) fail(where, 'the flag is kept after showing');
        await p.click('#welcome-close');
        if (await p.evaluate(() => document.getElementById('welcome').checkVisibility())) fail(where, 'Close does not close it');
        if (await p.evaluate(() => document.activeElement && document.activeElement.id) !== 'body') fail(where, 'Close does not move focus to the post box');
        await p.reload({ waitUntil: 'load' });
        await p.waitForTimeout(250);
        if (await p.evaluate(() => document.getElementById('welcome').checkVisibility())) fail(where, 'the welcome shows again after a reload');
        await p.close();

        // /account#notices: Notices first, and scrolled to.
        p = await open(ctx, base, '/account#notices', tag + ' /account', fail);
        where = tag + ' /account#notices';
        m = await p.evaluate(() => ({
          order: [...document.querySelectorAll('#details h2')].map((h) => h.textContent),
          top: Math.round(document.getElementById('notices').getBoundingClientRect().top)
        }));
        views++;
        if (JSON.stringify(m.order) !== JSON.stringify(['Notices', 'Shortcuts', 'Your name', 'How you sign in', 'Signing out', 'Delete your account'])) fail(where, 'order: ' + m.order);
        if (m.top < 0 || m.top > height / 2) fail(where, 'Notices are not brought into view (top ' + m.top + ')');
        await p.close();
        // /account#name: the name field, with the cursor in it.
        p = await open(ctx, base, '/account#name', tag + ' /account#name', fail);
        m = await p.evaluate(() => ({ focus: document.activeElement && document.activeElement.id, top: Math.round(document.getElementById('name').getBoundingClientRect().top) }));
        if (m.focus !== 'name' || m.top < 0 || m.top > height) fail(tag + ' /account#name', 'the name field is not reached: ' + JSON.stringify(m));
        await p.close();

        // /agents with a claim link, below level 2.
        p = await open(ctx, base, '/agents#claim=' + CODE, tag + ' /agents claim', fail);
        where = tag + ' /agents claim';
        m = await p.evaluate(() => ({ text: document.getElementById('claim-status').textContent,
          links: [...document.querySelectorAll('#claim-status a')].map((a) => a.getAttribute('href')),
          disabled: document.getElementById('claim-button').disabled }));
        views++;
        if (!/Our checks usually verify a GitHub account at its first sign-in; yours isn’t verified yet\. They look again each time you sign in/.test(m.text)) fail(where, 'no way forward: ' + m.text);
        if (JSON.stringify(m.links) !== JSON.stringify(['/join?return_to=%2Fagents', '/team#levels']) || !m.disabled) fail(where, 'links or button: ' + JSON.stringify(m));
        await p.close();

        // /team#levels.
        p = await open(ctx, base, '/team#levels', tag + ' /team', fail);
        m = await p.evaluate(() => ({ top: Math.round(document.getElementById('levels').getBoundingClientRect().top), items: [...document.querySelectorAll('#levels + p + ul li strong')].map((x) => x.textContent) }));
        views++;
        if (m.top < 0 || m.top > height / 2) fail(tag + ' /team#levels', 'not scrolled to');
        if (JSON.stringify(m.items) !== JSON.stringify(['GitHub member', 'Verified', 'Email only'])) fail(tag + ' /team#levels', 'levels: ' + m.items);
        await p.close();
        await ctx.close();
      }
    }
  } finally {
    await browser.close();
    server.close();
  }
  if (problems.length) {
    console.log('FAIL UX PR E (local copy of ' + ROOT + ')\n' + problems.map((x) => '  ' + x).join('\n'));
    process.exitCode = 1;
  } else {
    console.log('OK UX PR E (local copy of ' + ROOT + '): ' + views + ' page views at 390 and 1280 px, dark and light: /feed (announcements, levels, agent links, the welcome once), /account (notices first, #notices and #name), /agents (the way to level 2), /team#levels, /feed search (UX PR G)');
  }
}

main().catch((e) => { console.error(e && e.stack); process.exitCode = 2; });
