'use strict';
// The signed-in app pages to the design handoff of Nov 5, 2026 (static/account.html, agents.html, review.html,
// controls.html; CODING_AGENT_SPEC.md 2.2, 5.5 and section 6): Your account, Your agents, and the administrator's
// Review and Owner controls, which moved from /review and /controls to /admin/review and /admin/controls (as /agents
// moved to /account/agents). Each page's real <main> and script run in the small stand-in DOM (test/helpers/mini-dom.js).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { page, settle } = require('./helpers/mini-dom');
const shell = require('../scripts/shell');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const ID = (n) => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const headings = (html) => [...html.slice(html.indexOf('<main')).matchAll(/<h([12])\b[^>]*>([^<]+)</g)].map((m) => m[2].trim());
// The design's headings appear in the page in the design's order (the page may add its own between them).
const inOrder = (have, want) => { let i = 0; for (const h of have) if (h === want[i]) i++; return i === want.length; };

const PAGES = [
  { file: 'account.html', path: '/account', script: '/account.js', css: '/account.css', h1: 'Your account',
    h2: ['Notices', 'Shortcuts', 'Your name', 'How you sign in', 'Signing out', 'Delete your account'] },
  // 040: the design's own markup (static/agents.html), its cards from templates; no stylesheet of its own but the inline
  // classes the build makes (css/account-agents.css).
  { file: 'account/agents.html', path: '/account/agents', script: '/account/agents.js', css: '/css/account-agents.css', main: 'story', h1: 'Your agents',
    h2: ['Waiting for your approval', 'Add an agent', 'Your agents'] },
  { file: 'admin/review.html', path: '/admin/review', script: '/admin/review.js', css: '/admin/review.css', h1: 'Review', kicker: true,
    h2: ['Paused owners and appeals'] },
  { file: 'admin/controls.html', path: '/admin/controls', script: '/admin/controls.js', css: '/admin/controls.css', h1: 'Owner controls', kicker: true,
    h2: ['Deletion reviews', 'Emergency brake', 'Owners', 'JEVs, the automated checks', 'Second Look, the narrow AI', 'Same text, many posts'] }
];
// The design's sample figures and names (static/account.html, agents.html, review.html, controls.html): none may show.
const SAMPLES = ['3,841', '212', '@mira', 'mira', 'claude_helper', 'build_scribe', '@jordan_k', 'jordan_k', '@new_account', 'Check out this offer',
  'Great project!', 'Excited to build here', 'Low risk 31', 'Medium 3', 'High 4', '14 posts', 'A batch of replies went out together', 'Reported by 2 members',
  'from a new browser', 'Proposal filed: a weekly summary'];

test('each page is at its design path, carries the shell, and has the design\'s heading, sections in order, own script and styles', () => {
  for (const p of PAGES) {
    const html = read(p.file);
    assert.strictEqual(shell.render(p.file, html), html, p.file + ' carries the shell');
    assert.ok(shell.pages().includes(p.file), p.file + ' is one of the shell\'s pages');
    assert.match(html, new RegExp('<link rel="canonical" href="https://dayonegreat\\.com' + p.path.replace(/\//g, '\\/') + '">'), p.file);
    assert.match(html, /<meta name="robots" content="noindex">/, p.file + ': private');
    assert.match(html, new RegExp('<script defer src="' + p.script.replace(/\//g, '\\/').replace('.', '\\.') + '"><\\/script>'), p.file);
    assert.match(html, new RegExp('<link rel="stylesheet" href="' + p.css.replace(/\//g, '\\/').replace('.', '\\.') + '">'), p.file);
    // The design's stylesheet, then the app pages' shared one, then the page's own (tools/design/build.js).
    assert.match(html, new RegExp('<link rel="stylesheet" href="/design\\.css">\\n  <link rel="stylesheet" href="/app\\.css">\\n  <link rel="stylesheet" href="' + p.css.replace('.', '\\.') + '">'), p.file);
    assert.strictEqual((html.match(/<h1\b/g) || []).length, 1, p.file);
    const h = headings(html);
    assert.strictEqual(h[0], p.h1, p.file);
    assert.ok(inOrder(h.slice(1), p.h2), p.file + ': ' + h.join(' / '));
    if (p.kicker) assert.match(html, /<p class="kick">Administrator only<\/p>\n<h1>/, p.file + ': the design\'s kicker');
    assert.match(html, p.main ? new RegExp('<main class="' + p.main + '" id="main" tabindex="-1">') : /<main class="story feed [^"]*" id="main" tabindex="-1">/, p.file);
  }
});

test('no inline style, no inline script, no on* handler, text only in the scripts, and no sample figure from the design', () => {
  for (const p of PAGES) {
    const html = read(p.file);
    const js = read(p.script.slice(1));
    assert.ok(!/\sstyle=/.test(html), p.file + ': no inline style');
    assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/.test(html), p.file + ': no inline script');
    assert.ok(!/\son[a-z]+=/i.test(html), p.file + ': no on* handler');
    assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function/.test(js), p.script + ': text only');
    assert.ok(!/\.style\b/.test(js), p.script + ': no styles set from the script');
    for (const f of [...js.matchAll(/fetch\('([^']+)'/g)].map((m) => m[1])) assert.match(f, /^\/(api|auth)\//, p.script + ' fetches our own ' + f);
    const main = html.slice(html.indexOf('<main'), html.indexOf('</main>'));
    for (const s of SAMPLES) {
      assert.ok(!main.includes(s), p.file + ' shows the design\'s sample "' + s + '"');
      assert.ok(!js.replace(/^\s*\/\/.*$/gm, '').includes(s), p.script + ' writes the design\'s sample "' + s + '"');
    }
  }
});

test('the old /review and /controls pass a visitor on to /admin/review and /admin/controls, the query and the part after "#" kept', async () => {
  for (const [old, now] of [['review', '/admin/review'], ['controls', '/admin/controls']]) {
    const html = read(old + '.html');
    assert.match(html, new RegExp('<link rel="canonical" href="https://dayonegreat\\.com' + now.replace(/\//g, '\\/') + '">'));
    assert.match(html, new RegExp('<a id="moved-to" href="' + now.replace(/\//g, '\\/') + '">'), 'a plain link for anyone without JavaScript');
    assert.match(html, new RegExp('<script defer src="\\/' + old + '\\.js"><\\/script>'));
    assert.strictEqual(shell.render(old + '.html', html), html, old + '.html carries the shell');
    for (const [search, hash] of [['', ''], ['', '#appeals'], ['?tab=reports', ''], ['?x=1', '#y']]) {
      const p = page(old + '.html', old + '.js', () => [500, {}], search, hash);
      await settle();
      assert.deepStrictEqual(p.replaced, [now + search + hash], old + search + hash);
      assert.deepStrictEqual(p.asked, [], 'and loads nothing itself');
    }
  }
});

test('every link that sends Aaron to the review queue or the controls goes to /admin/...; nothing on our pages or in our API answers points at the old paths', () => {
  const html = read('account.html');
  assert.match(html, /<a href="\/admin\/review">Review queue<\/a>/);
  assert.match(html, /<a href="\/admin\/controls">Controls<\/a>/);
  assert.match(read('admin/review.html'), /href="\/join\?return_to=%2Fadmin%2Freview"/);
  assert.match(read('admin/controls.html'), /href="\/join\?return_to=%2Fadmin%2Fcontrols"/);
  const { returnPath } = require('../signin/http');
  for (const p of ['/admin/review', '/admin/controls', '/admin/review#appeals']) assert.strictEqual(returnPath(p.split('#')[0]), p.split('#')[0], 'sign-in comes back to ' + p);
  const files = ['account.html', 'account/agents.html', 'account/agents.js', 'admin/review.html', 'admin/review.js', 'admin/controls.html', 'admin/controls.js', 'nav.js', 'join.js']
    .concat(fs.readdirSync(path.join(root, 'api')).filter((f) => f.endsWith('.js')).map((f) => 'api/' + f));
  for (const f of files) {
    const s = read(f).replace(/^\s*\/\/.*$/gm, '');
    assert.ok(!/href="\/(review|controls)\b|'\/(review|controls)(?=[#?'])|return_to=%2F(review|controls)\b|dayonegreat\.com\/(review|controls)\b/.test(s), f + ' still points at /review or /controls');
  }
  // The scanner covers the moved scripts (R-7).
  assert.match(read('.github/workflows/checks.yml'), / admin\/review\.js admin\/controls\.js[ \n]/);
});

// ---- Your account ----

const ACCOUNT = { signed_in: true, display_name: 'Ada', trust_level: 2, joined: '2026-10-01T00:00:00Z', member_id: ID(1),
  sign_ins: [{ id: ID(2), provider: 'github', level: 1 }], sessions: 1, is_admin: false, deletion_review: null };
const notice = (o) => ({ id: ID(Math.floor(Math.random() * 1e6)), kind: 'alert', title: 'T', body: 'B', link: null, read: false, created_at: '2026-11-05T10:00:00Z', for_admins: false, ...o });
function account(notices, extra = {}) {
  const posted = [];
  const p = page('account.html', 'account.js', (url, init) => {
    if (init && init.method === 'POST') { posted.push({ url, body: JSON.parse(init.body) }); return [201, { agent: ID(30), rules: { version: 3 } }]; }
    if (url === '/auth/account') return [200, ACCOUNT];
    if (url === '/api/notify') return [200, { unread: notices.filter((n) => !n.read).length, notices }];
    if (url === '/api/agents/activity') return [200, extra.activity || { agents: [], inbox: [] }];
    if (url === '/api/feed?challenges=1') return [200, { challenges: extra.challenges || [] }];
    return [404, {}];
  });
  return { p, posted };
}

test('/account: "Signed in as <name> · <level>" under the heading, as the design draws it (the name shown on posts, never an invented @handle)', async () => {
  const { p } = account([]);
  await settle();
  assert.strictEqual(p.$('message').textContent, 'Signed in as Ada · Verified');
  assert.strictEqual(p.$('details').hidden, false);
  assert.strictEqual(p.$('notices-summary').textContent, 'No notices yet. When something needs you, it shows up here first.');
});

test('/account: each notice is a card with a pill naming its kind; old links open their new addresses', async () => {
  const notices = [
    notice({ kind: 'alert', title: 'Second Look published a held post', link: '/review' }),
    notice({ kind: 'alert', title: 'An owner appealed a containment', link: '/review#appeals' }),
    notice({ kind: 'alert', title: 'A deletion needs your decision', link: '/controls' }),
    notice({ kind: 'challenge', title: 'Please confirm making a new agent', link: '/join?return_to=%2Fagents' }),
    notice({ kind: 'act_reconfirm', title: 'Keep Scout acting on its own?', link: '/agents#agent-x' }),
    notice({ kind: 'signin_keyfile', title: 'Signed in with your key file', link: null, read: true }),
    notice({ kind: 'post_published', title: 'Your post was reviewed and published', link: '/feed#mine', read: true })
  ];
  const { p } = account(notices);
  await settle();
  const cards = p.$('notice-list').querySelectorAll('article');
  assert.strictEqual(cards.length, 7);
  assert.deepStrictEqual(cards.map((c) => c.className), notices.map((n) => 'card notice-card' + (n.read ? ' decided' : '')));
  assert.deepStrictEqual(cards.map((c) => [c.children[0].className, c.children[0].textContent]),
    [['pill a', 'Alert'], ['pill a', 'Alert'], ['pill a', 'Alert'], ['pill a', 'Held post'], ['pill a', '90-day check'], ['pill m', 'Sign-in'], ['pill m', 'Notice']]);
  const opens = cards.map((c) => { const a = c.querySelector('a'); return a && a.textContent === 'Open' ? a.getAttribute('href') : null; });
  assert.deepStrictEqual(opens, ['/admin/review', '/admin/review#appeals', '/admin/controls', '/join?return_to=%2Faccount%2Fagents', '/account/agents#agent-x', null, '/feed#mine']);
  // Only the moved paths are changed: a lookalike stays as it is.
  const js = read('account.js');
  const moved = new Function('return ' + js.match(/function moved\(link\) \{[\s\S]*?\n {2}\}/)[0])();
  assert.deepStrictEqual(['/reviews', '/controlsx', '/admin/review', '/join?return_to=%2Fagentsx', '/join?return_to=%2Freview%23x'].map(moved),
    ['/reviews', '/controlsx', '/admin/review', '/join?return_to=%2Fagentsx', '/join?return_to=%2Fadmin%2Freview%23x']);
});

test('/account: a draft\'s notice shows its exact words with "Approve and post" and "Reject" drawn alike; the 90-day check offers "Keep acting" and "Back to drafts"', async () => {
  const agent = { id: ID(30), name: 'Scout', status: 'active', rules: { version: 2, post: 'act', reply: 'act', report: 'draft', daily_cap: 20 },
    acting_alone: { confirmed_at: '2026-08-10T00:00:00Z', ask_at: '2026-10-29T00:00:00Z', drafts_at: '2026-11-08T00:00:00Z' } };
  const draft = { id: ID(40), agent: { id: ID(30), name: 'Scout' }, body: 'Exact words.\n\nTwo paragraphs.', created_at: '2026-11-05T09:00:00Z', expires_at: '2026-11-07T09:00:00Z' };
  const { p, posted } = account([
    notice({ kind: 'draft_waiting', title: 'Scout wrote a draft for you', subject: { kind: 'draft', id: ID(40) } }),
    notice({ kind: 'act_reconfirm', title: 'Keep Scout acting on its own?', subject: { kind: 'agent', id: ID(30) } })
  ], { activity: { agents: [agent], inbox: [draft] } });
  await settle();
  const [d, r] = p.$('notice-list').querySelectorAll('article');
  assert.strictEqual(d.querySelector('blockquote').textContent, 'Exact words.\n\nTwo paragraphs.', 'the words exactly as written');
  const dButtons = d.querySelector('.acts').querySelectorAll('button');
  assert.deepStrictEqual(dButtons.map((b) => [b.textContent, b.className]), [['Approve and post', 'btn s'], ['Reject', 'btn s']], 'equal weight (2.2)');
  const rButtons = r.querySelector('.acts').querySelectorAll('button');
  assert.deepStrictEqual(rButtons.map((b) => [b.textContent, b.className]), [['Keep acting', 'btn s'], ['Back to drafts', 'btn s']]);
  rButtons[1].click();
  await settle();
  // What the 90-day clock does itself (011, act_expire): every "act" becomes "draft", the daily limit kept.
  assert.deepStrictEqual(posted, [{ url: '/api/agents/rules', body: { agent: ID(30), post: 'draft', reply: 'draft', report: 'draft', daily_cap: 20 } }]);
  assert.match(r.textContent, /Back to drafts: its posts wait for your approval on Your agents\./);
  assert.match(read('db/migrations/011_notifications.sql'), /case when r\.post_mode = 'act' then 'draft' else r\.post_mode end,\s+case when r\.reply_mode = 'act' then 'draft' else r\.reply_mode end,\s+case when r\.report_mode = 'act' then 'draft' else r\.report_mode end, r\.daily_cap, 'act_expired'/);
});

test('/account: the administrator sees the moved shortcuts and no Delete; the forms are the design\'s, labels above their fields', async () => {
  const p = page('account.html', 'account.js', (url) => (url === '/auth/account' ? [200, { ...ACCOUNT, is_admin: true }] : [200, { unread: 0, notices: [] }]));
  await settle();
  assert.strictEqual(p.$('go-review').hidden, false);
  assert.strictEqual(p.$('go-controls').hidden, false);
  assert.strictEqual(p.$('delete-part').hidden, true);
  const html = read('account.html');
  assert.match(html, /<label for="name">Name shown on your posts<\/label>\n\s*<input name="name" id="name" type="text"/);
  assert.match(html, /<label for="delete-confirm">Type DELETE to confirm<\/label>\n\s*<input id="delete-confirm" name="confirm"/);
  assert.match(html, /<div class="acts sign-out">\n\s*<form method="post" action="\/auth\/logout"><button type="submit" class="btn">Sign out here<\/button><\/form>\n\s*<form method="post" action="\/auth\/logout-all"><button type="submit" class="btn">Sign out everywhere<\/button><\/form>/);
  assert.match(html, /<button type="submit" class="btn s danger">Delete my account<\/button>/);
});

// ---- Your agents ----

function agents(list, activity) {
  const posted = [];
  const p = page('account/agents.html', 'account/agents.js', (url, init) => {
    if (init && init.method === 'POST') { posted.push({ url, body: JSON.parse(init.body) }); return [201, { agent: ID(30), rules: { version: 4 } }]; }
    if (url === '/api/agents/activity') return [200, activity];
    return [200, { agents: list, can_own: true }];
  });
  return { p, posted };
}

test('/account/agents: each draft is a card with its exact words, and Approve and Reject drawn alike', async () => {
  const draft = { id: ID(40), agent: { id: ID(30), name: 'Scout' }, body: 'Exact words.', created_at: '2026-11-05T09:00:00Z', expires_at: '2026-11-07T09:00:00Z' };
  const { p, posted } = agents([], { agents: [], inbox: [draft], containment: null, unread_notices: 0 });
  await settle();
  assert.strictEqual(p.$('inbox').hidden, false);
  // 040: the design's own card (tools/design/pages/account_agents.main.html, its draft template).
  const card = p.$('drafts').querySelector('div');
  assert.match(card.className, /^card x[0-9a-f]{8}$/);
  assert.strictEqual(card.querySelector('[data-slot="body"]').textContent, 'Exact words.');
  const buttons = card.querySelectorAll('button');
  assert.deepStrictEqual(buttons.map((b) => [b.textContent, b.className]), [['Approve', 'btn s'], ['Reject', 'btn s']]);
  buttons[1].click();
  await settle();
  assert.deepStrictEqual(posted, [{ url: '/api/agents/decline', body: { draft: ID(40) } }]);
  assert.match(card.textContent, /Rejected\./);
});

test('/account/agents: each agent is a card with its name, a mode pill, and Drafts, Change limit, New key and Revoke; a sub-agent sits a step in', async () => {
  const now = Date.now();
  const list = [
    { id: ID(30), name: 'Scout', description: null, status: 'active', parent_id: null, depth: 0, expires_at: null, keys: [{ id: ID(50), revoked_at: null }] },
    { id: ID(31), name: 'Helper', description: null, status: 'active', parent_id: ID(30), depth: 1, expires_at: new Date(now + 6.2 * 86400000).toISOString(), keys: [{ id: ID(51), revoked_at: null }] }
  ];
  const activity = { inbox: [], containment: null, unread_notices: 0, agents: [
    { id: ID(30), rules: { version: 2, post: 'act', reply: 'act', report: 'draft', daily_cap: 20 }, acting_alone: null, last_30_days: null },
    { id: ID(31), rules: { version: 1, post: 'draft', reply: 'draft', report: 'draft', daily_cap: 5 }, acting_alone: null, last_30_days: null }] };
  const { p, posted } = agents(list, activity);
  await settle();
  // 040: the design's cards, cloned from the page's templates: a sub-agent from the one a step in for its level.
  const [scout, helper] = [p.$('agent-' + ID(30)), p.$('agent-' + ID(31))];
  assert.strictEqual(scout.className, 'card');
  const step = (n) => p.$('sub-tpl-' + n).firstElementChild.className;
  assert.strictEqual(helper.className, step(1));
  assert.notStrictEqual(step(1), step(2), 'each level its own step in');
  assert.strictEqual(scout.querySelector('h3').textContent, 'Scout');
  assert.strictEqual(helper.querySelector('h3').textContent, 'Helper (sub-agent)');
  assert.deepStrictEqual([scout, helper].map((c) => { const s = c.querySelector('.pill'); return [s.className, s.textContent]; }),
    [['pill a', 'Acts on its own · 20 a day'], ['pill', 'Drafts · expires in 6 days']]);
  const acts = (c) => c.querySelector('.acts').querySelectorAll('button').filter((b) => !b.hidden).map((b) => b.textContent);
  assert.deepStrictEqual(acts(scout), ['Drafts', 'Change limit', 'New key', 'Revoke, with 1 sub-agent under it']);
  assert.deepStrictEqual(acts(helper), ['Change limit', 'New key', 'Revoke'], 'Drafts only while something acts on its own');
  // Change limit opens the agent's rules (posting, replies, reports and the daily limit).
  const change = scout.querySelector('.acts').querySelectorAll('button')[1];
  const rules = p.$('rules-' + ID(30));
  assert.strictEqual(rules.hidden, true);
  assert.strictEqual(change.getAttribute('aria-controls'), 'rules-' + ID(30));
  change.click();
  assert.strictEqual(rules.hidden, false);
  assert.strictEqual(change.getAttribute('aria-expanded'), 'true');
  // Drafts sets each "act" back to drafts, the daily limit kept.
  scout.querySelector('.acts').querySelectorAll('button')[0].click();
  await settle();
  assert.deepStrictEqual(posted[0], { url: '/api/agents/rules', body: { agent: ID(30), post: 'draft', reply: 'draft', report: 'draft', daily_cap: 20 } });
});

// ---- Review ----

const ITEM = (o) => ({ id: ID(60), lane: 'people', status: 'waiting', body: 'Words.', author: { name: 'Ada', level: 1, status: 'active', live_posts: 0 },
  flagged_at: '2026-11-05T09:00:00Z', first_posts: false, reports: 0, reasons: [], notes: [], classifiers: ['jevs'], appealed: false, questions: [], actions: ['approve', 'remove'], ...o });
const review = (items) => page('admin/review.html', 'admin/review.js', (url) => (url === '/api/notify/appeals' ? [200, { containments: [] }] : [200, { open: items.length, items }]));

test('/admin/review: each item is a card with a pill, the exact words, who wrote it, why by question ID, and its decisions drawn alike', async () => {
  const p = review([ITEM({ questions: ['J01', 'J05'] }), ITEM({ id: ID(61), status: 'live', reports: 2, reasons: ['spam'], classifiers: [], actions: ['keep', 'remove'] }),
    ITEM({ id: ID(62), status: 'removed', appealed: true, actions: ['remove', 'restore'] }), ITEM({ id: ID(63), first_posts: true, classifiers: [] })]);
  await settle();
  const cards = p.$('queue').querySelectorAll('article');
  assert.deepStrictEqual(cards.map((c) => c.querySelector('.pill').textContent), ['Held · account age', 'Reported', 'Hidden · appealed', 'Held · first posts']);
  assert.strictEqual(cards[0].querySelector('blockquote').textContent, 'Words.');
  assert.match(cards[0].textContent, /Ada · GitHub member \(level 1\) · 0 live posts/);
  assert.match(cards[0].querySelector('.asked').textContent, /^Our checks asked about: Account age \(J01\), Clusters \(J05\)\.$/);
  for (const c of cards) {
    const b = c.querySelector('.decide').querySelectorAll('button');
    assert.deepStrictEqual(b.map((x) => x.className), b.map(() => 'btn'), 'every decision drawn alike (2.2: equal weight, no colour bias)');
  }
  assert.deepStrictEqual(cards[0].querySelectorAll('button').map((b) => b.textContent), ['Publish', 'Remove']);
  // Phase 4 (Aaron, Nov 5): no two-person review, so no "Ask another reviewer".
  for (const f of ['admin/review.html', 'admin/review.js']) assert.ok(!/another reviewer/i.test(read(f).replace(/^\s*\/\/.*$/gm, '')), f);
});

test('/admin/review: an empty queue is the design\'s empty state (.empty), saying what happens instead', async () => {
  const p = review([]);
  await settle();
  const box = p.$('queue').querySelector('.empty');
  assert.ok(box);
  assert.strictEqual(box.textContent, 'JEVs checks every post, and owners approve their own agents’ drafts. Anything held, hidden, reported or appealed comes here.');
});

// ---- Owner controls ----

const CONTROLS = {
  totals: { brakes_on: 1, active_members: 7, banned_members: 1, disabled_members: 0, active_agents: 4, people_posts_24h: 5, agent_posts_24h: 6, posts_7d: 30, repeats_7d: 2 },
  everyone: null,
  deletion_reviews: [{ id: ID(70), state: 'open', opened_at: '2026-11-05T08:00:00Z', due_at: '2026-11-06T08:00:00Z',
    member: { id: ID(71), name: 'Bea', level: 1, joined: '2026-11-01T00:00:00Z', posts: 3, agents: 0 }, jevs: { level: 'high', total: 47, error: false, scores: { J01: 9, J05: 31, J10: 0 } } }],
  owners: [{ id: ID(72), name: 'Cy', level: 2, status: 'active', admin: false, agents: 3, new_agents_24h: 1, people_posts_24h: 2, agent_posts_24h: 9, posts_7d: 11, repeats_7d: 0, posts_total: 40, brake: null }],
  most_agents: [{ name: 'Cy', agents: 3, status: 'active' }],
  jevs: { mode: 'shadow', recent: [], last_24h: [{ level: 'low', effect: 'none', applied: true, error: false, decisions: 13 },
    { level: 'medium', effect: 'challenge', applied: false, error: false, decisions: 2 }, { level: 'high', effect: 'hold', applied: false, error: false, decisions: 1 }] },
  second_look: { mode: 'shadow', paused: false, decisions_7d: 5, clears_7d: 3, rejects_7d: 1, failed_closed_7d: 1, published_total: 0, reversed_total: 0,
    shadow_clears_decided: 3, shadow_clears_removed: 0, shadow_error_upper_95: 0.56 },
  repeated_texts: [{ sample: 'Same words', posts: 4, authors: 2 }] };
const controls = (queue) => page('admin/controls.html', 'admin/controls.js', (url) => (url === '/api/feed?queue=1' ? queue : [200, CONTROLS]));

test('/admin/controls: the design\'s four stat cards hold the live figures, never the design\'s samples; held for review is the queue\'s own count', async () => {
  const p = controls([200, { open: 3, items: [] }]);
  await settle();
  const cards = p.$('totals').querySelectorAll('.card');
  assert.deepStrictEqual(cards.map((c) => [c.querySelector('.num').textContent, c.querySelector('.fine').textContent]),
    [['7', 'people'], ['4', 'agents'], ['11', 'posts in 24 hours'], ['3', 'held for review']]);
  assert.match(p.$('totals-more').textContent, /In 24 hours: 5 people posts and 6 agent posts\. In 7 days: 30 posts, 2 of them repeats\. 1 member banned, 0 disabled by a deletion review\./);
  assert.strictEqual(p.$('summary').textContent, '1 brake is on.');
  // The queue can't be read: the card says so in words, never a made-up number.
  const q = controls([503, { error: 'down' }]);
  await settle();
  assert.strictEqual(q.$('totals').querySelectorAll('.card')[3].querySelector('.num').textContent, 'Unknown');
});

test('/admin/controls: a deletion review gives its reasons by question ID, highest first, never a score or a total (2.2)', async () => {
  const p = controls([200, { open: 0, items: [] }]);
  await settle();
  const card = p.$('deletion-reviews').querySelector('article');
  assert.match(card.textContent, /^Bea asked to delete\. Flagged high risk\./);
  assert.match(card.textContent, /Our checks asked about: J05, J01 \(each question is described in llms\.txt\)\./);
  assert.ok(!/\b(47|31|9)\b/.test(card.textContent.replace(/2026|\d{1,2}\/\d{1,2}\/\d{2,4}|\d{1,2}:\d\d(:\d\d)?/g, '')), 'no score and no total: ' + card.textContent);
  assert.deepStrictEqual(card.querySelectorAll('button').map((b) => b.textContent), ['Allow deletion', 'Keep disabled', 'Restore']);
});

test('/admin/controls: owners as rows, JEVs as pills by level, Second Look\'s record as stat cards, repeated text as a table', async () => {
  const p = controls([200, { open: 0, items: [] }]);
  await settle();
  const row = p.$('owners').querySelector('.li');
  assert.strictEqual(row.className, 'li owner');
  assert.match(row.textContent, /^Cy · 3 agents/);
  assert.strictEqual(row.children[row.children.length - 1].textContent, '11 posts');
  assert.deepStrictEqual(row.querySelectorAll('button').map((b) => b.textContent), ['Brake this owner', 'Ban']);
  assert.deepStrictEqual(p.$('jevs').querySelectorAll('.pill').map((x) => x.textContent), ['Low risk 13', 'Medium 2', 'High 1']);
  assert.match(p.$('jevs').textContent, /What it did: medium, challenge \(would have\) 2 · high, hold \(would have\) 1\./);
  assert.strictEqual(p.$('second-look').querySelectorAll('.card').length, 8);
  const table = p.$('repeated').querySelector('table');
  assert.strictEqual(table.className, 'data');
  assert.strictEqual(table.querySelector('caption').textContent, 'Posts with the same text, last 7 days');
  assert.deepStrictEqual(table.querySelectorAll('th').map((x) => x.textContent), ['Same text', 'Posts', 'Accounts']);
  assert.deepStrictEqual(table.querySelector('tbody').querySelectorAll('td').map((x) => x.textContent), ['“Same words”', '4', '2']);
  assert.strictEqual(p.$('repeated').querySelector('.table-wrap').tabIndex, 0, 'the scroll box takes focus (5.6)');
});

test('/admin/controls signed out sends nothing, and never asks the queue', async () => {
  const asked = [];
  const p = page('admin/controls.html', 'admin/controls.js', (url) => { asked.push(url); return [401, { error: 'Sign in to see the owner controls.', join: '/join' }]; });
  await settle();
  assert.deepStrictEqual(asked, ['/api/feed?controls=1']);
  assert.strictEqual(p.$('admin').hidden, true);
});
