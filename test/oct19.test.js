// Checks for the Oct 19 milestone (ACCEPTANCE.md D1 to D5, C1 to C4).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { fakeIssue, mockGitHub, fresh, call } = require('./helpers');
const rules = require('../scripts/_rules');
const P = require('../api/_proposals');

const ROOT = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const body = (o) => '### What should change?\n\n' + (o.change ?? 'Add a weekly summary of what shipped.') +
  '\n\n### Why?\n\n' + (o.why ?? 'So people can follow along.') +
  '\n\n### Who is filing this?\n\n' + (o.filer ?? 'A person') +
  "\n\n### If you're an agent, who are you acting for?\n\n" + (o.acting_for ?? '_No response_');
const issue = (n, o) => fakeIssue({ number: n, title: 'Proposal: ' + (o.title || 'Weekly summary of shipped changes'), body: body(o), labels: (o.labels || ['proposal']).map((name) => ({ name })), created_at: o.created_at || '2026-10-15T10:00:00Z', state: o.state || 'open' });

test('D1: each automatic label is applied when, and only when, it fits', () => {
  assert.deepStrictEqual(rules.autoLabelsFor(issue(1, {}), []), []);
  assert.deepStrictEqual(rules.autoLabelsFor(issue(2, { filer: 'An AI agent acting for a person', acting_for: '@aaron' }), []), ['from an agent']);
  assert.deepStrictEqual(rules.autoLabelsFor(issue(3, { why: '_No response_' }), []), ['needs info']);
  assert.deepStrictEqual(rules.autoLabelsFor(issue(4, { change: 'Call me at (202) 555-0143' }), []), ['contains contact info']);
  assert.deepStrictEqual(rules.autoLabelsFor(issue(5, { why: 'Email me: someone@example.com' }), []), ['contains contact info']);
  const earlier = issue(6, { title: 'Weekly summary of shipped changes' });
  const later = issue(7, { title: 'A weekly summary of changes shipped' });
  assert.deepStrictEqual(rules.autoLabelsFor(later, [earlier, later]), ['possible duplicate']);
  assert.deepStrictEqual(rules.autoLabelsFor(earlier, [earlier, later]), [], 'only a later proposal is marked as the duplicate');
  assert.deepStrictEqual(rules.autoLabelsFor(issue(8, { title: 'Dark mode for the proposals page' }), [earlier]), []);
});

test('D1: dates, versions and short numbers are not mistaken for phone numbers', () => {
  for (const s of ['Ship by 2026-10-19', 'Release 2 on Nov 20, 2026', 'version 1.2.3', 'issue #1234']) {
    assert.strictEqual(P.hasContactInfo(s), false, s);
  }
  assert.strictEqual(P.hasContactInfo('+1 202 555 0143'), true);
  assert.strictEqual(P.hasContactInfo('2026-10-14 2026-10-19'), false, 'two dates side by side');
  assert.strictEqual(P.maskContacts('202-555-0143 202-555-0199'), '[number hidden]', 'two numbers side by side are both hidden');
  assert.strictEqual(P.maskContacts('Call +1 (202) 555-0143.'), 'Call [number hidden].');
});

test('D1/P4: contact detection stays fast on hostile input (no ReDoS)', () => {
  const hostile = ['a'.repeat(65000), '1-1-1-1-1-1-1-1-1-x'.repeat(3500), 'a.'.repeat(32000), 'a@'.repeat(32000), '1 '.repeat(32000)];
  for (const h of hostile) {
    const t = Date.now();
    P.hasContactInfo(h); P.maskContacts(h);
    P.shapeIssue(fakeIssue({ title: h.slice(0, 300), body: '### What should change?\n\n' + h + '\n\n### Why?\n\n' + h }));
    assert.ok(Date.now() - t < 250, 'took ' + (Date.now() - t) + ' ms on ' + h.slice(0, 12));
  }
});

test('D2: automation only ever adds or removes its own four labels, never a status', () => {
  const approved = issue(9, { why: '_No response_', labels: ['proposal', 'status: approved', 'from an agent', 'possible duplicate'] });
  const c = rules.labelChanges(approved, [approved], () => true);
  assert.deepStrictEqual(c, { add: ['needs info'], remove: ['possible duplicate'] });
  for (const l of c.add.concat(c.remove)) assert.ok(rules.AUTO_LABELS.includes(l));
  assert.ok(!c.remove.includes('from an agent'), '"from an agent" is never removed automatically');
  const byHand = rules.labelChanges(approved, [approved], () => false);
  assert.deepStrictEqual(byHand.remove, [], 'a label a person added is never removed automatically');
  assert.deepStrictEqual(rules.labelChanges(approved, [approved]).remove, [], 'removal needs proof the bot added it');
  const ev = (login, name) => ({ event: 'labeled', label: { name }, actor: { login } });
  assert.strictEqual(rules.addedByBotLast([ev('github-actions[bot]', 'needs info')], 'needs info'), true);
  assert.strictEqual(rules.addedByBotLast([ev('github-actions[bot]', 'needs info'), ev('aaron', 'needs info')], 'needs info'), false, 'Aaron re-added it last');
  assert.strictEqual(rules.addedByBotLast([ev('aaron', 'Needs info'), ev('github-actions[bot]', 'other')], 'needs info'), false);
  assert.strictEqual(rules.addedByBotLast([], 'needs info'), false);
  for (const f of ['scripts/sort.js', 'scripts/queue.js', 'scripts/_github.js', '.github/workflows/sorting.yml']) {
    assert.ok(!/status: (in review|approved|declined|shipped)/.test(read(f)), f + ' must not mention status labels');
  }
});

test('D3: the daily queue runs once a day at 7 a.m. Pacific, in daylight and standard time', () => {
  const wf = read('.github/workflows/sorting.yml');
  assert.ok(wf.includes("cron: '0 14 * * *'") && wf.includes("cron: '0 15 * * *'"));
  assert.strictEqual(rules.queueShouldRun(new Date('2026-10-19T14:00:00Z'), '2026-10-18'), true, '7 a.m. PDT');
  assert.strictEqual(rules.queueShouldRun(new Date('2026-10-19T15:00:00Z'), '2026-10-19'), false, 'already ran today');
  assert.strictEqual(rules.queueShouldRun(new Date('2026-11-09T14:00:00Z'), '2026-11-08'), false, '6 a.m. PST is too early');
  assert.strictEqual(rules.queueShouldRun(new Date('2026-11-09T15:00:00Z'), '2026-11-08'), true, '7 a.m. PST');
  assert.strictEqual(rules.queueShouldRun(new Date('2026-11-09T15:40:00Z'), '2026-11-08'), true, 'a late GitHub run still counts');
  assert.strictEqual(rules.queueShouldRun(new Date('2026-11-09T03:00:00Z'), '2026-11-08', true), true, 'a manual run always works');
  // Clock-change days: daylight time ends Nov 1, 2026 and starts Mar 14, 2027.
  assert.strictEqual(rules.queueShouldRun(new Date('2026-11-01T14:00:00Z'), '2026-10-31'), false, 'Nov 1: 14:00 UTC is 6 a.m.');
  assert.strictEqual(rules.queueShouldRun(new Date('2026-11-01T15:00:00Z'), '2026-10-31'), true, 'Nov 1: 15:00 UTC is 7 a.m.');
  assert.strictEqual(rules.queueShouldRun(new Date('2027-03-14T14:00:00Z'), '2027-03-13'), true, 'Mar 14: 14:00 UTC is 7 a.m.');
  // A manual run keeps the previous date, so it never stops that morning's 7 a.m. run.
  const manualBody = rules.buildQueue([], new Date('2026-10-20T13:00:00Z'), '2026-10-19');
  assert.strictEqual(rules.lastQueueDate(manualBody), '2026-10-19');
  assert.strictEqual(rules.queueShouldRun(new Date('2026-10-20T14:00:00Z'), rules.lastQueueDate(manualBody)), true);
});

test('D4: the queue lists new, waiting (oldest first), flagged and stale proposals, with no private data', () => {
  const now = new Date('2026-10-20T14:00:00Z');
  const list = [
    issue(1, { title: 'Old idea', created_at: '2026-10-05T10:00:00Z' }),
    issue(2, { title: 'Reach me at someone@example.com', created_at: '2026-10-19T20:00:00Z', labels: ['proposal', 'contains contact info'], change: 'secret text +1 202 555 0143' }),
    issue(3, { title: 'Approved thing', created_at: '2026-10-10T10:00:00Z', labels: ['proposal', 'status: approved'] }),
    issue(4, { title: 'Done', state: 'closed', labels: ['proposal', 'status: shipped'] }),
    // Filed and closed within the last day (like test #12 on Oct 14): needs no decision, so not "new".
    issue(6, { title: 'Filed and closed today', state: 'closed', created_at: '2026-10-20T08:00:00Z' })
  ];
  const q = rules.buildQueue(list, now);
  assert.match(q, /<!-- queue-date: 2026-10-20 -->/);
  assert.match(q, /### New since yesterday \(1\)\n\n- \[#2\]/);
  assert.match(q, /### Waiting for a decision, oldest first \(2\)\n\n- \[#1\][^\n]*\n- \[#2\]/);
  assert.match(q, /### Flagged \(1\)\n\n- \[#2\][^\n]*contains contact info/);
  assert.match(q, /### Waiting more than 7 days \(1\)\n\n- \[#1\]/);
  assert.ok(!EMAIL.test(q), 'no email addresses');
  assert.ok(!q.includes('555'), 'no phone numbers');
  assert.ok(!q.includes('secret text'), 'no proposal text');
  assert.ok(!q.includes('member1'), 'no usernames');
  assert.ok(!/@someone|#99\b/.test(rules.buildQueue([issue(5, { title: 'Ping @someone about #99' })], now)), 'titles never @mention people or link issues');
  assert.strictEqual(rules.lastQueueDate(q), '2026-10-20');
});

test('D5: plain rules, no AI: the same input always gives the same output', () => {
  const now = new Date('2026-10-20T14:00:00Z');
  const list = [issue(1, {}), issue(2, { title: 'Weekly summary of shipped changes please' })];
  assert.strictEqual(rules.buildQueue(list, now), rules.buildQueue(JSON.parse(JSON.stringify(list)), now));
  for (const f of ['scripts/_rules.js', 'scripts/sort.js', 'scripts/queue.js', 'scripts/_github.js']) {
    assert.ok(!/anthropic|openai|claude|gpt|llm/i.test(read(f).replace(/^\/\/.*$/gm, '')), f + ' must not call an AI model');
  }
});

test('C1: the home page Now and Next lists match /api/status exactly', () => {
  const { status } = fresh('_lib.js');
  const html = read('index.html');
  const esc = (s) => s.replace(/'/g, "'");
  for (const item of status.phase.live) {
    const href = item.url;
    assert.ok(html.includes('<a href="' + href + '">' + esc(item.text) + '</a>'), 'Now is missing: ' + item.text);
  }
  for (const item of status.phase.next) {
    assert.ok(html.includes('<strong>' + item.text + '</strong> <span>' + item.target + '</span>'), 'Next is missing: ' + item.text);
  }
  const nowCount = (html.match(/<h3>Now<\/h3>[\s\S]*?<\/ul>/)[0].match(/<li>/g) || []).length;
  const nextCount = (html.match(/<h3>Next<\/h3>[\s\S]*?<\/ul>/)[0].match(/<li>/g) || []).length;
  assert.strictEqual(nowCount, status.phase.live.length, 'Now has extra items not in /api/status');
  assert.strictEqual(nextCount, status.phase.next.length, 'Next has extra items not in /api/status');
});

test('C2: /api/shipped lists only shipped proposals, newest first, with credit; read-only and fresh', async () => {
  mockGitHub([
    fakeIssue({ number: 1, state: 'closed', closed_at: '2026-10-16T00:00:00Z', labels: [{ name: 'proposal' }, { name: 'status: shipped' }] }),
    fakeIssue({ number: 2, labels: [{ name: 'proposal' }, { name: 'status: approved' }] }),
    fakeIssue({ number: 3, state: 'closed', closed_at: '2026-10-18T00:00:00Z', labels: [{ name: 'proposal' }, { name: 'status: shipped' }],
      body: "### What should change?\n\nX\n\n### Who is filing this?\n\nAn AI agent acting for a person\n\n### If you're an agent, who are you acting for?\n\n@aaron" })
  ]);
  const r = await call(fresh('shipped.js'), 'GET', '/api/shipped');
  assert.deepStrictEqual(r.json.shipped.map((s) => s.number), [3, 1]);
  assert.strictEqual(r.json.shipped[0].proposed_by.label, "Says it's an AI agent acting for @aaron (not verified)");
  assert.strictEqual(r.json.shipped[1].proposed_by.github_user, 'member1');
  const cc = r.headers['cache-control'];
  assert.ok(Number(/s-maxage=(\d+)/.exec(cc)[1]) + Number(/stale-while-revalidate=(\d+)/.exec(cc)[1]) <= 300);
  assert.strictEqual((await call(fresh('shipped.js'), 'POST', '/api/shipped', {})).status, 405);
});

test('C2: the shipped page only inserts public text as plain text', () => {
  const code = read('shipped.js').replace(/\/\/.*$/gm, '');
  for (const banned of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function']) {
    assert.ok(!code.includes(banned), 'shipped.js must not use ' + banned);
  }
  assert.ok(read('shipped.js').includes("'https://github.com/MyChiefOS/start-of-something-great/issues/'"));
});

test('C3: draft_proposal returns a link for a person to submit, files nothing, and strips contact details', async () => {
  global.fetch = async () => { throw new Error('draft_proposal must not use the network'); };
  const mcp = fresh('mcp.js');
  const list = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const tool = list.json.result.tools.find((t) => t.name === 'draft_proposal');
  assert.ok(tool && tool.annotations.readOnlyHint === true);
  const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'draft_proposal', arguments: {
    title: 'Weekly summary', change: 'Post a weekly summary. Questions: me@example.com', why: 'Call (202) 555-0143 to discuss', acting_for: '@aaron' } } });
  const d = r.json.result.structuredContent;
  assert.strictEqual(r.json.result.isError, false);
  assert.ok(d.file_url.startsWith('https://github.com/MyChiefOS/start-of-something-great/issues/new?template=proposal.yml&'));
  const u = new URL(d.file_url);
  assert.strictEqual(u.searchParams.get('title'), 'Proposal: Weekly summary');
  assert.strictEqual(u.searchParams.get('filer'), 'An AI agent acting for a person');
  assert.strictEqual(u.searchParams.get('acting_for'), '@aaron');
  assert.ok(!EMAIL.test(d.file_url) && !EMAIL.test(decodeURIComponent(d.file_url)), 'no email in the link');
  assert.ok(!decodeURIComponent(d.file_url).includes('555'), 'no phone number in the link');
  assert.strictEqual(d.contact_info_removed, true);
  const missing = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'draft_proposal', arguments: { title: 'x', change: 'y', why: 'z' } } });
  assert.strictEqual(missing.json.result.isError, true);
  assert.match(missing.json.result.content[0].text, /acting_for is required/);
});

test('C4: the uptime monitor confirms a failure before alerting, and reports every check', async () => {
  const uptime = require('../scripts/uptime');
  const hdr = (h) => ({ get: (k) => h[k.toLowerCase()] || null });
  const okFetch = async (url) => (url.endsWith('/auth/github/start')
    ? { status: 302, headers: hdr({ location: '/join?error=unavailable' }), text: async () => '' }
    : {
      status: 200,
      headers: hdr({ 'strict-transport-security': 'max-age=63072000; includeSubDomains; preload', 'content-security-policy': "default-src 'self'" }),
      text: async () => (url.endsWith('/api/status') ? '{"name":"Day One Great","stage":"' + uptime.EXPECTED + '"}' : url.endsWith('/api/proposals') ? '{"proposals":[]}' : url.endsWith('/api/mcp') ? '{"jsonrpc":"2.0","id":1,"result":{}}' : url.endsWith('/api/feed') ? '{"posts":[]}' : url.endsWith('/api/ready') ? '{"timers":{"last_run_s_ago":30},"rules":{"last_run_s_ago":600},"broker":"ok"}' : '<title>Day One Great</title>')
    });
  let waits = 0;
  const all = await uptime.checkAll(okFetch, async () => { waits++; });
  assert.ok(all.every((r) => r.ok) && waits === 0);
  let calls = 0;
  const flaky = async (url, init) => (url.endsWith('/api/status') && calls++ === 0 ? { status: 500, text: async () => 'oops' } : okFetch(url, init));
  const once = await uptime.checkAll(flaky, async () => { waits++; });
  assert.ok(once.every((r) => r.ok), 'a single blip that recovers on retry is not an outage');
  assert.strictEqual(waits, 1);
  const down = async (url, init) => (url.endsWith('/api/mcp') ? { status: 502, text: async () => '' } : okFetch(url, init));
  const res = await uptime.checkAll(down, async () => {});
  assert.deepStrictEqual(res.filter((r) => !r.ok).map((r) => r.name), ['MCP server']);
  assert.match(uptime.report(res, new Date('2026-10-20T00:00:00Z')), /\*\*DOWN\*\* \| MCP server/);
  assert.ok(read('.github/workflows/uptime.yml').includes("cron: '7,22,37,52 * * * *'"), 'runs every 15 minutes');
});

test('launch checks: the go-live gate, sign-in and security headers are watched, and a leak or a server error is caught', async () => {
  const uptime = require('../scripts/uptime');
  const gate = uptime.CHECKS.find((c) => c.name === 'Go-live gate');
  const r = (status, h = {}) => ({ status, headers: { get: (k) => h[k.toLowerCase()] || null } });
  // What the removed preview stage answered signed-out readers (launch.js before R-14).
  const REFUSED = JSON.stringify({ error: 'This part of Day One Great isn\u2019t open yet.' });
  assert.ok(gate.test(r(200), '{"posts":[]}'), 'closed or public');
  assert.ok(!gate.test(r(401, { 'cache-control': 'no-store' }), REFUSED), 'no stage refuses signed-out visitors now');
  assert.ok(!gate.test(r(500), '{}'), 'a server error is a fault');
  assert.ok(gate.test(r(200), '{"posts":[]}', { stage: 'public' }));
  assert.ok(gate.test(r(200), '{"posts":[]}', { stage: 'closed' }));
  // D1: the live stage is a real one and, when the last setup run recorded one, that one. The check runs before the
  // gate check and tells it the stage.
  const stage = uptime.CHECKS.find((c) => c.name === 'Go-live stage');
  assert.ok(uptime.CHECKS.indexOf(stage) < uptime.CHECKS.indexOf(gate), 'the stage is learned before the gate is judged');
  const ctx = {};
  assert.strictEqual(stage.test(r(200), '{"name":"Day One Great","stage":"public"}', ctx), uptime.EXPECTED === 'public');
  assert.strictEqual(ctx.stage, 'public');
  // Since the go-live release the expected stage is the repository's own (launch.json), so a live stage that differs
  // (LAUNCH_STAGE closing it in Vercel, a rollback, a deploy that didn't happen) is reported. It only alerts.
  assert.strictEqual(uptime.EXPECTED, require('../launch').repoStage());
  assert.strictEqual(stage.test(r(200), '{"stage":"' + uptime.EXPECTED + '"}', {}), true);
  assert.strictEqual(stage.test(r(200), '{"stage":"' + (uptime.EXPECTED === 'public' ? 'closed' : 'public') + '"}', {}), false, 'a stage the repository doesn\'t say is a fault');
  assert.ok(!stage.test(r(200), '{"name":"Day One Great","stage":"preview"}', {}), 'preview is no longer a stage: a fault');
  assert.ok(!stage.test(r(200), '{"name":"Day One Great","stage":"open"}', {}), 'an unknown stage is a fault');
  assert.ok(!stage.test(r(200), '{"name":"Day One Great"}', {}), 'no stage at all is a fault');
  assert.ok(!stage.test(r(500), '{}', {}));
  const src = read('scripts/uptime.js');
  assert.match(src, /live === EXPECTED/, 'compares with the repository\'s stage');
  assert.match(src, /const EXPECTED = require\('\.\.\/launch'\)\.repoStage\(\);/);
  assert.doesNotMatch(read('.github/workflows/uptime.yml'), /EXPECTED_STAGE/, 'the repository variable is no longer read');
  const signin = uptime.CHECKS.find((c) => c.name === 'Sign-in start');
  assert.strictEqual(signin.init.redirect, 'manual');
  assert.ok(signin.test(r(302, { location: 'https://github.com/login/oauth/authorize?client_id=x' })));
  assert.ok(signin.test(r(302, { location: '/join?error=unavailable' })));
  assert.ok(!signin.test(r(302, { location: 'https://evil.example/login/oauth/authorize?' })), 'only GitHub or our own page');
  assert.ok(!signin.test(r(500), 'Something went wrong. Please try again.'));
  assert.ok(signin.test(r(503), 'Sign-in is not switched on here yet.'), 'closed: the designed answer');
  assert.ok(!signin.test(r(503), 'Service Unavailable'), 'any other 503 is a fault');
  const heads = uptime.CHECKS.find((c) => c.name === 'Security headers');
  assert.ok(!heads.test(r(200, { 'content-security-policy': "default-src 'self'" })), 'missing HSTS is a fault');
  const y = read('.github/workflows/uptime.yml');
  assert.match(y, /deployment_status:/, 'also runs after every deploy');
  assert.match(y, /github\.event\.deployment_status\.state == 'success'/);
});

test('C4: an outage opens one issue, comments only when it changes, and recovery closes it', () => {
  const { decide } = require('../scripts/uptime');
  const ok = [{ name: 'Home page', ok: true }, { name: 'MCP server', ok: true }];
  const mcpDown = [{ name: 'Home page', ok: true }, { name: 'MCP server', ok: false }];
  const bothDown = [{ name: 'Home page', ok: false }, { name: 'MCP server', ok: false }];
  assert.strictEqual(decide(ok, undefined).action, 'none');
  assert.strictEqual(decide(mcpDown, undefined).action, 'open');
  const open = { number: 7, body: '<!-- failing: MCP server -->\nProblem' };
  assert.strictEqual(decide(mcpDown, open).action, 'none', 'same outage: no new notification');
  assert.strictEqual(decide(bothDown, open).action, 'update', 'outage changed: one update');
  assert.strictEqual(decide(ok, open).action, 'close');
});

test('L3: every image, font and media file is recorded with its source and license', () => {
  const register = read('CONTENT-LICENSE.md');
  const media = require('child_process').execSync('git ls-files', { cwd: ROOT }).toString().split('\n')
    .filter((f) => /\.(jpe?g|png|gif|webp|svg|ico|woff2?|ttf|otf|mp4|mov|mp3|wav|pdf)$/i.test(f));
  assert.ok(media.length > 0);
  for (const f of media) assert.ok(register.includes('| `' + f + '` |'), f + ' is not in the media register in CONTENT-LICENSE.md');
  assert.match(read('fonts/OFL-source-serif-4.txt'), /^Copyright 2014 - 2023 Adobe/, 'font license keeps its copyright notice');
  assert.match(read('fonts/OFL-bricolage-grotesque.txt'), /^Copyright 2022 The Bricolage Grotesque Project Authors/);
  assert.match(register, /## Rules for what we publish/);
});
