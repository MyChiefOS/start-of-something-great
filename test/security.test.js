// Security checks from the Oct 14 red and blue team review (R1, R2, R3 and gap G1). Plain, repeatable, no network.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { fresh, call } = require('./helpers');
const root = path.join(__dirname, '..');
// Every HTML page the site serves, including pages in research/.
const htmlPages = () => fs.readdirSync(root).filter((x) => x.endsWith('.html'))
  .concat(fs.readdirSync(path.join(root, 'research')).filter((x) => x.endsWith('.html')).map((x) => 'research/' + x));
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;

function countingGitHub(fail) {
  const calls = [];
  global.fetch = async (url) => {
    calls.push(String(url));
    await new Promise((r) => setTimeout(r, 5));
    if (fail.now) return { status: 503, ok: false, headers: { get: () => null }, json: async () => ({}) };
    const u = String(url);
    const body = u.includes('/discussions/1/comments') ? [{ user: { login: 'x' }, created_at: 't', body: 'mail jane.doe@example.com or (202) 555-0143', html_url: 'h' }]
      : u.includes('/discussions/1') ? { title: 'Hi', html_url: 'h', user: { login: 'a' }, body: 'b', comments: 1 }
      : u.includes('/commits') ? Array.from({ length: 30 }, (_, i) => ({ commit: { message: 'c' + i, author: { name: 'n', date: 'd' } }, html_url: 'u' }))
      : [];
    return { status: 200, ok: true, headers: { get: () => '5000' }, json: async () => body };
  };
  return calls;
}

test('R1: 100 concurrent MCP calls and cache-busting REST calls cost one GitHub call per source', async () => {
  const calls = countingGitHub({});
  const mcp = fresh('mcp.js');
  const changes = require(path.join(root, 'api', 'changes.js'));
  const tool = (name, args) => call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
  const batch = Array.from({ length: 20 }, (_, i) => ({ jsonrpc: '2.0', id: i, method: 'tools/call', params: { name: 'list_proposals', arguments: {} } }));
  await Promise.all([
    ...Array.from({ length: 25 }, (_, i) => tool('get_recent_changes', { limit: (i % 30) + 1 })),
    ...Array.from({ length: 25 }, (_, i) => tool('get_conversation', { limit: (i % 50) + 1 })),
    ...Array.from({ length: 25 }, () => tool('list_shipped', {})),
    ...Array.from({ length: 25 }, (_, i) => call(changes, 'GET', '/api/changes?limit=' + ((i % 9) + 1) + '&_=' + i)),
    call(mcp, 'POST', '/api/mcp', batch)
  ]);
  assert.strictEqual(calls.length, 4, 'expected 4 GitHub calls (commits, issues, discussion, comments), got ' + calls.length + ':\n' + calls.join('\n'));
  const r = await tool('get_recent_changes', { limit: 3 });
  assert.strictEqual(r.json.result.structuredContent.changes.length, 3, 'limit still honoured after normalising');
});

test('R1: if GitHub fails, the last good answer is served instead of an error', async () => {
  const fail = { now: false };
  countingGitHub(fail);
  const lib = fresh('_lib.js');
  await lib.getProposals();
  const realNow = Date.now;
  Date.now = () => realNow() + 120000; // past the TTL
  try {
    fail.now = true;
    const again = await lib.getProposals();
    assert.ok(Array.isArray(again.proposals));
  } finally { Date.now = realNow; }
});

test('G1/P4: the public conversation never exposes email addresses or phone numbers (API and MCP)', async () => {
  countingGitHub({});
  const api = await call(fresh('conversation.js'), 'GET', '/api/conversation');
  assert.ok(!EMAIL.test(api.text) && !/555-0143/.test(api.text), api.text);
  const m = await call(fresh('mcp.js'), 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_conversation', arguments: {} } });
  assert.ok(!EMAIL.test(m.text) && !/555-0143/.test(m.text), m.text);
});

test('R3: look-alike characters and spaced-out numbers cannot slip contact details past masking', () => {
  const { maskContacts, hasContactInfo } = require(path.join(root, 'api', '_proposals.js'));
  const attacks = ['jane＠example.com', 'jane@example．com', 'ja​ne@exa​mple.com', '２０２ 555 0143 99',
    '202 -- 555 -- 0143', '202 / 555 / 0143', '202–555–0143'];
  for (const a of attacks) {
    assert.ok(hasContactInfo(a), 'not detected: ' + JSON.stringify(a));
    const out = maskContacts(a);
    assert.ok(!EMAIL.test(out) && (out.match(/\d/g) || []).length < 7, 'not masked: ' + JSON.stringify(a) + ' -> ' + out);
  }
  for (const ok of ['Released 2026-10-14, 2026-10-15', 'version 1.2.0', 'ship in 3 - 5 days']) assert.strictEqual(maskContacts(ok), ok);
});

test('R3: emoji built with the zero-width joiner survive masking unchanged', () => {
  const { maskContacts } = require(path.join(root, 'api', '_proposals.js'));
  for (const ok of ['Family 👨‍👩‍👧 day', 'Team 🧑‍💻🧑‍🔬', '🏳️‍🌈 welcome']) assert.strictEqual(maskContacts(ok), ok);
  assert.ok(!EMAIL.test(maskContacts('👨‍👩‍👧 ja‍ne@example.com')));
});

test('R2: HTTPS is required on the site and every subdomain', () => {
  const v = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  const hsts = v.headers.find((h) => h.source === '/(.*)').headers.find((h) => h.key === 'Strict-Transport-Security');
  assert.ok(hsts && /max-age=(\d+)/.test(hsts.value) && Number(hsts.value.match(/max-age=(\d+)/)[1]) >= 31536000);
  assert.match(hsts.value, /includeSubDomains/);
});

test('R3: masking stays fast on hostile input after the change (no ReDoS)', () => {
  const { maskContacts } = require(path.join(root, 'api', '_proposals.js'));
  for (const s of ['1 '.repeat(40000), '1-- '.repeat(20000), 'a@'.repeat(30000), '１'.repeat(60000)]) {
    const t = Date.now(); maskContacts(s); assert.ok(Date.now() - t < 500, 'slow: ' + (Date.now() - t) + ' ms');
  }
});

test('R2: every page gets a strict Content-Security-Policy and cannot be framed', () => {
  const v = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  const all = v.headers.find((h) => h.source === '/(.*)').headers;
  const get = (k) => (all.find((h) => h.key.toLowerCase() === k.toLowerCase()) || {}).value || '';
  const csp = v.headers.find((h) => h.source === '/((?!talk/?$|join/?$|account/?$|auth/).*)').headers.find((h) => h.key === 'Content-Security-Policy').value;
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /script-src 'self'(;|$)/);
  assert.ok(!/unsafe-inline|unsafe-eval|\*|data:|http:/.test(csp), 'no unsafe sources: ' + csp);
  assert.strictEqual(get('X-Frame-Options'), 'DENY');
});

test('R2: every page works under that policy (no inline code, styles or outside resources)', () => {
  for (const f of htmlPages()) {
    const html = fs.readFileSync(path.join(root, f), 'utf8');
    for (const tag of html.match(/<script\b[^>]*>/gi) || []) {
      const giscus = f === 'talk.html' && /\bsrc="https:\/\/giscus\.app\/client\.js"/.test(tag); // allowed by the /talk policy only
      assert.ok(giscus || /\bsrc="\/[^/]/.test(tag) || /type="application\/ld\+json"/.test(tag), f + ': inline or outside script ' + tag);
    }
    assert.ok(!/<style\b|\sstyle=|\son[a-z]+=|javascript:/i.test(html), f + ': inline style or handler');
    for (const m of html.matchAll(/<(?:link|img|iframe|source|video|audio)\b[^>]*\b(?:src|href)="([^"]+)"/gi)) {
      const tag = m[0];
      if (/rel="(canonical|alternate)"/.test(tag)) continue; // links, not loaded resources
      assert.ok(m[1].startsWith('/') && !m[1].startsWith('//'), f + ': loads an outside resource ' + m[1]);
    }
  }
  const css = fs.readFileSync(path.join(root, 'styles.css'), 'utf8');
  for (const m of css.matchAll(/url\(\s*["']?([^"')]+)/g)) assert.ok(m[1].startsWith('/'), 'styles.css loads ' + m[1]);
  assert.ok(!/@import/.test(css));
});

test('R2: only /talk may load giscus, only sign-in may post forms, and every path gets exactly one Content-Security-Policy', () => {
  const v = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  const cspRules = v.headers.filter((h) => h.headers.some((x) => x.key === 'Content-Security-Policy'));
  assert.deepStrictEqual(cspRules.map((h) => h.source), ['/((?!talk/?$|join/?$|account/?$|auth/).*)', '/talk', '/join', '/account', '/auth/(.*)']);
  const value = (i) => cspRules[i].headers.find((h) => h.key === 'Content-Security-Policy').value;
  // Sign-in's and the account page's policy is the strict one with one change: forms may post to this site (PR 2, SF4; /account added Oct 16).
  for (const i of [2, 3, 4]) assert.strictEqual(value(i), value(0).replace("form-action 'none'", "form-action 'self'"));
  const talk = cspRules[1].headers.find((h) => h.key === 'Content-Security-Policy').value;
  assert.match(talk, /script-src 'self' https:\/\/giscus\.app;/);
  assert.match(talk, /style-src 'self' https:\/\/giscus\.app;/);
  assert.match(talk, /frame-src https:\/\/giscus\.app/);
  assert.match(talk, /frame-ancestors 'none'/);
  // The same regular expressions Vercel builds from these sources (path-to-regexp 6, checked Oct 15).
  const rules = [/^(?:\/((?!talk\/?$|join\/?$|account\/?$|auth\/).*))[\/#?]?$/i, /^\/talk[\/#?]?$/i, /^\/join[\/#?]?$/i, /^\/account[\/#?]?$/i, /^\/auth(?:\/(.*))[\/#?]?$/i];
  for (const p of ['/', '/talk', '/talk/', '/TALK', '/talks', '/talk/x', '/about', '/api/status', '/fonts/a.woff2', '/research', '/research/decision-loop',
    '/join', '/join/', '/JOIN', '/joins', '/join/x', '/account', '/account/', '/accounts', '/account/x', '/auth/github/start', '/auth/email/continue', '/auth', '/authors']) {
    const n = rules.filter((r) => r.test(p)).length;
    assert.strictEqual(n, 1, p + ' gets ' + n + ' policies');
  }
  for (const f of htmlPages().filter((x) => x !== 'talk.html')) {
    assert.ok(!/giscus\.app\/client/.test(fs.readFileSync(path.join(root, f), 'utf8')), f);
  }
});

test('R2: every page whose forms post without a script is served a policy that lets them post (Oct 16: /account was blocked)', () => {
  const v = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  const cspRules = v.headers.filter((h) => h.headers.some((x) => x.key === 'Content-Security-Policy'));
  const selfSources = cspRules.filter((h) => /form-action 'self'/.test(h.headers.find((x) => x.key === 'Content-Security-Policy').value)).map((h) => h.source);
  for (const f of htmlPages()) {
    const html = fs.readFileSync(path.join(root, f), 'utf8');
    if (!/<form\b[^>]*\baction="\//i.test(html)) continue; // script-handled forms post with fetch, which form-action doesn't govern
    const route = '/' + f.replace(/\.html$/, '').replace(/^index$/, '');
    assert.ok(selfSources.includes(route), f + ' posts forms but ' + route + " isn't served form-action 'self'");
  }
  // Forms a page's own script builds and lets post natively (PR 15: /account's Unlink forms) count the same.
  for (const f of htmlPages()) {
    const js = path.join(root, f.replace(/\.html$/, '.js'));
    if (!fs.existsSync(js) || !/\.action = '\//.test(fs.readFileSync(js, 'utf8'))) continue;
    const route = '/' + f.replace(/\.html$/, '').replace(/^index$/, '');
    assert.ok(selfSources.includes(route), f.replace(/\.html$/, '.js') + ' builds forms that post but ' + route + " isn't served form-action 'self'");
  }
  assert.match(fs.readFileSync(path.join(root, 'account.js'), 'utf8'), /\.action = '\/auth\/account\/unlink'/, 'the Unlink form is one of them');
});

test('R3: every kind of invisible character, odd separator and non-ASCII digit is caught (review, Oct 15)', () => {
  const { maskContacts, hasContactInfo } = require(path.join(root, 'api', '_proposals.js'));
  const attacks = ['jane‎@example.com', 'jane@exa⁣mple.com', 'ja͏ne@example.com', 'jane@example.‭com',
    'jane\u{E0020}@example.com', '202‏555‏0143', '(202) ‍(555) 0143', '20️2 555 0143',
    '202·555·0143', '202•555•0143', '202|555|0143', '202 ------ 555 ------ 0143',
    '٢٠٢ ٥٥٥ ٠١٤٣', '२०२-५५५-०१४३'];
  for (const a of attacks) {
    assert.ok(hasContactInfo(a), 'not detected: ' + JSON.stringify(a));
    const out = maskContacts(a);
    assert.ok(!EMAIL.test(out) && (out.match(/\p{Nd}/gu) || []).length < 7, 'not masked: ' + JSON.stringify(a) + ' -> ' + out);
  }
});

test('R3: text with nothing to hide comes back exactly as written', () => {
  const { maskContacts } = require(path.join(root, 'api', '_proposals.js'));
  for (const ok of ['x² + y²', 'Wait…', '½ done', '①②③', 'Day One Great™', '❤️ love it', '1️⃣ first', 'England 🏴󠁧󠁢󠁥󠁮󠁧󠁿 fans',
    'Due 10/15/2026, then 10/16/2026', 'Due 10/15/2026 10/16/2026', 'mixed عربي text']) {
    assert.strictEqual(maskContacts(ok), ok);
  }
});

test('P4: masking happens before clipping, so a cut never leaves part of an address visible', () => {
  const { shapeIssue } = require(path.join(root, 'api', '_proposals.js'));
  const many = Array.from({ length: 60 }, (_, i) => 'reach.someone.number' + i + '@a-very-long-domain-name.example.com').join(' ');
  const s = shapeIssue({ number: 9, title: 'Proposal: test', state: 'open', labels: [{ name: 'proposal' }], user: { login: 'u' },
    created_at: '2026-10-15T00:00:00Z', updated_at: '2026-10-15T00:00:00Z', html_url: 'h', comments: 0,
    body: '### What should change?\n\n' + many + '\n\n### Why?\n\n' + many });
  for (const v of [s.change, s.why]) assert.ok(!/@|\.example\.com/.test(v), v.slice(-120));
});

test('P4: commit summaries and author names in the changes feed are masked (API and MCP)', async () => {
  global.fetch = async () => ({ status: 200, ok: true, headers: { get: () => '5000' },
    json: async () => [{ commit: { message: 'Fix typo, thanks jane.doe@example.com\n\nmore', author: { name: 'Call 202 555 0143', date: 'd' } }, html_url: 'u' }] });
  const api = await call(fresh('changes.js'), 'GET', '/api/changes');
  const m = await call(fresh('mcp.js'), 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_recent_changes', arguments: {} } });
  for (const r of [api, m]) assert.ok(!EMAIL.test(r.text) && !/555 0143/.test(r.text), r.text);
});

test('R1: if GitHub hangs, the call gives up quickly and serves the last good answer', async () => {
  let hang = false, calls = 0;
  global.fetch = (url, opts) => {
    calls++;
    if (!hang) return Promise.resolve({ status: 200, ok: true, headers: { get: () => '5000' }, json: async () => [] });
    return new Promise((_, reject) => opts.signal.addEventListener('abort', () => reject(new Error('timed out'))));
  };
  const lib = fresh('_lib.js');
  lib._resetCache({ timeoutMs: 50 });
  await lib.getProposals();
  const realNow = Date.now;
  Date.now = () => realNow() + 120000; // past the 60-second cache
  try {
    hang = true;
    const t = realNow();
    const again = await lib.getProposals();
    assert.ok(Array.isArray(again.proposals));
    assert.ok(realNow() - t < 1000, 'took ' + (realNow() - t) + ' ms');
  } finally { Date.now = realNow; }
});

test('R1: while GitHub is failing, it is asked again at most once every 15 seconds', async () => {
  let calls = 0;
  global.fetch = async () => { calls++; return { status: 503, ok: false, headers: { get: () => null }, json: async () => ({}) }; };
  const lib = fresh('_lib.js');
  for (let i = 0; i < 10; i++) await lib.getProposals().catch(() => {});
  assert.strictEqual(calls, 1, 'GitHub was called ' + calls + ' times');
});

test('Checks: runs on main are never cancelled; only older runs of the same pull request are', () => {
  const y = fs.readFileSync(path.join(root, '.github', 'workflows', 'checks.yml'), 'utf8');
  assert.match(y, /group: checks-\$\{\{ github\.event_name == 'pull_request' && github\.ref \|\| github\.run_id \}\}/);
});
