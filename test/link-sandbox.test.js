// 095, the link sandbox (Aaron, Nov 24: the "sandboxed penetration tester", "no cutting corners"; Nov 26: "I should only
// look at high risk cases after several reviews and sandbox testing"). The pure parts run everywhere, with fixtures and
// no network; the database parts need TEST_DATABASE_URL (required in CI):
//   LS1 what the page did is read into W51 (block) and W51b (flag); an honest page gives nothing;
//   LS2 the proxy lets nothing through but HTTPS to the link's own host at a public address (refusals only: no network);
//   LS3 the sandbox for real, where bubblewrap and Chrome are installed, on a stand-in page (no network);
//   LS4 the facts gather keeps only the sandbox's own words; dog-github takes the findings and the "links" mode;
//   LS5 the workflow: the link sandbox holds no token, no write right and no secret, and the asking job runs no code;
//   LS6-LS8 the database: only dog_ghsync lists and records; a block fails the work, a flag holds it for the settle;
//     the hosts it reached are read against the threat lists; each link once.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const links = require('../wall/links');
const workjobs = require('../db/workjobs');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const URL1 = 'https://good.example.org/work';
const codes = (r) => r.flags.map((f) => f.split(' ')[0]);
const clean = { ok: true, requests: [{ url: URL1, type: 'Document', from: null }, { url: 'https://cdn.example.org/a.js', type: 'Script', from: null }],
  responses: [{ url: URL1, status: 200, mime: 'text/html', type: 'Document', disp: '' }], downloads: [], failed: [], forms: { password: 0, card: 0 },
  scripts: ['document.title = "x"; const y = atob("aGk=");'], final: URL1 };

test('LS1 the page\'s behaviour becomes W51 and W51b; an honest page, on the same site, gives no flag', () => {
  assert.deepStrictEqual(links.analyze(clean, [], URL1).flags, [], 'subdomains of one site, an atob without eval: nothing');
  const cases = [
    [{ downloads: [{ url: 'https://good.example.org/setup.exe', name: 'setup.exe' }] }, 'W51 link sandbox: started a download of a program (exe)'],
    [{ responses: [{ url: 'https://good.example.org/x', status: 200, mime: 'application/octet-stream', type: 'Document', disp: 'attachment; filename="tool.msi"' }] }, 'W51 link sandbox: started a download of a program (msi)'],
    [{ responses: [{ url: 'https://good.example.org/x', status: 200, mime: 'application/x-msdownload', type: 'Document', disp: '' }] }, 'W51 link sandbox: started a download of a program (application/x-msdownload)'],
    [{ downloads: [{ url: 'https://good.example.org/a.zip', name: 'a.zip' }] }, 'W51b link sandbox: started a download of an archive (zip)'],
    [{ downloads: [{ url: 'https://good.example.org/r.pdf', name: 'r.pdf' }] }, 'W51b link sandbox: started a download (pdf)'],
    [{ requests: [{ url: 'https://evil.example.net/', type: 'Document', from: URL1 }] }, 'W51b link sandbox: redirected to a different site (evil.example.net)'],
    [{ final: 'https://other.example.com/' }, 'W51b link sandbox: redirected to a different site (other.example.com)'],
    [{ requests: [{ url: 'http://169.254.169.254/latest/meta-data/', type: 'Fetch' }] }, 'W51 link sandbox: tried to reach a cloud-metadata address (169.254.169.254)'],
    [{ requests: [{ url: 'http://metadata.google.internal/', type: 'Fetch' }] }, 'W51 link sandbox: tried to reach a cloud-metadata address (metadata.google.internal)'],
    [{ requests: [{ url: 'https://192.168.1.1/', type: 'Image' }] }, 'W51b link sandbox: tried to reach a private or local address (192.168.1.1)'],
    [{ forms: { password: 1, card: 0 } }, 'W51b link sandbox: has a password form'],
    [{ forms: { password: 0, card: 2 } }, 'W51b link sandbox: has a payment-card form'],
    [{ scripts: ['var m = new CoinHive.Anonymous("k"); m.start();'] }, 'W51 link sandbox: loads a crypto-miner (coinhive)'],
    [{ scripts: ['eval (atob ("YWxlcnQoMSk="))'] }, 'W51b link sandbox: hides code (eval(atob()'],
    [{ scripts: ["eval(function(p,a,c,k,e,d){return p}('x',1,1,'x'.split('|'),0,{}))"] }, 'W51b link sandbox: hides code (eval(function(p,a,c,k,e,)'],
    [{ ok: false, error: 'net::ERR_TUNNEL_CONNECTION_FAILED' }, 'W51b link sandbox: could not be opened (net::ERR_TUNNEL_CONNECTION_FAILED)']
  ];
  for (const [over, want] of cases) {
    const r = links.analyze({ ...clean, ...over }, [], URL1);
    assert.deepStrictEqual(r.flags, [want + ': ' + URL1], want);
  }
  // What the proxy refused: a metadata or private address flags even when the page never logged the request.
  assert.deepStrictEqual(codes(links.analyze(clean, [{ host: '169.254.169.254', port: 443, refused: 'metadata' }, { host: 'db.internal', port: 443, refused: 'private' }], URL1)), ['W51', 'W51b']);
  // Every host and link it reached or tried goes to the database for the threat lists.
  assert.deepStrictEqual(links.analyze(clean, [{ host: 'tracker.example.net', port: 443, refused: 'another host' }], URL1).seen, [URL1, 'https://cdn.example.org/a.js', 'tracker.example.net']);
  // Sites: two-label suffixes, addresses.
  assert.strictEqual(links.siteOf('a.b.example.co.uk'), 'example.co.uk');
  assert.strictEqual(links.siteOf('me.github.io'), 'me.github.io');
  assert.strictEqual(links.siteOf('203.0.113.4'), '203.0.113.4');
  for (const [a, k] of [['10.1.2.3', 'private'], ['172.20.0.1', 'private'], ['127.0.0.1', 'private'], ['100.64.0.1', 'private'], ['::1', 'private'], ['fd12::1', 'private'],
    ['::ffff:10.0.0.1', 'private'], ['169.254.169.254', 'metadata'], ['fd00:ec2::254', 'metadata'], ['203.0.113.4', ''], ['2606:4700::1', ''], ['8.8.8.8', '']]) assert.strictEqual(links.addressKind(a), k, a);
  // At most 10 flags, each at most 240 characters, never twice the same.
  const many = links.analyze({ ...clean, scripts: new Array(30).fill('coinhive eval(atob(') }, [], 'https://good.example.org/' + 'a'.repeat(400));
  assert.ok(many.flags.length === 2 && many.flags.every((f) => f.length <= 240));
});

test('LS2 the proxy: only CONNECT to port 443 of the link\'s own host, at a public address; every refusal recorded', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ls2-'));
  const events = [];
  const resolved = { 'good.example.org': '10.0.0.7', 'pub.example.org': '203.0.113.9' };
  const lookup = (h, o, cb) => (resolved[h] ? cb(null, [{ address: resolved[h], family: 4 }]) : cb(new Error('ENOTFOUND')));
  const sock = path.join(dir, 'p.sock');
  const server = await links.proxy(sock, 'good.example.org', events, { lookup });
  const ask = (line) => new Promise((resolve) => {
    const c = net.connect(sock, () => c.write(line + '\r\nHost: x\r\n\r\n'));
    let o = '';
    c.on('data', (d) => { o += d; });
    c.on('close', () => resolve(o.split('\r\n')[0]));
    c.on('error', () => resolve('error'));
  });
  assert.strictEqual(await ask('GET http://good.example.org/ HTTP/1.1'), 'HTTP/1.1 403 Forbidden', 'plain http: refused');
  assert.strictEqual(await ask('CONNECT good.example.org:80 HTTP/1.1'), 'HTTP/1.1 403 Forbidden', 'another port');
  assert.strictEqual(await ask('CONNECT pub.example.org:443 HTTP/1.1'), 'HTTP/1.1 403 Forbidden', 'another host, even a public one');
  assert.strictEqual(await ask('CONNECT 169.254.169.254:443 HTTP/1.1'), 'HTTP/1.1 403 Forbidden', 'metadata');
  assert.strictEqual(await ask('CONNECT good.example.org:443 HTTP/1.1'), 'HTTP/1.1 403 Forbidden', 'its own host, but the name points inside');
  server.close();
  assert.deepStrictEqual(events.map((e) => e.host + ' ' + e.refused), ['good.example.org not https', 'good.example.org not https', 'pub.example.org another host',
    '169.254.169.254 metadata', 'good.example.org private']);
});

test('LS3 the link sandbox for real, where bubblewrap and Chrome are installed: a stand-in page, no network', { skip: !links.available() && 'bubblewrap or Chrome not installed here' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ls3-'));
  const page = (html) => 'data:text/html,' + encodeURIComponent(html);
  const bad = await links.runOne(dir, URL1, { open: page('<form><input type=password name=p></form><a id=a href="data:application/octet-stream;base64,TVqQAA==" download="setup.exe">x</a>'
    + '<script>var x="Coinhive.Anonymous";a.click();fetch("https://169.254.169.254/latest").catch(()=>0)</script>') });
  for (const c of ['W51 link sandbox: started a download of a program (exe)', 'W51 link sandbox: loads a crypto-miner (coinhive)',
    'W51 link sandbox: tried to reach a cloud-metadata address (169.254.169.254)', 'W51b link sandbox: has a password form']) assert.ok(bad.flags.includes(c + ': ' + URL1), c);
  assert.deepStrictEqual(fs.readdirSync(fs.readdirSync(dir).map((d) => path.join(dir, d))[0]).filter((f) => f !== 'inner.js' && f !== 'proxy.sock'), [], 'the download was denied: nothing saved');
  const away = await links.runOne(dir, URL1, { open: page('<script>location.href="https://evil.example.net/x"</script>') });
  assert.ok(away.flags.includes('W51b link sandbox: redirected to a different site (evil.example.net): ' + URL1));
  assert.ok(away.seen.includes('evil.example.net'), 'the host it tried, for the threat lists');
  assert.deepStrictEqual((await links.runOne(dir, URL1, { open: page('<p>A plain page.</p><script>document.title="ok"</script>') })).flags, []);
  assert.deepStrictEqual(codes(await links.runOne(dir, 'ftp://x.example/')), ['W51b'], 'not a web link');
});

test('LS4 the facts gather keeps only the link sandbox\'s own words; dog-github takes the findings and lists links', async () => {
  const id = '0190f000-0000-7000-8000-000000000095';
  const got = workjobs.linkFindings({ [id]: { flags: ['W51 link sandbox: loads a crypto-miner (coinhive): x', 'W11 forged', 'W47 sandbox: x', 'W51b link sandbox: ' + 'a'.repeat(300)], seen: ['https://a.example/', 'x'.repeat(600)] },
    'not-an-id': { flags: ['W51 link sandbox: x: y'] }, [id.replace('95', '96')]: null });
  assert.deepStrictEqual(got, [{ id, flags: ['W51 link sandbox: loads a crypto-miner (coinhive): x'], seen: ['https://a.example/'] }]);
  assert.deepStrictEqual(workjobs.linkFindings('[]'), []);
  const one = workjobs.requests({ prs: [], issues: [], details: [], refused: 0, files: [], proposals: [], links: got });
  assert.deepStrictEqual(one[0].facts.links, got, 'the findings go with the first request');
  assert.ok(!('links' in workjobs.requests({ prs: [], issues: [], details: [], refused: 0, links: [] })[0].facts), 'none: the field is left out');
  const core = await import('../supabase/functions/dog-github/core.mjs');
  assert.deepStrictEqual(core.parse('{"mode":"links"}'), { mode: 'links' });
  assert.deepStrictEqual(core.parse(JSON.stringify({ mode: 'sync', facts: { links: got } })).links, got);
  assert.throws(() => core.parse(JSON.stringify({ mode: 'sync', facts: { links: new Array(11).fill({}) } })), /at most 10/);
  assert.deepStrictEqual(core.WORKFLOWS[core.WORKFLOW].modes, ['wanted', 'links', 'sync']);
  assert.deepStrictEqual(core.WORKFLOWS[core.WITNESS_WORKFLOW].modes, ['witness'], 'the witness can\'t ask for links');
});

test('LS5 the workflow: the link sandbox holds no token, no write right, no secret; the asking job runs no code', () => {
  const y = read('.github/workflows/github-facts.yml');
  const ask = y.slice(y.indexOf('\n  links:\n'), y.indexOf('\n  link_sandbox:\n'));
  const box = y.slice(y.indexOf('\n  link_sandbox:\n'), y.indexOf('\n  sandbox:\n'));
  assert.match(ask, /\n {4}permissions:\n {6}id-token: write[^\n]*\n {4}timeout-minutes: 5\n/);
  assert.doesNotMatch(ask, /uses:|node |npm|npx|\$\{\{\s*secrets\./, 'it checks nothing out and runs no code');
  assert.match(ask, /--data '\{"mode":"links"\}'/);
  assert.match(ask, /echo "::add-mask::\$t"/);
  assert.match(box, /\n {4}needs: links\n/);
  assert.match(box, /\n {4}permissions:\n {6}contents: read\n {4}timeout-minutes: 10\n/);
  assert.doesNotMatch(box, /id-token|: write|\$\{\{\s*secrets\.|ACTIONS_ID_TOKEN|GH_TOKEN|github\.token/, 'no token of any kind');
  assert.match(box, /WALL_LINKS_WANTED: \$\{\{ needs\.links\.outputs\.links \}\}\n/, 'the list only through the environment, never in the script');
  assert.deepStrictEqual((box.match(/\$\{\{[^}]*\}\}/g) || []), ['${{ steps.run.outputs.findings }}', '${{ needs.links.outputs.links }}'], 'no expression inside a script: only the output and the environment');
  assert.match(box, /node wall\/links\.js/);
  assert.match(y, /WALL_LINKS: \$\{\{ needs\.link_sandbox\.outputs\.findings \}\}\n/);
  for (const m of (ask + box).matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, 'pinned to a commit: ' + m[1]);
  // The sandbox itself: its own network namespace, the proxy its only way out, a fresh profile.
  const src = read('wall/links.js');
  assert.match(src, /'--unshare-all'/);
  assert.doesNotMatch(src, /--share-net/, 'no network inside the sandbox: only the proxy\'s socket');
  assert.match(read('wall/link-inner.js'), /--user-data-dir=\/tmp\/profile/);
  assert.match(read('wall/link-inner.js'), /behavior: 'deny', eventsEnabled: true/);
});

// ---- the database ----
const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('the link sandbox tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the link sandbox tests against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}
const postgres = require('postgres');
const db = require('../db');
const { migrate } = require('../scripts/migrate');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { promote, asSignin } = require('./helpers');
const NAME = 'dog_lsbx_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
let server, su, web, worker, room, project;
const q = (s) => su.unsafe(s);
const gh = (fn) => su.begin(async (t) => { await t`set local role dog_ghsync`; return fn(t); });
async function submit(url, kind = 'link') {
  const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, description, class, size, source, poster_member) values ('${project}', '${room}', 'T', '', 'either', 1, 'member', '${worker}') returning id`);
  const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at, status) values ('${t.id}', '${worker}', '${crypto.randomBytes(32).toString('hex')}', now() - interval '1 minute', 'expired') returning id`);
  const art = kind === 'link' ? `'link', '${url}', null` : `'file', null, '${crypto.randomBytes(32).toString('hex')}'`;
  const [s] = await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, artifact_sha256, note, seal_key, seal, status)
    values ('${t.id}', '${cl.id}', 'member', '${worker}', ${art}, 'Done.', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'waiting') returning id`);
  return s.id;
}
const latest = async (ref) => (await q(`select decision, flags from app.wall_decisions where kind = 'submission' and ref = '${ref}' order by created_at desc, id desc limit 1`))[0];
const record = (p) => gh((t) => t`select app.wall_links_record(${t.json(p)}::jsonb) as n`).then((r) => r[0].n);
test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(NAME, WEB, PW), { ssl: false, max: 2 });
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('gh:lsbx')], keyVersion: 1, level: 1, displayName: 'W', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  worker = out.memberId;
  [{ id: room }] = await q(`select id from app.work_rooms where code = '15-0000'`);
  [{ id: project }] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('P', '${room}', 'member', '${worker}') returning id`);
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) { await server.unsafe(`drop database if exists ${NAME} with (force)`); await server.unsafe(`drop role if exists ${WEB}`); await server.end({ timeout: 5 }); }
});

test('LS6 only dog_ghsync lists links and records findings; the site\'s role and the work module\'s can\'t', async () => {
  const a = await submit('https://lsix.example.org/a');
  const f = await submit('', 'file');
  const list = await gh((t) => t`select id, url from app.wall_links_wanted(5)`);
  assert.ok(list.some((r) => r.id === a && r.url === 'https://lsix.example.org/a'));
  assert.ok(!list.some((r) => r.id === f), 'a file has no link to open');
  await assert.rejects(db.tx(web, { actor: 'anon' }, (t) => t`select * from app.wall_links_wanted(5)`), /permission denied/);
  await assert.rejects(db.tx(web, { actor: 'anon' }, (t) => t`select app.wall_links_record('[]'::jsonb)`), /permission denied/);
  await assert.rejects(su.begin(async (t) => { await t`set local role dog_work`; await t`select app.wall_links_record('[]'::jsonb)`; }), /permission denied|dog_ghsync/);
  await assert.rejects(gh((t) => t`select app.wall_links_record('{}'::jsonb)`), /bad link findings/);
  // The waiting check (for the settle): waiting until the sandbox has run.
  assert.strictEqual((await q(`select app.wall_link_waiting('${a}') as w`))[0].w, true);
  assert.strictEqual(await record([{ id: a, flags: [], seen: ['https://lsix.example.org/a'] }]), 1);
  assert.strictEqual((await q(`select app.wall_link_waiting('${a}') as w`))[0].w, false);
  assert.ok(!(await gh((t) => t`select id from app.wall_links_wanted(5)`)).some((r) => r.id === a), 'opened once');
  assert.deepStrictEqual(await latest(a), { decision: 'allow', flags: [] }, 'a clean run is in the log too');
  assert.strictEqual(await record([{ id: a, flags: ['W51 link sandbox: loads a crypto-miner (coinhive): x'] }]), 0, 'a second report for the same link is ignored');
  assert.strictEqual((await q(`select status from app.work_submissions where id = '${a}'`))[0].status, 'waiting');
});

test('LS7 a W51 refuses the work at once; a W51b holds it for the settle; forged findings are dropped; the chain holds', async () => {
  const b = await submit('https://lseven.example.org/b');
  const g = await submit('https://lseven.example.org/g');
  const z = await submit('https://lseven.example.org/z');
  assert.strictEqual(await record([
    { id: b, flags: ['W51 link sandbox: started a download of a program (exe): https://lseven.example.org/b'] },
    { id: g, flags: ['W51b link sandbox: has a password form: https://lseven.example.org/g'] },
    { id: z, flags: ['W11 a real credential in content'] }]), 2, 'the forged one is dropped');
  assert.strictEqual((await latest(b)).decision, 'block');
  const sb = (await q(`select status, decided_by, reason from app.work_submissions where id = '${b}'`))[0];
  assert.deepStrictEqual([sb.status, sb.decided_by], ['failed', 'wall']);
  assert.match(sb.reason, /^Refused by the Agentic Wall: W51 link sandbox: started a download of a program/);
  assert.deepStrictEqual(await latest(g), { decision: 'hold', flags: ['W51b link sandbox: has a password form: https://lseven.example.org/g'] });
  assert.strictEqual((await q(`select status from app.work_submissions where id = '${g}'`))[0].status, 'waiting', 'a flag never refuses');
  assert.ok((await gh((t) => t`select id from app.wall_links_wanted(5)`)).some((r) => r.id === z), 'the forged report recorded nothing, so it is asked for again');
  // The log stays one unbroken line: every row's prev_hash is the row before it (or the start).
  assert.deepStrictEqual([...await q(`select count(*)::int as n from app.wall_decisions d where d.prev_hash <> repeat('0', 64) and not exists (select 1 from app.wall_decisions x where x.hash = d.prev_hash)`)], [{ n: 0 }]);
});

test('LS8 the hosts the page reached are read against the security wiki\'s threat lists (W28 blocks, W28b flags)', async () => {
  await q(`alter table app.wiki_versions disable row level security; alter table app.wiki_indicators disable row level security;
    update app.wiki_versions set status = 'kept' where status = 'active';
    insert into app.wiki_versions (id, status, entries, packages, sources) values ('0190f000-0000-7000-8000-000000000951', 'active', 1, 0, '{}');
    insert into app.wiki_indicators (version_id, kind, value, source, ref) values ('0190f000-0000-7000-8000-000000000951', 'domain', 'bad-c2.example.net', 'certpl', 'x'),
      ('0190f000-0000-7000-8000-000000000951', 'ip', '198.51.100.77', 'cins', 'y');
    alter table app.wiki_versions enable row level security; alter table app.wiki_indicators enable row level security;`);
  const k = await submit('https://leight.example.org/k');
  const s = await submit('https://leight.example.org/s');
  assert.strictEqual(await record([{ id: k, flags: [], seen: ['https://leight.example.org/k', 'cdn.bad-c2.example.net'] }, { id: s, flags: [], seen: ['198.51.100.77'] }]), 2);
  const dk = await latest(k);
  assert.strictEqual(dk.decision, 'block');
  assert.ok(dk.flags.some((f) => f.startsWith('W28 known-bad domain (security wiki, certpl')), JSON.stringify(dk.flags));
  const ds = await latest(s);
  assert.strictEqual(ds.decision, 'hold');
  assert.ok(ds.flags.some((f) => f.startsWith('W28b ')), JSON.stringify(ds.flags));
});

test('LS9 an appeal\'s recheck keeps the sandbox\'s findings: a refused link isn\'t cleared just by being appealed', async () => {
  const r = await submit('https://lnine.example.org/r');
  assert.strictEqual(await record([{ id: r, flags: ['W51 link sandbox: loads a crypto-miner (coinhive): https://lnine.example.org/r'] }]), 1);
  const [d] = await q(`select id from app.wall_decisions where kind = 'submission' and ref = '${r}' and decision = 'block'`);
  const [x] = await su.begin(async (t) => { await t`set local role dog_work`; return t`select app.wall_recheck_flags(${d.id}) as f`; });
  assert.deepStrictEqual(x.f, ['W51 link sandbox: loads a crypto-miner (coinhive): https://lnine.example.org/r']);
});
