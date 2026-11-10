// RK140 (migration 055): GitHub's facts come only from GitHub. The "GitHub facts" workflow reads this repository's pull
// requests and issues from GitHub's API inside GitHub and sends them to the dog-github function, which accepts only that
// workflow on main (GitHub's identity token, the shared check of dog-migrate and the JEVs gate) and records them as
// dog_ghsync. The site's role can no longer record them, and a pull request passes by rule only when GitHub's own read
// says Aaron's account merged it. These tests check:
//   - dog-github's token check: wrong issuer, audience, repository, branch, workflow or event, and a replay, refused;
//   - dog-github's answers: POST only, a refused token before the body is read or the database opened, the body's shape;
//   - the workflow: GitHub's events, main only, nothing from the event in a command, pinned actions, its alert;
//   - the site's timer no longer reads GitHub's pull requests for the work module or calls the sync;
//   - the read inside GitHub: who merged a pull request, by GitHub ID;
//   - with a database: only dog_ghsync records the facts (the site's role can't, nor switch to it); a pass by rule needs
//     Aaron's merge, anything else goes to a person, Third Look takes only Aaron's merges, and rows from before 055 wait
//     for GitHub's read.
// The database tests need TEST_DATABASE_URL (skipped without it, required in CI), like the other database tests.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const SERVER = process.env.TEST_DATABASE_URL;
const AARON_ID = 304218593; // MyChiefOS, by GitHub ID (028, 029; the shared check's OWNER_ID)
const REPO = 'MyChiefOS/start-of-something-great';
const { subtle } = globalThis.crypto;
const enc = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');

// Tokens signed by a test key, checked by the real shared check with that key (as test/oidc.test.js does).
async function setup() {
  const oidc = await import('../supabase/functions/_shared/github-oidc.mjs');
  const core = await import('../supabase/functions/dog-github/core.mjs');
  const gen = () => subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const pair = await gen();
  const other = await gen();
  const jwk = { ...(await subtle.exportKey('jwk', pair.publicKey)), kid: 'k1' };
  const keys = async () => [jwk];
  const now = 1_800_000_000;
  const good = {
    iss: oidc.ISSUER, aud: 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-github',
    exp: now + 300, iat: now - 5, nbf: now - 5,
    repository_id: '1418125608', repository_owner_id: '304218593', repository: REPO,
    ref: 'refs/heads/main', event_name: 'schedule', sha: 'a'.repeat(40), jti: 'gh-token-' + crypto.randomUUID(), run_id: '1', actor: 'MyChiefOS',
    workflow_ref: REPO + '/.github/workflows/github-facts.yml@refs/heads/main'
  };
  async function sign(claims, { key = pair.privateKey, header = { alg: 'RS256', kid: 'k1', typ: 'JWT' } } = {}) {
    const body = enc(header) + '.' + enc(claims);
    const sig = await subtle.sign('RSASSA-PKCS1-v1_5', key, Buffer.from(body));
    return body + '.' + Buffer.from(sig).toString('base64url');
  }
  const deps = (extra = {}) => ({ verify: oidc.verify, Refused: oidc.Refused, keys, now, seen: async () => false, ...extra });
  return { oidc, core, sign, good, other, deps, now };
}

test('RK140: dog-github accepts only the GitHub facts workflow, on main of this repository, for its own events, each token once', async () => {
  const { oidc, core, sign, good, other, deps } = await setup();
  assert.strictEqual(core.AUDIENCE, good.aud, 'the audience is the function\'s own address');
  for (const ev of ['pull_request_target', 'issues', 'schedule', 'workflow_dispatch']) {
    const claims = await core.checkToken(await sign({ ...good, event_name: ev }), deps());
    assert.strictEqual(claims.event_name, ev);
  }
  const wf = (ref) => REPO + '/.github/workflows/github-facts.yml@' + ref;
  const cases = [
    ['another issuer', { iss: 'https://evil.example' }, /issuer/],
    ['another audience (the runner\'s)', { aud: 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-migrate' }, /audience/],
    ['another repository (a fork)', { repository_id: '999', repository: 'someone/start-of-something-great', workflow_ref: 'someone/start-of-something-great/.github/workflows/github-facts.yml@refs/heads/main' }, /repository/],
    ['another repository owner', { repository_owner_id: '1' }, /owner/],
    ['this repository\'s numbers under another name', { repository: 'MyChiefOS/another' }, /repository name/],
    ['another branch', { ref: 'refs/heads/feature', workflow_ref: wf('refs/heads/feature') }, /main branch/],
    ['a pull_request run (the pull request\'s own ref and copy of the workflow)', { ref: 'refs/pull/7/merge', event_name: 'pull_request', workflow_ref: wf('refs/pull/7/merge') }, /main branch/],
    ['another workflow on main', { workflow_ref: REPO + '/.github/workflows/database.yml@refs/heads/main' }, /workflow/],
    ['this workflow from another branch', { workflow_ref: wf('refs/heads/feature') }, /workflow/],
    ['another event (push)', { event_name: 'push' }, /event/],
    ['another event (pull_request, on main)', { event_name: 'pull_request' }, /event/],
    ['expired', { exp: good.exp - 3600 }, /expired/]
  ];
  for (const [name, over, why] of cases) {
    await assert.rejects(core.checkToken(await sign({ ...good, ...over }), deps()), (e) => e instanceof oidc.Refused && why.test(e.message), name);
  }
  await assert.rejects(core.checkToken(await sign(good, { key: other.privateKey }), deps()), /signature/, 'signed by another key');
  await assert.rejects(core.checkToken(await sign(good), deps({ seen: async () => true })), /already used/, 'replayed');
});

test('RK140: dog-github answers POST only, refuses a bad token before reading the body or opening the database, and checks the body\'s shape', async () => {
  const { core, sign, good, deps } = await setup();
  const noDb = () => { throw new Error('the database was opened'); };
  const call = async (req, extra) => core.handle({ method: 'POST', contentLength: null, text: async () => '{"mode":"wanted"}', ...req }, deps({ db: noDb, ...extra }));
  assert.deepStrictEqual(await call({ method: 'GET' }), { status: 405, body: { ok: false, error: 'POST only' } });
  assert.strictEqual((await call({ contentLength: String(core.MAX_REQUEST + 1) })).status, 413);
  let bodyRead = false;
  const refused = await call({ authorization: 'Bearer ' + (await sign({ ...good, event_name: 'push' })), text: async () => { bodyRead = true; return '{}'; } });
  assert.deepStrictEqual([refused.status, refused.body.error], [401, 'refused: wrong event']);
  assert.strictEqual(bodyRead, false, 'the body of a refused request is never read');
  assert.strictEqual((await call({ authorization: '' })).status, 401);
  const bad = async (text) => (await call({ authorization: 'Bearer ' + (await sign({ ...good, jti: crypto.randomUUID() })), text: async () => text }));
  for (const [text, why] of [['not json', /JSON/], ['[]', /object/], ['{"mode":"apply"}', /mode/], ['{"mode":"sync"}', /facts/],
    [JSON.stringify({ mode: 'sync', facts: { prs: new Array(101).fill({}) } }), /at most 100/], [JSON.stringify({ mode: 'sync', facts: { prs: [1] } }), /objects/],
    [JSON.stringify({ mode: 'sync', facts: { sql: 'x' } }), /unknown field/], [JSON.stringify({ mode: 'sync', facts: { refused: -1 } }), /count/]]) {
    const r = await bad(text);
    assert.strictEqual(r.status, 400, text);
    assert.match(r.body.error, why, text);
  }
  assert.strictEqual((await bad('x'.repeat(core.MAX_REQUEST + 1))).status, 413);
  assert.deepStrictEqual(core.parse('{"mode":"sync","facts":{"prs":[{"number":1}]}}'), { mode: 'sync', facts: { prs: [{ number: 1 }], issues: [], details: [], refused: 0 },
    files: [], proposals: [] });
});

test('RK140: the deployed function is dog-github\'s core behind the shared check, with Supabase\'s own JWT check off', () => {
  const ix = read('supabase/functions/dog-github/index.ts');
  assert.match(ix, /^import \{ Refused, verify \} from "\.\.\/_shared\/github-oidc\.mjs";$/m, 'the shared check, not a new one');
  assert.match(ix, /^import \{ tokenUsed \} from "\.\.\/dog-migrate\/core\.mjs";$/m, 'each token once, as the runner and the gate record it');
  assert.match(ix, /^import \{ handle \} from "\.\/core\.mjs";$/m);
  assert.match(ix, /Deno\.env\.get\("SUPABASE_DB_URL"\)/, 'the login Supabase gives every function; no password of its own');
  assert.doesNotMatch(ix, /console\.|vault|password/i, 'it logs nothing and reads no secret');
  assert.match(read('supabase/config.toml'), /\[functions\.dog-github\]\nverify_jwt = false/);
  const core = read('supabase/functions/dog-github/core.mjs');
  assert.strictEqual((core.match(/set local role dog_ghsync/g) || []).length, 2, 'both database calls act as dog_ghsync');
});

test('RK140: the GitHub facts workflow reads GitHub inside GitHub on GitHub\'s own events, on main, and nothing from the event reaches a command', async () => {
  const core = await import('../supabase/functions/dog-github/core.mjs');
  const y = read('.github/workflows/github-facts.yml');
  const on = y.split(/^permissions:/m)[0].split(/^on:$/m)[1];
  const events = [...on.matchAll(/^ {2}([a-z_]+):/gm)].map((m) => m[1]);
  assert.deepStrictEqual(events.sort(), [...core.EVENTS].sort(), 'its events are exactly the ones dog-github accepts');
  assert.match(on, /pull_request_target:\n {4}types: \[closed\]/);
  assert.match(on, /schedule:\n {4}- cron: '\d+ \* \* \* \*'/, 'hourly, as the backstop');
  // Each job only the rights it needs (review F7): none for the workflow; the reading job can't write to GitHub; only the
  // alert job, which reads no event text, may comment.
  assert.match(y, /^permissions: \{\}$/m);
  assert.match(y, /^ {2}facts:\n[\s\S]*?\n {4}permissions:\n {6}contents: read\n {6}pull-requests: read\n {6}issues: read\n {6}id-token: write[^\n]*\n/m);
  assert.match(y, /^ {2}alert:\n {4}needs: facts\n {4}if: failure\(\) && github\.repository_id == 1418125608 && github\.ref == 'refs\/heads\/main'\n[\s\S]*?\n {4}permissions:\n {6}issues: write[^\n]*\n {4}steps:/m);
  assert.strictEqual((y.match(/issues: write/g) || []).length, 1, 'write rights in one place only');
  assert.match(y, /if: github\.repository_id == 1418125608 && github\.ref == 'refs\/heads\/main'/);
  assert.doesNotMatch(y, /\$\{\{\s*(github\.event|github\.head_ref|inputs\.)/, 'no text from the event anywhere');
  assert.doesNotMatch(y, /^\s+ref:/m, 'it checks out main\'s own code, never a pull request\'s');
  assert.match(y, /persist-credentials: false/);
  for (const m of y.matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, 'pinned to a commit: ' + m[1]);
  assert.match(y, new RegExp('FN_URL: ' + core.AUDIENCE.replace(/[.]/g, '\\.') + '\n'));
  assert.match(y, /audience=\$FN_URL/, 'the token is for dog-github alone');
  assert.match(y, /echo "::add-mask::\$t"/);
  assert.match(y, /node db\/workjobs\.js gather wanted\.json requests/);
  assert.doesNotMatch(y, /\$\{\{\s*secrets\.|npm (ci|install)/, 'no secret, no packages installed');
  assert.match(y, /if: failure\(\)[\s\S]*labels=jevs-alert/, 'a failed run alerts on the JEVs alerts issue');
});

test('RK140: the site\'s timer no longer reads GitHub\'s pull requests for the work module, nor calls the sync', async () => {
  const workjobs = require('../db/workjobs');
  const asked = [];
  const sql = [];
  const tag = (strings) => { sql.push(strings.join('?')); return Promise.resolve([{ r: { reopened: 0 }, number: 1 }]); };
  const runDb = async (ctx, fn) => fn(tag);
  const gh = async (p) => { asked.push(p); return []; };
  const out = await workjobs.run(runDb, { gh });
  assert.deepStrictEqual(asked, [], 'GitHub is never read');
  assert.deepStrictEqual(sql, ['select app.work_tick() as r'], 'only the work timer');
  assert.deepStrictEqual(Object.keys(out), ['tick']);
  const cron = read('api/cron.js');
  assert.match(cron, /require\('\.\.\/db\/workjobs'\)\.run\(run\);/, 'the timer passes it no GitHub reader');
  assert.doesNotMatch(read('db/workjobs.js'), /work_github_sync\(|work_github_wanted\(\$/, 'no call to the sync from the site\'s code');
});

test('RK140: the read inside GitHub gives each merge with who merged it, by GitHub ID, and splits the requests at 100 pull requests', async () => {
  const workjobs = require('../db/workjobs');
  const pr = (n, over = {}) => ({ number: n, user: { login: 'Octo', id: 7 }, state: 'closed', merged_at: '2026-11-01T00:00:00Z', base: { ref: 'main' },
    merge_commit_sha: 'c'.repeat(40), title: 'PR ' + n, body: '', created_at: '2026-10-30T00:00:00Z', labels: [], ...over });
  const asked = [];
  const get = async (p) => {
    asked.push(p);
    if (p.startsWith('/pulls?') && p.endsWith('page=1')) return Array.from({ length: 100 }, (_, i) => pr(i + 1));
    if (p.startsWith('/pulls?')) return Array.from({ length: 50 }, (_, i) => pr(i + 101));
    if (p.startsWith('/issues?labels=proposal')) return []; // 057: the proposals' labels (test/holes.test.js)
    if (p.startsWith('/issues?')) throw Object.assign(new Error('limited'), { githubStatus: 403 });
    if (p === '/pulls/5') return { ...pr(5), additions: 3, deletions: 1, merged_by: { login: 'MyChiefOS', id: AARON_ID } };
    if (p === '/pulls/6') return { ...pr(6), additions: 3, deletions: 1, merged_by: { login: 'mychiefos', id: 12345 } };
    if (p === '/pulls/7') return { ...pr(7, { merged_at: null, state: 'open' }), additions: 1, deletions: 0, merged_by: null };
    throw Object.assign(new Error('missing'), { githubStatus: 404 });
  };
  const facts = await workjobs.gather({ get, wanted: [5, 6, 7, 8, 'x', -1] });
  assert.deepStrictEqual(asked.filter((p) => p.startsWith('/pulls/')), ['/pulls/5', '/pulls/6', '/pulls/7', '/pulls/8'], 'only the numbers asked for');
  assert.strictEqual(facts.refused, 1, 'a refused read is counted, and changes nothing else');
  assert.deepStrictEqual(facts.details, [
    { number: 5, additions: 3, deletions: 1, state: 'closed', merged_at: '2026-11-01T00:00:00.000Z', base: 'main', merge_sha: 'c'.repeat(40), merged_by: 'mychiefos', merged_by_id: AARON_ID },
    { number: 6, additions: 3, deletions: 1, state: 'closed', merged_at: '2026-11-01T00:00:00.000Z', base: 'main', merge_sha: 'c'.repeat(40), merged_by: 'mychiefos', merged_by_id: 12345 },
    { number: 7, additions: 1, deletions: 0, state: 'open', merged_at: null, base: 'main', merge_sha: null, merged_by: null, merged_by_id: null }]);
  const reqs = workjobs.requests(facts);
  assert.deepStrictEqual(reqs.map((r) => [r.mode, r.facts.prs.length, r.facts.details.length, r.facts.refused]), [['sync', 100, 3, 1], ['sync', 50, 0, 0]]);
  assert.deepStrictEqual(workjobs.requests({ prs: [], issues: [], details: [], refused: 0 }).length, 1, 'one request even with nothing new');
});

// ---- With a database ----

if (!SERVER) {
  if (process.env.CI) test('the GitHub facts database tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the GitHub facts tests against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const { migrate } = require('../scripts/migrate');
const NAME = 'dog_ghfacts_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const q = (s) => su.unsafe(s);
const as = (role, fn) => su.begin(async (t) => { await t.unsafe('set local role ' + role); return fn(t); });
const pr = (n, over = {}) => ({ number: n, title: 'PR ' + n, author: 'octo', state: 'closed', merged_at: '2026-11-01T10:00:00Z', base: 'main', merge_sha: 'b'.repeat(40),
  refs: '', milestone: null, milestone_title: null, room: null, created_at: '2026-10-31T10:00:00Z', codes: [], ...over });
const det = (n, over = {}) => ({ number: n, additions: 10, deletions: 0, state: 'closed', merged_at: '2026-11-01T10:00:00Z', base: 'main', merge_sha: 'b'.repeat(40),
  merged_by: 'mychiefos', merged_by_id: AARON_ID, ...over });

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  // A login made like the site's own (dog_web, 022): it may switch to dog_app and nothing else.
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = postgres(at(NAME, WEB, PW), { max: 1, ssl: false, onnotice: () => {} });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

test('RK140: only dog_ghsync records GitHub\'s facts: the site\'s role can\'t call the sync or switch to that role, and the module\'s own role is refused by the function itself', async () => {
  const core = await import('../supabase/functions/dog-github/core.mjs');
  const asSite = (fn) => web.begin(async (t) => { await t`set local role dog_app`; return fn(t); });
  await assert.rejects(asSite((t) => t`select app.work_github_sync(${t.json({ prs: [pr(9401)] })}::jsonb)`), /permission denied for function work_github_sync/);
  await assert.rejects(asSite((t) => t`select * from app.work_github_wanted(5)`), /permission denied for function work_github_wanted/);
  await assert.rejects(web.begin((t) => t`set local role dog_ghsync`), /permission denied to set role "dog_ghsync"/, 'the site\'s login can never act as it');
  // The work module's own role owns the function, so it could call it; the function itself refuses anyone but dog_ghsync.
  await assert.rejects(as('dog_work', (t) => t`select app.work_github_sync(${t.json({})}::jsonb)`), /only the GitHub facts function records GitHub's facts/);
  await assert.rejects(as('dog_work', (t) => t`select * from app.work_github_wanted(5)`), /only the GitHub facts function reads this/);
  assert.strictEqual((await q('select count(*)::int as n from app.work_github_prs where number = 9401'))[0].n, 0, 'nothing was recorded');
  // dog-github's own path (core.mjs, as the deployed function runs it) records them.
  assert.deepStrictEqual(await core.sync(su, { prs: [pr(9401, { merged_at: null, state: 'open' })], issues: [], details: [], refused: 0 }),
    { prs: 1, tasks: 0, closed: 0, files: 0, proposals: 0 });
  assert.deepStrictEqual(await core.wanted(su), { wanted: [], files: [] });
  // And end to end, with a token: wanted, then the same token again (refused).
  const { sign, good, deps } = await setup();
  const { tokenUsed } = await import('../supabase/functions/dog-migrate/core.mjs');
  const token = 'Bearer ' + (await sign(good));
  const ask = () => core.handle({ method: 'POST', authorization: token, text: async () => '{"mode":"wanted"}' }, deps({ db: () => su, seen: (j) => tokenUsed(su, j) }));
  assert.deepStrictEqual(await ask(), { status: 200, body: { ok: true, wanted: [], files: [] } });
  assert.deepStrictEqual(await ask(), { status: 401, body: { ok: false, error: 'refused: token already used' } });
  // The database's own check of the facts answers 400, not 500.
  const bad = await core.handle({ method: 'POST', authorization: 'Bearer ' + (await sign({ ...good, jti: crypto.randomUUID() })),
    text: async () => JSON.stringify({ mode: 'sync', facts: { prs: [pr(9402, { merged_at: 'not a time' })] } }) }, deps({ db: () => su }));
  assert.strictEqual(bad.status, 400, JSON.stringify(bad.body));
});

test('RK140: a merged pull request passes by rule only when GitHub\'s read says Aaron\'s account merged it; anything else goes to a person, and Third Look leaves it alone', async () => {
  const core = await import('../supabase/functions/dog-github/core.mjs');
  const sync = ({ files = [], proposals = [], ...f }) => core.sync(su, { prs: [], issues: [], details: [], refused: 0, ...f }, { files, proposals });
  await sync({ prs: [pr(9501), pr(9502), pr(9503)] });
  // Listed as merged, but GitHub's read of each isn't in yet: no task, nothing passes; dog-github is asked to read them.
  assert.strictEqual((await q('select count(*)::int as n from app.work_tasks where github_kind = \'pr\' and github_number in (9501, 9502, 9503)'))[0].n, 0);
  assert.deepStrictEqual((await core.wanted(su)).wanted.filter((n) => n >= 9501 && n <= 9503), [9501, 9502, 9503]);
  await sync({ details: [det(9501), det(9502, { merged_by: 'octo', merged_by_id: 583231 }),
    det(9503, { merged_by: 'mychiefos', merged_by_id: 99999 }) /* Aaron's login, but not his account */] });
  const subs = Object.fromEntries((await q(`select t.github_number as n, s.id, s.status, s.route, s.decided_by, s.jevs_rules, t.status as task, t.id as task_id
    from app.work_tasks t join app.work_submissions s on s.task_id = t.id where t.github_kind = 'pr' and t.github_number in (9501, 9502, 9503)`)).map((r) => [r.n, r]));
  assert.deepStrictEqual([subs[9501].status, subs[9501].decided_by, subs[9501].task], ['passed', 'jevs', 'approved'], 'Aaron\'s merge: passed by rule, approved by its merge');
  // Still labelled with the merger's login, as before (042's "github:<login>", by "merge").
  const [label] = await q(`select actor, entry from app.log_entries where subject = 'task:${subs[9501].task_id}' and entry ->> 'type' = 'task.approved'`);
  assert.strictEqual(label && label.actor, 'github:mychiefos');
  for (const n of [9502, 9503]) {
    assert.deepStrictEqual([subs[n].status, subs[n].route, subs[n].jevs_rules], ['review', 'admin', 'W14'], n + ': a person decides');
    assert.strictEqual((await q(`select count(*)::int as n from app.work_points where submission_id = '${subs[n].id}'`))[0].n, 0, n + ': no points');
  }
  // Third Look takes only pull requests whose merge GitHub's read credits to Aaron's account (since 057 it reads the
  // changed files the GitHub facts workflow delivers: it doesn't even ask for the others').
  await q('update app.tl_settings set mode = \'on\', last_claim_at = null');
  const claim = () => as('dog_app', (t) => t`select * from app.tl_claim(3)`).then((r) => r.map((x) => x.pr_number));
  const mine = (list) => list.filter((n) => n >= 9501 && n <= 9503);
  assert.deepStrictEqual(mine((await core.wanted(su)).files), [], 'no changed files are asked for: not merged by Aaron\'s account');
  await sync({ files: [9502, 9503].map((n) => ({ number: n, files: [{ filename: 'a.js', status: 'modified', changes: 1, patch: '@@ -1 +1 @@\n-a\n+b' }] })) });
  assert.strictEqual((await q('select count(*)::int as n from app.tl_files where number in (9502, 9503)'))[0].n, 0, 'nor recorded if sent');
  assert.deepStrictEqual(mine(await claim()), [], 'not merged by Aaron\'s account: Third Look leaves it to a person');
  await as('dog_work', (t) => t`update app.work_github_prs set merged_by_id = ${AARON_ID} where number = 9502`);
  assert.deepStrictEqual(mine((await core.wanted(su)).files), [9502], 'once GitHub credits the merge to Aaron, its changed files are asked for');
  await sync({ files: [{ number: 9502, files: [{ filename: 'a.js', status: 'modified', changes: 1, patch: '@@ -1 +1 @@\n-a\n+b' }] }] });
  await q('update app.tl_settings set last_claim_at = null');
  assert.deepStrictEqual(mine(await claim()), [9502], 'the same work, once GitHub credits the merge to Aaron');
});

test('RK140: a pull request recorded before 055 (by the site) can\'t become finished work until GitHub\'s read confirms it', async () => {
  const core = await import('../supabase/functions/dog-github/core.mjs');
  // As the site's sync wrote rows before 055: merged, with a detail, who merged it by login only.
  await as('dog_work', (t) => t`insert into app.work_github_prs (number, title, author, state, merged_at, base, created_at, additions, deletions, merged_by, detail_at)
    values (9601, 'Old', 'octo', 'closed', now(), 'main', now(), 5, 0, 'mychiefos', now())`);
  await core.sync(su, { prs: [], issues: [], details: [], refused: 0 });
  assert.strictEqual((await q('select count(*)::int as n from app.work_tasks where github_kind = \'pr\' and github_number = 9601'))[0].n, 0, 'no task from the site\'s row');
  assert.ok((await core.wanted(su)).wanted.includes(9601), 'GitHub is asked to read it again');
  // A number GitHub doesn't have (a row the site's role could have forged before 055) is never confirmed; it can't
  // crowd out real work: a pull request GitHub's listing has just shown comes first.
  await as('dog_work', (t) => t`insert into app.work_github_prs (number, title, author, state, merged_at, base, created_at, seen_at)
    values (9602, 'Forged', 'x', 'closed', now(), 'main', now(), now() - interval '2 days')`);
  await core.sync(su, { prs: [pr(9603)], issues: [], details: [], refused: 0 });
  const order = (await core.wanted(su)).wanted.filter((n) => n === 9602 || n === 9603);
  assert.deepStrictEqual(order, [9603, 9602]);
  await core.sync(su, { prs: [], issues: [], details: [det(9601, { merged_by: 'octo', merged_by_id: 583231 })], refused: 0 });
  const [row] = await q('select merged_by, merged_by_id, merge_read_at is not null as read from app.work_github_prs where number = 9601');
  assert.deepStrictEqual(row, { merged_by: 'octo', merged_by_id: '583231', read: true }, 'GitHub\'s read replaces what the site wrote');
  const [s] = await q(`select s.status, s.jevs_rules from app.work_submissions s join app.work_tasks t on t.id = s.task_id where t.github_kind = 'pr' and t.github_number = 9601`);
  assert.deepStrictEqual([s.status, s.jevs_rules], ['review', 'W14']);
});

test('RK140: the coverage check passes with dog_ghsync, which can\'t sign in, belongs to no role, holds no table right and runs only its own functions', async () => {
  const { problems } = require('../db/checks');
  const snapshot = read('db/snapshot.txt').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
  const [r] = await q(`select rolcanlogin, rolinherit, rolbypassrls, (select count(*)::int from pg_auth_members m join pg_roles g on g.oid = m.roleid where m.member = r.oid) as member_of
    from pg_roles r where rolname = 'dog_ghsync'`);
  assert.deepStrictEqual(r, { rolcanlogin: false, rolinherit: false, rolbypassrls: false, member_of: 0 });
  const fns = await q(`select p.oid::regprocedure::text as fn from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'app' and has_function_privilege('dog_ghsync', p.oid, 'execute') order by 1`);
  // 055's two, and since 057 the changed files Third Look reads and the proposal decisions, from the same facts.
  assert.deepStrictEqual(fns.map((x) => x.fn), ['app.log_proposals_record(jsonb)', 'app.tl_files_record(jsonb)', 'app.tl_files_wanted(integer)',
    'app.work_github_sync(jsonb)', 'app.work_github_wanted(integer)']);
  const tables = await q(`select count(*)::int as n from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'app' and c.relkind = 'r' and has_table_privilege('dog_ghsync', c.oid, 'select, insert, update, delete')`);
  assert.strictEqual(tables[0].n, 0);
});
