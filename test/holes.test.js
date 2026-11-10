// Migration 057: the remaining access holes (RISKS.md RK135, RK144, RK112, RK100). The functions that record a model's
// or an outside system's answer leave the site's role:
//   - Second and Third Look run in their own Vercel project, "looks" (Aaron, Nov 10): the key broker gives that
//     project's identity token its own login, dog_looks_web, which may act as dog_looks only; the site's token never
//     gets it, the looks token never gets the site's; each token goes only to the broker and the AI Gateway. Third Look
//     reads only the changed files GitHub gave the GitHub facts workflow; a refused or failed model call gives the work
//     back; each claim has a 3-minute limit;
//   - the witness reports itself through dog-github (its own GitHub identity token) as dog_witness, and the timer checks
//     on its own (no input) when it has stopped;
//   - proposal decisions come with GitHub's facts (dog_ghsync): only real changes, only numbers GitHub can have, at most
//     30 an hour.
// These tests check the shared Vercel check and the broker for both projects; the looks route; that every token goes
// only to the broker and the gateway; with a login made like the site's (it may act as dog_app and nothing else) that
// each hole is shut; with the real looks login that it can run the looks' functions and nothing else; every refusal;
// and that a project or workflow that stops leaves work waiting for a person with nothing passed. The database tests
// need TEST_DATABASE_URL (skipped without it, required in CI).
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
const AARON_ID = 304218593;
const REPO = 'MyChiefOS/start-of-something-great';
const TOKEN = 'vercel.' + 'x'.repeat(40);
const imp = (f) => import('../supabase/functions/' + f);
const { subtle } = globalThis.crypto;
const enc = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');

// ---- The looks project's own identity (Aaron, Nov 10): the shared check, the broker, the looks route ----

// A stand-in gateway that records each request and answers with the given content.
function gateway(content, status = 200) {
  const sent = [];
  const f = async (url, opts) => { sent.push({ url, opts, body: JSON.parse(opts.body) }); return { status, json: async () => ({ choices: [{ message: { content } }] }) }; };
  f.sent = sent;
  return f;
}

// Vercel tokens signed by a test key, checked by the real shared check (as test/routeb.test.js does).
const LOOKS_TEST_ID = 'prj_looksTestProject0000000001';
async function vercel() {
  const oidc = await imp('_shared/vercel-oidc.mjs');
  const pair = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await subtle.exportKey('jwk', pair.publicKey)), kid: 'v1' };
  const now = 1_800_000_000;
  const claims = (projectId, name, over = {}) => ({ iss: 'https://oidc.vercel.com/chief-os', aud: 'https://vercel.com/chief-os', exp: now + 3600, iat: now - 5,
    owner: 'chief-os', owner_id: oidc.TEAM_ID, project: name, project_id: projectId, environment: 'production',
    sub: 'owner:chief-os:project:' + name + ':environment:production', ...over });
  async function sign(c) {
    const body = enc({ alg: 'RS256', kid: 'v1', typ: 'JWT' }) + '.' + enc(c);
    return body + '.' + Buffer.from(await subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, Buffer.from(body))).toString('base64url');
  }
  const keys = async () => [jwk];
  return { oidc, sign, keys, now, site: await sign(claims(oidc.PROJECT_ID, 'start-of-something-great')), looks: await sign(claims(LOOKS_TEST_ID, 'looks')),
    other: await sign(claims('prj_someoneelse', 'other')), claims };
}

test('057: the shared check accepts only the projects its caller names, says which, and while LOOKS_PROJECT_ID is empty refuses every token but the site\'s, as before', async () => {
  const { oidc, sign, keys, now, site, looks, other, claims } = await vercel();
  assert.strictEqual(oidc.LOOKS_PROJECT_ID, '', 'empty until Claude creates the project after the merge');
  assert.deepStrictEqual(oidc.PROJECTS, { site: oidc.PROJECT_ID, looks: '' });
  const v = (t, o = {}) => oidc.verify(t, { keys, now, ...o });
  // The site, as before: its claims come back whole, Vercel's own "project" claim untouched, with our name for it.
  const c = await v(site);
  assert.deepStrictEqual([c.our_project, c.project, c.project_id], ['site', 'start-of-something-great', oidc.PROJECT_ID]);
  // Today (empty): the looks token and any other project are refused, whatever the caller accepts.
  for (const t of [looks, other]) {
    await assert.rejects(v(t), /wrong project/);
    await assert.rejects(v(t, { projects: ['site', 'looks'] }), /wrong project/);
  }
  // A token claiming an empty project ID never matches the empty constant.
  await assert.rejects(v(await sign(claims('', 'blank')), { projects: ['site', 'looks'] }), /wrong project/);
  // Once set: each project only where its caller accepts it.
  const ids = { site: oidc.PROJECT_ID, looks: LOOKS_TEST_ID };
  assert.strictEqual((await v(looks, { projects: ['looks'], ids })).our_project, 'looks');
  await assert.rejects(v(looks, { ids }), /wrong project/, 'the site\'s callers (the default) never accept the looks token');
  await assert.rejects(v(site, { projects: ['looks'], ids }), /wrong project/, 'the looks route never accepts the site\'s token');
  await assert.rejects(v(other, { projects: ['site', 'looks'], ids }), /wrong project/);
  // Every other check is the same for the looks token: team, environment, subject, signature.
  for (const [over, why] of [[{ owner_id: 'team_other' }, /wrong team/], [{ environment: 'preview' }, /wrong environment/], [{ sub: 'owner:x:project:looks:environment:production' }, /wrong subject/]]) {
    await assert.rejects(v(await sign(claims(LOOKS_TEST_ID, 'looks', over)), { projects: ['looks'], ids }), why);
  }
});

// A stand-in for Vault, which records which entries were read.
function vault() {
  const values = { dog_web_password: 'w'.repeat(40), dog_looks_web_password: 'l'.repeat(40), dog_session_secret: 's'.repeat(40), dog_ip_hash_key: 'i'.repeat(40),
    dog_fingerprint_key_1: 'f'.repeat(40) };
  const asked = [];
  const sql = async (strings, names) => { asked.push([...names]); return names.filter((n) => n in values).map((n) => ({ name: n, v: values[n] })); };
  return { sql, asked, values };
}

test('057: the key broker gives the looks project\'s token the looks login and nothing else; the site\'s token gets exactly what it got before, and never the looks login', async () => {
  const core = await imp('dog-keys/core.mjs');
  const { oidc, keys, now, site, looks, other } = await vercel();
  const ids = { site: oidc.PROJECT_ID, looks: LOOKS_TEST_ID };
  const ask = async (token, idsNow) => {
    const store = vault();
    const out = await core.handle({ method: 'POST', token }, { verify: (t) => oidc.verify(t, { keys, now, projects: ['site', 'looks'], ids: idsNow }), Refused: oidc.Refused,
      values: (project) => core.read(store.sql, [], project), note: null });
    return { out, asked: store.asked };
  };
  const b64 = (s) => Buffer.from(s).toString('base64');
  // The site's answer, exactly as before 057 (the same shape the broker has always given), with LOOKS_PROJECT_ID empty or set.
  const before = { status: 200, body: { ok: true, database: { user: 'dog_web.' + core.PROJECT_REF, password: 'w'.repeat(40), hosts: core.POOLER_HOSTS, port: 6543, database: 'postgres' },
    keys: { SESSION_SECRET: b64('s'.repeat(40)), IP_HASH_KEY: b64('i'.repeat(40)), FINGERPRINT_KEY_1: b64('f'.repeat(40)) } } };
  for (const idsNow of [oidc.PROJECTS, ids]) {
    const s = await ask(site, idsNow);
    assert.deepStrictEqual(s.out, before);
    assert.deepStrictEqual(s.asked, [['dog_web_password', 'dog_session_secret', 'dog_ip_hash_key', 'dog_fingerprint_key_1']], 'the site never reads the looks login');
    assert.ok(!JSON.stringify(s.out).includes('dog_looks_web') && !JSON.stringify(s.out).includes('l'.repeat(40)));
  }
  // The looks project's token: its login only, read alone from Vault.
  const l = await ask(looks, ids);
  assert.deepStrictEqual(l.out, { status: 200, body: { ok: true, database: { user: 'dog_looks_web.' + core.PROJECT_REF, password: 'l'.repeat(40), hosts: core.POOLER_HOSTS,
    port: 6543, database: 'postgres' } } });
  assert.deepStrictEqual(l.asked, [['dog_looks_web_password']], 'nothing of the site\'s is even read');
  // While LOOKS_PROJECT_ID is empty (as committed), the looks token, and any other project's, get nothing.
  for (const t of [looks, other]) {
    const r = await ask(t, oidc.PROJECTS);
    assert.deepStrictEqual([r.out.status, r.out.body.error, r.asked], [401, 'refused: wrong project', []]);
  }
  // A check that names no project of ours gets nothing either.
  const none = await core.handle({ method: 'POST', token: 't' }, { verify: async () => ({ sub: 'x' }), Refused: oidc.Refused, values: async () => { throw new Error('read'); } });
  assert.deepStrictEqual([none.status, none.body.error], [401, 'refused: wrong project']);
  // The looks login missing from Vault: named, nothing sent.
  const missing = await core.handle({ method: 'POST', token: looks }, { verify: (t) => oidc.verify(t, { keys, now, projects: ['looks'], ids }), Refused: oidc.Refused,
    values: async () => ({}) });
  assert.deepStrictEqual([missing.status, missing.body.missing], [503, ['dog_looks_web_password']]);
  // The deployed broker accepts both projects, and nothing else changed about how it reads or answers.
  const ix = read('supabase/functions/dog-keys/index.ts');
  assert.match(ix, /checks\.verify\(t, \{ projects: \["site", "looks"\] \}\)/);
  assert.match(ix, /return checks\.read\(sql, project\);/);
  // The preview copy's broker (RK141, ./target.mjs) keeps both: the looks token there gets the branch's own looks login,
  // and only once the branch's Vault carries the preview copy's mark; the project and the mark both reach the read.
  const tg = await imp('dog-keys/target.mjs');
  const asked = [];
  const ck = tg.checksFor(tg.target('https://abcdefghijklmnopqrst.supabase.co'), { verify: async (t, o) => o, read: async (sql, extra, project) => { asked.push([project, extra]); return {}; } });
  assert.deepStrictEqual(await ck.verify('t', { projects: ['site', 'looks'] }), { projects: ['site', 'looks'], environment: 'preview' });
  await ck.read(null, 'looks');
  assert.deepStrictEqual(asked, [['looks', [tg.PREVIEW_MARKER]]]);
  const lv = { dog_looks_web_password: 'l'.repeat(40) };
  assert.deepStrictEqual(core.shapeLooks(lv, { ref: 'abcdefghijklmnopqrst', marker: tg.PREVIEW_MARKER }), { missing: [tg.PREVIEW_MARKER] });
  assert.strictEqual(core.shapeLooks({ ...lv, [tg.PREVIEW_MARKER]: 'yes' }, { ref: 'abcdefghijklmnopqrst', marker: tg.PREVIEW_MARKER }).database.user,
    'dog_looks_web.abcdefghijklmnopqrst');
});

test('057: the looks project is one route on a one-minute cron; it runs only on its own project\'s token, gets its login from the broker, and asks the gateway with its own token', async () => {
  assert.deepStrictEqual(fs.readdirSync(path.join(root, 'looks')).sort(), ['api', 'vercel.json']);
  assert.deepStrictEqual(fs.readdirSync(path.join(root, 'looks', 'api')), ['run.js'], 'only that route');
  const cfg = JSON.parse(read('looks/vercel.json'));
  assert.deepStrictEqual(cfg.crons, [{ path: '/api/run', schedule: '* * * * *' }]);
  assert.deepStrictEqual(Object.keys(cfg.functions), ['api/run.js']);
  assert.strictEqual(cfg.functions['api/run.js'].installCommand, 'cd .. && npm ci', 'the repository\'s one package, installed where db/ finds it');
  const src = read('looks/api/run.js');
  assert.match(src, /sitekeys\.verifiedToken\(req, \{ project: 'looks' \}\)/, 'only a token of the looks project');
  assert.match(src, /db\.looksRun/, 'its own login, acting as dog_looks');
  assert.doesNotMatch(src, /x-vercel-oidc-token|fetch\(|https?:\/\//, 'it reads no token itself and sends nothing itself');
  const run = require('../looks/api/run.js');
  const res = () => { const r = { statusCode: 0, headers: {}, setHeader(k, v) { r.headers[k] = v; }, end(b) { r.body = b; } }; return r; };
  // No token of the looks project (or no database): nothing runs.
  run._reset();
  const ran = [];
  const runTx = async (fn) => { ran.push('tx'); return fn(async () => []); };
  for (const [oidc, rt] of [[null, runTx], ['t'.repeat(30), null]]) {
    const r = res();
    await run.handle({ method: 'GET', headers: {} }, r, { oidc, runTx: rt });
    assert.deepStrictEqual([r.statusCode, JSON.parse(r.body), ran], [503, { ok: false }, []]);
  }
  const r405 = res();
  await run.handle({ method: 'POST', headers: {} }, r405, { oidc: TOKEN, runTx });
  assert.strictEqual(r405.statusCode, 405);
  // With its token: Second Look, then Third Look, each claim through the looks transaction; again within 25 s: nothing.
  let clock = 1e6;
  const r = res();
  await run.handle({ method: 'GET', headers: {} }, r, { oidc: TOKEN, runTx, now: () => clock });
  assert.deepStrictEqual([r.statusCode, JSON.parse(r.body), ran], [200, { ok: true }, ['tx', 'tx']]);
  clock += 10_000;
  await run.handle({ method: 'GET', headers: {} }, res(), { oidc: TOKEN, runTx, now: () => clock });
  assert.strictEqual(ran.length, 2);
  // The route as Vercel calls it: a token that is the site's, not the looks project's, runs nothing (LOOKS_PROJECT_ID empty).
  run._reset();
  const out = res();
  await run({ method: 'GET', headers: { 'x-vercel-oidc-token': 'h.' + 'z'.repeat(40) + '.s' } }, out);
  assert.deepStrictEqual([out.statusCode, JSON.parse(out.body)], [503, { ok: false }]);
});

test('057: the site\'s timer no longer runs Second or Third Look, and the site\'s token checks require the site\'s project', async () => {
  const cron = read('api/cron.js');
  assert.doesNotMatch(cron, /require\('\.\.\/db\/(secondlook|thirdlook)'\)|githubRead|getProposals|logFetch|workGithub/);
  const sk = read('db/sitekeys.js');
  assert.match(sk, /async function verifiedToken\(req, \{ verify = null, project = 'site' \} = \{\}\)/, 'the site\'s project unless the looks route says otherwise');
  // The site's own verifiedToken passes only 'site' to the check.
  const sitekeys = require('../db/sitekeys');
  const seen = [];
  const verify = async (t, o) => { seen.push(o.projects); return { our_project: o.projects[0] }; };
  const req = () => ({ headers: { 'x-vercel-oidc-token': 'h.' + 'z'.repeat(40) + '.s' } });
  await sitekeys.verifiedToken(req(), { verify });
  await sitekeys.verifiedToken(req(), { verify, project: 'looks' });
  assert.deepStrictEqual(seen, [['site'], ['looks']]);
  // Nothing in the site's code calls the looks' database functions, the witness's report or the proposals'.
  for (const f of ['db/logjobs.js', 'api/cron.js', 'db/workjobs.js']) {
    assert.doesNotMatch(read(f), /app\.(sl_claim|sl_decide|tl_claim|tl_decide|tl_release|log_witness_report|log_proposal|tl_files_record)\b/, f);
  }
  for (const f of fs.readdirSync(path.join(root, 'api'))) assert.doesNotMatch(read('api/' + f), /db\/(secondlook|thirdlook)'|looksRun/, 'api/' + f + ' runs no look');
  assert.doesNotMatch(read('db/logjobs.js'), /fetch\(|require\('\.\/log'\)/, 'the log jobs fetch nothing');
});

test('control 8: in api/, db/, looks/, secondlook/ and thirdlook/ the only requests carrying a Bearer credential are the reviewed ones; Vercel\'s token goes only to the broker and the gateway', () => {
  const files = [];
  const walk = (d) => { for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true })) { const p = d + '/' + e.name; if (e.isDirectory()) walk(p); else if (p.endsWith('.js')) files.push(p); } };
  for (const d of ['api', 'db', 'looks', 'secondlook', 'thirdlook']) walk(d);
  const found = [];
  for (const f of files) for (const m of read(f).matchAll(/['"]Bearer ['"]\s*\+\s*([A-Za-z_.]+)/g)) found.push(f + ' ' + m[1]);
  assert.deepStrictEqual(found.sort(), ['api/_lib.js token', 'db/sitekeys.js token', 'db/workjobs.js token', 'secondlook/v1.js token', 'secondlook/v1.js token', 'thirdlook/v1.js token']);
  // GitHub's own tokens, read from GitHub's settings, to GitHub's API.
  assert.match(read('api/_lib.js'), /const token = process\.env\.GITHUB_TOKEN;[\s\S]*fetch\(GH \+ path/);
  assert.match(read('db/workjobs.js'), /githubGet\(env\.GH_TOKEN/);
  // Vercel's token: the broker's fixed address, and the gateway's, never redirected.
  const sk = read('db/sitekeys.js');
  assert.match(sk, /const BROKER = 'https:\/\/nksagchwpyljvjiwolmp\.supabase\.co\/functions\/v1\/dog-keys';/);
  assert.match(sk, /fetchImpl\(broker, \{ method: 'POST', headers: \{ authorization: 'Bearer ' \+ token \}, redirect: 'error'/);
  // broker: production's fixed address, or (a preview deployment only) the preview branch's broker at its fixed form (RK141).
  assert.match(sk, /if \(vercel !== 'preview'\) return BROKER;/);
  assert.match(sk, /return 'https:\/\/' \+ previewRef \+ '\.supabase\.co\/functions\/v1\/dog-keys';/);
  const s2 = read('secondlook/v1.js');
  assert.match(s2, /const GATEWAY = 'https:\/\/ai-gateway\.vercel\.sh\/v1\/chat\/completions';/);
  assert.strictEqual((s2.match(/fetchImpl\(GATEWAY, \{\s*method: 'POST',? ?(?:\n\s*)?redirect: 'error'/g) || []).length, 2);
  assert.match(read('thirdlook/v1.js'), /fetchImpl\(sl\.GATEWAY, \{\s*method: 'POST', redirect: 'error'/);
  // And Semgrep scans looks/ with the rule that keeps the token there (control 8).
  const ci = read('.github/workflows/checks.yml').split('\n')[96];
  assert.match(ci, /semgrep scan --config \.semgrep\/ .* looks\/ /);
  const rule = read('.semgrep/database.yml');
  assert.match(rule, /id: dayonegreat\.routeb\.identity-token-only-to-broker[\s\S]*?exclude: \[db\/sitekeys\.js, api\/ready\.js, test\/\]/, 'looks/ is not excluded');
});

test('057: Third Look gives the work back only for a refused or failed call, or no read of GitHub; the model\'s own answer is one try', async () => {
  const tl = require('../thirdlook/v1');
  for (const [err, rel] of [['timeout', true], ['network', true], ['gateway 503', true], ['gateway 401', true], ['bad answer', false], ['not json', false], ['model not allowed', false]]) {
    assert.strictEqual(tl.releases(err), rel, err);
  }
  const item = { taskTitle: 'T', taskDescription: 'D', note: '', prTitle: 'P' };
  const files = [{ filename: 'a.js', status: 'modified', patch: '+x' }];
  const ok = JSON.stringify({ a1: 'yes', a2: 'yes', a3: 'no', reason: 'ok' });
  assert.strictEqual((await tl.review({ item, files: null, token: TOKEN, model: 'mistral/ministral-14b', fetchImpl: gateway(ok) })).release, 'github not read');
  assert.strictEqual((await tl.review({ item, files, token: TOKEN, model: 'mistral/ministral-14b', fetchImpl: gateway(ok, 503) })).release, 'gateway 503');
  assert.strictEqual((await tl.review({ item, files, token: TOKEN, model: 'mistral/ministral-14b', fetchImpl: gateway('nonsense') })).release, null);
  const pass = await tl.review({ item, files, token: TOKEN, model: 'mistral/ministral-14b', fetchImpl: gateway(ok) });
  assert.deepStrictEqual([pass.suggestion, pass.release], ['pass', null]);
});

test('057: the witness workflow reports through dog-github with its own identity token, after it has recorded, and nothing from the event reaches a command', async () => {
  const core = await imp('dog-github/core.mjs');
  const y = read('.github/workflows/log-witness.yml');
  const job = y.split(/^  report:$/m)[1];
  assert.ok(job, 'a report job');
  assert.match(job, /^ {4}needs: \[check, record\]$/m, 'only after the record job has written what it reports');
  assert.match(job, /^ {4}if: github\.repository_id == 1418125608 && github\.ref == 'refs\/heads\/main'$/m);
  assert.match(job, /^ {4}permissions:\n {6}contents: read\n {6}id-token: write[^\n]*\n {4}env:/m, 'only the rights it needs');
  assert.match(job, new RegExp('FN_URL: ' + core.AUDIENCE.replace(/[.]/g, '\\.') + '\n'));
  assert.match(job, /audience=\$FN_URL/, 'the token is for dog-github alone');
  assert.match(job, /echo "::add-mask::\$t"/);
  assert.match(job, /node db\/logjobs\.js witness-request state\.json request\.json/);
  assert.match(job, /WITNESS_STATE_B64: \$\{\{ needs\.check\.outputs\.state \}\}/);
  for (const m of job.matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, 'pinned to a commit: ' + m[1]);
  assert.match(job, /persist-credentials: false/);
  const run = job.split(/^ {8}run: \|$/m)[1];
  assert.doesNotMatch(run, /\$\{\{/, 'no ${{ }} inside the shell step');
  assert.doesNotMatch(y, /\$\{\{\s*(github\.event|github\.head_ref|inputs\.)/, 'no text from the event anywhere');
  assert.doesNotMatch(job, /\$\{\{\s*secrets\.|npm (ci|install)/, 'no secret, no packages installed');
  // The events the witness runs on are exactly the ones dog-github accepts from it.
  const on = y.split(/^permissions:/m)[0].split(/^on:$/m)[1];
  assert.deepStrictEqual([...on.matchAll(/^ {2}([a-z_]+):/gm)].map((m) => m[1]).sort(), [...core.WITNESS_EVENTS].sort());
  // The command shapes the report from the state the record job wrote.
  const jobs = require('../db/logjobs');
  const root = crypto.randomBytes(32).toString('base64');
  assert.deepStrictEqual(jobs.witnessRequest({ good: { size: 9, root }, last_run: '2026-11-10T10:00:00Z', alarm: { reason: 'Split view.' } }),
    { mode: 'witness', report: { size: 9, root, at: '2026-11-10T10:00:00.000Z', alarm: 'Split view.' } });
  assert.deepStrictEqual(jobs.witnessRequest({ last_run: '2026-11-10T10:00:00Z' }).report, { size: null, root: null, at: '2026-11-10T10:00:00.000Z', alarm: null });
  assert.throws(() => jobs.witnessRequest({ good: { size: 9, root } }), /no time/);
  assert.deepStrictEqual(core.parse(JSON.stringify(jobs.witnessRequest({ good: { size: 9, root }, last_run: '2026-11-10T10:00:00Z' }))).report,
    { size: 9, root, at: '2026-11-10T10:00:00.000Z', alarm: null }, 'what the command writes, dog-github reads');
});

// Tokens signed by a test key, checked by the real shared check with that key (as test/github-facts.test.js does).
async function github() {
  const oidc = await imp('_shared/github-oidc.mjs');
  const core = await imp('dog-github/core.mjs');
  const pair = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await subtle.exportKey('jwk', pair.publicKey)), kid: 'k1' };
  const now = 1_800_000_000;
  const claims = (workflow, over = {}) => ({ iss: oidc.ISSUER, aud: core.AUDIENCE, exp: now + 300, iat: now - 5, nbf: now - 5, repository_id: '1418125608',
    repository_owner_id: '304218593', repository: REPO, ref: 'refs/heads/main', event_name: 'schedule', sha: 'a'.repeat(40), jti: 'gh-' + crypto.randomUUID(),
    workflow_ref: REPO + '/.github/workflows/' + workflow + '@refs/heads/main', ...over });
  async function sign(c) {
    const body = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' }) + '.' + enc(c);
    return body + '.' + Buffer.from(await subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, Buffer.from(body))).toString('base64url');
  }
  const deps = (extra = {}) => ({ verify: oidc.verify, Refused: oidc.Refused, keys: async () => [jwk], now, seen: async () => false, ...extra });
  return { core, claims, sign, deps };
}

test('057: dog-github takes the witness\'s report only from the witness workflow, and facts only from the facts workflow', async () => {
  const { core, claims, sign, deps } = await github();
  const noDb = () => { throw new Error('the database was opened'); };
  const report = JSON.stringify({ mode: 'witness', report: { size: 3, root: crypto.randomBytes(32).toString('base64'), at: '2026-11-10T10:00:00Z', alarm: null } });
  const call = async (c, text) => core.handle({ method: 'POST', authorization: 'Bearer ' + (await sign(c)), text: async () => text }, deps({ db: noDb }));
  // Each workflow only for its own modes: 403 before the database is opened.
  for (const [wf, text] of [['log-witness.yml', '{"mode":"wanted"}'], ['log-witness.yml', JSON.stringify({ mode: 'sync', facts: {} })], ['github-facts.yml', report]]) {
    assert.deepStrictEqual(await call(claims(wf), text), { status: 403, body: { ok: false, error: 'not for this workflow' } }, wf + ' ' + text.slice(0, 20));
  }
  // The witness's token: its own events only, main only, this repository only, its own file only.
  for (const [over, why] of [[{ event_name: 'issues' }, /wrong event/], [{ event_name: 'pull_request_target' }, /wrong event/], [{ ref: 'refs/heads/x',
    workflow_ref: REPO + '/.github/workflows/log-witness.yml@refs/heads/x' }, /main branch/], [{ repository_id: '9' }, /repository/],
  [{ workflow_ref: REPO + '/.github/workflows/log-witness.yml@refs/heads/feature' }, /workflow/]]) {
    const r = await call(claims('log-witness.yml', over), report);
    assert.deepStrictEqual([r.status, why.test(r.body.error)], [401, true], JSON.stringify(over));
  }
  // The report's shape.
  for (const [rep, why] of [[{ size: 3, root: 'short', at: '2026-11-10T10:00:00Z' }, /root/], [{ size: 3, at: '2026-11-10T10:00:00Z' }, /together/],
    [{ size: -1, root: crypto.randomBytes(32).toString('base64'), at: '2026-11-10T10:00:00Z' }, /size/], [{ at: 'yesterday' }, /time/],
    [{ at: '2026-11-10T10:00:00Z', alarm: 'x'.repeat(301) }, /alarm/], [{ at: '2026-11-10T10:00:00Z', status: 'ok' }, /unknown field/]]) {
    const r = await call(claims('log-witness.yml'), JSON.stringify({ mode: 'witness', report: rep }));
    assert.deepStrictEqual([r.status, why.test(r.body.error)], [400, true], JSON.stringify(rep));
  }
  // The facts' new lists and their limits.
  const big = await call(claims('github-facts.yml'), JSON.stringify({ mode: 'sync', facts: { files: new Array(11).fill({}) } }));
  assert.deepStrictEqual([big.status, big.body.error], [400, 'files must be a list of at most 10 objects']);
  assert.strictEqual((await call(claims('github-facts.yml'), JSON.stringify({ mode: 'sync', facts: { proposals: new Array(101).fill({}) } }))).status, 400);
});

test('057: the GitHub facts read gives each wanted pull request\'s changed files within the database\'s limit, and the proposals\' decisions from their labels', async () => {
  const workjobs = require('../db/workjobs');
  const asked = [];
  const big = Array.from({ length: 30 }, (_, i) => ({ filename: 'f' + i + '.js', status: 'modified', changes: 9, patch: '+' + 'y'.repeat(4000) }));
  const get = async (p) => {
    asked.push(p);
    if (p === '/pulls/41/files?per_page=100') return big;
    if (p === '/pulls/42/files?per_page=100') throw Object.assign(new Error('limited'), { githubStatus: 429 });
    if (p.startsWith('/issues?labels=proposal')) {
      return [{ number: 7, state: 'open', labels: [{ name: 'proposal' }, { name: 'status: approved' }], title: 'Proposal: A', body: '', user: { login: 'x' } },
        { number: 8, state: 'open', labels: [{ name: 'proposal' }, { name: 'status: in review' }], title: 'Proposal: B', body: '', user: { login: 'x' } },
        { number: 9, state: 'closed', labels: [{ name: 'proposal' }, { name: 'status: shipped' }], title: 'Proposal: C', body: '', user: { login: 'x' } },
        { number: 10, state: 'open', labels: [{ name: 'proposal' }, { name: 'status: approved' }], pull_request: {}, title: 'A PR', body: '', user: { login: 'x' } }];
    }
    return [];
  };
  const facts = await workjobs.gather({ get, wanted: [], files: [41, 42, 43, 44, 45, 46, 'x'] });
  assert.deepStrictEqual(asked.filter((p) => p.endsWith('/files?per_page=100')), [41, 42, 43, 44, 45].map((n) => '/pulls/' + n + '/files?per_page=100'), 'at most 5, only numbers');
  assert.strictEqual(facts.refused, 1);
  const f41 = facts.files.find((x) => x.number === 41).files;
  assert.strictEqual(f41.length, 30, 'every file is listed');
  assert.ok(Buffer.byteLength(JSON.stringify(f41)) <= workjobs.FILES_BYTES, 'within the database\'s limit');
  assert.ok(f41.some((x) => !('patch' in x)), 'a patch that doesn\'t fit is left out, so Third Look sees the change wasn\'t read whole');
  assert.deepStrictEqual(facts.proposals, [{ number: 7, status: 'approved' }, { number: 9, status: 'shipped' }], 'decided ones only; never a pull request');
  const reqs = workjobs.requests(facts);
  assert.deepStrictEqual([reqs[0].facts.files.length, reqs[0].facts.proposals.length], [facts.files.length, 2]);
});

// ---- With a database ----

if (!SERVER) {
  if (process.env.CI) test('the access-hole database tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the access-hole tests against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const { migrate } = require('../scripts/migrate');
const NAME = 'dog_holes_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web, looksSql;
const db = require('../db');
const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const q = (s) => su.unsafe(s);
const as = (role, fn) => su.begin(async (t) => { await t.unsafe('set local role ' + role); return fn(t); });
// The site's own login: it may act as dog_app and nothing else (022).
const asSite = (fn) => web.begin(async (t) => { await t`set local role dog_app`; return fn(t); });
const NO = /permission denied for function/;
let gh;
// The looks project's own login (057), signing in as production's would, acting as dog_looks through db/index.js.
const lk = (fn) => db.looksTx(looksSql, fn);
const third = (opts) => require('../db/thirdlook').run(lk, TOKEN, opts);
const second = (opts) => require('../db/secondlook').run(lk, TOKEN, opts);
const facts = { prs: [], issues: [], details: [], refused: 0 };
const pr = (n) => ({ number: n, title: 'PR ' + n, author: 'octo', state: 'closed', merged_at: '2026-11-01T10:00:00Z', base: 'main', merge_sha: 'b'.repeat(40),
  refs: '', milestone: null, milestone_title: null, room: null, created_at: '2026-10-31T10:00:00Z', codes: [] });
const det = (n, by) => ({ number: n, additions: 10, deletions: 0, state: 'closed', merged_at: '2026-11-01T10:00:00Z', base: 'main', merge_sha: 'b'.repeat(40),
  merged_by: 'octo', merged_by_id: by });
const FILES = [{ filename: 'a.js', status: 'modified', changes: 2, patch: '@@ -1 +1 @@\n-a\n+b' }];
let next = 9700;

// Work waiting for a person on a merged pull request whose merge GitHub's read credits to Aaron (055), the way Third
// Look gets it: the repository's own pull request merged by someone else goes to a person (W14), and GitHub's read is
// then made Aaron's. Its changed files arrive through the facts path unless told not to.
async function waitingWork({ files = true } = {}) {
  const n = next++;
  await gh.sync(su, { ...facts, prs: [pr(n)] });
  await gh.sync(su, { ...facts, details: [det(n, 583231)] });
  await as('dog_work', (t) => t`update app.work_github_prs set merged_by_id = ${AARON_ID} where number = ${n}`);
  const [s] = await q(`select s.id, s.status, s.route from app.work_submissions s join app.work_tasks t on t.id = s.task_id where t.github_kind = 'pr' and t.github_number = ${n}`);
  assert.deepStrictEqual([s.status, s.route], ['review', 'admin']);
  if (files) await gh.sync(su, facts, { files: [{ number: n, files: FILES }] });
  return { n, s: s.id };
}
const status = async (s) => (await q(`select status || '/' || coalesce(route, '-') || '/' || coalesce(decided_by, '-') as x from app.work_submissions where id = '${s}'`))[0].x;
const claimNow = () => as('dog_work', (t) => t`update app.tl_settings set last_claim_at = null`);
const PASS = { a1: 'yes', a2: 'yes', a3: 'no' };
const yes = () => gateway(JSON.stringify({ ...PASS, reason: 'It does the task.' }));

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = postgres(at(NAME, WEB, PW), { max: 1, ssl: false, onnotice: () => {} });
  gh = await imp('dog-github/core.mjs');
  // The looks login exists on this server (057 made it); the test gives it a password of its own to sign in with, as
  // production's comes from Vault through the broker.
  const LPW = crypto.randomBytes(18).toString('base64url');
  await su.unsafe(`alter role dog_looks_web password '${LPW}'`);
  looksSql = postgres(at(NAME, 'dog_looks_web', LPW), { max: 1, ssl: false, onnotice: () => {} });
  await q(`update app.tl_settings set mode = 'on', daily_call_cap = 30`); // as the test's superuser: the table forces row-level security
});
test.after(async () => {
  for (const x of [looksSql, web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

test('RK135: the site\'s role can\'t claim Third Look\'s work, record its answer or give work back, nor act as dog_looks; the work module\'s own role is refused by each function', async () => {
  const w = await waitingWork({ files: false });
  await claimNow();
  await assert.rejects(asSite((t) => t`select * from app.tl_claim(3)`), NO, 'claim');
  await assert.rejects(asSite((t) => t`select app.tl_decide(${w.s}::uuid, 'v1', 'mistral/ministral-14b', 'pass', ${t.json(PASS)}::jsonb, 'x', false, false, 1)`), NO, 'answer');
  await assert.rejects(asSite((t) => t`select app.tl_release(${w.s}::uuid, 'timeout')`), NO, 'give back');
  await assert.rejects(asSite((t) => t`select * from app.tl_files_wanted(5)`), NO);
  await assert.rejects(asSite((t) => t`select app.tl_files_record('[]'::jsonb)`), NO);
  await assert.rejects(web.begin((t) => t`set local role dog_looks`), /permission denied to set role "dog_looks"/, 'the site\'s login can never act as it');
  // The owner of the functions could call them; each refuses any role in force but its own caller's.
  for (const [sqlText, why] of [['select * from app.tl_claim(3)', /only the looks project hands work to Third Look/],
    [`select app.tl_decide('${w.s}', 'v1', null, 'person', null, 'x', true, false, 1)`, /only the looks project records Third Look/],
    [`select app.tl_release('${w.s}', 'timeout')`, /only the looks project gives/],
    ['select * from app.tl_files_wanted(5)', /only the GitHub facts function/], [`select app.tl_files_record('[]')`, /only the GitHub facts function/]]) {
    await assert.rejects(as('dog_work', (t) => t.unsafe(sqlText)), why, sqlText);
    // And each is refused outright to the other narrow role (the looks role can't record files; dog-github's can't claim).
    await assert.rejects(as(sqlText.includes('files') ? 'dog_looks' : 'dog_ghsync', (t) => t.unsafe(sqlText)), NO, sqlText);
  }
  assert.strictEqual(await status(w.s), 'review/admin/-', 'nothing passed');
  assert.strictEqual((await q(`select count(*)::int as n from app.tl_reviews where submission_id = '${w.s}'`))[0].n, 0, 'nothing claimed');
});

test('RK135: the looks project claims, asks and records Third Look itself; a pass needs GitHub\'s changed files, Aaron\'s merge at the pass, and its claim\'s time limit', async () => {
  const w = await waitingWork();
  const g = yes();
  await claimNow();
  assert.deepStrictEqual(await third({ fetchImpl: g }), { claimed: 1, decided: 1, released: 0 });
  assert.strictEqual(await status(w.s), 'passed/-/third_look');
  assert.strictEqual(g.sent[0].opts.headers.authorization, 'Bearer ' + TOKEN, 'the caller\'s token, to the gateway');
  assert.match(g.sent[0].body.messages[1].content, /\+b/, 'the change GitHub gave the facts workflow');
  assert.strictEqual((await q(`select count(*)::int as n from app.tl_files where number = ${w.n}`))[0].n, 0, 'its files are deleted once answered');
  // No changed files from GitHub yet: not claimed; the facts workflow is asked for them.
  const nf = await waitingWork({ files: false });
  await claimNow();
  assert.deepStrictEqual((await third({ fetchImpl: yes() })).claimed, 0);
  assert.ok((await gh.wanted(su)).files.includes(nf.n));
  // A claim answered after its 3 minutes changes nothing.
  await gh.sync(su, facts, { files: [{ number: nf.n, files: FILES }] });
  await claimNow();
  const [c] = await as('dog_looks', (t) => t`select submission_id from app.tl_claim(1)`);
  assert.strictEqual(c.submission_id, nf.s);
  await q(`update app.tl_reviews set claimed_at = now() - interval '4 minutes' where submission_id = '${nf.s}'`);
  assert.strictEqual((await as('dog_looks', (t) => t`select app.tl_decide(${nf.s}::uuid, 'v1', 'mistral/ministral-14b', 'pass', ${t.json(PASS)}::jsonb, 'x', false, false, 1) as r`))[0].r, 'expired');
  assert.strictEqual(await status(nf.s), 'review/admin/-', 'nothing passed');
  // The next claim gives it back ("timed out"), and after 10 minutes it is claimed again.
  await claimNow();
  await as('dog_looks', (t) => t`select * from app.tl_claim(1)`);
  const [rel] = await q(`select why from app.tl_releases where submission_id = '${nf.s}'`);
  assert.strictEqual(rel.why, 'timed out');
  assert.strictEqual((await q(`select count(*)::int as n from app.tl_reviews where submission_id = '${nf.s}'`))[0].n, 0);
  // The gate again at the pass: if GitHub's read no longer credits Aaron, the pass is recorded but passes nothing.
  await q(`update app.tl_releases set released_at = now() - interval '11 minutes' where submission_id = '${nf.s}'`);
  await claimNow();
  const [c2] = await as('dog_looks', (t) => t`select submission_id from app.tl_claim(1)`);
  assert.strictEqual(c2.submission_id, nf.s, 'claimed again after 10 minutes');
  await as('dog_work', (t) => t`update app.work_github_prs set merged_by_id = 583231 where number = ${nf.n}`);
  assert.strictEqual((await as('dog_looks', (t) => t`select app.tl_decide(${nf.s}::uuid, 'v1', 'mistral/ministral-14b', 'pass', ${t.json(PASS)}::jsonb, 'x', false, false, 1) as r`))[0].r, 'not_owner_merged');
  assert.strictEqual(await status(nf.s), 'review/admin/-');
});

test('RK135: a refused or failed model call gives the work back without spending its try; a failing gateway can\'t loop, and Aaron is told once a day from the third', async () => {
  await q('delete from app.tl_releases');
  await q(`delete from app.notices where dedupe_key like 'thirdlook:released:%'`);
  const items = [await waitingWork(), await waitingWork(), await waitingWork()];
  await claimNow();
  const out = await third({ fetchImpl: gateway('{}', 503) });
  assert.deepStrictEqual(out, { claimed: 3, decided: 0, released: 3 });
  for (const w of items) {
    assert.strictEqual(await status(w.s), 'review/admin/-', 'nothing passes');
    assert.strictEqual((await q(`select count(*)::int as n from app.tl_reviews where submission_id = '${w.s}'`))[0].n, 0, 'its try isn\'t spent');
  }
  assert.deepStrictEqual((await q('select why from app.tl_releases order by why')).map((r) => r.why), ['gateway 503', 'gateway 503', 'gateway 503']);
  const told = await q(`select title, body from app.notices where member_id is null and dedupe_key like 'thirdlook:released:%'`);
  assert.strictEqual(told.length, 1, 'Aaron is told, once');
  assert.match(told[0].body, /Nothing passes while this lasts/);
  // Not claimed again for 10 minutes, and releases count against the day's calls.
  await claimNow();
  assert.strictEqual((await third({ fetchImpl: yes() })).claimed, 0);
  await q(`update app.tl_settings set daily_call_cap = (select count(*) from app.tl_reviews where claimed_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC') + 3`);
  await q(`update app.tl_releases set released_at = now() - interval '11 minutes'`);
  await claimNow();
  assert.strictEqual((await third({ fetchImpl: yes() })).claimed, 0, 'today\'s calls include the three given back');
  await q('update app.tl_settings set daily_call_cap = 30');
  // Timeouts and network failures the same; the model's own unusable answer is recorded as "a person" (one try).
  await claimNow();
  const slow = async () => { throw Object.assign(new Error('slow'), { name: 'TimeoutError' }); };
  assert.deepStrictEqual(await third({ fetchImpl: slow }), { claimed: 3, decided: 0, released: 3 });
  await q(`update app.tl_releases set released_at = now() - interval '11 minutes'`);
  await claimNow();
  assert.deepStrictEqual(await third({ fetchImpl: gateway('nonsense') }), { claimed: 3, decided: 3, released: 0 });
  for (const w of items) {
    const [r] = await q(`select suggestion, fail_closed from app.tl_reviews where submission_id = '${w.s}'`);
    assert.deepStrictEqual([r.suggestion, r.fail_closed, await status(w.s)], ['person', true, 'review/admin/-']);
  }
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id is null and dedupe_key like 'thirdlook:released:%'`))[0].n, 1, 'still once a day');
  // A release with a reason that isn't one of ours is refused.
  await assert.rejects(as('dog_looks', (t) => t`select app.tl_release(${items[0].s}::uuid, ${'<b>x</b>'})`), /bad Third Look release/);
});

test('checks alert, never lock out: if the looks project stops mid-claim, or the facts never come, nothing passes, the work waits for a person, and Aaron is told halfway', async () => {
  const w = await waitingWork();
  await claimNow();
  await lk((t) => t`select * from app.tl_claim(1)`); // the looks project claims, then stops before answering
  const nf = await waitingWork({ files: false }); // and this one's changed files never come
  await q(`update app.work_submissions set routed_at = now() - make_interval(hours => (select audit_hours from app.work_settings) / 2) - interval '1 minute'
    where id in ('${w.s}', '${nf.s}')`);
  await as('dog_work', (t) => t`update app.work_settings set last_tick_at = null`);
  await asSite((t) => t`select app.work_tick()`);
  for (const x of [w, nf]) {
    assert.strictEqual(await status(x.s), 'review/admin/-', 'nothing passed');
    assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id is null and dedupe_key = 'work:held:${x.s}'`))[0].n, 1, 'Aaron is told');
  }
});

test('RK100: the site\'s role can\'t claim held posts for Second Look or record its decision, nor act as dog_looks; JEVs\'s own role is refused by the functions', async () => {
  await assert.rejects(asSite((t) => t`select * from app.sl_claim(1)`), NO);
  await assert.rejects(asSite((t) => t`select app.sl_decide(${crypto.randomUUID()}::uuid, 'v1', 'mistral/ministral-3b', 'clear', '{}'::jsonb, 0, 'x', false, null, 1)`), NO);
  await assert.rejects(as('dog_jevs', (t) => t`select * from app.sl_claim(1)`), /only the looks project hands posts to Second Look/);
  await assert.rejects(as('dog_jevs', (t) => t`select app.sl_decide(${crypto.randomUUID()}::uuid, 'v1', null, 'leave', null, 0, 'x', false, null, 1)`), /only the looks project records Second Look/);
  // The looks project's own path runs it.
  await q(`update app.sl_settings set last_claim_at = null`);
  assert.deepStrictEqual(await second({ fetchImpl: gateway('{}') }), { claimed: 0, decided: 0 });
});

test('RK144: the site\'s role can\'t report the witness, nor act as dog_witness; only dog-github\'s path for the witness workflow can, and the timer\'s check takes no input', async () => {
  const [head] = await q('select size, app.log_root(size) as root from app.log_head');
  await assert.rejects(asSite((t) => t`select app.log_witness_report(${Number(head.size) || null}, ${head.root}, now(), null)`), NO);
  await assert.rejects(web.begin((t) => t`set local role dog_witness`), /permission denied to set role "dog_witness"/);
  for (const role of ['dog_log', 'dog_ghsync']) {
    await assert.rejects(as(role, (t) => t`select app.log_witness_report(null, null, now(), null)`), role === 'dog_log' ? /only the witness workflow reports the witness/ : NO, role);
  }
  assert.strictEqual(await gh.witness(su, { size: null, root: null, at: new Date().toISOString(), alarm: null }), 'unknown');
  // The timer's check: the site's role may run it, with nothing to say.
  assert.strictEqual((await asSite((t) => t`select app.log_witness_check() as s`))[0].s, 'unknown');
  await assert.rejects(asSite((t) => t`select app.log_witness_check(${'ok'})`), /does not exist/);
});

test('RK112: proposal decisions only from GitHub\'s facts: only real changes, only numbers GitHub can have, at most 30 an hour; the site\'s role can add none', async () => {
  await assert.rejects(asSite((t) => t`select app.log_proposal(${70}, 'approved')`), NO);
  await assert.rejects(asSite((t) => t`select app.log_proposals_record(${t.json([{ number: 70, status: 'approved' }])}::jsonb)`), NO);
  await assert.rejects(as('dog_log', (t) => t`select app.log_proposals_record('[]'::jsonb)`), /only the GitHub facts function records proposal decisions/);
  await assert.rejects(as('dog_ghsync', (t) => t`select app.log_proposal(70, 'approved')`), NO, 'only through the batch');
  const send = async (proposals) => (await gh.sync(su, facts, { proposals })).proposals;
  const entries = async (n) => (await q(`select entry_jcs from app.log_entries where subject = 'proposal:${n}' order by seq`)).map((r) => JSON.parse(r.entry_jcs).payload.decision);
  const maxPr = Number((await q('select max(number) as m from app.work_github_prs'))[0].m);
  // Only numbers GitHub can have: not a pull request, at most 100 past the newest number GitHub has shown.
  assert.strictEqual(await send([{ number: maxPr, status: 'approved' }, { number: maxPr + 101, status: 'approved' }, { number: 9_999_999, status: 'approved' }]), 0);
  // Malformed entries are skipped, the rest recorded.
  const n = maxPr + 1;
  assert.strictEqual(await send([{ number: n, status: 'approved' }, { number: 'x', status: 'approved' }, { number: n + 1, status: 'waiting' }, { status: 'approved' }]), 1);
  // Along the labels' flow at once (approved to shipped); a flip back and forth, at most once a day.
  assert.strictEqual(await send([{ number: n, status: 'declined' }]), 0, 'a reversal within a day waits');
  assert.strictEqual(await send([{ number: n, status: 'shipped' }]), 1);
  for (let i = 0; i < 10; i++) await send([{ number: n, status: i % 2 ? 'approved' : 'declined' }]);
  assert.deepStrictEqual(await entries(n), ['approved', 'shipped'], 'ten flips add nothing in a day');
  await q(`update app.log_proposals_seen set logged_at = now() - interval '25 hours' where number = ${n}`);
  assert.strictEqual(await send([{ number: n, status: 'declined' }]), 1, 'a day later a real reversal is logged');
  // At most 30 an hour; the rest wait for a later run, and Aaron is told once.
  await q(`update app.log_proposals_seen set logged_at = now() - interval '2 hours'`);
  const many = Array.from({ length: 40 }, (_, i) => ({ number: n + 2 + i, status: 'approved' }));
  assert.strictEqual(await send(many), 30);
  assert.strictEqual(await send(many), 0);
  assert.strictEqual((await q(`select count(*)::int as n from app.notices where member_id is null and dedupe_key like 'log.proposals.cap.%'`))[0].n, 1);
  await q(`update app.log_proposals_seen set logged_at = now() - interval '2 hours'`);
  assert.strictEqual(await send(many), 10, 'the rest on a later run');
});

test('057: the looks login signs in with no rights of its own, may act as dog_looks only, and as dog_looks can run the looks\' functions and nothing else', async () => {
  await assert.rejects(looksSql`select * from app.tl_claim(1)`, /permission denied for schema app/, 'nothing without taking its role (noinherit)');
  await assert.rejects(looksSql`select count(*) from app.posts`, /permission denied/);
  for (const role of ['dog_app', 'dog_work', 'dog_jevs', 'dog_ghsync', 'dog_witness', 'dog_owner']) {
    await assert.rejects(looksSql.begin((t) => t.unsafe('set local role ' + role)), new RegExp('permission denied to set role "' + role + '"'), role);
  }
  await claimNow();
  assert.ok(Array.isArray(await lk((t) => t`select * from app.tl_claim(1)`)), 'as dog_looks, Third Look\'s claim runs');
  await assert.rejects(lk((t) => t`select count(*) from app.work_submissions`), /permission denied/, 'but no table');
  await assert.rejects(lk((t) => t`select app.work_tick()`), NO, 'nor another module\'s function');
  await assert.rejects(lk((t) => t`select app.log_witness_report(null, null, now(), null)`), NO);
  // And the site's login can't take the looks role, so db/index.js's looks transaction fails there at once.
  await assert.rejects(db.looksTx(web, (t) => t`select 1`), /permission denied to set role "dog_looks"/);
  // The coverage check refuses the looks login with more than its one plain membership.
  const { problems } = require('../db/checks');
  await q('grant dog_app to dog_looks_web');
  try {
    assert.ok((await problems(su)).some((p) => /dog_looks_web belongs to dog_app, dog_looks/.test(p)));
  } finally { await q('revoke dog_app from dog_looks_web'); }
});

test('057: the coverage check passes; dog_looks and dog_witness can\'t sign in, belong to no role, hold no table right and run only their own functions', async () => {
  const { problems } = require('../db/checks');
  const snapshot = read('db/snapshot.txt').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
  for (const role of ['dog_looks', 'dog_witness']) {
    const [r] = await q(`select rolcanlogin, rolinherit, rolbypassrls, (select count(*)::int from pg_auth_members m join pg_roles g on g.oid = m.roleid where m.member = r.oid) as member_of
      from pg_roles r where rolname = '${role}'`);
    assert.deepStrictEqual(r, { rolcanlogin: false, rolinherit: false, rolbypassrls: false, member_of: 0 }, role);
    const [tables] = await q(`select count(*)::int as n from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'app' and c.relkind = 'r' and has_table_privilege('${role}', c.oid, 'select, insert, update, delete')`);
    assert.strictEqual(tables.n, 0, role);
  }
  const fns = async (role) => (await q(`select p.oid::regprocedure::text as fn from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'app' and has_function_privilege('${role}', p.oid, 'execute') order by 1`)).map((x) => x.fn);
  assert.deepStrictEqual(await fns('dog_looks'), ['app.sl_claim(integer)', 'app.sl_decide(uuid,text,text,text,jsonb,integer,text,boolean,text,integer)',
    'app.tl_claim(integer)', 'app.tl_decide(uuid,text,text,text,jsonb,text,boolean,boolean,integer)', 'app.tl_release(uuid,text)']);
  assert.deepStrictEqual(await fns('dog_witness'), ['app.log_witness_report(bigint,bytea,timestamp with time zone,text)']);
  // And the site's role runs none of the functions that record a model's or an outside system's answer.
  for (const f of ['app.sl_claim(integer)', 'app.tl_claim(integer)', 'app.tl_decide(uuid,text,text,text,jsonb,text,boolean,boolean,integer)',
    'app.sl_decide(uuid,text,text,text,jsonb,integer,text,boolean,text,integer)', 'app.log_witness_report(bigint,bytea,timestamp with time zone,text)',
    'app.log_proposal(integer,text)', 'app.work_github_sync(jsonb)']) {
    assert.strictEqual((await q(`select has_function_privilege('dog_app', '${f}', 'execute') as x`))[0].x, false, f);
  }
});
