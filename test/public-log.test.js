// The public log (038; CODING_AGENT_SPEC.md section 1, phase 2; Aaron, Nov 5: "Phase 2 we can use GItHUB for now", "2.5
// seem like it has a fix on its own"). The acceptance tests of 1.7: known answers (transparency-dev/merkle's published
// vectors, RFC 8032), a property test (every leaf of trees up to 2^16 proves), tamper tests (one byte of an entry, a
// proof node, a checkpoint, a signature or the witness's copy fails at its own step), the split-view test (two signed
// checkpoints of one size raise the witness's alarm), the offline test, and the page without JavaScript. Then the
// database: Ed25519 in SQL against Node's, the key nobody but dog_log reads, append-only for every role, what an
// agent post, a JEVs decision and a proposal decision put in the log, deletion, the checkpoint's self-check, the
// witness's reading, the endpoints, the timer route and appends at once. Database parts need TEST_DATABASE_URL.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { pathToFileURL } = require('url');
const merkle = require('../db/merkle');
const V = require('./fixtures/transparency-dev-merkle.json');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
let L, W, CLI, WIT;
const lib = async () => (L = L || (await import(pathToFileURL(path.join(root, 'verifier/lib.js')).href)));
const sha = (b) => crypto.createHash('sha256').update(b).digest();
const RFC8032_1 = { seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', pub: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  sig: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b' };
const nodeKey = (seed) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
const nodePub = (seed) => crypto.createPublicKey(nodeKey(seed)).export({ format: 'der', type: 'spki' }).subarray(12);

// ---- Known answers ----
test('known answers: every transparency-dev/merkle probe (196, valid and broken) is judged as published, and the prover makes the published roots and proofs', async () => {
  const l = await lib();
  const u = (x) => (x == null ? new Uint8Array() : l.unb64(x));
  let n = 0;
  for (const [k, p] of Object.entries(V.inclusion)) {
    assert.strictEqual(await l.verifyInclusion(p.leafIdx, p.treeSize, u(p.leafHash), (p.proof || []).map(u), u(p.root)), !p.wantErr, 'inclusion ' + k); n++;
  }
  for (const [k, p] of Object.entries(V.consistency)) {
    assert.strictEqual(await l.verifyConsistency(p.size1, p.size2, u(p.root1), u(p.root2), (p.proof || []).map(u)), !p.wantErr, 'consistency ' + k); n++;
  }
  assert.strictEqual(n, 196);
  const leaves = V.roots.leaves.map((h) => merkle.leafHash(Buffer.from(h, 'hex')));
  for (let size = 0; size <= 8; size++) {
    const t = merkle.memoryTree(leaves.slice(0, size));
    assert.strictEqual((await merkle.root(size, t.fetchNodes)).toString('hex'), V.roots.root_by_size[size], 'root of ' + size);
  }
  let made = 0;
  for (const p of Object.values(V.inclusion).filter((x) => !x.wantErr && x.treeSize <= 8)) {
    const t = merkle.memoryTree(leaves.slice(0, p.treeSize));
    assert.deepStrictEqual((await merkle.inclusionProof(p.leafIdx, p.treeSize, t.fetchNodes)).map((b) => b.toString('base64')), p.proof || []); made++;
  }
  for (const p of Object.values(V.consistency).filter((x) => !x.wantErr && x.size2 <= 8)) {
    const t = merkle.memoryTree(leaves.slice(0, p.size2));
    assert.deepStrictEqual((await merkle.consistencyProof(p.size1, p.size2, t.fetchNodes)).map((b) => b.toString('base64')), p.proof || []); made++;
  }
  assert.ok(made >= 12, made + ' published proofs reproduced');
});

test('known answers: the verifier checks RFC 8032 test 1 and Node’s own Ed25519 signatures, and refuses a changed byte', async () => {
  const l = await lib();
  assert.ok(await l.verifyEd25519(Buffer.from(RFC8032_1.sig, 'hex'), new Uint8Array(), Buffer.from(RFC8032_1.pub, 'hex')));
  assert.strictEqual(nodePub(Buffer.from(RFC8032_1.seed, 'hex')).toString('hex'), RFC8032_1.pub, 'Node agrees on the public key');
  for (let i = 0; i < 10; i++) {
    const seed = crypto.randomBytes(32), msg = crypto.randomBytes(i * 13);
    const sig = crypto.sign(null, msg, nodeKey(seed));
    assert.ok(await l.verifyEd25519(sig, msg, nodePub(seed)));
    sig[i % 64] ^= 1;
    assert.ok(!(await l.verifyEd25519(sig, msg, nodePub(seed))));
  }
});

test('canonical JSON (RFC 8785) as the verifier writes it: sorted keys, no spaces, ECMAScript strings and numbers', async () => {
  const l = await lib();
  assert.strictEqual(l.jcs({ b: [1, 'x', null, true], a: { d: 1, c: '\u0000"\\\n é😀' } }), '{"a":{"c":"\\u0000\\"\\\\\\n é😀","d":1},"b":[1,"x",null,true]}');
  assert.strictEqual(l.jcs({ '€': 1, '\r': 2, 1: 3 }), '{"\\r":2,"1":3,"€":1}', 'UTF-16 order, not JavaScript’s integer keys first');
  assert.throws(() => l.jcs(Infinity));
});

// ---- The property test ----
test('property: in random trees up to 2^16 entries, every leaf proves its inclusion and every size is consistent with the next', { timeout: 300000 }, async () => {
  const l = await lib();
  const rnd = (n) => crypto.randomInt(n);
  const sizes = [1, 2, 3, 5, 8, 9, 31, 32, 33, 100 + rnd(900), 1000 + rnd(9000), 65536];
  for (const size of sizes) {
    const leaves = Array.from({ length: size }, () => merkle.leafHash(crypto.randomBytes(8)));
    const t = merkle.memoryTree(leaves);
    const top = await merkle.root(size, t.fetchNodes);
    for (let i = 0; i < size; i++) {
      const p = await merkle.inclusionProof(i, size, t.fetchNodes);
      assert.ok(await l.verifyInclusion(i, size, leaves[i], p, top), 'leaf ' + i + ' of ' + size);
      if (i % 997 === 0) {
        assert.ok(!(await l.verifyInclusion(i, size, merkle.leafHash(crypto.randomBytes(8)), p, top)), 'another leaf doesn’t prove, at ' + i);
        assert.ok(!(await l.verifyInclusion(i, size, leaves[i], p, crypto.randomBytes(32))), 'nor against another root, at ' + i);
      }
    }
    for (let k = 0; k < 20 && size > 1; k++) {
      const m = 1 + rnd(size - 1);
      const r1 = await merkle.root(m, merkle.memoryTree(leaves.slice(0, m)).fetchNodes);
      const p = await merkle.consistencyProof(m, size, t.fetchNodes);
      assert.ok(await l.verifyConsistency(m, size, r1, top, p), m + ' to ' + size);
      if (p.length) { p[0] = Buffer.from(p[0]); p[0][0] ^= 1; assert.ok(!(await l.verifyConsistency(m, size, r1, top, p)), 'a changed proof fails'); }
    }
  }
});

// ---- The key is never the bundle's own (the independent review of Nov 5, H1 and M1) ----
async function memoryLog(seed, n, actorSeed) {
  const l = await lib();
  const pub = nodePub(seed);
  const entries = Array.from({ length: n }, (_, i) => ({ v: 1, type: i ? 'post' : 'key.registered', ts: 't' + i, actor: i ? 'agent:a' : 'log', on_behalf_of: null, subject: 'x:' + i, payload: {}, prev: null, sig: null }));
  // An entry signed by an actor key (which this log never writes in phase 2): entry 2, when a key is given.
  if (actorSeed && n > 2) entries[2].sig = crypto.sign(null, Buffer.from(l.jcs(entries[2])), nodeKey(actorSeed)).toString('base64');
  const leaves = entries.map((e) => merkle.leafHash(Buffer.from(l.jcs(e))));
  const sign = async (size, rootB64) => {
    const body = 'dayonegreat.com/log\n' + size + '\n' + rootB64 + '\n';
    return body + '\n— dayonegreat.com/log ' + Buffer.concat([Buffer.from(await l.keyId('dayonegreat.com/log', pub)), crypto.sign(null, Buffer.from(body), nodeKey(seed))]).toString('base64') + '\n';
  };
  const cp = async (size) => { const root = (await merkle.root(size, merkle.memoryTree(leaves.slice(0, size)).fetchNodes)).toString('base64'); return { size, root, note: await sign(size, root) }; };
  const bundle = async (i, size) => ({ entry: { seq: i, leaf_hash: leaves[i].toString('base64'), entry: entries[i] },
    inclusion: { index: i, size, path: (await merkle.inclusionProof(i, size, merkle.memoryTree(leaves.slice(0, size)).fetchNodes)).map((x) => x.toString('base64')) },
    checkpoint: await cp(size), log_key: { vkey: await l.vkey('dayonegreat.com/log', pub) } });
  return { pub, leaves, entries, sign, cp, bundle, vkey: await l.vkey('dayonegreat.com/log', pub) };
}
const resp = (status, body, text) => ({ ok: status >= 200 && status < 300, status, json: async () => (body === undefined ? JSON.parse(text) : body), text: async () => (text !== undefined ? text : JSON.stringify(body)) });
function gh({ copy, state, proof = (from, to) => resp(400, { error: 'The tree has only ' + from + ' entries.' }) }) {
  return async (u) => {
    const s = String(u);
    if (s.endsWith('/log-witness/checkpoint')) return copy ? resp(200, null, copy) : resp(404, null, '404');
    if (s.endsWith('/log-witness/state.json')) return state ? resp(200, state) : resp(404, null, '{}');
    const m = s.match(/consistency\?from=(\d+)&to=(\d+)/);
    if (m) return proof(Number(m[1]), Number(m[2]));
    throw new TypeError('fetch failed');
  };
}

test('H1: a bundle signed with a key of its own is never "Verified": "Key not confirmed" without a pin, "Failed" at step 5 against one', async () => {
  const l = await lib();
  const real = await memoryLog(crypto.randomBytes(32), 4);
  const evil = await memoryLog(crypto.randomBytes(32), 4);
  const forged = await evil.bundle(2, 4);
  for (const opts of [{}, { fetch: gh({}), site: '' }, { fetch: async () => { throw new TypeError('fetch failed'); }, site: '' }]) {
    const r = await l.verifyBundle(forged, opts);
    assert.strictEqual(r.status, 'key_unconfirmed', JSON.stringify(r.steps.map((s) => s.id + ':' + s.state)));
    assert.ok(!/^verified/.test(r.status));
    assert.strictEqual(r.memory, null);
  }
  // The witness's pin (the real key) refuses it at step 5, as does a key given to the CLI.
  let r = await l.verifyBundle(forged, { fetch: gh({ copy: (await real.cp(4)).note, state: { key: real.vkey } }), site: '' });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'checkpoint']);
  assert.match(r.steps.find((s) => s.id === 'checkpoint').text, /but the log’s key is/);
  r = await l.verifyBundle(forged, { pinnedKey: real.vkey });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'checkpoint']);
  // The genuine bundle passes against the same pin.
  r = await l.verifyBundle(await real.bundle(2, 4), { fetch: gh({ copy: (await real.cp(4)).note, state: { key: real.vkey } }), site: '' });
  assert.strictEqual(r.status, 'verified');
});

test('L5: a signed entry fails closed: with no actor keys registered in the log, a key the bundle names confirms nothing', async () => {
  const l = await lib();
  const actor = crypto.randomBytes(32);
  const log = await memoryLog(crypto.randomBytes(32), 4, actor);
  const b = { ...(await log.bundle(2, 4)), actor_keys: [{ actor: 'agent:a', public_key: nodePub(actor).toString('base64'), seq: 1 }] };
  const r = await l.verifyBundle(b, { pinnedKey: log.vkey });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'key']);
  assert.strictEqual(r.steps.find((x) => x.id === 'signature').state, 'pass', 'the signature itself is checked');
  assert.match(r.steps.find((x) => x.id === 'key').text, /no actor keys are registered in this log yet/);
  // The same log's unsigned entries pass against the same pin.
  assert.strictEqual((await l.verifyBundle(await log.bundle(1, 4), { pinnedKey: log.vkey })).status, 'verified_unwitnessed');
});

test('L7: the Merkle helpers split trees past 2^31 entries exactly as RFC 9162 does (no 32-bit arithmetic)', () => {
  const big = 2 ** 33;
  assert.deepStrictEqual(merkle.subtrees(0, big), [[33, 0]]);
  assert.deepStrictEqual(merkle.subtrees(0, big + 3), [[33, 0], [1, big / 2], [0, big + 2]]);
  assert.deepStrictEqual(merkle.subtrees(2 ** 31, 2 ** 32), [[31, 1]]);
  assert.strictEqual(merkle.split(2 ** 40 + 1), 2 ** 40);
});

test('M1: memory keeps only checkpoints signed by the confirmed key; a forged huge checkpoint can’t poison it, and network trouble is never a failure of the receipt', async () => {
  const l = await lib();
  const real = await memoryLog(crypto.randomBytes(32), 6);
  const evil = await memoryLog(crypto.randomBytes(32), 1);
  const copy6 = (await real.cp(6)).note;
  const net = (over = {}) => gh({ copy: copy6, state: { key: real.vkey }, ...over });
  // A forged checkpoint claiming 900,000,000,000,000 entries, signed by its own key: nothing is remembered.
  const huge = await evil.bundle(0, 1);
  huge.checkpoint = { size: 900000000000000, root: huge.checkpoint.root, note: await evil.sign(900000000000000, huge.checkpoint.root) };
  huge.inclusion = null;
  let r = await l.verifyBundle(huge, { fetch: net(), site: '', memory: null });
  assert.strictEqual(r.memory, null, 'nothing kept');
  // Without the network either.
  r = await l.verifyBundle(await evil.bundle(0, 1), {});
  assert.strictEqual(r.memory, null);
  // A genuine receipt in a browser that remembers size 4: kept as 6 when the proof comes.
  const c4 = await real.cp(4);
  const merkleTree6 = merkle.memoryTree(real.leaves);
  const goodProof = async (from, to) => resp(200, { proof: (await merkle.consistencyProof(from, to, merkleTree6.fetchNodes)).map((x) => x.toString('base64')) });
  r = await l.verifyBundle(await real.bundle(2, 6), { fetch: net({ proof: goodProof }), site: '', memory: { size: 4, root: c4.root } });
  assert.deepStrictEqual([r.status, r.memory.size, r.steps.find((s) => s.id === 'memory').state], ['verified', 6, 'pass']);
  // The proof endpoint answers 503 once, or the connection drops: step 7 isn't checked, the receipt isn't failed, memory unchanged.
  for (const proof of [async () => resp(503, { error: 'busy' }), async () => { throw new TypeError('fetch failed'); }]) {
    r = await l.verifyBundle(await real.bundle(2, 6), { fetch: net({ proof }), site: '', memory: { size: 4, root: c4.root } });
    assert.notStrictEqual(r.status, 'failed', r.reason);
    assert.strictEqual(r.steps.find((s) => s.id === 'memory').state, 'warn');
    assert.deepStrictEqual(r.memory, { size: 4, root: c4.root });
  }
  // Memory larger than the site's tree: "can't be compared", not a failure of this receipt.
  r = await l.verifyBundle(await real.bundle(2, 6), { fetch: net(), site: '', memory: { size: 9, root: c4.root } });
  assert.notStrictEqual(r.status, 'failed');
  assert.match(r.steps.find((s) => s.id === 'memory').text, /the site’s tree is smaller now, so the two can’t be compared/);
  // A proven inconsistency with what this verifier saw is the log's split view: unverified, never this receipt's failure.
  r = await l.verifyBundle(await real.bundle(2, 6), { fetch: net(), site: '', memory: { size: 6, root: c4.root } });
  assert.deepStrictEqual([r.status, r.firstFailure], ['unverified', null]);
});

// ---- The pages, the workflow and the policy ----
test('the Verify page: three ARIA tabs, a live results region, focus to the banner, a Worker, and without JavaScript the CLI and the raw bundle', () => {
  const html = read('receipts.html');
  const main = html.match(/<main[\s\S]*?<\/main>/)[0];
  assert.match(main, /<h1>Receipts<\/h1>/);
  assert.match(main, /<h2 id="verify-heading">Verify a receipt<\/h2>/);
  assert.match(main, /role="tablist"/);
  for (const [tab, panel] of [['tab-paste', 'panel-paste'], ['tab-file', 'panel-file'], ['tab-link', 'panel-link']]) {
    assert.match(main, new RegExp('role="tab" id="' + tab + '" aria-controls="' + panel + '" aria-selected="(true|false)"'));
    assert.match(main, new RegExp('role="tabpanel" id="' + panel + '" aria-labelledby="' + tab + '"'));
  }
  assert.match(main, /<input type="file" id="file"/);
  assert.match(main, /<section id="result" aria-live="polite"/);
  assert.match(main, /<button class="btn p" type="submit" id="go">Verify<\/button>/);
  assert.match(main, /Export proof bundle/);
  assert.match(main, /Copy CLI command/);
  const noscript = main.match(/<noscript>[\s\S]*?<\/noscript>/)[0];
  assert.match(noscript, /node tools\/verify\/dog-verify\.mjs/);
  assert.match(noscript, /\/api\/log\/receipt\//);
  assert.ok(!/Proposed\.|Sample figures/.test(main), 'no Proposed notice or sample pill: the page is live');
  assert.match(html, /<script defer src="\/receipts\.js"><\/script>/);
  const js = read('receipts.js');
  assert.match(js, /new Worker\('\/verifier\/worker\.js', \{ type: 'module' \}\)/);
  assert.match(js, /'dog\.maxCheckpoint'/);
  assert.match(js, /ArrowRight[\s\S]*ArrowLeft[\s\S]*Home[\s\S]*End/);
  assert.match(js, /\$\('banner'\)\.focus\(\)/);
  assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function/.test(js + read('receipt.js') + read('security.js') + read('log-health.js') + read('verifier/worker.js')));
  assert.match(js, /try \{ var m = JSON\.parse\(localStorage/, 'storage is read inside try');
  // The receipt detail: the design's facts, its log entry checked in the browser, and a Verify action.
  const r = read('receipt.html');
  assert.match(r, /<script defer src="\/receipt\.js"><\/script>/);
  assert.match(r, /id="verify-link" href="\/receipts">Verify step by step/);
  assert.match(read('receipt.js'), /new Worker\('\/verifier\/worker\.js'/);
});

test('/security publishes where the key is read, the witness, the verifier’s hashes as they are, and no claim the code doesn’t bear out', () => {
  const html = read('security.html');
  const main = html.match(/<main[\s\S]*?<\/main>/)[0];
  assert.ok(!/Proposed\./.test(html), 'no Proposed notice: the page is live');
  assert.ok(!/header that works but is not documented/.test(html), 'the gate checks a signed GitHub Actions token against GitHub’s published keys, not an undocumented header');
  for (const f of ['verifier/lib.js', 'verifier/worker.js', 'verifier/log-key.js', 'verifier/noble-ed25519-2.3.0.js', 'tools/verify/dog-verify.mjs']) {
    assert.ok(main.includes(sha(fs.readFileSync(path.join(root, f))).toString('hex')), f + '’s SHA-256 is the published one (rebuild with tools/design/build.js)');
  }
  assert.match(main, /id="log"/);
  assert.match(main, /id="key-vkey"/);
  assert.match(main, /Not arranged/);
  assert.match(html, /<script defer src="\/security\.js"><\/script>/);
  // The vendored library is npm's 2.3.0, byte for byte (its published integrity).
  const noble = fs.readFileSync(path.join(root, 'verifier/noble-ed25519-2.3.0.js'));
  assert.strictEqual(sha(noble).toString('hex'), '70cebecaaa6a126ced702198706c49d03f2d6f70317342b75e50e8d2d4951fe5');
  assert.match(read('verifier/noble-ed25519-2.3.0.LICENSE'), /MIT License/);
});

test('the witness workflow: on a schedule, only its own GITHUB_TOKEN, contents and issues only, pinned actions, the branch log-witness', () => {
  const y = read('.github/workflows/log-witness.yml');
  assert.match(y, /schedule:\n\s+- cron: '4,19,34,49 \* \* \* \*'/);
  assert.match(y, /^permissions: \{\}$/m);
  assert.match(y, /permissions:\n\s+contents: write\n\s+issues: write\n/);
  assert.deepStrictEqual([...y.matchAll(/secrets\.([A-Z_]+)/g)].map((m) => m[1]).filter((x, i, a) => a.indexOf(x) === i), ['GITHUB_TOKEN']);
  for (const m of y.matchAll(/uses: ([^\s]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, 'pinned: ' + m[1]);
  assert.match(y, /origin log-witness/);
  assert.ok(!/\$\{\{\s*github\.event/.test(y), 'no event text in a run step');
  const v = JSON.parse(read('vercel.json'));
  assert.ok(v.rewrites.some((r) => r.source === '/api/log/:path*' && r.destination === '/api/log?route=:path*'));
  assert.ok(v.rewrites.some((r) => r.source === '/receipts/:id' && r.destination === '/receipt'), 'the old and new receipt addresses both keep working');
  const csp = (src) => v.headers.find((h) => h.source === src).headers.find((h) => h.key === 'Content-Security-Policy').value;
  assert.match(csp('/(receipts?|receipts/.*|verifier/.*)'), /connect-src 'self' https:\/\/raw\.githubusercontent\.com\/MyChiefOS\/start-of-something-great\/log-witness\/;/,
    'the receipt pages and the verifier may read the witness’s branch, and nothing else outside (the review of 038, L3)');
  assert.match(csp('/((?!talk/?$|join/?$|account/?$|auth/|receipts?$|receipts/|verifier/).*)'), /connect-src 'self';/, 'no other page may');
});

test('the command line: no input is exit 3, with the usage', async () => {
  CLI = CLI || (await import(pathToFileURL(path.join(root, 'tools/verify/dog-verify.mjs')).href));
  const out = [];
  assert.strictEqual(await CLI.main([], { out: (s) => out.push(s) }), 3);
  assert.match(out.join('\n'), /usage: node tools\/verify\/dog-verify\.mjs/);
});

// ---- The database ----
const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('public log tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the public log against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const logdb = require('../db/log');
const { migrate } = require('../scripts/migrate');
const { problems } = require('../db/checks');
const { promote, shadowMode, asSignin } = require('./helpers');

const NAME = 'dog_publog_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
const ORIGIN = 'https://dayonegreat.com';
const CFG = { ipKey: crypto.randomBytes(32) };
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const anon = (fn) => run({ actor: 'anon' }, fn);
const as = (role, fn) => su.begin(async (t) => { await t.unsafe('set local role ' + role); return fn(t); });

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 4, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 4 });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
async function member(name) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level: 1, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
  await promote(su, out.memberId);
  await su`update app.members set display_name = ${name} where id = ${out.memberId}`;
  return { id: out.memberId, cookie: '__Host-dog_session=' + token, ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}
const agentsApi = async (method, route, { cookie, json, key } = {}) => {
  const headers = { host: 'dayonegreat.com', cookie: cookie || '', 'x-vercel-forwarded-for': '203.0.113.41', origin: ORIGIN };
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  const out = res();
  await require('../api/agents.js').handle({ method, url: '/api/agents/' + route, headers, query: { route }, body: json !== undefined ? JSON.stringify(json) : undefined }, out, run, CFG);
  return { status: out.statusCode, json: out.body ? JSON.parse(out.body) : null };
};
async function agent(owner, name) {
  const r = await agentsApi('POST', '', { cookie: owner.cookie, json: { name, post: 'act' } });
  assert.strictEqual(r.status, 201, JSON.stringify(r.json));
  return { id: r.json.agent_id, key: r.json.key };
}
async function say(a, body) {
  const out = res();
  await require('../api/feed.js').handle({ method: 'POST', url: '/api/feed', headers: { host: 'dayonegreat.com', 'content-type': 'application/json', authorization: 'Bearer ' + a.key }, query: {}, body: JSON.stringify({ body }) }, out, run);
  assert.strictEqual(out.statusCode, 201, out.body);
  return JSON.parse(out.body).id;
}
// The log's endpoints, called as Vercel would after the rewrite.
async function logGet(p) {
  const [route, qs] = p.split('?');
  const out = res();
  await require('../api/log.js').handle({ method: 'GET', url: '/api/log?route=' + encodeURIComponent(route) + (qs ? '&' + qs : ''), headers: {}, query: { route } }, out, run);
  return { status: out.statusCode, json: JSON.parse(out.body), cache: out.headers['cache-control'], headers: out.headers };
}
// A fake network for the verifier and the witness: this site's /api/log through its handler, and GitHub's raw copy.
function network(witness = {}) {
  const resp = (status, body, text) => ({ ok: status >= 200 && status < 300, status, headers: { get: () => null }, json: async () => body, text: async () => (text !== undefined ? text : JSON.stringify(body)) });
  return async (url) => {
    const u = String(url);
    if (u === 'https://raw.githubusercontent.com/MyChiefOS/start-of-something-great/log-witness/checkpoint') return witness.copy ? resp(200, null, witness.copy) : resp(404, null, '404');
    if (u === 'https://raw.githubusercontent.com/MyChiefOS/start-of-something-great/log-witness/state.json') return witness.state ? resp(200, witness.state) : resp(404, null);
    const m = u.match(/^(?:https:\/\/dayonegreat\.com)?\/api\/log\/(.*)$/);
    if (!m) throw new Error('no network in tests: ' + u);
    const r = await logGet(m[1]);
    return resp(r.status, r.json);
  };
}
const checkpointNow = async () => {
  // The timer route signs when the last checkpoint is 60 seconds old; tests age it, as the clock would.
  await su.begin(async (t) => {
    await t.unsafe('alter table app.log_checkpoints disable trigger log_checkpoints_no_change');
    await t`update app.log_checkpoints set created_at = created_at - interval '2 minutes'`;
    await t.unsafe('alter table app.log_checkpoints enable always trigger log_checkpoints_no_change');
  });
  const [r] = await anon((t) => t`select app.log_checkpoint() as n`);
  return Number(r.n);
};

test('the database passes the coverage check with the log (S1, S7, S8, G3), and the migration left the key and entry 0', async () => {
  const snapshot = read('db/snapshot.txt').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepStrictEqual(await problems(su, { snapshot }), []);
  const [e0] = await su`select entry_jcs from app.log_entries where seq = 0`;
  const e = JSON.parse(e0.entry_jcs);
  const [k] = await su`select public_key, key_id from app.log_keys`;
  assert.deepStrictEqual([e.type, e.actor, e.payload.public_key, e.subject], ['key.registered', 'log', k.public_key.toString('base64'), 'key:' + k.key_id.toString('hex')]);
});

test('Ed25519 in the database equals RFC 8032 test 1 and Node’s Ed25519 on random keys and messages', async () => {
  const [v] = await su`select app.log_ed25519_public(${Buffer.from(RFC8032_1.seed, 'hex')}) as pub, app.log_ed25519_sign(${Buffer.from(RFC8032_1.seed, 'hex')}, ''::bytea) as sig`;
  assert.deepStrictEqual([v.pub.toString('hex'), v.sig.toString('hex')], [RFC8032_1.pub, RFC8032_1.sig]);
  for (let i = 0; i < 12; i++) {
    const seed = crypto.randomBytes(32), msg = crypto.randomBytes(i * 17);
    const [r] = await su`select app.log_ed25519_public(${seed}) as pub, app.log_ed25519_sign(${seed}, ${msg}) as sig`;
    assert.ok(nodePub(seed).equals(r.pub), 'public key ' + i);
    assert.ok(crypto.sign(null, msg, nodeKey(seed)).equals(r.sig), 'signature ' + i);
  }
});

test('canonical JSON: the database writes exactly what the verifier recomputes, for every character below U+0080 and beyond', async () => {
  const l = await lib();
  const chars = Array.from({ length: 128 }, (_, i) => String.fromCharCode(i)).filter((ch) => ch !== '\u0000').join('') + 'é€😀  ﻿';
  for (const s of [chars, 'plain', '', '"quoted" \\ back/slash', Array.from(chars).reverse().join('')]) {
    const obj = { b: s, a: [1, null, true, false, { z: s, y: 0 }], c: -42 };
    const [r] = await su`select app.log_jcs(${su.json(obj)}::jsonb) as j`;
    assert.strictEqual(r.j, l.jcs(obj));
  }
  await assert.rejects(su`select app.log_jcs('{"Upper": 1}'::jsonb)`, /lower-case/);
  assert.strictEqual((await su`select app.log_jcs('{"body_sha256": "x", "a_1": 2}'::jsonb) as j`)[0].j, '{"a_1":2,"body_sha256":"x"}', 'digits and _ in keys, in byte order');
  await assert.rejects(su`select app.log_jcs('{"a": 1.5}'::jsonb)`, /whole numbers/);
});

test('the key: only dog_log reads its seed; the site may read no seed, no opening, and may not sign, append or seal', async () => {
  for (const q of ['select seed from app.log_keys', 'select key from app.log_openings', 'select * from app.log_proposals_seen',
    "select app.log_append('post', now(), 'agent:x', null, 'post:x', '{}'::jsonb)", "select app.log_seal('\\x00'::bytea, '{}'::jsonb)",
    "select app.log_ed25519_sign('\\x00'::bytea, '\\x00'::bytea)"]) {
    await assert.rejects(anon((t) => t.unsafe(q)), /permission denied/, q);
  }
  for (const role of ['dog_public', 'dog_jevs', 'dog_signin', 'dog_erase', 'dog_owner']) {
    const rows = await as(role, (t) => t.unsafe('select seed from app.log_keys')).then((x) => x, (e) => e);
    assert.ok(rows instanceof Error || rows.length === 0, role + ' reads no seed');
  }
  const [k] = await as('dog_log', (t) => t`select octet_length(seed) as n from app.log_keys`);
  assert.strictEqual(k.n, 32);
  const [pub] = await anon((t) => t`select public_key from app.log_keys`);
  assert.strictEqual(pub.public_key.length, 32, 'the public half is public');
});

test('append-only: no role, the superuser included, changes or deletes an entry, a node, a checkpoint or the key', async () => {
  await checkpointNow();
  const count = async () => (await su`select (select count(*) from app.log_entries)::int as e, (select count(*) from app.log_nodes)::int as n,
                                              (select count(*) from app.log_checkpoints)::int as c, (select count(*) from app.log_keys)::int as k`)[0];
  const before = await count();
  for (const tbl of ['log_entries', 'log_nodes', 'log_checkpoints', 'log_keys']) {
    await assert.rejects(su.unsafe(`update app.${tbl} set id = id`), /append-only/, 'superuser update ' + tbl);
    await assert.rejects(su.unsafe(`delete from app.${tbl}`), /append-only/, 'superuser delete ' + tbl);
    await assert.rejects(su.unsafe(`truncate app.${tbl} cascade`), /append-only/, 'superuser truncate ' + tbl);
    await assert.rejects(as('dog_log', (t) => t.unsafe(`delete from app.${tbl}`)), /append-only|permission denied/, 'dog_log delete ' + tbl);
    await as('dog_owner', (t) => t.unsafe(`delete from app.${tbl}`)).catch(() => {}); // forced RLS: the owner sees no rows
  }
  await assert.rejects(as('dog_log', (t) => t`update app.log_head set size = 0`), /only grows/);
  assert.deepStrictEqual(await count(), before);
});

let owner, bot, postId;
test('an agent post goes in the log as it goes live: typed IDs, the actor’s chain, sealed facts that open with the receipt’s key', async () => {
  owner = await member('Owner of a bot');
  bot = await agent(owner, 'Log bot');
  postId = await say(bot, 'the first post for the log');
  const second = await say(bot, 'and a second one');
  const rows = await su`select seq, entry_jcs from app.log_entries where subject in (${'post:' + postId}, ${'post:' + second}) order by seq`;
  assert.strictEqual(rows.length, 2);
  const [e1, e2] = rows.map((r) => JSON.parse(r.entry_jcs));
  // The agent and the member by the log's random names, never their own IDs (the review of 038, M2).
  const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  assert.deepStrictEqual([e1.type, e1.subject, e1.v, e1.sig], ['post', 'post:' + postId, 1, null]);
  assert.match(e1.actor, /^agent:/); assert.match(e1.on_behalf_of, /^member:/);
  assert.match(e1.actor.slice(6), V4); assert.match(e1.on_behalf_of.slice(7), V4);
  assert.ok(!rows[0].entry_jcs.includes(bot.id) && !rows[0].entry_jcs.includes(owner.id), 'no account ID in the entry');
  assert.deepStrictEqual([e2.actor, e2.on_behalf_of], [e1.actor, e1.on_behalf_of], 'the same names for the same agent and member');
  assert.strictEqual(e1.prev, null, 'the agent’s first entry');
  const [leaf1] = await su`select leaf_hash from app.log_entries where seq = ${rows[0].seq}`;
  assert.strictEqual(e2.prev, leaf1.leaf_hash.toString('hex'), 'each entry points at the same actor’s previous one');
  assert.deepStrictEqual(Object.keys(e1.payload), ['facts']);
  assert.ok(!rows[0].entry_jcs.includes('the first post'), 'never the text');
  const [o] = await anon((t) => t`select key, facts from app.log_opening(${rows[0].seq})`);
  assert.strictEqual(sha(Buffer.concat([o.key, Buffer.from((await lib()).jcs(o.facts))])).toString('hex'), e1.payload.facts);
  assert.deepStrictEqual([o.facts.post, o.facts.agent, o.facts.owner, o.facts.delegation, o.facts.body_sha256],
    [postId, bot.id, owner.id, 'rules', sha(Buffer.from('the first post for the log')).toString('hex')]);
  // A people post isn't logged; a post logged once isn't logged twice.
  const n = Number((await su`select size from app.log_head`)[0].size);
  await su`update app.posts set status = 'removed' where id = ${second}`.catch(() => {});
  assert.strictEqual(Number((await su`select size from app.log_head`)[0].size), n);
});

test('a receipt’s proof bundle verifies in full with the witness’s copy, and fails at its own step when one byte changes (1.7 tamper tests)', async () => {
  const l = await lib();
  await checkpointNow();
  const cp = (await logGet('checkpoint')).json;
  const net = network({ copy: cp.checkpoint.note, state: { key: cp.log_key.vkey, good: { size: cp.checkpoint.size, root: cp.checkpoint.root } } });
  const b = (await logGet('receipt/' + postId)).json;
  assert.strictEqual(b.kind, 'dayonegreat.com/log proof bundle');
  assert.ok(b.opening && b.inclusion && b.checkpoint);
  const ok = await l.verifyBundle(b, { fetch: net, site: '' });
  assert.strictEqual(ok.status, 'verified', JSON.stringify(ok.steps, null, 1));
  assert.deepStrictEqual(ok.steps.map((s) => s.id + ':' + s.state), ['entry:pass', 'signature:na', 'key:na', 'inclusion:pass', 'checkpoint:pass', 'witness:pass', 'memory:info', 'delegation:na']);
  // With what it remembered, the next check is against that checkpoint too.
  const again = await l.verifyBundle(b, { fetch: net, site: '', memory: ok.memory });
  assert.strictEqual(again.steps.find((s) => s.id === 'memory').state, 'pass');
  const flip = (s, i) => { const ch = s[i] === 'A' ? 'B' : 'A'; return s.slice(0, i) + ch + s.slice(i + 1); };
  const tamper = async (change) => { const x = JSON.parse(JSON.stringify(b)); change(x); return l.verifyBundle(x, { fetch: net, site: '' }); };
  // One byte of the entry.
  let r = await tamper((x) => { x.entry.entry.ts = x.entry.entry.ts.replace(/\d(?=Z$)/, (d) => String((Number(d) + 1) % 10)); });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'entry']);
  r = await tamper((x) => { x.entry.entry.subject = x.entry.entry.subject.replace(/.$/, (ch) => (ch === 'a' ? 'b' : 'a')); });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'entry']);
  // One byte of a proof node.
  r = await tamper((x) => { x.inclusion.path[0] = flip(x.inclusion.path[0], 3); });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'inclusion']);
  // One byte of the checkpoint's signed text, and one of its signature.
  r = await tamper((x) => { x.checkpoint.note = x.checkpoint.note.replace(/\n[A-Za-z0-9+/]{4}/, (m) => m.slice(0, 2) + (m[2] === 'A' ? 'B' : 'A') + m.slice(3)); });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'checkpoint']);
  r = await tamper((x) => { const i = x.checkpoint.note.lastIndexOf(' ') + 10; x.checkpoint.note = flip(x.checkpoint.note, i); });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'checkpoint']);
  // A forged key in the bundle can't pass a pinned key.
  const other = await l.vkey('dayonegreat.com/log', nodePub(crypto.randomBytes(32)));
  r = await l.verifyBundle(b, { fetch: net, site: '', pinnedKey: other });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'checkpoint']);
  // The sealed facts must open to this receipt.
  r = await tamper((x) => { x.opening.facts.rules_version = 99; });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'entry']);
  // One byte of the witness's copy (its cosignature, in this phase the signed copy it keeps): Unverified at step 6.
  const sigAt = cp.checkpoint.note.lastIndexOf(' ') + 12;
  r = await l.verifyBundle(b, { fetch: network({ copy: flip(cp.checkpoint.note, sigAt) }), site: '' });
  assert.strictEqual(r.status, 'unverified');
  assert.strictEqual(r.steps.find((s) => s.id === 'witness').state, 'fail');
  assert.strictEqual(r.firstFailure, null, 'every hard check still passed, and none is hidden');
  // The witness's alarm marks the record unverified (Aaron: "marks the log unverified").
  r = await l.verifyBundle(b, { fetch: network({ copy: cp.checkpoint.note, state: { key: cp.log_key.vkey, alarm: { reason: 'Split view: two different signed checkpoints of 3 entries.' } } }), site: '' });
  assert.strictEqual(r.status, 'unverified');
  assert.match(r.reason, /Split view/);
});

test('offline: a bundle verifies with the network off (steps 1 to 5) only against a key it already knows; the witness is shown as not checked, never as passed', async () => {
  const l = await lib();
  const b = (await logGet('receipt/' + postId)).json;
  const vk = (await logGet('checkpoint')).json.log_key.vkey;
  // No key known offline: never any kind of "Verified" (the review's H1).
  let r = await l.verifyBundle(b, { fetch: null });
  assert.strictEqual(r.status, 'key_unconfirmed');
  assert.strictEqual(r.steps.find((s) => s.id === 'checkpoint').state, 'warn');
  assert.strictEqual(r.memory, null, 'an unconfirmed key’s checkpoint is never remembered');
  // With the log's key given (as --key, or as verifier/log-key.js will pin it).
  r = await l.verifyBundle(b, { fetch: null, pinnedKey: vk });
  assert.strictEqual(r.status, 'verified_unwitnessed');
  assert.deepStrictEqual(r.steps.filter((s) => s.state === 'pass').map((s) => s.id), ['entry', 'inclusion', 'checkpoint']);
  assert.match(r.steps.find((s) => s.id === 'witness').text, /needs the network/);
  // The command line, offline, from a bundle file: exit 1 without a known key or with one but unwitnessed, 2 for a changed one.
  CLI = CLI || (await import(pathToFileURL(path.join(root, 'tools/verify/dog-verify.mjs')).href));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-verify-'));
  fs.writeFileSync(path.join(dir, 'a.dogproof.json'), JSON.stringify(b));
  const out = [];
  assert.strictEqual(await CLI.main([path.join(dir, 'a.dogproof.json'), '--offline'], { out: (s) => out.push(s) }), 1);
  assert.match(out[0], /^Key not confirmed/);
  out.length = 0;
  assert.strictEqual(await CLI.main([path.join(dir, 'a.dogproof.json'), '--offline', '--key', vk], { out: (s) => out.push(s) }), 1);
  assert.match(out[0], /^Verified, not yet witnessed/);
  const bad = JSON.parse(JSON.stringify(b)); bad.inclusion.path[0] = Buffer.alloc(32).toString('base64');
  fs.writeFileSync(path.join(dir, 'b.dogproof.json'), JSON.stringify(bad));
  assert.strictEqual(await CLI.main([path.join(dir, 'b.dogproof.json'), '--offline', '--key', vk], { out: () => {} }), 2);
  // Online, by ID, with the witness's pin and copy covering it: exit 0.
  const cp = (await logGet('checkpoint')).json;
  assert.strictEqual(await CLI.main([postId, '--remember', path.join(dir, 'max.json')], { fetchImpl: network({ copy: cp.checkpoint.note, state: { key: vk } }), out: () => {} }), 0);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(dir, 'max.json'), 'utf8')).size, cp.checkpoint.size);
  // The site's key isn't the witness's pin: step 5 fails (a site serving another key).
  const other = await l.vkey('dayonegreat.com/log', nodePub(crypto.randomBytes(32)));
  r = await l.verifyBundle(b, { fetch: network({ copy: cp.checkpoint.note, state: { key: other } }), site: '' });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'checkpoint']);
  // pin-key.mjs writes the key only when the site, entry 0 and the witness's pin agree.
  const PIN = await import(pathToFileURL(path.join(root, 'tools/verify/pin-key.mjs')).href);
  const pinned = await PIN.pinKey({ site: '', fetchImpl: network({ state: { key: vk } }) });
  assert.match(pinned.text, new RegExp('^export const PINNED_VKEY = ' + JSON.stringify(vk).replace(/[+/.]/g, '\\$&') + ';$', 'm'));
  await assert.rejects(PIN.pinKey({ site: '', fetchImpl: network({ state: { key: other } }) }), /the witness on GitHub pinned another key/);
});

test('the witness keeps each checkpoint, re-hashes the entries, and raises the alarm on a split view (1.7), keeping the last good one', async () => {
  WIT = WIT || (await import(pathToFileURL(path.join(root, 'tools/verify/witness.mjs')).href));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'log-witness-'));
  const site = network();
  let out = await WIT.witness({ dir, site: '', fetchImpl: site, cap: 3 });
  assert.strictEqual(out.alarm, null, JSON.stringify(out.state));
  const cp = (await logGet('checkpoint')).json.checkpoint;
  assert.strictEqual(fs.readFileSync(path.join(dir, 'checkpoint'), 'utf8'), cp.note);
  assert.strictEqual(out.state.rehashed, 3, 'capped runs re-hash part, and prove that part starts the signed tree');
  out = await WIT.witness({ dir, site: '', fetchImpl: site });
  assert.deepStrictEqual([out.alarm, out.state.rehashed], [null, cp.size]);
  // The log grows: still consistent.
  await say(bot, 'a third post, after the witness');
  await checkpointNow();
  out = await WIT.witness({ dir, site: '', fetchImpl: site });
  assert.strictEqual(out.alarm, null);
  const good = JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8')).good;
  // A second, validly signed checkpoint of the same size with another root (the log's key used to lie).
  const [k] = await as('dog_log', (t) => t`select seed, key_id from app.log_keys`);
  const body = 'dayonegreat.com/log\n' + good.size + '\n' + crypto.randomBytes(32).toString('base64') + '\n';
  const [s] = await su`select app.log_ed25519_sign(${k.seed}, ${Buffer.from(body)}) as sig`;
  const forged = body + '\n— dayonegreat.com/log ' + Buffer.concat([k.key_id, s.sig]).toString('base64') + '\n';
  const lying = async (url) => (String(url) === '/api/log/checkpoint' ? { ok: true, status: 200, json: async () => ({ ...(await (await site(url)).json()), checkpoint: { ...cp, size: good.size, note: forged } }) } : site(url));
  out = await WIT.witness({ dir, site: '', fetchImpl: lying });
  assert.match(String(out.alarm), /^Split view: two different signed checkpoints of \d+ entries\.$/);
  const st = JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8'));
  assert.deepStrictEqual(st.good, good, 'the last good checkpoint is kept');
  assert.strictEqual(st.alarm.seen, forged, 'with the checkpoint it saw');
  // A site that doesn't answer is not an alarm.
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'log-witness-'));
  out = await WIT.witness({ dir: dir2, site: '', fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }) });
  assert.deepStrictEqual([out.alarm, Boolean(out.state.last_error)], [null, true]);
});

test('the site reads the witness: a matching copy is "ok"; a copy that disagrees or an alarm marks the log unverified, alerts Aaron in his inbox, stays so until a reviewed migration clears it, and nothing stops', async () => {
  const jobs = require('../db/logjobs');
  const cp = (await logGet('checkpoint')).json.checkpoint;
  const state = (over) => ({ good: { size: cp.size, root: cp.root }, last_run: new Date().toISOString(), ...over });
  const fetchState = (s) => async () => ({ ok: true, status: 200, json: async () => s });
  jobs._reset();
  let out = await jobs.run(run, { fetchImpl: fetchState(state()) });
  assert.strictEqual(out.witness, 'ok');
  const w = (await logGet('checkpoint')).json.witnesses[0].site_reading;
  assert.deepStrictEqual([w.status, w.witness_size], ['ok', cp.size]);
  // No copy on the branch (not made yet): nothing to compare, so "unknown", never an alarm.
  jobs._reset();
  out = await jobs.run(run, { fetchImpl: async () => ({ ok: false, status: 404, json: async () => ({}) }) });
  assert.strictEqual(out.witness, 'unknown');
  assert.strictEqual((await su`select count(*)::int as n from app.notices where dedupe_key like 'log.%'`)[0].n, 0);
  // A copy of the same size with another root.
  jobs._reset();
  out = await jobs.run(run, { fetchImpl: fetchState(state({ good: { size: cp.size, root: crypto.randomBytes(32).toString('base64') } })) });
  assert.strictEqual(out.witness, 'unverified');
  const n = await su`select title, body, link from app.notices where member_id is null and kind = 'alert' and dedupe_key like 'log.unverified.%'`;
  assert.strictEqual(n.length, 1);
  assert.match(n[0].body, /doesn't match this log's tree\. The site keeps running/);
  // Asked again, the same reason alerts once.
  jobs._reset();
  await jobs.run(run, { fetchImpl: fetchState(state({ good: { size: cp.size, root: crypto.randomBytes(32).toString('base64') } })) });
  assert.strictEqual((await su`select count(*)::int as n from app.notices where dedupe_key like 'log.unverified.%'`)[0].n, 1, 'one alert per reason, however often it is read');
  // A bundle says so, and agents keep posting.
  const b = (await logGet('receipt/' + postId)).json;
  assert.strictEqual(b.site_status.status, 'unverified');
  await say(bot, 'still posting while the log is unverified');
  // The review of 038, M3: a matching copy, sent by the site's own login, doesn't clear it.
  jobs._reset();
  assert.strictEqual((await jobs.run(run, { fetchImpl: fetchState(state()) })).witness, 'unverified', 'the alarm stays');
  const [head] = await su`select size, app.log_root(size) as root from app.log_head`;
  assert.strictEqual((await anon((t) => t`select app.log_witness_report(${Number(head.size)}, ${head.root}, now(), null) as s`))[0].s, 'unverified', 'not even with the tree\'s own root');
  assert.strictEqual((await logGet('checkpoint')).json.witnesses[0].site_reading.alarm_until_cleared, true);
  await assert.rejects(anon((t) => t`select app.log_clear_alarm('the site tries to clear its own alarm')`), /permission denied/);
  // A reviewed migration clears it, and the clearing is itself an entry in the log, public.
  const [cleared] = await as('dog_owner', (t) => t`select app.log_clear_alarm('Checked: a test copy with a random root, not a real split view.') as seq`);
  const [e] = await su`select entry_jcs from app.log_entries where seq = ${cleared.seq}`;
  const entry = JSON.parse(e.entry_jcs);
  assert.deepStrictEqual([entry.type, entry.actor, entry.subject], ['log.alarm_cleared', 'log', 'log:witness']);
  assert.match(entry.payload.reason, /doesn't match this log's tree/);
  jobs._reset();
  assert.strictEqual((await jobs.run(run, { fetchImpl: fetchState(state()) })).witness, 'ok');
  // The witness's own alarm, the same way: it stays until a migration clears it.
  jobs._reset();
  out = await jobs.run(run, { fetchImpl: fetchState(state({ alarm: { reason: 'Split view: two different signed checkpoints of 5 entries.' } })) });
  assert.strictEqual(out.witness, 'unverified');
  assert.match((await logGet('checkpoint')).json.witnesses[0].site_reading.reason, /raised an alarm: Split view/);
  jobs._reset();
  assert.strictEqual((await jobs.run(run, { fetchImpl: fetchState(state()) })).witness, 'unverified');
  await as('dog_owner', (t) => t`select app.log_clear_alarm('Checked: a test alarm, not a real split view.')`);
  jobs._reset();
  assert.strictEqual((await jobs.run(run, { fetchImpl: fetchState(state()) })).witness, 'ok');
});

test('JEVs’s batch waits for the hour to end, takes at most 250 a call, runs one call at a time, and logs each decision once under a random ID', async () => {
  const ins = (when) => su`insert into app.jevs_decisions (created_at, action, subject_kind, subject_id, member_id, level, mode, effect, applied, error, total, scores)
    values (${when}::timestamptz, 'post.create', 'post', ${crypto.randomUUID()}, ${owner.id}, 'low', 'shadow', 'none', false, false, 0, '{}') returning id`;
  const queued = async (id) => (await su`select count(*)::int as n from app.log_queue where decision_id = ${id}`)[0].n;
  const opened = async (id) => (await su`select count(*)::int as n from app.log_openings where decision_id = ${id}`)[0].n;
  // This hour's decision waits in the queue, however often the batch is asked.
  const [now] = await ins(new Date().toISOString());
  assert.strictEqual(await queued(now.id), 1, 'queued in the decision’s own transaction');
  for (let i = 0; i < 3; i++) await anon((t) => t`select app.log_jevs_hours() as n`);
  assert.deepStrictEqual([await queued(now.id), await opened(now.id)], [1, 0], 'nothing from an hour that hasn’t ended');
  // 260 decisions of an hour that has ended: 250, then 10, then none; each once.
  const past = new Date(Date.now() - 2 * 3600e3).toISOString();
  const ids = [];
  for (let i = 0; i < 260; i++) ids.push((await ins(past))[0].id);
  const counts = [];
  for (let i = 0; i < 3; i++) counts.push((await anon((t) => t`select app.log_jevs_hours() as n`))[0].n);
  assert.deepStrictEqual(counts, [250, 10, 0]);
  const rows = await su`select o.decision_id, e.subject, e.entry_jcs from app.log_openings o join app.log_entries e on e.seq = o.seq where o.decision_id = any(${ids}::uuid[])`;
  assert.strictEqual(rows.length, 260, 'each decision once');
  assert.ok(rows.every((r) => /^decision:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.subject)), 'a random (v4) ID, which carries no time');
  assert.ok(rows.every((r) => !r.entry_jcs.includes(r.decision_id)), 'never the decision’s own ID (UUIDv7, which carries its time)');
  assert.strictEqual(new Set(rows.map((r) => r.subject)).size, 260);
  // One call at a time: a second call while the first holds the batch's lock logs nothing.
  for (let i = 0; i < 3; i++) await ins(past);
  const [held] = await su.begin(async (t) => {
    await t`select pg_advisory_xact_lock(4038000002)`;
    return anon((x) => x`select app.log_jevs_hours() as n`);
  });
  assert.strictEqual(held.n, 0);
  assert.strictEqual((await anon((t) => t`select app.log_jevs_hours() as n`))[0].n, 3);
  // A decision erased before its turn leaves the queue without an entry.
  const [gone] = await ins(past);
  await as('dog_erase', (t) => t`delete from app.jevs_decisions where id = ${gone.id}`);
  assert.strictEqual((await anon((t) => t`select app.log_jevs_hours() as n`))[0].n, 0);
  assert.strictEqual(await queued(gone.id), 0);
});

test('JEVs’s hourly batch from a fresh database: decisions before the migration are logged by it, sealed, and erased with their decision', async () => {
  // A database of its own, with decisions in past hours before 038 runs.
  const name = NAME + '_jevs';
  await server.unsafe('create database ' + name);
  const x = postgres(at(SERVER, name), { max: 2, ssl: false, onnotice: () => {} });
  try {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'migs-'));
    for (const f of fs.readdirSync(path.join(root, 'db/migrations'))) if (f < '038') fs.copyFileSync(path.join(root, 'db/migrations', f), path.join(dir, f));
    await migrate(x, { dir });
    const ids = [];
    for (let i = 0; i < 5; i++) {
      const [r] = await x`insert into app.jevs_decisions (created_at, action, subject_kind, subject_id, level, mode, effect, applied, error, total, scores)
        values (date_trunc('hour', now()) - interval '3 hours' + ${i * 7 + ' minutes'}::interval, 'post.create', 'post', ${crypto.randomUUID()}, ${i ? 'low' : 'high'}, 'shadow', 'none', false, false, 0, '{}') returning id`;
      ids.push(r.id);
    }
    const [late] = await x`insert into app.jevs_decisions (created_at, action, subject_kind, subject_id, level, mode, effect, applied, error, total, scores)
      values (now(), 'signup', 'member', ${crypto.randomUUID()}, 'low', 'shadow', 'none', false, false, 0, '{}') returning id`;
    fs.copyFileSync(path.join(root, 'db/migrations/038_public_log.sql'), path.join(dir, '038_public_log.sql'));
    await migrate(x, { dir });
    const rows = await x`select e.seq, e.subject, e.entry_jcs, o.decision_id from app.log_entries e join app.log_openings o on o.seq = e.seq where e.type = 'jevs.decision' order by e.seq`;
    assert.strictEqual(rows.length, 5, 'every decision of a whole past hour; none from this hour');
    assert.deepStrictEqual(rows.map((r) => r.decision_id).sort(), [...ids].sort());
    const entries = rows.map((r) => JSON.parse(r.entry_jcs));
    assert.ok(entries.every((e) => e.ts === entries[0].ts && /T\d\d:00:00\.000Z$/.test(e.ts)), 'one hour stamp');
    assert.ok(entries.every((e) => /^decision:[0-9a-f-]{36}$/.test(e.subject) && !ids.includes(e.subject.slice(9))), 'random IDs, not the decisions’ own');
    const byHash = [...ids].sort((a, b) => Buffer.compare(sha(Buffer.from('site' + a)), sha(Buffer.from('site' + b))));
    assert.deepStrictEqual(rows.map((r) => r.decision_id), byHash, 'shuffled within the hour (by a hash of the ID), not in the order they were made');
    assert.ok(!rows.some((r) => /high|low|post\.create/.test(r.entry_jcs)), 'the outcome is sealed');
    assert.strictEqual((await x`select count(*)::int as n from app.log_openings where decision_id = ${late.id}`)[0].n, 0);
    assert.strictEqual((await x`select count(*)::int as n from app.log_queue where decision_id = ${late.id}`)[0].n, 1, 'this hour’s decision waits in the queue');
    // Erased with the decision (as account deletion does, in dog_erase): the key goes, the entry stays.
    const seq = rows.find((r) => r.decision_id === ids[0]).seq;
    await x.begin(async (t) => { await t.unsafe('set local role dog_erase'); await t`delete from app.jevs_decisions where id = ${ids[0]}`; });
    assert.strictEqual((await x`select count(*)::int as n from app.log_openings where seq = ${seq}`)[0].n, 0);
    assert.strictEqual((await x`select count(*)::int as n from app.log_entries where seq = ${seq}`)[0].n, 1);
  } finally {
    await x.end({ timeout: 5 });
    await server.unsafe(`drop database if exists ${name} with (force)`);
  }
});

test('Aaron’s proposal decisions: logged once per change, public facts only, from the timer route’s reading of GitHub', async () => {
  const jobs = require('../db/logjobs');
  jobs._reset();
  const list = { proposals: [{ number: 12, status: 'approved' }, { number: 13, status: 'waiting' }, { number: 14, status: 'shipped' }] };
  let out = await jobs.run(run, { getProposals: async () => list });
  assert.strictEqual(out.proposals, 2);
  jobs._reset();
  out = await jobs.run(run, { getProposals: async () => list });
  assert.strictEqual(out.proposals, 0, 'the same decisions aren’t logged twice');
  jobs._reset();
  out = await jobs.run(run, { getProposals: async () => ({ proposals: [{ number: 12, status: 'shipped' }] }) });
  assert.strictEqual(out.proposals, 1);
  const rows = (await su`select entry_jcs from app.log_entries where subject = 'proposal:12' order by seq`).map((r) => JSON.parse(r.entry_jcs));
  assert.deepStrictEqual(rows.map((e) => [e.type, e.actor, e.payload.decision]), [['proposal.decided', 'github:mychiefos', 'approved'], ['proposal.decided', 'github:mychiefos', 'shipped']]);
  assert.deepStrictEqual(Object.keys(rows[0].payload).sort(), ['decision', 'proposal']);
  await assert.rejects(anon((t) => t`select app.log_proposal(12, 'waiting')`), /approved, declined or shipped/);
  assert.strictEqual((await logGet('receipt/proposal-12')).json.entry.entry.payload.decision, 'shipped');
});

test('the endpoints: read-only, cached as the spec says, every proof verifies, and bad requests are named', async () => {
  const l = await lib();
  await checkpointNow();
  const cp = await logGet('checkpoint');
  assert.match(cp.cache, /max-age=30/);
  const size = cp.json.checkpoint.size;
  assert.ok(size >= 5);
  const all = [];
  for (let from = 0; from < size; from += 2) {
    const page = await logGet('entries?from=' + from + '&limit=2');
    all.push(...page.json.entries);
    if (from + 2 <= size) assert.match(page.cache, /immutable/, 'a full page of committed entries never changes');
  }
  const leaves = [];
  for (const e of all.slice(0, size)) {
    const leaf = await l.leafHash(l.utf8(l.jcs(e.entry)));
    assert.strictEqual(l.b64(leaf), e.leaf_hash, 'entry ' + e.seq);
    leaves.push(leaf);
  }
  const t = merkle.memoryTree(leaves.map((x) => Buffer.from(x)));
  assert.strictEqual((await merkle.root(size, t.fetchNodes)).toString('base64'), cp.json.checkpoint.root, 'the entries rebuild the signed root');
  for (const e of all.slice(0, size)) {
    const p = await logGet('proof/inclusion?leaf=' + encodeURIComponent(e.leaf_hash) + '&size=' + size);
    assert.ok(await l.verifyInclusion(e.seq, size, l.unb64(e.leaf_hash), p.json.path.map(l.unb64), l.unb64(cp.json.checkpoint.root)));
    assert.match(p.cache, /immutable/);
  }
  const hexLeaf = Buffer.from(all[1].leaf_hash, 'base64').toString('hex');
  assert.strictEqual((await logGet('proof/inclusion?leaf=' + hexLeaf + '&size=' + size)).json.leaf_index, 1);
  for (let m = 1; m < size; m++) {
    const r1 = (await merkle.root(m, merkle.memoryTree(leaves.slice(0, m).map((x) => Buffer.from(x))).fetchNodes));
    const p = await logGet('proof/consistency?from=' + m + '&to=' + size);
    assert.ok(await l.verifyConsistency(m, size, r1, l.unb64(cp.json.checkpoint.root), p.json.proof.map(l.unb64)), m + ' to ' + size);
  }
  assert.deepStrictEqual((await logGet('entry/0')).json.entry.type, 'key.registered');
  assert.match((await logGet('entry/0')).cache, /immutable/);
  for (const [p, code] of [['entry/999999', 404], ['entry/x', 400], ['entries?limit=101', 400], ['entries?from=-1', 400], ['proof/consistency?from=0&to=2', 400],
    ['proof/consistency?from=1&to=99999', 400], ['proof/inclusion?leaf=nope&size=2', 400], ['proof/inclusion?leaf=' + 'a'.repeat(64) + '&size=2', 404],
    ['receipt/' + crypto.randomUUID(), 404], ['receipt/%E0%A4%A', 400], ['receipt/' + 'x'.repeat(120), 400], ['receipt/0', 200], ['receipt/' + hexLeaf, 200], ['nothing', 404]]) {
    const r = await logGet(p);
    assert.strictEqual(r.status, code, p + ' ' + JSON.stringify(r.json));
    if (code >= 400) assert.ok(r.json.error && r.json.error.length > 10, 'a named error: ' + p);
  }
  const out = res();
  await require('../api/log.js').handle({ method: 'POST', url: '/api/log?route=checkpoint', headers: {}, query: { route: 'checkpoint' } }, out, run);
  assert.strictEqual(out.statusCode, 405);
  const off = res();
  await require('../api/log.js').handle({ method: 'GET', url: '/api/log?route=checkpoint', headers: {}, query: { route: 'checkpoint' } }, off, null);
  assert.strictEqual(JSON.parse(off.body).available, false);
});

test('the timer route runs the log’s jobs after the timers: a new entry is in a signed checkpoint within a minute', async () => {
  const cron = require('../api/cron.js');
  await su.begin(async (t) => {
    await t.unsafe('alter table app.log_checkpoints disable trigger log_checkpoints_no_change');
    await t`update app.log_checkpoints set created_at = created_at - interval '2 minutes'`;
    await t.unsafe('alter table app.log_checkpoints enable always trigger log_checkpoints_no_change');
  });
  await say(bot, 'logged and then signed by the timer route');
  const n = Number((await su`select size from app.log_head`)[0].size);
  cron._reset();
  const out = res();
  await cron.handle({ method: 'GET', headers: { 'user-agent': 'vercel-cron/1.0' } }, out, run);
  assert.strictEqual((await logGet('checkpoint')).json.checkpoint.size, n);
});

test('appends at once (agents and sub-agents posting together) keep one ordered tree with no gaps', async () => {
  const before = Number((await su`select size from app.log_head`)[0].size);
  const subjects = Array.from({ length: 40 }, () => 'post:' + crypto.randomUUID());
  await Promise.all(subjects.map((s, i) => as('dog_log', (t) => t`select app.log_append('post', now(), ${'agent:' + (i % 4)}, null, ${s}, '{"facts":"00"}'::jsonb)`)));
  const rows = await su`select seq from app.log_entries where seq >= ${before} order by seq`;
  assert.deepStrictEqual(rows.map((r) => Number(r.seq)), Array.from({ length: 40 }, (_, i) => before + i));
  await checkpointNow();
  const cp = (await logGet('checkpoint')).json.checkpoint;
  const leaves = (await su`select leaf_hash from app.log_entries order by seq`).map((r) => r.leaf_hash);
  assert.strictEqual((await merkle.root(leaves.length, merkle.memoryTree(leaves).fetchNodes)).toString('base64'), cp.root);
  const [r] = await su`select app.log_root(${cp.size}) as r`;
  assert.strictEqual(r.r.toString('base64'), cp.root, 'the database’s own root agrees');
});

test('deleting an account removes the person’s data: the receipt’s key goes, the entry stays with IDs that point at nothing, and still verifies as unchanged', async () => {
  const l = await lib();
  const [{ seq }] = await su`select seq from app.log_entries where subject = ${'post:' + postId}`;
  const del = await run({ ...owner.ctx, fresh: true }, (t) => store.deleteAccount(t));
  assert.ok(del, JSON.stringify(del));
  assert.strictEqual((await su`select count(*)::int as n from app.posts where id = ${postId}`)[0].n, 0, 'the post is gone');
  assert.strictEqual((await su`select count(*)::int as n from app.log_openings where post_id = ${postId} or seq = ${seq}`)[0].n, 0, 'its key is gone');
  const b = (await logGet('receipt/' + postId)).json;
  assert.strictEqual(b.opening, null);
  assert.strictEqual(b.entry.seq, Number(seq));
  const r = await l.verifyBundle(b, { fetch: null });
  assert.strictEqual(r.steps[0].state, 'pass', 'the entry is unchanged');
  assert.ok(!JSON.stringify(b).includes('Owner of a bot') && !JSON.stringify(b).includes('Log bot'), 'no name anywhere');
});

test('a corrupted inner node fails every receipt under it in the verifier; one the root is built from stops the next checkpoint, marks the log unverified and tells Aaron', async () => {
  const l = await lib();
  const corrupt = (level, idx) => su.begin(async (t) => {
    await t.unsafe('alter table app.log_nodes disable trigger log_nodes_no_change');
    await t`update app.log_nodes set hash = ${crypto.randomBytes(32)} where level = ${level} and idx = ${idx}`;
    await t.unsafe('alter table app.log_nodes enable always trigger log_nodes_no_change');
  });
  // Corrupt leaf 1 as only the superuser could, with the guard off for the moment: entry 0's proof uses it.
  await corrupt(0, 1);
  const b = (await logGet('receipt/0')).json;
  const r = await l.verifyBundle(b, { fetch: null });
  assert.deepStrictEqual([r.status, r.firstFailure], ['failed', 'inclusion']);
  // Corrupt the subtree the last checkpoint's root starts with.
  const last = (await logGet('checkpoint')).json.checkpoint.size;
  await corrupt(Math.floor(Math.log2(last)), 0);
  await as('dog_log', (t) => t`select app.log_append('post', now(), 'agent:z', null, ${'post:' + crypto.randomUUID()}, '{"facts":"00"}'::jsonb)`);
  assert.strictEqual(await checkpointNow(), last, 'no new checkpoint');
  const w = (await logGet('checkpoint')).json.witnesses[0].site_reading;
  assert.deepStrictEqual([w.status, w.tree_matches_checkpoints], ['unverified', false]);
  assert.match(w.reason, /no longer reaches the root of signed checkpoint/);
  assert.strictEqual((await su`select count(*)::int as n from app.notices where member_id is null and title = 'The public log is unverified' and body like '%no longer reaches%'`)[0].n, 1);
});
