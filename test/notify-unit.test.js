// Release 2, PR 13: the parts of notifications that need no database. SigV4 against AWS's published test vectors,
// the SES request against a local fake server (no real network), the raw sign-in email, SNS signatures with a fixture
// certificate made fresh each run (our topic's region only, version 2 only), the cron secret, and vercel.json.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const sigv4 = require('../notify/sigv4');
const mime = require('../notify/mime');
const sns = require('../notify/sns');
const ncfg = require('../notify/config');
const { sesTransport, logTransport } = require('../notify/transport');
const { signinSender } = require('../notify/sender');
const fx = require('./notify-helpers');

const root = path.join(__dirname, '..');
// AWS's documented example credentials (https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html);
// they open nothing. Split so secret scanners don't mistake them for a real key.
const EXAMPLE = { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG' + '+bPxRfiCYEXAMPLEKEY' };
const AT = new Date('2015-08-30T12:36:00Z');

test('SigV4: matches AWS\'s published test vectors (get-vanilla, post-vanilla, query order)', () => {
  const s = (method, url) => sigv4.sign({ method, url, headers: {} }, EXAMPLE, { region: 'us-east-1', service: 'service', date: AT });
  const g = s('GET', 'https://example.amazonaws.com/');
  assert.strictEqual(g.signature, '5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
  assert.strictEqual(g.headers.authorization, 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
  assert.strictEqual(s('POST', 'https://example.amazonaws.com/').signature, '5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b');
  assert.strictEqual(s('GET', 'https://example.amazonaws.com/?Param2=value2&Param1=value1').signature, 'b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500');
  assert.throws(() => sigv4.sign({ method: 'GET', url: 'https://x.amazonaws.com/', headers: {} }, {}, { region: 'us-east-1', service: 's' }), /access key/);
});

// A fake SES that checks the signature itself, from the request it received, and answers like SES.
function fakeSes(answer) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      const a = answer(seen.length);
      res.writeHead(a.status, { 'content-type': 'application/json', ...(a.headers || {}) });
      res.end(JSON.stringify(a.body));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, base: 'http://127.0.0.1:' + server.address().port })));
}

test('SES: one signed SendEmail v2 request with our raw message, and only certain failures are retried', async () => {
  const { server, seen, base } = await fakeSes((n) => (n === 1 ? { status: 200, body: { MessageId: 'ses-1' } }
    : n === 2 ? { status: 429, body: { message: 'slow down' }, headers: { 'x-amzn-errortype': 'TooManyRequestsException' } }
      : { status: 400, body: { message: 'no' }, headers: { 'x-amzn-errortype': 'MessageRejected' } }));
  try {
    const now = new Date();
    const ses = sesTransport({ region: 'us-east-1', ...EXAMPLE, configurationSet: 'dog-events', endpoint: base, now: () => now });
    const raw = mime.build({ from: 'Day One Great <notices@dayonegreat.com>', to: 'ada@example.com', subject: 'Hello', text: 'Hi',
      unsubscribe: 'https://dayonegreat.com/api/notify/unsubscribe?c=x&s=y' });
    assert.deepStrictEqual(await ses.send({ from: 'Day One Great <notices@dayonegreat.com>', to: 'ada@example.com', raw }), { ok: true, id: 'ses-1' });
    const r = seen[0];
    assert.deepStrictEqual([r.method, r.url, r.headers['content-type']], ['POST', '/v2/email/outbound-emails', 'application/json']);
    const body = JSON.parse(r.body);
    assert.deepStrictEqual(Object.keys(body).sort(), ['ConfigurationSetName', 'Content', 'Destination', 'FromEmailAddress']);
    assert.deepStrictEqual(body.Destination, { ToAddresses: ['ada@example.com'] });
    assert.strictEqual(body.ConfigurationSetName, 'dog-events');
    assert.strictEqual(Buffer.from(body.Content.Raw.Data, 'base64').toString('utf8'), raw, 'the raw message is ours, unchanged');
    // The fake server recomputes the signature from what it received: same key, same canonical request.
    const m = /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/(\d{8})\/us-east-1\/ses\/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$/.exec(r.headers.authorization);
    assert.ok(m, r.headers.authorization);
    assert.strictEqual(m[2], 'content-type;host;x-amz-date');
    const again = sigv4.sign({ method: 'POST', url: base + r.url, headers: { 'content-type': r.headers['content-type'] }, body: r.body }, EXAMPLE,
      { region: 'us-east-1', service: 'ses', date: now });
    assert.strictEqual(again.signature, m[3]);
    assert.strictEqual(r.headers['x-amz-date'], sigv4.amzDate(now));
    assert.ok(!JSON.stringify(r.headers).includes(EXAMPLE.secretAccessKey), 'the secret never travels');
    assert.deepStrictEqual(await ses.send({ from: 'a@dayonegreat.com', to: 'b@example.com', raw }), { ok: false, retry: true, error: 'ses_429_TooManyRequestsException' });
    assert.deepStrictEqual(await ses.send({ from: 'a@dayonegreat.com', to: 'b@example.com', raw }), { ok: false, retry: false, error: 'ses_400_MessageRejected' });
  } finally { server.close(); }
  // A refused connection certainly didn't send, so it is retried; a timeout might have, so it isn't.
  const down = sesTransport({ region: 'us-east-1', ...EXAMPLE, endpoint: 'http://127.0.0.1:9', fetchImpl: async () => { throw new TypeError('fetch failed'); } });
  assert.strictEqual((await down.send({ from: 'a@x.com', to: 'b@x.com', raw: 'x' })).retry, true);
  const slow = sesTransport({ region: 'us-east-1', ...EXAMPLE, endpoint: 'http://127.0.0.1:9', fetchImpl: async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; } });
  assert.deepStrictEqual(await slow.send({ from: 'a@x.com', to: 'b@x.com', raw: 'x' }), { ok: false, retry: false, error: 'timeout' });
  assert.throws(() => sesTransport({ region: 'us-east-1', ...EXAMPLE, endpoint: 'http://ses.example.com' }), /HTTPS/);
  assert.throws(() => sesTransport({ region: 'nowhere', ...EXAMPLE }), /region/);
});

test('email: a plain sign-in message, UTF-8 subjects, no list headers, and no header injection from anything typed', () => {
  const raw = mime.build({ from: 'Day One Great <signin@dayonegreat.com>', to: 'ada@example.com', replyTo: 'hello@dayonegreat.com', subject: 'Héllo · ✓',
    text: 'line one\nline two ✓' });
  const p = fx.parse(raw);
  assert.ok(!('list-unsubscribe' in p.headers) && !('list-unsubscribe-post' in p.headers), 'not a mailing list: sign-in emails only');
  assert.strictEqual(p.headers['auto-submitted'], 'auto-generated');
  assert.match(p.headers.subject, /^=\?UTF-8\?B\?/);
  assert.strictEqual(p.text, 'line one\nline two ✓');
  assert.ok(raw.split('\r\n\r\n')[1].length > 0 && !/[^\r]\n/.test(raw), 'every line ends with CRLF');
  assert.strictEqual(p.headers['content-type'], 'text/plain; charset=UTF-8');
  for (const bad of ['Hi\r\nBcc: victim@example.com', 'Hi\nX: y', 'Hi there']) {
    assert.throws(() => mime.build({ from: 'a@dayonegreat.com', to: 'b@example.com', subject: bad, text: 'x' }), /control characters/);
  }
  assert.throws(() => mime.build({ from: 'a@dayonegreat.com', to: 'b@example.com\r\nBcc: c@example.com', subject: 's', text: 'x' }));
  // Every line of a raw message stays within the 998-character limit, however long the text.
  assert.ok(mime.build({ from: 'a@dayonegreat.com', to: 'b@example.com', subject: 's', text: 'x'.repeat(5000) }).split('\r\n').every((l) => l.length <= 998));
});

test('SNS: a message is trusted only with a good version 2 signature from our topic\'s own SNS region, for our topic, and fresh', async () => {
  const { key, cert } = fx.makeCert();
  const getCert = async (url) => { assert.strictEqual(url, fx.CERT_URL); return cert; };
  const ok = (m) => sns.verify(m, { topicArn: fx.TOPIC, getCert });
  assert.strictEqual((await ok(fx.signed(key, { Message: fx.bounce('a@example.com') }))).ok, true, 'version 2');
  assert.strictEqual((await ok(fx.signed(key, { Message: fx.bounce('a@example.com') }, { version: '1' }))).reason, 'version', 'SHA1 (version 1) is refused');
  assert.strictEqual((await ok(fx.signed(key, { Message: 'x', Subject: 'Amazon SES Email Event Notification' }))).ok, true, 'with a subject');
  const good = fx.signed(key, { Message: fx.bounce('a@example.com') });
  assert.strictEqual((await ok({ ...good, Message: fx.bounce('b@example.com') })).reason, 'signature', 'changed after signing');
  assert.strictEqual((await sns.verify(good, { topicArn: 'arn:aws:sns:us-east-1:999999999999:theirs', getCert })).reason, 'topic', 'another topic');
  assert.strictEqual((await sns.verify(good, { topicArn: null, getCert })).reason, 'topic', 'no topic configured: nothing trusted');
  for (const u of ['http://sns.us-east-1.amazonaws.com/c.pem', 'https://sns.us-east-1.amazonaws.com.evil.com/c.pem', 'https://evil.com/sns.us-east-1.amazonaws.com/c.pem',
    'https://sns.us-east-1.amazonaws.com/c.txt', 'https://sns.us-east-1.amazonaws.com:8443/c.pem',
    // Another region, or a host that only looks like SNS (the notifications review's suspicion): refused.
    'https://sns.eu-west-1.amazonaws.com/c.pem', 'https://sns.s3-external-1.amazonaws.com/c.pem']) {
    assert.strictEqual((await ok(fx.signed(key, { Message: 'x', SigningCertURL: u }))).reason, 'cert_url', u);
  }
  assert.strictEqual((await ok(fx.signed(key, { Message: 'x', Timestamp: new Date(Date.now() - 2 * 3600000).toISOString() }))).reason, 'stale');
  const other = fx.makeCert();
  assert.strictEqual((await ok(fx.signed(other.key, { Message: 'x' }))).reason, 'signature', 'signed with a key that isn\'t the certificate\'s');
  assert.strictEqual((await ok(null)).reason, 'shape');
  assert.strictEqual((await ok({ ...good, SignatureVersion: '3' })).reason, 'version');
  const conf = fx.signed(key, { Type: 'SubscriptionConfirmation', Message: 'confirm', Token: 'tok', SubscribeURL: 'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription' });
  assert.strictEqual((await ok(conf)).ok, true);
  assert.ok(sns.subscribeUrlOk(conf.SubscribeURL, fx.TOPIC) && !sns.subscribeUrlOk('https://evil.com/?Action=ConfirmSubscription', fx.TOPIC));
  assert.ok(!sns.subscribeUrlOk('https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription', fx.TOPIC), 'our region only');
  assert.strictEqual(sns.snsHost('arn:aws:sns:cn-north-1:123456789012:t'), 'sns.cn-north-1.amazonaws.com.cn');
  assert.strictEqual(sns.snsHost('arn:aws:sns:evil.com:1:t'), null, 'a malformed region gives no host, so nothing is trusted');
  assert.strictEqual(sns.snsHost(null), null);
  assert.deepStrictEqual(sns.suppressions({ Message: fx.bounce('a@example.com') }), [{ address: 'a@example.com', reason: 'bounce' }]);
  assert.deepStrictEqual(sns.suppressions({ Message: fx.bounce('a@example.com', 'Transient') }), [], 'a soft bounce isn\'t suppressed');
  assert.deepStrictEqual(sns.suppressions({ Message: fx.complaint('c@example.com') }), [{ address: 'c@example.com', reason: 'complaint' }]);
});

test('cron: no timer secret is read or needed (the timer slot, 027); the route says only ok, and never logs a header', async () => {
  assert.ok(!('cronSecret' in ncfg.load({ CRON_SECRET: 'a'.repeat(40) })), 'CRON_SECRET is no longer read for the timers');
  const cron = require('../api/cron.js');
  cron._reset();
  const r = { statusCode: 0, headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b; } };
  await cron.handle({ method: 'GET', headers: {} }, r, null);
  assert.deepStrictEqual([r.statusCode, r.body], [503, '{"ok":false}'], 'closed: no database');
  const src = fs.readFileSync(path.join(root, 'api', 'cron.js'), 'utf8') + fs.readFileSync(path.join(root, 'notify', 'config.js'), 'utf8');
  assert.ok(!/console\.(log|warn|error)/.test(src), 'nothing is logged');
});

test('the log transport sends nothing and logs no address or words; sign-in email waits for real email', async () => {
  const lines = [];
  const lt = logTransport({ log: (s) => lines.push(s) });
  const raw = mime.build({ from: 'a@dayonegreat.com', to: 'secret.person@example.com', subject: 'Private subject', text: 'private words' });
  assert.strictEqual((await lt.send({ raw })).ok, true);
  assert.ok(!/secret\.person|Private|private/.test(lines.join('\n')));
  const deps = { run: async () => false, keys: [{ version: 1, key: crypto.randomBytes(32) }] };
  assert.strictEqual(signinSender({ transport: lt }, deps), null, 'the log transport would swallow sign-in links');
  assert.strictEqual(typeof signinSender({ transport: { name: 'ses', send: async () => ({ ok: true }) }, from: 'a@dayonegreat.com', replyTo: 'hello@dayonegreat.com' }, deps), 'function');
  assert.strictEqual(signinSender({ transport: { name: 'ses' } }, { run: deps.run, keys: null }), null, 'no keys, no suppression check, so no sender');
  // Bounce fingerprints: the same address however it is written, keyed (never the address), one per key in use.
  const k2 = [{ version: 2, key: crypto.randomBytes(32) }, deps.keys[0]];
  const a = ncfg.suppressionPrints(k2, ' Ada@Example.com ');
  assert.deepStrictEqual(a, ncfg.suppressionPrints(k2, 'ada@example.com'));
  assert.strictEqual(a.length, 2);
  // Keyed, so never the address in a readable form: not its hex, and not its plain (unkeyed) SHA-256. (Not "doesn't
  // contain 'ada'": a, d and a are hex digits, so a random fingerprint contains them about 1.5% of the time, which made
  // this test fail now and then.)
  const plain = 'ada@example.com';
  const plainHex = Buffer.from(plain).toString('hex');
  const plainSha = crypto.createHash('sha256').update(plain).digest('hex');
  assert.ok(a.every((f) => /^[0-9a-f]{64}$/.test(f) && !f.includes(plainHex) && f !== plainSha));
  assert.notDeepStrictEqual(a[1], require('../signin/crypto').fingerprints(deps.keys, 'email', 'ada@example.com')[0], 'a label of its own, never a sign-in fingerprint');
});

test('vercel.json: the timers run every minute, /api/notify is routed, and the cron path is never redirected', () => {
  const v = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  assert.deepStrictEqual(v.crons, [{ path: '/api/cron', schedule: '* * * * *' }]);
  assert.ok(v.rewrites.some((r) => r.source === '/api/notify/:path*' && r.destination === '/api/notify?route=:path*'));
  // Vercel Cron doesn't follow redirects, and it may call a *.vercel.app address, which redirects everything else.
  // The same regular expression path-to-regexp builds from "/:path((?!api/cron$).*)".
  const rule = /^\/((?!api\/cron$).*)[/#?]?$/i;
  // Host redirects catch every path except the cron; the regional notice (PR 4) redirects only /join and /talk.
  for (const r of v.redirects) {
    if (r.has && r.has.some((h) => h.type === 'host')) assert.strictEqual(r.source, '/:path((?!api/cron$).*)');
    else assert.ok(['/join', '/talk'].includes(r.source), r.source);
  }
  assert.ok(!rule.test('/api/cron') && rule.test('/') && rule.test('/api/cronx') && rule.test('/agents') && rule.test('/api/notify'));
});

