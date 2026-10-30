// 023 (Aaron, Oct 28, 2026): signing in to the site by posting a one-time code through giscus. End to end against a
// real Postgres built from the migrations: the site's sign-in flow (signin/flow.js) makes the code, the JEVs gate's own
// code (supabase/functions/jevs/gate.mjs) claims it from a GitHub event shaped as jevs.yml builds it, and the site
// signs the browser in. Needs TEST_DATABASE_URL like test/signin.test.js.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const { make, SESSION } = require('../signin/flow');
const { migrate } = require('../scripts/migrate');
const { trustSystem } = require('./helpers');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const SERVER = process.env.TEST_DATABASE_URL;
const ORIGIN = 'https://dayonegreat.com';
// The gate's hash key is the Vault value dog_fingerprint_key_1; the site gets the same bytes from the broker as
// FINGERPRINT_KEY_1 (route B). The same stand-in here for both.
const GATE_KEY = 'f'.repeat(40);
const SITE_KEYS = [{ version: 1, key: Buffer.from(GATE_KEY, 'utf8') }];
// Key files (Aaron, Oct 28) as the browser sends them: the SHA-256 of the file, never the file.
const sha = (x) => crypto.createHash('sha256').update(x).digest('hex');
const FILE_A = sha('an original photo nobody else has'), FILE_B = sha('another private file');

// ---- Fake requests, responses and a browser's cookie jar (as in test/signin.test.js) ----
function req(method, url, { cookie = '', origin = ORIGIN, body, ip = '203.0.113.9', country } = {}) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': ip, 'sec-fetch-site': 'same-origin' };
  if (origin) headers.origin = origin;
  if (country) headers['x-vercel-ip-country'] = country;
  headers['content-type'] = 'application/x-www-form-urlencoded';
  return { method, url, headers, body: new URLSearchParams(body || {}).toString(), query: {} };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
function jar() {
  const j = {};
  return {
    take(r) {
      for (const sc of [].concat(r.getHeader('Set-Cookie') || [])) {
        const pair = sc.split(';')[0];
        const name = pair.slice(0, pair.indexOf('=')), value = pair.slice(pair.indexOf('=') + 1);
        assert.ok(name.startsWith('__Host-') && /HttpOnly/.test(sc) && /Secure/.test(sc) && /SameSite=Lax/.test(sc), name);
        if (/Max-Age=0/.test(sc) || !value) delete j[name]; else j[name] = value;
      }
      return r;
    },
    header() { return Object.entries(j).map(([k, v]) => k + '=' + v).join('; '); },
    get(name) { return j[name]; }
  };
}

test('the gate reads a code posted on purpose: alone, or on its own line under a hello; a mention, a quote or hidden markup is not a sign-in', async () => {
  const J = await import('../supabase/functions/jevs/core.mjs');
  const C = 'DOG-7K4M-Q2XH';
  assert.strictEqual(J.signinCode(C), C);
  assert.strictEqual(J.signinCode('  dog-7k4m-q2xh \n'), C, 'case and spaces around it are forgiven');
  // Aaron, Oct 30: "Most people are going to say something when they post." His own first sign-in was a hello, the code
  // on its own line and a thank-you, which the gate (then reading only a comment that was nothing but the code) ignored.
  for (const b of ['Hello,\n\n' + C + '\n\nThanks.', 'Hi!\n\n' + C, C + '\n\nthanks', 'hi\n\n   ' + C + '  \n', 'hi\r\n\r\n' + C + '\r\n\r\nbye',
    'hi\n\n' + C + '\n\n' + C]) {
    assert.strictEqual(J.signinCode(b), C, JSON.stringify(b));
  }
  assert.deepStrictEqual(J.signinCodes(C), { code: C, count: 1, alone: true, mentioned: false });
  assert.deepStrictEqual(J.signinCodes('Hello,\n\n' + C), { code: C, count: 1, alone: false, mentioned: false });
  // A mention is never a sign-in (the fresh review, Oct 30): "@you is this yours? DOG-..." and a quote-reply would
  // otherwise sign the asker's browser in as you. Nor is a code a reader can't see (the Keybase lesson).
  for (const b of ['my code: ' + C, '@you is this yours? ' + C, '> ' + C, 'Hi\n> ' + C + '\nwhat is this?', 'what is `' + C + '`?',
    '<!-- ' + C + ' -->\nhello', '<!--\n' + C + '\n-->\nhi', '[site](https://x/' + C + ')', '```\n' + C + '\n```\nhi',
    '<details><summary>x</summary>\n\n' + C + '\n</details>', 'hi\u200B\n\n' + C, 'hi &#8203;\n\n' + C, '(' + C + ')',
    // The second fresh review (Oct 30): a code a reader never sees, hidden by plain Markdown, or a line that renders as
    // something other than plain text, or a sentence pushed past the first 4,000 characters.
    'Hi all!\n\n[x]: /u \'\n' + C + '\n\'\n\nGlad to be here.', 'Hi all!\n\n[x]: /u (\n' + C + '\n)\n\nGlad to be here.',
    'hi [there](/u "\n\n' + C + '\n\n")', 'hi\n\n![\n\n' + C + '\n\n](x.png)', '$$\n\\phantom{\n\n' + C + '\n\n}\n$$',
    'hi\n' + C, C + '\n===', 'hi\n\n- ' + C, 'hi\n\n    ' + C, 'hi\n\n\t' + C, 'hi\n\n| ' + C + ' |',
    '````\n```\n\n' + C + '\n\n```\n````', '~~~\n\n' + C + '\n\n~~~', 'hi\u{E0041}\n\n' + C, 'hi\u{FFA0}\n\n' + C,
    C + ' '.repeat(3990) + ' is this yours, @victim?', 'hi\n\n' + C + '\n\n' + 'x'.repeat(4100),
    // The re-review (Oct 30): a line that only looks empty keeps a quote or a list going, so the code renders inside it.
    '> quoting you\n\u00A0\n' + C + '\n\nthanks', '- item\n\u00A0\n' + C, '> quoting you\n\u3000\n' + C, '> quoting you\n\u2028\n' + C]) {
    assert.deepStrictEqual(J.signinCodes(b), { code: null, count: 1, alone: false, mentioned: true }, JSON.stringify(b));
  }
  for (const b of ['DOG-7K4M-Q2X', 'DOG-7K0M-Q2XH', 'DOG-7K4M-Q2XHH', 'xDOG-7K4M-Q2XH', 'DOG-7K4M-Q2XH-2', '']) {
    assert.strictEqual(J.signinCode(b), null, JSON.stringify(b));
  }
  assert.deepStrictEqual(J.signinCodes('hi\n\n' + C + '\n\nor\n\nDOG-AAAA-BBBB'), { code: null, count: 2, alone: false, mentioned: false }, 'two codes: none');
  // The long s capitalizes to S: a near-miss in its own paragraph must not stand in for a code mentioned in a sentence.
  assert.strictEqual(J.signinCode('Is this yours? DOG-SK4M-Q2XH\n\nDOG-\u017FK4M-Q2XH'), null, 'the long s');
  assert.strictEqual(J.signinCode('x'.repeat(4100) + '\n\n' + C), null, 'a post over 4,000 characters is not a sign-in');
  // A lookalike gets a helpful reply; everyday words never do.
  for (const b of ['Hi DOG-7KOM-Q2XH', 'DOG-7K0M-Q2XH', 'DOG-7K4M-Q2XHH']) assert.strictEqual(J.looksLikeCode(b), true, JSON.stringify(b));
  for (const b of ['dog friendly park', 'dog-eat-dog world', 'We love DOGS', C, '']) assert.strictEqual(J.looksLikeCode(b), false, JSON.stringify(b));
  const flow = read('signin/flow.js');
  assert.match(flow, /const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';/, 'no 0, O, 1 or I: 32 characters, 40 random bits in a code');
  assert.match(read('supabase/functions/jevs/core.mjs'), /const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';/, 'the gate reads exactly the letters the site makes');
});

test('the workflow hides a sign-in code comment in either mode, replies, and a failed hide stops nothing', () => {
  const y = read('.github/workflows/jevs.yml');
  const step = y.match(/- name: Hide a sign-in code \(used or not, in either mode\)\n[\s\S]*?classifier: OUTDATED/);
  assert.ok(step, 'the hide step');
  assert.match(step[0], /continue-on-error: true/);
  // The expression itself, run through jq on every shape the gate can send (the fresh review, Oct 30: `.alone // true`
  // read false as true and would have hidden every hello).
  const expr = /jq -e '([^']+)' result\.json > \/dev\/null \|\| exit 0/.exec(step[0])[1];
  const jq = require('child_process').spawnSync('jq', ['--version'], { encoding: 'utf8' });
  if (jq.error) { if (process.env.CI) assert.fail('jq is needed in CI'); return; }
  const hides = (o) => require('child_process').spawnSync('jq', ['-e', expr], { input: JSON.stringify(o), encoding: 'utf8' }).status === 0;
  assert.strictEqual(hides({ signin: { claimed: true, founder: false, alone: true } }), true, 'only the code: hidden');
  assert.strictEqual(hides({ signin: { claimed: true, founder: false, alone: false } }), false, 'a hello around it: stays up');
  assert.strictEqual(hides({ signin: { claimed: false, founder: false, alone: false } }), false);
  assert.strictEqual(hides({ signin: { claimed: true, founder: false } }), true, 'a gate from before Oct 30 (no "alone"): hidden as before');
  assert.strictEqual(hides({ signin: null }), false);
  assert.strictEqual(hides({}), false);
  assert.match(y, /- name: Reply to \/agent commands and sign-in codes/);
});

if (!SERVER) {
  if (process.env.CI) test('code sign-in tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('code sign-in against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
} else {
  const NAME = 'dog_code_test_' + crypto.randomBytes(4).toString('hex');
  const WEB = NAME + '_web';
  const PW = crypto.randomBytes(18).toString('base64url');
  const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
  let server, su, web, G, flow, cfg;
  let n = 0;

  test.before(async () => {
    G = await import('../supabase/functions/jevs/gate.mjs');
    server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
    await server.unsafe('create database ' + NAME);
    su = postgres(at(NAME), { max: 2, ssl: false, prepare: false, onnotice: () => {} });
    await migrate(su);
    await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
    web = db.connect(at(NAME, WEB, PW), { ssl: false, max: 3 });
    await trustSystem(su);
    cfg = { ready: true, sessionKey: crypto.randomBytes(32).toString('base64'), ipKey: crypto.randomBytes(32), fingerprintKeys: SITE_KEYS, github: null, x: null };
    flow = make({ config: cfg, run: (ctx, fn) => db.tx(web, ctx, fn), providers: {}, sendEmail: null });
  });
  test.after(async () => {
    for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
    if (server) {
      await server.unsafe(`drop database if exists ${NAME} with (force)`);
      await server.unsafe(`drop role if exists ${WEB}`);
      await server.end({ timeout: 5 });
    }
  });

  // Asks for a code for a GitHub username (opts.login), as /join does (Aaron, Oct 28: option 2).
  const start = async (browser, opts = {}) => {
    const { login = 'someone', file = FILE_A, body = {}, ...rest } = opts;
    const r = res(); await flow.codeStart(req('POST', '/auth/code/start', { cookie: browser.header(), body: { login, file, ...body }, ...rest }), r);
    browser.take(r);
    return { status: r.statusCode, ...JSON.parse(r.body) };
  };
  const finish = async (browser, opts = {}) => {
    const r = res(); await flow.codeFinish(req('POST', '/auth/code/finish', { cookie: browser.header(), ...opts }), r);
    browser.take(r);
    return { status: r.statusCode, ...JSON.parse(r.body) };
  };
  // A comment posted through giscus, as jevs.yml sends it to the gate.
  const post = (id, login, body, extra = {}) => {
    n += 1;
    return G.handle(su, {
      event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1,
      post: { node_id: 'DC_code_' + n, thread_node_id: 'c' + n, body, created_at: new Date().toISOString() },
      author: { id, login, type: 'User', created_at: '2015-01-01T00:00:00Z' }, ...extra
    }, { key: GATE_KEY });
  };
  const me = async (browser) => { const r = res(); await flow.me(req('GET', '/auth/me', { cookie: browser.header() }), r); return JSON.parse(r.body); };
  // Reading and ageing rows straight in the database, as the test superuser (row-level security doesn't bind it).
  const owner = async (q) => [...await su.unsafe(q)];

  test('a person gets a code, posts it through giscus, and is signed in for 30 days; nothing names them but GitHub', async () => {
    const b = jar();
    const s = await start(b, { login: 'coder' });
    assert.strictEqual(s.status, 200);
    assert.match(s.code, /^DOG-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
    assert.strictEqual(s.expires_in, 600);
    assert.deepStrictEqual(await finish(b), { status: 200, waiting: true }, 'not posted yet');
    const g = await post(8001, 'coder', s.code);
    assert.deepStrictEqual(g.signin, { claimed: true, founder: false, alone: true });
    assert.match(g.reply, /This code is now claimed for `@coder`: the browser that asked for it can sign in to Day One Great as you\. If that wasn't you, sign out everywhere/);
    assert.strictEqual(g.alert, false, 'an ordinary member\'s sign-in alerts no one');
    const replay = await G.handle(su, { event: 'discussion_comment', action: 'created', mode: 'enforce', discussion: 1,
      post: { node_id: 'DC_code_' + n, thread_node_id: 'c' + n, body: s.code, created_at: new Date().toISOString() },
      author: { id: 8001, login: 'coder', type: 'User', created_at: '2015-01-01T00:00:00Z' } }, { key: GATE_KEY });
    assert.deepStrictEqual(replay.signin, { claimed: true, founder: false, alone: true }, 'a retried run of the same post still says claimed (the CSO\'s finding 8)');
    const f = await finish(b);
    assert.deepStrictEqual(f, { status: 200, signed_in: true, go: '/feed' });
    assert.ok(b.get(SESSION), 'a session cookie');
    const who = await me(b);
    assert.strictEqual(who.signed_in, true);
    // The menu's count (nav.js): a number of unread notices, read as the member, never anyone else's.
    assert.ok(Number.isInteger(who.unread) && who.unread >= 0, 'unread is a count: ' + who.unread);
    const [{ mine }] = await owner(`select count(*)::int as mine from app.notices where member_id = '${who.member_id}' and read_at is null`);
    assert.ok(who.unread >= mine, 'it counts at least their own unread notices');
    const [row] = await owner(`select s.expires_at > now() + interval '29 days 23 hours' as thirty, i.provider, i.fingerprint = '${c.fingerprints(SITE_KEYS, 'github', '8001')[0]}' as same_fp
      from app.sessions s join app.identities i on i.id = s.identity_id where s.member_id = '${who.member_id}'`);
    assert.deepStrictEqual(row, { thirty: true, provider: 'github', same_fp: true },
      'a 30-day session, and the same fingerprint GitHub sign-in gives this account, so both ways reach one member');
    const dump = JSON.stringify(await owner(`select * from app.code_signins`));
    assert.ok(!dump.includes(s.code) && !dump.includes('8001') && !dump.includes('coder'), 'no code, ID or name is stored, only keyed hashes');
  });

  test('a code on its own line under a hello signs the person in and the message stays up; a mention, two codes, another thread or a lookalike sign nobody in, each with a reply', async () => {
    // Its own network, so this test doesn't use up the shared one's 30 codes in 10 minutes (signin_ip) for later tests.
    const ip = '192.0.2.31';
    const b = jar();
    const s = await start(b, { login: 'greeter', ip });
    const g = await post(8011, 'greeter', 'Hello,\n\n' + s.code + '\n\nThanks.');
    assert.deepStrictEqual(g.signin, { claimed: true, founder: false, alone: false });
    assert.match(g.reply, /This code is now claimed for `@greeter`/);
    assert.match(g.reply, /Your message stays up; the code in it is used now\./);
    assert.strictEqual((await finish(b)).signed_in, true);
    // The attack the fresh review found: someone asks for a code for your username, then gets you to mention it.
    // A mention or a quote-reply claims nothing, and the code stays unclaimed for its own browser.
    const victim = jar();
    const bait = await start(victim, { login: 'victim', ip });
    for (const text of ['Is this yours? ' + bait.code, '> ' + bait.code + '\nNo, what is this?', 'what is `' + bait.code + '`?']) {
      const m = await post(8016, 'victim', text);
      assert.strictEqual(m.signin, undefined, JSON.stringify(text));
      assert.match(m.reply, /mentions a sign-in code but doesn't use it, so nobody was signed in/);
    }
    assert.deepStrictEqual(await finish(victim), { status: 200, waiting: true }, 'the asker\u2019s browser got nothing');
    // Someone else's copy, on its own line: claims nothing (the code is for "victim"), and the reply doesn't say it's dead.
    const other = await post(8012, 'someone', 'Is this yours?\n\n' + bait.code);
    assert.deepStrictEqual(other.signin, { claimed: false, founder: false, alone: false });
    assert.match(other.reply, /This code didn't sign anyone in/);
    assert.match(other.reply, /Your message stays up\.$/);
    // In another discussion, even alone: nothing (codes are read only in the welcome thread).
    const elsewhere = await post(8016, 'victim', bait.code, { discussion: 2 });
    assert.strictEqual(elsewhere.signin, undefined);
    assert.deepStrictEqual(await finish(victim), { status: 200, waiting: true });
    // Two codes: neither is used, and the reply says to post just one.
    const b2 = jar();
    const s2 = await start(b2, { login: 'twice', ip });
    const two = await post(8013, 'twice', s2.code + '\n\nor maybe\n\nDOG-AAAA-BBBB');
    assert.strictEqual(two.signin, undefined, 'nothing claimed');
    assert.match(two.reply, /more than one sign-in code in it, so none of them was used/);
    assert.deepStrictEqual(await finish(b2), { status: 200, waiting: true });
    assert.strictEqual((await post(8013, 'twice', 'Sorry!\n\n' + s2.code)).signin.claimed, true);
    assert.strictEqual((await finish(b2)).signed_in, true);
    // A lookalike (a zero where the site never puts one) gets a reply that says what a code looks like.
    const look = await post(8014, 'typo', 'DOG-7K0M-Q2XH');
    assert.strictEqual(look.signin, undefined);
    assert.match(look.reply, /looks like a sign-in code, but it isn't one the site gives out/);
    // Everyday words get no reply at all.
    const chat = await post(8015, 'chatter', 'Is the park dog-friendly? Our DOGS would love it.');
    assert.strictEqual(chat.signin, undefined);
    assert.strictEqual(chat.reply, null);
  });

  test('a code works once, only for the browser that asked for it', async () => {
    const b = jar(), thief = jar();
    const s = await start(b, { login: 'once' });
    await start(thief, { login: 'thief' });
    await post(8002, 'once', s.code);
    assert.deepStrictEqual(await finish(thief), { status: 200, waiting: true }, 'another browser gets nothing from this code');
    assert.strictEqual((await finish(b)).signed_in, true);
    const again = await post(8003, 'late', s.code);
    assert.deepStrictEqual(again.signin, { claimed: false, founder: false, alone: true }, 'posting a used code claims nothing');
    assert.match(again.reply, /This code didn't sign anyone in/);
    const b2 = jar();
    assert.deepStrictEqual(await finish(b2), { status: 200, expired: true }, 'a browser with no code of its own');
  });

  test('a code expires after 10 minutes, and an edited comment never claims one', async () => {
    const b = jar();
    const s = await start(b, { login: 'slow' });
    await owner(`update app.code_signins set expires_at = now() - interval '1 second' where status = 'waiting'`);
    const late = await post(8004, 'slow', s.code);
    assert.deepStrictEqual(late.signin, { claimed: false, founder: false, alone: true });
    assert.deepStrictEqual(await finish(b), { status: 200, expired: true });
    const b2 = jar();
    const s2 = await start(b2, { login: 'editor' });
    n += 1;
    const edited = await G.handle(su, { event: 'discussion_comment', action: 'edited', mode: 'enforce', discussion: 1,
      post: { node_id: 'DC_code_e' + n, thread_node_id: 'ce' + n, body: s2.code, created_at: new Date().toISOString() },
      author: { id: 8005, login: 'editor', type: 'User', created_at: '2015-01-01T00:00:00Z' } }, { key: GATE_KEY });
    assert.strictEqual(edited.signin, undefined);
    assert.deepStrictEqual(await finish(b2), { status: 200, waiting: true });
  });

  test('the site can\'t choose who signs in: only the gate\'s role may claim a code, and sign-in takes the account from the claim', async () => {
    const b = jar();
    const s = await start(b);
    const tagHash = c.sha256hex(b.get('__Host-dog_code'));
    const codeHash = c.hmacHex(SITE_KEYS[0].key, 'signin-code:' + s.code);
    await assert.rejects(web.begin(async (t) => { await t`set local role dog_app`; await t`select app.code_claim(${codeHash}, ${'a'.repeat(64)}, ${'b'.repeat(64)})`; }),
      /permission denied/, 'the site\'s role can\'t claim a code for any account');
    const [args] = await owner(`select pg_get_function_identity_arguments('app.code_sign_in(text, text, text, integer, text)'::regprocedure) as a`);
    assert.doesNotMatch(args.a, /fingerprint|github|account/i, 'sign-in takes no account from the caller');
    assert.deepStrictEqual(await finish(b), { status: 200, waiting: true });
    assert.ok(tagHash.length === 64);
  });

  test('a banned account\'s post claims nothing; the founder\'s account is never banned, and its claims alert', async () => {
    const b = jar();
    const s = await start(b, { login: 'banned-one' });
    const banned = await post(8006, 'banned-one', s.code, { bans: [8006] });
    assert.deepStrictEqual(banned.signin, { claimed: false, founder: false, alone: true });
    assert.match(banned.reply, /This account can't sign in to Day One Great, so this code didn't sign anyone in\.$/, 'a reply that is true for a banned account');
    assert.ok(!/has expired|different GitHub username/.test(banned.reply), 'not the general reasons, which aren\u2019t true for it');
    assert.deepStrictEqual(await finish(b), { status: 200, waiting: true });
    const b2 = jar();
    const s2 = await start(b2, { login: 'MyChiefOS' });
    // The administrator's account (which Claude also posts as) keeps the strict rule: a hello around the code claims
    // nothing, so no reply from that account can carry a sign-in (the fresh review, Oct 30, finding 1).
    const hello = await post(304218593, 'MyChiefOS', 'Hello,\n\n' + s2.code + '\n\nThanks.');
    assert.strictEqual(hello.signin, undefined);
    assert.match(hello.reply, /This account \(the administrator's\) signs in only with a comment that is the code and nothing else\./);
    assert.strictEqual(hello.alert, false, 'nothing was claimed, so nothing to alert on');
    assert.deepStrictEqual(await finish(b2), { status: 200, waiting: true });
    const f = await post(304218593, 'MyChiefOS', s2.code, { bans: [304218593] });
    assert.deepStrictEqual(f.signin, { claimed: true, founder: true, alone: true }, 'Aaron can always sign in, whatever the ban list says');
    assert.strictEqual(f.alert, true, 'a code claimed by the founder\'s account (Aaron\'s, which Claude also posts as) alerts on the JEVs alerts issue (the CSO\'s finding 1)');
    assert.strictEqual((await finish(b2)).signed_in, true);
    // 028 (fix 9): with no administrator yet, that sign-in made him administrator; undone here so the tests below
    // start with none (the founder's promotion has its own test, "028: ...").
    const aaron = (await me(b2)).member_id;
    assert.strictEqual((await owner(`select is_admin from app.members where id = '${aaron}'`))[0].is_admin, true);
    await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = false where id = '${aaron}'`); });
  });

  test('only from our own pages: a cross-site start or finish is refused', async () => {
    const b = jar();
    assert.strictEqual((await start(b, { origin: 'https://evil.example' })).status, 403);
    assert.strictEqual(b.get('__Host-dog_code'), undefined);
    const s = await start(b, { login: 'csrf' });
    await post(8007, 'csrf', s.code);
    assert.strictEqual((await finish(b, { origin: 'https://evil.example' })).status, 403);
    assert.strictEqual((await finish(b)).signed_in, true);
  });

  test('from a declined region: the page asks where the person lives before any code is made; a new person is declined and nothing of the code is kept; a member signs in', async () => {
    const b = jar();
    assert.deepStrictEqual(await start(b, { login: 'newfr', country: 'FR' }), { status: 200, region: 'France' }, 'no code yet');
    assert.strictEqual(b.get('__Host-dog_code'), undefined);
    const s = await start(b, { login: 'newfr', country: 'FR', body: { confirm: '1' } });
    assert.match(s.code, /^DOG-/);
    await post(8008, 'newfr', s.code);
    assert.deepStrictEqual(await finish(b, { country: 'FR', body: { confirm: '1' } }), { status: 200, declined: true });
    assert.strictEqual(b.get(SESSION), undefined);
    const fp = c.fingerprints(SITE_KEYS, 'github', '8008')[0];
    const [{ k }] = await owner(`select count(*)::int as k from app.identities where fingerprint = '${fp}'`);
    assert.strictEqual(k, 0, 'no account is made');
    const [{ left }] = await owner(`select count(*)::int as left from app.code_signins where fingerprint = '${fp}'`);
    assert.strictEqual(left, 0, 'the claimed code and the fingerprint it held are deleted at once (Oct 16 rule; the CSO\'s finding 4)');
    // A member who lives elsewhere, travelling.
    const home = jar();
    const s1 = await start(home, { login: 'traveller' });
    await post(8009, 'traveller', s1.code);
    assert.strictEqual((await finish(home)).signed_in, true);
    const away = jar();
    assert.deepStrictEqual(await start(away, { login: 'traveller', country: 'DE' }), { status: 200, region: 'Germany' });
    const s2 = await start(away, { login: 'traveller', country: 'DE', body: { confirm: '1' } });
    await post(8009, 'traveller', s2.code);
    assert.strictEqual((await finish(away, { country: 'DE', body: { confirm: '1' } })).signed_in, true);
  });

  test('a code is for one GitHub username: a copy reposted by anyone else claims nothing, and its owner can still use it (Aaron, Oct 28: option 2)', async () => {
    const b = jar();
    const s = await start(b, { login: '@Owner-One' });
    const copy = await post(8010, 'watcher', s.code);
    assert.deepStrictEqual(copy.signin, { claimed: false, founder: false, alone: true }, 'a watcher who reposts the code first gets nothing');
    assert.match(copy.reply, /made for a different GitHub username/);
    assert.deepStrictEqual(await finish(b), { status: 200, waiting: true }, 'the owner\'s browser is untouched');
    const own = await post(8011, 'owner-one', s.code);
    assert.deepStrictEqual(own.signin, { claimed: true, founder: false, alone: true }, 'the username matches whatever its case, with or without @');
    const f = await finish(b);
    assert.strictEqual(f.signed_in, true);
    const [row] = await owner(`select count(*)::int as n from app.identities where fingerprint = '${c.fingerprints(SITE_KEYS, 'github', '8011')[0]}'`);
    assert.strictEqual(row.n, 1, 'signed in as the owner, never as the watcher');
    for (const bad of ['', 'a b', '-starts-with-dash', 'x'.repeat(40), 'name!']) {
      assert.match((await start(jar(), { login: bad })).error, /GitHub username/, JSON.stringify(bad));
    }
  });

  test('the key file: after a code sign-in, the same username and file sign in again on any browser, with no post, and the member is told (Aaron, Oct 28)', async () => {
    const first = jar();
    const s = await start(first, { login: 'keeper', file: FILE_A });
    await post(8020, 'keeper', s.code);
    const who = (await finish(first)).signed_in && await me(first);
    assert.ok(who.signed_in);
    const key = async (browser, body, opts = {}) => {
      const r = res(); await flow.keyFileSignIn(req('POST', '/auth/key', { cookie: browser.header(), body, ...opts }), r);
      browser.take(r);
      return { status: r.statusCode, ...JSON.parse(r.body) };
    };
    const laptop = jar();
    assert.deepStrictEqual(await key(laptop, { login: 'Keeper', file: FILE_A }), { status: 200, signed_in: true, go: '/feed' }, 'the username in any case');
    assert.strictEqual((await me(laptop)).member_id, who.member_id, 'the same member');
    const [n] = await owner(`select count(*)::int as n from app.notices where member_id = '${who.member_id}' and kind = 'signin_keyfile'`);
    assert.strictEqual(n.n, 1, 'an in-app notice each time the key file is used');
    assert.match((await key(jar(), { login: 'keeper', file: FILE_B })).error, /don’t match/, 'another file');
    assert.match((await key(jar(), { login: 'someone-else', file: FILE_A })).error, /don’t match/, 'another username with the same file');
    assert.match((await key(jar(), { login: 'keeper' })).error, /choose your key file/, 'no file');
    assert.strictEqual((await key(jar(), { login: 'keeper', file: FILE_A }, { origin: 'https://evil.example' })).status, 403);
    const dump = JSON.stringify(await owner(`select * from app.file_keys`)) + JSON.stringify(await owner(`select * from app.code_signins`));
    assert.ok(!dump.includes(FILE_A) && !dump.includes('keeper'), 'neither the file\'s hash nor the username is stored as sent, only keyed again');
    // A new code sign-in with a new file replaces the old one.
    const again = jar();
    const s2 = await start(again, { login: 'keeper', file: FILE_B, ip: '203.0.113.73' });
    await post(8020, 'keeper', s2.code);
    assert.strictEqual((await finish(again)).signed_in, true);
    assert.strictEqual((await me(again)).member_id, who.member_id, 'a new code brings the person back to the same account (Aaron, Oct 28)');
    assert.match((await key(jar(), { login: 'keeper', file: FILE_A })).error, /don’t match/, 'the old file no longer works');
    const phone = jar();
    assert.strictEqual((await key(phone, { login: 'keeper', file: FILE_B })).signed_in, true);
    // "Sign out everywhere" cancels the key file too; a new code brings the member back to the same account.
    const out = res(); await flow.logout(req('POST', '/auth/logout-all', { cookie: phone.header() }), out, true);
    assert.strictEqual((await me(phone)).signed_in, false);
    assert.match((await key(jar(), { login: 'keeper', file: FILE_B })).error, /don’t match/, 'sign out everywhere cancels the key file');
    const back = jar();
    const s3 = await start(back, { login: 'keeper', file: FILE_A, ip: '203.0.113.71' });
    await post(8020, 'keeper', s3.code);
    assert.strictEqual((await finish(back)).signed_in, true);
    assert.strictEqual((await me(back)).member_id, who.member_id, 'the same account after starting again');
  });

  test('the key file: the 10th wrong file cancels it and asks the person to start again (Aaron, Oct 28), the administrator\'s file works like everyone\'s (Aaron, Oct 28), and a deleted account\'s file is gone', async () => {
    const b = jar();
    const s = await start(b, { login: 'tries', file: FILE_A });
    await post(8021, 'tries', s.code);
    assert.strictEqual((await finish(b)).signed_in, true);
    const key = async (body, ip) => { const r = res(); await flow.keyFileSignIn(req('POST', '/auth/key', { body, ip }), r); return { status: r.statusCode, ...JSON.parse(r.body) }; };
    const tries = jar();
    const memberId = (await me(b)).member_id;
    // A right file resets the count: 9 wrong, 1 right, then 9 wrong still works.
    for (let i = 0; i < 9; i++) assert.match((await key({ login: 'tries', file: sha('guess ' + i) }, '198.51.100.' + (i + 1))).error, /don’t match/);
    assert.strictEqual((await key({ login: 'tries', file: FILE_A }, '198.51.100.40')).signed_in, true, 'nine wrong files, then the right one works');
    for (let i = 0; i < 9; i++) await key({ login: 'tries', file: sha('again ' + i) }, '198.51.100.' + (i + 11));
    assert.strictEqual((await key({ login: 'tries', file: FILE_A }, '198.51.100.41')).signed_in, true, 'the right file reset the count');
    for (let i = 0; i < 9; i++) await key({ login: 'tries', file: sha('more ' + i) }, '198.51.100.' + (i + 21));
    const tenth = await key({ login: 'TRIES', file: sha('more 9') }, '198.51.100.31');
    assert.strictEqual(tenth.start_again, true, 'the 10th wrong file, in any spelling of the username, from any network');
    assert.match(tenth.error, /start again: get a new code/);
    assert.match((await key({ login: 'tries', file: FILE_A }, '198.51.100.42')).error, /don’t match/, 'the key file is cancelled');
    const [note] = await owner(`select title, link from app.notices where member_id = '${memberId}' and kind = 'signin_keyfile' and dedupe_key like 'signin:keyfile:cancelled:%'`);
    assert.deepStrictEqual({ ...note }, { title: 'Your key file was cancelled', link: '/join' }, 'the member is told');
    const s4 = await start(tries, { login: 'tries', file: FILE_B, ip: '203.0.113.72' });
    await post(8021, 'tries', s4.code);
    assert.strictEqual((await finish(tries)).signed_in, true);
    assert.strictEqual((await me(tries)).member_id, memberId, 'starting again brings back the same account');
    assert.strictEqual((await key({ login: 'tries', file: FILE_B }, '198.51.100.43')).signed_in, true, 'with the new file');
    // A new code sign-in starts the count again: 9 wrong, a new code and file, then 1 wrong doesn't cancel the new file.
    for (let i = 0; i < 9; i++) await key({ login: 'tries', file: sha('late ' + i) }, '198.51.100.' + (i + 50));
    const fresh = jar();
    const s5 = await start(fresh, { login: 'tries', file: FILE_A, ip: '203.0.113.74' });
    await post(8021, 'tries', s5.code);
    assert.strictEqual((await finish(fresh)).signed_in, true);
    assert.match((await key({ login: 'tries', file: sha('late 9') }, '198.51.100.60')).error, /don’t match/, 'the count started again at the code sign-in');
    assert.strictEqual((await key({ login: 'tries', file: FILE_A }, '198.51.100.61')).signed_in, true);
    // A username another GitHub account used before a rename: the newer account's code sign-in takes it, the older key
    // file for that name goes, and wrong tries still count.
    const old = jar();
    const s6 = await start(old, { login: 'renamed', file: FILE_A, ip: '203.0.113.75' });
    await post(8030, 'renamed', s6.code);
    assert.strictEqual((await finish(old)).signed_in, true);
    const taker = jar();
    const s7 = await start(taker, { login: 'renamed', file: FILE_B, ip: '203.0.113.76' });
    await post(8031, 'renamed', s7.code);
    assert.strictEqual((await finish(taker)).signed_in, true);
    assert.notStrictEqual((await me(taker)).member_id, (await me(old)).member_id, 'two GitHub accounts, two members');
    assert.match((await key({ login: 'renamed', file: FILE_A }, '198.51.100.62')).error, /don’t match/, 'the older account\'s file for that name is gone');
    assert.match((await key({ login: 'renamed', file: sha('wrong') }, '198.51.100.63')).error, /don’t match/, 'a wrong file is counted, not an error');
    assert.strictEqual((await key({ login: 'renamed', file: FILE_B }, '198.51.100.64')).signed_in, true);
    // An administrator: the reset works for Aaron's account too (Aaron, Oct 28).
    const a = jar();
    const sa = await start(a, { login: 'boss', file: FILE_A });
    await post(8022, 'boss', sa.code);
    const boss = (await finish(a)).signed_in && await me(a);
    await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${boss.member_id}'`); });
    const r = res(); await flow.keyFileSignIn(req('POST', '/auth/key', { body: { login: 'boss', file: FILE_A }, ip: '192.0.2.50' }), r);
    assert.deepStrictEqual(JSON.parse(r.body), { signed_in: true, go: '/feed' }, 'the administrator signs in with the key file, no post');
    const [adm] = await owner(`select s.member_id from app.sessions s where s.member_id = '${boss.member_id}' order by s.created_at desc limit 1`);
    assert.strictEqual(adm.member_id, boss.member_id, 'into the administrator\'s own account');
    // 025 (the CSO's review, Oct 29): the site's own role can't sign in an administrator by naming the fingerprint, as
    // the switched-off GitHub, X and email sign-ins do. The code and key-file sign-ins above still can.
    const store = require('../db/signin');
    const [idn] = await owner(`select i.fingerprint as fp from app.identities i where i.member_id = '${boss.member_id}' limit 1`);
    const [{ n: before }] = await owner(`select count(*)::int as n from app.sessions where member_id = '${boss.member_id}'`);
    const direct = await db.tx(web, { actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [idn.fp], keyVersion: 1, level: 1,
      displayName: 'x', sessionHash: c.sha256hex(c.token(32)), sessionDays: 30 }));
    assert.deepStrictEqual(direct, { refused: 'admin_code_only' }, 'refused for an administrator');
    const [{ n: after }] = await owner(`select count(*)::int as n from app.sessions where member_id = '${boss.member_id}'`);
    assert.strictEqual(after, before, 'and no session was made');
    await assert.rejects(web.begin(async (t) => { await t`set local role dog_app`; await t`select * from app.sign_in_core('github', ${[idn.fp]}::text[], 1::smallint, 1::smallint, 'x', ${'e'.repeat(64)}, 30, null::timestamptz, null::uuid, null)`; }),
      /permission denied/, 'the site\'s role can\'t call the sign-in role\'s own function');
    await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = false where id = '${boss.member_id}'`); });
    // Deleting the account takes its key file with it.
    await su.unsafe(`delete from app.file_keys where member_id = '${boss.member_id}'`);
    const [{ n }] = await owner(`select count(*)::int as n from app.file_keys f join app.members m on m.id = f.member_id where m.id = '${boss.member_id}'`);
    assert.strictEqual(n, 0);
    const [fk] = await owner(`select confdeltype from pg_constraint where conrelid = 'app.file_keys'::regclass and contype = 'f'`);
    assert.strictEqual(fk.confdeltype, 'c', 'a member\'s key file is deleted with the member (on delete cascade)');
  });

  test('codes that expired more than an hour ago are cleared every time a code is made', async () => {
    const b = jar();
    await start(b);
    await owner(`update app.code_signins set expires_at = now() - interval '2 hours'`);
    await start(jar());
    const [{ old }] = await owner(`select count(*)::int as old from app.code_signins where expires_at < now() - interval '1 hour'`);
    assert.strictEqual(old, 0);
  });

  test('025: making someone administrator ends their sessions and needs exactly one GitHub method, so no earlier session or linked account becomes the administrator\'s (the CSO\'s review, B1 and B2)', async () => {
    const store = require('../db/signin');
    const setAdmin = (id) => su.begin(async (x) => { await x.unsafe('set local role dog_owner'); return (await x`select app.set_administrator(${id}::uuid) as r`)[0].r; });
    const unAdmin = (id) => su.begin(async (x) => { await x.unsafe('set local role dog_owner'); await x.unsafe(`update app.members set is_admin = false where id = '${id}'`); });
    const sessions = async (id) => (await owner(`select count(*)::int as n from app.sessions where member_id = '${id}'`))[0].n;
    const direct = (fp, hash) => db.tx(web, { actor: 'anon' }, (x) => store.signIn(x, { provider: 'github', fingerprints: [fp], keyVersion: 1, level: 1,
      displayName: 'x', sessionHash: hash, sessionDays: 30 }));
    // B1: a session the site's role made before the promotion is gone after it.
    const h1 = c.sha256hex(c.token(32));
    const x = await direct(sha('github:9101'), h1);
    assert.ok(x.memberId);
    assert.strictEqual(await sessions(x.memberId), 1);
    assert.strictEqual(await setAdmin(x.memberId), 'set');
    assert.strictEqual(await sessions(x.memberId), 0, 'every session ended at the promotion');
    assert.deepStrictEqual(await direct(sha('github:9101'), c.sha256hex(c.token(32))), { refused: 'admin_code_only' }, 'and the site\'s role can\'t make a new one');
    await unAdmin(x.memberId);
    // B2: an account someone linked another GitHub fingerprint to can't be made administrator.
    const h2 = c.sha256hex(c.token(32));
    const y = await direct(sha('github:9102'), h2);
    const linked = await db.tx(web, { actor: 'member', memberId: y.memberId, session: h2, fresh: true }, (t2) => store.link(t2, { provider: 'github',
      fingerprints: [sha('github:9103')], keyVersion: 1, level: 1, sessionHash: h2 }));
    assert.strictEqual(linked.linked, true, 'the link itself still works for the switched-off path');
    await assert.rejects(setAdmin(y.memberId), /exactly one sign-in method, GitHub/);
    assert.strictEqual((await owner(`select is_admin from app.members where id = '${y.memberId}'`))[0].is_admin, false, 'nothing changed');
    // A member who signed in by code: promoted, signed out, then back in with the key file as the administrator.
    const b = jar();
    const sp = await start(b, { login: 'promoted', file: FILE_A, ip: '203.0.113.95' });
    await post(8045, 'promoted', sp.code);
    assert.strictEqual((await finish(b, { ip: '203.0.113.95' })).signed_in, true);
    const pm = await me(b);
    assert.strictEqual(await setAdmin(pm.member_id), 'set');
    assert.strictEqual((await me(b)).signed_in, false, 'signed out by the promotion');
    const back = jar(); const r = res();
    await flow.keyFileSignIn(req('POST', '/auth/key', { body: { login: 'promoted', file: FILE_A }, ip: '203.0.113.96' }), r); back.take(r);
    assert.strictEqual(JSON.parse(r.body).signed_in, true, 'Aaron signs straight back in with his key file');
    assert.strictEqual((await owner(`select is_admin from app.members where id = '${pm.member_id}'`))[0].is_admin, true);
    await unAdmin(pm.member_id);
  });

  test('the JEVs behaviour watch (Aaron, Oct 28; 026): it alerts Aaron and never refuses anyone', async () => {
    const store = require('../db/signin');
    const alerts = async (like, about = null) => (await owner(`select title from app.notices where member_id is null and kind = 'alert' and dedupe_key like '${like}'`
      + (about ? ` and subject_id = '${about}'` : '') + ` order by created_at`)).map((r) => r.title);
    const keyIn = async (login, file, { ip = '198.51.100.200', country } = {}) => {
      const b = jar(); const r = res(); await flow.keyFileSignIn(req('POST', '/auth/key', { body: { login, file }, ip, country }), r); b.take(r);
      return { b, ...JSON.parse(r.body) };
    };
    // A member with a key file, signing in from the United States.
    const first = jar();
    const s = await start(first, { login: 'watched', file: FILE_A, ip: '203.0.113.90', country: 'US' });
    await post(8040, 'watched', s.code);
    assert.strictEqual((await finish(first, { ip: '203.0.113.90', country: 'US' })).signed_in, true);
    const who = await me(first);
    // 1. Many sessions at once: more than 5 live sessions alerts, and every sign-in still works.
    for (let i = 0; i < 5; i++) assert.strictEqual((await keyIn('watched', FILE_A, { ip: '198.51.100.' + (110 + i), country: 'US' })).signed_in, true);
    assert.deepStrictEqual(await alerts('watch:sessions:' + who.member_id + ':%'), ['Many sessions at once'], '6 sessions, one alert a day');
    // 2. A new country alerts; the same country again doesn't.
    assert.deepStrictEqual(await alerts('watch:country:%', who.member_id), []);
    assert.strictEqual((await keyIn('watched', FILE_A, { ip: '198.51.100.120', country: 'CA' })).signed_in, true, 'still signed in');
    assert.deepStrictEqual(await alerts('watch:country:%', who.member_id), ['A sign-in from a new country']);
    await keyIn('watched', FILE_A, { ip: '198.51.100.121', country: 'CA' });
    assert.strictEqual((await alerts('watch:country:%', who.member_id)).length, 1, 'a country seen before is quiet');
    // A country unseen for 90 days is forgotten at the next sign-in (anyone's), and alerts again if it comes back.
    await su.unsafe(`update app.watch_seen set last_seen = now() - interval '100 days', first_seen = now() - interval '100 days' where member_id = '${who.member_id}'`);
    await su.unsafe(`insert into app.watch_seen (member_id, kind, key_hash) values ('${who.member_id}', 'country', '${'d'.repeat(64)}')`);
    assert.strictEqual((await keyIn('watched', FILE_A, { ip: '198.51.100.122', country: 'CA' })).signed_in, true);
    assert.deepStrictEqual(await alerts('watch:country:%', who.member_id), ['A sign-in from a new country', 'A sign-in from a new country'], 'CA, gone after 90 days, alerts again');
    assert.strictEqual((await owner(`select count(*)::int as n from app.watch_seen where last_seen < now() - interval '90 days'`))[0].n, 0, 'rows unseen for 90 days are deleted');
    // Alert keys name a row, never a hash.
    assert.ok((await owner(`select dedupe_key from app.notices where dedupe_key like 'watch:country:%'`)).every((r) => /^watch:country:[0-9a-f-]{36}$/.test(r.dedupe_key)));
    // A failure in the watch never stops a sign-in.
    await su.unsafe('revoke execute on function app.watch_signin(text, text) from dog_app');
    try {
      assert.strictEqual((await keyIn('watched', FILE_A, { ip: '198.51.100.123', country: 'US' })).signed_in, true, 'signed in with the watch failing');
    } finally {
      await su.unsafe('grant execute on function app.watch_signin(text, text) to dog_app');
    }
    // Only keyed hashes are kept, and no network for anyone but the administrator.
    const seen = await owner(`select kind, key_hash from app.watch_seen where member_id = '${who.member_id}'`);
    assert.deepStrictEqual([...new Set(seen.map((r) => r.kind))], ['country']);
    assert.ok(!JSON.stringify(seen).includes('US') && !JSON.stringify(seen).includes('CA'), 'no country in readable form');
    // 4. Failed tries: the 5th wrong file alerts; the 10th cancels it and alerts too.
    const [{ id: keyId }] = await owner(`select id from app.file_keys where member_id = '${who.member_id}'`);
    for (let i = 0; i < 5; i++) await keyIn('watched', sha('wrong ' + i), { ip: '198.51.100.' + (130 + i), country: 'US' });
    assert.deepStrictEqual(await alerts('watch:failed:' + keyId), ['Wrong key files for one account']);
    for (let i = 5; i < 10; i++) await keyIn('watched', sha('wrong ' + i), { ip: '198.51.100.' + (130 + i), country: 'US' });
    assert.deepStrictEqual(await alerts('watch:cancelled:' + keyId), ['A member\'s key file was cancelled']);
    // 3. The administrator: a new network alerts; a member's doesn't. And Aaron's own key file cancelled says so.
    const a = jar();
    const sa = await start(a, { login: 'chief', file: FILE_B, ip: '203.0.113.91', country: 'US' });
    await post(8041, 'chief', sa.code);
    assert.strictEqual((await finish(a, { ip: '203.0.113.91', country: 'US' })).signed_in, true);
    const chief = await me(a);
    await su.begin(async (x) => { await x.unsafe('set local role dog_owner'); await x.unsafe(`update app.members set is_admin = true where id = '${chief.member_id}'`); });
    assert.strictEqual((await keyIn('chief', FILE_B, { ip: '203.0.113.92', country: 'US' })).signed_in, true, 'the same /24: no new network');
    assert.deepStrictEqual(await alerts('watch:net:%', chief.member_id), []);
    assert.strictEqual((await keyIn('chief', FILE_B, { ip: '192.0.2.77', country: 'US' })).signed_in, true, 'still signed in');
    assert.deepStrictEqual(await alerts('watch:net:%', chief.member_id), ['Your account signed in from a new network']);
    // The same country gives each member a different hash.
    const [h1] = await owner(`select key_hash from app.watch_seen where member_id = '${who.member_id}' and kind = 'country' order by first_seen limit 1`);
    assert.ok(!(await owner(`select 1 from app.watch_seen where member_id = '${chief.member_id}' and key_hash = '${h1.key_hash}'`)).length);
    const [{ id: chiefKey }] = await owner(`select id from app.file_keys where member_id = '${chief.member_id}'`);
    for (let i = 0; i < 10; i++) await keyIn('chief', sha('guess ' + i), { ip: '198.51.100.' + (150 + i), country: 'US' });
    assert.deepStrictEqual(await alerts('watch:cancelled:' + chiefKey), ['Your own key file was cancelled']);
    // 5. Reaching for administrator powers: a member alerts, once a day per page; the administrator never does.
    const asMember = { actor: 'member', memberId: who.member_id, session: null };
    const whoSession = (await owner(`select token_hash from app.sessions where member_id = '${who.member_id}' order by created_at desc limit 1`))[0].token_hash;
    const asM = { ...asMember, session: whoSession };
    assert.strictEqual(await db.tx(web, asM, (x) => store.watchReach(x, 'controls')), true);
    assert.strictEqual(await db.tx(web, asM, (x) => store.watchReach(x, 'controls')), false, 'once a day');
    assert.deepStrictEqual(await alerts('watch:reach:' + who.member_id + ':%'), ['Someone reached for administrator powers']);
    const feedSrc = read('api/feed.js');
    assert.strictEqual((feedSrc.match(/await reach\(run, who, '(review|controls)'\)/g) || []).length, 4, 'all four administrator refusals in the feed API alert');
    // 6. A first-time sensitive action alerts once.
    await su.begin(async (x) => { await x.unsafe(`insert into app.jevs_decisions (action, subject_kind, member_id, level, mode, effect, applied, error, total, scores)
      values ('agent.key', 'member', '${who.member_id}', 'low', 'shadow', 'none', true, false, 0, '{}')`); });
    const first1 = await db.tx(web, asM, async (x) => (await x`select app.watch_first('agent.key') as a`)[0].a);
    assert.strictEqual(first1, true);
    await su.begin(async (x) => { await x.unsafe(`insert into app.jevs_decisions (action, subject_kind, member_id, level, mode, effect, applied, error, total, scores)
      values ('agent.key', 'member', '${who.member_id}', 'low', 'shadow', 'none', true, false, 0, '{}')`); });
    assert.strictEqual(await db.tx(web, asM, async (x) => (await x`select app.watch_first('agent.key') as a`)[0].a), false, 'not the first any more');
    assert.match(read('db/jevs.js'), /WATCH_FIRST = \['agent\.key', 'agent\.rules'\]/);
    await su.begin(async (x) => { await x.unsafe('set local role dog_owner'); await x.unsafe(`update app.members set is_admin = false where id = '${chief.member_id}'`); });
  });

  test('028 (go-live): the site\'s JEVs enforces, there is at most one administrator, and the founder\'s first code sign-in makes him administrator', async () => {
    const asOwner = (q) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); return [...await t.unsafe(q)]; });
    const adminOf = async (id) => (await owner(`select is_admin from app.members where id = '${id}'`))[0].is_admin;
    const sessionsOf = async (id) => Number((await owner(`select count(*) as n from app.sessions where member_id = '${id}'`))[0].n);
    await asOwner(`update app.members set is_admin = false where is_admin`);
    // Fix 7: the migrations leave the site's JEVs in enforce mode (this file's database is never put back in shadow).
    assert.strictEqual((await owner(`select value from app.jevs_settings where key = 'mode'`))[0].value, 'enforce');

    // A founder's earlier session, from before he was administrator.
    const old = jar();
    await post(304218593, 'MyChiefOS', (await start(old, { login: 'MyChiefOS' , ip: '198.51.100.21' })).code);
    assert.strictEqual((await finish(old)).signed_in, true);
    const aaron = (await me(old)).member_id;
    await asOwner(`update app.members set is_admin = false where id = '${aaron}'`);
    assert.strictEqual((await me(old)).signed_in, true, 'a member\'s session, before the promotion');

    // A member who isn't the founder: never promoted, even with no administrator.
    const m = jar();
    await post(8601, 'just-a-member', (await start(m, { login: 'just-a-member' , ip: '198.51.100.22' })).code);
    assert.strictEqual((await finish(m)).signed_in, true);
    assert.strictEqual(await adminOf((await me(m)).member_id), false);

    // The founder's code sign-in with no administrator: promoted, every earlier session ended, this browser signed in
    // as administrator with exactly one session.
    const b = jar();
    const g = await post(304218593, 'MyChiefOS', (await start(b, { login: 'MyChiefOS' , ip: '198.51.100.23' })).code);
    assert.deepStrictEqual(g.signin, { claimed: true, founder: true, alone: true });
    assert.strictEqual(g.alert, true, 'still alerts on GitHub');
    assert.strictEqual((await finish(b)).signed_in, true);
    assert.strictEqual(await adminOf(aaron), true);
    assert.strictEqual((await me(b)).member_id, aaron);
    assert.strictEqual((await me(old)).signed_in, false, 'the session from before the promotion is gone');
    assert.strictEqual(await sessionsOf(aaron), 1, 'only the browser that just signed in');
    const [audit] = await owner(`select detail->>'by' as by from app.audit_log where action = 'admin.set' and subject_id = '${aaron}' order by at desc limit 1`);
    assert.strictEqual(audit.by, 'founder code sign-in');
    // His key file was kept as well: the administrator signs in with it later, no post.
    assert.strictEqual(Number((await owner(`select count(*) as n from app.file_keys where member_id = '${aaron}'`))[0].n), 1);

    // Once an administrator exists, a founder claim is an ordinary sign-in: nothing ends, nobody else promoted.
    const b2 = jar();
    await post(304218593, 'MyChiefOS', (await start(b2, { login: 'MyChiefOS' , ip: '198.51.100.24' })).code);
    assert.strictEqual((await finish(b2)).signed_in, true);
    assert.strictEqual((await me(b)).signed_in, true, 'the administrator\'s other session stays');
    assert.strictEqual(await sessionsOf(aaron), 2);

    // At most one administrator, in the database.
    await assert.rejects(asOwner(`update app.members set is_admin = true where id = '${(await me(m)).member_id}'`), /members_one_admin/);

    // A refused promotion never locks him out: with a second sign-in method on his account, the founder's sign-in
    // stands as a member's, and the refusal is recorded by its error code only.
    await asOwner(`update app.members set is_admin = false where id = '${aaron}'`);
    await owner(`insert into app.identities (member_id, provider, fingerprint, key_version, level) values ('${aaron}', 'x', '${'e'.repeat(64)}', 1, 1)`);
    const b3 = jar();
    await post(304218593, 'MyChiefOS', (await start(b3, { login: 'MyChiefOS' , ip: '198.51.100.25' })).code);
    assert.strictEqual((await finish(b3)).signed_in, true, 'signed in');
    assert.strictEqual(await adminOf(aaron), false, 'not promoted');
    assert.strictEqual((await me(b2)).signed_in, true, 'and nothing of his was ended');
    const [refused] = await owner(`select detail from app.audit_log where action = 'admin.founder_refused' and subject_id = '${aaron}'`);
    assert.deepStrictEqual(refused.detail, { code: '42501' });
    await owner(`delete from app.identities where member_id = '${aaron}' and provider = 'x'`);

    // Only the gate can mark a claim as the founder's, and only the sign-in role can promote: not the site's role.
    for (const q of [`select app.founder_promote('${aaron}')`, `select app.code_claim('${'a'.repeat(64)}', '${'b'.repeat(64)}', '${'c'.repeat(64)}', true)`]) {
      await assert.rejects(web.begin(async (t) => { await t.unsafe('set local role dog_app'); await t.unsafe(q); }), /permission denied/, q);
    }
    // 023's three-argument claim (kept until the gate is redeployed) never marks the founder.
    const fn = (await owner(`select pg_get_functiondef('app.code_claim(text, text, text)'::regprocedure) as d`))[0].d;
    assert.match(fn, /app\.code_claim\(p_code_hash, p_fingerprint, p_login_hash, false\)/);
    await asOwner(`update app.members set is_admin = false where is_admin`);
  });

  test('after a code or key-file sign-in the person goes back to the page that sent them to /join, if it is on this site', async () => {
    const go = async (returnTo, ip) => {
      const b = jar();
      const s = await start(b, { login: 'returner', ip });
      await post(8701, 'returner', s.code);
      return (await finish(b, { body: returnTo === undefined ? {} : { return_to: returnTo } })).go;
    };
    assert.strictEqual(await go('/review?tab=reports', '198.51.100.61'), '/review?tab=reports');
    assert.strictEqual(await go(undefined, '198.51.100.62'), '/feed', 'nothing asked: the feed');
    for (const [bad, ip] of [['https://evil.example/x', '198.51.100.63'], ['//evil.example', '198.51.100.64'], ['/\\evil.example', '198.51.100.65'], ['javascript:alert(1)', '198.51.100.66']]) {
      assert.strictEqual(await go(bad, ip), '/feed', 'never another site: ' + bad);
    }
    const r = res();
    await flow.keyFileSignIn(req('POST', '/auth/key', { body: { login: 'returner', file: FILE_A, return_to: '/agents' }, ip: '198.51.100.67' }), r);
    assert.deepStrictEqual(JSON.parse(r.body), { signed_in: true, go: '/agents' });
    assert.match(read('join.js'), /if \(back\) fb\.return_to = back;/);
    assert.match(read('join.js'), /if \(back\) body\.return_to = back;/);
  });

  test('029: Aaron\'s administrator account is made inside the database, tied to MyChiefOS; his code sign-in lands in it and sets his key file (Aaron, Oct 29)', async () => {
    const asOwner = (q) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); return [...await t.unsafe(q)]; });
    await asOwner(`update app.members set is_admin = false where is_admin`);
    const fp = c.fingerprints(SITE_KEYS, 'github', '304218593')[0];
    // Without Vault and pgcrypto (this plain Postgres), the migration made nothing and said so.
    assert.strictEqual(Number((await owner(`select count(*) as n from app.audit_log where detail->>'by' = 'migration 029 (Aaron, Oct 29)'`))[0].n), 0);
    // The function that makes the account is used once inside 029 and dropped: nothing keeps a way to make it.
    assert.strictEqual((await owner(`select to_regprocedure('app.founder_account(text)') is null as gone`))[0].gone, true);
    // With Vault holding the gate's key (a stand-in here, as on Supabase), the migration's own block makes the account
    // administrator with the same fingerprint the gate and the site give MyChiefOS.
    await su.unsafe(`create schema if not exists vault; create table if not exists vault.decrypted_secrets (name text, decrypted_secret text);
      insert into vault.decrypted_secrets values ('dog_fingerprint_key_1', '${GATE_KEY}'); create schema if not exists extensions;
      create extension if not exists pgcrypto with schema extensions`);
    const doBlock = read('db/migrations/029_founder_account.sql'); // the whole migration again, as the runner would run it
    await su.begin((t) => t.unsafe(doBlock));
    const [made] = await owner(`select m.id, m.is_admin from app.members m join app.identities i on i.member_id = m.id where i.provider = 'github' and i.fingerprint = '${fp}'`);
    assert.strictEqual(made.is_admin, true, 'the account tied to MyChiefOS is the administrator');
    assert.strictEqual(Number((await owner(`select count(*) as n from app.sessions where member_id = '${made.id}'`))[0].n), 0, 'no sessions');
    // (Earlier tests in this file signed MyChiefOS in, so this member already exists here and 029 found it; on
    // production it is new, with no key file until his first code sign-in, which the check below shows sets one.)
    await su.begin((t) => t.unsafe(doBlock));
    assert.strictEqual(Number((await owner(`select count(*) as n from app.audit_log where action = 'admin.set' and detail->>'by' = 'migration 029 (Aaron, Oct 29)'`))[0].n), 1, 'run again, it changes nothing');
    // His process: a code posted from MyChiefOS signs into that same account, as administrator, and sets his key file.
    const before = Number((await owner(`select count(*) as n from app.audit_log where action = 'admin.set' and detail->>'by' = 'founder code sign-in'`))[0].n);
    const br = jar();
    await post(304218593, 'MyChiefOS', (await start(br, { login: 'MyChiefOS', ip: '198.51.100.71' })).code);
    assert.strictEqual((await finish(br)).signed_in, true);
    assert.strictEqual((await me(br)).member_id, made.id, 'into the account 029 made');
    assert.strictEqual((await owner(`select is_admin from app.members where id = '${made.id}'`))[0].is_admin, true);
    assert.strictEqual(Number((await owner(`select count(*) as n from app.file_keys where member_id = '${made.id}'`))[0].n), 1, 'his key file is set');
    assert.strictEqual(Number((await owner(`select count(*) as n from app.audit_log where action = 'admin.set' and detail->>'by' = 'founder code sign-in'`))[0].n), before, 'no promotion was needed');
    // Later, the username and key file sign him in with no post.
    const r = res();
    await flow.keyFileSignIn(req('POST', '/auth/key', { body: { login: 'MyChiefOS', file: FILE_A }, ip: '198.51.100.72' }), r);
    assert.deepStrictEqual(JSON.parse(r.body), { signed_in: true, go: '/feed' });
    await asOwner(`update app.members set is_admin = false where is_admin`);
  });

  test('sessions last a flat 30 days (Aaron, Oct 28): no idle limit', async () => {
    assert.strictEqual(require('../signin/config').IDLE_DAYS, 30);
    assert.strictEqual(require('../signin/config').SESSION_DAYS, 30);
  });
}
