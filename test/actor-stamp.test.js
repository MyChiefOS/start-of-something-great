// Fix 3 (harness/PLAN.md; 019): the database decides who is acting. Until 019 the site said who was acting with plain
// settings, and anyone holding the site's database login could act as Aaron. These are the attacks the prototype
// (test/prototypes/actor-stamp.js) tried on Oct 25, now against the real migration, through the site's own code path.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');
const { keyFor, trustSystem, promote } = require('./helpers');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

test('fix 3: the database\'s idle limit for sessions is the site\'s (signin/config.js IDLE_DAYS)', () => {
  // The newest migration that defines app.act_as decides (019; 023 since Aaron's 30 days, Oct 28).
  const dir = path.join(root, 'db', 'migrations');
  const last = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()
    .map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).filter((s) => /function app\.act_as\(/.test(s)).pop();
  const all = [...last.matchAll(/app\.session_resolve\(p_session, (\d+)\)/g)].map((m) => Number(m[1]));
  assert.deepStrictEqual(all, [require('../signin/config').IDLE_DAYS]);
});

if (!SERVER) {
  test('actor stamp tests need TEST_DATABASE_URL', { skip: !process.env.CI && 'set TEST_DATABASE_URL' }, () => { if (process.env.CI) assert.fail('no database'); });
} else {
  const NAME = 'dog_stamp_' + crypto.randomBytes(4).toString('hex');
  const WEB = 'dog_web_stamp_' + crypto.randomBytes(3).toString('hex');
  const PW = crypto.randomBytes(18).toString('base64url');
  let server, su, web;
  const at = (user, password) => { const u = new URL(SERVER); u.pathname = '/' + NAME; if (user) { u.username = user; u.password = password; } return u.toString(); };
  const run = (ctx, fn) => db.tx(web, ctx, fn);
  // The site's own login, raw: what someone holding it could do without going through db/index.js.
  const raw = (fn) => web.begin(async (t) => { await t`set local role dog_app`; return fn(t); });
  const who = (t) => t`select app.actor_kind() as kind, app.current_member() as member, app.current_agent() as agent,
    current_setting('app.fresh', true) as fresh`.then((r) => r[0]);

  async function member(level = 2) {
    const token = crypto.randomBytes(32).toString('base64url');
    const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [sha(crypto.randomUUID())], keyVersion: 1,
      level: Math.min(level, 1), displayName: 'Member', sessionHash: sha(token), sessionDays: 30 }));
    if (level >= 2) await promote(su, out.memberId);
    return { id: out.memberId, session: sha(token), ctx: { actor: 'member', memberId: out.memberId, session: sha(token) } };
  }

  test.before(async () => {
    server = postgres(SERVER, { max: 1, onnotice: () => {} });
    await server.unsafe('create database ' + NAME);
    su = postgres(at(), { max: 2, onnotice: () => {} });
    await migrate(su);
    await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
    web = db.connect(at(WEB, PW), { ssl: false, max: 3 });
  });
  test.after(async () => {
    for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
    if (server) { await server.unsafe(`drop database if exists ${NAME} with (force)`); await server.unsafe(`drop role if exists ${WEB}`); await server.end({ timeout: 5 }); }
  });

  test('fix 3: a real session acts as its member, decided by the database', async () => {
    const m = await member();
    const w = await run(m.ctx, who);
    assert.deepStrictEqual({ kind: w.kind, member: w.member }, { kind: 'member', member: m.id });
  });

  test('fix 3: the site\'s login declaring itself Aaron with plain settings counts as nobody', async () => {
    const m = await member();
    await su.begin(async (t) => { await t`set local role dog_owner`; await t`update app.members set is_admin = true where id = ${m.id}`; });
    const w = await raw(async (t) => {
      await t`select set_config('app.actor', 'admin', true), set_config('app.member_id', ${m.id}, true)`;
      return who(t);
    });
    assert.deepStrictEqual({ kind: w.kind, member: w.member }, { kind: 'anon', member: null });
    const made = await raw(async (t) => {
      await t`select set_config('app.actor', 'admin', true), set_config('app.member_id', ${m.id}, true), set_config('app.stamp', ${'0'.repeat(64)}, true)`;
      return who(t);
    });
    assert.strictEqual(made.kind, 'anon', 'a made-up stamp counts for nothing');
  });

  test('fix 3: editing a stamped actor, or copying a stamp into another transaction, counts as nobody', async () => {
    const m = await member();
    const edited = await run(m.ctx, async (t) => { await t`select set_config('app.actor', 'admin', true)`; return who(t); });
    assert.strictEqual(edited.kind, 'anon', 'member edited to admin');
    const stamp = await run(m.ctx, (t) => t`select current_setting('app.stamp') as s`.then((r) => r[0].s));
    const replay = await raw(async (t) => {
      await t`select set_config('app.actor', 'member', true), set_config('app.member_id', ${m.id}, true), set_config('app.agent_id', '', true),
        set_config('app.fresh', '', true), set_config('app.session', ${m.session}, true), set_config('app.stamp', ${stamp}, true)`;
      return who(t);
    });
    assert.strictEqual(replay.kind, 'anon', 'a stamp from an earlier transaction');
  });

  test('fix 3: proof that doesn\'t match the claim is refused outright', async () => {
    const a = await member(), b = await member();
    await assert.rejects(run({ actor: 'member', memberId: a.id, session: b.session }, who), /not_acting/, 'another member\'s session');
    await assert.rejects(run({ actor: 'admin', memberId: a.id, session: a.session }, who), /not_acting/, 'admin claimed by a member who isn\'t');
    await assert.rejects(run({ actor: 'member', memberId: a.id }, who), /need the session/, 'no session at all');
    await assert.rejects(raw((t) => t`select app.act_as('member', ${a.id}::uuid, null, false, ${sha('made up')}, null, null)`), /not_acting/,
      'a made-up session, calling the database directly');
  });

  test('fix 3: "fresh" is the database\'s call, from the session\'s own age', async () => {
    const m = await member();
    assert.strictEqual((await run({ ...m.ctx, fresh: true }, who)).fresh, '1', 'a session made a moment ago is fresh');
    await su`update app.sessions set created_at = now() - interval '11 minutes' where token_hash = ${m.session}`;
    assert.strictEqual((await run({ ...m.ctx, fresh: true }, who)).fresh, '', 'an 11-minute-old session isn\'t, whatever the site says');
  });

  test('fix 3: an agent acts only with a live key of its own, for its own owner', async () => {
    const owner = await member(2), other = await member(2);
    const [ag] = await run(owner.ctx, (t) => t`insert into app.agents (name) values ('Stamped') returning id`);
    const [ag2] = await run(other.ctx, (t) => t`insert into app.agents (name) values ('Someone else') returning id`);
    const key = await keyFor(su, ag.id), key2 = await keyFor(su, ag2.id);
    const w = await run({ actor: 'agent', memberId: owner.id, agentId: ag.id, keyHash: key }, who);
    assert.deepStrictEqual({ kind: w.kind, member: w.member, agent: w.agent }, { kind: 'agent', member: owner.id, agent: ag.id });
    await assert.rejects(run({ actor: 'agent', memberId: owner.id, agentId: ag.id, keyHash: key2 }, who), /not_acting/, 'another agent\'s key');
    await su`update app.agent_keys set revoked_at = now() where key_hash = ${key}`;
    await assert.rejects(run({ actor: 'agent', memberId: owner.id, agentId: ag.id, keyHash: key }, who), /not_acting/, 'a revoked key');
  });

  test('fix 3: the site itself acts only with its own secret, and only once fix 8 has stored its hash (route B: by migration)', async () => {
    delete process.env.CRON_SECRET;
    await assert.rejects(run({ actor: 'system' }, who), /not_acting/, 'no secret');
    process.env.CRON_SECRET = 'a-guess-at-the-secret';
    await assert.rejects(run({ actor: 'system' }, who), /not_acting/, 'no hash stored yet (until fix 8)');
    await trustSystem(su);
    assert.strictEqual((await run({ actor: 'system' }, who)).kind, 'system');
    process.env.CRON_SECRET = 'a-guess-at-the-secret';
    await assert.rejects(run({ actor: 'system' }, who), /not_acting/, 'the wrong secret');
  });

  test('fix 3: the site\'s role can\'t read the stamp key or make a stamp', async () => {
    await assert.rejects(raw((t) => t`select stamp_key from app.actor_keys`), /permission denied/);
    await assert.rejects(raw((t) => t`select app.actor_stamp('admin', '', '', '', '')`), /permission denied/);
  });

  test('fix 3: the setup run\'s administrator step still works, acting as the site itself by the owner\'s stamp', async () => {
    const m = await member();
    await su.begin(async (t) => { await t`set local role dog_owner`; await t`update app.members set is_admin = false where is_admin`; });
    const out = await su.begin(async (t) => { await t`set local role dog_owner`; return (await t`select app.set_administrator(${m.id}) as r`)[0].r; });
    assert.strictEqual(out, 'set');
    const [{ admin }] = await su`select is_admin as admin from app.members where id = ${m.id}`;
    assert.strictEqual(admin, true);
  });
}
