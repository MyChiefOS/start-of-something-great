// S2, S3: the fixed break-in suite. It reads the list of tables from the database itself, so a table added later is
// covered automatically: anyone who can see or change a row of a new table fails this suite until a reviewed
// expectation says they may (the ratchet in ACCEPTANCE.md). Member A has data in every table; someone not signed in,
// member B and B's agent each try to read and change everything.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const posts = require('../db/posts');
const review = require('../db/review');
const controls = require('../db/controls');
const { migrate } = require('../scripts/migrate');

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('break-in tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('break-in suite (S2, S3)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_breakin_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
let A, B, BAgent, tables;

// What each outsider may see: their own rows, nothing else. Any table not listed here may show them nothing.
const MAY_SEE = {
  anon: {},
  B: { members: 1, identities: 1, sessions: 1, agents: 1, agent_keys: 1, agent_rules: 1 },
  BAgent: { members: 1, agents: 1, agent_rules: 1 }
};

async function signIn(level, name) {
  const token = c.token(32);
  const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1,
    level, displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  return { id: out.memberId, ctx: { actor: 'member', memberId: out.memberId } };
}

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 3 });

  // Aaron, so A's footprint includes moderation, brakes and notes.
  const aaron = await signIn(2, 'Aaron');
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${aaron.id}'`); });
  const admin = { actor: 'admin', memberId: aaron.id };
  // Member A, with something in every table.
  A = await signIn(2, 'Member A');
  const [agent] = await run(A.ctx, (t) => t`insert into app.agents (name) values ('A agent') returning id`);
  await run(A.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${agent.id}, ${c.sha256hex('a-key')})`);
  const aAgent = { actor: 'agent', memberId: A.id, agentId: agent.id };
  await run(aAgent, (t) => t`insert into app.agent_drafts (body) values ('A draft')`);
  const p = await run(A.ctx, (t) => posts.create(t, { body: 'A post' }));
  const other = await signIn(2, 'Other');
  const op = await run(other.ctx, (t) => posts.create(t, { body: 'other post' }));
  await run(A.ctx, (t) => review.report(t, { post: op.id, reason: 'spam', note: 'A reports' }));
  await run(other.ctx, (t) => review.report(t, { post: p.id, reason: 'other' }));
  await run(admin, (t) => controls.setBrake(t, { member: A.id, people_per_hour: 100, note: 'A brake' }));
  await run({ ...admin, note: 'A note' }, (t) => controls.setStatus(t, { member: A.id, status: 'banned' }));
  await run(admin, (t) => controls.setStatus(t, { member: A.id, status: 'active' }));
  await run({ actor: 'anon' }, (t) => store.emailTokenIssue(t, { tokenHash: c.sha256hex('tok'), emailFingerprints: [c.sha256hex('a@example.com')],
    browserHash: c.sha256hex('browser'), keyVersion: 1 }));
  await run({ actor: 'anon' }, (t) => store.rateLimitHit(t, { bucket: 'breakin', keyHash: c.sha256hex('a'), windowSeconds: 60, max: 5 }));
  // Member B (level 2) with an agent of its own.
  B = await signIn(2, 'Member B');
  const [bAgent] = await run(B.ctx, (t) => t`insert into app.agents (name) values ('B agent') returning id`);
  await run(B.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${bAgent.id}, ${c.sha256hex('b-key')})`);
  BAgent = { actor: 'agent', memberId: B.id, agentId: bAgent.id };
  tables = (await q(`select c.relname as name from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'app' and c.relkind in ('r', 'p') order by 1`)).map((r) => r.name);
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

const who = () => ({ anon: { actor: 'anon' }, B: B.ctx, BAgent });

test('the fixture really has member A\'s data in every table, so the checks below mean something', async () => {
  for (const t of tables) {
    if (t === 'schema_migrations') continue;
    const [r] = await q(`select count(*)::int as n from app.${t}`);
    assert.ok(r.n > 0, t + ' is empty in the fixture: add A\'s row to it');
  }
});

test('S2, S3: nobody sees rows that aren\'t theirs in any table, now or in tables added later', async () => {
  for (const [label, ctx] of Object.entries(who())) {
    for (const t of tables) {
      let n;
      try {
        [{ n }] = await run(ctx, (x) => x.unsafe(`select count(*)::int as n from app.${t}`));
      } catch (e) {
        assert.strictEqual(e.code, '42501', label + ' reading ' + t + ': ' + e.message);
        continue; // no right to read the table at all
      }
      assert.strictEqual(n, MAY_SEE[label][t] || 0, label + ' sees ' + n + ' rows of ' + t);
    }
  }
});

test('S2, S3: nobody changes or deletes rows that aren\'t theirs in any table', async () => {
  const ROLLBACK = new Error('rollback');
  for (const [label, ctx] of Object.entries(who())) {
    for (const t of tables) {
      const [{ col }] = await q(`select a.attname as col from pg_attribute a where a.attrelid = 'app.${t}'::regclass and a.attnum > 0 and not a.attisdropped order by a.attnum limit 1`);
      for (const stmt of [`update app.${t} set ${col} = ${col}`, `delete from app.${t}`]) {
        let affected = 0;
        try {
          await run(ctx, async (x) => { affected = (await x.unsafe(stmt)).count; throw ROLLBACK; });
        } catch (e) {
          if (e === ROLLBACK) {
            assert.ok(affected <= (MAY_SEE[label][t] || 0), label + ': "' + stmt + '" touched ' + affected + ' rows');
            continue;
          }
          assert.ok(['42501', 'P0001', '23503', '22023'].includes(e.code) || /only|never|can't|cannot|refuse|append-only/i.test(e.message),
            label + ': "' + stmt + '" failed in an unexpected way: ' + e.code + ' ' + e.message);
        }
      }
    }
  }
});

test('S3: nobody can even lock a row that isn\'t theirs for changing (what an update or delete could reach)', async () => {
  for (const [label, ctx] of Object.entries(who())) {
    for (const t of tables) {
      for (const lock of ['for update', 'for no key update']) {
        let n;
        try {
          [{ n }] = await run(ctx, (x) => x.unsafe(`select count(*)::int as n from (select 1 from app.${t} ${lock}) r`));
        } catch (e) {
          assert.strictEqual(e.code, '42501', label + ' locking ' + t + ': ' + e.message);
          continue;
        }
        assert.ok(n <= (MAY_SEE[label][t] || 0), label + ' can reach ' + n + ' rows of ' + t + ' to change');
      }
    }
  }
});

test('S2: someone not signed in can write nothing at all', async () => {
  for (const t of tables) {
    await assert.rejects(run({ actor: 'anon' }, (x) => x.unsafe(`insert into app.${t} default values`)), (e) => e.code !== undefined, t);
  }
  // And member A's data is all still there.
  const [{ n }] = await q(`select count(*)::int as n from app.posts where author_id = '${A.id}'`);
  assert.strictEqual(n, 1);
});
