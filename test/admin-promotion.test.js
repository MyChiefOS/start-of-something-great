// 025 (the CSO's reviews of the sign-in lock-down, Oct 29): nothing the site's own role does before Aaron is made
// administrator ends up with the administrator's standing. Each case was first shown as an attack on a throwaway
// database; each is now refused, and Aaron still signs in by code afterwards (his rule: nothing locks him out).
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const { migrate } = require('../scripts/migrate');
const { trustSystem, promote: jevs2 } = require('./helpers');

const SERVER = process.env.TEST_DATABASE_URL;
const hex = () => crypto.randomBytes(32).toString('hex');

if (!SERVER) {
  test('admin promotion (needs TEST_DATABASE_URL)', { skip: 'set TEST_DATABASE_URL to a throwaway Postgres server' }, () => {});
} else {
  const NAME = 'dog_promo_' + crypto.randomBytes(4).toString('hex');
  const WEB = NAME + '_web', PW = crypto.randomBytes(12).toString('hex');
  const at = (d, u, p) => { const x = new URL(SERVER); x.pathname = '/' + d; if (u) { x.username = u; x.password = p; } return x.toString(); };
  let server, su, web;
  test.before(async () => {
    server = postgres(SERVER, { max: 1, onnotice: () => {} });
    await server.unsafe('create database ' + NAME);
    su = postgres(at(NAME), { max: 4, prepare: false, onnotice: () => {} });
    await migrate(su);
    await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
    await trustSystem(su);
    web = postgres(at(NAME, WEB, PW), { max: 4, prepare: false, onnotice: () => {} });
  });
  test.after(async () => {
    await web.end(); await su.end();
    await server.unsafe(`drop database ${NAME} with (force)`); await server.unsafe(`drop role ${WEB}`); await server.end();
  });
  const asApp = (fn) => web.begin(async (t) => { await t.unsafe('set local role dog_app'); return fn(t); });
  const asRole = (role, fn) => su.begin(async (t) => { await t.unsafe('set local role ' + role); return fn(t); });
  const core = (t, fp, sess) => t.unsafe(`select * from app.sign_in_core('github', array['${fp}'], 1::smallint, 1::smallint, 'n', '${sess}', 30, null, null, null)`);
  const wrap = (t, fp, sess) => t.unsafe(`select * from app.sign_in('github', array['${fp}'], 1::smallint, 1::smallint, 'n', '${sess}', 30, null, null, null)`);
  const setAdmin = (id) => asRole('dog_owner', async (t) => (await t.unsafe(`select app.set_administrator('${id}') as r`))[0].r);
  const demote = (id) => asRole('dog_owner', (t) => t.unsafe(`update app.members set is_admin = false where id = '${id}'`));
  const actAdmin = (sess, id) => asApp((t) => t.unsafe(`select app.act_as('admin', '${id}', null, false, '${sess}', null, null) as a`));

  test('a session the site\'s role made before the promotion is ended by it (B1)', async () => {
    const f = hex();
    const [m] = await asRole('dog_signin', (t) => core(t, f, hex()));
    const s = hex();
    await asApp((t) => wrap(t, f, s));
    assert.strictEqual(await setAdmin(m.member_id), 'set');
    await assert.rejects(actAdmin(s, m.member_id), /not_acting/);
    await assert.rejects(asApp((t) => wrap(t, f, hex())), /admin_code_only/, 'and no new one can be made');
    const [back] = await asRole('dog_signin', (t) => core(t, f, hex()));
    assert.strictEqual(back.is_admin, true, 'Aaron signs in by code afterwards');
    await demote(m.member_id);
  });

  test('an account someone linked Aaron\'s GitHub to can\'t be made administrator, even after unlinking its own method (B2)', async () => {
    const fAaron = hex(), fAtk = hex(), s = hex();
    const [x] = await asApp((t) => wrap(t, fAtk, s));
    await asApp(async (t) => { await t.unsafe(`select app.act_as('member', '${x.member_id}', null, true, '${s}', null, null)`);
      return t.unsafe(`select * from app.identity_link('github', array['${fAaron}'], 1::smallint, 1::smallint, null, '${s}', null)`); });
    const [b] = await asRole('dog_signin', (t) => core(t, fAaron, hex()));
    assert.strictEqual(b.member_id, x.member_id, 'Aaron\'s first sign-in lands in the account that linked his GitHub');
    await assert.rejects(setAdmin(b.member_id), /exactly one sign-in method, GitHub/);
  });

  test('a sign-in still running when the promotion starts finishes first, and its session is ended too (N1)', async () => {
    const f = hex();
    const [c] = await asRole('dog_signin', (t) => core(t, f, hex()));
    const s = hex();
    let release; const gate = new Promise((r) => { release = r; });
    let started; const startedP = new Promise((r) => { started = r; });
    const inflight = asApp(async (t) => { const r = await wrap(t, f, s); started(); await gate; return r; });
    await startedP;
    const promoted = setAdmin(c.member_id);
    await new Promise((r) => setTimeout(r, 300));
    release();
    await inflight;
    assert.strictEqual(await promoted, 'set');
    await assert.rejects(actAdmin(s, c.member_id), /not_acting/);
    await demote(c.member_id);
  });

  test('an agent made before the promotion has its key revoked by it (N2)', async () => {
    const f = hex(), s = hex();
    const [d] = await asRole('dog_signin', (t) => core(t, f, hex()));
    await jevs2(su, d.member_id);
    await asApp((t) => wrap(t, f, s));
    const key = hex(), claim = hex();
    const [ag] = await asApp((t) => t.unsafe(`select app.agent_register('mine', 'x', '${key}', '${claim}') as id`));
    await asApp(async (t) => { await t.unsafe(`select app.act_as('member', '${d.member_id}', null, true, '${s}', null, null)`);
      return t.unsafe(`select app.agent_claim('${claim}') as id`); });
    assert.strictEqual(await setAdmin(d.member_id), 'set');
    await assert.rejects(asApp((t) => t.unsafe(`select app.act_as('agent', '${d.member_id}', '${ag.id}', false, null, '${key}', null)`)), /not_acting/);
    await demote(d.member_id);
  });
}
