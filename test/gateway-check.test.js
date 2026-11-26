// 090: the AI Gateway check. GC1 once a UTC day, one tiny request to each reviewer model plus OpenAI's; one alert with
// each model's status and the gateway's own message, with anything token-like removed. GC2 the wiki's health check
// counts the entries the active version holds, so a carried-over feed is not "empty".
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const roles = require('../oversight/roles');

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('the gateway check tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the gateway check against a database', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}
const { migrate } = require('../scripts/migrate');
const NAME = 'dog_gwc_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
const at = (d, user, password) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
let server, su, web;
const q = (s) => su.unsafe(s);
const run = (ctx, fn) => db.tx(web, ctx, fn);
const TOKEN = 'y'.repeat(40);

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(NAME, WEB, PW), { ssl: false, max: 2 });
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) { await server.unsafe(`drop database if exists ${NAME} with (force)`); await server.unsafe(`drop role if exists ${WEB}`); await server.end({ timeout: 5 }); }
});

test('GC1 once a day: each reviewer model and OpenAI\'s get one tiny request; one alert lists each answer, no token', async () => {
  const sent = [];
  const fetchImpl = async (url, o) => {
    const b = JSON.parse(o.body);
    sent.push({ model: b.model, auth: o.headers.authorization, max: b.max_tokens });
    if (b.model.startsWith('anthropic/') || b.model.startsWith('deepseek/')) {
      return { status: 403, text: async () => JSON.stringify({ error: { message: 'Model not allowed for this team. Bearer ' + TOKEN + ' ' + 'k'.repeat(50), type: 'forbidden' } }) };
    }
    return { status: 200, text: async () => '{}', json: async () => ({ choices: [{ message: { content: 'ok' } }] }) };
  };
  const out = await roles.gatewayCheck(run, TOKEN, fetchImpl);
  const models = sent.map((s) => s.model).sort();
  assert.ok(models.includes('openai/gpt-5-mini') && models.includes('openai/gpt-5.5') && models.includes('anthropic/claude-haiku-5.5') && models.includes('deepseek/deepseek-v3.2'), JSON.stringify(models));
  assert.ok(sent.every((s) => s.max === 5));
  assert.strictEqual(out.checked, models.length);
  const [n] = await q(`select title, body from app.notices where dedupe_key like 'gateway-check:%'`);
  assert.match(n.title, /^AI Gateway check: \d+ of \d+ models refused$/);
  assert.match(n.body, /openai\/gpt-5-mini: 200/);
  assert.match(n.body, /anthropic\/claude-haiku-5\.5: 403 \(Model not allowed for this team\. Bearer \[removed\] \[removed\]\)/);
  assert.ok(!n.body.includes(TOKEN) && !n.body.includes('k'.repeat(50)), 'nothing token-like in the alert');
  // Once a day: a second run the same day sends nothing.
  const again = [];
  assert.deepStrictEqual(await roles.gatewayCheck(run, TOKEN, async (u, o) => { again.push(o); return { status: 200 }; }), { checked: 0 });
  assert.strictEqual(again.length, 0);
  // Only the timer may claim or record: an administrator's session can't.
  await assert.rejects(run({ actor: 'admin', memberId: crypto.randomUUID(), session: 'x', fresh: true }, (t) => t`select app.gateway_check_record('[]'::jsonb)`), /./);
});

test('GC2 the wiki health check: a feed carried over with its entries is not empty; a feed with none is', async () => {
  const [v] = await q(`insert into app.wiki_versions (status, entries, packages, indicators, sources) values ('active', 1, 0, 1, '{"spamhaus":0,"phishtank":0,"nvd":5,"kev":1}') returning id`);
  await q(`insert into app.wiki_indicators (version_id, kind, value, source) values ('${v.id}', 'cidr', '192.0.2.0/24', 'spamhaus')`).catch(async () => {
    const cols = (await q(`select string_agg(column_name, ',') c from information_schema.columns where table_schema='app' and table_name='wiki_indicators'`))[0].c;
    throw new Error('wiki_indicators columns: ' + cols);
  });
  const [{ r }] = await run({ actor: 'anon' }, (t) => t`select app.wiki_health_check() as r`);
  assert.ok(!r.problems.includes('empty: spamhaus'), JSON.stringify(r.problems));
  assert.ok(r.problems.includes('empty: phishtank'), JSON.stringify(r.problems));
});
