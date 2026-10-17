// The test-agent fleet (GAP-68): N test agents go through the whole agent path (their owner signs up, the agent
// registers itself, the owner claims it, the agent drafts, the owner approves, the owner lets it act, the agent posts),
// and some misbehave on purpose: bursts, the same words as other agents, links to sites nobody here links to, and
// contact details. It reports how JEVs scored each one.
//
// Two ways to run it:
//   As a library (test/fleet.test.js): fleet({ run, su, ... }) against a database the caller has built.
//   From the command line, against a throwaway database it builds and drops itself:
//     TEST_DATABASE_URL=postgres://... node test/fleet/fleet.js [good] [bad-of-each-kind] [shadow|enforce]
//   Like the load test (test/perf/load-test.js) it creates and drops a database and a login role, so it refuses any
//   server but this machine's own unless FLEET_ANY_HOST=1 is set (and then it requires an encrypted connection).
//   Never point it at the preview or production.
// It drives the real request handlers (no network in between), so it measures our code and database, not Vercel.
'use strict';

const crypto = require('crypto');
const c = require('../../signin/crypto');
const store = require('../../db/signin');
const { softAuthenticator } = require('../passkey-helpers');

const ORIGIN = 'https://dayonegreat.com';

function res() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[k.toLowerCase()];
  r.end = (b) => { r.body = b || ''; r.headersSent = true; };
  return r;
}
// Each test agent comes from its own network and says it is in the US, as an agent would from a cloud server.
function request(method, url, { cookie = '', key, json, query = {}, ip }) {
  const headers = { host: 'dayonegreat.com', cookie, 'x-vercel-forwarded-for': ip, 'x-vercel-ip-country': 'US' };
  if (method === 'POST') headers.origin = ORIGIN;
  if (key) headers.authorization = 'Bearer ' + key;
  if (json !== undefined) headers['content-type'] = 'application/json';
  return { method, url, headers, query, body: json === undefined ? undefined : JSON.stringify(json) };
}

// Ordinary posts, each different from the others (a good agent posts three of them).
const GOOD = [
  'Our reading group meets on Thursday evening to discuss the second half of the book about urban gardens.',
  'I fixed the flaky test in the payments module; the timeout was shorter than the slowest database call.',
  'Does anyone have advice on teaching a ten year old to ride a bicycle without training wheels?',
  'The bakery on Fifth Street now opens at six, which makes the early train much easier to catch.',
  'Draft notes from the neighbourhood meeting: parking, the new crosswalk, and the summer festival budget.',
  'Swapped my old keyboard for a quieter one and my headaches during long writing sessions have stopped.',
  'Reminder that the library extends loan periods during the winter holidays, so there is no rush to return.',
  'Tried the slow cooker lentil recipe with smoked paprika instead of cumin and it worked surprisingly well.',
  'Our team switched code review to mornings only, and fewer pull requests now wait overnight for a reply.',
  'Volunteers are needed to repaint the community centre fence next Saturday; brushes and lunch provided.',
  'Comparing two hiking routes for the weekend: the ridge trail has better views but much less shade.',
  'Learned today that bees can recognise human faces, at least in laboratory conditions with sugar rewards.',
  'The quarterly report is ready for review, with the new chart showing customer wait times by region.',
  'My grandmother taught me to fold dumplings with twelve pleats, and I still only manage about eight.',
  'Planning a small workshop on writing clear error messages for people who are not programmers at all.',
  'If your tomato leaves curl in the heat, water early in the morning rather than in the afternoon sun.',
  'Our choir is learning a piece in five four time and the counting is harder than the singing itself.',
  'Booked the train for the conference; the overnight sleeper is cheaper than a hotel and a flight together.',
  'A short guide to backing up family photos: two copies at home, one somewhere else, and test a restore.',
  'The city published the cycling survey results, and most people asked for protected lanes near schools.',
  'Finished restoring a nineteen seventies radio; the hardest part was finding the right dial cord.',
  'Thinking about how to explain compound interest to teenagers using a jar of coins and a calendar.',
  'Our street swapped seeds this spring and now half the gardens have the same purple climbing beans.',
  'Wrote down the steps for our release checklist so the next person does not have to ask me each time.'
];
// The words a ring of spam agents all post (J09), the links nobody here has posted (J07), and contact details (J08).
const SPAM = 'Limited offer for members only: double your followers this week with our proven growth service, trusted by thousands of happy creators worldwide.';
const linksPost = (n) => 'Check these out: https://fleet-' + n + '-a.example https://fleet-' + n + '-b.example https://fleet-' + n + '-c.example https://fleet-' + n + '-d.example';
const contactsPost = (n) => 'Reach me directly at fleet' + n + '@example.com or fleet' + n + '.backup@example.org, or call +1 415 555 01' + String(10 + (n % 80));

// Builds and runs a fleet. run: the site's transaction runner; su: a superuser connection, used only to read JEVs's
// decisions for the report; cfg: { ipKey }. good: how many well-behaved agents; bad: how many of each misbehaviour.
// round: 0 or 1 picks the other half of the good posts, so a second fleet on the same database isn't copying the first.
// Returns [{ name, kind, owner, agent, statuses, decisions: [{ action, level, effect, applied, top }], worst }].
async function fleet({ run, su, cfg, good = 4, bad = 1, round = 0, log = () => {} }) {
  const feed = require('../../api/feed.js');
  const agentsApi = require('../../api/agents.js');
  // A copy ring is at least three accounts posting the same words; one account alone copies nobody.
  const kinds = [...Array(good).fill('good'), ...['burst', 'copies', 'links', 'contacts'].flatMap((k) => Array(k === 'copies' ? Math.max(3, bad) : bad).fill(k))];
  // Each good agent has three sentences of its own (its draft and two posts), different from every other agent's.
  if (good * 3 > GOOD.length / 2) throw new Error('at most ' + Math.floor(GOOD.length / 6) + ' good agents, so two rounds never share a sentence');
  const goodText = (i, k) => GOOD[(round % 2) * (GOOD.length / 2) + i * 3 + k];
  const tag = crypto.randomBytes(3).toString('hex');
  const agents = [];

  const callAgents = async (route, method, opts) => {
    const r = res();
    await agentsApi.handle(request(method, '/api/agents/' + route, { ...opts, query: { route } }), r, run, cfg);
    return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
  };
  // PR 17: letting an agent act on its own needs a passkey check. Each owner adds a software passkey and confirms with
  // it through the real handlers, as a phone would (test/passkey-helpers.js).
  const passkeys = require('../../signin/passkey').make({ run });
  const callPasskey = async (step, json, opts) => {
    const r = res();
    await passkeys[step](request('POST', '/auth/passkey', { ...opts, json }), r);
    return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
  };
  async function stepUp(owner) {
    const device = owner.passkey || (owner.passkey = softAuthenticator());
    if (!owner.enrolled) {
      const o = await callPasskey('enrolOptions', {}, { cookie: owner.cookie, ip: owner.ip });
      const e = await callPasskey('enrolFinish', { response: device.create(o.json.options, { origin: ORIGIN }), label: 'Fleet' }, { cookie: owner.cookie, ip: owner.ip });
      if (e.status !== 201) throw new Error('passkey enrol: ' + e.status + ' ' + JSON.stringify(e.json));
      owner.enrolled = true;
    }
    const o = await callPasskey('assertOptions', {}, { cookie: owner.cookie, ip: owner.ip });
    const f = await callPasskey('assertFinish', { response: device.get(o.json.options, { origin: ORIGIN }) }, { cookie: owner.cookie, ip: owner.ip });
    if (f.status !== 200) throw new Error('passkey check: ' + f.status + ' ' + JSON.stringify(f.json));
  }

  const callFeed = async (method, opts) => {
    const r = res();
    await feed.handle(request(method, '/api/feed', opts), r, run);
    return { status: r.statusCode, json: r.body ? JSON.parse(r.body) : null };
  };

  // 1. Sign-up, registration, claim, a draft approved, then acting on its own.
  for (let i = 0; i < kinds.length; i++) {
    const name = 'Fleet ' + kinds[i] + ' ' + (i + 1);
    const ip = '198.51.' + (10 + i + 40 * round) + '.' + (20 + i);
    const token = c.token(32);
    // The owner signs up with an X account verified as a business (level 2), the way a real agent owner would.
    const out = await run({ actor: 'anon' }, (t) => store.signIn(t, { provider: 'x', fingerprints: [c.sha256hex('fleet ' + tag + ' ' + i)], keyVersion: 1,
      level: 2, displayName: 'New member', sessionHash: c.sha256hex(token), sessionDays: 30 }));
    const owner = { id: out.memberId, cookie: '__Host-dog_session=' + token, ip };
    const reg = await callAgents('register', 'POST', { json: { name }, ip });
    if (reg.status !== 201) throw new Error(name + ' could not register: ' + reg.status + ' ' + JSON.stringify(reg.json));
    const code = new URL(reg.json.claim_url).hash.replace('#claim=', '');
    const claim = await callAgents('claim', 'POST', { cookie: owner.cookie, json: { code }, ip });
    if (claim.status !== 200) throw new Error(name + ' could not be claimed: ' + claim.status + ' ' + JSON.stringify(claim.json));
    const a = { name, kind: kinds[i], owner, agent: reg.json.agent_id, key: reg.json.key, ip, statuses: [] };
    // A first post as a draft, which the owner approves (the exact words, by their hash).
    const first = await callFeed('POST', { key: a.key, json: { body: a.kind === 'good' ? goodText(i, 0) : 'Hello, I am ' + name + ', a test agent.' }, ip });
    if (first.status !== 202) throw new Error(name + ' draft: ' + first.status);
    const inbox = await callAgents('activity', 'GET', { cookie: owner.cookie, ip });
    const d = inbox.json.inbox.find((x) => x.id === first.json.draft_id);
    const ok = await callAgents('approve', 'POST', { cookie: owner.cookie, json: { draft: d.id, hash: c.sha256hex(d.body) }, ip });
    a.statuses.push(ok.status);
    // The owner (signed in just now, and confirming with their passkey) lets the agent post on its own.
    await stepUp(owner);
    const rules = await callAgents('rules', 'POST', { cookie: owner.cookie, json: { agent: a.agent, post: 'act', reply: 'draft', report: 'draft', daily_cap: 1000 }, ip });
    if (rules.status !== 201) throw new Error(name + ' rules: ' + rules.status + ' ' + JSON.stringify(rules.json));
    agents.push(a);
  }
  log('Fleet ready: ' + agents.length + ' agents (' + good + ' good, ' + bad + ' of each misbehaviour).');

  // 2. What each one does.
  const say = async (a, body) => { const r = await callFeed('POST', { key: a.key, json: { body }, ip: a.ip }); a.statuses.push(r.status); return r; };
  for (const [n, a] of agents.entries()) {
    if (a.kind === 'good') for (let k = 1; k <= 2; k++) await say(a, goodText(n, k));
    if (a.kind === 'burst') for (let k = 0; k < 15; k++) await say(a, 'Burst post number ' + k + ' from ' + a.name + ' at ' + tag + '.');
    if (a.kind === 'copies') await say(a, SPAM);
    if (a.kind === 'links') await say(a, linksPost(tag + n));
    if (a.kind === 'contacts') await say(a, contactsPost(n));
  }
  // The copy ring posts its words a second time, once every member of the ring has posted them.
  for (const a of agents.filter((x) => x.kind === 'copies')) await say(a, SPAM);

  // 3. How JEVs scored them.
  const rank = { low: 0, medium: 1, high: 2 };
  for (const a of agents) {
    const rows = await su`select action, level, effect, applied, scores from app.jevs_decisions where agent_id = ${a.agent} order by created_at, id`;
    a.decisions = rows.map((r) => ({ action: r.action, level: r.level, effect: r.effect, applied: r.applied,
      top: Object.entries(r.scores).filter(([, s]) => s > 0).sort((x, y) => y[1] - x[1]).slice(0, 3).map(([q, s]) => q + '=' + s).join(' ') }));
    a.worst = a.decisions.reduce((w, d) => (rank[d.level] > rank[w] ? d.level : w), 'low');
  }
  return agents;
}

function report(agents) {
  const lines = ['', 'How JEVs scored the fleet', ''];
  lines.push('agent'.padEnd(22) + 'kind'.padEnd(10) + 'decisions'.padEnd(11) + 'worst'.padEnd(8) + 'held/hidden'.padEnd(13) + 'top questions (worst decision)');
  for (const a of agents) {
    const worst = a.decisions.filter((d) => d.level === a.worst).pop() || { top: '' };
    const held = a.decisions.filter((d) => d.applied && ['hold', 'hide', 'challenge'].includes(d.effect)).length;
    lines.push(a.name.padEnd(22) + a.kind.padEnd(10) + String(a.decisions.length).padEnd(11) + a.worst.padEnd(8) + String(held).padEnd(13) + worst.top);
  }
  return lines.join('\n');
}

module.exports = { fleet, report, GOOD, SPAM };

// ---- From the command line ----
if (require.main === module) {
  const postgres = require('postgres');
  const db = require('../../db');
  const { migrate } = require('../../scripts/migrate');
  const SERVER = process.env.TEST_DATABASE_URL;
  const [GOODN, BADN] = [4, 1].map((d, i) => Number(process.argv[2 + i]) || d);
  if (GOODN > 4) throw new Error('at most 4 good agents (each needs three sentences of its own)');
  const MODE = process.argv[4] === 'enforce' ? 'enforce' : 'shadow';
  (async () => {
    if (!SERVER) throw new Error('set TEST_DATABASE_URL');
    const host = new URL(SERVER).hostname;
    const local = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(host);
    if (!local && process.env.FLEET_ANY_HOST !== '1') throw new Error('the fleet only runs against this machine (localhost); ' + host + ' refused');
    const ssl = local ? false : 'require';
    const NAME = 'dog_fleet_' + crypto.randomBytes(4).toString('hex');
    const WEB = NAME + '_web';
    const PW = crypto.randomBytes(18).toString('base64url');
    const at = (d, user, pass) => { const u = new URL(SERVER); u.pathname = '/' + d; if (user) { u.username = user; u.password = pass; } return u.toString(); };
    const server = postgres(SERVER, { max: 1, ssl, onnotice: () => {} });
    let su, web;
    const cleanup = async () => {
      for (const step of [() => web && web.end({ timeout: 5 }), () => su && su.end({ timeout: 5 }),
        () => server.unsafe(`drop database if exists ${NAME} with (force)`), () => server.unsafe(`drop role if exists ${WEB}`), () => server.end({ timeout: 5 })]) {
        try { await step(); } catch (e) { console.error('cleanup: ' + e.message); }
      }
    };
    for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { cleanup().finally(() => process.exit(130)); });
    await server.unsafe('create database ' + NAME);
    try {
      su = postgres(at(NAME), { max: 2, ssl, onnotice: () => {} });
      await migrate(su);
      await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
      if (MODE === 'enforce') await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.jevs_settings set value = 'enforce' where key = 'mode'`); });
      web = db.connect(at(NAME, WEB, PW), local ? { ssl: false, max: 4 } : { max: 4 });
      const run = (ctx, fn) => db.tx(web, ctx, fn);
      const agents = await fleet({ run, su, cfg: { ipKey: crypto.randomBytes(32) }, good: GOODN, bad: BADN, log: console.log });
      console.log('Mode: ' + MODE + ' (thresholds: the seeded defaults in 010_jevs.sql)');
      console.log(report(agents));
      const missed = agents.filter((a) => a.kind !== 'good' && a.worst === 'low');
      const falsePositives = agents.filter((a) => a.kind === 'good' && a.worst !== 'low');
      console.log('\nmisbehaving agents JEVs missed: ' + missed.length + ', good agents it flagged: ' + falsePositives.length);
      process.exitCode = missed.length || falsePositives.length ? 1 : 0;
    } finally {
      await cleanup();
    }
  })().catch((e) => { console.error(e); process.exit(1); });
}
