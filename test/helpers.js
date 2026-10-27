// Test helpers: a fake GitHub (no network) and a fake request/response for our endpoints.
const path = require('path');

function fakeIssue(over) {
  return Object.assign({
    number: 1,
    title: 'Proposal: Add a weekly what-shipped post',
    state: 'open',
    labels: [{ name: 'proposal' }],
    user: { login: 'member1' },
    comments: 2,
    created_at: '2026-10-15T10:00:00Z',
    updated_at: '2026-10-15T10:00:00Z',
    html_url: 'https://github.com/MyChiefOS/start-of-something-great/issues/1',
    body: '### What should change?\n\nA weekly post listing what shipped.\n\n### Why?\n\nSo people can follow along.\n\n### Who is filing this?\n\nA person\n\n### If you\'re an agent, who are you acting for?\n\n_No response_\n\n### The handshake\n\n- [X] I agree'
  }, over || {});
}

// Replaces global fetch with a fake GitHub that serves the given issues.
function mockGitHub(issues, opts) {
  opts = opts || {};
  global.fetch = async (url) => {
    const u = String(url);
    let body = [];
    if (u.includes('/issues?')) body = issues;
    else if (u.includes('/commits')) body = opts.commits || [];
    return {
      status: 200,
      ok: true,
      headers: { get: (h) => (h === 'x-ratelimit-limit' ? '5000' : null) },
      json: async () => body
    };
  };
}

function fresh(mod) {
  const p = path.join(__dirname, '..', 'api', mod);
  for (const k of Object.keys(require.cache)) if (k.includes(path.join('api', ''))) delete require.cache[k];
  return require(p);
}

async function call(handler, method, url, body, reqHeaders) {
  const headers = {};
  let status = 200;
  let out = '';
  const req = { method, url, body, headers: Object.assign({ 'content-type': 'application/json' }, reqHeaders || {}) };
  const res = {
    set statusCode(v) { status = v; },
    get statusCode() { return status; },
    setHeader: (k, v) => { headers[k.toLowerCase()] = String(v); },
    end: (s) => { out = s || ''; }
  };
  await handler(req, res);
  let json = null;
  try { json = JSON.parse(out); } catch (e) { /* not json */ }
  return { status, headers, text: out, json };
}

// Fix 3 (019): the database decides who is acting, from proof, so tests give it the same proof production does.
// An agent acts with a real key (by its hash); the site itself acts with its own secret, whose hash the database keeps.
// su: a superuser connection to the test database (it may add a key row directly, as the owner's API would).
const TEST_SYSTEM_SECRET = 'test-only-system-secret-0123456789abcdef';
async function keyFor(su, agentId) {
  const hash = require('crypto').randomBytes(32).toString('hex');
  await su`insert into app.agent_keys (agent_id, key_hash) values (${agentId}, ${hash})`;
  return hash;
}
async function agentCtx(su, ownerId, agentId) {
  return { actor: 'agent', memberId: ownerId, agentId, keyHash: await keyFor(su, agentId) };
}
async function trustSystem(su, secret = TEST_SYSTEM_SECRET) {
  process.env.CRON_SECRET = secret;
  await su.begin(async (t) => {
    await t`set local role dog_owner`;
    await t`update app.actor_keys set system_hash = sha256(convert_to(${secret}, 'UTF8')) where singleton`;
  });
}

// Phase 1 (migration 021, RK82): a sign-in gives level 1 at most, and only JEVs makes a member level 2. Tests that need
// a level-2 member get there by the same database write JEVs's promotion makes, as JEVs's role (app.jevs_decide,
// 014_subagents.sql: "update app.members x set jevs_level2_at = now(), trust_level = 2"). The scoring that decides a
// promotion is tested in jevs.test.js.
async function promote(su, memberId) {
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_jevs');
    await t`update app.members set jevs_level2_at = now(), trust_level = 2 where id = ${memberId}`;
  });
}

module.exports = { fakeIssue, mockGitHub, fresh, call, keyFor, agentCtx, trustSystem, promote, TEST_SYSTEM_SECRET };
