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

module.exports = { fakeIssue, mockGitHub, fresh, call };
