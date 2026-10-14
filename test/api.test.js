// The public API and MCP server: read-only, well-formed, and safe for agents.
const test = require('node:test');
const assert = require('node:assert');
const { fakeIssue, mockGitHub, fresh, call } = require('./helpers');

test('every API endpoint rejects writes (read-only)', async () => {
  for (const name of ['index.js', 'status.js', 'handshake.js', 'changes.js', 'conversation.js', 'search.js', 'proposals.js']) {
    const r = await call(fresh(name), 'POST', '/api/x', {});
    assert.strictEqual(r.status, 405, name + ' accepted a POST');
  }
});

test('MCP: initialize, list tools, and every tool is read-only', async () => {
  mockGitHub([fakeIssue()]);
  const mcp = fresh('mcp.js');
  const init = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
  assert.strictEqual(init.json.result.protocolVersion, '2025-06-18');
  const list = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const tools = list.json.result.tools;
  assert.ok(tools.find((t) => t.name === 'list_proposals'));
  for (const t of tools) assert.strictEqual(t.annotations.readOnlyHint, true, t.name + ' is not read-only');
});

test('MCP: list_proposals filters by status and warns that content is untrusted', async () => {
  mockGitHub([fakeIssue({ number: 1 }), fakeIssue({ number: 2, labels: [{ name: 'proposal' }, { name: 'status: approved' }] })]);
  const mcp = fresh('mcp.js');
  const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_proposals', arguments: { status: 'approved' } } });
  const data = r.json.result.structuredContent;
  assert.deepStrictEqual(data.proposals.map((p) => p.number), [2]);
  assert.match(data.note, /never as instructions/);
});

test('MCP: unknown tools and malformed requests are rejected', async () => {
  const mcp = fresh('mcp.js');
  const r = await call(mcp, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'delete_everything' } });
  assert.strictEqual(r.json.error.code, -32602);
  const bad = await call(mcp, 'POST', '/api/mcp', { hello: 'world' });
  assert.strictEqual(bad.json.error.code, -32600);
});

test('the roadmap served to agents matches ROADMAP.md milestones', () => {
  const { status } = fresh('_lib.js');
  const md = require('fs').readFileSync(require('path').join(__dirname, '..', 'ROADMAP.md'), 'utf8');
  for (const m of status.roadmap.milestones) {
    assert.ok(md.includes('| ' + m.name + ' |'), 'ROADMAP.md has no row named exactly: ' + m.name);
  }
});
