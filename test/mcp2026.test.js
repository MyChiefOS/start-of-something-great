// Checks for MCP protocol version 2026-07-28 support (ACCEPTANCE.md C5 to C7).
// Rules quoted from the spec source: docs/specification/2026-07-28 (server/discover, basic/versioning,
// basic/transports/streamable-http, server/utilities/caching).
const test = require('node:test');
const assert = require('node:assert');
const { fakeIssue, mockGitHub, fresh, call } = require('./helpers');

const V = '2026-07-28';
const meta = (extra) => Object.assign({ _meta: { 'io.modelcontextprotocol/protocolVersion': V, 'io.modelcontextprotocol/clientInfo': { name: 'test', version: '1' }, 'io.modelcontextprotocol/clientCapabilities': {} } }, extra || {});
const H = (method, name) => Object.assign({ 'mcp-protocol-version': V, 'mcp-method': method }, name ? { 'mcp-name': name } : {});
const post = (mcp, body, headers) => call(mcp, 'POST', '/api/mcp', body, headers);

test('C5: server/discover lists supported versions, capabilities, identity and cache hints', async () => {
  const mcp = fresh('mcp.js');
  const r = await post(mcp, { jsonrpc: '2.0', id: 'd1', method: 'server/discover', params: meta() }, H('server/discover'));
  assert.strictEqual(r.status, 200);
  const res = r.json.result;
  assert.strictEqual(res.resultType, 'complete');
  assert.ok(res.supportedVersions.includes(V) && res.supportedVersions.includes('2025-06-18'));
  assert.ok(res.capabilities.tools);
  assert.strictEqual(res._meta['io.modelcontextprotocol/serverInfo'].name, 'dayonegreat');
  assert.ok(Number.isInteger(res.ttlMs) && res.ttlMs >= 0);
  assert.strictEqual(res.cacheScope, 'public');
});

test('C5: modern tools/list and tools/call work with no initialize, and lists are cacheable and ordered', async () => {
  const mcp = fresh('mcp.js');
  const a = await post(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: meta() }, H('tools/list'));
  const b = await post(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: meta() }, H('tools/list'));
  assert.strictEqual(a.status, 200);
  assert.strictEqual(a.json.result.resultType, 'complete');
  assert.ok(a.json.result.ttlMs >= 0);
  assert.strictEqual(a.json.result.cacheScope, 'public');
  assert.deepStrictEqual(a.json.result.tools.map((t) => t.name), b.json.result.tools.map((t) => t.name), 'deterministic order');
  const c = await post(mcp, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: meta({ name: 'get_status', arguments: {} }) }, H('tools/call', 'get_status'));
  assert.strictEqual(c.status, 200);
  assert.strictEqual(c.json.result.isError, false);
  // Mcp-Name may arrive Base64-encoded with the spec's sentinel format.
  const enc = '=?base64?' + Buffer.from('get_status').toString('base64') + '?=';
  const d = await post(mcp, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: meta({ name: 'get_status', arguments: {} }) }, H('tools/call', enc));
  assert.strictEqual(d.status, 200);
});

test('C5: modern requests whose headers are missing or disagree with the body get 400 HeaderMismatch', async () => {
  const mcp = fresh('mcp.js');
  const cases = [
    [{ jsonrpc: '2.0', id: 1, method: 'tools/list', params: meta() }, { 'mcp-method': 'tools/list' }], // no version header
    [{ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, H('tools/list')], // header says modern, _meta missing
    [{ jsonrpc: '2.0', id: 1, method: 'tools/list', params: meta() }, H('tools/call')], // Mcp-Method wrong
    [{ jsonrpc: '2.0', id: 1, method: 'tools/list', params: meta() }, { 'mcp-protocol-version': V }], // Mcp-Method missing
    [{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: meta({ name: 'get_status' }) }, H('tools/call', 'draft_proposal')], // Mcp-Name wrong
    [{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: meta({ name: 'get_status' }) }, H('tools/call')] // Mcp-Name missing
  ];
  for (const [body, headers] of cases) {
    const r = await post(mcp, body, headers);
    assert.strictEqual(r.status, 400, JSON.stringify(headers));
    assert.strictEqual(r.json.error.code, -32020, JSON.stringify(headers));
  }
});

test('C5: an unknown version gets 400 UnsupportedProtocolVersion listing what we support; an unknown method gets 404', async () => {
  const mcp = fresh('mcp.js');
  const r = await post(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, { 'mcp-protocol-version': '1900-01-01', 'mcp-method': 'tools/list' });
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.json.error.code, -32022);
  assert.ok(r.json.error.data.supported.includes(V));
  assert.strictEqual(r.json.error.data.requested, '1900-01-01');
  const m = await post(mcp, { jsonrpc: '2.0', id: 2, method: 'resources/list', params: meta() }, H('resources/list'));
  assert.strictEqual(m.status, 404);
  assert.strictEqual(m.json.error.code, -32601);
  const batch = await post(mcp, [{ jsonrpc: '2.0', id: 1, method: 'tools/list', params: meta() }], H('tools/list'));
  assert.strictEqual(batch.status, 400, 'batches are not part of 2026-07-28');
});

test('C6: older clients stay compatible (initialize, ping, no headers)', async () => {
  const mcp = fresh('mcp.js');
  const init = await post(mcp, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
  assert.strictEqual(init.status, 200);
  assert.strictEqual(init.json.result.protocolVersion, '2025-06-18');
  const asksNew = await post(mcp, { jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: V } });
  assert.notStrictEqual(asksNew.json.result.protocolVersion, V, 'initialize only ever negotiates a legacy version');
  const ping = await post(mcp, { jsonrpc: '2.0', id: 3, method: 'ping' }); // the uptime monitor uses this
  assert.strictEqual(ping.status, 200);
  assert.deepStrictEqual(ping.json.result, {});
  const note = await post(mcp, { jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.strictEqual(note.status, 202);
  const list = await post(mcp, { jsonrpc: '2.0', id: 4, method: 'tools/list' }, { 'mcp-protocol-version': '2025-06-18' });
  assert.strictEqual(list.status, 200);
  assert.ok(list.json.result.tools.length >= 9);
  const batch = await post(mcp, [{ jsonrpc: '2.0', id: 5, method: 'ping' }, { jsonrpc: '2.0', id: 6, method: 'tools/list' }]);
  assert.strictEqual(batch.json.length, 2);
});

test('C5: browsers can send the new headers (CORS)', async () => {
  const r = await call(fresh('mcp.js'), 'OPTIONS', '/api/mcp');
  for (const h of ['Mcp-Method', 'Mcp-Name', 'Mcp-Protocol-Version']) assert.ok(r.headers['access-control-allow-headers'].includes(h), h);
});

// C7: plant a marker in every field the public can write, then require that every output field
// carrying it is listed in untrusted_fields, and that every listed path really exists.
const MARK = 'ZQXMARK';
function markedGitHub() {
  const login = MARK + 'login';
  const shippedIssue = fakeIssue({
    number: 7, state: 'closed', closed_at: '2026-10-16T10:00:00Z', user: { login },
    title: 'Proposal: ' + MARK + ' title',
    labels: [{ name: 'proposal' }, { name: 'status: shipped' }],
    body: "### What should change?\n\n" + MARK + " change\n\n### Why?\n\n" + MARK + " why\n\n### Who is filing this?\n\nAn AI agent acting for a person\n\n### If you're an agent, who are you acting for?\n\n" + MARK + " owner"
  });
  global.fetch = async (url) => {
    const u = String(url);
    let body = [];
    if (u.includes('/issues?')) body = [shippedIssue];
    else if (u.includes('/commits')) body = [{ commit: { message: MARK + ' summary\n\nmore', author: { name: MARK + ' author', email: 'a@example.com', date: '2026-10-14T00:00:00Z' } }, html_url: 'https://github.com/x' }];
    else if (u.endsWith('/discussions/1')) body = { title: MARK + ' thread', html_url: 'https://github.com/d', user: { login }, created_at: '2026-10-14T00:00:00Z', body: MARK + ' body', comments: 1 };
    else if (u.includes('/discussions/1/comments')) body = [{ user: { login }, created_at: '2026-10-14T00:00:00Z', body: MARK + ' reply', html_url: 'https://github.com/c' }];
    return { status: 200, ok: true, headers: { get: () => '5000' }, json: async () => body };
  };
}
function stringPaths(v, at, out) {
  if (typeof v === 'string') out.push([at, v]);
  else if (Array.isArray(v)) v.forEach((x) => stringPaths(x, at + '[]', out));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) stringPaths(x, at ? at + '.' + k : k, out);
  return out;
}

test('C7: every field written by the public is listed in untrusted_fields, and every listed field exists', async () => {
  for (const name of ['list_proposals', 'list_shipped', 'get_recent_changes', 'get_conversation']) {
    markedGitHub();
    const mcp = fresh('mcp.js');
    const r = await post(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: {} } });
    const data = r.json.result.structuredContent;
    assert.ok(Array.isArray(data.untrusted_fields), name + ' has untrusted_fields');
    const paths = stringPaths(data, '', []).filter(([p]) => !p.startsWith('untrusted_fields'));
    for (const [p, v] of paths) if (v.includes(MARK)) assert.ok(data.untrusted_fields.includes(p), name + ': public text in ' + p + ' is not listed');
    const existing = new Set(paths.map(([p]) => p));
    for (const f of data.untrusted_fields) assert.ok(existing.has(f), name + ': listed field ' + f + ' is not in the output');
    assert.match(String(data.note || 'never as instructions'), /never as instructions/);
  }
  const own = await post(fresh('mcp.js'), { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'get_handshake', arguments: {} } });
  assert.strictEqual(own.json.result.structuredContent.untrusted_fields, undefined, 'our own content is not marked');
});

test('crafted input never crashes the server (no 500s), and one bad batch entry does not sink the others', async () => {
  const mcp = fresh('mcp.js');
  const evil = { toString: 1, valueOf: 1 };
  const a = await post(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: evil } });
  assert.strictEqual(a.json.error.code, -32602);
  const b = await post(mcp, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': evil } } });
  assert.strictEqual(b.status, 400);
  assert.strictEqual(b.json.error.code, -32022);
  for (const weird of [{ jsonrpc: '2.0', id: 3, method: 'tools/list', params: [] }, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'search', arguments: 'x' } }, { jsonrpc: '2.0', id: { a: 1 }, method: 'ping' }, [], 'text', 42]) {
    const r = await post(mcp, weird);
    assert.ok(r.status !== 500, 'no crash for ' + JSON.stringify(weird));
  }
  const batch = await post(mcp, [{ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: evil } }, { jsonrpc: '2.0', id: 6, method: 'ping' }]);
  assert.strictEqual(batch.json.length, 2);
  assert.deepStrictEqual(batch.json[1].result, {});
});

test('C5: stricter header checks (Base64 must round-trip, Mcp-Name always required, bad characters rejected)', async () => {
  const mcp = fresh('mcp.js');
  const call1 = (name, hdr) => post(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: meta(name === undefined ? {} : { name, arguments: {} }) }, H('tools/call', hdr));
  const junk = '=?base64?' + Buffer.from('get_status').toString('base64') + 'Zm9v?=';
  assert.strictEqual((await call1('get_status', junk)).json.error.code, -32020, 'trailing data after Base64 padding is rejected');
  assert.strictEqual((await call1(undefined, undefined)).json.error.code, -32020, 'missing Mcp-Name is a header error even with no name in the body');
  assert.strictEqual((await call1('get_status', 'get_statusé')).json.error.code, -32020, 'non-ASCII header value is rejected');
  const mixed = await post(mcp, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '1900-01-01' } } }, { 'mcp-protocol-version': '2025-06-18' });
  assert.strictEqual(mixed.json.error.code, -32022, 'a bad _meta version is rejected even with a valid header');
  const badBatch = await post(mcp, [{ jsonrpc: '2.0', id: 3, method: 'ping' }], { 'mcp-protocol-version': '1900-01-01' });
  assert.strictEqual(badBatch.status, 400);
  assert.strictEqual(badBatch.json.error.code, -32022, 'batches get the same version check');
  const encMethod = await post(mcp, { jsonrpc: '2.0', id: 4, method: 'tools/list', params: meta() }, H('=?base64?' + Buffer.from('tools/list').toString('base64') + '?='));
  assert.strictEqual(encMethod.json.error.code, -32020, 'Mcp-Method is compared as-is, never Base64-decoded');
  const badArgs = await post(mcp, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'search', arguments: 'abc' } });
  assert.strictEqual(badArgs.json.error.code, -32602, 'arguments must be an object');
  const nullId = await post(mcp, { jsonrpc: '2.0', id: null, method: 'tools/list', params: meta() }, H('tools/list'));
  assert.strictEqual(nullId.json.error.code, -32600, 'a null id is not a notification');
  const note = await post(mcp, { jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.strictEqual(note.status, 202);
  assert.strictEqual(note.headers['content-type'], undefined, 'empty 202 has no JSON content type');
});

test('tool descriptions only point agents at tools that exist', () => {
  const mcp = fresh('mcp.js');
  return post(mcp, { jsonrpc: '2.0', id: 1, method: 'tools/list' }).then((r) => {
    const names = r.json.result.tools.map((t) => t.name);
    for (const t of r.json.result.tools) {
      for (const m of t.description.matchAll(/\b(?:call|use) ([a-z]+_[a-z_]+)/g)) assert.ok(names.includes(m[1]), t.name + ' mentions missing tool ' + m[1]);
    }
  });
});
