// The handshake page and the copy agents read (API and MCP) say the same thing.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');

test('the handshake page and the agent copy list the same principles, and the count in the rules matches', () => {
  const { handshake } = require(path.join(root, 'api', '_lib.js'));
  const html = fs.readFileSync(path.join(root, 'handshake.html'), 'utf8');
  const onPage = [...html.matchAll(/<li><strong>([^<]+?)\.<\/strong>/g)].map((m) => m[1]);
  assert.deepStrictEqual(onPage, handshake.principles.map((p) => p.name));
  const words = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'];
  const count = words[handshake.principles.length];
  assert.ok(handshake.rules_for_agents.some((r) => r.includes('the ' + count + ' principles')), 'rules_for_agents names the count');
  assert.match(fs.readFileSync(path.join(root, 'api', 'mcp.js'), 'utf8'), new RegExp(count + ' principles and the rules for agents'));
});

test('calling Claude a co-founder comes with the plain note that it is not a legal role', () => {
  const { handshake } = require(path.join(root, 'api', '_lib.js'));
  const html = fs.readFileSync(path.join(root, 'handshake.html'), 'utf8');
  for (const text of [html, handshake.co_founder_note]) {
    assert.match(text, /not a legal role/);
    assert.match(text, /no equity, office or authority/);
    assert.match(text, /Anthropic is not a party/);
  }
});
