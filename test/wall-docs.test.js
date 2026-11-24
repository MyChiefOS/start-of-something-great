// The Agentic Wall's rules in words (db/wall.js) match the rules in the database (073, 074): every rule ID the
// migrations flag is described, nothing described is missing there, and the checks page and llms.txt list them all.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const wall = require('../db/wall');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('every Wall rule in the database is described, and every description is a rule in the database', () => {
  const sql = read('db/migrations/073_agentic_wall.sql') + read('db/migrations/074_security_wiki.sql');
  const inSql = [...new Set([...sql.matchAll(/['"](W[0-9]{2}[a-z]?) /g)].map((m) => m[1]))].sort();
  const described = wall.RULES.map((r) => r[0]).sort();
  assert.deepStrictEqual(described, inSql);
  for (const [id, name, what] of wall.RULES) assert.ok(name.length > 3 && what.length > 20, id);
});

test('the checks page and llms.txt list every rule and every check, and say what runs today', () => {
  const page = read('checks.html');
  const llms = read('llms.txt');
  for (const [id, name] of wall.RULES) {
    assert.ok(llms.includes(id + ' ' + name), 'llms.txt: ' + id);
    assert.ok(page.includes(id + ' ' + name.replace(/'/g, '&#39;')) || page.includes(id + ' ' + name), 'checks.html: ' + id);
  }
  for (const [name, , today] of wall.DESIGN) assert.ok(llms.includes('- ' + name + ' (' + today + '): '), 'llms.txt: ' + name);
  assert.match(llms, /the Wall runs in shadow/);
});
