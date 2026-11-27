// The Agentic Wall's rules in words (db/wall.js) match the rules the database publishes (app.wall_rules, seeded by
// 081 on), with the same words and effect, and the checks page and llms.txt list them all.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const wall = require('../db/wall');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('every Wall rule in the database is described, and every description is a rule in the database', () => {
  // 081 on: every rule and its effect is seeded into app.wall_rules by a migration (095: the link sandbox's).
  const sql = fs.readdirSync(path.join(root, 'db/migrations')).filter((f) => /^0[89]\d_/.test(f)).map((f) => read('db/migrations/' + f)).join('\n');
  const seeded = {};
  for (const m of sql.matchAll(/\('(W[0-9]{2}[a-z]?)', '(block|flag)', '((?:[^']|'')*)'\)/g)) seeded[m[1]] = [m[3].replace(/''/g, "'"), m[2]];
  // 086 on: a later migration can reword a rule.
  for (const m of sql.matchAll(/update app\.wall_rules set what = '((?:[^']|'')*)' where rule = '(W[0-9]{2}[a-z]?)'/g)) seeded[m[2]][0] = m[1].replace(/''/g, "'");
  assert.deepStrictEqual(wall.RULES.map((r) => r[0]).sort(), Object.keys(seeded).sort());
  for (const [id, name, , effect] of wall.RULES) assert.deepStrictEqual([name, effect], seeded[id], id);
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
  assert.ok(!/the Wall runs in shadow/.test(llms), 'the Wall enforces (081): nothing may say it runs in shadow');
  assert.match(llms, /Only a clear breach of a published rule is refused/);
});
