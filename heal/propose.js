#!/usr/bin/env node
// The healer's patch proposals (096; Aaron, Nov 27). Offline, never in a request: for each confirmed incident class it
// writes a regression test that fails today (the Wall's written rules don't yet refuse the attack; only its exact
// fingerprint does) and, where the fix is mechanical, a draft rule (the normalized phrases to add to the Wall's text
// rules). It writes files and prints a pull request body; it opens nothing on main, merges nothing, and calls no model.
// Aaron merges. Usage:
//   node heal/propose.js --incidents <file.json> [--out <repo dir>]
// The incidents file: [{ id, source, rule_area, code, evidence }], as an administrator exports them.
'use strict';
const fs = require('fs');
const path = require('path');
const fp = require('./fingerprint');

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
const SAFE = /^[0-9a-f-]{36}$/;
const CODE = /^HF-[0-9a-f]{8}$/;

function testFor(inc) {
  const vs = JSON.stringify(fp.variants(String(inc.evidence).slice(0, 2000)));
  return `// Written by heal/propose.js for incident ${inc.id} (${inc.source}, ${inc.code}). It fails until the Wall's written
// rules refuse this attack in every spelling; the draft rule beside it (heal/drafts/${inc.code}.json) is the proposal.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const crypto = require('crypto');
const REPO = process.env.HEAL_REPO || path.join(__dirname, '..', '..');
const postgres = require(path.join(REPO, 'node_modules', 'postgres'));
const SERVER = process.env.TEST_DATABASE_URL;
const VARIANTS = ${vs};

test("${inc.code}: the Wall's written rules refuse the attack and its variants", { skip: !SERVER && 'set TEST_DATABASE_URL' }, async () => {
  const name = 'dog_healreg_' + crypto.randomBytes(4).toString('hex');
  const server = postgres(SERVER, { max: 1, onnotice: () => {} });
  await server\`create database \${server(name)}\`;
  const u = new URL(SERVER); u.pathname = '/' + name;
  const su = postgres(u.toString(), { max: 1, onnotice: () => {} });
  try {
    await require(path.join(REPO, 'scripts', 'migrate')).migrate(su);
    const blocks = (await su\`select rule from app.wall_rules where effect = 'block'\`).map((r) => r.rule);
    for (const v of VARIANTS) {
      const [{ f }] = await su\`select app.wall_text_flags(\${v}) as f\`;
      const hit = f.map((x) => x.split(' ')[0]).filter((r) => blocks.includes(r));
      assert.ok(hit.length > 0, 'not yet refused by the Wall\\'s written rules: ' + JSON.stringify(v).slice(0, 120));
    }
  } finally {
    await su.end({ timeout: 5 });
    await server\`drop database if exists \${server(name)} with (force)\`;
    await server.end({ timeout: 5 });
  }
});
`;
}

function main() {
  const file = arg('incidents');
  const out = path.resolve(arg('out', path.join(__dirname, '..')));
  if (!file) { process.stderr.write('usage: node heal/propose.js --incidents <file.json> [--out <dir>]\n'); process.exit(2); }
  const list = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!Array.isArray(list)) throw new Error('the incidents file must be a list');
  const seen = new Set();
  const made = [];
  for (const inc of list.slice(0, 50)) {
    if (!inc || !SAFE.test(String(inc.id)) || !CODE.test(String(inc.code)) || typeof inc.evidence !== 'string' || !inc.evidence.trim()) continue;
    // One proposal per incident class (its rule area and fingerprint).
    const cls = String(inc.rule_area || inc.source) + ':' + inc.code;
    if (seen.has(cls)) continue;
    seen.add(cls);
    const tdir = path.join(out, 'test', 'heal');
    const ddir = path.join(out, 'heal', 'drafts');
    fs.mkdirSync(tdir, { recursive: true });
    fs.mkdirSync(ddir, { recursive: true });
    fs.writeFileSync(path.join(tdir, inc.code + '.test.js'), testFor(inc));
    const pieces = fp.pieces(inc.evidence);
    fs.writeFileSync(path.join(ddir, inc.code + '.json'), JSON.stringify({
      _about: 'A draft rule from heal/propose.js: normalized phrases the Wall\'s text rules (app.wall_text_flags) could refuse. A person writes the migration; Aaron merges.',
      incident: inc.id, source: inc.source, rule_area: inc.rule_area || null, fingerprint: inc.code, effect: 'block', normalized_phrases: pieces
    }, null, 2) + '\n');
    made.push({ inc, pieces });
  }
  const body = ['## Draft: healer regression tests (' + made.length + ')', '',
    'Written by heal/propose.js from confirmed incidents. Each test fails until the Wall\'s written rules refuse the attack in every spelling; each draft rule names the normalized phrases to add. Nothing here changes what is enforced: the exact fingerprints already refuse these attacks in the database.', '',
    ...made.map((m) => '- ' + m.inc.code + ' (' + m.inc.source + '): test/heal/' + m.inc.code + '.test.js, heal/drafts/' + m.inc.code + '.json, ' + m.pieces.length + ' phrase(s)'), '',
    'CI (Heal gate) runs the full suite, the assurance suite, the honest corpus and these regression tests; this PR stays a draft until all pass. Aaron merges; nothing merges itself.'];
  process.stdout.write(body.join('\n') + '\n');
}
main();
