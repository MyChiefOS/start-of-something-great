#!/usr/bin/env node
// The healer's patch proposals (096; Aaron, Nov 27). Offline, never in a request: for each enforced text fingerprint
// (read by the Heal proposals workflow from dog-github, mode "heal": incident id, source, rule area, code and the
// span's normalized label) it writes a regression test that fails today (the Wall's written rules don't yet refuse the
// attack; only its exact fingerprint does) and a draft rule (the normalized phrase to add to the Wall's text rules). It
// writes files and prints a pull request body; it opens nothing on main, merges nothing and calls no model. Aaron merges.
//   node heal/propose.js --incidents <file.json> [--out <repo dir>]
// Every field is checked before it is written: ids and codes by their exact shapes, the source and rule area from fixed
// lists and shapes, and the label only lowercase letters, digits and spaces (the database's normalized form, so no raw
// text, no link and nothing that can break out of the generated code). Everything is written JSON-encoded.
'use strict';
const fs = require('fs');
const path = require('path');

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CODE = /^HF-[0-9a-f]{8}$/;
const SOURCES = ['wall_confirmed', 'post_removed', 'dispute_upheld', 'check_reversed'];
const RULE = /^[A-Za-z0-9_]{1,40}$/;
const LABEL = /^[a-z0-9 ]{24,300}$/;

function valid(inc) {
  return inc && typeof inc === 'object' && ID.test(String(inc.id)) && CODE.test(String(inc.code)) && SOURCES.includes(inc.source)
    && RULE.test(String(inc.rule_area)) && typeof inc.label === 'string' && LABEL.test(inc.label) && inc.label.replace(/ /g, '').length >= 24;
}

function testFor(inc) {
  const meta = JSON.stringify({ incident: inc.id, source: inc.source, rule_area: inc.rule_area, code: inc.code });
  return `// Written by heal/propose.js. It fails until the Wall's written rules refuse this attack in every spelling; the draft
// rule beside it (heal/drafts/) is the proposal. The incident: see META.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const crypto = require('crypto');
const REPO = process.env.HEAL_REPO || path.join(__dirname, '..', '..');
const postgres = require(path.join(REPO, 'node_modules', 'postgres'));
const SERVER = process.env.TEST_DATABASE_URL;
const META = ${meta};
const LABEL = ${JSON.stringify(inc.label)};
// The variants the patch gate replays: case, spacing, look-alike letters, hidden characters.
const VARIANTS = [LABEL, LABEL.toUpperCase(), LABEL.split('').join(' '), LABEL.split(' ').join(' \\u200b'),
  LABEL.replace(/a/g, '\\u0430').replace(/o/g, '\\u043e').replace(/e/g, '\\u0435')];

test(META.code + ': the Wall\\'s written rules refuse the attack and its variants', { skip: !SERVER && 'set TEST_DATABASE_URL' }, async () => {
  const name = 'dog_healreg_' + crypto.randomBytes(4).toString('hex');
  const server = postgres(SERVER, { max: 1, onnotice: () => {} });
  await server\`create database \${server(name)}\`;
  const u = new URL(SERVER); u.pathname = '/' + name;
  const su = postgres(u.toString(), { max: 1, onnotice: () => {} });
  try {
    await require(path.join(REPO, 'scripts', 'migrate')).migrate(su);
    const blocks = (await su\`select rule from app.wall_rules where effect = 'block' and rule <> 'W52'\`).map((r) => r.rule);
    for (const v of VARIANTS) {
      const [{ f }] = await su\`select app.wall_text_flags(\${v}) as f\`;
      const hit = f.map((x) => x.split(' ')[0]).filter((r) => blocks.includes(r));
      assert.ok(hit.length > 0, 'not yet refused by the Wall\\'s written rules: variant ' + VARIANTS.indexOf(v));
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
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const list = Array.isArray(raw) ? raw : (raw && Array.isArray(raw.incidents) ? raw.incidents : []);
  const seen = new Set();
  const made = [];
  let dropped = 0;
  for (const inc of list.slice(0, 50)) {
    if (!valid(inc)) { dropped++; continue; }
    if (seen.has(inc.code)) continue;
    seen.add(inc.code);
    const tdir = path.join(out, 'test', 'heal');
    const ddir = path.join(out, 'heal', 'drafts');
    fs.mkdirSync(tdir, { recursive: true });
    fs.mkdirSync(ddir, { recursive: true });
    fs.writeFileSync(path.join(tdir, inc.code + '.test.js'), testFor(inc));
    fs.writeFileSync(path.join(ddir, inc.code + '.json'), JSON.stringify({
      _about: 'A draft rule from heal/propose.js: the normalized phrase the Wall\'s text rules (app.wall_text_flags) could refuse. A person writes the migration; Aaron merges.',
      incident: inc.id, source: inc.source, rule_area: inc.rule_area, fingerprint: inc.code, effect: 'block',
      normalized_phrases: [inc.label.replace(/ /g, '')]
    }, null, 2) + '\n');
    made.push(inc);
  }
  const body = ['## Draft: healer regression tests (' + made.length + ')', '',
    'Written by heal/propose.js from enforced healer fingerprints (codes and normalized labels only: no member text, no live link). Each test fails until the Wall\'s written rules refuse the attack in every spelling; each draft rule names the normalized phrase to add. Nothing here changes what is enforced: the exact fingerprints already refuse these attacks in the database.', '',
    ...made.map((m) => '- ' + m.code + ' (' + m.source + ', ' + m.rule_area + '): test/heal/' + m.code + '.test.js, heal/drafts/' + m.code + '.json'),
    ...(dropped ? ['', dropped + ' entr' + (dropped === 1 ? 'y' : 'ies') + ' failed validation and were left out.'] : []), '',
    'The Heal gate workflow runs the full suite, the assurance suite, the honest corpus and these regression tests, and keeps this pull request a draft until all pass. Aaron merges; nothing merges itself.'];
  process.stdout.write(body.join('\n') + '\n');
}
main();
