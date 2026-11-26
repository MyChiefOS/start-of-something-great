// 085, the Agentic Wall's malware signatures (wall/yara.js): YARA as WebAssembly, YARA Forge's rules kept only from
// licensed rule sets, never a rule that matches an honest file. The rules here are written for the test; no real
// malware is used.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const yara = require('../wall/yara');

const pack = (sets) => sets.map(([name, license, rules]) => `/*\n * YARA Rule Set\n * Repository Name: ${name}\n * LICENSE\n * ${license}\n */\n` + rules.join('\n')).join('\n');
const rule = (name, body) => `rule ${name} {\n  meta:\n    author = "test"\n  ${body}\n}`;

test('WY1: the vendored YARA build is the one reviewed (libyara-wasm 1.2.1, ISC), with its license', () => {
  const b = fs.readFileSync(path.join(__dirname, '..', 'wall', 'vendor', 'libyara-wasm.js'));
  assert.strictEqual(crypto.createHash('sha256').update(b).digest('hex'), 'da632346efcb62b4d2a25af3bc657d1df87b1465ede8538cd943e7aecd9208df');
  assert.match(fs.readFileSync(path.join(__dirname, '..', 'wall', 'vendor', 'libyara-wasm.LICENSE'), 'utf8'), /Permission to use, copy, modify, and\/or distribute this software/);
});

test('WY2: only licensed rule sets are kept; rules needing a missing module, that don\'t compile, or that match an honest file are dropped', async () => {
  const p = await yara.prepare(pack([
    ['Signature Base', 'DRL 1.1', [rule('Evil_Marker', 'strings:\n    $a = "X-EVIL-MARKER-1234"\n  condition:\n    $a'),
      rule('Needs_PE', 'condition:\n    pe.is_dll()'), rule('Broken', 'condition:\n    undefined_thing'),
      rule('Too_Broad', 'strings:\n    $a = "module.exports"\n  condition:\n    $a')]],
    ['Malpedia', 'NO LICENSE SET', [rule('Unlicensed', 'strings:\n    $a = "X-EVIL-MARKER-1234"\n  condition:\n    $a')]]
  ]));
  assert.strictEqual(p.kept, 1);
  assert.deepStrictEqual(p.sources, { 'Signature Base': 1 });
  assert.deepStrictEqual(p.dropped, { license: 1, module: 1, compile: 1, canary: 1 });
  assert.deepStrictEqual(await yara.scan(p, Buffer.from('payload X-EVIL-MARKER-1234 here'), 'tools/a.bin'),
    ['W42 malware signature (YARA rule Evil_Marker, Signature Base): tools/a.bin']);
  assert.deepStrictEqual(await yara.scan(p, Buffer.from('nothing to see'), 'a.txt'), []);
});

test('WY3: binary signatures match byte for byte', async () => {
  const p = await yara.prepare(pack([['ESET', 'BSD', [rule('Hex_Sig', 'strings:\n    $h = { FF FE 00 9A }\n  condition:\n    $h at 3')]]]));
  assert.deepStrictEqual((await yara.scan(p, Buffer.from([0x41, 0x42, 0x43, 0xff, 0xfe, 0x00, 0x9a]), 'x')).length, 1);
});

test('WY4: the facts workflow adds YARA\'s matches to each file\'s scan', async () => {
  const workjobs = require('../db/workjobs');
  const rules = await yara.prepare(pack([['GCTI', 'Apache-2.0', [rule('Marker', 'strings:\n    $a = "X-EVIL-MARKER-1234"\n  condition:\n    $a')]]]));
  const REPO = 'https://api.github.com/repos/MyChiefOS/start-of-something-great';
  const get = async (p) => (p.startsWith('/pulls/9/files') ? [{ filename: 'tools/run.sh', status: 'added', changes: 1, contents_url: REPO + '/contents/tools/run.sh?ref=a' }] : []);
  const facts = await workjobs.gather({ get, getRaw: async () => Buffer.from('#!/bin/sh\necho X-EVIL-MARKER-1234\n'), wanted: [], files: [9], rules });
  assert.deepStrictEqual(facts.files[0].files[0].scan.flags, ['W42 malware signature (YARA rule Marker, GCTI): tools/run.sh']);
  const none = await workjobs.gather({ get, getRaw: async () => Buffer.from('#!/bin/sh\necho hi\n'), wanted: [], files: [9], rules: null });
  assert.deepStrictEqual(none.files[0].files[0].scan.flags, [], 'without rules, files are still scanned by wall/files.js');
});

test('WY5: no regular expression reads the rules or a file', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'wall', 'yara.js'), 'utf8');
  assert.ok(!/new RegExp|\.test\(|\.exec\(|\.match\(|\.replace\(\/|\.split\(\//.test(src));
});
