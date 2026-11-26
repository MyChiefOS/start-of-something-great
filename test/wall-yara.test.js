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

// A pack as YARA Forge writes it: each set's name, repository and license header, then its rules.
const REPOS = { 'Signature Base': ['https://github.com/Neo23x0/signature-base', 'Detection Rule License (DRL) 1.1'], ESET: ['https://github.com/eset/malware-ioc', 'Redistribution and use'],
  GCTI: ['https://github.com/chronicle/GCTI', 'Apache License Version 2.0'], Malpedia: ['https://github.com/malpedia/signator-rules/', 'NO LICENSE SET'] };
const pack = (sets) => sets.map(([name, , rules]) => `/*\n * YARA Rule Set\n * Repository Name: ${name}\n * Repository: ${REPOS[name][0]}\n * LICENSE\n * ${REPOS[name][1]}\n */\n` + rules.join('\n')).join('\n');
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

test('WY6 (085 review): a set counts only when its name, repository and license all match; a broad rule is dropped by the repository\'s own files', async () => {
  const set = (name, repo, license, rules) => `/*\n * YARA Rule Set\n * Repository Name: ${name}\n * Repository: ${repo}\n * LICENSE\n * ${license}\n */\n` + rules.join('\n');
  const r1 = rule('Evil_Marker', 'strings:\n    $a = "X-EVIL-MARKER-1234"\n  condition:\n    $a');
  const ok = await yara.prepare(set('ESET', 'https://github.com/eset/malware-ioc', 'Redistribution and use in source and binary forms', [r1]));
  assert.strictEqual(ok.kept, 1);
  for (const [repo, lic] of [['https://github.com/someone-else/fork', 'Redistribution and use'], ['https://github.com/eset/malware-ioc', 'NO LICENSE SET'], ['https://github.com/eset/malware-ioc', 'All rights reserved']]) {
    assert.strictEqual((await yara.prepare(set('ESET', repo, lic, [r1]))).kept, 0, repo + ' / ' + lic);
  }
  const broad = rule('Too_Broad_For_Code', 'strings:\n    $b = "describe("\n    $c = "test("\n  condition:\n    any of them');
  const own = [Buffer.from("describe('dates', () => { test('days', () => {}); });\n")]; // honest code, as the repository's own files would be
  const p = await yara.prepare(set('ESET', 'https://github.com/eset/malware-ioc', 'Redistribution and use', [r1, broad]), { extraCanaries: own });
  assert.deepStrictEqual([p.kept, p.dropped.canary], [1, 1]);
});

test('WY7 (085 review): a rule that matches widely in one run is flagged (W42b), not blocked', async () => {
  const workjobs = require('../db/workjobs');
  const rules = await yara.prepare(pack([['GCTI', 'Apache-2.0', [rule('Marker', 'strings:\n    $a = "X-EVIL-MARKER-1234"\n  condition:\n    $a')]]]));
  const REPO = 'https://api.github.com/repos/MyChiefOS/start-of-something-great';
  const get = async (p) => { const n = p.split('/')[2]; return p.endsWith('/files?per_page=100') ? [{ filename: 'f' + n + '.sh', status: 'added', changes: 1, contents_url: REPO + '/contents/f' + n + '.sh?ref=a' }] : []; };
  const one = await workjobs.gather({ get, getRaw: async () => Buffer.from('X-EVIL-MARKER-1234'), wanted: [], files: [1], rules });
  assert.ok(one.files[0].files[0].scan.flags[0].startsWith('W42 '), 'one pull request: blocked');
  const three = await workjobs.gather({ get, getRaw: async () => Buffer.from('X-EVIL-MARKER-1234'), wanted: [], files: [1, 2, 3], rules });
  for (const pr of three.files) assert.ok(pr.files[0].scan.flags[0].startsWith('W42b '), 'three pull requests: flagged');
});
