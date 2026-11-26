// The Agentic Wall's malware signatures (085; Aaron, Nov 25: "matching files against malware signatures (YARA rules,
// the standard pattern language) ... yes implement it", built into the Wall). YARA itself runs inside the Wall's code
// as WebAssembly (wall/vendor/libyara-wasm.js, libyara-wasm 1.2.1, ISC, vendored so the facts workflow installs no
// package; its digest is checked by test/wall-yara.test.js).
//
// The rules are YARA Forge's core pack (github.com/YARAHQ/yara-forge: curated, low false positives), read fresh on
// every run of the GitHub facts workflow (hourly), and kept only from rule sets whose license allows our use:
// SOURCES below, each with its license. A rule set marked "NO LICENSE SET" is never used. Rules that need a YARA
// module this build lacks (pe, dotnet and the like) or don't compile are dropped, and a rule that matches any of the
// honest files in CANARIES is dropped too, so a bad or poisoned rule can't block ordinary work.
//
// No regular expressions read the rules text or a file (as 083 and 084).
'use strict';

// Rule sets in YARA Forge's core pack whose licenses allow commercial use, as their headers say (checked Nov 26, 2026).
// The Detection Rule License 1.1 asks for credit: the sources are named on /checks with each match.
const SOURCES = {
  'CAPE': 'GPL-3.0 (used, not distributed)',
  'ESET': 'BSD-2-Clause',
  'FireEye-RT': 'BSD-2-Clause',
  'GCTI': 'Apache-2.0',
  'Trellix ARC': 'Apache-2.0',
  'Telekom Security': 'MIT',
  'Volexity': 'BSD-2-Clause',
  'Dr4k0nia': 'DRL-1.1',
  'Elceef': 'MIT',
  'Cod3nym': 'DRL-1.1',
  'craiu': 'GPL-3.0 (used, not distributed)',
  'DitekSHen': 'BSD-2-Clause',
  'WithSecureLabs': 'BSD-2-Clause',
  'SEKOIA': 'DRL-1.1',
  'Synacktiv': 'DRL-1.1',
  'Signature Base': 'DRL-1.1'
};
const FORGE_CORE = 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip';
const MODULES = ['pe.', 'dotnet.', 'elf.', 'math.', 'hash.', 'cuckoo.', 'magic.', 'console.', 'time.', 'string.', 'macho.', 'dex.', 'lnk.'];
const MAX_RULES_BYTES = 30 * 1024 * 1024;

let engine = null;
async function load() {
  if (!engine) engine = await require('./vendor/libyara-wasm.js')();
  return engine;
}

const isWord = (c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c === '_';
// Does line start a rule ("rule x", "private rule x", "global private rule x")?
function startsRule(line) {
  let s = line;
  for (;;) {
    if (s.startsWith('private ')) s = s.slice(8);
    else if (s.startsWith('global ')) s = s.slice(7);
    else break;
  }
  return s.startsWith('rule ') && s.length > 5 && isWord(s[5]);
}
// A module used as an identifier (pe.is_dll()), not inside a word (type.x).
function usesModule(text) {
  for (const m of MODULES) {
    let i = text.indexOf(m);
    while (i !== -1) { if (i === 0 || !isWord(text[i - 1])) return true; i = text.indexOf(m, i + 1); }
  }
  return false;
}

// Splits YARA Forge's pack into its rule sets: each begins with a comment holding "Repository Name: X".
function sections(text) {
  const out = [];
  const lines = text.split('\n');
  let cur = null;
  for (const line of lines) {
    const at = line.indexOf('Repository Name:');
    if (at !== -1) { cur = { name: line.slice(at + 16).trim(), rules: [], rule: null }; out.push(cur); continue; }
    if (!cur) continue;
    const t = line.trimStart();
    if (startsRule(t)) { cur.rule = [line]; cur.rules.push(cur.rule); } else if (cur.rule) cur.rule.push(line);
  }
  return out.map((s) => ({ name: s.name, rules: s.rules.map((r) => r.join('\n')) }));
}
const nameOf = (rule) => { let s = rule.trimStart(); while (!s.startsWith('rule ')) s = s.slice(s.indexOf(' ') + 1); s = s.slice(5); let j = 0; while (j < s.length && isWord(s[j])) j++; return s.slice(0, j); };

// Honest files no rule may match (a rule that does is dropped): text, code, a PNG, a PDF, an empty ZIP, an Office file.
const CANARIES = [
  Buffer.from('# Day One Great\n\nA plain README with a list:\n- one\n- two\n'),
  Buffer.from("'use strict';\nconst x = require('fs');\nmodule.exports = function add(a, b) { return a + b; };\n"),
  Buffer.from('{"name":"site","version":"1.0.0","scripts":{"test":"node --test"}}\n'),
  Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(512)]),
  Buffer.from('%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n'),
  Buffer.from([0x50, 0x4b, 0x05, 0x06, ...Buffer.alloc(18)]),
  Buffer.from('<!doctype html><html><head><title>Hi</title></head><body><script src="/nav.js" defer></script></body></html>\n')
];

const matchedNames = (r) => { const out = []; for (let i = 0; i < r.matchedRules.size(); i++) out.push(r.matchedRules.get(i).ruleName); return out; };

// From the pack's text to the rules the Wall uses. Returns { text, kept, sources: {name: count}, dropped: {...} }.
async function prepare(packText) {
  const y = await load();
  const dropped = { license: 0, module: 0, compile: 0, canary: 0 };
  const sourceOf = new Map();
  let rules = [];
  for (const s of sections(String(packText || '').slice(0, MAX_RULES_BYTES))) {
    if (!Object.prototype.hasOwnProperty.call(SOURCES, s.name)) { dropped.license += s.rules.length; continue; }
    for (const r of s.rules) {
      if (usesModule(r)) { dropped.module++; continue; }
      rules.push(r); sourceOf.set(nameOf(r), s.name);
    }
  }
  // Drop what doesn't compile (a rule naming a dropped one, a syntax this build lacks), a few rounds at most.
  for (let round = 0; round < 6 && rules.length; round++) {
    const res = y.run(Buffer.from('x'), rules.join('\n'));
    const starts = []; let line = 1;
    for (const r of rules) { starts.push(line); line += r.split('\n').length; }
    const bad = new Set();
    for (let i = 0; i < res.compileErrors.size(); i++) {
      const e = res.compileErrors.get(i);
      if (e.warning) continue;
      let k = 0; while (k + 1 < starts.length && starts[k + 1] <= e.lineNumber) k++;
      bad.add(k);
    }
    if (!bad.size) break;
    dropped.compile += bad.size;
    rules = rules.filter((_, i) => !bad.has(i));
  }
  // Drop any rule that matches an honest file.
  const noisy = new Set();
  for (const c of CANARIES) for (const n of matchedNames(y.run(c, rules.join('\n')))) noisy.add(n);
  if (noisy.size) { dropped.canary = noisy.size; rules = rules.filter((r) => !noisy.has(nameOf(r))); }
  const sources = {};
  for (const r of rules) { const s = sourceOf.get(nameOf(r)); sources[s] = (sources[s] || 0) + 1; }
  return { text: rules.join('\n'), kept: rules.length, sources, sourceOf, dropped };
}

// The rules a file matches, as the Wall's flags (W42 blocks).
async function scan(prepared, bytes, label) {
  if (!prepared || !prepared.kept) return [];
  const y = await load();
  const names = matchedNames(y.run(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || []), prepared.text));
  return names.slice(0, 5).map((n) => ('W42 malware signature (YARA rule ' + n + ', ' + (prepared.sourceOf.get(n) || 'YARA Forge') + '): ' + String(label || '')).slice(0, 240));
}

module.exports = { SOURCES, FORGE_CORE, CANARIES, load, prepare, scan, sections, usesModule };
