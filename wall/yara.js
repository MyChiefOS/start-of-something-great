// The Agentic Wall's malware signatures (085; Aaron, Nov 25: "matching files against malware signatures (YARA rules,
// the standard pattern language) ... yes implement it", built into the Wall). YARA itself runs inside the Wall's code
// as WebAssembly (wall/vendor/libyara-wasm.js, libyara-wasm 1.2.1, ISC, vendored so the facts workflow installs no
// package; its digest is checked by test/wall-yara.test.js).
//
// The rules are YARA Forge's core pack (github.com/YARAHQ/yara-forge: curated, low false positives), read fresh on
// every run of the GitHub facts workflow (its hourly schedule is best effort, as GitHub's are), and kept only from rule sets whose license allows our use:
// SOURCES below, each with its license. A rule set marked "NO LICENSE SET" is never used. Rules that need a YARA
// module this build lacks (pe, dotnet and the like) or don't compile are dropped, and a rule that matches any of the
// honest files in CANARIES is dropped too, so a bad or poisoned rule can't block ordinary work.
//
// No regular expressions read the rules text or a file (as 083 and 084).
'use strict';

// Rule sets in YARA Forge's core pack whose licenses allow commercial use, as their headers say (checked Nov 26, 2026).
// A set counts only when its name, its repository and its license header all match (085 review): a set that changes
// its license, or a new set that reuses a name, is left out until a pull request reviews it.
// The Detection Rule License 1.1 asks for credit: the sources are named on /checks with each match.
const SOURCES = {
  'CAPE': { license: 'GPL-3.0 (used, not distributed)', repo: 'https://github.com/kevoreilly/CAPEv2', mark: 'GNU General Public License' },
  'ESET': { license: 'BSD-2-Clause', repo: 'https://github.com/eset/malware-ioc', mark: 'Redistribution and use' },
  'FireEye-RT': { license: 'BSD-2-Clause', repo: 'https://github.com/mandiant/red_team_tool_countermeasures/', mark: 'BSD 2-Clause' },
  'GCTI': { license: 'Apache-2.0', repo: 'https://github.com/chronicle/GCTI', mark: 'Apache License' },
  'Trellix ARC': { license: 'Apache-2.0', repo: 'https://github.com/advanced-threat-research/Yara-Rules/', mark: 'Apache License' },
  'Telekom Security': { license: 'MIT', repo: 'https://github.com/telekom-security/malware_analysis/', mark: 'MIT License' },
  'Volexity': { license: 'BSD-2-Clause', repo: 'https://github.com/volexity/threat-intel', mark: 'BSD License' },
  'Dr4k0nia': { license: 'DRL-1.1', repo: 'https://github.com/dr4k0nia/yara-rules', mark: 'Detection Rule License' },
  'Elceef': { license: 'MIT', repo: 'https://github.com/elceef/yara-rulz', mark: 'MIT License' },
  'Cod3nym': { license: 'DRL-1.1', repo: 'https://github.com/cod3nym/detection-rules/', mark: 'Detection Rule License' },
  'craiu': { license: 'GPL-3.0 (used, not distributed)', repo: 'https://github.com/craiu/yararules', mark: 'GNU GENERAL PUBLIC LICENSE' },
  'DitekSHen': { license: 'BSD-2-Clause', repo: 'https://github.com/ditekshen/detection', mark: 'BSD License' },
  'WithSecureLabs': { license: 'BSD-2-Clause', repo: 'https://github.com/WithSecureLabs/iocs', mark: 'BSD 2-Clause' },
  'SEKOIA': { license: 'DRL-1.1', repo: 'https://github.com/SEKOIA-IO/Community', mark: 'Detection Rule License' },
  'Synacktiv': { license: 'DRL-1.1', repo: 'https://github.com/synacktiv/synacktiv-rules', mark: 'Detection Rule License' },
  'Signature Base': { license: 'DRL-1.1', repo: 'https://github.com/Neo23x0/signature-base', mark: 'Detection Rule License' }
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
    // A set's header is a comment block (" * Repository Name: X"); the same words anywhere else don't start a set.
    if (at !== -1 && line.trimStart().startsWith('*')) { cur = { name: line.slice(at + 16).trim(), repo: '', header: '', rules: [], rule: null }; out.push(cur); continue; }
    if (!cur) continue;
    if (!cur.rule) {
      const ra = line.indexOf('Repository:');
      if (ra !== -1 && !cur.repo) cur.repo = line.slice(ra + 11).trim();
      else if (cur.header.length < 4000) cur.header += line + '\n';
    }
    const t = line.trimStart();
    if (startsRule(t)) { cur.rule = [line]; cur.rules.push(cur.rule); } else if (cur.rule) cur.rule.push(line);
  }
  // 087: a rule ends at its own closing brace. Before, the lines after it (the next set's "/*" header comment, which
  // closes only after "Repository Name:") stayed on the rule, so the joined set opened a comment that never closed and
  // every rule after the first set read as a comment: W42 matched nothing (found by the Nov 26 simulation).
  const cut = (r) => { let e = r.length - 1; while (e > 0 && r[e].trim() !== '}') e--; return r.slice(0, e + 1); };
  return out.map((s) => ({ name: s.name, repo: s.repo, header: s.header, rules: s.rules.map((r) => cut(r).join('\n')) }));
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
// extraCanaries: more honest files (the facts workflow passes the repository files it has checked out), so a rule broad
// enough to match ordinary code is dropped before it can block anything (085 review).
async function prepare(packText, { extraCanaries = [] } = {}) {
  const y = await load();
  const dropped = { license: 0, module: 0, compile: 0, canary: 0 };
  const sourceOf = new Map();
  let rules = [];
  for (const s of sections(String(packText || '').slice(0, MAX_RULES_BYTES))) {
    const known = Object.prototype.hasOwnProperty.call(SOURCES, s.name) ? SOURCES[s.name] : null;
    if (!known || s.repo !== known.repo || !s.header.includes(known.mark) || s.header.includes('NO LICENSE SET')) { dropped.license += s.rules.length; continue; }
    for (const r of s.rules) {
      if (usesModule(r)) { dropped.module++; continue; }
      rules.push(r); sourceOf.set(nameOf(r), s.name);
    }
  }
  // Drop what doesn't compile (a rule naming a dropped one, a syntax this build lacks), a few rounds at most.
  for (let round = 0; round < 30 && rules.length; round++) {
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
  // 087: the set the Wall uses must compile with no errors at all: with one, YARA matches nothing. If it still doesn't,
  // nothing is kept and `broken` says so, and the scan flags every file it couldn't check (never silent).
  const left = rules.length ? y.run(Buffer.from('x'), rules.join('\n')).compileErrors : null;
  let errors = 0; if (left) for (let i = 0; i < left.size(); i++) if (!left.get(i).warning) errors++;
  if (errors) return { text: '', kept: 0, sources: {}, sourceOf: new Map(), dropped, broken: errors + ' compile errors left' };
  // Drop any rule that matches an honest file.
  const noisy = new Set();
  for (const c of [...CANARIES, ...extraCanaries.slice(0, 300)]) for (const n of matchedNames(y.run(c, rules.join('\n')))) noisy.add(n);
  if (noisy.size) { dropped.canary = noisy.size; rules = rules.filter((r) => !noisy.has(nameOf(r))); }
  const sources = {};
  for (const r of rules) { const s = sourceOf.get(nameOf(r)); sources[s] = (sources[s] || 0) + 1; }
  return { text: rules.join('\n'), kept: rules.length, sources, sourceOf, dropped };
}

// The rules a file matches, as the Wall's flags (W42 blocks).
async function scan(prepared, bytes, label) {
  if (prepared && prepared.broken) return [('W42b malware signature check did not run (' + prepared.broken + '): ' + String(label || '')).slice(0, 240)];
  if (!prepared || !prepared.kept) return [];
  const y = await load();
  const names = matchedNames(y.run(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || []), prepared.text));
  return names.slice(0, 5).map((n) => ('W42 malware signature (YARA rule ' + n + ', ' + (prepared.sourceOf.get(n) || 'YARA Forge') + '): ' + String(label || '')).slice(0, 240));
}

module.exports = { SOURCES, FORGE_CORE, CANARIES, load, prepare, scan, sections, usesModule };
