// The firewall's normalizer (087; Aaron, Nov 26: fixes must catch "permutations of that attack ... developed in novel
// ways that exhibit similar patterns"). Attackers hide one attack many ways: encodings stacked on each other, HTML
// entities, look-alike and full-width letters, hidden characters, comments inside keywords, quotes inside shell words.
// Each is undone here, before any check runs, so a check written once matches every spelling of its pattern.
//
// No regular expressions (Aaron, Nov 25): every step is a bounded pass over a capped string.
'use strict';

const MAX = 65536;
const HEX = '0123456789abcdef';
const hexVal = (c) => HEX.indexOf(String(c).toLowerCase());

// Percent-decoding, repeated up to 4 times (%25 stacks), lenient: a broken sequence is kept as it is. Also IIS's %uXXXX
// and the overlong UTF-8 spellings of "." "/" and "\" (%c0%ae, %c0%af, %c1%9c, %e0%80%ae).
const OVERLONG = [['%c0%ae', '.'], ['%c0%2e', '.'], ['%e0%80%ae', '.'], ['%c0%af', '/'], ['%c0%2f', '/'], ['%e0%80%af', '/'], ['%c1%9c', '\\'], ['%c1%1c', '\\']];
function percentOnce(s) {
  let out = '';
  let changed = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '%') {
      let hit = null;
      for (const [k, v] of OVERLONG) if (s.substr(i, k.length).toLowerCase() === k) { hit = [k, v]; break; }
      if (hit) { out += hit[1]; i += hit[0].length - 1; changed = true; continue; }
      if ((s[i + 1] === 'u' || s[i + 1] === 'U') && [2, 3, 4, 5].every((k) => hexVal(s[i + k]) !== -1)) {
        out += String.fromCharCode(parseInt(s.substr(i + 2, 4), 16)); i += 5; changed = true; continue;
      }
      const a = hexVal(s[i + 1]); const b = hexVal(s[i + 2]);
      if (a !== -1 && b !== -1) {
        // Bytes 0x80+ start UTF-8: collect the run and decode it as UTF-8 (bad bytes become U+FFFD).
        const bytes = [a * 16 + b]; let j = i + 3;
        while (bytes[0] >= 0x80 && s[j] === '%' && hexVal(s[j + 1]) !== -1 && hexVal(s[j + 2]) !== -1 && bytes.length < 4) { bytes.push(hexVal(s[j + 1]) * 16 + hexVal(s[j + 2])); j += 3; }
        if (bytes[0] < 0x80) { out += String.fromCharCode(bytes[0]); i = j - 1; changed = true; continue; }
        // Bytes that aren't valid UTF-8 are kept as written (an overlong pair split by another layer stays readable).
        const u = Buffer.from(bytes).toString('utf8');
        if (!u.includes('\ufffd')) { out += u; i = j - 1; changed = true; continue; }
      }
    }
    out += c;
  }
  return [out, changed];
}
function percent(s) {
  let out = s;
  for (let i = 0; i < 4; i++) { const [d, ch] = percentOnce(out); out = d; if (!ch) break; }
  return out;
}

// HTML entities: named ones that matter for attacks, and numeric ones in decimal or hex, with or without the ";",
// with leading zeros (&#0000060). Twice, for &amp;lt;.
const NAMED = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&', sol: '/', bsol: '\\', colon: ':', lpar: '(', rpar: ')', semi: ';', equals: '=', tab: '\t', newline: '\n',
  nbsp: ' ', grave: '`', lsqb: '[', rsqb: ']', lcub: '{', rcub: '}', period: '.', comma: ',', excl: '!', num: '#', dollar: '$', percnt: '%', plus: '+', ast: '*', vert: '|', hyphen: '-' };
function entitiesOnce(s) {
  let out = ''; let changed = false;
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '&') { out += s[i]; continue; }
    if (s[i + 1] === '#') {
      let j = i + 2; let hex = false;
      if (s[j] === 'x' || s[j] === 'X') { hex = true; j++; }
      const start = j;
      while (j < s.length && j - start < 12 && (hex ? hexVal(s[j]) !== -1 : (s[j] >= '0' && s[j] <= '9'))) j++;
      if (j > start) {
        const n = parseInt(s.slice(start, j), hex ? 16 : 10);
        if (n > 0 && n < 0x110000) { out += String.fromCodePoint(n); i = (s[j] === ';' ? j : j - 1); changed = true; continue; }
      }
    } else {
      let j = i + 1;
      while (j < s.length && j - i <= 8 && ((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z'))) j++;
      const name = s.slice(i + 1, j).toLowerCase();
      if (Object.prototype.hasOwnProperty.call(NAMED, name)) { out += NAMED[name]; i = (s[j] === ';' ? j : j - 1); changed = true; continue; }
    }
    out += s[i];
  }
  return [out, changed];
}
function entities(s) { let out = s; for (let i = 0; i < 2; i++) { const [d, ch] = entitiesOnce(out); out = d; if (!ch) break; } return out; }

// Backslash escapes as languages and JSON write them: \xHH, \uHHHH, \u{H..}, \NNN octal, and JSON's \n \t \r \" \/ \\.
const SIMPLE = { n: '\n', t: '\t', r: '\r', f: '\f', v: '\v', b: '', '"': '"', "'": "'", '/': '/', '\\': '\\', '`': '`' };
function escapes(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\') {
      const n = s[i + 1];
      if ((n === 'x' || n === 'X') && hexVal(s[i + 2]) !== -1 && hexVal(s[i + 3]) !== -1) { out += String.fromCharCode(parseInt(s.substr(i + 2, 2), 16)); i += 3; continue; }
      if (n === 'u' && s[i + 2] === '{') { const e = s.indexOf('}', i + 3); const h = e === -1 ? '' : s.slice(i + 3, e); if (h && h.length <= 6 && [...h].every((c) => hexVal(c) !== -1)) { out += String.fromCodePoint(Math.min(parseInt(h, 16), 0x10ffff)); i = e; continue; } }
      if (n === 'u' && [2, 3, 4, 5].every((k) => hexVal(s[i + k]) !== -1)) { out += String.fromCharCode(parseInt(s.substr(i + 2, 4), 16)); i += 5; continue; }
      if (n >= '0' && n <= '7' && s[i + 2] >= '0' && s[i + 2] <= '7' && s[i + 3] >= '0' && s[i + 3] <= '7') { out += String.fromCharCode(parseInt(s.substr(i + 1, 3), 8) & 255); i += 3; continue; }
      if (n !== undefined && Object.prototype.hasOwnProperty.call(SIMPLE, n)) { out += SIMPLE[n]; i += 1; continue; }
    }
    out += s[i];
  }
  return out;
}

// Look-alike letters (Cyrillic, Greek) that NFKC keeps, mapped to the Latin letter they imitate.
const LOOK = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l',
  'α': 'a', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'ν': 'v', 'κ': 'k', 'ι': 'i', 'ѵ': 'v', 'ɑ': 'a', 'ɡ': 'g', 'ı': 'i', 'ʟ': 'l', 'ꜱ': 's',
  '‘': "'", '’': "'", '‛': "'", '′': "'", '“': '"', '”': '"', '″': '"', '‹': '<', '›': '>', '«': '<', '»': '>', '⁄': '/', '∕': '/', '⧸': '/', '＼': '\\', '∖': '\\', '‐': '-', '‑': '-', '−': '-', '–': '-' };
// Characters that show nothing (zero-width, joiners, bidi controls, soft hyphen, tag characters).
const isHidden = (cp) => cp === 0xad || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064) || (cp >= 0x2066 && cp <= 0x2069)
  || cp === 0xfeff || cp === 0x180e || (cp >= 0xe0000 && cp <= 0xe007f) || (cp >= 0xfe00 && cp <= 0xfe0f);
function letters(s) {
  let t;
  try { t = s.normalize('NFKC'); } catch { t = s; }
  let out = '';
  for (const ch of t) {
    const cp = ch.codePointAt(0);
    if (isHidden(cp)) continue;
    // Combining marks (accents stacked on a letter to break a keyword) are dropped.
    if (cp >= 0x300 && cp <= 0x36f) continue;
    const l = ch.toLowerCase();
    out += Object.prototype.hasOwnProperty.call(LOOK, l) ? LOOK[l] : l;
  }
  return out;
}

// Everything above, until nothing changes (an encoding inside an entity inside an encoding), at most 8 rounds.
// withEscapes false: backslashes kept as they are (a Windows path ..\boot.ini is not "\b" then "oot").
function clean(input, max = MAX, withEscapes = true) {
  let s = String(input == null ? '' : input).slice(0, max);
  for (let i = 0; i < 8; i++) {
    const before = s;
    // Letters are folded before entities too: a full-width digit inside an entity (&#x5２;) must read as a digit.
    const e = entities(letters(percent(s.split('+').join(' '))));
    s = letters(withEscapes ? escapes(e) : e);
    if (s === before) break;
  }
  return s.slice(0, max * 2);
}

// Views of one cleaned string. A check runs on each: an attack hidden from one view shows in another.
//   spaced:  comments (/* */, and SQL's -- and # to the end of a line) read as a space, whitespace runs as one space.
//   joined:  comments removed outright (UN/**/ION is UNION), MySQL's /*! ... */ kept as its content.
//   shell:   quotes, backslashes and ^ inside words removed (c'a't, c\at, w^hoami), $IFS and ${IFS} as a space,
//            brace lists as words ({cat,/etc/passwd}), and newlines as command separators.
const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === ' ';
function comments(s, keep) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      const inner = s.slice(i + 2, end === -1 ? s.length : end);
      if (inner[0] === '!') { let k = 1; while (k < inner.length && inner[k] >= '0' && inner[k] <= '9') k++; out += ' ' + inner.slice(k) + ' '; } else out += keep;
      i = end === -1 ? s.length : end + 1;
      continue;
    }
    out += s[i];
  }
  return out;
}
function squeeze(s) {
  let out = ''; let sp = false;
  for (const c of s) { if (isSpace(c)) { if (!sp) out += ' '; sp = true; } else { out += c; sp = false; } }
  return out;
}
function shellView(s) {
  // The input is already lower case here: $IFS is read as ${ifs}.
  let t = s.split('${ifs}').join(' ').split('$ifs$9').join(' ').split('$ifs').join(' ').split('${ifs%??}').join(' ');
  let out = '';
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    const prevWord = i > 0 && !isSpace(t[i - 1]) && !';|&`<>()'.includes(t[i - 1]);
    if ((c === '\'' || c === '"' || c === '\\' || c === '^') && prevWord) continue; // c'a't, c\at, w^hoami
    if (c === '\'' || c === '"') { out += ' '; continue; }
    if (c === '\n' || c === '\r') { out += ';'; continue; }
    if (c === '{' || c === '}') { out += ' '; continue; }
    if (c === ',' && t.lastIndexOf('{', i) > t.lastIndexOf('}', i)) { out += ' '; continue; }
    out += c;
  }
  return squeeze(out);
}
function views(cleaned) {
  const spaced = squeeze(comments(cleaned, ' '));
  const joined = squeeze(comments(cleaned, ''));
  return { spaced, joined, shell: shellView(comments(cleaned, ' ')) };
}

module.exports = { clean, views, percent, entities, escapes, letters, squeeze, MAX };
