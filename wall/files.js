// The Agentic Wall's file scanner (084; Aaron, Nov 25: "checking a file's real type from its contents", "unpacking
// archives and scanning inside", "scanning files", built into the Wall). Pure: given a file's bytes and name, it says
// what the file really is and which rules it breaks. No regular expressions read the file (as the firewall, 083).
//
//   W39 disguised type   the contents are an executable or a different kind of file than the name says (a .pdf that is
//                        a Windows program, a .png that is a zip): blocked.
//   W40 archive bomb     an archive past the limits (depth 3, 1,000 files, 50 MB unpacked, or 100 times its size): blocked.
//   W41 active document  an Office file with macros, or a PDF with JavaScript or a launch action: blocked.
//   W31 executable       an executable or installer found inside an archive: blocked (the name rule, 082, sees the rest).
//   W30 unopened         an archive kind the Wall can't open (7z, RAR, CAB): flagged.
//
// Archives are opened in memory: ZIP (and Office files, which are ZIPs), GZIP and TAR. Each file inside is scanned the
// same way, to depth 3.
'use strict';

const zlib = require('zlib');

const LIMITS = { depth: 3, files: 1000, bytes: 50 * 1024 * 1024, ratio: 100 };

const startsWith = (b, sig, at = 0) => b.length >= at + sig.length && sig.every((x, i) => b[at + i] === x);
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

// What the first bytes say the file is.
function sniff(b) {
  if (startsWith(b, [0x4d, 0x5a])) return 'exe';
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (startsWith(b, [0xcf, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xce, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xca, 0xfe, 0xba, 0xbe])) return 'macho';
  if (startsWith(b, ascii('%PDF-'))) return 'pdf';
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) return 'zip';
  if (startsWith(b, [0x1f, 0x8b])) return 'gzip';
  if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (startsWith(b, ascii('Rar!'))) return 'rar';
  if (startsWith(b, ascii('MSCF'))) return 'cab';
  if (startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole';
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return 'png';
  if (startsWith(b, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (startsWith(b, ascii('GIF8'))) return 'gif';
  if (startsWith(b, ascii('RIFF')) && startsWith(b, ascii('WEBP'), 8)) return 'webp';
  if (b.length > 262 && startsWith(b, ascii('ustar'), 257)) return 'tar';
  if (startsWith(b, ascii('#!'))) return 'script';
  if (startsWith(b, [0x00, 0x61, 0x73, 0x6d])) return 'wasm';
  return 'other';
}

const EXECUTABLE = new Set(['exe', 'elf', 'macho']);
// What each name's extension says the file should be. Anything not listed can be any kind of text or data.
const EXPECT = {
  pdf: ['pdf'], png: ['png'], jpg: ['jpeg'], jpeg: ['jpeg'], gif: ['gif'], webp: ['webp'],
  zip: ['zip'], gz: ['gzip'], tgz: ['gzip'], tar: ['tar'], '7z': ['7z'], rar: ['rar'], cab: ['cab'],
  docx: ['zip'], xlsx: ['zip'], pptx: ['zip'], docm: ['zip'], xlsm: ['zip'], pptm: ['zip'], odt: ['zip'], ods: ['zip'], jar: ['zip'], apk: ['zip'],
  doc: ['ole'], xls: ['ole'], ppt: ['ole'], msi: ['ole'],
  exe: ['exe'], dll: ['exe'], scr: ['exe'], sys: ['exe'], com: ['exe', 'other'], wasm: ['wasm']
};
const extOf = (name) => { const s = String(name || '').toLowerCase(); const i = s.lastIndexOf('.'); const j = s.lastIndexOf('/'); return i > j ? s.slice(i + 1) : ''; };

// Does b contain the bytes of s (ASCII), or of s in UTF-16LE (as Office files store names)?
function hasBytes(b, s, utf16 = false) {
  const sig = utf16 ? Buffer.from(s, 'utf16le') : Buffer.from(s, 'latin1');
  return b.indexOf(sig) !== -1;
}

// PDF: JavaScript, or a launch action, is active content. Read as bytes (names can't be hidden from a byte search, but
// streams can be compressed: compressed streams are inflated and searched too, within the limits).
function pdfActive(b) {
  if (hasBytes(b, '/JavaScript') || hasBytes(b, '/JS ') || hasBytes(b, '/JS(') || hasBytes(b, '/JS<') || hasBytes(b, '/Launch')) return true;
  let at = b.indexOf('stream');
  let budget = 20 * 1024 * 1024;
  let n = 0;
  while (at !== -1 && n < 500 && budget > 0) {
    let start = at + 6;
    if (b[start] === 0x0d) start++;
    if (b[start] === 0x0a) start++;
    const end = b.indexOf('endstream', start);
    if (end === -1) break;
    try {
      const out = zlib.inflateSync(b.subarray(start, end), { maxOutputLength: Math.min(budget, 8 * 1024 * 1024) });
      budget -= out.length;
      if (hasBytes(out, '/JavaScript') || hasBytes(out, '/JS') || hasBytes(out, '/Launch')) return true;
    } catch { /* not a deflate stream */ }
    at = b.indexOf('stream', end + 9);
    n++;
  }
  return false;
}

// ZIP: the central directory, read by hand, so sizes are checked before anything is unpacked.
function zipEntries(b) {
  // The end-of-central-directory record is in the last 64 KB + 22 bytes.
  const sig = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
  const tail = Math.max(0, b.length - 65557);
  const eocd = b.lastIndexOf(sig);
  if (eocd < tail || eocd + 22 > b.length) return null;
  const count = b.readUInt16LE(eocd + 10);
  let p = b.readUInt32LE(eocd + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    if (p + 46 > b.length || b.readUInt32LE(p) !== 0x02014b50) return null;
    const method = b.readUInt16LE(p + 10);
    const csize = b.readUInt32LE(p + 20);
    const usize = b.readUInt32LE(p + 24);
    const nlen = b.readUInt16LE(p + 28); const xlen = b.readUInt16LE(p + 30); const clen = b.readUInt16LE(p + 32);
    const local = b.readUInt32LE(p + 42);
    const name = b.subarray(p + 46, p + 46 + nlen).toString('utf8');
    out.push({ name, method, csize, usize, local });
    p += 46 + nlen + xlen + clen;
  }
  return out;
}
function zipRead(b, e) {
  const l = e.local;
  if (l + 30 > b.length || b.readUInt32LE(l) !== 0x04034b50) return null;
  const start = l + 30 + b.readUInt16LE(l + 26) + b.readUInt16LE(l + 28);
  const data = b.subarray(start, start + e.csize);
  if (e.method === 0) return data;
  if (e.method === 8) return zlib.inflateRawSync(data, { maxOutputLength: Math.max(1, e.usize) + 1024 });
  return null;
}

// TAR: 512-byte headers.
function tarEntries(b) {
  const out = [];
  for (let p = 0; p + 512 <= b.length && out.length <= LIMITS.files;) {
    const h = b.subarray(p, p + 512);
    if (h.every((x) => x === 0)) break;
    const name = h.subarray(0, 100).toString('latin1').split('\u0000')[0];
    const size = parseInt(h.subarray(124, 136).toString('latin1').split('\u0000')[0].trim() || '0', 8) || 0;
    const kind = String.fromCharCode(h[156] || 48);
    if (kind === '0' || kind === '\u0000') out.push({ name, data: b.subarray(p + 512, p + 512 + size) });
    p += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

// Scans one file. Returns { type, flags: ['W.. reason: name'] }. ctx carries the limits across nested archives.
function scan(bytes, name, ctx = { depth: 0, files: 0, bytes: 0 }) {
  const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || []);
  const type = sniff(b);
  const ext = extOf(name);
  const flags = [];
  const label = String(name || '').slice(0, 120);
  const add = (f) => { if (flags.length < 20 && !flags.includes(f)) flags.push(f); };

  // W39: the contents are not what the name says.
  if (EXECUTABLE.has(type) && !['exe', 'dll', 'scr', 'sys', 'com', 'msi', ''].includes(ext) && ctx.depth === 0) add('W39 disguised type (really ' + type + '): ' + label);
  else if (EXPECT[ext] && !EXPECT[ext].includes(type) && type !== 'other') add('W39 disguised type (named .' + ext + ', really ' + type + '): ' + label);
  else if (EXPECT[ext] && type === 'other' && ['pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'gz', 'docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt'].includes(ext) && b.length > 0) {
    add('W39 disguised type (named .' + ext + ', contents don’t match): ' + label);
  }
  // W31 inside an archive: an executable or installer.
  if (ctx.depth > 0 && (EXECUTABLE.has(type) || ['exe', 'scr', 'msi', 'dll', 'hta', 'lnk', 'apk', 'vbe', 'wsf', 'pif', 'cpl'].includes(ext))) add('W31 executable or installer inside an archive: ' + label);

  // W41: active documents.
  if (type === 'pdf' && pdfActive(b)) add('W41 active document (PDF with JavaScript or a launch action): ' + label);
  if (type === 'ole' && (hasBytes(b, '_VBA_PROJECT', true) || hasBytes(b, 'VBA', true) || hasBytes(b, 'Macros', true))) add('W41 active document (Office macros): ' + label);

  // Archives: opened and scanned inside, within the limits.
  const open = (entries) => {
    for (const e of entries) {
      ctx.files++;
      if (ctx.files > LIMITS.files) { add('W40 archive bomb (more than ' + LIMITS.files + ' files): ' + label); return; }
      const data = e.data;
      if (!data) continue;
      ctx.bytes += data.length;
      if (ctx.bytes > LIMITS.bytes) { add('W40 archive bomb (more than 50 MB unpacked): ' + label); return; }
      const inner = scan(data, e.name, { depth: ctx.depth + 1, files: ctx.files, bytes: ctx.bytes, top: ctx.top || b.length });
      ctx.files = inner.ctx.files; ctx.bytes = inner.ctx.bytes;
      for (const f of inner.flags) add(f);
    }
  };
  if (type === 'zip' || type === 'gzip' || type === 'tar') {
    if (ctx.depth >= LIMITS.depth) add('W40 archive bomb (nested deeper than ' + LIMITS.depth + '): ' + label);
    else if (type === 'zip') {
      const list = zipEntries(b);
      if (!list) add('W30 archive the Wall can’t open (damaged ZIP): ' + label);
      else {
        const total = list.reduce((s, e) => s + e.usize, 0);
        if (list.length > LIMITS.files) add('W40 archive bomb (more than ' + LIMITS.files + ' files): ' + label);
        else if (total > LIMITS.bytes || total > Math.max(b.length, 1) * LIMITS.ratio) add('W40 archive bomb (unpacks to ' + total + ' bytes): ' + label);
        else {
          // Office files: macros live in vbaProject.bin.
          if (list.some((e) => e.name.toLowerCase().endsWith('vbaproject.bin'))) add('W41 active document (Office macros): ' + label);
          open(list.filter((e) => !e.name.endsWith('/')).map((e) => { try { return { name: e.name, data: zipRead(b, e) }; } catch { add('W30 archive the Wall can’t open (bad entry): ' + label); return { name: e.name, data: null }; } }));
        }
      }
    } else if (type === 'gzip') {
      try {
        const out = zlib.gunzipSync(b, { maxOutputLength: Math.min(LIMITS.bytes - ctx.bytes, Math.max(b.length, 1) * LIMITS.ratio) + 1 });
        const n = String(name || 'inner');
        const low = n.toLowerCase();
        const inner = low.endsWith('.tgz') ? n.slice(0, -4) + '.tar' : low.endsWith('.gz') ? n.slice(0, -3) : n + '.out';
        open([{ name: inner, data: out }]);
      } catch (e) {
        if (e && e.code === 'ERR_BUFFER_TOO_LARGE') add('W40 archive bomb (unpacks past the limits): ' + label);
        else add('W30 archive the Wall can’t open (damaged GZIP): ' + label);
      }
    } else {
      open(tarEntries(b));
    }
  } else if (type === '7z' || type === 'rar' || type === 'cab') {
    add('W30 archive the Wall can’t open (' + type + '): ' + label);
  }
  return { type, flags, ctx };
}

// What goes to the database with a changed file: its real type and the rules it breaks.
function summary(bytes, name) { const r = scan(bytes, name); return { type: r.type, flags: r.flags }; }

module.exports = { sniff, scan, summary, LIMITS, extOf };
