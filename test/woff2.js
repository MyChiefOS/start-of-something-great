// A small WOFF2 reader for the font tests: which tables a file has, its names and the characters it maps. Plain Node
// (brotli is built in). Only untransformed tables are read (name, cmap and fvar never are transformed by WOFF2).
'use strict';
const zlib = require('zlib');

const KNOWN = ['cmap', 'head', 'hhea', 'hmtx', 'maxp', 'name', 'OS/2', 'post', 'cvt ', 'fpgm', 'glyf', 'loca', 'prep', 'CFF ', 'VORG',
  'EBDT', 'EBLC', 'gasp', 'hdmx', 'kern', 'LTSH', 'PCLT', 'VDMX', 'vhea', 'vmtx', 'BASE', 'GDEF', 'GPOS', 'GSUB', 'EBSC', 'JSTF', 'MATH',
  'CBDT', 'CBLC', 'COLR', 'CPAL', 'SVG ', 'sbix', 'acnt', 'avar', 'bdat', 'bloc', 'bsln', 'cvar', 'fdsc', 'feat', 'fmtx', 'fvar', 'gvar',
  'hsty', 'just', 'lcar', 'mort', 'morx', 'opbd', 'prop', 'trak', 'Zapf', 'Silf', 'Glat', 'Gloc', 'Feat', 'Sill'];

function base128(buf, at) {
  let v = 0;
  for (let i = 0; i < 5; i++) {
    const b = buf[at.i++];
    v = v * 128 + (b & 0x7f);
    if (!(b & 0x80)) return v;
  }
  throw new Error('bad UIntBase128');
}

function read(buf) {
  if (buf.toString('latin1', 0, 4) !== 'wOF2') throw new Error('not a WOFF2 file');
  const numTables = buf.readUInt16BE(12);
  const compressed = buf.readUInt32BE(20);
  const at = { i: 48 };
  const dir = [];
  for (let n = 0; n < numTables; n++) {
    const flags = buf[at.i++];
    const tag = (flags & 0x3f) === 0x3f ? buf.toString('latin1', at.i, (at.i += 4)) : KNOWN[flags & 0x3f];
    const version = flags >> 6;
    const orig = base128(buf, at);
    const transformed = ((tag === 'glyf' || tag === 'loca') && version === 0) || (tag === 'hmtx' && version === 1);
    const length = transformed ? base128(buf, at) : orig;
    dir.push({ tag, length, transformed });
  }
  const data = zlib.brotliDecompressSync(buf.subarray(at.i, at.i + compressed));
  const tables = {};
  let off = 0;
  for (const t of dir) { tables[t.tag] = t.transformed ? null : data.subarray(off, off + t.length); off += t.length; }
  return { tags: dir.map((t) => t.tag), tables };
}

function names(table) {
  const count = table.readUInt16BE(2), strings = table.readUInt16BE(4), out = [];
  for (let i = 0; i < count; i++) {
    const r = 6 + i * 12;
    const platform = table.readUInt16BE(r), id = table.readUInt16BE(r + 6), len = table.readUInt16BE(r + 8), o = strings + table.readUInt16BE(r + 10);
    const raw = table.subarray(o, o + len);
    let text;
    if (platform === 3 || platform === 0) { const b = Buffer.from(raw); b.swap16(); text = b.toString('utf16le'); } else text = raw.toString('latin1');
    out.push({ platform, id, text });
  }
  return out;
}

// Every code point the font maps, from its Unicode subtable (format 4 or 12).
function codepoints(table) {
  const n = table.readUInt16BE(2);
  const subs = [];
  for (let i = 0; i < n; i++) {
    const p = table.readUInt16BE(4 + i * 8), e = table.readUInt16BE(6 + i * 8), o = table.readUInt32BE(8 + i * 8);
    if ((p === 3 && (e === 1 || e === 10)) || p === 0) subs.push({ o, format: table.readUInt16BE(o) });
  }
  const pick = subs.find((s) => s.format === 12) || subs.find((s) => s.format === 4);
  if (!pick) throw new Error('no Unicode cmap');
  const set = new Set();
  const t = table.subarray(pick.o);
  if (pick.format === 12) {
    const groups = t.readUInt32BE(12);
    for (let g = 0; g < groups; g++) {
      const s = t.readUInt32BE(16 + g * 12), e = t.readUInt32BE(20 + g * 12), gid = t.readUInt32BE(24 + g * 12);
      for (let c = s; c <= e; c++) if (gid + c - s) set.add(c);
    }
  } else {
    const seg = t.readUInt16BE(6) / 2;
    const ends = 14, starts = ends + seg * 2 + 2, deltas = starts + seg * 2, ranges = deltas + seg * 2;
    for (let s = 0; s < seg; s++) {
      const end = t.readUInt16BE(ends + s * 2), start = t.readUInt16BE(starts + s * 2), delta = t.readInt16BE(deltas + s * 2), ro = t.readUInt16BE(ranges + s * 2);
      for (let c = start; c <= end && c !== 0xffff; c++) {
        let gid;
        if (ro === 0) gid = (c + delta) & 0xffff;
        else { const g = t.readUInt16BE(ranges + s * 2 + ro + (c - start) * 2); gid = g ? (g + delta) & 0xffff : 0; }
        if (gid) set.add(c);
      }
    }
  }
  return set;
}

module.exports = { read, names, codepoints };
