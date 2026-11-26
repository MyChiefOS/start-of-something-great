// Upload scanning (088; Aaron's plan, Phase 1 item 4: "active security scanning for all file uploads"). Day One Great
// has no upload route today: its file inputs (the sign-in key file, the proof bundle) are read in the browser and never
// sent. So the scan sits in the firewall, in front of every route: any file that arrives in a request body (a
// multipart form) is read by the Wall's file scanner (wall/files.js) before any page or API code sees it, and any
// upload route added later is covered from its first request.
//
// Blocked: a program of any kind, a file whose contents aren't what its name says (W39), an archive bomb or a program
// inside an archive (W40, W31), an Office file with macros or a PDF with JavaScript (W41), the EICAR test file (W42).
// No regular expressions read the body (as 083).
'use strict';

const files = require('./files');

const BLOCK = ['W31', 'W39', 'W40', 'W41', 'W42'];
const PROGRAMS = new Set(['exe', 'elf', 'macho', 'dll', 'msi', 'jar', 'apk', 'wasm']);

function boundaryOf(contentType) {
  const ct = String(contentType || '');
  if (!ct.toLowerCase().startsWith('multipart/form-data')) return null;
  const at = ct.toLowerCase().indexOf('boundary=');
  if (at === -1) return null;
  let b = ct.slice(at + 9).split(';')[0].trim();
  if (b.startsWith('"') && b.endsWith('"')) b = b.slice(1, -1);
  return b && b.length <= 200 ? b : null;
}

// The file parts of a multipart body: [{ field, filename, bytes, complete }]. complete is false for the last part when
// the body was cut short (the firewall reads at most 64 KB).
function parts(body, contentType) {
  const b = boundaryOf(contentType);
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ''), 'latin1');
  if (!b) return [];
  const sep = Buffer.from('--' + b);
  const out = [];
  let at = buf.indexOf(sep);
  while (at !== -1 && out.length < 50) {
    const start = at + sep.length;
    if (buf[start] === 0x2d && buf[start + 1] === 0x2d) break; // the closing --boundary--
    const headEnd = buf.indexOf('\r\n\r\n', start);
    if (headEnd === -1) break;
    const head = buf.subarray(start, headEnd).toString('latin1');
    const next = buf.indexOf(sep, headEnd + 4);
    const end = next === -1 ? buf.length : next - 2; // the CRLF before the next boundary
    const disp = head.split('\r\n').find((l) => l.toLowerCase().startsWith('content-disposition:')) || '';
    const fnAt = disp.toLowerCase().indexOf('filename=');
    if (fnAt !== -1) {
      let fn = disp.slice(fnAt + 9).split(';')[0].trim();
      if (fn.startsWith('"')) fn = fn.slice(1, fn.indexOf('"', 1) === -1 ? undefined : fn.indexOf('"', 1));
      const nAt = disp.toLowerCase().indexOf(' name=');
      const field = nAt === -1 ? '' : disp.slice(nAt + 6).split(';')[0].trim().split('"').join('');
      out.push({ field: field.slice(0, 100), filename: fn.slice(0, 200), bytes: buf.subarray(headEnd + 4, Math.max(headEnd + 4, end)), complete: next !== -1 });
    }
    at = next;
  }
  return out;
}

// The body without its files' bytes, for the firewall's text checks: each file part is read by the file scanner instead
// (an image is not text, and its bytes would read as attacks). The file names stay.
function textOnly(body, contentType) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ''), 'latin1');
  const b = boundaryOf(contentType);
  if (!b) return buf.toString('utf8');
  let out = buf.toString('latin1');
  for (const p of parts(buf, contentType)) if (p.bytes.length) out = out.split(p.bytes.toString('latin1')).join(' ' + p.filename + ' ');
  return Buffer.from(out, 'latin1').toString('utf8');
}

// The first reason to refuse the body's files, or null: { rule, kind }.
function check(body, contentType) {
  for (const p of parts(body, contentType)) {
    const label = 'upload ' + (p.filename || 'file');
    const r = files.scan(p.bytes, p.filename || 'upload');
    if (PROGRAMS.has(r.type)) return { rule: 'W39', kind: label + ' is a program (' + r.type + ')' };
    // A part cut short can't be judged as an archive or a document; only what its first bytes already prove counts.
    const hits = r.flags.filter((f) => BLOCK.includes(f.split(' ')[0]) && (p.complete || f.startsWith('W39') || f.startsWith('W42')));
    if (hits.length) return { rule: hits[0].split(' ')[0], kind: (label + ': ' + hits[0].slice(hits[0].indexOf(' ') + 1)).slice(0, 160) };
  }
  return null;
}

module.exports = { parts, check, textOnly, boundaryOf, BLOCK };
