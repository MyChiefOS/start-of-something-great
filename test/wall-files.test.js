// 084, the Agentic Wall's file scanner (wall/files.js): real type from contents, archives opened inside, active
// documents, archive bombs. Files are built here in memory; no real malware is used or stored.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const zlib = require('zlib');
const files = require('../wall/files');

const rules = (r) => r.flags.map((f) => f.split(' ')[0]);
// A ZIP written by hand (stored or deflated entries), so the tests need no library.
function zip(entries, { claim } = {}) {
  const locals = []; const centrals = []; let off = 0;
  for (const [name, data, deflate] of entries) {
    const body = deflate ? zlib.deflateRawSync(data) : data;
    const n = Buffer.from(name);
    const l = Buffer.alloc(30); l.writeUInt32LE(0x04034b50, 0); l.writeUInt16LE(deflate ? 8 : 0, 8); l.writeUInt32LE(body.length, 18); l.writeUInt32LE(data.length, 22); l.writeUInt16LE(n.length, 26);
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(deflate ? 8 : 0, 10); c.writeUInt32LE(body.length, 20); c.writeUInt32LE(claim || data.length, 24); c.writeUInt16LE(n.length, 28); c.writeUInt32LE(off, 42);
    locals.push(l, n, body); centrals.push(c, n); off += 30 + n.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const e = Buffer.alloc(22); e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(entries.length, 8); e.writeUInt16LE(entries.length, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, e]);
}
function tar(entries) {
  const parts = [];
  for (const [name, data] of entries) {
    const h = Buffer.alloc(512); h.write(name, 0, 'latin1'); h.write(data.length.toString(8).padStart(11, '0') + '\u0000', 124, 'latin1'); h[156] = 48; h.write('ustar', 257, 'latin1');
    parts.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  return Buffer.concat([...parts, Buffer.alloc(1024)]);
}
const EXE = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(200, 1)]);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(100)]);
const PDF = Buffer.from('%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer <<>>\n%%EOF');
const OLE = Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.alloc(500)]);

test('WF1: plain files pass; the real type is read from the contents', () => {
  for (const [b, n, t] of [[PNG, 'logo.png', 'png'], [PDF, 'guide.pdf', 'pdf'], [Buffer.from('const a = 1;\n'), 'src/a.js', 'other'], [Buffer.from('# Title\n'), 'README.md', 'other']]) {
    const r = files.summary(b, n);
    assert.deepStrictEqual([r.type, r.flags], [t, []], n);
  }
});

test('WF2 (W39): a program or another kind of file under the wrong name is blocked', () => {
  assert.deepStrictEqual(rules(files.summary(EXE, 'invoice.pdf')), ['W39']);
  assert.deepStrictEqual(rules(files.summary(zip([['a.txt', Buffer.from('hi')]]), 'photo.png')), ['W39']);
  assert.deepStrictEqual(rules(files.summary(Buffer.from('just text'), 'report.pdf')), ['W39']);
  assert.deepStrictEqual(files.summary(EXE, 'setup.exe').flags, [], 'a program named as one is the name rule\'s job (W31, 082)');
});

test('WF3: archives are opened and scanned inside, three deep (ZIP, GZIP, TAR)', () => {
  assert.deepStrictEqual(files.summary(zip([['docs/a.txt', Buffer.from('hello')], ['b.png', PNG, true]]), 'bundle.zip').flags, []);
  assert.deepStrictEqual(rules(files.summary(zip([['tools/run.exe', EXE, true]]), 'bundle.zip')), ['W31']);
  assert.deepStrictEqual(rules(files.summary(zlib.gzipSync(tar([['x/y.pdf', EXE]])), 'data.tgz')).sort(), ['W31', 'W39'], 'a program named .pdf inside a TAR inside a GZIP');
  const nested = zip([['l1.zip', zip([['l2.zip', zip([['l3.zip', zip([['deep.exe', EXE]])]])]])]]);
  assert.ok(rules(files.summary(nested, 'n.zip')).includes('W40'), 'nested deeper than 3');
});

test('WF4 (W40): archive bombs are blocked before anything is unpacked', () => {
  assert.ok(rules(files.summary(zip([['big.txt', Buffer.alloc(10)]], { claim: 200 * 1024 * 1024 }), 'b.zip')).includes('W40'), 'claims 200 MB');
  const many = zip(Array.from({ length: 1001 }, (_, i) => ['f' + i + '.txt', Buffer.from('x')]));
  assert.ok(rules(files.summary(many, 'many.zip')).includes('W40'));
  const gz = zlib.gzipSync(Buffer.alloc(60 * 1024 * 1024));
  assert.ok(rules(files.summary(gz, 'z.gz')).includes('W40'), 'a gzip that unpacks past the limits');
});

test('WF5 (W41): Office macros and PDF scripts or launch actions are blocked; plain documents pass', () => {
  assert.deepStrictEqual(rules(files.summary(zip([['word/document.xml', Buffer.from('<w/>')], ['word/vbaProject.bin', OLE]]), 'memo.docm')), ['W41']);
  assert.deepStrictEqual(files.summary(zip([['word/document.xml', Buffer.from('<w/>')]]), 'memo.docx').flags, []);
  assert.deepStrictEqual(rules(files.summary(Buffer.concat([OLE, Buffer.from('_VBA_PROJECT', 'utf16le')]), 'old.doc')), ['W41']);
  assert.deepStrictEqual(rules(files.summary(Buffer.from('%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj'), 'a.pdf')), ['W41']);
  assert.deepStrictEqual(rules(files.summary(Buffer.from('%PDF-1.7\n<< /Type /Action /S /Launch /F (cmd.exe) >>'), 'b.pdf')), ['W41']);
  const hidden = Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj << /Filter /FlateDecode >> stream\n'), zlib.deflateSync(Buffer.from('<< /S /JavaScript /JS (x) >>')), Buffer.from('\nendstream endobj')]);
  assert.deepStrictEqual(rules(files.summary(hidden, 'c.pdf')), ['W41'], 'inside a compressed stream');
});

test('WF6 (W30): archive kinds the Wall can\'t open are flagged', () => {
  assert.deepStrictEqual(rules(files.summary(Buffer.concat([Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), Buffer.alloc(50)]), 'a.7z')), ['W30']);
  assert.deepStrictEqual(rules(files.summary(Buffer.concat([Buffer.from('Rar!'), Buffer.alloc(50)]), 'a.rar')), ['W30']);
});

test('WF7: no regular expression reads a file, and a worst-case file stays fast', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'wall', 'files.js'), 'utf8');
  assert.ok(!/new RegExp|\.test\(|\.exec\(|\.match\(|\.replace\(\//.test(src));
  const t0 = Date.now();
  files.summary(Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.from('stream\nxx\nendstream\n'.repeat(2000))]), 'x.pdf');
  files.summary(Buffer.alloc(5 * 1024 * 1024, 0x50), 'big.bin');
  assert.ok(Date.now() - t0 < 3000, 'took ' + (Date.now() - t0) + ' ms');
});
