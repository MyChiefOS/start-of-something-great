// The healer's normalizing, in JavaScript, for heal/propose.js: the firewall's own de-obfuscation (wall/normalize.js:
// encodings, entities, look-alike and full-width letters, hidden characters), then letters and digits only, as the
// database's app.heal_norm does (096). The database decides what is enforced; this only writes proposals.
'use strict';
const { clean } = require('../wall/normalize');

const fold = (s) => clean(String(s == null ? '' : s).slice(0, 6000)).replace(/hxxp/g, 'http').split('[.]').join('.').replace(/\s+/g, ' ');
const norm = (s) => fold(s).replace(/[^a-z0-9]+/g, '');

// The variants the patch gate replays (096): case, spacing, look-alike letters, hidden characters, defanging.
function variants(s) {
  return [s, s.toUpperCase(), s.split('').join(' '), s.split(' ').join(' ​'),
    s.replace(/a/g, 'а').replace(/o/g, 'о').replace(/e/g, 'е'), s.replace(/http/g, 'hxxp').split('.').join('[.]')];
}

// The text pieces the database fingerprints: the whole normalized text up to 48 characters, else up to four 40s.
function pieces(s) {
  const n = norm(s);
  if (n.length <= 48) return n ? [n] : [];
  const out = [];
  for (let i = 0; i < 4 && n.length >= i * 40 + 40; i++) out.push(n.slice(i * 40, i * 40 + 40));
  return out;
}
module.exports = { fold, norm, variants, pieces };
