// Trains Second Look v0's weights (secondlook/model-v0.json) from public data that PEOPLE labelled, and sets its
// threshold. Run by hand; the data isn't kept in the repository (it carries the original posters' names):
//   node secondlook/train.js <folder with Youtube01-Psy.csv ... Youtube05-Shakira.csv> <SMSSpamCollection file>
// Sources (both CC BY 4.0, attribution in research/second-look/MODEL-CARD.md):
//   UCI YouTube Spam Collection: https://archive.ics.uci.edu/static/public/380/youtube+spam+collection.zip
//   UCI SMS Spam Collection:     https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip
// Nothing here comes from Claude's outputs as a label or a training example (Anthropic's rule), and nothing from the
// site's members.
//
// Method: logistic regression (spam = 1) on secondlook/index.js's own features, full-batch gradient descent with L2,
// trained on YouTube videos 01 to 03 plus the SMS set. Videos 04 and 05 are held out to set the threshold: the lowest
// "ordinary" probability at which, among the held-out comments it would clear, at most 1 in 80 were spam (Aaron's
// limit), stepped up by a safety margin. Deterministic: the same data always gives the same weights.
'use strict';

const fs = require('fs');
const path = require('path');

const BUCKETS = 1 << 14;
const ITERATIONS = 300, RATE = 2.0, L2 = 1e-4, MARGIN = 0.02;

function readYoutube(dir, names) {
  const out = [];
  for (const n of names) {
    const text = fs.readFileSync(path.join(dir, n), 'utf8');
    // A small CSV reader: quoted fields may hold commas, quotes ("") and line breaks.
    const rows = []; let row = [], field = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (q) { if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (ch === '"') q = false; else field += ch; continue; }
      if (ch === '"') q = true; else if (ch === ',') { row.push(field); field = ''; } else if (ch === '\n' || ch === '\r') { if (ch === '\r' && text[i + 1] === '\n') i++; row.push(field); rows.push(row); row = []; field = ''; } else field += ch;
    }
    if (field || row.length) { row.push(field); rows.push(row); }
    const head = rows.shift(); const ci = head.indexOf('CONTENT'), li = head.indexOf('CLASS');
    for (const r of rows) if (r.length > li && r[li] !== '') out.push({ text: r[ci].replace(/<[^>]+>/g, ' '), spam: Number(r[li]) });
  }
  return out;
}
function readSms(file) {
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => {
    const [lab, ...rest] = l.split('\t');
    return { text: rest.join('\t'), spam: lab === 'spam' ? 1 : 0 };
  });
}

function train(rows, features) {
  const X = rows.map((r) => features(r.text)); const y = rows.map((r) => r.spam);
  const w = new Float64Array(BUCKETS); let b = 0; const n = rows.length;
  // Balanced classes: each class weighs the same in the loss.
  const pos = y.reduce((a, c) => a + c, 0); const cw = [n / (2 * (n - pos)), n / (2 * pos)];
  for (let it = 0; it < ITERATIONS; it++) {
    const g = new Float64Array(BUCKETS); let gb = 0;
    for (let k = 0; k < n; k++) {
      let z = b; for (const [i, x] of X[k]) z += w[i] * x;
      const err = (1 / (1 + Math.exp(-z)) - y[k]) * cw[y[k]];
      for (const [i, x] of X[k]) g[i] += err * x;
      gb += err;
    }
    for (let i = 0; i < BUCKETS; i++) w[i] -= RATE * (g[i] / n + L2 * w[i]);
    b -= RATE * gb / n;
  }
  return { weights: Array.from(w, (x) => Math.round(x * 1e4) / 1e4), bias: Math.round(b * 1e4) / 1e4 };
}

function auc(scores, labels) { // labels: 1 = ordinary
  const idx = scores.map((s, i) => i).sort((a, b) => scores[a] - scores[b]);
  let rank = 0, sumPos = 0, nPos = 0;
  for (const i of idx) { rank++; if (labels[i]) { sumPos += rank; nPos++; } }
  const nNeg = labels.length - nPos;
  return (sumPos - nPos * (nPos + 1) / 2) / (nPos * nNeg);
}

function main() {
  const [dir, smsFile] = process.argv.slice(2);
  if (!dir || !smsFile) { console.error('usage: node secondlook/train.js <youtube folder> <SMSSpamCollection>'); process.exit(2); }
  const fit = readYoutube(dir, ['Youtube01-Psy.csv', 'Youtube02-KatyPerry.csv', 'Youtube03-LMFAO.csv']).concat(readSms(smsFile));
  const held = readYoutube(dir, ['Youtube04-Eminem.csv', 'Youtube05-Shakira.csv']);
  // Train with a placeholder model so index.js's features (which read buckets from the model) are used exactly.
  const tmp = path.join(__dirname, 'model-v0.json');
  const keep = fs.existsSync(tmp) ? fs.readFileSync(tmp, 'utf8') : null;
  fs.writeFileSync(tmp, JSON.stringify({ version: 'v0', buckets: BUCKETS, bias: 0, threshold: 1, weights: [] }));
  delete require.cache[require.resolve('./index.js')];
  const sl = require('./index.js');
  const m = train(fit, sl.features);
  const model = { version: 'v0', buckets: BUCKETS, bias: m.bias, threshold: 1, weights: m.weights };
  const p = held.map((r) => sl.ordinary(r.text, model)); const ok = held.map((r) => 1 - r.spam);
  // The threshold: walk down from the most confident; keep the largest set whose spam share is at most 1 in 80.
  const order = p.map((s, i) => i).sort((a, b) => p[b] - p[a]);
  let spam = 0, best = 1;
  order.forEach((i, k) => { spam += 1 - ok[i]; if (spam / (k + 1) <= 1 / 80) best = p[i]; });
  model.threshold = Math.min(0.9999, Math.round((best + MARGIN) * 1e4) / 1e4);
  const cleared = p.filter((s) => s >= model.threshold).length, wrong = p.filter((s, i) => s >= model.threshold && !ok[i]).length;
  model.trained = { examples: fit.length, held_out: held.length, auc_held_out: Math.round(auc(p, ok) * 1e4) / 1e4,
    held_out_cleared_share_of_ordinary: Math.round(cleared - wrong) / ok.reduce((a, c) => a + c, 0),
    held_out_wrong_clears: wrong, held_out_clears: cleared,
    sources: ['UCI YouTube Spam Collection (CC BY 4.0), videos 01-03 for training, 04-05 held out', 'UCI SMS Spam Collection (CC BY 4.0)'] };
  model.trained.held_out_cleared_share_of_ordinary = Math.round(model.trained.held_out_cleared_share_of_ordinary * 1e4) / 1e4;
  fs.writeFileSync(tmp, JSON.stringify(model));
  if (keep === null) { /* first run */ }
  console.log(JSON.stringify(model.trained, null, 1), 'threshold', model.threshold);
}

if (require.main === module) main();
module.exports = { train, auc, readYoutube, readSms, BUCKETS };
