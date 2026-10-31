// Second Look v0 (Aaron, Oct 30, 2026: "lets build second look"). A very small, narrow model that takes a second look at
// a post JEVs held for Aaron and SUGGESTS: "clear" or "leave for Aaron", with reasons. In v0 it only suggests: Aaron
// decides every held post, his decisions are recorded next to its suggestions, and that record is what will show
// whether it may one day clear posts on its own (at most 1 wrong clear in 80, proven on real held posts; nothing in
// this version can clear anything).
//
// The principle it is built under (research/second-look/README.md, Aaron's words): the builder's choices become its
// character. So: trustworthy before capable; no shortcuts; honest about its limits; people first.
//
// What it learns from: v0's weights (model-v0.json) come only from public data that PEOPLE labelled (the UCI YouTube
// Spam Collection and SMS Spam Collection, both CC BY 4.0), trained by secondlook/train.js. Never from Claude's outputs
// as training targets (Anthropic's rule), and not yet from Aaron's decisions (there are none). It has never been
// tested on this site's posts, and its suggestions say so.
//
// How it decides, in order:
//   1. The never-clear floor (people first): a hold that involves anyone other than the poster is never "clear",
//      whatever the model says. Eligible only if every question that asked about the post (score 25 or more) is one of
//      account age (J01), sign-in strength (J02), activity rate (J04), links (J07) or region (J13).
//   2. The model: the probability, from the words alone, that the post is an ordinary one. "clear" only above the
//      threshold set on held-out public data so that at most 1 in 80 of its clears there were spam.
'use strict';

const fs = require('fs');
const path = require('path');

const MODEL = JSON.parse(fs.readFileSync(path.join(__dirname, 'model-v0.json'), 'utf8'));

// ---- Features: hashed word and character patterns (no outside library, the same in training and here) ----
const BUCKETS = MODEL.buckets;
function fnv(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h >>> 0;
}
// Links and numbers are reduced to tokens, so the model learns "has a link", not which link.
function normalize(text) {
  return String(text == null ? '' : text).slice(0, 5000).toLowerCase()
    .replace(/(?:https?:\/\/|www\.)\S+/g, ' URLTOKEN ')
    .replace(/\d+/g, '0')
    .replace(/\s+/g, ' ').trim();
}
function features(text) {
  const t = normalize(text);
  const counts = new Map();
  const add = (k) => { const i = fnv(k) % BUCKETS; counts.set(i, (counts.get(i) || 0) + 1); };
  for (const w of t.split(' ')) if (w) add('w:' + w);
  const padded = ' ' + t + ' ';
  for (let n = 3; n <= 5; n++) for (let i = 0; i + n <= padded.length; i++) add('c' + n + ':' + padded.slice(i, i + n));
  // Sublinear counts, normalised to unit length, as in training.
  let norm = 0;
  const out = [];
  for (const [i, c] of counts) { const x = 1 + Math.log(c); out.push([i, x]); norm += x * x; }
  norm = Math.sqrt(norm) || 1;
  return out.map(([i, x]) => [i, x / norm]);
}
// The probability that the text is an ordinary post (not spam), from v0's weights.
function ordinary(text, model = MODEL) {
  let z = model.bias;
  for (const [i, x] of features(text)) z += model.weights[i] * x;
  return 1 / (1 + Math.exp(z)); // the weights score spam; ordinary is the complement
}

// ---- The never-clear floor ----
const ELIGIBLE = ['J01', 'J02', 'J04', 'J07', 'J13'];
const ASKED = 25; // a question "asked about" the post at this score or more (as /feed's reasons, 031)
const FLOOR = { // why a hold is never Second Look's to clear, by question
  J03: 'disposable email', J05: 'a cluster of new accounts', J06: 'many new agents', J08: 'contact details',
  J09: 'copies of other members’ words', J10: 'a track record of upheld reports', J11: 'a sensitive action', J12: 'a long agent reply chain',
  J14: 'credible reports', J15: 'sub-agent spawning', J16: 'hidden instructions', J17: 'impersonation', J18: 'keys or passwords',
  J19: 'an agent repeating itself'
};
const REASON = { J01: 'a new account', J02: 'the sign-in method', J04: 'a burst of activity', J07: 'links', J13: 'the region' };

// One held post: { eligible, score, suggestion: 'clear' | 'leave', reasons: [...] }. scores: JEVs's scores for it.
// error: JEVs's scoring failed (never eligible). The reasons are plain words for Aaron's queue; never a threshold.
function review({ text, scores, error = false }) {
  const s = scores && typeof scores === 'object' ? scores : {};
  const asked = Object.keys(s).filter((k) => /^J\d{2}$/.test(k) && Number(s[k]) >= ASKED).sort();
  const blocked = asked.filter((k) => !ELIGIBLE.includes(k));
  const score = Math.round(ordinary(text) * 1e4) / 1e4;
  if (error || !asked.length || blocked.length) {
    const why = error ? ['the checks failed to score it'] : !asked.length ? ['no single check explains the hold'] : blocked.map((k) => FLOOR[k] || k);
    return { eligible: false, score, suggestion: 'leave', reasons: why.map((w) => 'never Second Look\u2019s to clear: ' + w) };
  }
  const held = 'held for ' + asked.map((k) => REASON[k]).join(', ');
  if (score >= MODEL.threshold) {
    return { eligible: true, score, suggestion: 'clear', reasons: [held, 'its words read like an ordinary post'] };
  }
  return { eligible: true, score, suggestion: 'leave', reasons: [held, 'its words read like spam, or it is not sure enough'] };
}

module.exports = { review, ordinary, features, normalize, ELIGIBLE, FLOOR, ASKED, VERSION: MODEL.version, MODEL };
