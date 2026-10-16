// Amazon SNS messages (bounces and complaints from SES), trusted only after their signature checks out
// (https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html):
//   1. the signing certificate comes from an https://sns.<region>.amazonaws.com address, ending in .pem
//   2. the signature over the message's fields, in SNS's fixed order, verifies with that certificate
//      (SignatureVersion 1 is SHA1withRSA, 2 is SHA256withRSA)
//   3. the topic is ours (SNS_TOPIC_ARN). Anyone can create a topic and point it at us, and SNS signs their messages
//      too, so a good signature alone proves only that the message came through SNS.
//   4. it is less than an hour old, so an old message can't be replayed.
'use strict';

const crypto = require('crypto');

const CERT_HOST = /^sns\.[a-z0-9-]{3,}\.amazonaws\.com(\.cn)?$/;
const MAX_AGE_MS = 3600 * 1000;
const FIELDS = {
  Notification: ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type'],
  SubscriptionConfirmation: ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'],
  UnsubscribeConfirmation: ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type']
};

function certUrlOk(s) {
  let u;
  try { u = new URL(s); } catch { return false; }
  return u.protocol === 'https:' && u.port === '' && CERT_HOST.test(u.hostname) && u.pathname.endsWith('.pem') && !u.search && !u.username;
}

// The exact text SNS signed: each field present, as "Name\nValue\n", in SNS's order.
function stringToSign(m) {
  const names = FIELDS[m.Type];
  if (!names) return null;
  let out = '';
  for (const n of names) {
    if (m[n] === undefined || m[n] === null) {
      if (n === 'Subject') continue;
      return null;
    }
    if (typeof m[n] !== 'string') return null;
    out += n + '\n' + m[n] + '\n';
  }
  return out;
}

// Certificates are fetched once per address and kept for the life of the function instance.
const cache = new Map();
async function fetchCert(url) {
  if (cache.has(url)) return cache.get(url);
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 4000);
  try {
    const r = await fetch(url, { signal: ctl.signal, redirect: 'error' });
    if (!r.ok) throw new Error('certificate fetch failed');
    const pem = await r.text();
    if (pem.length > 20000) throw new Error('certificate too large');
    if (cache.size > 20) cache.clear();
    cache.set(url, pem);
    return pem;
  } finally {
    clearTimeout(timer);
  }
}

// { ok: true, message } or { ok: false, reason }. Never throws for a bad message.
async function verify(m, { topicArn, getCert = fetchCert, now = Date.now() } = {}) {
  if (!m || typeof m !== 'object' || Array.isArray(m)) return { ok: false, reason: 'shape' };
  if (!topicArn || m.TopicArn !== topicArn) return { ok: false, reason: 'topic' };
  if (m.SignatureVersion !== '1' && m.SignatureVersion !== '2') return { ok: false, reason: 'version' };
  if (!certUrlOk(m.SigningCertURL)) return { ok: false, reason: 'cert_url' };
  const text = stringToSign(m);
  if (text === null || typeof m.Signature !== 'string' || m.Signature.length > 1024) return { ok: false, reason: 'shape' };
  const at = Date.parse(m.Timestamp);
  if (!Number.isFinite(at) || Math.abs(now - at) > MAX_AGE_MS) return { ok: false, reason: 'stale' };
  let pem;
  try { pem = await getCert(m.SigningCertURL); } catch { return { ok: false, reason: 'cert_fetch' }; }
  let key;
  try {
    const cert = new crypto.X509Certificate(pem);
    if (Date.parse(cert.validTo) < now || Date.parse(cert.validFrom) > now) return { ok: false, reason: 'cert_dates' };
    key = cert.publicKey;
  } catch { return { ok: false, reason: 'cert' }; }
  let good = false;
  try {
    good = crypto.verify(m.SignatureVersion === '1' ? 'sha1' : 'sha256', Buffer.from(text, 'utf8'), key, Buffer.from(m.Signature, 'base64'));
  } catch { good = false; }
  return good ? { ok: true, message: m } : { ok: false, reason: 'signature' };
}

// From a verified SES notification: the addresses that bounced for good or complained, and which.
function suppressions(m) {
  let body;
  try { body = JSON.parse(m.Message); } catch { return []; }
  if (!body || typeof body !== 'object') return [];
  const kind = body.notificationType || body.eventType;
  const list = (xs) => (Array.isArray(xs) ? xs : []).map((r) => r && r.emailAddress).filter((a) => typeof a === 'string' && a.length <= 254);
  if (kind === 'Bounce' && body.bounce && body.bounce.bounceType === 'Permanent') return list(body.bounce.bouncedRecipients).map((a) => ({ address: a, reason: 'bounce' }));
  if (kind === 'Complaint' && body.complaint) return list(body.complaint.complainedRecipients).map((a) => ({ address: a, reason: 'complaint' }));
  return [];
}

// Where to confirm a subscription: only an SNS address over HTTPS.
function subscribeUrlOk(s) {
  let u;
  try { u = new URL(s); } catch { return false; }
  return u.protocol === 'https:' && u.port === '' && CERT_HOST.test(u.hostname);
}

module.exports = { verify, stringToSign, certUrlOk, subscribeUrlOk, suppressions, fetchCert };
