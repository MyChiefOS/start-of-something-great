// Test fixtures for notifications (PR 13): a throwaway certificate standing in for SNS's signing certificate, made fresh
// on every run with openssl (nothing secret is kept in the repository), messages signed the way SNS signs them, and a
// reader for raw emails.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { stringToSign } = require('../notify/sns');

const TOPIC = 'arn:aws:sns:us-east-1:123456789012:dayonegreat-email-events';
const CERT_URL = 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem';

function makeCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-sns-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'),
      '-days', '2', '-subj', '/CN=sns.amazonaws.com'], { stdio: 'ignore' });
    return { key: fs.readFileSync(path.join(dir, 'k.pem'), 'utf8'), cert: fs.readFileSync(path.join(dir, 'c.pem'), 'utf8') };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// A message as SNS would send it, signed with the fixture key (SignatureVersion 2 = SHA256withRSA, 1 = SHA1withRSA).
function signed(key, fields, { version = '2' } = {}) {
  const m = { Type: 'Notification', MessageId: crypto.randomUUID(), TopicArn: TOPIC, Timestamp: new Date().toISOString(),
    SignatureVersion: version, SigningCertURL: CERT_URL, ...fields };
  m.Signature = crypto.sign(version === '1' ? 'sha1' : 'sha256', Buffer.from(stringToSign(m), 'utf8'), key).toString('base64');
  return m;
}

const bounce = (address, type = 'Permanent') => JSON.stringify({ notificationType: 'Bounce', bounce: { bounceType: type, bouncedRecipients: [{ emailAddress: address }] } });
const complaint = (address) => JSON.stringify({ notificationType: 'Complaint', complaint: { complainedRecipients: [{ emailAddress: address }] } });

// Reads a raw message back: its headers and the decoded text.
function parse(raw) {
  const i = raw.indexOf('\r\n\r\n');
  const headers = {};
  for (const l of raw.slice(0, i).split('\r\n')) { const k = l.slice(0, l.indexOf(':')); headers[k.toLowerCase()] = l.slice(k.length + 2); }
  return { headers, text: Buffer.from(raw.slice(i + 4).replace(/\r\n/g, ''), 'base64').toString('utf8').replace(/\r\n/g, '\n') };
}

module.exports = { TOPIC, CERT_URL, makeCert, signed, bounce, complaint, parse };
