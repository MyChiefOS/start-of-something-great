// Test fixtures for notifications (PR 13): a throwaway certificate standing in for SNS's signing certificate, made fresh
// on every run with openssl (nothing secret is kept in the repository), and messages signed the way SNS signs them.
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

module.exports = { TOPIC, CERT_URL, makeCert, signed, bounce, complaint };
