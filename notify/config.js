// Email settings, from environment variables Aaron sets in Vercel himself (EMAIL-SETUP.md). Claude never sees their
// values. Without NOTIFY_KEY, members can't add an address and no email copies exist; the in-app inbox works either way.
//   NOTIFY_KEY             base64, at least 32 random bytes: seals addresses, fingerprints them for bounces, signs
//                          unsubscribe links (separate keys derived from it with HKDF)
//   EMAIL_TRANSPORT        "ses" to send through Amazon SES; anything else (or nothing) is the log transport
//   SES_REGION             e.g. us-east-1
//   SES_FROM               e.g. Day One Great <notices@dayonegreat.com> (an address on the verified domain)
//   SES_ACCESS_KEY_ID      an IAM user allowed only ses:SendEmail (and ses:SendRawEmail)
//   SES_SECRET_ACCESS_KEY  its secret
//   SES_CONFIGURATION_SET  optional: the configuration set that publishes bounces and complaints to SNS
//   SNS_TOPIC_ARN          the one SNS topic whose bounce and complaint messages we accept
//   CRON_SECRET            Vercel sends it to /api/cron as "Authorization: Bearer <value>"
// (Vercel keeps AWS_* names for its own use, so these use their own names.)
'use strict';

const crypto = require('crypto');
const c = require('../signin/crypto');
const { logTransport, sesTransport } = require('./transport');

const FROM_DEFAULT = 'Day One Great <notices@dayonegreat.com>';
const REPLY_TO = 'hello@dayonegreat.com';

function keys(b64) {
  if (!b64 || Buffer.from(b64, 'base64').length < 32) return null;
  return { seal: c.subkey(b64, 'email address seal'), fp: c.subkey(b64, 'email address fingerprint'), unsub: c.subkey(b64, 'email unsubscribe') };
}

let sharedLog;
function load(env = process.env) {
  const k = keys(env.NOTIFY_KEY);
  let transport = null;
  let error = null;
  if (env.EMAIL_TRANSPORT === 'ses') {
    try {
      transport = sesTransport({ region: env.SES_REGION, accessKeyId: env.SES_ACCESS_KEY_ID, secretAccessKey: env.SES_SECRET_ACCESS_KEY,
        configurationSet: env.SES_CONFIGURATION_SET || null });
    } catch (e) {
      error = e.message;
    }
  } else {
    transport = sharedLog || (sharedLog = logTransport());
  }
  return {
    keys: k,
    transport,
    error,
    // Members may add an address only when there is a key to seal it and a way to send.
    offered: Boolean(k && transport),
    from: env.SES_FROM || FROM_DEFAULT,
    replyTo: REPLY_TO,
    topicArn: env.SNS_TOPIC_ARN || null,
    cronSecret: env.CRON_SECRET && env.CRON_SECRET.length >= 16 ? env.CRON_SECRET : null
  };
}

// The address, sealed and bound to its member, so a sealed value copied onto another member's row doesn't open.
const seal = (k, memberId, address) => c.seal(k.seal, { m: memberId, a: address });
function open(k, memberId, sealed) {
  const v = c.open(k.seal, sealed);
  return v && v.m === memberId && typeof v.a === 'string' ? v.a : null;
}
const fingerprint = (k, address) => c.hmacHex(k.fp, String(address).trim().toLowerCase());

// One-click unsubscribe: the contact's ID and a signature over it. Stateless, so it works from any old email.
const unsubSig = (k, contactId) => c.hmacHex(k.unsub, 'unsubscribe ' + contactId);
const unsubOk = (k, contactId, sig) => typeof sig === 'string' && /^[0-9a-f]{64}$/.test(sig) && c.same(unsubSig(k, contactId), sig);

// "j***@example.com", for showing a member which address they chose without printing it in full.
function masked(address) {
  const [user, domain] = String(address).split('@');
  return (user ? user[0] : '') + '***@' + (domain || '');
}

// Constant-time check of Vercel Cron's header against CRON_SECRET (compared as hashes, so lengths don't leak).
function cronOk(cfg, header) {
  if (!cfg.cronSecret || typeof header !== 'string') return false;
  const want = crypto.createHash('sha256').update('Bearer ' + cfg.cronSecret).digest();
  const got = crypto.createHash('sha256').update(header).digest();
  return crypto.timingSafeEqual(want, got);
}

module.exports = { load, keys, seal, open, fingerprint, unsubSig, unsubOk, masked, cronOk, FROM_DEFAULT };
