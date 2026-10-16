// Email settings, from environment variables Aaron sets in Vercel himself (EMAIL-SETUP.md). Claude never sees their
// values. Notices are in-app only (Aaron, Oct 16, 2026): email carries sign-in links and nothing else, and no member's
// address is ever stored.
//   EMAIL_TRANSPORT        "ses" to send sign-in emails through Amazon SES; anything else (or nothing) keeps email
//                          sign-in off
//   SES_REGION             e.g. us-east-1
//   SES_FROM               e.g. Day One Great <signin@dayonegreat.com> (an address on the verified domain)
//   SES_ACCESS_KEY_ID      an IAM user allowed only to send (ses:SendEmail and ses:SendRawEmail, EMAIL-SETUP.md)
//   SES_SECRET_ACCESS_KEY  its secret
//   SES_CONFIGURATION_SET  optional: the configuration set that publishes bounces and complaints to SNS
//   SNS_TOPIC_ARN          the one SNS topic whose bounce and complaint messages we accept
//   CRON_SECRET            Vercel sends it to /api/cron as "Authorization: Bearer <value>"
// (Vercel keeps AWS_* names for its own use, so these use their own names.)
// Addresses that bounced or complained are kept only as a keyed fingerprint, under the sign-in fingerprint keys Aaron
// already sets (signin/config.js), with a label of their own, so no new secret is needed.
'use strict';

const crypto = require('crypto');
const c = require('../signin/crypto');
const { logTransport, sesTransport } = require('./transport');

const FROM_DEFAULT = 'Day One Great <signin@dayonegreat.com>';
const REPLY_TO = 'hello@dayonegreat.com';

let sharedLog;
function load(env = process.env) {
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
    transport,
    error,
    from: env.SES_FROM || FROM_DEFAULT,
    replyTo: REPLY_TO,
    topicArn: env.SNS_TOPIC_ARN || null,
    cronSecret: env.CRON_SECRET && env.CRON_SECRET.length >= 16 ? env.CRON_SECRET : null
  };
}

// An address's fingerprint for suppressions, under each sign-in fingerprint key still in use (current key first).
const suppressionPrints = (keys, address) => c.fingerprints(keys, 'suppress', String(address).trim().toLowerCase());

// Constant-time check of Vercel Cron's header against CRON_SECRET (compared as hashes, so lengths don't leak).
function cronOk(cfg, header) {
  if (!cfg.cronSecret || typeof header !== 'string') return false;
  const want = crypto.createHash('sha256').update('Bearer ' + cfg.cronSecret).digest();
  const got = crypto.createHash('sha256').update(header).digest();
  return crypto.timingSafeEqual(want, got);
}

module.exports = { load, suppressionPrints, cronOk, FROM_DEFAULT };
