// Sign-in emails (email links, PR 2) through Amazon SES, straight away. Notices are in-app only (Aaron, Oct 16, 2026),
// so this is the only email the site sends. The address is used to send and then forgotten; it is never stored.
// An address that bounced for good or complained (app.email_suppressions, a keyed fingerprint only) is skipped, to
// keep the sending domain's reputation; the reply on /join is the same either way, so nobody learns which.
// Only with SES: the log transport would swallow the link, so email sign-in stays off until real email is on.
'use strict';

const mime = require('./mime');
const { suppressionPrints } = require('./config');
const store = require('../db/notify');

const SYSTEM = { actor: 'system' };

// cfg: notify/config.js load(). run: the database runner. keys: the sign-in fingerprint keys (signin/config.js).
function signinSender(cfg, { run, keys }) {
  if (!cfg.transport || cfg.transport.name !== 'ses' || !run || !keys || !keys.length) return null;
  return async (to, link) => {
    if (await run(SYSTEM, (t) => store.suppressed(t, suppressionPrints(keys, to)))) return;
    const raw = mime.build({ from: cfg.from, to, replyTo: cfg.replyTo, subject: 'Your Day One Great sign-in link',
      text: 'Here is your sign-in link. It works once, for 15 minutes, and opens a page with a Continue button:\n\n' + link
        + '\n\nIf you didn’t ask for it, ignore this email.\n' });
    const out = await cfg.transport.send({ from: cfg.from, to, raw });
    if (!out.ok) throw new Error('email not sent');
  };
}

module.exports = { signinSender };
