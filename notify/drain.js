// The outbox drain: sends the email copies that are due, at most once each.
//   1. claim (one transaction): pick what is due, reserve each member's hour, mark the rows "sending", mint links
//   2. send: open each address (sealed, bound to its member), build the message, hand it to the transport
//   3. record (one transaction): sent, back to waiting (retry), or failed
// A crash between 2 and 3 leaves rows "sending"; the next run closes them as failed, never resent (db/notify.js).
'use strict';

const c = require('../signin/crypto');
const mime = require('./mime');
const ncfg = require('./config');
const store = require('../db/notify');
const { ORIGIN } = require('../signin/config');

const SYSTEM = { actor: 'system' };
const mint = () => { const token = c.token(32); return { token, hash: c.sha256hex(token) }; };
const quote = (s) => String(s).split(/\r?\n/).map((l) => '> ' + l).join('\n');

function compose(batch, cfg) {
  const unsubscribe = ORIGIN + '/api/notify/unsubscribe?c=' + batch.contactId + '&s=' + ncfg.unsubSig(cfg.keys, batch.contactId);
  const footer = '\n--\nDay One Great sends copies of your notices only because you asked for them. Everything here is also in your inbox at '
    + ORIGIN + '/account.\nStop these emails: ' + ORIGIN + '/act#unsub=' + batch.contactId + '.' + ncfg.unsubSig(cfg.keys, batch.contactId)
    + '\nQuiet hours and settings: ' + ORIGIN + '/account\n';
  if (batch.purpose === 'confirm_email') {
    const item = batch.items[0];
    if (!item) return null;
    return { subject: 'Confirm email copies from Day One Great', unsubscribe,
      text: 'Someone signed in to a Day One Great account asked for copies of its notices to be sent to this address.\n\n'
        + 'If it was you, confirm here (you will be asked to press a button while signed in):\n' + ORIGIN + '/act#confirm=' + item.token + '\n\n'
        + 'If it wasn’t you, ignore this email. Nothing more will be sent to this address.\n' + footer };
  }
  const parts = batch.items.map((i) => {
    let s = i.title + '\n' + (i.body ? i.body + '\n' : '');
    if (i.approve) {
      s += '\n' + i.approve.agentName + ' wrote, word for word:\n\n' + quote(i.approve.words) + '\n\n'
        + 'To approve exactly these words, open this link and press Approve while signed in:\n' + ORIGIN + '/act#approve=' + i.approve.token + '\n';
    } else if (i.decided) {
      s += '(Already decided, or expired.)\n';
    }
    if (i.keep) s += '\nTo keep it acting on its own, open this link and press the button while signed in:\n' + ORIGIN + '/act#keep=' + i.keep.token + '\n';
    if (i.link) s += '\n' + ORIGIN + i.link + '\n';
    return s;
  });
  const subject = batch.items.length === 1 ? batch.items[0].title : 'Day One Great: ' + batch.items.length + ' things for you';
  return { subject, unsubscribe, text: parts.join('\n') + footer };
}

// One run. Returns counts for the cron log (no addresses, no words).
async function drain({ run, cfg, limit = 200, now = () => new Date() }) {
  if (!cfg.keys || !cfg.transport) return { off: true };
  const claimed = await run(SYSTEM, (t) => store.claim(t, { limit, mint }));
  if (claimed.busy) return { busy: true };
  const outcomes = [];
  for (const b of claimed.batches) {
    const address = ncfg.open(cfg.keys, b.memberId, b.sealed);
    const msg = compose(b, cfg);
    if (!address || !msg) { outcomes.push({ batchId: b.batchId, ok: false, retry: false, error: address ? 'nothing_to_send' : 'address_unreadable', attempts: b.attempts, purpose: b.purpose, contactId: b.contactId }); continue; }
    let out;
    try {
      const raw = mime.build({ from: cfg.from, to: address, replyTo: cfg.replyTo, subject: msg.subject, text: msg.text, unsubscribe: msg.unsubscribe, date: now() });
      out = await cfg.transport.send({ from: cfg.from, to: address, raw });
    } catch (e) {
      out = { ok: false, retry: false, error: 'build_failed' };
    }
    outcomes.push({ batchId: b.batchId, attempts: b.attempts, purpose: b.purpose, contactId: b.contactId, ...out });
  }
  if (outcomes.length) await run(SYSTEM, (t) => store.finish(t, outcomes));
  return { reaped: claimed.reaped, batches: claimed.batches.length, sent: outcomes.filter((o) => o.ok).length,
    retry: outcomes.filter((o) => !o.ok && o.retry).length, failed: outcomes.filter((o) => !o.ok && !o.retry).length };
}

// A sign-in email (email links, PR 2) through the same transport, straight away. Only with SES: the log transport
// would swallow the link, so email sign-in stays off until real email is on.
function signinSender(cfg) {
  if (!cfg.transport || cfg.transport.name !== 'ses') return null;
  return async (to, link) => {
    const raw = mime.build({ from: cfg.from, to, replyTo: cfg.replyTo, subject: 'Your Day One Great sign-in link',
      text: 'Here is your sign-in link. It works once, for 15 minutes, and opens a page with a Continue button:\n\n' + link
        + '\n\nIf you didn’t ask for it, ignore this email.\n' });
    const out = await cfg.transport.send({ from: cfg.from, to, raw });
    if (!out.ok) throw new Error('email not sent');
  };
}

module.exports = { drain, compose, signinSender, mint };
