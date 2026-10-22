// Sign-in for Release 2: /auth/<route>, rewritten here by vercel.json. Its writes are all same-site form POSTs:
// starting an email link, finishing one, logging out, and (PR 8) renaming yourself or deleting your account. Sign-up
// steps decline the EU, EEA, UK and Switzerland before anything is stored, and a member travelling there confirms
// where they live before signing in (PR 12, in signin/flow.js). PR 15 adds unlinking a sign-in method.
// Off unless every production setting is present and the request is for dayonegreat.com itself.
'use strict';

const config = require('../signin/config');
const { PROVIDERS } = require('../signin/providers');
const { make } = require('../signin/flow');
const db = require('../db');
const notifyConfig = require('../notify/config');
const { signinSender } = require('../notify/sender');
const passkey = require('../signin/passkey');

// The passkey handlers under the names the routes below call.
const passkeyRoutes = (p) => ({ passkeyList: p.list, passkeyEnrolOptions: p.enrolOptions, passkeyEnrolFinish: p.enrolFinish,
  passkeyAssertOptions: p.assertOptions, passkeyAssertFinish: p.assertFinish, passkeyRemove: p.remove,
  passkeyRecoveryStart: p.recoveryStart, passkeyRecoveryCancel: p.recoveryCancel });

let flow;
function get() {
  if (!flow) {
    const cfg = config.load();
    // PR 13: email links go out through Amazon SES once Aaron switches it on (EMAIL-SETUP.md), skipping addresses that
    // bounced or complained; until then they stay off.
    const sendEmail = db.configured() ? signinSender(notifyConfig.load(), { run: db.run, keys: cfg.fingerprintKeys }) : null;
    flow = cfg.ready && db.configured() ? make({ config: cfg, run: db.run, providers: PROVIDERS, sendEmail }) : null;
    // PR 17: passkeys, the step-up risky grants need (D5), under the same switch as sign-in.
    if (flow) Object.assign(flow, passkeyRoutes(passkey.make({ run: db.run })));
  }
  return flow;
}

const ROUTES = {
  'GET github/start': (f, q, s) => f.start(q, s, 'github'),
  'GET github/callback': (f, q, s) => f.callback(q, s, 'github'),
  'GET x/start': (f, q, s) => f.start(q, s, 'x'),
  'GET x/callback': (f, q, s) => f.callback(q, s, 'x'),
  'POST email/start': (f, q, s) => f.emailStart(q, s),
  'GET email/continue': (f, q, s) => f.emailContinue(q, s),
  'POST email/finish': (f, q, s) => f.emailFinish(q, s),
  'POST logout': (f, q, s) => f.logout(q, s, false),
  'POST logout-all': (f, q, s) => f.logout(q, s, true),
  'GET me': (f, q, s) => f.me(q, s),
  // PR 8: your account (F8).
  'GET account': (f, q, s) => f.account(q, s),
  'POST account/name': (f, q, s) => f.rename(q, s),
  'POST account/delete': (f, q, s) => f.deleteAccount(q, s),
  // PR 15: unlink one of your sign-in methods (a fresh session, never the last one).
  'POST account/unlink': (f, q, s) => f.unlink(q, s),
  // PR 12: the email form's sealed time stamp (a bot check), and a traveller's confirmation before signing in from
  // a region where we don't sign people up (Continue finishes signing in; Cancel stores nothing).
  'GET form': (f, q, s) => f.formToken(q, s),
  'POST region/continue': (f, q, s) => f.regionContinue(q, s),
  'POST region/cancel': (f, q, s) => f.regionCancel(q, s),
  // PR 17: passkeys (signin/passkey.js). JSON posts from our own pages; adding one needs a fresh sign-in, and a
  // second one (or removing one) needs a passkey check too.
  'GET passkey/list': (f, q, s) => f.passkeyList(q, s),
  'POST passkey/enrol/options': (f, q, s) => f.passkeyEnrolOptions(q, s),
  'POST passkey/enrol/finish': (f, q, s) => f.passkeyEnrolFinish(q, s),
  'POST passkey/assert/options': (f, q, s) => f.passkeyAssertOptions(q, s),
  'POST passkey/assert/finish': (f, q, s) => f.passkeyAssertFinish(q, s),
  'POST passkey/remove': (f, q, s) => f.passkeyRemove(q, s),
  'POST passkey/recovery/start': (f, q, s) => f.passkeyRecoveryStart(q, s),
  'POST passkey/recovery/cancel': (f, q, s) => f.passkeyRecoveryCancel(q, s)
};

function plain(res, status, text) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(text);
}

module.exports = async (req, res) => {
  const route = String((req.query && req.query.route) || '').replace(/^\/+|\/+$/g, '');
  const handler = ROUTES[req.method + ' ' + route];
  if (!handler) {
    const known = Object.keys(ROUTES).some((k) => k.endsWith(' ' + route));
    return plain(res, known ? 405 : 404, known ? 'Method not allowed' : 'Not found');
  }
  const { onSite } = require('../signin/http');
  const f = get();
  if (!f || !onSite(req)) return plain(res, 503, 'Sign-in is not switched on here yet.');
  try {
    await handler(f, req, res);
  } catch {
    // Never show internal errors; the audit log and Vercel's logs have what we need.
    if (!res.headersSent) plain(res, 500, 'Something went wrong. Please try again.');
  }
};

module.exports.ROUTES = ROUTES;
