// Sign-in as the JEVs gateway serves it (GATEWAY.md): the same flow as api/auth.js (signin/flow.js), wired without
// passkeys or email links, which phase 1 doesn't offer, so the gateway carries neither their code nor their
// dependencies. GitHub's start and callback stay on Vercel; complete is the gateway's half of the callback.
'use strict';

const config = require('../signin/config');
const { PROVIDERS } = require('../signin/providers');
const { make } = require('../signin/flow');
const { onSite } = require('../signin/http');
const db = require('../db');

const ROUTES = {
  'POST github/complete': (f, q, s) => f.complete(q, s, 'github'),
  'POST logout': (f, q, s) => f.logout(q, s, false),
  'POST logout-all': (f, q, s) => f.logout(q, s, true),
  'GET me': (f, q, s) => f.me(q, s),
  'GET account': (f, q, s) => f.account(q, s),
  'POST account/name': (f, q, s) => f.rename(q, s)
};

let flow;
function get() {
  if (!flow) {
    const cfg = config.load();
    flow = cfg.ready && db.configured() ? make({ config: cfg, run: db.run, providers: PROVIDERS, sendEmail: null }) : null;
  }
  return flow;
}

function plain(res, status, text) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(text);
}

async function handle(req, res, route) {
  const handler = ROUTES[req.method + ' ' + route];
  if (!handler) {
    const known = Object.keys(ROUTES).some((k) => k.endsWith(' ' + route));
    return plain(res, known ? 405 : 404, known ? 'Method not allowed' : 'Not found');
  }
  const f = get();
  if (!f || !onSite(req)) return plain(res, 503, 'Sign-in is not switched on here yet.');
  try {
    await handler(f, req, res);
  } catch {
    if (!res.headersSent) plain(res, 500, 'Something went wrong. Please try again.');
  }
}

module.exports = { handle, ROUTES };
