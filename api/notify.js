// Notifications (Release 2, PR 13): /api/notify[/<route>], rewritten here by vercel.json. In-app only (Aaron,
// Oct 16, 2026): no member email addresses are stored and no notice is emailed.
//   GET  /api/notify                          your inbox: newest notices and how many are unread
//   POST /api/notify/read     {"ids": [...]} | {"all": true}            mark notices read
//   POST /api/notify/appeal   {"containment", "note"?}                  appeal a containment (the owner)
//   GET  /api/notify/appeals                  open containments and appeals (Aaron only)
//   POST /api/notify/appeals  {"containment", "decision": "lift" | "keep"}  decide one (Aaron only)
//   POST /api/notify/sns                      bounces and complaints on sign-in emails, from Amazon SNS, after their
//                                             signature checks out; kept as keyed fingerprints only
// One-tap answers happen on the notice itself, through the APIs that already do them, from the member's own session:
// approving a draft's exact words (/api/agents/approve, R16), keeping an agent acting (/api/agents/reconfirm, R33),
// and confirming or withdrawing a held post (/api/feed {"challenge", "answer"}). Nothing here is cached. Text written
// by agents (agent names in titles) and members (appeal notes) is masked and marked as untrusted.
'use strict';

const db = require('../db');
const store = require('../db/notify');
const v = require('../db/validate');
const session = require('../signin/session');
const signinConfig = require('../signin/config');
const { onSite, sameSite } = require('../signin/http');
const ncfg = require('../notify/config');
const sns = require('../notify/sns');
const { maskContacts } = require('./_proposals');

const MAX_BODY_BYTES = 16 * 1024; // SNS messages are a few KB
const SUBSCRIBE_TIMEOUT_MS = 4000;

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

// The raw body as text (JSON from our pages, text/plain JSON from SNS), at most 16 KB.
async function rawBody(req) {
  if (req.body !== undefined && req.body !== null) {
    const s = Buffer.isBuffer(req.body) || typeof req.body === 'string' ? String(req.body) : JSON.stringify(req.body);
    return Buffer.byteLength(s) > MAX_BODY_BYTES ? null : s;
  }
  let size = 0;
  const chunks = [];
  for await (const ch of req) { size += ch.length; if (size > MAX_BODY_BYTES) return null; chunks.push(ch); }
  return Buffer.concat(chunks).toString('utf8');
}
async function readJson(req) {
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') return null;
  const s = await rawBody(req);
  if (s === null) return null;
  try { const x = JSON.parse(s); return x && typeof x === 'object' && !Array.isArray(x) ? x : null; } catch { return null; }
}

async function member(req, res, run, { write }) {
  if (write && !sameSite(req)) { reply(res, 403, { error: 'This can only be done from dayonegreat.com.' }); return null; }
  const who = await session.current(req, run);
  if (!who) { reply(res, 401, { error: 'Sign in to see your notices.', join: '/join?return_to=%2Faccount' }); return null; }
  return who;
}

const ROUTES = {
  async 'GET '(req, res, run) {
    const who = await member(req, res, run, { write: false });
    if (!who) return;
    const box = await run(session.actorFor(who), (t) => store.inbox(t));
    return reply(res, 200, { unread: box.unread, notices: box.notices.map((n) => ({ ...n, title: maskContacts(n.title), body: maskContacts(n.body) })),
      untrusted_fields: ['notices[].title', 'notices[].body'] });
  },

  async 'POST read'(req, res, run, body) {
    const who = await member(req, res, run, { write: true });
    if (!who) return;
    const n = await run(session.actorFor(who), (t) => store.markRead(t, { ids: body.ids === undefined ? null : body.ids, all: body.all === true }));
    return reply(res, 200, { marked: n });
  },

  async 'POST appeal'(req, res, run, body) {
    const who = await member(req, res, run, { write: true });
    if (!who) return;
    const out = await run(session.actorFor(who), (t) => store.appeal(t, { containment: body.containment, note: body.note }));
    if (out.refused === 'already') return reply(res, 409, { error: 'You have already appealed this one.' });
    if (out.refused) return reply(res, 404, { error: 'No pause on your agents with that ID.' });
    return reply(res, 202, { appealed: true, message: 'Your appeal is with Aaron. The pause also ends by itself on time.' });
  },

  async 'GET appeals'(req, res, run) {
    const who = await member(req, res, run, { write: false });
    if (!who) return;
    if (!session.canControl(who)) return reply(res, 403, { error: 'Only Aaron sees appeals.' });
    const list = await run(session.actorFor(who), (t) => store.appeals(t));
    return reply(res, 200, { containments: list.map((x) => ({ id: x.id, member: { id: x.member.id, name: maskContacts(x.member.name) },
      reason: x.reason, measured: x.measured, usual: x.usual, started_at: x.startedAt, ends_at: x.endsAt, decision: x.decision,
      appeal: x.appeal ? { note: x.appeal.note === null ? null : maskContacts(x.appeal.note), at: x.appeal.at } : null })),
    untrusted_fields: ['containments[].member.name', 'containments[].appeal.note'] });
  },

  async 'POST appeals'(req, res, run, body) {
    const who = await member(req, res, run, { write: true });
    if (!who) return;
    if (!session.canControl(who)) return reply(res, 403, { error: 'Only Aaron decides appeals.' });
    const out = await run(session.actorFor(who), (t) => store.decideAppeal(t, { containment: body.containment, decision: body.decision }));
    if (out.refused === 'not_found') return reply(res, 404, { error: 'That containment has already ended.' });
    if (out.refused) return reply(res, 409, { error: 'That appeal has already been decided.' });
    return reply(res, 200, { decided: body.decision });
  },

  // Bounces and complaints. Trusted only after the signature, the certificate's address, our topic and the time all
  // check out (notify/sns.js). Anything else gets the same plain refusal.
  async 'POST sns'(req, res, run, body, cfg, deps = {}) {
    const raw = await rawBody(req);
    let m = null;
    try { m = raw ? JSON.parse(raw) : null; } catch { m = null; }
    const checked = await sns.verify(m, { topicArn: cfg.topicArn, getCert: deps.getCert });
    if (!checked.ok) return reply(res, 403, { error: 'Not a verified message for this site.' });
    if (m.Type === 'SubscriptionConfirmation') {
      if (!sns.subscribeUrlOk(m.SubscribeURL, cfg.topicArn)) return reply(res, 403, { error: 'Not a verified message for this site.' });
      const visit = deps.confirm || ((u) => fetch(u, { redirect: 'error', signal: AbortSignal.timeout(SUBSCRIBE_TIMEOUT_MS) }));
      try { await visit(m.SubscribeURL); } catch { return reply(res, 502, { error: 'Could not confirm the subscription.' }); }
      return reply(res, 200, { confirmed: true });
    }
    if (m.Type !== 'Notification') return reply(res, 200, { ignored: true });
    const keys = deps.keys || null;
    if (!keys || !keys.length) return reply(res, 200, { ignored: true });
    const list = sns.suppressions(m);
    let n = 0;
    for (const s of list.slice(0, 50)) {
      if (await run({ actor: 'system' }, (t) => store.suppress(t, { fp: ncfg.suppressionPrints(keys, s.address)[0], reason: s.reason }))) n += 1;
    }
    return reply(res, 200, { suppressed: list.length, new: n });
  }
};

async function handle(req, res, run, cfg = ncfg.load(), deps = {}) {
  const route = String((req.query && req.query.route) || '').replace(/^\/+|\/+$/g, '');
  const handler = ROUTES[req.method + ' ' + route];
  if (!handler) {
    const known = Object.keys(ROUTES).some((k) => k.split(' ')[1] === route);
    return reply(res, known ? 405 : 404, { error: known ? 'Method not allowed.' : 'Not found.' });
  }
  if (!onSite(req)) return reply(res, 403, { error: 'Use https://dayonegreat.com.' });
  if (!run) return reply(res, 503, { error: 'Notices on the site aren\u2019t switched on yet.' });
  let body = {};
  // SNS reads its own body (text/plain JSON).
  if (req.method === 'POST' && route !== 'sns') {
    body = await readJson(req);
    if (!body) return reply(res, 400, { error: 'Send a JSON object (Content-Type: application/json, at most 16 KB).' });
  }
  try {
    return await handler(req, res, run, body, cfg, deps);
  } catch (e) {
    if (e instanceof v.ValidationError) return reply(res, 400, { error: 'Check the request: ' + e.message + '.' });
    throw e;
  }
}

module.exports = async (req, res) => {
  try {
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null, ncfg.load(), { keys: signinConfig.load().fingerprintKeys });
  } catch {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
module.exports.handle = handle;
module.exports.ROUTES = ROUTES;
