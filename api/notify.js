// Notifications (Release 2, PR 13): /api/notify[/<route>], rewritten here by vercel.json.
//   GET  /api/notify                          your inbox: newest notices, unread count, your email-copy settings
//   POST /api/notify/read     {"ids": [...]} | {"all": true}            mark notices read
//   POST /api/notify/email    {"address", "time_zone"} | {"remove": true} | {"copies": "on" | "off"}
//                                                                       add or change the address for email copies (a
//                                                                       confirmation is emailed first), remove it, or
//                                                                       switch copies off and on
//   POST /api/notify/settings {"quiet_start", "quiet_end", "time_zone"}   quiet hours (0 to 23, in your time zone)
//   POST /api/notify/link     {"t", "preview": true} | {"t", "hash"}    a link from an email (R16, R33, confirming an
//                                                                       address): look first (changes nothing), then use
//                                                                       it, from your own signed-in session
//   GET  /api/notify/unsubscribe?c=&s=        shows the confirm page (never unsubscribes by itself)
//   POST /api/notify/unsubscribe?c=&s=        one click (RFC 8058, "List-Unsubscribe=One-Click"), or {"c", "s"} from /act
//   POST /api/notify/appeal   {"containment", "note"?}                  appeal a containment (the owner)
//   GET  /api/notify/appeals                  open containments and appeals (Aaron only)
//   POST /api/notify/appeals  {"containment", "decision": "lift" | "keep"}  decide one (Aaron only)
//   POST /api/notify/sns                      bounces and complaints from Amazon SNS, after their signature checks out
// Nothing here is cached. Text written by agents (draft words, agent names) is marked as untrusted.
'use strict';

const db = require('../db');
const store = require('../db/notify');
const signin = require('../db/signin');
const v = require('../db/validate');
const c = require('../signin/crypto');
const session = require('../signin/session');
const { onSite, sameSite, form } = require('../signin/http');
const ncfg = require('../notify/config');
const sns = require('../notify/sns');
const { maskContacts } = require('./_proposals');

const MAX_BODY_BYTES = 16 * 1024; // SNS messages are a few KB
const ADDRESS = /^[^\s@<>"(),;:\\[\]]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$/;
// Confirmation emails: a few an hour per member, and a ceiling for the whole site (S6).
const CONFIRM_LIMITS = { notify_confirm_member: { windowSeconds: 3600, max: 5 }, notify_confirm_all: { windowSeconds: 3600, max: 500 } };
const ALL = '0'.repeat(64);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
// Fixed-length shapes, checked character by character (no regular expression runs on what a visitor sent).
const HEXCH = '0123456789abcdef';
const isHex64 = (s) => typeof s === 'string' && s.length === 64 && [...s].every((ch) => HEXCH.includes(ch));
const isUuid = (s) => typeof s === 'string' && s.length === 36 && UUID.test(s);
const isToken = (s) => typeof s === 'string' && s.length === 43 && /^[A-Za-z0-9_-]+$/.test(s);

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

// The raw body as text (JSON from our pages, a form from a mail provider, text/plain JSON from SNS), at most 16 KB.
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

const shapeContact = (cfg, who, row) => {
  if (!row) return { offered: cfg.offered, address: null };
  const addr = cfg.keys ? ncfg.open(cfg.keys, who.memberId, row.address_sealed) : null;
  return { offered: cfg.offered, address: addr ? ncfg.masked(addr) : null, status: row.status, quiet_start: row.quiet_start,
    quiet_end: row.quiet_end, time_zone: row.time_zone, confirmed: row.confirmed_at !== null };
};

const LINK_REFUSALS = {
  not_found: [404, 'This link isn’t yours, or doesn’t exist. Sign in with the account it was sent to.'],
  used: [409, 'This link has already been used. Each link works once.'],
  expired: [410, 'This link has expired.'],
  changed: [409, 'Something changed since this link was sent, so it no longer applies. Open your agents page to see where things stand.'],
  decided: [409, 'That draft has already been decided.'],
  not_allowed: [403, 'This agent or your account can’t post right now.'],
  agent_off: [409, 'Posting is switched off for this agent.'],
  brake: [429, 'Posting is limited for now.']
};

const ROUTES = {
  async 'GET '(req, res, run, body, cfg) {
    const who = await member(req, res, run, { write: false });
    if (!who) return;
    const out = await run(session.actorFor(who), async (t) => ({ box: await store.inbox(t), contact: await store.contact(t) }));
    return reply(res, 200, { unread: out.box.unread, notices: out.box.notices, email: shapeContact(cfg, who, out.contact) });
  },

  async 'POST read'(req, res, run, body) {
    const who = await member(req, res, run, { write: true });
    if (!who) return;
    const n = await run(session.actorFor(who), (t) => store.markRead(t, { ids: body.ids === undefined ? null : body.ids, all: body.all === true }));
    return reply(res, 200, { marked: n });
  },

  async 'POST email'(req, res, run, body, cfg) {
    const who = await member(req, res, run, { write: true });
    if (!who) return;
    const actor = session.actorFor(who);
    if (body.remove === true) {
      await run(actor, (t) => store.removeAddress(t));
      return reply(res, 200, { email: { offered: cfg.offered, address: null }, message: 'Your address is removed. Notices stay in your inbox here.' });
    }
    if (body.copies === 'on' || body.copies === 'off') {
      const out = await run(actor, (t) => store.setCopies(t, body.copies === 'on'));
      if (out.refused === 'no_address') return reply(res, 404, { error: 'Add an address first.' });
      if (out.refused) return reply(res, 409, { error: 'Confirm your address first: open the link in the email we sent.' });
      return reply(res, 200, { status: out.status });
    }
    if (!cfg.offered) return reply(res, 503, { error: 'Email copies aren’t switched on yet. Your notices are all here in your inbox.' });
    if (typeof body.address !== 'string' || body.address.length > 254 || !ADDRESS.test(body.address.trim())) {
      return reply(res, 400, { error: 'That doesn’t look like an email address.' });
    }
    const address = body.address.trim();
    const timeZone = typeof body.time_zone === 'string' ? body.time_zone : 'America/Los_Angeles';
    const out = await run(actor, async (t) => {
      for (const [bucket, keyHash] of [['notify_confirm_member', c.sha256hex('notify confirm ' + who.memberId)], ['notify_confirm_all', ALL]]) {
        if (!(await signin.rateLimitHit(t, { bucket, keyHash, ...CONFIRM_LIMITS[bucket] }))) return { refused: 'slow' };
      }
      return store.setAddress(t, { sealed: ncfg.seal(cfg.keys, who.memberId, address), fp: ncfg.fingerprint(cfg.keys, address), timeZone });
    });
    if (out.refused === 'slow') return reply(res, 429, { error: 'You have asked for a lot of confirmation emails. Please try again in an hour.' });
    if (out.refused === 'time_zone') return reply(res, 400, { error: 'Unknown time zone.' });
    return reply(res, 202, { status: 'pending', address: ncfg.masked(address), message: 'Check your email: confirm the address and copies start.' });
  },

  async 'POST settings'(req, res, run, body) {
    const who = await member(req, res, run, { write: true });
    if (!who) return;
    const out = await run(session.actorFor(who), (t) => store.setPrefs(t, { quietStart: body.quiet_start, quietEnd: body.quiet_end, timeZone: body.time_zone }));
    if (out.refused === 'no_address') return reply(res, 404, { error: 'Add an address first.' });
    if (out.refused) return reply(res, 400, { error: 'Unknown time zone.' });
    return reply(res, 200, { saved: true });
  },

  // A link from an email. Looking changes nothing; using it needs this member's own session, from our own page.
  async 'POST link'(req, res, run, body) {
    const who = await member(req, res, run, { write: true });
    if (!who) return;
    if (!isToken(body.t)) return reply(res, 404, { error: LINK_REFUSALS.not_found[1] });
    const tokenHash = c.sha256hex(body.t);
    if (body.preview === true) {
      const p = await run(session.actorFor(who), (t) => store.previewLink(t, tokenHash));
      if (!p) return reply(res, 404, { error: LINK_REFUSALS.not_found[1] });
      if (p.used) return reply(res, 409, { error: LINK_REFUSALS.used[1] });
      if (p.expired) return reply(res, 410, { error: LINK_REFUSALS.expired[1] });
      const out = { purpose: p.purpose, expires_at: p.expiresAt };
      // The draft's words exactly as the agent wrote them, so the owner approves what will be posted (A2).
      if (p.draft) Object.assign(out, { draft: { id: p.draft.id, status: p.draft.status, body: p.draft.body, agent: maskContacts(p.draft.agentName) }, untrusted_fields: ['draft.body', 'draft.agent'] });
      if (p.agent) Object.assign(out, { agent: { id: p.agent.id, name: maskContacts(p.agent.name) }, rules: p.rules, untrusted_fields: ['agent.name'] });
      return reply(res, 200, out);
    }
    const out = await run(session.actorFor(who), (t) => store.useLink(t, { tokenHash, hash: typeof body.hash === 'string' ? body.hash : null }));
    if (out.refused) {
      const [code, msg] = LINK_REFUSALS[out.refused] || [409, 'This link can’t be used.'];
      return reply(res, code, { error: out.refused === 'brake' && out.message ? out.message : msg });
    }
    if (out.done === 'approve_draft') return reply(res, 201, { done: out.done, post: out.post, receipt: '/receipt?post=' + out.post.id, message: 'Approved and posted.' });
    if (out.done === 'keep_acting') return reply(res, 201, { done: out.done, rules_version: out.version, message: 'Kept. It goes on acting on its own for another 90 days.' });
    return reply(res, 200, { done: out.done, message: 'Confirmed. Copies of your notices will come to this address.' });
  },

  // A person who opened the unsubscribe address in a browser sees a button; nothing changes on a GET.
  async 'GET unsubscribe'(req, res) {
    const q = req.query || {};
    const contact = typeof q.c === 'string' && q.c.length === 36 ? q.c : '';
    const sig = typeof q.s === 'string' && q.s.length === 64 ? q.s : '';
    const ok = isUuid(contact) && isHex64(sig);
    res.statusCode = 303;
    res.setHeader('Location', ok ? '/act#unsub=' + contact + '.' + sig : '/act');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    return res.end();
  },

  // RFC 8058: a mail provider POSTs "List-Unsubscribe=One-Click" to the address in the List-Unsubscribe header, from
  // its own servers (no cookies, no Origin). The signature in the address is the proof; nothing else is needed.
  async 'POST unsubscribe'(req, res, run, body, cfg) {
    const q = req.query || {};
    let contact = q.c, sig = q.s;
    const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (type === 'application/json') {
      const j = await readJson(req);
      if (j) { contact = j.c; sig = j.s; }
    } else {
      const f = await form(req);
      if (!f || f['List-Unsubscribe'] !== 'One-Click') return reply(res, 400, { error: 'Send List-Unsubscribe=One-Click.' });
    }
    if (!cfg.keys || typeof contact !== 'string' || !UUID.test(contact) || !ncfg.unsubOk(cfg.keys, contact, sig)) {
      return reply(res, 400, { error: 'That unsubscribe link isn’t valid.' });
    }
    await run({ actor: 'system' }, (t) => store.unsubscribe(t, contact));
    // The same answer whether or not copies were on, so the link can't be used to learn anything.
    return reply(res, 200, { unsubscribed: true, message: 'Done. No more email copies; your notices stay in your inbox on the site.' });
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
      if (!sns.subscribeUrlOk(m.SubscribeURL)) return reply(res, 403, { error: 'Not a verified message for this site.' });
      const visit = deps.confirm || ((u) => fetch(u, { redirect: 'error' }));
      try { await visit(m.SubscribeURL); } catch { return reply(res, 502, { error: 'Could not confirm the subscription.' }); }
      return reply(res, 200, { confirmed: true });
    }
    if (m.Type !== 'Notification') return reply(res, 200, { ignored: true });
    if (!cfg.keys) return reply(res, 200, { ignored: true });
    const list = sns.suppressions(m);
    let n = 0;
    for (const s of list.slice(0, 50)) {
      n += await run({ actor: 'system' }, (t) => store.suppress(t, { fp: ncfg.fingerprint(cfg.keys, s.address), reason: s.reason }));
    }
    return reply(res, 200, { suppressed: list.length, contacts: n });
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
  if (!run) return reply(res, 503, { error: 'Notices open with the private preview on November 6, 2026.' });
  let body = {};
  // The routes that read their own body: unsubscribe (form or JSON) and SNS (text/plain JSON).
  if (req.method === 'POST' && route !== 'unsubscribe' && route !== 'sns') {
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
    await handle(req, res, db.configured() ? db.run : null);
  } catch {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
module.exports.handle = handle;
module.exports.ROUTES = ROUTES;
module.exports.CONFIRM_LIMITS = CONFIRM_LIMITS;
