// Passkeys (PR 17): the proof that riskier grants need (requirement D5). GitHub and X can't make someone sign in again
// on demand (GitHub offers only select_account), so a WebAuthn passkey, with user verification, is the step-up.
//   POST /auth/passkey/enrol/options   a challenge to add a passkey (a fresh sign-in: the last 10 minutes)
//   POST /auth/passkey/enrol/finish    {response, label}  checks it and adds the passkey
//   POST /auth/passkey/assert/options  a challenge to confirm it's you
//   POST /auth/passkey/assert/finish   {response}  checks it; this session counts as stepped up for 5 minutes
//   POST /auth/passkey/remove          {id}  removes one (needs a step-up; never the last one)
//   POST /auth/passkey/recovery/start  lost every passkey: a 72-hour cool-off, then a new one can be added, which removes
//                                      every earlier one and signs out every other session
//   POST /auth/passkey/recovery/cancel from a session signed in with the method that started it, or an older one
//   GET  /auth/passkey/list            your passkeys (labels and dates only), any recovery, and this session's state
// Every write is a JSON POST from our own pages (Origin and Sec-Fetch-Site), for the signed-in member's own session.
// Challenges are random 32 bytes; only their SHA-256 is stored, for 2 minutes, bound to this session, used once. The
// signature, origin, RP ID and user verification are checked here with @simplewebauthn/server (pinned, 14.0.3); the
// database then uses the challenge up, checks the credential is the member's own and that its counter moved forward,
// and records the step-up by its own clock. Nothing private is ever stored: a passkey's private key, and any
// fingerprint or face check, stay on the person's device.
'use strict';

const swa = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');
const c = require('./crypto');
const h = require('./http');
const session = require('./session');
const { ORIGIN, HOST } = require('./config');
const store = require('../db/passkeys');
const v = require('../db/validate');

const RP_NAME = 'Day One Great';
// ES256, EdDSA and RS256: what passkey providers use today (Apple, Google and Microsoft use ES256).
const ALGORITHMS = [-7, -8, -257];
const TIMEOUT_MS = 2 * 60 * 1000; // the challenge lives 2 minutes in the database too
const MAX_BODY = 16 * 1024;
const REAUTH = '/join?return_to=%2Faccount';

// Where passkeys are valid. The RP ID is dayonegreat.com and the only origin https://dayonegreat.com, unless Aaron sets
// both for a preview (PASSKEY_RP_ID and PASSKEY_ORIGINS, comma-separated exact https origins). WebAuthn only accepts an
// origin whose host is the RP ID or under it, so a preview on *.vercel.app needs its own RP ID (its own host); no
// wildcard is ever accepted. Anything malformed switches passkeys off rather than widening them.
function relyingParty(env = process.env) {
  const rpID = env.PASSKEY_RP_ID ? String(env.PASSKEY_RP_ID).trim().toLowerCase() : HOST;
  const list = env.PASSKEY_ORIGINS ? String(env.PASSKEY_ORIGINS).split(',').map((s) => s.trim()).filter(Boolean) : [ORIGIN];
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(rpID)) return null;
  if (!list.length || list.length > 5) return null;
  for (const o of list) {
    let u;
    try { u = new URL(o); } catch { return null; }
    if (u.protocol !== 'https:' || u.origin !== o || u.port !== '' || o.includes('*')) return null;
    if (u.hostname !== rpID && !u.hostname.endsWith('.' + rpID)) return null;
  }
  return { rpID, origins: list };
}

function reply(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

// A JSON object of at most 16 KB (an attestation is a few KB at most), whether or not Vercel has parsed it already.
async function json(req) {
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') return null;
  let raw;
  if (req.body !== undefined && req.body !== null) {
    raw = Buffer.isBuffer(req.body) || typeof req.body === 'string' ? String(req.body) : JSON.stringify(req.body);
  } else {
    let size = 0;
    const chunks = [];
    for await (const ch of req) { size += ch.length; if (size > MAX_BODY) return null; chunks.push(ch); }
    raw = Buffer.concat(chunks).toString('utf8');
  }
  if (Buffer.byteLength(raw) > MAX_BODY) return null;
  try { const o = JSON.parse(raw); return o && typeof o === 'object' && !Array.isArray(o) ? o : null; } catch { return null; }
}

// The challenge a browser's answer carries (from its clientDataJSON), as the SHA-256 we stored, or null.
function answeredChallengeHash(response) {
  try {
    const cd = JSON.parse(Buffer.from(String(response.response.clientDataJSON), 'base64url').toString('utf8'));
    return typeof cd.challenge === 'string' && /^[A-Za-z0-9_-]{43}$/.test(cd.challenge) ? c.sha256hex(cd.challenge) : null;
  } catch {
    return null;
  }
}
const isAnswer = (r) => Boolean(r && typeof r === 'object' && typeof r.id === 'string' && /^[A-Za-z0-9_-]{16,1366}$/.test(r.id)
  && r.type === 'public-key' && r.response && typeof r.response === 'object' && typeof r.response.clientDataJSON === 'string');

const ENROL_REFUSED = {
  session: [401, 'Sign in again, then add your passkey.'],
  challenge: [409, 'That took too long or was already used. Please try again.'],
  not_active: [403, 'This account can’t add a passkey right now.'],
  fresh: [403, 'To add a passkey, sign in again first, then add it within 10 minutes.'],
  signin_again: [403, 'Please sign in again first: this session started before passkeys existed.'],
  cool_off: [403, 'Passkey recovery is under way: a new passkey can be added once the 72-hour wait is over.'],
  bad_id: [400, 'That passkey’s ID is too long or doesn’t match what the device said.'],
  step_up: [403, 'You already have a passkey, so confirm with it first. Lost it? Start passkey recovery on this page.'],
  too_many: [409, 'You have the most passkeys an account can have (10). Remove one first.'],
  taken: [409, 'That passkey is already registered.']
};
const ASSERT_REFUSED = {
  session: [401, 'Sign in again, then confirm it’s you.'],
  challenge: [409, 'That took too long or was already used. Please try again.'],
  unknown: [403, 'That passkey isn’t one of yours on this account.'],
  recovery: [403, 'Passkey recovery is under way, so risky steps are blocked until it ends or you cancel it.'],
  counter: [403, 'That passkey’s check was refused: it may have been copied. Remove it on your account page and add a new one.']
};
const REMOVE_REFUSED = {
  session: [401, 'Sign in again first.'],
  recovery: [403, 'Passkey recovery is under way; cancel it first, or wait until it ends.'],
  not_found: [404, 'No passkey of yours with that ID.'],
  last: [409, 'This is your only passkey. Add another first, then remove this one, so your account is never left without one.'],
  senior: [403, 'From this session you can remove only a passkey added with the sign-in method you used, or one added after it. Sign in with your oldest method to remove this one.']
};

function make({ run, rp = relyingParty() }) {
  // A signed-in member, writing from our own pages.
  async function member(req, res, { write = true } = {}) {
    if (write && !h.sameSite(req)) { reply(res, 403, { error: 'This can only be done from dayonegreat.com.' }); return null; }
    if (!rp) { reply(res, 503, { error: 'Passkeys are not switched on here.' }); return null; }
    const who = await session.current(req, run);
    if (!who) { reply(res, 401, { error: 'Sign in first.', join: REAUTH }); return null; }
    return who;
  }
  // A new challenge, stored as its SHA-256 for this session.
  async function newChallenge(req, who, purpose) {
    const challenge = c.token(32);
    const out = await run(session.actorFor(who), (t) => store.challenge(t, { sessionHash: session.sessionHash(req), purpose, challengeHash: c.sha256hex(challenge) }));
    return out.refused ? { refused: out.refused } : { challenge };
  }
  const drop = (req, who, challengeHash) => (challengeHash
    ? run(session.actorFor(who), (t) => store.dropChallenge(t, { sessionHash: session.sessionHash(req), challengeHash })).catch(() => false) : false);

  return {
    relyingParty: rp,

    async list(req, res) {
      const who = await member(req, res, { write: false });
      if (!who) return;
      const out = await run(session.actorFor(who), async (t) => ({ keys: await store.mine(t), recovery: await store.recovery(t) }));
      return reply(res, 200, {
        // method: the sign-in method it was added under, so the page knows which unlinks need a passkey check.
        passkeys: out.keys.map((k) => ({ id: k.id, label: k.label, created_at: k.createdAt, last_used_at: k.lastUsedAt, synced: k.backedUp, method: k.identityId })),
        recovery: out.recovery ? { started_at: out.recovery.startedAt, ends_at: out.recovery.endsAt } : null,
        stepped_up: who.stepUp === true, fresh: who.fresh === true, max: store.MAX_PASSKEYS,
        linking_from: who.linkingFrom ? new Date(who.linkingFrom).toISOString() : null,
        untrusted_fields: ['passkeys[].label']
      });
    },

    async enrolOptions(req, res) {
      const who = await member(req, res);
      if (!who) return;
      if (who.fresh !== true) return reply(res, 403, { error: ENROL_REFUSED.fresh[1], reauth: REAUTH });
      const ch = await newChallenge(req, who, 'enrol');
      if (ch.refused === 'fresh') return reply(res, 403, { error: ENROL_REFUSED.fresh[1], reauth: REAUTH });
      if (ch.refused) return reply(res, 429, { error: 'Too many passkey requests at once. Please wait a minute.' });
      const existing = await run(session.actorFor(who), (t) => store.mine(t));
      const options = await swa.generateRegistrationOptions({
        rpName: RP_NAME, rpID: rp.rpID,
        // The member's ID as the passkey's user handle: stable and meaningless outside this site. The name shown in the
        // device's passkey list is the member's own chosen name.
        userID: Buffer.from(who.memberId.replace(/-/g, ''), 'hex'), userName: who.displayName || 'Day One Great member',
        challenge: Buffer.from(ch.challenge, 'base64url'), timeout: TIMEOUT_MS, attestationType: 'none',
        excludeCredentials: existing.map((k) => ({ id: k.credentialId, transports: k.transports })),
        // Discoverable keys preferred, not required; user verification (a PIN, fingerprint or face, on the device) required.
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        supportedAlgorithmIDs: ALGORITHMS
      });
      return reply(res, 200, { options });
    },

    async enrolFinish(req, res) {
      const who = await member(req, res);
      if (!who) return;
      const body = await json(req);
      if (!body || !isAnswer(body.response)) return reply(res, 400, { error: 'Send {"response": <the browser’s answer>, "label": "a name for this passkey"}.' });
      let label;
      try { label = v.text('label', body.label === undefined || body.label === '' ? 'Passkey' : body.label, { max: 60 }); } catch { return reply(res, 400, { error: 'A label is 1 to 60 characters on one line.' }); }
      const hash = answeredChallengeHash(body.response);
      if (!hash) return reply(res, 400, { error: 'That answer doesn’t carry one of our challenges.' });
      let info;
      try {
        const out = await swa.verifyRegistrationResponse({ response: body.response, expectedChallenge: (x) => c.same(c.sha256hex(x), hash),
          expectedOrigin: rp.origins, expectedRPID: rp.rpID, requireUserVerification: true, supportedAlgorithmIDs: ALGORITHMS });
        info = out.verified ? out.registrationInfo : null;
      } catch { info = null; }
      if (!info || info.userVerified !== true) {
        await drop(req, who, hash);
        return reply(res, 400, { error: 'That passkey couldn’t be checked (wrong site, no verification on the device, or a broken answer). Please try again.' });
      }
      // The credential ID the device attested: at most 1023 bytes (the WebAuthn limit, and what the database holds), and
      // the same as the ID the browser sent alongside it (the review, finding 5). Otherwise refused, and the challenge used up.
      const credId = info.credential.id;
      if (typeof credId !== 'string' || !/^[A-Za-z0-9_-]{16,1364}$/.test(credId) || Buffer.from(credId, 'base64url').length > 1023
          || credId !== body.response.id) {
        await drop(req, who, hash);
        return reply(res, ENROL_REFUSED.bad_id[0], { error: ENROL_REFUSED.bad_id[1] });
      }
      const out = await run(session.actorFor(who), (t) => store.enrol(t, { sessionHash: session.sessionHash(req), challengeHash: hash,
        credentialId: info.credential.id, publicKey: isoBase64URL.fromBuffer(info.credential.publicKey), signCount: info.credential.counter,
        transports: info.credential.transports || body.response.response.transports, label, backedUp: info.credentialBackedUp === true }));
      if (out.refused) {
        const [code, error] = ENROL_REFUSED[out.refused] || [409, 'That passkey wasn’t added.'];
        return reply(res, code, { error, ...(out.refused === 'fresh' || out.refused === 'signin_again' ? { reauth: REAUTH } : {}),
          ...(out.refused === 'step_up' ? { step_up: session.stepUpNeeded(who).step_up } : {}) });
      }
      return reply(res, 201, { passkey: out.passkeyId, recovery_completed: out.recoveryCompleted,
        message: out.recoveryCompleted ? 'Added. Passkey recovery is complete.' : 'Added. You’ll use it to confirm risky steps.' });
    },

    async assertOptions(req, res) {
      const who = await member(req, res);
      if (!who) return;
      if (who.recoveryUntil || !(who.passkeys > 0)) return reply(res, 403, session.stepUpNeeded(who));
      const keys = await run(session.actorFor(who), (t) => store.mine(t));
      const ch = await newChallenge(req, who, 'step_up');
      if (ch.refused) return reply(res, ch.refused === 'session' ? 401 : 429, { error: ch.refused === 'session' ? 'Sign in first.' : 'Too many passkey requests at once. Please wait a minute.' });
      const options = await swa.generateAuthenticationOptions({ rpID: rp.rpID, challenge: Buffer.from(ch.challenge, 'base64url'), timeout: TIMEOUT_MS,
        userVerification: 'required', allowCredentials: keys.map((k) => ({ id: k.credentialId, transports: k.transports })) });
      return reply(res, 200, { options });
    },

    async assertFinish(req, res) {
      const who = await member(req, res);
      if (!who) return;
      const body = await json(req);
      if (!body || !isAnswer(body.response)) return reply(res, 400, { error: 'Send {"response": <the browser’s answer>}.' });
      const hash = answeredChallengeHash(body.response);
      if (!hash) return reply(res, 400, { error: 'That answer doesn’t carry one of our challenges.' });
      const keys = await run(session.actorFor(who), (t) => store.mine(t, { keys: true }));
      const key = keys.find((k) => k.credentialId === body.response.id);
      let info = null;
      if (key) {
        try {
          // The stored counter is given as 0 on purpose: the database compares counters itself, under the passkey's row
          // lock, and records a counter that went backwards (a copied key) before refusing it.
          const out = await swa.verifyAuthenticationResponse({ response: body.response, expectedChallenge: (x) => c.same(c.sha256hex(x), hash),
            expectedOrigin: rp.origins, expectedRPID: rp.rpID, requireUserVerification: true,
            credential: { id: key.credentialId, publicKey: isoBase64URL.toBuffer(key.publicKey), counter: 0, transports: key.transports } });
          info = out.verified && out.authenticationInfo.userVerified === true ? out.authenticationInfo : null;
        } catch { info = null; }
      }
      if (!info) {
        await drop(req, who, hash);
        return reply(res, 403, { error: key ? 'That passkey check didn’t go through (wrong site, no verification on the device, or a broken answer). Please try again.'
          : ASSERT_REFUSED.unknown[1] });
      }
      const out = await run(session.actorFor(who), (t) => store.assert(t, { sessionHash: session.sessionHash(req), challengeHash: hash,
        credentialId: key.credentialId, signCount: info.newCounter, backedUp: info.credentialBackedUp === true }));
      if (out.refused) {
        const [code, error] = ASSERT_REFUSED[out.refused] || [403, 'That passkey check didn’t go through.'];
        return reply(res, code, { error });
      }
      return reply(res, 200, { stepped_up_until: out.until, message: 'Confirmed. Risky steps are open for 5 minutes.' });
    },

    async remove(req, res) {
      const who = await member(req, res);
      if (!who) return;
      const body = await json(req);
      if (!body || typeof body.id !== 'string') return reply(res, 400, { error: 'Send {"id": "<passkey id>"}.' });
      const status = await run(session.actorFor(who), (t) => store.remove(t, { sessionHash: session.sessionHash(req), passkey: body.id }));
      if (status === 'step_up') return reply(res, 403, session.stepUpNeeded(who));
      if (status !== 'ok') { const [code, error] = REMOVE_REFUSED[status] || [409, 'Nothing was removed.']; return reply(res, code, { error }); }
      return reply(res, 200, { removed: body.id, message: 'Removed. It can no longer confirm anything on your account.' });
    },

    async recoveryStart(req, res) {
      const who = await member(req, res);
      if (!who) return;
      if (who.fresh !== true) return reply(res, 403, { error: 'To start passkey recovery, sign in again first, then start it within 10 minutes.', reauth: REAUTH });
      const out = await run(session.actorFor(who), (t) => store.recoveryStart(t, { sessionHash: session.sessionHash(req) }));
      if (out.refused === 'fresh') return reply(res, 403, { error: 'To start passkey recovery, sign in again first, then start it within 10 minutes.', reauth: REAUTH });
      if (out.refused === 'open') return reply(res, 409, { error: 'Passkey recovery is already under way.' });
      if (out.refused === 'no_passkeys') return reply(res, 409, { error: 'You have no passkey to recover: add one instead, straight away.' });
      if (out.refused === 'signin_again') return reply(res, 403, { error: 'Please sign in again first: this session started before passkeys existed.', reauth: REAUTH });
      if (out.refused) return reply(res, 403, { error: 'Passkey recovery can’t be started on this account right now.' });
      return reply(res, 201, { recovery: { ends_at: out.endsAt },
        message: 'Recovery started. Risky steps are blocked until ' + new Date(out.endsAt).toISOString() + '; then you can add a new passkey. Any session of yours can cancel it.' });
    },

    async recoveryCancel(req, res) {
      const who = await member(req, res);
      if (!who) return;
      const status = await run(session.actorFor(who), (t) => store.recoveryCancel(t, { sessionHash: session.sessionHash(req) }));
      if (status === 'none') return reply(res, 404, { error: 'No passkey recovery is under way.' });
      if (status === 'senior') {
        return reply(res, 403, { error: 'This session signed in with a sign-in method added after the one that started the recovery, so it can’t cancel it. Sign in with your oldest method to cancel it.' });
      }
      if (status !== 'ok') return reply(res, 401, { error: 'Sign in first.' });
      return reply(res, 200, { cancelled: true, message: 'Cancelled. Your passkeys work as before.' });
    }
  };
}

module.exports = { make, relyingParty, answeredChallengeHash, ALGORITHMS, TIMEOUT_MS };
