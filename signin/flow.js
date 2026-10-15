// The sign-in flows behind /auth/... (S5, S6, S12, SF4, F1, F10).
//   GitHub and X: /auth/<provider>/start sends the visitor to the provider with a fresh state and PKCE challenge,
//   kept in a sealed, 10-minute, single-use cookie; /auth/<provider>/callback checks both, asks the provider who the
//   person is, and signs them in.
//   Email: /auth/email/start (POST) sends a 15-minute, single-use link. Its token is after the "#", so it never
//   reaches our server or its logs by opening the page. Opening it shows a Continue button
//   (/auth/email/continue); only pressing it (/auth/email/finish, POST) signs in, so mail scanners that open links
//   can't use them up or sign anyone in. A link opened in another browser than the one that asked for it asks
//   first, so nobody can quietly sign someone else into the asker's account.
//   Sessions: a fresh random token at every sign-in, kept by the browser in a __Host- cookie and by us only as a
//   SHA-256. /auth/logout and /auth/logout-all are POSTs; /auth/me says who is signed in.
'use strict';

const c = require('./crypto');
const h = require('./http');
const { ORIGIN, SESSION_DAYS, IDLE_DAYS, STATE_MINUTES } = require('./config');
const store = require('../db/signin');
const v = require('../db/validate');

const session = require('./session');
const { SESSION, isToken } = session;
const EMAIL_BROWSER = '__Host-dog_email';
const NEW_NAME = 'New member'; // names from GitHub or X are not kept (S12); members choose their own later
const stateCookie = (p) => '__Host-dog_oauth_' + p;
const ANON = { actor: 'anon' };

// Rate limits (S6): sign-in attempts per IP range, email links per IP range and per address.
const LIMITS = {
  signin_ip: { windowSeconds: 600, max: 30 },
  email_ip: { windowSeconds: 3600, max: 10 },
  email_addr: { windowSeconds: 3600, max: 5 },
  // A ceiling on all sign-in emails, so nobody can turn the form into a way to flood inboxes.
  email_all: { windowSeconds: 3600, max: 500 }
};
const ALL = '0'.repeat(64);

function make(deps) {
  const { config, run, providers, sendEmail } = deps;
  const stateKey = config.sessionKey ? c.subkey(config.sessionKey, 'oauth state') : null;
  const keys = config.fingerprintKeys;

  const limited = async (bucket, keyHash) => !(await run(ANON, (t) => store.rateLimitHit(t, { bucket, keyHash, ...LIMITS[bucket] })));
  const sessionHash = session.sessionHash;
  const current = (req) => session.current(req, run);

  // Signs in and sets a fresh session cookie. Returns the outcome so the caller can redirect.
  async function finish(res, ctx, args) {
    const token = c.token(32);
    const out = await run(ctx, (t) => store.signIn(t, { ...args, sessionHash: c.sha256hex(token), sessionDays: SESSION_DAYS }));
    if (!out.refused) h.addCookie(res, h.cookie(SESSION, token, { maxAge: SESSION_DAYS * 86400 }));
    return out;
  }

  return {
    async start(req, res, provider) {
      const p = providers[provider];
      const creds = config[provider];
      if (!p || !creds) return h.redirect(res, '/join?error=unavailable');
      if (await limited('signin_ip', h.ipKey(req, config.ipKey))) return h.redirect(res, '/join?error=slow');
      const url = new URL(req.url, ORIGIN);
      // Adding a second sign-in method is only for someone already signed in, and only links after they
      // complete that provider's sign-in. A matching email address never joins two accounts.
      let link = null;
      if (url.searchParams.get('link') === '1') {
        const me = await current(req);
        if (!me) return h.redirect(res, '/join?error=signin');
        link = me.memberId;
      }
      const state = c.token(32);
      const { verifier, challenge } = c.pkce();
      const sealed = c.seal(stateKey, { p: provider, s: state, v: verifier, r: h.returnPath(url.searchParams.get('return_to')),
        l: link, e: Date.now() + STATE_MINUTES * 60000 });
      h.addCookie(res, h.cookie(stateCookie(provider), sealed, { maxAge: STATE_MINUTES * 60 }));
      return h.redirect(res, p.authorizeUrl(creds, { state, challenge }), 302);
    },

    async callback(req, res, provider) {
      const p = providers[provider];
      const creds = config[provider];
      const url = new URL(req.url, ORIGIN);
      const saved = stateKey ? c.open(stateKey, h.cookies(req)[stateCookie(provider)]) : null;
      // Single use: the state cookie is cleared whatever happens next.
      h.addCookie(res, h.clear(stateCookie(provider)));
      if (!p || !creds) return h.redirect(res, '/join?error=unavailable');
      if (url.searchParams.has('error')) return h.redirect(res, '/join?error=cancelled');
      const code = url.searchParams.get('code');
      if (!saved || saved.p !== provider || !(saved.e > Date.now()) || !c.same(url.searchParams.get('state'), saved.s)
          || typeof code !== 'string' || code.length < 1 || code.length > 512) {
        return h.redirect(res, '/join?error=expired');
      }
      let who;
      try { who = await p.identify(creds, { code, verifier: saved.v }); } catch { who = null; }
      if (!who) return h.redirect(res, '/join?error=provider');

      let ctx = ANON;
      if (saved.l) {
        // Still the same person who started the link?
        const me = await current(req);
        if (!me || me.memberId !== saved.l) return h.redirect(res, '/join?error=signin');
        ctx = { actor: me.isAdmin ? 'admin' : 'member', memberId: me.memberId };
      }
      const out = await finish(res, ctx, { provider, fingerprints: c.fingerprints(keys, provider, who.accountId), keyVersion: keys[0].version,
        level: who.level, displayName: NEW_NAME, recheckAfter: who.recheckAfter, linkMember: saved.l || null });
      if (out.refused === 'banned') return h.redirect(res, '/join?error=unavailable');
      if (out.refused === 'taken') return h.redirect(res, '/join?error=taken');
      // A fresh session replaces any older one in this browser.
      const old = sessionHash(req);
      if (old) await run(ANON, (t) => store.sessionEnd(t, old));
      return h.redirect(res, saved.r || '/');
    },

    async emailStart(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/join?error=expired');
      if (!sendEmail) return h.redirect(res, '/join?error=email_off');
      const body = await h.form(req);
      let email;
      try {
        email = v.text('email', body && body.email, { max: 254, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ }).toLowerCase();
      } catch { return h.redirect(res, '/join?error=email'); }
      const emailFps = c.fingerprints(keys, 'email', email);
      if (await limited('email_ip', h.ipKey(req, config.ipKey)) || await limited('email_addr', emailFps[0]) || await limited('email_all', ALL)) {
        return h.redirect(res, '/join?error=slow');
      }
      // Remembers this browser, so the link can tell whether it is opened where it was asked for.
      let nonce = h.cookies(req)[EMAIL_BROWSER];
      if (!isToken(nonce)) nonce = c.token(32);
      h.addCookie(res, h.cookie(EMAIL_BROWSER, nonce, { maxAge: 20 * 60 }));
      const token = c.token(32);
      await run(ANON, (t) => store.emailTokenIssue(t, { tokenHash: c.sha256hex(token), emailFingerprints: emailFps,
        browserHash: c.sha256hex(nonce), keyVersion: keys[0].version }));
      // The link is always built from our own address, never from the request.
      const link = ORIGIN + '/auth/email/continue#t=' + token;
      try { await sendEmail(email, link); } catch { /* the reply is the same either way */ }
      // The same answer whether or not the address has an account (no enumeration).
      return h.redirect(res, '/join?sent=1');
    },

    // Shows a button; changes nothing. The token stays in the address after "#", which browsers never send, and a
    // small script (/signin.js) copies it into the form.
    async emailContinue(req, res) {
      htmlPage(res, 200, '<h1>Continue signing in</h1><p>Press the button to finish signing in to Day One Great.</p>'
        + '<form id="finish" method="post" action="/auth/email/finish"><input type="hidden" name="t" value="">'
        + '<button type="submit" class="button">Continue</button></form>'
        + '<noscript><p>This page needs JavaScript to read your link. Please turn it on, or ask for a new link from a browser that has it.</p></noscript>'
        + '<script src="/signin.js"></script>');
    },

    async emailFinish(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/join?error=expired');
      const body = await h.form(req);
      const t = body && body.t;
      if (!isToken(t)) return h.redirect(res, '/join?error=expired');
      const nonce = h.cookies(req)[EMAIL_BROWSER];
      const used = await run(ANON, (x) => store.emailTokenRedeem(x, { tokenHash: c.sha256hex(t),
        browserHash: isToken(nonce) ? c.sha256hex(nonce) : null, confirmed: body.confirm === '1' }));
      if (!used) return h.redirect(res, '/join?error=expired');
      if (used.status === 'confirm') {
        return htmlPage(res, 200, '<h1>Was this you?</h1><p>This link was asked for in a different browser or on another device. '
          + 'If you asked for it, continue. If you didn\u2019t, close this page: someone may be trying to sign you in to their account.</p>'
          + '<form method="post" action="/auth/email/finish"><input type="hidden" name="t" value="' + t + '"><input type="hidden" name="confirm" value="1">'
          + '<button type="submit" class="button">Yes, I asked for it</button></form>');
      }
      const out = await finish(res, ANON, { provider: 'email', fingerprints: used.emailFingerprints, keyVersion: used.keyVersion,
        level: 0, displayName: NEW_NAME });
      h.addCookie(res, h.clear(EMAIL_BROWSER));
      if (out.refused) return h.redirect(res, '/join?error=unavailable');
      const old = sessionHash(req);
      if (old) await run(ANON, (x) => store.sessionEnd(x, old));
      return h.redirect(res, '/');
    },

    async logout(req, res, everywhere) {
      if (!h.sameSite(req)) return h.redirect(res, '/');
      const hash = sessionHash(req);
      if (hash) {
        if (everywhere) {
          const me = await run(ANON, (t) => store.sessionResolve(t, hash, IDLE_DAYS));
          if (me) await run({ actor: me.isAdmin ? 'admin' : 'member', memberId: me.memberId }, (t) => store.sessionsEndAll(t));
        }
        await run(ANON, (t) => store.sessionEnd(t, hash));
      }
      h.addCookie(res, h.clear(SESSION));
      return h.redirect(res, '/');
    },

    async me(req, res) {
      const who = await current(req);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      // Your own member ID is shown to you (Aaron needs it once, to make himself the administrator).
      res.end(JSON.stringify(who ? { signed_in: true, member_id: who.memberId, display_name: who.displayName, trust_level: who.trustLevel } : { signed_in: false }));
    },

    current
  };
}

function htmlPage(res, status, inner) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  // Same-origin: our own form posts carry an Origin header (sameSite() needs it); nothing goes to other sites.
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Robots-Tag', 'noindex');
  res.end(page(inner));
}

// The pages sign-in draws itself; everything else is on /join.
function page(inner) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    + '<meta name="robots" content="noindex"><title>Sign in · Day One Great</title><link rel="stylesheet" href="/styles.css"></head>'
    + '<body><main class="wrap signin">' + inner + '</main></body></html>';
}

module.exports = { make, SESSION, LIMITS };
