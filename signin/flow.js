// The sign-in flows behind /auth/... (S5, S6, S12, SF4, F1, F10).
//   GitHub and X: /auth/<provider>/start sends the visitor to the provider with a fresh state and PKCE challenge,
//   kept in a sealed, 10-minute, single-use cookie; /auth/<provider>/callback checks both, asks the provider who the
//   person is, and signs them in.
//   Email: /auth/email/start (POST) sends a 15-minute, single-use link. Opening it shows a Continue button
//   (/auth/email/continue); only pressing it (/auth/email/finish, POST) signs in, so mail scanners that open links
//   can't use them up or sign anyone in.
//   Sessions: a fresh random token at every sign-in, kept by the browser in a __Host- cookie and by us only as a
//   SHA-256. /auth/logout and /auth/logout-all are POSTs; /auth/me says who is signed in.
'use strict';

const c = require('./crypto');
const h = require('./http');
const { ORIGIN, SESSION_DAYS, IDLE_DAYS, STATE_MINUTES } = require('./config');
const store = require('../db/signin');
const v = require('../db/validate');

const SESSION = '__Host-dog_session';
// Every token we hand out is 32 random bytes in base64url: exactly 43 of these characters.
const isToken = (s) => typeof s === 'string' && s.length === 43 && Buffer.from(s, 'base64url').toString('base64url') === s;
const stateCookie = (p) => '__Host-dog_oauth_' + p;
const ANON = { actor: 'anon' };

// Rate limits (S6): sign-in attempts per IP range, email links per IP range and per address.
const LIMITS = {
  signin_ip: { windowSeconds: 600, max: 30 },
  email_ip: { windowSeconds: 3600, max: 10 },
  email_addr: { windowSeconds: 3600, max: 5 }
};

function make(deps) {
  const { config, run, providers, sendEmail } = deps;
  const stateKey = config.sessionKey ? c.subkey(config.sessionKey, 'oauth state') : null;
  const keys = config.fingerprintKeys;

  const limited = async (bucket, keyHash) => !(await run(ANON, (t) => store.rateLimitHit(t, { bucket, keyHash, ...LIMITS[bucket] })));
  const sessionHash = (req) => {
    const tok = h.cookies(req)[SESSION];
    return isToken(tok) ? c.sha256hex(tok) : null;
  };
  async function current(req) {
    const hash = sessionHash(req);
    return hash ? run(ANON, (t) => store.sessionResolve(t, hash, IDLE_DAYS)) : null;
  }

  // Signs in and sets a fresh session cookie. Returns the outcome so the caller can redirect.
  async function finish(res, ctx, args) {
    const token = c.token(32);
    const out = await run(ctx, (t) => store.signIn(t, { ...args, sessionHash: c.sha256hex(token), sessionDays: SESSION_DAYS }));
    if (!out.refused) h.addCookie(res, h.cookie(SESSION, token, { maxAge: SESSION_DAYS * 86400 }));
    return out;
  }

  const display = (name) => {
    try { return v.text('displayName', String(name || ''), { max: 80 }); } catch { return 'New member'; }
  };

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
        level: who.level, displayName: display(who.name), recheckAfter: who.recheckAfter, linkMember: saved.l || null });
      if (out.refused === 'banned') return h.redirect(res, '/join?error=unavailable');
      if (out.refused === 'taken') return h.redirect(res, '/join?error=taken');
      // A fresh session replaces any older one in this browser.
      const old = sessionHash(req);
      if (old) await run(ANON, (t) => store.sessionEnd(t, old));
      return h.redirect(res, saved.r || '/');
    },

    async emailStart(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/join?error=expired');
      if (!sendEmail) return h.redirect(res, '/join?error=unavailable');
      const body = await h.form(req);
      let email;
      try {
        email = v.text('email', body && body.email, { max: 254, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ }).toLowerCase();
      } catch { return h.redirect(res, '/join?error=email'); }
      const emailFp = c.fingerprints(keys, 'email', email);
      if (await limited('email_ip', h.ipKey(req, config.ipKey)) || await limited('email_addr', emailFp[0])) {
        return h.redirect(res, '/join?error=slow');
      }
      const token = c.token(32);
      await run(ANON, (t) => store.emailTokenIssue(t, { tokenHash: c.sha256hex(token), emailFingerprint: emailFp[0], keyVersion: keys[0].version }));
      // The link is always built from our own address, never from the request.
      const link = ORIGIN + '/auth/email/continue?t=' + token;
      try { await sendEmail(email, link); } catch { /* the reply is the same either way */ }
      // The same answer whether or not the address has an account (no enumeration).
      return h.redirect(res, '/join?sent=1');
    },

    // Shows a button; changes nothing. Opening the link (as mail scanners do) uses nothing up.
    async emailContinue(req, res) {
      const t = new URL(req.url, ORIGIN).searchParams.get('t');
      const ok = isToken(t);
      res.statusCode = ok ? 200 : 400;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('X-Robots-Tag', 'noindex');
      res.end(page(ok
        ? '<h1>Continue signing in</h1><p>Press the button to finish signing in to Day One Great.</p>'
          + '<form method="post" action="/auth/email/finish"><input type="hidden" name="t" value="' + t + '">'
          + '<button type="submit" class="button">Continue</button></form>'
        : '<h1>This link doesn’t work</h1><p><a href="/join">Ask for a new one</a>.</p>'));
    },

    async emailFinish(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/join?error=expired');
      const body = await h.form(req);
      const t = body && body.t;
      if (!isToken(t)) return h.redirect(res, '/join?error=expired');
      const used = await run(ANON, (x) => store.emailTokenRedeem(x, c.sha256hex(t)));
      if (!used) return h.redirect(res, '/join?error=expired');
      const out = await finish(res, ANON, { provider: 'email', fingerprints: [used.emailFingerprint], keyVersion: used.keyVersion,
        level: 0, displayName: 'New member' });
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
      res.end(JSON.stringify(who ? { signed_in: true, display_name: who.displayName, trust_level: who.trustLevel } : { signed_in: false }));
    },

    current
  };
}

// The one page sign-in draws itself; everything else is on /join.
function page(inner) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    + '<meta name="robots" content="noindex"><title>Sign in · Day One Great</title><link rel="stylesheet" href="/styles.css"></head>'
    + '<body><main class="wrap signin">' + inner + '</main></body></html>';
}

module.exports = { make, SESSION, LIMITS };
