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
//   PR 12: the regional gate declines sign-up from the EU, EEA, UK and Switzerland before anything is stored (only a
//   daily count per country). It decides only after the provider or the emailed link has confirmed who the person
//   is, so whether an account exists is never told to anyone else: a new person is declined, and a member who lives
//   elsewhere sees a confirmation page (/auth/region/continue or /cancel) before sign-in finishes (Aaron, Oct 16).
//   The email form carries two bot checks people never notice (a field they can't see, and a sealed time stamp from
//   /auth/form, so a form sent within a second of the page opening is turned back); a sign-up leaves JEVs's network
//   mark, and every sign-in an account check, which can promote a member to level 2 automatically.
//   PR 15: linking another sign-in method needs a fresh session (begun in the last 10 minutes, by the database clock)
//   to start, completes only for that same session, makes no new session (so a link can never make anyone fresh),
//   ends every other session of the member and tells them in-app. A method can be unlinked from /account the same way,
//   never the last one, and only a method added after the one the session signed in with (seniority: whoever holds
//   the older method wins). After the review: a link starts only from our own pages, a failed one returns to /account,
//   and a traveller's sealed confirmation is used once.
'use strict';

const launch = require('../launch');

const c = require('./crypto');
const h = require('./http');
const { ORIGIN, SESSION_DAYS, IDLE_DAYS, STATE_MINUTES } = require('./config');
const store = require('../db/signin');
const v = require('../db/validate');
const jevs = require('../db/jevs');
const region = require('./region');

const session = require('./session');
const { SESSION, isToken } = session;
const EMAIL_BROWSER = '__Host-dog_email';
// A sign-in waiting for a traveller's confirmation: sealed, 10 minutes, cleared when used. Nothing is stored for it.
const REGION = '__Host-dog_region';
const REGION_MINUTES = 10;
// A session whose member confirmed they live outside the declined regions: a keyed tag of the session, so JEVs's
// region question (J13) doesn't challenge them on every post while they travel. Cleared with the session.
const RESIDENT = jevs.RESIDENT;
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
  // There is no ceiling on all GitHub and X sign-ins together: one network could use it to lock everyone out (the
  // JEVs review, F8). The per-network limit and the providers' own limits stand.
};
// The email form must have been open at least this long (a person needs longer to type or pick an address; scripts
// send at once), and its time stamp lasts this long.
const MIN_FILL_MS = 1000;
const FORM_TTL_MS = 2 * 3600 * 1000;
const ALL = '0'.repeat(64);

function make(deps) {
  const { config, run, providers, sendEmail } = deps;
  const stateKey = config.sessionKey ? c.subkey(config.sessionKey, 'oauth state') : null;
  const formKey = config.sessionKey ? c.subkey(config.sessionKey, 'form time') : null;
  const regionKey = config.sessionKey ? c.subkey(config.sessionKey, 'region confirmation') : null;
  const keys = config.fingerprintKeys;
  // Whether an email link's address (known here only by its fingerprints) is on the preview's allow-list now.
  const previewEmailAllowed = (fps) => {
    const mine = new Set(fps);
    for (const entry of launch.allowList()) {
      if (!entry.startsWith('email:')) continue;
      if (c.fingerprints(keys, 'email', entry.slice(6)).some((f) => mine.has(f))) return true;
    }
    return false;
  };

  const limited = async (bucket, keyHash) => !(await run(ANON, (t) => store.rateLimitHit(t, { bucket, keyHash, ...LIMITS[bucket] })));
  const sessionHash = session.sessionHash;
  const current = (req) => session.current(req, run);

  // Signs in and sets a fresh session cookie. Returns the outcome so the caller can redirect. A traveller who just
  // confirmed (args.region) also gets the resident tag for this session.
  async function finish(res, ctx, args) {
    const token = c.token(32);
    const out = await run(ctx, (t) => store.signIn(t, { ...args, sessionHash: c.sha256hex(token), sessionDays: SESSION_DAYS }));
    if (!out.refused) {
      h.addCookie(res, h.cookie(SESSION, token, { maxAge: SESSION_DAYS * 86400 }));
      if (args.region && config.ipKey) h.addCookie(res, h.cookie(RESIDENT, jevs.residentTag(config.ipKey, c.sha256hex(token)), { maxAge: SESSION_DAYS * 86400 }));
    }
    return out;
  }

  // The polite refusal for a new sign-up from a declined region. Nothing is kept but one more in that country's count
  // for today; no cookie is set.
  async function countDecline(country) {
    try { await run(ANON, (t) => jevs.regionDecline(t, country)); } catch { /* the count is not worth failing the answer */ }
  }
  async function decline(res, country) {
    await countDecline(country);
    res.statusCode = 451;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag', 'noindex');
    res.end(region.page());
  }

  // Someone the provider (or the emailed link) has just confirmed, signing in from a declined region. A new person is
  // declined. A member (or a signed-in member linking another method) sees the confirmation page; what the sign-in
  // (or the link) needs waits in a sealed cookie, so nothing is stored until they press Continue.
  async function regional(res, country, args, extra) {
    if (!args.linkMember && !(await run(ANON, (t) => store.known(t, { provider: args.provider, fingerprints: args.fingerprints })))) {
      return decline(res, country);
    }
    if (!regionKey) return h.redirect(res, '/join?error=unavailable');
    // n: a random nonce, recorded as used when Continue is pressed, so a copy of this cookie works once (review F6).
    h.addCookie(res, h.cookie(REGION, c.seal(regionKey, { a: args, c: country, x: extra, n: c.token(32), e: Date.now() + REGION_MINUTES * 60000 }), { maxAge: REGION_MINUTES * 60 }));
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Robots-Tag', 'noindex');
    res.end(region.confirmPage(country));
  }

  // After a sign-in: a new account's network mark (sign-up only, so an established member's network never counts
  // against them; the JEVs review, F3) and an email link's marks, then JEVs's account check, which can promote the
  // member to level 2. A failure here never undoes the sign-in; it is logged.
  async function afterSignIn(req, out, emailToken = null, confirmed = false) {
    try {
      const f = { ...jevs.facts(req, config.ipKey), ...(confirmed ? { confirmed: true } : {}) };
      await run({ actor: out.isAdmin ? 'admin' : 'member', memberId: out.memberId }, async (t) => {
        if (emailToken) await jevs.claimMarks(t, emailToken);
        if (out.isNew && f.netHash) await jevs.mark(t, { kind: 'net', keyHash: f.netHash });
        await jevs.check(t, { action: out.isNew ? 'signup' : 'account.check', ...f });
      });
    } catch (e) {
      jevs.logFailure('after sign-in', e);
    }
  }

  // An email link asked for from a declined region (see emailStart). Only for an address with an account: within the
  // usual limits, a link without JEVs's sign-up marks. The reply is the same in every case.
  async function regionalEmail(req, res, country, email, emailFps) {
    const SAME = '/join?sent=region';
    if (!(await run(ANON, (t) => store.known(t, { provider: 'email', fingerprints: emailFps })))) {
      await countDecline(country);
      return h.redirect(res, SAME);
    }
    if (await limited('email_ip', h.ipKey(req, config.ipKey)) || await limited('email_addr', emailFps[0]) || await limited('email_all', ALL)) {
      return h.redirect(res, SAME);
    }
    let nonce = h.cookies(req)[EMAIL_BROWSER];
    if (!isToken(nonce)) nonce = c.token(32);
    h.addCookie(res, h.cookie(EMAIL_BROWSER, nonce, { maxAge: 20 * 60 }));
    const token = c.token(32);
    await run(ANON, (t) => store.emailTokenIssue(t, { tokenHash: c.sha256hex(token), emailFingerprints: emailFps, browserHash: c.sha256hex(nonce), keyVersion: keys[0].version }));
    try { await sendEmail(email, ORIGIN + '/auth/email/continue#t=' + token); } catch { /* the reply is the same either way */ }
    return h.redirect(res, SAME);
  }

  // Where a refused sign-in goes.
  const REFUSED = { banned: '/join?error=unavailable', disabled: '/join?error=disabled', taken: '/join?error=taken' };
  // Linking or unlinking from a session that didn't begin in the last 10 minutes (PR 15).
  const FRESH_METHOD = '/account?error=fresh_method';
  // A link that didn't go through returns to the account page (the member is still signed in), never /join.
  const LINK_FAILED = '/account?error=link';
  const LINK_REFUSED = { taken: '/account?error=taken_method', busy: '/account?error=busy' };

  // A link starts only from our own pages (the review, F5): the browser must say the request came from this origin,
  // and an Origin or Referer, where sent, must be ours. A plain sign-in may still start from anywhere.
  function fromOurPages(req) {
    if (req.headers['sec-fetch-site'] !== 'same-origin') return false;
    if (req.headers.origin !== undefined && req.headers.origin !== ORIGIN) return false;
    const ref = req.headers.referer;
    return ref === undefined || ref === ORIGIN || String(ref).startsWith(ORIGIN + '/');
  }

  // Whether this request still carries the very session that started a link (PR 15: not merely the same member).
  function sameSession(req, me, memberId, sessionHashSealed) {
    const now = sessionHash(req);
    return Boolean(me && now && me.memberId === memberId && c.same(now, sessionHashSealed));
  }

  // PR 15: finishes a link for the signed-in member, from the session they started it in. No session cookie is set,
  // and once a method is added every session of theirs ends, this one too (the re-review, R4): the browser is signed
  // out and sent to /join to sign in again. Verifying again a method that is already theirs keeps the session. A traveller who
  // confirmed (country) gets the resident tag for this session, as after a sign-in.
  async function completeLink(req, res, me, args, ret, country = null) {
    const hash = sessionHash(req);
    const out = await run(session.strongActorFor(me), (t) => store.link(t, { provider: args.provider,
      fingerprints: args.fingerprints, keyVersion: args.keyVersion, level: args.level, recheckAfter: args.recheckAfter || null,
      sessionHash: hash, region: country }));
    if (out.refused === 'fresh') return h.redirect(res, FRESH_METHOD);
    if (out.refused) return h.redirect(res, LINK_REFUSED[out.refused] || REFUSED[out.refused] || LINK_FAILED);
    await afterSignIn(req, { memberId: out.memberId, isAdmin: out.isAdmin, isNew: false }, null, Boolean(country));
    // A new method ended every session of the member, this one too (PR 15's re-review, R4): this browser signs in
    // again, with whichever method they like, and the join page says why.
    if (out.linked) {
      h.addCookie(res, h.clear(SESSION));
      return h.redirect(res, '/join?linked=1');
    }
    if (country && config.ipKey) h.addCookie(res, h.cookie(RESIDENT, jevs.residentTag(config.ipKey, hash), { maxAge: SESSION_DAYS * 86400 }));
    return h.redirect(res, ret || '/');
  }

  return {
    async start(req, res, provider) {
      const p = providers[provider];
      const creds = config[provider];
      if (!p || !creds) return h.redirect(res, '/join?error=unavailable');
      // From a declined region nothing is stored before the provider says who this is (not even a rate-limit count);
      // the provider's own limits stand in front of its sign-in page.
      if (!region.declined(req) && await limited('signin_ip', h.ipKey(req, config.ipKey))) return h.redirect(res, '/join?error=slow');
      const url = new URL(req.url, ORIGIN);
      // Adding a second sign-in method is only for someone already signed in, and only links after they
      // complete that provider's sign-in. A matching email address never joins two accounts.
      // PR 15: and only from a fresh session (begun in the last 10 minutes), so a stolen or forgotten session cookie
      // can't link its holder's own GitHub or X. The link is bound to this very session, sealed with the state.
      let link = null;
      if (url.searchParams.get('link') === '1') {
        const me = await current(req);
        if (!me) return h.redirect(res, '/join?error=signin');
        if (!fromOurPages(req)) return h.redirect(res, LINK_FAILED);
        if (me.fresh !== true) return h.redirect(res, FRESH_METHOD);
        link = { m: me.memberId, k: sessionHash(req) };
      }
      const state = c.token(32);
      const { verifier, challenge } = c.pkce();
      const sealed = c.seal(stateKey, { p: provider, s: state, v: verifier, r: h.returnPath(url.searchParams.get('return_to')),
        l: link ? link.m : null, k: link ? link.k : null, e: Date.now() + STATE_MINUTES * 60000 });
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
      // A link that fails at any step returns to /account (the member is still signed in there).
      const linking = Boolean(saved && saved.l);
      if (url.searchParams.has('error')) return h.redirect(res, linking ? LINK_FAILED : '/join?error=cancelled');
      const code = url.searchParams.get('code');
      if (!saved || saved.p !== provider || !(saved.e > Date.now()) || !c.same(url.searchParams.get('state'), saved.s)
          || typeof code !== 'string' || code.length < 1 || code.length > 512) {
        return h.redirect(res, linking ? LINK_FAILED : '/join?error=expired');
      }
      let who;
      try { who = await p.identify(creds, { code, verifier: saved.v }); } catch { who = null; }
      if (!who) return h.redirect(res, linking ? LINK_FAILED : '/join?error=provider');

      const args = { provider, fingerprints: c.fingerprints(keys, provider, who.accountId), keyVersion: keys[0].version,
        level: who.level, displayName: NEW_NAME, recheckAfter: who.recheckAfter };
      const country = region.declined(req);
      if (saved.l) {
        // Still the same session that started the link (PR 15), not just the same member?
        const me = await current(req);
        if (!sameSession(req, me, saved.l, saved.k)) return h.redirect(res, me ? LINK_FAILED : '/join?error=signin');
        if (country) return regional(res, country, { ...args, linkMember: saved.l, linkSession: saved.k }, { r: saved.r || null });
        return completeLink(req, res, me, args, saved.r);
      }
      if (country) return regional(res, country, args, { r: saved.r || null });
      // The go-live gate (launch.js): during the preview a new account is made only for an allow-listed account ID.
      // Existing members sign in as usual. Nothing is stored for someone turned away.
      if (!launch.mayJoin(provider, who.accountId) && !(await run(ANON, (t) => store.known(t, { provider, fingerprints: args.fingerprints })))) {
        return h.redirect(res, '/join?error=preview');
      }
      const out = await finish(res, ANON, args);
      if (out.refused) return h.redirect(res, REFUSED[out.refused] || '/join?error=unavailable');
      await afterSignIn(req, out);
      // A fresh session replaces any older one in this browser.
      const old = sessionHash(req);
      if (old) await run(ANON, (t) => store.sessionEnd(t, old));
      return h.redirect(res, saved.r || '/');
    },

    async emailStart(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/join?error=expired');
      if (!sendEmail) return h.redirect(res, '/join?error=email_off');
      const body = await h.form(req);
      // Bot checks (S6, PR 12). A field people never see must be empty: if a script filled it in, it is told the
      // link was sent and nothing is done or kept. And the form's sealed time stamp must be at least a second old.
      if (body && typeof body.website === 'string' && body.website !== '') return h.redirect(res, '/join?sent=1');
      const stamp = formKey && body && typeof body.ft === 'string' ? c.open(formKey, body.ft) : null;
      const age = stamp && stamp.k === 'join' && Number.isFinite(stamp.t) ? Date.now() - stamp.t : NaN;
      if (!(age >= 0 && age <= FORM_TTL_MS)) return h.redirect(res, '/join?error=expired');
      if (age < MIN_FILL_MS) return h.redirect(res, '/join?error=fast');
      let email;
      try {
        email = v.text('email', body && body.email, { max: 254, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ }).toLowerCase();
      } catch { return h.redirect(res, '/join?error=email'); }
      const emailFps = c.fingerprints(keys, 'email', email);
      // From a declined region, a link goes only to an address that already has an account, and the answer is the
      // same either way, so it tells nobody whether one exists. Nothing is stored for a new address but the count.
      const country = region.declined(req);
      if (country) return regionalEmail(req, res, country, email, emailFps);
      // The go-live gate (launch.js): during the preview a link goes only to an allow-listed address or an existing
      // member, and every request gets the same answer, even when it is slowed down, so the form can't be used to
      // learn who is in the preview or who has an account (the gate's review, finding 1).
      const previewing = launch.stage() === 'preview';
      const SENT = previewing ? '/join?sent=preview' : '/join?sent=1';
      if (previewing && !launch.mayJoin('email', email) && !(await run(ANON, (t) => store.known(t, { provider: 'email', fingerprints: emailFps })))) {
        return h.redirect(res, SENT);
      }
      if (await limited('email_ip', h.ipKey(req, config.ipKey)) || await limited('email_addr', emailFps[0]) || await limited('email_all', ALL)) {
        return h.redirect(res, previewing ? SENT : '/join?error=slow');
      }
      // Remembers this browser, so the link can tell whether it is opened where it was asked for.
      let nonce = h.cookies(req)[EMAIL_BROWSER];
      if (!isToken(nonce)) nonce = c.token(32);
      h.addCookie(res, h.cookie(EMAIL_BROWSER, nonce, { maxAge: 20 * 60 }));
      const token = c.token(32);
      await run(ANON, async (t) => {
        await store.emailTokenIssue(t, { tokenHash: c.sha256hex(token), emailFingerprints: emailFps, browserHash: c.sha256hex(nonce), keyVersion: keys[0].version });
        // JEVs's marks for this address (J03, J05): its domain, keyed, unless everyone uses it, and whether it is a
        // throwaway service. They wait with the link and become the member's when it is used; never the address.
        for (const m of jevs.emailMarks(email, config.ipKey)) await jevs.mark(t, { kind: m.kind, keyHash: m.keyHash, token: c.sha256hex(token) });
      });
      // The link is always built from our own address, never from the request.
      const link = ORIGIN + '/auth/email/continue#t=' + token;
      try { await sendEmail(email, link); } catch { /* the reply is the same either way */ }
      // The same answer whether or not the address has an account (no enumeration).
      return h.redirect(res, SENT);
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

    // A sealed time stamp for the email form (PR 12), fetched by /join.js when the page opens. It names no one.
    async formToken(req, res) {
      res.statusCode = formKey ? 200 : 503;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.end(JSON.stringify(formKey ? { token: c.seal(formKey, { k: 'join', t: Date.now() }) } : { error: 'Sign-in is not switched on here yet.' }));
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
      const args = { provider: 'email', fingerprints: used.emailFingerprints, keyVersion: used.keyVersion, level: 0, displayName: NEW_NAME };
      h.addCookie(res, h.clear(EMAIL_BROWSER));
      const country = region.declined(req);
      if (country) return regional(res, country, args, { et: c.sha256hex(t) });
      // The go-live gate, checked again when the link is used (the gate's review, finding 2): a link sent while the
      // site was public, or while the address was on the list, makes no new account once that has changed.
      if (launch.stage() === 'preview' && !previewEmailAllowed(used.emailFingerprints)
          && !(await run(ANON, (x) => store.known(x, { provider: 'email', fingerprints: used.emailFingerprints })))) {
        return h.redirect(res, '/join?error=preview');
      }
      const out = await finish(res, ANON, args);
      if (out.refused) return h.redirect(res, REFUSED[out.refused] || '/join?error=unavailable');
      await afterSignIn(req, out, c.sha256hex(t));
      const old = sessionHash(req);
      if (old) await run(ANON, (x) => store.sessionEnd(x, old));
      return h.redirect(res, '/');
    },

    // The traveller pressed Continue: sign-in finishes, recording only that they confirmed (when, the country, the
    // member). If the account went away meanwhile, sign-in doesn't make a new one ('region').
    async regionContinue(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/join?error=expired');
      const p = regionKey ? c.open(regionKey, h.cookies(req)[REGION]) : null;
      h.addCookie(res, h.clear(REGION));
      if (!p || !(p.e > Date.now()) || !p.a || !region.countryName(p.c)) return h.redirect(res, '/join?error=expired');
      // Used once, in the database too (review F6): a replayed copy of the cookie signs nobody in.
      if (!isToken(p.n) || !(await run(ANON, (t) => store.regionConfirmUse(t, c.sha256hex(p.n))))) return h.redirect(res, '/join?error=expired');
      if (p.a.linkMember) {
        // A link waiting for the traveller's confirmation (PR 15): the same session that started it, as at the callback.
        const me = await current(req);
        if (!sameSession(req, me, p.a.linkMember, p.a.linkSession)) return h.redirect(res, me ? LINK_FAILED : '/join?error=signin');
        return completeLink(req, res, me, p.a, (p.x && p.x.r) || null, p.c);
      }
      const out = await finish(res, ANON, { ...p.a, region: p.c });
      if (out.refused === 'region') return decline(res, p.c);
      if (out.refused) return h.redirect(res, REFUSED[out.refused] || '/join?error=unavailable');
      await afterSignIn(req, out, (p.x && p.x.et) || null, true);
      // A fresh session replaces any older one in this browser, as after any sign-in.
      const old = sessionHash(req);
      if (old) await run(ANON, (x) => store.sessionEnd(x, old));
      return h.redirect(res, (p.x && p.x.r) || '/');
    },

    // Cancel: the sealed cookie goes and nothing is stored.
    async regionCancel(req, res) {
      h.addCookie(res, h.clear(REGION));
      return h.redirect(res, '/');
    },

    async logout(req, res, everywhere) {
      if (!h.sameSite(req)) return h.redirect(res, '/');
      const hash = sessionHash(req);
      if (hash) {
        if (everywhere) {
          let me;
          try {
            me = await run(ANON, (t) => store.sessionResolve(t, hash, IDLE_DAYS, { strict: true }));
          } catch (e) {
            // Nothing ended and the cookie stays, so the member is told to try again rather than wrongly reassured.
            if (e && e.code === 'SESSION_BUSY') return h.redirect(res, '/account?error=busy');
            throw e;
          }
          if (me) await run({ actor: me.isAdmin ? 'admin' : 'member', memberId: me.memberId }, (t) => store.sessionsEndAll(t));
        }
        await run(ANON, (t) => store.sessionEnd(t, hash));
      }
      h.addCookie(res, h.clear(SESSION));
      h.addCookie(res, h.clear(RESIDENT));
      return h.redirect(res, '/');
    },

    // The account page's data (PR 8): who you are, how you sign in, how many sessions are open.
    async account(req, res) {
      const who = await current(req);
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      if (!who) { res.statusCode = 401; return res.end(JSON.stringify({ signed_in: false })); }
      const a = await run(session.actorFor(who), (t) => store.account(t));
      res.statusCode = 200;
      res.end(JSON.stringify({ signed_in: true, member_id: a.memberId, display_name: a.displayName, trust_level: a.trustLevel, joined: a.joined,
        is_admin: who.isAdmin === true, sign_ins: a.signIns.map((i) => ({ id: i.id, provider: i.provider, level: i.level, verified_at: i.verifiedAt })), sessions: a.sessions,
        deletion_review: a.deletionReview ? { since: a.deletionReview.since, disables_at: a.deletionReview.disablesAt } : null }));
    },

    async rename(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/account');
      const who = await current(req);
      if (!who) return h.redirect(res, '/join?error=signin');
      const body = await h.form(req);
      try {
        await run(session.actorFor(who), (t) => store.rename(t, body && body.name));
      } catch (e) {
        if (e instanceof v.ValidationError) return h.redirect(res, '/account?error=name');
        throw e;
      }
      return h.redirect(res, '/account?saved=name');
    },

    // F8: delete your account. A form on /account, from our own pages, signed in within the last few minutes (RK3; the
    // database decides), with the word DELETE typed in. Aaron can't delete himself here (the database refuses too).
    async deleteAccount(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/account');
      const who = await current(req);
      if (!who) return h.redirect(res, '/join?error=signin');
      const body = await h.form(req);
      if (!body || body.confirm !== 'DELETE') return h.redirect(res, '/account?error=confirm');
      if (who.isAdmin) return h.redirect(res, '/account?error=admin');
      // Signed in within the last few minutes first (RK3), so a stolen session cookie can't even start a review.
      if (who.fresh !== true) return h.redirect(res, '/account?error=fresh');
      // JEVs checks the deletion (PR 12): low risk deletes; medium risk is confirmed by that fresh sign-in; high risk
      // (or a check that couldn't finish) deletes nothing and goes to Aaron as a deletion review (Oct 16, 2026). The
      // member is told their account was flagged; if he hasn't decided in 24 hours it is disabled, never deleted.
      const d = await run(session.strongActorFor(who),
        (t) => jevs.check(t, { action: 'account.delete', ...jevs.facts(req, config.ipKey) }));
      if (jevs.blocks(d)) return h.redirect(res, '/account?error=' + (d.effect === 'challenge' ? 'fresh' : 'review'));
      const out = await run(session.strongActorFor(who), (t) => store.deleteAccount(t));
      if (out.refused === 'fresh') return h.redirect(res, '/account?error=fresh');
      if (out.refused === 'under_review') return h.redirect(res, '/account?error=review');
      if (out.refused) return h.redirect(res, '/account?error=' + (out.refused === 'not_member' ? 'admin' : 'gone'));
      h.addCookie(res, h.clear(SESSION));
      return h.redirect(res, '/join?deleted=1');
    },

    // PR 15: unlink one of your sign-in methods. A form on /account, from our own pages, signed in within the last 10
    // minutes (the database decides, by its clock); never the last method. Every other session of yours ends, and you
    // get a notice. What that method's sessions did goes with it (the second review, R1): the methods they linked, the
    // agent keys they made, and the agents they let act on their own (back to drafting).
    async unlink(req, res) {
      if (!h.sameSite(req)) return h.redirect(res, '/account');
      const who = await current(req);
      if (!who) return h.redirect(res, '/join?error=signin');
      if (who.fresh !== true) return h.redirect(res, FRESH_METHOD);
      const body = await h.form(req);
      const out = await run(session.strongActorFor(who), (t) => store.unlink(t, { identity: body && body.id, sessionHash: sessionHash(req) }));
      if (out.refused === 'fresh') return h.redirect(res, FRESH_METHOD);
      if (out.refused === 'last') return h.redirect(res, '/account?error=last_method');
      if (out.refused === 'senior') return h.redirect(res, '/account?error=senior');
      if (out.refused === 'busy') return h.redirect(res, '/account?error=busy');
      if (out.refused) return h.redirect(res, '/account?error=unlink');
      return h.redirect(res, '/account?saved=unlinked');
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

module.exports = { make, SESSION, LIMITS, MIN_FILL_MS, FORM_TTL_MS };
