// GitHub and X sign-in (OAuth 2.0 authorization code with PKCE, S256). We ask each provider only who the person
// is, keep nothing it sends back except the level it verifies, and throw the access token away straight after.
'use strict';

const { ORIGIN } = require('./config');

const TIMEOUT_MS = 5000;
async function call(url, init = {}, ms = TIMEOUT_MS) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { ...init, signal: ctl.signal, redirect: 'error' });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { ok: r.ok, status: r.status, json, headers: r.headers };
  } finally {
    clearTimeout(timer);
  }
}
const basic = (c) => 'Basic ' + Buffer.from(encodeURIComponent(c.clientId) + ':' + encodeURIComponent(c.clientSecret)).toString('base64');

const PROVIDERS = {
  github: {
    // Each provider has its own callback address, registered exactly, so one provider's answer can't be passed off
    // as another's (the OAuth "mix-up" attack).
    redirectUri: ORIGIN + '/auth/github/callback',
    authorizeUrl(c, { state, challenge }) {
      const q = new URLSearchParams({ client_id: c.clientId, redirect_uri: this.redirectUri, scope: '', state,
        code_challenge: challenge, code_challenge_method: 'S256', allow_signup: 'true' });
      return 'https://github.com/login/oauth/authorize?' + q;
    },
    // The three steps of identifying someone, apart so the JEVs gateway can do the middle one without the client
    // secret (GATEWAY.md): Vercel swaps the code for a token (it holds the secret), the gateway asks GitHub whose
    // token it is, and Vercel revokes it afterwards. identify() still does all three in one place.
    async exchange(c, { code, verifier }) {
      const t = await call('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: c.clientId, client_secret: c.clientSecret, code, redirect_uri: this.redirectUri, code_verifier: verifier })
      });
      return t.ok && t.json && typeof t.json.access_token === 'string' ? t.json.access_token : null;
    },
    // Whose token this is, and only if our own sign-in app issued it: GitHub names the issuing app's client ID in the
    // X-OAuth-Client-Id header of every answer (checked live on Oct 23, 2026; not in GitHub's documentation). A
    // token from any other app, a personal token, or an answer without the header is refused, never guessed at.
    async whoIs(accessToken, { clientId }) {
      if (typeof accessToken !== 'string' || accessToken.length < 8 || accessToken.length > 256 || !clientId) return null;
      const u = await call('https://api.github.com/user', {
        headers: { Authorization: 'Bearer ' + accessToken, Accept: 'application/vnd.github+json', 'User-Agent': 'dayonegreat-signin', 'X-GitHub-Api-Version': '2022-11-28' }
      });
      const issuer = u.headers && typeof u.headers.get === 'function' ? u.headers.get('x-oauth-client-id') : null;
      if (!u.ok || !u.json || !Number.isSafeInteger(u.json.id) || issuer !== clientId) return null;
      return { accountId: String(u.json.id), level: 1, recheckAfter: null };
    },
    async revoke(c, accessToken) {
      await call('https://api.github.com/applications/' + encodeURIComponent(c.clientId) + '/token', {
        method: 'DELETE', headers: { Authorization: basic(c), Accept: 'application/vnd.github+json', 'User-Agent': 'dayonegreat-signin' },
        body: JSON.stringify({ access_token: accessToken })
      }, 2000).catch(() => {});
    },
    async identify(c, { code, verifier }) {
      const accessToken = await this.exchange(c, { code, verifier });
      if (!accessToken) return null;
      try {
        return await this.whoIs(accessToken, { clientId: c.clientId });
      } finally {
        await this.revoke(c, accessToken);
      }
    }
  },
  x: {
    redirectUri: ORIGIN + '/auth/x/callback',
    authorizeUrl(c, { state, challenge }) {
      const q = new URLSearchParams({ response_type: 'code', client_id: c.clientId, redirect_uri: this.redirectUri,
        scope: 'tweet.read users.read', state, code_challenge: challenge, code_challenge_method: 'S256' });
      return 'https://x.com/i/oauth2/authorize?' + q;
    },
    async identify(c, { code, verifier }) {
      const t = await call('https://api.x.com/2/oauth2/token', {
        method: 'POST',
        headers: { Authorization: basic(c), 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: this.redirectUri, code_verifier: verifier })
      });
      const accessToken = t.ok && t.json && typeof t.json.access_token === 'string' ? t.json.access_token : null;
      if (!accessToken) return null;
      try {
        // One paid read per sign-in (about $0.01 under X's pay-per-use pricing; spend cap set by Aaron).
        const u = await call('https://api.x.com/2/users/me?user.fields=verified_type', { headers: { Authorization: 'Bearer ' + accessToken } });
        const d = u.ok && u.json && u.json.data;
        if (!d || typeof d.id !== 'string' || !/^\d{1,20}$/.test(d.id)) return null;
        // Level 2 only for an X account verified as a business or government. Badges can lapse, so it is rechecked
        // at the next sign-in after 30 days.
        const two = d.verified_type === 'business' || d.verified_type === 'government';
        return { accountId: d.id, level: two ? 2 : 1,
          recheckAfter: two ? new Date(Date.now() + 30 * 86400000).toISOString() : null };
      } finally {
        await call('https://api.x.com/2/oauth2/revoke', {
          method: 'POST', headers: { Authorization: basic(c), 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token: accessToken, token_type_hint: 'access_token' })
        }, 2000).catch(() => {});
      }
    }
  }
};

module.exports = { PROVIDERS, call };
