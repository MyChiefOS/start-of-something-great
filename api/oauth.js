// OAuth 2.1 for agents (069; Aaron, Nov 22, 2026: "an agent card, a poster rating, OAuth ... without needing me to take
// any action but approving the PR"). An AI app (Claude, ChatGPT, an open-model client) registers itself, sends its
// person to /oauth/authorize, and the person, signed in here, approves it: that makes a new agent of theirs through the
// site's own agent creation (POST /api/agents, with JEVs, the level-2 rule and a fresh sign-in to act alone), and the
// agent's key becomes the app's access token. Every acting route already checks that key, and the owner revokes it on
// /account/agents like any agent. Public clients with PKCE (S256) only; no client secrets; no refresh tokens (the key
// lasts until revoked).
//
//   GET  /.well-known/oauth-authorization-server   RFC 8414 metadata        (rewritten to ?route=as)
//   GET  /.well-known/oauth-protected-resource     RFC 9728 metadata, /mcp   (rewritten to ?route=pr)
//   POST /oauth/register   {client_name, redirect_uris}   RFC 7591, public client  (?route=register)
//   GET  /api/oauth/client?id=                     the app's name and return addresses, for the consent page
//   POST /api/oauth/code   {client_id, redirect_uri, code_challenge, state, key}   our consent page only, signed in
//   POST /oauth/token      form: grant_type=authorization_code, code, redirect_uri, client_id, code_verifier
//
// The key is never stored readable: the code's row holds it sealed (AES-256-GCM) under SHA-256 of the code, which only
// the app receives, and only the code's own hash (with a different label) is kept.
'use strict';

const crypto = require('crypto');
const db = require('../db');
const c = require('../signin/crypto');
const config = require('../signin/config');
const session = require('../signin/session');
const agentkey = require('../signin/agentkey');
const store = require('../db/signin');
const { onSite, sameSite, ipKey } = require('../signin/http');
const { ORIGIN } = require('../signin/config');

const MAX = 8192;
const REGISTER_LIMIT = { windowSeconds: 3600, max: 20 };
const TOKEN_LIMIT = { windowSeconds: 600, max: 60 };
const B64URL43 = /^[A-Za-z0-9_-]{43}$/;
const CLIENT = /^doc_[A-Za-z0-9_-]{22}$/;

const AS_META = {
  issuer: ORIGIN,
  authorization_endpoint: ORIGIN + '/oauth/authorize',
  token_endpoint: ORIGIN + '/oauth/token',
  registration_endpoint: ORIGIN + '/oauth/register',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['none'],
  scopes_supported: ['mcp'],
  authorization_response_iss_parameter_supported: true,
  service_documentation: ORIGIN + '/connect'
};
const PR_META = {
  resource: ORIGIN + '/mcp',
  authorization_servers: [ORIGIN],
  scopes_supported: ['mcp'],
  bearer_methods_supported: ['header'],
  resource_name: 'Day One Great MCP',
  resource_documentation: ORIGIN + '/connect'
};
// RFC 8707: a resource, when sent, must be this server's MCP address. The token is an agent key, so it also works on
// the site's own acting API routes for that agent (said in the token response).
const RESOURCES = new Set([ORIGIN + '/mcp', ORIGIN + '/api/mcp', ORIGIN]);
const resourceOk = (r) => r === undefined || r === null || r === '' || RESOURCES.has(String(r).replace(/\/+$/, ''));

function reply(res, code, body, { cache = false } = {}) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', cache ? 'public, max-age=3600' : 'no-store');
  if (cache) res.setHeader('Access-Control-Allow-Origin', '*');
  res.end(JSON.stringify(body, null, 2));
}
// RFC 6749 section 5.2: { error, error_description }.
const oauthError = (res, code, error, description) => reply(res, code, { error, error_description: description });

async function readBody(req) {
  let raw;
  if (req.body !== undefined && req.body !== null) {
    raw = Buffer.isBuffer(req.body) || typeof req.body === 'string' ? String(req.body) : null;
    if (raw === null) return { type: 'object', value: req.body };
  } else {
    let size = 0;
    const chunks = [];
    for await (const ch of req) { size += ch.length; if (size > MAX) return null; chunks.push(ch); }
    raw = Buffer.concat(chunks).toString('utf8');
  }
  if (Buffer.byteLength(raw) > MAX) return null;
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type === 'application/x-www-form-urlencoded') return { type: 'form', value: Object.fromEntries(new URLSearchParams(raw)) };
  if (type === 'application/json') { try { const v = JSON.parse(raw); return v && typeof v === 'object' && !Array.isArray(v) ? { type: 'json', value: v } : null; } catch { return null; } }
  return null;
}

// The seal: AES-256-GCM under SHA-256("dog oauth seal" + code). The code's stored hash uses another label, so the
// database never holds what opens the seal.
const codeHash = (code) => c.sha256hex('dog oauth code ' + code);
const sealKey = (code) => crypto.createHash('sha256').update('dog oauth seal ' + code).digest();
function seal(code, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sealKey(code), iv);
  const body = Buffer.concat([cipher.update(key, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}
function unseal(code, buf) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', sealKey(code), buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
}
const s256 = (verifier) => crypto.createHash('sha256').update(verifier).digest('base64url');
const eq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

const str = (x, max) => (typeof x === 'string' && x.length > 0 && x.length <= max ? x : null);

const ROUTES = {
  'GET as': (req, res) => reply(res, 200, AS_META, { cache: true }),
  'GET pr': (req, res) => reply(res, 200, PR_META, { cache: true }),

  async 'POST register'(req, res, run, body, cfg) {
    const b = body.value;
    const name = str(b.client_name, 80) || 'An MCP client';
    const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris : null;
    if (!uris || !uris.length || uris.length > 5 || uris.some((u) => !str(u, 500))) {
      return oauthError(res, 400, 'invalid_redirect_uri', 'Give redirect_uris: 1 to 5 addresses, https or http on localhost.');
    }
    const id = 'doc_' + crypto.randomBytes(16).toString('base64url').slice(0, 22);
    const out = await run({ actor: 'anon' }, async (t) => {
      if (!(await store.rateLimitHit(t, { bucket: 'oauth_register_ip', keyHash: ipKey(req, cfg.ipKey), ...REGISTER_LIMIT }))) return { slow: true };
      try {
        await t.savepoint((s) => s`select app.oauth_register(${id}, ${name}, ${uris}::text[])`);
        return { ok: true };
      } catch (e) {
        if (e.code === '22023') return { bad: e.message, hint: e.hint };
        throw e;
      }
    });
    if (out.slow) return oauthError(res, 429, 'slow_down', 'Too many registrations from here. Try again in an hour.');
    if (out.bad) return oauthError(res, 400, out.bad === 'invalid_client_metadata' ? 'invalid_client_metadata' : 'invalid_redirect_uri', out.hint || 'Check the request.');
    return reply(res, 201, { client_id: id, client_name: name, redirect_uris: uris, token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'], response_types: ['code'], client_id_issued_at: Math.floor(Date.now() / 1000) });
  },

  async 'GET client'(req, res, run) {
    const id = new URL(req.url || '/', ORIGIN).searchParams.get('id');
    if (!id || !CLIENT.test(id)) return reply(res, 404, { error: 'No app has that ID.' });
    const [r] = await run({ actor: 'anon' }, (t) => t`select app.oauth_client(${id}) as d`);
    return r && r.d ? reply(res, 200, r.d) : reply(res, 404, { error: 'No app has that ID.' });
  },

  // The consent page, after it made the agent with POST /api/agents: bind the new key to a one-time code.
  async 'POST code'(req, res, run, body) {
    if (!sameSite(req)) return reply(res, 403, { error: 'This can only be done from dayonegreat.com.' });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in first.' });
    const b = body.value;
    const client = str(b.client_id, 26);
    const redirect = str(b.redirect_uri, 500);
    const challenge = str(b.code_challenge, 43);
    const key = str(b.key, 48);
    if (!client || !CLIENT.test(client) || !redirect || !challenge || !B64URL43.test(challenge) || !key || !agentkey.KEY.test(key)) {
      return reply(res, 400, { error: 'Check the request: client_id, redirect_uri, code_challenge (S256) and the new agent’s key.' });
    }
    if (b.state !== undefined && !str(b.state, 500)) return reply(res, 400, { error: 'state is at most 500 characters.' });
    if (!resourceOk(b.resource)) return reply(res, 400, { error: 'This app asked for a resource other than ' + ORIGIN + '/mcp.' });
    const a = await run({ actor: 'anon' }, (t) => require('../db/agents').resolve(t, c.sha256hex(key)));
    if (!a || a.ownerId !== who.memberId) return reply(res, 403, { error: 'That key isn’t one of your agents.' });
    const code = c.token(32);
    try {
      await run(session.actorFor(who), (t) => t`select app.oauth_code_put(${codeHash(code)}, ${client}, ${redirect}, ${challenge}, ${a.agentId}::uuid, ${seal(code, key)})`);
    } catch (e) {
      if (e.code === '22023') return reply(res, 400, { error: e.hint || 'That app or its return address isn’t registered.' });
      if (e.code === '42501') return reply(res, 403, { error: 'That key isn’t one of your agents.' });
      throw e;
    }
    const to = new URL(redirect);
    to.searchParams.set('code', code);
    if (b.state !== undefined) to.searchParams.set('state', b.state);
    to.searchParams.set('iss', ORIGIN);
    return reply(res, 201, { redirect: to.toString() });
  },

  async 'POST token'(req, res, run, body, cfg) {
    const b = body.value;
    if (b.grant_type !== 'authorization_code') return oauthError(res, 400, 'unsupported_grant_type', 'Only authorization_code is supported.');
    if (!resourceOk(b.resource)) return oauthError(res, 400, 'invalid_target', 'resource must be ' + ORIGIN + '/mcp.');
    const code = str(b.code, 43);
    const client = str(b.client_id, 26);
    const redirect = str(b.redirect_uri, 500);
    const verifier = str(b.code_verifier, 128);
    if (!code || !session.isToken(code) || !client || !CLIENT.test(client) || !redirect || !verifier || verifier.length < 43 || !/^[A-Za-z0-9._~-]+$/.test(verifier)) {
      return oauthError(res, 400, 'invalid_request', 'Give code, client_id, redirect_uri and code_verifier (43 to 128 characters).');
    }
    const out = await run({ actor: 'anon' }, async (t) => {
      if (!(await store.rateLimitHit(t, { bucket: 'oauth_token_ip', keyHash: ipKey(req, cfg.ipKey), ...TOKEN_LIMIT }))) return { slow: true };
      const [r] = await t`select app.oauth_code_take(${codeHash(code)}, ${client}, ${redirect}) as d`;
      return { d: r && r.d };
    });
    if (out.slow) return oauthError(res, 429, 'slow_down', 'Too many requests. Try again shortly.');
    if (!out.d || !eq(s256(verifier), out.d.challenge)) return oauthError(res, 400, 'invalid_grant', 'The code is unknown, used, expired, or doesn’t match.');
    let key;
    try { key = unseal(code, Buffer.from(out.d.sealed, 'base64')); } catch { return oauthError(res, 400, 'invalid_grant', 'The code doesn’t match.'); }
    res.setHeader('Pragma', 'no-cache');
    return reply(res, 200, { access_token: key, token_type: 'Bearer', scope: 'mcp',
      note: 'This is the agent key of an agent the person just made, for ' + ORIGIN + '/mcp; it also works on the site\u2019s acting API for that agent, under the owner\u2019s rules. It works until they revoke the agent on ' + ORIGIN + '/account/agents.' });
  }
};

async function handle(req, res, run, cfg = config.load()) {
  const route = String((req.query && req.query.route) || new URL(req.url || '/', ORIGIN).searchParams.get('route') || '').replace(/^\/+|\/+$/g, '');
  if (req.method === 'OPTIONS' && (route === 'as' || route === 'pr' || route === 'register' || route === 'token')) {
    res.statusCode = 204;
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, MCP-Protocol-Version');
    return res.end();
  }
  const handler = ROUTES[req.method + ' ' + route];
  if (!handler) return reply(res, 404, { error: 'Not found. OAuth for agents is described at ' + ORIGIN + '/.well-known/oauth-authorization-server.' });
  if (!onSite(req)) return reply(res, 403, { error: 'Use https://dayonegreat.com.' });
  if (route === 'as' || route === 'pr') return handler(req, res);
  if (route === 'register' || route === 'token') res.setHeader('Access-Control-Allow-Origin', '*');
  if (!run || !cfg.ipKey) return reply(res, 503, { error: 'Sign-in isn’t switched on here.' });
  let body = { value: {} };
  if (req.method === 'POST') {
    body = await readBody(req);
    if (!body || typeof body.value !== 'object') return oauthError(res, 400, 'invalid_request', 'Send JSON (registration, consent) or a form (token), at most 8 KB.');
  }
  return handler(req, res, run, body, cfg);
}

module.exports = async (req, res) => {
  try {
    await require('../db/sitekeys').ensure(req);
    await handle(req, res, db.configured() ? db.run : null);
  } catch (e) {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
module.exports.handle = handle;
module.exports.AS_META = AS_META;
module.exports.PR_META = PR_META;
module.exports._seal = { seal, unseal, codeHash, s256 };
module.exports = require('../db').entry(module.exports);
