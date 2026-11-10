// The red-team copy (RK141; harness/STANDARDS.md gap 1): the site's real API handlers, run in this process against a
// throwaway database built from the migrations, with made-up accounts. Nothing here reaches production: the database
// is created on the Postgres server it is given and dropped at the end, and no handler is given a network to call.
//
// An attack plan is data, never code: a list of steps, each one request as one of the copy's accounts, with what the
// answer must be. redteam/plan.js runs a plan and reports each step; redteam/baseline.json is the plan every PR runs.
'use strict';

const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const { migrate } = require('../scripts/migrate');

const ORIGIN = 'https://dayonegreat.com';
const HANDLERS = { agents: 'agents', notify: 'notify', log: 'log', work: 'work', feed: 'feed', decisions: 'decisions', directory: 'directory' };
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };

function response() {
  const r = { statusCode: 200, headers: {}, body: '', headersSent: false };
  r.setHeader = (k, v) => { r.headers[String(k).toLowerCase()] = v; };
  r.getHeader = (k) => r.headers[String(k).toLowerCase()];
  r.end = (b) => { r.body = b === undefined ? '' : String(b); r.headersSent = true; };
  return r;
}

async function start(server) {
  const name = 'dog_redteam_copy_' + crypto.randomBytes(4).toString('hex');
  const webRole = name + '_web';
  const pw = crypto.randomBytes(18).toString('base64url');
  const root = postgres(server, { max: 1, ssl: false, onnotice: () => {} });
  await root.unsafe('create database ' + name);
  const su = postgres(at(server, name), { max: 2, ssl: false, onnotice: () => {} });
  let web = null;
  const close = async () => {
    for (const x of [web, su]) if (x) await x.end({ timeout: 5 }).catch(() => {});
    await root.unsafe(`drop database if exists ${name} with (force)`).catch(() => {});
    await root.unsafe(`drop role if exists ${webRole}`).catch(() => {});
    await root.end({ timeout: 5 }).catch(() => {});
  };
  try {
    await migrate(su);
    // The site's own login, exactly as production has it: a member of dog_app and nothing else.
    await su.unsafe(`create role ${webRole} login noinherit password '${pw}'; grant dog_app to ${webRole}`);
    web = db.connect(at(server, name, webRole, pw), { ssl: false, max: 4 });
    const run = (ctx, fn) => db.tx(web, ctx, fn);
    const asOwner = (sqlText) => su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(sqlText); });

    // Made-up accounts: two ordinary members at level 2 and one administrator, each with a real session.
    async function member(label, { admin = false } = {}) {
      const token = c.token(32);
      const out = await su.begin(async (t) => {
        await t.unsafe('set local role dog_signin');
        return store.signIn(t, { provider: 'github', fingerprints: [c.sha256hex(crypto.randomUUID())], keyVersion: 1, level: 1,
          displayName: label, sessionHash: c.sha256hex(token), sessionDays: 30 });
      });
      await su.begin(async (t) => { await t.unsafe('set local role dog_jevs'); await t`update app.members set jevs_level2_at = now(), trust_level = 2 where id = ${out.memberId}`; });
      await su.unsafe(`update app.members set created_at = now() - interval '30 days' where id = '${out.memberId}'`);
      if (admin) await asOwner(`update app.members set is_admin = true where id = '${out.memberId}'`);
      return { id: out.memberId, cookie: '__Host-dog_session=' + token };
    }
    const accounts = { anon: { cookie: '' }, memberA: await member('Member A'), memberB: await member('Member B'), admin: await member('Admin', { admin: true }) };

    // One request, as one account, through the real handler for its address.
    async function call(step) {
      const u = new URL(step.path, ORIGIN);
      const parts = u.pathname.split('/').filter(Boolean); // ['api', 'work', 'console']
      const mod = HANDLERS[parts[1]];
      if (parts[0] !== 'api' || !mod) return { status: 0, error: 'no such handler: ' + step.path };
      const route = parts.slice(2).join('/');
      const query = Object.fromEntries(u.searchParams);
      if (route) query.route = route;
      const who = accounts[step.as || 'anon'];
      if (!who) return { status: 0, error: 'no such account: ' + step.as };
      const headers = { host: 'dayonegreat.com', 'x-vercel-forwarded-for': '203.0.113.' + (10 + Object.keys(accounts).indexOf(step.as || 'anon')), 'x-vercel-ip-country': 'US' };
      if (who.cookie) headers.cookie = who.cookie;
      const method = (step.method || 'GET').toUpperCase();
      if (method !== 'GET') { headers.origin = ORIGIN; headers['sec-fetch-site'] = 'same-origin'; headers['content-type'] = 'application/json'; }
      for (const [k, v] of Object.entries(step.headers || {})) {
        if (v === null) delete headers[k.toLowerCase()]; else headers[k.toLowerCase()] = String(v);
      }
      const url = '/api/' + parts[1] + (route ? '?route=' + encodeURIComponent(route) : '') + (u.search ? (route ? '&' : '?') + u.search.slice(1) : '');
      const req = { method, url, headers, query, body: step.body === undefined ? undefined : JSON.stringify(step.body) };
      const res = response();
      const handler = require('../api/' + mod + '.js').handle;
      const cfg = mod === 'agents' ? { ipKey: crypto.randomBytes(32) } : undefined;
      try {
        if (cfg) await handler(req, res, run, cfg); else await handler(req, res, run);
      } catch (e) {
        return { status: 500, error: 'the handler threw: ' + String(e && e.message || e).slice(0, 200) };
      }
      let json = null;
      try { json = JSON.parse(res.body); } catch { /* not json */ }
      return { status: res.statusCode, json };
    }
    return { call, accounts, su, close };
  } catch (e) {
    await close();
    throw e;
  }
}

module.exports = { start, ORIGIN };
