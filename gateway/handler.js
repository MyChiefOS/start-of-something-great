// The JEVs gateway's router (GATEWAY.md). Runs inside a Supabase Edge Function: the only code that holds a database
// login. Vercel forwards sign-in and posting here; everything else on the site stays on Vercel and never touches
// the database. The handlers are the site's own, unchanged; this file only chooses which one answers.
'use strict';

const auth = require('./auth');
const feed = require('../api/feed');
const db = require('../db');

function notFound(res) {
  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end('Not found');
}

// What the health check reports: the stage, whether a request can switch to the site role, and how many migrations
// are recorded. Nothing else, and nothing secret.
async function health(res) {
  const out = { ok: false, stage: require('../launch').stage(), role: null, migrations: null };
  try {
    const rows = await db.run({ actor: 'anon' }, (t) => t`select current_user as role`);
    out.role = rows[0].role;
    out.ok = out.role === 'dog_app';
  } catch (e) {
    out.error = String(e && e.message).slice(0, 120);
  }
  res.statusCode = out.ok ? 200 : 503;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(out));
}

async function handle(req, res) {
  const path = new URL(req.url, 'https://dayonegreat.com').pathname.replace(/^\/(functions\/v1\/)?jevs-gateway/, '') || '/';
  if (path === '/health' && req.method === 'GET') return health(res);
  if (path === '/api/feed') return feed(req, res);
  const m = path.match(/^\/auth\/(.+)$/);
  if (m) return auth.handle(req, res, m[1].replace(/\/+$/, ''));
  return notFound(res);
}

module.exports = { handle };
