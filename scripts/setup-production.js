#!/usr/bin/env node
// Production setup, run only by the "Production setup" GitHub workflow (.github/workflows/setup.yml): on main, in the
// protected "production" environment, after Aaron approves the run. Nothing here runs on anyone's own computer, and no
// secret is ever printed, saved to a file or seen by a person: each one is made inside the run and goes straight to
// Vercel (as a "sensitive" variable nobody can read back) or to the database (as a hash).
//
// Steps (SETUP_STEPS, comma separated, in this order whatever order they're given):
//   database  remove Supabase's ensure_rls trigger if it's there; apply the migrations; create the site's login role
//             dog_web if it's missing (or give it a new password when SETUP_ROTATE_DB_PASSWORD=yes) and put its
//             transaction-pooler address in Vercel as DATABASE_URL, with DATABASE_CA; then the coverage check.
//   keys      SESSION_SECRET, IP_HASH_KEY, FINGERPRINT_KEY_1 and CRON_SECRET, each made only if it isn't there yet.
//             An existing key is never replaced: members are recognised by FINGERPRINT_KEY_1.
//   stage     LAUNCH_STAGE (closed, preview or public) and, for the preview, LAUNCH_PREVIEW_ALLOW.
//   admin     makes SETUP_ADMIN_MEMBER_ID the administrator (after Aaron has signed in once and read it at /auth/me).
//   redeploy  redeploys the current production build, so Vercel's new settings take effect.
//
// Settings it reads (placeholders until Aaron adds them; see SETUP.md):
//   secrets  MIGRATION_DATABASE_URL, MIGRATION_DATABASE_CA, VERCEL_TOKEN
//   inputs   SETUP_STEPS, SETUP_STAGE, SETUP_PREVIEW_ALLOW, SETUP_ADMIN_MEMBER_ID, SETUP_ROTATE_DB_PASSWORD
'use strict';

const crypto = require('crypto');

const VERCEL_PROJECT = 'prj_cXnWySYVpJE9TVZaNPSocXMMzkZI';
const VERCEL_TEAM = 'team_Hv5YS8LhIiKe06SSiDrUucd4';
const SUPABASE_REF = 'nksagchwpyljvjiwolmp';
const ORDER = ['database', 'keys', 'stage', 'admin', 'redeploy'];
const KEYS = ['SESSION_SECRET', 'IP_HASH_KEY', 'FINGERPRINT_KEY_1', 'CRON_SECRET'];

// ---- Hashing a password the way Postgres stores it (SCRAM-SHA-256), so the database never receives the password
// itself and no log can show it. The same thing psql's \password does.
function scramVerifier(password, { salt = crypto.randomBytes(16), iterations = 4096 } = {}) {
  const salted = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, 32, 'sha256');
  const hmac = (key, msg) => crypto.createHmac('sha256', key).update(msg).digest();
  const storedKey = crypto.createHash('sha256').update(hmac(salted, 'Client Key')).digest();
  const serverKey = hmac(salted, 'Server Key');
  return 'SCRAM-SHA-256$' + iterations + ':' + salt.toString('base64') + '$' + storedKey.toString('base64') + ':' + serverKey.toString('base64');
}

// A strong password with only URL-safe characters, so it needs no escaping in the connection address.
const newPassword = () => crypto.randomBytes(32).toString('base64url');
const newKey = () => crypto.randomBytes(32).toString('base64');

// The site's address: Supabase's shared transaction pooler (port 6543) on the same host as the migration address
// (the session pooler, port 5432), as user dog_web.<project ref>. The site refuses any other kind of address (G1).
function siteDatabaseUrl(migrationUrl, password, ref = SUPABASE_REF) {
  const m = new URL(migrationUrl);
  if (!/\.pooler\.supabase\.com$/.test(m.hostname)) {
    throw new Error('MIGRATION_DATABASE_URL must be the Supabase session pooler address (…pooler.supabase.com:5432), so the site\'s address can be made from it');
  }
  const u = new URL('postgresql://placeholder@' + m.hostname + ':6543/postgres');
  u.username = 'dog_web.' + ref;
  u.password = password;
  return u.toString();
}

// ---- Vercel, through its REST API, with a token that only this run sees. Values are sent, never logged.
function vercel(token, { fetchImpl = fetch, project = VERCEL_PROJECT, team = VERCEL_TEAM } = {}) {
  if (!token) throw new Error('VERCEL_TOKEN is not set (SETUP.md, step 2)');
  const call = async (method, path, body) => {
    const r = await fetchImpl('https://api.vercel.com' + path + (path.includes('?') ? '&' : '?') + 'teamId=' + team, {
      method, headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const text = await r.text();
    // Vercel's error messages never contain the values we send, but only its code and message are reported.
    if (!r.ok) { let e = {}; try { e = JSON.parse(text).error || {}; } catch { /* not JSON */ } throw new Error('Vercel ' + method + ' failed (' + r.status + '): ' + (e.code || '') + ' ' + (e.message || '')); }
    return text ? JSON.parse(text) : {};
  };
  return {
    // The names of the variables set for Production (never their values).
    async productionNames() {
      const out = await call('GET', '/v10/projects/' + project + '/env');
      return new Set((out.envs || []).filter((e) => (e.target || []).includes('production')).map((e) => e.key));
    },
    async set(key, value, { sensitive = true } = {}) {
      await call('POST', '/v10/projects/' + project + '/env?upsert=true', { key, value, type: sensitive ? 'sensitive' : 'plain', target: ['production'] });
    },
    async redeploy() {
      const list = await call('GET', '/v6/deployments?projectId=' + project + '&target=production&state=READY&limit=1');
      const d = (list.deployments || [])[0];
      if (!d) throw new Error('no ready production deployment to redeploy');
      const out = await call('POST', '/v13/deployments', { name: d.name, deploymentId: d.uid, target: 'production' });
      return out.id || out.uid;
    }
  };
}

// ---- The steps.
async function stepDatabase(sql, v, { migrationUrl, ca, rotate, log, migrate, check, role = 'dog_web' }) {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(role)) throw new Error('bad role name');
  // Supabase adds an event trigger at project creation that our coverage check refuses (it turns row-level security
  // on behind the migrations' back). Aaron approved removing it (gap register GAP-44).
  try {
    await sql.unsafe('drop event trigger if exists ensure_rls');
    await sql.unsafe('drop function if exists public.rls_auto_enable()');
    log('ensure_rls: removed (or was not there)');
  } catch (e) {
    throw new Error('could not remove Supabase\'s ensure_rls trigger (' + e.message + '). Run SETUP.md\'s one-line fix in the Supabase SQL editor, then run this again');
  }
  const applied = await migrate(sql, { log });
  log(applied.length ? 'migrations applied: ' + applied.join(', ') : 'migrations: already up to date');
  const [{ exists }] = await sql`select exists (select 1 from pg_roles where rolname = ${role}) as exists`;
  if (!exists) {
    await sql.unsafe('create role ' + role + ' login noinherit');
    await sql.unsafe('grant dog_app to ' + role);
    log('login role ' + role + ': created');
  }
  if (!exists || rotate) {
    const password = newPassword();
    // Vercel first: if that fails, the database password is unchanged and the site keeps working.
    await v.set('DATABASE_URL', siteDatabaseUrl(migrationUrl, password));
    if (ca) await v.set('DATABASE_CA', ca);
    await sql.unsafe('alter role ' + role + " password '" + scramVerifier(password) + "'");
    log('DATABASE_URL and DATABASE_CA: set in Vercel for Production; dog_web\'s password set (as a hash) to match');
  } else {
    log('login role ' + role + ': exists; password unchanged (set SETUP_ROTATE_DB_PASSWORD=yes to replace it)');
  }
  const p = await check(sql);
  if (p.length) throw new Error('database coverage check failed:\n- ' + p.join('\n- '));
  log('database coverage check: passed');
}

async function stepKeys(v, { log }) {
  const have = await v.productionNames();
  for (const k of KEYS) {
    if (have.has(k)) { log(k + ': already set, left as it is'); continue; }
    await v.set(k, newKey());
    log(k + ': made and set in Vercel (sensitive)');
  }
}

async function stepStage(v, { stage, allow, log }) {
  const { STAGES, allowList } = require('../launch');
  if (!STAGES.includes(stage)) throw new Error('SETUP_STAGE must be closed, preview or public');
  if (stage === 'preview') {
    const n = allowList({ LAUNCH_PREVIEW_ALLOW: allow || '' }).size;
    if (!n) throw new Error('the preview needs at least one entry in SETUP_PREVIEW_ALLOW, like github:<your numeric GitHub account ID>');
    await v.set('LAUNCH_PREVIEW_ALLOW', allow);
    log('LAUNCH_PREVIEW_ALLOW: ' + n + ' entr' + (n === 1 ? 'y' : 'ies') + ' set');
  }
  await v.set('LAUNCH_STAGE', stage, { sensitive: false });
  log('LAUNCH_STAGE: ' + stage);
}

async function stepAdmin(sql, { memberId, log }) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(memberId || '')) {
    throw new Error('SETUP_ADMIN_MEMBER_ID must be your member_id from https://dayonegreat.com/auth/me after signing in once');
  }
  const n = await sql.begin(async (t) => {
    await t`set local role dog_owner`;
    const r = await t`update app.members set is_admin = true where id = ${memberId} and status = 'active'`;
    return r.count;
  });
  if (n !== 1) throw new Error('no active member with that ID; nothing changed');
  log('administrator: set');
}

function steps(list) {
  const want = String(list || '').split(/[\s,]+/).filter(Boolean);
  const bad = want.filter((s) => !ORDER.includes(s));
  if (bad.length) throw new Error('unknown step(s): ' + bad.join(', ') + ' (choose from ' + ORDER.join(', ') + ')');
  return ORDER.filter((s) => want.includes(s));
}

async function main(env = process.env, deps = {}) {
  const log = deps.log || ((m) => console.log(m));
  const todo = steps(env.SETUP_STEPS);
  if (!todo.length) throw new Error('nothing to do: set SETUP_STEPS');
  const v = deps.vercel || vercel(env.VERCEL_TOKEN);
  let sql = deps.sql || null;
  const needsDb = todo.includes('database') || todo.includes('admin');
  if (needsDb && !sql) {
    if (!env.MIGRATION_DATABASE_URL) throw new Error('MIGRATION_DATABASE_URL is not set (SETUP.md, step 2)');
    const db = require('../db');
    sql = db.connect(env.MIGRATION_DATABASE_URL, { max: 1, ssl: env.MIGRATION_SSL === 'off' ? false : db.tls(env.MIGRATION_DATABASE_CA) });
  }
  try {
    for (const s of todo) {
      log('== ' + s);
      if (s === 'database') {
        const { migrate } = require('./migrate');
        const check = deps.check || (async (x) => {
          const fs = require('fs'); const path = require('path'); const { problems } = require('../db/checks');
          const snapshot = fs.readFileSync(path.join(__dirname, '..', 'db', 'snapshot.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
          return problems(x, { snapshot });
        });
        await stepDatabase(sql, v, { migrationUrl: env.MIGRATION_DATABASE_URL, ca: env.MIGRATION_DATABASE_CA, rotate: env.SETUP_ROTATE_DB_PASSWORD === 'yes', log, migrate: deps.migrate || migrate, check });
      }
      if (s === 'keys') await stepKeys(v, { log });
      if (s === 'stage') await stepStage(v, { stage: String(env.SETUP_STAGE || '').trim().toLowerCase(), allow: env.SETUP_PREVIEW_ALLOW, log });
      if (s === 'admin') await stepAdmin(sql, { memberId: String(env.SETUP_ADMIN_MEMBER_ID || '').trim(), log });
      if (s === 'redeploy') log('redeploy started: ' + await v.redeploy());
    }
  } finally {
    if (sql && !deps.sql) await sql.end({ timeout: 5 });
  }
}

if (require.main === module) {
  main().then(() => console.log('setup: done')).catch((e) => { console.error('setup stopped: ' + e.message); process.exit(1); });
}

module.exports = { main, steps, scramVerifier, siteDatabaseUrl, vercel, stepDatabase, stepKeys, stepStage, stepAdmin, KEYS };
