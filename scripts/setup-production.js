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
//   stage     LAUNCH_STAGE (closed, preview or public; "unchanged", the default, leaves it alone) and, for the
//             preview, LAUNCH_PREVIEW_ALLOW.
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

// Inside GitHub Actions, tells the runner to blank a value wherever it might appear in the log (::add-mask::), before
// the value is used anywhere. Outside Actions it does nothing, so the value is never printed by this.
function maskInActions(value) {
  if (process.env.GITHUB_ACTIONS === 'true' && value) process.stdout.write('::add-mask::' + value + '\n');
}

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
    // Sets a Production variable. With replace (the default) an existing one is overwritten. With replace: false the
    // variable is only ever created: Vercel itself refuses when it exists, and that refusal is returned as
    // { existed: true }, so no list we fetched beforehand (complete or not) decides whether a key is replaced.
    // Vercel can also answer 201 with a `failed` list instead of an error; that counts as a failure too (S2).
    async set(key, value, { sensitive = true, replace = true } = {}) {
      const body = { key, value, type: sensitive ? 'sensitive' : 'plain', target: ['production'] };
      let out;
      try {
        out = await call('POST', '/v10/projects/' + project + '/env' + (replace ? '?upsert=true' : ''), body);
      } catch (e) {
        if (!replace && /ENV_ALREADY_EXISTS|already exists/i.test(e.message)) return { existed: true };
        throw e;
      }
      const failed = Array.isArray(out.failed) ? out.failed : [];
      if (failed.length) {
        const errs = failed.map((f) => (f.error && f.error.code) || 'unknown');
        if (!replace && errs.every((c) => /ENV_ALREADY_EXISTS/i.test(c))) return { existed: true };
        throw new Error('Vercel did not set ' + key + ': ' + errs.join(', '));
      }
      return { existed: false };
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
async function stepDatabase(sql, v, { migrationUrl, ca, rotate, log, migrate, check, role = 'dog_web', mask = maskInActions }) {
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
    const address = siteDatabaseUrl(migrationUrl, password);
    mask(password); mask(address);
    // Order (S4): the certificate first, because it's harmless on its own; then the address; then the database
    // password to match. If Vercel refuses, the database password is unchanged and the site keeps working. If the
    // database refuses after the address went in, the message below says exactly how to put it right.
    if (ca) await v.set('DATABASE_CA', ca);
    await v.set('DATABASE_URL', address);
    try {
      await sql.unsafe('alter role ' + role + " password '" + scramVerifier(password) + "'");
    } catch (e) {
      throw new Error('DATABASE_URL in Vercel now carries a password the database did not accept (' + e.message + '). Do not redeploy. Run Production setup again with "database" and rotate_db_password ticked: it makes a new password and sets both sides to match');
    }
    log('DATABASE_URL and DATABASE_CA: set in Vercel for Production; dog_web\'s password set (as a hash) to match');
  } else {
    log('login role ' + role + ': exists; password unchanged (set SETUP_ROTATE_DB_PASSWORD=yes to replace it)');
  }
  const p = await check(sql);
  if (p.length) throw new Error('database coverage check failed:\n- ' + p.join('\n- '));
  log('database coverage check: passed');
}

// Each key is created, never replaced (S1): Vercel refuses a create when the key exists, and that refusal is the
// signal, not a list fetched beforehand that could be incomplete. FINGERPRINT_KEY_1 above all: members are
// recognised by it, and replacing it would lose every account.
async function stepKeys(v, { log, mask = maskInActions }) {
  for (const k of KEYS) {
    const value = newKey();
    mask(value);
    const r = await v.set(k, value, { replace: false });
    log(k + (r && r.existed ? ': already set, left as it is' : ': made and set in Vercel (sensitive)'));
  }
}

// 'unchanged' (the workflow's default) leaves the stage exactly as it is, so a re-run of the default steps can never
// move the site forwards or backwards by accident (S6b).
async function stepStage(v, { stage, allow, log }) {
  const { STAGES, allowList } = require('../launch');
  if (stage === 'unchanged' || stage === '') { log('LAUNCH_STAGE: unchanged'); return; }
  if (!STAGES.includes(stage)) throw new Error('SETUP_STAGE must be unchanged, closed, preview or public');
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

// What a run would do, from its inputs alone (S6a): shown to Aaron before he approves the run, with no secret in reach.
// Bad input stops here, before the approval, not after it.
function plan(env = process.env) {
  const todo = steps(env.SETUP_STEPS);
  if (!todo.length) throw new Error('nothing to do: set SETUP_STEPS');
  const stage = String(env.SETUP_STAGE || 'unchanged').trim().toLowerCase();
  const { STAGES, allowList } = require('../launch');
  const lines = [];
  for (const s of todo) {
    if (s === 'database') lines.push('database: remove ensure_rls if present; apply any new migrations; create dog_web if missing' + (env.SETUP_ROTATE_DB_PASSWORD === 'yes' ? ', and give it a NEW password (DATABASE_URL in Vercel is replaced to match)' : ' (an existing password is kept)') + '; run the coverage check');
    if (s === 'keys') lines.push('keys: create any of ' + KEYS.join(', ') + ' that is missing; an existing key is never replaced');
    if (s === 'stage') {
      if (stage === 'unchanged') lines.push('stage: unchanged');
      else if (!STAGES.includes(stage)) throw new Error('SETUP_STAGE must be unchanged, closed, preview or public');
      else if (stage === 'preview') {
        const n = allowList({ LAUNCH_PREVIEW_ALLOW: env.SETUP_PREVIEW_ALLOW || '' }).size;
        if (!n) throw new Error('the preview needs at least one entry in SETUP_PREVIEW_ALLOW, like github:<your numeric GitHub account ID>');
        lines.push('stage: PREVIEW, open to the ' + n + ' allow-listed account' + (n === 1 ? '' : 's') + ' only');
      } else lines.push(stage === 'public' ? 'stage: PUBLIC. This is the go-live decision: Release 2 opens to everyone' : 'stage: CLOSED. Release 2 is off; the site looks as before');
    }
    if (s === 'admin') {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(env.SETUP_ADMIN_MEMBER_ID || '').trim())) throw new Error('SETUP_ADMIN_MEMBER_ID must be your member_id from https://dayonegreat.com/auth/me after signing in once');
      lines.push('admin: make member ' + String(env.SETUP_ADMIN_MEMBER_ID).trim() + ' the administrator');
    }
    if (s === 'redeploy') lines.push('redeploy: rebuild the current production deployment so Vercel uses the new settings');
  }
  return lines;
}

async function main(env = process.env, deps = {}) {
  const log = deps.log || ((m) => console.log(m));
  const todo = steps(env.SETUP_STEPS);
  if (!todo.length) throw new Error('nothing to do: set SETUP_STEPS');
  plan(env); // the same input checks the plan job ran, in case the run was started another way
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
      if (s === 'stage') await stepStage(v, { stage: String(env.SETUP_STAGE || 'unchanged').trim().toLowerCase(), allow: env.SETUP_PREVIEW_ALLOW, log });
      if (s === 'admin') await stepAdmin(sql, { memberId: String(env.SETUP_ADMIN_MEMBER_ID || '').trim(), log });
      if (s === 'redeploy') log('redeploy started: ' + await v.redeploy());
    }
  } finally {
    if (sql && !deps.sql) await sql.end({ timeout: 5 });
  }
}

if (require.main === module) {
  if (process.argv.includes('--plan')) {
    try { console.log(plan().map((l) => '- ' + l).join('\n')); } catch (e) { console.error('setup refused: ' + e.message); process.exit(1); }
  } else {
    main().then(() => console.log('setup: done')).catch((e) => { console.error('setup stopped: ' + e.message); process.exit(1); });
  }
}

module.exports = { main, plan, steps, scramVerifier, siteDatabaseUrl, vercel, stepDatabase, stepKeys, stepStage, stepAdmin, maskInActions, KEYS };
