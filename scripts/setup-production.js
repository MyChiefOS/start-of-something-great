#!/usr/bin/env node
// Production setup, run only by the "Production setup" GitHub workflow (.github/workflows/setup.yml): on main, in the
// protected "production" environment, after Aaron approves the run. Nothing here runs on anyone's own computer.
//
// It makes no password and no key (Oct 23, 2026, Aaron: "remove the Old Path"). The site's database login (dog_web),
// its password and the sign-in keys are made inside the database by migration 017 and kept in Supabase Vault, where
// the JEVs gateway reads them (GATEWAY.md). The steps that used to make them here (the "keys" step, and the
// database step's login, password, rotation and DATABASE_URL in Vercel) are removed: run again, they would have
// replaced the gateway's password and cut it off.
//
// Steps (SETUP_STEPS, comma separated, in this order whatever order they're given):
//   database  remove Supabase's ensure_rls trigger if it's there; apply the migrations; report whether the site's
//             login role dog_web exists (never creating it or touching its password); then the coverage check.
//   stage     LAUNCH_STAGE (closed, preview or public; "unchanged", the default, leaves it alone) and, for the
//             preview, LAUNCH_PREVIEW_ALLOW.
//   admin     makes SETUP_ADMIN_MEMBER_ID the administrator (after Aaron has signed in once and read it at /auth/me);
//             refuses if someone else already is (one administrator), and writes an audit row.
//   redeploy  redeploys the deployment production currently serves (so it works after a rollback too), waits for it
//             to be ready, then checks the live site answers and, if the stage was set in this run, shows it.
//
// The stage step also records the stage as the repository variable EXPECTED_STAGE (GITHUB_TOKEN, actions: write), so
// the uptime monitor can tell when the live stage drifts from the last approved run (D1).
//
// Settings it reads, only when someone runs it (none is needed to launch; see SETUP.md):
//   secrets  MIGRATION_DATABASE_URL for "database" and "admin"; VERCEL_TOKEN for "stage" and "redeploy" (and
//            MIGRATION_DATABASE_CA only to override the Supabase root certificate kept in
//            db/certs/supabase-root-2021.crt: it is public, not a secret, so it lives in the repo)
//   inputs   SETUP_STEPS, SETUP_STAGE, SETUP_PREVIEW_ALLOW, SETUP_ADMIN_MEMBER_ID
'use strict';

const VERCEL_PROJECT = 'prj_cXnWySYVpJE9TVZaNPSocXMMzkZI';
const VERCEL_TEAM = 'team_Hv5YS8LhIiKe06SSiDrUucd4';
const ORDER = ['database', 'stage', 'admin', 'redeploy'];
// Steps that no longer exist, with the reason, so a run that asks for one is told why instead of only "unknown".
const REMOVED = { keys: 'the sign-in keys are made by migration 017 and kept in Supabase Vault, where the gateway reads them (removed Oct 23, 2026)' };

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
    // The deployment production serves right now: the project's production target, which is what a rollback moves,
    // so a redeploy after a rollback rebuilds the rolled-back code, not the newest build (RK68, S5).
    async currentProduction() {
      const p = await call('GET', '/v9/projects/' + project);
      const t = p.targets && p.targets.production;
      if (t && (t.id || t.uid)) return { uid: t.id || t.uid, name: t.name || p.name };
      const list = await call('GET', '/v6/deployments?projectId=' + project + '&target=production&state=READY&limit=1');
      const d = (list.deployments || [])[0];
      if (!d) throw new Error('no ready production deployment to redeploy');
      return { uid: d.uid, name: d.name };
    },
    async redeploy() {
      const d = await this.currentProduction();
      const out = await call('POST', '/v13/deployments', { name: d.name, deploymentId: d.uid, target: 'production' });
      return out.id || out.uid;
    },
    // Waits until a deployment is ready (or has failed), so the run reports what really happened.
    async waitReady(id, { timeoutMs = 10 * 60 * 1000, everyMs = 10000, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
      const until = Date.now() + timeoutMs;
      for (;;) {
        const d = await call('GET', '/v13/deployments/' + id);
        const state = d.readyState || d.state;
        if (state === 'READY') return d;
        if (['ERROR', 'CANCELED'].includes(state)) throw new Error('the redeploy ' + state.toLowerCase() + ' (' + id + '); the previous deployment is still serving');
        if (Date.now() > until) throw new Error('the redeploy is still building after ' + Math.round(timeoutMs / 60000) + ' minutes; check it in Vercel before running again');
        await sleep(everyMs);
      }
    }
  };
}

// ---- GitHub, through its REST API with the run's own token: records the stage the last approved run set, as the
// repository variable EXPECTED_STAGE, which the uptime monitor compares with the live site (D1).
function github(token, repo, { fetchImpl = fetch } = {}) {
  const call = async (method, path, body) => {
    const r = await fetchImpl('https://api.github.com/repos/' + repo + path, {
      method, headers: { authorization: 'Bearer ' + token, accept: 'application/vnd.github+json', 'content-type': 'application/json', 'x-github-api-version': '2022-11-28' }, body: body ? JSON.stringify(body) : undefined });
    if (!r.ok && r.status !== 404) throw new Error('GitHub ' + method + ' ' + path + ' failed (' + r.status + ')');
    return r.status;
  };
  return {
    async setVariable(name, value) {
      const st = await call('PATCH', '/actions/variables/' + name, { name, value });
      if (st === 404) await call('POST', '/actions/variables', { name, value });
    }
  };
}

// After a redeploy: the live site answers, and shows the stage this run set (if it set one). Read through a unique
// address so no cache answers for the previous deployment.
async function verifyLive({ site, stage, fetchImpl = fetch, tag }) {
  const r = await fetchImpl(site + '/api/status?after=' + encodeURIComponent(tag || Date.now()), { headers: { 'cache-control': 'no-cache' }, signal: AbortSignal.timeout(15000) });
  if (r.status !== 200) throw new Error('after the redeploy the site answered ' + r.status + ' at /api/status');
  const body = JSON.parse(await r.text());
  if (stage && body.stage !== stage) throw new Error('after the redeploy the site reports stage "' + body.stage + '", not "' + stage + '"; Vercel may still be switching, check again in a minute, and do not open anything until it matches');
  return body.stage;
}

// ---- The steps.
async function stepDatabase(sql, { log, migrate, check, role = 'dog_web' }) {
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
  // The site's login role is reported, never made or changed here: on Supabase migration 017 makes it, with its
  // password in Vault, and the gateway signs in with that password. A missing role is said, not fixed (it alerts,
  // it doesn't block): the coverage check below still runs.
  const [{ exists }] = await sql`select exists (select 1 from pg_roles where rolname = ${role}) as exists`;
  log(exists
    ? 'login role ' + role + ': exists; this run never changes its password (it lives in Supabase Vault)'
    : 'login role ' + role + ': missing. On Supabase, migration 017 makes it with its password in Vault; this run makes no logins or passwords');
  const p = await check(sql);
  if (p.length) throw new Error('database coverage check failed:\n- ' + p.join('\n- '));
  log('database coverage check: passed');
}

// 'unchanged' (the workflow's default) leaves the stage exactly as it is, so a re-run of the default steps can never
// move the site forwards or backwards by accident (S6b).
async function stepStage(v, { stage, allow, log, gh = null }) {
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
  if (gh) {
    try { await gh.setVariable('EXPECTED_STAGE', stage); log('EXPECTED_STAGE: ' + stage + ' (recorded in GitHub for the uptime monitor)'); }
    catch (e) { log('EXPECTED_STAGE: could not be recorded (' + e.message + '). Set the repository variable EXPECTED_STAGE to ' + stage + ' by hand (Settings, Secrets and variables, Actions), or the uptime monitor will report the stage as drifted'); }
  }
}

async function stepAdmin(sql, { memberId, log }) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(memberId || '')) {
    throw new Error('SETUP_ADMIN_MEMBER_ID must be your member_id from https://dayonegreat.com/auth/me after signing in once');
  }
  // The database does it (migration 013, app.set_administrator): one administrator, a second call for the same
  // member changes nothing, and the change and its audit row ('admin.set', as the system) land together (S8).
  let outcome;
  try {
    outcome = await sql.begin(async (t) => {
      await t`set local role dog_owner`;
      const [{ set_administrator }] = await t`select app.set_administrator(${memberId})`;
      return set_administrator;
    });
  } catch (e) {
    throw new Error(/already the administrator|no active member/.test(e.message) ? e.message : 'could not set the administrator (' + e.message + ')');
  }
  log(outcome === 'already' ? 'administrator: already this member; nothing changed' : 'administrator: set, and recorded in the audit log');
}

function steps(list) {
  const want = String(list || '').split(/[\s,]+/).filter(Boolean);
  const gone = want.filter((s) => REMOVED[s]);
  if (gone.length) throw new Error('step ' + gone.join(', ') + ' was removed: ' + gone.map((s) => REMOVED[s]).join('; '));
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
    if (s === 'database') lines.push('database: remove ensure_rls if present; apply any new migrations; report whether dog_web exists (no login, password or key is made or changed); run the coverage check');
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

// Supabase's public root certificate (Supabase Root 2021 CA, valid to 2031), kept in the repository so nobody has to
// copy it into a secret. A MIGRATION_DATABASE_CA secret, if set, takes its place.
const SUPABASE_CA_FILE = require('path').join(__dirname, '..', 'db', 'certs', 'supabase-root-2021.crt');
function databaseCa(env) {
  if (env.MIGRATION_DATABASE_CA && env.MIGRATION_DATABASE_CA.trim()) return env.MIGRATION_DATABASE_CA;
  return require('fs').readFileSync(SUPABASE_CA_FILE, 'utf8');
}

async function main(env = process.env, deps = {}) {
  const log = deps.log || ((m) => console.log(m));
  const todo = steps(env.SETUP_STEPS);
  if (!todo.length) throw new Error('nothing to do: set SETUP_STEPS');
  plan(env); // the same input checks the plan job ran, in case the run was started another way
  // Vercel only for the steps that change it, so "database" or "admin" alone need no Vercel token.
  const needsVercel = todo.includes('stage') || todo.includes('redeploy');
  const v = deps.vercel || (needsVercel ? vercel(env.VERCEL_TOKEN) : null);
  const gh = deps.github || (env.GITHUB_TOKEN && env.GITHUB_REPOSITORY ? github(env.GITHUB_TOKEN, env.GITHUB_REPOSITORY) : null);
  const site = env.SITE_URL || 'https://dayonegreat.com';
  const stageSet = todo.includes('stage') ? String(env.SETUP_STAGE || 'unchanged').trim().toLowerCase() : 'unchanged';
  let sql = deps.sql || null;
  const needsDb = todo.includes('database') || todo.includes('admin');
  if (needsDb && !sql) {
    if (!env.MIGRATION_DATABASE_URL) throw new Error('MIGRATION_DATABASE_URL is not set (SETUP.md, step 2)');
    const db = require('../db');
    sql = db.connect(env.MIGRATION_DATABASE_URL, { max: 1, ssl: env.MIGRATION_SSL === 'off' ? false : db.tls(databaseCa(env)) });
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
        await stepDatabase(sql, { log, migrate: deps.migrate || migrate, check });
      }
      if (s === 'stage') await stepStage(v, { stage: stageSet, allow: env.SETUP_PREVIEW_ALLOW, log, gh });
      if (s === 'admin') await stepAdmin(sql, { memberId: String(env.SETUP_ADMIN_MEMBER_ID || '').trim(), log });
      if (s === 'redeploy') {
        const id = await v.redeploy();
        log('redeploy started: ' + id);
        await v.waitReady(id);
        log('redeploy ready');
        const live = await (deps.verifyLive || verifyLive)({ site, stage: stageSet === 'unchanged' ? null : stageSet, tag: id });
        log('live site answers; stage: ' + live);
      }
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

module.exports = { databaseCa, SUPABASE_CA_FILE, main, plan, steps, vercel, github, verifyLive, stepDatabase, stepStage, stepAdmin, ORDER, REMOVED };
