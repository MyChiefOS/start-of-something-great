#!/usr/bin/env node
// Production setup, run only by the "Production setup" GitHub workflow (.github/workflows/setup.yml), started by hand
// on main. Its job names the "production" environment, but that environment has no approval or branch rule (found
// Oct 25, probe PR #46, OPERATIONS.md), so a run does not wait for anyone's approval. Nothing here runs on anyone's own
// computer, and no secret is ever printed, saved to a file or seen by a person: each one is made inside the run and
// goes straight to Vercel (as a "sensitive" variable nobody can read back).
//
// Steps (SETUP_STEPS, comma separated, in this order whatever order they're given):
//   keys      SESSION_SECRET, IP_HASH_KEY, FINGERPRINT_KEY_1 and CRON_SECRET, each made only if it isn't there yet.
//             An existing key is never replaced: members are recognised by FINGERPRINT_KEY_1.
//   stage     LAUNCH_STAGE (closed or public; "unchanged", the default, leaves it alone). Since the go-live release
//             it can only close the site: closed closes it, public lifts that close, and the repository's launch.json
//             decides the stage (launch.js). "preview" is no longer a stage and is refused.
//   admin     makes SETUP_ADMIN_MEMBER_ID the administrator (after Aaron has signed in once and read it at /auth/me);
//             refuses if someone else already is (one administrator), and writes an audit row.
//   redeploy  redeploys the deployment production currently serves (so it works after a rollback too), waits for it
//             to be ready, then checks the live site answers and, if the stage was set in this run, shows it.
//
// There is no "database" step any more (harness/REVIEW-2026-10-26.md, R-14): it applied migrations outside the runner
// and made the site's login with a password it put in Vercel. The database changes only through the runner
// (supabase/functions/dog-migrate, from a merged PR), and under route B migration 022 makes the site's login with its
// password in Vault. Supabase's ensure_rls trigger, which the step also removed (GAP-44), went with the fresh build of
// Oct 24 (db/reset/fresh-build.sql); the runner reports it if public.rls_auto_enable() ever comes back.
//
// The stage step also records the stage as the repository variable EXPECTED_STAGE (GITHUB_TOKEN, actions: write), so
// the uptime monitor can tell when the live stage drifts from the last setup run (D1).
//
// Settings it reads (placeholders until Aaron adds them; see SETUP.md):
//   secrets  VERCEL_TOKEN; MIGRATION_DATABASE_URL for the admin step only (and MIGRATION_DATABASE_CA only to override
//            the Supabase root certificate kept in db/certs/supabase-root-2021.crt: it is public, so it lives in the repo)
//   inputs   SETUP_STEPS, SETUP_STAGE, SETUP_ADMIN_MEMBER_ID
'use strict';

const crypto = require('crypto');

const VERCEL_PROJECT = 'prj_cXnWySYVpJE9TVZaNPSocXMMzkZI';
const VERCEL_TEAM = 'team_Hv5YS8LhIiKe06SSiDrUucd4';
const ORDER = ['keys', 'stage', 'admin', 'redeploy'];
const KEYS = ['SESSION_SECRET', 'IP_HASH_KEY', 'FINGERPRINT_KEY_1', 'CRON_SECRET'];

const newKey = () => crypto.randomBytes(32).toString('base64');

// Inside GitHub Actions, tells the runner to blank a value wherever it might appear in the log (::add-mask::), before
// the value is used anywhere. Outside Actions it does nothing, so the value is never printed by this.
function maskInActions(value) {
  if (process.env.GITHUB_ACTIONS === 'true' && value) process.stdout.write('::add-mask::' + value + '\n');
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

// ---- GitHub, through its REST API with the run's own token: records the stage the last setup run set, as the
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
async function stepStage(v, { stage, log, gh = null }) {
  const { STAGES } = require('../launch');
  if (stage === 'unchanged' || stage === '') { log('LAUNCH_STAGE: unchanged'); return; }
  if (!STAGES.includes(stage)) throw new Error('SETUP_STAGE must be unchanged, closed or public');
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
  const bad = want.filter((s) => !ORDER.includes(s));
  if (bad.length) throw new Error('unknown step(s): ' + bad.join(', ') + ' (choose from ' + ORDER.join(', ') + ')');
  return ORDER.filter((s) => want.includes(s));
}

// What a run would do, from its inputs alone (S6a), written to the run's summary by a job with no secret in reach.
// Bad input stops here, before any secret is read. (The plan does not wait for an approval: the "production"
// environment has no approval rule, OPERATIONS.md, Oct 25.)
function plan(env = process.env) {
  const todo = steps(env.SETUP_STEPS);
  if (!todo.length) throw new Error('nothing to do: set SETUP_STEPS');
  const stage = String(env.SETUP_STAGE || 'unchanged').trim().toLowerCase();
  const { STAGES } = require('../launch');
  const lines = [];
  for (const s of todo) {
    if (s === 'keys') lines.push('keys: create any of ' + KEYS.join(', ') + ' that is missing; an existing key is never replaced');
    if (s === 'stage') {
      if (stage === 'unchanged') lines.push('stage: unchanged');
      else if (!STAGES.includes(stage)) throw new Error('SETUP_STAGE must be unchanged, closed or public');
      else lines.push(stage === 'public' ? 'stage: PUBLIC. Lifts a close set in Vercel; the repository\'s launch.json decides whether Release 2 is open (the go-live decision is Aaron\'s merge)' : 'stage: CLOSED. Release 2 is off, whatever launch.json says, until this setting is lifted');
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
  const v = deps.vercel || vercel(env.VERCEL_TOKEN);
  const gh = deps.github || (env.GITHUB_TOKEN && env.GITHUB_REPOSITORY ? github(env.GITHUB_TOKEN, env.GITHUB_REPOSITORY) : null);
  const site = env.SITE_URL || 'https://dayonegreat.com';
  const stageSet = todo.includes('stage') ? String(env.SETUP_STAGE || 'unchanged').trim().toLowerCase() : 'unchanged';
  let sql = deps.sql || null;
  const needsDb = todo.includes('admin');
  if (needsDb && !sql) {
    if (!env.MIGRATION_DATABASE_URL) throw new Error('MIGRATION_DATABASE_URL is not set (SETUP.md, step 2)');
    const db = require('../db');
    sql = db.connect(env.MIGRATION_DATABASE_URL, { max: 1, ssl: env.MIGRATION_SSL === 'off' ? false : db.tls(databaseCa(env)) });
  }
  try {
    for (const s of todo) {
      log('== ' + s);
      if (s === 'keys') await stepKeys(v, { log });
      if (s === 'stage') await stepStage(v, { stage: stageSet, log, gh });
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

module.exports = { databaseCa, SUPABASE_CA_FILE, main, plan, steps, vercel, github, verifyLive, stepKeys, stepStage, stepAdmin, maskInActions, KEYS };
