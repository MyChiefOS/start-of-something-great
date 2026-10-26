#!/usr/bin/env node
// Route B probe (harness/STATUS.md, step 2). Runs as Vercel's build step on the branch `oidc-probe` only, which is
// never merged. It answers ONE yes-or-no question per commit through the build's own result: the build succeeds
// for yes and fails for no, and GitHub shows that as the commit's "Vercel" status. Nothing is printed except
// "probe <question>: yes" or "no". The token itself is never printed, stored or sent anywhere; only its claims are
// read, in memory, without verifying the signature (we're asking what Vercel issues, not trusting it).
'use strict';

const QUESTION = 'token-present'; // changed by each probe commit

function claims(token) {
  try { return JSON.parse(Buffer.from(String(token).split('.')[1] || '', 'base64url').toString('utf8')); } catch { return null; }
}

function answer(q, env) {
  const c = env.VERCEL_OIDC_TOKEN ? claims(env.VERCEL_OIDC_TOKEN) : null;
  switch (q) {
    case 'control-pass': return true;
    case 'control-fail': return false;
    case 'token-present': return Boolean(env.VERCEL_OIDC_TOKEN);
    case 'issuer-team': return Boolean(c) && c.iss === 'https://oidc.vercel.com/chief-os';
    case 'issuer-global': return Boolean(c) && c.iss === 'https://oidc.vercel.com';
    case 'claims-match': return Boolean(c) && c.project_id === 'prj_cXnWySYVpJE9TVZaNPSocXMMzkZI' && c.owner_id === 'team_Hv5YS8LhIiKe06SSiDrUucd4' && c.environment === 'preview';
    case 'launch-stage-set': return Boolean(String(env.LAUNCH_STAGE || '').trim());
    default: return false;
  }
}

if (require.main === module) {
  // Only ever on the probe branch: anywhere else this step does nothing and passes.
  if (process.env.VERCEL_GIT_COMMIT_REF !== 'oidc-probe') process.exit(0);
  const yes = answer(QUESTION, process.env);
  console.log('probe ' + QUESTION + ': ' + (yes ? 'yes' : 'no'));
  process.exit(yes ? 0 : 1);
}

module.exports = { answer, claims };
