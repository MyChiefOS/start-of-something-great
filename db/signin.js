// Database calls for sign-in. Each calls one of the narrow functions in migration 002, which run as dog_signin;
// the site's own role never reads sessions, identities or email links directly.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;
const hex = (field, s) => v.text(field, s, { max: 64, min: 64, pattern: HEX64 });

async function rateLimitHit(t, { bucket, keyHash, windowSeconds, max }) {
  const [r] = await t`select app.rate_limit_hit(${v.text('bucket', bucket, { max: 32, pattern: /^[a-z_]+$/ })}, ${hex('keyHash', keyHash)},
                      ${v.int('windowSeconds', windowSeconds, { min: 1, max: 86400 })}::integer, ${v.int('max', max, { min: 1, max: 100000 })}::integer) as allowed`;
  return r.allowed === true;
}

async function emailTokenIssue(t, { tokenHash, emailFingerprint, keyVersion }) {
  await t`select app.email_token_issue(${hex('tokenHash', tokenHash)}, ${hex('emailFingerprint', emailFingerprint)},
          ${v.int('keyVersion', keyVersion, { min: 1, max: 999 })}::smallint)`;
}

async function emailTokenRedeem(t, tokenHash) {
  if (typeof tokenHash !== 'string' || !HEX64.test(tokenHash)) return null;
  const [r] = await t`select email_fingerprint, key_version from app.email_token_redeem(${tokenHash})`;
  return r ? { emailFingerprint: r.email_fingerprint, keyVersion: r.key_version } : null;
}

// Returns { memberId, isNew, trustLevel, isAdmin }, or { refused: 'banned' | 'taken' }.
async function signIn(t, { provider, fingerprints, keyVersion, level, displayName, sessionHash, sessionDays, recheckAfter = null, linkMember = null }) {
  const fps = fingerprints.map((f) => hex('fingerprint', f));
  if (fps.length < 1 || fps.length > 5) throw new v.ValidationError('fingerprints', 'must have 1 to 5 entries');
  const args = {
    provider: v.oneOf('provider', provider, ['github', 'x', 'email', 'linkedin']),
    keyVersion: v.int('keyVersion', keyVersion, { min: 1, max: 999 }),
    level: v.int('level', level, { min: 0, max: 2 }),
    name: v.text('displayName', displayName, { max: 80 }),
    session: hex('sessionHash', sessionHash),
    days: v.int('sessionDays', sessionDays, { min: 1, max: 30 }),
    recheck: recheckAfter === null ? null : new Date(recheckAfter),
    link: linkMember === null ? null : v.uuid('linkMember', linkMember)
  };
  try {
    // A savepoint, so a refusal leaves the surrounding transaction usable.
    const [r] = await t.savepoint((s) => s`select * from app.sign_in(${args.provider}, ${s.array(fps)}::text[], ${args.keyVersion}::smallint,
      ${args.level}::smallint, ${args.name}, ${args.session}, ${args.days}::integer, ${args.recheck}::timestamptz, ${args.link}::uuid)`);
    return { memberId: r.member_id, isNew: r.is_new, trustLevel: r.trust_level, isAdmin: r.is_admin };
  } catch (e) {
    if (e.code === 'P0001' && (e.message === 'banned' || e.message === 'taken')) return { refused: e.message };
    throw e;
  }
}

async function sessionResolve(t, sessionHash, idleDays) {
  if (typeof sessionHash !== 'string' || !HEX64.test(sessionHash)) return null;
  const [r] = await t`select * from app.session_resolve(${sessionHash}, ${v.int('idleDays', idleDays, { min: 1, max: 30 })}::integer)`;
  return r ? { memberId: r.member_id, trustLevel: r.trust_level, isAdmin: r.is_admin, displayName: r.display_name } : null;
}

async function sessionEnd(t, sessionHash) {
  if (typeof sessionHash === 'string' && HEX64.test(sessionHash)) await t`select app.session_end(${sessionHash})`;
}

// "Log out everywhere": as the member, through their own row-level security policy.
async function sessionsEndAll(t) {
  const rows = await t`delete from app.sessions where member_id = app.current_member() returning id`;
  return rows.length;
}

module.exports = { rateLimitHit, emailTokenIssue, emailTokenRedeem, signIn, sessionResolve, sessionEnd, sessionsEndAll };
