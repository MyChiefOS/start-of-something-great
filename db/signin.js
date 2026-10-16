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

// emailFingerprints: the address's fingerprint under each key still in use, current key first.
async function emailTokenIssue(t, { tokenHash, emailFingerprints, browserHash, keyVersion }) {
  const fps = emailFingerprints.map((f) => hex('emailFingerprint', f));
  if (fps.length < 1 || fps.length > 5) throw new v.ValidationError('emailFingerprints', 'must have 1 to 5 entries');
  await t`select app.email_token_issue(${hex('tokenHash', tokenHash)}, ${fps.join(',')}, ${hex('browserHash', browserHash)},
          ${v.int('keyVersion', keyVersion, { min: 1, max: 999 })}::smallint)`;
}

// Returns { status: 'ok', emailFingerprints, keyVersion }, { status: 'confirm' } (opened in another browser, not
// yet confirmed; nothing used up), or null (unknown, used or expired).
async function emailTokenRedeem(t, { tokenHash, browserHash, confirmed }) {
  if (typeof tokenHash !== 'string' || !HEX64.test(tokenHash)) return null;
  const b = typeof browserHash === 'string' && HEX64.test(browserHash) ? browserHash : null;
  const [r] = await t`select status, email_fingerprints, key_version from app.email_token_redeem(${tokenHash}, ${b}, ${confirmed === true})`;
  if (!r) return null;
  return r.status === 'ok' ? { status: 'ok', emailFingerprints: r.email_fingerprints.split(','), keyVersion: r.key_version } : { status: 'confirm' };
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
  // Two first sign-ins of the same account at the same moment: one wins, the other tries once more and finds it.
  for (let attempt = 0; ; attempt++) {
    try {
      // A savepoint, so a refusal or a lost race leaves the surrounding transaction usable.
      const [r] = await t.savepoint((s) => s`select * from app.sign_in(${args.provider}, ${s.array(fps)}::text[], ${args.keyVersion}::smallint,
        ${args.level}::smallint, ${args.name}, ${args.session}, ${args.days}::integer, ${args.recheck}::timestamptz, ${args.link}::uuid)`);
      return { memberId: r.member_id, isNew: r.is_new, trustLevel: r.trust_level, isAdmin: r.is_admin };
    } catch (e) {
      if (e.code === 'P0001' && (e.message === 'banned' || e.message === 'taken')) return { refused: e.message };
      if (e.code === '23505' && attempt === 0) continue;
      throw e;
    }
  }
}

async function sessionResolve(t, sessionHash, idleDays) {
  if (typeof sessionHash !== 'string' || !HEX64.test(sessionHash)) return null;
  const [r] = await t`select * from app.session_resolve(${sessionHash}, ${v.int('idleDays', idleDays, { min: 1, max: 30 })}::integer)`;
  // fresh: this session began in the last 10 minutes, by the database's clock (PR 7: letting an agent do more on its
  // own needs a fresh sign-in).
  return r ? { memberId: r.member_id, trustLevel: r.trust_level, isAdmin: r.is_admin, displayName: r.display_name, fresh: r.fresh === true } : null;
}

async function sessionEnd(t, sessionHash) {
  if (typeof sessionHash === 'string' && HEX64.test(sessionHash)) await t`select app.session_end(${sessionHash})`;
}

// "Log out everywhere": as the member, through their own row-level security policy.
async function sessionsEndAll(t) {
  const rows = await t`delete from app.sessions where member_id = app.current_member() returning id`;
  return rows.length;
}

// The signed-in member's own account page: their name, level, when they joined, and how they sign in (the provider
// only; fingerprints are never shown or needed), through their own row-level security policies.
async function account(t) {
  const [m] = await t`select id, display_name, trust_level, created_at from app.members where id = app.current_member()`;
  if (!m) return null;
  const ids = await t`select provider, level, verified_at from app.identities where member_id = app.current_member() order by created_at`;
  const [s] = await t`select count(*)::int as n from app.sessions where member_id = app.current_member()`;
  return { memberId: m.id, displayName: m.display_name, trustLevel: m.trust_level, joined: m.created_at,
    signIns: ids.map((i) => ({ provider: i.provider, level: i.level, verifiedAt: i.verified_at })), sessions: s.n };
}

// A member renames themselves (1 to 80 characters, one line).
async function rename(t, name) {
  const n = v.text('name', name, { max: 80 });
  const r = await t`update app.members set display_name = ${n} where id = app.current_member()`;
  return r.count === 1;
}

// F8: deletes the signed-in member's account and everything about them (007_account_deletion.sql). Returns the counts,
// or { refused: 'not_member' | 'not_active' | 'fresh' } ('fresh': the session didn't start recently enough, RK3).
async function deleteAccount(t) {
  try {
    const [r] = await t.savepoint((s) => s`select * from app.delete_account()`);
    return { posts: r.posts, reports: r.reports, agents: r.agents, keys: r.keys, sessions: r.sessions, identities: r.identities };
  } catch (e) {
    if (e.code === '42501' && (e.message === 'not_member' || e.message === 'not_active')) return { refused: e.message };
    if (e.code === 'P0001' && e.message === 'fresh_sign_in') return { refused: 'fresh' };
    throw e;
  }
}

module.exports = { rateLimitHit, emailTokenIssue, emailTokenRedeem, signIn, sessionResolve, sessionEnd, sessionsEndAll, account, rename, deleteAccount };
