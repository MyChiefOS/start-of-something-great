// Database calls for sign-in. Each calls one of the narrow functions in migration 002, which run as dog_signin;
// the site's own role never reads sessions, identities or email links directly.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;
// A link or unlink that lost a race it can't wait out (a deadlock, a serialization failure, a lock it couldn't get):
// nothing was changed, and trying again works. A clean refusal, never an error page (PR 15's second review, R3).
const BUSY = ['40P01', '40001', '55P03'];
const RESOLVE_TRIES = 3;
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

// Returns { memberId, isNew, trustLevel, isAdmin }, or { refused: 'banned' | 'disabled' | 'region' }.
// region: the country a member confirmed they are travelling in (PR 12); with it, no new account is ever made
// ('region'), and the confirmation is recorded. Signing in never links a method (PR 15: see link below).
async function signIn(t, { provider, fingerprints, keyVersion, level, displayName, sessionHash, sessionDays, recheckAfter = null, region = null }) {
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
    region: region === null ? null : v.text('region', region, { min: 2, max: 2, pattern: /^[A-Z]{2}$/ })
  };
  // Two first sign-ins of the same account at the same moment: one wins, the other tries once more and finds it.
  for (let attempt = 0; ; attempt++) {
    try {
      // A savepoint, so a refusal or a lost race leaves the surrounding transaction usable.
      const [r] = await t.savepoint((s) => s`select * from app.sign_in(${args.provider}, ${s.array(fps)}::text[], ${args.keyVersion}::smallint,
        ${args.level}::smallint, ${args.name}, ${args.session}, ${args.days}::integer, ${args.recheck}::timestamptz, null::uuid, ${args.region})`);
      return { memberId: r.member_id, isNew: r.is_new, trustLevel: r.trust_level, isAdmin: r.is_admin };
    } catch (e) {
      if (e.code === 'P0001' && ['banned', 'disabled', 'taken', 'region'].includes(e.message)) return { refused: e.message };
      if (e.code === '23505' && attempt === 0) continue;
      throw e;
    }
  }
}

// PR 15: the signed-in member links another sign-in method, from their own session (sessionHash), which must have
// begun in the last 10 minutes (the database decides, by its own clock). No session is made, so a link never makes
// anyone fresh; every other session of the member ends, and they get a notice. region: as for signIn.
// Returns { memberId, trustLevel, isAdmin, linked, sessionsEnded }, or { refused: 'fresh' | 'taken' | 'banned' | 'disabled' | 'busy' }.
async function link(t, { provider, fingerprints, keyVersion, level, sessionHash, recheckAfter = null, region = null }) {
  const fps = fingerprints.map((f) => hex('fingerprint', f));
  if (fps.length < 1 || fps.length > 5) throw new v.ValidationError('fingerprints', 'must have 1 to 5 entries');
  const p = v.oneOf('provider', provider, ['github', 'x', 'email', 'linkedin']);
  const kv = v.int('keyVersion', keyVersion, { min: 1, max: 999 });
  const lv = v.int('level', level, { min: 0, max: 2 });
  const sh = hex('sessionHash', sessionHash);
  const recheck = recheckAfter === null ? null : new Date(recheckAfter);
  const rg = region === null ? null : v.text('region', region, { min: 2, max: 2, pattern: /^[A-Z]{2}$/ });
  try {
    const [r] = await t.savepoint((s) => s`select * from app.identity_link(${p}, ${s.array(fps)}::text[], ${kv}::smallint, ${lv}::smallint,
      ${recheck}::timestamptz, ${sh}, ${rg})`);
    return { memberId: r.member_id, trustLevel: r.trust_level, isAdmin: r.is_admin, linked: r.linked, sessionsEnded: r.sessions_ended };
  } catch (e) {
    if (e.code === 'P0001' && e.message === 'fresh_sign_in') return { refused: 'fresh' };
    if (e.code === 'P0001' && ['taken', 'banned', 'disabled'].includes(e.message)) return { refused: e.message };
    // Two members linking the same method at the same moment: whoever comes second finds it taken (review F4).
    if (e.code === '23505') return { refused: 'taken' };
    if (BUSY.includes(e.code)) return { refused: 'busy' };
    throw e;
  }
}

// PR 15: the signed-in member removes one of their sign-in methods (by its ID, from their account page), from their
// own session begun in the last 10 minutes. Never the last one, and (review F1, seniority) only a method added after
// the one this session signed in with. What the method's sessions did goes with it (the second review, R1).
// Returns { provider, trustLevel, sessionsEnded, alsoUnlinked, keysRevoked, agentsLowered }, or
// { refused: 'fresh' | 'not_found' | 'last' | 'senior' | 'busy' }.
async function unlink(t, { identity, sessionHash }) {
  let id;
  try { id = v.uuid('identity', identity); } catch { return { refused: 'not_found' }; }
  const sh = hex('sessionHash', sessionHash);
  try {
    const [r] = await t.savepoint((s) => s`select * from app.identity_unlink(${id}::uuid, ${sh})`);
    return { provider: r.provider, trustLevel: r.trust_level, sessionsEnded: r.sessions_ended, alsoUnlinked: r.also_unlinked,
      keysRevoked: r.keys_revoked, agentsLowered: r.agents_lowered };
  } catch (e) {
    if (e.code === 'P0001' && e.message === 'fresh_sign_in') return { refused: 'fresh' };
    if (e.code === 'P0001' && e.message === 'not_found') return { refused: 'not_found' };
    if (e.code === 'P0001' && e.message === 'last_method') return { refused: 'last' };
    if (e.code === 'P0001' && e.message === 'not_senior') return { refused: 'senior' };
    if (BUSY.includes(e.code)) return { refused: 'busy' };
    throw e;
  }
}

// PR 15's review (F6): true the first time a traveller's sealed confirmation (by its nonce's SHA-256) is used.
async function regionConfirmUse(t, tokenHash) {
  const [r] = await t`select app.region_confirm_use(${hex('tokenHash', tokenHash)}) as ok`;
  return r.ok === true;
}

// Whether a sign-in method already belongs to an account. Ask only after the provider (or an emailed link) has
// confirmed who the person is, so the answer reaches nobody but the account holder.
async function known(t, { provider, fingerprints }) {
  const fps = fingerprints.map((f) => hex('fingerprint', f));
  if (fps.length < 1 || fps.length > 5) throw new v.ValidationError('fingerprints', 'must have 1 to 5 entries');
  const [r] = await t`select app.sign_in_known(${v.oneOf('provider', provider, ['github', 'x', 'email', 'linkedin'])}, ${t.array(fps)}::text[]) as known`;
  return r.known === true;
}

async function sessionResolve(t, sessionHash, idleDays) {
  if (typeof sessionHash !== 'string' || !HEX64.test(sessionHash)) return null;
  const days = v.int('idleDays', idleDays, { min: 1, max: 30 });
  // A page read must never fail on a race (PR 15's re-review, probe H): a deadlock, serialization failure or lock it
  // couldn't get is retried, each in its own savepoint, after a short random wait. If every try loses, this one
  // request is treated as not signed in (the cookie is kept, and the next request tries again), never an error page.
  let r;
  for (let attempt = 1; ; attempt++) {
    try {
      [r] = await t.savepoint((s) => s`select * from app.session_resolve(${sessionHash}, ${days}::integer)`);
      break;
    } catch (e) {
      if (!BUSY.includes(e.code)) throw e;
      if (attempt >= RESOLVE_TRIES) return null;
      await new Promise((ok) => setTimeout(ok, 10 + Math.floor(Math.random() * 40)));
    }
  }
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
  const ids = await t`select id, provider, level, verified_at from app.identities where member_id = app.current_member() order by created_at`;
  const [s] = await t`select count(*)::int as n from app.sessions where member_id = app.current_member()`;
  // A deletion JEVs flagged as high risk, waiting for Aaron (PR 12).
  const [r] = await t`select created_at from app.deletion_reviews where member_id = app.current_member() and decision is null`;
  return { memberId: m.id, displayName: m.display_name, trustLevel: m.trust_level, joined: m.created_at,
    signIns: ids.map((i) => ({ id: i.id, provider: i.provider, level: i.level, verifiedAt: i.verified_at })), sessions: s.n,
    deletionReview: r ? { since: r.created_at, disablesAt: new Date(new Date(r.created_at).getTime() + 24 * 3600 * 1000) } : null };
}

// A member renames themselves (1 to 80 characters, one line).
async function rename(t, name) {
  const n = v.text('name', name, { max: 80 });
  const r = await t`update app.members set display_name = ${n} where id = app.current_member()`;
  return r.count === 1;
}

// F8: deletes the signed-in member's account and everything about them (007_account_deletion.sql). Returns the counts,
// or { refused: 'not_member' | 'not_active' | 'fresh' | 'under_review' } ('fresh': the session didn't start recently
// enough, RK3; 'under_review': JEVs flagged an earlier request and Aaron hasn't decided yet, PR 12).
async function deleteAccount(t) {
  try {
    const [r] = await t.savepoint((s) => s`select * from app.delete_account()`);
    return { posts: r.posts, reports: r.reports, agents: r.agents, keys: r.keys, sessions: r.sessions, identities: r.identities };
  } catch (e) {
    if (e.code === '42501' && (e.message === 'not_member' || e.message === 'not_active')) return { refused: e.message };
    if (e.code === 'P0001' && e.message === 'fresh_sign_in') return { refused: 'fresh' };
    if (e.code === 'P0001' && e.message === 'under_review') return { refused: 'under_review' };
    throw e;
  }
}

module.exports = { rateLimitHit, emailTokenIssue, emailTokenRedeem, signIn, link, unlink, regionConfirmUse, known, sessionResolve, sessionEnd, sessionsEndAll, account, rename, deleteAccount };
