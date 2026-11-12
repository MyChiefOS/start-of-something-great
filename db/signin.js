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
      if (e.code === 'P0001' && ['banned', 'disabled', 'taken', 'region', 'admin_code_only', 'locked'].includes(e.message)) return { refused: e.message };
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

async function sessionResolve(t, sessionHash, idleDays, { strict = false } = {}) {
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
      if (attempt >= RESOLVE_TRIES) {
        // strict (sign out everywhere): a lost race must never pass for "not signed in", or the button an owner
        // presses after a takeover would quietly end only this browser (PR 15's final re-review, probe J).
        if (strict) { const err = new Error('the session read lost a race; try again'); err.code = 'SESSION_BUSY'; throw err; }
        return null;
      }
      await new Promise((ok) => setTimeout(ok, require('crypto').randomInt(10, 50)));
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
  // The key file goes too (Aaron, Oct 28), and since 037 every browser key: the member starts again with a new code,
  // back in the same account.
  await t`select app.file_key_revoke()`;
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
// { held: true } (060): the account is under a legal hold, so it was closed and hidden and nothing was deleted; the
// database answers a row of nulls.
async function deleteAccount(t) {
  try {
    const [r] = await t.savepoint((s) => s`select * from app.delete_account()`);
    if (r && r.posts === null && r.identities === null) return { held: true };
    return { posts: r.posts, reports: r.reports, agents: r.agents, keys: r.keys, sessions: r.sessions, identities: r.identities };
  } catch (e) {
    if (e.code === '42501' && (e.message === 'not_member' || e.message === 'not_active')) return { refused: e.message };
    if (e.code === 'P0001' && e.message === 'fresh_sign_in') return { refused: 'fresh' };
    if (e.code === 'P0001' && e.message === 'under_review') return { refused: 'under_review' };
    throw e;
  }
}

// Signing in with a code posted through giscus (023; Aaron, Oct 28). A new code for one browser (only keyed hashes).
async function codeIssue(t, { codeHash, browserHash, loginHash, fileKey }) {
  await t`select app.code_issue(${hex('codeHash', codeHash)}, ${hex('browserHash', browserHash)}, ${hex('loginHash', loginHash)},
    ${hex('fileKey', fileKey)})`;
}

// 037 (Aaron, Nov 5, 2026): a browser key and a PIN at the end of every way in. Byte strings go to the database as
// bytea; the database checks the browser's signature itself (app.p256_verify) and the PIN (keyed, salted).
const bytes = (field, b, len) => {
  if (!Buffer.isBuffer(b) || b.length !== len) throw new v.ValidationError(field, 'must be ' + len + ' bytes');
  return b;
};
const PIN = /^[0-9]{6}$/;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const ORIGIN_RE = /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/;
const LABEL = /^[A-Za-z ]{3,40}$/;
const pin = (p) => v.text('pin', p, { min: 6, max: 6, pattern: PIN });
const proof = ({ challenge, origin, signature }) => ({
  challenge: v.text('challenge', challenge, { min: 43, max: 43, pattern: CHALLENGE }),
  origin: v.text('origin', origin, { max: 100, pattern: ORIGIN_RE }),
  signature: bytes('signature', signature, 64)
});
const region = (r) => (r === null ? null : v.text('region', r, { min: 2, max: 2, pattern: /^[A-Z]{2}$/ }));
const REFUSALS = ['banned', 'disabled', 'taken', 'region', 'locked'];
// Since the review of 037 (L1) a refusal by the sign-in itself comes back as a status, not an error, so the challenge
// stays used up: it reads { refused } as before.
const out = (r) => (REFUSALS.includes(r.status) ? { refused: r.status }
  : r.status !== 'ok' ? { status: r.status, triesLeft: r.tries_left === undefined ? null : r.tries_left, waitSeconds: r.wait_seconds === undefined ? null : r.wait_seconds }
  : { status: 'ok', memberId: r.member_id, isNew: r.is_new, trustLevel: r.trust_level, isAdmin: r.is_admin, keyId: r.key_id || null });

// A one-time challenge for this site's address, good for 2 minutes.
async function challengeIssue(t, origin) {
  const [r] = await t`select app.signin_challenge(${v.text('origin', origin, { max: 100, pattern: ORIGIN_RE })}) as c`;
  return r.c;
}

// Lane 1's waiting step: { status: 'waiting' | 'claimed' | 'expired', secondsLeft, hasPin, browsers } (the last two once
// claimed, for the person's own account).
async function codeStatus(t, browserHash) {
  const [r] = await t`select status, seconds_left, has_pin, browsers from app.code_status(${hex('browserHash', browserHash)})`;
  return { status: r.status, secondsLeft: r.seconds_left, hasPin: r.has_pin === true, browsers: r.browsers || 0 };
}

// The public half of a browser's key, for the site's own check of lane 3's signature (the review of 037, M2), or null.
async function browserKeyPublic(t, keyId) {
  let id;
  try { id = v.uuid('keyId', keyId); } catch { return null; }
  const [r] = await t`select app.browser_key_public(${id}::uuid) as k`;
  return r.k ? Buffer.from(r.k) : null;
}

// Lane 1: the claimed code, then the new PIN and this browser's key. { status: 'ok', ..., keyId } or { status:
// 'waiting' | 'expired' | 'region' | 'weak_pin' | 'bad_proof' }, or { refused }.
async function codeSignInPin(t, { browserHash, displayName, sessionHash, sessionDays, region: rg = null, pin: p, publicKey, label, removeOthers = false, ...pr }) {
  const a = proof(pr);
  const args = [hex('browserHash', browserHash), v.text('displayName', displayName, { max: 80 }), hex('sessionHash', sessionHash),
    v.int('sessionDays', sessionDays, { min: 1, max: 30 }), region(rg), pin(p), bytes('publicKey', publicKey, 65),
    v.text('label', label, { min: 3, max: 40, pattern: LABEL })];
  for (let attempt = 0; ; attempt++) {
    try {
      const [r] = await t.savepoint((s) => s`select * from app.code_sign_in_pin(${args[0]}, ${args[1]}, ${args[2]}, ${args[3]}::integer,
        ${args[4]}, ${args[5]}, ${args[6]}, ${args[7]}, ${a.challenge}, ${a.origin}, ${a.signature}, ${removeOthers === true})`);
      return out(r);
    } catch (e) {
      if (e.code === 'P0001' && REFUSALS.includes(e.message)) return { refused: e.message };
      if (e.code === '23505' && attempt === 0) continue;
      throw e;
    }
  }
}

// Lane 2: the key file and the PIN, adding this browser. { status: 'ok', ..., keyId } or { status: 'no_match' |
// 'start_again' | 'wrong_pin' (triesLeft) | 'weak_pin' | 'bad_proof' }, or { refused }.
async function fileSignInPin(t, { loginHash, keyHash, displayName, sessionHash, sessionDays, region: rg = null, pin: p, pinAgain = null, publicKey, label, ...pr }) {
  const a = proof(pr);
  const args = [hex('loginHash', loginHash), hex('keyHash', keyHash), v.text('displayName', displayName, { max: 80 }), hex('sessionHash', sessionHash),
    v.int('sessionDays', sessionDays, { min: 1, max: 30 }), region(rg), pin(p), bytes('publicKey', publicKey, 65),
    v.text('label', label, { min: 3, max: 40, pattern: LABEL })];
  try {
    const [r] = await t.savepoint((x) => x`select * from app.file_sign_in_pin(${args[0]}, ${args[1]}, ${args[2]}, ${args[3]},
      ${args[4]}::integer, ${args[5]}, ${args[6]}, ${args[7]}, ${args[8]}, ${a.challenge}, ${a.origin}, ${a.signature},
      ${typeof pinAgain === 'string' && PIN.test(pinAgain) ? pinAgain : null})`);
    return out(r);
  } catch (e) {
    if (e.code === 'P0001' && REFUSALS.includes(e.message)) return { refused: e.message };
    throw e;
  }
}

// Lane 3: this browser's key and the PIN. { status: 'ok', ... } or { status: 'no_key' | 'wrong_pin' (triesLeft) |
// 'cancelled' | 'bad_proof' }, or { refused }.
async function browserSignIn(t, { keyId, displayName, sessionHash, sessionDays, region: rg = null, pin: p, ...pr }) {
  const a = proof(pr);
  const args = [v.uuid('keyId', keyId), v.text('displayName', displayName, { max: 80 }), hex('sessionHash', sessionHash),
    v.int('sessionDays', sessionDays, { min: 1, max: 30 }), region(rg), pin(p)];
  try {
    const [r] = await t.savepoint((x) => x`select * from app.browser_sign_in(${args[0]}::uuid, ${args[1]}, ${args[2]}, ${args[3]}::integer,
      ${args[4]}, ${args[5]}, ${a.challenge}, ${a.origin}, ${a.signature})`);
    return out(r);
  } catch (e) {
    if (e.code === 'P0001' && REFUSALS.includes(e.message)) return { refused: e.message };
    throw e;
  }
}

// 063, the buyer door (Aaron, Nov 11): a WebAuthn buyer key, checked again by the database itself. Byte lengths are
// checked here first; the database decides.
const between = (field, b, min, max) => {
  if (!Buffer.isBuffer(b) || b.length < min || b.length > max) throw new v.ValidationError(field, 'must be ' + min + ' to ' + max + ' bytes');
  return b;
};
async function buyerKeyPublic(t, credentialId) {
  if (!Buffer.isBuffer(credentialId) || credentialId.length < 16 || credentialId.length > 1023) return null;
  const [r] = await t`select app.buyer_key_public(${credentialId}) as k`;
  return r.k ? Buffer.from(r.k) : null;
}
// { status: 'ok', memberId, isNew, ... } or { status: 'bad_key' | 'bad_proof' | 'no_key' }, or { refused }.
async function buyerRegister(t, { credentialId, publicKey, clientData, authData, displayName, sessionHash, sessionDays }) {
  const args = [between('credentialId', credentialId, 16, 1023), bytes('publicKey', publicKey, 65), between('clientData', clientData, 50, 2048),
    between('authData', authData, 37, 4096), v.text('displayName', displayName, { max: 80 }), hex('sessionHash', sessionHash),
    v.int('sessionDays', sessionDays, { min: 1, max: 30 })];
  const [r] = await t.savepoint((x) => x`select * from app.buyer_register(${args[0]}, ${args[1]}, ${args[2]}, ${args[3]}, ${args[4]}, ${args[5]}, ${args[6]}::integer)`);
  return out(r);
}
// 065: a signed-in buyer's backup key ('ok', 'fresh', 'full', 'bad_proof', 'taken' or 'not_buyer').
async function buyerKeyBackup(t, { credentialId, publicKey, clientData, authData, sessionHash }) {
  const args = [between('credentialId', credentialId, 16, 1023), bytes('publicKey', publicKey, 65), between('clientData', clientData, 50, 2048),
    between('authData', authData, 37, 4096), hex('sessionHash', sessionHash)];
  const [r] = await t.savepoint((x) => x`select app.buyer_key_backup(${args[0]}, ${args[1]}, ${args[2]}, ${args[3]}, ${args[4]}) as s`);
  return r.s;
}
async function buyerSignIn(t, { credentialId, clientData, authData, signature, displayName, sessionHash, sessionDays, region: rg = null }) {
  const args = [between('credentialId', credentialId, 16, 1023), between('clientData', clientData, 50, 2048), between('authData', authData, 37, 4096),
    bytes('signature', signature, 64), v.text('displayName', displayName, { max: 80 }), hex('sessionHash', sessionHash),
    v.int('sessionDays', sessionDays, { min: 1, max: 30 }), region(rg)];
  const [r] = await t.savepoint((x) => x`select * from app.buyer_sign_in(${args[0]}, ${args[1]}, ${args[2]}, ${args[3]}, ${args[4]}, ${args[5]}, ${args[6]}::integer, ${args[7]})`);
  return out(r);
}

// The account page, as the signed-in member: { pin: { set_at } | null, key_file: { created_at, used_at } | null,
// browsers: [{ id, label, created_at, used_at }] }.
async function signinMethods(t) {
  const [r] = await t`select app.signin_methods() as m`;
  return r.m || { pin: null, key_file: null, browsers: [] };
}
async function browserKeyRemove(t, keyId) {
  let id;
  try { id = v.uuid('keyId', keyId); } catch { return false; }
  const [r] = await t`select app.browser_key_remove(${id}::uuid) as ok`;
  return r.ok === true;
}
// { status: 'ok' | 'wrong_pin' (tries_left) | 'weak_pin' | 'no_pin' | 'signed_out' }.
async function pinChange(t, { current, next }) {
  const cur = typeof current === 'string' && PIN.test(current) ? current : '';
  const nxt = typeof next === 'string' && PIN.test(next) ? next : '';
  const [r] = await t`select app.pin_change(${cur}, ${nxt}) as out`;
  return r.out;
}

// The JEVs behaviour watch (026): after a sign-in, as the member just signed in. country and net are the site's keyed
// hashes of the request's country and network, or null. Alerts only; never refuses.
async function watchSignin(t, { country = null, net = null }) {
  const opt = (field, x) => (x === null ? null : hex(field, x));
  const [r] = await t`select app.watch_signin(${opt('country', country)}, ${opt('net', net)}) as out`;
  return r.out;
}
// A signed-in member who isn't the administrator asking for an administrator's page ('review' or 'controls').
async function watchReach(t, what) {
  const [r] = await t`select app.watch_reach(${v.text('what', what, { max: 20, pattern: /^(review|controls)$/ })}) as alerted`;
  return r.alerted === true;
}

// The behaviour watch's web indicators (030), at a signed-in request (signin/watch.js). ua and country: the site's keyed
// hashes, or null. Returns { alerts, place? }: place.sealed is the account's latest sealed place when a comparison is due.
async function watchSession(t, { sessionHash, ua = null, country = null }) {
  const opt = (field, x) => (x === null ? null : hex(field, x));
  const [r] = await t`select app.watch_session(${hex('sessionHash', sessionHash)}, ${opt('ua', ua)}, ${opt('country', country)}) as out`;
  return r.out;
}
const SEALED = /^[A-Za-z0-9_-]{40,200}$/;
async function watchTravel(t, { sessionHash, place = null, km = null, prev = null }) {
  const sealed = (field, x) => (x === null ? null : v.text(field, x, { min: 40, max: 200, pattern: SEALED }));
  const [r] = await t`select app.watch_travel(${hex('sessionHash', sessionHash)}, ${sealed('place', place)},
    ${km === null ? null : v.int('km', km, { min: 0, max: 25000 })}::integer, ${sealed('prev', prev)}) as alerted`;
  return r.alerted === true;
}

module.exports = { watchSignin, watchReach, watchSession, watchTravel, codeIssue, challengeIssue, codeStatus, codeSignInPin, fileSignInPin,
  browserSignIn, browserKeyPublic, buyerKeyPublic, buyerRegister, buyerSignIn, buyerKeyBackup, signinMethods, browserKeyRemove, pinChange, rateLimitHit, emailTokenIssue, emailTokenRedeem, signIn, link, unlink, regionConfirmUse, known, sessionResolve, sessionEnd, sessionsEndAll, account, rename, deleteAccount };
