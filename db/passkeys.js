// Database calls for passkeys (PR 17, migration 014). Writes go through the narrow sign-in functions (dog_signin); the
// site's own role can only read the signed-in member's own passkeys and recovery, under row-level security.
'use strict';

const v = require('./validate');

const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const hex = (field, s) => v.text(field, s, { max: 64, min: 64, pattern: HEX64 });
const TRANSPORTS = ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'];
const MAX_PASSKEYS = 10;

// Whether this session passed a passkey check in the last 5 minutes (the database's clock) with a passkey that still
// exists, how many passkeys its member has, when an open recovery's cool-off ends, and, within 24 hours of the oldest
// passkey, when linking a sign-in method opens. Asked as someone not signed in, alongside session_resolve.
async function sessionStepUp(t, sessionHash) {
  if (typeof sessionHash !== 'string' || !HEX64.test(sessionHash)) return null;
  const [r] = await t`select * from app.session_step_up(${sessionHash})`;
  return r ? { stepUp: r.stepped_up === true, passkeys: r.passkeys, recoveryUntil: r.recovery_until, linkingFrom: r.linking_from } : null;
}

// A new challenge (its SHA-256 only) for this session: 'enrol' or 'step_up'. { expiresAt } or { refused: 'session' |
// 'fresh' | 'too_many' }.
async function challenge(t, { sessionHash, purpose, challengeHash }) {
  const [r] = await t`select * from app.passkey_challenge(${hex('sessionHash', sessionHash)}, ${v.oneOf('purpose', purpose, ['enrol', 'step_up'])},
    ${hex('challengeHash', challengeHash)})`;
  return r.status === 'ok' ? { expiresAt: r.expires_at } : { refused: r.status };
}

// Uses a challenge up without doing anything (a signature that didn't check out).
async function dropChallenge(t, { sessionHash, challengeHash }) {
  if (typeof challengeHash !== 'string' || !HEX64.test(challengeHash)) return false;
  const [r] = await t`select app.passkey_challenge_drop(${hex('sessionHash', sessionHash)}, ${challengeHash}) as ok`;
  return r.ok === true;
}

const credId = (s) => v.text('credentialId', s, { min: 16, max: 1366, pattern: B64URL });
function transports(list) {
  if (!Array.isArray(list)) return '';
  return [...new Set(list.filter((x) => TRANSPORTS.includes(x)))].sort().join(',');
}

// Adds a passkey the site has verified. { passkeyId, recoveryCompleted } or { refused: 'session' | 'challenge' |
// 'not_active' | 'fresh' | 'signin_again' | 'cool_off' | 'step_up' | 'too_many' | 'taken' }.
async function enrol(t, { sessionHash, challengeHash, credentialId, publicKey, signCount, transports: tr, label, backedUp }) {
  const [r] = await t`select * from app.passkey_enrol(${hex('sessionHash', sessionHash)}, ${hex('challengeHash', challengeHash)}, ${credId(credentialId)},
    ${v.text('publicKey', publicKey, { min: 16, max: 2048, pattern: B64URL })}, ${v.int('signCount', signCount, { min: 0, max: 4294967295 })}::bigint,
    ${transports(tr)}, ${v.text('label', label, { max: 60 })}, ${backedUp === true})`;
  return r.status === 'ok' ? { passkeyId: r.passkey_id, recoveryCompleted: r.recovery_completed } : { refused: r.status };
}

// A verified passkey check. { until } or { refused: 'session' | 'challenge' | 'unknown' | 'recovery' | 'counter' }.
async function assert(t, { sessionHash, challengeHash, credentialId, signCount, backedUp }) {
  const [r] = await t`select * from app.passkey_assert(${hex('sessionHash', sessionHash)}, ${hex('challengeHash', challengeHash)}, ${credId(credentialId)},
    ${v.int('signCount', signCount, { min: 0, max: 4294967295 })}::bigint, ${backedUp === true})`;
  return r.status === 'ok' ? { until: r.until } : { refused: r.status };
}

// 'ok' or a refusal: 'session' | 'step_up' | 'recovery' | 'not_found' | 'last' | 'senior'.
async function remove(t, { sessionHash, passkey }) {
  let id;
  try { id = v.uuid('passkey', passkey); } catch { return 'not_found'; }
  const [r] = await t`select app.passkey_remove(${hex('sessionHash', sessionHash)}, ${id}::uuid) as status`;
  return r.status;
}

// { endsAt } or { refused: 'session' | 'fresh' | 'not_active' | 'open' | 'no_passkeys' | 'signin_again' }.
async function recoveryStart(t, { sessionHash }) {
  const [r] = await t`select * from app.passkey_recovery_start(${hex('sessionHash', sessionHash)})`;
  return r.status === 'ok' ? { endsAt: r.ends_at } : { refused: r.status };
}

// 'ok', 'none' (nothing open), 'session' or 'senior' (this session signed in with a newer method than the one that
// started it).
async function recoveryCancel(t, { sessionHash }) {
  const [r] = await t`select app.passkey_recovery_cancel(${hex('sessionHash', sessionHash)}) as status`;
  return r.status;
}

// The signed-in member's own passkeys, through their row-level security policy. With keys: true, the public keys and
// counters the site needs to check a signature; the account page never gets those.
async function mine(t, { keys = false } = {}) {
  const rows = await t`select id, credential_id, public_key, sign_count, transports, label, backed_up, created_at, last_used_at, identity_id
    from app.passkeys where member_id = app.current_member() order by created_at`;
  return rows.map((r) => ({ id: r.id, credentialId: r.credential_id, label: r.label, backedUp: r.backed_up, createdAt: r.created_at,
    lastUsedAt: r.last_used_at, identityId: r.identity_id, transports: r.transports ? r.transports.split(',') : [],
    ...(keys ? { publicKey: r.public_key, signCount: Number(r.sign_count) } : {}) }));
}

// Once, at sign-up: a notice offering a passkey before the first risky step (in-app only, like every notice). Returns
// false if it was already left.
async function offer(t) {
  const [r] = await t`select app.notify(app.current_member(), 'passkey_offer', 'Add a passkey',
    'Riskier steps, such as letting an agent act on its own, changing how you sign in or deleting your account, ask you to confirm with a passkey: one tap with your fingerprint, face or device PIN. Add one on your account page.',
    '/account#passkeys', 'member', app.current_member(), 'passkey:offer:' || app.current_member()::text) as ok`;
  return r.ok === true;
}

// The signed-in member's open recovery, if any.
async function recovery(t) {
  const [r] = await t`select id, started_at, ends_at from app.passkey_recoveries
    where member_id = app.current_member() and cancelled_at is null and completed_at is null`;
  return r ? { id: r.id, startedAt: r.started_at, endsAt: r.ends_at } : null;
}

module.exports = { sessionStepUp, challenge, dropChallenge, enrol, assert, remove, recoveryStart, recoveryCancel, mine, recovery, offer, transports, MAX_PASSKEYS, TRANSPORTS };
