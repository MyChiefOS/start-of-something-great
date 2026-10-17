// Test helpers for passkeys (PR 17). No real secrets: every key here is a fresh ES256 pair made for the run.
//   softAuthenticator(): a software passkey that answers WebAuthn the way a phone or laptop does (attestation "none",
//     user presence and verification flags, a sign counter it controls), so tests drive the real checks in
//     @simplewebauthn/server end to end.
//   stepUpFor(su, memberId): for tests about other rules, gives a member a passkey and marks their sessions as having
//     passed a passkey check, straight in the database (the test superuser), as a real check would.
'use strict';

const crypto = require('crypto');
const { isoCBOR } = require('@simplewebauthn/server/helpers');

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

// flags: UP 0x01, UV 0x04, BE 0x08, BS 0x10, AT 0x40.
function authData(rpID, flags, counter, attested) {
  const c = Buffer.alloc(4);
  c.writeUInt32BE(counter >>> 0);
  return Buffer.concat([sha256(Buffer.from(rpID)), Buffer.from([flags]), c, attested || Buffer.alloc(0)]);
}

function softAuthenticator({ uv = true } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = crypto.randomBytes(32);
  const me = {
    id: b64u(credId),
    counter: 0,
    // What the browser would send for navigator.credentials.create(), given the server's options.
    create(options, { origin, rpID = options.rp.id, flags } = {}) {
      const cose = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
      const len = Buffer.alloc(2);
      len.writeUInt16BE(credId.length);
      const attested = Buffer.concat([Buffer.alloc(16), len, credId, Buffer.from(cose)]);
      const ad = authData(rpID, flags !== undefined ? flags : (0x01 | (uv ? 0x04 : 0) | 0x40), me.counter, attested);
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }));
      const att = isoCBOR.encode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', ad]]));
      return { id: me.id, rawId: me.id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {},
        response: { clientDataJSON: b64u(clientData), attestationObject: b64u(att), transports: ['internal', 'hybrid'] } };
    },
    // What the browser would send for navigator.credentials.get(). Each use moves the counter on, unless told not to.
    get(options, { origin, rpID = options.rpId, counter, flags, challenge = options.challenge } = {}) {
      me.counter = counter !== undefined ? counter : me.counter + 1;
      const ad = authData(rpID, flags !== undefined ? flags : (0x01 | (uv ? 0x04 : 0)), me.counter);
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
      const sig = crypto.sign('sha256', Buffer.concat([ad, sha256(clientData)]), privateKey);
      return { id: me.id, rawId: me.id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {},
        response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(ad), signature: b64u(sig) } };
    }
  };
  return me;
}

// A passkey for this member (if they have none) and every session of theirs stepped up for the next hour. su is the
// test's superuser connection; the site itself can never write either.
async function stepUpFor(su, memberId) {
  await su`insert into app.passkeys (member_id, identity_id, credential_id, public_key, label)
    select ${memberId}, i.id, ${b64u(crypto.randomBytes(32))}, ${b64u(crypto.randomBytes(64))}, 'Test passkey'
    from app.identities i where i.member_id = ${memberId}
      and not exists (select 1 from app.passkeys k where k.member_id = ${memberId})
    order by i.created_at limit 1`;
  await su`update app.sessions set stepped_up_at = now() + interval '1 hour' where member_id = ${memberId}`;
}

module.exports = { softAuthenticator, stepUpFor };
