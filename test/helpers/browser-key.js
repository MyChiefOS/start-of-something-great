// A stand-in for a browser's sign-in key (037): an ECDSA P-256 key pair, as Web Crypto makes it on /join, and its
// signature over a one-time challenge and the site's address, in the shape /join sends (base64url, r || s).
'use strict';

const crypto = require('crypto');
const c = require('../../signin/crypto');

// A PIN no rule refuses (not a repeat, a run or a pattern), used wherever a test doesn't care which PIN it is.
const PIN = '135792';
const LABEL = 'Firefox on Linux';

function make() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  return {
    raw,
    pub: raw.toString('base64url'),
    sign: (msg) => crypto.sign('sha256', msg, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')
  };
}

// The fields a sign-in sends with its proof: the challenge and the signature over it with this origin.
function proof(key, challenge, origin = 'https://dayonegreat.com') {
  return { challenge, sig: key.sign(c.signinMessage(origin, challenge)) };
}

module.exports = { make, proof, PIN, LABEL };
