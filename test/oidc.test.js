// USE-CASES.md row 16: the GitHub identity-token check that guards the database runner (and, from PR 3, the JEVs
// gate) refuses every token that isn't from our own workflow on main, freshly made and signed by GitHub.
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { subtle } = globalThis.crypto;
const enc = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');

async function setup() {
  const oidc = await import('../supabase/functions/_shared/github-oidc.mjs');
  const pair = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const other = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await subtle.exportKey('jwk', pair.publicKey)), kid: 'k1' };
  const keys = async () => [jwk];
  const now = 1_800_000_000;
  const good = {
    iss: oidc.ISSUER, aud: 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-migrate',
    exp: now + 300, iat: now - 5, nbf: now - 5,
    repository_id: '1418125608', repository_owner_id: '304218593', repository: 'MyChiefOS/start-of-something-great',
    ref: 'refs/heads/main', event_name: 'push', sha: 'a'.repeat(40), jti: 'token-1', run_id: '1', actor: 'MyChiefOS',
    workflow_ref: 'MyChiefOS/start-of-something-great/.github/workflows/database.yml@refs/heads/main'
  };
  async function sign(claims, { header = { alg: 'RS256', kid: 'k1', typ: 'JWT' }, key = pair.privateKey } = {}) {
    const body = enc(header) + '.' + enc(claims);
    const sig = await subtle.sign('RSASSA-PKCS1-v1_5', key, Buffer.from(body));
    return body + '.' + Buffer.from(sig).toString('base64url');
  }
  const opts = { audience: good.aud, workflow: '.github/workflows/database.yml', events: ['push', 'workflow_dispatch'], now, keys };
  return { oidc, sign, good, opts, other };
}

test('row 16: a token from our database workflow on main is accepted, and its commit is returned', async () => {
  const { oidc, sign, good, opts } = await setup();
  const claims = await oidc.verify(await sign(good), opts);
  assert.strictEqual(claims.sha, good.sha);
});

test('row 16: forged, expired, wrong-branch, wrong-workflow, fork, oversized and replayed tokens are all refused', async () => {
  const { oidc, sign, good, opts, other } = await setup();
  const cases = [
    ['signed by another key', await sign(good, { key: other.privateKey }), /signature/],
    ['unknown key ID', await sign(good, { header: { alg: 'RS256', kid: 'nope' } }), /unknown key/],
    ['no signature (alg none)', enc({ alg: 'none', kid: 'k1' }) + '.' + enc(good) + '.', /signed token|signature type/],
    ['HS256', await sign(good, { header: { alg: 'HS256', kid: 'k1' } }), /signature type/],
    ['payload edited after signing', await (async () => { const t = (await sign(good)).split('.'); t[1] = enc({ ...good, ref: 'refs/heads/main', sha: 'b'.repeat(40) }); return t.join('.'); })(), /signature/],
    ['another issuer', await sign({ ...good, iss: 'https://evil.example' }), /issuer/],
    ['another audience', await sign({ ...good, aud: 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/jevs' }), /audience/],
    ['expired', await sign({ ...good, exp: opts.now - 120 }), /expired/],
    ['made long ago', await sign({ ...good, iat: opts.now - 3600 }), /too old/],
    ['made in the future', await sign({ ...good, iat: opts.now + 3600 }), /future/],
    ['a fork', await sign({ ...good, repository_id: '999', repository: 'someone/start-of-something-great', workflow_ref: 'someone/start-of-something-great/.github/workflows/database.yml@refs/heads/main' }), /repository/],
    ['another owner', await sign({ ...good, repository_owner_id: '1' }), /owner/],
    ['a pull request', await sign({ ...good, ref: 'refs/pull/38/merge', event_name: 'pull_request' }), /main branch/],
    ['another branch', await sign({ ...good, ref: 'refs/heads/jevs-gateway' }), /main branch/],
    ['another workflow on main', await sign({ ...good, workflow_ref: 'MyChiefOS/start-of-something-great/.github/workflows/checks.yml@refs/heads/main' }), /workflow/],
    ['our workflow from another branch', await sign({ ...good, workflow_ref: 'MyChiefOS/start-of-something-great/.github/workflows/database.yml@refs/heads/x' }), /workflow/],
    ['another event', await sign({ ...good, event_name: 'schedule' }), /event/],
    ['no commit', await sign({ ...good, sha: undefined }), /commit/],
    ['oversized', 'a'.repeat(9000), /too large/],
    ['empty', '', /missing/],
    ['garbage', 'not.a.token!', /signed token/]
  ];
  for (const [name, token, why] of cases) {
    await assert.rejects(oidc.verify(token, opts), (e) => e instanceof oidc.Refused && why.test(e.message), name);
  }
  await assert.rejects(oidc.verify(await sign(good), { ...opts, seen: async () => true }), /already used/, 'replayed');
});
