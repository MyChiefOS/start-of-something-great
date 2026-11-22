// Idempotency keys (071; Fable's review of Nov 21: a retried claim lost its one-time code). A sender puts
// "Idempotency-Key: <8 to 128 characters>" on a write. The key never leaves this request readable: the database holds
// only a hash of it with who sent it (so one agent's key can't touch another's), a hash of the request, and the answer
// sealed under the key (AES-256-GCM), so even a one-time claim code in the answer can only be read by the sender.
'use strict';

const crypto = require('crypto');

// 32 characters at least (the fresh review, M3): the scope and the seal are hashes of who sent it and the key, and the
// first is public, so a short key could be guessed offline by someone who could read the table.
const KEY = /^[A-Za-z0-9._~:-]{32,128}$/;
const who = (ctx) => (ctx.agentId ? 'agent:' + ctx.agentId : 'member:' + ctx.memberId);

function fromRequest(req) {
  const h = req.headers && (req.headers['idempotency-key'] || req.headers['Idempotency-Key']);
  if (h === undefined || h === null || h === '') return { key: null };
  const k = String(Array.isArray(h) ? h[0] : h).replace(/^"|"$/g, '');
  return KEY.test(k) ? { key: k } : { bad: 'Idempotency-Key is 32 to 128 letters, digits or ._~:- characters: use a random value, such as a UUID without its dashes.' };
}
const scope = (key, ctx) => crypto.createHash('sha256').update('dog idem scope ' + who(ctx) + ' ' + key).digest('hex');
// The request's own words, in a fixed order, so the same request always hashes the same.
const canon = (v) => (Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}' : JSON.stringify(v));
const requestHash = (route, body) => crypto.createHash('sha256').update(route + ' ' + canon(body)).digest('hex');
const sealKey = (key, ctx) => crypto.createHash('sha256').update('dog idem seal ' + who(ctx) + ' ' + key).digest();
function seal(key, ctx, value) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', sealKey(key, ctx), iv, { authTagLength: 16 });
  const body = Buffer.concat([c.update(JSON.stringify(value), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]);
}
function unseal(key, ctx, buf) {
  const d = crypto.createDecipheriv('aes-256-gcm', sealKey(key, ctx), buf.subarray(0, 12), { authTagLength: 16 });
  d.setAuthTag(buf.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8'));
}

const MAX_SEALED = 65536;
module.exports = { MAX_SEALED, fromRequest, scope, requestHash, seal, unseal, KEY };
