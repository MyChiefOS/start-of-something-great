// AWS Signature Version 4 (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html),
// for one kind of request: an HTTPS call to an AWS service with a JSON or form body. Node's own crypto only, no SDK.
// The keys come from environment variables Aaron sets in Vercel; they are passed in here and never logged or returned.
'use strict';

const crypto = require('crypto');

const sha256hex = (data) => crypto.createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data, 'utf8').digest();

// RFC 3986 encoding, as SigV4 wants it: everything but A-Z a-z 0-9 - _ . ~ is percent-encoded.
function encode(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase());
}

// "20150830T123600Z" from a Date.
function amzDate(d) {
  return d.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}

function canonicalQuery(searchParams) {
  const pairs = [];
  for (const [k, v] of searchParams) pairs.push([encode(k), encode(v)]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return pairs.map((p) => p[0] + '=' + p[1]).join('&');
}

// Each path segment encoded once (services other than S3).
function canonicalPath(pathname) {
  return (pathname || '/').split('/').map((seg) => encode(decodeURIComponent(seg))).join('/') || '/';
}

// The signing key for a day, region and service.
// The first key is the literal prefix "AWS4" followed by the secret access key (the SigV4 spec).
const PREFIX = Buffer.from('AWS4', 'utf8');
function signingKey(keyMaterial, day, region, service) {
  const first = Buffer.concat([PREFIX, Buffer.from(String(keyMaterial), 'utf8')]);
  return hmac(hmac(hmac(hmac(first, day), region), service), 'aws4_request');
}

// Signs a request and returns the headers to send: the given ones plus host, x-amz-date and authorization.
//   req: { method, url, headers: { name: value }, body: string | Buffer }
//   creds: { accessKeyId, secretAccessKey, sessionToken? }
function sign(req, creds, { region, service, date = new Date() }) {
  if (!creds || !creds.accessKeyId || !creds.secretAccessKey) throw new Error('signing needs an access key');
  const url = new URL(req.url);
  const stamp = amzDate(date);
  const day = stamp.slice(0, 8);
  const headers = {};
  for (const [k, v] of Object.entries(req.headers || {})) headers[k.toLowerCase()] = String(v).trim().replace(/\s+/g, ' ');
  headers.host = url.host;
  headers['x-amz-date'] = stamp;
  if (creds.sessionToken) headers['x-amz-security-token'] = creds.sessionToken;
  const names = Object.keys(headers).sort();
  const canonical = [
    req.method.toUpperCase(),
    canonicalPath(url.pathname),
    canonicalQuery(url.searchParams),
    names.map((n) => n + ':' + headers[n]).join('\n') + '\n',
    names.join(';'),
    sha256hex(req.body === undefined || req.body === null ? '' : req.body)
  ].join('\n');
  const scope = day + '/' + region + '/' + service + '/aws4_request';
  const toSign = ['AWS4-HMAC-SHA256', stamp, scope, sha256hex(canonical)].join('\n');
  const signature = crypto.createHmac('sha256', signingKey(creds.secretAccessKey, day, region, service)).update(toSign, 'utf8').digest('hex');
  const out = {};
  for (const n of names) out[n] = headers[n];
  out.authorization = 'AWS4-HMAC-SHA256 Credential=' + creds.accessKeyId + '/' + scope + ', SignedHeaders=' + names.join(';') + ', Signature=' + signature;
  return { headers: out, canonical, toSign, signature };
}

module.exports = { sign, encode, amzDate, canonicalQuery, canonicalPath, signingKey };
