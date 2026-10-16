// How an email leaves the site. One interface, two transports:
//   log: the default, for tests and previews. It sends nothing; it keeps the last messages in memory (for tests)
//        and logs one line per email with no address and no words in it.
//   ses: Amazon SES v2 SendEmail over HTTPS (POST /v2/email/outbound-emails), signed with SigV4 (./sigv4.js). The raw
//        message is ours (./mime.js), so the one-click unsubscribe headers are exactly what we wrote.
// send({ from, to, raw }) answers { ok: true, id } or { ok: false, retry, error }: retry is true only when the email
// certainly didn't go (throttled, a server error, no connection). A timeout is not retried, because SES may have
// sent it; the in-app notice is the copy that always arrives.
'use strict';

const { sign } = require('./sigv4');

const TIMEOUT_MS = 8000;

function logTransport({ keep = 50, log = console.log } = {}) {
  const sent = [];
  return {
    name: 'log',
    sent,
    async send({ raw }) {
      const id = 'log-' + Date.now().toString(36) + '-' + sent.length;
      sent.push({ id, raw });
      if (sent.length > keep) sent.shift();
      // No address and no words: this is a log line, and logs are kept by the host.
      log('email (log transport, not sent): ' + id + ', ' + Buffer.byteLength(raw) + ' bytes');
      return { ok: true, id };
    }
  };
}

// Errors SES returns that mean "try again later" rather than "this email will never go".
const RETRY_TYPES = /TooManyRequests|LimitExceeded|Throttling|ServiceUnavailable|InternalFailure/i;

function sesTransport({ region, accessKeyId, secretAccessKey, configurationSet = null, endpoint = null, fetchImpl = fetch, now = () => new Date() }) {
  if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(region || '')) throw new Error('SES_REGION must be an AWS region such as us-east-1');
  if (!accessKeyId || !secretAccessKey) throw new Error('SES needs SES_ACCESS_KEY_ID and SES_SECRET_ACCESS_KEY');
  const base = endpoint || 'https://email.' + region + '.amazonaws.com';
  const u = new URL(base);
  // Tests point this at a local fake server; anywhere else it must be HTTPS.
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost'))) {
    throw new Error('the SES endpoint must be HTTPS');
  }
  const url = base.replace(/\/$/, '') + '/v2/email/outbound-emails';
  return {
    name: 'ses',
    async send({ from, to, raw }) {
      const payload = { FromEmailAddress: from, Destination: { ToAddresses: [to] }, Content: { Raw: { Data: Buffer.from(raw, 'utf8').toString('base64') } } };
      if (configurationSet) payload.ConfigurationSetName = configurationSet;
      const body = JSON.stringify(payload);
      const signed = sign({ method: 'POST', url, headers: { 'content-type': 'application/json' }, body },
        { accessKeyId, secretAccessKey }, { region, service: 'ses', date: now() });
      const headers = { ...signed.headers };
      // fetch sets Host itself from the address.
      delete headers.host;
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
      let r;
      try {
        r = await fetchImpl(url, { method: 'POST', headers, body, signal: ctl.signal, redirect: 'error' });
      } catch (e) {
        return { ok: false, retry: !(e && e.name === 'AbortError'), error: e && e.name === 'AbortError' ? 'timeout' : 'network' };
      } finally {
        clearTimeout(timer);
      }
      let json = null;
      try { json = JSON.parse(await r.text()); } catch { /* not JSON */ }
      if (r.ok && json && typeof json.MessageId === 'string') return { ok: true, id: json.MessageId.slice(0, 200) };
      const type = String((r.headers && r.headers.get && r.headers.get('x-amzn-errortype')) || (json && (json.__type || json.code)) || '').split(':')[0];
      const retry = r.status === 429 || r.status >= 500 || RETRY_TYPES.test(type);
      return { ok: false, retry, error: ('ses_' + r.status + (type ? '_' + type.replace(/[^A-Za-z]/g, '') : '')).slice(0, 200) };
    }
  };
}

module.exports = { logTransport, sesTransport, TIMEOUT_MS };
