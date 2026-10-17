// Builds the raw email (RFC 5322 with MIME) that SES sends as is: today only sign-in links. Plain text only, UTF-8,
// base64 body. Every header value is checked here: line breaks and other control characters are refused, so nothing
// a visitor typed can add a header (header injection).
'use strict';

const crypto = require('crypto');

const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
const ADDRESS = /^[^\s@<>"(),;:\\[\]]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$/;

function headerValue(name, v) {
  const s = String(v);
  if (CONTROL.test(s)) throw new Error('header ' + name + ' contains control characters');
  if (s.length > 998) throw new Error('header ' + name + ' is too long');
  return s;
}

// A display name and address: "Day One Great <notices@dayonegreat.com>" or a bare address.
function mailbox(s) {
  const v = headerValue('address', s).trim();
  const m = /^(?:(.*?)\s*<([^<>]+)>|([^<>\s]+))$/.exec(v);
  const addr = m && (m[2] || m[3]);
  if (!addr || !ADDRESS.test(addr)) throw new Error('not an email address');
  const name = m[1] ? m[1].replace(/^"|"$/g, '') : '';
  return { address: addr, header: name ? word(name) + ' <' + addr + '>' : addr };
}

// RFC 2047: ASCII as is; anything else as UTF-8 base64 encoded-words of at most 75 characters each. A display name
// (a "phrase") with special characters is quoted; a subject is free text and never is.
function word(s, { phrase = true } = {}) {
  const v = headerValue('text', s);
  const ascii = [...v].every((ch) => ch >= ' ' && ch <= '~');
  if (ascii) {
    const special = [...v].some((ch) => '",:;<>@()[]\\'.includes(ch));
    if (!phrase || !special) return v;
    return '"' + [...v].map((ch) => (ch === '"' || ch === '\\' ? '\\' + ch : ch)).join('') + '"';
  }
  const out = [];
  let chunk = '';
  for (const ch of v) {
    if (Buffer.byteLength(chunk + ch, 'utf8') > 45) { out.push(chunk); chunk = ''; }
    chunk += ch;
  }
  if (chunk) out.push(chunk);
  return out.map((c) => '=?UTF-8?B?' + Buffer.from(c, 'utf8').toString('base64') + '?=').join(' ');
}

const lines76 = (b64) => b64.replace(/.{1,76}/g, '$&\r\n');

// { from, to, replyTo?, subject, text, date?: Date } -> the raw message as a string.
function build({ from, to, replyTo, subject, text, date = new Date(), domain = 'dayonegreat.com' }) {
  const f = mailbox(from);
  const t = mailbox(to);
  const headers = [
    ['From', f.header],
    ['To', t.header],
    ['Subject', word(subject, { phrase: false })],
    ['Date', date.toUTCString().replace('GMT', '+0000')],
    ['Message-ID', '<' + crypto.randomUUID() + '@' + domain + '>'],
    ['MIME-Version', '1.0'],
    ['Content-Type', 'text/plain; charset=UTF-8'],
    ['Content-Transfer-Encoding', 'base64'],
    // Sent by the site itself, so vacation responders don't answer it (RFC 3834).
    ['Auto-Submitted', 'auto-generated']
  ];
  if (replyTo) headers.push(['Reply-To', mailbox(replyTo).header]);
  const body = String(text).replace(/\r?\n/g, '\r\n');
  return headers.map(([k, v]) => k + ': ' + headerValue(k, v)).join('\r\n') + '\r\n\r\n' + lines76(Buffer.from(body, 'utf8').toString('base64'));
}

module.exports = { build };
