// Builds the raw email (RFC 5322 with MIME) that SES sends as is. Plain text only, UTF-8, base64 body. Every header
// value is checked here: line breaks and other control characters are refused, so nothing a member or an agent wrote
// can add a header (header injection). One-click unsubscribe follows RFC 8058: a List-Unsubscribe https address and
// List-Unsubscribe-Post: List-Unsubscribe=One-Click.
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

// RFC 2047: ASCII as is; anything else as UTF-8 base64 encoded-words of at most 75 characters each.
function word(s) {
  const v = headerValue('text', s);
  if (/^[\x20-\x7e]*$/.test(v)) return /[",:;<>@()[\]\\]/.test(v) ? '"' + v.replace(/(["\\])/g, '\\$1') + '"' : v;
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

// { from, to, replyTo?, subject, text, unsubscribe?: https url, date?: Date, id? } -> the raw message as a string.
function build({ from, to, replyTo, subject, text, unsubscribe, date = new Date(), domain = 'dayonegreat.com' }) {
  const f = mailbox(from);
  const t = mailbox(to);
  const headers = [
    ['From', f.header],
    ['To', t.header],
    ['Subject', word(subject)],
    ['Date', date.toUTCString().replace('GMT', '+0000')],
    ['Message-ID', '<' + crypto.randomUUID() + '@' + domain + '>'],
    ['MIME-Version', '1.0'],
    ['Content-Type', 'text/plain; charset=UTF-8'],
    ['Content-Transfer-Encoding', 'base64'],
    // Our own notices, not a list anyone else can post to; mail clients use this to file and to offer "unsubscribe".
    ['Auto-Submitted', 'auto-generated']
  ];
  if (replyTo) headers.push(['Reply-To', mailbox(replyTo).header]);
  if (unsubscribe) {
    const u = new URL(unsubscribe);
    if (u.protocol !== 'https:') throw new Error('one-click unsubscribe needs an https address (RFC 8058)');
    headers.push(['List-Unsubscribe', '<' + headerValue('List-Unsubscribe', u.toString()) + '>']);
    headers.push(['List-Unsubscribe-Post', 'List-Unsubscribe=One-Click']);
  }
  const body = String(text).replace(/\r?\n/g, '\r\n');
  return headers.map(([k, v]) => k + ': ' + headerValue(k, v)).join('\r\n') + '\r\n\r\n' + lines76(Buffer.from(body, 'utf8').toString('base64'));
}

// Reads a raw message back (tests and the log transport): its headers and the decoded text.
function parse(raw) {
  const i = raw.indexOf('\r\n\r\n');
  const head = raw.slice(0, i).split('\r\n');
  const headers = {};
  for (const l of head) { const k = l.slice(0, l.indexOf(':')); headers[k.toLowerCase()] = l.slice(k.length + 2); }
  return { headers, text: Buffer.from(raw.slice(i + 4).replace(/\r\n/g, ''), 'base64').toString('utf8') };
}

module.exports = { build, parse, mailbox, word, ADDRESS };
