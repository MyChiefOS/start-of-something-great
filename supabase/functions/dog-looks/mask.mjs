// What Second and Third Look hide or flag before any text reaches a model (057, RK135 and RK100: the looks moved from
// the site into the dog-looks function). A copy, in plain JavaScript modules for Supabase (Deno) and Node, of the site's
// own masking: maskSecrets from api/_secrets.js, and maskContacts, hasContactInfo and stripHidden from
// api/_proposals.js. test/dog-looks.test.js keeps the copies equal: it runs both on the same texts and fails on any
// difference, so a change to one that isn't made to the other fails the build.
// Characters outside plain ASCII are written as \u{...} escapes (the deploy tool turns \uXXXX into the character itself,
// as supabase/functions/jevs/core.mjs notes), and a test keeps this file ASCII-only.

// ---- Keys and passwords (api/_secrets.js) ----
const B = '(?<![A-Za-z0-9_-])'; // not inside a longer token
const E = '(?![A-Za-z0-9_-])';
const FORMATS = [
  ['dayonegreat-agent-key', B + 'dogk_[A-Za-z0-9_-]{43}' + E],
  ['dayonegreat-recovery-key', B + 'dogr_[A-Za-z0-9_-]{43}' + E],
  ['github-token', B + 'gh[pousr]_[A-Za-z0-9]{36,255}' + E],
  ['github-fine-grained', B + 'github_pat_[A-Za-z0-9_]{82,255}' + E],
  ['aws-access-key-id', '(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}(?![A-Z0-9])'],
  ['anthropic', B + 'sk-ant-[a-z]{3,8}\\d{2}-[A-Za-z0-9_-]{80,200}' + E],
  ['openai', B + 'sk-(?:proj-|svcacct-|admin-)[A-Za-z0-9_-]{40,250}' + E + '|' + B + 'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}' + E],
  ['stripe', B + '(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,250}' + E],
  ['slack', B + 'xox[abposr]-\\d{6,20}-[A-Za-z0-9-]{8,250}' + E + '|' + B + 'xapp-\\d-[A-Z0-9]{6,20}-\\d{6,20}-[A-Za-z0-9]{20,250}' + E],
  ['google-api-key', B + 'AIza[A-Za-z0-9_-]{35}' + E],
  ['supabase-secret', B + 'sb_secret_[A-Za-z0-9_-]{20,250}' + E],
  ['npm', B + 'npm_[A-Za-z0-9]{36}' + E],
  ['sendgrid', B + 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}' + E],
  ['jwt', B + 'eyJ[A-Za-z0-9_-]{8,2000}\\.eyJ[A-Za-z0-9_-]{8,8000}\\.[A-Za-z0-9_-]{16,2000}' + E],
  ['connection-password', '(?<=\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|rediss?|amqps?)://[^\\s:@/]{0,128}:)[^\\s@/]{1,256}(?=@[^\\s/:?#]{1,253})']
];
const RE = new RegExp(FORMATS.map(([, s]) => '(' + s + ')').join('|'), 'g');
const KEY_HIDDEN = '[key hidden]';
const MAX_SECRET_SCAN = 70000;
const PREFIX = /^(?:dog[kr]_|gh[pousr]_|github_pat_|sk-ant-[a-z]{3,8}\d{2}-|sk-(?:proj-|svcacct-|admin-)?|[sr]k_(?:live|test)_|xox[abposr]-|xapp-|AIza|sb_secret_|npm_|SG\.|AKIA|ASIA|ABIA|ACCA)/;
const placeholder = (m) => new Set(m.replace(PREFIX, '')).size < 6;
const PASSWORD_PLACEHOLDER = /^(?:<[^>]*>|\[[^\]]*\]|\{[^}]*\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|password|passwd|pass|pwd|secret|changeme|postgres|root|admin|\*+|x+)$/i;
const LOCAL_HOST = /^@(?:localhost|127\.0\.0\.1|\[?::1\]?)(?![A-Za-z0-9.-])/i;
const JWT_IO_SAMPLE = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';
// base64url to text, as Node's Buffer.from(s, 'base64url').toString('utf8') reads a JWT's middle part.
function base64urlText(s) {
  const b = s.replace(/-/g, '+').replace(/_/g, '/');
  const usable = b.length % 4 === 1 ? b.slice(0, -1) : b; // a lone trailing character carries no whole byte
  const bin = atob(usable + '==='.slice((usable.length + 3) % 4));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}
function publicJwt(m) {
  const body = m.split('.')[1];
  if (body === JWT_IO_SAMPLE) return true;
  try {
    const p = JSON.parse(base64urlText(body));
    return !p || typeof p !== 'object' || p.role === 'anon';
  } catch {
    return true;
  }
}
const PEM_BEGIN = /-----BEGIN (?:[A-Z0-9]{2,10} ){0,2}PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_END = /-----END (?:[A-Z0-9]{2,10} ){0,2}PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_BODY = /^[A-Za-z0-9+/=\s:,-]*$/;
function hidePrivateKeys(raw) {
  if (!raw.includes('PRIVATE KEY')) return { text: raw, hits: 0 };
  const ends = [...raw.matchAll(PEM_END)].map((x) => ({ at: x.index, to: x.index + x[0].length }));
  if (!ends.length) return { text: raw, hits: 0 };
  let out = '', from = 0, hits = 0, e = 0;
  for (const b of raw.matchAll(PEM_BEGIN)) {
    if (b.index < from) continue;
    const bodyAt = b.index + b[0].length;
    while (e < ends.length && ends[e].at < bodyAt) e++;
    if (e === ends.length) break;
    const end = ends[e];
    if (end.at - bodyAt > 8000 || PEM_BODY.exec(raw.slice(bodyAt, end.at)) === null) continue;
    out += raw.slice(from, b.index) + KEY_HIDDEN;
    from = end.to;
    hits++;
  }
  return { text: out + raw.slice(from), hits };
}
export function maskSecrets(text) {
  const raw = String(text == null ? '' : text);
  if (raw.length > MAX_SECRET_SCAN || !/dog[kr]_|gh[pousr]_|github_pat_|A[KSBC][IC]A|sk-|_live_|_test_|xox|xapp-|AIza|sb_secret_|npm_|SG\.|eyJ|PRIVATE KEY|:\/\//.test(raw)) {
    return { text: raw, hits: 0 };
  }
  const pem = hidePrivateKeys(raw);
  let hits = pem.hits;
  const out = pem.text.replace(RE, (m, ...g) => {
    const i = g.slice(0, FORMATS.length).findIndex((x) => x !== undefined);
    const kind = FORMATS[i][0];
    if (m.endsWith('EXAMPLE')) return m;
    if (kind === 'jwt' ? publicJwt(m) : kind === 'connection-password'
      ? PASSWORD_PLACEHOLDER.exec(m) !== null || LOCAL_HOST.exec(g[FORMATS.length + 1].slice(g[FORMATS.length] + m.length, g[FORMATS.length] + m.length + 260)) !== null
      : placeholder(m)) return m;
    hits++;
    return KEY_HIDDEN;
  });
  return { text: out, hits };
}

// ---- Contact details and hidden text (api/_proposals.js) ----
const EMAIL = /(?<![\p{L}\p{M}\p{N}._%+-])[\p{L}\p{M}\p{N}._%+-]{1,64}@[\p{L}\p{M}\p{N}-]{1,63}(?:\.[\p{L}\p{M}\p{N}-]{1,63}){0,8}\.[\p{L}\p{M}]{2,24}/gu;
const PHONE = /\+?\(?\d(?:[\s().\/_|\u{B7}\u{2022}\u{2010}-\u{2015}\u{2212}\p{Cf}\u{34F}\u{FE00}-\u{FE0F}-]{0,8}\d){9,60}/gu;
const DATES_ONLY = /^(?:(?:\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/(?:\d{4}|\d{2}))[\s,.]*)+$/;
const isPhone = (m) => !DATES_ONLY.test(m.replace(/[\p{Cf}\u{34F}\u{FE00}-\u{FE0F}]/gu, '').trim()) && m.replace(/\D/g, '').length >= 10;
const INVISIBLE_RUN = /(?<=[A-Za-z0-9@.+%_()-])[\p{Cf}\u{34F}]+|[\p{Cf}\u{34F}]+(?=[A-Za-z0-9@.+%_()-])/gu;
const VARIATION_IN_TEXT = /(?<=[A-Za-z0-9@.])[\u{FE00}-\u{FE0F}](?!\u{20E3})/gu;
const MAX_SCAN = 70000;
function digitValue(ch) {
  let cp = ch.codePointAt(0), k = 0;
  while (k < 60 && /\p{Nd}/u.test(String.fromCodePoint(cp - 1))) { cp--; k++; }
  return String(k % 10);
}
function fold(text) {
  return String(text == null ? '' : text).slice(0, MAX_SCAN).normalize('NFKC').slice(0, MAX_SCAN)
    .replace(/[^\x00-\x7F]/gu, (ch) => (/\p{Nd}/u.test(ch) ? digitValue(ch) : ch))
    .replace(INVISIBLE_RUN, '').replace(VARIATION_IN_TEXT, '')
    .replace(/[\u{3002}\u{FF61}]/gu, '.');
}
const hasEmail = (t) => new RegExp(EMAIL.source, 'u').test(t);
const hasPhone = (t) => (t.match(PHONE) || []).some(isPhone);
export function hasContactInfo(text) {
  const t = fold(text);
  return hasEmail(t) || hasPhone(t);
}
export function maskContacts(text) {
  const raw = maskSecrets(text).text;
  const t = fold(raw);
  if (!hasEmail(t) && !hasPhone(t)) return raw;
  return t.replace(EMAIL, '[email hidden]').replace(PHONE, (m) => (isPhone(m) ? '[number hidden]' : m));
}
const HIDDEN_MARKUP = /<!--[\s\S]*?(?:-->|$)|[\u{200B}\u{202A}-\u{202E}\u{2066}-\u{2069}\u{2060}-\u{2064}]|(?!^)\u{FEFF}/gu;
const LINK_DEFINITION = /^[ \t]{0,3}(?:(?:>|[-*+]|\d{1,9}[.)])[ \t]{0,3}){0,20}\[(?!\^)(?:[^\]\n\\]|\\.){1,999}\]:[ \t]*(?:<[^>\n]*>|\S+)(?:[ \t]+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?[ \t]*$/gm;
export function stripHidden(text) {
  const raw = String(text == null ? '' : text);
  const clean = raw.replace(HIDDEN_MARKUP, '').replace(LINK_DEFINITION, '');
  return { text: clean, removed: clean !== raw };
}
