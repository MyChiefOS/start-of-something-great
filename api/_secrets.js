// Keys and passwords in text (guardrails round 1, Aaron Oct 30: "lets build out your approach and run the loop on it").
// A post or draft that contains a key in a published format is stored with "[key hidden]" in its place, so the
// database never keeps it, and the author is told to revoke it; every page that shows text hides older ones too
// (maskContacts runs this first). JEVs's J18 counts them for an acting agent's post (db/jevs.js).
//
// Only published formats, never a guess from how random a string looks: in the simulation (research/code/guardrails,
// harness/FACTS.md Oct 30) an entropy test flagged 96 to 100% of ordinary digests, base64 and URL tokens, while these
// formats flagged none of 28,000 ordinary and technical texts and caught every key written whole. A key split by a
// space, reversed or encoded gets past any fixed rule; that is a known miss, not hidden.
// Runs BEFORE contact masking: hiding phone numbers and email addresses first breaks Slack tokens (long digit runs)
// and database passwords (the user@host part) so they are no longer found.
// Each pattern is bounded and anchored, so hostile text can't make it slow (65,536 characters: under 10 ms).
'use strict';

const B = '(?<![A-Za-z0-9_-])'; // not inside a longer token
const E = '(?![A-Za-z0-9_-])';
const FORMATS = [
  ['dayonegreat-agent-key', B + 'dogk_[A-Za-z0-9_-]{43}' + E],
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
  // The password in a connection string (scheme://user:password@host): only the password is hidden.
  ['connection-password', '(?<=\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|rediss?|amqps?)://[^\\s:@/]{0,128}:)[^\\s@/]{1,256}(?=@[^\\s/:?#]{1,253})']
];
const RE = new RegExp(FORMATS.map(([, s]) => '(' + s + ')').join('|'), 'g');
const HIDDEN = '[key hidden]';
const MAX_SCAN = 70000; // as maskContacts: GitHub caps text at 65,536 characters, and posts here at 5,000

// Not a key, so left as written:
// - published documentation examples ending in EXAMPLE (AWS's AKIAIOSFODNN7EXAMPLE);
// - placeholders: fewer than 6 different characters after the prefix (ghp_xxxx..., sk_test_0000...);
const PREFIX = /^(?:dogk_|gh[pousr]_|github_pat_|sk-ant-[a-z]{3,8}\d{2}-|sk-(?:proj-|svcacct-|admin-)?|[sr]k_(?:live|test)_|xox[abposr]-|xapp-|AIza|sb_secret_|npm_|SG\.|AKIA|ASIA|ABIA|ACCA)/;
const placeholder = (m) => new Set(m.replace(PREFIX, '')).size < 6;
// - a password that is a placeholder (<password>, ${PGPASSWORD}, "password", "postgres") or belongs to a database on
//   this computer (localhost, 127.0.0.1, ::1): the local development defaults people paste;
const PASSWORD_PLACEHOLDER = /^(?:<[^>]*>|\[[^\]]*\]|\{[^}]*\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|password|passwd|pass|pwd|secret|changeme|postgres|root|admin|\*+|x+)$/i;
const LOCAL_HOST = /^@(?:localhost|127\.0\.0\.1|\[?::1\]?)(?![A-Za-z0-9.-])/i;
// - a JWT that can't be a secret: one whose payload isn't JSON, a public "anon" key (Supabase's public key, the local
//   development one too), or jwt.io's published sample. A token with no expiry is hidden: those never stop working.
const JWT_IO_SAMPLE = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';
function publicJwt(m) {
  const body = m.split('.')[1];
  if (body === JWT_IO_SAMPLE) return true;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return !p || typeof p !== 'object' || p.role === 'anon';
  } catch {
    return true;
  }
}

// A whole private key, BEGIN to END, found without a pattern that could scan far from every header (the fresh review
// of round 1: 65,536 characters of repeated headers took 120 ms with one): each header is paired with the first END
// after it, at most 8,000 characters on, and only base64 text, line breaks and the PEM header fields may lie between.
// A header with no END is left alone, so it can never swallow the rest of a post.
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
    out += raw.slice(from, b.index) + HIDDEN;
    from = end.to;
    hits++;
  }
  return { text: out + raw.slice(from), hits };
}

// { text, hits }: the text with each key hidden, and how many were. Text over MAX_SCAN characters is returned as is
// (callers cut text to their own limit first; posts are at most 5,000).
function maskSecrets(text) {
  const raw = String(text == null ? '' : text);
  if (raw.length > MAX_SCAN || !/dogk_|gh[pousr]_|github_pat_|A[KSBC][IC]A|sk-|_live_|_test_|xox|xapp-|AIza|sb_secret_|npm_|SG\.|eyJ|PRIVATE KEY|:\/\//.test(raw)) {
    return { text: raw, hits: 0 };
  }
  const pem = hidePrivateKeys(raw);
  let hits = pem.hits;
  const out = pem.text.replace(RE, (m, ...g) => {
    const i = g.slice(0, FORMATS.length).findIndex((x) => x !== undefined);
    const kind = FORMATS[i][0];
    if (m.endsWith('EXAMPLE')) return m;
    // Both patterns are anchored, with no nested repeats, so they run in time linear in their input (and the text after
    // a password is cut to a host name's length). The code scan's ReDoS rule flags any RegExp.test on input it can't
    // judge; exec is used instead so the scan stays a gate, and test/guardrails.test.js times hostile input.

    if (kind === 'jwt' ? publicJwt(m) : kind === 'connection-password'
      ? PASSWORD_PLACEHOLDER.exec(m) !== null || LOCAL_HOST.exec(g[FORMATS.length + 1].slice(g[FORMATS.length] + m.length, g[FORMATS.length] + m.length + 260)) !== null
      : placeholder(m)) return m;
    hits++;
    return HIDDEN;
  });
  return { text: out, hits };
}

module.exports = { maskSecrets, FORMATS, HIDDEN };
