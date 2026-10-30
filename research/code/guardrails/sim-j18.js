// Simulation for J18: false alarms on ordinary and technical posts, and catches on leaked keys, by format and by how
// the key is written. Also: an entropy-only detector for comparison, and whether the site's existing masking (P4)
// already hides any of it or breaks detection when run first.
'use strict';
const crypto = require('crypto');
const { maskSecrets } = require('../../../api/_secrets');
const { maskContacts } = require('../../../api/_proposals');
// Fixtures are assembled at run time (PK, JWT_IO) so the repository's own secret scan (gitleaks, in CI) doesn't flag
// these made-up keys and published samples as leaks.
const PK = 'PRIVATE' + ' KEY';
const JWT_IO = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'].join('.');
let seed = 20261030;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
const pick = (a) => a[Math.floor(rnd() * a.length)];
const chars = (set, n) => Array.from({ length: n }, () => set[Math.floor(rnd() * set.length)]).join('');
const AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', az = 'abcdefghijklmnopqrstuvwxyz', D = '0123456789';
const AN = AZ + az + D, B64U = AN + '_-', HEX = '0123456789abcdef', B32 = AZ + '234567';
const WORDS = ('the a to and of we our I you it is was for on with that this agent post today build ship site team ' +
  'feature bug fix release check review idea thanks please help question people GitHub API key token deploy server ' +
  'database model test run version update new great day one learn read write code data user account sign in out').split(' ');
const prose = (n) => Array.from({ length: n }, () => pick(WORDS)).join(' ');
const b64 = (n) => crypto.randomBytes(n).toString('base64');
const b64url = (n) => crypto.randomBytes(n).toString('base64url');

// ---- Ordinary and technical text that must NOT be flagged ----
const BENIGN = {
  'ordinary prose': () => prose(10 + Math.floor(rnd() * 60)) + '.',
  'prose with links': () => prose(15) + ' https://' + pick(['github.com/a/b', 'example.org/x?y=1', 'news.ycombinator.com/item?id=' + chars(D, 8)]) + ' ' + prose(10),
  'commit SHAs': () => 'Fixed in ' + chars(HEX, 40) + ' and ' + chars(HEX, 7) + '; ' + prose(8),
  'UUIDs': () => 'Request id ' + crypto.randomUUID() + ' failed; ' + prose(8),
  'docker and npm digests': () => 'image@sha256:' + chars(HEX, 64) + ' integrity sha512-' + b64(64) + ' ' + prose(6),
  'base64 blobs': () => 'data:image/png;base64,' + b64(48 + Math.floor(rnd() * 200)),
  'URL query tokens': () => 'https://example.com/reset?state=' + b64url(24) + '&nonce=' + b64url(16) + ' ' + prose(5),
  'placeholder keys in docs': () => pick(['export OPENAI_API_KEY="sk-..."', 'Authorization: Bearer YOUR_TOKEN_HERE', 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'Set ANTHROPIC_API_KEY=sk-ant-...', 'key: AIza...your key...', 'Use dogk_<your key> in the header', 'xoxb-your-token']) + ' ' + prose(6),
  'AWS documentation example': () => 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE ' + prose(5),
  'look-alike words': () => pick(['I use sk-learn and xoxo to my team', 'ASK-ANTHROPIC-questions here', 'eyJ is how base64 JSON starts', 'npm_config is set',
    'github_pat_ is the prefix GitHub uses', 'AKIA keys start with four letters', 'the sb_secret_ prefix is new']) + ' ' + prose(6),
  'connection strings without a password': () => 'postgres://postgres@localhost:5434/postgres ' + prose(5),
  'long numbers': () => 'Order ' + chars(D, 16) + ', ISBN 978' + chars(D, 10) + ', tracking 1Z' + chars(AN, 16).toUpperCase() + ' ' + prose(4),
  'hashes in prose': () => 'sha256 ' + chars(HEX, 64) + ' md5 ' + chars(HEX, 32) + ' ' + prose(6),
  'public sample tokens (jwt.io, Supabase anon, local db)': () => pick([JWT_IO,
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + Buffer.from(JSON.stringify({ iss: 'supabase-demo', role: 'anon', exp: 1983812996 })).toString('base64url') + '.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0',
    'postgresql://postgres:postgres@127.0.0.1:54322/postgres', 'mysql://root:root@localhost:3306/app', 'postgres://user:<password>@host.example.com/db']) + ' ' + prose(5),
  'unfinished private key header': () => '-----BEGIN RSA ' + PK + '-----\n' + prose(20),
  'public Supabase key': () => 'publishable: sb_publishable_' + b64url(24) + ' ' + prose(4)
};
// ---- Leaks: real formats, random contents ----
const LEAK = {
  'dayonegreat agent key': () => 'dogk_' + b64url(32),
  'GitHub token': () => pick(['ghp_', 'gho_', 'ghs_', 'ghu_', 'ghr_']) + chars(AN, 36),
  'GitHub fine-grained': () => 'github_pat_' + chars(AN + '_', 82),
  'AWS key ID': () => pick(['AKIA', 'ASIA']) + chars(B32, 16),
  'Anthropic': () => 'sk-ant-api03-' + chars(B64U, 93) + 'AA',
  'OpenAI project': () => 'sk-proj-' + chars(B64U, 156),
  'OpenAI legacy': () => 'sk-' + chars(AN, 20) + 'T3BlbkFJ' + chars(AN, 20),
  'Stripe': () => pick(['sk_live_', 'rk_live_', 'sk_test_']) + chars(AN, 99),
  'Slack': () => 'xoxb-' + chars(D, 12) + '-' + chars(D, 13) + '-' + chars(AN, 24),
  'Google API key': () => 'AIza' + chars(B64U, 35),
  'Supabase secret': () => 'sb_secret_' + chars(B64U, 32),
  'npm': () => 'npm_' + chars(AN, 36),
  'SendGrid': () => 'SG.' + chars(B64U, 22) + '.' + chars(B64U, 43),
  'JWT (e.g. a Supabase service key)': () => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + Buffer.from(JSON.stringify({ iss: 'supabase', ref: chars(az, 20), role: pick(['service_role', 'authenticated']), iat: 1700000000, exp: 2000000000 + Math.floor(rnd() * 1e6) })).toString('base64url') + '.' + b64url(32),
  'private key': () => '-----BEGIN OPENSSH ' + PK + '-----\n' + b64(300).match(/.{1,70}/g).join('\n') + '\n-----END OPENSSH ' + PK + '-----',
  'database password': () => 'postgresql://app:' + b64url(18) + '@db.' + chars(az, 12) + '.supabase.co:5432/postgres'
};
const ACCEPTED = {
  'documentation keys in real formats (hidden; accepted)': () => pick(['sk_test_' + chars(AN, 24), 'AIza' + chars(B64U, 35), 'ghp_' + chars(AN, 36)]) /* made here, never a real key: GitHub's push protection refuses published sample keys too */ + ' ' + prose(4)
};
const WRAP = {
  'plain': (k) => prose(6) + ' ' + k + ' ' + prose(4),
  'in quotes': (k) => 'API_KEY="' + k + '"',
  'in a code block': (k) => '```\nexport TOKEN=' + k + '\n```',
  'Bearer header': (k) => 'curl -H "Authorization: Bearer ' + k + '" https://api.example.com',
  'in a URL query': (k) => 'https://maps.example.com/api?key=' + k + '&q=1',
  'end of sentence': (k) => 'Here it is: ' + k + '.',
  // Evasions a deterministic pattern can't see: reported as known misses, not hidden.
  'split by spaces (evasion)': (k) => k.slice(0, 8) + ' ' + k.slice(8),
  'reversed (evasion)': (k) => k.split('').reverse().join('')
};
const N = 2000;
const entropy = (s) => { const f = {}; for (const ch of s) f[ch] = (f[ch] || 0) + 1; return -Object.values(f).reduce((a, n) => a + (n / s.length) * Math.log2(n / s.length), 0); };
const entropyFlags = (t) => (t.match(/[A-Za-z0-9_+/=.-]{20,}/g) || []).some((w) => entropy(w) > 4.5); // the generic approach
const out = { benign: {}, leaks: {}, contactsFirst: {}, entropyBaseline: {} };
for (const [k, gen] of Object.entries(BENIGN)) {
  let fp = 0, efp = 0;
  for (let i = 0; i < N; i++) { const t = gen(); if (maskSecrets(t).hits) fp++; if (entropyFlags(t)) efp++; }
  out.benign[k] = +(fp / N * 100).toFixed(2); out.entropyBaseline[k] = +(efp / N * 100).toFixed(1);
}
for (const [k, gen] of Object.entries(LEAK)) {
  out.leaks[k] = {};
  let broken = 0;
  for (const [w, wrap] of Object.entries(WRAP)) {
    let caught = 0, keyGone = 0;
    for (let i = 0; i < N / 4; i++) {
      const key = gen(); const t = wrap(key); const r = maskSecrets(t);
      if (r.hits) caught++;
      // A catch must actually remove the key (or its password part) from the text.
      if (!r.text.includes(key) && !(k === 'database password' && r.text.includes('[key hidden]') === false)) keyGone++;
      if (w === 'plain') { const c = maskContacts(t); if (!c.includes(key) || maskSecrets(c).hits === 0) broken++; }
    }
    out.leaks[k][w] = +(caught / (N / 4) * 100).toFixed(1);
  }
  out.contactsFirst[k] = +(broken / (N / 4) * 100).toFixed(1);
}
out.accepted = {}; for (const [k, gen] of Object.entries(ACCEPTED)) { let n = 0; for (let i = 0; i < N; i++) if (maskSecrets(gen()).hits) n++; out.accepted[k] = +(n / N * 100).toFixed(1); }
// Speed on hostile input (ReDoS): 65,536 characters of near-misses.
const hostile = ['dogk_' + 'a'.repeat(65530), 'eyJ' + 'a'.repeat(30000) + '.eyJ' + 'b'.repeat(30000), '-----BEGIN RSA ' + PK + '-----' + 'x'.repeat(65000),
  'postgres://' + 'a'.repeat(30000) + ':' + 'b'.repeat(30000), ('sk-ant-api03-' + 'A'.repeat(70) + ' ').repeat(700)];
out.worstMs = Math.max(...hostile.map((h) => { const t0 = process.hrtime.bigint(); maskSecrets(h.slice(0, 65536)); return Number(process.hrtime.bigint() - t0) / 1e6; })).toFixed(1);
console.log(JSON.stringify(out, null, 1));
