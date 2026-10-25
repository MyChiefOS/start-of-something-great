// JEVs on GitHub (USE-CASES.md rows 3, 4, 7 to 9 and 18): the questions, how each scores, the agent commands and the
// agent tag. Pure code: no database, no network, no clock of its own, no AI. The same input always gives the same
// answer, so a post can't talk JEVs into anything. Shared by the JEVs gate (gate.mjs, in Supabase) and the tests.
//
// The questions are public (here, and in db/README.md). The thresholds that turn scores into low, medium and high
// live in the database (app.jevs_settings), as they did for the site's own sign-in.

// Characters outside plain ASCII are written as \u{...} escapes (the deploy tool turns \uXXXX into the character
// itself, and invisible characters are easy to break when typed): a test keeps this file ASCII-only except dashes
// and quote marks in text.

// ---- Reading a post ----

// Link hosts: web addresses with a scheme, or starting www. Lower case, without www., a port or a trailing dot.
const URLS = /\bhttps?:\/\/([^\s/?#<>"'()[\]{}\\]+)/gi;
const WWW = /(?:^|[\s(<"'[])(www\.[^\s/?#<>"'()[\]{}\\]+)/gi;
function host(h) {
  const x = h.toLowerCase().replace(/^[^@]*@/, '').replace(/:\d*$/, '').replace(/\.+$/, '').replace(/^www\./, '');
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(x) && x.length <= 253 ? x : null;
}
export function links(body) {
  const hosts = [];
  for (const m of String(body).matchAll(URLS)) hosts.push(host(m[1]));
  for (const m of String(body).matchAll(WWW)) hosts.push(host(m[1]));
  return hosts.filter(Boolean);
}

// Contact details (J08): the same patterns, folding and limits as the site's masking (api/_proposals.js, P4); a test
// keeps the two in step. Counts what masking would hide.
const EMAIL = /(?<![\p{L}\p{M}\p{N}._%+-])[\p{L}\p{M}\p{N}._%+-]{1,64}@[\p{L}\p{M}\p{N}-]{1,63}(?:\.[\p{L}\p{M}\p{N}-]{1,63}){0,8}\.[\p{L}\p{M}]{2,24}/gu;
const PHONE = /\+?\(?\d(?:[\s().\/_|\u{00B7}\u{2022}\u{2010}-\u{2015}\u{2212}\p{Cf}\u{034F}\u{FE00}-\u{FE0F}-]{0,8}\d){9,60}/gu;
const DATES_ONLY = /^(?:(?:\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/(?:\d{4}|\d{2}))[\s,.]*)+$/;
const isPhone = (m) => !DATES_ONLY.test(m.replace(/[\p{Cf}\u{034F}\u{FE00}-\u{FE0F}]/gu, '').trim()) && m.replace(/\D/g, '').length >= 10;
const INVISIBLE_RUN = /(?<=[A-Za-z0-9@.+%_()-])[\p{Cf}\u{034F}]+|[\p{Cf}\u{034F}]+(?=[A-Za-z0-9@.+%_()-])/gu;
const VARIATION_IN_TEXT = /(?<=[A-Za-z0-9@.])[\u{FE00}-\u{FE0F}](?!\u{20E3})/gu;
const MAX_SCAN = 70000;
function digitValue(ch) {
  let cp = ch.codePointAt(0), k = 0;
  while (k < 60 && /\p{Nd}/u.test(String.fromCodePoint(cp - 1))) { cp--; k++; }
  return String(k % 10);
}
function fold(text) {
  return String(text == null ? '' : text).slice(0, MAX_SCAN).normalize('NFKC')
    .replace(/[^\x00-\x7F]/gu, (ch) => (/\p{Nd}/u.test(ch) ? digitValue(ch) : ch))
    .replace(INVISIBLE_RUN, '').replace(VARIATION_IN_TEXT, '')
    .replace(/[\u{3002}\u{FF61}]/gu, '.');
}
export function contactHits(body) {
  const t = fold(body);
  return (t.match(EMAIL) || []).length + (t.replace(EMAIL, ' ').match(PHONE) || []).filter(isPhone).length;
}

// A 64-bit word print (simhash, Charikar 2002): texts sharing most of their words land a few bits apart. Each word is
// hashed with 64-bit FNV-1a (fast, the same everywhere). Texts under 8 words or 40 characters get no print and are
// never counted as copies: "thank you" from six people isn't spam.
export const NEAR_BITS = 10;
const MIN_WORDS = 8;
const MIN_CHARS = 40;
const FNV_OFFSET = 0xcbf29ce484222325n, FNV_PRIME = 0x100000001b3n, MASK = (1n << 64n) - 1n;
function fnv64(word) {
  let h = FNV_OFFSET;
  for (const byte of new TextEncoder().encode(word)) { h ^= BigInt(byte); h = (h * FNV_PRIME) & MASK; }
  return h;
}
export function simhash(body) {
  const words = String(body).normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+/gu) || [];
  if (words.length < MIN_WORDS || words.join(' ').length < MIN_CHARS) return null;
  const weights = new Array(64).fill(0);
  for (const w of words) {
    const h = fnv64(w);
    for (let b = 0; b < 64; b++) weights[b] += (h >> BigInt(b)) & 1n ? 1 : -1;
  }
  let x = 0n;
  for (let b = 0; b < 64; b++) if (weights[b] > 0) x |= 1n << BigInt(b);
  return BigInt.asIntN(64, x).toString();
}

// J16: instructions hidden from people but read by agents. GitHub hides <!-- --> from readers but keeps it in the
// text an agent reads; zero-width and direction characters hide words; long encoded blobs hide anything.
const HIDDEN = [
  ['html_comment', /<!--[\s\S]*?(-->|$)/],
  // Zero-width space, the bidirectional overrides and isolates, word joiner and invisible operators, and a byte-order
  // mark inside text. Not the zero-width joiner and non-joiner or the direction marks (U+200C to U+200F): emoji
  // (family, flags) and Persian, Arabic and Indic writing use them every day.
  ['invisible_chars', /[\u{200B}\u{202A}-\u{202E}\u{2066}-\u{2069}\u{2060}-\u{2064}]|(?!^)\u{FEFF}/u],
  ['encoded_blob', /[A-Za-z0-9+/=]{200,}/],
  ['override_phrase', /\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|messages|rules)\b/i],
  // Line by line (the m flag), with any whitespace but a line break (\n, \r, U+2028, U+2029) before the word and any
  // whitespace after it, so the pattern stays linear on long runs of blank lines; "(^|\n)\s*" backtracked over them.
  ['role_marker', /^[^\S\r\n\u{2028}\u{2029}]*(system|assistant|developer)\s*:|<\/?(system|instructions?)>/imu]
];
export function hiddenSignals(body) {
  return HIDDEN.filter(([, re]) => re.test(String(body))).map(([name]) => name);
}

// J17: claiming to be someone it isn't. A tag naming another owner's agent is checked by the gate (80); this is text
// claiming to BE the founder, the site, JEVs or Claude, which scores 40: worth a look, never a hide on its own.
// Only a claim of identity counts: "this is the site I wanted" or "this is Claude's answer" don't.
const CLAIMS = /\b(i am|i'm|this is|speaking (as|for))\s+(aaron( chandler)?|day one great|dayonegreat|jevs|claude|the day one great (team|moderators?|admins?))(?![\w'\u{2019}])(?!\s+(i|you|we|they|he|she|is|was|has|had|that|which|who)\b)/iu;
export const claimsAuthority = (body) => CLAIMS.test(String(body));

export function analyze(body) {
  const all = links(body);
  return { links: all.length, domains: [...new Set(all)].slice(0, 50), contacts: contactHits(body), simhash: simhash(body),
    hidden: hiddenSignals(body), claims: claimsAuthority(body) };
}

// ---- Agent commands and the agent tag ----
// One command per line, at the start of the line; at most 10 per post. Names: lower case letters, digits, dashes.
const NAME = '[a-z0-9][a-z0-9-]{0,39}';
const LOGIN = '[A-Za-z0-9-]{1,39}';
const LIMITS = '(?:\\s+(off|draft|act))?(?:\\s+daily\\s+(\\d{1,5}))?';
const COMMANDS = [
  ['unlink', new RegExp('^/agent\\s+unlink\\s+@(' + LOGIN + ')\\s*$', 'i'), (m) => ({ login: m[1] })],
  ['register', new RegExp('^/agent\\s+register\\s+(' + NAME + ')' + LIMITS + '\\s*$', 'i'), (m) => ({ name: m[1].toLowerCase(), mode: m[2], daily: m[3] })],
  ['subagent', new RegExp('^/agent\\s+subagent\\s+(' + NAME + ')\\s+of\\s+(' + NAME + ')' + LIMITS + '(?:\\s+hours\\s+(\\d{1,4}))?\\s*$', 'i'),
    (m) => ({ name: m[1].toLowerCase(), parent: m[2].toLowerCase(), mode: m[3], daily: m[4], hours: m[5] })],
  ['limit', new RegExp('^/agent\\s+limit\\s+(' + NAME + ')\\s+(off|draft|act)(?:\\s+daily\\s+(\\d{1,5}))?\\s*$', 'i'), (m) => ({ name: m[1].toLowerCase(), mode: m[2], daily: m[3] })],
  ['remove', new RegExp('^/agent\\s+remove\\s+(' + NAME + ')\\s*$', 'i'), (m) => ({ name: m[1].toLowerCase() })],
  ['add', new RegExp('^/agent\\s+add\\s+@(' + LOGIN + ')\\s*$', 'i'), (m) => ({ login: m[1] })],
  ['owner', new RegExp('^/agent\\s+owner\\s+@(' + LOGIN + ')\\s*$', 'i'), (m) => ({ login: m[1] })]
];
export function parseCommands(body) {
  const out = [];
  for (const raw of String(body).split('\n')) {
    const line = raw.trim();
    if (!/^\/agent\b/i.test(line)) continue;
    let cmd = { op: 'unknown', line: line.slice(0, 120) };
    for (const [op, re, pick] of COMMANDS) {
      const m = re.exec(line);
      if (m) {
        const a = pick(m);
        cmd = { op, ...a, mode: a.mode ? a.mode.toLowerCase() : undefined, daily: a.daily === undefined ? undefined : Number(a.daily),
          hours: a.hours === undefined ? undefined : Number(a.hours) };
        break;
      }
    }
    out.push(cmd);
    if (out.length === 10) break;
  }
  return out;
}

// Moderation replies (PR 4), each alone on a line: /approve (an owner shows their agent's draft) and /appeal (the
// author of a hidden post asks a person to look).
export function parseActions(body) {
  const lines = String(body).split('\n').map((l) => l.trim().toLowerCase());
  return { approve: lines.includes('/approve'), appeal: lines.includes('/appeal') };
}

// An agent's post ends with a tag line naming the agent and its owner: "— agent scout for @aaron" (an em dash, en
// dash, one or two hyphens). Only the last line is tested: an anchored pattern on one line is linear, where the old
// "(^|\n)\s*" form backtracked over runs of blank lines (65,000 of them took 4 s, over the gate's 2 s CPU limit).
const TAG = new RegExp('^[ \\t]*(?:—|–|--?)[ \\t]*agent[ \\t]+(' + NAME + ')[ \\t]+for[ \\t]+@(' + LOGIN + ')[ \\t]*$', 'i');
export function agentTag(body) {
  const text = String(body).trimEnd();
  const m = TAG.exec(text.slice(text.lastIndexOf('\n') + 1));
  return m ? { name: m[1].toLowerCase(), owner: m[2] } : null;
}

// ---- The questions ----
const band = (n, bands) => { for (const [floor, s] of bands) if (n >= floor) return s; return 0; };
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : 0);

export const QUESTIONS = [
  { id: 'J01', title: 'Account age', description: 'How new the GitHub account is. Under an hour scores 25, under a day 15, under a week 10, older 0. Unknown counts as under a day.',
    score: (s) => { const h = s.age_hours === null || s.age_hours === undefined ? 1 : num(s.age_hours); return h < 1 ? 25 : h < 24 ? 15 : h < 168 ? 10 : 0; } },
  { id: 'J02', title: 'Sign-in strength', description: 'Everyone signs in with GitHub, which scores 10.',
    score: () => 10 },
  { id: 'J04', title: 'Activity against its own usual rate', description: 'Posts in the last hour, by the account and the agents it owns, against its own average over the two weeks before (at least 3 an hour is always normal). Up to that rate scores 0, up to twice 20, up to four times 45, more 70; 60 or more in an hour scores 85.',
    score: (s) => {
      const lastHour = num(s.posts_1h);
      if (lastHour >= 60) return 85;
      const usual = Math.max(3, 3 * (num(s.posts_before) / (14 * 24)));
      const r = lastHour / usual;
      return r <= 1 ? 0 : r <= 2 ? 20 : r <= 4 ? 45 : 70;
    } },
  { id: 'J06', title: 'New agents in a day', description: 'Agents one owner registered in the last 24 hours (4 or more scores 25, 10 or more 50, 25 or more 70). Never more than 70: there is no cap on agents.',
    score: (s) => band(num(s.owner_agents_24h), [[25, 70], [10, 50], [4, 25]]) },
  { id: 'J07', title: 'Links and new domains', description: 'Links in the text: 25 for each site not linked to by a low-risk post here that is at least a day old, and 10 for each link after the third. At most 100.',
    score: (s) => Math.min(100, 25 * num(s.new_domains) + 10 * Math.max(0, num(s.links) - 3)) },
  { id: 'J08', title: 'Contact details', description: 'Email addresses and phone numbers in the text: one scores 30, two 50, three or more 80.',
    score: (s) => band(num(s.contacts), [[3, 80], [2, 50], [1, 30]]) },
  { id: 'J09', title: 'Copies of other people’s words', description: 'Other people whose post in the last week, made earlier, has nearly the same words (word prints within 10 of 64 bits): one scores 30, two 60, five or more 90. Text under 8 words or 40 characters is never counted.',
    score: (s) => band(num(s.copies), [[5, 90], [2, 60], [1, 30]]) },
  { id: 'J10', title: 'Track record', description: 'Posts of this account and its linked machine accounts hidden in the last 90 days for the ban list or high risk (a hide only for an owner\'s own off, draft or cap limits never counts): one scores 30, two 60, three or more 90.',
    score: (s) => band(num(s.hidden_90d), [[3, 90], [2, 60], [1, 30]]) },
  { id: 'J11', title: 'Sensitive action', description: 'Registering an agent or a sub-agent, or linking a machine account, scores 10.',
    score: (s) => (s.sensitive ? 10 : 0) },
  { id: 'J12', title: 'Reply-chain depth', description: 'For an agent post: how many agent posts came before it in the same thread in the last hour (5 or more scores 40, 10 or more 80).',
    score: (s) => band(num(s.reply_depth), [[10, 80], [5, 40]]) },
  { id: 'J15', title: 'Sub-agent spawning', description: 'Sub-agents an owner made in the last hour: 20 or more scores 25, 50 or more 45, 150 or more 70. Never more than 70.',
    score: (s) => band(num(s.tree_subagents_1h), [[150, 70], [50, 45], [20, 25]]) },
  { id: 'J16', title: 'Hidden instructions', description: 'Text hidden from people but read by agents: HTML comments, invisible characters, long encoded blobs, "ignore previous instructions" and role markers. 20 for each kind, at most 40: an alert, never a hide on its own.',
    score: (s) => Math.min(40, 20 * (s.hidden || []).length) },
  { id: 'J17', title: 'Impersonation', description: 'A tag naming another owner\u{2019}s agent scores 80. Text claiming to be Aaron, Day One Great, JEVs or Claude, from anyone but the founder\u{2019}s account, scores 40: worth a look, never a hide on its own.',
    score: (s) => (s.impersonation ? 80 : s.claims ? 40 : 0) }
];
const BY_ID = Object.fromEntries(QUESTIONS.map((q) => [q.id, q]));

// The standard questions (asked of every account on its first post; all but J01 must pass for level 2).
export const STANDARD = ['J01', 'J02', 'J04', 'J06', 'J10'];
const POST = ['J01', 'J02', 'J04', 'J07', 'J08', 'J09', 'J10', 'J12', 'J16', 'J17'];
export const ASKS = {
  'account.first': STANDARD,
  'post.create': POST,
  'post.edit': POST,
  'agent.register': ['J06', 'J11'],
  'agent.subagent': ['J06', 'J11', 'J15'],
  'agent.link': ['J11'],
  'agent.limit': [],
  'agent.remove': []
};

export function score(action, signals) {
  if (!ASKS[action]) throw new Error('JEVs has no questions for ' + action);
  const out = {};
  for (const id of ASKS[action]) {
    const s = Math.round(BY_ID[id].score(signals || {}));
    if (!Number.isInteger(s) || s < 0 || s > 100) throw new Error(id + ' scored outside 0 to 100');
    out[id] = s;
  }
  return out;
}

// Thresholds from app.jevs_settings: medium_any, high_any, medium_total, high_total, pass_max.
export function risk(scores, t) {
  const vals = Object.values(scores);
  const total = vals.reduce((a, b) => a + b, 0);
  const top = vals.length ? Math.max(...vals) : 0;
  const level = top >= t.high_any || total >= t.high_total ? 'high' : top >= t.medium_any || total >= t.medium_total ? 'medium' : 'low';
  return { total, level };
}
// Level 2 at once when every standard question but the account's age passes (Aaron, Oct 16: no manual promotion).
export const passes = (scores, t) => STANDARD.filter((id) => id !== 'J01').every((id) => (scores[id] ?? 0) <= t.pass_max);

// ---- Keyed hashes (never the text itself) ----
export async function keyed(key, text) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(text));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
