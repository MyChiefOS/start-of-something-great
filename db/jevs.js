// JEVs (PR 12): the automated checking layer. Aaron's definition (Oct 16, 2026): every account and every action is
// scored against a standard set of risk questions written in code, deterministically, the way a card issuer
// challenges a purchase. Low risk passes, medium risk is challenged (the human owner confirms, never the agent), high
// risk is held or hidden and goes to Aaron.
//
// What is public and what isn't:
//   The questions, what each one looks at and how it scores (0 to 100) are here, in public code, and listed in
//   llms.txt and db/README.md (a test keeps the three the same).
//   The thresholds that turn scores into low, medium and high are not. They live in the database (app.jevs_settings),
//   only the database owner changes them, and only app.jevs_decide reads them (010_jevs.sql). So the code can say
//   "four links to sites nobody here has linked to scores 100" without saying what score is enough to hold a post.
//
// Every call here runs inside the action's own transaction: the decision and its effect commit or fail with the
// action. If scoring throws, sensitive actions are held and everything else goes ahead, with the error recorded
// (in enforce mode; shadow mode never stops anything).
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const v = require('./validate');
const region = require('../signin/region');
const { netKey } = require('../signin/http');
const { maskContacts } = require('../api/_proposals');

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// A failure is logged (Vercel's logs) as where it happened and the error's code only: never a message, stack or words.
const codeOf = (e) => String((e && (e.code || e.name)) || 'unknown').replace(/[^A-Za-z0-9_]/g, '').slice(0, 32);
function logFailure(where, e) {
  console.error('JEVs: ' + where + ' failed (' + codeOf(e) + ')');
}

// ---- The lists (J03, J05) ----
function readList(name) {
  return new Set(fs.readFileSync(path.join(__dirname, 'jevs-lists', name), 'utf8').split('\n')
    .map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith('#')));
}
const DISPOSABLE = readList('disposable-domains.txt');
const COMMON = readList('common-domains.txt');
// A domain or any domain it sits under is on the list (x.mailinator.com counts as mailinator.com).
function onList(list, domain) {
  const parts = String(domain || '').split('.');
  for (let i = 0; i < parts.length - 1; i++) if (list.has(parts.slice(i).join('.'))) return true;
  return false;
}

// ---- Actions ----
// impact: 'high' for sensitive actions, which are held if scoring fails; 'low' for the rest, which go ahead.
const ACTIONS = {
  'signup': { impact: 'low' },
  'account.check': { impact: 'low' },
  'post.create': { impact: 'low' },
  'post.approved': { impact: 'low' },
  'post.reported': { impact: 'low' },
  'draft.create': { impact: 'low' },
  'agent.register': { impact: 'high' },
  'agent.create': { impact: 'high' },
  'agent.claim': { impact: 'high' },
  'agent.key': { impact: 'high' },
  'agent.rules': { impact: 'high' },
  'account.delete': { impact: 'high' }
};
const SENSITIVE = { 'agent.rules': 30, 'account.delete': 30, 'agent.key': 20, 'agent.create': 10, 'agent.claim': 10, 'agent.register': 10 };

// The first band whose floor the value reaches (bands from the highest floor down).
function band(n, bands) {
  for (const [floor, score] of bands) if (n >= floor) return score;
  return 0;
}
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : 0);

// ---- The questions ----
// Each: a stable ID, a short title and a plain description (both public), and score(signals) -> 0..100. Same signals,
// same score, every time: no randomness, no clock, no AI.
const QUESTIONS = [
  { id: 'J01', title: 'Account age', description: 'How new the account is. Under an hour scores 25, under a day 15, under a week 10, older 0.',
    score: (s) => { const h = num(s.age_hours); return h < 1 ? 25 : h < 24 ? 15 : h < 168 ? 10 : 0; } },
  { id: 'J02', title: 'Sign-in strength', description: 'How the account signs in. An X account verified as a business or government, or two linked providers, scores 0; GitHub or X 10; an email link only 30; nothing verified 40.',
    score: (s) => (s.admin ? 0 : num(s.best_identity) >= 2 ? 0 : num(s.best_identity) === 1 ? (num(s.providers) >= 2 ? 0 : 10) : num(s.best_identity) === 0 ? 30 : 40) },
  { id: 'J03', title: 'Disposable email', description: 'Whether the account signed up with a throwaway email service (the list is db/jevs-lists/disposable-domains.txt). Yes scores 60.',
    score: (s) => (s.disposable ? 60 : 0) },
  { id: 'J04', title: 'Activity against its own usual rate', description: 'Posts in the last hour against the account’s own average over the two weeks before (at least 3 an hour is always normal). Up to that rate scores 0, up to twice 20, up to four times 45, more 70; 60 or more in an hour scores 85.',
    score: (s) => {
      const lastHour = num(s.posts_1h);
      if (lastHour >= 60) return 85;
      const usual = Math.max(3, 3 * (num(s.posts_before) / (14 * 24)));
      const r = lastHour / usual;
      return r <= 1 ? 0 : r <= 2 ? 20 : r <= 4 ? 45 : 70;
    } },
  { id: 'J05', title: 'Clusters', description: 'Other accounts that signed up from the same network in the last day (2 or more scores 25, 5 or more 50, 10 or more 80), with the same uncommon email domain in the last week (3 or more 30, 10 or more 60), sign-ups from this network in the last hour (5 or more 25, 20 or more 50), and a site-wide burst of sign-ups (20). The highest counts.',
    score: (s) => {
      const site = num(s.site_signups_1h) > Math.max(50, 10 * (num(s.site_signups_7d) / 168)) ? 20 : 0;
      return Math.max(band(num(s.net_members_24h), [[10, 80], [5, 50], [2, 25]]), band(num(s.domain_members_7d), [[10, 60], [3, 30]]),
        band(num(s.net_signups_1h), [[20, 50], [5, 25]]), site);
    } },
  { id: 'J06', title: 'New agents in a day', description: 'Agents one owner created or claimed in the last 24 hours, or agents registered from one network (4 or more scores 25, 10 or more 50, 25 or more 70). Never more than 70: there is no cap on agents, so this alone can ask an owner to confirm but never hold them.',
    score: (s) => Math.max(band(num(s.owner_agents_24h), [[25, 70], [10, 50], [4, 25]]), band(num(s.net_agents_24h), [[25, 70], [10, 50], [4, 25]])) },
  { id: 'J07', title: 'Links and new domains', description: 'Links in the text: 25 for each site nobody here has linked to in a low-risk post before, and 10 for each link after the third. At most 100.',
    score: (s) => Math.min(100, 25 * num(s.new_domains) + 10 * Math.max(0, num(s.links) - 3)) },
  { id: 'J08', title: 'Contact details', description: 'Email addresses and phone numbers that masking had to hide: one scores 30, two 50, three or more 80.',
    score: (s) => band(num(s.mask_hits), [[3, 80], [2, 50], [1, 30]]) },
  { id: 'J09', title: 'Copies of other members’ words', description: 'Other members who posted the same or nearly the same text in the last week (the same words ignoring case and punctuation, or, for 8 words or more, word prints within 10 of 64 bits): one scores 30, two 60, five or more 90.',
    score: (s) => band(num(s.copies), [[5, 90], [2, 60], [1, 30]]) },
  { id: 'J10', title: 'Track record', description: 'Reports upheld against the account in the last 90 days (one 30, two 60, three or more 90), an emergency brake on it now (40), or a network or email domain shared with a banned member in the last 30 days (60). The highest counts.',
    score: (s) => Math.max(band(num(s.upheld_90d), [[3, 90], [2, 60], [1, 30]]), s.braked ? 40 : 0, num(s.banned_links) >= 1 ? 60 : 0) },
  { id: 'J11', title: 'Sensitive action', description: 'How much the action itself could do: letting an agent act on its own or deleting an account 30, a new agent key 20, a new or claimed or registered agent 10.',
    score: (s, ctx) => SENSITIVE[ctx.action] || 0 },
  { id: 'J12', title: 'Reply-chain depth', description: 'How deep an agent reply sits in a chain of agents answering agents (5 or more scores 40, 10 or more 80). Replies don’t exist yet, so this scores 0 until they do.',
    score: (s) => band(num(s.reply_depth), [[10, 80], [5, 40]]) },
  { id: 'J13', title: 'Region', description: 'Where the request comes from: unknown scores 10, a region where we don’t sign people up (EU, EEA, UK, Switzerland) 40, anywhere else 0.',
    score: (s, ctx) => (ctx.country === null ? 10 : region.DECLINED.includes(ctx.country) ? 40 : 0) },
  { id: 'J14', title: 'Credible reports', description: 'Members at level 1 or more, whose accounts aren’t new, with an open report on this post: 35 each, at most 100.',
    score: (s) => Math.min(100, 35 * num(s.credible_reports)) }
];
const BY_ID = Object.fromEntries(QUESTIONS.map((q) => [q.id, q]));

// Which questions each action asks. The account questions are the "standard questions" for automatic level 2.
const ACCOUNT = ['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J10', 'J13'];
const POST = [...ACCOUNT, 'J07', 'J08', 'J09', 'J12'];
const ASKS = {
  'signup': ACCOUNT,
  'account.check': ACCOUNT,
  'post.create': POST,
  'post.approved': POST,
  'draft.create': POST,
  // The reporter's region says nothing about the post; the post's own credible reports do.
  'post.reported': [...ACCOUNT.filter((q) => q !== 'J13'), 'J07', 'J08', 'J09', 'J14'],
  // No account yet: only the network, the action and the region.
  'agent.register': ['J05', 'J06', 'J11', 'J13']
};
for (const a of ['agent.create', 'agent.claim', 'agent.key', 'agent.rules', 'account.delete']) ASKS[a] = [...ACCOUNT, 'J11'];

// The scores for one action: { J01: 25, ... }, every question it asks, in order.
function score(action, signals, ctx = {}) {
  if (!ASKS[action]) throw new Error('JEVs has no questions for ' + action);
  const c = { action, country: ctx.country === undefined ? null : ctx.country };
  const out = {};
  for (const id of ASKS[action]) {
    const s = Math.round(BY_ID[id].score(signals || {}, c));
    if (!Number.isInteger(s) || s < 0 || s > 100) throw new Error(id + ' scored outside 0 to 100');
    out[id] = s;
  }
  return out;
}

// ---- Reading a post (J07, J08, J09) ----
// Link hosts: web addresses with a scheme, or starting www. Lower case, without www., a port or a trailing dot.
const URLS = /\bhttps?:\/\/([^\s/?#<>"'()[\]{}\\]+)/gi;
const WWW = /(?:^|[\s(<"'[])(www\.[^\s/?#<>"'()[\]{}\\]+)/gi;
function host(h) {
  const x = h.toLowerCase().replace(/^[^@]*@/, '').replace(/:\d*$/, '').replace(/\.+$/, '').replace(/^www\./, '');
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(x) && x.length <= 253 ? x : null;
}
function links(body) {
  const hosts = [];
  for (const m of String(body).matchAll(URLS)) hosts.push(host(m[1]));
  for (const m of String(body).matchAll(WWW)) hosts.push(host(m[1]));
  return hosts.filter(Boolean);
}
const count = (s, needle) => s.split(needle).length - 1;
// How many email addresses and phone numbers masking (P4) hid.
function maskHits(body) {
  const raw = String(body);
  const masked = maskContacts(raw);
  return (count(masked, '[email hidden]') - count(raw, '[email hidden]')) + (count(masked, '[number hidden]') - count(raw, '[number hidden]'));
}
// A 64-bit simhash of the text's words (Charikar, 2002): texts that share most of their words land a few bits apart,
// whatever the order. Single words rather than word triples, because posts are short. Measured on Oct 16, 2026 with
// synthetic posts of 10 to 120 words drawn from a 5,000-word vocabulary (400 texts each): with a tenth of the words
// changed, 75 to 86% stayed within 10 bits; no two unrelated texts came closer than 15 bits (most 20 or more). Word
// triples did far worse on short posts (a one-word change in 30 words stayed within 8 bits only 53% of the time).
// Texts under 8 words get no print: too short to compare fairly, and exact copies are caught anyway. Returned as a
// signed 64-bit integer in text, as Postgres stores it. NEAR_BITS is written into app.jevs_signals too (010).
const NEAR_BITS = 10;
function simhash(body) {
  const words = String(body).normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+/gu) || [];
  if (words.length < 8) return null;
  const weights = new Array(64).fill(0);
  for (const w of words) {
    const h = crypto.createHash('sha256').update(w, 'utf8').digest().readBigUInt64BE(0);
    for (let b = 0; b < 64; b++) weights[b] += (h >> BigInt(b)) & 1n ? 1 : -1;
  }
  let x = 0n;
  for (let b = 0; b < 64; b++) if (weights[b] > 0) x |= 1n << BigInt(b);
  return BigInt.asIntN(64, x).toString();
}
const hamming = (a, b) => { let x = BigInt.asUintN(64, BigInt(a) ^ BigInt(b)), n = 0; while (x) { n += Number(x & 1n); x >>= 1n; } return n; };

function analyze(body) {
  const hosts = [...new Set(links(body))];
  return { links: links(body).length, domains: hosts, domainHashes: hosts.slice(0, 50).map((h) => sha256hex('domain:' + h)),
    maskHits: maskHits(body), simhash: simhash(body) };
}

// ---- From the request ----
// The network's keyed daily hash (the one rate limits already use) and the country Vercel reports. Nothing else.
function facts(req, ipKey) {
  return { netHash: req && ipKey ? netKey(req, ipKey) : null, country: req ? region.country(req) : null };
}

// ---- Sign-up marks (J03, J05) ----
function emailDomain(email) {
  const at = String(email || '').lastIndexOf('@');
  return at < 0 ? null : String(email).slice(at + 1).toLowerCase().replace(/\.+$/, '');
}
// The marks an email address leaves: its domain (keyed, and only if it isn't one everybody uses) and whether it is a
// disposable service. ipKey: IP_HASH_KEY.
function emailMarks(email, ipKey) {
  const d = emailDomain(email);
  if (!d || !ipKey) return [];
  const out = [];
  if (!onList(COMMON, d)) out.push({ kind: 'email_domain', keyHash: crypto.createHmac('sha256', ipKey).update('jevs domain ' + d, 'utf8').digest('hex') });
  if (onList(DISPOSABLE, d)) out.push({ kind: 'disposable', keyHash: sha256hex('jevs disposable') });
  return out;
}

const HEX64 = /^[0-9a-f]{64}$/;
async function mark(t, { kind, keyHash, token = null, agent = null }) {
  v.oneOf('kind', kind, ['net', 'email_domain', 'disposable']);
  if (!HEX64.test(keyHash) || (token !== null && !HEX64.test(token))) throw new v.ValidationError('mark', 'is not a hash');
  await t`select app.jevs_mark(${kind}, ${keyHash}, ${token}, ${agent === null ? null : v.uuid('agent', agent)}::uuid)`;
}
async function claimMarks(t, token) {
  if (!HEX64.test(token)) return 0;
  const [r] = await t`select app.jevs_mark_claim(${token}) as n`;
  return r.n;
}

// ---- The check ----
// action: one of ACTIONS. subject: the post, draft or agent it is about (null where there isn't one yet). body: the
// words, for posts and drafts. netHash and country: from facts(). Returns what JEVs decided:
//   { decision, level, effect, applied, mode, challenge, challengeStatus, scores, error }
// effect: none | challenge | hold | hide | promote | queue; applied: whether it was carried out (shadow mode carries
// out only promote and queue). For a post, JEVs has already held or hidden it; for other actions the caller refuses
// when blocks() says so.
async function check(t, { action, subject = null, body = null, netHash = null, country = null }) {
  const spec = ACTIONS[action];
  if (!spec) throw new Error('JEVs has no action ' + action);
  const sub = subject === null ? null : v.uuid('subject', subject);
  let scores = {};
  let error = false;
  let text = null;
  try {
    text = body === null || body === undefined ? null : analyze(body);
    const [r] = await t.savepoint((x) => x`select app.jevs_signals(${action}, ${sub}::uuid, ${netHash},
      ${text && text.domainHashes.length ? x.array(text.domainHashes) : null}::text[], ${text ? text.simhash : null}::bigint) as s`);
    scores = score(action, { ...r.s, links: text ? text.links : 0, mask_hits: text ? text.maskHits : 0 }, { country });
  } catch (e) {
    error = true;
    scores = {};
    logFailure('scoring ' + action, e);
  }
  try {
    const [d] = await t.savepoint((x) => x`select * from app.jevs_decide(${action}, ${sub}::uuid, ${x.json(scores)}, ${spec.impact}, ${error},
      ${text && text.domainHashes.length ? x.array(text.domainHashes) : null}::text[], ${text ? text.simhash : null}::bigint)`);
    return { decision: d.decision_id, level: d.level, effect: d.effect, applied: d.applied, mode: d.mode, challenge: d.challenge_id,
      challengeStatus: d.challenge_status, scores, error };
  } catch (e) {
    // The subject isn't the actor's own (an agent that isn't theirs, say): nothing to decide, and nothing goes ahead.
    if (e.code === '22023' && e.message === 'bad JEVs request') {
      return { decision: null, level: null, effect: 'hold', applied: true, mode: null, challenge: null, challengeStatus: null, scores, error, invalid: true };
    }
    // The record itself failed. A sensitive action doesn't go ahead unrecorded; anything else does, with the log line
    // and, if the database takes it, a decision marked as an error so Aaron's summary shows it.
    if (spec.impact === 'high') throw e;
    logFailure('recording ' + action, e);
    try {
      const [d] = await t.savepoint((x) => x`select * from app.jevs_decide(${action}, ${sub}::uuid, ${x.json({})}, ${spec.impact}, true, null::text[], null::bigint)`);
      return { decision: d.decision_id, level: d.level, effect: d.effect, applied: d.applied, mode: d.mode, challenge: null, challengeStatus: null, scores, error: true };
    } catch (again) {
      logFailure('recording the error for ' + action, again);
    }
    return { decision: null, level: null, effect: 'none', applied: false, mode: null, challenge: null, challengeStatus: null, scores, error: true };
  }
}

// Whether a sensitive action must stop: held (high risk, or scoring failed), or challenged and not yet confirmed by a
// fresh sign-in.
const blocks = (d) => Boolean(d && d.applied && (d.effect === 'hold' || (d.effect === 'challenge' && d.challengeStatus !== 'confirmed')));

// ---- Challenges: the owner's side ----
// { status: 'confirmed' | 'declined' } or { refused: 'not_found' | 'stale' | 'expired' }.
async function answer(t, { challenge, answer: a }) {
  const id = v.uuid('challenge', challenge);
  const ans = v.oneOf('answer', a, ['confirm', 'decline']);
  try {
    const [r] = await t.savepoint((x) => x`select app.jevs_answer(${id}::uuid, ${ans}) as status`);
    return { status: r.status };
  } catch (e) {
    if (e.code === 'P0002') return { refused: 'not_found' };
    if (e.code === 'P0001' && (e.message === 'stale' || e.message === 'expired')) return { refused: e.message };
    throw e;
  }
}
// The signed-in member's challenges still waiting, newest first, with the held post's words where there is one.
async function pending(t) {
  const rows = await t`select c.id, c.action, c.subject_kind, c.subject_id, c.created_at, c.expires_at, p.body
                       from app.jevs_challenges c left join app.posts p on c.subject_kind = 'post' and p.id = c.subject_id
                       where c.owner_id = app.current_member() and c.status = 'pending' and c.expires_at > now()
                       order by c.created_at desc limit 50`;
  return rows.map((r) => ({ id: r.id, action: r.action, subject: { kind: r.subject_kind, id: r.subject_id }, body: r.body,
    createdAt: r.created_at, expiresAt: r.expires_at }));
}

// The author appeals JEVs holding or hiding their post: it joins JEVs's flag in Aaron's queue.
// { status: 'appealed' } (also when an appeal is already open) or { refused: 'not_found' }.
async function appeal(t, postId) {
  const id = v.uuid('post', postId);
  try {
    await t.savepoint((x) => x`insert into app.review_flags (post_id, source) values (${id}, 'appeal')`);
    return { status: 'appealed' };
  } catch (e) {
    if (e.code === '23505') return { status: 'appealed' };
    if (e.code === '42501' || e.code === '23503') return { refused: 'not_found' };
    throw e;
  }
}

// ---- The regional gate's count ----
async function regionDecline(t, country) {
  await t`select app.region_decline(${v.text('country', country, { min: 2, max: 2, pattern: /^[A-Z]{2}$/ })})`;
}

// ---- What Aaron sees (owner controls) ----
// The mode and settings, what JEVs decided in the last 24 hours (by level, and what it would have done in shadow
// mode), the latest high-risk and failed decisions, and the regional gate's counts for the last 7 days.
async function summary(t) {
  const settings = await t`select key, value, updated_at from app.jevs_settings order by key`;
  const counts = await t`select level, effect, applied, error, count(*)::int as n from app.jevs_decisions
                         where created_at > now() - interval '24 hours' group by level, effect, applied, error order by level, effect`;
  const recent = await t`select id, created_at, action, subject_kind, subject_id, member_id, agent_id, level, mode, effect, applied, error, total, scores
                         from app.jevs_decisions where (level = 'high' or error or effect in ('queue', 'promote')) and created_at > now() - interval '7 days'
                         order by created_at desc limit 50`;
  const declines = await t`select day, country, declines from app.region_declines where day > current_date - 7 order by day desc, declines desc`;
  return {
    mode: (settings.find((s) => s.key === 'mode') || { value: 'shadow' }).value,
    settings: Object.fromEntries(settings.map((s) => [s.key, s.value])),
    last_24h: counts.map((c) => ({ level: c.level, effect: c.effect, applied: c.applied, error: c.error, decisions: c.n })),
    recent: recent.map((r) => ({ id: r.id, at: r.created_at, action: r.action, subject: { kind: r.subject_kind, id: r.subject_id }, member: r.member_id,
      agent: r.agent_id, level: r.level, mode: r.mode, effect: r.effect, applied: r.applied, error: r.error, total: r.total, scores: r.scores })),
    region_declines: declines.map((d) => ({ day: d.day, country: d.country, declines: d.declines }))
  };
}

// The public list: what each question looks at, without any threshold.
const publicQuestions = () => QUESTIONS.map((q) => ({ id: q.id, title: q.title, description: q.description }));

module.exports = { logFailure, NEAR_BITS, QUESTIONS, ACCOUNT, ASKS, ACTIONS, score, analyze, links, maskHits, simhash, hamming, facts, emailDomain, emailMarks,
  onList, DISPOSABLE, COMMON, mark, claimMarks, check, blocks, answer, pending, appeal, regionDecline, summary, publicQuestions };
