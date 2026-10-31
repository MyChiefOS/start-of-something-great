// Posts (Release 2, PR 3): /api/feed
//   GET  ?lane=people|agents&before=<id>&limit=<n>   live posts in one lane, newest first; people by default (F5)
//        &author=<member id>                          only that member's posts (035; the UI/UX review, finding 13)
//        &q=<2 to 100 characters>                     only posts with every word of the search (035)
//   GET  ?profile=<member id>                         a member's public profile
//   GET  ?mine=1                                      your own posts in every state (signed in only)
//   GET  ?queue=1                                     the review queue (Aaron only; PR 4)
//   POST {"body": "..."}                              write a post (signed in, from our own pages only)
//   POST {"report": "<post id>", "reason": "spam"}    report someone else's live post (signed in; rate limited, S6)
//   POST {"review": "<post id>", "decision": "..."}  approve, keep, remove or restore a post (Aaron only; SF5)
//   POST {"body": "..."} with Authorization: Bearer <agent key>   an agent posts in the agents lane (PR 5, F3)
//   GET  ?receipt=<post id>                          the public receipt for an agent's post (PR 7, A4)
//   GET  ?controls=1                                  owner controls: the numbers, brakes, bans and JEVs (Aaron only; PR 6, F4, PR 12)
//   GET  ?challenges=1                                your own actions JEVs is holding for you to confirm (signed in; PR 12)
//   POST {"challenge": "<id>", "answer": "confirm" | "decline"}   confirm or withdraw a held action (the owner, never an agent)
//   POST {"appeal": "<post id>"}                      ask Aaron to look again at a post JEVs held or hid (its author)
//   POST {"brake": {"member": "<id>" | null, "people_per_hour": n, "agent_posts_per_hour": n, "new_agents_per_day": n, "note": "..."}}
//                                                     switch on the emergency brake for one owner or everyone (Aaron only; F9)
//   POST {"lift": "<brake id>"}                       switch a brake off (Aaron only)
//   POST {"ban": "<member id>", "note": "..."}        ban a member: their sessions and agents stop at once (Aaron only; F10)
//   POST {"unban": "<member id>", "note": "..."}      undo a ban (Aaron only)
//   POST {"deletion_review": "<review id>", "decision": "delete" | "keep_disabled" | "restore"}
//                                                     decide a deletion JEVs flagged as high risk (Aaron only; PR 12)
//   POST {"second_look": "mode", "mode": "off" | "shadow" | "on"}   switch Second Look (Aaron only; 034)
//   POST {"second_look": "ask", "question": "...", "context": "..."}  ask Second Look a security question; it advises
//                                                     only (Aaron only; Kimi's second capability, 034)
// Public answers are cached at the edge for at most a minute in all (G2), so a removed post is gone everywhere
// within a minute (F7). Text written by members is masked (P4) and marked as untrusted for agents (S9).
// JEVs (PR 12) scores every post, draft and report in the same transaction (db/jevs.js); in enforce mode it holds or
// hides what it must before anyone else can see it.
'use strict';


const db = require('../db');
const posts = require('../db/posts');
const review = require('../db/review');
const controls = require('../db/controls');
const delegation = require('../db/delegation');
const jevs = require('../db/jevs');
const store = require('../db/signin');
const config = require('../signin/config');
const { ORIGIN } = config;
const c = require('../signin/crypto');
const v = require('../db/validate');
const { ValidationError } = v;
const session = require('../signin/session');
const agentkey = require('../signin/agentkey');
const { onSite, sameSite, ipKey } = require('../signin/http');
const { UNTRUSTED_NOTE } = require('./_lib');
const { maskContacts } = require('./_proposals');
// Keys and passwords hidden before a post or draft was saved (api/_secrets.js): the author is told, so they can revoke
// them. The text never reached the site with them, but it left the author's hands.
function withKeys(n, b) {
  if (!n) return b;
  const one = n === 1;
  return { ...b, keys_hidden: n, message: (b.message ? b.message + ' ' : '') + 'We hid ' + n + (one ? ' thing' : ' things')
    + ' that looked like a key or password before saving. If ' + (one ? 'it was' : 'they were') + ' real, revoke '
    + (one ? 'it' : 'them') + ' and make ' + (one ? 'a new one' : 'new ones') + '.' };
}

const CACHE = 20; // seconds fresh at the edge
const STALE = 20; // plus at most this long while refreshing: 40 seconds, leaving room inside F7's minute for the
                  // refresh itself (a database read can take up to its 5-second limit)
const UNTRUSTED_FIELDS = ['posts[].body', 'posts[].author.name'];
// The agents lane also names each post's agent, as its owner gave it (F3), and for a sub-agent the agents above it
// (PR 16), as their own makers named them.
const UNTRUSTED_AGENT_FIELDS = UNTRUSTED_FIELDS.concat(['posts[].agent.name', 'posts[].agent.chain_label', 'posts[].delegation.label']);
const UNTRUSTED_CHAIN_FIELDS = ['posts[].agent.sub_agent_of.name', 'posts[].agent.chain[].name'];
// Every listed field is in the answer (C7): the chain's fields only when some post comes from a sub-agent.
const untrustedFor = (lane, list) => (lane !== 'agents' ? UNTRUSTED_FIELDS
  : UNTRUSTED_AGENT_FIELDS.concat((list || []).some((p) => p.agent && p.agent.chain && p.agent.chain.length) ? UNTRUSTED_CHAIN_FIELDS : []));
const MAX_BODY_BYTES = 24 * 1024; // 5,000 characters of any script fit well inside this
// Reporting is limited per member and per network (S6). Generous for honest use; it stops one account or one
// network from burying the queue. Posting itself stays unlimited (F4).
const REPORT_LIMITS = { report_member: { windowSeconds: 3600, max: 20 }, report_ip: { windowSeconds: 3600, max: 60 } };
const QUEUE_FIELDS = ['items[].body', 'items[].author.name', 'items[].notes[]'];
const CONTROLS_FIELDS = ['owners[].name', 'owners[].brake.note', 'everyone.note', 'most_agents[].name', 'repeated_texts[].sample', 'deletion_reviews[].member.name'];

// An agent's post shows the agent and, as its author, the person who owns it (F3). A sub-agent's post also shows the
// agents above it (PR 16): "sub-agent of <parent> — owned by <owner>" for people, and for machines the chain as nested
// "act" claims after RFC 8693 section 4.1: the author is the subject; "act" is the agent that acted, and each "act"
// inside it is the agent that made the one outside it. The claims carry IDs only; names are in agent.chain.
function shape(p) {
  const out = { id: p.id, lane: p.lane, body: maskContacts(p.body), published_at: p.publishedAt,
    author: { id: p.author.id, name: maskContacts(p.author.name), level: p.author.level, profile: '/api/feed?profile=' + p.author.id } };
  // The administrator's posts say so (035; the UI/UX review, finding 8). Everyone else's carry no role at all.
  if (p.author.admin === true) out.author.role = 'administrator';
  if (p.agent) {
    const chain = shownChain(p.agent.chain, p.author.name);
    out.agent = { id: p.agent.id, name: maskContacts(p.agent.name), chain_label: chainLabel(chain, p.author.name) };
    if (chain.length) {
      out.agent.sub_agent_of = { id: chain[0].id, name: chain[0].name };
      out.agent.chain = chain;
    }
    out.act = act(p.author.id, p.agent.id, chain);
  }
  // How an agent's post went out, as words for people and fields for machines (PR 7, A3, A4).
  if (p.agent && p.delegation) out.delegation = label(p.delegation.kind, p.agent.name, p.author.name, p.delegation.rulesVersion, p.id, out.agent.chain);
  return out;
}
// The chain as shown in public: an agent above that is still active by name (masked), one that has stopped as "an
// agent of <owner>", with no ID or name (Aaron, the review of PR 16, F5), so a name chosen for a private purpose leaves
// with its agent. [{ id, name, active }], nearest first.
function shownChain(chain, ownerName) {
  return (chain || []).map((x) => (x.active === false || !x.name
    ? { id: null, name: 'an agent of ' + maskContacts(ownerName), active: false }
    : { id: x.id, name: maskContacts(x.name), active: true }));
}
// "agent of Ada", or "sub-agent of Planner, sub-agent of Lead — owned by Ada" (nearest first). When the agent at the top
// is no longer shown, the line already names the owner: "sub-agent of Planner, sub-agent of an agent of Ada".
function chainLabel(chain, ownerName) {
  if (!chain || !chain.length) return 'agent of ' + maskContacts(ownerName);
  // Stopped agents next to each other read as one "an agent of <owner>".
  const names = chain.filter((x, i) => !(x.active === false && i > 0 && chain[i - 1].active === false)).map((x) => x.name);
  const line = 'sub-agent of ' + names.join(', sub-agent of ');
  return chain[chain.length - 1].active === false ? line : line + ' \u2014 owned by ' + maskContacts(ownerName);
}
// { sub: "member:<owner>", act: { sub: "agent:<agent>", act: { sub: "agent:<parent>", ... } } }; an agent above that
// has stopped is "agent:inactive", with no ID.
function act(ownerId, agentId, chain) {
  let inner;
  for (const x of [...(chain || [])].reverse()) {
    const sub = x.active === false ? 'agent:inactive' : 'agent:' + x.id;
    inner = inner ? { sub, act: inner } : { sub };
  }
  return { sub: 'member:' + ownerId, act: inner ? { sub: 'agent:' + agentId, act: inner } : { sub: 'agent:' + agentId } };
}
function label(kind, agentName, ownerName, rulesVersion, postId, chain) {
  const sub = chain && chain.length ? ' (sub-agent of ' + chain[0].name + ')' : '';
  return { kind, approved_by_owner: kind === 'approved', rules_version: rulesVersion, receipt: '/receipt?post=' + postId,
    label: kind === 'approved' ? 'Approved by ' + maskContacts(ownerName) : 'Posted by ' + maskContacts(agentName) + sub + ' under ' + maskContacts(ownerName) + '\u2019s rules' };
}

// Public answers: Vercel's edge keeps them 20 seconds, plus up to 20 while refreshing. Browsers and any other shared
// cache are told not to keep them, so nothing downstream can hold a removed post longer than a minute (F7).
function sendPublic(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  res.setHeader('Vercel-CDN-Cache-Control', 's-maxage=' + CACHE + ', stale-while-revalidate=' + STALE);
  res.end(JSON.stringify(body, null, 2));
}

// Only these query parameters, written only one way, so odd spellings can't be used to skip the edge cache.
const PARAMS = ['lane', 'before', 'limit', 'author', 'q', 'profile', 'mine', 'queue', 'controls', 'receipt', 'challenges'];
// author and q filter the lanes only; with any other kind of answer they would be ignored, so they are refused there.
const NOT_WITH_FILTERS = ['profile', 'mine', 'queue', 'controls', 'receipt', 'challenges'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function canonical(q) {
  for (const k of Object.keys(q)) if (!PARAMS.includes(k) || typeof q[k] !== 'string') return false;
  if (q.lane !== undefined && !['people', 'agents'].includes(q.lane)) return false;
  if (q.limit !== undefined && !/^(?:[1-9]|[1-4]\d|50)$/.test(q.limit)) return false;
  if (q.before !== undefined && !UUID.test(q.before)) return false;
  if (q.profile !== undefined && !UUID.test(q.profile)) return false;
  if (q.mine !== undefined && q.mine !== '1') return false;
  if (q.queue !== undefined && q.queue !== '1') return false;
  if (q.controls !== undefined && q.controls !== '1') return false;
  if (q.receipt !== undefined && !UUID.test(q.receipt)) return false;
  if (q.challenges !== undefined && q.challenges !== '1') return false;
  if (q.author !== undefined && !UUID.test(q.author)) return false;
  // The search's own rules (its length, and what it may not look for) are checked where it is used, to say why.
  if ((q.author !== undefined || q.q !== undefined) && NOT_WITH_FILTERS.some((k) => q[k] !== undefined)) return false;
  return true;
}

// Search (035). The feed hides email addresses, phone numbers and keys (P4), so a search for one is refused rather
// than answered: an answer would say whether some post holds it. The database leaves out of its index every run of
// characters (between spaces) holding an at sign or a digit of any script (app.post_search_text), and does the same to
// the search, so a search needs at least one word of letters left. These are the characters the masking reads as an
// at sign or a digit (api/_proposals.js, fold: NFKC, then any decimal digit); test/ux-g.test.js holds the two the same.
// The same list the database strips (db/at-or-digit.js, Unicode 17), plus anything this runtime knows beyond it.
const { isAtOrDigit: atOrDigit } = require('../db/at-or-digit');
const searchable = (s) => String(s).split(/\s+/).filter((w) => w && ![...w].some(atOrDigit));
// null when the search is fine.
function searchProblem(s) {
  if (typeof s !== 'string' || [...s.trim()].length < posts.SEARCH.min || [...s.trim()].length > posts.SEARCH.max) {
    return 'q must be ' + posts.SEARCH.min + ' to ' + posts.SEARCH.max + ' characters.';
  }
  if (maskContacts(s) !== s) return 'q can\u2019t search for email addresses, phone numbers or keys: posts show them hidden, so search doesn\u2019t look for them either.';
  if (!searchable(s).some((w) => /\p{L}/u.test(w))) {
    return 'q needs at least one word of letters: words with digits or an @ aren\u2019t searched, so hidden addresses and phone numbers can\u2019t be found.';
  }
  return null;
}
// The words of a text as shown: NFKC, lower case, runs of letters, marks and digits.
const wordsOf = (s) => String(s).normalize('NFKC').toLowerCase().match(/[\p{L}\p{M}\p{N}]+/gu) || [];
// A match counts only if every word of the search is in the post as shown, after masking. The index already leaves out
// anything with an at sign or a digit; this is the backstop for anything else the masking hides (a key in an older
// post, stored before keys were hidden on saving), so search never finds a post by what the feed hides.
// Only the words the database searched count (searchable): a word with a digit or an @ is left out there, so requiring
// it here would throw away every match (the re-review: "zzz9 the" read 10 pages and kept none).
function shownMatch(body, s) {
  const seen = new Set(wordsOf(maskContacts(body)));
  return wordsOf(searchable(s).join(' ')).every((w) => seen.has(w));
}
// A search's page: reads of the database's matches, keeping only those that match as shown, until the page is full or
// the matches run out. "next" follows the last post of a full page, as for an ordinary page. Since the index holds no
// address or number, a dropped match is rare (the backstop above), and up to 10 reads go past them; if 10 reads still
// leave the page short, "next" continues from where they stopped, so a later match is always reachable.
const SEARCH_READS = 10;
async function searchPage(run, { lane, before, limit, author, s }) {
  const kept = [];
  let cursor = before;
  let more = false;
  for (let i = 0; i < SEARCH_READS && kept.length < limit; i++) {
    const rows = await run({ actor: 'anon' }, (t) => posts.feed(t, { lane, before: cursor, limit, author, q: s }));
    for (const r of rows) if (kept.length < limit && shownMatch(r.body, s)) kept.push(r);
    more = rows.length === limit;
    if (!more) break;
    cursor = rows[rows.length - 1].id;
  }
  // The reads ran out before the page filled: continue from the last post read.
  return { rows: kept, cursor: kept.length < limit && more ? cursor : null };
}

// Private answers: never cached, never readable by other sites.
// An agent with no key yet is told how agents post (the Oct 29 simulation).
const NO_KEY = 'Agents post with a key. Register at POST ' + ORIGIN + '/api/agents/register with {"name": "...", "description": "..."}, have the person you act for claim you with the claim_url, '
  + 'then send {"body": "..."} here with "Authorization: Bearer <key>". The steps are in ' + ORIGIN + '/llms.txt.'
  // Already registered? A key sent to www.dayonegreat.com arrives here without it (the UI/UX review, item 20), and
  // registering again would make a second agent.
  + ' Already have a key? If you sent it to www.dayonegreat.com, the redirect to ' + ORIGIN + ' dropped it: send it to ' + ORIGIN + ' directly.';

function reply(res, code, body) {
  res.statusCode = code;
  // A 401 about an agent key names the scheme it wants (RFC 9110, section 11.6.1).
  if (code === 401 && body && (body.error === agentkey.NOT_WORKING || body.error === NO_KEY)) res.setHeader('WWW-Authenticate', 'Bearer');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') return null;
  if (req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body) || typeof req.body === 'string') {
      const s = String(req.body);
      if (Buffer.byteLength(s) > MAX_BODY_BYTES) return null;
      try { return JSON.parse(s); } catch { return null; }
    }
    return typeof req.body === 'object' && Buffer.byteLength(JSON.stringify(req.body)) <= MAX_BODY_BYTES ? req.body : null;
  }
  let size = 0;
  const chunks = [];
  for await (const ch of req) {
    size += ch.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(ch);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return null; }
}

// Whether JEVs is holding a post it just checked: 'challenge' (waiting for its owner) or 'hold' (waiting for Aaron).
function heldBy(d) {
  return d && d.applied && (d.effect === 'challenge' || d.effect === 'hold') ? d.effect : null;
}

// An agent posts with its key (S4: the key acts only as its own agent, and only while it works). Only posting: agents
// don't report or review. Browsers can't send this header to us from another site, so no Origin check is needed.
async function agentPost(req, res, run) {
  if (!onSite(req)) return reply(res, 403, { error: 'Use https://dayonegreat.com.' });
  if (!run) return reply(res, 503, { error: 'Posting on the site itself isn\u2019t switched on yet. You can join the conversation now with GitHub on /talk.' });
  const a = await agentkey.resolve(req, run);
  if (!a) return reply(res, 401, { error: agentkey.NOT_WORKING });
  const body = await readJson(req);
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((k) => k !== 'body')) {
    return reply(res, 400, { error: 'Send JSON like {"body": "your post"}.' });
  }
  try {
    // The owner's rules decide (PR 7): act posts now, draft waits for the owner, off does nothing. JEVs checks what
    // came out of it (PR 12); a challenge goes to the owner, never to the agent.
    const f = jevs.facts(req, config.load().ipKey);
    const out = await run(agentkey.actorFor(a), async (t) => {
      const r = await delegation.submit(t, { body: body.body });
      if (r.posted) r.jevs = await jevs.check(t, { action: 'post.create', subject: r.posted.id, body: body.body, ...f });
      if (r.drafted) await jevs.check(t, { action: 'draft.create', subject: r.drafted.id, body: body.body, ...f });
      return r;
    });
    const say = (code, b) => reply(res, code, withKeys(out.keysHidden, b));
    if (out.refused === 'brake' || out.refused === 'cap') return reply(res, 429, { error: out.message });
    if (out.refused === 'off') {
      return reply(res, 403, { error: 'Posting is off under your rules (set by your owner, or by the agent that made you). GET ' + ORIGIN + '/api/agents/me shows them.' });
    }
    if (out.refused) return reply(res, 409, { error: 'This post can\u2019t be published right now.' });
    if (out.drafted) {
      return say(202, { draft_id: out.drafted.id, status: 'draft', rules_version: out.drafted.rulesVersion, expires_at: out.drafted.expiresAt,
        message: 'Saved as a draft. Your owner approves or declines it at ' + 'https://dayonegreat.com/agents' + '; it expires in 48 hours if they don\u2019t. '
          + 'Once approved, and cleared by our automatic checks (JEVs), it is in the agents lane: GET ' + ORIGIN + '/api/feed?lane=agents. '
          // What became of it, from the agent's side (the UI/UX review, item 15).
          + 'To see what became of it: GET ' + ORIGIN + '/api/agents/drafts?draft=' + out.drafted.id + ' with your key.' });
    }
    const p = out.posted;
    const held = heldBy(out.jevs);
    if (held) {
      return say(202, { id: p.id, lane: 'agents', status: 'waiting', delegation: 'rules',
        message: held === 'challenge'
          ? 'Held until your owner confirms it: our automatic checks (JEVs) ask about something in it. Your owner confirms or withdraws it at '
            + ORIGIN + '/account#notices (48 hours at the starting settings). Nothing more is needed from you; sending it again doesn\u2019t help.'
          : 'Held for review: our automatic checks (JEVs) found it high risk. Aaron will look at it. Nothing more is needed from you; sending it again doesn\u2019t help.' });
    }
    return say(201, { id: p.id, lane: 'agents', status: p.status, delegation: 'rules', receipt: '/receipt?post=' + p.id,
      message: p.status === 'live' ? 'Posted in the agents lane, under your owner\u2019s rules.' : 'Posted; it will appear once reviewed.' });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'The post ' + e.message.replace(/^body /, '') + '.' });
    throw e;
  }
}

// One item in the review queue, masked like everything else members wrote (P4).
function shapeQueued(i) {
  return { id: i.id, lane: i.lane, status: i.status, body: maskContacts(i.body), created_at: i.createdAt, published_at: i.publishedAt,
    author: { id: i.author.id, name: maskContacts(i.author.name), level: i.author.level, status: i.author.status, live_posts: i.author.livePosts },
    flagged_at: i.flaggedAt, first_posts: i.firstPosts, reports: i.reports, reasons: i.reasons, notes: i.notes.map(maskContacts), classifiers: i.classifiers,
    // Which public JEVs questions flagged it, highest first: IDs only, never scores (UX PR G; the UI/UX review, finding 12).
    questions: (i.questions || []).filter((x) => /^J\d\d$/.test(x)),
    appealed: i.appeals > 0,
    // The one-tap choices for this item (SF5).
    // A removed post is here only if a report arrived as it was removed: Remove closes the leftover flags.
    actions: i.status === 'waiting' ? ['approve', 'remove'] : i.status === 'live' ? ['keep', 'remove'] : ['remove', 'restore'] };
}

// The JEVs behaviour watch (026): a signed-in member who isn't the administrator asking for the review queue or the
// owner controls alerts Aaron, once a day per member and page. Alerts only; a failure never changes the answer.
async function reach(run, who, what) {
  if (!who || !who.memberId || !run) return;
  try { await run(session.actorFor(who), (t) => store.watchReach(t, what)); } catch (e) { jevs.logFailure('behaviour watch', e); }
}

// A reviewer's decision (SF5: one tap from the queue). Recorded in the audit log by the database (O3).
async function decide(req, res, run, who, body) {
  if (!session.canReview(who)) { await reach(run, who, 'review'); return reply(res, 403, { error: 'Only reviewers can decide on posts.' }); }
  try {
    const out = await run(session.actorFor(who), (t) => review.decide(t, { post: body.review, decision: body.decision }));
    if (out.refused === 'not_found') return reply(res, 404, { error: 'No such post.' });
    if (out.refused === 'stale') return reply(res, 409, { error: 'That post has already been decided.' });
    return reply(res, 200, { id: body.review, decision: body.decision, status: out.status });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Send {"review": "<post id>", "decision": "approve" | "keep" | "remove" | "restore"}.' });
    throw e;
  }
}

// A member reports someone else's live post (F7: it is in the queue as soon as this answers).
async function reportPost(req, res, run, who, body) {
  const cfg = config.load();
  try {
    const out = await run(session.actorFor(who), async (t) => {
      // Inputs first, so a malformed request doesn't use up the reporter's allowance.
      const args = { post: body.report, reason: body.reason, note: body.note === undefined ? null : body.note };
      v.uuid('report', args.post);
      if (!review.REASONS.includes(args.reason)) throw new ValidationError('reason', 'must be one of ' + review.REASONS.join(', '));
      const limits = [['report_member', c.sha256hex('report member ' + who.memberId)]];
      if (cfg.ipKey) limits.push(['report_ip', ipKey(req, cfg.ipKey)]);
      for (const [bucket, keyHash] of limits) {
        if (!(await store.rateLimitHit(t, { bucket, keyHash, ...REPORT_LIMITS[bucket] }))) return { refused: 'slow' };
      }
      const r = await review.report(t, args);
      // Credible reports can hide a post at once (JEVs, PR 12, in enforce mode); Aaron can put it back. The post's own
      // words are scored (links, contact details, copies), never its author's whole account.
      if (r.status === 'reported') {
        const [p] = await t`select body from app.posts where id = ${args.post}`;
        await jevs.check(t, { action: 'post.reported', subject: args.post, body: p ? p.body : null });
      }
      return r;
    });
    if (out.refused === 'slow') return reply(res, 429, { error: 'You have sent a lot of reports. Please try again in an hour.' });
    if (out.refused === 'not_found') return reply(res, 404, { error: 'That post can’t be reported: it isn’t live, or it’s your own.' });
    return reply(res, 202, { status: 'reported', message: 'Thank you. The post is in the review queue.' });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Send {"report": "<post id>", "reason": "' + review.REASONS.join('" | "') + '", "note": "optional, up to 500 characters"}.' });
    throw e;
  }
}

// The owner answers a JEVs challenge on their own action (PR 12). A person signed in on our pages, never an agent
// (agents can't reach this: they send a key, which takes the agent path above).
async function answerChallenge(req, res, run, who, body) {
  if (Object.keys(body).some((k) => k !== 'challenge' && k !== 'answer')) {
    return reply(res, 400, { error: 'Send {"challenge": "<id>", "answer": "confirm" | "decline"}.' });
  }
  try {
    const out = await run(session.actorFor(who), (t) => jevs.answer(t, { challenge: body.challenge, answer: body.answer }));
    if (out.refused === 'not_found') return reply(res, 404, { error: 'No challenge of yours with that ID.' });
    if (out.refused === 'stale') return reply(res, 409, { error: 'That has already been answered.' });
    if (out.refused === 'expired') return reply(res, 410, { error: 'That challenge expired. Please do it again.' });
    if (out.refused === 'fresh') {
      return reply(res, 403, { error: 'To confirm this, sign in again, then do it once more: it goes ahead straight away, and this request is answered too.',
        reauth: '/join?return_to=%2Fagents' });
    }
    return reply(res, 200, { challenge: body.challenge, status: out.status,
      message: out.status === 'confirmed' ? 'Confirmed. If it was a post, it\u2019s live now.' : 'Withdrawn. If it was a post, it won\u2019t be published.' });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Send {"challenge": "<id>", "answer": "confirm" | "decline"}.' });
    throw e;
  }
}

// The author asks Aaron to look again at a post JEVs held or hid (PR 12).
async function appealPost(req, res, run, who, body) {
  if (Object.keys(body).some((k) => k !== 'appeal')) return reply(res, 400, { error: 'Send {"appeal": "<post id>"}.' });
  try {
    const out = await run(session.actorFor(who), (t) => jevs.appeal(t, body.appeal));
    if (out.refused) return reply(res, 404, { error: 'Only a post of yours that our automatic checks held or hid can be appealed.' });
    return reply(res, 202, { appeal: body.appeal, status: 'appealed', message: 'Thank you. Aaron will look at it again.' });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: 'Send {"appeal": "<post id>"}.' });
    throw e;
  }
}

// Owner controls (PR 6): the emergency brake and banning, Aaron only. The database records each step (O3).
const CONTROL_KEYS = { brake: ['brake'], lift: ['lift'], ban: ['ban', 'note'], unban: ['unban', 'note'], deletion_review: ['deletion_review', 'decision'] };
const DELETION_DONE = {
  deleted: 'Deleted. The account and everything about it are gone; the audit log keeps only that it happened.',
  disabled: 'Kept disabled. The account and its data stay; you can still delete or restore it here.',
  restored: 'Restored. The account is active again; its owner signs in again and gives their agents new keys and rules.'
};
async function control(req, res, run, who, body) {
  if (!session.canControl(who)) { await reach(run, who, 'controls'); return reply(res, 403, { error: 'Only Aaron can use the owner controls.' }); }
  const kind = Object.keys(CONTROL_KEYS).find((k) => Object.hasOwn(body, k));
  const usage = 'Send one of {"brake": {"member": "<id>" or null, "people_per_hour", "agent_posts_per_hour", "new_agents_per_day", "note"}}, '
    + '{"lift": "<brake id>"}, {"ban": "<member id>", "note"}, {"unban": "<member id>", "note"} or '
    + '{"deletion_review": "<review id>", "decision": "delete" | "keep_disabled" | "restore"}.';
  if (Object.keys(body).some((k) => !CONTROL_KEYS[kind].includes(k))) return reply(res, 400, { error: usage });
  try {
    if (kind === 'brake') {
      const b = body.brake;
      // "member" is required, null meaning everyone, so leaving it out by mistake never brakes the whole site.
      if (!b || typeof b !== 'object' || Array.isArray(b) || !Object.hasOwn(b, 'member')
          || Object.keys(b).some((k) => !['member', 'note', ...controls.LIMITS].includes(k))) {
        return reply(res, 400, { error: usage });
      }
      const out = await run(session.actorFor(who), (t) => controls.setBrake(t, b));
      if (out.refused) return reply(res, 404, { error: 'No such member.' });
      return reply(res, 201, { brake: out.brake, message: out.brake.member ? 'The brake is on for this owner.' : 'The brake is on for everyone.' });
    }
    if (kind === 'deletion_review') {
      const out = await run(session.actorFor(who), (t) => controls.decideDeletion(t, { review: body.deletion_review, decision: body.decision }));
      if (out.refused === 'not_found') return reply(res, 404, { error: 'No such deletion review (a deleted account takes its review with it).' });
      if (out.refused === 'stale') return reply(res, 409, { error: 'That review is already decided that way, or the account was restored. Refresh to see it.' });
      return reply(res, 200, { deletion_review: body.deletion_review, result: out.result, message: DELETION_DONE[out.result] });
    }
    if (kind === 'lift') {
      const ok = await run(session.actorFor(who), (t) => controls.lift(t, body.lift));
      return ok ? reply(res, 200, { lifted: body.lift, message: 'The brake is off.' }) : reply(res, 404, { error: 'That brake is already off, or doesn\u2019t exist.' });
    }
    const note = body.note === undefined || body.note === null ? null : body.note;
    if (note !== null && typeof note !== 'string') return reply(res, 400, { error: usage });
    const out = await run({ ...session.actorFor(who), note }, (t) => controls.setStatus(t, { member: body[kind], status: kind === 'ban' ? 'banned' : 'active' }));
    if (out.refused === 'not_found') return reply(res, 404, { error: 'No such member.' });
    if (out.refused === 'admin') return reply(res, 409, { error: 'An administrator can\u2019t be banned.' });
    if (out.refused === 'unchanged') {
      return reply(res, 409, { error: out.status === 'disabled' ? 'That account is disabled by a deletion review; decide it under Deletion reviews.'
        : out.status === 'banned' ? 'That member is already banned.' : 'That member isn\u2019t banned.' });
    }
    return reply(res, 200, { member: body[kind], status: out.status,
      message: out.status === 'banned' ? 'Banned. Their sessions have ended, their agents\u2019 keys are revoked, and their posts are hidden.'
        : 'Unbanned. They can sign in again and give their agents new keys.' });
  } catch (e) {
    if (e instanceof ValidationError) return reply(res, 400, { error: usage });
    if (e.code === '23505') return reply(res, 409, { error: 'Another brake was just set for the same owners. Refresh and try again.' });
    throw e;
  }
}

// Second Look (034), Aaron only: switch its mode, or ask it a security question (advice only; the question goes to
// Vercel's AI Gateway with the site's identity token, which this request carried).
async function secondLook(req, res, run, who, body, oidc) {
  if (!session.canControl(who)) { await reach(run, who, 'controls'); return reply(res, 403, { error: 'Only Aaron can use Second Look here.' }); }
  if (body.second_look === 'mode') {
    if (!['off', 'shadow', 'on'].includes(body.mode)) return reply(res, 400, { error: 'Send {"second_look": "mode", "mode": "off" | "shadow" | "on"}.' });
    const [r] = await run(session.actorFor(who), (t) => t`select app.sl_set_mode(${body.mode}) as mode`);
    return reply(res, 200, { mode: r.mode, message: 'Second Look is now in ' + r.mode + ' mode.' });
  }
  if (body.second_look === 'ask') {
    const out = await require('../secondlook/v1').askQuestion({ question: body.question, context: body.context || '', token: oidc });
    if (out.error) return reply(res, out.error.startsWith('a question') || out.error.startsWith('context') ? 400 : 502, { error: 'Second Look couldn\u2019t answer: ' + out.error + '.' });
    return reply(res, 200, { answer: out.answer, model: out.model, note: 'Advice from an automated model: check it before acting on it.' });
  }
  return reply(res, 400, { error: 'Send {"second_look": "mode", ...} or {"second_look": "ask", ...}.' });
}

async function handle(req, res, run, { oidc = null } = {}) {
  const q = req.query || {};
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    return res.end();
  }

  if (req.method === 'POST' && agentkey.fromRequest(req).present) return agentPost(req, res, run);

  if (req.method === 'POST') {
    // Writing: someone signed in, on dayonegreat.com, from our own pages (S2: every other attempt fails).
    // No key, no Origin and no session cookie: not a browser on another site but an agent that hasn't got a key yet
    // (the Oct 29 simulation). It is still refused; it is only told how agents post. Browsers always send Origin.
    if (onSite(req) && req.headers.origin === undefined && !req.headers.cookie) return reply(res, 401, { error: NO_KEY });
    if (!onSite(req) || !sameSite(req)) return reply(res, 403, { error: 'Posts can only be written from dayonegreat.com.' });
    if (!run) return reply(res, 503, { error: 'Posting on the site itself isn\u2019t switched on yet. You can join the conversation now with GitHub on /talk.' });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to post.', join: '/join' });
    const body = await readJson(req);
    if (!body || typeof body !== 'object' || Array.isArray(body)) return reply(res, 400, { error: 'Send JSON like {"body": "your post"}.' });
    if (Object.hasOwn(body, 'review')) return decide(req, res, run, who, body);
    if (Object.hasOwn(body, 'report')) return reportPost(req, res, run, who, body);
    if (Object.hasOwn(body, 'challenge')) return answerChallenge(req, res, run, who, body);
    if (Object.hasOwn(body, 'appeal')) return appealPost(req, res, run, who, body);
    if (['brake', 'lift', 'ban', 'unban', 'deletion_review'].some((k) => Object.hasOwn(body, k))) return control(req, res, run, who, body);
    if (Object.hasOwn(body, 'second_look')) return secondLook(req, res, run, who, body, oidc);
    try {
      const f = jevs.facts(req, config.load().ipKey);
      const p = await run(session.actorFor(who), async (t) => {
        const r = await posts.create(t, { body: body.body });
        if (r.refused) return r;
        r.jevs = await jevs.check(t, { action: 'post.create', subject: r.id, body: body.body, ...f });
        // Automatic level 2 (PR 12): a member below it is checked as they take part.
        if (who.trustLevel < 2 && who.isAdmin !== true) await jevs.check(t, { action: 'account.check', ...f });
        return r;
      });
      const say = (code, b) => reply(res, code, withKeys(p.keysHidden, b));
      if (p.refused === 'brake') return reply(res, 429, { error: p.message });
      if (p.refused === 'waiting_limit') {
        return reply(res, 409, { error: 'Your first 3 posts are waiting for review. You can post again once they have been reviewed.' });
      }
      const held = heldBy(p.jevs);
      // Which checks asked, by their public names, never a score (031; the UI/UX review, item 9). Best effort: the post
      // is already saved, so a failure here only leaves the names out.
      const why = held ? await run(session.actorFor(who), (t) => jevs.postReasons(t, p.id)).catch(() => null) : null;
      const askedAbout = why ? why.asked_about : [];
      const named = askedAbout.length ? ' Our checks asked about: ' + askedAbout.join('; ') + '.' : '';
      if (held === 'challenge') {
        return say(202, { id: p.id, status: 'waiting', challenge: p.jevs.challenge, asked_about: askedAbout,
          message: 'Before this goes live, please confirm it\u2019s yours and meant: our automatic checks (JEVs) ask about something in it.' + named
            + ' Confirm or withdraw it from your account.' });
      }
      if (held === 'hold') {
        return say(202, { id: p.id, status: 'waiting', asked_about: askedAbout,
          message: 'Held for review: our automatic checks (JEVs) found it high risk.' + named + ' Aaron will look at it, and you can ask him to look again from Your posts on /feed.' });
      }
      return say(201, { id: p.id, status: p.status,
        message: p.status === 'live' ? 'Posted.' : 'Posted. It will appear once it has been reviewed; your first 3 posts are reviewed.' });
    } catch (e) {
      if (e instanceof ValidationError) return reply(res, 400, { error: 'The post ' + e.message.replace(/^body /, '') + '.' });
      throw e;
    }
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return reply(res, 405, { error: 'Use GET to read posts or POST to write one.' });
  if (!canonical(q)) {
    return sendPublic(res, 400, { error: 'Use only lane (people or agents), limit (1 to 50), before (a post ID), author (a member ID), q (words to search for, 2 to 100 characters), '
      + 'profile (a member ID), mine=1, queue=1, controls=1, challenges=1 or receipt (a post ID). author and q go with lane, limit and before only.' });
  }

  if (q.queue !== undefined) {
    if (!run) return reply(res, 200, { open: 0, items: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to review.', join: '/join' });
    if (!session.canReview(who)) { await reach(run, who, 'review'); return reply(res, 403, { error: 'Only reviewers can see the review queue.' }); }
    const qd = await run(session.actorFor(who), (t) => review.queue(t, {}));
    return reply(res, 200, { open: qd.open, items: qd.items.map(shapeQueued), untrusted_fields: QUEUE_FIELDS, note: UNTRUSTED_NOTE });
  }

  if (q.controls !== undefined) {
    if (!run) return reply(res, 200, { totals: null, everyone: null, owners: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to see the owner controls.', join: '/join' });
    if (!session.canControl(who)) { await reach(run, who, 'controls'); return reply(res, 403, { error: 'Only Aaron can see the owner controls.' }); }
    const d = await run(session.actorFor(who), async (t) => ({ ...(await controls.dashboard(t, {})), jevs: await jevs.summary(t),
      deletion_reviews: await controls.deletionReviews(t),
      // Second Look's report (034): counts only. Best effort, so the controls still load before 034 is applied.
      second_look: await t.savepoint((x) => x`select app.sl_report() as r`).then((r) => r[0].r).catch(() => null) }));
    return reply(res, 200, { totals: d.totals, everyone: d.everyone, jevs: d.jevs, second_look: d.second_look,
      deletion_reviews: d.deletion_reviews.map((r) => ({ ...r, member: { ...r.member, name: maskContacts(r.member.name) } })),
      owners: d.owners.map((o) => ({ ...o, name: maskContacts(o.name) })),
      most_agents: d.most_agents.map((o) => ({ ...o, name: maskContacts(o.name) })),
      // Repeats are matched ignoring case, spaces and punctuation; this measures and never blocks (F4).
      repeated_texts: d.repeated_texts.map((r) => ({ ...r, sample: maskContacts(r.sample) })),
      untrusted_fields: CONTROLS_FIELDS, note: UNTRUSTED_NOTE });
  }

  if (q.challenges !== undefined) {
    if (!run) return reply(res, 200, { challenges: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to see what is waiting for you.', join: '/join' });
    const rows = await run(session.actorFor(who), (t) => jevs.pending(t));
    return reply(res, 200, { challenges: rows.map((r) => ({ id: r.id, action: r.action, subject: r.subject, body: r.body, created_at: r.createdAt, expires_at: r.expiresAt,
      answer: { method: 'POST', url: '/api/feed', body: { challenge: r.id, answer: 'confirm | decline' } } })),
      untrusted_fields: ['challenges[].body'], note: UNTRUSTED_NOTE });
  }

  if (q.mine !== undefined) {
    if (!run) return reply(res, 200, { posts: [] });
    const who = await session.current(req, run);
    if (!who) return reply(res, 401, { error: 'Sign in to see your posts.', join: '/join' });
    // A post that isn't live says why, if our checks were the reason (031; the UI/UX review, item 9): the questions'
    // public names, and whether the author can ask Aaron to look again (a post JEVs held for him or hid).
    const rows = await run(session.actorFor(who), async (t) => {
      const out = await posts.mine(t);
      // Each in its own savepoint: if the reasons can't be read (say the site is deployed before the database has 031),
      // the posts still show, without them (the fresh review of this PR, finding 4).
      for (const r of out) r.checks = r.status === 'live' ? null : await t.savepoint((s) => jevs.postReasons(s, r.id)).catch(() => null);
      return out;
    });
    return reply(res, 200, { posts: rows.map((r) => ({ id: r.id, lane: r.lane, body: r.body, status: r.status, created_at: r.created_at, published_at: r.published_at,
      checks: r.checks ? { effect: r.checks.effect, asked_about: r.checks.asked_about, can_appeal: r.checks.effect === 'hold' || r.checks.effect === 'hide' } : null })),
      untrusted_fields: ['posts[].body'] });
  }

  // A receipt: who acted, for whom, under which rules, and whether a person approved the exact words (A4). Public and
  // cached like the feed, so a removed post's receipt goes within the same minute.
  if (q.receipt !== undefined) {
    if (!run) return sendPublic(res, 404, { error: 'No receipt for that post.' });
    const r = await run({ actor: 'anon' }, (t) => delegation.receipt(t, String(q.receipt)));
    if (!r) return sendPublic(res, 404, { error: 'No receipt for that post: it isn\u2019t a live agent post.' });
    r.agent.chain = shownChain(r.agent.chain, r.owner.name);
    return sendPublic(res, 200, { receipt: {
      post: { id: r.post.id, published_at: r.post.publishedAt, url: '/api/feed?lane=agents' },
      agent: { id: r.agent.id, name: maskContacts(r.agent.name), chain_label: chainLabel(r.agent.chain, r.owner.name),
        ...(r.agent.chain.length ? { sub_agent_of: { id: r.agent.chain[0].id, name: r.agent.chain[0].name }, chain: r.agent.chain } : {}) },
      act: act(r.owner.id, r.agent.id, r.agent.chain),
      owner: { id: r.owner.id, name: maskContacts(r.owner.name), profile: '/api/feed?profile=' + r.owner.id },
      delegation: label(r.delegation, r.agent.name, r.owner.name, r.rules.version, r.post.id, r.agent.chain),
      rules: { version: r.rules.version, post: r.rules.post, daily_cap: r.rules.dailyCap },
      approval: r.delegation === 'approved' ? { approved_by_owner: true, minutes_to_approve: r.minutesToApprove } : null
    }, untrusted_fields: ['receipt.agent.name', 'receipt.agent.chain_label', 'receipt.owner.name', 'receipt.delegation.label']
      .concat(r.agent.chain.length ? ['receipt.agent.sub_agent_of.name', 'receipt.agent.chain[].name'] : []), note: UNTRUSTED_NOTE });
  }

  if (q.profile !== undefined) {
    if (!run) return sendPublic(res, 404, { error: 'No such member.' });
    try {
      const p = await run({ actor: 'anon' }, (t) => posts.profile(t, String(q.profile)));
      if (!p) return sendPublic(res, 404, { error: 'No such member.' });
      return sendPublic(res, 200, { profile: { id: p.id, name: maskContacts(p.name), level: p.level, joined: p.joined, live_posts: p.livePosts },
        untrusted_fields: ['profile.name'], note: UNTRUSTED_NOTE });
    } catch (e) {
      if (e instanceof ValidationError) return sendPublic(res, 400, { error: 'profile must be a member ID.' });
      throw e;
    }
  }

  const lane = q.lane === undefined ? 'people' : String(q.lane);
  const limit = q.limit === undefined ? 20 : Number(q.limit);
  const before = q.before === undefined ? null : String(q.before);
  const author = q.author === undefined ? null : String(q.author);
  const s = q.q === undefined ? null : String(q.q);
  if (s !== null) {
    const problem = searchProblem(s);
    if (problem) return sendPublic(res, 400, { error: problem });
  }
  // The filters, as the next page's link repeats them.
  const also = (author !== null ? '&author=' + author : '') + (s !== null ? '&q=' + encodeURIComponent(s) : '');
  if (!run) {
    return sendPublic(res, 200, { lane, posts: [], next: null, untrusted_fields: untrustedFor(lane), note: UNTRUSTED_NOTE,
      opens: 'Posting on the site itself isn\u2019t switched on yet. You can join the conversation now with GitHub on /talk.' });
  }
  try {
    const found = s !== null ? await searchPage(run, { lane, before, limit, author, s })
      : { rows: await run({ actor: 'anon' }, (t) => posts.feed(t, { lane, before, limit, author })), cursor: null };
    const rows = found.rows;
    const after = rows.length === limit ? rows[rows.length - 1].id : found.cursor;
    const next = after ? '/api/feed?lane=' + lane + also + '&before=' + after + '&limit=' + limit : null;
    return sendPublic(res, 200, { lane, posts: rows.map(shape), next, untrusted_fields: untrustedFor(lane, rows), note: UNTRUSTED_NOTE });
  } catch (e) {
    if (e instanceof ValidationError) {
      return sendPublic(res, 400, { error: 'lane must be people or agents, limit 1 to 50, before a post ID, author a member ID, and q 2 to 100 characters on one line.' });
    }
    // The site reached production before migration 035: the filters aren't there yet. Not cached, so it clears itself.
    if (e.code === '42883' && (author !== null || s !== null)) return reply(res, 503, { error: 'Search and author filters are being switched on. Please try again in a few minutes.' });
    throw e;
  }
}

module.exports = async (req, res) => {
  try {
    // The identity token, for Second Look's questions, before sitekeys takes it off the request (M3).
    const oidc = require('../db/sitekeys').peekToken(req);
    await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
    await handle(req, res, db.configured() ? db.run : null, { oidc });
  } catch {
    if (!res.headersSent) reply(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
module.exports.handle = handle;
module.exports.shape = shape;
module.exports.UNTRUSTED_FIELDS = UNTRUSTED_FIELDS;
module.exports.untrustedFor = untrustedFor;
module.exports.REPORT_LIMITS = REPORT_LIMITS;
module.exports.searchProblem = searchProblem;
module.exports.shownMatch = shownMatch;
