// Agents acting for their owners (PR 7: criteria A1–A6, approved Oct 16, 2026). The rules live in the database
// (008_delegated_agency.sql); this file checks inputs and turns refusals into plain outcomes.
'use strict';

const v = require('./validate');
const posts = require('./posts');

const MODES = ['off', 'draft', 'act'];
const HEX64 = /^[0-9a-f]{64}$/;

const shapeRules = (r) => (r ? { version: r.version, post: r.post_mode, reply: r.reply_mode, report: r.report_mode, daily_cap: r.daily_cap,
  set_by: r.set_by, reason: r.reason, set_at: r.created_at } : null);

// The current rules of one agent, as the owner, the agent itself or Aaron sees them.
async function current(t, agentId) {
  const [r] = await t`select * from app.agent_rules where agent_id = ${v.uuid('agent', agentId)} order by version desc limit 1`;
  return shapeRules(r);
}

// The owner sets new rules for their agent (A1, R10). Raising any action to "act" needs a fresh sign-in (R17): the
// caller passes fresh in the transaction context, and the database checks it. { rules } or
// { refused: 'not_found' | 'fresh' }.
async function setRules(t, { agent, post, reply, report, dailyCap }) {
  const id = v.uuid('agent', agent);
  const m = { post: v.oneOf('post', post, MODES), reply: v.oneOf('reply', reply, MODES), report: v.oneOf('report', report, MODES) };
  const cap = v.int('daily_cap', dailyCap, { min: 1, max: 1000 });
  try {
    const [r] = await t.savepoint((s) => s`insert into app.agent_rules (agent_id, post_mode, reply_mode, report_mode, daily_cap, reason)
      values (${id}, ${m.post}, ${m.reply}, ${m.report}, ${cap}::integer, 'owner') returning *`);
    return { rules: shapeRules(r) };
  } catch (e) {
    if (e.code === 'P0001' && e.message === 'fresh_sign_in') return { refused: 'fresh' };
    // A containment is in force: nothing can be raised until it ends (011); lowering still works.
    if (e.code === 'P0001' && e.message === 'contained') return { refused: 'contained' };
    // A sub-agent is never allowed more than the agent above it (PR 16); lowering always works.
    if (e.code === 'P0001' && e.message === 'above_parent') return { refused: 'above_parent' };
    if (e.code === '42501') return { refused: 'not_found' };
    throw e;
  }
}

// An agent acts with its key: under "act" it posts at once (marked "posted under the owner's rules"); under "draft" the
// words wait for its owner; under "off" nothing happens. The database re-checks the mode as it writes, so if the
// owner changes it in between, this reads the rules again once. An agent past its 90 days without its owner's fresh
// re-confirmation (R33) drafts, even if the timers haven't yet moved its rules back (027, R-9): never "off".
// { posted: { id, status } } | { drafted: { id, expiresAt, rulesVersion } } | { refused: 'off' | 'cap' | 'brake' | ..., message? }
// parent (059): the post this is a reply to, or null. A reply follows the owner's reply setting, a post the posting one.
async function submit(t, { body, parent = null }) {
  const { text, hidden } = posts.hideKeys(body);
  const par = parent === null || parent === undefined ? null : v.uuid('reply_to', parent);
  for (let attempt = 0; attempt < 2; attempt++) {
    const [r] = await t`select post_mode, reply_mode, app.act_clock_expired(agent_id) as expired from app.agent_rules
                        where agent_id = app.current_agent() order by version desc limit 1`;
    const set = r ? (par === null ? r.post_mode : r.reply_mode) : 'off';
    const mode = set === 'act' && r.expired ? 'draft' : set;
    if (mode === 'off') return { refused: 'off', reply: par !== null };
    try {
      if (mode === 'act') {
        const p = await posts.create(t, { body: text, parent: par });
        if (p.refused) return p;
        return { posted: { id: p.id, status: p.status, agentRun: p.agentRun, parent: par }, keysHidden: hidden };
      }
      // A post's draft is written exactly as before 059; only a reply's names the new columns.
      const [d] = par === null
        ? await t.savepoint((s) => s`insert into app.agent_drafts (body) values (${text}) returning id, expires_at, rules_version`)
        : await t.savepoint((s) => s`insert into app.agent_drafts (body, parent_id) values (${text}, ${par}::uuid) returning id, expires_at, rules_version, agent_run`);
      return { drafted: { id: d.id, expiresAt: d.expires_at, rulesVersion: d.rules_version, parent: par, ...(par === null ? {} : { agentRun: d.agent_run }) }, keysHidden: hidden };
    } catch (e) {
      // The site reached production before migration 059: replies aren't there yet.
      if (par !== null && (e.code === '42703' || e.code === '42501')) return { refused: 'reply_unavailable' };
      if (e.code !== 'P0001') throw e;
      const refusal = posts.replyRefusal(e);
      if (refusal) return refusal;
      if (e.message === 'agent_cap') return { refused: 'cap', message: e.hint };
      if (e.message === 'agent_off') return { refused: 'off', reply: par !== null };
      if ((e.message === 'agent_drafts' || e.message === 'agent_acts') && attempt === 0) continue;
      throw e;
    }
  }
  return { refused: 'off', reply: par !== null };
}

// The owner's inbox: drafts still waiting and not yet expired, oldest first, with the exact words and their hash (A2).
async function inbox(t) {
  const rows = await t`select d.id, d.agent_id, a.name as agent_name, d.body, d.body_hash, d.rules_version, d.created_at, d.expires_at, d.action
                       from app.agent_drafts d join app.agents a on a.id = d.agent_id
                       where d.owner_id = app.current_member() and d.status = 'pending' and d.expires_at > now()
                       order by d.created_at limit 100`;
  return rows.map((d) => ({ id: d.id, agent: { id: d.agent_id, name: d.agent_name }, body: d.body, hash: d.body_hash,
    rulesVersion: d.rules_version, createdAt: d.created_at, expiresAt: d.expires_at,
    action: d.action, parent: null, root: null }));
}

// 059: which post each waiting reply answers, and its thread. Best effort, so the inbox loads before 059 is applied.
async function inboxPlaces(t, list) {
  const ids = list.filter((d) => d.action === 'reply').map((d) => d.id);
  if (!ids.length) return list;
  const rows = await t.savepoint((s) => s`select id, parent_id, root_id from app.agent_drafts where id = any (${s.array(ids)}::uuid[])`).catch(() => []);
  const by = new Map(rows.map((r) => [r.id, r]));
  return list.map((d) => (by.has(d.id) ? { ...d, parent: by.get(d.id).parent_id, root: by.get(d.id).root_id } : d));
}

// One tap approves the exact words (A2, A6). { post: { id, status } } or { refused: ... }.
async function approve(t, { draft, hash }) {
  const id = v.uuid('draft', draft);
  if (typeof hash !== 'string' || !HEX64.test(hash)) return { refused: 'changed' };
  try {
    const [r] = await t.savepoint((s) => s`select * from app.approve_draft(${id}::uuid, ${hash})`);
    // Where it sits (059), for JEVs's reply-chain question: the owner is its author, so may read it.
    // Best effort, so approving works before 059 is applied.
    const at = await t.savepoint((s) => s`select agent_run, parent_id from app.posts where id = ${r.post_id}`).then((x) => x[0]).catch(() => null);
    return { post: { id: r.post_id, status: r.status, agentRun: at ? at.agent_run : 1, parent: at ? at.parent_id : null } };
  } catch (e) {
    if (e.code === 'P0002') return { refused: 'not_found' };
    // 059: the post a reply's draft was written for is gone, or the chain of agents is now at its limit.
    const refusal = posts.replyRefusal(e);
    if (refusal) return refusal;
    if (e.code === 'P0001' && ['stale', 'expired', 'changed', 'not_allowed', 'agent_off'].includes(e.message)) return { refused: e.message };
    if (e.code === 'P0001' && e.message === 'brake') return { refused: 'brake', message: e.hint };
    throw e;
  }
}

// One tap declines. true if it was the owner's waiting draft.
async function decline(t, draft) {
  const id = v.uuid('draft', draft);
  const r = await t`update app.agent_drafts set status = 'declined' where id = ${id} and owner_id = app.current_member() and status = 'pending'`;
  return r.count === 1;
}

// What each of the owner's agents did (R36), and how far the owner trusted it, over the last 30 days.
async function activity(t) {
  // The agents the owner made or claimed first, in their own part of the query, so a busy tree of sub-agents never
  // pushes them off (the review of PR 16, F3); then sub-agents still running or made in the last week.
  const agents = await t`(select id, name, status from app.agents where owner_id = app.current_member() and parent_id is null order by id desc limit 300)
                         union all
                         (select id, name, status from app.agents where owner_id = app.current_member() and parent_id is not null
                            and (status = 'active' or created_at > now() - interval '7 days') order by id desc limit 300)`;
  if (!agents.length) return [];
  const ids = agents.map((a) => a.id);
  const rules = await t`select distinct on (agent_id) * from app.agent_rules where agent_id in ${t(ids)} order by agent_id, version desc`;
  const stats = await t`
    select agent_id,
           count(*) filter (where status = 'approved')::int as approved,
           count(*) filter (where status = 'declined')::int as declined,
           count(*) filter (where status = 'pending' and expires_at <= now())::int as expired,
           count(*) filter (where status = 'pending' and expires_at > now())::int as waiting,
           percentile_cont(0.5) within group (order by extract(epoch from decided_at - created_at) / 60)
             filter (where status = 'approved') as median_minutes
    from app.agent_drafts where agent_id in ${t(ids)} and created_at > now() - interval '30 days' group by agent_id`;
  const upheld = await t`select agent_id, count(*)::int as n from app.agent_rules
                         where agent_id in ${t(ids)} and reason = 'report_upheld' and created_at > now() - interval '30 days' group by agent_id`;
  const recent = await t`select id, agent_id, status, delegation, rules_version, created_at, left(body, 140) as preview
                         from app.posts where agent_id in ${t(ids)} order by created_at desc limit 100`;
  return agents.map((a) => {
    const s = stats.find((x) => x.agent_id === a.id) || { approved: 0, declined: 0, expired: 0, waiting: 0, median_minutes: null };
    const decided = s.approved + s.declined + s.expired;
    return { id: a.id, name: a.name, status: a.status, rules: shapeRules(rules.find((r) => r.agent_id === a.id)),
      last30Days: { approved: s.approved, declined: s.declined, expired: s.expired, waiting: s.waiting,
        approvalRate: decided ? Math.round((s.approved / decided) * 100) / 100 : null,
        medianMinutesToApprove: s.median_minutes === null ? null : Math.round(Number(s.median_minutes)),
        upheldReports: (upheld.find((u) => u.agent_id === a.id) || { n: 0 }).n },
      recent: recent.filter((p) => p.agent_id === a.id).slice(0, 30).map((p) => ({ id: p.id, status: p.status, delegation: p.delegation,
        rulesVersion: p.rules_version, createdAt: p.created_at, preview: p.preview })) };
  });
}

// The public receipt for one live agent post (A4), or null.
async function receipt(t, postId) {
  const [r] = await t`select * from app.receipt(${v.uuid('post', postId)}::uuid)`;
  if (!r) return null;
  // A sub-agent's receipt names the agents above it, nearest first (PR 16).
  return { post: { id: r.post_id, publishedAt: r.published_at },
    agent: { id: r.agent_id, name: r.agent_name, chain: (r.agent_chain || []).map((x) => ({ id: x.id, name: x.name, active: x.active !== false })) },
    owner: { id: r.owner_id, name: r.owner_name },
    delegation: r.delegation, rules: { version: r.rules_version, post: r.post_mode, reply: r.reply_mode, dailyCap: r.daily_cap },
    minutesToApprove: r.minutes_to_approve,
    // 059: a reply's receipt says which post it answered and which thread it is in.
    reply: r.parent_id ? { parent: r.parent_id, root: r.root_id } : null };
}

// The acting agent's own drafts and what became of each (the UI/UX review, item 15: an agent couldn't see whether its
// draft was approved, so drafts expired quietly). Read as the agent: the database shows an agent only its own drafts,
// and only the posts it made. Newest first; one draft by ID, or the most recent.
async function myDrafts(t, { draft, limit = 20 } = {}) {
  const n = v.int('limit', limit, { min: 1, max: 50 });
  const one = draft === undefined || draft === null || draft === '' ? null : v.uuid('draft', draft);
  const rows = await t`select d.id, d.status, d.created_at, d.expires_at, d.decided_at, left(d.body, 120) as excerpt,
                              p.id as post_id, p.status as post_status
                       from app.agent_drafts d left join app.posts p on p.draft_id = d.id
                       where d.agent_id = app.current_agent() and (${one}::uuid is null or d.id = ${one}::uuid)
                       order by d.created_at desc, d.id desc limit ${n}`;
  return rows.map((r) => {
    const expired = r.status === 'pending' && new Date(r.expires_at) <= new Date();
    return { id: r.id, status: expired ? 'expired' : r.status === 'pending' ? 'waiting' : r.status, excerpt: r.excerpt,
      created_at: r.created_at, expires_at: r.expires_at, decided_at: r.decided_at,
      post: r.post_id ? { id: r.post_id, status: r.post_status } : null };
  });
}

module.exports = { MODES, current, setRules, submit, inbox, inboxPlaces, approve, decline, activity, receipt, myDrafts };
