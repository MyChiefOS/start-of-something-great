// The JEVs gate's work (USE-CASES.md rows 3 to 9, 13 and 16): one GitHub event in, one transaction, the decision
// out. Shared by the Supabase function (index.ts) and the tests, so the code CI tests is the code that runs.
//
// What it never does: refuse anyone, keep the words of a post, or act on an account. What it does:
//   * the first post of a GitHub account makes its record (JEVs-1): level 2 at once if the standard questions pass,
//     level 1 otherwise, with an alert if high risk;
//   * every post and edit is scored (JEVs-2); high risk alerts, and in enforce mode is hidden (reversibly);
//   * /agent commands register, limit, remove and nest agents under their owner, and link a machine account;
//   * a post tagged "— agent <name> for @owner" is attributed to that agent, and its owner's limits apply;
//   * a deleted post is erased from our records, and an account with nothing left is erased too.
import * as J from './core.mjs';

export const FOUNDER_ID = 304218593; // MyChiefOS: Aaron's account, which co-founder Claude also posts as
const MODES = ['off', 'draft', 'act'];
const wider = (a, b) => MODES.indexOf(a) > MODES.indexOf(b);
const MAX_BODY = 65536; // GitHub's own limit on a comment
const MAX_DEPTH = 3; // sub-agent levels below an agent its owner made, as on the site (014_subagents.sql)

class BadEvent extends Error {}
export { BadEvent };

// The event as the workflow sends it (from GitHub's own event payload). Anything else is refused as malformed.
export function checkEvent(ev) {
  const bad = (m) => { throw new BadEvent(m); };
  if (!ev || typeof ev !== 'object') bad('no event');
  if (!['discussion', 'discussion_comment'].includes(ev.event)) bad('event');
  if (!['created', 'edited', 'deleted'].includes(ev.action)) bad('action');
  if (!['shadow', 'enforce'].includes(ev.mode)) bad('mode');
  const p = ev.post || {}, a = ev.author || {};
  if (!Number.isInteger(ev.discussion) || ev.discussion < 1) bad('discussion');
  if (typeof p.node_id !== 'string' || !/^[A-Za-z0-9_=-]{1,100}$/.test(p.node_id)) bad('post id');
  if (p.thread_node_id != null && (typeof p.thread_node_id !== 'string' || !/^[A-Za-z0-9_=-]{1,100}$/.test(p.thread_node_id))) bad('thread id');
  if (typeof p.body !== 'string' || p.body.length > MAX_BODY) bad('body');
  if (Number.isNaN(Date.parse(p.created_at))) bad('created_at');
  if (!Number.isSafeInteger(a.id) || a.id < 1) bad('author id');
  if (typeof a.login !== 'string' || !/^[A-Za-z0-9-]{1,39}(\[bot\])?$/.test(a.login)) bad('author login');
  if (a.created_at != null && Number.isNaN(Date.parse(a.created_at))) bad('author created_at');
  if (ev.bans !== undefined && !(Array.isArray(ev.bans) && ev.bans.length <= 10000 && ev.bans.every((x) => Number.isSafeInteger(x) && x > 0))) bad('bans');
  return ev;
}

async function thresholds(t) {
  const rows = await t`select key, value from app.jevs_settings where key = any (${['medium_any', 'high_any', 'medium_total', 'high_total', 'pass_max']})`;
  const s = Object.fromEntries(rows.map((r) => [r.key, Number(r.value)]));
  for (const k of ['medium_any', 'high_any', 'medium_total', 'high_total', 'pass_max']) if (!Number.isFinite(s[k])) throw new Error('JEVs setting missing: ' + k);
  return s;
}

// Logins can change hands on GitHub; the account seen most recently with this login is the one meant.
const accountByLogin = async (t, login) => (await t`select * from app.gh_accounts where lower(login) = lower(${login}) order by id desc limit 1`)[0];
// Logins in replies are in code quotes, so the bot never @-mentions (notifies) anyone.
const at = (login) => '`@' + login + '`';

async function record(t, out, { action, account, post = null, agent = null, scores, level, effect, reason = '', mode }) {
  const total = Object.values(scores).reduce((a, b) => a + b, 0);
  const applied = effect === 'promote' || effect === 'alert' || effect === 'none' || ((effect === 'hide' || effect === 'unhide') && mode === 'enforce');
  await t`insert into app.gh_decisions (action, member_id, post_id, agent_id, scores, total, risk, mode, effect, reason, applied)
    values (${action}, ${account}, ${post}, ${agent}, ${t.json(scores)}, ${total}, ${level}, ${mode}, ${effect}, ${reason}, ${applied})`;
  out.decisions.push({ action, risk: level, total, effect, reason, applied, questions: Object.keys(scores).filter((k) => scores[k] > 0) });
}

// The account whose agents and limits apply: a linked machine account acts for its owner.
const principalOf = (acct) => acct.owner_id || acct.id;

async function runCommand(t, out, cmd, { acct, principal, principalLogin, mode, th }) {
  const say = (s) => out.replies.push(s);
  const decide = async (action, sig, agent = null) => {
    const scores = J.score(action, sig);
    const r = J.risk(scores, th);
    if (r.level === 'high') out.alert = true;
    await record(t, out, { action, account: principal, agent, scores, level: r.level, effect: r.level === 'high' ? 'alert' : 'none', mode });
  };
  const counts = async () => (await t`select
      (select count(*)::int from app.gh_agents where owner_id = ${principal} and created_at > now() - interval '24 hours') as owner_agents_24h,
      (select count(*)::int from app.gh_agents where owner_id = ${principal} and parent_id is not null and created_at > now() - interval '1 hour') as tree_subagents_1h`)[0];
  const find = async (name) => (await t`select * from app.gh_agents where owner_id = ${principal} and name = ${name} and (expires_at is null or expires_at > now())`)[0];
  // A linked machine account acts for its owner, but may only narrow what its owner allowed (fix 1.1, harness/PLAN.md):
  // lower an agent's limits, remove one, make a sub-agent (never wider than its parent, at most 3 levels, expiring;
  // Aaron, Oct 25: "i want agents to be able to make sub agents"), or unlink itself. Registering a new top-level agent,
  // linking and raising limits need the owner's own account, as /approve does.
  const machine = acct.id !== principal;
  const ownerOnly = () => say('Only ' + at(principalLogin) + ', posting from their own account, can do that. A linked machine account can only lower its owner\'s agents\' limits, remove an agent, make a sub-agent, or unlink itself.');

  if (machine && (cmd.op === 'register' || cmd.op === 'add' || cmd.op === 'owner')) return ownerOnly();
  if (cmd.op === 'register') {
    if (await find(cmd.name)) return say('`' + cmd.name + '` is already one of your agents. Change it with `/agent limit ' + cmd.name + ' off|draft|act daily <n>`.');
    const c = await counts();
    const [ag] = await t`insert into app.gh_agents (owner_id, name, mode, daily_cap) values (${principal}, ${cmd.name}, ${cmd.mode || 'act'},
      ${Math.min(10000, cmd.daily ?? 20)}) on conflict (owner_id, name) do update set mode = excluded.mode, daily_cap = excluded.daily_cap,
      expires_at = null, parent_id = null returning *`;
    await decide('agent.register', { ...c, owner_agents_24h: c.owner_agents_24h, sensitive: true }, ag.id);
    return say('Registered agent `' + ag.name + '` for ' + at(principalLogin) + ': ' + ag.mode + ', up to ' + ag.daily_cap + ' posts a day. Its posts end with the line `— agent ' + ag.name + ' for @' + principalLogin + '`.');
  }
  if (cmd.op === 'subagent') {
    const parent = await find(cmd.parent);
    if (!parent) return say('`' + cmd.parent + '` isn\'t one of your agents, so it can\'t have a sub-agent.');
    const m = cmd.mode || parent.mode, daily = cmd.daily ?? parent.daily_cap;
    if (wider(m, parent.mode) || daily > parent.daily_cap) {
      return say('A sub-agent can\'t have wider limits than `' + parent.name + '` (' + parent.mode + ', ' + parent.daily_cap + ' a day). Nothing changed.');
    }
    if (await find(cmd.name)) return say('`' + cmd.name + '` is already one of your agents.');
    // At most 3 levels below an agent its owner made, as on the site (SA4).
    const [d] = await t`with recursive up (id, parent_id, lvl) as (
        select a.id, a.parent_id, 0 from app.gh_agents a where a.id = ${parent.id}
        union all select a.id, a.parent_id, up.lvl + 1 from app.gh_agents a join up on a.id = up.parent_id where up.lvl < 10)
      select max(lvl)::int as depth from up`;
    if (d.depth + 1 > MAX_DEPTH) return say('Sub-agents go at most ' + MAX_DEPTH + ' levels below an agent you made, and `' + parent.name + '` is already at level ' + d.depth + '. Nothing changed.');
    const hours = Math.min(720, Math.max(1, cmd.hours ?? 24));
    const c = await counts();
    const [ag] = await t`insert into app.gh_agents (owner_id, name, parent_id, mode, daily_cap, expires_at)
      values (${principal}, ${cmd.name}, ${parent.id}, ${m}, ${daily},
              least(now() + make_interval(hours => ${hours}), coalesce(${parent.expires_at}::timestamptz, 'infinity'::timestamptz)))
      on conflict (owner_id, name) do update set parent_id = excluded.parent_id, mode = excluded.mode, daily_cap = excluded.daily_cap,
        expires_at = excluded.expires_at returning *`;
    await decide('agent.subagent', { ...c, sensitive: true }, ag.id);
    return say('Made sub-agent `' + ag.name + '` of `' + parent.name + '`: ' + ag.mode + ', up to ' + ag.daily_cap + ' posts a day, for ' + hours + ' hours. Removing `' + parent.name + '` removes it too.');
  }
  if (cmd.op === 'limit') {
    const ag = await find(cmd.name);
    if (!ag) return say('`' + cmd.name + '` isn\'t one of your agents.');
    if (machine && (wider(cmd.mode, ag.mode) || (cmd.daily ?? ag.daily_cap) > ag.daily_cap)) return ownerOnly();
    if (ag.parent_id) {
      const [p] = await t`select * from app.gh_agents where id = ${ag.parent_id}`;
      if (wider(cmd.mode, p.mode) || (cmd.daily ?? ag.daily_cap) > p.daily_cap) return say('A sub-agent can\'t have wider limits than its parent `' + p.name + '`. Nothing changed.');
    }
    const daily = Math.min(10000, cmd.daily ?? ag.daily_cap);
    await t`update app.gh_agents set mode = ${cmd.mode}, daily_cap = ${daily} where id = ${ag.id}`;
    // Children never end up wider than their parent.
    await t`with recursive tree as (select id from app.gh_agents where parent_id = ${ag.id}
              union all select a.id from app.gh_agents a join tree on a.parent_id = tree.id)
            update app.gh_agents set daily_cap = least(daily_cap, ${daily}),
              mode = case when array_position(${MODES}::text[], mode) > array_position(${MODES}::text[], ${cmd.mode}::text) then ${cmd.mode} else mode end
            where id in (select id from tree)`;
    await decide('agent.limit', {}, ag.id);
    return say('`' + ag.name + '` is now ' + cmd.mode + ', up to ' + daily + ' posts a day.');
  }
  if (cmd.op === 'remove') {
    const ag = await find(cmd.name);
    if (!ag) return say('`' + cmd.name + '` isn\'t one of your agents.');
    await decide('agent.remove', {}, null);
    await t`delete from app.gh_agents where id = ${ag.id}`;
    return say('Removed `' + ag.name + '` and any sub-agents under it. Its posts stay. A new post with its tag line gets a reply saying it isn\'t registered.');
  }
  if (cmd.op === 'unlink') {
    const other = await accountByLogin(t, cmd.login);
    if (other && (acct.owner_id === other.id || other.owner_id === acct.id)) {
      const machine = acct.owner_id === other.id ? acct : other;
      await t`update app.gh_accounts set owner_id = null where id = ${machine.id}`;
      await decide('agent.link', {}, null);
      return say('Unlinked ' + at(machine.login) + '. It no longer posts for anyone.');
    }
    return say(at(cmd.login) + ' isn\'t linked to this account.');
  }
  if (cmd.op === 'add' || cmd.op === 'owner') {
    // add: a person names their machine account. owner: the machine account names its person. Both are needed,
    // each naming an account that has already posted here, within 24 hours of each other.
    const other = await accountByLogin(t, cmd.login);
    if (!other) return say(at(cmd.login) + ' hasn\'t posted here yet under that login (a login that just changed counts as new). Post once from it (a hello is enough), then try again.');
    if (other.id === acct.id) return say('An account can\'t be linked to itself.');
    // Lock both accounts (in id order) and read them again, so two links made at the same moment can't both pass the
    // checks below and form a chain (review R3).
    const rows = await t`select * from app.gh_accounts where id in (${acct.id}, ${other.id}) order by id for no key update`;
    const now = (id) => rows.find((x) => x.id === id);
    const person = now(cmd.op === 'add' ? acct.id : other.id), machine = now(cmd.op === 'add' ? other.id : acct.id);
    if (person.owner_id) return say(at(person.login) + ' is itself a linked machine account, so it can\'t own one.');
    // No chains: an account that already has machine accounts linked to it can't become one, or a ban on the person
    // at the top wouldn't reach the accounts below (review F4).
    const [chain] = await t`select exists (select 1 from app.gh_accounts where owner_id = ${machine.id}) as yes`;
    if (chain.yes) return say(at(machine.login) + ' has machine accounts linked to it, so it can\'t be linked as one. Unlink those first.');
    await t`update app.gh_accounts set link_wanted = ${other.id}, link_wanted_at = now() where id = ${acct.id}`;
    const [ok] = await t`select exists (select 1 from app.gh_accounts where id = ${other.id} and link_wanted = ${acct.id}
      and link_wanted_at > now() - interval '24 hours') as yes`;
    if (ok.yes) {
      await t`update app.gh_accounts set owner_id = ${person.id}, link_wanted = null, link_wanted_at = null where id = ${machine.id}`;
      await t`update app.gh_accounts set link_wanted = null, link_wanted_at = null where id = ${person.id}`;
      await decide('agent.link', { sensitive: true }, null);
      return say('Linked: ' + at(machine.login) + ' now posts for ' + at(person.login) + ', within its agent limits. Undo with `/agent unlink @' + machine.login + '`.');
    }
    return say(cmd.op === 'add'
      ? 'Waiting for ' + at(cmd.login) + ' to confirm with `/agent owner @' + acct.login + '` within 24 hours.'
      : 'Waiting for ' + at(cmd.login) + ' to confirm with `/agent add @' + acct.login + '` within 24 hours.');
  }
  return say('Unknown command `' + String(cmd.line).replace(/`/g, '') + '`. Commands: `/agent register <name> [off|draft|act] [daily <n>]`, `/agent subagent <name> of <parent> [off|draft|act] [daily <n>] [hours <h>]`, `/agent limit <name> off|draft|act [daily <n>]`, `/agent remove <name>`, `/agent add @machine`, `/agent owner @person`, `/agent unlink @account`.');
}

// Erase a deleted post, and the account if nothing of it is left. IDs-only record of the erasure.
// A deleted discussion takes every comment in it with it, so all of its posts are erased.
async function erase(t, ev, key) {
  const who = await J.keyed(key, 'github:' + ev.author.id);
  const gone = ev.event === 'discussion'
    ? await t`delete from app.gh_posts where node_id = ${ev.post.node_id} or discussion_number = ${ev.discussion} returning author_id`
    : await t`delete from app.gh_posts where node_id = ${ev.post.node_id} returning author_id`;
  let accountErased = false;
  for (const author of new Set(gone.map((p) => p.author_id))) {
    const [left] = await t`select
        exists (select 1 from app.gh_posts where author_id = ${author}) or exists (select 1 from app.gh_agents where owner_id = ${author})
        or exists (select 1 from app.gh_accounts where owner_id = ${author}) as keep`;
    if (!left.keep) {
      const [a] = await t`delete from app.gh_accounts where id = ${author} returning github_id`;
      if (a && Number(a.github_id) === ev.author.id) accountErased = true;
      else if (a) await t`insert into app.gh_erasures (github_key, account_erased) values (${await J.keyed(key, 'github:' + a.github_id)}, true)`;
    }
  }
  await t`insert into app.gh_erasures (github_key, post_node_id, account_erased) values (${who}, ${ev.post.node_id}, ${accountErased})`;
  return { ok: true, mode: ev.mode, erased: gone.length, account_erased: accountErased, decisions: [], alert: false, hide: false, reply: null };
}

// What a hidden post's reply says, in plain words (enforce mode only).
const HIDDEN_BECAUSE = {
  banned: 'Hidden by JEVs: this account is on the ban list. Reply `/appeal` under this post to ask a person to look.',
  agent_off: 'Hidden by JEVs: this agent is switched off by its owner (`/agent limit <name> act` turns it on).',
  agent_draft: 'Hidden by JEVs until the agent\'s owner approves it: the owner replies `/approve` under this post.',
  agent_cap: 'Hidden by JEVs: this agent is over its owner\'s daily limit. Its owner can raise it with `/agent limit <name> act daily <n>`.',
  high_risk: 'Hidden by JEVs: this post scored high risk on its automated checks. Reply `/appeal` under this post and a person will look.'
};

// What the reply to a sign-in code says. Logins are in code quotes, so nobody is @-mentioned.
const SIGNED_IN = (login) => 'This code is now claimed for ' + at(login) + ': the browser that asked for it can sign in to '
  + 'Day One Great as you. If that wasn\'t you, sign out everywhere from your account page (https://dayonegreat.com/account), '
  + 'remove any agent keys you didn\'t make, and never post a code someone else gave you. The code works once and is hidden now.';
const NOT_SIGNED_IN = 'This code didn\'t sign anyone in: it was made for a different GitHub username, has expired (codes '
  + 'last 10 minutes), was already used, or wasn\'t one the site gave out. Get a new one at https://dayonegreat.com/join. '
  + 'The code is hidden now.';

// /approve and /appeal, replied under a post in the same thread.
async function moderate(t, out, { ev, acct, principal, mode, body, tagged, banned }) {
  const act = J.parseActions(body);
  const thread = ev.post.thread_node_id;
  if (!thread || (!act.approve && !act.appeal)) return;
  if (act.approve) {
    // Only the owner, posting as themselves: never a linked machine account, never a post tagged as an agent's, and
    // never a banned account. Only drafts: never a post that was also high risk or from a banned account.
    if (acct.id !== principal || tagged || banned) {
      out.replies.push('Only the agent\'s owner, posting from their own account (not a machine account or an agent), can approve a draft.');
    } else {
      const drafts = await t`update app.gh_posts p set approved = true, hidden = case when ${mode} = 'enforce' then false else p.hidden end
        from app.gh_agents a where a.id = p.agent_id and a.owner_id = ${principal} and p.thread_node_id = ${thread}
          and p.node_id <> ${ev.post.node_id} and not p.approved and p.risk <> 'high'
          and coalesce(p.edited_at, p.created_at) <= ${new Date(ev.post.created_at)}
          and exists (select 1 from app.gh_decisions d where d.post_id = p.id and d.reason = 'agent_draft')
          and not exists (select 1 from app.gh_decisions d where d.post_id = p.id and d.reason in ('high_risk', 'banned'))
        returning p.id, p.node_id, p.agent_id`;
      for (const d of drafts) {
        await record(t, out, { action: 'post.approve', account: principal, post: d.id, agent: d.agent_id, scores: {}, level: 'low', effect: 'unhide', mode });
        if (mode === 'enforce') out.unhide.push(d.node_id);
      }
      let later = false;
      if (!drafts.length) {
        [{ later }] = await t`select exists (select 1 from app.gh_posts p join app.gh_agents a on a.id = p.agent_id
          where a.owner_id = ${principal} and p.thread_node_id = ${thread} and not p.approved and p.risk <> 'high'
            and p.edited_at > ${new Date(ev.post.created_at)}) as later`;
      }
      out.replies.push(drafts.length ? 'Approved: ' + drafts.length + ' draft' + (drafts.length > 1 ? 's' : '') + (mode === 'enforce' ? ' shown again.' : ' (nothing was hidden: JEVs is in shadow mode).')
        : later ? 'Not approved: the draft was edited after your `/approve` was posted. Read it again, then reply `/approve`.'
        : 'Nothing of your agents\' is waiting for approval in this thread.');
    }
  }
  if (act.appeal) {
    const [p] = await t`select p.id from app.gh_posts p
      where p.thread_node_id = ${thread} and p.node_id <> ${ev.post.node_id}
        and p.author_id in (select id from app.gh_accounts where id = ${principal} or owner_id = ${principal})
        and exists (select 1 from app.gh_decisions d where d.post_id = p.id and d.effect = 'hide' and d.applied)
        and not exists (select 1 from app.gh_decisions d where d.post_id = p.id and d.action = 'post.appeal')
      order by p.created_at desc limit 1`;
    // One appeal per post: posts already appealed are left out, so an older hidden post can still be appealed.
    if (!p) return void out.replies.push('Nothing of yours in this thread is hidden by JEVs and waiting for a person, so there is nothing (more) to appeal.');
    await record(t, out, { action: 'post.appeal', account: acct.id, post: p.id, scores: {}, level: 'low', effect: 'alert', mode });
    out.alert = true;
    out.appeal = true;
    out.replies.push('Thanks. Your appeal has gone to a person, who will look at the post and decide. JEVs never decides an appeal.');
  }
}

// key: the secret for keyed hashes (from Supabase Vault in production).
export async function handle(sql, raw, { key }) {
  const ev = checkEvent(raw);
  if (!key || key.length < 16) throw new Error('no hash key');
  if (/\[bot\]$/.test(ev.author.login) || ev.author.type === 'Bot') {
    return { ok: true, mode: ev.mode, skipped: 'bot', decisions: [], alert: false, hide: false, reply: null };
  }
  const mode = ev.mode;
  const body = ev.event === 'discussion' ? String(ev.post.title || '') + '\n' + ev.post.body : ev.post.body;
  const text = J.analyze(body);
  const bodyKey = await J.keyed(key, 'post:' + body);
  const domainKeys = await Promise.all(text.domains.map((d) => J.keyed(key, 'domain:' + d)));

  return sql.begin(async (t) => {
    await t`set local role dog_jevs`;
    await t`select pg_advisory_xact_lock(hashtext('jevs ' || ${String(ev.author.id)}))`;
    if (ev.action === 'deleted') return erase(t, ev, key);
    // Events can arrive out of order: a post already erased (deleted on GitHub) is never recorded again.
    const [gone] = await t`select exists (select 1 from app.gh_erasures where post_node_id = ${ev.post.node_id}) as yes`;
    if (gone.yes) return { ok: true, mode: ev.mode, skipped: 'erased', decisions: [], alert: false, hide: false, reply: null };

    const th = await thresholds(t);
    const out = { ok: true, mode, first: false, level: null, decisions: [], alert: false, hide: false, appeal: false, unhide: [], replies: [] };

    let [acct] = await t`select * from app.gh_accounts where github_id = ${ev.author.id}`;
    if (!acct) {
      [acct] = await t`insert into app.gh_accounts (github_id, login, github_created_at) values (${ev.author.id}, ${ev.author.login},
        ${ev.author.created_at || null}) on conflict (github_id) do update set login = excluded.login returning *`;
      out.first = true;
    }
    // A changed login or a newly known account age is written after the commands run, not before: /agent add and owner
    // lock both accounts' rows in id order, and an earlier write here would already hold this row, so two links made at
    // once could deadlock (review T1). Until then the post uses the new values in memory.
    const refresh = acct.login !== ev.author.login || (!acct.github_created_at && ev.author.created_at);
    if (refresh) acct = { ...acct, login: ev.author.login, github_created_at: acct.github_created_at || ev.author.created_at };
    const principal = principalOf(acct);
    const principalLogin = principal === acct.id ? acct.login : (await t`select login from app.gh_accounts where id = ${principal}`)[0].login;
    const founder = ev.author.id === FOUNDER_ID;
    // The ban list (moderation/bans.json) covers an account and every machine account linked to it.
    const bans = new Set(ev.bans || []);
    const principalGithub = principal === acct.id ? Number(acct.github_id) : Number((await t`select github_id from app.gh_accounts where id = ${principal}`)[0].github_id);
    const banned = !founder && (bans.has(ev.author.id) || bans.has(principalGithub));

    // Commands run once, when the post is made (not again on edits).
    if (ev.action === 'created') {
      const cmds = J.parseCommands(body);
      // Every account this post's link commands name, and the poster's own, are locked at once, in id order, before
      // any command runs. Locking pair by pair let a post with two link commands deadlock with another account's link
      // post (review, fourth pass).
      // "no key update", not "update": it still excludes another link, but not the key-share locks the foreign keys of
      // gh_posts and gh_decisions take on these rows, which deadlocked (review, fifth pass).
      const named = cmds.filter((c) => c.op === 'add' || c.op === 'owner' || c.op === 'unlink').map((c) => c.login.toLowerCase());
      if (named.length) {
        await t`select id from app.gh_accounts where id = ${acct.id} or lower(login) = any(${named}::text[]) order by id for no key update`;
      }
      for (const cmd of cmds) await runCommand(t, out, cmd, { acct, principal, principalLogin, mode, th });
    }
    if (refresh) {
      await t`update app.gh_accounts set login = ${ev.author.login}, github_created_at = coalesce(github_created_at, ${ev.author.created_at || null})
        where id = ${acct.id}`;
    }

    // Who wrote it: a person, or one of their agents (the tag line).
    const tag = J.agentTag(body);
    let agent = null, impersonation = false;
    if (tag) {
      const owner = await accountByLogin(t, tag.owner);
      const mine = owner && (owner.id === principal);
      if (mine) {
        [agent] = await t`select * from app.gh_agents where owner_id = ${owner.id} and name = ${tag.name} and (expires_at is null or expires_at > now())`;
        if (!agent && ev.action === 'created' && !out.replies.some((r) => r.includes('`' + tag.name + '`'))) {
          out.replies.push('This post is tagged as agent `' + tag.name + '`, which isn\'t registered to ' + at(principalLogin) + '. Register it with `/agent register ' + tag.name + '`.');
        }
      } else {
        impersonation = true; // tagged as someone else's agent
      }
    }
    // A post that was an agent's stays that agent's: an edit that drops or changes the tag line keeps the earlier
    // agent's limits, so an approved or capped post can't be swapped out by editing the tag (fix 1.5, review F2).
    // An approval covers the text that was approved: an edit that changes it needs approving again.
    const [prior] = await t`select approved, body_key, agent_id from app.gh_posts where node_id = ${ev.post.node_id}`;
    if (prior && prior.agent_id && (!agent || agent.id !== prior.agent_id)) {
      [agent] = await t`select * from app.gh_agents where id = ${prior.agent_id}`;
    }
    const approved = Boolean(prior && prior.approved && prior.body_key === bodyKey);
    // A linked machine account's post that names no registered agent of its owner (no tag line, or a tag naming an agent
    // that doesn't exist, was removed or has expired) would skip the owner's off, draft and cap limits (fix 1.2). For now
    // it alerts, once, when it is made, and asks for the tag; whether such posts are hidden is Aaron's decision
    // (harness/PLAN.md section 4). A post that is only commands (/agent, /approve, /appeal) is not asked.
    // At most 10 lines, the most commands one post runs, so a post of many command-shaped lines still counts (review T2).
    const lines = String(body).split('\n').map((l) => l.trim()).filter(Boolean);
    const commandsOnly = lines.length <= 10
      && lines.every((l) => /^\/(approve|appeal)$/i.test(l) || J.agentTag(l) || (J.parseCommands(l)[0] || { op: 'unknown' }).op !== 'unknown');
    const machineNoAgent = acct.id !== principal && !agent && !commandsOnly;
    // An approved post whose agent has since been removed has no limits left to apply; a machine account changing its
    // text alerts, even on an edit (review R2).
    const swapped = machineNoAgent && ev.action === 'edited' && Boolean(prior && prior.approved) && !approved;
    if (machineNoAgent && !tag && ev.action === 'created') {
      out.replies.push('This post is from ' + at(acct.login) + ', a machine account linked to ' + at(principalLogin) + ', but has no agent tag line, so its owner\'s agent limits can\'t be applied. End posts from this account with `— agent <name> for @' + principalLogin + '`.');
    }

    // Signals: counts only.
    const created = new Date(ev.post.created_at);
    const thread = ev.post.thread_node_id || ev.post.node_id;
    const [sig] = await t`
      with mine as (select id from app.gh_accounts where id = ${principal} or owner_id = ${principal})
      select
        (select count(*)::int from app.gh_posts where author_id in (select id from mine) and created_at > now() - interval '1 hour' and node_id <> ${ev.post.node_id}) as posts_1h,
        (select count(*)::int from app.gh_posts where author_id in (select id from mine) and created_at between now() - interval '15 days' and now() - interval '1 hour') as posts_before,
        (select count(*)::int from app.gh_posts p where p.author_id in (select id from mine) and p.hidden and p.created_at > now() - interval '90 days'
           and exists (select 1 from app.gh_decisions d where d.post_id = p.id and d.effect = 'hide'
             and (d.reason in ('banned', 'high_risk') or d.risk = 'high'))) as hidden_90d,
        (select count(distinct author_id)::int from app.gh_posts where author_id not in (select id from mine) and simhash is not null
           and ${text.simhash}::bigint is not null and created_at > now() - interval '7 days' and created_at < ${created}
           and bit_count((simhash # ${text.simhash}::bigint)::bit(64)) <= ${J.NEAR_BITS}) as copies,
        (select count(*)::int from unnest(${domainKeys}::text[]) d(k) where not exists (
           select 1 from app.gh_post_domains pd join app.gh_posts p on p.id = pd.post_id
           where pd.domain_key = d.k and p.risk = 'low' and p.created_at < now() - interval '1 day')) as new_domains,
        (select count(*)::int from app.gh_posts where ${agent ? agent.id : null}::uuid is not null and agent_id is not null
           and coalesce(thread_node_id, node_id) = ${thread} and node_id <> ${ev.post.node_id} and created_at > now() - interval '1 hour') as reply_depth,
        (select count(*)::int from app.gh_posts where ${agent ? agent.id : null}::uuid is not null and agent_id = ${agent ? agent.id : null}::uuid
           and created_at > now() - interval '24 hours' and node_id <> ${ev.post.node_id}) as agent_posts_24h`;
    const ageHours = acct.github_created_at ? (Date.now() - new Date(acct.github_created_at).getTime()) / 3600000 : null;
    const signals = { ...sig, age_hours: ageHours, links: text.links, contacts: text.contacts, hidden: text.hidden, impersonation, claims: text.claims && !founder };

    const action = ev.action === 'created' ? 'post.create' : 'post.edit';
    const scores = J.score(action, signals);
    const r = J.risk(scores, th);

    // What JEVs does. The ban list first, then the owner's own limits (off, draft, daily cap), then risk.
    let reason = '';
    if (banned) reason = 'banned';
    else if (agent && agent.mode === 'off') reason = 'agent_off';
    else if (agent && agent.mode === 'draft' && !approved) reason = 'agent_draft';
    else if (agent && action === 'post.create' && sig.agent_posts_24h >= agent.daily_cap) reason = 'agent_cap';
    else if (r.level === 'high') reason = 'high_risk';
    else if (machineNoAgent) reason = 'machine_no_agent';
    const alertOnly = reason === 'machine_no_agent'; // never hidden (see above)
    // GitHub can hide a comment but not a discussion, so a discussion that would be hidden is alerted instead.
    const hideable = ev.event === 'discussion_comment';
    const effect = reason && hideable && !alertOnly ? 'hide' : (reason && !(reason.startsWith('agent_'))) || scores.J16 > 0 || scores.J17 > 0 ? 'alert' : 'none';
    // A discussion can't be hidden: a banned or high-risk one alerts Aaron, once, when it is started. An agent's own
    // limits (off, draft, cap) on a discussion are the owner's business and alert no one.
    const ownLimit = reason === 'agent_off' || reason === 'agent_draft' || reason === 'agent_cap';
    if (r.level === 'high' || scores.J16 > 0 || scores.J17 > 0 || ((reason && !hideable && !ownLimit || alertOnly) && ev.action === 'created') || swapped) out.alert = true;
    out.hide = effect === 'hide' && mode === 'enforce';
    if (out.hide) out.replies.push(HIDDEN_BECAUSE[reason]);

    const [post] = await t`insert into app.gh_posts (node_id, kind, discussion_number, thread_node_id, author_id, agent_id, created_at, body_key, simhash, risk, hidden)
      values (${ev.post.node_id}, ${ev.event === 'discussion' ? 'discussion' : 'comment'}, ${ev.discussion}, ${ev.post.thread_node_id || null}, ${acct.id},
              ${agent ? agent.id : null}, ${created}, ${bodyKey}, ${text.simhash}::bigint, ${r.level}, ${out.hide})
      on conflict (node_id) do update set edited_at = case when app.gh_posts.body_key = excluded.body_key then app.gh_posts.edited_at else now() end, body_key = excluded.body_key, simhash = excluded.simhash, risk = excluded.risk,
        agent_id = excluded.agent_id, hidden = app.gh_posts.hidden or excluded.hidden,
        approved = app.gh_posts.approved and app.gh_posts.body_key = excluded.body_key
      returning id`;
    await t`delete from app.gh_post_domains where post_id = ${post.id}`;
    for (const k of new Set(domainKeys)) await t`insert into app.gh_post_domains (post_id, domain_key) values (${post.id}, ${k})`;
    await record(t, out, { action, account: acct.id, post: post.id, agent: agent ? agent.id : null, scores, level: r.level, effect, reason, mode });

    // JEVs-1: a new account's record and level, decided on its first post.
    if (out.first) {
      const std = J.score('account.first', signals);
      const ar = J.risk(std, th);
      const promote = J.passes(std, th) && ar.level !== 'high';
      if (promote) await t`update app.gh_accounts set level = 2 where id = ${acct.id}`;
      if (ar.level === 'high') out.alert = true;
      await record(t, out, { action: 'account.first', account: acct.id, scores: std, level: ar.level, effect: promote ? 'promote' : ar.level === 'high' ? 'alert' : 'none', mode });
      out.level = promote ? 2 : 1;
    } else {
      out.level = acct.level;
    }

    if (ev.action === 'created') await moderate(t, out, { ev, acct, principal, mode, body, tagged: Boolean(tag), banned });

    // Signing in to the site with a code (023; Aaron, Oct 28). A new comment that is exactly a sign-in code claims it
    // for the GitHub account that posted it, by that account's fingerprint: the same keyed hash GitHub sign-in uses,
    // made with the same key (dog_fingerprint_key_1). The post was scored above like any other. A banned account claims
    // nothing. The workflow then hides the code comment, used or not, and replies, which GitHub tells the poster about:
    // the alert if someone talked them into posting a code that wasn't theirs. A code claimed by the founder's account
    // (Aaron's, which Claude also posts as) also alerts on the JEVs alerts issue, outside the site, where a session made
    // from it can't hide the alert: that session would be the administrator's (the CSO's review, finding 1).
    const code = ev.event === 'discussion_comment' && ev.action === 'created' ? J.signinCode(body) : null;
    if (code) {
      let claimed = false;
      if (!banned) {
        const [c] = await t`select app.code_claim(${await J.keyed(key, 'signin-code:' + code)}, ${await J.keyed(key, 'github:' + ev.author.id)},
          ${await J.keyed(key, 'signin-login:' + ev.author.login.toLowerCase())}) as ok`;
        claimed = Boolean(c && c.ok);
      }
      const founderClaim = claimed && ev.author.id === FOUNDER_ID;
      out.signin = { claimed, founder: founderClaim };
      if (founderClaim) out.alert = true;
      out.replies.push(claimed ? SIGNED_IN(ev.author.login) : NOT_SIGNED_IN);
    }

    const reply = out.replies.length ? out.replies.join('\n\n') : null;
    delete out.replies;
    return { ...out, reply };
  });
}
