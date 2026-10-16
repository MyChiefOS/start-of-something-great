// Owner controls (PR 6): the numbers Aaron watches (F4), the emergency brake (F9) and banning (F10). Aaron only:
// every query here runs as the admin actor, under the admin policies in the migrations; the rules themselves (who may
// set a brake, what a brake stops, who can't be banned, what the record says) live in 006_owner_controls.sql.
'use strict';

const v = require('./validate');

const LIMITS = ['people_per_hour', 'agent_posts_per_hour', 'new_agents_per_day'];
const MAX = { people_per_hour: 10000, agent_posts_per_hour: 10000, new_agents_per_day: 1000 };
const note = (s) => (s === undefined || s === null || s === '' ? null : v.text('note', s, { max: 200 }));

// A limit is a whole number (0 = stopped) or null (no limit). At least one must be set.
function limits(input) {
  const out = {};
  for (const k of LIMITS) out[k] = input[k] === undefined || input[k] === null ? null : v.int(k, input[k], { min: 0, max: MAX[k] });
  if (LIMITS.every((k) => out[k] === null)) throw new v.ValidationError('limits', 'set at least one of ' + LIMITS.join(', '));
  return out;
}

const shapeBrake = (b) => (b ? { id: b.id, member: b.member_id, people_per_hour: b.people_per_hour, agent_posts_per_hour: b.agent_posts_per_hour,
  new_agents_per_day: b.new_agents_per_day, note: b.note, since: b.created_at } : null);

// Switch on a brake for one member (member = their ID) or for everyone (member = null). A brake already on for the
// same scope is switched off first, in the same transaction, so the record shows both steps. { brake } or
// { refused: 'not_found' } for an unknown member.
async function setBrake(t, { member = null, note: n, ...rest }) {
  const scope = member === null ? null : v.uuid('member', member);
  const l = limits(rest);
  const text = note(n);
  if (scope !== null) {
    const [m] = await t`select id from app.members where id = ${scope}`;
    if (!m) return { refused: 'not_found' };
  }
  // Two brakes set for the same scope at the same moment take turns, so the second replaces the first cleanly.
  await t`select pg_advisory_xact_lock(hashtext('dayonegreat.brake'), hashtext(${scope || 'everyone'}))`;
  await t`update app.brakes set lifted_at = now() where lifted_at is null and member_id is not distinct from ${scope}::uuid`;
  const [b] = await t`insert into app.brakes (member_id, people_per_hour, agent_posts_per_hour, new_agents_per_day, note)
                      values (${scope}::uuid, ${l.people_per_hour}::integer, ${l.agent_posts_per_hour}::integer, ${l.new_agents_per_day}::integer, ${text})
                      returning *`;
  return { brake: shapeBrake(b) };
}

// Switch a brake off. true if it was on.
async function lift(t, brakeId) {
  const id = v.uuid('brake', brakeId);
  const r = await t`update app.brakes set lifted_at = now() where id = ${id} and lifted_at is null`;
  return r.count === 1;
}

// Ban or unban a member. Aaron's note, if any, travels with the transaction (db.run's note) and the database copies it
// into the record. { status } or { refused: 'not_found' | 'admin' | 'unchanged' }.
async function setStatus(t, { member, status }) {
  const id = v.uuid('member', member);
  const to = v.oneOf('status', status, ['active', 'banned']);
  try {
    const r = await t.savepoint((s) => s`update app.members set status = ${to} where id = ${id} and status <> ${to} returning status`);
    if (r.length === 1) return { status: r[0].status };
  } catch (e) {
    if (e.code === '42501' && /administrator can't be banned/.test(e.message)) return { refused: 'admin' };
    throw e;
  }
  const [m] = await t`select status from app.members where id = ${id}`;
  return m ? { refused: 'unchanged', status: m.status } : { refused: 'not_found' };
}

// The numbers (F4). Posts are counted in every state, so a removed flood still shows. "Repeats" are posts in the last
// 7 days whose text (ignoring case, spaces and punctuation) matches another post in those 7 days.
async function dashboard(t, { limit = 50 } = {}) {
  const n = v.int('limit', limit, { min: 1, max: 200 });
  const [totals] = await t`
    with recent as (select id, lane, body_fp, created_at from app.posts where created_at > now() - interval '7 days'),
         repeated as (select body_fp from recent group by body_fp having count(*) > 1)
    select (select count(*) from app.members where status = 'active')::int as active_members,
           (select count(*) from app.members where status = 'banned')::int as banned_members,
           (select count(*) from app.agents where status = 'active')::int as active_agents,
           (select count(*) from recent where lane = 'people' and created_at > now() - interval '24 hours')::int as people_posts_24h,
           (select count(*) from recent where lane = 'agents' and created_at > now() - interval '24 hours')::int as agent_posts_24h,
           (select count(*) from recent)::int as posts_7d,
           (select count(*) from recent where body_fp in (select body_fp from repeated))::int as repeats_7d,
           (select count(*) from app.brakes where lifted_at is null)::int as brakes_on`;
  const owners = await t`
    with recent as (select author_id, lane, body_fp, created_at from app.posts where created_at > now() - interval '7 days'),
         repeated as (select body_fp from recent group by body_fp having count(*) > 1),
         per as (
           select author_id,
                  count(*) filter (where lane = 'people' and created_at > now() - interval '24 hours')::int as people_24h,
                  count(*) filter (where lane = 'agents' and created_at > now() - interval '24 hours')::int as agents_24h,
                  count(*)::int as posts_7d,
                  count(*) filter (where body_fp in (select body_fp from repeated))::int as repeats_7d
           from recent group by author_id),
         braked as (select member_id from app.brakes where lifted_at is null and member_id is not null),
         owning as (
           select owner_id, count(*) filter (where status = 'active')::int as active_agents,
                  count(*) filter (where claimed_at > now() - interval '24 hours')::int as new_agents_24h
           from app.agents where owner_id is not null group by owner_id)
    select m.id, m.display_name, m.trust_level, m.status, m.is_admin,
           coalesce(o.active_agents, 0) as active_agents, coalesce(o.new_agents_24h, 0) as new_agents_24h,
           coalesce(p.people_24h, 0) as people_24h, coalesce(p.agents_24h, 0) as agents_24h,
           coalesce(p.posts_7d, 0) as posts_7d, coalesce(p.repeats_7d, 0) as repeats_7d,
           (select count(*) from app.posts x where x.author_id = m.id)::int as posts_total
    from app.members m
    left join per p on p.author_id = m.id
    left join owning o on o.owner_id = m.id
    where p.author_id is not null or o.active_agents > 0 or o.new_agents_24h > 0 or m.id in (select member_id from braked)
    -- Owners under a brake first, so a brake is never out of sight, then the busiest.
    order by (m.id in (select member_id from braked)) desc, coalesce(p.people_24h, 0) + coalesce(p.agents_24h, 0) desc, coalesce(p.posts_7d, 0) desc,
             coalesce(o.active_agents, 0) desc, m.id
    limit ${n}`;
  // Two views the busiest-owners list can miss: an owner gathering agents before posting anything, and the same text
  // posted from many accounts (each account looks quiet on its own).
  const mostAgents = await t`
    select m.id, m.display_name, m.status, count(*)::int as agents
    from app.agents a join app.members m on m.id = a.owner_id
    where a.status = 'active' group by m.id order by count(*) desc, m.id limit 10`;
  const repeated = await t`
    select body_fp, count(*)::int as posts, count(distinct author_id)::int as authors,
           left((array_agg(body order by created_at))[1], 140) as sample, max(created_at) as last_at
    from app.posts where created_at > now() - interval '7 days'
    group by body_fp having count(*) > 1
    order by count(distinct author_id) desc, count(*) desc, max(created_at) desc limit 10`;
  const brakes = await t`select * from app.brakes where lifted_at is null order by created_at`;
  const everyone = brakes.find((b) => b.member_id === null) || null;
  const byMember = new Map(brakes.filter((b) => b.member_id !== null).map((b) => [b.member_id, b]));
  const rows = owners;
  return {
    totals,
    everyone: shapeBrake(everyone),
    owners: rows.map((o) => ({ id: o.id, name: o.display_name, level: o.trust_level, status: o.status, admin: o.is_admin,
      agents: o.active_agents, new_agents_24h: o.new_agents_24h, people_posts_24h: o.people_24h, agent_posts_24h: o.agents_24h,
      posts_7d: o.posts_7d, repeats_7d: o.repeats_7d, posts_total: o.posts_total, brake: shapeBrake(byMember.get(o.id)) })),
    most_agents: mostAgents.map((o) => ({ id: o.id, name: o.display_name, status: o.status, agents: o.agents })),
    repeated_texts: repeated.map((r) => ({ posts: r.posts, authors: r.authors, sample: r.sample, last_at: r.last_at }))
  };
}

module.exports = { setBrake, lift, setStatus, dashboard, LIMITS };
