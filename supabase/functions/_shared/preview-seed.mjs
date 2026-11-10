// The preview copy's made-up data (RK141; design/preview-copy.md). Run once on a freshly migrated, empty copy of the
// database: it makes the copy's own three site keys inside the database (nobody sees them), marks the database as a
// preview copy, and adds made-up members, an administrator, agents, posts, a project and tasks through the database's
// own functions, under the same roles the site, the sign-in and JEVs use.
//
// It refuses any database that already holds a member, an agent, a post, a site key or the mark (production holds all
// but the mark), so it can never add made-up data to production, and it never runs twice on the same copy: to start
// again the copy is reset and migrated first. Everything happens in one transaction, so a refusal or a failure leaves
// nothing behind.
//
// No usable credential is made: every session and agent key is a random hash whose secret never existed, so nobody can
// sign in as a made-up account or act as a made-up agent. The made-up accounts exist to give the copy realistic data.
//
// Plain JavaScript taking a postgres.js connection, like the key broker's core.mjs, so the same file runs in the tests
// (Node) and in a Supabase function on the preview branch (Deno). It lives here, under supabase/functions, because a
// function can be deployed only with files from there (scripts/function-digests.js); no function imports it yet (the
// branch's runner is the next step, design/preview-copy.md). The connection must be the database's own owner login
// (Supabase's SUPABASE_DB_URL), which can take the dog_* roles as the migrations do.

export const MARKER = 'dog_preview_copy';
// The Vault names the key broker hands out (supabase/functions/dog-keys/core.mjs KEYS), made here for the copy only.
export const SITE_KEYS = ['dog_session_secret', 'dog_ip_hash_key', 'dog_fingerprint_key_1'];
const ROOM = '15-0000'; // Computer & Mathematical (042)

// Made-up and plainly labelled: no real person, GitHub account or address.
export const PLAN = {
  members: [
    { name: 'Copy Admin', admin: true, level: 2 },
    { name: 'Copy Member Ada', level: 2 },
    { name: 'Copy Member Ben', level: 2 },
    { name: 'Copy Member Cy', level: 2 },
    { name: 'Copy Newcomer Dee', level: 1 }
  ],
  agents: [
    { owner: 'Copy Member Ada', name: 'copy-helper-ada', description: 'A made-up agent on the preview copy.' },
    { owner: 'Copy Member Ben', name: 'copy-helper-ben', description: 'A made-up agent on the preview copy.' }
  ],
  posts: [
    { by: 'Copy Admin', body: 'Welcome to the preview copy. Everything here is made up, and it is reset for each pull request.' },
    { by: 'Copy Member Ada', body: 'Testing a post on the preview copy: nothing here is real.' },
    { by: 'Copy Member Ben', body: 'A second made-up post, so the feed has more than one author.' },
    { by: 'Copy Member Cy', body: 'Made-up post three. Red teams attack this copy, never the live site.' },
    { by: 'Copy Newcomer Dee', body: 'A newcomer at level 1 says hello on the preview copy.' }
  ],
  projects: [
    { by: 'Copy Admin', title: 'Preview copy project', description: 'A made-up project with tasks to claim on the preview copy.',
      tasks: [
        { title: 'Made-up task for an agent', description: 'Nothing real depends on this.', class: 'agent', size: 1 },
        { title: 'Made-up task for a person', description: 'Nothing real depends on this.', class: 'person', size: 2 },
        { title: 'Made-up task for either', description: 'Nothing real depends on this.', class: 'either', size: 3 }
      ] }
  ]
};

// Why this database may not be seeded, or null when it may. Read-only. Two independent facts each refuse production:
// it holds members, agents and posts, and its Vault holds the three site keys (harness/FACTS.md, Oct 25, names only).
// The rows are counted as the connecting login itself, never as dog_owner: every app table forces row-level security,
// and dog_owner has no policy on app.posts, so as dog_owner a full table would count 0 (tested). The owner login sees
// every row (a superuser here; Supabase's postgres login can bypass row-level security), and a count it can't read
// fails the whole seed.
export async function refusal(t) {
  const [s] = await t`select to_regclass('app.members') is not null as app, to_regnamespace('vault') is not null as vault`;
  if (!s.app) return 'not migrated: app.members is missing';
  if (!s.vault) return 'no Vault: the preview copy runs only on a Supabase database';
  const [n] = await t`select (select count(*) from app.members)::int as members, (select count(*) from app.agents)::int as agents,
    (select count(*) from app.posts)::int as posts`;
  const [v] = await t`select count(*) filter (where name = ${MARKER})::int as marker,
    count(*) filter (where name = any(${SITE_KEYS}))::int as keys from vault.secrets`;
  if (v.marker) return 'already a seeded preview copy: reset and migrate it first';
  if (v.keys) return 'this database already has site keys in Vault: it is not a fresh copy';
  if (n.members || n.agents || n.posts) return 'this database already has members, agents or posts: it is not a fresh copy';
  return null;
}

// Random hex from Postgres's own strong random source (gen_random_uuid, built in): 64 characters, 244 random bits.
// Written inside each query, so no value is ever put into SQL as text (no raw SQL here: .semgrep/database.yml).
const hex64 = (t) => t`select replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '') as h`.then(([r]) => r.h);

// As the member (or administrator) whose made-up session hash we hold: exactly how db/index.js tx() acts for a request.
async function actAs(t, who, { admin = false } = {}) {
  await t`set local role dog_app`;
  await t`select set_config('app.req_ip', '', true), set_config('app.req_ua', 'preview-seed.mjs', true),
                 set_config('app.req_referer', '', true), set_config('app.req_method', '', true),
                 set_config('app.req_path', '', true), set_config('app.req_host', '', true), set_config('app.note', '', true)`;
  await t`select app.act_as(${admin ? 'admin' : 'member'}, ${who.id}::uuid, null::uuid, false, ${who.session}, null, null)`;
}

// JEVs's decision for a made-up action, as db/jevs.js check() records it: nothing scored, so the database decides on
// the action's own rules. The site's JEVs is in enforce mode (028), which refuses a post with no decision.
async function decide(t, action, subject, impact) {
  await t`select app.jevs_signals(${action}, ${subject}::uuid, null, null::text[], null::bigint)`;
  const [d] = await t`select * from app.jevs_decide(${action}, ${subject}::uuid, ${t.json({})}, ${impact}, false, null::text[], null::bigint, null)`;
  return d;
}

export async function seed(sql, { log = () => {} } = {}) {
  return sql.begin(async (t) => {
    const why = await refusal(t);
    if (why) throw new Error('seed refused: ' + why);
    // No migration switches to dog_app, so the owner login may not be allowed to (unknown on Supabase). If it isn't, it
    // takes dog_app for this transaction only and gives it back at the end, leaving the roles as the migrations made them.
    const [{ can }] = await t`select pg_has_role(current_user, 'dog_app', 'SET') as can`;
    if (!can) await t`grant dog_app to current_user`;

    // The copy's own keys, made and kept inside its database (the key broker hands them to the copy's preview site).
    // 128 hex characters each, made and kept in the database: never returned, logged or seen.
    for (const name of SITE_KEYS) {
      await t`select vault.create_secret(replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')
        || replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''), ${name}, 'Preview copy only (preview-seed.mjs)')`;
    }
    await t`select vault.create_secret('yes', ${MARKER}, 'This database is the preview copy: made-up data only (preview-seed.mjs)')`;

    const members = {};
    for (const m of PLAN.members) {
      const h = { fp: await hex64(t), session: await hex64(t) };
      await t`set local role dog_signin`;
      const [r] = await t`select * from app.sign_in('github', ${[h.fp]}::text[], 1::smallint, 1::smallint, ${m.name}, ${h.session},
        30, null::timestamptz, null::uuid, null)`;
      await t`reset role`;
      if (m.level === 2) {
        await t`set local role dog_jevs`;
        await t`update app.members set jevs_level2_at = now(), trust_level = 2 where id = ${r.member_id}`;
        await t`reset role`;
      }
      if (m.admin) {
        await t`set local role dog_owner`;
        await t`update app.members set is_admin = true where id = ${r.member_id}`;
        await t`reset role`;
      }
      members[m.name] = { id: r.member_id, session: h.session, admin: Boolean(m.admin) };
    }

    let agents = 0;
    for (const a of PLAN.agents) {
      const who = members[a.owner];
      await actAs(t, who);
      const d = await decide(t, 'agent.create', null, 'high');
      if (d.applied && d.effect === 'hold') throw new Error('seed: JEVs held a made-up agent');
      const key = await hex64(t);
      const [g] = await t`insert into app.agents (name, description) values (${a.name}, ${a.description}) returning id`;
      await t`insert into app.agent_keys (agent_id, key_hash) values (${g.id}, ${key})`;
      await t`reset role`;
      agents++;
    }

    let posts = 0;
    for (const p of PLAN.posts) {
      await actAs(t, members[p.by]);
      const [row] = await t`insert into app.posts (body) values (${p.body}) returning id`;
      await decide(t, 'post.create', row.id, 'low');
      await t`reset role`;
      posts++;
    }

    let projects = 0, tasks = 0;
    for (const pj of PLAN.projects) {
      const who = members[pj.by];
      await actAs(t, who, { admin: who.admin });
      const [{ id }] = await t`select app.work_project_create(${pj.title}, ${pj.description}, ${ROOM}) as id`;
      projects++;
      for (const k of pj.tasks) {
        await t`select app.work_task_create(${id}::uuid, ${k.title}, ${k.description}, ${k.class}, ${k.size}::integer)`;
        tasks++;
      }
      await t`reset role`;
    }

    if (!can) await t`revoke dog_app from current_user`;
    const out = { members: PLAN.members.length, admins: PLAN.members.filter((m) => m.admin).length, agents, posts, projects, tasks, keys: SITE_KEYS.length, marker: true };
    log('seeded ' + JSON.stringify(out));
    return out;
  });
}
