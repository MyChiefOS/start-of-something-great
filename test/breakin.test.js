// S2, S3: the fixed break-in suite. It reads the list of tables from the database itself, so a table added later is
// covered automatically: anyone who can see or change a row of a new table fails this suite until a reviewed
// expectation says they may (the ratchet in ACCEPTANCE.md). Member A has data in every table; someone not signed in,
// member B and B's agent each try to read and change everything.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const postgres = require('postgres');
const db = require('../db');
const c = require('../signin/crypto');
const store = require('../db/signin');
const posts = require('../db/posts');
const review = require('../db/review');
const controls = require('../db/controls');
const jevs = require('../db/jevs');
const { migrate } = require('../scripts/migrate');
const { trustSystem, promote, shadowMode, asSignin } = require('./helpers');

const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('break-in tests need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('break-in suite (S2, S3)', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}

const NAME = 'dog_breakin_test_' + crypto.randomBytes(4).toString('hex');
const WEB = NAME + '_web';
const PW = crypto.randomBytes(18).toString('base64url');
let server, su, web;
const at = (base, d, user, password) => { const u = new URL(base); u.pathname = '/' + d; if (user) { u.username = user; u.password = password; } return u.toString(); };
const run = (ctx, fn) => db.tx(web, ctx, fn);
const q = (s) => su.unsafe(s);
let A, B, BAgent, tables;

// What each outsider may see: their own rows, nothing else. Any table not listed here may show them nothing.
// jevs_settings: everyone sees the one public row, JEVs's mode (shadow or enforce); never a threshold (PR 12).
// subagent_settings: anyone signed in sees the one row of limits sub-agents are made within (PR 16; public in 013).
// timer_slot (027): its one row, the heartbeat, which anyone may read (only when the timers last finished).
// invariant_slot (032): the same for the hourly never-break checks (only when they last finished).
// The public log (038): every row of its tree, checkpoints, head, the key's public half and the witness reading is public
// by design (random IDs and keyed hashes only), so everyone sees all of them, and nobody may change any (below). The
// key's seed and the keyed hashes' keys (app.log_openings) stay out of reach like every private table.
const PUBLIC_LOG = new Set(['log_entries', 'log_nodes', 'log_checkpoints', 'log_head', 'log_keys', 'log_witness']);
const MAY_SEE = {
  anon: { jevs_settings: 1, timer_slot: 1, invariant_slot: 1 },
  B: { members: 1, identities: 1, sessions: 1, agents: 1, agent_keys: 1, agent_rules: 1, jevs_settings: 1, subagent_settings: 1, timer_slot: 1, invariant_slot: 1 },
  BAgent: { members: 1, agents: 1, agent_rules: 1, jevs_settings: 1, subagent_settings: 1, timer_slot: 1, invariant_slot: 1 }
};

async function signIn(level, name, fp = c.sha256hex(crypto.randomUUID())) {
  const token = c.token(32);
  const out = await asSignin(su)((t) => store.signIn(t, { provider: 'github', fingerprints: [fp], keyVersion: 1,
    level: Math.min(level, 1), displayName: name, sessionHash: c.sha256hex(token), sessionDays: 30 }));
  if (level >= 2) await promote(su, out.memberId);
  return { id: out.memberId, fp, sessionHash: c.sha256hex(token), ctx: { actor: 'member', memberId: out.memberId, session: c.sha256hex(token) } };
}

test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  su = postgres(at(SERVER, NAME), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
  await shadowMode(su); // the features under JEVs, tested without it (helpers.js)
  await su.unsafe(`create role ${WEB} login noinherit password '${PW}'; grant dog_app to ${WEB}`);
  web = db.connect(at(SERVER, NAME, WEB, PW), { ssl: false, max: 3 });
  await trustSystem(su); // fix 3: the site itself acts only with its own secret

  // Aaron, so A's footprint includes moderation, brakes and notes.
  const aaron = await signIn(2, 'Aaron');
  await su.begin(async (t) => { await t.unsafe('set local role dog_owner'); await t.unsafe(`update app.members set is_admin = true where id = '${aaron.id}'`); });
  const admin = { actor: 'admin', memberId: aaron.id, session: aaron.sessionHash };
  // Member A, with something in every table.
  A = await signIn(2, 'Member A');
  const [agent] = await run(A.ctx, (t) => t`insert into app.agents (name) values ('A agent') returning id`);
  await run(A.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${agent.id}, ${c.sha256hex('a-key')})`);
  const aAgent = { actor: 'agent', memberId: A.id, agentId: agent.id, keyHash: c.sha256hex('a-key') };
  await run(aAgent, (t) => t`insert into app.agent_drafts (body) values ('A draft')`);
  // A's post goes through JEVs, which leaves a decision, a text print and a link domain (PR 12).
  const p = await run(A.ctx, async (t) => {
    const made = await posts.create(t, { body: 'A post that links to https://a-example.org and has enough words to leave a print' });
    made.jevs = await jevs.check(t, { action: 'post.create', subject: made.id, body: 'A post that links to https://a-example.org and has enough words to leave a print' });
    return made;
  });
  await run(A.ctx, (t) => jevs.mark(t, { kind: 'net', keyHash: c.sha256hex('A network') }));
  // A domain row as JEVs keeps it for a low-risk post; A's own post no longer is one since 021 (a GitHub method scores
  // J02 = 10), so the row is written here.
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_jevs');
    await t.unsafe(`insert into app.jevs_post_domains (post_id, domain_hash) values ('${p.id}', '${c.sha256hex('a-example.org')}') on conflict do nothing`);
  });
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_jevs');
    await t.unsafe(`insert into app.jevs_challenges (decision_id, owner_id, action, subject_kind, subject_id, expires_at)
                    values ('${p.jevs.decision}', '${A.id}', 'post.create', 'post', '${p.id}', now() + interval '1 day')`);
  });
  // Second Look's suggestion on a post of A's that JEVs held (033), written as the database's own function would.
  await su.begin(async (t) => {
    await t.unsafe(`insert into app.review_flags (post_id, source, classifier, score) values ('${p.id}', 'classifier', 'jevs', 0.9)`);
    await t.unsafe('set local role dog_jevs');
    await t.unsafe(`insert into app.sl_reviews (post_id, model, eligible, score, suggestion, reasons) values ('${p.id}', 'v0', true, 0.9, 'clear', 'held for links')`);
    // Second Look v1 (034): the post handed to the model, its decision, and its publication.
    await t.unsafe(`insert into app.sl_claims (post_id) values ('${p.id}')`);
    const [d] = await t.unsafe(`insert into app.sl_decisions (post_id, version, model, mode, decision, answers, risk, reason, fail_closed, latency_ms)
      values ('${p.id}', 'v1', 'mistral/ministral-3b', 'shadow', 'leave', null, 25, 'no usable answer from the model (timeout)', true, 3000) returning id`);
    await t.unsafe(`insert into app.sl_releases (post_id, decision_id) values ('${p.id}', '${d.id}')`);
    // Aaron's decision on a shadow clear, kept as an outcome (it names no post or person; nobody but him reads it).
    await t.unsafe(`insert into app.sl_outcomes (approved) values (true)`);
    // 041: A's post drawn for the sample, and a planted test (canary), made ahead of time as the timer makes them.
    await t.unsafe(`insert into app.review_samples (post_id) values ('${p.id}')`);
    await t.unsafe(`select app.review_canary_make()`);
    // And one day of the public oversight figures, counted as the timer counts them (counts only, no member's row).
    await t.unsafe(`select app.review_count_day((now() at time zone 'UTC')::date - 3)`);
  });
  // The public log (038): an entry for A's post with its opening (the key of its keyed hash), a signed checkpoint and a
  // proposal decision, written by the log's own functions in its own role.
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_log');
    await t.unsafe(`select app.log_post('${p.id}', '${agent.id}', '${A.id}', 'rules', 1, 'A post', now())`);
    await t.unsafe(`select app.log_checkpoint()`);
  });
  // Since 057 (RK112) a proposal decision comes only from GitHub's facts, as dog_ghsync.
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_ghsync');
    await t.unsafe(`select app.log_proposals_record('[{"number": 1, "status": "approved"}]'::jsonb)`);
  });
  // 041: a reviewer's decision on A's post (as the test's superuser; the site writes it in app.review_record).
  await q(`insert into app.review_decisions (post_id, decided_by, decision, tier, item_type, reason, bound_sha256, prior_status)
    values ('${p.id}', '${A.id}', 'remove', 2, 'held', 'spam', repeat('a', 64), 'live')`);
  // 042: A's work: a project and a task A posted, B's... no: everything here is A's own (A's claim, submission, points,
  // a dispute A opened, Aaron's vote and the check after), and one pull request with a claim code from GitHub. Written
  // directly as the test's superuser; the work module writes them through its own functions.
  await su.begin(async (t) => {
    const [room] = await t.unsafe(`select id from app.work_rooms where code = '15-0000'`);
    const [pj] = await t.unsafe(`insert into app.work_projects (title, room_id, source, poster_member) values ('A project', '${room.id}', 'member', '${A.id}') returning id`);
    const [tk] = await t.unsafe(`insert into app.work_tasks (project_id, room_id, title, class, size, source, poster_member) values ('${pj.id}', '${room.id}', 'A task', 'either', 1, 'member', '${A.id}') returning id`);
    const [cl] = await t.unsafe(`insert into app.work_claims (task_id, member_id, code_hash, expires_at) values ('${tk.id}', '${A.id}', repeat('c', 64), now() + interval '1 day') returning id`);
    await t.unsafe(`insert into app.work_actions (member_id, kind) values ('${A.id}', 'claim')`);
    await t.unsafe(`insert into app.work_github_prs (number, title, author, state, base, created_at) values (1, 'A pull request', 'a-dev', 'open', 'main', now())`);
    await t.unsafe(`insert into app.work_github_codes (pr_number, code_hash) values (1, repeat('c', 64))`);
    const [sb] = await t.unsafe(`insert into app.work_submissions (task_id, claim_id, worker_kind, worker_member, artifact_kind, artifact_url, seal_key, seal, status, decided_by)
      values ('${tk.id}', '${cl.id}', 'member', '${A.id}', 'link', 'https://example.org/a', decode(repeat('ab', 32), 'hex'), repeat('d', 64), 'passed', 'poster') returning id`);
    await t.unsafe(`insert into app.work_person_votes (submission_id, member_id, verdict, reason) values ('${sb.id}', '${A.id}', 'pass', 'A reason')`);
    await t.unsafe(`insert into app.work_points (submission_id, task_id, room_id, citizen_kind, citizen_member, size, confidence, independence, points, final_at)
      values ('${sb.id}', '${tk.id}', '${room.id}', 'member', '${A.id}', 1, 100, 100, 10, now() + interval '3 days')`);
    await t.unsafe(`insert into app.work_checks (submission_id, why) values ('${sb.id}', 'random')`);
    await t.unsafe(`insert into app.work_disputes (submission_id, member_id, reason) values ('${sb.id}', '${A.id}', 'A dispute')`);
    await t.unsafe(`insert into app.tl_reviews (submission_id, suggestion, reason) values ('${sb.id}', 'person', 'A reason')`);
    // 057: the changed files Third Look reads, and a claim given back.
    await t.unsafe(`insert into app.tl_files (number, files) values (1, '[{"filename": "a.js", "status": "modified", "changes": 1}]')`);
    await t.unsafe(`insert into app.tl_releases (submission_id, why) values ('${sb.id}', 'timeout')`);
    await t.unsafe(`insert into app.work_dispute_evidence (dispute_id, member_id, role, note) select d.id, '${A.id}', 'opener', 'A note' from app.work_disputes d where d.submission_id = '${sb.id}'`);
    await t.unsafe(`insert into app.work_milestones (project_id, code, title, first_target, target, source) values ('${pj.id}', 'M1', 'A milestone', current_date + 7, current_date + 7, 'member')`);
    // 056: the trust Engine's records about A's agent (a license and its change, a forecast citing a precedent, a
    // finding, a work order and its resume), written directly as the test's superuser; the Engine writes them through
    // its own functions.
    await t.unsafe(`insert into app.engine_licenses (agent_id, room_id, level, verified, succeeded, lower_bound, forecasts) values ('${agent.id}', '${room.id}', 0, 1, 1, 0.2065, 0)`);
    await t.unsafe(`insert into app.engine_license_history (agent_id, room_id, old_level, new_level, reason, verified, succeeded, lower_bound, forecasts)
      values ('${agent.id}', '${room.id}', 0, 0, 'suspended', 1, 1, 0.2065, 0)`);
    const [pc] = await t.unsafe(`insert into app.engine_precedents (room_id, facts, decision, reason, decided_by) values ('${room.id}', 'Facts of A''s case.', 'Pass', 'A reason for it.', '${A.id}') returning id`);
    const [fc] = await t.unsafe(`insert into app.engine_forecasts (claim_id, task_id, room_id, agent_id, chance_bp) values ('${cl.id}', '${tk.id}', '${room.id}', '${agent.id}', 5000) returning id`);
    await t.unsafe(`insert into app.engine_citations (forecast_id, precedent_id) values ('${fc.id}', '${pc.id}')`);
    await t.unsafe(`insert into app.engine_findings (agent_id, room_id, attack_class, succeeded, vaccine, found_by) values ('${agent.id}', '${room.id}', 'ASI01', true, 'A vaccine test', '${A.id}')`);
    const [od] = await t.unsafe(`insert into app.engine_orders (agent_id, project_id, created_by, goal_size, budget, deadline, rollback)
      values ('${agent.id}', '${pj.id}', '${A.id}', 1, 1, now() + interval '1 day', 'Undo it by hand.') returning id`);
    await t.unsafe(`insert into app.engine_order_resumes (order_id, member_id, add_budget, add_hours) values ('${od.id}', '${A.id}', 1, 0)`);
  });
  await run({ actor: 'anon' }, (t) => jevs.regionDecline(t, 'FR'));
  // A deletion review of A (PR 12), as JEVs opens one for a high-risk deletion.
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_jevs');
    await t.unsafe(`insert into app.deletion_reviews (member_id, decision_id) values ('${A.id}', '${p.jevs.decision}')`);
  });
  // 060: a legal hold on A (already lifted, so it holds nothing here), as the deletion role keeps one.
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_erase');
    await t.unsafe(`insert into app.legal_holds (member_id, reason, placed_by, lifted_at, lifted_by, lift_reason)
      values ('${A.id}', 'A hold for the fixture.', '${A.id}', now(), '${A.id}', 'Lifted for the fixture.')`);
  });
  const other = await signIn(2, 'Other');
  const op = await run(other.ctx, (t) => posts.create(t, { body: 'other post' }));
  await run(A.ctx, (t) => review.report(t, { post: op.id, reason: 'spam', note: 'A reports' }));
  await run(other.ctx, (t) => review.report(t, { post: p.id, reason: 'other' }));
  await run(admin, (t) => controls.setBrake(t, { member: A.id, people_per_hour: 100, note: 'A brake' }));
  await run({ ...admin, note: 'A note' }, (t) => controls.setStatus(t, { member: A.id, status: 'banned' }));
  await run(admin, (t) => controls.setStatus(t, { member: A.id, status: 'active' }));
  await run({ actor: 'anon' }, (t) => store.emailTokenIssue(t, { tokenHash: c.sha256hex('tok'), emailFingerprints: [c.sha256hex('a@example.com')],
    browserHash: c.sha256hex('browser'), keyVersion: 1 }));
  await run({ actor: 'anon' }, (t) => store.rateLimitHit(t, { bucket: 'breakin', keyHash: c.sha256hex('a'), windowSeconds: 60, max: 5 }));
  // 023 (Oct 28, 2026): a waiting sign-in code, and one the JEVs gate claimed (only its role may), as they are written.
  await run({ actor: 'anon' }, (t) => store.codeIssue(t, { codeHash: c.sha256hex('code one'), browserHash: c.sha256hex('code browser'), loginHash: c.sha256hex('login one'), fileKey: c.sha256hex('file one') }));
  await run({ actor: 'anon' }, (t) => store.codeIssue(t, { codeHash: c.sha256hex('code two'), browserHash: c.sha256hex('code browser 2'), loginHash: c.sha256hex('login two'), fileKey: c.sha256hex('file two') }));
  await su.begin(async (t) => { await t.unsafe('set local role dog_jevs'); await t.unsafe(`select app.code_claim('${c.sha256hex('code two')}', '${'e'.repeat(64)}', '${c.sha256hex('login two')}')`); });
  // A's key file (023, Oct 28), as a code sign-in keeps it (the sign-in role writes it).
  await su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(`insert into app.file_keys (member_id, fingerprint, login_hash, key_hash)
    values ('${A.id}', '${'f'.repeat(64)}', '${c.sha256hex('login a')}', '${c.sha256hex('key a')}')`); });
  // 037 (Nov 5, 2026): A's PIN (a keyed hash and its salt), a browser's public key and a one-time challenge, as the
  // sign-in role writes them, so the checks below prove nobody else can read them.
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_signin');
    await t.unsafe(`insert into app.signin_pins (member_id, salt, pin_hash) values ('${A.id}', '\\x${'1'.repeat(32)}', '\\x${'2'.repeat(64)}')`);
    await t.unsafe(`insert into app.browser_keys (member_id, public_key, label) values ('${A.id}', '\\x04${'3'.repeat(128)}', 'Firefox on Linux')`);
  });
  await run({ actor: 'anon' }, (t) => store.challengeIssue(t, 'https://dayonegreat.com'));
  // 026: a country the behaviour watch saw A sign in from (a keyed hash).
  await su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(`insert into app.watch_seen (member_id, kind, key_hash)
    values ('${A.id}', 'country', '${c.sha256hex('country a')}')`); });
  // PR 15's review (F6): a used traveller confirmation.
  await run({ actor: 'anon' }, (t) => store.regionConfirmUse(t, c.sha256hex('a traveller nonce')));
  // PR 13: A's notices (the brake and the draft above left some), a suppressed sign-in address and a containment.
  await run({ actor: 'system' }, (t) => t`insert into app.email_suppressions (address_fp, reason) values (${c.sha256hex('gone@example.com')}, 'bounce')`);
  await run({ actor: 'system' }, (t) => t`insert into app.containments (member_id, reason, measured, usual_x100, ends_at) values (${A.id}, 'volume', 600, 0, now() + interval '1 day')`);
  // The ban above ended A's sessions, so A signs in again, leaving a session row.
  A.sessionHash = (await signIn(2, 'Member A', A.fp)).sessionHash;
  A.ctx = { ...A.ctx, session: A.sessionHash };
  // 040: A's agent's recovery key, set the one way the site can (with a working key). After the ban, which took A's
  // agent keys and its recovery key (the review of Nov 5, H1), so A makes the agent a new key first.
  const [aAgentRow] = await su`select id from app.agents where owner_id = ${A.id} and name = 'A agent'`;
  await run(A.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${aAgentRow.id}, ${c.sha256hex('a-key-2')})`);
  await run({ actor: 'anon' }, (t) => t`select app.agent_recovery_issue(${c.sha256hex('a-key-2')}, ${c.sha256hex('a-recovery')}, null::text)`);
  // 030: the behaviour watch's web records for A's session and account (a request, and its sealed place), as the site
  // writes them, and a removal count.
  await run({ actor: 'anon' }, (t) => store.watchSession(t, { sessionHash: A.sessionHash, ua: c.sha256hex('ua a'), country: c.sha256hex('country a') }));
  await run({ actor: 'anon' }, (t) => store.watchTravel(t, { sessionHash: A.sessionHash, place: 'p'.repeat(64) }));
  await su.begin(async (t) => { await t.unsafe('set local role dog_signin'); await t.unsafe(`insert into app.watch_counts (member_id, kind, hour)
    values ('${A.id}', 'post.remove', date_trunc('hour', now()))`); });
  // PR 2 (Oct 24, 2026): one change-log row and one used runner token, as the migration runner writes them (dog_owner).
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_owner');
    // 027: the key broker's counts (written with the owner's rights, as the broker's login does).
    await t.unsafe(`insert into app.broker_uses (hour, handed, failed) values (date_trunc('hour', now()), 3, 1)`);
    await t.unsafe(`insert into app.change_log (commit_sha, run_id, actor, event, result) values ('${'a'.repeat(40)}', '1', 'breakin', 'push', 'ok')`);
    await t.unsafe(`insert into app.runner_tokens (jti) values ('breakin-token')`);
  });
  // PR 3 (Oct 24, 2026): a GitHub account with an agent, a post linking a site, its decision and an erasure note,
  // as the JEVs gate writes them (dog_jevs).
  await su.begin(async (t) => {
    await t.unsafe('set local role dog_jevs');
    await t.unsafe(`with a as (insert into app.gh_accounts (github_id, login) values (99001, 'breakin-a') returning id),
      g as (insert into app.gh_agents (owner_id, name) select id, 'breakin-agent' from a returning id, owner_id),
      p as (insert into app.gh_posts (node_id, kind, discussion_number, author_id, agent_id, created_at, body_key, risk)
            select 'DC_breakin', 'comment', 1, owner_id, id, now(), '${'b'.repeat(64)}', 'low' from g returning id, author_id),
      d as (insert into app.gh_post_domains (post_id, domain_key) select id, '${'c'.repeat(64)}' from p)
      insert into app.gh_decisions (action, member_id, post_id, scores, total, risk, mode, effect, applied)
      select 'post.create', author_id, id, '{}'::jsonb, 0, 'low', 'shadow', 'none', true from p`);
    await t.unsafe(`insert into app.gh_erasures (github_key, post_node_id) values ('${'d'.repeat(64)}', 'DC_gone')`);
  });
  // Member B (level 2) with an agent.
  B = await signIn(2, 'Member B');
  const [bAgent] = await run(B.ctx, (t) => t`insert into app.agents (name) values ('B agent') returning id`);
  await run(B.ctx, (t) => t`insert into app.agent_keys (agent_id, key_hash) values (${bAgent.id}, ${c.sha256hex('b-key')})`);
  BAgent = { actor: 'agent', memberId: B.id, agentId: bAgent.id, keyHash: c.sha256hex('b-key') };
  // 053, audit logging: a failed sign-in, an expired lock and an audit row's request record, all A's.
  await q(`insert into app.signin_failures (member_id) values ('${A.id}')`);
  await q(`insert into app.signin_locks (member_id, until) values ('${A.id}', now() - interval '1 hour')`);
  await q(`insert into app.audit_net (audit_id, ip, user_agent, method, path, host) values (gen_random_uuid(), '203.0.113.7', 'A browser', 'GET', '/feed', 'dayonegreat.com')`);
  tables = (await q(`select c.relname as name from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'app' and c.relkind in ('r', 'p') order by 1`)).map((r) => r.name);
});
test.after(async () => {
  for (const x of [web, su]) if (x) await x.end({ timeout: 5 });
  if (server) {
    await server.unsafe(`drop database if exists ${NAME} with (force)`);
    await server.unsafe(`drop role if exists ${WEB}`);
    await server.end({ timeout: 5 });
  }
});

const who = () => ({ anon: { actor: 'anon' }, B: B.ctx, BAgent });

test('the fixture really has member A\'s data in every table, so the checks below mean something', async () => {
  for (const t of tables) {
    if (t === 'schema_migrations') continue;
    const [r] = await q(`select count(*)::int as n from app.${t}`);
    assert.ok(r.n > 0, t + ' is empty in the fixture: add A\'s row to it');
  }
});

test('S2, S3: nobody sees rows that aren\'t theirs in any table, now or in tables added later', async () => {
  for (const [label, ctx] of Object.entries(who())) {
    for (const t of tables) {
      let n;
      try {
        [{ n }] = await run(ctx, (x) => x.unsafe(`select count(*)::int as n from app.${t}`));
      } catch (e) {
        assert.strictEqual(e.code, '42501', label + ' reading ' + t + ': ' + e.message);
        continue; // no right to read the table at all
      }
      const want = PUBLIC_LOG.has(t) ? (await q(`select count(*)::int as n from app.${t}`))[0].n : MAY_SEE[label][t] || 0;
      assert.strictEqual(n, want, label + ' sees ' + n + ' rows of ' + t);
    }
  }
});

test('S2, S3: nobody changes or deletes rows that aren\'t theirs in any table', async () => {
  const ROLLBACK = new Error('rollback');
  for (const [label, ctx] of Object.entries(who())) {
    for (const t of tables) {
      const [{ col }] = await q(`select a.attname as col from pg_attribute a where a.attrelid = 'app.${t}'::regclass and a.attnum > 0 and not a.attisdropped order by a.attnum limit 1`);
      for (const stmt of [`update app.${t} set ${col} = ${col}`, `delete from app.${t}`]) {
        let affected = 0;
        try {
          await run(ctx, async (x) => { affected = (await x.unsafe(stmt)).count; throw ROLLBACK; });
        } catch (e) {
          if (e === ROLLBACK) {
            assert.ok(affected <= (MAY_SEE[label][t] || 0), label + ': "' + stmt + '" touched ' + affected + ' rows');
            continue;
          }
          assert.ok(['42501', 'P0001', '23503', '22023'].includes(e.code) || /only|never|can't|cannot|refuse|append-only/i.test(e.message),
            label + ': "' + stmt + '" failed in an unexpected way: ' + e.code + ' ' + e.message);
        }
      }
    }
  }
});

test('S3: nobody can even lock a row that isn\'t theirs for changing (what an update or delete could reach)', async () => {
  for (const [label, ctx] of Object.entries(who())) {
    for (const t of tables) {
      for (const lock of ['for update', 'for no key update']) {
        let n;
        try {
          [{ n }] = await run(ctx, (x) => x.unsafe(`select count(*)::int as n from (select 1 from app.${t} ${lock}) r`));
        } catch (e) {
          assert.strictEqual(e.code, '42501', label + ' locking ' + t + ': ' + e.message);
          continue;
        }
        assert.ok(n <= (MAY_SEE[label][t] || 0), label + ' can reach ' + n + ' rows of ' + t + ' to change');
      }
    }
  }
});

test('S2: someone not signed in can write nothing at all', async () => {
  for (const t of tables) {
    await assert.rejects(run({ actor: 'anon' }, (x) => x.unsafe(`insert into app.${t} default values`)), (e) => e.code !== undefined, t);
  }
  // And member A's data is all still there.
  const [{ n }] = await q(`select count(*)::int as n from app.posts where author_id = '${A.id}'`);
  assert.strictEqual(n, 1);
});
